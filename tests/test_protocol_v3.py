import json
import tempfile
import time
import unittest
from pathlib import Path

from h3ntun.protocol import (
    ACK_UP,
    DATA_UP,
    FRAME_OVERHEAD,
    MAX_MESSAGE_SIZE,
    FrameCodec,
    PersistentReplayWindow,
    ProtocolError,
)
from h3ntun.reliability import Reassembler, ReliableSender, fragment_message


class EncryptedProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tunnel_id = bytes.fromhex("ab" * 16)
        self.secret = b"v3-secret".ljust(32, b"!")
        self.codec = FrameCodec(self.tunnel_id, self.secret, session_id=1234)

    def test_payload_is_encrypted_and_round_trips(self) -> None:
        payload = b"recognizable-secret-payload" * 10
        packet = self.codec.encode(DATA_UP, 1, payload, message_id=9)
        self.assertNotIn(payload, packet)
        frame = self.codec.decode(packet)
        self.assertEqual(frame.payload, payload)
        self.assertEqual(frame.message_id, 9)

    def test_nonce_changes_ciphertext_for_each_sequence(self) -> None:
        first = self.codec.encode(DATA_UP, 1, b"same", message_id=1)
        second = self.codec.encode(DATA_UP, 2, b"same", message_id=1)
        self.assertNotEqual(first, second)

    def test_header_tamper_is_rejected(self) -> None:
        packet = bytearray(self.codec.encode(DATA_UP, 1, b"payload", message_id=1))
        packet[30] ^= 1
        with self.assertRaises(ProtocolError):
            self.codec.decode(bytes(packet))

    def test_ack_is_encrypted_and_decoded(self) -> None:
        packet = self.codec.encode_ack(ACK_UP, 3, 55, 99)
        self.assertNotIn((55).to_bytes(8, "big") + (99).to_bytes(8, "big"), packet)
        self.assertEqual(self.codec.decode_ack(self.codec.decode(packet)), (55, 99))

    def test_frame_stays_below_typical_mtu(self) -> None:
        packet = self.codec.encode(DATA_UP, 1, b"x" * 1200, message_id=1)
        self.assertEqual(len(packet), FRAME_OVERHEAD + 1200)
        self.assertLessEqual(len(packet) + 28, 1500)

    def test_maximum_fragment_fits_ipv4_mtu(self) -> None:
        maximum_payload = 1500 - 28 - FRAME_OVERHEAD
        packet = self.codec.encode(DATA_UP, 1, b"x" * maximum_payload, message_id=1)
        self.assertEqual(len(packet) + 28, 1500)
        with self.assertRaises(ProtocolError):
            self.codec.encode(DATA_UP, 2, b"x" * (maximum_payload + 1), message_id=2)


class FragmentationAndFecTests(unittest.TestCase):
    def _frames(self, payload: bytes):
        codec = FrameCodec(bytes.fromhex("cd" * 16), b"f" * 32, session_id=7)
        frames = []
        for sequence, spec in enumerate(fragment_message(payload, 1200, True), 1):
            packet = codec.encode(
                DATA_UP,
                sequence,
                spec.payload,
                message_id=44,
                message_len=spec.message_len,
                fragment_index=spec.fragment_index,
                fragment_count=spec.fragment_count,
                flags=spec.flags,
            )
            frames.append(codec.decode(packet))
        return frames

    def test_sixty_thousand_byte_message_reassembles(self) -> None:
        payload = bytes(index % 251 for index in range(MAX_MESSAGE_SIZE))
        reassembler = Reassembler()
        delivered = None
        for frame in self._frames(payload):
            result = reassembler.add(frame)
            if result.payload is not None:
                delivered = result.payload
        self.assertEqual(delivered, payload)

    def test_fec_recovers_one_missing_fragment(self) -> None:
        payload = b"A" * 5000
        frames = self._frames(payload)
        reassembler = Reassembler()
        result = None
        for frame in frames:
            if not frame.is_parity and frame.fragment_index == 2:
                continue
            result = reassembler.add(frame)
        self.assertEqual(result.payload, payload)
        self.assertTrue(result.recovered_by_fec)

    def test_two_missing_fragments_wait_for_retransmission(self) -> None:
        payload = b"B" * 5000
        frames = self._frames(payload)
        reassembler = Reassembler()
        result = None
        for frame in frames:
            if not frame.is_parity and frame.fragment_index in {1, 2}:
                continue
            result = reassembler.add(frame)
        self.assertIsNone(result.payload)

    def test_completed_message_is_not_delivered_twice(self) -> None:
        payload = b"C" * 2000
        frames = self._frames(payload)
        reassembler = Reassembler()
        delivered = None
        for frame in frames:
            result = reassembler.add(frame)
            if result.payload is not None:
                delivered = result.payload
        self.assertEqual(delivered, payload)
        duplicate = reassembler.add(frames[0])
        self.assertTrue(duplicate.duplicate)
        self.assertIsNone(duplicate.payload)


class ReliableSenderTests(unittest.TestCase):
    def test_timeout_retransmits_and_ack_clears_pending(self) -> None:
        sender = ReliableSender(
            retransmit_timeout_seconds=0.5,
            max_retries=2,
            initial_window=2,
            max_window=8,
        )
        self.assertTrue(sender.enqueue(10, [b"one", b"two"]))
        started = time.monotonic()
        initial = sender.pump(started)
        self.assertEqual([item.retransmission for item in initial.packets], [False, False])
        retry = sender.pump(started + 0.6)
        self.assertEqual([item.retransmission for item in retry.packets], [True, True])
        accepted, _latency = sender.acknowledge(10)
        self.assertTrue(accepted)
        self.assertEqual(sender.snapshot()["inflight_messages"], 0)

    def test_retry_budget_exhausts_message(self) -> None:
        sender = ReliableSender(retransmit_timeout_seconds=0.1, max_retries=1)
        sender.enqueue(1, [b"packet"])
        started = time.monotonic()
        sender.pump(started)
        sender.pump(started + 0.2)
        exhausted = sender.pump(started + 0.4)
        self.assertEqual(exhausted.exhausted_messages, 1)


class PersistentReplayTests(unittest.TestCase):
    def test_state_survives_receiver_restart(self) -> None:
        tunnel_id = bytes.fromhex("ef" * 16)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "replay.json"
            first = PersistentReplayWindow(path, tunnel_id, size=64)
            self.assertTrue(first.accept(100, session_id=1))
            second = PersistentReplayWindow(path, tunnel_id, size=64)
            self.assertFalse(second.accept(100, session_id=1))
            self.assertTrue(second.accept(101, session_id=1))

    def test_retired_session_survives_restart(self) -> None:
        tunnel_id = bytes.fromhex("12" * 16)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "replay.json"
            first = PersistentReplayWindow(path, tunnel_id, size=64)
            first.accept(1, session_id=10)
            first.accept(1, session_id=11)
            second = PersistentReplayWindow(path, tunnel_id, size=64)
            self.assertFalse(second.accept(2, session_id=10))

    def test_corrupt_state_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "replay.json"
            path.write_text(json.dumps({"format": 1, "window": {}}), encoding="utf-8")
            with self.assertRaises(ProtocolError):
                PersistentReplayWindow(path, b"t" * 16, size=64)


if __name__ == "__main__":
    unittest.main()
