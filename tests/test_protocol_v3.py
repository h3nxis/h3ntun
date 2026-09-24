import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

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
        exhausted = sender.pump(started + 0.45)
        self.assertEqual(exhausted.exhausted_messages, 1)


class PersistentReplayTests(unittest.TestCase):
    @staticmethod
    def wait_for(predicate, timeout: float = 2.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.005)
        return False

    def test_state_survives_receiver_restart(self) -> None:
        tunnel_id = bytes.fromhex("ef" * 16)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "replay.json"
            first = PersistentReplayWindow(path, tunnel_id, size=64)
            self.assertTrue(first.accept(100, session_id=1))
            self.assertTrue(first.close())
            second = PersistentReplayWindow(path, tunnel_id, size=64)
            self.assertFalse(second.accept(100, session_id=1))
            self.assertTrue(second.accept(101, session_id=1))
            self.assertTrue(second.close())

    def test_retired_session_survives_restart(self) -> None:
        tunnel_id = bytes.fromhex("12" * 16)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "replay.json"
            first = PersistentReplayWindow(path, tunnel_id, size=64)
            first.accept(1, session_id=10)
            first.accept(1, session_id=11)
            self.assertTrue(first.close())
            second = PersistentReplayWindow(path, tunnel_id, size=64)
            self.assertFalse(second.accept(2, session_id=10))
            self.assertTrue(second.close())

    def test_corrupt_state_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "replay.json"
            path.write_text(json.dumps({"format": 1, "window": {}}), encoding="utf-8")
            with self.assertRaises(ProtocolError):
                PersistentReplayWindow(path, b"t" * 16, size=64)

    def test_packet_storm_coalesces_without_waiting_for_blocked_disk(self) -> None:
        tunnel_id = b"s" * 16
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "replay.json"
            window = PersistentReplayWindow(path, tunnel_id, size=4096, batch_frames=1)
            entered = threading.Event()
            release = threading.Event()
            real_write = window._write_snapshot

            def slow_write(state):
                entered.set()
                if not release.wait(3):
                    raise OSError("simulated stalled disk")
                real_write(state)

            try:
                with patch.object(window, "_write_snapshot", side_effect=slow_write):
                    self.assertTrue(window.accept(1, session_id=1))
                    self.assertTrue(entered.wait(1))
                    started = time.monotonic()
                    for sequence in range(2, 1002):
                        self.assertTrue(window.accept(sequence, session_id=1))
                    self.assertLess(time.monotonic() - started, 1.0)
                    stats = window.stats()
                    self.assertEqual(stats["replay_checkpoint_queue_depth"], 1)
                    self.assertEqual(stats["replay_checkpoint_lag_frames"], 1001)
                    self.assertGreater(stats["replay_snapshots_coalesced"], 0)
            finally:
                release.set()
                self.assertTrue(window.close())
            restarted = PersistentReplayWindow(path, tunnel_id)
            self.assertFalse(restarted.accept(1001, session_id=1))
            self.assertTrue(restarted.close())

    def test_interval_group_commit_and_latency_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            window = PersistentReplayWindow(
                Path(folder) / "replay.json", b"g" * 16,
                interval_seconds=0.05, batch_frames=1000,
            )
            for sequence in range(10):
                self.assertTrue(window.accept(sequence, session_id=4))
            self.assertTrue(self.wait_for(lambda: window.stats()["replay_checkpoints"] == 1))
            stats = window.stats()
            self.assertEqual(stats["replay_checkpoint_lag_frames"], 0)
            self.assertEqual(stats["replay_checkpoint_lag_ms"], 0)
            self.assertIsNotNone(stats["replay_write_latency_ms"])
            self.assertTrue(window.close())

    def test_write_failure_is_reported_and_retried(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "replay.json"
            window = PersistentReplayWindow(
                path, b"e" * 16, interval_seconds=0.01, batch_frames=1,
            )
            real_write = window._write_snapshot
            attempts = 0

            def fail_once(state):
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise OSError("simulated disk failure")
                real_write(state)

            with patch.object(window, "_write_snapshot", side_effect=fail_once):
                self.assertTrue(window.accept(10, session_id=1))
                self.assertTrue(self.wait_for(lambda: window.stats()["replay_persistence_errors"] == 1))
                self.assertTrue(self.wait_for(lambda: window.stats()["replay_checkpoints"] == 1))
            self.assertEqual(window.stats()["replay_persistence_errors"], 1)
            self.assertIsNone(window.stats()["replay_persistence_last_error"])
            self.assertTrue(window.close())

    @unittest.skipUnless(os.name == "posix", "directory fsync is POSIX-specific")
    def test_checkpoint_fsyncs_file_and_directory(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            window = PersistentReplayWindow(Path(folder) / "replay.json", b"d" * 16)
            with patch("h3ntun.protocol.os.fsync", wraps=os.fsync) as fsync:
                self.assertTrue(window.accept(1, session_id=1))
                self.assertTrue(window.close())
            self.assertGreaterEqual(fsync.call_count, 2)


if __name__ == "__main__":
    unittest.main()
