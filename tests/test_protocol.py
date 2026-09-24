import time
import unittest

from asym_link.protocol import DATA_UP, FrameCodec, ProtocolError, ReplayWindow


class ProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.codec = FrameCodec(bytes.fromhex("11" * 16), b"s" * 32)

    def test_round_trip(self) -> None:
        packet = self.codec.encode(DATA_UP, 7, b"payload")
        frame = self.codec.decode(packet)
        self.assertEqual(frame.sequence, 7)
        self.assertEqual(frame.payload, b"payload")

    def test_tamper_is_rejected(self) -> None:
        packet = bytearray(self.codec.encode(DATA_UP, 8, b"payload"))
        packet[-1] ^= 1
        with self.assertRaises(ProtocolError):
            self.codec.decode(bytes(packet))

    def test_old_timestamp_is_rejected(self) -> None:
        packet = self.codec.encode(DATA_UP, 9, timestamp_ms=1)
        with self.assertRaises(ProtocolError):
            self.codec.decode(packet, now_ms=int(time.time() * 1000))

    def test_replay_window(self) -> None:
        window = ReplayWindow(64)
        self.assertTrue(window.accept(10))
        self.assertTrue(window.accept(12))
        self.assertTrue(window.accept(11))
        self.assertFalse(window.accept(11))
        self.assertFalse(window.accept(-1))

    def test_new_authenticated_session_can_restart_at_lower_sequence(self) -> None:
        window = ReplayWindow(64)
        self.assertTrue(window.accept(1_000_000, session_id=10))
        self.assertTrue(window.accept(100, session_id=11))
        self.assertFalse(window.accept(1_000_000, session_id=10))

    def test_retired_session_stays_rejected_after_many_restarts(self) -> None:
        window = ReplayWindow(64)
        self.assertTrue(window.accept(1, session_id=1))
        for session_id in range(2, 100):
            self.assertTrue(window.accept(1, session_id=session_id))
        self.assertFalse(window.accept(2, session_id=1))


if __name__ == "__main__":
    unittest.main()
