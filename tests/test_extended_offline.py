"""Small offline functional matrices; failures assert desired behavior."""
import base64
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from asym_link.config import ConfigError, load_config
from asym_link.health import is_healthy
from asym_link.metrics import Metrics
from asym_link.protocol import DATA_UP, DATA_DOWN, PING, PONG, FrameCodec, ProtocolError, ReplayWindow


class ExtendedOfflineTests(unittest.TestCase):
    def test_health_fresh_downlink_not_masked_by_old_pong(self):
        with patch('asym_link.health.time.time', return_value=1000):
            self.assertTrue(is_healthy(dict(role='iran', last_pong_at=900,
                                           last_downlink_at=999), 20))

    def test_metrics_snapshot_independent(self):
        metrics = Metrics('iran', '')
        snapshot = metrics.snapshot()
        snapshot['uplink_tx_packets'] = 999
        self.assertEqual(metrics.snapshot()['uplink_tx_packets'], 0)

    def test_metrics_bounded_concurrent_increments(self):
        metrics = Metrics('iran', '')
        def add():
            for _ in range(100):
                metrics.add('uplink_tx', 16)
        threads = [threading.Thread(target=add) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
        self.assertEqual(metrics.snapshot()['uplink_tx_packets'], 400)
        self.assertEqual(metrics.snapshot()['uplink_tx_bytes'], 6400)

    def test_metrics_persist_and_replace(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'nested' / 'metrics.json'
            metrics = Metrics('iran', str(path))
            metrics.persist()
            metrics.add('downlink_rx', 55)
            metrics.persist()
            data = json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(data['downlink_rx_bytes'], 55)
            self.assertEqual(data['downlink_rx_packets'], 1)
            self.assertEqual(list(path.parent.glob('*.tmp')), [])

    def test_replay_window_boundary(self):
        replay = ReplayWindow(64)
        self.assertTrue(replay.accept(100))
        self.assertTrue(replay.accept(37))
        self.assertFalse(replay.accept(36))
        self.assertFalse(replay.accept(37))

    def test_replay_reordering(self):
        replay = ReplayWindow()
        for sequence in (100, 103, 101, 102, 104):
            self.assertTrue(replay.accept(sequence))
        for sequence in (100, 101, 102, 103, 104):
            self.assertFalse(replay.accept(sequence))

    def test_replay_forward_jump(self):
        replay = ReplayWindow(64)
        self.assertTrue(replay.accept(1))
        self.assertTrue(replay.accept(10000))
        self.assertFalse(replay.accept(1))
        self.assertLessEqual(replay.bitmap.bit_length(), 64)

    def test_encode_rejects_over_limit(self):
        codec = FrameCodec(b't' * 16, b's' * 32)
        with self.assertRaises(ProtocolError):
            codec.encode(DATA_UP, 1, b'x' * 60001)


def config_case(field, value, rejected):
    def test(self):
        data = dict(role='iran', tunnel_id='22' * 16,
                    shared_secret=base64.b64encode(b'k' * 32).decode(),
                    inner_listen='127.0.0.1:5000', foreign_uplink='127.0.0.1:7000',
                    downlink_listen='127.0.0.1:7001')
        data[field] = value
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'config.json'
            path.write_text(json.dumps(data), encoding='utf-8')
            if rejected:
                with self.assertRaises(ConfigError, msg=f'{field}={value!r} must be rejected'):
                    load_config(path)
            else:
                self.assertEqual(getattr(load_config(path), field), value)
    return test


for field in ('keepalive_seconds', 'health_timeout_seconds'):
    for label, value, rejected in (
        ('zero', 0, True), ('negative', -1, True),
        ('nan', 'NaN', True), ('infinity', 'Infinity', True),
        ('negative_infinity', '-Infinity', True),
        ('positive', 5, False), ('fraction', 0.25, False),
    ):
        setattr(ExtendedOfflineTests, f'test_config_{field}_{label}', config_case(field, value, rejected))


def health_case(role, age, expected):
    def test(self):
        key = 'last_downlink_at' if role == 'iran' else 'last_uplink_at'
        snapshot = dict(role=role)
        if age is not None:
            snapshot[key] = 1000 - age
        with patch('asym_link.health.time.time', return_value=1000):
            self.assertEqual(is_healthy(snapshot, 20), expected)
    return test


for role in ('iran', 'foreign'):
    for label, age, expected in (('missing', None, False), ('fresh', 1, True),
                                 ('boundary', 20, True), ('stale', 21, False)):
        setattr(ExtendedOfflineTests, f'test_health_{role}_{label}', health_case(role, age, expected))


def roundtrip_case(kind, size):
    def test(self):
        codec = FrameCodec(b't' * 16, b's' * 32)
        payload = bytes(index % 256 for index in range(size))
        frame = codec.decode(codec.encode(kind, 17, payload, timestamp_ms=1000000), now_ms=1000000)
        self.assertEqual((frame.kind, frame.sequence, frame.payload), (kind, 17, payload))
    return test


for kind in (DATA_UP, DATA_DOWN):
    for size in (0, 1, 256, 1200, 60000):
        setattr(ExtendedOfflineTests, f'test_roundtrip_kind_{kind}_size_{size}', roundtrip_case(kind, size))
for kind in (PING, PONG):
    setattr(ExtendedOfflineTests, f'test_control_kind_{kind}', roundtrip_case(kind, 0))


def timestamp_case(offset, accepted):
    def test(self):
        codec = FrameCodec(b't' * 16, b's' * 32)
        packet = codec.encode(DATA_UP, 1, b'ok', timestamp_ms=1000000)
        if accepted:
            self.assertEqual(codec.decode(packet, now_ms=1000000 + offset).payload, b'ok')
        else:
            with self.assertRaises(ProtocolError):
                codec.decode(packet, now_ms=1000000 + offset)
    return test


for label, offset, accepted in (('past_boundary', 600000, True), ('past_outside', 600001, False),
                                ('future_boundary', -600000, True), ('future_outside', -600001, False)):
    setattr(ExtendedOfflineTests, f'test_timestamp_{label}', timestamp_case(offset, accepted))


if __name__ == '__main__':
    unittest.main()
