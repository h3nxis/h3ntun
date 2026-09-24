"""Bounded loopback regressions. Production code is deliberately unchanged."""
import socket
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from h3ntun.agent import IranAgent, ForeignAgent
from h3ntun.config import IranConfig, ForeignConfig
from tests.test_integration import UdpEcho


class ExtendedLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.agents = []
        self.addCleanup(self.stop_agents)
        self.echo = UdpEcho(0)
        self.addCleanup(self.echo.stop)
        self.echo.start()
        common = dict(tunnel_id=b't' * 16, shared_secret=b's' * 32,
                      health_listen=('127.0.0.1', 0), keepalive_seconds=60,
                      health_timeout_seconds=120, recv_buffer_bytes=65536)
        foreign_config = ForeignConfig(
            **common, role='foreign', metrics_file=str(Path(self.folder.name) / 'foreign.json'),
            uplink_listen=('127.0.0.1', 0), inner_bridge_listen=('127.0.0.1', 0),
            inner_peer=self.echo.socket.getsockname(), iran_downlink=('127.0.0.1', 1),
            downlink_mode='udp', downlink_source='127.0.0.1', downlink_source_port=0)
        self.foreign = ForeignAgent(foreign_config)
        self.agents.append(self.foreign)
        self.iran_config = IranConfig(
            **common, role='iran', metrics_file=str(Path(self.folder.name) / 'iran.json'),
            inner_listen=('127.0.0.1', 0), uplink_bind=('127.0.0.1', 0),
            foreign_uplink=self.foreign.uplink_sock.getsockname(),
            downlink_listen=('127.0.0.1', 0), expected_downlink_source='127.0.0.1')
        with patch('h3ntun.agent.secrets.randbits', return_value=1_000_000):
            self.iran = IranAgent(self.iran_config)
        self.agents.append(self.iran)
        self.foreign.config = replace(self.foreign.config,
                                      iran_downlink=self.iran.downlink_sock.getsockname())
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(self.client.close)
        self.client.bind(('127.0.0.1', 0))
        self.client.settimeout(2)
        self.foreign.start()
        self.iran.start()

    def stop_agents(self):
        for agent in reversed(self.agents):
            agent.stop()

    def exchange(self, payload):
        self.client.sendto(payload, self.iran.inner_sock.getsockname())
        try:
            received, _ = self.client.recvfrom(65535)
        except socket.timeout:
            self.fail('No echo within 2 seconds; foreign replay_drops=' +
                      str(self.foreign.metrics.snapshot()['replay_drops']))
        self.assertEqual(received, payload)

    def restart_iran(self, sequence):
        downlink = self.iran.downlink_sock.getsockname()
        inner = self.iran.inner_sock.getsockname()
        self.iran.stop()
        self.agents.remove(self.iran)
        with patch('h3ntun.agent.secrets.randbits', return_value=sequence):
            self.iran = IranAgent(replace(self.iran_config,
                                         downlink_listen=downlink, inner_listen=inner))
        self.agents.append(self.iran)
        self.iran.start()

    def test_one_sided_restart_lower_sequence_recovers(self):
        self.exchange(b'before-restart')
        self.restart_iran(100)
        self.exchange(b'after-restart')

    def test_one_sided_restart_higher_sequence_recovers(self):
        self.exchange(b'before-restart')
        self.restart_iran(2_000_000)
        self.exchange(b'after-restart')

    def test_empty_datagram_roundtrip(self):
        self.exchange(b'')

    def test_binary_datagram_roundtrip(self):
        self.exchange(bytes(range(256)) * 4)

    def test_payload_size_matrix(self):
        for size in (1, 16, 64, 512, 1200, 1400):
            with self.subTest(size=size):
                self.exchange(b'x' * size)

    def test_twenty_ordered_exchanges(self):
        for index in range(20):
            with self.subTest(index=index):
                self.exchange(('message-%03d' % index).encode())
                time.sleep(0.005)

    def test_stop_joins_workers(self):
        self.exchange(b'before-stop')
        self.iran.stop()
        self.assertTrue(all(not t.is_alive() for t in self.iran.runtime.threads))
        self.assertTrue(all(s.fileno() == -1 for s in self.iran.runtime.sockets))


if __name__ == '__main__':
    unittest.main()
