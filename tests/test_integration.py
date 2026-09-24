import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from h3ntun.agent import ForeignAgent, IranAgent
from h3ntun.config import ForeignConfig, IranConfig
from h3ntun.protocol import DATA_DOWN, FrameCodec


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_for(predicate, timeout: float = 2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


class UdpEcho:
    def __init__(self, port: int):
        self.stop_event = threading.Event()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", port))
        self.socket.settimeout(0.2)
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                payload, peer = self.socket.recvfrom(65_535)
                self.socket.sendto(payload, peer)
            except socket.timeout:
                pass
            except OSError:
                break

    def stop(self) -> None:
        self.stop_event.set()
        self.socket.close()
        if self.thread.ident is not None:
            self.thread.join(timeout=1)


class IntegrationTests(unittest.TestCase):
    def test_bidirectional_authenticated_datagram(self) -> None:
        ports = [free_udp_port() for _ in range(5)]
        inner_port, uplink_port, downlink_port, bridge_port, echo_port = ports
        tunnel_id = bytes.fromhex("33" * 16)
        secret = b"z" * 32

        with tempfile.TemporaryDirectory() as folder:
            iran = IranAgent(IranConfig(
                role="iran",
                tunnel_id=tunnel_id,
                shared_secret=secret,
                health_listen=("127.0.0.1", 0),
                metrics_file=str(Path(folder) / "iran.json"),
                keepalive_seconds=0.2,
                health_timeout_seconds=2,
                recv_buffer_bytes=65_536,
                inner_listen=("127.0.0.1", inner_port),
                uplink_bind=("127.0.0.1", 0),
                foreign_uplink=("127.0.0.1", uplink_port),
                downlink_listen=("127.0.0.1", downlink_port),
                expected_downlink_source="127.0.0.1",
            ))
            foreign = ForeignAgent(ForeignConfig(
                role="foreign",
                tunnel_id=tunnel_id,
                shared_secret=secret,
                health_listen=("127.0.0.1", 0),
                metrics_file=str(Path(folder) / "foreign.json"),
                keepalive_seconds=0.2,
                health_timeout_seconds=2,
                recv_buffer_bytes=65_536,
                uplink_listen=("127.0.0.1", uplink_port),
                inner_bridge_listen=("127.0.0.1", bridge_port),
                inner_peer=("127.0.0.1", echo_port),
                iran_downlink=("127.0.0.1", downlink_port),
                downlink_mode="udp",
                downlink_source="127.0.0.1",
                downlink_source_port=0,
            ))
            echo = UdpEcho(echo_port)
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.bind(("127.0.0.1", 0))
            client.settimeout(3)

            try:
                echo.start()
                foreign.start()
                iran.start()
                payload = b"end-to-end-test"
                client.sendto(payload, ("127.0.0.1", inner_port))
                received, _ = client.recvfrom(65_535)
                self.assertEqual(received, payload)
                self.assertGreater(iran.metrics.snapshot()["uplink_tx_packets"], 0)
                self.assertGreater(foreign.metrics.snapshot()["downlink_tx_packets"], 0)
                self.assertEqual(iran.metrics.snapshot()["last_downlink_source"], "127.0.0.1")
            finally:
                client.close()
                iran.stop()
                foreign.stop()
                echo.stop()

    def test_wrong_return_source_is_dropped(self) -> None:
        inner_port, uplink_port, downlink_port = [free_udp_port() for _ in range(3)]
        tunnel_id = bytes.fromhex("44" * 16)
        secret = b"m" * 32
        with tempfile.TemporaryDirectory() as folder:
            iran = IranAgent(IranConfig(
                role="iran",
                tunnel_id=tunnel_id,
                shared_secret=secret,
                health_listen=("127.0.0.1", 0),
                metrics_file=str(Path(folder) / "iran.json"),
                keepalive_seconds=10,
                health_timeout_seconds=2,
                recv_buffer_bytes=65_536,
                inner_listen=("127.0.0.1", inner_port),
                uplink_bind=("127.0.0.1", 0),
                foreign_uplink=("127.0.0.1", uplink_port),
                downlink_listen=("127.0.0.1", downlink_port),
                expected_downlink_source="127.0.0.2",
            ))
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                iran.start()
                packet = FrameCodec(tunnel_id, secret).encode(DATA_DOWN, 1, b"must-drop")
                sender.sendto(packet, ("127.0.0.1", downlink_port))
                self.assertTrue(wait_for(lambda: iran.metrics.snapshot()["source_mismatch_drops"] == 1))
                self.assertEqual(iran.metrics.snapshot()["downlink_rx_packets"], 0)
            finally:
                sender.close()
                iran.stop()

    def test_duplicate_authenticated_frame_is_dropped(self) -> None:
        inner_port, uplink_port, downlink_port = [free_udp_port() for _ in range(3)]
        tunnel_id = bytes.fromhex("55" * 16)
        secret = b"r" * 32
        with tempfile.TemporaryDirectory() as folder:
            iran = IranAgent(IranConfig(
                role="iran",
                tunnel_id=tunnel_id,
                shared_secret=secret,
                health_listen=("127.0.0.1", 0),
                metrics_file=str(Path(folder) / "iran.json"),
                keepalive_seconds=10,
                health_timeout_seconds=2,
                recv_buffer_bytes=65_536,
                inner_listen=("127.0.0.1", inner_port),
                uplink_bind=("127.0.0.1", 0),
                foreign_uplink=("127.0.0.1", uplink_port),
                downlink_listen=("127.0.0.1", downlink_port),
                expected_downlink_source="127.0.0.1",
            ))
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.bind(("127.0.0.1", 0))
            client.settimeout(1)
            try:
                iran.start()
                client.sendto(b"register-peer", ("127.0.0.1", inner_port))
                self.assertTrue(wait_for(lambda: iran.metrics.snapshot()["inner_rx_packets"] == 1))
                packet = FrameCodec(tunnel_id, secret).encode(DATA_DOWN, 77, b"once-only")
                sender.sendto(packet, ("127.0.0.1", downlink_port))
                sender.sendto(packet, ("127.0.0.1", downlink_port))
                received, _ = client.recvfrom(65_535)
                self.assertEqual(received, b"once-only")
                self.assertTrue(wait_for(lambda: iran.metrics.snapshot()["replay_drops"] == 1))
                self.assertEqual(iran.metrics.snapshot()["inner_tx_packets"], 1)
            finally:
                sender.close()
                client.close()
                iran.stop()

    def test_link_recovers_when_foreign_side_starts_late(self) -> None:
        inner_port, uplink_port, downlink_port, bridge_port, echo_port = [free_udp_port() for _ in range(5)]
        tunnel_id = bytes.fromhex("66" * 16)
        secret = b"q" * 32
        with tempfile.TemporaryDirectory() as folder:
            iran = IranAgent(IranConfig(
                role="iran", tunnel_id=tunnel_id, shared_secret=secret,
                health_listen=("127.0.0.1", 0), metrics_file=str(Path(folder) / "iran.json"),
                keepalive_seconds=0.2, health_timeout_seconds=2, recv_buffer_bytes=65_536,
                inner_listen=("127.0.0.1", inner_port), uplink_bind=("127.0.0.1", 0),
                foreign_uplink=("127.0.0.1", uplink_port),
                downlink_listen=("127.0.0.1", downlink_port), expected_downlink_source="127.0.0.1",
            ))
            foreign_config = ForeignConfig(
                role="foreign", tunnel_id=tunnel_id, shared_secret=secret,
                health_listen=("127.0.0.1", 0), metrics_file=str(Path(folder) / "foreign.json"),
                keepalive_seconds=0.2, health_timeout_seconds=2, recv_buffer_bytes=65_536,
                uplink_listen=("127.0.0.1", uplink_port),
                inner_bridge_listen=("127.0.0.1", bridge_port), inner_peer=("127.0.0.1", echo_port),
                iran_downlink=("127.0.0.1", downlink_port), downlink_mode="udp",
                downlink_source="127.0.0.1", downlink_source_port=0,
            )
            foreign = None
            echo = UdpEcho(echo_port)
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.bind(("127.0.0.1", 0))
            try:
                iran.start()
                client.settimeout(0.25)
                client.sendto(b"lost-before-foreign-start", ("127.0.0.1", inner_port))
                with self.assertRaises(socket.timeout):
                    client.recvfrom(65_535)

                echo.start()
                foreign = ForeignAgent(foreign_config)
                foreign.start()
                client.settimeout(3)
                client.sendto(b"works-after-recovery", ("127.0.0.1", inner_port))
                received, _ = client.recvfrom(65_535)
                self.assertEqual(received, b"works-after-recovery")
                self.assertTrue(wait_for(lambda: iran.metrics.snapshot()["last_pong_at"] is not None))
            finally:
                client.close()
                iran.stop()
                if foreign is not None:
                    foreign.stop()
                echo.stop()

    def test_foreign_rejects_unconfigured_inner_response_source(self) -> None:
        uplink_port, bridge_port, expected_peer_port, downlink_port = [
            free_udp_port() for _ in range(4)
        ]
        with tempfile.TemporaryDirectory() as folder:
            foreign = ForeignAgent(ForeignConfig(
                role="foreign", tunnel_id=bytes.fromhex("77" * 16), shared_secret=b"i" * 32,
                health_listen=("127.0.0.1", 0),
                metrics_file=str(Path(folder) / "foreign.json"),
                keepalive_seconds=10, health_timeout_seconds=2, recv_buffer_bytes=65_536,
                uplink_listen=("127.0.0.1", uplink_port),
                inner_bridge_listen=("127.0.0.1", bridge_port),
                inner_peer=("127.0.0.1", expected_peer_port),
                iran_downlink=("127.0.0.1", downlink_port), downlink_mode="udp",
                downlink_source="127.0.0.1", downlink_source_port=0,
            ))
            attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            attacker.bind(("127.0.0.1", 0))
            try:
                foreign.start()
                attacker.sendto(b"local-injection", ("127.0.0.1", bridge_port))
                self.assertTrue(wait_for(
                    lambda: foreign.metrics.snapshot()["inner_source_mismatch_drops"] == 1
                ))
                self.assertEqual(foreign.metrics.snapshot()["downlink_tx_packets"], 0)
            finally:
                attacker.close()
                foreign.stop()

    def test_iran_can_pin_expected_inner_peer(self) -> None:
        inner_port, expected_port, uplink_port, downlink_port = [
            free_udp_port() for _ in range(4)
        ]
        with tempfile.TemporaryDirectory() as folder:
            iran = IranAgent(IranConfig(
                role="iran", tunnel_id=bytes.fromhex("88" * 16), shared_secret=b"j" * 32,
                health_listen=("127.0.0.1", 0), metrics_file=str(Path(folder) / "iran.json"),
                keepalive_seconds=10, health_timeout_seconds=2, recv_buffer_bytes=65_536,
                inner_listen=("127.0.0.1", inner_port), uplink_bind=("127.0.0.1", 0),
                foreign_uplink=("127.0.0.1", uplink_port),
                downlink_listen=("127.0.0.1", downlink_port),
                expected_downlink_source=None,
                expected_inner_peer=("127.0.0.1", expected_port),
            ))
            unexpected = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            unexpected.bind(("127.0.0.1", 0))
            try:
                iran.start()
                unexpected.sendto(b"peer-hijack", ("127.0.0.1", inner_port))
                self.assertTrue(wait_for(
                    lambda: iran.metrics.snapshot()["inner_source_mismatch_drops"] == 1
                ))
                self.assertIsNone(iran.inner_peer)
                self.assertEqual(iran.metrics.snapshot()["uplink_tx_packets"], 0)
            finally:
                unexpected.close()
                iran.stop()


if __name__ == "__main__":
    unittest.main()
