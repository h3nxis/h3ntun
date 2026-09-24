import base64
import contextlib
import io
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from scripts.source_scanner import (
    ProbeError,
    decode_probe,
    encode_probe,
    parse_ip_targets,
    run_receiver,
    run_scanner,
)


TUNNEL_ID_HEX = "77" * 16
TUNNEL_ID = bytes.fromhex(TUNNEL_ID_HEX)
SECRET = b"p" * 32
SECRET_B64 = base64.b64encode(SECRET).decode()


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def write_configs(folder: str) -> tuple[Path, Path]:
    iran = Path(folder) / "iran.json"
    foreign = Path(folder) / "foreign.json"
    iran.write_text(json.dumps({
        "role": "iran",
        "tunnel_id": TUNNEL_ID_HEX,
        "shared_secret": SECRET_B64,
        "inner_listen": "127.0.0.1:5000",
        "foreign_uplink": "127.0.0.1:7000",
        "downlink_listen": "127.0.0.1:7001",
        "expected_downlink_source": None,
    }), encoding="utf-8")
    foreign.write_text(json.dumps({
        "role": "foreign",
        "tunnel_id": TUNNEL_ID_HEX,
        "shared_secret": SECRET_B64,
        "uplink_listen": "127.0.0.1:7000",
        "inner_bridge_listen": "127.0.0.1:5001",
        "inner_peer": "127.0.0.1:51820",
        "iran_downlink": "127.0.0.1:7001",
        "downlink_mode": "udp",
    }), encoding="utf-8")
    return iran, foreign


class ScannerTests(unittest.TestCase):
    def test_parse_cidr(self) -> None:
        ips = parse_ip_targets(cidr="192.0.2.0/29")
        self.assertEqual(len(ips), 6)
        self.assertIn("192.0.2.1", ips)
        self.assertIn("192.0.2.6", ips)

    def test_parse_range(self) -> None:
        ips = parse_ip_targets(ip_range="10.0.0.5-10.0.0.10")
        self.assertEqual(ips[0], "10.0.0.5")
        self.assertEqual(ips[-1], "10.0.0.10")

    def test_large_cidr_requires_bounded_sample(self) -> None:
        with self.assertRaises(ValueError):
            parse_ip_targets(cidr="10.0.0.0/8")
        sampled = parse_ip_targets(cidr="10.0.0.0/8", sample_limit=15)
        self.assertEqual(len(sampled), 15)

    def test_probe_authentication_and_tamper(self) -> None:
        packet = encode_probe(TUNNEL_ID, SECRET, "127.0.0.2", 1, 3)
        probe = decode_probe(packet, TUNNEL_ID, SECRET)
        self.assertEqual(probe.candidate_ip, "127.0.0.2")
        tampered = bytearray(packet)
        tampered[-1] ^= 1
        with self.assertRaises(ProbeError):
            decode_probe(bytes(tampered), TUNNEL_ID, SECRET)

    def test_stale_probe_is_rejected(self) -> None:
        packet = encode_probe(TUNNEL_ID, SECRET, "127.0.0.2", 1, 3, timestamp_ns=1)
        with self.assertRaises(ProbeError):
            decode_probe(packet, TUNNEL_ID, SECRET, now_ns=time.time_ns())

    def test_source_bound_scan_and_atomic_config_update(self) -> None:
        port = free_port()
        with tempfile.TemporaryDirectory() as folder:
            iran_config, foreign_config = write_configs(folder)
            result: dict[str, object] = {}

            def receive() -> None:
                result["best"] = run_receiver(
                    "127.0.0.1", port, str(iran_config), duration_seconds=0.8,
                    update_config=True,
                )

            thread = threading.Thread(target=receive)
            thread.start()
            time.sleep(0.1)
            sent = run_scanner(
                "127.0.0.1", port, ["127.0.0.2"], str(foreign_config),
                probes_per_ip=3, delay_ms=0,
            )
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(sent["127.0.0.2"], "sent:3")
            self.assertEqual(result.get("best"), "127.0.0.2")
            updated = json.loads(iran_config.read_text(encoding="utf-8"))
            self.assertEqual(updated["expected_downlink_source"], "127.0.0.2")
            self.assertTrue(Path(str(iran_config) + ".bak").exists())

    def test_claimed_candidate_must_match_observed_source(self) -> None:
        port = free_port()
        with tempfile.TemporaryDirectory() as folder:
            iran_config, _foreign_config = write_configs(folder)
            output = io.StringIO()

            def receive() -> None:
                with contextlib.redirect_stdout(output):
                    run_receiver("127.0.0.1", port, str(iran_config), duration_seconds=0.5)

            thread = threading.Thread(target=receive)
            thread.start()
            time.sleep(0.1)
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.bind(("127.0.0.1", 0))
            packet = encode_probe(TUNNEL_ID, SECRET, "127.0.0.2", 1, 3)
            sender.sendto(packet, ("127.0.0.1", port))
            sender.close()
            thread.join(timeout=2)
            self.assertIn("source_mismatches=1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
