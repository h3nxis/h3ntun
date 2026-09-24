import base64
import json
import tempfile
import unittest
from pathlib import Path

from asym_link.config import ConfigError, ForeignConfig, IranConfig, load_config


TUNNEL_ID = "22" * 16
SECRET = base64.b64encode(b"k" * 32).decode()


def write_config(folder: str, data: dict) -> Path:
    path = Path(folder) / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class ConfigTests(unittest.TestCase):
    def test_iran_config(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = write_config(folder, {
                "role": "iran",
                "tunnel_id": TUNNEL_ID,
                "shared_secret": SECRET,
                "inner_listen": "127.0.0.1:5000",
                "foreign_uplink": "127.0.0.1:7000",
                "downlink_listen": "0.0.0.0:7001",
            })
            self.assertIsInstance(load_config(path), IranConfig)

    def test_iran_expected_inner_peer(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = write_config(folder, {
                "role": "iran",
                "tunnel_id": TUNNEL_ID,
                "shared_secret": SECRET,
                "inner_listen": "127.0.0.1:5000",
                "expected_inner_peer": "127.0.0.1:5002",
                "foreign_uplink": "127.0.0.1:7000",
                "downlink_listen": "0.0.0.0:7001",
            })
            config = load_config(path)
            self.assertEqual(config.expected_inner_peer, ("127.0.0.1", 5002))

    def test_foreign_config(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = write_config(folder, {
                "role": "foreign",
                "tunnel_id": TUNNEL_ID,
                "shared_secret": SECRET,
                "uplink_listen": "0.0.0.0:7000",
                "inner_bridge_listen": "127.0.0.1:5001",
                "inner_peer": "127.0.0.1:51820",
                "iran_downlink": "127.0.0.1:7001",
                "downlink_mode": "udp",
            })
            self.assertIsInstance(load_config(path), ForeignConfig)

    def test_placeholder_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = write_config(folder, {
                "role": "iran",
                "tunnel_id": "replace_tunnel_id",
                "shared_secret": SECRET,
                "inner_listen": "127.0.0.1:5000",
                "foreign_uplink": "foreign_ip:7000",
                "downlink_listen": "0.0.0.0:7001",
            })
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_live_raw_mode_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = write_config(folder, {
                "role": "foreign",
                "tunnel_id": TUNNEL_ID,
                "shared_secret": SECRET,
                "uplink_listen": "0.0.0.0:7000",
                "inner_bridge_listen": "127.0.0.1:5001",
                "inner_peer": "127.0.0.1:51820",
                "iran_downlink": "127.0.0.1:7001",
                "downlink_mode": "raw",
            })
            with self.assertRaises(ConfigError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
