import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class ReleaseContractTests(unittest.TestCase):
    def test_package_identity_and_crypto_dependency(self) -> None:
        metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('name = "h3ntun"', metadata)
        self.assertIn('version = "0.4.0"', metadata)
        self.assertIn('"cryptography>=42"', metadata)

    def test_service_runs_installed_virtualenv_binary(self) -> None:
        service = (ROOT / "systemd" / "h3ntun.service").read_text(encoding="utf-8")
        self.assertIn("ExecStart=/opt/h3ntun/venv/bin/h3ntun run", service)
        self.assertIn("User=h3ntun", service)
        self.assertNotIn("hy-asym-link", service)

    def test_example_configs_enable_reliability_and_durable_replay(self) -> None:
        for name in ("iran.example.json", "foreign.example.json"):
            config = json.loads((ROOT / "config" / name).read_text(encoding="utf-8"))
            self.assertTrue(config["reliable"])
            self.assertTrue(config["fec_enabled"])
            self.assertEqual(config["fragment_payload_bytes"], 1200)
            self.assertTrue(config["replay_state_file"].startswith("/var/lib/h3ntun/"))

    def test_ci_installs_package_and_checks_shell(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("python -m pip install -e .", workflow)
        self.assertIn("bash -n scripts/*.sh", workflow)
        self.assertIn("python -m compileall -q h3ntun", workflow)


if __name__ == "__main__":
    unittest.main()
