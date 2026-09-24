import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class SafetyContractTests(unittest.TestCase):
    def test_scanner_has_no_live_raw_socket_path(self) -> None:
        scanner = (ROOT / "scripts" / "spoof_scanner.py").read_text(encoding="utf-8")
        self.assertNotIn("SOCK_RAW", scanner)
        self.assertNotIn("IP_HDRINCL", scanner)
        self.assertNotIn("IPPROTO_RAW", scanner)

    def test_network_helper_does_not_disable_global_rp_filter(self) -> None:
        helper = (ROOT / "scripts" / "setup-iran-network.sh").read_text(encoding="utf-8")
        self.assertNotIn("net.ipv4.conf.all.rp_filter=0", helper)
        self.assertNotIn("net.ipv4.conf.default.rp_filter=0", helper)
        self.assertIn("--restore-rp-filter", helper)
        self.assertIn("--restore-route", helper)

    def test_source_nat_requires_assigned_local_address(self) -> None:
        helper = (ROOT / "scripts" / "setup-foreign-snat.sh").read_text(encoding="utf-8")
        self.assertIn("source_is_local", helper)
        self.assertIn("--apply", helper)
        self.assertNotIn("ip_forward=1", helper)


if __name__ == "__main__":
    unittest.main()
