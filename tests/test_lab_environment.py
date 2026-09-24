import unittest

from scripts.lab_environment import AsymmetricLab, LinkProfile


class LabEnvironmentTests(unittest.TestCase):
    def test_clean_independent_paths(self) -> None:
        lab = AsymmetricLab(LinkProfile(delay_ms=2), LinkProfile(delay_ms=3))
        lab.start()
        try:
            result = lab.run_burst(20, timeout_seconds=2)
            self.assertEqual(result["received"], 20)
            self.assertEqual(result["agent_drops"]["iran_source"], 0)
            self.assertGreaterEqual(result["latency_ms"]["min"], 4)
        finally:
            lab.stop()

    def test_deterministic_loss_is_visible(self) -> None:
        lab = AsymmetricLab(LinkProfile(drop_every=5), LinkProfile())
        lab.start()
        try:
            result = lab.run_burst(20, timeout_seconds=3)
            self.assertGreater(result["uplink"]["dropped"], 0)
            self.assertEqual(result["received"], 20)
            self.assertGreater(result["reliability"]["iran_retransmitted_frames"], 0)
        finally:
            lab.stop()

    def test_downlink_outage_and_recovery(self) -> None:
        lab = AsymmetricLab()
        lab.start()
        try:
            lab.downlink.set_enabled(False)
            failed = lab.run_burst(3, timeout_seconds=0.3)
            self.assertEqual(failed["received"], 0)
            lab.downlink.set_enabled(True)
            recovered = lab.run_burst(5, timeout_seconds=2)
            self.assertEqual(recovered["received"], 5)
        finally:
            lab.stop()

    def test_single_fragment_loss_is_recovered_by_fec(self) -> None:
        lab = AsymmetricLab(
            LinkProfile(drop_indices=(3,)),
            LinkProfile(),
            response_size=5000,
        )
        lab.start()
        try:
            result = lab.run_burst(1, request_size=5000, timeout_seconds=2)
            self.assertEqual(result["received"], 1)
            self.assertEqual(result["reliability"]["foreign_fec_recoveries"], 1)
            self.assertEqual(result["reliability"]["iran_retransmitted_frames"], 0)
        finally:
            lab.stop()

    def test_maximum_payload_crosses_both_relays(self) -> None:
        lab = AsymmetricLab(response_size=60_000)
        lab.start()
        try:
            result = lab.run_burst(3, request_size=60_000, timeout_seconds=3)
            self.assertEqual(result["received"], 3)
        finally:
            lab.stop()

    def test_oversize_payload_is_counted_and_not_forwarded(self) -> None:
        lab = AsymmetricLab()
        lab.start()
        try:
            result = lab.run_burst(1, request_size=60_001, timeout_seconds=0.3)
            self.assertEqual(result["received"], 0)
            self.assertEqual(result["backend_requests"], 0)
            self.assertEqual(lab.iran.metrics.snapshot()["oversize_drops"], 1)
        finally:
            lab.stop()
