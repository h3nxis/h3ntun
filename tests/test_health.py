import time
import unittest

from h3ntun.health import is_healthy


class HealthTests(unittest.TestCase):
    def test_iran_requires_recent_downlink(self) -> None:
        self.assertFalse(is_healthy({"role": "iran", "last_pong_at": None, "last_downlink_at": None}, 10))
        self.assertTrue(is_healthy({"role": "iran", "last_pong_at": time.time(), "last_downlink_at": None}, 10))

    def test_foreign_requires_recent_uplink(self) -> None:
        self.assertFalse(is_healthy({"role": "foreign", "last_uplink_at": time.time() - 20}, 10))
        self.assertTrue(is_healthy({"role": "foreign", "last_uplink_at": time.time()}, 10))


if __name__ == "__main__":
    unittest.main()
