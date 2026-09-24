import contextlib
import io
import json
import socket
import threading
import unittest

from h3ntun.cli import main


class CliTests(unittest.TestCase):
    def test_packet_selftest(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["packet-selftest"])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output.getvalue())["ok"])

    def test_probe_against_echo(self) -> None:
        echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        echo.bind(("127.0.0.1", 0))
        echo.settimeout(1)
        port = echo.getsockname()[1]

        def serve() -> None:
            try:
                for _ in range(2):
                    payload, peer = echo.recvfrom(65_535)
                    echo.sendto(payload, peer)
            finally:
                echo.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["probe", "--target", f"127.0.0.1:{port}", "--count", "2"])
        thread.join(timeout=2)
        result = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(result["received"], 2)


if __name__ == "__main__":
    unittest.main()
