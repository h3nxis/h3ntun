from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .metrics import Metrics


def is_healthy(snapshot: dict, timeout_seconds: float) -> bool:
    now = time.time()
    if snapshot["role"] == "iran":
        candidates = [
            float(value)
            for value in (snapshot.get("last_pong_at"), snapshot.get("last_downlink_at"))
            if value is not None
        ]
        last = max(candidates, default=None)
        return bool(last and now - float(last) <= timeout_seconds)
    last = snapshot.get("last_uplink_at")
    return bool(last and now - float(last) <= timeout_seconds)


def start_health_server(bind: tuple[str, int], metrics: Metrics, timeout_seconds: float) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            snapshot = metrics.snapshot()
            healthy = is_healthy(snapshot, timeout_seconds)
            if self.path == "/healthz":
                body = json.dumps({"ok": healthy, "role": snapshot["role"]}).encode()
                self.send_response(200 if healthy else 503)
            elif self.path == "/status":
                snapshot["healthy"] = healthy
                body = json.dumps(snapshot, ensure_ascii=False, indent=2).encode()
                self.send_response(200)
            else:
                body = b'{"error":"not found"}'
                self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(bind, Handler)
    thread = threading.Thread(target=server.serve_forever, name="health-http", daemon=True)
    thread.start()
    return server
