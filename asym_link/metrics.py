from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any


class Metrics:
    def __init__(self, role: str, metrics_file: str):
        now = time.time()
        self._lock = threading.Lock()
        self.metrics_file = metrics_file
        self.data: dict[str, Any] = {
            "role": role,
            "started_at": now,
            "updated_at": now,
            "uplink_tx_packets": 0,
            "uplink_tx_bytes": 0,
            "uplink_rx_packets": 0,
            "uplink_rx_bytes": 0,
            "downlink_tx_packets": 0,
            "downlink_tx_bytes": 0,
            "downlink_rx_packets": 0,
            "downlink_rx_bytes": 0,
            "inner_tx_packets": 0,
            "inner_tx_bytes": 0,
            "inner_rx_packets": 0,
            "inner_rx_bytes": 0,
            "auth_failures": 0,
            "replay_drops": 0,
            "source_mismatch_drops": 0,
            "inner_source_mismatch_drops": 0,
            "oversize_drops": 0,
            "last_uplink_peer": None,
            "last_downlink_source": None,
            "last_uplink_at": None,
            "last_downlink_at": None,
            "last_inner_at": None,
            "last_pong_at": None,
            "last_rtt_ms": None,
            "last_error": None,
        }

    def add(self, prefix: str, byte_count: int) -> None:
        with self._lock:
            self.data[f"{prefix}_packets"] += 1
            self.data[f"{prefix}_bytes"] += byte_count
            self.data["updated_at"] = time.time()

    def increment(self, key: str) -> None:
        with self._lock:
            self.data[key] += 1
            self.data["updated_at"] = time.time()

    def set(self, **values: Any) -> None:
        with self._lock:
            self.data.update(values)
            self.data["updated_at"] = time.time()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return dict(self.data)

    def persist(self) -> None:
        path = Path(self.metrics_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temp.write_text(json.dumps(self.snapshot(), ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temp, path)
