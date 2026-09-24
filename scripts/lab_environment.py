#!/usr/bin/env python3
"""Deterministic loopback lab for the asymmetric UDP transport.

The lab creates two independent one-way UDP relays. It can inject latency,
jitter, deterministic loss, duplication, temporary outages, and reordering.
It never opens a raw socket and never sends outside loopback.
"""

from __future__ import annotations

import argparse
import heapq
import json
import socket
import struct
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from asym_link.agent import ForeignAgent, IranAgent
from asym_link.config import ForeignConfig, IranConfig


def free_udp_port(host: str = "127.0.0.1") -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@dataclass(frozen=True)
class LinkProfile:
    delay_ms: float = 0.0
    jitter_ms: float = 0.0
    drop_every: int = 0
    duplicate_every: int = 0
    reorder_every: int = 0

    def validate(self) -> None:
        if self.delay_ms < 0 or self.jitter_ms < 0:
            raise ValueError("delay and jitter cannot be negative")
        for name in ("drop_every", "duplicate_every", "reorder_every"):
            value = getattr(self, name)
            if value < 0 or value == 1:
                raise ValueError(f"{name} must be zero or at least two")


class UdpLinkEmulator:
    def __init__(
        self,
        name: str,
        bind: tuple[str, int],
        destination: tuple[str, int],
        profile: LinkProfile,
    ):
        profile.validate()
        self.name = name
        self.destination = destination
        self.profile = profile
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(bind)
        self.socket.settimeout(0.2)
        self.stop_event = threading.Event()
        self.enabled = threading.Event()
        self.enabled.set()
        self.condition = threading.Condition()
        self.queue: list[tuple[float, int, bytes]] = []
        self.queue_order = 0
        self.packet_index = 0
        self.stats = {
            "received": 0,
            "forwarded": 0,
            "dropped": 0,
            "duplicated": 0,
            "reordered": 0,
        }
        self.receive_thread = threading.Thread(
            target=self._receive_loop, name=f"{name}-receive", daemon=True
        )
        self.send_thread = threading.Thread(
            target=self._send_loop, name=f"{name}-send", daemon=True
        )

    @property
    def address(self) -> tuple[str, int]:
        return self.socket.getsockname()

    def start(self) -> None:
        self.receive_thread.start()
        self.send_thread.start()

    def set_enabled(self, enabled: bool) -> None:
        if enabled:
            self.enabled.set()
        else:
            self.enabled.clear()

    def _enqueue(self, payload: bytes, due: float) -> None:
        with self.condition:
            self.queue_order += 1
            heapq.heappush(self.queue, (due, self.queue_order, payload))
            self.condition.notify()

    def _receive_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                payload, _peer = self.socket.recvfrom(65_535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.packet_index += 1
            index = self.packet_index
            self.stats["received"] += 1
            if not self.enabled.is_set() or (
                self.profile.drop_every and index % self.profile.drop_every == 0
            ):
                self.stats["dropped"] += 1
                continue

            jitter = 0.0
            if self.profile.jitter_ms:
                jitter = self.profile.jitter_ms if index % 2 else -self.profile.jitter_ms
            delay_ms = max(0.0, self.profile.delay_ms + jitter)
            if self.profile.reorder_every and index % self.profile.reorder_every == 1:
                delay_ms += max(2.0, self.profile.jitter_ms * 2, self.profile.delay_ms)
                self.stats["reordered"] += 1
            due = time.monotonic() + delay_ms / 1000.0
            self._enqueue(payload, due)
            if self.profile.duplicate_every and index % self.profile.duplicate_every == 0:
                self._enqueue(payload, due + 0.001)
                self.stats["duplicated"] += 1

    def _send_loop(self) -> None:
        while not self.stop_event.is_set():
            with self.condition:
                while not self.queue and not self.stop_event.is_set():
                    self.condition.wait(timeout=0.2)
                if self.stop_event.is_set():
                    break
                due, order, payload = self.queue[0]
                wait_seconds = due - time.monotonic()
                if wait_seconds > 0:
                    self.condition.wait(timeout=wait_seconds)
                    continue
                heapq.heappop(self.queue)
            try:
                self.socket.sendto(payload, self.destination)
                self.stats["forwarded"] += 1
            except OSError:
                break

    def stop(self) -> None:
        self.stop_event.set()
        with self.condition:
            self.condition.notify_all()
        self.socket.close()
        if self.receive_thread.ident is not None:
            self.receive_thread.join(timeout=2)
        if self.send_thread.ident is not None:
            self.send_thread.join(timeout=2)


class ExpandingBackend:
    def __init__(self, bind: tuple[str, int], response_size: int = 1024):
        self.response_size = response_size
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        self.socket.bind(bind)
        self.socket.settimeout(0.2)
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._loop, name="lab-backend", daemon=True)
        self.requests = 0

    @property
    def address(self) -> tuple[str, int]:
        return self.socket.getsockname()

    def start(self) -> None:
        self.thread.start()

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                payload, peer = self.socket.recvfrom(65_535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.requests += 1
            response = payload[:8] + b"R" * max(0, self.response_size - 8)
            try:
                self.socket.sendto(response, peer)
            except OSError:
                break

    def stop(self) -> None:
        self.stop_event.set()
        self.socket.close()
        if self.thread.ident is not None:
            self.thread.join(timeout=2)


class AsymmetricLab:
    def __init__(
        self,
        uplink_profile: LinkProfile | None = None,
        downlink_profile: LinkProfile | None = None,
        response_size: int = 1024,
    ):
        self.folder = tempfile.TemporaryDirectory()
        root = Path(self.folder.name)
        self.backend = ExpandingBackend(("127.0.0.1", free_udp_port()), response_size)

        uplink_agent_port = free_udp_port()
        downlink_agent_port = free_udp_port()
        inner_port = free_udp_port()
        bridge_port = free_udp_port()
        uplink_relay_port = free_udp_port()
        downlink_relay_port = free_udp_port("127.0.0.2")
        tunnel_id = bytes.fromhex("91" * 16)
        secret = b"lab-secret".ljust(32, b"!")

        self.uplink = UdpLinkEmulator(
            "uplink",
            ("127.0.0.1", uplink_relay_port),
            ("127.0.0.1", uplink_agent_port),
            uplink_profile or LinkProfile(),
        )
        self.downlink = UdpLinkEmulator(
            "downlink",
            ("127.0.0.2", downlink_relay_port),
            ("127.0.0.1", downlink_agent_port),
            downlink_profile or LinkProfile(),
        )

        self.iran = IranAgent(IranConfig(
            role="iran", tunnel_id=tunnel_id, shared_secret=secret,
            health_listen=("127.0.0.1", 0),
            metrics_file=str(root / "iran-metrics.json"),
            keepalive_seconds=60, health_timeout_seconds=120,
            recv_buffer_bytes=4 * 1024 * 1024,
            inner_listen=("127.0.0.1", inner_port),
            uplink_bind=("127.0.0.1", 0),
            foreign_uplink=self.uplink.address,
            downlink_listen=("127.0.0.1", downlink_agent_port),
            expected_downlink_source="127.0.0.2",
        ))
        self.foreign = ForeignAgent(ForeignConfig(
            role="foreign", tunnel_id=tunnel_id, shared_secret=secret,
            health_listen=("127.0.0.1", 0),
            metrics_file=str(root / "foreign-metrics.json"),
            keepalive_seconds=60, health_timeout_seconds=120,
            recv_buffer_bytes=4 * 1024 * 1024,
            uplink_listen=("127.0.0.1", uplink_agent_port),
            inner_bridge_listen=("127.0.0.1", bridge_port),
            inner_peer=self.backend.address,
            iran_downlink=self.downlink.address,
            downlink_mode="udp", downlink_source="127.0.0.1",
            downlink_source_port=0,
        ))
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        self.client.bind(("127.0.0.1", 0))
        self.next_request_id = 0
        self.started = False

    def start(self) -> None:
        self.backend.start()
        self.uplink.start()
        self.downlink.start()
        self.foreign.start()
        self.iran.start()
        self.started = True

    def run_burst(
        self,
        count: int,
        request_size: int = 64,
        timeout_seconds: float = 3.0,
    ) -> dict:
        if not self.started:
            raise RuntimeError("lab is not started")
        if request_size < 8:
            raise ValueError("request_size must be at least 8 bytes")
        sent_at: dict[int, float] = {}
        received: set[int] = set()
        latencies: list[float] = []
        receive_lock = threading.Lock()
        deadline = time.monotonic() + timeout_seconds

        def receive_responses() -> None:
            while time.monotonic() < deadline:
                with receive_lock:
                    if len(received) >= count:
                        return
                self.client.settimeout(max(0.01, min(0.2, deadline - time.monotonic())))
                try:
                    payload, _peer = self.client.recvfrom(65_535)
                except socket.timeout:
                    continue
                if len(payload) < 8:
                    continue
                sequence = struct.unpack("!Q", payload[:8])[0]
                with receive_lock:
                    if sequence in sent_at and sequence not in received:
                        received.add(sequence)
                        latencies.append(
                            (time.perf_counter() - sent_at[sequence]) * 1000
                        )

        receiver = threading.Thread(
            target=receive_responses, name="lab-client-receiver", daemon=True
        )
        receiver.start()
        first_request_id = self.next_request_id
        self.next_request_id += count
        for sequence in range(first_request_id, first_request_id + count):
            payload = struct.pack("!Q", sequence) + b"Q" * (request_size - 8)
            sent_at[sequence] = time.perf_counter()
            self.client.sendto(payload, self.iran.inner_sock.getsockname())
        receiver.join(timeout=max(0.1, deadline - time.monotonic() + 0.2))

        iran_metrics = self.iran.metrics.snapshot()
        foreign_metrics = self.foreign.metrics.snapshot()
        return {
            "sent": count,
            "received": len(received),
            "loss_percent": round((count - len(received)) * 100 / count, 2) if count else 0,
            "latency_ms": {
                "min": round(min(latencies), 2) if latencies else None,
                "avg": round(sum(latencies) / len(latencies), 2) if latencies else None,
                "max": round(max(latencies), 2) if latencies else None,
            },
            "uplink": dict(self.uplink.stats),
            "downlink": dict(self.downlink.stats),
            "backend_requests": self.backend.requests,
            "agent_drops": {
                "iran_auth": iran_metrics["auth_failures"],
                "iran_replay": iran_metrics["replay_drops"],
                "iran_source": iran_metrics["source_mismatch_drops"],
                "foreign_auth": foreign_metrics["auth_failures"],
                "foreign_replay": foreign_metrics["replay_drops"],
                "foreign_inner_source": foreign_metrics["inner_source_mismatch_drops"],
            },
            "framed_byte_ratio": (
                round(
                    iran_metrics["downlink_rx_bytes"]
                    / iran_metrics["uplink_tx_bytes"],
                    3,
                )
                if iran_metrics["uplink_tx_bytes"]
                else 0
            ),
        }

    def stop(self) -> None:
        self.client.close()
        self.iran.stop()
        self.foreign.stop()
        self.uplink.stop()
        self.downlink.stop()
        self.backend.stop()
        self.folder.cleanup()


def run_profile(name: str) -> dict:
    if name == "clean":
        lab = AsymmetricLab(
            LinkProfile(delay_ms=5),
            LinkProfile(delay_ms=10),
        )
        count = 100
    elif name == "impaired":
        lab = AsymmetricLab(
            LinkProfile(delay_ms=15, jitter_ms=5, drop_every=10, reorder_every=7),
            LinkProfile(delay_ms=25, jitter_ms=10, drop_every=20, duplicate_every=13, reorder_every=9),
        )
        count = 200
    elif name == "outage":
        lab = AsymmetricLab(LinkProfile(delay_ms=5), LinkProfile(delay_ms=10))
        lab.start()
        try:
            lab.downlink.set_enabled(False)
            during = lab.run_burst(10, timeout_seconds=0.5)
            lab.downlink.set_enabled(True)
            recovered = lab.run_burst(30, timeout_seconds=3)
            return {"profile": name, "during_outage": during, "after_recovery": recovered}
        finally:
            lab.stop()
    elif name == "stress":
        lab = AsymmetricLab(response_size=1200)
        count = 1000
    elif name == "boundary":
        lab = AsymmetricLab(response_size=60_000)
        lab.start()
        try:
            maximum = lab.run_burst(5, request_size=60_000, timeout_seconds=5)
            oversize = lab.run_burst(1, request_size=60_001, timeout_seconds=0.5)
            return {
                "profile": name,
                "maximum_payload": maximum,
                "oversize_payload": oversize,
                "oversize_drops": lab.iran.metrics.snapshot()["oversize_drops"],
            }
        finally:
            lab.stop()
    else:
        raise ValueError(f"unknown profile: {name}")

    lab.start()
    try:
        result = lab.run_burst(count, timeout_seconds=5)
        return {"profile": name, "link_profiles": {
            "uplink": asdict(lab.uplink.profile),
            "downlink": asdict(lab.downlink.profile),
        }, "result": result}
    finally:
        lab.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description="Loopback asymmetric-link fault lab")
    parser.add_argument(
        "--profile",
        choices=["clean", "impaired", "outage", "stress", "boundary", "all"],
        default="all",
    )
    parser.add_argument("--output", help="optional JSON report path")
    args = parser.parse_args()
    names = (
        ["clean", "impaired", "outage", "stress", "boundary"]
        if args.profile == "all"
        else [args.profile]
    )
    report = {"generated_at": time.time(), "scope": "loopback-only", "scenarios": []}
    for name in names:
        report["scenarios"].append(run_profile(name))
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    print(rendered)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
