from __future__ import annotations

import logging
import secrets
import socket
import threading
import time
from dataclasses import dataclass

from .config import ForeignConfig, IranConfig
from .health import start_health_server
from .metrics import Metrics
from .protocol import DATA_DOWN, DATA_UP, PING, PONG, FrameCodec, ProtocolError, ReplayWindow
from .raw_udp import NormalUDPSender


LOG = logging.getLogger("hy-asym-link")


def _configure_udp_socket(sock: socket.socket, recv_buffer: int) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, recv_buffer)
    sock.settimeout(1.0)


@dataclass
class Runtime:
    stop: threading.Event
    threads: list[threading.Thread]
    sockets: list[socket.socket]


class BaseAgent:
    def __init__(self, config: IranConfig | ForeignConfig):
        self.config = config
        self.codec = FrameCodec(config.tunnel_id, config.shared_secret)
        self.metrics = Metrics(config.role, config.metrics_file)
        self.runtime = Runtime(threading.Event(), [], [])
        self.health_server = None
        # A randomized start avoids sequence reuse across ordinary process restarts.
        self._sequence = secrets.randbits(63)
        self._sequence_lock = threading.Lock()

    def next_sequence(self) -> int:
        with self._sequence_lock:
            self._sequence += 1
            return self._sequence

    def spawn(self, target, name: str) -> None:
        thread = threading.Thread(target=target, name=name, daemon=True)
        self.runtime.threads.append(thread)
        thread.start()

    def persist_loop(self) -> None:
        while not self.runtime.stop.wait(2.0):
            try:
                self.metrics.persist()
            except Exception as exc:  # pragma: no cover - filesystem dependent
                self.metrics.set(last_error=f"metrics: {exc}")

    def start_common(self) -> None:
        self.health_server = start_health_server(
            self.config.health_listen,
            self.metrics,
            self.config.health_timeout_seconds,
        )
        self.spawn(self.persist_loop, "metrics-writer")

    def stop(self) -> None:
        self.runtime.stop.set()
        for sock in self.runtime.sockets:
            try:
                sock.close()
            except OSError:
                pass
        if self.health_server:
            self.health_server.shutdown()
            self.health_server.server_close()
        for thread in self.runtime.threads:
            thread.join(timeout=2.0)
        try:
            self.metrics.persist()
        except OSError:
            pass


class IranAgent(BaseAgent):
    def __init__(self, config: IranConfig):
        super().__init__(config)
        self.config = config
        self.inner_peer: tuple[str, int] | None = None
        self.expected_inner_peer = (
            (socket.gethostbyname(config.expected_inner_peer[0]), config.expected_inner_peer[1])
            if config.expected_inner_peer
            else None
        )
        self.inner_lock = threading.Lock()
        self.replay = ReplayWindow()

        self.inner_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.inner_sock.bind(config.inner_listen)
        _configure_udp_socket(self.inner_sock, config.recv_buffer_bytes)

        self.downlink_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.downlink_sock.bind(config.downlink_listen)
        _configure_udp_socket(self.downlink_sock, config.recv_buffer_bytes)

        self.uplink = NormalUDPSender(config.uplink_bind)
        self.runtime.sockets.extend([self.inner_sock, self.downlink_sock, self.uplink.socket])

    def start(self) -> None:
        self.start_common()
        self.spawn(self.inner_loop, "iran-inner")
        self.spawn(self.downlink_loop, "iran-downlink")
        self.spawn(self.keepalive_loop, "iran-keepalive")

    def inner_loop(self) -> None:
        while not self.runtime.stop.is_set():
            try:
                payload, peer = self.inner_sock.recvfrom(65_535)
            except socket.timeout:
                continue
            except OSError:
                break
            if self.expected_inner_peer and peer != self.expected_inner_peer:
                self.metrics.increment("inner_source_mismatch_drops")
                continue
            with self.inner_lock:
                self.inner_peer = peer
            try:
                packet = self.codec.encode(DATA_UP, self.next_sequence(), payload)
            except ProtocolError:
                self.metrics.increment("oversize_drops")
                continue
            try:
                self.uplink.sendto(packet, self.config.foreign_uplink)
                now = time.time()
                self.metrics.add("inner_rx", len(payload))
                self.metrics.add("uplink_tx", len(packet))
                self.metrics.set(last_inner_at=now, last_uplink_at=now)
            except OSError as exc:
                self.metrics.set(last_error=f"uplink send: {exc}")

    def downlink_loop(self) -> None:
        while not self.runtime.stop.is_set():
            try:
                packet, peer = self.downlink_sock.recvfrom(65_535)
            except socket.timeout:
                continue
            except OSError:
                break
            expected = self.config.expected_downlink_source
            if expected and peer[0] != expected:
                self.metrics.increment("source_mismatch_drops")
                continue
            try:
                frame = self.codec.decode(packet)
            except ProtocolError:
                self.metrics.increment("auth_failures")
                continue
            if not self.replay.accept(frame.sequence, frame.session_id):
                self.metrics.increment("replay_drops")
                continue
            now = time.time()
            self.metrics.add("downlink_rx", len(packet))
            self.metrics.set(last_downlink_source=peer[0], last_downlink_at=now)
            if frame.kind == PONG:
                self.metrics.set(last_pong_at=now, last_rtt_ms=max(0, int(now * 1000) - frame.timestamp_ms))
                continue
            if frame.kind != DATA_DOWN:
                continue
            with self.inner_lock:
                inner_peer = self.inner_peer
            if inner_peer is None:
                continue
            try:
                self.inner_sock.sendto(frame.payload, inner_peer)
                self.metrics.add("inner_tx", len(frame.payload))
            except OSError as exc:
                self.metrics.set(last_error=f"inner send: {exc}")

    def keepalive_loop(self) -> None:
        while not self.runtime.stop.wait(self.config.keepalive_seconds):
            packet = self.codec.encode(PING, self.next_sequence())
            try:
                self.uplink.sendto(packet, self.config.foreign_uplink)
                self.metrics.add("uplink_tx", len(packet))
                self.metrics.set(last_uplink_at=time.time())
            except OSError as exc:
                self.metrics.set(last_error=f"keepalive: {exc}")


class ForeignAgent(BaseAgent):
    def __init__(self, config: ForeignConfig):
        super().__init__(config)
        self.config = config
        self.replay = ReplayWindow()

        self.uplink_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.uplink_sock.bind(config.uplink_listen)
        _configure_udp_socket(self.uplink_sock, config.recv_buffer_bytes)

        self.inner_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.inner_sock.bind(config.inner_bridge_listen)
        _configure_udp_socket(self.inner_sock, config.recv_buffer_bytes)
        self.inner_peer_address = (
            socket.gethostbyname(config.inner_peer[0]),
            config.inner_peer[1],
        )

        # A configured source address must be assigned to this host.  The normal
        # UDP bind is deliberately kernel-enforced; this runtime never forges it.
        source_address = config.downlink_source or "0.0.0.0"
        self.downlink = NormalUDPSender((source_address, config.downlink_source_port))
        self.runtime.sockets.extend([self.uplink_sock, self.inner_sock, self.downlink.socket])

    def start(self) -> None:
        self.start_common()
        self.spawn(self.uplink_loop, "foreign-uplink")
        self.spawn(self.inner_loop, "foreign-inner")

    def send_downlink(self, kind: int, payload: bytes = b"", timestamp_ms: int | None = None) -> None:
        packet = self.codec.encode(kind, self.next_sequence(), payload, timestamp_ms=timestamp_ms)
        self.downlink.sendto(packet, self.config.iran_downlink)
        self.metrics.add("downlink_tx", len(packet))
        self.metrics.set(last_downlink_at=time.time())

    def uplink_loop(self) -> None:
        while not self.runtime.stop.is_set():
            try:
                packet, peer = self.uplink_sock.recvfrom(65_535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                frame = self.codec.decode(packet)
            except ProtocolError:
                self.metrics.increment("auth_failures")
                continue
            if not self.replay.accept(frame.sequence, frame.session_id):
                self.metrics.increment("replay_drops")
                continue
            now = time.time()
            self.metrics.add("uplink_rx", len(packet))
            self.metrics.set(last_uplink_peer=f"{peer[0]}:{peer[1]}", last_uplink_at=now)
            if frame.kind == PING:
                try:
                    self.send_downlink(PONG, timestamp_ms=frame.timestamp_ms)
                except (OSError, ProtocolError) as exc:
                    self.metrics.set(last_error=f"pong send: {exc}")
                continue
            if frame.kind != DATA_UP:
                continue
            try:
                self.inner_sock.sendto(frame.payload, self.inner_peer_address)
                self.metrics.add("inner_tx", len(frame.payload))
                self.metrics.set(last_inner_at=now)
            except OSError as exc:
                self.metrics.set(last_error=f"inner send: {exc}")

    def inner_loop(self) -> None:
        while not self.runtime.stop.is_set():
            try:
                payload, peer = self.inner_sock.recvfrom(65_535)
            except socket.timeout:
                continue
            except OSError:
                break
            if peer != self.inner_peer_address:
                self.metrics.increment("inner_source_mismatch_drops")
                continue
            self.metrics.add("inner_rx", len(payload))
            self.metrics.set(last_inner_at=time.time())
            try:
                self.send_downlink(DATA_DOWN, payload)
            except ProtocolError:
                self.metrics.increment("oversize_drops")
            except OSError as exc:
                self.metrics.set(last_error=f"downlink send: {exc}")
