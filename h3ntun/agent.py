from __future__ import annotations

import logging
import secrets
import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable

from .config import ForeignConfig, IranConfig
from .health import start_health_server
from .metrics import Metrics
from .protocol import (
    ACK_DOWN,
    ACK_UP,
    DATA_DOWN,
    DATA_UP,
    PING,
    PONG,
    Frame,
    FrameCodec,
    PersistentReplayWindow,
    ProtocolError,
    ReplayWindow,
)
from .reliability import Reassembler, ReliableSender, fragment_message
from .raw_udp import NormalUDPSender


LOG = logging.getLogger("h3ntun")


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
        self._sequence = secrets.randbits(63)
        self._message_id = secrets.randbits(63)
        self._counter_lock = threading.Lock()
        replay_path = getattr(config, "replay_state_file", None)
        self.replay: ReplayWindow = (
            PersistentReplayWindow(
                replay_path,
                config.tunnel_id,
                interval_seconds=config.replay_checkpoint_interval_seconds,
                batch_frames=config.replay_checkpoint_batch_frames,
                on_checkpoint=lambda stats: self.metrics.set(**stats),
            )
            if replay_path
            else ReplayWindow()
        )
        self.reassembler = Reassembler(
            timeout_seconds=config.reassembly_timeout_seconds,
            max_messages=config.max_pending_messages,
        )
        self.sender = ReliableSender(
            retransmit_timeout_seconds=config.retransmit_timeout_seconds,
            max_retries=config.max_retries,
            max_pending_messages=config.max_pending_messages,
        )

    def next_sequence(self) -> int:
        with self._counter_lock:
            self._sequence += 1
            return self._sequence

    def next_message_id(self) -> int:
        with self._counter_lock:
            self._message_id += 1
            return self._message_id

    def spawn(self, target: Callable[[], None], name: str) -> None:
        thread = threading.Thread(target=target, name=name, daemon=True)
        self.runtime.threads.append(thread)
        thread.start()

    def persist_loop(self) -> None:
        while not self.runtime.stop.wait(2.0):
            try:
                if isinstance(self.replay, PersistentReplayWindow):
                    self.metrics.set(**self.replay.stats())
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
        self.spawn(self.reliability_loop, "reliability")

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
        if isinstance(self.replay, PersistentReplayWindow):
            if not self.replay.close():
                self.metrics.set(last_error="replay checkpoint did not finish during shutdown")
            self.metrics.set(**self.replay.stats())
        try:
            self.metrics.persist()
        except OSError:
            pass

    def _transport_send(self, packet: bytes, retransmission: bool = False) -> None:
        raise NotImplementedError

    def reliability_loop(self) -> None:
        interval = min(0.05, self.config.retransmit_timeout_seconds / 4)
        while not self.runtime.stop.wait(interval):
            if not self.config.reliable:
                continue
            result = self.sender.pump()
            for item in result.packets:
                try:
                    self._transport_send(item.payload, item.retransmission)
                except OSError as exc:
                    self.metrics.set(last_error=f"reliable send: {exc}")
            if result.exhausted_messages:
                self.metrics.increment("retry_exhausted", result.exhausted_messages)
            expired = self.reassembler.cleanup()
            if expired:
                self.metrics.increment("reassembly_timeouts", expired)
            self.metrics.set(**self.sender.snapshot())

    def build_data_packets(self, kind: int, payload: bytes) -> tuple[int, list[bytes]]:
        message_id = self.next_message_id()
        fragments = fragment_message(
            payload,
            self.config.fragment_payload_bytes,
            self.config.fec_enabled,
        )
        packets = [
            self.codec.encode(
                kind,
                self.next_sequence(),
                fragment.payload,
                message_id=message_id,
                message_len=fragment.message_len,
                fragment_index=fragment.fragment_index,
                fragment_count=fragment.fragment_count,
                flags=fragment.flags,
            )
            for fragment in fragments
        ]
        return message_id, packets

    def send_data(self, kind: int, payload: bytes) -> bool:
        _message_id, packets = self.build_data_packets(kind, payload)
        self.metrics.increment("fragment_messages")
        self.metrics.increment("fragments_created", len(packets))
        if self.config.reliable:
            queued = self.sender.enqueue(_message_id, packets)
            if not queued:
                self.metrics.increment("queue_drops")
            return queued
        for packet in packets:
            self._transport_send(packet)
        return True

    def handle_ack(self, frame: Frame, expected_kind: int) -> bool:
        if frame.kind != expected_kind:
            return False
        acknowledged_session, message_id = self.codec.decode_ack(frame)
        if acknowledged_session != self.codec.session_id:
            self.metrics.increment("stale_ack_drops")
            return True
        accepted, latency = self.sender.acknowledge(message_id)
        if accepted:
            self.metrics.increment("acked_messages")
            if latency is not None:
                self.metrics.set(last_ack_rtt_ms=round(latency * 1000, 3))
        else:
            self.metrics.increment("unknown_ack_drops")
        return True

    def record_received_frame(self, frame: Frame) -> bool:
        accepted = self.replay.accept(frame.sequence, frame.session_id)
        if not accepted:
            self.metrics.increment("replay_drops")
        elif isinstance(self.replay, PersistentReplayWindow):
            self.metrics.set(**self.replay.stats())
        return accepted

    def accept_fragment(self, frame: Frame) -> bytes | None:
        result = self.reassembler.add(frame)
        self.metrics.increment("fragments_received")
        if result.duplicate:
            self.metrics.increment("duplicate_messages")
        if result.recovered_by_fec:
            self.metrics.increment("fec_recoveries")
        return result.payload


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

    def _transport_send(self, packet: bytes, retransmission: bool = False) -> None:
        self.uplink.sendto(packet, self.config.foreign_uplink)
        self.metrics.add("uplink_tx", len(packet))
        self.metrics.increment("encrypted_frames_tx")
        if retransmission:
            self.metrics.increment("retransmitted_frames")
        self.metrics.set(last_uplink_at=time.time())

    def send_uplink_control(self, kind: int, payload: bytes = b"", timestamp_ms: int | None = None) -> None:
        packet = self.codec.encode(kind, self.next_sequence(), payload, timestamp_ms=timestamp_ms)
        self._transport_send(packet)

    def send_ack_down(self, frame: Frame) -> None:
        packet = self.codec.encode_ack(
            ACK_DOWN,
            self.next_sequence(),
            frame.session_id,
            frame.message_id,
        )
        self._transport_send(packet)
        self.metrics.increment("acks_tx")

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
            self.metrics.add("inner_rx", len(payload))
            self.metrics.set(last_inner_at=time.time())
            try:
                self.send_data(DATA_UP, payload)
            except ProtocolError:
                self.metrics.increment("oversize_drops")

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
            if not self.record_received_frame(frame):
                if frame.kind == DATA_DOWN and self.reassembler.is_completed(frame.session_id, frame.message_id):
                    try:
                        self.send_ack_down(frame)
                    except OSError as exc:
                        self.metrics.set(last_error=f"duplicate ack: {exc}")
                continue
            now = time.time()
            self.metrics.add("downlink_rx", len(packet))
            self.metrics.increment("encrypted_frames_rx")
            self.metrics.set(last_downlink_source=peer[0], last_downlink_at=now)
            try:
                if self.handle_ack(frame, ACK_UP):
                    self.metrics.increment("acks_rx")
                    continue
                if frame.kind == PONG:
                    self.metrics.set(
                        last_pong_at=now,
                        last_rtt_ms=max(0, int(now * 1000) - frame.timestamp_ms),
                    )
                    continue
                if frame.kind != DATA_DOWN:
                    continue
                payload = self.accept_fragment(frame)
                if payload is None:
                    continue
                with self.inner_lock:
                    inner_peer = self.inner_peer
                if inner_peer is None:
                    continue
                self.inner_sock.sendto(payload, inner_peer)
                self.metrics.add("inner_tx", len(payload))
                if self.config.reliable:
                    self.send_ack_down(frame)
            except (OSError, ProtocolError) as exc:
                self.metrics.set(last_error=f"downlink handling: {exc}")

    def keepalive_loop(self) -> None:
        while not self.runtime.stop.wait(self.config.keepalive_seconds):
            try:
                self.send_uplink_control(PING)
            except (OSError, ProtocolError) as exc:
                self.metrics.set(last_error=f"keepalive: {exc}")


class ForeignAgent(BaseAgent):
    def __init__(self, config: ForeignConfig):
        super().__init__(config)
        self.config = config

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

        source_address = config.downlink_source or "0.0.0.0"
        self.downlink = NormalUDPSender((source_address, config.downlink_source_port))
        self.runtime.sockets.extend([self.uplink_sock, self.inner_sock, self.downlink.socket])

    def start(self) -> None:
        self.start_common()
        self.spawn(self.uplink_loop, "foreign-uplink")
        self.spawn(self.inner_loop, "foreign-inner")

    def _transport_send(self, packet: bytes, retransmission: bool = False) -> None:
        self.downlink.sendto(packet, self.config.iran_downlink)
        self.metrics.add("downlink_tx", len(packet))
        self.metrics.increment("encrypted_frames_tx")
        if retransmission:
            self.metrics.increment("retransmitted_frames")
        self.metrics.set(last_downlink_at=time.time())

    def send_downlink_control(self, kind: int, payload: bytes = b"", timestamp_ms: int | None = None) -> None:
        packet = self.codec.encode(kind, self.next_sequence(), payload, timestamp_ms=timestamp_ms)
        self._transport_send(packet)

    def send_ack_up(self, frame: Frame) -> None:
        packet = self.codec.encode_ack(
            ACK_UP,
            self.next_sequence(),
            frame.session_id,
            frame.message_id,
        )
        self._transport_send(packet)
        self.metrics.increment("acks_tx")

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
            if not self.record_received_frame(frame):
                if frame.kind == DATA_UP and self.reassembler.is_completed(frame.session_id, frame.message_id):
                    try:
                        self.send_ack_up(frame)
                    except OSError as exc:
                        self.metrics.set(last_error=f"duplicate ack: {exc}")
                continue
            now = time.time()
            self.metrics.add("uplink_rx", len(packet))
            self.metrics.increment("encrypted_frames_rx")
            self.metrics.set(last_uplink_peer=f"{peer[0]}:{peer[1]}", last_uplink_at=now)
            try:
                if self.handle_ack(frame, ACK_DOWN):
                    self.metrics.increment("acks_rx")
                    continue
                if frame.kind == PING:
                    self.send_downlink_control(PONG, timestamp_ms=frame.timestamp_ms)
                    continue
                if frame.kind != DATA_UP:
                    continue
                payload = self.accept_fragment(frame)
                if payload is None:
                    continue
                self.inner_sock.sendto(payload, self.inner_peer_address)
                self.metrics.add("inner_tx", len(payload))
                self.metrics.set(last_inner_at=now)
                if self.config.reliable:
                    self.send_ack_up(frame)
            except (OSError, ProtocolError) as exc:
                self.metrics.set(last_error=f"uplink handling: {exc}")

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
                self.send_data(DATA_DOWN, payload)
            except ProtocolError:
                self.metrics.increment("oversize_drops")
