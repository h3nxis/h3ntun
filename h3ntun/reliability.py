from __future__ import annotations

import collections
import math
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from .protocol import (
    FLAG_PARITY,
    MAX_FRAGMENT_PAYLOAD,
    MAX_FRAGMENTS,
    MAX_MESSAGE_SIZE,
    Frame,
    ProtocolError,
)


@dataclass(frozen=True)
class FragmentSpec:
    payload: bytes
    message_len: int
    fragment_index: int
    fragment_count: int
    flags: int = 0


def fragment_message(payload: bytes, fragment_payload_bytes: int, fec_enabled: bool) -> list[FragmentSpec]:
    if not 256 <= fragment_payload_bytes <= MAX_FRAGMENT_PAYLOAD:
        raise ProtocolError(
            f"fragment payload must be between 256 and {MAX_FRAGMENT_PAYLOAD} bytes"
        )
    if len(payload) > MAX_MESSAGE_SIZE:
        raise ProtocolError(f"message exceeds {MAX_MESSAGE_SIZE} bytes")
    count = max(1, math.ceil(len(payload) / fragment_payload_bytes))
    if count > MAX_FRAGMENTS:
        raise ProtocolError("message requires too many fragments")
    pieces = [
        payload[index * fragment_payload_bytes:(index + 1) * fragment_payload_bytes]
        for index in range(count)
    ]
    result = [
        FragmentSpec(piece, len(payload), index, count)
        for index, piece in enumerate(pieces)
    ]
    if fec_enabled and count > 1:
        parity = bytearray(fragment_payload_bytes)
        for piece in pieces:
            for offset, value in enumerate(piece):
                parity[offset] ^= value
        result.append(
            FragmentSpec(bytes(parity), len(payload), count, count, FLAG_PARITY)
        )
    return result


@dataclass(frozen=True)
class ReassemblyResult:
    payload: bytes | None
    duplicate: bool = False
    recovered_by_fec: bool = False


@dataclass
class _Assembly:
    message_len: int
    fragment_count: int
    created_at: float
    updated_at: float
    fragments: dict[int, bytes] = field(default_factory=dict)
    parity: bytes | None = None


class Reassembler:
    def __init__(
        self,
        timeout_seconds: float = 30.0,
        max_messages: int = 1024,
        completed_ttl_seconds: float = 120.0,
    ):
        if timeout_seconds <= 0 or max_messages < 1 or completed_ttl_seconds <= 0:
            raise ValueError("invalid reassembly limits")
        self.timeout_seconds = timeout_seconds
        self.max_messages = max_messages
        self.completed_ttl_seconds = completed_ttl_seconds
        self._assemblies: dict[tuple[int, int], _Assembly] = {}
        self._completed: collections.OrderedDict[tuple[int, int], float] = collections.OrderedDict()
        self._lock = threading.Lock()

    def _purge(self, now: float) -> int:
        expired = [
            key for key, assembly in self._assemblies.items()
            if now - assembly.updated_at > self.timeout_seconds
        ]
        for key in expired:
            del self._assemblies[key]
        while self._completed:
            key, completed_at = next(iter(self._completed.items()))
            if now - completed_at <= self.completed_ttl_seconds:
                break
            self._completed.pop(key)
        return len(expired)

    def cleanup(self) -> int:
        with self._lock:
            return self._purge(time.monotonic())

    def is_completed(self, session_id: int, message_id: int) -> bool:
        key = (session_id, message_id)
        with self._lock:
            self._purge(time.monotonic())
            return key in self._completed

    @staticmethod
    def _assemble(assembly: _Assembly) -> tuple[bytes | None, bool]:
        if len(assembly.fragments) == assembly.fragment_count:
            payload = b"".join(assembly.fragments[index] for index in range(assembly.fragment_count))
            if len(payload) != assembly.message_len:
                raise ProtocolError("reassembled message length mismatch")
            return payload, False
        if assembly.parity is None or len(assembly.fragments) != assembly.fragment_count - 1:
            return None, False
        missing = next(
            index for index in range(assembly.fragment_count)
            if index not in assembly.fragments
        )
        fragment_size = len(assembly.parity)
        if fragment_size == 0:
            raise ProtocolError("empty parity fragment")
        recovered = bytearray(assembly.parity)
        for piece in assembly.fragments.values():
            if len(piece) > fragment_size:
                raise ProtocolError("fragment exceeds parity size")
            for offset, value in enumerate(piece):
                recovered[offset] ^= value
        expected_length = (
            fragment_size
            if missing < assembly.fragment_count - 1
            else assembly.message_len - fragment_size * (assembly.fragment_count - 1)
        )
        if not 0 <= expected_length <= fragment_size:
            raise ProtocolError("invalid recovered fragment length")
        assembly.fragments[missing] = bytes(recovered[:expected_length])
        payload = b"".join(assembly.fragments[index] for index in range(assembly.fragment_count))
        if len(payload) != assembly.message_len:
            raise ProtocolError("FEC-recovered message length mismatch")
        return payload, True

    def add(self, frame: Frame) -> ReassemblyResult:
        key = (frame.session_id, frame.message_id)
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            if key in self._completed:
                self._completed.move_to_end(key)
                return ReassemblyResult(None, duplicate=True)
            assembly = self._assemblies.get(key)
            if assembly is None:
                if len(self._assemblies) >= self.max_messages:
                    oldest = min(self._assemblies, key=lambda item: self._assemblies[item].updated_at)
                    del self._assemblies[oldest]
                assembly = _Assembly(
                    message_len=frame.message_len,
                    fragment_count=frame.fragment_count,
                    created_at=now,
                    updated_at=now,
                )
                self._assemblies[key] = assembly
            elif (
                assembly.message_len != frame.message_len
                or assembly.fragment_count != frame.fragment_count
            ):
                raise ProtocolError("inconsistent fragment metadata")
            assembly.updated_at = now
            if frame.is_parity:
                if assembly.parity is not None and assembly.parity != frame.payload:
                    raise ProtocolError("conflicting parity fragment")
                assembly.parity = frame.payload
            else:
                existing = assembly.fragments.get(frame.fragment_index)
                if existing is not None and existing != frame.payload:
                    raise ProtocolError("conflicting data fragment")
                assembly.fragments[frame.fragment_index] = frame.payload
            payload, recovered = self._assemble(assembly)
            if payload is None:
                return ReassemblyResult(None)
            del self._assemblies[key]
            self._completed[key] = now
            self._completed.move_to_end(key)
            while len(self._completed) > self.max_messages * 2:
                self._completed.popitem(last=False)
            return ReassemblyResult(payload, recovered_by_fec=recovered)


@dataclass
class _Transmission:
    message_id: int
    packets: tuple[bytes, ...]
    queued_at: float
    first_sent_at: float | None = None
    last_sent_at: float | None = None
    attempts: int = 0


@dataclass(frozen=True)
class OutboundPacket:
    payload: bytes
    retransmission: bool


@dataclass(frozen=True)
class PumpResult:
    packets: tuple[OutboundPacket, ...]
    exhausted_messages: int


class ReliableSender:
    """Bounded message sender with ACK, retransmission, and AIMD windowing."""

    def __init__(
        self,
        retransmit_timeout_seconds: float = 0.5,
        max_retries: int = 8,
        max_pending_messages: int = 2048,
        initial_window: int = 64,
        max_window: int = 512,
    ):
        if retransmit_timeout_seconds <= 0:
            raise ValueError("retransmit timeout must be positive")
        if max_retries < 0 or max_pending_messages < 1:
            raise ValueError("invalid reliability limits")
        if not 1 <= initial_window <= max_window:
            raise ValueError("invalid congestion window")
        self.retransmit_timeout_seconds = retransmit_timeout_seconds
        self.max_attempts = max_retries + 1
        self.max_pending_messages = max_pending_messages
        self.max_window = float(max_window)
        self.cwnd = float(initial_window)
        self._queue: collections.deque[_Transmission] = collections.deque()
        self._pending: dict[int, _Transmission] = {}
        self._lock = threading.Lock()

    def enqueue(self, message_id: int, packets: list[bytes]) -> bool:
        if not packets:
            raise ValueError("at least one packet is required")
        with self._lock:
            if len(self._queue) + len(self._pending) >= self.max_pending_messages:
                return False
            if message_id in self._pending or any(item.message_id == message_id for item in self._queue):
                raise ValueError("duplicate outbound message id")
            self._queue.append(
                _Transmission(message_id, tuple(packets), time.monotonic())
            )
            return True

    def acknowledge(self, message_id: int) -> tuple[bool, float | None]:
        with self._lock:
            transmission = self._pending.pop(message_id, None)
            if transmission is None:
                return False, None
            self.cwnd = min(self.max_window, self.cwnd + 1.0 / max(1.0, self.cwnd))
            latency = None
            if transmission.first_sent_at is not None:
                latency = time.monotonic() - transmission.first_sent_at
            return True, latency

    def pump(self, now: float | None = None) -> PumpResult:
        if now is None:
            now = time.monotonic()
        packets: list[OutboundPacket] = []
        exhausted = 0
        with self._lock:
            for message_id, transmission in list(self._pending.items()):
                if transmission.last_sent_at is None:
                    continue
                timeout = self.retransmit_timeout_seconds * min(
                    2 ** max(0, transmission.attempts - 1),
                    16,
                )
                if now - transmission.last_sent_at < timeout:
                    continue
                if transmission.attempts >= self.max_attempts:
                    del self._pending[message_id]
                    exhausted += 1
                    self.cwnd = max(1.0, self.cwnd / 2.0)
                    continue
                transmission.attempts += 1
                transmission.last_sent_at = now
                self.cwnd = max(1.0, self.cwnd / 2.0)
                packets.extend(OutboundPacket(packet, True) for packet in transmission.packets)

            window = max(1, int(self.cwnd))
            while self._queue and len(self._pending) < window:
                transmission = self._queue.popleft()
                transmission.attempts = 1
                transmission.first_sent_at = now
                transmission.last_sent_at = now
                self._pending[transmission.message_id] = transmission
                packets.extend(OutboundPacket(packet, False) for packet in transmission.packets)
        return PumpResult(tuple(packets), exhausted)

    def snapshot(self) -> dict[str, float | int]:
        with self._lock:
            return {
                "queued_messages": len(self._queue),
                "inflight_messages": len(self._pending),
                "congestion_window": round(self.cwnd, 3),
            }


def send_pump_result(
    result: PumpResult,
    send_packet: Callable[[bytes], None],
) -> tuple[int, int]:
    sent = 0
    retransmitted = 0
    for item in result.packets:
        send_packet(item.payload)
        sent += 1
        if item.retransmission:
            retransmitted += 1
    return sent, retransmitted
