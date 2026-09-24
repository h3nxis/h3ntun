from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass


MAGIC = b"HYAL"
VERSION = 2
DATA_UP = 1
DATA_DOWN = 2
PING = 3
PONG = 4

_PREFIX = struct.Struct("!4sBB16sQQQH")
_HEADER = struct.Struct("!4sBB16sQQQH16s")
MAX_PAYLOAD = 60_000


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Frame:
    kind: int
    tunnel_id: bytes
    session_id: int
    sequence: int
    timestamp_ms: int
    payload: bytes


class FrameCodec:
    def __init__(
        self,
        tunnel_id: bytes,
        secret: bytes,
        max_clock_skew_seconds: int = 600,
        session_id: int | None = None,
    ):
        if len(tunnel_id) != 16:
            raise ValueError("tunnel_id must be exactly 16 bytes")
        if len(secret) < 32:
            raise ValueError("shared secret must be at least 32 bytes")
        self.tunnel_id = tunnel_id
        self.secret = secret
        self.session_id = (
            int.from_bytes(secrets.token_bytes(8), "big")
            if session_id is None
            else session_id
        )
        if not 0 <= self.session_id <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("session_id must fit in 64 bits")
        self.max_clock_skew_ms = max_clock_skew_seconds * 1000

    def encode(self, kind: int, sequence: int, payload: bytes = b"", timestamp_ms: int | None = None) -> bytes:
        if kind not in {DATA_UP, DATA_DOWN, PING, PONG}:
            raise ProtocolError("unknown frame kind")
        if len(payload) > MAX_PAYLOAD:
            raise ProtocolError(f"payload exceeds {MAX_PAYLOAD} bytes")
        if timestamp_ms is None:
            timestamp_ms = int(time.time() * 1000)
        prefix = _PREFIX.pack(
            MAGIC,
            VERSION,
            kind,
            self.tunnel_id,
            self.session_id,
            sequence,
            timestamp_ms,
            len(payload),
        )
        tag = hmac.new(self.secret, prefix + payload, hashlib.sha256).digest()[:16]
        return _HEADER.pack(
            MAGIC,
            VERSION,
            kind,
            self.tunnel_id,
            self.session_id,
            sequence,
            timestamp_ms,
            len(payload),
            tag,
        ) + payload

    def decode(self, packet: bytes, now_ms: int | None = None) -> Frame:
        if len(packet) < _HEADER.size:
            raise ProtocolError("packet is shorter than the frame header")
        (
            magic,
            version,
            kind,
            tunnel_id,
            session_id,
            sequence,
            timestamp_ms,
            payload_len,
            tag,
        ) = _HEADER.unpack_from(packet)
        if magic != MAGIC or version != VERSION:
            raise ProtocolError("bad magic or protocol version")
        if tunnel_id != self.tunnel_id:
            raise ProtocolError("unexpected tunnel id")
        if kind not in {DATA_UP, DATA_DOWN, PING, PONG}:
            raise ProtocolError("unknown frame kind")
        payload = packet[_HEADER.size:]
        if payload_len != len(payload) or payload_len > MAX_PAYLOAD:
            raise ProtocolError("invalid payload length")
        prefix = _PREFIX.pack(
            magic,
            version,
            kind,
            tunnel_id,
            session_id,
            sequence,
            timestamp_ms,
            payload_len,
        )
        expected = hmac.new(self.secret, prefix + payload, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected):
            raise ProtocolError("authentication failed")
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        if abs(now_ms - timestamp_ms) > self.max_clock_skew_ms:
            raise ProtocolError("frame timestamp is outside the accepted window")
        return Frame(kind, tunnel_id, session_id, sequence, timestamp_ms, payload)


class ReplayWindow:
    """A compact monotonic replay window for one packet direction."""

    def __init__(self, size: int = 2048):
        if size < 64:
            raise ValueError("replay window must be at least 64")
        self.size = size
        self.session_id: int | None = None
        self.retired_sessions: set[int] = set()
        self.highest = -1
        self.bitmap = 0

    def _select_session(self, session_id: int) -> bool:
        if self.session_id is None:
            self.session_id = session_id
            return True
        if session_id == self.session_id:
            return True
        if session_id in self.retired_sessions:
            return False
        self.retired_sessions.add(self.session_id)
        self.session_id = session_id
        self.highest = -1
        self.bitmap = 0
        return True

    def accept(self, sequence: int, session_id: int = 0) -> bool:
        if sequence < 0:
            return False
        if not self._select_session(session_id):
            return False
        if self.highest < 0:
            self.highest = sequence
            self.bitmap = 1
            return True
        if sequence > self.highest:
            shift = sequence - self.highest
            self.bitmap = 1 if shift >= self.size else ((self.bitmap << shift) | 1) & ((1 << self.size) - 1)
            self.highest = sequence
            return True
        distance = self.highest - sequence
        if distance >= self.size:
            return False
        mask = 1 << distance
        if self.bitmap & mask:
            return False
        self.bitmap |= mask
        return True
