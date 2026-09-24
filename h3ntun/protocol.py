from __future__ import annotations

import hashlib
import json
import os
import secrets
import struct
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


MAGIC = b"H3TN"
VERSION = 3

DATA_UP = 1
DATA_DOWN = 2
PING = 3
PONG = 4
ACK_UP = 5
ACK_DOWN = 6

FLAG_PARITY = 0x01
VALID_FLAGS = FLAG_PARITY
VALID_KINDS = {DATA_UP, DATA_DOWN, PING, PONG, ACK_UP, ACK_DOWN}

# The default deployed fragment is 1200 bytes. 1391 is the IPv4 hard ceiling so a
# complete frame still remains below a typical Ethernet MTU after UDP/IP.
DEFAULT_FRAGMENT_PAYLOAD = 1200
MAX_FRAGMENT_PAYLOAD = 1391
MAX_MESSAGE_SIZE = 60_000
MAX_FRAGMENTS = 256

# Everything in this prefix is authenticated as AEAD associated data. The
# encrypted payload follows it and already includes the 16-byte Poly1305 tag.
_AAD = struct.Struct("!4sBBB16sQQQQIHHH")
AEAD_TAG_SIZE = 16
FRAME_OVERHEAD = _AAD.size + AEAD_TAG_SIZE
_ACK = struct.Struct("!QQ")


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Frame:
    kind: int
    flags: int
    tunnel_id: bytes
    session_id: int
    sequence: int
    timestamp_ms: int
    message_id: int
    message_len: int
    fragment_index: int
    fragment_count: int
    payload: bytes

    @property
    def is_parity(self) -> bool:
        return bool(self.flags & FLAG_PARITY)


class FrameCodec:
    """Protocol-v3 authenticated encryption codec.

    One codec represents one process session. Its random session id and global
    monotonic sequence counter make every derived 96-bit AEAD nonce unique.
    """

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
        self.session_id = (
            int.from_bytes(secrets.token_bytes(8), "big")
            if session_id is None
            else session_id
        )
        if not 0 <= self.session_id <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("session_id must fit in 64 bits")
        if not max_clock_skew_seconds > 0:
            raise ValueError("max_clock_skew_seconds must be positive")
        self.max_clock_skew_ms = int(max_clock_skew_seconds * 1000)
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=tunnel_id,
            info=b"h3ntun-wire-v3-chacha20poly1305",
        ).derive(secret)
        self._aead = ChaCha20Poly1305(key)

    @staticmethod
    def _nonce(session_id: int, sequence: int, kind: int, flags: int, fragment_index: int) -> bytes:
        if not 0 <= sequence <= 0xFFFFFFFFFFFFFFFF:
            raise ProtocolError("sequence must fit in 64 bits")
        context = struct.pack("!QBBH", session_id, kind, flags, fragment_index)
        prefix = hashlib.blake2s(context, digest_size=4, person=b"h3ntun").digest()
        return prefix + struct.pack("!Q", sequence)

    def encode(
        self,
        kind: int,
        sequence: int,
        payload: bytes = b"",
        timestamp_ms: int | None = None,
        *,
        message_id: int = 0,
        message_len: int | None = None,
        fragment_index: int = 0,
        fragment_count: int = 1,
        flags: int = 0,
    ) -> bytes:
        if kind not in VALID_KINDS:
            raise ProtocolError("unknown frame kind")
        if flags & ~VALID_FLAGS:
            raise ProtocolError("unknown frame flags")
        if len(payload) > MAX_FRAGMENT_PAYLOAD:
            raise ProtocolError(f"fragment exceeds {MAX_FRAGMENT_PAYLOAD} bytes")
        if not 0 <= message_id <= 0xFFFFFFFFFFFFFFFF:
            raise ProtocolError("message_id must fit in 64 bits")
        if message_len is None:
            message_len = len(payload)
        if not 0 <= message_len <= MAX_MESSAGE_SIZE:
            raise ProtocolError(f"message exceeds {MAX_MESSAGE_SIZE} bytes")
        if not 1 <= fragment_count <= MAX_FRAGMENTS:
            raise ProtocolError("invalid fragment count")
        if flags & FLAG_PARITY:
            if fragment_count < 2 or fragment_index != fragment_count:
                raise ProtocolError("invalid parity fragment index")
        elif not 0 <= fragment_index < fragment_count:
            raise ProtocolError("invalid fragment index")
        if kind not in {DATA_UP, DATA_DOWN} and (
            flags or message_id or fragment_index or fragment_count != 1 or message_len != len(payload)
        ):
            raise ProtocolError("control frames cannot be fragmented")
        if timestamp_ms is None:
            timestamp_ms = int(time.time() * 1000)
        aad = _AAD.pack(
            MAGIC,
            VERSION,
            kind,
            flags,
            self.tunnel_id,
            self.session_id,
            sequence,
            timestamp_ms,
            message_id,
            message_len,
            fragment_index,
            fragment_count,
            len(payload),
        )
        nonce = self._nonce(self.session_id, sequence, kind, flags, fragment_index)
        return aad + self._aead.encrypt(nonce, payload, aad)

    def decode(self, packet: bytes, now_ms: int | None = None) -> Frame:
        if len(packet) < FRAME_OVERHEAD:
            raise ProtocolError("packet is shorter than the frame header")
        try:
            (
                magic,
                version,
                kind,
                flags,
                tunnel_id,
                session_id,
                sequence,
                timestamp_ms,
                message_id,
                message_len,
                fragment_index,
                fragment_count,
                payload_len,
            ) = _AAD.unpack_from(packet)
        except struct.error as exc:
            raise ProtocolError("invalid frame header") from exc
        if magic != MAGIC or version != VERSION:
            raise ProtocolError("bad magic or protocol version")
        if tunnel_id != self.tunnel_id:
            raise ProtocolError("unexpected tunnel id")
        if kind not in VALID_KINDS:
            raise ProtocolError("unknown frame kind")
        if flags & ~VALID_FLAGS:
            raise ProtocolError("unknown frame flags")
        if payload_len > MAX_FRAGMENT_PAYLOAD:
            raise ProtocolError("invalid fragment length")
        if len(packet) != _AAD.size + payload_len + AEAD_TAG_SIZE:
            raise ProtocolError("invalid encrypted payload length")
        if message_len > MAX_MESSAGE_SIZE:
            raise ProtocolError("invalid message length")
        if not 1 <= fragment_count <= MAX_FRAGMENTS:
            raise ProtocolError("invalid fragment count")
        if flags & FLAG_PARITY:
            if fragment_count < 2 or fragment_index != fragment_count:
                raise ProtocolError("invalid parity metadata")
        elif fragment_index >= fragment_count:
            raise ProtocolError("invalid fragment metadata")
        if kind not in {DATA_UP, DATA_DOWN} and (
            flags or message_id or fragment_index or fragment_count != 1 or message_len != payload_len
        ):
            raise ProtocolError("invalid control frame metadata")
        aad = packet[:_AAD.size]
        encrypted = packet[_AAD.size:]
        nonce = self._nonce(session_id, sequence, kind, flags, fragment_index)
        try:
            payload = self._aead.decrypt(nonce, encrypted, aad)
        except InvalidTag as exc:
            raise ProtocolError("authentication failed") from exc
        if len(payload) != payload_len:
            raise ProtocolError("decrypted payload length mismatch")
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        if abs(now_ms - timestamp_ms) > self.max_clock_skew_ms:
            raise ProtocolError("frame timestamp is outside the accepted window")
        return Frame(
            kind=kind,
            flags=flags,
            tunnel_id=tunnel_id,
            session_id=session_id,
            sequence=sequence,
            timestamp_ms=timestamp_ms,
            message_id=message_id,
            message_len=message_len,
            fragment_index=fragment_index,
            fragment_count=fragment_count,
            payload=payload,
        )

    def encode_ack(self, kind: int, sequence: int, acknowledged_session: int, message_id: int) -> bytes:
        if kind not in {ACK_UP, ACK_DOWN}:
            raise ProtocolError("invalid acknowledgement kind")
        return self.encode(kind, sequence, _ACK.pack(acknowledged_session, message_id))

    @staticmethod
    def decode_ack(frame: Frame) -> tuple[int, int]:
        if frame.kind not in {ACK_UP, ACK_DOWN} or len(frame.payload) != _ACK.size:
            raise ProtocolError("invalid acknowledgement payload")
        return _ACK.unpack(frame.payload)


class ReplayWindow:
    """A compact session-aware replay window for one packet direction."""

    def __init__(self, size: int = 4096):
        if size < 64:
            raise ValueError("replay window must be at least 64")
        self.size = size
        self.session_id: int | None = None
        self.retired_sessions: set[int] = set()
        self.highest = -1
        self.bitmap = 0
        self._lock = threading.Lock()

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
        with self._lock:
            if sequence < 0 or not self._select_session(session_id):
                return False
            if self.highest < 0:
                self.highest = sequence
                self.bitmap = 1
                return True
            if sequence > self.highest:
                shift = sequence - self.highest
                self.bitmap = (
                    1
                    if shift >= self.size
                    else ((self.bitmap << shift) | 1) & ((1 << self.size) - 1)
                )
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

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "size": self.size,
                "session_id": self.session_id,
                "retired_sessions": sorted(self.retired_sessions),
                "highest": self.highest,
                "bitmap": format(self.bitmap, "x"),
            }

    def restore(self, state: dict[str, Any]) -> None:
        try:
            size = int(state["size"])
            session_id = state["session_id"]
            retired = {int(item) for item in state["retired_sessions"]}
            highest = int(state["highest"])
            bitmap = int(str(state["bitmap"]), 16)
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("invalid replay state") from exc
        if size != self.size:
            raise ProtocolError("replay state window size mismatch")
        if session_id is not None:
            session_id = int(session_id)
        if highest < -1 or bitmap < 0 or bitmap.bit_length() > self.size:
            raise ProtocolError("invalid replay state values")
        with self._lock:
            self.session_id = session_id
            self.retired_sessions = retired
            self.highest = highest
            self.bitmap = bitmap


class PersistentReplayWindow(ReplayWindow):
    """Replay window persisted atomically before an accepted frame is used."""

    def __init__(self, path: str | Path, tunnel_id: bytes, size: int = 4096):
        super().__init__(size)
        self.path = Path(path)
        self.fingerprint = hashlib.sha256(tunnel_id).hexdigest()
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        try:
            envelope = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProtocolError(f"cannot load replay state: {exc}") from exc
        if envelope.get("format") != 1 or envelope.get("tunnel") != self.fingerprint:
            raise ProtocolError("replay state belongs to a different tunnel or format")
        self.restore(envelope.get("window", {}))

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        envelope = {
            "format": 1,
            "tunnel": self.fingerprint,
            "window": self.snapshot(),
        }
        fd, temp_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(envelope, handle, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, self.path)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def accept(self, sequence: int, session_id: int = 0) -> bool:
        accepted = super().accept(sequence, session_id)
        if accepted:
            self._persist()
        return accepted
