from __future__ import annotations

import base64
import ipaddress
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PLACEHOLDER_RE = re.compile(
    r"(^|[_-])(iran|foreign|spoof|source|authorized|replace|change|example)([_-]|$)",
    re.I,
)


class ConfigError(ValueError):
    pass


def parse_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{field} must be true or false")
    return value


def split_host_port(value: str, field: str) -> tuple[str, int]:
    if not isinstance(value, str) or ":" not in value:
        raise ConfigError(f"{field} must use host:port format")
    host, raw_port = value.rsplit(":", 1)
    if not host:
        raise ConfigError(f"{field} host is empty")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise ConfigError(f"{field} port is not an integer") from exc
    if not 0 <= port <= 65535:
        raise ConfigError(f"{field} port is outside 0..65535")
    return host, port


def remote_host_port(value: str, field: str) -> tuple[str, int]:
    host, port = split_host_port(value, field)
    reject_placeholder(host, f"{field} host")
    if port == 0:
        raise ConfigError(f"{field} port cannot be zero")
    return host, port


def reject_placeholder(value: str, field: str) -> None:
    normalized = value.strip().replace(".", "_")
    if not value.strip() or PLACEHOLDER_RE.search(normalized):
        raise ConfigError(f"{field} still contains a placeholder")


def parse_ipv4(value: str, field: str, allow_unspecified: bool = False) -> str:
    reject_placeholder(value, field)
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigError(f"{field} is not a valid IP address") from exc
    if ip.version != 4:
        raise ConfigError(f"{field} must be IPv4")
    if ip.is_unspecified and not allow_unspecified:
        raise ConfigError(f"{field} cannot be unspecified")
    if ip.is_multicast:
        raise ConfigError(f"{field} cannot be multicast")
    return str(ip)


@dataclass(frozen=True, kw_only=True)
class CommonConfig:
    role: str
    tunnel_id: bytes
    shared_secret: bytes
    health_listen: tuple[str, int]
    metrics_file: str
    keepalive_seconds: float
    health_timeout_seconds: float
    recv_buffer_bytes: int
    fragment_payload_bytes: int = 1200
    fec_enabled: bool = True
    reliable: bool = True
    retransmit_timeout_seconds: float = 0.5
    max_retries: int = 8
    max_pending_messages: int = 2048
    reassembly_timeout_seconds: float = 30.0
    replay_checkpoint_interval_seconds: float = 0.05
    replay_checkpoint_batch_frames: int = 128


@dataclass(frozen=True, kw_only=True)
class IranConfig(CommonConfig):
    inner_listen: tuple[str, int]
    uplink_bind: tuple[str, int]
    foreign_uplink: tuple[str, int]
    downlink_listen: tuple[str, int]
    expected_downlink_source: str | None
    expected_inner_peer: tuple[str, int] | None = None
    replay_state_file: str | None = None


@dataclass(frozen=True, kw_only=True)
class ForeignConfig(CommonConfig):
    uplink_listen: tuple[str, int]
    inner_bridge_listen: tuple[str, int]
    inner_peer: tuple[str, int]
    iran_downlink: tuple[str, int]
    downlink_mode: str
    downlink_source: str | None
    downlink_source_port: int
    replay_state_file: str | None = None


def _decode_tunnel_id(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ConfigError("tunnel_id must be a 32-character hex string")
    reject_placeholder(value, "tunnel_id")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ConfigError("tunnel_id must be hexadecimal") from exc
    if len(decoded) != 16:
        raise ConfigError("tunnel_id must decode to 16 bytes")
    return decoded


def _decode_secret(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ConfigError("shared_secret must be base64 text")
    reject_placeholder(value, "shared_secret")
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ConfigError("shared_secret is not valid base64") from exc
    if len(decoded) < 32:
        raise ConfigError("shared_secret must decode to at least 32 bytes")
    return decoded


def load_config(path: str | Path) -> IranConfig | ForeignConfig:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ConfigError("configuration root must be an object")
    role = str(raw.get("role", "")).strip().lower()
    if role not in {"iran", "foreign"}:
        raise ConfigError("role must be iran or foreign")
    common = dict(
        role=role,
        tunnel_id=_decode_tunnel_id(raw.get("tunnel_id")),
        shared_secret=_decode_secret(raw.get("shared_secret")),
        health_listen=split_host_port(raw.get("health_listen", "127.0.0.1:9081"), "health_listen"),
        metrics_file=str(raw.get("metrics_file", "/var/lib/h3ntun/metrics.json")),
        keepalive_seconds=float(raw.get("keepalive_seconds", 5.0)),
        health_timeout_seconds=float(raw.get("health_timeout_seconds", 20.0)),
        recv_buffer_bytes=int(raw.get("recv_buffer_bytes", 4 * 1024 * 1024)),
        fragment_payload_bytes=int(raw.get("fragment_payload_bytes", 1200)),
        fec_enabled=parse_bool(raw.get("fec_enabled", True), "fec_enabled"),
        reliable=parse_bool(raw.get("reliable", True), "reliable"),
        retransmit_timeout_seconds=float(raw.get("retransmit_timeout_seconds", 0.5)),
        max_retries=int(raw.get("max_retries", 8)),
        max_pending_messages=int(raw.get("max_pending_messages", 2048)),
        reassembly_timeout_seconds=float(raw.get("reassembly_timeout_seconds", 30.0)),
        replay_checkpoint_interval_seconds=float(raw.get("replay_checkpoint_interval_seconds", 0.05)),
        replay_checkpoint_batch_frames=int(raw.get("replay_checkpoint_batch_frames", 128)),
    )
    if (
        not math.isfinite(common["keepalive_seconds"])
        or not math.isfinite(common["health_timeout_seconds"])
        or common["keepalive_seconds"] <= 0
        or common["health_timeout_seconds"] <= 0
        or not math.isfinite(common["retransmit_timeout_seconds"])
        or not math.isfinite(common["reassembly_timeout_seconds"])
        or not math.isfinite(common["replay_checkpoint_interval_seconds"])
        or common["retransmit_timeout_seconds"] <= 0
        or common["reassembly_timeout_seconds"] <= 0
        or common["replay_checkpoint_interval_seconds"] <= 0
    ):
        raise ConfigError("all timeout values must be finite and positive")
    if common["recv_buffer_bytes"] < 65_536:
        raise ConfigError("recv_buffer_bytes is too small")
    if not 256 <= common["fragment_payload_bytes"] <= 1391:
        raise ConfigError("fragment_payload_bytes must be between 256 and 1391")
    if not 0 <= common["max_retries"] <= 100:
        raise ConfigError("max_retries must be between 0 and 100")
    if not 1 <= common["max_pending_messages"] <= 100_000:
        raise ConfigError("max_pending_messages must be between 1 and 100000")
    if not 1 <= common["replay_checkpoint_batch_frames"] <= 100_000:
        raise ConfigError("replay_checkpoint_batch_frames must be between 1 and 100000")

    if role == "iran":
        expected = raw.get("expected_downlink_source")
        if expected:
            expected = parse_ipv4(str(expected), "expected_downlink_source")
        expected_inner_peer = raw.get("expected_inner_peer")
        if expected_inner_peer:
            expected_inner_peer = remote_host_port(
                str(expected_inner_peer), "expected_inner_peer"
            )
        return IranConfig(
            **common,
            inner_listen=split_host_port(raw["inner_listen"], "inner_listen"),
            uplink_bind=split_host_port(raw.get("uplink_bind", "0.0.0.0:0"), "uplink_bind"),
            foreign_uplink=remote_host_port(raw["foreign_uplink"], "foreign_uplink"),
            downlink_listen=split_host_port(raw["downlink_listen"], "downlink_listen"),
            expected_downlink_source=expected,
            expected_inner_peer=expected_inner_peer,
            replay_state_file=(
                str(raw.get("replay_state_file", "/var/lib/h3ntun/iran-replay.json"))
                if raw.get("replay_state_file", "/var/lib/h3ntun/iran-replay.json")
                else None
            ),
        )

    mode = str(raw.get("downlink_mode", "udp")).strip().lower()
    if mode != "udp":
        raise ConfigError(
            "downlink_mode must be udp; live forged-source raw mode is intentionally not implemented"
        )
    source = raw.get("downlink_source")
    if source:
        source = parse_ipv4(str(source), "downlink_source")
    source_port = int(raw.get("downlink_source_port", 0))
    if not 0 <= source_port <= 65535:
        raise ConfigError("downlink_source_port is outside 0..65535")
    return ForeignConfig(
        **common,
        uplink_listen=split_host_port(raw["uplink_listen"], "uplink_listen"),
        inner_bridge_listen=split_host_port(raw["inner_bridge_listen"], "inner_bridge_listen"),
        inner_peer=split_host_port(raw["inner_peer"], "inner_peer"),
        iran_downlink=remote_host_port(raw["iran_downlink"], "iran_downlink"),
        downlink_mode=mode,
        downlink_source=source,
        downlink_source_port=source_port,
        replay_state_file=(
            str(raw.get("replay_state_file", "/var/lib/h3ntun/foreign-replay.json"))
            if raw.get("replay_state_file", "/var/lib/h3ntun/foreign-replay.json")
            else None
        ),
    )
