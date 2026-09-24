#!/usr/bin/env python3
"""Authenticated source-bound reachability scanner.

This tool does not open raw sockets and cannot forge a non-local source
address. Every candidate must be bindable by the kernel on the sender. It is
intended for owned/authorized addresses and local lab simulations.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import random
import shutil
import socket
import struct
import sys
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from h3ntun.config import ForeignConfig, IranConfig, load_config


PROBE_MAGIC = b"HYPROBE1"
PROBE_PREFIX = struct.Struct("!8s16s4sIIQ")
PROBE_HEADER = struct.Struct("!8s16s4sIIQ16s")
MAX_CANDIDATES = 4096
MAX_CLOCK_SKEW_SECONDS = 600
DEFAULT_CANDIDATE_POOLS = {"loopback": ["127.0.0.1", "127.0.0.2"]}


class ProbeError(ValueError):
    pass


@dataclass(frozen=True)
class Probe:
    candidate_ip: str
    sequence: int
    total_probes: int
    timestamp_ns: int


def encode_probe(
    tunnel_id: bytes,
    secret: bytes,
    candidate_ip: str,
    sequence: int,
    total_probes: int,
    timestamp_ns: int | None = None,
) -> bytes:
    if len(tunnel_id) != 16 or len(secret) < 32:
        raise ProbeError("invalid tunnel credentials")
    if not 1 <= sequence <= total_probes:
        raise ProbeError("invalid probe sequence")
    timestamp_ns = time.time_ns() if timestamp_ns is None else timestamp_ns
    candidate = ipaddress.IPv4Address(candidate_ip).packed
    prefix = PROBE_PREFIX.pack(
        PROBE_MAGIC, tunnel_id, candidate, sequence, total_probes, timestamp_ns
    )
    tag = hmac.new(secret, prefix, hashlib.sha256).digest()[:16]
    return PROBE_HEADER.pack(
        PROBE_MAGIC, tunnel_id, candidate, sequence, total_probes, timestamp_ns, tag
    )


def decode_probe(
    packet: bytes,
    tunnel_id: bytes,
    secret: bytes,
    now_ns: int | None = None,
) -> Probe:
    if len(packet) != PROBE_HEADER.size:
        raise ProbeError("invalid probe length")
    magic, received_tunnel, candidate, sequence, total, timestamp_ns, tag = PROBE_HEADER.unpack(packet)
    if magic != PROBE_MAGIC or received_tunnel != tunnel_id:
        raise ProbeError("unexpected probe identity")
    prefix = PROBE_PREFIX.pack(magic, received_tunnel, candidate, sequence, total, timestamp_ns)
    expected = hmac.new(secret, prefix, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, expected):
        raise ProbeError("probe authentication failed")
    if not 1 <= sequence <= total:
        raise ProbeError("invalid probe sequence")
    now_ns = time.time_ns() if now_ns is None else now_ns
    if abs(now_ns - timestamp_ns) > MAX_CLOCK_SKEW_SECONDS * 1_000_000_000:
        raise ProbeError("probe timestamp is stale")
    return Probe(str(ipaddress.IPv4Address(candidate)), sequence, total, timestamp_ns)


def _sample_integer_range(first: int, count: int, limit: int | None) -> list[int]:
    if count <= 0:
        return []
    if limit is not None:
        if limit <= 0 or limit > MAX_CANDIDATES:
            raise ValueError(f"sample limit must be within 1..{MAX_CANDIDATES}")
        if count > limit:
            return sorted(random.sample(range(first, first + count), limit))
    if count > MAX_CANDIDATES:
        raise ValueError(
            f"candidate set contains {count} addresses; use --sample up to {MAX_CANDIDATES}"
        )
    return list(range(first, first + count))


def parse_ip_targets(
    candidates_file: str | None = None,
    cidr: str | None = None,
    ip_range: str | None = None,
    pool: str | None = None,
    sample_limit: int | None = None,
) -> list[str]:
    """Parse a bounded, deduplicated list of IPv4 source addresses."""
    selected = sum(value is not None for value in (candidates_file, cidr, ip_range, pool))
    if selected != 1:
        raise ValueError("select exactly one candidate source")

    values: list[str]
    if cidr is not None:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.version != 4:
            raise ValueError("only IPv4 candidates are supported")
        if network.prefixlen < 31:
            first = int(network.network_address) + 1
            count = network.num_addresses - 2
        else:
            first = int(network.network_address)
            count = network.num_addresses
        numbers = _sample_integer_range(first, count, sample_limit)
        values = [str(ipaddress.IPv4Address(number)) for number in numbers]
    elif ip_range is not None:
        if "-" in ip_range:
            start_text, end_text = ip_range.split("-", 1)
        else:
            start_text = end_text = ip_range
        start = int(ipaddress.IPv4Address(start_text.strip()))
        end = int(ipaddress.IPv4Address(end_text.strip()))
        if start > end:
            start, end = end, start
        numbers = _sample_integer_range(start, end - start + 1, sample_limit)
        values = [str(ipaddress.IPv4Address(number)) for number in numbers]
    elif candidates_file is not None:
        lines = Path(candidates_file).read_text(encoding="utf-8").splitlines()
        raw_values = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
        if len(raw_values) > MAX_CANDIDATES:
            raise ValueError(f"candidate file exceeds {MAX_CANDIDATES} entries")
        values = [str(ipaddress.IPv4Address(value)) for value in raw_values]
        if sample_limit is not None:
            if not 1 <= sample_limit <= MAX_CANDIDATES:
                raise ValueError(f"sample limit must be within 1..{MAX_CANDIDATES}")
            if len(values) > sample_limit:
                values = random.sample(values, sample_limit)
    else:
        if pool not in DEFAULT_CANDIDATE_POOLS:
            raise ValueError("unknown safe candidate pool")
        values = list(DEFAULT_CANDIDATE_POOLS[pool])

    return list(dict.fromkeys(values))


def _atomic_update_iran_config(config_path: str, best_ip: str) -> None:
    path = Path(config_path)
    config = load_config(path)
    if not isinstance(config, IranConfig):
        raise ValueError("receiver config must have role=iran")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["expected_downlink_source"] = str(ipaddress.IPv4Address(best_ip))
    backup = path.with_suffix(path.suffix + ".bak")
    shutil.copy2(path, backup)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, path.stat().st_mode)
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _print_receiver_table(stats: dict, auth_failures: int, source_mismatches: int) -> str | None:
    print("\nSOURCE             RECEIVED   DECLARED   LOSS       AGE-ESTIMATE")
    print("-" * 70)
    ranked = []
    for candidate, values in stats.items():
        declared = max(values["declared"], len(values["sequences"]))
        received = len(values["sequences"])
        loss = max(0.0, (declared - received) * 100.0 / declared) if declared else 100.0
        ages = values["age_ms"]
        average_age = sum(ages) / len(ages) if ages else 0.0
        ranked.append((loss, -received, candidate, declared, average_age))
    for loss, negative_received, candidate, declared, average_age in sorted(ranked):
        received = -negative_received
        print(
            f"{candidate:<18} {received:<10} {declared:<10} "
            f"{loss:>5.1f}%    {average_age:>8.2f} ms"
        )
    print(f"auth_failures={auth_failures} source_mismatches={source_mismatches}")
    if not ranked:
        return None
    loss, negative_received, candidate, declared, _ = sorted(ranked)[0]
    received = -negative_received
    return candidate if received >= 3 and loss <= 20.0 and declared >= 3 else None


def run_receiver(
    listen_host: str,
    listen_port: int,
    config_path: str,
    duration_seconds: float | None = None,
    update_config: bool = False,
) -> str | None:
    config = load_config(config_path)
    if not isinstance(config, IranConfig):
        raise ValueError("receiver config must have role=iran")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen_host, listen_port))
    sock.settimeout(0.5)
    stats = defaultdict(lambda: {"sequences": set(), "declared": 0, "age_ms": []})
    seen: set[tuple[str, int, int]] = set()
    auth_failures = 0
    source_mismatches = 0
    deadline = time.monotonic() + duration_seconds if duration_seconds else None
    try:
        while deadline is None or time.monotonic() < deadline:
            try:
                packet, peer = sock.recvfrom(2048)
            except socket.timeout:
                continue
            try:
                probe = decode_probe(packet, config.tunnel_id, config.shared_secret)
            except ProbeError:
                auth_failures += 1
                continue
            if peer[0] != probe.candidate_ip:
                source_mismatches += 1
                continue
            replay_key = (probe.candidate_ip, probe.sequence, probe.timestamp_ns)
            if replay_key in seen:
                continue
            seen.add(replay_key)
            values = stats[probe.candidate_ip]
            values["sequences"].add(probe.sequence)
            values["declared"] = max(values["declared"], probe.total_probes)
            values["age_ms"].append(
                max(0.0, (time.time_ns() - probe.timestamp_ns) / 1_000_000.0)
            )
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    best_ip = _print_receiver_table(stats, auth_failures, source_mismatches)
    if update_config:
        if not best_ip:
            raise RuntimeError("no candidate met the authenticated delivery threshold")
        _atomic_update_iran_config(config_path, best_ip)
    return best_ip


def run_scanner(
    target_host: str,
    target_port: int,
    candidate_list: list[str],
    config_path: str,
    probes_per_ip: int = 20,
    delay_ms: int = 20,
) -> dict[str, str]:
    config = load_config(config_path)
    if not isinstance(config, ForeignConfig):
        raise ValueError("scanner config must have role=foreign")
    if not 1 <= probes_per_ip <= 10_000:
        raise ValueError("probes must be within 1..10000")
    if not 0 <= delay_ms <= 60_000:
        raise ValueError("delay-ms must be within 0..60000")

    results: dict[str, str] = {}
    for candidate in candidate_list:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((candidate, 0))
        except OSError as exc:
            results[candidate] = f"not-local: {exc}"
            sock.close()
            continue
        try:
            for sequence in range(1, probes_per_ip + 1):
                packet = encode_probe(
                    config.tunnel_id,
                    config.shared_secret,
                    candidate,
                    sequence,
                    probes_per_ip,
                )
                sock.sendto(packet, (target_host, target_port))
                if delay_ms:
                    time.sleep(delay_ms / 1000.0)
            results[candidate] = f"sent:{probes_per_ip}"
        finally:
            sock.close()
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authenticated source-bound reachability scanner"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    receiver = subcommands.add_parser("receiver")
    receiver.add_argument("--listen", default="0.0.0.0:7001")
    receiver.add_argument("--config", required=True)
    receiver.add_argument("--duration", type=float)
    receiver.add_argument("--update-config", action="store_true")

    scanner = subcommands.add_parser("scanner")
    scanner.add_argument("--target", required=True)
    scanner.add_argument("--config", required=True)
    sources = scanner.add_mutually_exclusive_group(required=True)
    sources.add_argument("--cidr")
    sources.add_argument("--range", dest="ip_range")
    sources.add_argument("--candidates-file")
    sources.add_argument("--pool", choices=DEFAULT_CANDIDATE_POOLS.keys())
    scanner.add_argument("--sample", type=int)
    scanner.add_argument("--probes", type=int, default=20)
    scanner.add_argument("--delay-ms", type=int, default=20)

    args = parser.parse_args()
    try:
        if args.command == "receiver":
            host, port = args.listen.rsplit(":", 1)
            run_receiver(
                host, int(port), args.config, args.duration, args.update_config
            )
            return 0
        host, port = args.target.rsplit(":", 1)
        candidates = parse_ip_targets(
            candidates_file=args.candidates_file,
            cidr=args.cidr,
            ip_range=args.ip_range,
            pool=args.pool,
            sample_limit=args.sample,
        )
        result = run_scanner(
            host, int(port), candidates, args.config, args.probes, args.delay_ms
        )
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
