from __future__ import annotations

import argparse
import base64
import json
import logging
import secrets
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.request

from .agent import ForeignAgent, IranAgent
from .config import ConfigError, ForeignConfig, IranConfig, load_config
from .raw_udp import build_ipv4_udp_packet


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hy-asym-link")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run an Iran or foreign agent")
    run.add_argument("--config", required=True)
    run.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    check = sub.add_parser("check", help="validate configuration without opening sockets")
    check.add_argument("--config", required=True)

    doctor = sub.add_parser("doctor", help="check DNS, route selection and local source binding")
    doctor.add_argument("--config", required=True)

    secret = sub.add_parser("generate-secret", help="generate a tunnel id and shared secret")
    secret.add_argument("--json", action="store_true")

    status = sub.add_parser("status", help="read the local health endpoint")
    status.add_argument("--url", default="http://127.0.0.1:9081/status")

    verify = sub.add_parser("verify", help="verify a running agent against its configuration")
    verify.add_argument("--config", required=True)

    packet = sub.add_parser("packet-selftest", help="build and validate a local raw-packet sample")
    packet.add_argument("--source", default="127.0.0.2")
    packet.add_argument("--destination", default="127.0.0.1")

    echo = sub.add_parser("echo", help="run a UDP echo peer for acceptance testing")
    echo.add_argument("--listen", default="127.0.0.1:51820")

    probe = sub.add_parser("probe", help="send test datagrams through a local agent")
    probe.add_argument("--target", default="127.0.0.1:5000")
    probe.add_argument("--count", type=int, default=5)
    probe.add_argument("--timeout", type=float, default=3.0)

    return parser


def run_agent(config_path: str, log_level: str) -> int:
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s %(levelname)s %(threadName)s %(message)s",
    )
    config = load_config(config_path)
    agent = IranAgent(config) if isinstance(config, IranConfig) else ForeignAgent(config)
    stopped = threading.Event()

    def handle_signal(_signum: int, _frame: object) -> None:
        stopped.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    agent.start()
    logging.info("agent started role=%s", config.role)
    try:
        while not stopped.wait(1.0):
            pass
    finally:
        agent.stop()
    return 0


def get_status(url: str) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return json.loads(response.read().decode())
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read status endpoint: {exc}") from exc


def read_status(url: str) -> int:
    data = get_status(url)
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0 if data.get("healthy") else 2


def doctor(config_path: str) -> int:
    config = load_config(config_path)
    if isinstance(config, IranConfig):
        remote = config.foreign_uplink
        bind = config.uplink_bind
    else:
        remote = config.iran_downlink
        bind = (config.downlink_source or "0.0.0.0", config.downlink_source_port)
    resolved = socket.gethostbyname(remote[0])
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(bind)
        probe.connect((resolved, remote[1]))
        chosen_source = probe.getsockname()[0]
    finally:
        probe.close()
    result = {
        "ok": True,
        "role": config.role,
        "remote_host": remote[0],
        "remote_resolved": resolved,
        "selected_local_source": chosen_source,
        "note": "No packet was transmitted by this check.",
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def verify(config_path: str) -> int:
    config = load_config(config_path)
    status_host = "127.0.0.1" if config.health_listen[0] in {"0.0.0.0", "::"} else config.health_listen[0]
    data = get_status(f"http://{status_host}:{config.health_listen[1]}/status")
    checks = {
        "role_matches": data.get("role") == config.role,
        "healthy": bool(data.get("healthy")),
        "authenticated_traffic_seen": (
            int(data.get("downlink_rx_packets", 0)) > 0
            if isinstance(config, IranConfig)
            else int(data.get("uplink_rx_packets", 0)) > 0
        ),
    }
    if isinstance(config, IranConfig) and config.expected_downlink_source:
        checks["expected_source_seen"] = data.get("last_downlink_source") == config.expected_downlink_source
    result = {"ok": all(checks.values()), "checks": checks, "status": data}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 2


def split_endpoint(value: str) -> tuple[str, int]:
    host, raw_port = value.rsplit(":", 1)
    return host, int(raw_port)


def echo_server(listen: str) -> int:
    bind = split_endpoint(listen)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(bind)
    print(json.dumps({"listening": f"{bind[0]}:{bind[1]}"}))
    try:
        while True:
            payload, peer = sock.recvfrom(65_535)
            sock.sendto(payload, peer)
    except KeyboardInterrupt:
        return 0
    finally:
        sock.close()


def probe_link(target: str, count: int, timeout: float) -> int:
    if count <= 0 or timeout <= 0:
        raise ValueError("count and timeout must be positive")
    destination = split_endpoint(target)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(timeout)
    samples = []
    try:
        for sequence in range(1, count + 1):
            payload = f"hy-asym-probe:{sequence}:{time.time_ns()}".encode()
            started = time.perf_counter()
            sock.sendto(payload, destination)
            try:
                received, _peer = sock.recvfrom(65_535)
                valid = received == payload
                rtt_ms = round((time.perf_counter() - started) * 1000, 2)
            except socket.timeout:
                valid = False
                rtt_ms = None
            samples.append({"sequence": sequence, "ok": valid, "rtt_ms": rtt_ms})
    finally:
        sock.close()
    received_count = sum(1 for sample in samples if sample["ok"])
    result = {
        "ok": received_count == count,
        "sent": count,
        "received": received_count,
        "loss_percent": round((count - received_count) * 100 / count, 2),
        "samples": samples,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "run":
            return run_agent(args.config, args.log_level)
        if args.command == "check":
            config = load_config(args.config)
            print(json.dumps({"ok": True, "role": config.role}, ensure_ascii=False))
            return 0
        if args.command == "doctor":
            return doctor(args.config)
        if args.command == "generate-secret":
            values = {
                "tunnel_id": secrets.token_hex(16),
                "shared_secret": base64.b64encode(secrets.token_bytes(32)).decode(),
            }
            if args.json:
                print(json.dumps(values, indent=2))
            else:
                print(f"tunnel_id={values['tunnel_id']}")
                print(f"shared_secret={values['shared_secret']}")
            return 0
        if args.command == "status":
            return read_status(args.url)
        if args.command == "verify":
            return verify(args.config)
        if args.command == "packet-selftest":
            packet = build_ipv4_udp_packet(args.source, 40000, args.destination, 40001, b"selftest", packet_id=1)
            print(json.dumps({"ok": len(packet) == 20 + 8 + 8, "packet_length": len(packet)}))
            return 0
        if args.command == "echo":
            return echo_server(args.listen)
        if args.command == "probe":
            return probe_link(args.target, args.count, args.timeout)
    except (ConfigError, ValueError, RuntimeError, OSError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
