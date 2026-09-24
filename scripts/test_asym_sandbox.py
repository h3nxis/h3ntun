#!/usr/bin/env python3
"""
End-to-End Simulation & Benchmark Sandbox for Asymmetric Link:
- Simulates a separate paid uplink (small requests / ACKs)
- Simulates a separately sourced UDP downlink by binding a local loopback alias
- Measures: Latency, Throughput, Loss, and the exact Asymmetric Ratio Multiplier.
- Tests AEAD tamper rejection and an unexpected observed source.

This sandbox does not perform SNAT, raw-source spoofing, or public routing.
"""

from __future__ import annotations

import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

# Ensure UTF-8 output on Windows
if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from h3ntun.agent import ForeignAgent, IranAgent
from h3ntun.config import ForeignConfig, IranConfig
from h3ntun.protocol import DATA_DOWN, FrameCodec


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class AsymBackboneEchoServer:
    """
    Simulates a foreign VPN Core / Web server that takes small requests (e.g. 64B)
    and returns large bulk download data (e.g. 1024B) to test the asymmetric multiplier.
    """

    def __init__(self, listen_port: int, bridge_port: int, response_multiplier: int = 16):
        self.listen_port = listen_port
        self.bridge_port = bridge_port
        self.multiplier = response_multiplier
        self.stop_event = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", listen_port))
        self.sock.settimeout(0.2)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                payload, peer = self.sock.recvfrom(65_535)
                # Expand payload to simulate 10x-16x download response
                seq = payload[:8]
                response_data = seq + b"X" * (64 * self.multiplier - 8)
                self.sock.sendto(response_data, ("127.0.0.1", self.bridge_port))
            except (socket.timeout, OSError):
                continue

    def stop(self) -> None:
        self.stop_event.set()
        self.sock.close()
        self.thread.join(timeout=1.0)


def run_simulation():
    print("=" * 70)
    print("[*] INITIALIZING ASYMMETRIC LINK BENCHMARK & SIMULATION SANDBOX")
    print("=" * 70)

    inner_port = free_udp_port()
    uplink_port = free_udp_port()
    downlink_port = free_udp_port()
    bridge_port = free_udp_port()
    echo_port = free_udp_port()

    tunnel_id = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
    shared_secret = b"K" * 32
    simulated_return_source_ip = "127.0.0.2"  # Locally valid loopback alias, not spoofing

    with tempfile.TemporaryDirectory() as folder:
        iran_config = IranConfig(
            role="iran",
            tunnel_id=tunnel_id,
            shared_secret=shared_secret,
            health_listen=("127.0.0.1", 0),
            metrics_file=str(Path(folder) / "iran_metrics.json"),
            keepalive_seconds=5.0,
            health_timeout_seconds=10.0,
            recv_buffer_bytes=4 * 1024 * 1024,
            inner_listen=("127.0.0.1", inner_port),
            uplink_bind=("127.0.0.1", 0),
            foreign_uplink=("127.0.0.1", uplink_port),
            downlink_listen=("127.0.0.1", downlink_port),
            expected_downlink_source=simulated_return_source_ip,
        )

        foreign_config = ForeignConfig(
            role="foreign",
            tunnel_id=tunnel_id,
            shared_secret=shared_secret,
            health_listen=("127.0.0.1", 0),
            metrics_file=str(Path(folder) / "foreign_metrics.json"),
            keepalive_seconds=5.0,
            health_timeout_seconds=10.0,
            recv_buffer_bytes=4 * 1024 * 1024,
            uplink_listen=("127.0.0.1", uplink_port),
            inner_bridge_listen=("127.0.0.1", bridge_port),
            inner_peer=("127.0.0.1", echo_port),
            iran_downlink=("127.0.0.1", downlink_port),
            downlink_mode="udp",
            downlink_source=simulated_return_source_ip,
            downlink_source_port=0,
        )

        echo_server = AsymBackboneEchoServer(echo_port, bridge_port, response_multiplier=16)
        iran_agent = IranAgent(iran_config)
        foreign_agent = ForeignAgent(foreign_config)

        print("[+] Components started:")
        print(f"    - Iran Agent:      Inner=127.0.0.1:{inner_port} | Downlink=127.0.0.1:{downlink_port}")
        print(f"    - Uplink Route:    Simulated paid uplink -> Foreign Agent (127.0.0.1:{uplink_port})")
        print(f"    - Foreign Agent:   Bridge=127.0.0.1:{bridge_port} | VPN Core=127.0.0.1:{echo_port}")
        print(f"    - Downlink Route:  Locally bound source={simulated_return_source_ip} -> Iran Downlink (127.0.0.1:{downlink_port})")

        echo_server.start()
        foreign_agent.start()
        iran_agent.start()
        time.sleep(0.5)

        # Client simulation (User in Iran)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))
        client.settimeout(2.0)

        num_packets = 100
        packet_size = 64  # Small request packet (representing HTTP GET / TCP ACK)
        latencies_ms = []
        received_count = 0

        print(f"\n[+] Executing Benchmark: Sending {num_packets} datagrams through asymmetric path...")
        start_time = time.perf_counter()

        for seq in range(1, num_packets + 1):
            req_payload = f"REQ:{seq:04d}:".encode() + b"A" * (packet_size - 9)
            t0 = time.perf_counter()
            client.sendto(req_payload, ("127.0.0.1", inner_port))
            try:
                resp_payload, _ = client.recvfrom(65_535)
                t1 = time.perf_counter()
                if resp_payload.startswith(req_payload[:8]):
                    received_count += 1
                    latencies_ms.append((t1 - t0) * 1000)
            except socket.timeout:
                pass

        total_duration = time.perf_counter() - start_time
        client.close()

        # Gather metrics from agents
        iran_m = iran_agent.metrics.snapshot()
        foreign_m = foreign_agent.metrics.snapshot()

        print("\n" + "=" * 70)
        print("[-] BENCHMARK & MULTIPLIER RESULTS")
        print("=" * 70)

        uplink_bytes = iran_m["uplink_tx_bytes"]
        downlink_bytes = iran_m["downlink_rx_bytes"]
        multiplier = (downlink_bytes / uplink_bytes) if uplink_bytes > 0 else 0

        print(f"[OK] Packets Sent:               {num_packets}")
        print(f"[OK] Packets Received:           {received_count} ({received_count/num_packets*100:.1f}%)")
        print(f"[OK] Packet Loss:                {(num_packets - received_count)/num_packets*100:.1f}%")
        print(f"[OK] Avg RTT Latency:            {sum(latencies_ms)/len(latencies_ms):.2f} ms")
        print(f"[OK] Min/Max RTT Latency:        {min(latencies_ms):.2f} ms / {max(latencies_ms):.2f} ms")
        print(f"[OK] Simulated Uplink Consumed:  {uplink_bytes:,} bytes ({uplink_bytes/1024:.2f} KB)")
        print(f"[OK] Actual Downlink Delivered:  {downlink_bytes:,} bytes ({downlink_bytes/1024:.2f} KB)")
        print(f"[+] MEASURED LOOPBACK RATIO:     {multiplier:.2f}x MULTIPLIER")

        print("\n" + "=" * 70)
        print("[-] SECURITY & ANTI-TAMPER VERIFICATION")
        print("=" * 70)

        # Test 1: Verified observed return source
        print(f"[OK] Observed Downlink Source:   {iran_m['last_downlink_source']} (Matches expected '{simulated_return_source_ip}')")
        assert iran_m["last_downlink_source"] == simulated_return_source_ip, "Source IP check failed!"

        # Test 2: Unexpected observed source rejection
        print("[+] Testing untrusted source packet rejection...")
        forger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forged_packet = FrameCodec(tunnel_id, shared_secret).encode(DATA_DOWN, 9999, b"untrusted")
        # Send from 127.0.0.1 (not 127.0.0.2)
        forger.bind(("127.0.0.1", 0))
        forger.sendto(forged_packet, ("127.0.0.1", downlink_port))
        forger.close()
        time.sleep(0.2)

        iran_m_after = iran_agent.metrics.snapshot()
        print(f"[OK] Untrusted Source Packets Dropped: {iran_m_after['source_mismatch_drops']}")
        assert iran_m_after["source_mismatch_drops"] >= 1, "Unexpected source was not dropped!"

        # Test 3: AEAD tamper rejection
        print("[+] Testing AEAD tamper rejection...")
        tamperer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tamperer.bind((simulated_return_source_ip, 0))
        tampered_packet = bytearray(forged_packet)
        tampered_packet[-1] ^= 0xFF  # Change ciphertext; the AEAD tag must reject it
        tamperer.sendto(bytes(tampered_packet), ("127.0.0.1", downlink_port))
        tamperer.close()
        time.sleep(0.2)

        iran_m_tamper = iran_agent.metrics.snapshot()
        print(f"[OK] Tampered AEAD Packets Dropped:   {iran_m_tamper['auth_failures']}")
        assert iran_m_tamper["auth_failures"] >= 1, "Tampered ciphertext was not rejected!"

        # Clean shutdown
        iran_agent.stop()
        foreign_agent.stop()
        echo_server.stop()

        print("\n" + "=" * 70)
        print("[*] ALL LOCAL SANDBOX TESTS PASSED; PUBLIC ROUTING/SNAT WAS NOT TESTED")
        print("=" * 70)


if __name__ == "__main__":
    run_simulation()
