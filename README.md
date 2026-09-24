# h3ntun

`h3ntun` is an encrypted, reliable UDP transport for deployments where the uplink and downlink use different authorized network paths. It accepts local UDP datagrams, encrypts and fragments them into MTU-safe frames, transports them over the configured paths, and reconstructs them at the other endpoint.

Persian guide: [README_FA.md](README_FA.md)

## Version 0.4.0

- ChaCha20-Poly1305 authenticated encryption with a per-tunnel key derived by HKDF-SHA256.
- Wire protocol 3 with random process sessions and unique sequence-derived nonces.
- 1200-byte default fragments, reassembly for messages up to 60000 bytes, and single-loss XOR parity FEC.
- End-to-end message ACKs, retransmission with exponential backoff, bounded queues, and AIMD congestion windowing.
- Persistent, fail-closed replay state with atomic replacement before an accepted frame is delivered.
- Exact outer-source and local-peer allowlists.
- Deterministic loopback fault lab covering delay, jitter, loss, duplication, reordering, outage, recovery, FEC, stress, and payload boundaries.

Wire protocol 3 is incompatible with earlier releases. Upgrade both endpoints together.

## Architecture

```text
local UDP app
     │
     ▼
Iran agent ── encrypted DATA/ACK uplink ──► foreign agent ──► remote UDP app
     ▲                                          │
     └──── encrypted DATA/ACK downlink ─────────┘
```

The runtime uses ordinary UDP sockets. A configured source address must be assigned to the sending host and accepted by its provider. `h3ntun` does not forge non-local source addresses and does not create an Internet route that the underlying networks do not provide.

## Quick start

Requirements: Linux, Python 3.10+, systemd, and reachable authorized UDP paths in both directions.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
h3ntun generate-secret --json
```

Copy and edit the examples:

```bash
cp config/iran.example.json iran.json
cp config/foreign.example.json foreign.json
```

Use the same `tunnel_id` and `shared_secret` on both sides. Replace every placeholder, then install:

```bash
sudo bash scripts/install-iran.sh ./iran.json
sudo bash scripts/install-foreign.sh ./foreign.json
```

The installer creates `/opt/h3ntun/venv`, installs the package and its cryptography dependency, creates an unprivileged `h3ntun` service account, and starts `h3ntun.service`.

## Important configuration

- `fragment_payload_bytes`: 256–1391; default 1200. The upper bound fits the
  encrypted h3ntun frame plus IPv4/UDP headers in a 1500-byte MTU.
- `fec_enabled`: add one parity fragment to multi-fragment messages.
- `reliable`: enable ACK and retransmission.
- `retransmit_timeout_seconds`: initial retransmission timeout; later attempts use capped exponential backoff.
- `max_retries`: retransmissions allowed after the initial send.
- `max_pending_messages`: bounded queued plus in-flight messages.
- `replay_state_file`: durable receiver replay state. Do not share one file between agents.
- `expected_downlink_source`: optional observed-source allowlist at the Iran endpoint.
- `expected_inner_peer`: optional fixed local application endpoint at the Iran side.
- `downlink_source`: an address assigned to the foreign host, or `null` for kernel route selection.

## Verification

```bash
python -m compileall -q h3ntun tests scripts
python -m unittest discover -s tests -q
python scripts/lab_environment.py --profile all --output LAB_REPORT.json
python scripts/test_asym_sandbox.py
```

See [TEST_REPORT.md](TEST_REPORT.md), [LAB_REPORT_FA.md](LAB_REPORT_FA.md), and [RELEASE_NOTES_0.4.0.md](RELEASE_NOTES_0.4.0.md).

## Operational boundaries

- Both authorized paths must be routable; software cannot override upstream filtering or provider policy.
- Reliability is bounded by queue and retry settings. An outage longer than that budget can still expire messages.
- `h3ntun` transports UDP datagrams; it is not a TUN/TAP device or a general IP router.
- Clock synchronization is required for the authenticated timestamp window.
- Linux firewall, routing, MTU, and provider source validation must be accepted on the actual hosts.

Use only on systems and addresses you own or are authorized to operate. See [SECURITY.md](SECURITY.md).
