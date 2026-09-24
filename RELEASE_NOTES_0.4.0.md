# h3ntun v0.4.0 — encrypted and reliable asymmetric transport

This release renames the project to `h3ntun` and replaces wire protocol 2 with protocol 3.

## Security and protocol

- ChaCha20-Poly1305 now encrypts and authenticates every tunnel frame.
- HKDF-SHA256 derives a per-tunnel encryption key from the configured secret.
- Header tampering, ciphertext tampering, stale timestamps, wrong tunnel ids, and replayed frames are rejected.
- Replay state survives receiver restarts and is persisted atomically before delivery.

## Reliability

- Messages up to 60000 bytes are split into MTU-safe fragments.
- Multi-fragment messages optionally include an XOR parity fragment that recovers one loss.
- End-to-end message ACKs travel on the opposite asymmetric path.
- Missing ACKs trigger retransmission with capped exponential backoff.
- A bounded queue and AIMD message window prevent unbounded memory growth.

## Validation

- 108 automated tests pass on the release workstation.
- Impaired loopback profile delivered 200/200 messages with intentional loss, duplication, jitter, and reordering.
- Stress profile delivered 1000/1000 messages.
- FEC profile recovered an intentionally removed fragment without retransmission.
- Outage profile delivered no traffic while the return path was disabled and recovered after restoration.
- 60000-byte messages passed; 60001-byte messages were rejected and counted.

## Breaking changes

- Package, module, command, service account, service, and install paths are renamed to `h3ntun`.
- Protocol 3 is incompatible with protocol 2. Upgrade both endpoints together.
- Python package dependency `cryptography>=42` is required.
- Deployment configuration should add reliability fields and a distinct `replay_state_file` on each endpoint.

The runtime still requires real, authorized, routable paths. It cannot override upstream filtering or source-address policy.
