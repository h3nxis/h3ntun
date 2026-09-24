# Changelog

All notable changes to this project are documented here.

## 0.4.0 — 2026-09-24

### Added

- ChaCha20-Poly1305 frame encryption and HKDF-SHA256 key derivation.
- MTU-safe fragmentation and bounded reassembly up to 60000-byte messages.
- Optional single-loss XOR parity FEC.
- Bidirectional acknowledgements, retransmission with capped exponential backoff, bounded queues, and AIMD windowing.
- Atomic persistent replay state that survives receiver restarts.
- Linux CI installation, shell syntax validation, fault profiles, FEC tests, and protocol-v3 security tests.

### Changed

- Renamed the package, module, command, service, account, install paths, and release bundle to `h3ntun`.
- Upgraded the wire format to protocol 3. Both endpoints must be upgraded together.
- The installer now creates a virtual environment and installs declared dependencies.

### Fixed

- Lost tunnel messages can now recover through FEC or retransmission.
- Large application datagrams no longer depend on IP fragmentation by default.
- Receiver-process restarts no longer discard replay history when a replay-state file is configured.
- Payload confidentiality is now provided by the transport itself.

## 0.3.0 — 2026-09-23

### Added

- Authenticated random session IDs in wire protocol version 2.
- Session-aware replay protection with retired-session rejection.
- Optional fixed `expected_inner_peer` validation on the Iran agent.
- Exact inner-peer source validation on the foreign agent.
- Loopback-only asymmetric link laboratory with clean, impaired, outage, recovery, stress, and boundary profiles.
- GitHub Actions coverage for Python 3.10 through 3.14.

### Fixed

- One-sided restart no longer locks out a peer whose sequence counter restarts.
- Non-finite timeout values are rejected during configuration loading.
- Iran health status selects the freshest valid downlink activity.
- The lab client receives concurrently and uses larger socket buffers for burst tests.
- Request identifiers remain unique across consecutive lab bursts.

### Security

- Local UDP replies are accepted only from the configured inner peer where that peer is fixed.
- Protocol version 2 is not wire-compatible with version 1; upgrade both endpoints together.

## 0.2.0 — 2026-08-31

- Replaced raw-source transmission paths with source-bound UDP behavior.
- Added authenticated source reachability checks and rollback-aware network scripts.
- Added integration, scanner, safety-contract, and packaging tests.
