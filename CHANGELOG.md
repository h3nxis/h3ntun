# Changelog

All notable changes to this project are documented here.

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
