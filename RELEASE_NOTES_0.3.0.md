# v0.3.0 — authenticated sessions and reproducible link lab

This release hardens the asymmetric UDP research prototype and adds a deterministic, loopback-only environment for validating its behavior without touching public networks.

## Highlights

- Wire protocol 2 adds an authenticated random session ID, allowing safe one-sided restarts without weakening replay protection.
- Both agents can enforce the exact local application peer and count rejected local-source mismatches.
- Configuration rejects NaN, infinity, zero, and negative timeout values.
- Health reporting uses the freshest valid downlink activity.
- A reproducible lab simulates independent uplink and downlink delay, jitter, loss, duplication, reordering, outage, recovery, stress, and payload boundaries.

## Verification

- 90/90 automated tests passed on the release workstation.
- Stress profile delivered 1000/1000 loopback responses.
- Outage profile delivered 0/10 during the outage and 30/30 after recovery.
- A 60000-byte payload passed; a 60001-byte payload was rejected and counted.
- The standalone sandbox delivered 100/100 responses and rejected both a wrong return source and a tampered HMAC.

See `TEST_REPORT.md`, `TEST_REPORT_USER_CHANGES_FA.md`, `LAB_REPORT_FA.md`, and `LAB_REPORT.json` for the complete results.

## Upgrade notice

Wire protocol 2 is incompatible with protocol 1. Upgrade both endpoints together and restart both services. Regenerate deployment configuration from the supplied examples if you want to set `expected_inner_peer`.

## Scope and limitations

The runtime uses ordinary source-bound UDP and only binds addresses assigned to the host. It does not send forged-source raw packets. The release does not implement encryption, retransmission, forward error correction, congestion control, or persistent replay state. Public routing, provider source validation, Linux firewall rules, and systemd deployment must be accepted on the operator's authorized endpoints.
