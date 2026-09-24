# Test report

Date: 2026-09-23

Runtime: Python 3.13.14 on Windows

Package version: 0.3.0

Wire protocol version: 2

## Executed

- `python -m compileall -q asym_link tests scripts`: passed.
- `python -m unittest discover -s tests -q`: 90/90 passed in 20.115 seconds.
- `python scripts/lab_environment.py --profile all --output LAB_REPORT.json`: passed.
- `python scripts/test_asym_sandbox.py`: passed, 100/100 responses.
- Protocol encode/decode, authenticated session IDs, HMAC tamper rejection, timestamp window, replay window, one-sided restart, and retired-session replay rejection: passed.
- IPv4 and UDP checksum verification for the offline packet builder: passed.
- Full local integration with the Iran agent, foreign agent, one-way uplink/downlink relays, and UDP backend: passed.
- Expected outer return-source enforcement and fixed inner-peer enforcement on both agents: passed.
- Configuration validation rejects NaN, infinity, zero, and negative timeouts: passed.
- Outage and recovery, deterministic loss, duplication, reordering, delay, jitter, stress burst, maximum payload, and oversize rejection: passed.
- Placeholder rejection, live raw-mode rejection, safe scanner behavior, and rollback-script contracts: passed.

## Lab summary

- Clean: 100/100 responses, 0% loss, average 33.99 ms simulated RTT.
- Impaired: 171/200 responses. The 14.5% loss matches intentionally injected uplink/downlink drops; 13 duplicates were rejected by replay protection.
- Outage: 0/10 responses during the outage; 30/30 after recovery.
- Stress: 1000/1000 responses, 0% loss.
- Boundary: 5/5 payloads of 60000 bytes passed; a 60001-byte payload was rejected and counted.
- Sandbox: 100/100 responses, 8.50x application payload ratio, wrong source and tampered HMAC rejected.

The machine-readable results are in `LAB_REPORT.json`; interpretation and limitations are in `LAB_REPORT_FA.md`.

## Important limitations

- This transport does not implement retransmission, forward error correction, congestion control, or fragmentation.
- HMAC authenticates frames but does not encrypt their payloads.
- Replay history is in memory. A complete receiver-process restart loses retired-session history.
- The 60000-byte application limit can exceed a real path MTU; small payloads around 1200 bytes are safer unless the path has been measured.
- `expected_inner_peer` should be configured when the local application uses a fixed address and port.
- Wire protocol 2 is incompatible with version 1; both endpoints must be upgraded together.

## Not executable in this workspace

- systemd installation and hardening directives require a Linux host.
- iproute2, nftables/iptables, route policy, and actual provider source-address validation were not executed because this Windows environment has no Linux/WSL/Docker runtime.
- A real external uplink/downlink acceptance test requires the operator's two authorized endpoints and routes.
- No public endpoint, third-party address, or live forged-source transmission was tested or is claimed by this project.

The on-server acceptance procedure is documented in `README_FA.md` and implemented by `preflight.sh`, `verify.sh`, `echo`, and `probe`.
