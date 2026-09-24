# h3ntun 0.4.0 test report

Date: 2026-09-24

Release workstation: Windows, Python 3.13.14

Wire protocol: 3

## Result

- `python -m compileall -q h3ntun tests scripts`: passed.
- `python -m unittest discover -s tests -q`: 108/108 passed.
- Full loopback fault lab: passed.
- Standalone asymmetric sandbox: 100/100 responses; source mismatch and AEAD tamper rejected.
- Standard sdist and wheel build: passed.
- Import and version check directly from the built wheel: passed.

## Security and protocol coverage

- ChaCha20-Poly1305 plaintext confidentiality and round trip;
- different ciphertext for different sequence-derived nonces;
- header and ciphertext tamper rejection;
- encrypted acknowledgement payloads;
- timestamp, tunnel-id, frame-kind, length, and fragment validation;
- replay rejection within one process session;
- one-sided restart and retired-session rejection;
- atomic replay-state restore and fail-closed corrupt-state handling;
- expected outer-source and exact inner-peer checks.

## Reliability coverage

- MTU-safe encrypted frames with 1200-byte plaintext fragments;
- reassembly of a 60000-byte application datagram;
- one-fragment loss recovery using XOR parity FEC;
- two-fragment loss waiting for retransmission;
- ACK completion, timeout retransmission, retry exhaustion, and duplicate-delivery suppression;
- delay, jitter, loss, duplication, reordering, complete downlink outage, recovery, and 1000-message stress.

## Final lab summary

- Clean: 100/100 delivered, no retransmission or exhausted retry.
- Impaired: 200/200 delivered despite 47 uplink drops, 22 downlink drops, 33 injected duplicates, and reordering. 68 frames were retransmitted; no message exhausted its retry budget.
- Outage: 0/10 while downlink was disabled; 30/30 after recovery. Previously queued messages were also acknowledged after restoration.
- Stress: 1000/1000 delivered; 2000 frames in each direction including ACKs, no retry exhaustion.
- FEC: one selected fragment dropped, 1/1 message recovered with no retransmission.
- Boundary: 5/5 messages of 60000 bytes delivered; a 60001-byte message was rejected and counted.

## Environment boundary

The release workstation does not provide Linux systemd, iproute2, or iptables. Their scripts are covered by contract tests and GitHub CI shell parsing; actual routing, firewall, service-manager, provider source validation, and public endpoints require an acceptance test on the operator's authorized Linux hosts.

No forged-source transmission or third-party address was tested.
