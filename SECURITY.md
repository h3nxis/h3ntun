# Security boundary

- This project is for systems and addresses the operator owns or is explicitly authorized to test.
- The live runtime uses kernel-enforced UDP source binding only. It does not transmit forged-source raw packets.
- The framing authenticates packets with HMAC-SHA256 and rejects stale or replayed frames; it does not encrypt payloads.
- Wire protocol version 2 authenticates a random per-process session id so a one-sided restart can safely begin with a lower sequence number. Both peers must run the same wire version.
- Configure `expected_inner_peer` when the Iran-side application has a fixed source port. The foreign-side inner peer is always source-pinned.
- Keep health endpoints on loopback and protect configuration files because they contain the shared secret.
- Restrict the two public UDP ports with the host firewall and provider firewall.
- Rotate both `tunnel_id` and `shared_secret` after suspected disclosure.
- Do not expose the echo command as a permanent public service.
