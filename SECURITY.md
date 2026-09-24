# Security policy

## Design boundary

- The live runtime uses kernel-enforced UDP source binding and does not transmit forged non-local source packets.
- Wire protocol 3 encrypts and authenticates each frame with ChaCha20-Poly1305.
- HKDF-SHA256 derives the AEAD key from the shared secret and tunnel id.
- Nonces are deterministically derived from the random process session, global sequence, frame kind, flags, and fragment index. A sequence is never intentionally reused within a session.
- The full cleartext header is authenticated as AEAD associated data.
- Replay state is written atomically before an accepted frame is processed. Missing, corrupt, wrong-tunnel, or wrong-format state fails closed.
- Exact observed outer sources and local application peers can be allowlisted.
- Queues, reassembly tables, retry counts, fragment size, and message size are bounded.

## Operator requirements

- Generate at least 32 random bytes for `shared_secret`; do not reuse deployment examples.
- Give each tunnel a unique random `tunnel_id` and secret.
- Protect `/etc/h3ntun/config.json` and `/var/lib/h3ntun/*` from other users.
- Use distinct replay-state files for distinct agents.
- Keep system time synchronized and rotate both the tunnel id and secret after suspected disclosure.
- Keep the `cryptography` dependency and operating system patched.
- Bind the health endpoint to loopback or a protected management network.
- Use only addresses and routes you own or are authorized to operate.

## Reporting

Do not include production secrets, addresses, packet captures, or customer data in a public issue. Reproduce security reports with loopback placeholders and a newly generated test secret.
