# Handoff: scan-ssh-kex — SSH algorithm advertisement

## Discovery → Design
- **Need:** flag weak SSH algorithms and record post-quantum names the server advertises.
- **Constraints:** same connection, bytes sent stay the identification line, no client key exchange, no auth.
- **Recommendation:** build.

## Design → Implementation
- After the banner, read `SSH_MSG_KEXINIT` and stop. Weak set: SHA-1 key exchange, CBC and 3DES ciphers, SHA-1 and MD5 MACs. `mlkem`, `sntrup`, `kyber` names are recorded as advertised, not as proof of what an older client would negotiate.
- Host-key reuse is not collected. The host key is the next message, and reading it means sending our own key exchange, which this item forbids.

## Implementation → Review
- Loopback test: weak set and `mlkem768x25519` observed; the server receives only the identification line; a banner with no second message returns cleanly.
