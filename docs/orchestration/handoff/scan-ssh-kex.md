# scan-ssh-kex — handoff (plan_id w1-6f3a)

Catalog rows built: `ssh-algorithm-advertisement`, `post-quantum-ssh-kex`. Not built: `ssh-host-key-reuse` (see "Not done").

## Discovery
- Before: on an SSH port `probe.mjs` read the greeting (up to readMs / 16 KB), then `sock.end(SSH_IDENT + "\r\n")` and closed.
- An SSH server sends `SSH_MSG_KEXINIT` (RFC 4253 7.1) either right after its identification line or, like OpenSSH, once it has the
  client's identification line. The KEXINIT is plain (no encryption, no MAC before NEWKEYS) and carries only algorithm NAMES:
  kex, host-key, cipher c2s/s2c, MAC c2s/s2c, compression c2s/s2c, language c2s/s2c. It does NOT carry the host key.

## Design
- `scanner/lib/ssh-kex.mjs` (new, pure): `kexinitFrom(buf)` -> `{ kex }` | `{ need: true }` | `{ error }`; `parsePacket`,
  `parsePayload`; frozen `WEAK` (exact names, per category, severity + reason) and `PQC_KEX`; `weakOf`, `sshKexInfo`,
  `sshKexObservations`. Bounds: packet length 67..16384, padding >= 4, each name-list <= 4096 bytes printable ASCII, at most
  64 names of at most 64 chars per list. Never throws.
- `probe.mjs` (minimal hook): if the greeting is SSH and the KEXINIT is not already in it, `sock.write(SSH_IDENT + "\r\n")`
  (the same bytes as before), then a second bounded read (readMs, remaining of maxBytes) on the same socket that stops as soon
  as a whole KEXINIT has arrived, then `sock.end()`. If the KEXINIT came with the greeting, or the server already closed, the old
  `sock.end(SSH_IDENT + "\r\n")` path is used. `readFor` got an optional `enough(bytes)` predicate. Result: `out.ssh_kex`.
  The existing hard timer (connect + 2 x read + 1 s) already covers both reads.
- `scan.mjs` (hook): observations from `sshKexObservations`, and `h.ssh[] = { port, kex, hostkey, ciphers, macs, compression,
  strict_kex, pqc, weak }`; the report's host gets `ssh` only when present (input for scan-cbom later).
- Observation kinds: `ssh-weak-kex`, `ssh-weak-hostkey`, `ssh-weak-cipher`, `ssh-weak-mac` (one per category, highest severity of
  the names found, every name listed with its reason), `ssh-pqc-kex` (severity info).

### Frozen weak set (exact names)
| Category | Name | Severity |
|---|---|---|
| kex | diffie-hellman-group1-sha1, rsa1024-sha1, gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g== | high |
| kex | diffie-hellman-group14-sha1, diffie-hellman-group-exchange-sha1, gss-gex-sha1-…, gss-group14-sha1-… | medium |
| host key | ssh-dss, ssh-dss-cert-v01@openssh.com | high |
| host key | ssh-rsa, ssh-rsa-cert-v01@openssh.com | medium |
| cipher | none, des-cbc, 3des-cbc, blowfish-cbc, cast128-cbc, arcfour, arcfour128, arcfour256 | high |
| cipher | aes128-cbc, aes192-cbc, aes256-cbc, rijndael-cbc@lysator.liu.se | medium |
| MAC | none | high |
| MAC | hmac-md5, hmac-md5-96, hmac-md5-etm@openssh.com, hmac-md5-96-etm@openssh.com | medium |
| MAC | hmac-sha1-96, hmac-sha1-96-etm@openssh.com | low |

PQC / hybrid (information): mlkem768x25519-sha256, mlkem768nistp256-sha256, mlkem1024nistp384-sha384, sntrup761x25519-sha512,
sntrup761x25519-sha512@openssh.com, sntrup4591761x25519-sha512@tinyssh.org.

## Not done / follow-ons
- `ssh-host-key-reuse`: the host key is only in the server's KEX reply (KEXDH_REPLY), which needs the client to send its own
  KEXINIT and a KEX init. That crosses the rail (no client KEXINIT/KEX), so it is not built. It would need an owner decision.
- Terrapin (CVE-2023-48795) exposure could be read from the same lists (chacha20-poly1305 or -etm MACs without
  `kex-strict-s-v00@openssh.com`); `strict_kex` is recorded but no observation is made. Not requested; left for a Design.
- Absence of PQC kex is recorded (`pqc: []` in `h.ssh`) but not turned into an observation.

## Doc text for docs/scanner.md (what it sends / reads)
> **SSH.** After reading the server's greeting the scanner sends its identification line (unchanged) and then reads, on the same
> connection, the server's algorithm list (SSH_MSG_KEXINIT), at most 4 seconds and 16 KB, and closes. It never sends a KEXINIT of
> its own, never starts a key exchange and never logs in. The report lists, per SSH port, the advertised key-exchange, host-key,
> cipher and MAC algorithms; observations flag a fixed list of weak ones (SHA-1 key exchange, DSA and SHA-1 RSA host keys, CBC,
> 64-bit block and RC4 ciphers, MD5 and 96-bit SHA-1 MACs) and note post-quantum hybrid key exchanges (ML-KEM, sntrup761) as
> information. "Offers" is not "uses": a modern client picks a strong algorithm first.

## Doc text for scanner/README.md ("what it reads")
> - SSH: the identification line and the server's advertised algorithms (KEXINIT), on the same connection; weak algorithms
>   from a fixed list are reported, post-quantum key exchange is noted. The scanner does not do a key exchange, so it does not
>   see the host key.
