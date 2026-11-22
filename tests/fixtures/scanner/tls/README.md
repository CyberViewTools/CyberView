# Test-only TLS fixtures

Self-signed certificates and their private keys, generated once for `tests/unit/scanner.test.mjs` and the loopback
stand-in TLS service (`startTlsServer` in `../servers.mjs`). They protect nothing and are never used outside the tests.

- `weak-*`: RSA 1024-bit key, SHA-1 signature, CN/SAN `weak.fixture.test` (exercises `tls-weak-key` and `tls-weak-signature`)
- `good-*`: ECDSA P-256 key, SHA-256 signature, SAN `good.fixture.test` and `*.apps.fixture.test`

Both are valid for 100 years so the tests do not start failing on a date; expiry is tested with an injected clock.
