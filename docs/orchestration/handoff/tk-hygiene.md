# Handoff: tk-hygiene — TLS, header and default-page hygiene

## Discovery → Design
- **Need / user story:** A scan already holds a TLS handshake, the response headers and the `GET /` body, but
  `observations()` flagged only expired or self-signed certificates and cleartext FTP/Telnet. A defender wants the
  hygiene faults hiding in data the scan already collected (weak TLS, weak certificates, missing security headers, default
  and debug pages, downgrade redirects) without a second tool or any extra traffic. This is also crypto-lane step 1.
- **Constraints:** detection only; **zero extra connections or requests** (no extra hello, no OPTIONS, no path); `CAPS`
  unchanged; no `child_process`/`openssl`; never store response bodies; a sourced distrust list only (no live reputation
  query); section 7 of `scripts/security-check.mjs` stays green.
- **Prior art / standards:** RFC 8996 (TLS 1.0/1.1 retired), RFC 6125 (name matching), CA/B Forum baseline
  (SHA-1, RSA ≥ 2048), OWASP Secure Headers Project (HSTS, CSP, X-Content-Type-Options, X-Frame-Options/`frame-ancestors`,
  Referrer-Policy, Permissions-Policy), RFC 6265 cookie attributes.
- **Data / APIs that exist:** `tls.TLSSocket` `getProtocol()`, `getCipher()` (`name`, `standardName`),
  `getEphemeralKeyInfo()`, `getPeerCertificate()` (`bits`, `nistCurve`, `fingerprint256`, `raw`). Node 22 does **not**
  expose the signature or public-key algorithm, so a bounded DER reader is needed. `getEphemeralKeyInfo()` returns `{}`
  when a hybrid post-quantum group (X25519MLKEM768, offered by default by Node 22's bundled OpenSSL 3.5) is negotiated.
- **Feasibility / risks:** results describe one client's handshake, not the server's full configuration (stated in the
  report). The scanner sends no ALPN, so HTTP/2 is visible only through `Alt-Svc`. Session-ticket/resumption needs a
  second handshake: out of scope. A distrusted-issuer list must be sourced before it ships.
- **Recommendation:** build, in two PRs (TLS first, then HTTP/mail).

## Design → Implementation
- **Interfaces / CLI:** no new flags. `observations(port, { banner, cert, tls, names, now })` (was `{ banner, cert, now }`);
  PR 2 adds `http` and an `inScope(host)` predicate for redirect checks. Each observation is
  `{ port, kind, severity: high|medium|low|info, text }`.
- **Data model:** `hosts[].tls[]` gains `cipher_std, kex_type, kex_group, kex_bits, kex_note, pqc` and `cert` gains
  `not_yet_valid, days_left, key_type, key_bits, curve, sig_alg, sig_hash, fingerprint256` (the DER itself is never
  written to the report). `hosts[].observations_dropped` counts any over the 60-per-host cap.
- **Safety-model check:** every new check reads the existing handshake or response; `SENDS` unchanged; the loopback test
  asserts a TLS service sees exactly one connection; no body text is copied into evidence (PR 2 stores only the matched
  marker name).
- **Test plan:** DER reader on fixture certificates (RSA-1024/SHA-1, P-256/SHA-256) and on truncated/garbage input; pure
  observation tests with an injected clock (expiring, not-yet-valid, weak key, weak signature, name mismatch with
  wildcards and IP literals, retired protocol, weak cipher, weak DH, RSA key exchange, unreported group); a loopback TLS 1.3
  service and a TLS 1.2 DHE-1024 service through `probePort`, each asserting one connection; summary ordering. Test
  certificates are made at test time (`tests/fixtures/scanner/certgen.mjs`): no private key is committed.
- **PR plan:**
  1. `[tk-hygiene] TLS and certificate hygiene` — persist the TLS/cert fields, `certAlgorithms()`, `tlsInfo()`,
     RFC 6125 name matching, the TLS observations, severities, the per-host cap, the TLS lines in `summary.txt`.
  2. `[tk-hygiene] HTTP and mail hygiene` — from the collected `GET /` only: missing HSTS (HTTPS only), CSP
     (missing, or `unsafe-inline`/`unsafe-eval`), X-Content-Type-Options, X-Frame-Options/`frame-ancestors`,
     Referrer-Policy (missing or `unsafe-url`), Permissions-Policy; cookies without `Secure`/`HttpOnly`; CORS `*`;
     default welcome and setup-wizard titles (a fixed, cited title list); debug markers by name only (Django debug page,
     stack-trace footers, `X-Debug-Token`); a directory listing; an `http://` Location from HTTPS and an out-of-scope
     redirect host (recorded, never followed); a plain-HTTP site with no redirect to HTTPS; `Allow` naming TRACE/TRACK or
     WebDAV methods, and a `DAV` header (no OPTIONS request); HTTP/2 or HTTP/3 in `Alt-Svc`; a CDN/WAF front
     (`CF-Ray`, `X-Amz-Cf-Id`, `X-Akamai-*`, `X-Sucuri-ID` …); `Date` clock skew over 5 minutes; a Server header carrying
     a distribution patch level; cleartext POP3/IMAP (110/143) and SMTP submission (587) greetings.

### Catalog rows (39) and where they land
| PR | Rows |
|---|---|
| 1 | certificate-key-size-and-signature, certificate-public-key-algorithm, tls-certificate-expiry-window, tls-protocol-version, tls-cipher-suite, weak-dh-or-export-residue-in-tls, post-quantum-tls-group (recorded honestly; "not reported" when Node cannot name it) |
| 2 | missing-or-weak-http-security-headers, content-security-policy-missing-or-unsafe, clickjacking-header-missing, mime-sniffing-header-missing, referrer-policy-missing-or-unsafe, permissions-policy-missing, cookie-without-secure-or-httponly, cors-wildcard-on-the-root-page, default-welcome-or-test-page, published-default-page-signature, setup-wizard-title-on-the-root-page, django-debug-page, stack-trace-or-debug-footer-on-the-root-page, x-debug-or-profiler-header, source-map-file-referenced, directory-listing-on-the-root-page, https-downgrade-redirect, http-to-https-redirect-missing, http-trace-or-track-advertised, webdav-advertised, http-2-advertised-in-alpn-or-alt-svc (Alt-Svc only), cdn-or-waf-in-front-of-the-origin, http-date-clock-skew, server-token-discloses-patch-level, cleartext-pop3-or-imap, cleartext-smtp-submission |
| deferred | http-server-header-missing-or-generic (a missing or generic Server header is good practice, not a fault; nothing to flag), sourced-distrusted-certificate-issuer (needs a sourced list), fortra-cobalt-strike and hostname-in-a-public-default-key-or-example-cert (need sourced fingerprints), session-ticket-or-tls-resumption (needs a second handshake), tls-alpn-protocol (the scanner offers no ALPN; changing the hello is a product-limit change) |

## Implementation → Review
- **PR 1:** `[tk-hygiene] TLS and certificate hygiene` — see the PR; `npm run unit` (scanner suite 53/53) and
  `security-check` green.
- **PR 2:** `[tk-hygiene] HTTP and mail hygiene` — `httpObservations()` and `mailObservations()`; the scope-aware redirect
  label (`probeAll({ inScope })`, from `hostInScope`/`inScope`); scanner suite 59/59, `security-check` green.
- **Open questions / follow-ups:** the sourced distrust list; whether `scan-cert-inventory` should reuse
  `fingerprint256` as its join key (it should); `scanner/README.md` still says a host is written off after the discovery
  ports, which #87 changed (left for the PR that next edits that section).
