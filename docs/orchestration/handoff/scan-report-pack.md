# Handoff: scan-report-pack — certificate inventory, mail STARTTLS, KEV coverage gap, scan diff

Covers build items `scan-cert-inventory`, `scan-mail-starttls`, `scan-kev-coverage`, `tk-diff` (and records why
`scan-snmp-sysdescr` was not built). Wave 2, plan `w2-7c1e`. All four work on data the scan already holds or on local
files: no new connection, request, hello or datagram.

## Discovery → Design
- **Need:** defenders want the certificates they expose in one table (reuse, internal names, wildcards), to know which
  mail services advertise STARTTLS, to see which known-exploited products the scanner cannot identify, and to compare
  one scan with the last (new / fixed / still open).
- **Constraints:** detection only; no extra bytes to any target; outputs opt-in (the default five files are unchanged);
  the `--compare` file is untrusted input; inventory, not findings (headline counts and observations unchanged).
- **Prior art:** RFC 6962 (embedded SCT list, OID 1.3.6.1.4.1.11129.2.4.2), RFC 7633 (TLS Feature / must-staple, OID
  1.3.6.1.5.5.7.1.24, status_request = 5), RFC 5280 subjectAltName, RFC 9051/3501 §7.1 (IMAP CAPABILITY response code in
  the greeting), RFC 6762/6761/8375 (.local, .localhost, .home.arpa).
- **Data that exists:** the leaf certificate's DER (`cert.raw`) from the one TLS handshake, SAN text, fingerprint256 (from
  tk-hygiene); the greeting's first line in `hosts[].ports[].banner`; `data/workbench.json` in a local snapshot; the
  fingerprint tables in `fingerprint.mjs`.
- **Risks / out of scope:** SCTs sent in the TLS handshake or by OCSP stapling are not visible to Node's client without
  asking for them (not done); SMTP/POP3 capabilities need EHLO/CAPA (not sent); SSH host keys are never collected.

## Design → Implementation
- **Modules (pure, no network):** `scanner/lib/cert-inventory.mjs`, `scanner/lib/mail-starttls.mjs`,
  `scanner/lib/kev-coverage.mjs`, `scanner/lib/diff.mjs`.
- **Hooks:** `scan.mjs` stores `certRecord(r.tls.cert)` instead of `certInfo(...)` (certInfo's fields plus `serial`,
  `spki_sha256`, `san_dns[]`, `san_ip[]`, `sct`, `must_staple`, read from the DER already received); `fingerprint.mjs`
  exports `FINGERPRINT_TABLES` (read-only, for the coverage report); `cyberview-scan.mjs` gains `--certs`, `--mail`,
  `--compare FILE` and the `coverage` command.
- **Outputs:** `certs.csv` (`--certs`), `mail.csv` (`--mail`), `diff.json` + `diff.txt` (`--compare`), and
  `coverage --data DIR [--out kev-coverage.csv]`. The `--compare` file is read and validated before anything is scanned.
- **Fixed rules:** short-lived = validity of 10 days or less; internal names = single-label names and the suffixes
  `.local .localhost .localdomain .internal .intranet .lan .corp .private .home.arpa`; internal addresses = private
  (RFC 1918 / ULA), loopback, link-local (scope.mjs `classify`). Reuse groups: same certificate (fingerprint) on 2+
  addresses; same public key in different certificates; same issuer+serial in different certificates. `one_name` marks a
  group whose addresses share an attested name (likely one host with several addresses). Wildcard coverage and "SAN
  names beyond the attested names" are computed only when the host was scanned by name (`h.names` known).
- **Diff semantics:** fixed only when the same host:port answered again and the CVE no longer matched; "gone" when the
  port no longer answers (not proof of a fix); "not rechecked" when the host was absent or down, the port was not in the
  port list, or a limit/interruption left the host partly unchecked. Issuer change is flagged for review, never as a
  compromise. The previous file: must parse as JSON with `tool.name = "CyberView Scanner"`, at most 64 MB; only compared
  fields are kept, each type-checked and clipped.
- **Safety-model check:** no file in the pack opens a socket, sends a request or spawns a process; security-check §7 green
  (17 scanner files). No body, cookie or secret is stored: certificate identifiers are public hashes and serials.
- **Tests:** `tests/unit/scanner-reportpack.test.mjs` (13 tests), fixtures `tests/fixtures/scanner/reportpack/der.mjs`
  (certificates built at test time). No-extra-bytes proofs: the stand-in probe sees the identical host:port list with
  and without `--certs --mail --compare`; the loopback TLS service sees one connection; the `coverage` command never
  probes or fetches; a bad `--compare` file is refused before any probe.

## Not built (catalog IDs)
- `snmp-sysdescr-product-parsing` (`scan-snmp-sysdescr`): no reviewed sysDescr-to-CPE mapping exists in the catalog row
  or a Design, and the row forbids inventing a version pattern. Needs a reviewed list (vendor format → CPE, version
  rule) in a Design; the plumbing would then be a `fromUdp` branch for `proto === "snmp"`.
- `open-mail-relay-advertisement`: the row names no concrete greeting text; any pattern would be invented. Relay
  testing itself is rejected (§9).
- `unexpected-ssh-host-key-change`: the scanner never collects an SSH host key (the banner only; even `scan-ssh-kex`'s
  KEXINIT carries no host key). Would need a separately approved collection step.
- Handshake/OCSP SCTs (part of `certificate-transparency-scts`): only SCTs embedded in the certificate are reported.
- SMTP/POP3 STARTTLS (part of `starttls-capability`): needs EHLO/CAPA on the same connection — a later, separately
  approved slice. Reported as "not checked", never as absent.

## Doc text to add

### docs/scanner.md (outputs section)
> **Report pack (opt-in, no extra traffic).** `--certs` writes `certs.csv`: every leaf certificate this scan's one TLS
> handshake returned, with validity, key, signature, SHA-256 fingerprint, serial, public-key hash, SAN count, wildcards,
> internal names (single-label, `.local`, `.internal`, `.corp` … and private/loopback/link-local IP SANs), SCTs embedded
> in the certificate, OCSP must-staple, and reuse (the same certificate, public key or issuer+serial on more than one
> address). `--mail` writes `mail.csv`: mail services found, implicit TLS, STARTTLS as far as the greeting shows it (an
> IMAP greeting's capability list; SMTP and POP3 need EHLO/CAPA, which is not sent, so they read "not checked"), and an
> SMTP service on port 25 with no submission port. `--compare PREVIOUS/report.json` writes `diff.json` and `diff.txt`:
> findings new, fixed (the same port answered and the CVE no longer matches), gone with their port, still open and not
> rechecked; services and versions changed; certificates changed (issuer change flagged for review, not as compromise);
> observations new and resolved. `coverage --data DIR [--out kev-coverage.csv]` compares the snapshot's KEV catalog with
> the scanner's fingerprint tables (no scope, no network) and lists the products the scanner cannot identify.
> report.json's `hosts[].tls[].cert` also carries `serial`, `spki_sha256`, `san_dns`, `san_ip`, `sct`, `must_staple`.

### scanner/README.md (options list)
> - `--certs` adds `certs.csv` (certificate inventory and reuse), `--mail` adds `mail.csv` (STARTTLS from greetings
>   already read), `--compare old/report.json` adds `diff.json` and `diff.txt` (what changed since that scan). None of
>   them sends anything more to your hosts.
> - `node scanner/cyberview-scan.mjs coverage --data cyberview-data --out kev-coverage.csv` lists the known-exploited
>   products this scanner cannot fingerprint yet (offline; no scope needed).

## Implementation → Review
- **Branch/commit:** see the commit tagged `[scan-report-pack]` on this worktree's branch (not pushed).
- **Follow-ups:** fingerprints added by other wave modules (outside `FINGERPRINT_TABLES` / `INLINE`) are not counted by
  the coverage report until they register there; a scheduled re-scan + alert (the "watch" half of `tk-diff`) is not built.
