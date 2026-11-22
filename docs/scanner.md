# The CyberView Scanner (scanner/)

A command-line tool an operator downloads and runs against their **own, authorized** network to find known-vulnerable
software and rank what to patch first. Approved by the owner on 2026-11-21 as a detection and prioritization tool. The
operator's guide, with the authorization notice and the exact network behaviour, is `scanner/README.md`; the site offers
the tool in the Vulnerabilities page's "My software" view (`vulnerabilities.html#scanner`). Mechanical code only, no AI
model, Node's standard library only, nothing scheduled (no `routines.json` entry).

## Design limits (the product, not options)

The scanner detects; it never attacks. These hold for the code, the tests, the fixtures and the docs:

- No exploitation, payloads, injection strings or crafted input beyond reading a greeting, one request for a web
  server's root page and a TLS handshake. No check that works by triggering a flaw.
- No credentials of any kind: no logins, password guessing or spraying, hash capture or cracking.
- No denial of service, flooding or amplification: politeness limits whose defaults are also their ceilings
  (`scanner/lib/limits.mjs` CAPS, frozen), no UDP or raw sockets, no "fast" mode.
- No evasion: ordinary TCP connections only, an honest User-Agent and SSH identification line, no spoofing.
- No scanning outside the operator's scope file; no wide public sweeps (public ranges at most a /24, at most 1,024 public
  addresses per scan, and only with `--i-am-authorized-for-public-ranges`).
- Nothing is uploaded. The only outbound requests besides the targets are read-only GETs for CyberView's own published
  data files (`ALLOWED` in `scanner/lib/data.mjs`), and only with `--online` or `data`.
- Write-ups follow the NOCODE rule in `scripts/lib/validate.mjs`: no attack commands or payloads anywhere.

`scripts/security-check.mjs` (section 7) fails CI if scanner code starts processes, opens UDP or raw sockets, sends a
POST, PUT, PATCH or DELETE, evaluates text as code, offers an aggressive or unlimited mode, connects to targets anywhere
but `scanner/lib/probe.mjs`, or raises the ceilings. `tests/unit/scanner.test.mjs` checks the scanner, its docs and its
fixtures for NOCODE's attack patterns.

## Files

| File | What it does |
|---|---|
| `scanner/cyberview-scan.mjs` | the command line: `init`, `check`, `data`, `scan`; the authorization gate runs before anything else |
| `scanner/lib/scope.mjs` | the scope file, the attestation (exact `STATEMENT`), address kinds, CIDR expansion, `gate()`; pure |
| `scanner/lib/limits.mjs` | rate, concurrency, per-host and global budgets, the time limit; `settings()` refuses values above a ceiling |
| `scanner/lib/probe.mjs` | the only network code that touches targets: connect, read a greeting, SSH identification, one root-page request, TLS handshake |
| `scanner/lib/fingerprint.mjs` | banners, headers and certificates to product, vendor and version (NVD's CPE names); pure |
| `scanner/lib/data.mjs` | CyberView's data online (GET, allowlisted paths) or from a snapshot folder; `snapshot()` for air-gapped use |
| `scanner/lib/shared.mjs` | loads `site/workbench-lib.js` and `site/cvedb-lib.js` unchanged, as `scripts/cve.mjs` does |
| `scanner/lib/match.mjs` | services to findings with the site's `matchFlaw`, rated with the site's `score` and `rate`, ranked |
| `scanner/lib/scan.mjs` | resolve and gate the scope, probe politely, fingerprint, assemble the report |
| `scanner/lib/report.mjs` | the run header, JSON, CSV (formula-safe), SARIF 2.1.0, the inventory CSV, the text summary |

## One answer, on the site and in the scanner

Matching and rating are not reimplemented. `site/workbench-lib.js` holds `cleanRange`, `matchFlaw` (version ranges first,
name-only flaws as "check"), `cmp`, `inRange`, `nameHit` and the patch-queue `score`; the Vulnerabilities page and the
scanner both call them. `site/cvedb-lib.js` holds the lookup rows (`cleanRow`, `parseFile`), the CyberView rating
(`score`: CVSS base x CVSS v3.1 Exploit Code Maturity) and CISA's SSVC priority (`rate`, with BOD 26-04 timelines). The
scanner rates each finding from its CVE lookup row, with vendor advisories attached as the page attaches them; if the
lookup file is missing it rates from the KEV entry and says so in the finding. The unit tests compare the scanner's
answers with the libraries loaded independently.

A finding's exposure answer for SSVC comes from the address: a public address counts as exposed, a private one as
internal.

## Ranking and confidence

Known exploited (KEV) first, then other exploitation evidence (CISA's SSVC, the vendor's advisory, the CVE record), then
past CISA's deadline; within those, version-confirmed before product-only, then the CyberView rating, the SSVC priority,
the nearest deadline and EPSS. Confidence: high when the service stated a version inside an affected range; medium for a
distribution package build (backports) or an inferred product; low when the version could not be read or no range
exists.

## Fix information

Each finding carries the fixed versions (the ends of NVD's ranges and the guide's `fixed` list), the guide's workarounds,
CISA's required action, the vendor advisory link and the CVE's CyberView page. A guide's check steps, signs of
compromise and hunt resources, and exploitation analyses, are linked, never copied (indicators of compromise stay on the
page that cites them). AI-written material is labelled "CyberView AI (a Claude model)".

## Deliberately left out

Credentialed (authenticated) scanning, UDP and SNMP probing, protocol commands beyond the greeting (for example Redis or
database queries), following redirects, crawling, vulnerability checks that send test input, operating-system
fingerprinting from packet quirks, and any upload of results. Each would either cross the limits above or add risk
without changing the finding much; version matching against published data is the whole method.

## Tests

`tests/unit/scanner.test.mjs` (in `npm run unit`): the gate (no scope, bad attestation, out of scope, excluded, public
without the flag, too-wide ranges), the fingerprint parsers on real-format banners (`tests/fixtures/scanner/banners.json`),
matching and rating against the site's libraries, the CSV, SARIF and inventory exports, the limits and budgets, offline
and online data (with a stand-in fetch), Ctrl-C, and an end-to-end scan of stand-in services on 127.0.0.1
(`tests/fixtures/scanner/servers.mjs`) that records every byte the scanner sends. No test contacts a real host. The
snapshot under `tests/fixtures/scanner/snapshot/` uses invented CVE ids (CVE-2026-90xxx) and is marked as test data.
