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
- No denial of service, flooding or amplification: politeness limits whose rate and open-at-once defaults are also their
  ceilings (`scanner/lib/limits.mjs` CAPS, frozen), no raw sockets, no "fast" mode. The UDP checks send exactly one benign
  datagram per service per host (no retransmit storm); raw sockets are never used (node `dgram` only, in one file).
- No credentials or credential iteration: no logins, no password or community-string guessing. The SNMP check uses only the
  single standard read community `public`; no other community is ever tried.
- No evasion: ordinary TCP connections and single UDP datagrams only, an honest User-Agent and SSH identification line, no
  spoofing.
- No scanning outside the operator's scope file. Discovery (below) can only narrow the attested scope, never widen it: every
  host it finds is re-checked by the gate. No wide public sweeps (public ranges at most a /24, at most 1,024 public addresses
  per scan — the hard stop — and only with `--i-am-authorized-for-public-ranges`).
- Nothing is uploaded. The only outbound requests besides the targets are read-only GETs for CyberView's own published
  data files (`ALLOWED` in `scanner/lib/data.mjs`, with `--online`/`data`) and, when `discover.ct` is set, read-only GETs to
  the Certificate Transparency source (`crt.sh`) for the operator's own attested domains.
- Write-ups follow the NOCODE rule in `scripts/lib/validate.mjs`: no attack commands or payloads anywhere.

`scripts/security-check.mjs` (section 7) fails CI if scanner code starts processes, opens a raw socket, opens a UDP socket
(`dgram`) anywhere but `scanner/lib/udp.mjs`, sends more than one UDP datagram per service per host (a loop or timer in
`udp.mjs`), iterates SNMP community strings, sends a POST, PUT, PATCH or DELETE, evaluates text as code, offers an
aggressive or unlimited mode, makes a TCP connection to a target anywhere but `scanner/lib/probe.mjs`, raises the rate /
open-at-once ceilings, or lets the private budget scaling touch those ceilings. `tests/unit/scanner.test.mjs` checks the
scanner, its docs and its fixtures for NOCODE's attack patterns and exercises each of these rules.

## Files

| File | What it does |
|---|---|
| `scanner/cyberview-scan.mjs` | the command line: `init`, `check`, `data`, `scan`; the authorization gate runs before anything else |
| `scanner/lib/scope.mjs` | the scope file, the attestation (exact `STATEMENT`), address kinds, CIDR expansion, `gate()`; pure |
| `scanner/lib/limits.mjs` | rate, concurrency, per-host and global budgets, the time limit; `settings()` refuses values above a ceiling |
| `scanner/lib/probe.mjs` | the only TCP network code that touches targets: connect, read a greeting, SSH identification, one root-page request, TLS handshake |
| `scanner/lib/udp.mjs` | the only file that opens a UDP socket (`dgram`): one benign read-only datagram per service per host (DNS, NTP, SNMP); exactly one `send`, no loop |
| `scanner/lib/udp-codec.mjs` | pure UDP query builders and response parsers (version.bind TXT, NTP mode-6 read, SNMPv1 GET sysDescr with community `public`); no sockets |
| `scanner/lib/discover.mjs` | discovery sources: asset-list/CSV/nmap-XML parsing, read-only cloud inventory parsing, and Certificate Transparency lookup; candidates are re-gated by the scope |
| `scanner/lib/fingerprint.mjs` | banners, headers, certificates and UDP answers to product, vendor and version (NVD's CPE names); pure |
| `scanner/lib/data.mjs` | CyberView's data online (GET, allowlisted paths) or from a snapshot folder; `snapshot()` for air-gapped use |
| `scanner/lib/shared.mjs` | loads `site/workbench-lib.js` and `site/cvedb-lib.js` unchanged, as `scripts/cve.mjs` does |
| `scanner/lib/match.mjs` | services to findings with the site's `matchFlaw`, rated with the site's `score` and `rate`, ranked |
| `scanner/lib/scan.mjs` | run discovery, resolve and gate the scope (with the public-cap stop), probe politely over TCP and UDP, fingerprint, assemble the report |
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

## Discovery: "find the hosts for me", within the attested scope

An optional `discover` block in the scope file lets the operator avoid hand-listing every host. It never widens the scope:
every address a source yields is re-checked by the same gate as a listed target (out of scope, or public without the flag
and under the cap, means dropped and logged), so discovery can only narrow the attested scope down to the live hosts.

| Source | What it does and exactly what it contacts/reads |
|---|---|
| `cidr` | sweeps the attested CIDR ranges for live hosts (the existing liveness check expands the ranges; no new network behaviour) |
| `domains` | resolves the attested owned domains with the system resolver. With `ct`, it also reads the domain's subdomains from Certificate Transparency: one read-only `GET https://crt.sh/?q=%25.<domain>&output=json` per domain (the documented public JSON endpoint; `redirect: error`, the scanner's User-Agent). Only domains the operator attests they own. |
| `import` | reads an asset list from disk: a plain host/IP list, a CSV (a column named host/ip/address/name/fqdn/dns…), or nmap `-oX` XML. No network; the file is parsed for hosts and addresses. |
| `cloud` | reads the JSON the operator's **own read-only** cloud command printed — `aws ec2 describe-instances`, `aws elbv2 describe-load-balancers`, `gcloud compute instances list --format=json`, `az network public-ip list` / `az vm list-ip-addresses` — and extracts the public IPs and DNS names. **The scanner never runs the cloud CLI and never asks for, reads or stores cloud keys**: the operator runs the read-only command with their own local credentials and points `cloud` at the saved file. (This keeps the no-process-spawning rule; live enumeration from inside the scanner is deliberately not done.) |

An attested domain also authorises its subdomains for the gate (a resolved subdomain inside the attested domain is in
scope; a public one it resolves to still needs `--i-am-authorized-for-public-ranges` and counts against the public cap).

## Depth: more ports and read-only UDP checks

- `--all-ports` scans every TCP port (1–65535). It is allowed **only for owned private ranges** (it refuses a scope with
  any public address). For a private-only scan the per-host and total connection budgets scale (`PRIVATE_CAPS`) so a large
  own-network sweep is not artificially blocked; the rate (20/s) and the time ceiling still bound the work. Any scan that
  includes a public address keeps the strict public budgets (300 per host, 20,000 total).
- `--udp` adds three read-only UDP service checks, each a **single standard benign query** per service per host, no
  retransmit: DNS `version.bind` CHAOS TXT (53), NTP mode-6 read-variables (123), and one SNMPv1 GET of `sysDescr`
  (1.3.6.1.2.1.1.1.0) with the standard read community `public` only (161). No other UDP, no raw sockets (node `dgram`),
  no other community, no iteration. A BIND or ntpd version becomes a matchable service; an SNMP agent answering `public`
  is reported as an observation with its `sysDescr`.

## Deliberately left out

Credentialed (authenticated) scanning; password, community-string or any credential guessing; protocol commands beyond the
greeting and the three benign UDP queries (for example Redis or database queries, SNMP writes or walks); following
redirects; crawling; vulnerability checks that send test input; operating-system fingerprinting from packet quirks; running
the cloud CLI from inside the scanner; and any upload of results. Each would either cross the limits above or add risk
without changing the finding much; version matching against published data is the whole method.

## Tests

`tests/unit/scanner.test.mjs` (in `npm run unit`): the gate (no scope, bad attestation, out of scope, excluded, public
without the flag, too-wide ranges), the fingerprint parsers on real-format banners (`tests/fixtures/scanner/banners.json`),
matching and rating against the site's libraries, the CSV, SARIF and inventory exports, the limits and budgets, offline
and online data (with a stand-in fetch), Ctrl-C, and an end-to-end scan of stand-in services on 127.0.0.1
(`tests/fixtures/scanner/servers.mjs`) that records every byte the scanner sends. No test contacts a real host. The
snapshot under `tests/fixtures/scanner/snapshot/` uses invented CVE ids (CVE-2026-90xxx) and is marked as test data.
