# CyberView Scanner

> **Scan only systems you own, or systems whose owner has given you written permission to test.**
> Scanning other people's systems without permission may be unlawful where you are. The scanner will not start until you
> list your targets in a scope file and attest, in that file, that you are authorized. It prints your attestation and your
> scope at the start of every run and writes both into the report.

The CyberView Scanner finds known-vulnerable software on your own network and tells you what to patch first. It reads the
version each service states about itself (an SSH banner, a web server's `Server` header, a mail server's greeting, a TLS
certificate), matches it against CyberView's published data on known-exploited flaws (CISA's KEV catalog with NVD's
affected-version ranges), and ranks what it finds by the CyberView rating, the same calculation the
[Vulnerabilities page](https://xanderhutch.github.io/CyberView/vulnerabilities.html) uses.

It is a **detection tool**. It does not exploit anything, log in, guess or test passwords or SNMP community strings, send
crafted input, flood, hide what it is, or scan the internet at large. There is no "aggressive" setting. Mechanical code
only; no AI model runs in it.

It can also **find the hosts for you** within the scope you attest to — sweep your ranges, resolve and expand your own
domains, import an asset list, or read your own read-only cloud inventory — and scan **deeper**: every TCP port, and
read-only DNS, NTP and SNMP service checks. Every host discovery finds is re-checked against your scope before it is
scanned; nothing outside it is ever contacted.

## What you need

- Node.js 22 or later. Nothing to install: the scanner uses Node's standard library only.
- A copy of the CyberView repository (it reuses the site's own matching and rating code from `site/`):
  [download the ZIP](https://github.com/xanderhutch/CyberView/archive/refs/heads/main.zip) or clone it, then run the
  commands below from the repository's folder.

## Quick start

```
node scanner/cyberview-scan.mjs init --out scope.json        # 1. write a scope file
#   2. edit scope.json: owner, contact, targets; set attestation.agreed to true and attestation.name to your name
node scanner/cyberview-scan.mjs check --scope scope.json     # 3. check it; nothing is scanned
node scanner/cyberview-scan.mjs scan --scope scope.json --online
```

For an air-gapped network, download the data on a connected machine, carry the folder across, and scan offline:

```
node scanner/cyberview-scan.mjs data --out cyberview-data            # on a connected machine
node scanner/cyberview-scan.mjs scan --scope scope.json --data cyberview-data
```

`data --full` also downloads every CVE lookup file (about 300,000 CVEs). With a full snapshot the report adds, per
product, how many other CVEs in the CVE List name it; those carry no version ranges, so they are listed as leads to check,
never as findings.

## The scope file

```json
{
  "cyberview_scope": 1,
  "owner": "Example Ltd IT",
  "contact": "secops@example.org",
  "attestation": {
    "statement": "I own the systems listed in targets, or I hold written permission from their owner to scan them for known vulnerabilities, and this scan stays within that permission.",
    "agreed": true,
    "name": "Your Name",
    "date": "2026-11-21",
    "expires": "2027-05-21",
    "authorization_ref": "change ticket or engagement letter"
  },
  "targets": ["192.168.10.0/24", "10.20.0.5", "intranet.example.lan"],
  "exclude": ["192.168.10.1"],
  "ports": [22, 80, 443]
}
```

- `statement` must be copied exactly; `agreed` must be `true`; `name` and `date` are required. An attestation older than
  a year needs renewing unless `expires` says otherwise, and an expired one is refused.
- `targets` lists hosts, addresses and CIDR ranges. There is **no default**: nothing outside this list is ever contacted,
  and a host name is checked again after it resolves (an excluded or public address it resolves to is skipped).
- Limits that cannot be lifted: at most 65,536 addresses per scan; no IPv4 range wider than a /16; no IPv6 range wider
  than a /120; unspecified, multicast, broadcast and reserved addresses are refused.
- **Public addresses.** Private ranges (10/8, 172.16/12, 192.168/16, loopback, link-local and IPv6 fc00::/7) run with
  the scope file alone. Any other address is public: the scan also needs `--i-am-authorized-for-public-ranges`, prints a
  warning and waits ten seconds so you can cancel. Even then, a public range may be at most a /24 and a scan may include
  at most 1,024 public addresses. Use it only for addresses you own, such as your own internet-facing servers.
- `ports` is optional (the default is 22 common service ports). `--ports 22,80,8000-8010` overrides it;
  `--http-ports` and `--https-ports` name web services on non-standard ports. `--all-ports` scans every TCP port
  (1–65535) and is allowed **only for private ranges** you own (it refuses a scope with any public address).
- `--udp` adds read-only DNS, NTP and SNMP service checks (see "what goes over the network").

## Finding the hosts for you: `discover`

Add an optional `discover` block so you do not have to hand-list every host. It **never widens your scope**: every address
it finds is re-checked against `targets` (and the public rules) before anything is contacted, so it can only narrow your
attested scope down to the hosts that are actually there.

```json
"discover": {
  "cidr": true,
  "domains": ["example.com"],
  "ct": true,
  "import": [{ "file": "assets.csv" }, { "file": "scan.xml", "format": "nmap-xml" }],
  "cloud": [{ "file": "ec2.json", "provider": "aws-ec2" }]
}
```

- **cidr** — sweep the attested ranges for live hosts (the usual liveness check), then scan each.
- **domains** — resolve domains **you own**. With `"ct": true`, also read the domain's subdomains from Certificate
  Transparency (one read-only `GET` to `crt.sh` per domain). A subdomain of an attested domain is in scope; a public
  address it resolves to still needs `--i-am-authorized-for-public-ranges` and counts against the public cap.
- **import** — read an asset list from disk: a plain host/IP list, a CSV (a `host`/`ip`/`address`/`name`/`fqdn`/`dns`
  column), or nmap `-oX` XML.
- **cloud** — read the JSON **your own read-only command** printed, and scan the public IPs/DNS names in it. The scanner
  **never runs your cloud CLI and never sees your cloud keys**; you run the read-only command with your own credentials
  and point `cloud` at the file:
  - `aws-ec2`: `aws ec2 describe-instances > ec2.json`
  - `aws-elb`: `aws elbv2 describe-load-balancers > elb.json`
  - `gcp`: `gcloud compute instances list --format=json > gcp.json`
  - `azure`: `az network public-ip list > az.json` (or `az vm list-ip-addresses`)

Any IP a source yields that is not inside your attested `targets` (or a listed/attested domain) is dropped and logged,
never scanned. If discovery would push the number of public addresses over the cap (1,024), the scan **stops** and tells
you — it does not silently scan a subset.

## Exactly what goes over the network

To each target address, one ordinary TCP connection per port (no raw packets, no half-open or stealth scanning, no
spoofed source address):

| Port kind | What the scanner sends |
|---|---|
| Any port | A TCP connect. A refused connection shows the host is up; a port that does not answer is skipped. |
| SSH, FTP, SMTP, POP3, IMAP, MySQL, VNC | Nothing. It reads the greeting the service sends on its own (at most 16 KB, a few seconds). |
| SSH | After reading the server's banner, its own identification line, `SSH-2.0-CyberViewScanner_1.0.0 authorized-vulnerability-scan`, so your logs show who connected. |
| Web (80, 8080, 8000, 8008, 8888, ... and `--http-ports`) | One HTTP request for the root page (method GET, path "/"), with the User-Agent below. Redirects are recorded, not followed. |
| TLS (443, 8443, 993, 995, 465, ... and `--https-ports`) | A standard TLS handshake to read the certificate (read, never trusted), then on web ports the same single request. |

With `--udp`, one benign read-only UDP datagram per service per host (never more; no retransmit, no raw packets — node
`dgram` only):

| UDP service | The single datagram sent |
|---|---|
| DNS (53) | A `version.bind` query: QNAME `version.bind`, type `TXT`, class `CHAOS`. Reads the resolver's stated version. |
| NTP (123) | A mode-6 (control) **read-variables** request (opcode 2), no payload. Reads ntpd's version/system string. |
| SNMP (161) | One SNMPv1 `GET` of `sysDescr` (OID `1.3.6.1.2.1.1.1.0`) with the standard read community **`public`** only. No other community is ever tried; there is no walk and no write. |

Every web request carries the User-Agent
`CyberView-Scanner/1.0.0 (authorized vulnerability scan, detection only; +https://xanderhutch.github.io/CyberView/vulnerabilities.html#scanner)`.

A host is first tried on up to four discovery ports (22, 80, 443, 3389 when in the list); if none answers, it is treated
as down and nothing more is sent to it (`--assume-up` tries every port anyway).

Host names in the scope are resolved with your system's resolver. With `--online` the scanner also downloads CyberView's
public data, read-only, with GET requests and no key, cookie or account, from `https://xanderhutch.github.io/CyberView/`:

- `data/workbench.json`: the known-exploited flaws with affected-version ranges, CISA's due dates and required actions,
  EPSS, and fix guides
- `data/psirt.json`: vendors' own advisories joined on CVE
- `data/cve/index.json` and `data/cve/<year>/<n>.json`: the CVE lookup files (CVSS, CISA's SSVC assessment, KEV date,
  EPSS) for the CVEs that matched

KEV and EPSS arrive inside those files; the scanner never contacts CISA, FIRST or NVD itself. With `--data` it makes no
data request at all. It **never uploads anything**: no findings, no scope, no addresses, no telemetry. Results are
written only to the output folder on your machine, readable only by you.

## Politeness limits

| Setting | Default and ceiling | Flag |
|---|---|---|
| New connections per second | 20 | `--rate` |
| Connections open at once | 8 | `--concurrency` |
| Connections open at once to one host | 2 | `--host-concurrency` |
| Connections to one host per run | 300 (public) | `--host-budget` |
| Connections per run | 20,000 (public) | `--budget` |
| Longest run | 60 minutes (ceiling 480) | `--max-minutes` |

The rate and open-at-once limits can be set lower, never higher, and none can be switched off. The **per-host and total
connection budgets** are 300 and 20,000 for any scan that includes a public address; for a scan of **only private ranges
you own** (no public address, no `--i-am-authorized-for-public-ranges`) they scale up so a large own-network sweep and
`--all-ports` are not artificially blocked — the rate (20/s) and the time ceiling still bound the work. Each connection has
fixed time limits (3 s to connect, 4 s to read). Ctrl-C stops new connections, lets open ones finish and still writes the
report for what was checked (exit code 3); a second Ctrl-C quits at once.

## The report

Written to `cyberview-scan-<time>/` (or `--out`):

- `summary.txt`: hosts, services, findings, how many are known exploited, Critical, at priority Act or past CISA's
  deadline, then each finding.
- `report.json`: everything, including the attestation, the scope, the limits used, what was sent and every service seen.
- `findings.csv`: one row per CVE and place it was seen.
- `report.sarif`: SARIF 2.1.0, for dashboards that read code-scanning results.
- `inventory.csv`: the software found, in the format the Vulnerabilities page's "My software" view imports.

Each finding shows the CVE, where it was seen (address, port, product, the version as stated), and:

- **Ranking**: known exploited (CISA KEV) first, then other evidence of exploitation, then past CISA's deadline; within
  those, the CyberView rating.
- **CyberView rating**: the CVSS base score adjusted for exploitation evidence (CVSS v3.1 Exploit Code Maturity), with the
  whole calculation written out; CISA's SSVC priority (Track, Track*, Attend, Act) with every input and its source; and
  the patch-queue points with the reason for each point.
- **Confidence**: high when the service stated a version inside the affected range; medium when it is a Linux
  distribution's package build (the distribution may have backported the fix under the old version number) or the
  product was inferred; low when the product was seen but its version could not be read.
- **Fix**: the fixed versions (from NVD's ranges and the vendor's advisory), workarounds, CISA's required action, the
  vendor advisory's link, and the CVE's page on CyberView. Check steps, signs of compromise and detection resources are
  linked there, not copied. Exploitation analyses and fix guides are written by CyberView AI (a Claude model) from vendor
  and government sources, and say so.

A clean result is not proof that a host has no vulnerabilities: the scanner knows only the flaws CyberView's data covers,
and a service can hide or misstate its version.

## What it deliberately does not do

- No exploitation, payloads, injection strings or crafted input; no checks that work by triggering a flaw.
- No logins, password guessing, credential testing, SNMP community-string guessing, hash capture or cracking.
- No denial of service, flooding or amplification; the UDP checks send exactly one benign datagram per service per host
  (no retransmit); no raw sockets; no mode that removes the rate limit.
- No evasion: no spoofed addresses, no stealth or fragmented packets, no disguised User-Agent.
- No scanning of addresses outside the scope file (discovery is re-checked against it), and no wide sweeps of public
  address space (the public cap is a hard stop).
- The scanner never runs your cloud CLI and never reads or stores your cloud or API keys.

`scripts/security-check.mjs` checks the scanner's code for these on every change. More detail: `docs/scanner.md`.

## Licence

Copyright (c) 2026 xanderhutch (the CyberView maintainer). All rights reserved.

The CyberView Scanner is a **proprietary CyberView product**, licensed under
`scanner/LICENSE` — **not** the MIT licence that covers the rest of the
repository. You may download and use it to scan systems you own or are
authorised in writing to test, including inside your own organisation; you may
not redistribute, modify for distribution, sublicense or sell it without
written permission. It is provided with no warranty. For permissions beyond the
licence: cyberviewthreats@gmail.com.
