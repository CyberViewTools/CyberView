# The CyberView Scanner (scanner/)

A command-line tool an operator downloads and runs against their **own, authorized** network to find known-vulnerable
software and rank what to patch first. Approved by the owner on 2026-11-21 as a detection and prioritization tool. The
operator's guide, with the authorization notice and the exact network behaviour, is `scanner/README.md`; the site offers
the tool on its own Scanner page (`scanner.html`, with counts read from `scanner/lib` at every build by
`scripts/scanner-stats.mjs`) and in the Vulnerabilities page's "My software" view (`vulnerabilities.html#scanner`).
Mechanical code only, no AI model, Node's standard library only, nothing scheduled (no `routines.json` entry).

## Design limits (the product, not options)

The scanner detects; it never attacks. These hold for the code, the tests, the fixtures and the docs:

- No exploitation, payloads, injection strings or crafted input beyond reading a greeting (on SSH, also the server's
  algorithm list that follows it), one request for a web server's root page and a TLS handshake — and, only with
  `--paths`, the bounded path rail below. No check that works by triggering a flaw.
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
  data files (`ALLOWED` in `scanner/lib/data.mjs`, with `--online`/`data`; the event archive only with `--data-incidents`)
  and, when `discover.ct` is set, read-only GETs to the Certificate Transparency source (`crt.sh`) for the operator's own
  attested domains.
- Everything the scan reports beyond the first read comes from data it already holds: the hygiene observations, the
  fingerprint packs, the certificate and mail inventories, the scan diff and the HTML report add no connection, request,
  hello or datagram. Each slice's tests prove it on loopback (the stand-in services see the same bytes with and without
  the feature). The path rail is the one exception, and it is off by default.
- Write-ups follow the NOCODE rule in `scripts/lib/validate.mjs`: no attack commands or payloads anywhere.

`scripts/security-check.mjs` (section 7) fails CI if scanner code starts processes, opens a raw socket, opens a UDP socket
(`dgram`) anywhere but `scanner/lib/udp.mjs`, sends more than one UDP datagram per service per host (a loop or timer in
`udp.mjs`), iterates SNMP community strings, sends a POST, PUT, PATCH or DELETE, evaluates text as code, offers an
aggressive or unlimited mode, makes a TCP connection to a target anywhere but `scanner/lib/probe.mjs`, raises the rate /
open-at-once ceilings, or lets the private budget scaling touch those ceilings. It also fails if the path rail
(`scanner/lib/paths.mjs`) holds a path that is not a plain string literal, holds a login, management or exploit-class
path, names an HTTP method, or sets `PATHS_PER_HOST` above 16; if `getPath` in `probe.mjs` does not refuse every path
outside the frozen table before connecting; if any request method in `probe.mjs` is not GET; or if anything but a
planned rail item's path reaches it (`scripts/lib/scanner-rail-check.mjs`). `tests/unit/scanner.test.mjs` checks the
scanner, its docs and its fixtures for NOCODE's attack patterns and exercises each of these rules.

## Files

| File | What it does |
|---|---|
| `scanner/cyberview-scan.mjs` | the command line: `init`, `check`, `data`, `scan`; the authorization gate runs before anything else |
| `scanner/lib/scope.mjs` | the scope file, the attestation (exact `STATEMENT`), address kinds, CIDR expansion, `gate()`; pure |
| `scanner/lib/limits.mjs` | rate, concurrency, per-host and global budgets, the time limit; `settings()` refuses values above a ceiling |
| `scanner/lib/probe.mjs` | the only TCP network code that touches targets: connect, read a greeting, SSH identification and the server's KEXINIT, one root-page request, TLS handshake, and `getPath` for the path rail; `SENDS` says each in words |
| `scanner/lib/udp.mjs` | the only file that opens a UDP socket (`dgram`): one benign read-only datagram per service per host (DNS, NTP, SNMP); exactly one `send`, no loop |
| `scanner/lib/udp-codec.mjs` | pure UDP query builders and response parsers (version.bind TXT, NTP mode-6 read, SNMPv1 GET sysDescr with community `public`); no sockets |
| `scanner/lib/discover.mjs` | discovery sources: asset-list/CSV/nmap-XML parsing, read-only cloud inventory parsing, and Certificate Transparency lookup; candidates are re-gated by the scope |
| `scanner/lib/fingerprint.mjs` | banners, headers, certificates and UDP answers to product, vendor and version (NVD's CPE names), the hygiene observations; exports `FINGERPRINT_TABLES` for the coverage report; pure |
| `scanner/lib/ssh-kex.mjs` | parses the server's SSH_MSG_KEXINIT (bounded, never throws); the frozen weak-algorithm set `WEAK` and the post-quantum list `PQC_KEX`; pure |
| `scanner/lib/fp-cms.mjs` | CMS, WordPress plugin and theme, and JavaScript library versions from the root page already fetched; pure |
| `scanner/lib/fp-edge.mjs` | edge appliances (VPN gateways, firewalls, routers, cameras, NAS, switches) from the root page, its headers and the greeting; pure rules table |
| `scanner/lib/fp-apps.mjs`, `fp-apps2.mjs` | application fingerprint packs 1 and 2 (file transfer, web applications, frameworks, mail gateways, IT management consoles, proxies); pure rules tables |
| `scanner/lib/fp-identify.mjs` | the passive identify pack (consoles, brokers, search engines, cameras, VoIP and mail servers); pure rules table |
| `scanner/lib/paths.mjs` | the bounded HTTP path rail: the frozen, reviewed table of literal version/status paths (data), the hints over already-collected evidence, the parsers, the per-host cap `PATHS_PER_HOST` (8) |
| `scanner/lib/cite.mjs` | with `--data-incidents`: reviewed CyberView incidents per finding; hunt links on every finding |
| `scanner/lib/data.mjs` | CyberView's data online (GET, allowlisted paths) or from a snapshot folder; `snapshot()` for air-gapped use |
| `scanner/lib/shared.mjs` | loads `site/workbench-lib.js` and `site/cvedb-lib.js` unchanged, as `scripts/cve.mjs` does |
| `scanner/lib/match.mjs` | services to findings with the site's `matchFlaw`, rated with the site's `score` and `rate`, ranked |
| `scanner/lib/scan.mjs` | run discovery, resolve and gate the scope (with the public-cap stop), probe politely over TCP and UDP, fingerprint, assemble the report |
| `scanner/lib/report.mjs` | the run header, JSON, CSV (formula-safe), SARIF 2.1.0, the inventory CSV, the text summary, and the `coverage()` blind-spot report |
| `scanner/lib/html-report.mjs` | `--html`: the self-contained `report.html`, scope-file advice, the scan profile, the stale-data warning; pure |
| `scanner/lib/cert-inventory.mjs`, `mail-starttls.mjs`, `diff.mjs`, `kev-coverage.mjs` | the report pack: `--certs`, `--mail`, `--compare` and the `coverage` command; pure, no network |

**Coverage (never a silent clean).** `scan.mjs` records every probe outcome — open, closed, filtered, errored, and banners cut off before a version is read — not just open ports, and probes beyond the first few ports before calling a host unreachable (a firewall or IPS may drop the first probes). `report.mjs` `coverage()` turns that into a Coverage section in `summary.txt`/`report.json` listing hosts that answered on no port, filtered ports, truncated banners, ports left unchecked, and hosts that were **throttled**. A host that resets connections after answering (IPS/fail2ban) is backed off once (the Limiter's clock, so tests stay instant) and its reset ports are re-probed one at a time, recovering hidden services. When coverage is incomplete the command exits **2**, so a scan with blind spots is never mistaken for a clean one. Tests: `probeAll` finds an open port past dropped discovery ports, `coverage()` classifies gaps, `isTruncatedBanner` flags cut banners.

**Hygiene observations (`tk-hygiene`).** `fingerprint.mjs` `observations()` turns what the one connection already returned
into findings that are not CVEs, each `{ port, kind, severity, text }`. The TLS half reads the negotiated protocol,
cipher suite (OpenSSL and IANA names) and ephemeral key-exchange group (`getEphemeralKeyInfo()`), and the certificate's
key size, curve, SHA-256 fingerprint, and the signature and public-key algorithms (`certAlgorithms()`, a bounded DER
reader, because Node 22 does not expose them). Thresholds are fixed in `TLS_RULES`: expiring within 30 days, RSA/DSA under
2048 bits, EC under 224, a DH group under 2048, MD2/MD5/SHA-1 signatures, SSL 3.0 to TLS 1.1, NULL/export/RC4/DES/3DES/
MD5/anonymous suites. A name mismatch is reported only when the host was reached by an attested name (RFC 6125 matching:
SAN DNS names, CN only when there is none, one wildcard label). A blank key-exchange group on TLS 1.3 is recorded as "not
reported" (Node does not name hybrid post-quantum groups such as `X25519MLKEM768`), never as proof of PQC or its absence.
No extra connection, no extra hello, no cipher or group enumeration; the test suite proves a loopback TLS service sees
exactly one connection. At most 60 observations are kept per host (`OBS_PER_HOST`); any over the cap are counted in
`observations_dropped`. The HTTP half, `httpObservations()`, reads only the one root-page response: security headers
(judged on 2xx HTML pages only), cookie attributes (names only, never values), CORS `*`, redirects (an `http://`
downgrade, a target outside the scope via the scope's own `hostInScope`/`inScope`; never followed), default, installer and
directory-listing pages by title from fixed lists, debug output by fixed marker (only the marker's name is reported; no
body text is stored), `Allow`/`DAV`/`Alt-Svc` headers the server sent anyway (no OPTIONS request), CDN/WAF fronts,
`Date` clock skew over 5 minutes (`HTTP_RULES`), and version disclosure in `Server`. `mailObservations()` flags POP3/IMAP
on 110/143 and SMTP submission on 587 answering without TLS. The end-to-end test proves the stand-in web service still
receives exactly one request, for the root page.

**SSH algorithms (`scan-ssh-kex`).** After reading the server's greeting the scanner sends its identification line
(unchanged) and then reads, on the same connection, the server's algorithm list (SSH_MSG_KEXINIT, RFC 4253 7.1), at most
4 seconds and 16 KB, and closes. A KEXINIT is sent in the clear and carries only algorithm names; the scanner never sends
a KEXINIT of its own, never starts a key exchange and never logs in, so it never sees the host key. `ssh-kex.mjs` parses
it with fixed bounds (a packet of at most 16,384 bytes, at most 64 names of at most 64 characters per list) and never
throws. The report lists, per SSH port (`hosts[].ssh`), the advertised key-exchange, host-key, cipher, MAC and
compression algorithms and whether strict key exchange is offered. Observations flag a frozen list of weak names, one per
category with every name and its reason (`ssh-weak-kex`, `ssh-weak-hostkey`, `ssh-weak-cipher`, `ssh-weak-mac`: SHA-1
key exchange, DSA and SHA-1 RSA host keys, CBC, 64-bit block and RC4 ciphers, MD5 and 96-bit SHA-1 MACs), and note
post-quantum hybrid key exchange (ML-KEM, sntrup761) as information (`ssh-pqc-kex`). "Offers" is not "uses": a modern
client picks a strong algorithm first.

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

## Fingerprints from data already collected

Besides `fingerprint.mjs`'s banner, Server header, generator and certificate parsers, five rules tables name products from
what the scan already holds for a port: the greeting read on connect, the one root-page response (status, title, headers,
cookie **names**, body markers, a recorded redirect `Location`) and the TLS certificate subject. None adds a request,
path, port, hello or datagram; each hooks into `scan.mjs` `servicesOf()` with one line, after the existing parsers, so a
product already named on the port is not repeated. Evidence is the rule's fixed description of the marker, or a short
header, greeting or version token; page text, bodies and cookie values are never stored. Each rule cites the detection
catalog ids it builds (`ids`/`catalog` on the record).

- **CMS and JavaScript libraries (`fp-cms.mjs`).** WordPress (generator, wordpress.org `?v=`, wp-emoji `ver=`, asset
  paths, api.w.org Link, X-Pingback), Drupal (generator, X-Generator, X-Drupal-Cache, settings markup), Joomla
  (generator), Craft CMS, DotNetNuke, Kentico, October CMS, Sitefinity, SAP Commerce Cloud, ThinkPHP, cPanel & WHM and
  XWiki; WordPress plugins and themes named in the page's own asset URLs; and jQuery, jQuery UI, Bootstrap, AngularJS,
  Lodash, Moment.js, Vue.js, Handlebars and Underscore from script file names, CDN paths and banner comments. A version
  in a file name, CDN path, banner, generator or Server header is compared with the affected ranges. A `?ver=`
  cache-buster (WordPress may put its own version there) is listed in the inventory only and can at most give a
  low-confidence "check the version". Script URLs are never stored; this pack fetches nothing (no script, stylesheet or
  plugin file; the only plugin files ever requested are the three reviewed readmes in the path rail's table, with
  `--paths`).
- **Edge appliances (`fp-edge.mjs`).** About 45 VPN gateways, firewalls, load balancers, SOHO routers, cameras, NAS and
  switches on CISA's KEV list are named from the root page, its Server and WWW-Authenticate headers, or the greeting. A
  version is reported only where that data states one (for example a Server header's `Ver` suffix or a `Version:` line on
  the login page, never a page title). Version files on fixed paths belong to the path rail.
- **Application pack 1 (`fp-apps.mjs`).** File-transfer products, web applications and frameworks (Jenkins, MOVEit
  Transfer, GoAnywhere MFT, CrushFTP, WS_FTP, ServiceNow, SharePoint, ASP.NET, Django, Rails and others). A version stated
  in a header or greeting is compared and can be high confidence; one printed in the page is compared but the product
  stays inferred (medium at most); one in a login-page title is shown but never compared.
- **Application pack 2 (`fp-apps2.mjs`).** Mail gateways, IT management consoles, proxies and small web servers (Cisco
  Secure Email Gateway, MDaemon, SmarterMail, WhatsUp Gold, N-central, ManageEngine, Splunk, Orion, Superset, Jaspersoft,
  APISIX, GoAhead, nostromo and others). A number that is not the product's release (Microsoft-HTTPAPI/2.0, an OpenView
  component, a Roundcube build number) is shown but never compared.
- **Passive identify pack (`fp-identify.mjs`).** GitLab, Apache ActiveMQ (OpenWire version), RocketMQ console, Pi-hole,
  Adminer, CouchDB, Elasticsearch, OpenSearch, mongo-express, phpMyAdmin, VMware Aria Operations / vRealize Operations,
  ESXi, vCenter, Workspace ONE Access, Dell RecoverPoint, Hikvision, PaperCut MF/NG, Reolink, Contec SolarView Compact,
  OpenSMTPD, qmail, CWP, CyberPanel, HPE OneView, Alcatel OmniPCX Enterprise, Grandstream UCM6200, Openfire, Mitel
  (generic, inventory only) and UnrealIRCd. A version is used only where the service states it (ActiveMQ, Adminer,
  CouchDB, Elasticsearch, OpenSearch, Aria Operations, HPE OneView, Openfire).

Most of these products state no version on the pages the scanner reads, so most identifications are guessed and
version-less: they appear in the inventory and as low-confidence "check" findings, never in the headline counts (below).
A product named from a greeting replaces the anonymous "FTP server" or "SMTP server" record on that port. The
`coverage` command (Outputs) lists the known-exploited products none of these tables can name yet.

## Ranking and confidence

Known exploited (KEV) first, then other exploitation evidence (CISA's SSVC, the vendor's advisory, the CVE record), then
past CISA's deadline; within those, version-confirmed before product-only, then the CyberView rating, the SSVC priority,
the nearest deadline and EPSS. Confidence: high when the service stated a version inside an affected range; medium for a
distribution package build (backports) or an inferred product; low when the version could not be read or no range
exists.

The summary's **headline counts** (known exploited, Critical, Act, past-deadline) are the confident findings only;
low-confidence rows — where no version was read, the product was only inferred, or a certificate merely names a vendor —
are still listed in full and in `report.json`/`findings.csv`, and counted as `low_confidence`, but never inflate those
numbers, so a page of "may-be-affected" guesses cannot read as a wall of confirmed criticals. A banner the scanner can
place but not version (an OpenSSH with no release string, a bare `220` FTP/SMTP greeting) is named by its product at low
confidence rather than dropped to an anonymous "server", so it still shows up as something to check.

The same rules hold for every fingerprint source (the packs above and the path rail):

- A version is compared with the affected ranges only when the service states the product's own release: in a banner, a
  header, a greeting, a generator tag, a file name or a documented version file. Such a record is not `guessed`, and a
  version inside a range is high confidence (medium for a distribution build).
- A version printed in the page body, or a product inferred from markers, keeps the record `guessed`: a version inside a
  range is medium confidence at most.
- A number that is not the product's release (a cache-buster `?ver=`, a component or runtime version, a build number, a
  login-page title) is kept as `shown_version` for the inventory and never compared. A login-page title alone never
  yields "affected".
- A product with no compared version can only be "check", at low confidence: listed in full, counted as
  `low_confidence`, and left out of the headline counts.

## Fix information

Each finding carries the fixed versions (the ends of NVD's ranges and the guide's `fixed` list), the guide's workarounds,
CISA's required action, the vendor advisory link and the CVE's CyberView page. A guide's check steps, signs of
compromise and hunt resources, and exploitation analyses, are linked, never copied (indicators of compromise stay on the
page that cites them). AI-written material is labelled "CyberView AI (a Claude model)".

**Hunt links.** Every finding also lists the publishers' detection files for its CVE (Sigma, YARA, STIX and so on; at
most 12, https only, CSAF/CVRF/VEX left out), from the guide and workbench data the scanner already loads. They are links
only; their contents are never downloaded or copied.

**Incident citations (`--data-incidents`, off by default).** On `scan` and on `data`, the scanner also reads CyberView's
event archive (`data/archive/search.json` and the `data/archive/<YYYY-MM>.json` months that hold events naming a matched
CVE, newest first, at most 36) and cites, per finding, the CyberView events that name its CVE (at most 10). Only events
that are confirmed or official and passed (or were corrected by) CyberView's second review are cited: title, date, a link
to the event on CyberView, the number of sources it cites, and, only when a government or the investigating firm made it,
who attributed it and where. Attackers' claims are never cited; they are counted and labelled as unconfirmed, with no
title or victim. Other unreviewed or developing events are only counted. Nothing else from the event (no indicators, no
hunt rules, no summary, no actor name) is copied. On `data`, the flag adds a thin archive to the snapshot (only events
naming a workbench CVE, trimmed to the fields above). Without the flag no archive file is read, the report is unchanged
and offline snapshots stay small. Citations are in `summary.txt`, `report.json` and `report.html`, not in the CSV or
SARIF.

## Outputs

Every scan writes `report.json`, `findings.csv`, `report.sarif`, `inventory.csv` and `summary.txt` (mode 0600). The rest
is opt-in and built only from what the scan already holds:

- **`--html`** also writes `report.html`: one self-contained page (inline CSS, no script, nothing loaded from the network,
  a Content-Security-Policy that forbids everything else, no referrer). It shows the run header (what was sent, limits,
  the recorded attestation wording and the scope file's sha256), the scan profile and what it does not cover, the summary
  counts (low-confidence findings grouped per product, collapsed, and left out of the headline), coverage blind spots
  (including root pages cut at the 16 KB size cap, `hosts[].http[].body_truncated`), and the ranked findings with the
  CyberView rating, SSVC priority, KEV deadline, confidence and its reason, "why it matched" (the banner or header that
  supported it), fix information and advisory links. A finding whose version came from a Linux distribution's package
  build carries a "Possibly already fixed" box: the distribution may have backported the fix without changing the version
  number. Every value from a target is HTML-escaped; links are https only. `report.json` gains `run.profile` and
  `scope.coaching`.
- **Scope-file advice and old data.** `check` and `scan` print advice for a scope file that passes its checks but looks
  wrong (unknown keys with a "did you mean", duplicate targets, an entry both targeted and excluded, an exclusion outside
  every listed range, an attestation expiring within 14 days, an empty `authorization_ref` or `contact`); it is never a
  refusal. A scan warns when the offline snapshot or the workbench data is more than 7 days old, or its age is unknown.
- **`--certs`** writes `certs.csv`: every leaf certificate the scan's one TLS handshake returned, with validity, key,
  signature, SHA-256 fingerprint, serial, public-key hash, SAN count, wildcards, internal names (single-label, `.local`,
  `.internal`, `.corp` … and private, loopback or link-local IP SANs), SCTs embedded in the certificate, OCSP
  must-staple, short-lived certificates (10 days or less), and reuse (the same certificate, public key or issuer+serial
  on more than one address). Wildcard coverage and SAN names beyond the attested names are computed only for hosts
  scanned by name. `report.json`'s `hosts[].tls[].cert` also carries `serial`, `spki_sha256`, `san_dns`, `san_ip`, `sct`
  and `must_staple`.
- **`--mail`** writes `mail.csv`: mail services found, implicit TLS, STARTTLS as far as the greeting shows it (an IMAP
  greeting's capability list; SMTP and POP3 need EHLO/CAPA, which is not sent, so they read "not checked", never
  "absent"), and an SMTP service on port 25 with no submission port.
- **`--compare PREVIOUS/report.json`** writes `diff.json` and `diff.txt`: findings new, fixed (the same port answered and
  the CVE no longer matches), gone with their port (not proof of a fix), still open and not rechecked (host absent or
  down, port not in the list, or a limit left it partly unchecked); services and versions changed; certificates changed
  (an issuer change is flagged for review, never as a compromise); observations new and resolved. The previous file is
  untrusted input: it is read and validated before anything is scanned (it must be a CyberView Scanner report, at most
  64 MB; only compared fields are kept, each type-checked and clipped).
- **`coverage --data DIR [--out kev-coverage.csv]`** compares the snapshot's KEV catalog with the scanner's fingerprint
  tables and lists the known-exploited products the scanner cannot identify. No scope file, no target, no network.
  (Products named only by modules outside `FINGERPRINT_TABLES` are not counted until they register there.)

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

## The bounded path rail (`--paths`, off by default)

Some products state their version only in a documented version or status file, not on the root page. With `--paths` the
scanner may make a few extra GET requests for those files, and nothing else:

- **A frozen table, not a wordlist.** `scanner/lib/paths.mjs` holds 39 literal paths for 50 reviewed catalog rows. A path
  is added only after a Design review; operator-supplied URLs are not accepted. No login, management, debug or
  exploit-class path is allowed (section 7 enforces it).
- **Hint-gated.** A host gets a path only when its own already-collected evidence on that port — the root page's title,
  headers, cookie names, body markers, a recorded redirect, the TLS certificate or the port — points at that product. A
  host with no hint gets the root request and nothing more. Hints that rely on a port fire only when that port is scanned
  as a web port (`--http-ports` / `--https-ports`). Rows sharing a path are served by one request.
- **Bounded.** At most 8 extra requests per host across all its ports (`PATHS_PER_HOST`; `--paths-per-host N` can lower
  it, never raise it). Each request takes a Limiter slot like a connection, so the rate, open-at-once and budget limits
  all apply. Baseboard management controllers (the AMI MegaRAC and Redfish service-root rows) stay opt-in even with
  `--paths` (`--paths-bmc`). `--paths-per-host` and `--paths-bmc` without `--paths` are refused.
- **Read, not followed.** GET only, the scanner's User-Agent, one connection per request. Redirects are recorded, not
  followed. The body is read up to 16 KB and only a product and version token is kept; bodies, cookie values and headers
  are never written to the report. Only a 200 is parsed.
- **Every outcome recorded.** Each rail request's status (ok, redirect with its Location, unauthorized, forbidden,
  not-found, other code, timeout, error) and every hinted path left unsent (per-host cap, budget or time) is in
  `coverage.paths` and `hosts[].paths` in report.json, with a "Path rail:" line in the run header and in summary.txt.
- Products identified only by presence, or whose file states a build number rather than the release name NVD uses, are
  reported as inferred (low confidence) and stay out of the headline counts.

Known gaps, kept on purpose: Tomcat usually answers `/docs` with a redirect to `/docs/`, which is recorded, not followed,
so a Tomcat version is read only where `/docs` answers directly; `/CHANGELOG.txt` covers Drupal 7, not Drupal 8 and later.

## Deliberately left out

Credentialed (authenticated) scanning; password, community-string or any credential guessing; protocol commands beyond the
greeting, the SSH identification line and the three benign UDP queries (for example Redis or database queries, SNMP writes
or walks, SMTP EHLO or POP3 CAPA, a client KEXINIT or any key exchange, so no SSH host key is ever collected); following
redirects; crawling; requesting any path outside the reviewed frozen table; fetching a page's scripts, stylesheets or
plugin files other than the few the rail's table names; trying plugin or theme names from a list; vulnerability checks
that send test input; operating-system fingerprinting from packet quirks; running the cloud CLI from inside the scanner;
and any upload of results. Each would either cross the limits above or add risk
without changing the finding much; version matching against published data is the whole method.

## Tests

`tests/unit/scanner.test.mjs` (in `npm run unit`): the gate (no scope, bad attestation, out of scope, excluded, public
without the flag, too-wide ranges), the fingerprint parsers on real-format banners (`tests/fixtures/scanner/banners.json`),
matching and rating against the site's libraries, the CSV, SARIF and inventory exports, the limits and budgets, offline
and online data (with a stand-in fetch), Ctrl-C, and an end-to-end scan of stand-in services on 127.0.0.1
(`tests/fixtures/scanner/servers.mjs`) that records every byte the scanner sends. No test contacts a real host. The
snapshot under `tests/fixtures/scanner/snapshot/` uses invented CVE ids (CVE-2026-90xxx) and is marked as test data.

Each later slice has its own file, loopback only, and each proves that the stand-in services see no new bytes:
`scanner-sshkex.test.mjs` (KEXINIT parsing, bounds, the weak set, one connection), `scanner-html.test.mjs` (escaping of
hostile banners, titles and names, no external loads, https-only links, the backport box, the five-file list unchanged
without `--html`), `scanner-cms.test.mjs`, `scanner-edge.test.mjs`, `scanner-apps1.test.mjs`, `scanner-apps2.test.mjs` and
`scanner-identify.test.mjs` (each rule on fixtures, look-alikes, version trust, headline counts, exactly one root request),
`scanner-cite.test.mjs` (the citation rule, claims never cited, no archive read without the flag),
`scanner-reportpack.test.mjs` (certificates built at test time, the diff, a bad `--compare` file refused before any probe,
`coverage` never probes or fetches) and `scanner-paths.test.mjs` (an unhinted host sees only the root request, a hinted
host only its frozen paths, the per-host cap, budgets, a redirect recorded and not followed, 401/404 in coverage, the flag
off sends nothing extra, the parsers on canned responses, and each section 7 failure case).

## Decisions

Taken by the build lead on 2026-11-22, under the owner's instruction to complete the full build and decide when a
blocker came up. Each keeps the scanner detection-only and inside the limits above; the owner can reverse any of them.

1. **QNAP's login CGI: rejected.** It is a login endpoint, and the path rail never requests login or authentication
   endpoints. QNAP stays identified from its certificate and root page, without a version.
2. **Spring Boot's actuator health endpoint: rejected.** The whole actuator family is refused by section 7 because it
   sits beside environment and heap-dump endpoints; one exception would weaken the rule.
3. **The OpenAI-compatible model list: rejected.** It lists what is deployed (a model inventory) and often needs a key;
   such services are identified from the root page only.
4. **`security.txt` as a fingerprint source: rejected.** It names a contact, not a product or a version.
5. **Redfish service root: kept as shipped.** Behind `--paths-bmc` on top of `--paths`, presence only, guessed.
6. **A version shown only on a login page (Cisco FMC, Sophos, FatPipe and similar): passive only.** It is read when the
   root page or a recorded redirect already is that page; the login page is never requested as a path.
7. **SSH host-key reuse: deferred.** Reading the host key needs a completed key exchange, which the scanner does not do.
   It comes back only with its own Design.
8. **The nine hint markers the path-rail builder chose** (Chroma, Ollama, Weaviate, Prometheus, Kubernetes, OpenShift,
   MagicINFO, JGS516, Nexus): **accepted as shipped.** The rail is off by default, and the presence-only rows stay
   guessed and out of the headline counts.
9. **Tomcat's `/docs/`: not added.** `/docs` stays; its redirect is recorded, never followed. Tomcat versions otherwise
   come from the default error page or the Server header when they state one.
10. **New protocol hellos: allowed only as an opt-in family with its own flag**, one standard unauthenticated client
    message per protocol, no authentication, no enumeration, declared in `SENDS` and enforced in section 7. Mail STARTTLS
    (SMTP EHLO, POP3 CAPA) is the first candidate. Each protocol is listed in a Design before it is built; anything that
    enumerates users, shares or zones, or authenticates, is rejected.
11. **Industrial (ICS/OT) identification reads: allowed only behind an explicit `--ics` opt-in**, one read-only
    identification request per protocol, private ranges by default, never a write or a function that changes state.
    (Not built yet.)
12. **Single-file executables and tagged GitHub Releases (Grok brief #89): approved** as part of the full build. Releases
    are built from tags by CI, with checksums.
13. **A browser report viewer and scope-file builder on the Scanner page: approved** (the owner asked earlier; it waited
    for the other work). A real network scanner in the browser is not possible and is not built.

## Licence

The scanner is a proprietary CyberView product under `scanner/LICENSE` (CyberView as a whole is proprietary; this sets the scanner's end-user terms): download and use on systems you own or are authorised to test, no redistribution without permission.
