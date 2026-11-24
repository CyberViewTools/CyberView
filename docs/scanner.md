# The CyberView Scanner (scanner/)

A command-line tool an operator downloads and runs against their **own, authorized** network to find known-vulnerable
software and rank what to patch first. Approved by the owner on 2026-11-21 as a detection and prioritization tool. The
operator's guide, with the authorization notice and the exact network behaviour, is `scanner/README.md`; the site offers
the tool on its own Scanner page in the site's Tools section (`scanner.html`, marked "in development", with counts read from `scanner/lib` at every build by
`scripts/scanner-stats.mjs`, its "Recently added" list from `config/scanner-page.json`, and two browser-only tools: a
viewer for one or more `report.json` files with what changed between them, and a scope-file builder that checks targets
with the scanner's own rules and will not produce a file until the exact attestation is ticked; nothing is uploaded) and in
the Tools section's "My software" page (`tools.html`; the old `vulnerabilities.html#scanner` and `#inv` links redirect there).
Mechanical code only, no AI model, Node's standard library only, nothing scheduled (no `routines.json` entry).

## Design limits (the product, not options)

The scanner detects; it never attacks. These hold for the code, the tests, the fixtures and the docs:

- No exploitation, payloads, injection strings or crafted input beyond reading a greeting (on SSH, also the server's
  algorithm list that follows it), one request for a web server's root page and a TLS handshake — and, each only with its
  own flag and off by default, the bounded path rail (`--paths`), the identify hellos (`--identify`), the industrial
  identification reads (`--ics`) and the DNS record checks (`--dns-records`) below. No check that works by triggering a
  flaw.
- No credentials of any kind: no logins, password guessing or spraying, hash capture or cracking.
- No denial of service, flooding or amplification: politeness limits whose rate and open-at-once defaults are also their
  ceilings (`scanner/lib/limits.mjs` CAPS, frozen), no raw sockets, no "fast" mode. The UDP checks send exactly one benign
  datagram per service per host (no retransmit storm), always unicast to the attested address, never broadcast or
  multicast; raw sockets are never used (node `dgram` only, in two files: `udp.mjs`, which also sends the `--ics` BACnet
  query, and `hello.mjs` for the `--identify` hellos).
- No credentials or credential iteration: no logins, no password or community-string guessing. The SNMP check uses only the
  single standard read community `public`; no other community is ever tried. The hellos never authenticate: no SMTP AUTH,
  no POP3 USER/PASS, no LDAP bind, no SMB session setup, no RDP security exchange, no OPC UA session.
- No state changes on industrial devices: `--ics` sends only read-only identification requests (no write or control
  function code, no Modbus register or coil read, no S7 job beyond one system-status read, no DICOM command), and only to
  private, loopback or link-local addresses.
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
  fingerprint packs, the certificate and mail inventories, the scan diff, the relationship map and the HTML report add no
  connection, request, hello or datagram, and the offline `import`, `depmap` and `rematch` commands contact nothing at
  all. Each slice's tests prove it on loopback (the stand-in services see the same bytes with and without the feature).
  The exceptions are the opt-in families — the path rail, the identify hellos, the industrial reads and the DNS record
  checks — each off by default, each declared in the run header's "what is sent" lines (`SENDS`, `HELLO_SENDS`,
  `DNS_SENDS`, `icsSends`) and each through the same Limiter (rate, budgets, time limit, Ctrl-C).
- Write-ups follow the NOCODE rule in `scripts/lib/validate.mjs`: no attack commands or payloads anywhere.

`scripts/security-check.mjs` (section 7) fails CI if scanner code starts processes, opens a raw socket, opens a UDP socket
(`dgram`) anywhere but `scanner/lib/udp.mjs` and `scanner/lib/hello.mjs`, sends more than one UDP datagram per service per
host (a loop or timer in `udp.mjs`), iterates SNMP community strings, sends a POST, PUT, PATCH or DELETE, evaluates text as
code, offers an aggressive or unlimited mode, makes a TCP connection to a target anywhere but `scanner/lib/probe.mjs`,
`scanner/lib/ics.mjs` and `scanner/lib/hello.mjs`, raises the rate /
open-at-once ceilings, or lets the private budget scaling touch those ceilings. It also fails if the path rail
(`scanner/lib/paths.mjs`) holds a path that is not a plain string literal, holds a login, management or exploit-class
path, names an HTTP method, or sets `PATHS_PER_HOST` above 16; if `getPath` in `probe.mjs` does not refuse every path
outside the frozen table before connecting; if any request method in `probe.mjs` is not GET; or if anything but a
planned rail item's path reaches it (`scripts/lib/scanner-rail-check.mjs`). The two opt-in protocol families have their
own checkers in the same section:

- **Hellos and DNS records (`scripts/lib/scanner-hello-check.mjs`).** `hello.mjs` is the second file allowed to own a UDP
  socket (a lead decision, 2026-11-22), under its own rules rather than `udp.mjs`'s: every request is a plain frozen
  literal; text requests start with EHLO, CAPA or OPTIONS, and no line may start with a login, mail-transfer, address
  verification, call-setup, streaming, zone-transfer or bind verb (AUTH, USER, PASS, APOP, VRFY, EXPN, MAIL, RCPT,
  STARTTLS, STLS, REGISTER, INVITE, DESCRIBE, SETUP, PLAY, AXFR, BIND and the like); SIP needs Max-Forwards 0; the binary
  messages (mDNS, the RMCP/ASF ping, RDP, SMB2, LDAP and its unbind) must equal the checker's own reviewed bytes; the file
  holds exactly one socket write and one datagram send, in a loop-free transport block; no broadcast or multicast;
  `identifyHost` refuses to run unless the opt-in is on, and only `scan.mjs` calls it. DNS: TXT and CAA only, frozen
  reviewed prefixes, no ANY, AXFR or IXFR, and only `dns-records.mjs` may use a `Resolver`.
- **Industrial reads (`scripts/lib/scanner-ics-check.mjs`).** `ics.mjs` writes in one place, only the frozen request
  bytes, sends no datagram and imports no `dgram`: BACnet goes through `udp.mjs` (one send, no retransmit), the only
  caller allowed to pass it a service table. Every step must decode to the allowed read-only message (no write function
  code, no extra message, unit id not 0, no broadcast BVLC or DNET); only the six reviewed protocols (no DNP3, no FHIR);
  nothing is planned without `--ics`, for a public host, a possible broadcast address, an unlisted port or a closed TCP
  port, and each protocol at most once per host.

`tests/unit/scanner.test.mjs` checks the scanner, its docs and its fixtures for NOCODE's attack patterns and exercises
each of these rules; the hello and industrial test files mutate each checker rule and prove it fires.

## Files

| File | What it does |
|---|---|
| `scanner/cyberview-scan.mjs` | the command line: `init`, `check`, `data`, `scan`, `coverage`, and the offline `import`, `depmap`, `rematch`; the authorization gate runs before anything is scanned |
| `scanner/lib/scope.mjs` | the scope file, the attestation (exact `STATEMENT`), address kinds, CIDR expansion, `gate()`; pure |
| `scanner/lib/limits.mjs` | rate, concurrency, per-host and global budgets, the time limit; `settings()` refuses values above a ceiling |
| `scanner/lib/probe.mjs` | the base scan's TCP network code (the opt-in `ics.mjs` and `hello.mjs` are the only other files that connect to a target): connect, read a greeting, SSH identification and the server's KEXINIT, one root-page request, TLS handshake, and `getPath` for the path rail; `SENDS` says each in words |
| `scanner/lib/udp.mjs` | the `--udp` socket (`dgram`): one benign read-only datagram per service per host (DNS, NTP, SNMP, and the `--ics` BACnet Who-Is with `ics.mjs`'s frozen bytes); exactly one `send`, no loop |
| `scanner/lib/hello.mjs` | `--identify`: the frozen `HELLO` table (one standard unauthenticated client message per service), its own TCP connection or single UDP datagram per service per host, the reply parsers, `helloPlan`, `identifyHost`; `HELLO_SENDS` says each in words. The second file allowed `dgram` (own section 7 rules) |
| `scanner/lib/dns-records.mjs` | `--dns-records`: the frozen `QUERIES` table (TXT and CAA), attested names only, system resolver; `interpret`, `dns.csv`; `DNS_SENDS` |
| `scanner/lib/ics.mjs` | `--ics`: the frozen read-only identification requests per industrial protocol (each beside the specification section it follows), `icsPlan`, `icsTargetOk`, the TCP exchange and the reply parsers; `icsSends` |
| `scanner/lib/udp-codec.mjs` | pure UDP query builders and response parsers (version.bind TXT, NTP mode-6 read, SNMPv1 GET sysDescr with community `public`); no sockets |
| `scanner/lib/discover.mjs` | discovery sources: asset-list/CSV/nmap-XML parsing, read-only cloud inventory parsing, and Certificate Transparency lookup; candidates are re-gated by the scope |
| `scanner/lib/fingerprint.mjs` | banners, headers, certificates and UDP answers to product, vendor and version (NVD's CPE names), the hygiene observations; exports `FINGERPRINT_TABLES` for the coverage report; pure |
| `scanner/lib/ssh-kex.mjs` | parses the server's SSH_MSG_KEXINIT (bounded, never throws); the frozen weak-algorithm set `WEAK` and the post-quantum list `PQC_KEX`; pure |
| `scanner/lib/fp-cms.mjs` | CMS, WordPress plugin and theme, and JavaScript library versions from the root page already fetched; pure |
| `scanner/lib/fp-edge.mjs` | edge appliances (VPN gateways, firewalls, routers, cameras, NAS, switches) from the root page, its headers and the greeting; pure rules table |
| `scanner/lib/fp-apps.mjs`, `fp-apps2.mjs` | application fingerprint packs 1 and 2 (file transfer, web applications, frameworks, mail gateways, IT management consoles, proxies); pure rules tables |
| `scanner/lib/fp-identify.mjs` | the passive identify pack (consoles, brokers, search engines, cameras, VoIP and mail servers); pure rules table |
| `scanner/lib/fp-pack3.mjs` | passive pack 3 (helpdesks, monitoring, remote management, building and industrial panels, cameras, IP phones) and the login-page inventory; pure rules table |
| `scanner/lib/fp-research.mjs` | the research pack: fingerprints from public references, each rule citing its source (`RULES`, and `DNS_RULES` for version.bind answers); pure |
| `scanner/lib/paths.mjs` | the bounded HTTP path rail: the frozen, reviewed table of literal version/status paths (data), the hints over already-collected evidence, the parsers, the per-host cap `PATHS_PER_HOST` (8) |
| `scanner/lib/cite.mjs` | with `--data-incidents`: reviewed CyberView incidents per finding; hunt links on every finding |
| `scanner/lib/data.mjs` | CyberView's data online (GET, allowlisted paths) or from a snapshot folder; `snapshot()` for air-gapped use |
| `scanner/lib/shared.mjs` | loads `site/workbench-lib.js` and `site/cvedb-lib.js` unchanged, as `scripts/cve.mjs` does |
| `scanner/lib/match.mjs` | services to findings with the site's `matchFlaw`, rated with the site's `score` and `rate`, ranked |
| `scanner/lib/scan.mjs` | run discovery, resolve and gate the scope (with the public-cap stop), probe politely over TCP and UDP, fingerprint, assemble the report |
| `scanner/lib/report.mjs` | the run header, JSON, CSV (formula-safe), SARIF 2.1.0, the inventory CSV, the text summary, and the `coverage()` blind-spot report |
| `scanner/lib/html-report.mjs` | `--html`: the self-contained `report.html`, scope-file advice, the scan profile, the stale-data warning; pure |
| `scanner/lib/cert-inventory.mjs`, `mail-starttls.mjs`, `diff.mjs`, `kev-coverage.mjs` | the report pack: `--certs`, `--mail`, `--compare` and the `coverage` command; pure, no network |
| `scanner/lib/depmap.mjs`, `imports.mjs`, `rematch.mjs`, `offline-cmds.mjs` | report pack 2: the relationship map (`--depmap`), the operator's import parsers and local package matching, the offline rematch, and the `match`, `import`, `depmap` and `rematch` commands; no network |
| `scanner/lib/lookup.mjs` | the `lookup` reader: one CVE from a local snapshot — rating, both exposure deadlines, NVD ranges, the fix, whether a fingerprint can find the product, and a version the operator holds against the ranges; no network, nothing new fetched |
| `scanner/lib/inputs.mjs` | the `match` adapters: nmap `-oX` hosts and services, CPE and purl vendors, an inventory with no address as one pseudo-host; returns the records `fingerprint.mjs` builds, so the matching, rating and outputs are unchanged |
| `site/scanner-lib.js`, `site/scanner.js` | the Scanner page's report viewer and scope-file builder (browser only; mirrors of `diff.mjs` and `checkScope` that the unit tests compare with the real modules) |

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

Besides `fingerprint.mjs`'s banner, Server header, generator and certificate parsers, seven rules tables name products from
what the scan already holds for a port: the greeting read on connect, the one root-page response (status, title, headers,
cookie **names**, body markers, a recorded redirect `Location`), the TLS certificate subject and issuer, and (research
pack only) the `--udp` DNS version.bind answer. None adds a request,
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
- **Passive pack 3 (`fp-pack3.mjs`).** Citrix StoreFront, Zimbra Collaboration Suite, GLPI, Zammad, SolarWinds
  Virtualization Manager, the Zabbix frontend, Ivanti Cloud Services Appliance, Soliton FileZen, the TeamViewer web
  placeholder, Quest KACE SMA, NextGen Mirth Connect, Nice Linear eMerge, ScadaBR, Unitronics PLC/HMI web panels, ZKTeco
  BioTime, Amcrest cameras and NVRs, NUUO NVRs, Intel AMT / Standard Manageability and Cisco IP Phones. A version is used
  only where it is stated: GLPI (footer or asset token), Zabbix (`jsLoader.php?ver=` or footer), KACE (its version header)
  and Intel AMT (Server header). Families (NUUO, eMerge, Unitronics, Amcrest) are never versioned; a KACE header naming the
  deployment appliance is never taken for the SMA. Mirth Connect is named from its exact administrator page title on the
  root page only (lead decision). The pack also records, as inventory, a **login page**: a password field on the root
  page, or a recorded redirect into a login path. No login path is ever requested; the line names no product, is never
  matched and is not in `inventory.csv`.
- **Research pack (`fp-research.mjs`).** 55 products from fingerprints published in public references (Recog, Nmap's
  service probes, Wappalyzer, nuclei templates and the products' own source; each rule cites its source), among them
  Jupyter, MLflow, Ray, GeoServer, OFBiz, SAP NetWeaver, Atlassian Jira, Confluence and Bitbucket, Rocket.Chat, Docker
  registries, Harbor, NetApp ONTAP, Synology DSM, Commvault, Axis cameras, HP printers, CUPS, FreeIPA, Barracuda,
  FortiMail, Cacti, PRTG, Wazuh, ScreenConnect, Dell iDRAC, HPE iLO, Supermicro BMCs, and the DNS servers dnsmasq, Knot
  DNS, NSD, Unbound and CoreDNS from the version.bind answer `--udp` already reads (BIND stays with `fingerprint.mjs`).
  Versions only where the data states them (for example Rocket.Chat's version header, PRTG, HPE iLO and Netdata Server
  headers, Jira's application meta tag, Cacti, and the five DNS servers); CUPS's major.minor and SAP NetWeaver's kernel
  number are shown, never compared. Serial numbers, product numbers, device tokens and certificate CNs are matched,
  never stored. A product named from a greeting replaces the product-less greeting record, and a guessed
  certificate-inferred record a rule supersedes gives way (the FortiMail default certificate no longer reads as FortiOS).
  Fingerprints that need a protocol hello (Redis, MQTT, Kafka, Oracle TNS, PJL, SQL Server, MongoDB, ACME) are not used.

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
  greeting's capability list; SMTP and POP3 need EHLO/CAPA, which a plain scan does not send, so they read "not
  checked", never "absent"; with `--identify` they read advertised or not advertised from the EHLO/CAPA reply), and an
  SMTP service on port 25 with no submission port.
- **`--compare PREVIOUS/report.json`** writes `diff.json` and `diff.txt`: findings new, fixed (the same port answered and
  the CVE no longer matches), gone with their port (not proof of a fix), still open and not rechecked (host absent or
  down, port not in the list, or a limit left it partly unchecked); services and versions changed; certificates changed
  (an issuer change is flagged for review, never as a compromise); observations new and resolved. The previous file is
  untrusted input: it is read and validated before anything is scanned (it must be a CyberView Scanner report, at most
  64 MB; only compared fields are kept, each type-checked and clipped).
- **`coverage --data DIR [--out kev-coverage.csv]`** compares the snapshot's KEV catalog with the scanner's fingerprint
  tables and lists the known-exploited products the scanner cannot identify. No scope file, no target, no network.
  (Products named only by modules outside `FINGERPRINT_TABLES` are not counted until they register there.)
- **`--dns-records`** writes `dns.csv` and `report.json`'s `dns` (see "Opt-in protocol checks" below).

### One CVE from the snapshot (`lookup`, no network)

`lookup CVE-… --data DIR` is a reader, not a matcher: an analyst with a CVE number from a bulletin, in a change freeze
or an air-gapped SOC, gets what the Vulnerabilities page would tell them without a browser or a network. It adds no data
path — the same `workbench.json`, `psirt.json` and CVE lookup file the scan reads, through the same `dirSource`
(`scanner/lib/lookup.mjs`).

It prints the identity, whether CISA lists it as known-exploited (with the catalog date, the deadline and whether it has
passed), EPSS, the CyberView rating with every note, and CISA's SSVC priority for **both** exposure answers, because no
inventory was given and assuming one would be a guess. Then the affected ranges as NVD states them, the vendor's fixed
versions, workarounds and advisory, and `detectionFor`: whether this scanner's own fingerprints can read the product's
version, name it only (findings stay low confidence), or not find it at all — stated as a detection gap, never as
evidence the product is absent. `--version` runs the engine's own comparison on a version the operator holds and names
the state it returned (`affected`, `check`, `clear`, `none`), each with the backport caveat.

A CVE the catalog does not hold is reported as absent, with why (the catalog is CISA's known-exploited flaws plus recent
high-risk ones, not every CVE), plus the CVE lookup row if the snapshot happens to have it. Nothing is invented for it.
Rule 11 and rule 15 hold: the exploitation analysis, check steps and signs of compromise stay on CyberView's page,
linked and never copied, and the guide and analysis are labelled as written by CyberView AI (a Claude model).

### Matching a list you already hold (`match`, no network)

Defenders who cannot scan — change freeze, third-party or air-gapped assets, "scanning is forbidden", or only an SBOM
from CI — get the same report from files they already have. `match --data DIR` takes `--nmap scan.xml` (nmap `-oX`, run
with `-sV`) and/or an inventory (`--sbom`, `--packages`, `--manifest`) and writes the five report files a scan writes.
No scope file, no attestation and no authorization gate: no host is contacted, and the module imports neither the probe
functions nor the web data source.

The adapter is `scanner/lib/inputs.mjs`. It returns the same host and service records `fingerprint.mjs` builds from a
real probe, so `match.mjs findings()`, the rating, CISA's priority and all five writers are the scan's own code,
unchanged — the scanner and the Vulnerabilities page cannot disagree about a product either way it was learned.

- **nmap `-oX`** gives real addresses, ports, products and versions. The `<service>` line's `product`/`version` are the
  label and the version; a `<cpe>` child supplies the vendor and, when it names the product differently
  (`http_server` for "Apache httpd"), that name is matched as well, because `nameHit` needs every word of a range's
  product to appear in the name. nmap's `version` attribute often carries build text ("8.2p1 Ubuntu 4ubuntu0.5"): the
  leading version is compared, the whole string is shown, and the rest is read for the distribution, so a distribution
  build is medium confidence (the fix may be backported) exactly as a banner read from the service would be. A service
  nmap named from its port table alone (`method="table"`), or with no version, is `guessed`, so it can never be high
  confidence. Hosts reported down and ports reported closed or filtered are skipped.
- **CPE and purl** are parsed for both nmap and SBOMs (`parseCpe`, `parsePurl`): CPE 2.2 and 2.3 (`*` and `-` are "any",
  not a version), and purl's namespace as the vendor with qualifiers and subpaths discarded. For an SBOM this fills in a
  vendor the site's `parseInventory` does not carry, which sharpens the match; SPDX falls back to the stated supplier.
- **An SBOM or package list has no address**, so it becomes one pseudo-host named after the file, with no port. Exposure
  is then unknown: it is rated as internal unless the operator states `--assume-exposed`, which moves only CISA's BOD
  26-04 deadline (the CyberView rating does not depend on exposure). A finding with no port prints as the file, not
  `file:null`, and its SARIF location is a `file://` artifact with a `resource` logical location.
- **The report says what it is.** `run.network` records `sent: 0` and that nothing was contacted, `coverage.from` is
  `files` with `complete: false`, a `match` block lists the inputs and the exposure assumption, and the first note says a
  host, port or product the files do not mention is absent, not clean.

### Relationship map, imports and offline rematch (no network)

`scan ... --depmap` also writes `depmap.json` and `depmap.mmd` (Mermaid), and a "Relationship map" section in
`report.html` with `--html`. It is computed from what the scan already read: services on one host (co-located, low
confidence), certificates with the same SAN list or naming another scanned host (medium), and recorded redirects inside
the scope (medium, never followed). Every edge carries whether it is inferred and its evidence. Names and addresses
outside the scope that appear in a certificate or a `Location` header are listed as "mentioned, not scanned"; in-scope
names the scan did not start from are listed as shadow IT. Both are only listed, never resolved or contacted.
Certificate and DNS answers that do not match the scanned address are listed for review (NAT or split-horizon DNS); no
new DNS query is made. Each host gets a 0–100 risk score with every point and the formula printed (per confirmed finding
+25 if known exploited, else +15 Critical, +8 High, +4 other; +5 ransomware; +5 past CISA's due date; +2 per
version-to-check finding, never KEV points; +10 for a public address with any finding; observations +4/+2/+1 by severity,
at most +15; capped at 100; from this report only, not a prediction). Each finding gets a blast radius: what shares its
host, its certificate or an imported relationship with it, each labelled with how (at most 200).

The operator's own files can add what a remote scan cannot see. All are optional, parsed only (never collected by the
scanner) and treated as untrusted: the size is checked before reading (16 MB; a Zeek `conn.log` 64 MB), at most 200,000
lines and 5,000 nodes or items and 20,000 edges per file (anything over a cap is counted, never silently dropped),
strings clipped and stripped of control characters, `JSON.parse` only.

| Flag | What it reads |
|---|---|
| `--sbom` | CycloneDX or SPDX JSON (components and their dependency relationships) |
| `--manifest` | Docker Compose or Kubernetes, **JSON only** (`docker compose config --format json`, `kubectl get ... -o json`); YAML is not parsed, and Secrets' data is never read |
| `--zeek` | a Zeek `conn.log` (TSV with `#fields`, or JSON lines): observed connections, counted |
| `--survey` | a Wi-Fi or Bluetooth survey CSV (a WiGLE export or any CSV with a MAC/BSSID column): inventory only |
| `--connections` | `/proc/net/tcp`/`tcp6`, `ss` or `netstat` output saved on the host itself; `--connections-host IP` attaches it to a scanned host |
| `--cloud` | a cloud CLI's describe/list JSON (`--cloud-provider aws-ec2`, `aws-elb`, `gcp` or `azure`): resources and their relationships |
| `--packages` | `dpkg -l`, `rpm -qa`, a Windows `Get-Package` export saved with `Export-Csv`, or an uninstall-key CSV, or any list the Vulnerabilities page reads |

Use them with `scan --depmap` (an import flag without `--depmap` is refused, and the files are read and checked before
anything is scanned), or offline, with no scope file because nothing is contacted:

- `import [files] [--data DIR]` writes `imports.json`; with a snapshot, packages and SBOM components are matched against
  KEV and NVD exactly like the Vulnerabilities page's "My software" (`matchFlaw`, `score`). Distribution package versions
  (dpkg, rpm) carry the backport caveat, so an affected match is medium confidence at most.
- `depmap --report R/report.json [--scope scope.json] [files]` builds the map from an earlier report. Without `--scope`
  the in-scope test uses only the report's recorded targets and exclusions, so more names land in "mentioned".
- `rematch --report OLD/report.json --data NEWER-SNAPSHOT` re-matches an old scan's recorded services with newer data and
  writes `rematch.json` and `rematch.txt`: newly matched, no longer matched, still matched. The old report is untrusted
  (it must be a CyberView Scanner report, at most 64 MB; only the service fields matching needs are kept, clipped). No
  target is contacted, so rescan to confirm.

Limits kept on purpose: Linux package names do not always match NVD's product names (`apache2` against `http_server`);
the site's matcher is used unchanged, so such packages stay unmatched rather than guessed. Container image tags from
manifests are listed, not matched. Shadow-IT names come only from certificate SANs and `Location` headers, because the
scanner sends only attested names as Host and SNI.

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

- **A frozen table, not a wordlist.** `scanner/lib/paths.mjs` holds 39 literal paths for 51 reviewed catalog rows. A path
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

- The Ivanti Connect Secure row (lead decision, 2026-11-22) reuses the Pulse Connect Secure row's existing version file,
  so the path count is unchanged; it is also hinted by a recorded root redirect into `/dana-na/`, and when both rows hint,
  one request is made. The file states a build number, not the release NVD's ranges use, so it is shown, never compared
  (the file is absent on newer releases).

Known gaps, kept on purpose: Tomcat usually answers `/docs` with a redirect to `/docs/`, which is recorded, not followed,
so a Tomcat version is read only where `/docs` answers directly; `/CHANGELOG.txt` covers Drupal 7, not Drupal 8 and later.

## Opt-in protocol checks (`--identify`, `--dns-records`, `--ics`; all off by default)

Lead decisions 10 and 11 allow new protocol messages only as opt-in families, each with its own flag, one standard
unauthenticated client message (or one fixed identification exchange) per service per host, frozen literals declared in
the run header's "what is sent" lines and enforced in section 7. Every exchange takes a Limiter slot, so the rate, the
per-host and total budgets, `--max-minutes` and Ctrl-C all apply. Nothing found this way carries a compared version: it
stays out of the headline counts. All byte layouts were written from the public specifications and are decoded field by
field in the tests; no live device was contacted while building them.

**Identify hellos (`--identify`, `scanner/lib/hello.mjs`).** One message per service, the reply's first lines read, then
the connection closed. TCP hellos go only to ports the probe found open and that are not implicit TLS (so SMTP and POP3
on 465 and 995 are skipped); the UDP ones go to every in-scope address, as `--udp` does, so UDP-only hosts are not missed.

| Service | Port | The one message, and what is read |
|---|---|---|
| SMTP | an open SMTP port (greeting 220) | `EHLO cyberview-scanner.invalid` then `QUIT`: the STARTTLS and SIZE keywords and the AUTH mechanism **names**. Never AUTH, MAIL, RCPT, VRFY, EXPN or STARTTLS |
| POP3 | an open POP3 port (greeting +OK) | `CAPA` then `QUIT`: the capability names. Never USER, PASS, APOP or STLS |
| RTSP | TCP 554, 8554 | one `OPTIONS *` request: the Server and Public headers. Never DESCRIBE, SETUP or PLAY (no stream) |
| SIP | TCP 5060; UDP 5060 when 5060 is in the port list | one OPTIONS with Max-Forwards 0 (answered by the target, never forwarded): User-Agent, Server, Allow. Never REGISTER or INVITE |
| mDNS / DNS-SD | UDP 5353 | one unicast service-type query (RFC 6763 section 9) from an ephemeral port, so the answer comes back to the scanner only; never multicast |
| RDP | TCP 3389 | one X.224 Connection Request with an RDP negotiation request (TLS or CredSSP offered): whether NLA is required. Never TLS, CredSSP, MCS or a login |
| SMB | TCP 445 | one SMB2 NEGOTIATE (dialects 2.0.2 to 3.0.2): the dialect chosen and whether signing is required. Never SMB1, SESSION_SETUP or TREE_CONNECT |
| LDAP | TCP 389 | one anonymous base-scope read of the root DSE for supportedLDAPVersion, vendorName, vendorVersion and objectClass, then an unbind. Never a bind, a subtree search or another attribute |
| BMC (`--identify-bmc`, needs `--identify`) | UDP 623 | one RMCP/ASF presence ping: whether a BMC with IPMI answers. No IPMI session, no authentication-capabilities or cipher request |

Results are in `hosts[].identify[]` (service, port, state, the verbs sent, and what was read; raw replies are never
stored), and as observations: `smtp-no-starttls`, `smtp-auth-cleartext`, `pop3-no-stls`, `rtsp-answers`, `sip-answers`,
`mdns-unicast`, `ipmi-exposed`, `rdp-no-nla`, `smb-signing-not-required` and `ldap-anonymous-rootdse`. Services named
from a hello are guessed and version-less. With `--mail`, `mail.csv` reads STARTTLS from the EHLO/CAPA reply. Not built:
SMB 3.1.1 (it needs negotiate contexts; a server that offers only 3.1.1 answers with an error, which is recorded), EHLO
over implicit TLS, mapping an IPMI OEM enterprise number to a vendor.

**DNS records (`--dns-records DOMAIN[,DOMAIN]`, `scanner/lib/dns-records.mjs`).** Only host names listed in the scope
file's targets (anything else is refused before any query; at most 16). One query each to the system resolver: SPF (TXT),
DMARC (`_dmarc` TXT), CAA, BIMI (`default._bimi` TXT) and MTA-STS (`_mta-sts` TXT); `--dkim-selectors s1,s2` (at most 8,
needs `--dns-records`) adds DKIM for the selectors the operator names. **DKIM selectors are never guessed.** Nothing is
sent to the targets. Results go to `report.json` (`dns`) and `dns.csv`, with observations for SPF (missing, multiple,
`+all`, `?all`, no `all`), DMARC (missing, multiple, no policy, `p=none`), a missing CAA and a DKIM RSA key under 1,024
bits (only the key type and length are kept, never the key). Not done: DNSSEC presence (`node:dns` cannot ask for DS or
DNSKEY), the MTA-STS policy file (an HTTPS request awaiting a path-rail review), zone transfers, ANY, brute force,
look-alike names.

**Industrial and clinical identification (`--ics`, `scanner/lib/ics.mjs`).** One read-only identification exchange per
protocol per host, only to private, loopback or link-local addresses (a public address is refused per host, even with
`--i-am-authorized-for-public-ranges`), only on the protocol's standard port, only when that port is in the port list
(none is in the default list, so name them with `--ports`) and, for TCP, the probe found it open:

| Protocol | Port | Sent (each step only after the expected reply) | Why it cannot change the device |
|---|---|---|---|
| Modbus/TCP | TCP 502 | one Read Device Identification (function 0x2B, MEI 0x0E, basic objects; unit 0xFF) | a read of identification objects; no coil or register read, no write or diagnostics function; "more follows" is never followed |
| EtherNet/IP | TCP 44818 | one ListIdentity (encapsulation command 0x63, no session); covers Rockwell | no session registration, no CIP service |
| S7comm | TCP 102 | COTP Connection Request, S7 Setup Communication, one system-status read (SZL ID 0x0011, module identification) | Setup only negotiates the PDU size; no variable read or write, no start, stop, program or block function |
| BACnet/IP | UDP 47808 | one unicast Who-Is to the host's own address, sent by `udp.mjs` (one datagram, no retransmit) | an unconfirmed discovery request; never a broadcast BVLC, never a DNET (routers would re-broadcast it), no broadcast socket option, IPv4 `.0` and `.255` addresses refused; no ReadProperty |
| OPC UA | TCP 4840 | Hello, OpenSecureChannel (SecurityPolicy None, no certificate), GetEndpoints | no CreateSession or ActivateSession, so no login, Read, Browse, Write or Call is possible; the server certificate is skipped, never kept |
| DICOM | TCP 104 | A-ASSOCIATE-RQ for the Verification SOP class only, then A-RELEASE-RQ after an accept | no P-DATA, so no DIMSE command, not even C-ECHO; a rejection ends the exchange |

Results are inventory only, in `report.json` (`hosts[].ics[]`: protocol, port, messages sent, outcome, and the vendor,
product, model and firmware where the device states them; `version_stated` only where the protocol's own field states a
version). They are not matched to KEV or NVD (device names do not map cleanly to NVD's) and are not yet shown in
`summary.txt`, `inventory.csv` or `report.html`. Known limits: the S7 module or plant name needs a second read and is not
read, and a PLC that refuses the one TSAP is not retried; BACnet devices that answer only with a broadcast I-Am are not
heard (the scanner does not listen for broadcasts); an OPC UA GetEndpoints reply over 16 KB is recorded as an error;
DICOM only on 104, not 11112; DNP3 and FHIR are not included (see Decisions).

### What `--identify` asks each service (wave 4)

Four more services answer one standard message each, all behind the same `--identify` flag and all off by default. The
request for each is a frozen byte sequence built field by field from that protocol's own published specification, with
the derivation written beside it in `scanner/lib/hello.mjs` and the bytes locked in `REVIEWED_HEX`
(`scripts/lib/scanner-hello-check.mjs`), so section 7 fails if one byte changes.

| Service | Port | The one message | What is read |
|---|---|---|---|
| Apache Kafka | 9092 | `ApiVersions` v0, null client id | presence and the API count. **No release number**: no published mapping from an API set to a Kafka release exists |
| Redis | 6379 | `PING` (RESP array of one bulk string) | `+PONG` means **no password at all**; a `-` error reply means one is set |
| MQTT broker | 1883 | `CONNECT` (clean session, no user name, password or will), then `DISCONNECT` | the CONNACK return code: whether the broker **accepts anonymous connections** |
| MongoDB | 27017-27019 | `hello` as one OP_MSG | standalone, replica set member or mongos, and the wire-version range **as the numbers it states** |

Three of the four answer a posture question rather than a version question, and that is the point: an unprotected Redis
or an MQTT broker that takes anonymous connections is a more direct route into an organisation than most unpatched
versions are. None of the four reads data: Redis `INFO` was rejected for reading configuration and metrics, and the
MongoDB and Kafka messages are the handshakes their own clients send before anything else.

Two details are deliberate. MQTT sets Clean Session, because leaving it clear would make the broker **create and keep
session state** for the scanner's client id — a change to the operator's own broker. And the MongoDB finding says in so
many words that `hello` is answered before authentication by design, so it does **not** show whether access control is
enabled; the alternative would be a reassuring sentence that happens to be wrong.

## Deliberately left out

Credentialed (authenticated) scanning; password, community-string or any credential guessing; protocol commands beyond the
greeting, the SSH identification line, the three benign UDP queries and the opt-in families above (for example Redis or
database queries, SNMP writes or walks, any login, bind or session, any industrial write or control function, a client
KEXINIT or any key exchange, so no SSH host key is ever collected); broadcast or multicast; guessing DKIM selectors or
transferring zones; following
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
off sends nothing extra, the parsers on canned responses, and each section 7 failure case). Wave 3 adds
`scanner-pack3.test.mjs` and `scanner-research.test.mjs` (every rule and its look-alikes, the site's `nameHit` on the KEV
spellings, identifiers never stored, a greeting service sent zero bytes, a web service exactly one root request),
`scanner-reportpack2.test.mjs` (each import format, hostile imports, matching equal to the site's, the map's edges, risk
points and blast radius, and `import`, `depmap` and `rematch` run with every network call replaced by a trap: zero calls),
`scanner-hello.test.mjs` and `scanner-ics.test.mjs` (the exact bytes each loopback stand-in receives per protocol, later
steps not sent after a refusal, one datagram and no retransmit on a silent port, nothing sent without the flag, a public
host, an unlisted port or a spent budget, and a mutation test for every checker rule), and `scanner-view.test.mjs` (the
Scanner page's viewer and builder against the real `diff.mjs`, `checkScope` and the CLI's `check`).

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
    enumerates users, shares or zones, or authenticates, is rejected. Built as `--identify` (#122).
11. **Industrial (ICS/OT) identification reads: allowed only behind an explicit `--ics` opt-in**, one read-only
    identification request per protocol, private ranges by default, never a write or a function that changes state.
    Built in #121, private ranges only (a public address is refused even with the public flag).
12. **Single-file executables and tagged GitHub Releases (Grok brief #89): approved** as part of the full build. Releases
    are built from tags by CI, with checksums. Built in #118.
13. **A browser report viewer and scope-file builder on the Scanner page: approved** (the owner asked earlier; it waited
    for the other work). A real network scanner in the browser is not possible and is not built. Built in #124: both run
    in the visitor's browser only, and nothing is uploaded or kept.

Wave 3, taken by the build lead on 2026-11-22 under the same instruction:

14. **Netlogon: rejected.** No Netlogon exchange is added to `--identify`: any Netlogon/NRPC call is an enumeration and exploit surface, not an identification read.
15. **Docker Desktop: out of scope.** Its flaw is local to the workstation, so a network scan cannot see it.
16. **Path-rail candidates rejected:** `/.git/HEAD`, `/sitemap.xml`, `/.well-known/change-password`,
    `/.well-known/caldav`, Keycloak's OpenID configuration document and vLLM's version endpoint. None is in the rail's
    table; the products stay identified from the root page where they can be. Reasons: `/.git/HEAD` exposes repository
    data; `/sitemap.xml`, the two `.well-known` files and vLLM's `/version` name no product or have nothing on the root
    page to hint them; Keycloak's path was not confirmed by a source.
17. **Ivanti Connect Secure's version file: accepted on the rail.** The same literal path the Pulse Connect Secure row
    already requests, so no new path; its build number is shown, never compared.
18. **`robots.txt` as a fingerprint source: rejected.** It is not requested: it names paths, not a product or version, so it gives no hint the rail could use.
19. **Mirth Connect: identified in normal scans, root page only.** No separate clinical opt-in; the exact administrator
    page title on the root page is the only signal, and nothing more is requested.
20. **DNP3: deferred** until an operator-supplied outstation address exists in the scope file (with its own Design). A
    fixed guess would rarely match, trying several would be enumeration, and the all-stations addresses are DNP3
    broadcast.
21. **RDP X.224, SMB2 NEGOTIATE and the LDAP root DSE: added to `--identify`.** One message each; the LDAP read asks for
    four attributes (supportedLDAPVersion, vendorName, vendorVersion, objectClass) with no bind.
22. **`hello.mjs` may own a UDP socket** under the `scanner-hello-check` rules (one datagram send, frozen reviewed bytes, no
    broadcast or multicast), as the second file beside `udp.mjs`. The `--ics` BACnet query still goes through `udp.mjs`.
23. **Four more identify hellos: Kafka ApiVersions, Redis PING, MQTT CONNECT, MongoDB `hello` (wave 4).** Each is a
    Design under decision 10, built only from the protocol's own published specification, read for this build:
    - **Kafka** `ApiVersions` v0 with a null client id (kafka.apache.org/protocol). The page states a broker "returns
      its full list of supported ApiKeys and versions regardless of current authentication state", so this is the
      protocol's own pre-authentication handshake, not a way around authentication. Presence and the API count only: the
      page publishes no mapping from an API set to a Kafka release, so **no release number is claimed**.
    - **Redis** `PING` as a RESP array of one bulk string (redis.io protocol spec). PING is the protocol's liveness
      command: it reads no key and changes nothing. `INFO` was **rejected** — it would give a version, but it reads the
      server's configuration and metrics, which is more than identification. The answer still carries the finding that
      matters: `+PONG` means no password at all, an error reply means one is set. The error is matched by its `-` prefix
      and first word only, because the exact text of Redis's authentication error is not on any page read for this
      build and will not be written from memory.
    - **MQTT** 3.1.1 `CONNECT` with no user name, no password and no will, then `DISCONNECT` (OASIS mqtt-v3.1.1-os).
      Clean Session is set deliberately: with it clear, the broker would have to **create and keep session state** for
      the scanner's client id, which would leave something behind on the operator's own broker. The client id is 16
      bytes of `0-9a-zA-Z`, inside the 1-to-23 range of that character set a server MUST accept ([MQTT-3.1.3-5]), so
      the probe never depends on a MAY. The CONNACK return code says whether the broker accepts anonymous connections.
    - **MongoDB** `hello` as one OP_MSG (the wire protocol page and the BSON 1.1 specification). It is the handshake
      every driver sends and reads no collection. It is answered **before authentication by design**, so the finding
      says the port is reachable and explicitly says it does *not* show whether access control is on. `maxWireVersion`
      is reported as the number it is: no page read for this build publishes a wire-version-to-release table, so none
      is inferred.
24. **SQL Server TDS PRELOGIN: deferred, not rejected.** It is the most valuable of the candidates, because PRELOGIN
    returns an exact build number before authentication, and the PRELOGIN body itself is fully specified ([MS-TDS]
    2.2.6.5: 5-byte options, big-endian offsets, VERSION first, TERMINATOR 0xFF). Three questions were left unanswered
    by the pages read, and a reviewed byte sequence will not be frozen around a guess:
    - the **Window** field of the 8-byte packet header is not described on the Packet Header page or any page it links
      to, so what a client must send there is unknown;
    - the **base of `PL_OFFSET`** is not stated (from the start of the PRELOGIN body, or of the whole packet);
    - the Length page says Length "MUST be greater than or equal to 512 bytes", which a ~30-byte PRELOGIN packet
      cannot satisfy; the page's "until Length is successfully negotiated" and "has not logged in" clauses may be the
      intended exception, but it does not say so.
    Resolving these (the [MS-TDS] PDF, or the Type and Window subsections) is all that stands in the way.
25. **JetDirect PJL `INFO ID`: rejected.** TCP 9100 is a raw print channel. A device that is not PJL-aware prints what
    it receives, so the probe would push a page of text out of the operator's own printers — a physical side effect on
    their hardware. Detection-only means no side effects, not merely no exploitation. Printers stay identified from
    their HTTP server and certificate, without a version.
26. **NetBackup vnetd and the ACME `acme-tls/1` ALPN: deferred.** The vnetd greeting needs a non-NULL probe with no
    public specification to build it from. The ACME check is not a hello at all: it needs a TLS handshake offering a
    named ALPN protocol, which `hello.mjs` may not do (section 7 allows it no `tls.connect`); it belongs with the TLS
    code, with its own Design, if ever.
27. **Oracle TNS `(CONNECT_DATA=(COMMAND=version))`: deferred.** Oracle publishes no specification of the TNS wire
    format, so the bytes could only come from a reverse-engineered third-party source. The listener's version command
    is also commonly restricted, so the probe would often be refused even when correct.
28. **`match` ships with `--assume-exposed`, defaulting to internal.** An SBOM or package list carries no address, so
    exposure cannot be read. The Discovery recommendation was to ship the internal default and add the flag later; both
    are in, because the flag changes only CISA's deadline and the alternative is silently rating an internet-facing
    inventory as internal. `match` stays offline-only (`--data DIR`, no `--online`), so one command never both downloads
    and matches.

## Releases

The scanner is also published as one file, `cyberview-scan-<version>.mjs`, on GitHub Releases (tag `scanner-v<version>`),
with `SHA256SUMS` and `LICENSE`. `scripts/scanner-release.mjs` builds it with no dependencies: the entry and every
`scanner/lib` module it imports, copied verbatim into their own function scopes, and `site/workbench-lib.js` and
`site/cvedb-lib.js` embedded and run with `node:vm` exactly as `scanner/lib/shared.mjs` runs them from disk. The build
is deterministic (same commit, same checksum). `tests/unit/scanner-release.test.mjs` proves the bundle holds no code the
source lacks and behaves like the source CLI (same refusals, same WHAT IS SENT, same bytes on a loopback scan). The
bundle is never committed; the security check refuses one in the repository.

Cutting a release (owner):

1. Set `VERSION` in `scanner/lib/probe.mjs` to the new version in a pull request and merge it.
2. Tag that commit on main and push the tag:

       git checkout main && git pull
       git tag scanner-v1.1.0
       git push origin scanner-v1.1.0

3. `.github/workflows/scanner-release.yml` checks the tag matches `VERSION` (it stops otherwise), runs the security check
   and the scanner tests, builds the file, writes `SHA256SUMS` and publishes the release. To try the build without
   releasing, run the workflow by hand (Actions → Scanner release → Run workflow): it uploads the files as an artifact only.

## Licence

The scanner is a proprietary CyberView product under `scanner/LICENSE` (CyberView as a whole is proprietary; this sets the scanner's end-user terms): download and use on systems you own or are authorised to test, no redistribution without permission.
