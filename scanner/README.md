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

An overview, with live counts of the products it can identify, is on CyberView's
[Scanner page](https://xanderhutch.github.io/CyberView/scanner.html).

## What you need

- Node.js 22 or later (`node --version`). Nothing else to install: the scanner uses Node's standard library only.
- The scanner itself, in one of two ways:
  - **One file (recommended).** From the repository's [Releases](https://github.com/xanderhutch/CyberView/releases),
    take the latest `scanner-v…` release and download `cyberview-scan-<version>.mjs` and `SHA256SUMS` into one folder.
    Check the file before you run it:

    ```
    sha256sum -c --ignore-missing SHA256SUMS            # Linux
    shasum -a 256 -c --ignore-missing SHA256SUMS        # macOS
    (Get-FileHash .\cyberview-scan-<version>.mjs -Algorithm SHA256).Hash   # Windows PowerShell: compare with SHA256SUMS
    ```

    It must print `cyberview-scan-<version>.mjs: OK` (on Windows, the same hash as in `SHA256SUMS`). Then run it with
    `node cyberview-scan-<version>.mjs` wherever the commands below say `node scanner/cyberview-scan.mjs`. The file is
    the scanner and the site's matching and rating code in one, built by CI from the tagged commit (named in its first
    lines); it contains nothing the repository's scanner does not.
  - **From the repository** (developers): [download the ZIP](https://github.com/xanderhutch/CyberView/archive/refs/heads/main.zip)
    or clone it, then run the commands below from the repository's folder.

## Quick start

```
node scanner/cyberview-scan.mjs init --out scope.json        # 1. write a scope file
#   2. edit scope.json: owner, contact, targets; set attestation.agreed to true and attestation.name to your name
node scanner/cyberview-scan.mjs check --scope scope.json     # 3. check it; nothing is scanned
node scanner/cyberview-scan.mjs scan --scope scope.json --online
```

With the one-file release, the same steps are:

    node cyberview-scan-<version>.mjs init --out scope.json
    node cyberview-scan-<version>.mjs check --scope scope.json
    node cyberview-scan-<version>.mjs scan --scope scope.json --online
    node cyberview-scan-<version>.mjs data --out cyberview-data          # air-gapped: on a connected machine
    node cyberview-scan-<version>.mjs scan --scope scope.json --data cyberview-data

The help text still shows `node scanner/cyberview-scan.mjs`; the commands and flags are the same.


For an air-gapped network, download the data on a connected machine, carry the folder across, and scan offline:

```
node scanner/cyberview-scan.mjs data --out cyberview-data            # on a connected machine
node scanner/cyberview-scan.mjs scan --scope scope.json --data cyberview-data
```

`data --full` also downloads every CVE lookup file (about 300,000 CVEs). With a full snapshot the report adds, per
product, how many other CVEs in the CVE List name it; those carry no version ranges, so they are listed as leads to check,
never as findings.

`--data-incidents` (on `data` and on `scan`, off by default) cites, per finding, the reviewed CyberView incidents that
name its CVE: title, date and a link, with who attributed it only when a government or the investigating firm did.
Attackers' claims are never cited, only counted as unconfirmed. On `data` it adds a small, trimmed event archive to the
snapshot for offline use; without it no archive file is read.

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
- `--paths` (off by default) adds at most 8 GET requests per host for frozen, reviewed version/status files, only where
  the host's own root page, headers, certificate or port already point at that product (see "what goes over the
  network"). `--paths-per-host N` lowers the cap; `--paths-bmc` adds BMC identification (Redfish service root). Both
  are refused without `--paths`.

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
| SSH | After reading the server's banner, its own identification line, `SSH-2.0-CyberViewScanner_<version> authorized-vulnerability-scan`, so your logs show who connected. It then reads, on the same connection, the list of algorithms the server advertises (its KEXINIT; at most 4 seconds and 16 KB) and closes. It sends no algorithm list of its own and does no key exchange, so it never sees the host key. |
| Web (80, 8080, 8000, 8008, 8888, ... and `--http-ports`) | One HTTP request for the root page (method GET, path "/"), with the User-Agent below. Redirects are recorded, not followed. |
| TLS (443, 8443, 993, 995, 465, ... and `--https-ports`) | A standard TLS handshake to read the certificate (read, never trusted), then on web ports the same single request. |

With `--udp`, one benign read-only UDP datagram per service per host (never more; no retransmit, no raw packets — node
`dgram` only):

| UDP service | The single datagram sent |
|---|---|
| DNS (53) | A `version.bind` query: QNAME `version.bind`, type `TXT`, class `CHAOS`. Reads the resolver's stated version. |
| NTP (123) | A mode-6 (control) **read-variables** request (opcode 2), no payload. Reads ntpd's version/system string. |
| SNMP (161) | One SNMPv1 `GET` of `sysDescr` (OID `1.3.6.1.2.1.1.1.0`) with the standard read community **`public`** only. No other community is ever tried; there is no walk and no write. |

With `--paths` (off by default), at most 8 extra HTTP requests per host, method GET, the same User-Agent, one
connection each, each for a literal path from the reviewed table in `scanner/lib/paths.mjs`, and only when that host's
own root page, headers, certificate or port already hint at the product. Redirects are recorded, not followed; only a
product and version token is kept. Every request's status, and every hinted path the cap or a budget left unsent, is in
the report's coverage. Without `--paths`, a web port gets the one root-page request and nothing else.

Every web request carries the User-Agent
`CyberView-Scanner/<version> (authorized vulnerability scan, detection only; +https://xanderhutch.github.io/CyberView/vulnerabilities.html#scanner)`.

A host is first tried on up to four discovery ports (22, 80, 443, 3389 when in the list), then on the rest of the port
list even if none of those answered (a firewall or IPS may drop the first probes); a host that answers on no port is
reported in Coverage as unreachable, never as clean. `--assume-up` skips the discovery-port step.

Host names in the scope are resolved with your system's resolver. With `--online` the scanner also downloads CyberView's
public data, read-only, with GET requests and no key, cookie or account, from `https://xanderhutch.github.io/CyberView/`:

- `data/workbench.json`: the known-exploited flaws with affected-version ranges, CISA's due dates and required actions,
  EPSS, and fix guides
- `data/psirt.json`: vendors' own advisories joined on CVE
- `data/cve/index.json` and `data/cve/<year>/<n>.json`: the CVE lookup files (CVSS, CISA's SSVC assessment, KEV date,
  EPSS) for the CVEs that matched
- only with `--data-incidents`: `data/archive/search.json` and the `data/archive/<YYYY-MM>.json` months that hold
  events naming a matched CVE

KEV and EPSS arrive inside those files; the scanner never contacts CISA, FIRST or NVD itself. With `--data` it makes no
data request at all. It **never uploads anything**: no findings, no scope, no addresses, no telemetry. Results are
written only to the output folder on your machine, readable only by you.

## What it identifies

From the greeting, the root-page response and the certificate it has already read (no extra request), besides the
SSH, web, mail and database servers it names from their banners and headers:

- **SSH algorithms**: the key-exchange, host-key, cipher and MAC algorithms the server advertises; weak ones from a
  fixed list are reported, post-quantum key exchange is noted.
- **CMS and JavaScript libraries**: WordPress (and the plugins and themes its page names), Drupal, Joomla, Craft CMS,
  DotNetNuke, Kentico, October CMS, Sitefinity, SAP Commerce Cloud, ThinkPHP, cPanel & WHM, XWiki, and jQuery, jQuery UI,
  Bootstrap, AngularJS, Lodash, Moment.js, Vue.js, Handlebars and Underscore. A WordPress `?ver=` number is shown in the
  inventory but never compared.
- **Edge and appliance products**: Array Networks, Aviatrix, Cisco vManage / DCNM / ACS, D-Link, DD-WRT, Ivanti CSA,
  Juniper ScreenOS, Microsoft TMG, NETGEAR WAP, Palo Alto Expedition, Kemp LoadMaster, Sierra Wireless ALEOS, SonicWall
  SMA 1000, Sophos, TP-Link, Zyxel and Brocade Fabric OS.
- **Applications**: Jenkins, MOVEit Transfer, GoAnywhere MFT, CrushFTP, WS_FTP Server, Rejetto HFS, Accellion FTA,
  ProjectSend, SysAid, ServiceNow, NAKIVO, VeraCore, Citrix ShareFile, SharePoint, ONLYOFFICE, Oracle Fusion Middleware
  and Business Intelligence, Telerik UI and Report Server, Apache Axis2, HugeGraph, Kylin and Spark, Ray, Kestra, QNAP,
  D-Link and TerraMaster NAS, Envoy, and the frameworks ASP.NET, Django, Express, Laravel, Rails and Yii; mail gateways,
  IT management consoles, proxies and small web servers such as Cisco Secure Email Gateway, MDaemon, SmarterMail,
  WhatsUp Gold, N-central, ManageEngine, Splunk, SolarWinds Orion and Serv-U, Superset, Jaspersoft, APISIX, GoAhead,
  nostromo, HAProxy, Squid, Traefik and Varnish.
- **Around 30 more products** (management consoles, message brokers, search engines, cameras, VoIP and mail servers),
  for example GitLab, ActiveMQ, CouchDB, Elasticsearch, OpenSearch, phpMyAdmin, VMware ESXi, vCenter and Aria
  Operations, Hikvision, PaperCut, Openfire and Grandstream UCM6200.

Most of these do not state a version where the scanner looks. They are listed as "version not read" and reported as
"check by hand" at low confidence, outside the headline counts. A version is compared with the affected ranges only
where the product states its own release; a number that is not the release (a cache-buster, a component or runtime
version, a build number, a login-page title) is shown but never compared. With `--paths`, a few products can also be
versioned from a documented version file. `coverage` (below) lists the known-exploited products the scanner cannot
identify yet.

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
report for what was checked (exit code 3); a second Ctrl-C quits at once. The exit code is **0** when the scan was
clean and complete, **2** when coverage was incomplete (a host or port could not be checked — see the Coverage section
below; a clean result does not cover it), **3** when the scan stopped early, and 1 on an error.

## The report

Written to `cyberview-scan-<time>/` (or `--out`):

- `summary.txt`: hosts, services, findings, how many are known exploited, Critical, at priority Act or past CISA's
  deadline — these headline counts are the **confident** findings only; low-confidence guesses are counted separately as
  `low_confidence` and still listed in full, so a pile of maybes never reads as confirmed criticals — a **Coverage**
  section when the scan could not see everything (hosts that answered on no port, filtered ports, banners cut off before a
  version was read, ports left unchecked when a limit was hit), then each finding.
- `report.json`: everything, including the attestation, the scope, the limits used, what was sent and every service seen.
- `findings.csv`: one row per CVE and place it was seen.
- `report.sarif`: SARIF 2.1.0, for dashboards that read code-scanning results.
- `inventory.csv`: the software found, in the format the Vulnerabilities page's "My software" view imports.

Optional extra files, built only from what the scan already read (none of them sends anything more to your hosts):

- `report.html` (with `--html`): the same report as one page to open in a browser or send on; it loads nothing and runs
  no script, and every value from your hosts is escaped. Findings that may already be fixed by a distribution backport
  are marked "Possibly already fixed".
- `certs.csv` (with `--certs`): certificate inventory and reuse — validity, key, signature, fingerprint, serial, SANs,
  wildcards, internal names, embedded SCTs, must-staple, and the same certificate or key on more than one address.
- `mail.csv` (with `--mail`): mail services and STARTTLS as far as the greetings already read show it (IMAP's
  capability list; SMTP and POP3 read "not checked", because the scanner does not send EHLO or CAPA).
- `diff.json` and `diff.txt` (with `--compare old/report.json`): what changed since that scan — findings new, fixed,
  gone, still open or not rechecked; services, versions, certificates and observations changed. The old file is checked
  before anything is scanned.

`check` and `scan` also print advice when a scope file passes its checks but looks wrong (an unknown key, a duplicate
target, an attestation about to expire), and a scan warns when CyberView's data is more than 7 days old.

To see which known-exploited products this scanner cannot fingerprint yet (offline; no scope needed, nothing contacted):

```
node scanner/cyberview-scan.mjs coverage --data cyberview-data --out kev-coverage.csv
```

`summary.txt` and `report.json` also list **observations**: problems that are not CVEs, worked out only from what the one
connection already returned (no extra connection or request), each with a severity (high, medium, low), most severe
first, at most 60 per host:

| Observation | When |
|---|---|
| `tls-expired`, `tls-expiring`, `tls-not-yet-valid` | the certificate has expired, expires within 30 days, or is not valid yet |
| `tls-self-signed` | the certificate's subject and issuer are the same |
| `tls-weak-key` | an RSA or DSA key under 2048 bits, or an EC key under 224 bits |
| `tls-weak-signature` | the certificate is signed with MD2, MD5 or SHA-1 |
| `tls-name-mismatch` | the scan reached the host by a name from your scope and the certificate does not name it |
| `tls-old-protocol` | the handshake negotiated SSL 3.0, TLS 1.0 or TLS 1.1 (retired by RFC 8996) |
| `tls-weak-cipher` | the negotiated suite uses NULL, export, RC4, DES or 3DES, MD5, or no authentication |
| `tls-weak-dh` | the ephemeral Diffie-Hellman group is under 2048 bits |
| `tls-no-forward-secrecy` | the negotiated suite uses RSA key exchange |
| `http-missing-headers` | a page (2xx HTML) lacks Strict-Transport-Security (HTTPS only), Content-Security-Policy, X-Content-Type-Options, X-Frame-Options or CSP `frame-ancestors`, Referrer-Policy, or Permissions-Policy (one observation listing them) |
| `http-weak-hsts`, `http-weak-csp`, `http-weak-referrer-policy` | HSTS `max-age` under 180 days; CSP allowing `'unsafe-inline'` or `'unsafe-eval'` for scripts; Referrer-Policy `unsafe-url` |
| `http-cookie-not-secure`, `http-cookie-not-httponly` | a cookie set without `Secure` over HTTPS, or without `HttpOnly` (cookie **names** only; values are never copied) |
| `http-cors-wildcard` | `Access-Control-Allow-Origin: *` on the root page |
| `http-no-https`, `http-downgrade-redirect`, `http-redirect-out-of-scope` | a page served over plain HTTP with no redirect; HTTPS redirecting to `http://`; a redirect to a host outside your scope (recorded, never followed) |
| `http-default-page`, `http-setup-page`, `http-directory-listing` | a known default welcome page, an unfinished installer (WordPress, Joomla, Drupal, phpMyAdmin, Matomo), or a directory listing, by page title |
| `http-debug-page`, `http-debug-header`, `http-source-map` | debug output on the root page (Django debug, Werkzeug, Whoops, ASP.NET, Rails, PHP errors, Java or Python stack traces), a Symfony-style `X-Debug-Token`, or a JavaScript source map — the marker's **name** only; the page text is never copied |
| `http-trace-allowed`, `http-webdav`, `http-alt-svc` | the `Allow` header the server sent lists TRACE or TRACK, WebDAV is advertised, or `Alt-Svc` advertises HTTP/2 or HTTP/3 (no OPTIONS request is sent) |
| `http-cdn-front` | the response came through a CDN or WAF (Cloudflare, CloudFront, Akamai, Fastly, Imperva, Sucuri, Azure Front Door, Vercel): the results describe the front, not the origin |
| `http-clock-skew`, `http-server-version`, `http-server-patch-level` | the server's `Date` is more than 5 minutes off; the `Server` header states a version, or a version and a distribution package build |
| `cleartext-mail`, `cleartext-submission` | POP3 (110) or IMAP (143) answering without TLS; SMTP submission (587) without TLS (whether STARTTLS is required is not checked) |
| `cleartext-login` | Telnet, or FTP that does not show it requires TLS |
| `snmp-public` | with `--udp`: SNMP answers the default `public` community |
| `ssh-weak-kex`, `ssh-weak-hostkey`, `ssh-weak-cipher`, `ssh-weak-mac` | the SSH server offers a weak algorithm from a fixed list (SHA-1 key exchange, DSA or SHA-1 RSA host keys, CBC, 64-bit block or RC4 ciphers, MD5 or 96-bit SHA-1 MACs); every name is listed with its reason. Offering is not using: a modern client picks a strong one first |
| `ssh-pqc-kex` | information: the SSH server offers post-quantum hybrid key exchange (ML-KEM, sntrup761) |

The TLS findings describe what **this scan's one handshake** negotiated; a different client can get different
parameters, and the scanner never enumerates protocols or ciphers. The key-exchange group is recorded as Node reports it
(for example `X25519`, or a Diffie-Hellman size). When a TLS 1.3 server picks a hybrid post-quantum group such as
`X25519MLKEM768`, Node does not name it, and the report says "not reported" rather than guessing either way.

Each finding shows the CVE, where it was seen (address, port, product, the version as stated), and:

- **Ranking**: known exploited (CISA KEV) first, then other evidence of exploitation, then past CISA's deadline; within
  those, the CyberView rating.
- **CyberView rating**: the CVSS base score adjusted for exploitation evidence (CVSS v3.1 Exploit Code Maturity), with the
  whole calculation written out; CISA's SSVC priority (Track, Track*, Attend, Act) with every input and its source; and
  the patch-queue points with the reason for each point.
- **Confidence**: high when the service stated a version inside the affected range; medium when it is a Linux
  distribution's package build (the distribution may have backported the fix under the old version number) or the
  product was inferred; low when the product was seen but its version could not be read. A service the scanner can name
  but not version (an OpenSSH banner with no release string, a bare `220` FTP or SMTP greeting) is reported at low
  confidence under its product, so you still see it as something to check — it just stays out of the headline counts.
- **Fix**: the fixed versions (from NVD's ranges and the vendor's advisory), workarounds, CISA's required action, the
  vendor advisory's link, and the CVE's page on CyberView. Check steps, signs of compromise and detection resources are
  linked there, not copied. Exploitation analyses and fix guides are written by CyberView AI (a Claude model) from vendor
  and government sources, and say so.
- **Hunt**: links to publishers' detection files for the CVE (Sigma, YARA, STIX and so on), links only; their contents
  are never downloaded or copied.
- **Incidents** (with `--data-incidents`): the reviewed CyberView incidents that name the CVE, with title, date and link;
  attackers' claims are counted as unconfirmed, never cited.

A clean result is not proof that a host has no vulnerabilities: the scanner knows only the flaws CyberView's data covers,
and a service can hide or misstate its version. It also does not cover whatever the **Coverage** section lists — a host
that answered on no port (a firewall or IPS may be dropping probes), a filtered port, or a banner that was cut off before
its version could be read. The scan probes beyond the first few ports before calling a host unreachable, and reports what
it could not reach rather than passing a blind spot off as clean (exit code 2 when coverage is incomplete). If a host
resets connections after it has answered (an IPS or fail2ban throttling the scan), the scanner backs off once and
re-probes those ports one at a time, recovering services the first pass was blocked from, and notes it in Coverage — if
anything still looks thin, re-scan slower with `--rate 0.1`.

## What it deliberately does not do

- No exploitation, payloads, injection strings or crafted input; no checks that work by triggering a flaw.
- No logins, password guessing, credential testing, SNMP community-string guessing, hash capture or cracking.
- No denial of service, flooding or amplification; the UDP checks send exactly one benign datagram per service per host
  (no retransmit); no raw sockets; no mode that removes the rate limit.
- No evasion: no spoofed addresses, no stealth or fragmented packets, no disguised User-Agent.
- No scanning of addresses outside the scope file (discovery is re-checked against it), and no wide sweeps of public
  address space (the public cap is a hard stop).
- The scanner never runs your cloud CLI and never reads or stores your cloud or API keys.
- It does not fetch a page's scripts or stylesheets, or try plugin or theme names from a list: CMS and library versions
  come from what the root page itself names (and, only with `--paths`, from the few reviewed version files in the path
  rail's table, such as three WordPress plugin readmes).
- No crawling, no wordlists and no paths you supply: the optional path rail requests only the reviewed literal paths in
  `scanner/lib/paths.mjs`, never a login or management page, and is off unless you pass `--paths`.

`scripts/security-check.mjs` checks the scanner's code for these on every change. More detail: `docs/scanner.md`.

## Licence

Copyright (c) 2026 xanderhutch (the CyberView maintainer). All rights reserved.

The CyberView Scanner is a **proprietary CyberView product**, licensed under
`scanner/LICENSE`. CyberView as a whole is proprietary (root `LICENSE`); this
file sets the scanner's end-user terms. You may download and use it to scan systems you own or are
authorised in writing to test, including inside your own organisation; you may
not redistribute, modify for distribution, sublicense or sell it without
written permission. It is provided with no warranty. For permissions beyond the
licence: cyberviewthreats@gmail.com.
