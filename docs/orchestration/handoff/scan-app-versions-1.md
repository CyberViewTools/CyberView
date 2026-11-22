# Handoff: scan-app-versions (passive pack 1) — application products from data already collected

Swarm run plan_id w2-7c1e. Slice: `scan-app-versions`, passive pack 1 (42 catalog rows). A sibling slice (`fp-apps2.mjs`)
adds a second pack beside this one; the path rail (`scan-http-paths`) is a separate slice and is NOT used here.

## Discovery → Design
- **Need:** many KEV-relevant web applications and file-transfer products answer the scanner's one `GET /` (or the greeting
  it already reads) with a recognisable header, cookie name, title or page marker, but the scanner named none of them, so
  they never reached the inventory or a "check" finding.
- **Constraints:** passive only. No new connection, request, path, hello or datagram. Every input is already in the probe
  result for that port: HTTP status, headers, title, body (as already capped by probe.mjs), cookie NAMES, the recorded
  redirect `Location` (only on a 3xx), the TLS certificate subject, the greeting's first line. Rows with a reviewer decision
  PASSIVE use only the stated signal; every login/admin path in the catalog rows was dropped.
- **Recommendation:** built as a data-driven rules table plus one evaluator (`scanner/lib/fp-apps.mjs`).

## Design → Implementation
- **Module:** `scanner/lib/fp-apps.mjs` exports `RULES` (frozen table), `SKIPPED` (catalog id → reason), `collected(r)`
  (what the port already returned, cookie names only) and `appServices(r, existing)` (pure).
- **Rule shape:** `{ ids: [catalog ids], cpe: "vendor:product" (NVD CPE names), vendor, product, label?, when: [[signal...]...],
  version?: [[where, regex, trust]], stamp? }`. A signal is `[where, regex, description, {port}?]` with `where` one of
  `server`, `powered` (X-Powered-By), `h:<header>`, `hname` (header names), `cookie` (cookie names), `title`, `body`,
  `location`, `cert`, `banner`. A rule matches when every signal of any one group matches.
- **Version trust** (only where the catalog row states a version source):
  - `header` (a header or greeting states it) → compared with the ranges; `guessed: false` (high confidence possible):
    Jenkins `X-Jenkins`, MOVEit `X-MOVEitISAPI-Version`, CrushFTP `Server`/`WWW-Authenticate`, HFS `Server`,
    Oracle Fusion Middleware `Server`, WS_FTP FTP greeting.
  - `page` (printed in the page body) → compared but the record stays `guessed` (medium at most): ProjectSend footer,
    HFS footer, Fusion Middleware welcome text, SysAid `ajaxTools.js?v=` / `master.css?v=` (dotted versions only).
  - `shown` → kept as `shown_version`, never compared, record stays version-less and low: NAKIVO login-page title (a
    login-page title alone never yields `affected`), `X-AspNet-Version` (the CLR runtime, not an ASP.NET release).
  - ServiceNow `g_builddate` is a build stamp: evidence only (the release mapping is not known).
  - Every other rule yields a guessed, version-less record: a finding is `check`, confidence low, out of the headline counts.
- **Record:** the fingerprint.mjs service shape plus `catalog` (ids) and `cpe`. Evidence names the signal(s) that fired
  (header name and short value, cookie NAME, marker description), never page text or a cookie value; ≤ 200 chars.
- **Hook:** `scanner/lib/scan.mjs` `servicesOf()` — one import and one line, `out.push(...appServices(r, out));`, after the
  certificate/HTTP/MySQL parsers and before the greeting fallback. A product already named on the port (e.g. fingerprint.mjs's
  QNAP certificate hint) is not repeated. A product named from an FTP greeting replaces the anonymous "FTP server" record.
- **Safety-model check:** no network code in the module (pure functions); security-check section 7 green; no new SENDS.

### Built (38 catalog ids, 36 rules)
`ray-project-ray`, `advantive-veracore`, `apache-axis`, `apache-hugegraph-server`, `apache-kylin`, `apache-spark`,
`asp-net-or-system-web`, `django-application`, `express-or-node-js-http`, `laravel-application`, `oracle-fusion-middleware`,
`oracle-intelligence-enterprise-edition`, `progress-telerik-report-server`, `ruby-on-rails-application`,
`telerik-user-interface-ui-for-asp-net-ajax`, `yiiframework-yii`, `accellion-fta`, `crushftp-crushftp`,
`d-link-multiple-nas-devices`, `fortra-goanywhere-mft`, `nakivo-backup-and-replication`, `progress-moveit-transfer`,
`progress-ws-ftp-server`, `projectsend-projectsend`, `qnap-network-attached-storage-nas`, `rejetto-http-file-server`,
`terramaster-terramaster-os`, `jenkins`, `kestra-kestra-oss`, `saltstack-salt` (related web UI only, no product, never
matched), `citrix-sharefile` + `citrix-content-collaboration` (one rule), `microsoft-sharepoint`, `onlyoffice-docs`,
`servicenow-utah-vancouver-and-washington-dc-now-platform`, `sysaid-sysaid-on-prem` + `sysaid-sysaid-server` (one rule),
`istio-or-envoy-admin`.

### Skipped (4)
- `qdrant` — the reviewed signal ("the root document of a Qdrant server") states no token; nothing to match without inventing one.
- `apache-tomcat` — already identified by fingerprint.mjs (`Server: Apache-Coyote`, no version); the row states no further passive version signal.
- `veritas-backup-exec-agent` — NDMP is binary; the row states no byte signature or version field.
- `microsoft-internet-key-exchange-ike-service-extensions` — needs an IKE hello on UDP/500 (no codec, a new datagram); Vendor ID mapping not stated.

### Open questions / follow-ups
- CPE names were set from NVD naming as known; `ray_project:ray`, `apache:hugegraph` (product named `HugeGraph-Server` so either
  NVD spelling matches), `laravel:framework`, `telerik:ui_for_asp.net_ajax`, `microsoft:sharepoint_server` and
  `envoyproxy:envoy` are worth a check against live KEV/NVD rows. D-Link NAS has one CPE per model; the record is inventory only.
- Weak, single-token signals (`csrftoken`, `X-Runtime`, `Server: envoy` on any Envoy-fronted site, bare `ONLYOFFICE`) stay
  guessed and version-less by design.
- Version upgrades for the version-less rows need the path rail and a reviewed Design (out of scope here).

## Implementation → Review
- **Tests:** `tests/unit/scanner-apps1.test.mjs` (11 tests): table covers all 42 ids (built xor skipped); one positive fixture per
  built rule; two-signal rules and look-alikes (Ray 401, HugeGraph Studio, generic WebResource.axd, Spark redirect off 4040,
  Location on a 200); version trust per source; QNAP certificate and dedupe through `servicesOf`; Salt related-only; matching
  (header version → affected/high; NAKIVO title version → check/low; version-less → low; headline counts exclude both);
  cookie values never kept; a loopback 127.0.0.1 server sees exactly one `GET /`; `probeAll` calls the probe once per port.

## Doc text to add (orchestrator consolidates)

**docs/scanner.md** — under the fingerprints section:

> **Application fingerprints (passive, `scanner/lib/fp-apps.mjs`).** A rules table names web applications and file-transfer
> products from what the scan already collected for a port: the `GET /` response's headers, cookie names, title and page
> markers, a redirect's recorded `Location`, the certificate subject and the greeting. No request is added. A version is
> read only where the product states one: in a header or greeting it is compared with the affected ranges; printed in the
> page it is compared but the product stays "inferred" (medium confidence at most); in a login-page title it is shown but
> never compared. Products named without a version are listed as low-confidence "check" findings and stay out of the
> headline counts. Evidence names the signal that matched; page text and cookie values are never stored.

**scanner/README.md** — in "What it identifies":

> Also names, from the same root-page response, certificate and greeting (no extra request): Jenkins, MOVEit Transfer,
> GoAnywhere MFT, CrushFTP, WS_FTP Server, Rejetto HFS, Accellion FTA, ProjectSend, SysAid, ServiceNow, NAKIVO, VeraCore,
> Citrix ShareFile, SharePoint, ONLYOFFICE, Oracle Fusion Middleware and Business Intelligence, Telerik UI and Report Server,
> Apache Axis2, HugeGraph, Kylin and Spark, Ray, Kestra, QNAP and D-Link NAS, TerraMaster, Envoy, and the frameworks
> ASP.NET, Django, Express, Laravel, Rails and Yii (version only when stated; most are version-less, low confidence).
