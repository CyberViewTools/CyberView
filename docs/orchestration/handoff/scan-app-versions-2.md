# Handoff: scan-app-versions (passive pack 2) — application fingerprints from data already collected

Plan id w2-7c1e. Module `scanner/lib/fp-apps2.mjs`, tests `tests/unit/scanner-apps2.test.mjs`, hook: one import and one line in
`servicesOf()` (`scanner/lib/scan.mjs`). Catalog rows are referenced by id only.

## Discovery → Design
- **Need:** name more of the KEV-heavy applications (mail gateways, IT management consoles, proxies and small web servers) from what
  the scan already reads, so findings say "check <product>" instead of nothing, and confirm a version where the service states one.
- **Constraints:** passive only. No new connection, request, path, hello or datagram (the path rail is a separate slice). Reads the
  one `GET /` response (status, title, headers, body markers, cookie NAMES; one named cookie's value only where the row states it
  carries the release), the recorded redirect `Location` (never followed) and a greeting the service sent on its own.
- **Recommendation:** build as a data table (one rule per product, any matcher is enough) plus one evaluator, so later packs are data.

## Design → Implementation
- **Data model:** each rule `{ ids: [catalog ids], vendor, product, label?, cpe (NVD vendor:product, reference only), note?, version?, any: [matcher] }`;
  matcher `{ field, re, label, all?, version?, compare?, proto? }` where field is one of title, body, location, server, via, www-authenticate,
  headers, header:<name>, cookie-name, cookie:<name>, banner. Output is the fingerprint.mjs service record plus `catalog: [ids]`.
- **Version rule:** a version only from a matcher whose row states one. `compare: false` records the stated number (shown_version)
  but never compares it with affected ranges, because it names a component, not the product release (Microsoft-HTTPAPI/2.0, OpenView
  BBC/coda component versions, WDaemon, Roundcube's rcversion build number). Anything without a compared version is `guessed`, so
  matching can say only "check" (low confidence), which `summarize()` keeps out of the headline counts. A login-page title alone never
  yields "affected" (tested).
- **Hook:** `withPack2(existing, r)` adds pack-2 records that are not already named on the port, and drops a product-less greeting
  record ("SMTP server") on the same port when pack 2 named the product from that same greeting.
- **Safety-model check:** no network, timer or process code in the module (tested); `security-check` passes; probe.mjs, SENDS,
  limits and the CLI are unchanged. Evidence holds the rule's own marker label or the header/greeting line, never body text or a
  cookie value (tested).

## Implementation → Review
Built (34 catalog ids): micro-focus-micro-focus-access-manager, omnissa-workspace-one-uem, cisco-secure-email-gateway,
mdaemon-email-server, playsms-playsms, roundcube-webmail~kev-auto, smartertools-smartermail, apache-superset,
hewlett-packard-hp-openview-network-node-manager, progress-whatsup-gold, sciencelogic-sl1, solarwinds-orion,
splunk-enterprise~kev-auto, tibco-jasperreports, ivanti-endpoint-manager-epm, microsoft-remote-desktop-services (RD Web Access
cookie/body on the root page only), n-able-n-central, solarwinds-serv-u, wing-ftp-server,
kaseya-virtual-system-server-administrator-vsa, trend-micro-apex-one + trend-micro-officescan (one record),
zoho-manageengine (10 console titles), apache-apisix, apache-traffic-server, embedthis-goahead, envoy-proxy, haproxy,
microsoft-http-protocol-stack + microsoft-http-sys (one record), nostromo-nhttpd, squid-caching-proxy, traefik, varnish-cache.

Already covered by the existing greeting parser (no new rule, tests added): exim-mail-transfer-agent-mta, proftpd-proftpd.

Not built: microsoft-kerberos-key-distribution-center-kdc (needs a Kerberos hello on 88), samba-samba (needs an SMB negotiate: nothing
is read on 445), icewarp-mail-server, anydesk-server, rustdesk-server, teamviewer-server (no concrete signal in the row; binary
protocols send no text greeting).

Open questions / follow-ups:
- CPE names in the `cpe` field are reference only (matching uses vendor + product with the site's name matching); verify against
  NVD when the KEV data for these CVEs is in the snapshot.
- Versions left uncompared until a sourced mapping exists: Roundcube rcversion build number -> release; WDaemon -> MDaemon release;
  Squid/Varnish/Traefik/Envoy/HAProxy/ATS header version tokens (rows forbid inventing a version regex); ATS's own `ATS/<v>` token.
- Overlap with pack 1: `istio-or-envoy-admin` also reads `Server: envoy`. The hook skips a product already named on the port, but
  only if pack 1 names it "Envoy"; reconcile names when merging.
- Favicon-hash signals (Superset, WhatsUp Gold, SL1, EPM, N-central) need a favicon request: path-rail territory.
- Desktop/Endpoint Central titles are left to the zoho-desktop-central row.

## Text for docs/scanner.md and scanner/README.md (orchestrator to place)
> **Application fingerprints from the root page and greetings (pack 2).** Besides the Server header and generator tag, the scanner
> recognises a set of applications from what it already received: the root page's title, headers, fixed body markers and cookie
> names, a recorded redirect Location (never followed) and a greeting the service sent on its own — for example Cisco Secure Email
> Gateway (IronPort FTP/SMTP greeting), MDaemon and SmarterMail greetings, WhatsUp Gold, N-central, APISIX, GoAhead and nostromo
> Server headers, and ManageEngine, Splunk, Orion, Superset and Jaspersoft titles. This sends nothing new. A product named without a
> stated version is reported as "check by hand" (low confidence) and is not counted in the headline numbers; a number that is not
> the product's release (Microsoft-HTTPAPI/2.0, an OpenView component, a Roundcube build number) is shown but never compared.
