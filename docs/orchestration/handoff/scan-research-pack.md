# Handoff: scan-research-pack — public-reference fingerprints, passive (plan w3-build)

Builds the 65 SOURCED rows the research agents found in public references (Recog, Nmap service probes, Wappalyzer/
webappanalyzer, nuclei templates, the products' own source), limited to what the scan already collects, plus the one rail
row the lead accepted on 2026-11-22.

## Discovery → Design
- **Need:** many products announce themselves in the greeting, the root page, the certificate or the DNS version.bind
  answer the scanner already reads; the research pack names the exact tokens and where they come from.
- **Constraints:** zero extra bytes for the fingerprints (no new connection, request, path, port, hello or datagram;
  `SENDS` unchanged); no body, cookie value, serial number, certificate CN or device token stored; a version only from a
  capture the source names; everything else `guessed` (low confidence, out of the headline counts).
- **Design:** new module `scanner/lib/fp-research.mjs`: a frozen `RULES` table (one entry per product; each carries `id` =
  the research row and `src` = its first source URL), a frozen `DNS_RULES` table for version.bind answers, one evaluator
  `research(r, existing)`. Signals: `title`, `body`, `server`, `header {name}`, `cookie` (name only), `location` (recorded),
  `banner` (greeting), `subject` / `issuer` (per-field certificate tests: CN, O, OU, L, ST, C). Versions: `{ from, re,
  compare?, minParts? }`; `compare: false` shows a number that is not the product's release, `minParts: 3` shows a
  major.minor-only version (CUPS) without comparing it.
- **Hooks (shared files, smallest possible):**
  - `scanner/lib/scan.mjs` `servicesOf()`: one import line and one line after `identify(...)`:
    `out.splice(0, out.length, ...withResearch(out, r));` — product-name dedupe (a product already named on the port is
    not added twice), a product-less greeting record ("SMTP server") gives way to the product named from that greeting,
    and a guessed certificate-inferred record a rule `replaces` gives way (the FortiMail default certificate otherwise
    reads as FortiOS through `CERT_HINTS`' `/fortinet/`).
  - `scanner/lib/scan.mjs` `oneUdp`: `fromUdp(r)` wrapped as `withResearchUdp(r, fromUdp(r))` — the generic "DNS server"
    record gives way to dnsmasq / Knot DNS / NSD / Unbound / CoreDNS read from the same version.bind answer. BIND is untouched.
  - `scanner/lib/paths.mjs`: one RAIL row (below) and one line in `railResult()`: when two rows share one path and both
    parse the same product, the first in table order wins (one service, not two).

## Path rail: the one accepted row (lead decision 2026-11-22)
- `ivanti-connect-secure-version-path`, path `/dana-na/nc/nc_gina_ver.txt` — the SAME literal path the shipped
  `pulse-secure-pulse-connect-secure` row already requests, so `RAIL_PATHS` stays at 39; rows go 50 → 51.
- Hint: the root page's recorded redirect `Location` whose path starts `/dana-na/` (relative or absolute), or the existing
  `/dana-na/css/ds.css` marker already in paths.mjs. Placed before the Pulse row, so when both hint, one request is made and
  this row's record wins.
- Parse (research output, nuclei `pulse-secure-version.yaml`): `NAME="ProductVersion"\s+?VALUE="([^"]+)"`. A dotted value
  is stated → `guessed: false`; it is a build number ("9.1.11.10541"), not the release naming NVD's ranges use ("9.1R11"),
  so `version` is empty (shown, never compared), as the Pulse row does. Anything else → `guessed: true`, no version.
  The research notes the file is absent on newer releases.
- Rejected by the lead and not added: `/version` (vLLM), `/.well-known/caldav`, `/realms/master/.well-known/openid-configuration`,
  `/.well-known/change-password`, `/.git/HEAD`, `/sitemap.xml`.
- No "reviewed JSON" fixture exists in the repo for the rail; the table test in `tests/unit/scanner-paths.test.mjs`
  (row count 50 → 51, unique ids 51, the `/dana-na/auth/` hint now lists both ids) carries the note "lead decision 2026-11-22".
  One assertion there ("nothing parsed from a non-200") now checks only rail-sourced MLflow records, because the root title
  `MLflow` now names MLflow passively.

## Versions read (stated captures only)
Rocket.Chat (`X-Rocket-Chat-Version`), ScreenConnect (Server, group 1 only), Netdata (Server), HPE iLO (`HP-iLO-Server/`),
Intel AMT (Server), PRTG (`PRTG/`), NetApp Data ONTAP (`NetApp/`), Jira (`data-version` on the application-name meta),
Confluence (print-only footer), Bitbucket (`product-version` footer), Gogs (footer), Cacti (`versionInfo` on the root page),
CUPS (Server; major.minor-only shown, not compared), SAP NetWeaver (Server; kernel/ICM/engine number shown, never compared),
dnsmasq / Knot DNS / NSD / Unbound / CoreDNS (version.bind). Everything else is `guessed`.

## Identifiers never kept
HP `HP HTTP Server` Server header: serial number, product number and build date dropped; only the model family ("LaserJet
Pro") goes into the label. ScreenConnect: the number after the hyphen is matched, not kept. Barracuda: the 32-hex greeting
token is matched, not kept. iDRAC: the CN (MAC-like id or service tag) is matched, not kept. Wazuh: node CN not kept.
Cookie values never read. Tests prove each.

## Weak / low confidence (built, kept guessed)
Sentry (logo path, usually on the login page), Shibboleth (title only), SimpleHelp (title seen on `/welcome` by the source),
Jupyter / Jira / Consul / GeoServer / Guacamole (root usually redirects; the marker is on the target, which is not followed),
FreeNAS (legacy only; TrueNAS has no static marker), FreeIPA (`/ipa/ui` redirect, with or without the `IPASESSION` cookie),
MongoDB (the HTTP notice is only collected when the operator names 27017 with `--http-ports`), Axis / iDRAC / iRMC /
HP printer (family; model or generation only), Docker registry (API version only), Wazuh / iDRAC / FortiMail (only while
the default certificate is in use), Commvault / Backup Exec NDMP (binary greetings; no version).

## Needs a hello (not built here)
Kafka ApiVersions, MQTT CONNECT, Redis PING, ACME `acme-tls/1` ALPN (and the acmeIdentifier extension only appears on the
challenge certificate), SQL Server PRELOGIN, Oracle TNS `(CONNECT_DATA=(COMMAND=version))`, JetDirect PJL `INFO ID`;
RDP X.224, SMB NEGOTIATE and LDAP rootDSE are being built by another slice. Also not built from the research reasons:
NetBackup vnetd (`^1\0$` needs a non-NULL probe), MongoDB `hello`, AMT `/logon.htm`, MLflow `/version` (already in the rail).

## Bytes sent beyond today's behaviour
None for the fingerprints (loopback tests: one `GET /`, zero bytes written to greeting services, one DNS datagram).
The rail row adds no new path; with `--paths` it may request the existing frozen path on hosts the Pulse row did not hint
(a relative `/dana-na/` redirect).

## Doc text for docs/scanner.md (fingerprints section)
> **Research pack (`scanner/lib/fp-research.mjs`).** 55 products from fingerprints published in public references (Recog,
> Nmap's service probes, Wappalyzer, nuclei templates and the products' own source; each rule cites its source). Read only
> from what the scan already collects: the greeting, the root page (title, headers, cookie names, body markers, the recorded
> redirect), the certificate subject/issuer, and the DNS version.bind answer (dnsmasq, Knot DNS, NSD, Unbound, CoreDNS).
> Versions only where the data states them; serial numbers, device tokens and certificate CNs are matched, never stored.
> Fingerprints that need a protocol hello (Redis, MQTT, Kafka, Oracle TNS, PJL, SQL Server, MongoDB, ACME) are not used.

## Doc text for scanner/README.md (what it identifies)
> Also identifies, without any extra request: Jupyter, Langflow, MLflow, Ray, GeoServer, OFBiz, n8n, SAP NetWeaver,
> Atlassian Jira/Confluence/Bitbucket, Gogs, HashiCorp Boundary/Consul, Rocket.Chat, Docker registries, Harbor, NetApp
> ONTAP, Synology DSM, FreeNAS, Commvault, Backup Exec (NDMP), Axis cameras, HP printers, CUPS, Authelia, Duo gateways,
> FreeIPA, Shibboleth IdP, Barracuda and FortiMail, mailcow, Proofpoint, Cacti, Jaeger, LibreNMS, PRTG, Sentry, Wazuh,
> Netdata, Guacamole, ScreenConnect, SimpleHelp, Jitsi Meet, GitHub Enterprise, Dell iDRAC, Fujitsu iRMC, HPE iLO, Intel
> AMT, Supermicro BMC, and the DNS servers dnsmasq, Knot DNS, NSD, Unbound and CoreDNS.

## Per-row source list
### Built rows (55)

| Research row | Signal type | Sources (as recorded by the research agents) |
|---|---|---|
| jupyter-notebook-or-lab | title | https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml |
| langflow | title | https://raw.githubusercontent.com/langflow-ai/langflow/main/src/frontend/index.html |
| mlflow | title | https://raw.githubusercontent.com/mlflow/mlflow/master/mlflow/server/js/public/index.html<br>https://raw.githubusercontent.com/mlflow/mlflow/master/mlflow/server/__init__.py |
| ray-dashboard | title | https://raw.githubusercontent.com/ray-project/ray/master/python/ray/dashboard/client/public/index.html |
| osgeo-geoserver | title | https://raw.githubusercontent.com/geoserver/geoserver/main/src/web/core/src/main/java/org/geoserver/web/GeoServerBasePage.html<br>https://raw.githubusercontent.com/geoserver/geoserver/main/src/web/app/src/main/webapp/index.html |
| apache-ofbiz | cookie_name | https://raw.githubusercontent.com/apache/ofbiz-framework/trunk/framework/webapp/src/main/java/org/apache/ofbiz/webapp/stats/VisitHandler.java |
| sap-netweaver | header | https://raw.githubusercontent.com/rapid7/recog/main/xml/http_servers.xml<br>https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/s.json<br>https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml |
| commvault | banner | https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes |
| netapp-ontap-or-oncommand | header | https://raw.githubusercontent.com/rapid7/recog/main/xml/http_servers.xml<br>https://raw.githubusercontent.com/rapid7/recog/main/xml/ssh_banners.xml |
| synology-dsm-version-path | body_marker | https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/s.json<br>https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml<br>https://raw.githubusercontent.com/rapid7/recog/main/xml/http_servers.xml |
| truenas-or-freenas | title | https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml<br>https://raw.githubusercontent.com/truenas/webui/master/src/index.html |
| veritas-netbackup-or-backup-exec | banner | https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes |
| atlassian-bitbucket-server | cookie_name | https://raw.githubusercontent.com/rapid7/recog/main/xml/http_cookies.xml<br>https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml<br>https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/a.json |
| hashicorp-terraform-enterprise-or-boundary | body_marker | https://raw.githubusercontent.com/hashicorp/boundary-ui/main/ui/admin/app/index.html<br>https://raw.githubusercontent.com/hashicorp/consul/main/ui/packages/consul-ui/app/index.html |
| gogs | cookie_name | https://raw.githubusercontent.com/rapid7/recog/main/xml/http_cookies.xml<br>https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/g.json |
| n8n | body_marker | https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/n.json |
| atlassian-confluence | header | https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/a.json<br>https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml |
| atlassian-jira | body_marker | https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/a.json<br>https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/technologies/jira-detect.yaml |
| rocket-chat | header | https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes<br>https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/r.json<br>https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/exposed-panels/rocketchat-panel.yaml |
| docker-registry-v2 | header | https://raw.githubusercontent.com/distribution/distribution/main/docs/content/spec/api.md<br>https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes |
| harbor-registry | body_marker | https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/h.json<br>https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/exposed-panels/harbor-panel.yaml<br>https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/technologies/harbor-detect.yaml |
| coredns | banner | https://raw.githubusercontent.com/coredns/coredns/master/plugin/chaos/README.md<br>https://raw.githubusercontent.com/coredns/coredns/master/plugin/health/README.md |
| dnsmasq | banner | https://raw.githubusercontent.com/rapid7/recog/main/xml/dns_versionbind.xml<br>https://raw.githubusercontent.com/imp/dnsmasq/master/man/dnsmasq.8 |
| knot-dns | banner | https://raw.githubusercontent.com/rapid7/recog/main/xml/dns_versionbind.xml<br>https://raw.githubusercontent.com/CZ-NIC/knot/master/doc/reference.rst |
| nsd | banner | https://raw.githubusercontent.com/rapid7/recog/main/xml/dns_versionbind.xml |
| unbound | banner | https://raw.githubusercontent.com/rapid7/recog/main/xml/dns_versionbind.xml<br>https://raw.githubusercontent.com/NLnetLabs/unbound/master/doc/unbound.conf.rst |
| mongodb-handshake | banner | https://raw.githubusercontent.com/mongodb/docs/master/source/reference/command/hello.txt<br>https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes |
| axis-communications-camera | title | https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml<br>https://raw.githubusercontent.com/rapid7/recog/main/xml/http_servers.xml<br>https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes |
| hp-or-vendor-printer-web-ui | header | https://raw.githubusercontent.com/rapid7/recog/main/xml/http_servers.xml<br>https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml |
| ipp-or-cups-printer-identification | header | https://raw.githubusercontent.com/OpenPrinting/cups/master/man/cupsd.conf.5<br>https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes<br>https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/technologies/cups-detect.yaml |
| authelia | title | https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/exposed-panels/authelia-panel.yaml |
| duo-authentication-proxy-or-web-sdk | title | https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml<br>https://duo.com/docs/authproxy-reference |
| freeipa | location | https://raw.githubusercontent.com/freeipa/freeipa/master/install/share/ipa-rewrite.conf.template<br>https://raw.githubusercontent.com/freeipa/freeipa/master/install/share/ipa.conf.template<br>https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/exposed-panels/freeipa-panel.yaml |
| shibboleth-idp | title | https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/technologies/shibboleth-detect.yaml<br>https://shibboleth.atlassian.net/wiki/rest/api/content/search?cql=space=IDP5%20and%20text~%22idp-metadata.xml%22&limit=10&expand=body.storage |
| barracuda-email-security-gateway | banner | https://raw.githubusercontent.com/rapid7/recog/main/xml/smtp_banners.xml<br>https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes |
| fortinet-fortimail | cert | https://raw.githubusercontent.com/rapid7/recog/main/xml/x509_subjects.xml<br>https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes<br>https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/exposed-panels/fortinet/fortimail-panel.yaml |
| mailcow | body_marker | https://raw.githubusercontent.com/mailcow/mailcow-dockerized/master/data/web/templates/base.twig<br>https://raw.githubusercontent.com/mailcow/mailcow-dockerized/master/data/web/inc/functions.customize.inc.php |
| proofpoint-on-prem-appliance | title | https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/exposed-panels/proofpoint-protection-server-panel.yaml |
| cacti | title | https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml<br>https://raw.githubusercontent.com/Cacti/cacti/1.2.x/auth_login.php |
| jaeger-ui | title | https://raw.githubusercontent.com/jaegertracing/jaeger-ui/main/packages/jaeger-ui/index.html |
| librenms | title | https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml |
| prtg-network-monitor | header | https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes<br>https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml<br>https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/technologies/prtg-detect.yaml |
| sentry | body_marker | https://raw.githubusercontent.com/getsentry/sentry/master/src/sentry/templates/sentry/layout.html<br>https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/exposed-panels/sentry-panel.yaml |
| wazuh-or-ossec-dashboard | cert | https://raw.githubusercontent.com/wazuh/wazuh-packages/master/unattended_installer/cert_tool/certFunctions.sh<br>https://raw.githubusercontent.com/wazuh/wazuh-installation-assistant/main/cert_tool/certFunctions.sh<br>https://raw.githubusercontent.com/wazuh/wazuh-packages/master/stack/dashboard/base/files/etc/opensearch_dashboards.yml<br>https://raw.githubusercontent.com/opensearch-project/OpenSearch-Dashboards/main/src/core/server/http/lifecycle_handlers.ts<br>https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/exposed-panels/wazuh-panel.yaml |
| apache-guacamole | body_marker | https://raw.githubusercontent.com/apache/guacamole-client/main/guacamole/src/main/frontend/src/index.html<br>https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/technologies/apache/apache-guacamole.yaml |
| connectwise-screenconnect | header | https://raw.githubusercontent.com/rapid7/recog/main/xml/http_servers.xml<br>https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/exposed-panels/connectwise-panel.yaml |
| simplehelp | title | https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/exposed-panels/simplehelp-login-panel.yaml |
| dell-idrac | cert | https://raw.githubusercontent.com/rapid7/recog/main/xml/x509_subjects.xml |
| fujitsu-irmc | title | https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml |
| hpe-ilo | header | https://raw.githubusercontent.com/rapid7/recog/main/xml/http_servers.xml<br>https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml<br>https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/h.json |
| intel-amt-or-vpro-web-ui | header | https://raw.githubusercontent.com/rapid7/recog/main/xml/http_servers.xml<br>https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes<br>https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/technologies/intel-amt-detect.yaml<br>https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/i.json |
| supermicro-bmc | title | https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/exposed-panels/supermicro-bmc-panel.yaml<br>https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes |
| jitsi-meet | body_marker | https://raw.githubusercontent.com/jitsi/jitsi-meet/master/index.html<br>https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/j.json |
| github-enterprise-server | title | https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml |
| netdata | header | https://raw.githubusercontent.com/rapid7/recog/main/xml/http_servers.xml<br>https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes<br>https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/exposed-panels/netdata-panel.yaml |

### Not built: needs a hello (10)

| Research row | Signal type | Sources |
|---|---|---|
| apache-kafka-protocol-identification | banner | https://kafka.apache.org/42/design/protocol/ |
| mqtt-connect-identification | banner | https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes |
| redis-ping-identification | banner | https://redis.io/docs/latest/commands/ping/<br>https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes |
| acme-http-01-or-tls-alpn-challenge-leftover | cert | https://www.rfc-editor.org/rfc/rfc8737.txt |
| microsoft-sql-server-handshake | banner | https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes |
| oracle-database-tns-listener | banner | https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes |
| jetdirect-identification | banner | https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes |
| rdp-protocol-identification | banner | https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes<br>https://raw.githubusercontent.com/nmap/nmap/master/nselib/rdp.lua |
| smb-protocol-identification | banner | https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes<br>https://raw.githubusercontent.com/nmap/nmap/master/nselib/smb2.lua |
| ldap-root-dse | banner | https://raw.githubusercontent.com/rapid7/recog/main/xml/ldap_searchresult.xml<br>https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes |
