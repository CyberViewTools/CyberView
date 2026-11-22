# Handoff: scan-edge-versions — edge / appliance fingerprints, PR A (collected pages, headers, greetings, certs)

## Discovery → Design
- **Need / user story:** KEV-heavy edge appliances (VPN gateways, firewalls, load balancers, SOHO routers, cameras, NAS,
  switches) were only cert-guessed, so they could never become version-confirmed findings. A defender wants them named
  from what the scan already read, with a version only where that data states one.
- **Constraints:** detection only; **zero extra bytes** (no new request, path, connection, hello or datagram); no
  logins, no management APIs, no exploit-class URLs; `CAPS` unchanged; never store bodies (evidence holds a fixed marker
  name or a short header/title/realm token); security-check section 7 green.
- **Prior art / standards:** the owner's detection catalog (rows by catalog id; each rule cites the ids it builds).
  Product names follow NVD/KEV vendor/product naming so `site/workbench-lib.js` `matchFlaw` finds the entries.
- **Data that exists:** probe.mjs's `GET /` result (status, headers incl. `Server` and `WWW-Authenticate`, body up to
  64 KB), the greeting banner on non-web ports, the TLS certificate.
- **Feasibility / risks:** most login pages state no version, so most rules give guessed, version-less hints (low
  confidence, out of the headline). Version files and hash tables need the path rail (PR B = `scan-edge-paths`).
- **Recommendation:** build PR A as a data-driven rules table.

## Design → Implementation
- **Interfaces:** new `scanner/lib/fp-edge.mjs`: `fromEdge(r, have)` (pure; `r` is probe.mjs's per-port result,
  `have` the services other parsers already found on that port), `edgeFields(r)`, `RULES` (one row per catalog entry
  or group of duplicate entries, `ids` = catalog ids), `CERT_ROWS` (catalog ids already served by
  `fingerprint.mjs` `CERT_HINTS`). Hook: one import and one line in `scan.mjs` `servicesOf()`
  (`out.push(...fromEdge(r, out))`, before the banner fallback). No CLI change.
- **Data model:** service records as `fingerprint.mjs` produces them, plus `catalog: [ids]`. `guessed: true` and empty
  `version` unless the rule's `version` field matched; then `source` says where (HTTP Server header, root page text,
  greeting banner) and `evidence` quotes only the stated version and the identifying token.
- **Rules of the table:** fields are `title`, `body`, `text` (body without the title — versions are never read from a
  title), `server`, `realm`, `ssh`, `greeting`. `any` identifies, `all` adds the second marker a row requires, `model`
  captures a model token (a rule with a model fires only when the model is present), `fallback` lets a family rule step
  aside for a model rule of the same vendor. A product already stated on the port is not repeated; a stated version
  replaces a hint through the existing `servicesOf` filter.
- **Safety-model check:** no network code in the module; it reads only fields probe.mjs already returns; the loopback
  test records every byte: one connection, one `GET /` (unchanged from today). `SENDS` unchanged.
- **Test plan (tests/unit/scanner-edge.test.mjs, fixtures in tests/fixtures/scanner/edge/pages.json):** versions read
  from Server header / page text / asset path / telnet greeting; version-less guessed hints for every other rule;
  negatives (generic realms/titles, a model not named in the row, SMA without an SMA 1000 token, `User Portal` without the
  theme path, RomPager without the P-660HN token, ordinary SSH); a number in a title is not a version; cert-only rows
  covered by `CERT_HINTS`; a title-only login page matches as `check`/low and leaves `known_exploited`, `critical`,
  `act`, `version_confirmed` at 0, a stated version matches as `affected`/high; evidence never copies page content;
  loopback byte recorder.

## Implementation → Review
- **Built (catalog ids):** 47 rows as rules — arcserve-unified-data-protection-udp, array-networks-ag-vxag-arrayos,
  array-networks-arrayos-ag, aviatrix-aviatrix-controller, aviatrix-controllers, broadcom-brocade-fabric-os,
  cisco-catalyst-sd-wan-controller-and-manager, cisco-catalyst-sd-wan-manager, cisco-catalyst-sd-wan-manger,
  cisco-prime-data-center-network-manager-dcnm, cisco-secure-access-control-system-acs,
  d-link-dcs-2530l-and-dcs-2670l-devices, d-link-dcs-930l-devices, d-link-dir-300-router, d-link-dir-600-router,
  d-link-dir-605-router, d-link-dir-610-devices, d-link-dir-645-router, d-link-dir-820-router, d-link-dir-820l,
  d-link-dir-823x, d-link-dir-825-r1-devices, d-link-dir-859-router, d-link-dnr-322l, d-link-dns-320-device,
  d-link-dns-320-storage-device, d-link-dsl-2750b-devices, d-link-dsl-2760u, dd-wrt-dd-wrt,
  ivanti-cloud-services-appliance-csa, juniper-screenos, microsoft-forefront-threat-management-gateway-tmg,
  netgear-wireless-access-point-wap-devices, palo-alto-networks-expedition, progress-loadmaster,
  sierra-wireless-airlink-aleos, sonicwall-sma1000-appliances, sophos-cyberoamos, sophos-sg-utm, sophos-web-appliance,
  tp-link-archer-ax21, tp-link-multiple-routers, tp-link-tl-wa855re, tp-link-tl-wr841n, zyxel-gs1900-series-switches,
  zyxel-multiple-firewalls, zyxel-p660hn-t1a-routers.
- **Already served, verified by test (no code change):** the 10 certificate-hint rows in `CERT_ROWS` (qnap-qts,
  synology-diskstation-manager, citrix-netscaler-adc, fortinet-fortios, ivanti-connect-secure, mikrotik-routeros,
  palo-alto-pan-os, sonicwall-sonicos, sophos-firewall, zyxel-firmware).
- **Version read when stated:** cisco-secure-access-control-system-acs (Server), cisco-prime-dcnm (`Version:` line;
  `7.0(2)` compared as `7.0.2`), D-Link DIR-600/605/645/820/820L (`Ver` suffix on Server), sierra-wireless-airlink-aleos
  (page text), sonicwall-sma1000-appliances (`Server: SMA/x.x`, only when SMA 1000 is named), sophos-cyberoamos (asset
  path `version=`), broadcom-brocade-fabric-os (telnet greeting).
- **Partly built / deliberate narrowings:**
  - cisco-ios-ios-xe: NOT built — the row names the Server header but states no pattern, and says not to invent one.
  - zyxel-gs1900-series-switches: title only; the row's web-server-name context is not used (the scanner's
    attack-string guard in tests/unit/scanner.test.mjs refuses that word in scanner files); `Server` version not used
    (it is the web server's, not the firmware's).
  - zyxel-p660hn-t1a-routers: RomPager's `/VERSION` is the web server's version, not read as firmware.
  - tp-link-tl-wr841n: the UPnP Server `TL-WR841N/x.0` token is hardware/version-ambiguous, not read as a version.
  - microsoft-forefront-threat-management-gateway-tmg: the vague "502 Proxy Error" wording is not matched.
  - Favicon hashes (arcserve, vManage, expedition, sophos-web-appliance, juniper-screenos) need a `/favicon.ico`
    request: left for the path rail.
- **Named in the slice brief but with no BUILD-NOW catalog row (not built, no sourced signal):** Fortinet SSL-VPN
  redirect/markers, GlobalProtect portal, Pulse Connect Secure pages, Veeam consoles, Synology/QNAP/other NAS titles,
  Proxmox, Teltonika/Cradlepoint/Digi, Dell iDRAC, HPE iLO, Tridium Niagara. They need catalog rows first.
- **Deferred (LATER rows, path rail or research; follow-ons for scan-edge-paths):** arcadyan-buffalo-firmware,
  arista-extensible-operating-system, arista-velocloud-orchestrator, aruba-instant-or-clearpass, asus-routers,
  check-point-gaia, check-point-quantum-or-gaia-portal-already-listed-complement, check-point-security-gateway,
  check-point-smartconsole, cisco-anyconnect-secure, cisco-asa-or-ftd,
  cisco-catalyst-4500-series-switches-and-cisco-catalyst-4500-x-series-switches, cisco-catalyst-6800-series-switches,
  cisco-nx-os, cisco-secure-firewall-asa-software-and-cisco-secure-ftd-software,
  cisco-secure-firewall-management-center-fmc-and-security-cloud-control-scc-firew, cisco-small-business-rv-series-routers,
  cisco-small-business-rv160-rv260-rv340-and-rv345-series-routers, cisco-small-business-rv320-and-rv325-routers,
  cisco-smart-licensing-utility, cisco-vpn-routers, citrix-application-delivery-controller-adc-and-gateway,
  citrix-netscaler-gateway, citrix-sd-wan, d-link-dwl-2600ap-access-point, d-link-routers,
  dasan-gigabit-passive-optical-network-gpon-routers, draytek-vigor-routers, draytek-vigorconnect,
  eg-secure-solutions-siteguard-server-edition, f5-big-ip, fatpipe-warp-ipvpn-and-mpvpn-software,
  fortinet-fortianalyzer, fortinet-forticlient-ems, fortinet-fortimanager, fortinet-fortiproxy, fortinet-fortisandbox,
  fortinet-fortiweb, fxc-ae1021-ae1021pe,
  hewlett-packard-hp-procurve-manager-pcm-pcm-identity-driven-manager-idm-and-appl, igel-igel-os, ivanti-policy-secure,
  ivanti-virtual-traffic-manager, juniper-junos, lantronix-eds5000, looking-glass-multi-router-looking-glass-mrlg,
  mikrotik-routeros-version-path, netgear-dgn2200-devices, netgear-jgs516pe-devices, netgear-multiple-routers,
  netgear-wireless-router-dgn2200, netgear-wnr2000v5-router, netis-wf2419-devices, openvpn-access-server, opnsense,
  palo-alto-globalprotect-portal, pfsense, pulse-secure-pulse-connect-secure, rconfig-rconfig,
  sonicwall-secure-remote-access-sra, sonicwall-sma, sonicwall-sma100-appliances, sonicwall-sonicwall-email-security,
  sonicwall-sslvpn-sma100, sophos-sfos, sophos-xg-firewall, sumavision-enhanced-multimedia-router-emr, sunhillo-sureline,
  tenda-ac11-router, tenda-ac1900-router-ac15-model, tenda-ac7-ac9-and-ac10-routers, ubiquiti-airos,
  ubiquiti-unifi-network, ubiquiti-unifi-os, versa-concerto, versa-director, vmware-sd-wan-edge,
  vmware-velocloud-or-sd-wan-orchestrator, watchguard-firebox, zyxel-dsl-cpe-devices, zyxel-emg2926-routers.
  Cisco ASA/AnyConnect and Synology/QNAP CGI/login-check paths stay deferred per the roadmap.
- **Open questions:** product names for SOHO models use `<model> Firmware` (NVD's `<model>_firmware` CPE products);
  KEV naming for some (Ivanti CSA, Zyxel firewall models) may need a mapping table once real KEV rows are checked.

## Doc text to add (orchestrator merges)
**docs/scanner.md — Fingerprints:** "Edge appliances (scanner/lib/fp-edge.mjs): about 45 VPN gateways, firewalls, load
balancers, SOHO routers, cameras, NAS and switches on CISA's KEV list are named from the root page, its Server and
WWW-Authenticate headers, or the greeting already read — no extra request. A version is reported only where that data
states one (for example a Server header's `Ver` suffix or a `Version:` line on the login page, never a page title);
otherwise the product is a guessed, version-less hint, matched as 'product seen, version to check' with low confidence
and left out of the headline counts. Version files on fixed paths are a separate, later change."

**scanner/README.md — What it identifies:** "Edge and appliance products (Array Networks, Aviatrix, Cisco vManage / DCNM
/ ACS, D-Link, DD-WRT, Ivanti CSA, Juniper ScreenOS, Microsoft TMG, NETGEAR WAP, Palo Alto Expedition, Kemp
LoadMaster, Sierra Wireless ALEOS, SonicWall SMA 1000, Sophos, TP-Link, Zyxel, Brocade Fabric OS) from the page and
banner already collected; most are version-less hints."
