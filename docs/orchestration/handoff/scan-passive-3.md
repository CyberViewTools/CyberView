# Handoff: scan-passive-3 — passive pack 3 (plan w3-build)

28 catalog rows, all reviewed PASSIVE: identify from data the scan already collects. Branch `scanner/passive-pack-3`.

## Discovery → Design
- **Need:** more KEV products (helpdesks, monitoring, file transfer, remote management, building/OT panels, cameras,
  phones) announce themselves in the root-page response, headers, cookie names or certificate the scan already holds.
- **Constraints:** zero extra bytes: no new connection, request, path, port, hello or datagram; `SENDS` unchanged; no body,
  cookie value or page text stored; a version only where the collected data states it (a header, a footer, an asset
  token), otherwise `guessed` (low confidence, out of the headline counts); OT, building, camera and clinical rows are
  identification only. Decision 6 applies to the login-page inventory: read only when the root page or the recorded
  redirect already is that page; `/login` is never requested.
- **Design:** `scanner/lib/fp-pack3.mjs`, a frozen `RULES` table and one evaluator `pack3(r, existing, { clinical })`, the
  same shape as `fp-identify.mjs` (it reuses `facts()` from there). Signals: `title`, `body`, `server`, `header`, `cookie`
  name, `location`, `cert` subject, `banner`, with `not` guards. Evidence is the signal's fixed `why` text plus the version
  or a short sanitised model token. Dedupe: a product (or label) already named on the port, compared normalised, is not
  added twice. Hook: one import and one line in `servicesOf()` (`scan.mjs`), after `identify()`.
- **Duplicate rows** are one rule carrying both catalog IDs; the product name contains both KEV spellings so the site's
  `nameHit` matches each (tested): Zimbra (`Zimbra Collaboration/Collaborate Suite (ZCS)`), Quest KACE
  (`KACE System/Systems Management Appliance (SMA)`), NUUO (`NVRmini/NVRmini2 Devices`, family only).

## Built (20 catalog IDs, 19 rules + the login-page inventory)
| Rule | Catalog IDs | Signals (all already collected) | Version |
|---|---|---|---|
| citrix-storefront | citrix-storefront-server | body `CTXS.WebApiClient` / `CTXS.AccessGateway`; script `ctxs.core.min.js`. A NetScaler/ADC title alone is not StoreFront | none |
| zimbra | synacor-zimbra-collaboration-suite-zcs, synacor-zimbra-collaborate-suite-zcs | three login titles; cookie name `ZM_TEST` (value not read); cert `OU=Zimbra Collaboration Server` | none (ZmSettings.js needs the rail) |
| glpi | teclib-glpi | body `GLPI` (upper case) together with `glpi-project.org` | footer `GLPI version x.y.z`; `common.min.js?v=` |
| zammad | zammad-gmbh-zammad | title `Zammad Helpdesk`; an element id containing `zammad_form_script` | none |
| solarwinds-vman | solarwinds-virtualization-manager | exact title `SolarWinds Virtualization Manager` | none |
| zabbix | zabbix-frontend | body `zbxCallPostScripts`; meta Author `ZABBIX SIA`; title `Zabbix` / `<server>: Zabbix` | `jsLoader.php?ver=`; footer `Zabbix x.y.z ©/Copyright` |
| ivanti-csa | ivanti-endpoint-manager-cloud-service-appliance-epm-csa | title `Ivanti(R) Cloud Services Appliance`; body `LANDESK(R)` + `Cloud Services Appliance` | none |
| filezen | soliton-systems-k-k-filezen | title `FileZen`; body `FileZen, Copyrights(C)` (Last-Modified is not a version) | none |
| teamviewer | teamviewer-desktop | the WhatWeb placeholder body `This site is running ... TeamViewer.` | none |
| kace-sma | quest-kace-system-management-appliance, quest-kace-systems-management-appliance-sma | headers `X-DellKACE-Version`, `X-KBOX-Version`, `X-DellKACE-Appliance` naming the SMA; titles `KACE Systems Management Appliance` / `K1000 Service Center`. Guard: an appliance header naming K2000/SDA/Deployment is never taken for the SMA; the SDA title does not match | the version header; model token from `X-DellKACE-Appliance` in evidence |
| mirth-connect | nextgen-healthcare-mirth-connect | exact title `Mirth Connect Administrator`. **Off by default** (clinical tier): only with `{ clinical: true }` | none |
| linear-emerge | nice-linear-emerge-e3-series | title contains `Linear eMerge` (family; E3 not confirmed; `/emerge.ico` not added) | none |
| scadabr | openplc-scadabr | title `ScadaBR`; body `ScadaBR Software` (identifies ScadaBR, as the reviewer noted) | none |
| unitronics | unitronics-vision-plc-and-hmi | title `Unitronics`; `Logo-Unitronics.svg`; `unitronics.com` (family; model not read) | none |
| biotime | zkteco-biotime | title starting `BioTime` (the suffix is never read: group not reviewed) | none |
| amcrest | amcrest-cameras-and-network-video-recorder-nvr | body `Amcrest Technologies` AND `LDAPUser` (the decision names both) | none |
| nuuo-nvr | nuuo-nvrmini-devices, nuuo-nvrmini2-devices | title `NUUO Network Video Recorder Login` (family; NVRmini vs NVRmini2 not told apart) | none |
| intel-amt | intel-active-management-technology-amt-small-business-technology-sbt-and-standar | Server `Intel(R) Active Management Technology` / `Intel(R) Standard Manageability`; no digest realm answered | Server header version |
| cisco-ip-phone | cisco-cisco-ip-phones | title `Cisco Systems, Inc.` with `Cisco IP Phone`; `Cisco IP Phone CP-<model>` in title or body (HTTP only) | none (model token CP-nnnn in the label, never a version) |
| login page | login-page-inventory | a password `<input>` on the root page, or a recorded `Location` whose path contains `login` (not followed). One inventory line per port, no product, never matched, never in the inventory CSV | n/a |

## Already covered elsewhere (verified, not rebuilt; listed in `ALREADY_COVERED`)
- `internal-names-in-certificate-san`, `ocsp-must-staple-advertised`, `wildcard-certificate-breadth`:
  `scanner/lib/cert-inventory.mjs` (#114): `internal_names`, `must_staple`, `wildcards[].covers_attested`.
- `mta-open-submission-on-port-25-only`: `scanner/lib/mail-starttls.mjs` (#114): `submission` on the port-25 row.
- `proftpd-proftpd`: `scanner/lib/fingerprint.mjs` GREET (`ProFTPD <version>` from the FTP greeting; version-less otherwise).
  Existing behaviour noted, not changed: a letter release (`1.3.5e`) keeps `shown_version` 1.3.5e but compares as 1.3.5.

## Left out (would need a request, or was not concretely specified)
- Versions needing a path: Zimbra `ZmSettings.js` CLIENT_VERSION, GLPI `/status.php` and `/glpi/`, Zabbix `/zabbix/`,
  KACE `/common/about.php`, Zimbra admin `/zimbraAdmin/` (admin title not in the decision signal), eMerge `/emerge.ico`.
- Favicon hashes (Zabbix, KACE, Zimbra, SolarWinds VMan, FileZen): no favicon is fetched.
- Zimbra login-page `v=` token (not concretely specified); BioTime title-suffix version (group not reviewed).
- TeamViewer native protocol (TCP 5938): no sourced banner. Cisco IP phone SIP OPTIONS and SSH `SSH-*-1.00`: SIP waits for a
  reviewed SIP identify; the SSH banner is too generic to name a phone.
- The `/login` GET of the login-page row: not requested (the decision keeps the root page only).
- **No `--clinical` CLI flag exists yet.** The Mirth Connect rule is built and tested but stays off on the scan path until
  the orchestrator adds the flag and passes `{ clinical: true }` to `pack3()` in `servicesOf()`.

## Doc text to add
**docs/scanner.md** (fingerprints section, after the passive identify pack):
> **Passive pack 3.** From the same collected data the scanner also names: Citrix StoreFront, Zimbra Collaboration Suite,
> GLPI, Zammad, SolarWinds Virtualization Manager, the Zabbix frontend, Ivanti Cloud Services Appliance, Soliton FileZen,
> the TeamViewer web placeholder, Quest KACE SMA, Nice Linear eMerge, ScadaBR, Unitronics PLC/HMI web panels, ZKTeco
> BioTime, Amcrest cameras/NVRs, NUUO NVRs, Intel AMT / Standard Manageability and Cisco IP Phones. A version is used only
> where it is stated: GLPI (footer or asset token), Zabbix (`jsLoader.php?ver=` or footer), KACE (`X-DellKACE-Version` /
> `X-KBOX-Version` header) and Intel AMT (Server header). Families (NUUO, eMerge, Unitronics, Amcrest) are never versioned.
> NextGen Mirth Connect (clinical) is identified only when clinical identification is turned on. It also records, as
> inventory, a login page: a password field on the root page or a recorded redirect into a login path; no login path is
> ever requested and the line is never a finding. No request, path, port or datagram is added.

**scanner/README.md** ("what it detects"):
> Also names about 18 more products (helpdesks, monitoring, file transfer, remote management, building and industrial
> panels, cameras, IP phones) from the same root page, headers and certificate, and lists web login pages as inventory —
> no extra traffic. Most do not state a version and are listed as "version not read" (low confidence).

## Implementation → Review
- Files: `scanner/lib/fp-pack3.mjs` (new), `scanner/lib/scan.mjs` (+2: import, one call in `servicesOf`),
  `tests/unit/scanner-pack3.test.mjs` (new, 22 tests: table covers all 28 rows, KEV name matching with the site's
  `nameHit`, every rule's signals and negatives, clinical gate, families, login inventory, dedupe, evidence hygiene,
  already-covered rows, findings confidence, and loopback proofs: an FTP greeting service receives zero bytes; a web
  service sees one connection and exactly `GET /` with a login redirect recorded, not followed).
- Bytes sent beyond today's behaviour: none.
