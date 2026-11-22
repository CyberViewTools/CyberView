# Handoff: scan-identify-passive — passive identify pack (plan w2-7c1e)

Covers the passive part of `scan-service-identify`, `scan-sprint2-packs`, `scan-iot-identify`, `scan-voip-identify`,
`scan-mgmt-identify` and `scan-ics-identify`: rows that need no new probe.

## Discovery → Design
- **Need:** a scan already holds the greeting read on connect, the one root-page response (status, title, headers,
  Set-Cookie names, recorded `Location`, body) and the TLS certificate, but `fingerprint.mjs` named only a handful of
  servers. Many KEV products announce themselves in exactly that data.
- **Constraints:** zero extra bytes: no new connection, request, path, port, hello or datagram; `SENDS` unchanged; no body,
  cookie value or page text stored; a version only where the collected data states it, otherwise `guessed` (low confidence,
  out of the headline counts); ICS/camera/building rows identification only.
- **Design:** one data-driven table (`RULES` in `scanner/lib/fp-identify.mjs`) and one evaluator `identify(r, existing)`.
  A rule matches when any of its signals matches; a signal matches when all its fields match (`title`, `body`, `server`,
  `header`, `cookie` name, `location`, `cert` subject, `banner`, `json` paths) and none of its `not` fields does. Evidence is
  the signal's fixed `why` text plus the version read. Hook: one import and one line in `servicesOf()` (`scan.mjs`), after
  the existing parsers, so a product they already named on the port is not added twice.

## Built (32 catalog IDs, 29 rules)
| Rule | Catalog IDs | Signals (all already collected) | Version |
|---|---|---|---|
| gitlab | gitlab-community-and-enterprise-editions, gitlab-community-edition-and-enterprise-edition | cookie name `_gitlab_session`; body `GitLab` + `https://about.gitlab.com` | none (guessed) |
| activemq | apache-activemq | OpenWire WireFormatInfo frame read on connect; root title / console welcome | OpenWire `ProviderVersion` |
| rocketmq-console | apache-rocketmq | root title | none |
| pi-hole | pi-hole-adminlte | root title; tagline | none |
| adminer | adminer-adminer | root title | `<span class="version">` |
| couchdb | apache-couchdb | Server header; welcome JSON (`couchdb`, `vendor`) | Server header / JSON `version` |
| elasticsearch / opensearch | elasticsearch-root-document, opensearch-root-document | root JSON (`cluster_name`, `version.number`; OpenSearch by `version.distribution`) | `version.number` (+ cluster name, sanitised, in evidence) |
| mongo-express | mongodb-mongo-express | root title | none |
| phpmyadmin | phpmyadmin-phpmyadmin | root title; logo alt, login field name, pmahomme theme | none (`v=` asset token not used) |
| aria-operations | broadcom-vmware-aria-operations, vmware-vrealize-operations-manager-api | root title (either brand) | `SessionProvider.js?version=` |
| esxi | broadcom-vmware-esx | `esxUiApp`, `ID_ESX_Welcome`/`ID_EESX_Welcome` | none |
| vcenter | broadcom-vmware-vcenter | Location or link to `/ui`/`/websso/` plus VMware vSphere/vCenter, never on an ESXi page | none |
| recoverpoint | dell-recoverpoint-for-virtual-machines-rp4vms | body `RecoverPoint Wizard` (family; RP4VMs not told apart) | none |
| hikvision | hikvision-security-cameras-web-server | Server `Hikvision-Webs`/`DNVRS-Webs`/`DVRDVS-Webs`; realm hikvision; cert O=HIKVISION | none |
| papercut | papercut-mf-ng | title `PaperCut Login`; meta content PaperCut (root or any collected page) | none |
| reolink | reolink-multiple-ip-cameras, reolink-rlc-410w-ip-camera | title ending `Reolink` (family only; RLC-410W model not read) | none |
| solarview | solarview-compact | body `SolarView Compact` | none |
| workspace-one-access | vmware-workspace-one-access-and-identity-manager | Location into `/SAAS/`; body `/SAAS/auth` | none |
| opensmtpd, qmail | opensmtpd, qmail | product name in the SMTP greeting | none |
| cwp | cwp-control-web-panel | Server `cwpsrv`; cookie name `cwpsrv-<32 hex>`; title | none |
| cyberpanel | cyberpersons-cyberpanel | title contains CyberPanel | none |
| hpe-oneview | hewlett-packard-enterprise-hpe-oneview | title `OneView` | `var artifactVersion` |
| omnipcx | alcatel-omnipcx-enterprise | FTP greeting `Alize Session Manager FTP Server` | none |
| grandstream-ucm6200 | grandstream-ucm6200 | title `Grandstream Device Configuration` + UCM marker (`tl.account.ucm.js` or `UCM62xx`); telnet greeting `Grandstream UCM62xx Command Shell` | none |
| openfire | ignite-realtime-openfire | title; `Openfire, Version:` | `Openfire, Version:` |
| mitel | mitel-sip-phones | body `Mitel Networks Corporation` — generic Mitel: inventory label only, no product, never matched to a flaw | none |
| unrealircd | unrealircd | product name in the greeting | none |

## Skipped (5) and parts left out
- `puppet-server`, `xenserver-or-xcp-ng`, `verifone-or-ingenico-terminal-service`: the rows give no concrete signal
  ("do not invent").
- `postgresql-handshake`: PostgreSQL does not speak first; reading it needs a startup message (a new send).
- `ietf-service-location-protocol-slp`: needs an SLP datagram or TCP request; no greeting exists to read.
- Parts left out of built rows: ActiveMQ STOMP error banner (needs a command sent), ActiveMQ console version (on `/admin/`),
  vCenter LDAP PSC attribute (LDAP does not greet), CouchDB Fauxton title (not in the reviewer decision), favicon hashes
  (no favicon is fetched), ESXi bare meta-refresh to `/ui` (too generic alone), GitLab bare `/users/sign_in` redirect
  (Devise default), Grandstream title without a UCM marker, the Mitel SIP phone product attribution, Reolink model.

## Doc text to add
**docs/scanner.md** (fingerprints section):
> **Passive identify pack.** From the data a scan already collects — the greeting read on connect, the root-page title,
> headers, cookie *names*, recorded `Location` and body markers, and the TLS certificate subject — the scanner also names:
> GitLab, Apache ActiveMQ (OpenWire version), RocketMQ console, Pi-hole, Adminer, CouchDB, Elasticsearch, OpenSearch,
> mongo-express, phpMyAdmin, VMware Aria Operations / vRealize Operations, ESXi, vCenter, Workspace ONE Access, Dell
> RecoverPoint, Hikvision, PaperCut MF/NG, Reolink, Contec SolarView Compact, OpenSMTPD, qmail, CWP, CyberPanel, HPE OneView,
> Alcatel OmniPCX Enterprise, Grandstream UCM6200, Openfire, Mitel (generic) and UnrealIRCd. No request, path, port or
> datagram is added. A version is used only where the service states it (ActiveMQ, Adminer, CouchDB, Elasticsearch,
> OpenSearch, Aria Operations, HPE OneView, Openfire); every other identification is version-less, low confidence and
> out of the headline counts. Evidence is a fixed description of the marker; page text and cookie values are never kept.

**scanner/README.md** ("what it detects"):
> Also names around 30 more products (management consoles, message brokers, search engines, cameras, VoIP and mail
> servers) from the same greeting, root page and certificate — no extra traffic. Most do not state a version and are
> listed as "version not read" (low confidence).

## Implementation → Review
- Files: `scanner/lib/fp-identify.mjs` (new), `scanner/lib/scan.mjs` (+2: import, one call in `servicesOf`),
  `tests/unit/scanner-identify.test.mjs` (new, 18 tests, including loopback proofs: a greeting service receives zero bytes,
  a web service sees one connection and exactly `GET /`).
- Follow-ups: favicon hashes and frozen paths (`/users/sign_in`, `/ui/login.action`, `/admin/`) wait on `scan-http-paths`;
  STOMP, SLP, PostgreSQL and LDAP need a reviewed identify hello; ICS active queries stay opt-in.
