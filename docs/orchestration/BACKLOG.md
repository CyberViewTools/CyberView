# Backlog

Every build item, its stage and the next action. Stages: **Discovery → Design → Implementation → Review → Done**
(or **Parked**). The orchestrator keeps this current. See [`README.md`](README.md).

## Active

| id | Item | Stage | Lead | Next action |
|---|---|---|---|---|
| scan-release-tag | First scanner release: tag `scanner-v1.1.0` on main (`VERSION` is already 1.1.0); `scanner-release.yml` builds and publishes it | Implementation | Owner | the owner pushes the tag (steps in `docs/scanner.md`, Releases) |
| scan-hellos-2 | Fingerprints that need a protocol hello: Kafka ApiVersions, MQTT CONNECT, Redis PING, ACME `acme-tls/1` ALPN, SQL Server pre-login, Oracle TNS version, JetDirect PJL, NetBackup vnetd, MongoDB hello | Discovery | Design | one Design per protocol under decision 10 (opt-in, one standard unauthenticated message, frozen bytes, section 7) |
| scan-dnp3 | DNP3 identification (`dnp3-identify`) | Parked | Design | deferred (decision 20) until the scope file can carry an operator-supplied outstation address; then its own Design |
| scan-rail-review | Path-rail review: the MTA-STS policy file (for `--dns-records`) and FHIR `/metadata` (`fhir-or-hl7-http-endpoint`, opt-in) | Discovery | Design | list both in a rail Design for the lead's review |
| scan-dnssec | DNSSEC presence for `--dns-records` | Parked | Design | `node:dns` cannot ask for DS or DNSKEY; needs a stdlib-only approach or stays out |
| scan-no-fp | 31 catalog rows with no public fingerprint | Parked | Discovery | kept as gaps; revisit if a public fingerprint appears |
| tk-matchers | Toolkit: offline matchers — SBOM (CycloneDX/SPDX) / nmap-XML / CVE-lookup, no network, reuse the site matching engine | Design | Design | SBOM and package-list matching shipped in #120 (`import`, `scanner/lib/imports.mjs`); check what of the [handoff](handoff/tk-matchers.md) remains (nmap-XML, CVE-lookup, `--assume-exposed`) |
| tk-diff (watch) | Scheduled re-scan + alert, the "watch" half of tk-diff (the compare half shipped in #114) | Discovery | Discovery | brief: state model, alerts tie-in |

## Parked (owner decision pending)

| id | Item | Why parked |
|---|---|---|
| ops-registry | `routines.json` does not list the owner-created fresh-session watchers (health watch every 2 h, Grok review hourly). The Guardian itself IS present and enabled - a 2026-11-23 audit lane reported it missing from a partial trigger listing and was wrong; a complete listing of 126 tasks confirmed it runs `47 */2 * * *` and last succeeded 20:47Z | not worth doing as a registry change: an active routine row would oblige a `config/about.json` entry (about.mjs check), which puts internal ops detail on the public About page, and neither watcher has a heartbeat for pipecheck to judge. Both are documented in `swarm/CONTINUITY.md` instead, which is the runbook for unattended operation |
| ukpn-access | UK Power Networks grid source, `paused` since 2026-11-19; `config/data-access.json` holds a drafted permission request (status `not_asked`, `why_not: robots`) | owner: send the drafted request to their open-data contact, or drop the source. Dropping is legitimate - robots.txt disallows `/api/`. It makes no requests while paused, so the only cost is a coverage gap |
| usage-blindspot | The ledger counts headless workers only, so it is blind to an estimated 25-50% of window use (dispatcher sessions 1.25B+221M cache reads, interactive sessions, and the subagent-run claims/outage/moderator jobs). `canBuild`'s 35% pipeline reserve is therefore computed on a partial number and the real reserve is smaller than intended - this is how the 22 Nov build swarm ate the window | owner: choose how to close it. (a) record each worker's `rate_limit_info` if the headless stream exposes it (most honest, ~20-40 lines, unverified), (b) add a `dispatcher_allowance_pct` to the denominator (~5 lines, crude, and it makes PARKING more likely - see the 5-day stall that one transient hit caused in #136), or (c) leave it measured-and-labelled, which is what #136 does |
| dispatcher-context | The ops and standby sessions carry 370K and 500K of context; every trigger fire re-reads it (ops: 1.25B cumulative cache reads, $218). `dispatch.mjs` states the intent to keep history small but nothing enforces it, and `persist_session` lives in the trigger config, outside the repo | owner infrastructure: recreate the two triggers as fresh-session-per-fire (as the health watch and Grok review already are), or add a recycle that retires the session after N turns. Nothing in the repo holds per-session state, and the loop's lock and heartbeat are file-based, so continuity survives |
| strict-accuracy-checks | Promoting `PROPOSED_STRICT_FROM`'s five checks to build errors | DECIDED AGAINST 2026-11-23, with measurement: they catch ~14% of corrections (33 of 234), not ~40%; `occurred-round-hour` is 50% precision and `source-published-partial` 66%, so promoting them would quarantine ~49 events reviewers PASSED. An error hides an event from defenders, which is the wrong trade for a style rule. Revisit only with better precision data; `long-summary` is the only one at 100% (on 12 cases) |
| loose-age-limits | Several `max_age_hours` are loose: `backlog` 7 h for an hourly desk, `link-check` 200 h against a 168 h cadence, `report-review`/`analysis`/`regional`/`improver` 30 h against 24 h | not fixed on purpose: pipecheck now judges all of them (#136), so correctness is covered, and tightening thresholds without evidence invites false alarms. Tighten only if a real lapse hides inside one |
| tk-package | Toolkit rename + downloadable app (bundled CLI + OS binaries via release workflow) | owner: features first, package later (the binaries part is now scan-release) |
| gdacs-history | GDACS Part 2: browsable disaster history (SEARCH backfill) | owner: deferred after the live layer |
| xleads-p2 | x-leads (#72) Phase 2: official X API + budget caps | needs the pay-per-use route decision |
| subs | Subscriptions / monetization (freemium, open-core) | long-term (see the roadmap doc) |

## Done: scanner, wave 3 (2026-11-22)

Review of waves 1–2 and the research-driven slices. Docs consolidated in `docs/scanner.md` (lead decisions 14–22) and
`scanner/README.md`.

| id | Item | PR | Handoff |
|---|---|---|---|
| scan-release | Single-file scanner bundle and tagged GitHub Releases built by CI, with checksums (Grok brief #89) | #118 | [scanner-releases](handoff/scanner-releases.md) |
| scan-passive-3 | Passive pack 3: 20 more products from data already collected, and the login-page inventory | #119 | [scan-passive-3](handoff/scan-passive-3.md) |
| scan-report-pack-2 | Relationship map (`--depmap`), operator imports, local package matching, offline rematch | #120 | [scan-report-pack-2](handoff/scan-report-pack-2.md) |
| scan-ics-identify | `--ics`: read-only industrial and clinical identification, private ranges only | #121 | [scan-ics-identify](handoff/scan-ics-identify.md) |
| scan-identify-hellos | `--identify`, `--identify-bmc` (incl. RDP, SMB2, LDAP root DSE) and `--dns-records` | #122 | [scan-identify-hellos](handoff/scan-identify-hellos.md) |
| scan-research-pack | 55 public-reference fingerprints, DNS version.bind names, the Ivanti rail row | #123 | [scan-research-pack](handoff/scan-research-pack.md) |
| scan-viewer | Report viewer and scope-file builder on the Scanner page (browser only) | #124 | — |

## Done: scanner, waves 1–2 (2026-11-22)

Each slice's build record is its handoff file; the docs are consolidated in `docs/scanner.md` and `scanner/README.md`.

| id | Item | PR | Handoff |
|---|---|---|---|
| tk-hygiene (PR 1) | TLS and certificate hygiene from the one handshake | #97 | [tk-hygiene](handoff/tk-hygiene.md) |
| tk-hygiene (PR 2) | HTTP and mail hygiene from the one root-page response | #98 | [tk-hygiene](handoff/tk-hygiene.md) |
| scan-incidents-cite + scan-hunt-links | Reviewed incident citations (`--data-incidents`) and hunt links on findings | #108 | [scan-incidents-cite](handoff/scan-incidents-cite.md) |
| scan-ssh-kex | Read the server's SSH KEXINIT; weak set, PQC note | #109 | [scan-ssh-kex](handoff/scan-ssh-kex.md) |
| scan-html | Self-contained `report.html` (`--html`) with the backport caveat | #110 | [scan-html](handoff/scan-html.md) |
| scan-cms-html | CMS, plugin, theme and JS library versions from the root page | #111 | [scan-cms-html](handoff/scan-cms-html.md) |
| scan-edge-versions (PR A) | Edge appliance fingerprints from collected data | #112 | [scan-edge-versions](handoff/scan-edge-versions.md) |
| scan-app-versions (packs 1–2) + scan-identify-passive | Passive application and identify packs | #113 | [pack 1](handoff/scan-app-versions-1.md), [pack 2](handoff/scan-app-versions-2.md), [identify](handoff/scan-identify-passive.md) |
| scan-report-pack (incl. tk-diff compare) | `--certs`, `--mail`, `--compare`, `coverage` | #114 | [scan-report-pack](handoff/scan-report-pack.md) |
| scan-http-paths | Bounded HTTP path rail (`--paths`, off by default) | #115 | [scan-http-paths](handoff/scan-http-paths.md) |
| scan-site-tab | The Scanner page on the site, with live counts | #116 | — |

## Recently done (earlier)

| Item | PR |
|---|---|
| Scanner #82 item 5 (low-confidence out of headline counts; version-less OpenSSH + FTP/SMTP-by-banner) | #91 |
| Scanner #82 items 1–4 (coverage, host-down, throttle, plain-HTTP) | #87 (merged) |
| store.mjs month-move cleanup | #85 (merged) |
| grok-watch: Grok messages anywhere + handled-signal fix | #86 (merged) |
| GDACS layer: recent ARCHIVE, dated, 2/3/7-day bands, 30-day window | #81, #83 (merged) |
| GDACS source fix (RSS, then ARCHIVE) | #78 (merged) |
