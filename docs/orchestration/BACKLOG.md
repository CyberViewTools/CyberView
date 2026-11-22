# Backlog

Every build item, its stage and the next action. Stages: **Discovery → Design → Implementation → Review → Done**
(or **Parked**). The orchestrator keeps this current. See [`README.md`](README.md).

## Active

| id | Item | Stage | Lead | Next action |
|---|---|---|---|---|
| scan-wave3 | Scanner wave 3: review of waves 1–2 and research for the next slices (from the deferred rows in the handoffs) | Review | Orchestration | in progress |
| scan-release | Single-file executables and tagged GitHub Releases built by CI, with checksums (Grok brief #89; approved, decision 12 in `docs/scanner.md`) | Implementation | Implementation | in progress |
| scan-viewer | Browser report viewer and scope-file builder on the Scanner page (approved, decision 13; no in-browser scanning) | Implementation | Implementation | in progress |
| tk-matchers | Toolkit: offline matchers — SBOM (CycloneDX/SPDX) / nmap-XML / CVE-lookup, no network, reuse the site matching engine | Design | Design | Discovery done ([handoff](handoff/tk-matchers.md), BUILD); confirm `--assume-exposed`, then start PR1 (`inputs.mjs` adapter) |
| tk-diff (watch) | Scheduled re-scan + alert, the "watch" half of tk-diff (the compare half shipped in #114) | Discovery | Discovery | brief: state model, alerts tie-in |

## Parked (owner decision pending)

| id | Item | Why parked |
|---|---|---|
| tk-package | Toolkit rename + downloadable app (bundled CLI + OS binaries via release workflow) | owner: features first, package later (the binaries part is now scan-release) |
| gdacs-history | GDACS Part 2: browsable disaster history (SEARCH backfill) | owner: deferred after the live layer |
| xleads-p2 | x-leads (#72) Phase 2: official X API + budget caps | needs the pay-per-use route decision |
| subs | Subscriptions / monetization (freemium, open-core) | long-term (see the roadmap doc) |

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
