# Backlog

Every build item, its stage and the next action. Stages: **Discovery → Design → Implementation → Review → Done**
(or **Parked**). The orchestrator keeps this current. See [`README.md`](README.md).

## Active

| id | Item | Stage | Lead | Next action |
|---|---|---|---|---|
| scan-html | Scanner HTML report (self-contained `report.html`) + surface the backport caveat in the report | Design | Design | spec the report + PR plan |
| tk-matchers | Toolkit: offline matchers — SBOM (CycloneDX/SPDX) / nmap-XML / CVE-lookup, no network, reuse the site matching engine | Design | Design | Discovery done ([handoff](handoff/tk-matchers.md), BUILD); confirm `--assume-exposed`, then start PR1 (`inputs.mjs` adapter) |
| tk-diff | Scan diff / watch — compare to last scan (new/fixed/still-open), optional scheduled re-scan + alert | Discovery | Discovery | brief: state model, alerts tie-in |
| tk-hygiene | TLS & exposure hygiene — cert expiry/weak protocols, missing security headers, version disclosure, default pages (from data already collected) | Implementation | Implementation | Discovery + Design done ([handoff](handoff/tk-hygiene.md)); PR 1 (TLS/cert) open, then PR 2 (HTTP/mail) |

## Parked (owner decision pending)

| id | Item | Why parked |
|---|---|---|
| tk-package | Toolkit rename + downloadable app (bundled CLI + OS binaries via release workflow) | owner: features first, package later |
| gdacs-history | GDACS Part 2: browsable disaster history (SEARCH backfill) | owner: deferred after the live layer |
| xleads-p2 | x-leads (#72) Phase 2: official X API + budget caps | needs the pay-per-use route decision |
| subs | Subscriptions / monetization (freemium, open-core) | long-term (see the roadmap doc) |

## Recently done (this session)

| Item | PR |
|---|---|
| Scanner #82 item 5 (low-confidence out of headline counts; version-less OpenSSH + FTP/SMTP-by-banner) | #91 |
| Scanner #82 items 1–4 (coverage, host-down, throttle, plain-HTTP) | #87 (merged) |
| store.mjs month-move cleanup | #85 (merged) |
| grok-watch: Grok messages anywhere + handled-signal fix | #86 (merged) |
| GDACS layer: recent ARCHIVE, dated, 2/3/7-day bands, 30-day window | #81, #83 (merged) |
| GDACS source fix (RSS, then ARCHIVE) | #78 (merged) |
