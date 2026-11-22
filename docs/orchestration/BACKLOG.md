# Backlog

Every build item, its stage and the next action. Stages: **Discovery → Design → Implementation → Review → Done**
(or **Parked**). The orchestrator keeps this current. See [`README.md`](README.md).

## Active

| id | Item | Stage | Lead | Next action |
|---|---|---|---|---|
| scan-counts | Scanner #82 item 5: low-confidence rows out of the headline counts; fingerprint fixes (version-less `SSH-2.0-OpenSSH`, FTP-on-non-21 mislabel) | Implementation | Impl | build on a branch, tests, PR |
| scan-html | Scanner HTML report (self-contained `report.html`) + surface the backport caveat in the report | Design | Design | spec the report + PR plan |
| tk-matchers | Toolkit: offline matchers — SBOM (CycloneDX/SPDX) / nmap-XML / CVE-lookup, no network, reuse the site matching engine | Discovery | Discovery | brief: formats, data needs, safety fit, CLI shape |
| tk-diff | Scan diff / watch — compare to last scan (new/fixed/still-open), optional scheduled re-scan + alert | Discovery | Discovery | brief: state model, alerts tie-in |
| tk-hygiene | TLS & exposure hygiene — cert expiry/weak protocols, missing security headers, version disclosure, default pages (from data already collected) | Discovery | Discovery | brief: which checks, thresholds, detection-only |

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
| Scanner #82 items 1–4 (coverage, host-down, throttle, plain-HTTP) | #87 (merged) |
| store.mjs month-move cleanup | #85 (merged) |
| grok-watch: Grok messages anywhere + handled-signal fix | #86 (merged) |
| GDACS layer: recent ARCHIVE, dated, 2/3/7-day bands, 30-day window | #81, #83 (merged) |
| GDACS source fix (RSS, then ARCHIVE) | #78 (merged) |
