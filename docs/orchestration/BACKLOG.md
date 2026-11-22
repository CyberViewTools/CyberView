# Backlog

Every build item, its stage and the next action. Stages: **Discovery → Design → Implementation → Review → Done**
(or **Parked**). The orchestrator keeps this current. See [`README.md`](README.md).

## Active

| id | Item | Stage | Lead | Next action |
|---|---|---|---|---|
| scan-html | Scanner HTML report (self-contained `report.html`) + surface the backport caveat in the report | Review | Implementation | self-contained report.html on scan and match; backport caveat in the header ([handoff](handoff/scan-html.md)) |
| tk-matchers | Toolkit: offline matchers — SBOM (CycloneDX/SPDX) / nmap-XML / CVE-lookup, no network, reuse the site matching engine | Review | Implementation | `match` command, `--assume-exposed` off by default ([handoff](handoff/tk-matchers.md)) |
| tk-diff | Scan diff / watch — compare to last scan (new/fixed/still-open), optional scheduled re-scan + alert | Review | Implementation | `diff` of two reports; watch list is a file, not a sender ([handoff](handoff/tk-diff.md)) |
| tk-hygiene | TLS & exposure hygiene — cert expiry/weak protocols, missing security headers, version disclosure, default pages (from data already collected) | Implementation | Implementation | Discovery + Design done ([handoff](handoff/tk-hygiene.md)); PR 1 (TLS/cert) open, then PR 2 (HTTP/mail) |
| scan-http-paths | Bounded HTTP path rail | Review | Implementation | `--paths` hint-gated, cap 8 ([handoff](handoff/scan-http-paths.md)) |
| scan-cms-html | CMS and JS versions from the root page | Review | Implementation | plugins disclosed in the body, script filenames ([handoff](handoff/scan-cms-html.md)) |
| scan-incidents-cite | CVE citations, claimed events omitted | Review | Implementation | `--data-incidents` offline index ([handoff](handoff/scan-incidents-cite.md)) |
| scan-hunt-links | Hunt pointers, links only | Review | Implementation | publisher URLs from the workbench ([handoff](handoff/scan-hunt-links.md)) |
| scan-ssh-kex | SSH KEXINIT on the same connection | Review | Implementation | weak set and PQC names; no client key exchange ([handoff](handoff/scan-ssh-kex.md)) |
| scan-edge-versions | Appliance hints from collected pages and greetings | Review | Implementation | cited literals only; login titles stay guesses ([handoff](handoff/scan-edge-versions.md)) |

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
