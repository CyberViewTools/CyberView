# CyberView — orchestration state

Durable working memory for the CyberView lead/build lane. Read this plus `docs/orchestration/BACKLOG.md` to pick up where the last session left off without reading any prior chat. The chat is a disposable driver; the repo is the memory. Rewrite this file in place (not append-only) as things change.

## In flight / recent (as of 2026-11-23)

Merged today:
- #126 — efficiency gates (fixes the follow-up 15-minute clock bug, turn caps, usage reserve)
- #127 — accuracy eval set (`scripts/evals.mjs`)
- #128 — phone-feed test fix
- #129 — API-key fallback
- #130 — `--ics` results in summary.txt / inventory.csv / report.html
- #132 — cost tiering

Merged since: #134 — public + internal description refresh (About/Status prose for the accuracy eval set, API fallback
and cost tiering; feed count corrected to 280; BUILD 1.70).

Open (this session):
- #136 — started as three fixes from the status page Routines section, then grew into the audit below (branch claudex/zen-hypatia-y3utma, DRAFT by choice, full CI green: 1043 unit, 668 browser). Opening it ready triggers a one-off ~67-run review drain, so the owner picks the moment. First three fixes:
  - `scripts/review.mjs`: the queue windowed on `first_seen` while `needsReview` fires on `updated_at`, so 66 of 67 events changed after their review could never be re-queued (queue said 1, pipecheck 60). Now an exported pure `inReviewWindow()` on `waitingSince`. Live effect: queue 1 -> 67. Draining it is a one-off ~67 reviewer runs, so expect a short spike and a truer accuracy number afterwards.
  - `config/pipeline.json`: `sweep.gap_pass` false. The pass sat at the gap_max_every_minutes ceiling and then ran 143 times in a row adding nothing: 278 runs, 118.4 M tokens, $76.56 of the week's $858.58. Every other gap_* dial untouched, so flipping it back restores prior behaviour exactly.
  - `scripts/collect.mjs` + `scripts/lib/net.mjs`: on a 415 only, ask once more without our `accept` list, same identifying UA. Fixes the four 415 collectors (Daily News/HabariLeo Tanzania, Lefaso.net, Ciberseguridad LATAM). Not a block workaround: 401/403 stop is untouched and a persistent 415 still fails as 415.
  - Done with two worktree subagents (lanes A and B, Sonnet, ~200 K tokens total) plus inline work; one CI run, one PR. Note for next time: the feed collector uses `fetchFeed` in `scripts/collect.mjs`, NOT `net.mjs` `get()`.

- #140 — scanner `match`: a full report from files the operator already holds (nmap `-oX` with `-sV`, an SBOM, a package
  list), for assets that cannot be scanned. New `scanner/lib/inputs.mjs` adapters return `fingerprint.mjs`'s own record
  shape, so the matching, rating, CISA priority and all five outputs are the scan's code unchanged; CPE/purl give the
  vendor the matcher needs; `--assume-exposed` (default internal) moves only CISA's deadline. Nothing is contacted and the
  report says so. Closes most of tk-matchers; only an offline `lookup <CVE>` reader remains. Decision 23 in
  `docs/scanner.md`.

Prior open item (merged):
- Public + internal description refresh. Surfaces the recent operational work (#127 accuracy eval set, #129 API fallback, #132 cost tiering) in the public prose and corrects drift:
  - `config/about.json` "ops": added measured-accuracy test set, model tiering (least-costly-capable, Opus only where needed) and non-stalling publishing (subscription-primary, API fallback within a monthly cap). Numbers still live-filled; `about.mjs check` green.
  - `legal/about.html` "How it is made": feed count 220→280 (live total is 280 = 228 collect + 52 feeds.json), X noted as a lead-only source (never evidence), new "Accuracy, cost and reliability" bullet linking the status page.
  - `site/status.html`: one-line note on the Accuracy section about the eval test set (fallback/tiering/accuracy are already surfaced live via health.json + the Accuracy/Improver sections, and `nav.js` injects the Actors/Scanner links, so no nav edit needed).
  - `site/app.js`: BUILD 1.69→1.70 (2026-11-23), since a tracked site/ file changed.

Open PRs: #140 (scanner `match`) and #136 (pipeline audit) (confirm with the GitHub tools when you run — there is no `gh pr list` here, only `gh api search/*`).

## Audit of 2026-11-23 (four read-only lanes; findings VERIFIED by the lead before acting)

Fixed in #136 (full CI green: 1043 unit, 668 browser):
- `usage.mjs resetFrom` could not parse the weekly reset format ("resets Nov 28, 8pm (UTC)") and fell back to 60 minutes against a real 125 hours. With the API fallback armed this made it FLAP hourly instead of staying on fallback. Cross-checked against the session's own `rate_limit_info.resetsAt`.
- `linkcheck` took a HEAD 404 as authoritative; dailysecu.com returns HEAD 404 / GET 200, so the 9 "dead links" were false positives and the verify desk could replace VALID citations. Now retries GET on 404/410 and rotates through all ~1250 URLs instead of re-checking the first 400.
- `pipecheck` judged 14 of 34 routines with a heartbeat, so verify (30 h) and advisory (28 h) were dead while the page said "24 of 24 on time". Now derived from routines.json, with a grace window for never-run routines and the MAX_OPEN_PER_RUN cap respected.
- Five metric artefacts: feed "waste" ranking counted first-run backfill; heartbeat-only routines read "0 runs"; `scams` read 100% idle while publishing 54 warnings; `closed` summed stories and leads; 130 pre-logging events read "unknown writer" (22% of the accuracy denominator).
- 170 of 361 hygiene warnings were invented tags: the preamble named 3 of 23 allowed tags. All 23 now listed, with a drift test.
- On-file gate (`gates.mjs`, wired into `updates.mjs`): no updater worker when the only new input is a publisher the event already cites. Reopens on a new publisher, gov/vendor/research source, new CVE, new figure, claim kind, or after 24 h.
- Research loop: span-bounded leader lease; no heartbeat or hand-over commits, one claims commit per cycle (~120-190 of 358 daily bookkeeping commits). CONTINUITY.md's lease row was updated to match.
- **A limit park now ends when a worker is served again.** Parsing the weekly reset correctly (above) turned ONE transient refusal into a 5-day park: `budget.mjs` flipped from BUILD OK to "no build work until 2026-11-28" even though 83 workers were served after the 13:57 refusal and the plan reports status `allowed`. A worker served past a 5-minute grace now ends the park, so a genuine limit still holds to its reset but a transient one cannot stop publishing. This was MY regression, caught by running the gate rather than trusting it.
- The usage percentages now say they are headless-only, since the ledger cannot see the dispatcher or interactive sessions.

Corrections to earlier conclusions in this session (all MY errors, recorded so they are not repeated):
0. **The Guardian was never missing.** An audit lane read a PARTIAL trigger listing, found no Guardian in it, and reported it absent; that went into the lead's report to the owner and into these files as a possible broken reliability invariant. A complete listing (126 tasks, 8 pages, `has_more: false`) shows "CyberView: Guardian" `trig_01AQNQvXJeLj2JLtnCuDDHUX` ENABLED, `47 */2 * * *`, fresh session, last run SUCCEEDED 2026-11-23 20:47Z. Lesson: never report a scheduled task as absent from a listing that was not paged to completion. The repo also resists de-registering it on purpose - `tests/unit/jobs.test.mjs` asserts guardian stays active, and `about.mjs check` requires every active routine to be described.
1. The "most wasteful feeds" list (msrc 129 leads/0 used, zdi 31/0) is first-run BACKFILL, not ongoing waste. Feed pruning saves almost nothing: a feed is a cheap HTTP GET and the spend is in agent workers.
2. The 1,711 "already on file" closures are `backlog.mjs auto` RULE closures and cost no worker — `isOpen = s.open > 0 && !s.event` (fuse.mjs:161) means an on-file story never reaches a researcher. It is log noise, not spend. The gate targets updater workers, a smaller real win.
3. Lease commits never drove deploys: `NO_DEPLOY` (repo.mjs:50) already exempts `leases.json` and git-sync returns early when every changed file matches.

Also measured, deliberately NOT changed:
- Do NOT promote the proposed accuracy checks to errors. Measured catch is ~14% of corrections (33 of 234), not 40%; `occurred-round-hour` is 50% precision and `source-published-partial` 66%, so promoting them would quarantine ~49 events reviewers PASSED. An error hides an event from defenders — wrong trade for a style rule.
- Rework costs ~$11-15/week at the margin, not hundreds. Fix accuracy for quality, not savings.
- `monitor.mjs:50-55` DOES check every routine, but only alerts above 2x `max_age_hours` (exit 1); between 1x and 2x it exits 2 and the workflow opens nothing. That is why a 30-hour-dead desk was silent. LEFT AS IS on purpose: pipecheck now catches at 1x and opens the `pipeline-alert`, verified live (`4 problem(s); 24 of 24 stages on time` became `10 problem(s); 34 of 41`, with verify 30 h and advisory 29 h both `late` and scout `idle` in its grace window). Lowering monitor's threshold too would only duplicate alerts; it stays the second-tier "it has stopped" signal.
- The usage ledger is blind to 25-50% of consumption (dispatchers, interactive sessions, subagent-run claims/outage/moderator). `canBuild`'s 35% pipeline reserve is computed on headless-only numbers, so the real reserve is smaller than intended.
- Leave the ~154 old hygiene warnings, and `action-unsourced` / `corroborated-note` (chance-level precision).

## Pending owner actions

1. Set env var `CYBERVIEW_FALLBACK_ANTHROPIC_API_KEY` in the cyberview environment to arm the API fallback. The subscription stays primary (see CLAUDE.md "Reliability rules"). Name only — never a value here.
2. Optionally disconnect unused MCP connectors: Alpha Vantage, Inkbox, Netlify (CyberView uses none of these). Keep the Cloudflare Radar, EIA and ENTSO-E API keys — the grid-analysis pipeline uses them.

## Model map (from #132)

- Opus: exploit-analyst, analysis, security-review only.
- Sonnet: researcher-deep, updater-deep, followup-deep, editor, tabletop (detailed-harness prompts in `docs/jobs.md`).
- Haiku: classifier, moderator.

Changed directly by the owner citing the #127 evals (the Opus deep roles were not more accurate).

## Scanner remainder (see docs/orchestration/BACKLOG.md "Remaining")

Protocol fingerprints each needing one new reviewed send, off by default — Kafka, Redis, MQTT, SQL Server pre-login, Oracle TNS, JetDirect, MongoDB hello, NetBackup (byte layouts sourced in the wave-3 research). DNP3 (needs an operator-supplied address). MTA-STS policy fetch + FHIR `/metadata` (path-rail review). DNSSEC. ~31 rows unbuildable (no public fingerprint). The heavy protocol work is held until the fallback key is set so build spend can't stall publishing.

## Known flaky test

Two scanner cert/TLS tests in `tests/unit/scanner.test.mjs` are CPU-timing-flaky under full-suite parallel load (pass in isolation / on re-run). Pre-existing.

## How to continue cheaply

Start a FRESH session per workstream, seeded from a standing prompt plus this file; don't keep one long thread. Write decisions here the moment they're made.
