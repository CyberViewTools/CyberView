# Grid review fixes: handoff (lane grid-fixes, 2026-11-20)
The 46 findings of swarm/grid-review-20261120/out/{logic,ops,news,sources}.json, fixed on this branch in 7 commits (not
pushed). Every changed behaviour has a unit test, most built from the finding's own evidence. Checks at the last commit:
`npm run unit` 319/319, `tests/test_all.py` ALL PASS (458 checks), security check, about check and `grid.mjs verify` pass.
A live `grid.mjs collect` in a scratch copy (02:28 UTC) confirmed: Hydro-Québec (data from 00:00Z) and NGED (23:40Z)
are now marked stale, ECG Ghana and Ecowatt dormant, Liander bands read "under 300 customers", the series is written
sparse, and the paused UK Power Networks is no longer in the map layer's error.

Commits: f2d1298 tracker and source state · 4d63abb grid desk · 2ea04bb corroboration · 1ceb1c5 series and trends ·
94b65f0 grid-news · 169cb8d source adapters and audit · 73f4bbf site, health, status page, guard.

| id | severity | result |
|---|---|---|
| logic-1 | high | fixed 4d63abb: plan_id includes each incident's tries; retry recorded (tries 2, final at max_tries) |
| logic-2 | high | fixed 2ea04bb: EIA by balancing authority / 300 km; IODA and Radar only for national incidents in large countries, labelled nationwide |
| logic-3 | medium | fixed 4d63abb: registrable-domain match with the source's hosts; bare "energy" dropped |
| logic-4 | medium | fixed f2d1298: stale instead of closed; close_after_minutes 30; reopen within 120 min keeps the id; page label 73f4bbf |
| logic-5 | medium | fixed 1ceb1c5: step integration (hold <= 60 min), coverage, week null under 90% coverage; app 73f4bbf; trends.js caveat: request |
| logic-6 | medium | fixed 2ea04bb: grid-news reports skip POWER_WORDS, matched by country and nearness; POWER_WORDS widened |
| logic-7 | medium | fixed 4d63abb (newsCandidates in grid-desk), 73f4bbf (result on the news row); docs/jobs.md text: request |
| logic-8 | low | fixed f2d1298: placeholder causes need 25% share and 6 h after the peak; cyber words always; planned first |
| logic-9 | low | fixed f2d1298: WEATHER covers Hydro-Québec labels (precipitation, temperature, vegetation, natural disaster ...) |
| logic-10 | low | fixed f2d1298 + 1ceb1c5: one history line per id on write, dedupe on read, verify warns; merge by key in git-sync: request |
| logic-11 | low | fixed f2d1298: signal sources' level-less notices are level 0, customers null |
| ops-1 | high | fixed f2d1298 (same as logic-4; failed and paused cases tested) |
| ops-2 | medium | request (run-job.mjs re-exec on code change) |
| ops-3 | medium | fixed for readers 1ceb1c5 (series one point per key, slot lines merged, baseline counts a slot once); merge.mjs and collect.yml gate: request |
| ops-4 | medium | fixed 1ceb1c5: sparse series (slot line + non-quiet points), expandSeries for readers and roll-up, size comment corrected |
| ops-5 | medium | fixed f2d1298: full grid run log only on change or hourly (state in live.json `log`); the compact per-collect jsonl was not added |
| ops-6 | medium | fixed 73f4bbf: health last_grid_news_at, grid_waiting, grid_audit_flags; status rows per stage; guard warns; heal grid -> collect.yml |
| ops-7 | medium | fixed 73f4bbf: status page renders every source from health, failing first, flags in words |
| ops-8 | medium | request (grid-news async in the flow) |
| ops-9 | low | request (collect.yml timeouts) |
| ops-10 | low | fixed f2d1298: failures back off (15 min after 3, hourly after a day), state in live.json |
| ops-11 | low | partly fixed 1ceb1c5 (trends hold and coverage make gaps visible, not undercounted); loop restart timing: request |
| ops-12 | low | request (run-job phase notes from stdout) |
| ops-13 | low | fixed 169cb8d (series_large relative to SERIES_KEEP_DAYS, never-successful sources) and 73f4bbf (build reads audit.json); wiring into the flow, collect.yml, routines.json and about.json: request |
| ops-14 | low | fixed f2d1298: paused listed apart, not failed, not in the layer's error |
| news-1 | high | fixed 94b65f0: Thai, Greek, Arabic, Turkish, English planned words; headline dates after publication; future auxiliary |
| news-2 | high | fixed 94b65f0: dated article addresses older than the window are too_old; blog platforms refused |
| news-3 | high | fixed 94b65f0: osint bingTime (US Pacific -> UTC, DST aware, clamped) used by osint and grid-news; verified on the saved fixtures (WLUC 10:53 Bing vs 18:53 Google) |
| news-4 | medium | fixed 94b65f0: grouping by nearness (50 km cities, 300 km with a region), same article id under another language path; "SA" alias deferred (needs co-occurrence logic) |
| news-5 | medium | fixed 94b65f0: attacking country ranked last, possessive place first, 3+ regions -> country |
| news-6 | medium | fixed 94b65f0: statistics, repair delays, laments, trend pieces, galleries, explainers |
| news-7 | medium | fixed 94b65f0: dotless ı folded in fold() and rx() |
| news-8 | medium | fixed 94b65f0: collect.mjs link limit 4,000; publisherUrl refuses cut escapes, takes up to 1,000; app 73f4bbf |
| news-9 | medium | fixed 94b65f0: own name as alias (ambiguous list), 12 places added, no_place sample in news.json stats; utility-area fallback by query country not done |
| news-10 | low | fixed 94b65f0: no figure from a cut headline; properties/premises are customers |
| news-11 | low | fixed 94b65f0: syndicator copies not counted; multi-area utilities placed at the country |
| sources-1 | high | fixed 2ea04bb (same as logic-2; EIA items at their authority) |
| sources-2 | medium | fixed f2d1298 + 169cb8d: data_at from Hydro-Québec, SSEN, NGED, PacifiCorp, ENRE, ERCOT; stale sources kept, labelled, not used for incidents or series; audit flag stale_data. Eversource's directory stamp deferred: its time zone is not documented and a wrong guess would mark a live feed stale |
| sources-3 | medium | fixed 169cb8d: shape checks (NES, ODIN, LADWP, SSEN, NGED, BC Hydro, PacifiCorp total, ENRE total, Eversource, TAURON, Hydro-Québec); audit flags zero_customers, customers_missing, customers_fell |
| sources-4 | medium | fixed 169cb8d + f2d1298 + 73f4bbf: customers_band (Liander "under 300", Eversource masked "a few") shown as words |
| sources-5 | low | fixed 169cb8d: ECG (14 days) and Ecowatt (3 days) dormant from their own dates; audit and status page show it |
| sources-6 | low | fixed 169cb8d: arcgisPages for Liander and Elvia; a cut after 5 pages is bad_shape |
| sources-7 | low | fixed 169cb8d: ONS restore_est = start + mean duration; Range comment corrected |
| sources-8 | low | fixed f2d1298 (same as logic-8) |
| sources-9 | low | deferred: the finding itself asks to confirm on Elvia's map first whether those rows are stale |
| sources-10 | low | deferred: switching NES to /map/events needs the robots and terms check first (CyberView never works around a site's rules) |

Notes for whoever picks this up
- New config: config/grid.json `close_after_minutes` (30) and `reopen_minutes` (120); config/grid-news.json `ambiguous`
  and `multi_area_utilities`. Source definitions may set `data_stale_min` (default 90; null = never stale) and
  `dormant_hours`.
- New fields: incidents `stale`, `stale_since`, `below_since`, `reopened_at`; context items `stale`, `stale_since`,
  `customers_band`; live.json sources `stale`, `dormant`, `data_at`, `failures`, `next_try_at` and top-level `log`;
  series slot lines `{at, ok:[...]}`; analysis trends `coverage`, `week` may be null; news items may carry `checked`
  (from research.json grid-news-<id>, added by the build).
- Existing news.json items with Bing times from before the fix keep their wrong time until they age out (72 h);
  items whose titles today's rules reject are removed on the next grid-news run (recheck()).
- Requests for other lanes are in swarm/REQUESTS.md under "From grid-fixes".
