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

Open (this session):
- #136 — three fixes found by reviewing the status page Routines section (branch claudex/zen-hypatia-y3utma, draft, CI green locally):
  - `scripts/review.mjs`: the queue windowed on `first_seen` while `needsReview` fires on `updated_at`, so 66 of 67 events changed after their review could never be re-queued (queue said 1, pipecheck 60). Now an exported pure `inReviewWindow()` on `waitingSince`. Live effect: queue 1 -> 67. Draining it is a one-off ~67 reviewer runs, so expect a short spike and a truer accuracy number afterwards.
  - `config/pipeline.json`: `sweep.gap_pass` false. The pass sat at the gap_max_every_minutes ceiling and then ran 143 times in a row adding nothing: 278 runs, 118.4 M tokens, $76.56 of the week's $858.58. Every other gap_* dial untouched, so flipping it back restores prior behaviour exactly.
  - `scripts/collect.mjs` + `scripts/lib/net.mjs`: on a 415 only, ask once more without our `accept` list, same identifying UA. Fixes the four 415 collectors (Daily News/HabariLeo Tanzania, Lefaso.net, Ciberseguridad LATAM). Not a block workaround: 401/403 stop is untouched and a persistent 415 still fails as 415.
  - Done with two worktree subagents (lanes A and B, Sonnet, ~200 K tokens total) plus inline work; one CI run, one PR. Note for next time: the feed collector uses `fetchFeed` in `scripts/collect.mjs`, NOT `net.mjs` `get()`.

Prior open item (merged):
- Public + internal description refresh. Surfaces the recent operational work (#127 accuracy eval set, #129 API fallback, #132 cost tiering) in the public prose and corrects drift:
  - `config/about.json` "ops": added measured-accuracy test set, model tiering (least-costly-capable, Opus only where needed) and non-stalling publishing (subscription-primary, API fallback within a monthly cap). Numbers still live-filled; `about.mjs check` green.
  - `legal/about.html` "How it is made": feed count 220→280 (live total is 280 = 228 collect + 52 feeds.json), X noted as a lead-only source (never evidence), new "Accuracy, cost and reliability" bullet linking the status page.
  - `site/status.html`: one-line note on the Accuracy section about the eval test set (fallback/tiering/accuracy are already surfaced live via health.json + the Accuracy/Improver sections, and `nav.js` injects the Actors/Scanner links, so no nav edit needed).
  - `site/app.js`: BUILD 1.69→1.70 (2026-11-23), since a tracked site/ file changed.

No scanner PRs currently open; #136 is the open pipeline PR (confirm with the GitHub tools when you run — there is no `gh pr list` here, only `gh api search/*`).

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
