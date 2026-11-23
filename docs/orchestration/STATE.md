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

No scanner or pipeline PRs currently open (confirm with `gh pr list` when you run).

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
