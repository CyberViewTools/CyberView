# Lanes

One owner per lane. Update the status line when you pick up or hand off an item. See [`README.md`](README.md).

| Lane | Lead | Owns right now | Status | Updated |
|---|---|---|---|---|
| Discovery | Grok + Claude discovery agent | toolkit offline matchers (SBOM / nmap-XML / CVE-lookup); scan-diff/watch; TLS & exposure hygiene | idle — ready to scope the offline matchers first | 2026-11-22 |
| Design | Claude design agent | scanner HTML report + backport-caveat surfacing | idle | 2026-11-22 |
| Implementation | Claude impl agent + Grok review | scanner #82 item 5 (quieter counts + fingerprint fixes) | ready to start | 2026-11-22 |
| Orchestration | this session (Claude lead) | the backlog, assignments, merge gating | active | 2026-11-22 |

## Conventions
- A lane edits only its own handoff files and the row it owns here; cross-lane needs go to the orchestrator.
- One branch/worktree per implementation item; small commits; only the orchestrator merges to `main`.
- When a lane finishes an item, it writes/updates `handoff/<id>.md` and sets the item's stage in `BACKLOG.md`.
