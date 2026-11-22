# Lanes

One owner per lane. Update the status line when you pick up or hand off an item. See [`README.md`](README.md).

| Lane | Lead | Owns right now | Status | Updated |
|---|---|---|---|---|
| Discovery | Grok + Claude discovery agent | (continue-in-place items handed to implementation) | idle | 2026-11-22 |
| Design | Claude design agent | (scan-html designed with the implementation) | idle | 2026-11-22 |
| Implementation | Claude impl agent + Grok review | tk-matchers, scan-html, tk-diff, stacked on tk-hygiene | in review | 2026-11-22 |
| Orchestration | this session (Claude lead) | the backlog, assignments, merge gating | active | 2026-11-22 |

## Conventions
- A lane edits only its own handoff files and the row it owns here; cross-lane needs go to the orchestrator.
- One branch/worktree per implementation item; small commits; only the orchestrator merges to `main`.
- When a lane finishes an item, it writes/updates `handoff/<id>.md` and sets the item's stage in `BACKLOG.md`.
