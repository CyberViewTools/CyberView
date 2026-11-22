# CyberView build orchestration

How we run the build work: a **Discovery → Design → Implementation** pipeline with a lead per lane and one
orchestrator. The point is that no item stalls on one thread and no state lives only in a session's memory — every
item and hand-off is written down here, so any agent (and Grok) can pick it up.

State lives in three files, kept current:
- [`LANES.md`](LANES.md) — the lanes, their leads and what each owns right now.
- [`BACKLOG.md`](BACKLOG.md) — every item, its stage, its lead, and the next action.
- `handoff/<item-id>.md` — what one lane hands the next (see [`handoff/TEMPLATE.md`](handoff/TEMPLATE.md)).

## The lanes

| Lane | Lead | Produces | Done when |
|---|---|---|---|
| **Discovery** | Grok + a Claude discovery agent | a one-page brief: the need, constraints, prior art/standards, feasibility, the data/APIs that exist | the brief is in `handoff/<id>.md` and the orchestrator accepts it |
| **Design** | Claude (design agent) | a spec: interfaces, data model, test plan, a check against the safety model, and a sequenced PR breakdown | the design is reviewed and the PR plan is agreed |
| **Implementation** | Claude (impl agent) + Grok as reviewer | merged PRs with tests, CI green | the PRs are merged to `main` |
| **Orchestration** | this session (Claude, the lead) | assignments, integration across lanes, merge gating | — |

## How work flows

1. The **orchestrator** adds an item to `BACKLOG.md` at stage **Discovery** with a short goal.
2. **Discovery** produces the brief (a Claude discovery agent, or a `[Grok]` brief from Grok). The orchestrator
   accepts it, writes `handoff/<id>.md`, and moves the item to **Design**.
3. **Design** writes the spec + PR plan into the handoff, checks it against the safety model, moves the item to
   **Implementation**.
4. **Implementation** builds each PR in its own worktree, with tests, keeps CI green, and opens PRs to `main`.
   Grok reviews. The **orchestrator** is the only one who merges.
5. The orchestrator updates `LANES.md`/`BACKLOG.md` at every stage change.

## How agents are spawned (orchestrated-agents model)

The orchestrator (this session) spawns a **task-scoped agent per item**, not standing sessions:
- **Discovery** → a read-only research agent (repo + public sources) returning the brief; or a `[Grok]` brief.
- **Design** → an agent that reads the brief and the relevant code and returns the spec + PR plan.
- **Implementation** → an agent (or the orchestrator) that builds in a worktree and opens the PR.

Agents are given the item id, the handoff file, and the rails below — nothing else. Several items can be in
different lanes at once; the orchestrator integrates.

## Rails (every lane keeps these)

- `main` changes only through PRs; CI must pass; **only the orchestrator merges**. A code branch never carries data.
- The scanner/toolkit stays **detection-only, keyless, authorization-gated** — keep every `scanner/README.md`
  "deliberately does not do" rule and `scripts/security-check.mjs` green.
- Everything CyberView writes is labelled as written by an AI model (`AI_BY`); data rules in the root `CLAUDE.md` hold.
- Grok's briefs and comments are **proposals**, surfaced by `scripts/grok-watch.mjs`; a person still gates every merge.
