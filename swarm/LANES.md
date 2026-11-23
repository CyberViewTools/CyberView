# Lanes

One owner per path or queue. A lane edits only what it owns; anything else goes in swarm/REQUESTS.md for the owner.
Code lives on main (pull requests only), data on the data branch at ./data (docs/branches.md); no lane pushes code to main directly.
Grok Bot agents are read-only (they do not take the ops, guardian or build lanes, do not edit scripts/, and do not push data): they file `[Grok] ...` issues labelled `for-claude` and/or dated entries in swarm/REQUESTS.md for the build lane, and Claude Code implements them as pull requests to main (CLAUDE.md, "Grok Bot / Claude Code").
Queues are shared through leases (data/leases.json), not by pausing jobs: a run claims what it works, everyone else skips it until the lease ends.
One status view for everything: `node scripts/swarm.mjs board`.

| lane | session | owns | status | updated |
|------|---------|------|--------|---------|
| ops | CyberView ops 4 (dispatcher, session_013C7AZ5CZCr8dMQSMHM1eo5) | every scheduled job ("CyberView 4: ..."); each runs as one `scripts/run-job.mjs` call (plan, claim, work, check, retry, commit, report); the research loop while it holds the `flow:leader` lease | running | 2026-11-19 21:29 |
| standby | CyberView standby (session_013C7AZ7WzHrDL7e9QagpvvF) | the research loop only, when the `flow:leader` lease has expired ("CyberView standby: Research :12 / :42") | waiting | 2026-11-19 21:29 |
| guardian | a fresh session each run ("CyberView: Guardian", every 2 h) | nothing; reads and heals from the outside (`guard.mjs --heal`), nudges ops 4 and standby | running | 2026-11-19 21:29 |
| catch-up | planning session (owner's chat) | one-off swarms over a whole queue: `swarm.mjs freeze <kind>` then `swarm.mjs run <run>` (headless workers, leases), then `close` | idle (review swarm closed: 204 of 204) | 2026-11-19 05:16 |
| build | planning session (owner's chat) | scripts/, site/, scanner/, docs/, tests/, config/, routines.json, README.md, the scheduled tasks' definitions; changes reach main only as pull requests (CI must pass) | running (integrating lanes A+B below) | 2026-11-23 |
| build/review-window (lane A) | worktree agent, branch lane/review-window | scripts/review.mjs, tests/unit/review.test.mjs | done -> integrating | 2026-11-23 |
| build/feed-415 (lane B) | worktree agent, branch lane/feed-415 | scripts/lib/net.mjs, config/feeds.json, tests/unit/net.test.mjs | done -> integrating | 2026-11-23 |
| migration | planning session (owner's chat) | the code/data branch switch-over: the data branch, data-forward.yml, the stage B removal of data/ from main; runbook swarm/handoff/data-branch.md, explanation docs/branches.md | done (stage B merged; rulesets: owner) | 2026-11-20 |
