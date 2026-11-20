# Lanes

One owner per path or queue. A lane edits only what it owns; anything else goes in swarm/REQUESTS.md for the owner.
Code lives on main (pull requests only), data on the data branch at ./data (docs/branches.md); no lane pushes code to main directly.
Queues are shared through leases (data/leases.json), not by pausing jobs: a run claims what it works, everyone else skips it until the lease ends.
One status view for everything: `node scripts/swarm.mjs board`.

| lane | session | owns | status | updated |
|------|---------|------|--------|---------|
| ops | CyberView ops 4 (dispatcher, session_013C7AZ5CZCr8dMQSMHM1eo5) | every scheduled job ("CyberView 4: ..."); each runs as one `scripts/run-job.mjs` call (plan, claim, work, check, retry, commit, report); the research loop while it holds the `flow:leader` lease | running | 2026-11-19 21:29 |
| standby | CyberView standby (session_013C7AZ7WzHrDL7e9QagpvvF) | the research loop only, when the `flow:leader` lease has expired ("CyberView standby: Research :12 / :42") | waiting | 2026-11-19 21:29 |
| guardian | a fresh session each run ("CyberView: Guardian", every 2 h) | nothing; reads and heals from the outside (`guard.mjs --heal`), nudges ops 4 and standby | running | 2026-11-19 21:29 |
| catch-up | planning session (owner's chat) | one-off swarms over a whole queue: `swarm.mjs freeze <kind>` then `swarm.mjs run <run>` (headless workers, leases), then `close` | idle (review swarm closed: 204 of 204) | 2026-11-19 05:16 |
| build | planning session (owner's chat) | scripts/, site/, docs/, tests/, config/, routines.json, the scheduled tasks' definitions; changes reach main only as pull requests (CI must pass) | idle | 2026-11-20 |
| migration | planning session (owner's chat) | the code/data branch switch-over: the data branch, data-forward.yml, the stage B removal of data/ from main; runbook swarm/handoff/data-branch.md, explanation docs/branches.md | done (stage B merged; rulesets: owner) | 2026-11-20 |
