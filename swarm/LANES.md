# Lanes

One owner per path or queue. A lane edits only what it owns; anything else goes in swarm/REQUESTS.md for the owner.
Queues are shared through leases (data/leases.json), not by pausing jobs: a run claims what it works, everyone else skips it until the lease ends.
One status view for everything: `node scripts/swarm.mjs board`.

| lane | session | owns | status | updated |
|------|---------|------|--------|---------|
| ops | CyberView ops 3 (dispatcher) | every scheduled job; each runs as one `scripts/run-job.mjs` call (plan, claim, work, check, retry, commit, report) | running | 2026-11-19 05:08 |
| catch-up | planning session (owner's chat) | one-off swarms over a whole queue: `swarm.mjs freeze <kind>` then `swarm.mjs run <run>` (headless workers, leases), then `close` | idle (review swarm closed: 204 of 204) | 2026-11-19 05:16 |
| build | planning session (owner's chat) | scripts/, site/, docs/, tests/, config/, routines.json, the scheduled tasks' definitions | idle | 2026-11-19 05:16 |
