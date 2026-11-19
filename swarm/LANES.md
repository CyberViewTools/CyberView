# Lanes

One owner per path or queue. A lane edits only what it owns; anything else goes in swarm/REQUESTS.md for the owner.
Swarm runs live in swarm/<run>/ (not committed); every data change reaches main through scripts/finish.mjs (git-sync merges status.json and leads).

| lane | session | owns | status | updated |
|------|---------|------|--------|---------|
| catch-up | CyberView catch-up (swarm) | the research backlog and the exploit analyst queue while paused; restoring the triggers in swarm/paused.json | running | 2026-11-19 04:30 |
| ops | CyberView ops 3 (dispatcher) | every scheduled job not listed in swarm/paused.json | running | 2026-11-19 04:30 |
| build | planning session (owner's chat) | scripts/, site/, docs/, tests/, config/, routines.json, the triggers' definitions | idle | 2026-11-19 04:30 |
