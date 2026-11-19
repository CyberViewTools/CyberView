# Continuity runbook

How CyberView keeps running with nobody watching: every component, its heartbeat, its limit, and what restarts it.
The guard (`node scripts/guard.mjs`, run by the guardian every 2 hours from its own fresh session) checks all of it from the
outside: the live site, the public GitHub API and the public `data/leases.json`.

| Component | Heartbeat | Limit | Restarted by |
|---|---|---|---|
| Research loop (research, second review, updaters, follow-up desk) | `flow:leader` lease in `data/leases.json`, renewed every cycle, published at least every 8 minutes | lease expires 20 minutes after the last renewal | the four research schedules in the ops session (`:05 :20 :35 :50`) restart it when it is not running; the **standby session** takes the lease when it expires (its schedules `:12 :42`) |
| Deploy | `manifest.json` `built_at`; main's newest commit live | 90 minutes; 20 minutes lag | every push; the guard starts `pages.yml` |
| CVE corpus | `last_cve_at` | 3 hours | every finished deploy (gated to hourly), its schedule, any push to the CVE code; the guard starts `cve.yml` |
| Feeds (KEV, EPSS, context layers) | `last_feeds_at` | 6 hours | every finished deploy (gated to 110 minutes), its schedule; the guard starts `feeds.yml` |
| Lead collection | `last_collect_at` | 2 hours | every research cycle collects; `collect.yml` as backup; the guard starts it |
| Brief, analysis, exploit analyst, triage, advisory, verify, report review, steward, editor | `last_<job>_at` | brief 7 h, analysis 15 h, analyst 5 h | their schedules in the ops session; the guard warns |
| The guard itself | the guardian's scheduled runs (push notification to the owner on ALERT) | 2 hours | its own schedule, in a fresh session each time |

## Why it does not stop
- **Two sessions, one leader.** The ops session and the standby session both try to run the research loop. Only the one
  holding the live `flow:leader` lease runs it; the other ends in seconds. If the ops session's container is reclaimed or it
  hits a usage limit, its lease expires and the standby takes over within about 30 minutes. A race is settled by git: after
  publishing its claim each loop pulls again and backs off if another run's claim is the one on main.
- **Leases, not locks.** Stories, events and CVEs being worked are leased for 45 minutes; a crashed worker's items free
  themselves. Nothing waits on a dead process.
- **Checkpoints.** Each cycle commits its own work (events, reviews, updates, run logs) before the next starts, so a crash loses
  at most one cycle; the next cycle starts from what is on main.
- **No silent stalls.** GitHub's own scheduler runs this repository's schedules late or not at all, so the data workflows also
  start after every deploy and let themselves through only when due.
- **One writer per file.** Shared state (`data/status.json`) is read through `readStatus()`, which falls back to the last
  committed copy, so no job can wipe another's keys; `git-sync` merges JSON by key and line files by union.

## If something is stuck
1. `node scripts/guard.mjs` (add `NODE_USE_ENV_PROXY=1` behind a proxy) says what is late and why.
2. `node scripts/swarm.mjs board` shows queues, live leases, the loop and the speed.
3. Loop not running and no lease: send "Run the sweep job now" to the ops or standby session, or wait for their next schedule.
4. A workflow late: start it from GitHub Actions (Run workflow) or let the guard's `--heal` do it.
