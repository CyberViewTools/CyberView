# Continuity runbook

How CyberView keeps running with nobody watching: every component, its heartbeat, its limit, and what restarts it.
The guard (`node scripts/guard.mjs`, run by the guardian every 2 hours from its own fresh session) checks all of it from the
outside: the live site, the public GitHub API and the public `data/leases.json`.

| Component | Heartbeat | Limit | Restarted by |
|---|---|---|---|
| Research loop (research, second review, updaters, follow-up desk) | `flow:leader` lease in `data/leases.json`, published once at the start of each span; a span-bounded loop (under 20 min left, which is how it runs today at ~7 foreground minutes) renews LOCALLY and makes no heartbeat or hand-over commit (#136) | the published lease expires at the span's end, so at most ~7 minutes, not 20 | the four research schedules in the ops session (`:05 :20 :35 :50`) restart it when it is not running; the **standby session** takes the lease when it expires (its schedules `:12 :42`) |
| Deploy | `manifest.json` `built_at`; the newest code and data live | 90 minutes; 20 minutes lag | every data push dispatches `pages.yml` (scripts/lib/repo.mjs `dispatchDeploy`), every merge to main; the guard starts `pages.yml` |
| Data branch switch (stage A) | every checkout has `./data` on the data branch; `data-forward.yml` has nothing to forward | 24 hours quiet before stage B | `node scripts/data-branch.mjs ensure` at every job start (dispatch.mjs); runbook: `swarm/handoff/data-branch.md` |
| CVE corpus | `last_cve_at` | 3 hours | every finished deploy (gated to hourly), its schedule, any push to the CVE code; the guard starts `cve.yml` |
| Feeds (KEV, EPSS, context layers) | `last_feeds_at` | 6 hours | every finished deploy (gated to 110 minutes), its schedule; the guard starts `feeds.yml` |
| Power grid outages | `last_grid_at` | 2 hours (warn) | every research cycle runs `grid.mjs collect` and the grid researchers; collect.yml every 30 min as backup (stands down while the loop collects) |
| Lead collection | `last_collect_at` | 2 hours | every research cycle collects; `collect.yml` as backup; the guard starts it |
| Brief, analysis, exploit analyst, triage, advisory, verify, report review, steward, editor | `last_<job>_at` | brief 7 h, analysis 15 h, analyst 5 h | their schedules in the ops session; the guard warns |
| Health watch (owner-created, not in routines.json: it has no heartbeat to judge) | its own scheduled runs, push to the owner only when degraded | every 2 h (`trig_01CCrJLGHhRaqCawfxoduFq5`, Toronto :33, fresh session) | its own schedule. Reads open `pipeline-alert` issues and the live bundle's age; it does NOT run `guard.mjs --heal`, so it reports and does not repair |
| Grok review (owner-created, not in routines.json) | its own scheduled runs, push only when a Grok thread waits on Claude | hourly (`trig_01ExzauUi9CgJHPJz8LwR8Y4`, :17, fresh session) | its own schedule; runs `scripts/grok-watch.mjs` read-only |
| The guard itself | the guardian's scheduled runs (push notification to the owner on ALERT) | 2 hours | its own schedule, in a fresh session each time. **Confirmed present 2026-11-23** by a complete listing of all 126 scheduled tasks: "CyberView: Guardian" (`trig_01AQNQvXJeLj2JLtnCuDDHUX`), enabled, `47 */2 * * *` UTC, fresh session, push on, last run SUCCEEDED 2026-11-23 20:47Z. An earlier partial listing wrongly reported it missing. Note `guardian` has `status_key: null`, so nothing inside the repo can detect it if it ever does stop: the push notification on ALERT is the only signal |

## Why it does not stop
- **Two sessions, one leader.** The ops session and the standby session both try to run the research loop. Only the one
  holding the live `flow:leader` lease runs it; the other ends in seconds. If the ops session's container is reclaimed or it
  hits a usage limit, its lease expires and the standby takes over within about 30 minutes. A race is settled by git: after
  publishing its claim each loop pulls again and backs off if another run's claim is the one on the data branch.
- **Leases, not locks.** Stories, events and CVEs being worked are leased for 45 minutes; a crashed worker's items free
  themselves. Nothing waits on a dead process.
- **Checkpoints.** Each cycle commits its own work (events, reviews, updates, run logs) before the next starts, so a crash loses
  at most one cycle; the next cycle starts from what is on the data branch.
- **No silent stalls.** GitHub's own scheduler runs this repository's schedules late or not at all, so the data workflows also
  start after every deploy and let themselves through only when due.
- **One writer per file.** Shared state (`data/status.json`) is read through `readStatus()`, which falls back to the last
  committed copy, so no job can wipe another's keys; `git-sync` merges JSON by key and line files by union.

## If something is stuck
1. `node scripts/guard.mjs` (add `NODE_USE_ENV_PROXY=1` behind a proxy) says what is late and why.
2. `node scripts/swarm.mjs board` shows queues, live leases, the loop and the speed.
3. Loop not running and no lease: send "Run the sweep job now" to the ops or standby session, or wait for their next schedule.
4. A workflow late: start it from GitHub Actions (Run workflow) or let the guard's `--heal` do it.
5. A checkout in a bad state (data commits failing, `./data` missing or not on the data branch): `node scripts/data-branch.mjs status`, then the recovery steps in `docs/branches.md`.

## Sessions and rotation
| Session | Id | Runs |
|---|---|---|
| CyberView ops 4 | session_013C7AZ5CZCr8dMQSMHM1eo5 | every "CyberView 4: ..." schedule (research :05 :20 :35 :50, review desk :25, backlog desk :57, triage, analyst, brief, analysis, advisory, verify, report review, deep sweep, watchdog, security review, regional, follow-up, steward, tabletop, scout, editor, improver) |
| CyberView standby | session_013C7AZ7WzHrDL7e9QagpvvF | "CyberView standby: Research :12" and ":42"; ends in seconds while ops holds the leader lease |
| Guardian | a fresh session each time | "CyberView: Guardian" every 2 hours; pushes an ALERT to the owner and messages both sessions when the loop has no leader |

Retired: ops 3 (session_013C7AZ5wTsxwP5Xg9AFNesw), its "CyberView 3: ..." schedules are disabled, not deleted, so they can be switched back on.

**Rotate the ops session** when its context passes about 400,000 tokens or its jobs slow down (the status page's job durations
climb): create a fresh session, create the same schedules as "CyberView N+1: ..." pointing at it with the same dispatcher
prompt, switch the old ones off (never delete), update the guardian's prompt and the table above. Nothing is lost in a
rotation: all state is in the repository (code on main, data and `leases.json` on the data branch), and the leader lease hands the research loop over by itself.
