# catch-up handoff (2026-11-19)

## Runs
- backlog-20261119T0424: 41/41 done, closed. 12 new events, 2 updated, rest closed as already on file or not events.
- analyst-20261119T0427: 82/84 done, closed. Batch 1 calibration passed; waves of 6; one retry wave.
  The 2 left (batches 19, 21) were handed out twice: their analyses (CVE-2026-114938, CVE-2026-121653) were written by the retry. The validator count looks stale; `node scripts/analyst.mjs queue` showed 0 waiting.

## Triggers restored
All six in swarm/paused.json are enabled again (Research :05/:20/:35/:50, Backlog desk, Exploit analyst).

## Left over
- Could not confirm: ICO GTA 6 scam warning, Dark Reading "Sleeper Agent" (403s).
- Many new analyses rest on secondary sources because vendor portals (Ivanti, SonicWall, F5, Check Point, SAP) need JavaScript; open leads are in the run logs.

## review-20261119T0507 (planning session, 2026-11-19)
- 204 of 204 events reviewed by 17 headless Sonnet reviewers, leased (no jobs paused); $9.50. 132 passed, 56 corrected, 16 flagged.
- Requests above done: analyst done-check and KEV import gap fixed (87e97a5); off-list tags dropped from 19 events.
- Left to the scheduled jobs: 9 analyses that break length rules go out as FIX ONLY in the next analyst run.
