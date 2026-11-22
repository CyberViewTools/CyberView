# Handoff: tk-diff — scan diff / watch

## Discovery → Design
- **Need / user story:** compare this scan with the last one: what is new, what is gone, what is still open.
- **Constraints:** detection-only. No re-scan inside the command, no mail, no process spawn. Scheduling stays with the operator.
- **Prior art / standards:** a join of findings on CVE, host and port.
- **Data / APIs that exist:** two `report.json` files the operator already has.
- **Feasibility / risks:** "resolved" can mean the host was down. The report says so. Out of scope: sending alerts, a daemon, a cron entry in this repo.
- **Recommendation:** build the comparison and a watch list file. Do not build a sender.

## Design → Implementation
- **Interfaces / CLI:** `diff --before report.json --after report.json [--out DIR]`.
- **Data model:** `{ new, resolved, still, changed, watch, counts, note }`. Watch is new known-exploited or Act rows.
- **Safety-model check:** reads local files only, 8 MB cap, no probe.
- **Test plan:** new, resolved and still; the watch row; the command writes files and does not call the probe.
- **PR plan:** same continue-in-place PR as `tk-matchers` and `scan-html`.

## Implementation → Review
- **PRs:** this branch. `scanner/lib/diff.mjs`.
- **Open questions / follow-ups:** a person can point their own alerting at `diff.json` `watch`. This repo does not send it.
