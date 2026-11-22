# Handoff: scan-html — self-contained HTML report

## Discovery → Design
- **Need / user story:** an operator wants one file they can open, with the backport caveat impossible to miss.
- **Constraints:** detection-only. No external resources, no executable markup, every value escaped. No new probe.
- **Prior art / standards:** a single HTML document with an embedded style sheet.
- **Data / APIs that exist:** the report object `buildReport` already returns.
- **Feasibility / risks:** low. Out of scope: interactive filtering, copied hunt-rule bodies.
- **Recommendation:** build.

## Design → Implementation
- **Interfaces / CLI:** `scan` and `match` write `report.html` next to `report.json`.
- **Data model:** `toHtml(report)` in `scanner/lib/html.mjs`. Links only when the URL is https.
- **Safety-model check:** no network, no executable markup, section 7 unchanged.
- **Test plan:** the page contains the backport caveat; a title with markup is escaped; a non-https details URL is not linked; a distribution package is named when one was seen.
- **PR plan:** one PR with `tk-matchers` and `tk-diff` (continue-in-place), stacked on the tk-hygiene HTTP branch.

## Implementation → Review
- **PRs:** this branch. `report.html` is written by `writeReportFiles`.
- **Open questions / follow-ups:** none for this slice.
