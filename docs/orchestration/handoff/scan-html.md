# Handoff: scan-html — Self-contained HTML report + backport caveat

Run scanner-build-2026-11-22, plan_id w1-6f3a. Roadmap section 4 (Continue, Design), issue #82 items 1-3. Catalog rows built here:
`explain-mode-evidence`, `http-body-truncation-recorded`, `scan-profile-used`, `scope-typo-or-attestation-coaching`, `stale-snapshot-warning`.

## Discovery → Design
- **Need:** operators and their managers read a page, not report.json. The page must keep the scanner's honesty: blind spots, low-confidence rows out of the headline, and the distribution backport caveat impossible to miss (issue #82 item 3: the demo's Ubuntu OpenSSH row read as "vulnerable").
- **Constraints:** detection only; no new bytes to any target; the report is written to the operator's disk only. The page holds attacker-controlled text (banners, Server headers, titles, certificate names, host names), so it is an XSS surface when opened in a browser.
- **Prior art:** summary.txt (same sections), SARIF (same ranking). No HTML existed on `main`.
- **Data:** everything is already in the report object; nothing new is fetched.
- **Risks:** script injection from banners (handled: every value escaped + CSP with `default-src 'none'`, no script at all); external loads (none: inline CSS only); leaking bodies/cookies (the page never reads `hosts[].http` beyond `port` and `body_truncated`).
- **Recommendation:** build (done).

## Design → Implementation
- **Interfaces / CLI:** `scan ... --html` also writes `report.html` (mode 0600, beside report.json, findings.csv, report.sarif, inventory.csv, summary.txt). **Opt-in for now** because `tests/unit/scanner.test.mjs` (not editable by this slice) asserts the exact five-file output list. To make it default: drop the `a.html &&` guard in `scanner/cyberview-scan.mjs` and add `"report.html"` to the list at `tests/unit/scanner.test.mjs` "offline mode" test (one line each).
- **Module:** `scanner/lib/html-report.mjs`, all pure:
  - `toHtml(report)` → one HTML string. `esc()`, `safeHref()` (https only, no credentials, no quotes/space), `link()`.
  - `backportOf(finding)` → the places capped at medium because of a distro package build.
  - `explain(finding, place)` (explain-mode-evidence): the banner/header/cert evidence, stated version, compared version, range result and confidence reason, in words.
  - `truncatedBodies(report)` (http-body-truncation-recorded): web ports whose root page hit `TIMEOUTS.maxBytes`.
  - `scanProfile({...flags})` (scan-profile-used): profile name (default ports / custom ports / all TCP ports, + UDP on, + discovery on, + assume up) and what it does not cover.
  - `scopeCoaching(text, scope, {today})` (scope-typo-or-attestation-coaching): advice for a scope file that PASSED `checkScope`: unknown keys (with "did you mean targets / exclude / expires / authorization_ref"), duplicate targets, an entry both targeted and excluded, an excluded address/range outside every listed range (skipped when a host-name target exists), attestation expiring within 14 days, empty `authorization_ref`, empty `contact`. Never a refusal.
  - `staleData(report)` (stale-snapshot-warning): offline snapshot `fetched_at` or the workbench `built_at` older than `STALE_DAYS` (7) at scan start; unknown snapshot age is flagged.
- **Hooks in shared files (smallest possible):**
  - `scanner/cyberview-scan.mjs`: import; `--html` boolean; `loadScope` also returns the text; prints "SCOPE FILE ADVICE" after the header on `check` and `scan` (before any probe); after `buildReport` sets `report.run.profile` and `report.scope.coaching` and prints each stale-data warning to stderr; writes report.html when `--html`.
  - `scanner/lib/probe.mjs`: the root-page result carries `truncated: n >= maxBytes` (a field only; no new byte sent).
  - `scanner/lib/scan.mjs`: `hosts[].http[]` gets `body_truncated: true` when the probe says so.
- **Data model additions in report.json:** `run.profile`, `scope.coaching[]`, `hosts[].http[].body_truncated`.
- **Page sections:** Run; Authorization (scope file, full sha256, owner, attested by, recorded statement); Scope and limits (targets, ports, UDP, limits, connections) + Scan profile + What was sent (User-Agent, `SENDS`, data line) + Scope file advice; Old-data warning; Summary counts (same as summary.txt; low-confidence out of the headline); Coverage blind spots (from `coverage()`) + truncated root pages; Findings ranked (same order as findings.csv) each with KEV/added/due/OVERDUE, rating + points text, SSVC priority + BOD fix-by, queue points, confidence + reason, seen on, Why it matched, fixed in, vendor workaround, CISA action, advisory/reference/details links; a top-of-list backport banner and a per-finding "Possibly already fixed: distribution package build (Ubuntu)" box; Low-confidence findings grouped per product in collapsed `<details>` (issue #82 item 2); Observations most severe first; Also named; Notes.
- **Safety-model check:** no new connection, request, handshake or datagram; `probe.mjs` change is a returned field. No script, no `src=`, no `<link>`, no `@import`/`url()`; CSP meta `default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'`; `<meta name="referrer" content="no-referrer">`; anchors are `href="https://..." rel="noopener noreferrer"` only. `security-check` section 7 green.
- **Test plan (tests/unit/scanner-html.test.mjs, 14 tests):** escaping of `<script>`/quotes/`<img onerror>` from banner, title, host names, owner, attestation name, notes, observations; every tag in the page has only our quoted attributes; no `src=`/`<link>`/external loads; only https anchors with rel; credentialed/http/javascript URLs not linked; header carries statement, full scope hash, User-Agent, SENDS, limits; backport caveat present for a medium distro finding and absent otherwise; coverage blind spots listed and "complete" wording; ranking, KEV/OVERDUE, SSVC, confidence; low-confidence grouping; each catalog row; loopback end to end (report.html written beside the others, mode 0600, equals `toHtml(report.json)`, hostile Server header escaped, services received only the SSH ident and one `GET /`; without `--html` the five-file list is unchanged); probe truncation flag on loopback with exactly one `GET /` per port.

## Implementation → Review
- **Branch:** this worktree's branch, one commit `[scan-html] ...`. Not pushed (orchestrator merges).
- **Follow-ons / open questions:**
  - Make `report.html` default (see above) once the orchestrator edits the scanner.test.mjs file list.
  - summary.txt could also print the stale-data warning, the profile and the backport count (report.mjs is shared; left to consolidation).
  - SARIF could carry `run.profile` (scan-sarif-coverage).
  - The `/NVD` path token in the stale-snapshot catalog row was not used (no path is requested; the age is computed from the snapshot manifest).

## Doc text to add

### docs/scanner.md (Outputs section)
> `--html` also writes `report.html`: one self-contained page (inline CSS, no script, nothing loaded from the network, a Content-Security-Policy that forbids everything else). It shows the run header (what was sent, limits, the recorded attestation wording and the scope file's sha256), the scan profile and what it does not cover, the summary counts (low-confidence findings listed separately and left out of the headline), coverage blind spots (including root pages cut at the 16 KB size cap), and the ranked findings with the CyberView rating, SSVC priority, KEV deadline, confidence and its reason, "why it matched" (the banner or header that supported it), fix information and advisory links. A finding whose version came from a Linux distribution's package build carries a "Possibly already fixed" box: the distribution may have backported the fix without changing the version number. Every value from a target is HTML-escaped; links are https only. The scan also prints advice for likely typos in a scope file that passes its checks, and warns when the KEV/NVD data is more than 7 days old.

### scanner/README.md (Output files list)
> - `report.html` (with `--html`) — the same report as one page to open in a browser or send on; it loads nothing and runs no script. Findings that may already be fixed by a distribution backport are marked "Possibly already fixed".
