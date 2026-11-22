# Handoff: scan-incidents-cite + scan-hunt-links — reviewed incident citations and hunt links on findings

Catalog IDs: `incident-citations-on-a-finding` (scan-incidents-cite), `hunt-pointers-links-only` (scan-hunt-links). Both built in one slice (run scanner-build-2026-11-22, plan_id w1-6f3a), module `scanner/lib/cite.mjs`.

## Discovery → Design
- **Need:** a finding already says KEV / EPSS / ransomware; defenders also want "where has CyberView seen this exploited" (reviewed incidents) and "what do publishers give me to hunt for it" (links), without the report becoming an IoC or rule dump.
- **Constraints:** detection only, no new probe or packet; reads only CyberView's own published files; reviewed events only; claims never cited; attribution only from a government or the investigating firm; links only, no rule/IoC bodies; air-gapped snapshot stays small unless asked.
- **Data that exists (published by `scripts/build.mjs`):** `site/data/archive/search.json` (one compact row per event, with `status` and `cves`) and `site/data/archive/<YYYY-MM>.json` (full events with `review`, `attribution`, `sources`) — the archive page reads the same pair. `workbench.json` `event_of` is first-wins (one id per CVE) and has no review state, so it is NOT used as the index. `workbench.json` `hunt` (and `guides[CVE].hunt`) already holds publisher detection-file links.
- **Recommendation:** build (done below).

## Design → Implementation
- **CLI:** `--data-incidents` (boolean) on `scan` and on `data`.
  - `scan --data-incidents`: after matching, reads `data/archive/search.json`, builds a CVE → every-event index for the matched CVEs, then reads only the month files those events sit in (newest first, at most 36), and attaches `finding.incidents`. Without the flag nothing is read and the report is unchanged.
  - `data --out DIR --data-incidents`: adds a thin archive to the snapshot under the same paths (only events naming a workbench CVE; fields id, title, date, status, cves, review.state, source URLs, government/investigator attribution) and `incidents`, `incident_events`, `incident_months` to `manifest.json`. Without the flag the snapshot is byte-for-byte what it was.
- **Allowlist (`scanner/lib/data.mjs` `ALLOWED`):** added `data/archive/search.json` and `data/archive/\d{4}-\d{2}.json` only (both already published read-only GET paths). `events.jsonl`, `index.json`, `undated.json`, `data/events/...` stay refused.
- **Rule (`citeRule`):** cited only when `status` ∈ {confirmed, official} AND `review.state` ∈ {passed, corrected}. `status: claimed` → never cited, counted as `claimed_not_cited` and printed as "attacker CLAIM(S) ... not cited (unconfirmed ...)" with no title or victim. Everything else (developing, unreviewed, flagged) → `unreviewed_not_cited` count.
- **Data model:** `finding.incidents = { cited: [{ event_id, title, date, status, review, sources (count), link (https://xanderhutch.github.io/CyberView/archive.html#q=<id>), attribution? { by, by_type: government|investigator, url } }], claimed_not_cited, unreviewed_not_cited, rule, by }` (max 10 cited). No actor name, no summary, no IoCs. `finding.hunt = [{ name, format, publisher, url }]` (max 12, https only, the site's format list, CSAF/CVRF/VEX dropped, deduplicated): from the CVE's guide, the workbench hunt list for the CVE, and hunt entries of events the finding cites (never a claim's). Hunt is attached always (data already loaded; links only). `run.data.incidents = { requested, available, months_read, months_skipped }` when the flag is used. CSV, SARIF, inventory unchanged.
- **Shared-file hooks:** `data.mjs` (allowlist + comment), `scan.mjs` (import, 4 lines after `matchFindings`, a note, `run.data.incidents`), `report.mjs` (import + `L.push(...citeLines(f))` in the finding block), `cyberview-scan.mjs` (flag, usage, data step, header data line, `incidents` into `buildReport`).
- **Safety check:** no new connection, request to a target, datagram or probe call; `cite.mjs` imports only `node:fs`, `node:path`, `./data.mjs`. security-check section 7 green. `CAPS` untouched.
- **Tests (`tests/unit/scanner-cite.test.mjs`, fixtures `tests/fixtures/scanner/cite/`):** multi-event index vs first-wins; claims rule; offline scan with the flag: 2 reviewed citations + links print, claim labelled and not cited, government attribution kept and press attribution dropped, hunt URLs print, IoC/rule bodies and actor names absent, probe calls identical with and without the flag (and UDP never called); without the flag: no archive read, no `incidents` key, base snapshot report has no new keys; `data` without flag unchanged, with flag thin and no bodies; online: GET + allowlist only, archive paths only with the flag; static import check of `cite.mjs`.

## Doc text to add (orchestrator)

**docs/scanner.md** (data section, after the list of files the scanner reads):

> With `--data-incidents` (on `scan` and on `data`), the scanner also reads CyberView's event archive (`data/archive/search.json` and the `data/archive/<YYYY-MM>.json` months that hold events naming a matched CVE) and cites, per finding, the CyberView events that name its CVE. Only events that are confirmed or official and passed (or were corrected by) CyberView's second review are cited: title, date, a link to the event on CyberView, the number of sources it cites, and, only when a government or the investigating firm made it, who attributed it and where. Attackers' claims are never cited; they are counted and labelled as unconfirmed. Nothing else from the event (no indicators, no hunt rules, no summary, no actor name) is copied. Without the flag no archive file is read and offline snapshots stay small. Every finding also lists the publishers' detection files for its CVE (Sigma, YARA, STIX and so on) as links only, from the workbench data the scanner already loads; their contents are never downloaded or copied.

**scanner/README.md** (options list):

> `--data-incidents` — cite reviewed CyberView incidents that name each finding's CVE (title, date, link; claims never cited). On `data`, adds a small, trimmed event archive to the snapshot for offline use. Off by default.
> Findings also carry "Hunt" links: publishers' detection files for the CVE, links only.

## Implementation → Review
- **Follow-ups / not built:** patch-queue boost from incidents, actor names, campaign stories, tabletop (out of scope by the roadmap). Incidents are not added to CSV or SARIF (columns unchanged on purpose; a later item can add a count column). `event_of` in workbench.json stays first-wins for the site; the scanner does not use it.
