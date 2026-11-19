# Grid outage pipeline: build contract

Goal: track electrical grid outages continuously, as **context** for defenders, and find the rare ones that an official
source links to a cyberattack. Scripts collect, track and verify; agents only judge the cause of big incidents.
Rules that do not change: CLAUDE.md rule 9 (context layers: neutral ink, dashed, "context, not a cyber event", parser with
unit tests, `CTX_DEFS` entry, `cleanCtx` branch with a link host allowlist) and the data rule "Outages are category `outage`
and are never called attacks unless an official source says so". Every AI-written text is labelled
"CyberView AI (a Claude model)". Do not work around sites that block automated readers.

## Pipeline (one cycle, inside the research loop `run-job.mjs flow`, and every 30 min from collect.yml as backup)
```
grid.mjs collect   (script)  sources -> data/grid/live.json -> incidents (open/update/close) -> data/grid/incidents.json
                              -> closed ones appended to data/grid/history/<YYYY-MM>.jsonl -> data/context/grid.json
                              -> rule pass: research_needed true/false with a reason code (run log)
grid-desk.mjs plan (script)  incidents with research_needed, no lease, no final result, retry due -> plan file + leases
grid workers       (agents)  role "grid": find the operator's/official cause statement; one decision per incident
grid-desk.mjs apply(script)  validate (plan_id, ids, decision set, https sources, no front pages) -> data/grid/research.json
                              cyber_official / cyber_reported -> a lead in data/leads/<day>.jsonl for the normal research
                              loop (events are only ever written there, with its second review)
grid.mjs verify    (script)  shapes of every grid file; exit 1 names the file
```

## Sources (all public, no key; checked from this container on 2026-11-19)
| key | operator | URL | gives |
|---|---|---|---|
| hydroquebec | Hydro-Québec (CA, Quebec) | https://pannes.hydroquebec.com/pannes/donnees/v3_0/bisversion.json then .../bismarkers<version>.json | each outage: customers, start, est. restore, status, [lng,lat], cause code |
| bchydro | BC Hydro (CA, British Columbia) | https://www.bchydro.com/power-outages/app/outages-map-data.json | each outage: numCustomersOut, cause text, municipality, crew status, polygon/point |
| ukpn | UK Power Networks (GB, London / South East / East) | https://ukpowernetworks.opendatasoft.com/api/explore/v2.1/catalog/datasets/ukpn-live-faults/records | each fault: planned/unplanned, customers affected, postcode, geopoint |
| eskom | Eskom (ZA, national) | https://loadshedding.eskom.co.za/LoadShedding/GetStatus | load-shedding stage: value - 1 (1 = none) |
| ercot | ERCOT (US, Texas) | https://www.ercot.com/api/1/services/read/dashboards/daily-prc.json | grid condition, `eea_level` (energy emergency) |
| aemo | AEMO (AU, national market) | https://www.nemweb.com.au/REPORTS/CURRENT/Market_Notice/ (directory, newest files) | market notices: LOR1/2/3, load shedding, directions, by region |

Not used: ODIN (login), Energex (blocks readers), poweroutage.us (terms), EIA / Cloudflare Radar / ENTSO-E (need a free key:
later, through request_credential, never in code or config).

## Files and shapes (one writer per file)
`config/grid.json` (owner-adjustable thresholds; lane A): `{ open_customers: 5000, close_customers: 2000, close_after: 2,
research_customers: 50000, research_suspicious_customers: 10000, levels: { eskom: 4, ercot: 1, aemo: 3 }, retry_hours: 6,
max_tries: 3 }`

`data/grid/live.json` (lane A writes): `{ fetched_at, sources: { <key>: { name, url, ok, error, fetched_at, items } },
items: [Item] }`; a failing source keeps its previous items with ok:false.
Item: `{ id: "<key>:<native id>", source, country (ISO-2), region, area (<=120), lat, lng (3 dp, or null), customers (int or
null), kind: "outage"|"load_shedding"|"grid_emergency"|"supply_warning", planned (bool), cause (<=120, as the operator
reports it, or ""), level (int or null), started_at, restore_est (ISO or ""), url (https, operator's own host) }`

`data/grid/incidents.json` (lane A writes): `{ updated_at, open: [Incident], closed: [Incident] }` (closed: last 30 days).
`data/grid/history/<YYYY-MM>.jsonl` (lane A appends closed incidents; never deleted).
Incident: `{ id: "grid-<source>-<region slug>-<YYYYMMDDHHmm opened>", source, country, region, kind, name (<=120, e.g.
"Hydro-Québec: 152,300 customers without power"), opened_at, updated_at, closed_at ("" while open), customers,
peak_customers, peak_at, level (or null), planned_share (0..1), causes: [{ cause, customers }] (top 3 as reported),
lat, lng (centroid; approx: true when it is a region/country centroid), url, research_needed (bool), research_reason
(reason code) }`. An incident is one operator region (coarse: the operator's service area or licence area; national for
signals). Open when unplanned customers >= open_customers or level >= 1 (any load shedding, EEA, actual LOR); close after
`close_after` collections below close_customers / back to normal.
Reason codes: `big` (peak >= research_customers), `suspicious_cause` (cause text matches cyber|hack|malware|ransom|
unknown|investigat and peak >= research_suspicious_customers), `grid_level` (level >= levels[source]), and closures
`planned` (planned_share > 0.5), `weather` (cause matches storm|wind|weather|snow|ice|tree|lightning|wildfire|heat|flood),
`small`.

`data/grid/research.json` (lane B writes, through apply only): `{ <incident id>: { decision, cause_summary (<=300),
sources: [https urls], read_depth: "full"|"summary"|"secondary", checked_at, tries, by: "CyberView AI (a Claude model)",
final (bool), next_at } }`.
Decisions: `weather`, `equipment`, `planned`, `supply_shortfall`, `wildfire_safety`, `third_party`, `cyber_official`,
`cyber_reported`, `under_investigation`, `unknown`. `under_investigation` and `unknown` are not final: retried after
retry_hours, final after max_tries.

`data/context/grid.json` (lane A writes): the context-layer shape used by ioda/gdacs:
`{ layer: "grid", source: "Grid operators: Hydro-Québec, BC Hydro, UK Power Networks, Eskom, ERCOT, AEMO", source_url: "",
fetched_at, ok, error, items: [ { id, source, kind, name, country, region, customers, level, lat, lng, approx, since, cause,
checked: { decision, summary, by } or null, url } ] }` (open incidents, biggest first, max 60).
`data/status.json`: `last_grid_at` (grid.mjs collect), `last_grid_research_at` (grid-desk apply).

## Lanes (each in its own worktree; commit on your branch; do not push; the orchestrator merges)
- **A, grid-sources**: owns `scripts/grid.mjs` (export every parser and the tracker as pure functions), `config/grid.json`,
  `tests/unit/grid.test.mjs`, `tests/fixtures/grid/*` (real responses saved once), `data/grid/*` except research.json,
  `data/context/grid.json`, the grid step in `.github/workflows/collect.yml` (continue-on-error, commits data/grid and
  data/context/grid.json). CLI: `collect`, `verify`, `status`.
- **B, grid-desk**: owns `scripts/grid-desk.mjs` (`plan --max N --per K --file F`, `apply <out file>`, `list`), leases kind
  `grid` via scripts/lib/lease.mjs, `tests/unit/grid-desk.test.mjs`, the `grid` role in `config/models.json` (sonnet,
  research toolset, ~40 turns), `flow.grid_workers` / `flow.grid_per_worker` in `config/pipeline.json`, the "Grid
  researcher" brief in `docs/jobs.md` (GOAL, INPUTS, STEPS, RULES, LIMITS, DONE WHEN, TIMESTAMP), the grid section of
  `docs/schema.md`, and the integration in `scripts/run-job.mjs` flow (each cycle: `grid.mjs collect`, then plan, workers,
  apply; nothing in it may stop the cycle).
- **C, grid-site**: owns `site/app.js` (CTX_DEFS.grid, cleanCtx branch, drawing, layers-panel list, BUILD bump),
  `site/index.html`, `site/status.js`/`status.html` (grid row), `scripts/build.mjs` (health.json `last_grid_at`,
  `last_grid_research_at`), `scripts/guard.mjs` (grid limit 120 min, warn only), `tests/test_all.py`.
Anything outside your lane: write it in `swarm/REQUESTS.md` on your branch.
