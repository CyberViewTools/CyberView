# Grid pipeline phase 2: keyed sources and analysis (contract)

Builds on grid-contract.md and handoff/grid.md (read both). Same rules: scripts plan, agents judge, scripts verify; context,
never called an attack unless an official source says so; AI text labelled "CyberView AI (a Claude model)".

## Keyed sources (switch on by themselves)
Keys are never in code, config or the repo. The environment's network proxy adds them to requests for these hosts once the
owner saves them. So an adapter just calls the API; HTTP 400/401/403 that says the key is missing means
`{ ok: false, error: "not connected (no key saved for <host>)" }`, which is reported but is not a failure.
| key | host | auth (added by the proxy) | use |
|---|---|---|---|
| eia | api.eia.gov | header X-Api-Key | hourly demand by US balancing authority (electricity/rto/region-data, type D and DF): a drop well below forecast is a US grid signal |
| cfradar | api.cloudflare.com | Authorization: Bearer | /client/v4/radar/annotations/outages (last 7 days): internet outages with cause, country, description, linked URL; cause "Power outage" corroborates grid incidents worldwide |
| entsoe | web-api.tp.entsoe.eu | header SECURITY_TOKEN (owner adds it in the environment settings) | unavailability of generation/transmission (documentType A80/A78) and outages in Europe |
Each adapter: fetch + pure parser with a saved or hand-made fixture, items in the grid Item shape (kind "grid_emergency" or
"supply_warning" for signals, "outage" for Radar power-cause outages with country centroid, approx true).

## Time series (lane D)
`data/grid/series/<YYYY-MM-DD>.jsonl`: one line per region per 15 minutes at most:
`{ at, source, region, customers, unplanned, level }`. Written by grid.mjs collect. Kept 90 days in git; older days are
rolled into `data/grid/series/monthly/<YYYY-MM>.json` (daily max/mean per region) and the daily files removed by the script
(the one exception to "never delete": these are derived numbers, the monthly roll-up keeps them).

## Analysis (lane D): scripts/grid-analysis.mjs, no AI model, every research cycle after grid collect
Pure exported functions with unit tests, writes `data/grid/analysis.json`:
- `baseline(series, region, now)`: median and MAD of unplanned customers for the same hour-of-week over the last 4 weeks
  (falls back to all hours when there are fewer than 8 points); `anomaly` = robust z = (x - median) / (1.4826 * MAD),
  flagged when z >= 4 and x >= open_customers. Signal sources: any level above their normal (0) is notable.
- `corroborate(incident, ctx)`: for each open incident, independent signals in the same country/region within +-6 h:
  IODA (data/context/ioda.json: country code, signals), GDACS (data/context/gdacs.json: country, type), Cloudflare Radar
  power outages (when connected), EIA demand drop (when connected), and news leads (data/leads/<today and yesterday>.jsonl
  whose title matches blackout|power outage|power cut|apagón|panne|Stromausfall|load shedding|grid and the region or
  country). Output per incident: `{ id, signals: [{ kind, source, detail, url }], score }`, where score = number of
  independent kinds (operator, internet, disaster, news, demand). Leads are counted, never quoted beyond their title.
- `trends(history, series)`: per region last 30 days: incidents opened, total customer-hours (sum over 15-min points of
  unplanned * 0.25), the largest incident, causes mix (as operators report them); and week-over-week change.
- `analysis.json`: `{ updated_at, anomalies: [...], corroboration: [...], trends: {...}, sources: { <key>: { ok, error } } }`.
- Rule feed-back: an incident with an anomaly AND score >= 3, or an internet-outage corroboration with no weather cause,
  sets `research_needed` with reason `corroborated` (add the code to grid.mjs triage and verify) so the grid researchers
  check it even below 50,000 customers.
- `verify` covers analysis.json and series files.

## Site (lane E)
- Trends page (site/trends.html, trends.js, archive.css): a "Power grid" section built from analysis.json (bundled by
  build.mjs as docs["grid/analysis"]): per region customer-hours over 30 days (single-colour bars, rule 5: lead with the
  question, caveats underneath: operator-reported, six operators only, outages are not cyber events), incidents opened, the
  largest, causes mix in the tooltip.
- Map: the grid layer tooltip and list show "corroborated by: internet (IODA), news (2)" from the corroboration and an
  "unusual for this hour" note for anomalies.
- Status page: one row per grid source including keyed ones ("not connected" shown as neutral, not as a fault).
- tests/test_all.py checks for all of it with fixtures.

## Ownership
- D (grid-analysis): scripts/grid.mjs, scripts/grid-analysis.mjs, config/grid.json, tests/unit/grid*.test.mjs (not
  grid-desk's), tests/fixtures/grid/*, data/grid/* except research.json, data/context/grid.json, scripts/run-job.mjs (only
  to add `node scripts/grid-analysis.mjs` right after the existing grid collect call, guarded like it), .github/workflows/
  collect.yml (the same after its grid step).
- E (grid-site-2): site/*, scripts/build.mjs, tests/test_all.py. Requests elsewhere go in swarm/REQUESTS.md.
