# Grid outage pipeline: handoff (2026-11-19)
Built by three lanes in parallel (A sources/tracker, B research desk, C site), merged on main; contract in grid-contract.md.
- Live: `node scripts/grid.mjs status`. First real runs: 6 of 6 sources ok, 82 items, 0 incidents (nothing above 5,000 customers).
- Continuous: each research cycle runs grid collect, then up to flow.grid_workers researchers (role grid, Sonnet) on
  incidents the rule pass flagged, then grid-desk apply. collect.yml is the backup and skips when the loop collected <20 min ago.
- Not yet exercised with live data: an opened incident, a grid researcher run, a cyber lead (unit-tested only).
- Next (phase 2): keyed sources (EIA, Cloudflare Radar, ENTSO-E) once the owner has keys; analysis (cross-source
  corroboration with IODA, history trends, anomaly flags).

## Phase 2 merged (2026-11-19)
- Lanes D (keyed sources, series, analysis) and E (trends section, map notes, status rows; BUILD 1.45) merged.
- Keyed sources EIA, Cloudflare Radar, ENTSO-E report "not connected (no key saved)" until the owner saves a key on the
  "cyberview" environment; then they switch on with no code change. EIA's success parser waits for one real reply.
- Open: an opened incident and a grid researcher run have still only been seen in tests.
