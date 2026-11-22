# Handoff: scan-http-paths — bounded HTTP path rail

## Discovery → Design
- **Need:** one rail so later checks do not each invent a crawler.
- **Constraints:** GET only, frozen paths, hint-gated, cap 8, off unless `--paths`. No wordlist, no login, no `/actuator/env`, no debug console, no configuration-backup fetch.
- **Recommendation:** build.

## Design → Implementation
- **CLI:** `--paths` (hint-gated). `--well-known` adds the published well-known group. Default is off.
- **Data:** `scanner/lib/paths.mjs` `PATH_RAIL`. `probeHttpPath` refuses anything not on that list and discards status-page bodies.
- **Not built, on purpose:** WordPress configuration backups (secret files) and Laravel Ignition or Telescope (debug surfaces).
- **Tests:** loopback records only hinted paths; an unhinted host stays at the root; an off-rail path makes no connection; the cap holds.

## Implementation → Review
- This branch, with the rest of sprint 1.
