<p align="center"><img src="site/icon-512.png" alt="CyberView logo: a pixel-art masked head" width="128"></p>

# CyberView

**Live site: https://xanderhutch.github.io/CyberView** · [Archive](https://xanderhutch.github.io/CyberView/archive.html) · [Trends](https://xanderhutch.github.io/CyberView/trends.html)

A rolling seven-day world map of publicly reported cyber events: incidents, outages, exploited vulnerabilities, government and vendor reports, laws, enforcement and security investment. Built for defenders: every event says what happened, why it matters and what to do, with its sources.

- **Map, Timeline and Correlation views**, a known-exploited feed with patch deadlines, a daily brief, and a copy-ready shift handover.
- **Sources first.** Events are reviewed against original government and vendor documents where possible; corrections are logged; unverified attacker claims are hidden unless you ask for them.
- **My environment.** Drop in a software or asset inventory (CSV), an SBOM (CycloneDX or SPDX), `package.json`, `requirements.txt` or a plain list, or tick common platforms. The file is read in your browser and never uploaded. Matching is whole-word, and the profile can be copied to another device or a colleague.
- **Exposure check.** Your environment drives a report: known-exploited flaws with patch deadlines (overdue ones flagged), this week's matching events, and matches across the whole archive. It runs in your browser; the list never leaves your device.
- **Share and subscribe.** Every event has a link (`#e=<id>`) and a Copy link button. High-severity and known-exploited events are published as an [RSS feed](https://xanderhutch.github.io/CyberView/data/feed.xml) and a [JSON Feed](https://xanderhutch.github.io/CyberView/data/feed.json).
- **Trends.** [What is moving](https://xanderhutch.github.io/CyberView/trends.html): this week against last by event type, sector, country, actor, product and theme, with daily counts and an honest caveat while history is short.
- **Time-lapse and deep search.** Play the window day by day on the map; searches also point to older matches in the archive.
- **Runs itself, in the open.** A [status page](https://xanderhutch.github.io/CyberView/status.html) lists every routine, when it last ran and what it found; a collector reads 22 agency, vendor and news feeds so the AI jobs start from leads instead of web searches.
- **Globe and context layers.** Switch the map to a globe you can turn (G), and open the layers panel (L) for internet-disruption signals (IODA) and orange and red disaster alerts (GDACS). Each layer shows its source, its age and whether it is live, stale or offline. They are context, never counted as cyber events.
- **Optional accounts.** Sign in with an email link to sync your environment across devices (encrypted in your browser with your own passphrase) and get email alerts when something matches it. Export or delete everything yourself at any time. See [privacy](https://xanderhutch.github.io/CyberView/privacy.html) and [docs/accounts.md](docs/accounts.md).
- **Static site.** One HTML page reading one JSON bundle. No tracking, no cookies, no account needed; your environment stays in your browser unless you choose to sync it.

## How it stays current

Scheduled Claude jobs research new events and commit JSON files under `data/`. Each push runs `scripts/build.mjs`, which validates every record and rebuilds the bundle and archive; GitHub Pages then publishes `site/` (`.github/workflows/pages.yml`). Jobs and their prompts: `docs/jobs.md`.

## Run it on your own computer (for developers)

You only need this to work on the code; visitors use the live site above.

```bash
npm run build      # validate the data, build the bundle, archive and feeds
npm run preview    # build, then serve the site on your machine, port 8000
npm run ci         # build, security check, unit tests, browser regression suite
```

No packages to install: the scripts use only Node 22's standard library. The browser suite needs `pip install playwright`.

Rules for the page and the data: `CLAUDE.md`. Field reference: `docs/schema.md`.

## Limits

Coverage reflects what public sources report and leans toward English-language and government sources. Dates are mostly publication dates. This is an information aid, not security advice for your organisation.

## Report an error

Every event has a "Report an error" button that opens a pre-filled GitHub issue. The jobs check each report against the sources and log any correction.

## Credits

The globe view, layer health badges, build-time context manifests, network retry and circuit-breaker helper, intel wire and `npm run ci` layout adapt patterns from [Godseye](https://github.com/VrushankPatel/godseye) by Vrushank Patel (Apache License 2.0). CyberView's code is its own; no Godseye files are copied. Context data: [IODA](https://ioda.inetintel.cc.gatech.edu/) (Georgia Tech Internet Intelligence Lab) and [GDACS](https://www.gdacs.org/) (European Commission JRC and UN OCHA). Map: Natural Earth via world-atlas; d3 and topojson-client.
