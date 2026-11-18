<p align="center"><img src="site/icon-512.png" alt="CyberView logo: a pixel-art masked head" width="128"></p>

# CyberView

**Live site: https://xanderhutch.github.io/CyberView** · [Archive](https://xanderhutch.github.io/CyberView/archive.html) · [Trends](https://xanderhutch.github.io/CyberView/trends.html)

A rolling seven-day world map of publicly reported cyber events: incidents, outages, exploited vulnerabilities, government and vendor reports, laws, enforcement and security investment. Built for defenders: every event says what happened, why it matters and what to do, with its sources.

- **Map, Timeline and Correlation views**, a known-exploited feed with patch deadlines, a daily brief, and a copy-ready shift handover.
- **Sources first.** Events are reviewed against original government and vendor documents where possible; corrections are logged; unverified attacker claims are hidden unless you ask for them.
- **Exposure check.** List your vendors and products in the watchlist and get a report: known-exploited flaws with patch deadlines (overdue ones flagged), this week's matching events, and matches across the whole archive. It runs in your browser; the list never leaves your device.
- **Share and subscribe.** Every event has a link (`#e=<id>`) and a Copy link button. High-severity and known-exploited events are published as an [RSS feed](https://xanderhutch.github.io/CyberView/data/feed.xml) and a [JSON Feed](https://xanderhutch.github.io/CyberView/data/feed.json).
- **Trends.** [What is moving](https://xanderhutch.github.io/CyberView/trends.html): this week against last by event type, sector, country, actor, product and theme, with daily counts and an honest caveat while history is short.
- **Time-lapse and deep search.** Play the window day by day on the map; searches also point to older matches in the archive.
- **Static site.** One HTML page reading one JSON bundle. No accounts, no tracking. Watchlists stay in your browser.

## How it stays current

Scheduled Claude jobs research new events and commit JSON files under `data/`. Each push runs `scripts/build.mjs`, which validates every record and rebuilds the bundle and archive; GitHub Pages then publishes `site/` (`.github/workflows/pages.yml`). Jobs and their prompts: `docs/jobs.md`.

## Run it on your own computer (for developers)

You only need this to work on the code; visitors use the live site above.

```bash
node scripts/build.mjs                        # validate the data, build the bundle, archive and feeds
cd site && python3 ../tests/serve.py 8000     # serve the built site on your machine, port 8000
python3 tests/test_all.py                     # browser regression suite
```

Rules for the page and the data: `CLAUDE.md`. Field reference: `docs/schema.md`.

## Limits

Coverage reflects what public sources report and leans toward English-language and government sources. Dates are mostly publication dates. This is an information aid, not security advice for your organisation.

## Report an error

Every event has a "Report an error" button that opens a pre-filled GitHub issue. The jobs check each report against the sources and log any correction.
