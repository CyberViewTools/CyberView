<p align="center"><img src="site/icon-512.png" alt="CyberView logo: a pixel-art masked head" width="128"></p>

# CyberView

**Live site: https://cyberview.tools** · [Archive](https://cyberview.tools/archive.html) · [Trends](https://cyberview.tools/trends.html)

A live, verified picture of cyber threats worldwide for defenders: what happened, what is being exploited, and the outages around it, updated around the clock.

CyberView is always growing; its full, current description is generated from [`config/about.json`](config/about.json) and published on the [About page](https://cyberview.tools/about.html#what), and CI fails if a new page, view, map layer or routine is added without an entry there.

- **Map, Timeline and Correlation views**, a known-exploited feed with patch deadlines, a daily brief, and a copy-ready shift handover.
- **Sources first.** Events are reviewed against original government and vendor documents where possible; corrections are logged; unverified attacker claims are hidden unless you ask for them.
- **My environment.** Drop in a software or asset inventory (CSV), an SBOM (CycloneDX or SPDX), `package.json`, `requirements.txt` or a plain list, or tick common platforms. The file is read in your browser and never uploaded. Matching is whole-word, and the profile can be copied to another device or a colleague.
- **Patch deadlines in your calendar.** One click saves the open deadlines for known-exploited flaws (only those matching your environment, if you set one) as a calendar file with a reminder 3 days before.
- **Desktop notifications.** Turn on "Notify me on this device" and get a notification when a new event or exploited flaw matches your environment, while CyberView is open in a tab.
- **Exposure check.** Your environment drives a report: known-exploited flaws with patch deadlines (overdue ones flagged), this week's matching events, and matches across the whole archive. It runs in your browser; the list never leaves your device.
- **Share and subscribe.** Every event has a link (`#e=<id>`) and a Copy link button. High-severity and known-exploited events are published as an [RSS feed](https://cyberview.tools/data/feed.xml) and a [JSON Feed](https://cyberview.tools/data/feed.json).
- **Trends.** [What is moving](https://cyberview.tools/trends.html): this week against last by event type, sector, country, actor, product and theme, with daily counts and an honest caveat while history is short.
- **Time-lapse and deep search.** Play the window day by day on the map; searches also point to older matches in the archive.
- **Runs itself, in the open.** A [status page](https://cyberview.tools/status.html) lists every routine, when it last ran and what it found; a collector reads 22 agency, vendor and news feeds so the AI jobs start from leads instead of web searches.
- **Globe and context layers.** Switch the map to a globe you can turn (G), and open the layers panel (L) for internet-disruption signals (IODA) and orange and red disaster alerts (GDACS). Each layer shows its source, its age and whether it is live, stale or offline. They are context, never counted as cyber events.
- **Optional accounts.** Sign in with an email link to sync your environment across devices (encrypted in your browser with your own passphrase) and get email alerts when something matches it. Export or delete everything yourself at any time. See [privacy](https://cyberview.tools/privacy.html) and [docs/accounts.md](docs/accounts.md).
- **Static site.** One HTML page reading one JSON bundle. No tracking, no cookies, no account needed; your environment stays in your browser unless you choose to sync it.

## How it stays current

Scheduled Claude jobs and GitHub workflows research new events and commit JSON files to the `data` branch, which every checkout mounts at `./data`. Each data push starts the deploy (`.github/workflows/pages.yml`): `scripts/build.mjs` validates every record and rebuilds the bundle and archive, and GitHub Pages publishes `site/`. The code is on `main` and changes only through pull requests that pass CI. How the two branches work: `docs/branches.md`. Jobs and their prompts: `docs/jobs.md`.

## Run it on your own computer (for developers)

You only need this to work on the code; visitors use the live site above.

```bash
npm run build      # validate the data, build the bundle, archive and feeds
npm run preview    # build, then serve the site on your machine, port 8000
npm run ci         # build, security check, unit tests, browser regression suite
```

After cloning, run `node scripts/data-branch.mjs ensure` once: it mounts the data branch at `./data`. No packages to install: the scripts use only Node 22's standard library. The browser suite needs `pip install playwright`.

Rules for the page and the data: `CLAUDE.md`. Field reference: `docs/schema.md`.

## Limits

Coverage reflects what public sources report and leans toward English-language and government sources. Dates are mostly publication dates. This is an information aid, not security advice for your organisation.

## Report an error

Every event has a "Report an error" button that opens a pre-filled GitHub issue. The jobs check each report against the sources and log any correction.

## Credits

Context data: [IODA](https://ioda.inetintel.cc.gatech.edu/) (Georgia Tech Internet Intelligence Lab) and [GDACS](https://www.gdacs.org/) (European Commission JRC and UN OCHA). Map: Natural Earth via world-atlas; d3 and topojson-client.

## Licence

CyberView is **proprietary** — copyright (c) 2026 xanderhutch, all rights reserved (`LICENSE`). The source is public to be read and audited, but may not be copied, redistributed, modified, hosted or run as a service without written permission. Two exceptions: the third-party libraries in `site/vendor/` keep their own licences (`THIRD_PARTY_NOTICES`), and the downloadable scanner in `scanner/` has its own end-user terms (`scanner/LICENSE`). Files obtained before this change remain under the MIT licence they were released under. Permissions: cyberviewthreats@gmail.com.
