# Cyber Watch Map: handoff and build-out plan

Prepared 2026-11-17 for moving the project from a Claude artifact to **GitHub + Netlify**, maintained with **Claude Code**.

---

## 1. What the product is

A rolling seven-day world map of publicly reported cyber events, built for defenders. Each event says what happened, why it matters and what to do, with its sources.

- **Owner:** Xander.
- **Audience:** public. Visitors read; they do not mark anything. Watchlists stay in each visitor's browser.
- **Covers:** incidents and breaches, outages, exploited vulnerabilities and patches, government and vendor threat reports, laws and regulation, law enforcement, and security investment and vendor news.

## 2. What exists today

### 2.1 The live artifact (current production)

| Item | Value |
|---|---|
| URL | https://claude.ai/artifact/9tgpvAxSXLWuGMt69DHRmA (private, owner only) |
| Slug | `480095d5-6613-4f00-b113-f4ee0e03aa61` |
| Live version | `1794964920-ae57` (page v1.0) |
| Data store | the artifact's own database (~270 documents) |
| Data | ~190 events, ~16 known-exploited entries, corrections, patterns, ripples, brief, status, maintainer guide (`meta/guide`) |

This keeps running unchanged until the Netlify site replaces it.

### 2.2 Page features (v1.0 artifact, v1.1 in this repo)

- **Three views:**
  - **Map:** world map, markers by category shape and colour, clusters, country shading.
  - **Timeline:**
    - Events per day against a typical-day line.
    - Attack-surface swimlanes (edge, identity, email, cloud and AI, apps and supply chain, endpoints, OT, telecom, policy), switchable to event type or sector.
    - "How long do we have to patch?": a countdown from today to each known-exploited flaw's federal deadline.
  - **Correlation:**
    - Ripple effects: direct effect, what it leads to, what to watch for.
    - Threat-to-target flow: kind of threat, then part of the environment, then sector.
    - Chains (what led to what, stated, inferred or timing).
    - Shared factors (actor, CVE, product across events).
    - Surface-by-threat matrix with a lift test.
- **Side panel tabs:**
  - **Brief:** daily summary.
  - **Feed:** priority-sorted, with a "Do:" line on urgent items, a detail view with previous and next, and J/K keys.
  - **Exploited:** a direct CISA known-exploited feed with deadlines and ransomware flags.
  - **Patterns.**
  - **Insights:** quality metrics, corrections, update-pipeline health, and an About section covering method and limits.
- **Event detail:**
  - Plain, standard and executive reading levels.
  - "What to do".
  - A government or vendor report review: key findings, the report's own recommendations, whether it publishes IOCs, and how deeply it was read.
  - CVE scores (CVSS, EPSS, known-exploited).
  - Sources, validation and an error-report form.
- **Controls:**
  - Category chips, a 24-hour / 3-day / 7-day window, severity, status, sector lens and search.
  - A watchlist, and an "unverified claims" switch that is off by default.
  - Light and dark glass appearance, and full screen.
  - Refresh (reloads the data and resets to the main view).
  - Handover: a copy-ready shift summary.
- **Engineering:**
  - Every record passes through a `clean*()` validator before use.
  - Each panel renders in isolation (`safe()`), so one failure cannot blank the page.
  - The category palette is colour-blind safe and validated for both light and dark.
  - The browser regression suite has 51 checks in the artifact version and 43 in this repo.

### 2.3 Data rules (non-negotiable)

- Facts only from pages actually read. Never invent document numbers, findings or URLs.
- Prefer the original government or vendor document; record `report.read_depth` (full, summary or secondary).
- Outages are never called attacks unless an official source says so.
- Unconfirmed attacker claims are `status: claimed`, `severity: 1` and hidden by default.
- Known-exploited flaws, public exploit code, or an official "patch immediately" mean severity 3 for widely used or internet-facing software.
- Corrections are logged whenever an original contradicts an entry.
- Sources are specific article URLs, never front pages. Use real timestamps, never estimates.
- Slow sites get spaced retries. Sites that block automated readers are not worked around.

Full rules: `CLAUDE.md`. Fields: `docs/schema.md`.

### 2.4 Scheduled tasks (currently writing to the artifact database)

| Job | Task id | Schedule |
|---|---|---|
| Hourly sweep | `trig_01TabG7pDaRQCf3ZcNieuarY` | :10 every hour |
| Validation pass | `trig_01NKHBGprPJLC3pMk6XXLiS8` | :19 every 2 h |
| Feeds and enrichment (KEV, NVD, EPSS) | `trig_01BJ2EYCycYREe9WxeDFVH1h` | :59 every 2 h |
| Correlation and ripples | `trig_019eTHWuuXPYuo1QYkdEHwqo` | :50 every 3 h |
| Primary-source report review | `trig_012cMW9qvL4bHXVX1c7P6CTr` | 1:17 am and 1:17 pm ET |
| Daily deep sweep | `trig_0194AprfFRoQAnWv7iWFqvVJ` | 5:17 am ET |
| Daily brief and baseline | `trig_01SDa3PPJ4QaKed3FS3jWZ6H` | 6:40 am ET |
| Daily cleanup and health | `trig_01VEUdDAWAFsG5sPZavdYyiV` | 3:41 am ET |

All have automatic approval. Their GitHub-based replacements are written in `docs/jobs.md`.

**Unfinished on these tasks:** the "record hygiene" rule (no front-page sources, real timestamps, always-present arrays, re-rating severity on known-exploited status, 75-word summaries) was never added. The agent stopped at the usage limit. The rule text is in `docs/jobs.md` and `CLAUDE.md`.

---

## 3. Target architecture

```
GitHub: xanderhutch/cyber-watch-map (private)
 ├─ data/                 source of truth: one JSON file per record
 ├─ scripts/build.mjs     validates data/, writes site/data/bundle.json (fails on bad data)
 ├─ site/                 static page (index.html, vendor/d3, vendor/topojson, world-110m.json)
 └─ netlify.toml          build = node scripts/build.mjs, publish = site, security headers

Claude scheduled tasks ──clone, research, edit data/*.json, build, commit, push──▶ GitHub main
GitHub main ──push──▶ Netlify build (validate + bundle) ──▶ public site
Visitors ──read──▶ site/data/bundle.json (re-read every 5 minutes and on tab focus)
Visitors ──error report──▶ Netlify Forms ("event-report") ──▶ reviewed by the validation job
```

Why this shape:
- **One static file to read.** No database, no keys, no server.
- **Git is the audit trail.** Every data change is a reviewable commit.
- **Bad data stops at the build.** A failing build never publishes; the last good site stays live.

### What changed in the page for Netlify (v1.1)

- The Claude artifact database calls were replaced with `openStore()`. It reads `data/bundle.json` and keeps the same interface, so the rest of the page is unchanged.
- d3 and topojson are served from `site/vendor/`; there are no third-party requests.
- The watchlist is saved in the browser only.
- Error reports go to a Netlify form; the hidden form is declared in the page.
- A Content Security Policy and other security headers are set in `netlify.toml`.

---

## 4. Repository contents (this zip)

```
README.md            public description
CLAUDE.md            rules Claude Code follows when working in the repo
HANDOFF.md           this document
netlify.toml         build, publish and headers
.gitignore           excludes site/data/ (generated) and .netlify/
site/index.html      the page, v1.1
site/vendor/         d3.min.js 7.9.0, topojson.min.js 3.0.2
site/world-110m.json country outlines
scripts/build.mjs    validator and bundler
tests/test_all.py    browser regression suite (light, dark, phone, missing data, no bundle, ~160 events)
docs/schema.md       every field
docs/jobs.md         shared preamble and the 8 job prompts for GitHub
data/events/         28 events exported so far (see 5.1)
data/kev/            24 known-exploited entries
legacy/artifact-index.html          the artifact page as published (v1.0), for reference
legacy/kev-catalog-2026-11-17.json  CISA catalog snapshot
```

Verified in this environment: `node scripts/build.mjs` builds, and `python3 tests/test_all.py` gives **43 checks, ALL PASS** on the exported data.

---

## 5. Build-out steps

### 5.1 Finish the data export (first task in Claude Code)

The export from the artifact database stopped partway (environment restart): 28 of about 190 events, 24 KEV entries, and none of the corrections or single documents. In Claude Code, with the artifact tools available:

1. For each date range, page through `events` with `db_query` (slug above) and write each document's `data` object unchanged to `data/events/<id>.json`.
2. Do the same for `kev` and `corrections`.
3. Write `meta/status`, `analysis/latest`, `analysis/ripples`, `brief/latest` and `stats/history` to `data/status.json`, `analysis.json`, `ripples.json`, `brief.json` and `history.json`.
4. Run `node scripts/build.mjs` and `python3 tests/test_all.py`.

If the artifact tools are not available in Claude Code, run the export from a claude.ai session. Alternatively, start fresh and let the jobs repopulate within a day; the map only shows seven days anyway.

### 5.2 GitHub

1. Create the empty private repo `xanderhutch/cyber-watch-map` on github.com. This session's GitHub token could not create repositories.
2. Push this folder:
   ```
   git init -b main && git add . && git commit -m "Cyber Watch Map v1.1: static site, data, build, tests"
   git remote add origin git@github.com:xanderhutch/cyber-watch-map.git && git push -u origin main
   ```
3. Protect `main` lightly. Scheduled jobs push directly, so do not require pull requests. Add a GitHub Action running `node scripts/build.mjs` on every push, so a bad commit is flagged even before Netlify sees it.

### 5.3 Netlify

1. Connect the Netlify connector or the dashboard to GitHub, choose **Import from Git**, and pick `xanderhutch/cyber-watch-map`.
2. Build settings come from `netlify.toml` (build `node scripts/build.mjs`, publish `site`, Node 20).
3. Enable **Forms** and confirm the `event-report` form appears after the first deploy.
4. Optional: a custom domain, and form notifications by email.
5. The Netlify account had no projects when checked; the connector is connected in claude.ai.

### 5.4 Move the scheduled jobs to GitHub

For each of the eight tasks, replace its prompt with **shared preamble + job section** from `docs/jobs.md`, and attach the repository with push access to the task's environment. Then:
- Run one task by hand and check that the commit, the Netlify build and the site all update.
- Once the site is confirmed, disable writes to the artifact database. The artifact can stay as an archive.

Commit-collision guard: jobs run at different minutes, and the preamble requires `git pull --rebase` before every push.

### 5.5 Verify in production

- The page loads, the bundle is fresh, and the "swept X ago" stat updates after a job runs.
- An error report arrives in Netlify Forms.
- The security headers are present (`curl -I`), and the browser console shows no CSP violations.
- Lighthouse scores for accessibility and performance.

---

## 6. Backlog (recommended order)

1. **Data hygiene rule in the jobs** (5 faults from the audit): no front-page sources, real timestamps, arrays always present, re-rate on known-exploited status, summary length. It is already in `CLAUDE.md`; make sure the job prompts follow it.
2. **Fix the 22 events that rest only on a front-page link** (mostly leak-site claims), and the two date conflicts (ConnectWise, N-able).
3. **GitHub Action for the mechanical feeds.** KEV, NVD and EPSS are plain API calls; moving them out of Claude makes them faster and more reliable.
4. **Netlify Forms to validation job.** The job reads form submissions through the Netlify API (token as a secret) and logs corrections.
5. **RSS or JSON feed of high-severity events** generated at build time, so others can subscribe.
6. **Per-event permalinks** (`/#e=<id>`) for sharing.
7. **Consolidate the CSS.** The page carries layered overrides from several redesigns; it works and is tested, but should be collapsed into one token set.
8. **Coverage:** Africa, Turkey, the Middle East, Latin America, and native-language national CERTs.
9. **Exposure check:** paste a product or asset list and highlight matching events and known-exploited flaws, in the browser only.

## 7. Known limits

- Neither the live artifact nor the Netlify build has been checked in a signed-in browser. All verification ran on local copies.
- Analysis rows (attack surface, sector) are assigned by keyword.
- Ripple effects marked "reasoned" are inferences, not reports.
- Germany's BSI, Australia's cyber.gov.au and SAP notes block automated readers.
