# Data schema

All files are UTF-8 JSON. The build (`scripts/build.mjs`) rejects files that break the required rules and warns on the rest.

Where it lives: every path below that starts with `data/` is a file on the `data` branch (the branch root is the data folder, so `data/events/...` is `events/...` there), mounted at `./data` in every checkout. Code is on `main`. Scripts read and write `data/...` as before; commit only with `scripts/finish.mjs` or `scripts/data-commit.mjs`. See `docs/branches.md`.

## data/events/&lt;id&gt;.json

`id` is the file name: lowercase letters, digits and hyphens, usually `<org>-<few-words>-<yyyy>-<mm>`.

| Field | Required | Type and rule |
|---|---|---|
| title | yes | plain, under 110 characters, no trailing full stop |
| date | yes | `YYYY-MM-DD`, the day it happened (or was published if unknown); not in the future |
| category | yes | `incident`, `outage`, `vuln`, `report`, `policy`, `investment`, `enforcement` |
| severity | yes | 1 low, 2 medium, 3 high |
| status | | `confirmed`, `official`, `developing`, `claimed` |
| date_note | | why the date is uncertain or differs from publication |
| occurred_at | | ISO time with offset; within a day of `date` |
| time_basis | | `occurred`, `reported`, `published`, `approx` |
| org, sector, country, place | | strings |
| lat, lng | | numbers, or null when unknown |
| geo_basis | | what the pin location is based on |
| pin_type | | `victim`, `hq`, `agency`, `actor`, `researcher`, `country`, `none` |
| actor | | as named by the sources, else empty |
| summary | | 2 to 4 sentences, at most 75 words |
| plain | | non-technical, at most 240 characters |
| exec | | business significance, at most 170 characters |
| action | | one instruction for a defender, at most 280 characters |
| impact | | free text |
| records_affected | | number |
| products, attack, cves | | lists of strings; cves match `CVE-YYYY-NNNN` |
| tags | | list from: ransomware, data-breach, supply-chain, zero-day, ddos, espionage, critical-infrastructure, ai-enabled, third-party, phishing, insider, hacktivism, ot-ics, cloud, identity, fraud, takedown, regulation, funding, acquisition, malware, rce, poc-public. Sector, country and product go in their own fields, not in tags; the list is defined as `TAGS` in `scripts/lib/validate.mjs` |
| aliases | | optional list of the event's names in other scripts or languages (e.g. 富岳 for Fugaku), max 8 of up to 60 characters; lets scripts/triage.mjs match retellings in other languages to this event |
| cve_meta | | list of `{id, cvss, epss, kev, kev_due}` |
| sources | | list of `{name, url}`; url is the specific page read |
| source_tier | | `primary`, `established`, `aggregator` |
| validation | | `{state, checked_at, note}`; state is `corroborated`, `single_source`, `unconfirmed_claim`, `disputed`, `source_unreachable` |
| report | | review of an original document: `{publisher, publisher_type (government or vendor), doc_id, published, key_findings[], recommendations[], iocs_available, read_depth (full, summary, secondary), url}` |
| attribution | | `{actor, origin_country, lat, lng, by, by_type, url}`: who a government (`by_type` `government`) or the investigating firm (`investigator`) says did it, where the actor is said to be based (lat, lng of that country's capital) and the https page where the attribution is made. Drawn as a dashed, labelled arc from the origin to the victim. Never from attacker boasts or press speculation. |
| links | | `[{to, rel, url}]`: other events a source says this one is connected to (`to` is an event id on file, `rel` at most 60 characters such as "customer of breached supplier", `url` the page that states it). Drawn as arcs on the globe. |
| hunt | | `[{name, format, url, publisher}]`: indicator files and detection rules the original document publishes (format: stix, sigma, yara, snort, suricata, kql, spl, csv, json, misp, openioc, text, pdf). Links only; indicators themselves are never stored. Shown in the workbench's hunt pack. |
| review | | `{state, at, first_at, note, flags[]}` (`at` the latest review, `first_at` the first one, kept through re-reviews of updates): the second review by a different agent (the review desk), written only by `scripts/review.mjs`: `passed`, `corrected` (the reviewer fixed the record) or `flagged` (a problem remains; validation becomes `disputed` until verify settles it). |
| duplicate_of | | id of the richer record; the build leaves this one out |
| first_seen, updated_at, qa_checked_at | | ISO times |

## data/kev/&lt;CVE&gt;.json

`cve, vendor, product, name, added (YYYY-MM-DD), due (YYYY-MM-DD), ransomware (bool), desc (plain, at most 260 characters), cvss (number), epss (0 to 1)`, and from the feeds script: `required` (CISA's required action), `refs` (advisory links CISA cites), `av` (CVSS attack vector N, A, L or P), `affected` (version ranges from NVD: `[{vendor, product, part, from, from_incl, to, to_incl, exact}]`) and `affected_at`. Entries added in the last 45 days are published.

## data/corrections/&lt;id&gt;.json

`at, event_id, title, what_changed`.

## Single files

- `status.json`: `last_sweep_at, last_validation_at, last_feeds_at, last_kev_at, last_analysis_at, last_reports_at, last_deep_sweep_at, last_brief_at, last_maintenance_at`, notes, `health {checked_at, late[], note}`, `quality {...}`.
- `analysis.json`: `generated_at, summary, patterns[{id, title, kind (stated, inferred, timing), confidence, narrative, caveat, event_ids[], chain[], edges[{from, to, rel, basis}]}]`.
- `ripples.json`: `generated_at, items[{event_id, basis (stated, inferred), who_should_care[], direct[], downstream[], watch_for[]}]`.
- `brief.json`: `generated_at, date, headline, plain_summary, items[{title, why, action, event_id}]`.
- `history.json`: `days {YYYY-MM-DD: {total, incident, ...}}`.

## data/runs/&lt;YYYY-MM-DD&gt;/&lt;HHMM&gt;-&lt;job&gt;.json

One file per job run, never deleted. It keeps the research so it is not wasted:
`job, started_at, finished_at, model, searches[], pages_read[{url, title, used_in}], added[ids], updated[ids], skipped[{title, url, reason}], open_leads[{title, url, note}], failed_sites[], notes`.
The feeds script writes its own shape (`kev_added, kev_updated, cvss_added, events_updated, rerated, failed`).
`node scripts/q.mjs leads` lists open leads and skipped items that never became events; `q.mjs seen <url>` checks whether a page was already read.

## data/guides/&lt;CVE&gt;.json

A fix guide written by the advisory desk from the vendor's own advisory (never from news coverage), checked by `checkGuide` in `scripts/lib/validate.mjs`:
`cve, advisory {name, url}, read_at, read_depth (full, summary), check[], fixed[], workaround[], compromise_signs[], exposure (internet, internal, local), exploit_public (bool), hunt[]`.
The workbench (`workbench.html`, from `site/data/workbench.json`) shows it under each flaw and uses `exposure` and `exploit_public` in the priority score.

## data/chat/&lt;YYYY-MM&gt;/&lt;issue&gt;.json

A reviewed community post: `id` (issue number), `at`, `author` (GitHub login), `kind` (comment, tip, question), `text` (plain, at most 600), `event_id`, `links` (at most 2, https), `reviewed_at`, optional `note` (moderator's note), `removed`, `removed_at`, `removed_reason`. Written only by `scripts/chat.mjs approve`; the build publishes the newest 300 that are not removed to `site/data/chat.json`.

## data/tabletop.json

The weekly tabletop exercise (the tabletop job), copied to `data/snapshots/tabletop/<YYYY-MM-DD>.json`. The build rejects it unless every field passes `scripts/lib/validate.mjs`:
`label` ("exercise"), `generated_at`, `date`, `title` (at most 120), `based_on` [event ids on file], `real_story` (at most 900, facts only), `facts` [{text, source_url}] (at least 2), `scenario` (hypothetical, at most 1200), `duration_min` (20 to 180), `roles` [], `injects` [{at_min, title, text, ask}] (3 to 10, in time order), `questions` (4 to 12), `good_looks_like` (3 to 10), `adapt`, `sources` [{name, url}].
The site shows it on `tabletop.html` with past exercises from the snapshots.

## data/grid/ (electrical grid outages: context, never cyber events)

Tracked by `scripts/grid.mjs collect` from the operators' own public feeds (Hydro-Québec, BC Hydro, UK Power Networks, Eskom, ERCOT, AEMO); the full contract is `swarm/handoff/grid-contract.md`. One writer per file.
- `live.json` (grid.mjs): `fetched_at, sources {<key>: {name, url, ok, error, fetched_at, items}}, items[]` (each item: `id` "<source>:<native id>", `source, country, region, area, lat, lng, customers, kind` (outage, load_shedding, grid_emergency, supply_warning), `planned, cause, level, started_at, restore_est, url`).
- `incidents.json` (grid.mjs): `updated_at, open[], closed[]` (closed: last 30 days; older ones stay in `history/<YYYY-MM>.jsonl`, never deleted). Incident: `id` ("grid-<source>-<region slug>-<YYYYMMDDHHmm>"), `source, country, region, kind, name` (120), `opened_at, updated_at, closed_at, customers, peak_customers, peak_at, level, planned_share, causes [{cause, customers}], lat, lng, approx, url, research_needed, research_reason` (big, suspicious_cause, grid_level; or planned, weather, small).
- `research.json` (written only by `scripts/grid-desk.mjs apply`): `{<incident id>: {decision, cause_summary (at most 300), sources [https pages read], read_depth (full, summary, secondary), checked_at, tries, by ("CyberView AI (a Claude model)"), final, next_at, plan_id}}`. `decision`: weather, equipment, planned, supply_shortfall, wildfire_safety, third_party, cyber_official (the operator, a regulator or a government says so on its own site), cyber_reported (a named publisher reports it; unconfirmed), under_investigation, unknown. under_investigation and unknown are tried again after `retry_hours` (config/grid.json) and become final after `max_tries`; `plan_id` makes applying the same worker file twice a no-op.
- A cyber_official or cyber_reported decision files ONE lead per incident in `data/leads/<date>.jsonl` (`via: "grid-desk"`, `kind: "grid"`, `grid_id`, tier `gov` for official, `news` for reported, title "Grid outage linked to a cyberattack (official | reported, unconfirmed): <name>"); only the research loop turns it into an event, with its second review.
- Worker files: `data/grid-plan-<run>.json` (`plan_id, planned_at, run, batches [{batch, out, incidents}]`) and `data/grid-out-<run>-<batch>.json` (`plan_id, batch, results [{id, decision, cause_summary, sources, read_depth}]`) are working state, deleted after each cycle. Leases are kind `grid` in `data/leases.json`.
- `data/context/grid.json` (grid.mjs) is the map's context layer, in the ioda/gdacs shape, with `checked {decision, summary, by}` from research.json. `status.json` gets `last_grid_at` (collect) and `last_grid_research_at` (grid-desk apply).

## data/outages/ (the outage desk: AI checks of outage reports nobody had checked)

`scripts/outage-desk.mjs` plans unchecked outage reports for outage checkers (role `outage`, the "Outage checker" section of docs/jobs.md) in the research loop and is the only writer of `checks.json`. Three kinds of report, each with an id and a `key` (two reports with the same key are not checked within `outage_desk.recheck_hours` of each other):
- `power`: a power outage reported in the news (`data/grid/news.json`) that the grid desk does not take and no operator incident covers; id and key `pw-<news id>`.
- `internet`: a country's IODA signal (`data/context/ioda.json`) above `outage_desk.ioda_min_score` or with `ioda_min_signals` measurements; id `net-<cc>-<YYYYMMDD>`, key `net-<cc>`.
- `service`: a status-page lead (`kind: "status"`, scripts/osint.mjs) from the last `status_hours`; id and key `svc-<12 hex of the URL's SHA-1>`.
Thresholds: `outage_desk` in config/pipeline.json; workers: `flow.outage_workers`, `flow.outage_per_worker`.
- `checks.json`: `{<report id>: {kind, key, title (160), country, place, decision, summary (300), publisher (80), said_by (cyber_lead only: official or reported), cause (200; "cause not stated" for a confirmed report without one), figures (200, the source's own words), started_at, ended_at (UTC, only when a page states them), sources [https pages read, at most 8], read_depth, event_id (a confirmed internet or service outage on the map, category outage), checked_at, tries, by ("CyberView AI (a Claude model)"), final, plan_id}}`. `decision`: confirmed (the operator's, provider's or a government's own page, or two independent credible publishers; measurement and crowd-report sites never count), not_confirmed (checked again after recheck_hours, final after `max_tries`), cyber_lead (final). `apply` refuses an attack named outside a cyber_lead, a cyber_lead said_by official without an official page, a reported one whose summary does not say it is unconfirmed, and an event_id on a power report.
- A cyber_lead files ONE lead per report in `data/leads/<date>.jsonl` (`via: "outage-desk"`, `kind: "outage"`, `outage_id`, tier `gov` for official, `news` for reported, title "Outage linked to a cyberattack (official | reported, unconfirmed): <title>"); only the research loop turns it into an event, with its second review.
- Worker files: `data/outage-plan-<run>.json` (`plan_id, planned_at, run, batches [{batch, out, items}]`) and `data/outage-out-<run>-<batch>.json` (`plan_id, batch, results [...]`) are working state, deleted after each cycle. Leases are kind `outage`. `status.json` gets `last_outage_at` and `outage_note` (the research loop, every cycle the desk runs).
- Published: the build adds `verified {decision, summary, publisher, said_by, url, at, by}` to each `grid/news` item checked (`pw-<id>`) and to each IODA item of `context.ioda` with a check of its country in the last 48 hours; `site/data/health.json` gets `last_outage_at` and `outage_queue {waiting, checked_24h, confirmed_24h, cyber_leads_24h, oldest_min, by_kind}`.

## data/ics/advisories.json (industrial control system and OT advisories, no AI model)

Written only by `scripts/ics.mjs` (feeds.yml, every 2 hours; dials in config/ics.json). Sources: CISA ICS and ICS medical advisories (CSAF from cisagov/CSAF, CISA's RSS as fallback), Siemens ProductCERT, ABB (CSAF ROLIE feeds), Schneider Electric, Phoenix Contact via CERT@VDE (CSAF changes.csv), CERT@VDE, Moxa, Mitsubishi Electric (RSS). Every host's robots.txt is read first. Not read: Rockwell Automation (refuses automated readers), Honeywell (no machine-readable feed).
- `{updated_at, window_days, count, sources {<key>: {name, tier, at, ok, count, error, fetched, failed, waiting, listed, stale}}, advisories [...], filed {"<source>:<id>": <iso>}}`. A failing source keeps its last records (`stale`); `filed` remembers which advisories became leads (60 days).
- Each advisory: `{id (the publisher's: ICSA-26-323-03, SSA-566435, SEVD-2026-314-01, VDE-2026-150, MPSA-264520, MEL-2025-022), source, vendor (60), title (200), products [affected product names, 12], products_total, cves [200], cve_cvss {CVE: base score}, cvss (highest base score, v3 or v4; null when the feed gives none), cvss_version, cvss_vector, severity (C/H/M/L/N), cwes, exploited ("kev" a CVE is on CISA's KEV catalog | "active" the advisory or CISA's SSVC says exploited | "poc" public exploit | "none" the advisory says no known exploitation | ""), exploit_note (the advisory's own sentence, 200), kev_cves, sectors [CISA's critical infrastructure sectors], countries, hq, remediation [CSAF categories: vendor_fix, mitigation, workaround, none_available, no_fix_planned], fix, not_affected (the vendor says its products are not affected), url (the advisory's own web page or PDF, where the mitigations are), doc (the CSAF document), summary (300), published, updated, src_at (the index time it was read at), v (parser version)}`. Kept: first published within `window_days` (365), newest first, at most 3,000.
- Leads: an advisory first published within `lead_days` that is known exploited, exploited per the advisory, CVSS ≥ `lead_cvss` (9.0), or CVSS ≥ `sector_cvss` (8.0) in a `lifeline_sectors` sector, and not a not-affected notice, is filed once in `data/leads/<date>.jsonl` (`via: "ics"`, `kind: "advisory"`, tier `gov` for CISA and CERT@VDE, `vendor` for a vendor's own feed, title "<id> <vendor> industrial advisory: <title> (CVSS …; known exploited …; critical infrastructure: …)"). Only the research loop turns it into an event. `status.json` gets `last_ics_at`.
- Published: the build writes `site/data/ics.json` (`siteData()`: `{built_at, updated_at, window_days, sources, lifeline, advisories}`, every field cut to length, unsafe links dropped) for the Vulnerabilities page's Industrial view and the "Industrial advisory" box beside a CVE; a missing or broken file only leaves that view empty.

## data/snapshots/

`brief/<YYYY-MM-DD>.json` is a copy of that day's brief. `analysis/<YYYY-MM-DD>.json` is `{analysis, ripples}` as of that day's last analysis run. `tabletop/<YYYY-MM-DD>.json` is that week's exercise.

## Published archive (generated, site/data/archive/)

`index.json` (months with counts), `<YYYY-MM>.json` (full events of the month), `search.json` (compact rows: id, date, category, severity, status, title, org, country, cves, tags, actor), `events.jsonl` (everything), `kev.json` (every known-exploited entry).

## CVE corpus (scripts/cve.mjs; the Actions cache; published as site/data/cve/)

Every CVE in the official CVE List (CVEProject/cvelistV5), with CISA's enrichment, kept current hourly by `.github/workflows/cve.yml`. The working corpus (`cache/cve/<year>.jsonl` plus `state.json`) is kept in the GitHub Actions cache (key `cve-corpus-<run>`), never committed; the deploy restores the newest copy. The deploy runs `node scripts/cve.mjs site`.
Row: `id`, `state` (P published, R rejected), `pub`, `upd` (YYYY-MM-DD), `cvss`, `sev` (C H M L N), `ver` (CVSS version), `cwe`, `vendor`, `product`, `title` (160), `desc` (600), `cna` (assigner), `expl` (CISA SSVC exploitation: none, poc, active), `kev` (date CISA listed it), `epss`, `pct` (EPSS percentile).
Site files: `index.json` (counts, sources' freshness), `recent.json` (published or changed in the last 14 days, up to 3000), `<year>/<floor(n/1000)>.json` (`{fields, rows}` with rows as arrays in `fields` order).
New CVEs that are exploited per CISA, on KEV, or CVSS 9+ and published in the last 7 days are filed as leads (`via: cvelist`, `kind: exploited` or `cve`).

## SUPERSEDED: CVE database (the `cve-data` branch, generated by scripts/cve-db.mjs; no longer published)

Every CVE NVD has published, compact. Not on main: `.github/workflows/cve-db.yml` rebuilds the branch daily as ONE force-pushed commit and `pages.yml` copies it into the site.
`index.json`: `{ built_at, updated_at, total, years: [{ year, count, sev: {C,H,M,L,N}, files: [{ f: "2024/3.json.gz", from, to, n }] }], vendors: [[vendor, count] ...300] }`.
Each shard `<year>/<k>.json.gz` is a gzip JSON array of up to 4000 records of one year in number order; the shard for `CVE-YYYY-S` is the file whose `from <= S <= to`.
Record: `i` id, `p` published, `m` modified (YYYY-MM-DD), `s` status (A analyzed, R rejected, U other), `c` CVSS base score or null, `v` severity letter (C H M L N or ""), `a` attack vector (N A L P or ""), `w` up to 3 CWE ids, `vp` up to 4 "vendor:product", `d` description (300 characters).
Known-exploited flags are joined by the site from data/kev; EPSS is not stored (it changes daily for every record).
