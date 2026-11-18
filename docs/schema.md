# Data schema

All files are UTF-8 JSON. The build (`scripts/build.mjs`) rejects files that break the required rules and warns on the rest.

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
| tags | | list from: ransomware, data-breach, supply-chain, zero-day, ddos, espionage, critical-infrastructure, ai-enabled, third-party, phishing, insider, hacktivism, ot-ics, cloud, identity, fraud, takedown, regulation, funding, acquisition |
| cve_meta | | list of `{id, cvss, epss, kev, kev_due}` |
| sources | | list of `{name, url}`; url is the specific page read |
| source_tier | | `primary`, `established`, `aggregator` |
| validation | | `{state, checked_at, note}`; state is `corroborated`, `single_source`, `unconfirmed_claim`, `disputed`, `source_unreachable` |
| report | | review of an original document: `{publisher, publisher_type (government or vendor), doc_id, published, key_findings[], recommendations[], iocs_available, read_depth (full, summary, secondary), url}` |
| duplicate_of | | id of the richer record; the build leaves this one out |
| first_seen, updated_at, qa_checked_at | | ISO times |

## data/kev/&lt;CVE&gt;.json

`cve, vendor, product, name, added (YYYY-MM-DD), due (YYYY-MM-DD), ransomware (bool), desc (plain, at most 260 characters), cvss (number), epss (0 to 1)`. Entries added in the last 45 days are published.

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

## data/snapshots/

`brief/<YYYY-MM-DD>.json` is a copy of that day's brief. `analysis/<YYYY-MM-DD>.json` is `{analysis, ripples}` as of that day's last analysis run.

## Published archive (generated, site/data/archive/)

`index.json` (months with counts), `<YYYY-MM>.json` (full events of the month), `search.json` (compact rows: id, date, category, severity, status, title, org, country, cves, tags, actor), `events.jsonl` (everything), `kev.json` (every known-exploited entry).
