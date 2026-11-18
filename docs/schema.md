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
| attribution | | `{actor, origin_country, lat, lng, by, by_type, url}`: who a government (`by_type` `government`) or the investigating firm (`investigator`) says did it, where the actor is said to be based (lat, lng of that country's capital) and the https page where the attribution is made. Drawn as a dashed, labelled arc from the origin to the victim. Never from attacker boasts or press speculation. |
| links | | `[{to, rel, url}]`: other events a source says this one is connected to (`to` is an event id on file, `rel` at most 60 characters such as "customer of breached supplier", `url` the page that states it). Drawn as arcs on the globe. |
| hunt | | `[{name, format, url, publisher}]`: indicator files and detection rules the original document publishes (format: stix, sigma, yara, snort, suricata, kql, spl, csv, json, misp, openioc, text, pdf). Links only; indicators themselves are never stored. Shown in the workbench's hunt pack. |
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

## data/snapshots/

`brief/<YYYY-MM-DD>.json` is a copy of that day's brief. `analysis/<YYYY-MM-DD>.json` is `{analysis, ripples}` as of that day's last analysis run. `tabletop/<YYYY-MM-DD>.json` is that week's exercise.

## Published archive (generated, site/data/archive/)

`index.json` (months with counts), `<YYYY-MM>.json` (full events of the month), `search.json` (compact rows: id, date, category, severity, status, title, org, country, cves, tags, actor), `events.jsonl` (everything), `kev.json` (every known-exploited entry).
