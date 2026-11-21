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
| org, sector, country, place | | strings (`sector` is free text as the sources put it) |
| sectors | from 22 Nov 2026 | `{values, basis}`: who was hit, 1 to 4 keys from the fixed list, most affected first. The US CISA 16 critical infrastructure sectors: `chemical`, `commercial-facilities` (retail, hotels, venues, media), `communications`, `critical-manufacturing`, `dams`, `defense-industrial-base`, `emergency-services`, `energy`, `financial-services`, `food-agriculture`, `government-facilities`, `healthcare-public-health`, `information-technology`, `nuclear`, `transportation-systems`, `water-wastewater`; and `education`, `professional-services`, `manufacturing` (other manufacturing), `nonprofit`, `individuals`, `cross-sector` (no one sector: a flaw in widely used software, a law for everyone), `unknown` (both stand alone). `basis` is `stated` (a page in sources says it) or `inferred` (CyberView AI concluded it from what the sources say). The list is `scripts/lib/taxonomy.mjs`; checked by `checkClassification` in scripts/lib/validate.mjs |
| surface | from 22 Nov 2026 | `{value, basis}`: the way in (an incident) or the kind of system the flaw is in: `edge-appliance` (internet-facing VPN, firewall, gateway), `web-app`, `email-phishing`, `endpoint` (computers, servers, browsers), `cloud-saas`, `supply-chain` (supplier, MSP, package, update channel), `ot-ics`, `identity` (credentials, MFA, SSO), `mobile`, `physical-insider`, `unknown`; `basis` as for sectors. Without both fields the analysis views, trends and status coverage fall back to keywords and say so; `node scripts/classify.mjs` backfills older events |
| lat, lng | | numbers, or null when unknown |
| geo_basis | | what the pin location is based on |
| pin_type | | `victim`, `hq`, `agency`, `actor`, `researcher`, `country`, `none` |
| actor | | as named by the sources, else empty |
| summary | | 2 to 4 sentences, at most 75 words |
| plain | | non-technical, at most 240 characters |
| exec | | business significance, at most 170 characters |
| action | | one instruction for a defender, at most 280 characters; says whose advice it is, starts with "General advice:" when it is CyberView's own, or is "No action needed; for awareness." (`action-unsourced`) |
| impact | | free text |
| records_affected | | number |
| products, attack, cves | | lists of strings; cves match `CVE-YYYY-NNNN` |
| tags | | list from: ransomware, data-breach, supply-chain, zero-day, ddos, espionage, critical-infrastructure, ai-enabled, third-party, phishing, insider, hacktivism, ot-ics, cloud, identity, fraud, takedown, regulation, funding, acquisition, malware, rce, poc-public. Sector, country and product go in their own fields, not in tags; the list is defined as `TAGS` in `scripts/lib/validate.mjs` |
| aliases | | optional list of the event's names in other scripts or languages (e.g. 富岳 for Fugaku), max 8 of up to 60 characters; lets scripts/triage.mjs match retellings in other languages to this event |
| cve_meta | | list of `{id, cvss, epss, kev, kev_due}` |
| sources | | list of `{name, url, published}`; url is the specific page read; `published` (YYYY-MM-DD) is the page's own date, required on the first source of an incident, outage or enforcement first seen from 22 November 2026 (`date-is-publication`, `source-published-missing` in scripts/lib/validate.mjs) |
| evidence | | list of at most 12 `{url, quote}`: the sentence of a page in `sources` that states each figure (10 or more, money, percentages) in title, summary, plain, exec, action or impact, and records_affected, and the time of day in `occurred_at`; copied word for word, at most 240 characters. Required for those from 22 November 2026 (`figure-no-evidence`, `figure-qualifier`, `occurred-no-evidence`); the second review checks each quote against its page. Not shown on the site |
| source_tier | | `primary`, `established`, `aggregator` |
| validation | | `{state, checked_at, note}`; state is `corroborated`, `single_source`, `unconfirmed_claim`, `disputed`, `source_unreachable` |
| report | | review of an original document: `{publisher, publisher_type (government or vendor), doc_id, published, key_findings[], recommendations[], iocs_available, read_depth (full, summary, secondary), url}` |
| attribution | | `{actor, origin_country, lat, lng, by, by_type, url}`: who a government (`by_type` `government`) or the investigating firm (`investigator`) says did it, where the actor is said to be based (lat, lng of that country's capital) and the https page where the attribution is made. Drawn as a dashed, labelled arc from the origin to the victim. Never from attacker boasts or press speculation. |
| links | | `[{to, rel, url}]`: other events a source says this one is connected to (`to` is an event id on file, `rel` at most 60 characters such as "customer of breached supplier", `url` the page that states it). Drawn as arcs on the globe. |
| hunt | | `[{name, format, url, publisher}]`: indicator files and detection rules the original document publishes (format: stix, sigma, yara, snort, suricata, kql, spl, csv, json, misp, openioc, text, pdf). Links only; indicators themselves are never stored. Shown in the workbench's hunt pack. |
| review | | `{state, at, first_at, note, flags[]}` (`at` the latest review, `first_at` the first one, kept through re-reviews of updates): the second review by a different agent (the review desk), written only by `scripts/review.mjs`: `passed`, `corrected` (the reviewer fixed the record) or `flagged` (a problem remains; validation becomes `disputed` until verify settles it). A corrected or flagged review also carries `categories`, the correction types read from its note (`ERROR_TYPES` in scripts/review.mjs; `node scripts/review.mjs errors` counts them). |
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

## Breach notices (scripts/breaches.mjs; leads of kind `breach-notice`)

A notice an organisation filed with a regulator, read from the register that publishes it, filed as one line in `data/leads/<date>.jsonl`: `seen_at, source` (the regulator, e.g. "California Attorney General"), `tier: "gov"` (an official filing), `via` (`breach-ca`, `breach-wa`, `breach-ia`, `breach-ico`, `breach-sec`), `kind: "breach-notice"`, `title` ("<organisation>: data breach notification filed with <regulator>"; ICO: "ICO <action>: <organisation>: <first sentence>"; SEC: "<company>: Form 8-K Item 1.05 ..."), `url` (the regulator's own page or file for that notice: the one to cite), `published` (the day the register posted it), `summary` (300; the law it was filed under, dates and figures the register states, and "Matches event <id> on file" when it does), `lang: "en"`, `country`, `org` (the filer's name in lower case without legal form, used to join the same breach across registers). Not a bare database row: the backlog rules never close it as one, and fuse.mjs scores it as a government source; it never heads the "being checked" list (its headline is the collector's). Each register's health is in `data/breaches.json`: `checked_at, sources {<via>: {ok, error, items, new, at, last_ok, idle}}` (`idle`: not connected, e.g. the SEC until `config/site.json` contact_email is set); `status.json` gets `last_breaches_at` and `last_breaches_new`.

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

Tracked by `scripts/grid.mjs collect` from the operators' own public feeds (Hydro-Québec, BC Hydro, UK Power Networks, Eskom, ERCOT, AEMO) and the source files in `scripts/grid-sources/` (utilities, system operators, and government agencies' statewide or national counts: Pennsylvania PEMA, Maryland MDEM, Chile SEC via SENAPRED; Japan's OCCTO reserve level); the full contract is `swarm/handoff/grid-contract.md`. One writer per file. An item may carry `customers_band` (at most 30 characters) when the source states a band or a ceiling rather than a count (e.g. "32,767 or more" for SENAPRED's 16-bit field); `customers` is then the floor.
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
- `service`: a status-page lead (`kind: "status"`, scripts/status-pages.mjs via scripts/osint.mjs) from the last `status_hours` (filed or started); id and key `svc-<12 hex of the URL's SHA-1>`; queued by the lead's `priority` (the provider's tier, 1 the biggest; none counts as 3), then newest.
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

## data/services/ (providers' own status pages: outage reports, never cyber events)

`scripts/status-pages.mjs` (no AI model; run as osint.mjs's `cloud-status` collector) reads the pages in `config/status-pages.json` (each at most every `poll_minutes`) and writes `status.json`:
- `updated_at`, `providers {<id>: {name, ok, error, at, last_ok, incidents, qualifying, new}}`, `cache {<id>: [incident]}` (the qualifying or open incidents of each page's last read), `incidents [incident + {provider, name, category, tier, page, minutes, why}]` (qualifying, open or resolved within `show_resolved_hours`; open first, then by tier, at most 60).
- incident: `{id, title, impact (the provider's own words), level (critical | major | minor | none | "" when not stated), components [], status, started_at, resolved_at, mitigated_at (moved to monitoring), updated_at, url, maintenance}`.
- An incident qualifies when the provider states a major or critical impact, or it lasts `min_minutes` or more (to its resolution; while monitoring, to the move to monitoring; while open, to now), or, on a page that states neither impact nor state, the provider's own title says the service is out. Maintenance, notices and a stated impact "none" never qualify.
- A qualifying incident files ONE lead in `data/leads/<date>.jsonl`: `kind: "status"`, `via: "cloud-status"`, `tier: "vendor"`, `source: "<provider> status"`, title "<provider> status page: <incident title>", the summary with the impact as stated, components, times and "not a cyber event", plus `status_id` ("<provider id>:<incident id>", deduped across polls), `priority` (the provider's tier) and `category`.
- Published: `docs["services/status"] {updated_at, pages, pages_ok, items [{provider, name, category, page, title, impact, level, components, status, started_at, resolved_at, minutes, url, verified}]}`, `verified` being the outage desk's check of `svc-<id>` when there is one; the map page lists them under Service status in the layers panel, never drawn.

## data/claims/ (the claims desk: AI checks of ransomware and extortion leak-site claims)

`scripts/claims-desk.mjs` plans leak-site claims (leads of kind `claim`, `scripts/osint.mjs`) for claims checkers (role `claims`, the "Claims checker" section of docs/jobs.md) in the research loop and is the only writer of `checks.json`. One item per group and victim (the title "Claim: <group> lists <victim> (<CC>) on its leak site"), id and key `cl-<12 hex of the SHA-1 of the group and the victim's core name>`. Left out: masked victims (private people, "J... W..."), a victim named by an incident event dated within `claims_desk.match_days`, and a claim never checked that is older than `new_hours`. Order: notability (critical sector, government or health by sector or name; other leads that name the victim in an incident headline; the group's confirmed events and confirmed checks; a company suffix), then newest. Settings: `claims_desk` in config/pipeline.json; workers: `flow.claims_workers`, `flow.claims_per_worker`.
- `checks.json`: `{<claim id>: {key, group (60), claimed_victim (160, as listed), victim (160, as its own pages name it), country, sector, claimed_at (UTC), decision, summary (300), confirmed_by (120, confirmed_by_victim only), victim_site (its own domain), sources [https pages read, at most 8], read_depth, event_id, checked_at, tries, by ("CyberView AI (a Claude model)"), final, plan_id}}`. `decision`: `confirmed_by_victim` (the organisation's own page, a regulator's or a government's page; `event_id` names a status confirmed incident that cites that page and names the group's claim), `reported` (two independent publishers; `event_id` names a status claimed, severity 1 incident naming the group's claim), `denied` (optional `event_id` of a claimed event whose summary carries the denial), `unconfirmed` (no event; checked again after `recheck_hours` until `max_tries`), `not_found` (no event). All but unconfirmed are final; the follow-up desk takes a claimed event from there.
- `apply` refuses: leak sites, `.onion` addresses, claim trackers (ransomware.live and the like), forums and social media as sources (`LEAK_HOST`); sources that are not https article pages (`badSource`); confirmed_by_victim without a victim, regulator or government page; any e-mail address, phone or identity number, card or account number, file name, password, sample, screenshot, file tree, `.onion` address or link in summary, victim or confirmed_by (`DATA_CONTENT`); an event that cites a leak site or tracker.
- Worker files: `data/claims-plan-<run>.json` (`plan_id, planned_at, run, batches [{batch, out, items}]`) and `data/claims-out-<run>-<batch>.json` (`plan_id, batch, results [...]`) are working state, deleted after each cycle. Leases are kind `claim`. `status.json` gets `last_claims_at` and `claims_note` (the research loop, every cycle the desk runs).
- Published: the build adds `claim_check {decision, summary, group, claimed_at, confirmed_by, url, at, by}` (scripts/claims-desk.mjs `siteCheck`, the newest check naming the event) to that event in the bundle and the archive; `site/data/health.json` gets `last_claims_at` and `claims_queue {waiting, checked_24h, confirmed_24h, reported_24h, denied_24h, unconfirmed_24h, not_found_24h, oldest_min}`.

## data/scams/warnings.json (official scam and phishing warnings: never cyber events)

Written only by `scripts/scams.mjs` (no AI model; feeds.yml every 2 hours) from the issuers in `config/scams.json` (each: `key, name, kind` government|police|regulator|cert|consumer, `country` ISO 3166-1 alpha-2, `lang, format` rss|hkma, `url, home, hosts` (the issuer's own hosts), `filter` (the title must name a scam), `url_match`, `title_strip`).
- `{updated_at, types_by: "keyword", types [the 8 keys], sources {<key>: {name, country, lang, home, hosts, ok, error, items, at, last_ok, fails}}, items [warning]}`.
- warning: `{id (<issuer>-<12 hex of the URL's SHA-1>), issuer, issuer_name, country, lang, title (220, the issuer's own words and language), published (UTC, "" when the feed gives none), first_seen, url (https, on the issuer's hosts, tracking parameters dropped), types [impersonation|investment|delivery|bank_sms|tech_support|romance|job|crypto] (scripts/scams.mjs TYPES, a fixed keyword map; can be empty), types_by: "keyword", incident (true when the text names a breach or other cyber incident), lead_at}`. Items published in the last `max_age_days` are added; kept `keep_days`, at most `per_issuer` each; a failing issuer keeps its earlier items.
- A warning with `incident` files ONE lead in `data/leads/<date>.jsonl` (`via: "scams"`, `kind: "advisory"`, tier `gov`); only the research loop turns it into an event. `status.json` gets `last_scams_at`, `scams_sources_ok`, `scams_sources`.
- Published as `docs["scams/warnings"]` `{updated_at, types_by, issuers {<key>: {name, kind, country, lang, home, hosts, ok, error, last_ok}}, items}`; the map page lists them in the Insights tab (`#scams`), links only to the issuer's own https hosts, labels the type as keyword-assigned, and never draws or counts them as events.

## data/snapshots/

`brief/<YYYY-MM-DD>.json` is a copy of that day's brief. `analysis/<YYYY-MM-DD>.json` is `{analysis, ripples}` as of that day's last analysis run. `tabletop/<YYYY-MM-DD>.json` is that week's exercise.

## Published archive (generated, site/data/archive/)

`index.json` (months with counts), `<YYYY-MM>.json` (full events of the month), `search.json` (compact rows: id, date, category, severity, status, title, org, country, cves, tags, actor), `events.jsonl` (everything), `kev.json` (every known-exploited entry).

## Threat actor profiles (generated, site/data/actors.json; scripts/actors.mjs, no AI model)

Built at every build from the events on file (duplicates left out); nothing is stored on the data branch. `built_at, attack_version, attack_notice, counts {profiles, checked, claims_only, attack_matched}, profiles[]`, each:
`id` (link: actors.html#a=<id>), `name` (the name CyberView's events use most), `attack {id, name, url}` (MITRE ATT&CK group, or null), `aliases[{name, basis (attack or event), source, url | event_id}]`, `attributed[{event_id, title, date, status, by, by_type (government or investigator), url, origin_country, note}]` (from the event's `attribution`), `named[{event_id, title, date, status, as_written}]` (from the event's `actor`: the sources' words), `claimed[{event_id, title, date, org, as_written}]` (status `claimed`, or the actor text says "claimed": never counted below), `origins[]`, `sectors[{k, n}]`, `countries[{k, n}]`, `cves[{id, event_ids}]`, `advisories[{publisher, doc_id, url, event_id}]` (government `report`s and government attributions), `related[]` (names an event joined that ATT&CK keeps apart), `ambiguous[]` (names ATT&CK lists under two groups), `attack_namesake` (an ATT&CK group sharing the name of a group seen only in claims; not merged), `first_seen, last_seen, claims_only`.
Merge rules: same name in another spelling; ATT&CK lists it as an alias; one event's actor text states it ("A / B", "A (also B, C)"). Never on similarity alone.

`config/attack-groups.json`: MITRE ATT&CK group names, aliases and IDs only (no descriptions), with MITRE's notice; refresh with `node scripts/actors.mjs attack` (keyless, raw.githubusercontent.com) and commit through a pull request.

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
