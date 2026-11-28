# Website software matching: every CVE, by product and version

Date: 2026-11-27. Status: draft for the owner's approval. Scope: the website's software and version matching only.

For reviewers: read this file first (why, scope, what exists, approaches, order of work), then
`2026-11-27-match-schema.md` (exact data model, version rules, verdicts, the 99% accuracy proof in section 12, running and
billing in section 13). Everything measured here was measured on 2026-11-27 from the repository and the data branch.

## Why

The Vulnerabilities page lets a visitor load a software list (name and version) and see which flaws apply. The owner wants
that list checked against **every CVE** ("we need all CVEs"), not the ~170 it is checked against today.

NVD used to do the product-and-version work for everyone: one standard product code (CPE) per product and affected-version
ranges per CVE. Since 15 April 2026 NIST enriches only CISA known-exploited CVEs, software used by the US government and
"critical software"; its pre-March 2026 backlog (about 29,000 CVEs) is "Not Scheduled". CyberView takes its ranges only from
NVD, so most new CVEs cannot be matched by version. CyberView will do that work itself, from data it already pulls.

Scope (owner, 2026-11-27): only the **My software** feature matches, and the work is split as "back end builds, browser
looks up": everything built from CVE data (product dictionary, ranges, rules) is made on GitHub Actions and published as
static files; the browser only parses the client's list and looks it up, so client data never reaches CyberView. The exact
match schema (data model, version schemes, resolution order, verdicts, reason codes, explanations, tests) is in
`2026-11-27-match-schema.md`.

The Scanner desktop app handles everything about IPs, ports and network detection. It is out of scope, except that it reuses
`site/workbench-lib.js`, so fixes to the shared matcher reach it automatically.

## What exists today (measured 2026-11-27)

- A loaded list is checked against: the CISA known-exploited entries on file (92; 70 have NVD ranges), the 80 most recent
  flaws from events (product name only, never version), and in the All CVEs view only the rows the visitor opens
  (`mineMatch` in `site/vulnerabilities.js`). It is never checked against the 433,336 CVEs in the corpus.
- Ranges come only from NVD: `aff` in the corpus (`scripts/cve.mjs nvd`) and `affected` on KEV files (`scripts/feeds.mjs`).
- `compact()` in `scripts/lib/cve.mjs` keeps only the first vendor and product of each CVE record and drops its version
  lists and CISA's additions.
- `W.cmp` orders `9.8p1` before `9.8` (wrong). The fix exists only as `engine-patches/0003` in cyberview-scanner-desktop.
- Product names are fuzzy-matched word by word (`W.nameHit`); there is no dictionary or alias list.

Sample of 3,742 published CVE records (CVE List, blocks 2025-5xxx, 2025-6xxx, 2026-1xxx, 2026-2xxx):

| In the record itself | Share |
|---|---|
| Affected versions from the assigner (CNA) | 96% (47% ranges, 49% exact versions) |
| CVSS from the assigner / from CISA only | 94% / 6% |
| CWE | 99% |
| A CPE code (assigner 10%, CISA 2%) | 12% |
| A product name but no usable versions | 2.4% |

Version types written on version rows: none given 5,761; semver 1,673; custom 1,272; rpm 1,108; python 61; maven 27;
cpe 24; date 19. Product naming: 2,447 distinct vendor+product strings across 3,742 CVEs, 1,653 seen only once, many with
versions or platforms inside the name ("Red Hat Satellite 6.17 for RHEL 9").

The hard part is not scores or versions (the records carry them); it is one name per product and comparing versions across
numbering styles.

## Goals

1. Every published CVE can be matched by product and version wherever any source states versions.
2. A visitor's list is checked against all CVEs, in the browser; the list never leaves the browser (CLAUDE.md rule 11).
3. One matcher (`site/workbench-lib.js`) for the page and the Scanner.
4. 99% accurate (owner, 2026-11-27): every decisive verdict type proven at least 99% correct at 95% confidence, false
   "not affected" at most 0.1%; anything unproven shows as "check". How it is proven and enforced: match schema section 12.

## Non-goals

- Anything about IPs, ports or network detection (the Scanner app), and the desktop app's screens.
- Matching events, actors and the Library to each other (parked; see the Whiteboard "CyberView matching engine map").
- CyberView's own CVSS scores. Scores stay the assigner's, CISA's or NVD's as given; the existing CyberView rating stays.

## Anti-goals (a failure even if it works)

- Any AI model touching client data (owner, 2026-11-27: "we cannot use our AI to view clients' environment data"; "we can
  use AI if it's not part of the processing of clients' data"). Verdicts are computed by code in the browser. AI works
  only on the back end on public CVE data (alias proposals, reading vendor advisories for missing ranges, labelling the
  gold set), always with a second independent check; see the match schema.
- A visitor's list sent or uploaded anywhere.
- A version range no source states.
- "Not affected" when the matcher cannot tell. Unknown is always "check", never "clear".

## Approaches considered

- **A. Rules only.** Chosen first on 2026-11-27, then widened to B for back-end work on public data only. Free, predictable and explainable; names the rules cannot
  resolve stay unmatched and show as "check by hand". Coverage is measured in the test (section 6).
- **B. Rules first, AI on the back end for what rules cannot resolve, with a second check.** Chosen by the owner on
  2026-11-27: AI never processes client data.
- **C. Paid enrichment (VulnCheck and the like).** Rejected: CyberView brings the value itself. The free OSV database is
  used as a source for open-source packages under A and B.

## Design

### 1. Version comparison (`site/workbench-lib.js`)

- Bring in the `cmp` change and its tests from desktop `engine-patches/0003` (patch letters: `9.8p1 > 9.8`,
  `1.0.2k > 1.0.2`; rc, beta and alpha before the release) and the range-cap change in `scripts/lib/cve.mjs` from `0004`.
  Nothing else from the desktop patches comes over.
- Compare by numbering style, from the row's `versionType`: `semver` (pre-release rules), `rpm` (epoch:version-release,
  rpmvercmp order), `deb` (Debian order, as in desktop `0006`'s distro.mjs), `python` (PEP 440), `maven`
  (ComparableVersion order), `date`; anything else uses today's general order. When the style is unknown and the two
  strings cannot be ordered with confidence, `inRange` returns `null` (shown as "check").
- Read CVE JSON 5 version rows fully: `version` with `lessThan` / `lessThanOrEqual`, `status` affected / unaffected,
  `changes`, and the entry's `defaultStatus`.

### 2. The corpus keeps the full affected data (`scripts/lib/cve.mjs`)

- `compact()` keeps every affected entry of the assigner and of CISA (vendor, product, packageName, collectionURL, cpes,
  version rows with their type, defaultStatus), at most 60 ranges per CVE as today. `CORPUS_VERSION` goes to 3, so the
  workflow rebuilds the corpus once.
- Every range carries its source: `cna`, `adp` (CISA), `nvd` or `advisory` (vendor CSAF or OSV).
- NVD's ranges stay. All sources are kept side by side. A version counts as affected when any source says so, and a
  disagreement between sources is recorded and counted in the test (section 6).

### 3. Product dictionary (new: `scripts/products.mjs`, `data/products/`)

- One id per product, CPE-style `vendor:product` (lowercase, `_` for spaces); open-source packages use package URLs
  (`pkg:npm/...`, `pkg:pypi/...`, `pkg:maven/...`) from `packageName` and `collectionURL`.
- Seeds: NVD's product list (CPE dictionary, read by the existing NVD step), CVE records that give both a name and a CPE
  (each teaches an alias), the Scanner's detection rules that carry a `cpe` (`scanner/lib/fp-apps2.mjs` and the rest),
  CISA KEV vendor and product names, and vendor names in PSIRT and ICS advisories.
- Rules first: case and punctuation, vendor aliases ("Red Hat, Inc." is "redhat"), version and platform words removed
  from product names ("6.17 for RHEL 9" is a version and a platform, not part of the name).
- What the rules cannot resolve stays unresolved: its CVEs are matched by name only and shown as "check by hand". Each
  alias records its basis: `rule`, `cpe`, `scanner` or `package`. Unresolved names are counted and listed for the owner,
  so the rules can be extended by hand.

### 4. Filling gaps without AI

- CVEs with a product but no usable versions (2.4% of the sample): read the vendor's CSAF advisory linked from the record
  (a structured format with product trees and fixed versions) and, for open-source packages, OSV. Both are parsed by code.
  When neither exists, the CVE stays a name-only "check by hand".

### 5. What the site publishes (`site/data/products/`)

- `index.json`: every product id with its aliases, for resolving a visitor's names in the browser.
- One file per product: its CVE ids, ranges with sources, and the fields the page ranks by (CVSS, KEV, EPSS, CISA
  exploitation status).
- Page flow: parse the list (`W.parseInventory`), resolve each item to product ids (exact alias first, then `W.nameHit`),
  download only those products' files, match (`W.match`), rank (`W.score`). The page says how many CVEs were checked and
  lists the items it could not recognise as "check by hand".
- The KEV and recent-flaw lists stay as they are and are checked first, so the page answers quickly.

### 6. Test before going live

- Ground truth: CVEs where NVD has ranges (most CVEs before 2024, and all KEV entries). For a sample of 1,000 such CVEs
  and versions on both sides of each range, compare CyberView's verdict from the non-NVD sources with NVD's. Report:
  agreement, false "clear" (the serious one), false "affected", and "check" rates.
- Run the Scanner's lab fixtures through the new matcher too, so the shared code does not regress there.
- The result goes to the owner before the page switches to the new lookup.

### 7. Rules and docs (in the same pull requests)

- CLAUDE.md rule 11: version ranges come from NVD, the CVE record, CISA and vendor advisories, each labelled with its
  source; no AI model takes part in matching.
- `docs/layout.md`, `docs/schema.md`, `config/about.json`, `README.md` and unit tests, as `node scripts/docs-check.mjs`
  and `npm run ci` require.

## Order of work

1. Version comparison fixes and numbering styles (section 1).
2. The corpus keeps the full affected data (section 2).
3. Product dictionary by rules (section 3), gap filling from CSAF and OSV (section 4), and the test (section 6).
4. Published lookup and the page change (section 5), after the owner sees the test report.

## Decided by the owner

- Only the My software feature matches; back end builds, browser looks up (2026-11-27).
- The most detailed match schema possible (2026-11-27): `2026-11-27-match-schema.md`.
- 99% accurate; architecture and schema only for now, no building (2026-11-27).

- The website's software and version matching only; the Scanner app handles IPs and networks; desktop app features stay
  out (2026-11-27).
- All CVEs (2026-11-27).
- No AI on client data; AI allowed on the back end on public data, with a second check (2026-11-27).
- Test and report before building the live switch.

## Left to the builder (marked as the builder's calls)

- Ranges from different sources are kept side by side; "affected" when any source says so (builder's call).
- Exact numbering styles beyond the list above, and the per-product file layout and size limits (builder's call).
- Rejected CVEs are left out of the lookup (builder's call).
- A visitor item that resolves to no product shows as "check by hand", never hidden (builder's call).
- NVD's product list comes from its Products API, read alongside the existing NVD step with the same paging and pauses
  (builder's call).
- An entry with `defaultStatus: affected` and no version rows means every version is affected, as desktop `0004` already
  treats CISA's all-versions entries; it is a finding only when the vendor and product resolve exactly (builder's call).
- GitHub Pages limits a site to 1 GB: per-product files are grouped into shards when the product count makes single files
  impractical, and the alias index is split by first letter if it passes about 2 MB compressed; both measured in the test
  (builder's call).
