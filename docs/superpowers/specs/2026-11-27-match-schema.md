# Match schema: My software against every CVE

Date: 2026-11-27. Status: draft for the owner's approval. Companion to
`2026-11-27-website-software-matching-design.md`, which says why and in what order; this file says exactly how a software
list item becomes a verdict on a CVE.

## 0. Ground rules (owner, 2026-11-27)

- Only the **My software** feature matches: the My software tab, and the places that use its list ("Affects my software",
  "Only flaws on my software list"). Nothing else on the site matches lists.
- **Back end builds, browser looks up.** Everything that needs the CVE data (product dictionary, version ranges, rules,
  compiled lookups) is built on GitHub Actions and published as static files. The browser parses the client's list,
  resolves names, downloads only the product files it needs and decides verdicts locally. The list never leaves the
  browser (CLAUDE.md rule 11; `legal/privacy.html`).
- **No AI model ever touches client data** (owner, 2026-11-27: "we can use AI if it's not part of the processing of
  clients' data"). The browser has no AI, and every verdict is computed by code from published data, so it can be
  explained and reproduced. AI is allowed only on the back end, on public CVE data, for three jobs: proposing aliases the
  rules cannot make (3.4 step 8), reading vendor advisories for missing ranges (4.6), and labelling the gold set (12.4).
  Every AI output is checked by a second, independent run before use, and AI-made data is its own stratum that must earn
  trust like any other source (12.3c).
- **Never "not affected" when unsure.** Any doubt is a `check` verdict with a reason code.
- **Never a range no source states.** Ranges are copied from sources or parsed from their structured fields; text parsing
  is allowed only for the narrow patterns in section 5.4 and is flagged.

## 1. Words used here

- **Source**: where a range comes from: `cna` (the CVE record's assigner), `adp` (CISA's additions to the CVE record),
  `nvd` (NVD's CPE configurations), `csaf` (a vendor's CSAF advisory), `osv` (the OSV database), `kev` (CISA's
  known-exploited entry, product level only), `ai` (a vendor advisory read by the back-end AI desk and approved by a
  second run, 4.6).
- **Product id**: CyberView's one name for a product (section 3).
- **Item**: one row of a client's list after parsing (section 6).
- **Range**: one statement "these versions of this product are affected / not affected by this CVE" (section 4).
- **Scheme**: a version numbering style with its own ordering rules (section 5).
- **Verdict**: the answer for one item and one CVE (section 8).

## 2. What the back end publishes

All under `site/data/match/`, rebuilt by the deploy from the corpus (`cache/cve`) and `data/products/`. Every file
carries `v` (schema version) and `built_at`; the browser refuses a file whose `v` it does not know and says so.

| File | Content | Loaded |
|---|---|---|
| `meta.json` | schema version, counts, build time, source freshness (CVE List, NVD, CSAF, OSV, KEV), alias index shard list, product shard list, coverage figures (section 11) | always, first |
| `alias/<k>.json` | alias index shard `k` (first character of the normalised key, `0` for digits, `_` for other) | per shard needed by the list |
| `purl.json` | package-URL type and namespace/name to product id | when the list has purls or package lines |
| `cpe.json` | CPE `vendor:product` to product id | when the list has CPEs |
| `p/<shard>.json` | product records and their ranges (section 4), shard = first 2 hex of SHA-1 of the product id | only shards of resolved products |
| `cve/<year>/<n>.json` | existing corpus lookup files (scores, KEV, EPSS, CISA exploitation) | only for CVEs that produced a verdict |
| `schemes.json` | per product: default scheme, platform vocabulary, edition vocabulary | with `meta.json` |
| `unresolved.json` | not published; written to `data/products/unresolved.json` for the owner (section 3.6) | never in browser |

Size limits (checked in CI, build fails when passed): any one file 5 MB uncompressed; alias shards 2 MB; product shards
2 MB. A shard over the limit is split by the next hex digit and listed in `meta.json`.

## 3. Product identity

### 3.1 Product record

```jsonc
{
  "id": "openbsd:openssh",            // CPE-style vendor:product, lowercase, [a-z0-9_.-], ':' between
  "name": "OpenSSH",                   // display name
  "vendor": "OpenBSD",                 // display vendor
  "kind": "application",               // application | os | firmware | hardware | library | package | service
  "cpe": ["openbsd:openssh"],          // every CPE vendor:product this id covers (renames, acquisitions)
  "purl": ["pkg:generic/openssh"],     // package URLs without version, when a package exists
  "scheme": "openssh",                 // default scheme (section 5); a range's own versionType wins
  "platforms": [],                     // platform vocabulary for this product (section 7.2), empty = not platform-split
  "editions": [],                      // edition vocabulary (section 7.3)
  "family": null,                      // parent id for split products ("microsoft:windows_10" for 22H2 builds)
  "successor": null,                   // id this product was renamed to (e.g. vmware:workspace_one_uem -> omnissa:...)
  "basis": ["cpe", "scanner"]          // how the record was established (3.4)
}
```

### 3.2 Alias record (in `alias/<k>.json`)

```jsonc
{ "k": "openssh",                      // normalised key (3.3)
  "to": [{ "id": "openbsd:openssh", "vendor_key": "openbsd", "strength": "A", "basis": "cpe" }] }
```

`strength`: `A` exact identifier (purl, CPE, or an alias proven by a record that gives both name and CPE); `B` rule-made
alias with the vendor present; `C` rule-made alias, product words only. One key can point to several ids; the vendor
decides between them (6.3), and when it cannot, the item is ambiguous (verdict `check`, reason `AMBIGUOUS_PRODUCT`).

### 3.3 Name normalisation (identical code at build and in the browser: `W.normName`)

Applied in this order, each step tested:

1. Unicode NFKD, accents dropped, lowercase.
2. Trademark marks removed (`®`, `™`, `(r)`, `(tm)`).
3. Legal forms removed from vendors: inc, inc., corp, corporation, co, ltd, limited, llc, gmbh, ag, sa, s.a., bv, nv,
   plc, pty, srl, oy, ab, kk, the leading "the".
4. Vendor alias table applied (`config/match/vendors.json`, reviewed by hand): e.g. "red hat" → `redhat`, "the apache
   software foundation" / "apache software foundation" → `apache`, "microsoft corporation" → `microsoft`, "palo alto
   networks" → `paloaltonetworks`, "f5 networks" / "f5, inc." → `f5`, "broadcom" + VMware products → `vmware` (with
   `successor` handling).
5. Version, build and platform tokens cut from the product name into separate fields (7.1): `version 22h2`, `6.17`,
   `for rhel 9`, `for x64-based systems`, `(64-bit)`, `x86_64`, `amd64`, `arm64`, `(x64)`, `(x86)`, language tags
   (`en-us`, `(english)`), edition words from the product's edition vocabulary.
6. The vendor name repeated at the start of the product removed ("Microsoft Edge" with vendor Microsoft → "edge").
7. Punctuation to single spaces; `+` kept as `plus`, `#` as `sharp`, `.net` as `dotnet`.
8. The key is the remaining words joined by `_`.

### 3.4 How the dictionary is built (back end, `scripts/products.mjs`, no AI)

Evidence is applied in this order; a later rule never overrides an earlier, stronger one:

1. **NVD CPE dictionary** (Products API): every `vendor:product`, titles in English as aliases (strength A).
2. **CVE records with both a name and a CPE** (CNA or ADP `cpes`): the record's vendor/product name becomes an alias of
   the CPE's product (strength A, basis `cpe`).
3. **Scanner detection rules** that carry a `cpe` (`scanner/lib/fp-*.mjs`): their vendor/product labels (strength A).
4. **Package identities**: `packageName` + `collectionURL` on CVE records, OSV `package.ecosystem` + `name`, CSAF
   `product_identification_helper.purl` → purl-based ids (`pkg:npm/lodash` → id `npm:lodash`) (strength A).
5. **CSAF product trees**: `vendor` → `product_name` branches, linked to a CPE or purl when the helper gives one
   (strength A), else rule-made (B).
6. **CISA KEV** `vendorProject` + `product` (strength B, joined to a CPE when the KEV entry's CVE has an NVD CPE).
7. **Rule-made aliases** for every other vendor/product pair seen in CVE records: normalised as 3.3; joined to an existing
   id when the normalised vendor and product keys equal an existing id's keys (B), or when the product key alone is unique
   across all vendors and at least 6 characters (C). Otherwise a new id `<vendor_key>:<product_key>` is made (basis
   `rule`).
8. **AI alias desk (back end, public data only)**: names still unjoined after step 7 go in batches to a Claude model (one
   turn, no tools, `scripts/lib/oneshot.mjs`, as the Library desk), which proposes an existing id or "new product" with a
   reason. A second run that did not write the proposal approves or rejects it. Approved aliases get strength `B`, basis
   `ai-reviewed`, and are held to the same identity test as rule aliases (12.3a).

### 3.5 Renames, splits and families

- `successor`: a renamed product keeps both ids; ranges of the old id apply to items that resolve to either.
- `family`: products the sources split by release ("Windows 10 Version 22H2", "Red Hat Enterprise Linux 9") get one id
  per release with `family` set; an item that names only the family ("Windows 10") with a build number resolves to the
  release whose build prefix matches (7.4), else to the family with verdict `check` (`RELEASE_UNKNOWN`).

### 3.6 Unresolved names

Every vendor/product pair the rules could not join is counted and written to `data/products/unresolved.json` with its CVE
count, so rules or vendor aliases can be added by hand. The CVEs behind them still get a product id (a new rule-made id),
so they still match by name.

## 4. Range records (in `p/<shard>.json`)

```jsonc
{
  "id": "openbsd:openssh",
  "ranges": [
    {
      "cve": "CVE-2024-6387",
      "src": "cna",                     // cna | adp | nvd | csaf | osv | kev | ai
      "ref": "https://...",             // the source document (CVE record, advisory) for the explanation
      "status": "affected",             // affected | unaffected (an explicit "not affected" statement)
      "scheme": "openssh",              // from versionType, else the product's default, else "generic"
      "intro": "8.5p1", "intro_incl": true,   // lower bound; null = from the first version
      "fixed": "9.8p1",                 // first version NOT affected (exclusive upper bound), or null
      "last": null,                     // last affected version (inclusive upper bound), or null
      "exact": [],                      // listed versions when the source gives a list, not a range
      "changes": [],                    // [{at, status}] inside the range (CVE JSON 5 "changes"): backports
      "open": false,                    // true when the source states no upper bound ("lessThan": "*")
      "all_versions": false,            // true for defaultStatus affected with no versions, or KEV all-versions
      "platforms": [],                  // section 7.2; empty = every platform
      "editions": [],                   // section 7.3
      "update": null,                   // CPE "update" field (sp1, r2, p3) when the source splits by it
      "target_sw": null, "target_hw": null,   // CPE target fields when set
      "modules": [],                    // affected modules/components (CVE JSON 5 "modules", "programFiles")
      "requires": [],                   // NVD AND-configurations: [{id, range}] another product that must be present
      "distro": null,                   // {name: debian|ubuntu|rhel|..., release} for distribution builds
      "text_parsed": false              // true when the bounds came from a text pattern (5.4)
    }
  ]
}
```

### 4.1 From the CVE record (CNA and ADP), CVE JSON 5

For each `affected[]` entry with a resolvable product:

| CVE JSON 5 | Range |
|---|---|
| `versions[]` row with `lessThan` | `intro` = `version` (`"0"` → null), `fixed` = `lessThan` (`"*"` → `open: true`) |
| row with `lessThanOrEqual` | `intro` = `version`, `last` = `lessThanOrEqual` (`"*"` → `open`) |
| row with only `version`, status affected | added to `exact` |
| row with status `unaffected` | a separate range with `status: "unaffected"` |
| row status `unknown` | dropped from ranges; counted (coverage) |
| `changes[]` inside a row | copied to `changes`; evaluated in 8.2 step 6 |
| `versionType` | `scheme` (section 5 table) |
| `defaultStatus: affected`, no rows | `all_versions: true` |
| `defaultStatus: unaffected` / missing | versions outside all rows are not affected **by this source only** |
| `platforms[]` | `platforms` (7.2 vocabulary) |
| `modules[]`, `programFiles[]` | `modules` |
| `cpes[]` | joins the entry to a CPE id (3.4 step 2) |
| `packageName`, `collectionURL` | purl id (3.4 step 4) |

### 4.2 From NVD (CPE configurations)

Each `cpeMatch` with `vulnerable: true` becomes a range: `versionStartIncluding/Excluding` → `intro`/`intro_incl`,
`versionEndExcluding` → `fixed`, `versionEndIncluding` → `last`; a version in the CPE string itself → `exact`; `*` with no
bounds → `all_versions`. CPE `update`, `sw_edition`, `target_sw`, `target_hw` are copied. A node with operator `AND`
(an application "running on" an OS, firmware "on" hardware): the vulnerable side becomes the range and the
`vulnerable: false` side becomes `requires`.

### 4.3 From CSAF advisories (vendor PSIRT feeds already collected, `data/psirt/`)

`product_status.known_affected` / `first_affected` / `last_affected` → affected ranges; `fixed` / `first_fixed` →
`fixed` bounds; `known_not_affected` → unaffected ranges. Product versions come from `product_version` (exact) and
`product_version_range` (`vers:` or `vls` strings, parsed by the `vers` grammar). The product joins by its
`product_identification_helper` (cpe or purl) first, then by vendor/product name (3.3).

### 4.4 From OSV

`affected[].package` → purl id; `ranges[]` of type `SEMVER` or `ECOSYSTEM`: each `introduced` / `fixed` /
`last_affected` event pair becomes one range (`"0"` introduced → null); `limit` events ignored; `GIT` ranges dropped (no
version to compare); `versions[]` → `exact`. Debian and Ubuntu OSV entries set `distro` (desktop patch 0006's data).

### 4.6 From vendor advisories read by AI (back end, public data only)

For a CVE with a product but no usable versions from any structured source, the AI range desk reads the vendor advisory
linked from the record and proposes ranges, each with an evidence quote of at most 160 characters from the advisory. A
second, independent run checks every range against the same page. Approved ranges get `src: "ai"` with the advisory as
`ref`. Until the gold set proves the `ai` source at 99% (12.3c), its ranges can give `affected` but never `not_affected`.

### 4.5 From CISA KEV

KEV gives a product, not versions. A KEV entry adds no range; it marks every range of that CVE `kev` for ranking. When a
KEV entry's product has no range from any source, one `all_versions` range with `src: "kev"` is added so the item is at
least `check` (`NO_VERSION_DATA`), never silently clear.

## 5. Versions

### 5.1 Schemes and their order

The range's `versionType` (CVE JSON 5) picks the scheme; when absent, the product's default; when none, `generic`.

| Scheme | From `versionType` / product | Order rules |
|---|---|---|
| `generic` | none, `custom` without a product scheme | split on `. - _ + ~ :`; numbers compare numerically; a letter run after a number (`1.0.2k`, `9.8p1`) sorts after the bare number; `alpha` < `beta` < `pre` < `rc` < release; leading `v` dropped; trailing `.0` parts equal (`1.2` = `1.2.0`) |
| `semver` | `semver`, npm, cargo, Go, NuGet | SemVer 2.0.0: MAJOR.MINOR.PATCH, pre-release after `-` sorts before the release (identifiers compared numerically or ASCII), build metadata after `+` ignored; Go: leading `v`, pseudo-versions `v0.0.0-YYYYMMDDHHMMSS-hash` ordered by the timestamp; NuGet: optional 4th part |
| `python` | `python`, PyPI | PEP 440: epoch `N!`, release, pre (`a`, `b`, `rc` and their spellings), post (`.postN`, `-N`), dev (`.devN`), local (`+…`) ignored for ranges |
| `maven` | `maven`, Maven | ComparableVersion: numbers then qualifiers `alpha` < `beta` < `milestone` < `rc` = `cr` < `snapshot` < release (`ga`, `final`, `release`, empty) < `sp` |
| `rpm` | `rpm`, RHEL, SUSE, Fedora, Amazon Linux | `epoch:version-release`; rpmvercmp segment rules; `~` sorts before anything, `^` after; missing epoch = 0 |
| `deb` | Debian, Ubuntu packages | dpkg order: `epoch:upstream-revision`; `~` sorts before everything including the empty string |
| `gem` | RubyGems | Gem::Version: segments; a segment with letters makes a pre-release |
| `openssh` | product default for `openbsd:openssh` | `generic` with `pN` portable suffix numeric |
| `windows_build` | Microsoft products with build numbers | four numeric parts `10.0.19045.4529`; compared numerically part by part; the first three parts must match a release (7.4) |
| `cisco_ios` | Cisco IOS / IOS XE trains | exact matches only; any range → `check` (`UNORDERABLE_VERSION`) |
| `date` | `date` | ISO dates or `YYYYMMDD` compared as dates |
| `git` | `git` | not orderable: exact commit only, else `check` |

A product can carry its own scheme when its vendor's numbering is known (`config/match/schemes.json`, hand-maintained,
each entry with a test). A comparison the scheme cannot make (unknown token, mixed schemes, garbage) returns `null`, never
`false`.

### 5.2 Version normalisation on both sides

Trim; drop a leading `v`/`V` or `version`; cut a trailing build tag in brackets (`5.4 (build 1234)` keeps `1234` as
`build` for `windows_build`, drops it otherwise); `x`/`*` wildcards (`1.2.x`) become a range `>= 1.2, < 1.3`;
architecture and distro suffixes (`.el9`, `+deb12u1`, `ubuntu0.22.04.1`) are kept for `rpm` / `deb` and set `distro` on
the item.

### 5.3 Equality

Two versions are equal when the scheme orders them equal (so `1.2` = `1.2.0` under `generic`, but not under `semver`
when the source wrote full three-part versions and the item did too).

### 5.4 Text patterns (the only text parsing allowed)

Some assigners put a range into the `version` string. Only these patterns are parsed, each producing `text_parsed: true`:
`< X`, `<= X`, `>= X, < Y`, `X - Y`, `X through Y`, `X to Y`, `prior to X`, `before X`, `up to X`, `X and earlier`,
`X and prior`, `all versions`. Anything else stays an exact string, which can only match an identical item version.

## 6. The client's list (browser only)

### 6.1 Item record

```jsonc
{ "line": 12, "raw": "OpenSSH 9.8p1 (x64)",      // kept for the explanation, never sent anywhere
  "vendor": "", "name": "openssh", "version": "9.8p1",
  "purl": null, "cpe": null, "ecosystem": null,
  "arch": "x64", "platform": null, "edition": null,
  "distro": null,                                  // {name, release} from an rpm/deb package line or an #os line
  "count": 1 }
```

### 6.2 Formats read (extends `W.parseInventory`)

CycloneDX JSON (`components[]`: `group`, `name`, `version`, `purl`, `cpe`, `publisher`/`supplier`), SPDX JSON
(`packages[]`: `name`, `versionInfo`, `supplier`, `externalRefs` purl / `cpe23Type`), CSV and spreadsheet exports with
name / version / vendor / count columns, Windows "Programs and Features" and `Get-Package` exports (`DisplayName`,
`DisplayVersion`, `Publisher`), `dpkg -l` and `rpm -qa` output (name, epoch:version-release, arch, with an `#os` line
for the release), `pip freeze`, `npm ls --json`, `go version -m`, plain lines `name version`.

### 6.3 Resolution order (first hit wins; strength carried to the verdict)

1. **purl** on the item → `purl.json` (A).
2. **CPE** on the item → `cpe.json` (A).
3. **Package line** (dpkg, rpm, pip, npm, go) → purl built from ecosystem + name → `purl.json` (A).
4. **Alias with vendor**: normalised vendor + product key → alias shard entry whose `vendor_key` matches (B, or A when
   the alias itself is A).
5. **Alias without vendor**: product key → a single id (C); several ids → `AMBIGUOUS_PRODUCT`.
6. **Fuzzy** (`W.nameHit`): only for listing candidates; a fuzzy-only product can never give `affected` or
   `not_affected`, only `check` (`WEAK_IDENTITY`).
7. Nothing → the item is shown as **not recognised** with its line number, never dropped silently.

## 7. Platforms, editions, releases and components

### 7.1 Tokens cut from names

Name normalisation (3.3 step 5) moves version, release, platform and edition words into fields, so "Windows 10 Version
22H2 for x64-based Systems" becomes product family `microsoft:windows_10`, release `22h2`, platform `x64`.

### 7.2 Platforms

Vocabulary: `windows`, `macos`, `linux`, `android`, `ios`, `x86`, `x64`, `arm`, `arm64`, plus product-specific ones
(`config/match/platforms.json`). A range with `platforms` applies to an item only when the item's platform is in the list;
an item with no platform against a platform-split range → `check` (`PLATFORM_UNKNOWN`) unless every platform split gives
the same answer.

### 7.3 Editions

Same rule as platforms (`Enterprise`, `Community`, `Server`, `LTSC`, ...): mismatch → range does not apply; item edition
unknown and ranges differ by edition → `check` (`EDITION_UNKNOWN`).

### 7.4 Releases inside families

For `windows_build`, the release is found from the build's third part (19045 → Windows 10 22H2) using
`config/match/releases.json`; for RHEL and similar, from `.elN` / the `#os` line. No release found → `check`
(`RELEASE_UNKNOWN`).

### 7.5 Components and modules

A range with `modules` (a plugin, a library inside a product) applies only when the item names that module; otherwise
`check` (`COMPONENT_ONLY`), with the module named in the explanation.

### 7.6 Required products (NVD AND-configurations)

A range with `requires` applies only when the list also contains the required product in the required range; required
product absent from the list → `check` (`CONFIG_DEPENDENT`), never `not_affected` (the list may be incomplete).

## 8. Verdicts

### 8.1 States

| Verdict | Meaning |
|---|---|
| `affected` | the item's version is inside a stated affected range, identity strength A or B, every condition in 7 met |
| `fixed_in_build` | a distribution or vendor build statement (`changes`, distro range, CSAF `fixed` for that build) says this exact build is fixed although the upstream version is in range |
| `not_affected` | every source with data for this product puts the version outside its affected ranges (or inside an unaffected range), identity A or B, scheme known |
| `check` | anything else, always with one or more reason codes (8.3) |

### 8.2 Per item and CVE: the steps

1. Gather every range of every product id the item resolved to (with `successor` and `family` applied).
2. Drop ranges whose platform, edition, update, target or release conditions exclude the item (7); remember those left
   undecided for reason codes.
3. For each remaining range, compare the item version using the range's scheme: inside an affected range → `in`; inside
   an unaffected range → `out`; outside all bounds → `out` for that range; comparison impossible → `null`.
4. `exact` lists: equal → `in`; not equal → `out` only when the source lists exact versions and no range for this product
   (a full list); otherwise `null`.
5. `open` ranges: `in` becomes `null` (`OPEN_RANGE`): an unbounded range is a lead, never a finding (desktop patch 0003).
6. `changes` and `distro`: when a `changes` entry or a distro range marks the item's build `unaffected`, `in` becomes
   `fixed_in_build`.
7. Combine across sources for this CVE:
   - any source `in` with identity A or B → `affected` (other sources' disagreement kept as `SOURCES_DISAGREE` evidence);
   - else any `fixed_in_build` → `fixed_in_build`;
   - else every source with data `out` and none `null` → `not_affected`;
   - else `check`.
8. Identity C or fuzzy: `affected` and `not_affected` become `check` (`WEAK_IDENTITY`).
9. Item has no version → `check` (`NO_VERSION_IN_LIST`) for every CVE of the product.
10. `all_versions` ranges → `affected` when identity is A or B and no unaffected statement covers the version, with
    `ALL_VERSIONS` noted.

### 8.3 Reason codes for `check`

`NAME_ONLY` (the product has no ranges from any source), `NO_VERSION_DATA` (KEV or name with no versions),
`NO_VERSION_IN_LIST`, `UNORDERABLE_VERSION`, `UNKNOWN_SCHEME`, `OPEN_RANGE`, `SOURCES_DISAGREE` (some in, some null, none
decisive), `PLATFORM_UNKNOWN`, `EDITION_UNKNOWN`, `RELEASE_UNKNOWN`, `COMPONENT_ONLY`, `CONFIG_DEPENDENT`, `WEAK_IDENTITY`,
`AMBIGUOUS_PRODUCT`, `TEXT_PARSED_ONLY` (the only `in` came from a text pattern, 5.4).

### 8.4 Confidence shown with `affected` and `not_affected`

| | Identity A | Identity B |
|---|---|---|
| range from `cna`, `csaf`, `osv` (vendor or ecosystem) | high | medium |
| range from `nvd`, `adp` | high | medium |
| range only from a text pattern | medium | low → `check` |

### 8.5 The explanation every verdict carries

```jsonc
{ "item": "OpenSSH 9.8p1 (x64)  · line 12",
  "product": { "id": "openbsd:openssh", "how": "alias 'openssh' (from NVD's product list)", "strength": "A" },
  "cve": "CVE-2024-6387",
  "verdict": "not_affected", "confidence": "high",
  "steps": [
    { "src": "cna", "range": "8.5p1 ≤ v < 9.8p1", "scheme": "openssh", "result": "out", "ref": "https://..." },
    { "src": "nvd", "range": "8.5p1 ≤ v < 9.8p1", "scheme": "openssh", "result": "out" } ],
  "reasons": [] }
```

The page shows the explanation as plain sentences on the row; "Scores must list every point on the row" (rule 11)
extends to verdicts: every source and rule that decided it is shown.

## 9. Ranking (unchanged scoring, new inputs)

`W.score` keeps its points. New inputs: verdict (`affected` > `check` > others), confidence, KEV, CISA exploitation, EPSS,
CVSS, count of the item. `not_affected` and `fixed_in_build` rows are hidden by default and shown with "show cleared".

## 10. Back-end build and checks

- `scripts/products.mjs build`: corpus + NVD products + CSAF + OSV + KEV + scanner rules → `data/products/` (dictionary,
  aliases, unresolved list). `scripts/match-build.mjs`: `data/products/` + corpus → `site/data/match/`. Both run in the
  deploy after the CVE lookup step; a failure leaves the last good files in place and raises a `pipeline-alert`.
- Unit tests (`tests/unit/match-*.test.mjs`): every scheme's order with its tricky cases; every CVE JSON 5, NVD, CSAF and
  OSV field mapping in section 4 on real records saved as fixtures; every resolution step in 6.3; every reason code in
  8.3; the explanations.
- Same code at both ends: `site/workbench-lib.js` holds normalisation, schemes and the verdict steps; the build imports
  it (as `scripts/cve.mjs` already imports `cvedb-lib.js`), so build and browser cannot disagree.

## 11. Measuring it (before the page switches, and on every build after)

- **Ground truth test** (owner sees the report before going live): 1,000 CVEs where NVD has ranges; for each, versions
  just below, at and just above every bound; verdicts from non-NVD sources only, compared with NVD's. Reported: agreement,
  false `not_affected` (target 0), false `affected`, `check` rate by reason code.
- **Coverage** in `meta.json` and on the status page: share of published CVEs with at least one range, by source; share
  of vendor/product names resolved, by strength; unresolved names count; schemes by count.
- **Regression**: the Scanner's lab fixtures and a fixed set of sample lists (CycloneDX, SPDX, Windows export, dpkg,
  rpm, pip, npm) with expected verdicts, run in CI.

## 12. Accuracy architecture: 99% (owner, 2026-11-27)

The owner's bar: the matching must be 99% accurate. Sources themselves disagree and contain errors, so 99% cannot be
promised for every CVE by trusting them. It is reached by **proving** accuracy per part of the problem and letting only
proven parts give a decisive answer; everything else says `check`. Accuracy and coverage are reported separately and
never traded silently.

### 12.1 What is measured

- **Unit**: one verdict for one software item and one CVE.
- **Decisive precision** (the 99% bar): of all `affected`, `fixed_in_build` and `not_affected` verdicts, the share that
  are right. Required: **at least 99% for each verdict on its own**, proven at 95% confidence (12.4).
- **False clear rate**: `not_affected` given when the item is affected. The most harmful error. Required: **at most
  0.1%**, proven the same way (about 3,000 checked `not_affected` cases with no error).
- **Coverage**: the share of verdicts that are decisive rather than `check`. Reported on every build, by reason code;
  raised over time by fixing what the reason codes show, never by loosening a gate.

### 12.2 Where errors come from, and the control for each

| Error source | Control |
|---|---|
| Wrong product identity (item resolved to the wrong product) | identity test 12.3a; only identity strengths that pass may give decisive verdicts |
| Wrong version order (scheme bug) | differential tests against the reference implementations 12.3b |
| Wrong range from a source (assigner or NVD mistake) | source trust 12.3c; disagreements become `check` |
| Range read wrongly from the source format | field-mapping fixtures 12.3d |
| Client list parsed wrongly (name, version, arch cut wrongly) | parser corpus 12.3e |
| Platform, edition, release or component missed | conditions in section 7 default to `check`; tested in 12.3f |

### 12.3 The tests that earn trust (all deterministic, no AI, run on every build)

a. **Identity**: take every CVE record that gives both a free-text name and a CPE (12% of records, tens of thousands of
   pairs). Hide the CPE, resolve the name with the rules, compare. Measured per strength (A, B, C) and per vendor. A
   vendor's rule-made aliases (B) may give decisive verdicts only when that vendor's held-out precision is at least 99%
   on at least 300 pairs; otherwise its B aliases act like C (only `check`). C never gives a decisive verdict.

b. **Version order**: for every scheme, compare CyberView's order with the scheme's reference implementation on every
   distinct version string the corpus holds for that scheme, paired with its neighbours: `rpm` against `rpmdev-vercmp`,
   `deb` against `dpkg --compare-versions`, `python` against the `packaging` library, `maven` against Maven's
   `ComparableVersion`, `semver` against `node-semver`, `gem` against `Gem::Version`. These run in CI on the Ubuntu
   runner. Required: 100% agreement; any disagreement fails the build. `generic`, `openssh` and `windows_build` are
   tested against hand-written cases from vendors' own release lists.

c. **Source trust**: where two independent sources give ranges for the same CVE and product (assigner vs NVD, assigner
   vs vendor CSAF, OSV vs assigner), evaluate both at every bound and just either side of it. Agreement is recorded per
   assigner (CNA), per vendor and per scheme. A source whose agreement with the others is under 99% on at least 300
   cases is downgraded for that assigner or vendor: its ranges alone can give `affected` but never `not_affected`
   (an unproven source can raise a flag, never clear one).

d. **Field mapping**: real records saved as fixtures for every mapping row in section 4 (CVE JSON 5 incl. `changes`,
   `defaultStatus`, `lessThan: "*"`, platforms; NVD AND-configurations; CSAF `vers` ranges; OSV events), with the
   expected ranges written out by hand.

e. **Client lists**: a corpus of real list files per format (CycloneDX, SPDX, Windows programs export, `Get-Package`,
   `dpkg -l`, `rpm -qa`, `pip freeze`, `npm ls`, CSV), each line labelled by hand with its expected product id and
   version. Required: 99% of lines parsed and resolved correctly per format, or that format's unresolved lines show as
   "not recognised" rather than guessed.

f. **Conditions**: platform, edition, release, component and AND-configuration cases from real Microsoft, Red Hat,
   Cisco and Oracle records, each with the expected verdict.

### 12.4 The gold set (the proof of 99%)

- **Silver (automatic)**: verdicts where three independent sources agree (for example assigner, NVD and vendor CSAF).
  Used to calibrate, not to prove: agreement cases are the easy ones.
- **Gold (checked against the vendor's advisory)**: a stratified sample of verdicts. Each case is labelled by two
  independent AI runs (different prompts, one Sonnet and one Opus), each reading the vendor's own advisory and quoting
  the line that decides it; the verdict code under test is never shown to them. Where the two agree, that is the label.
  Where they disagree, and for a fixed 5% random sample of the agreed ones, a person checks the advisory (the owner or
  someone he names). The labellers' own accuracy is measured on that person-checked sample; if it falls under 99%, AI
  labels stop counting as gold until it is fixed. Only public CVE data and advisories are read; no client data.
- **The owner's review packet** (owner, 2026-11-27: he checks these himself, with Claude Fable). The back end writes
  `data/match/review/<YYYY-MM-DD>.csv` and a matching `.md` (readable on a phone), one row per case to check, with
  everything needed to decide without opening anything else in CyberView: case id; CVE; vendor and product as the source
  writes them and the resolved product id; the version under test; the vendor advisory URL; labeller 1's answer
  (affected / not affected / can't tell) and its quote; labeller 2's answer and quote; why the case is in the packet
  (disagreement or 5% sample); and an empty `owner_answer` column (affected / not_affected / cant_tell / source_wrong)
  with `owner_note`. A packet holds at most 50 cases, disagreements first. Answers are returned by committing the filled
  file (or pasting it into a GitHub issue labelled `match-review`); `scripts/match-review.mjs apply` reads them, and
  `source_wrong` records the advisory as the reason a case is set aside. Nothing in a packet comes from a client. Strata: verdict (`affected`, `not_affected`, `fixed_in_build`) × scheme × identity strength × source.
  Sample sizes for 99% at 95% confidence: 299 cases with no error, 473 with one, 628 with two; for the 0.1% false-clear
  bar, about 3,000 `not_affected` cases with no error (gold and silver combined, silver only where all three sources
  agree).
- The gold set is versioned in `data/match/gold/` and re-run on every build. A failed gold case blocks the build until
  the cause is fixed or the case is shown to be a source error (recorded with the source's page).

### 12.5 Gates (what the build refuses to publish)

1. Any reference-implementation disagreement (12.3b): the build fails.
2. Any gold-set failure (12.4): the build fails.
3. A stratum under 99% decisive precision, or without enough gold cases to prove it: that stratum's verdicts are
   published as `check` with reason `UNPROVEN` until it passes. Nothing decisive ships unproven.
4. `not_affected` overall over 0.1% false clears: every `not_affected` becomes `check` until fixed.
5. Coverage falling by more than 2 points from the last build: the build publishes, and raises a `pipeline-alert`.

### 12.6 What the client sees

Each decisive verdict shows "proven" with the stratum's measured precision and sample size (for example "99.6% on 1,204
checked cases"). Each `check` shows its reason code in plain words. The page states the overall coverage and decisive
precision from `meta.json`, with the build date.

## 13. Running it (owner, 2026-11-27)

- **Backfill: run until done.** The first pass (every unjoined name, every CVE without usable versions, and the first gold
  set) runs continuously on GitHub Actions until its queue is empty, with no monthly cap of its own. It stops early only
  when the API key has no credit left or hits its own limit, and says so in a `pipeline-alert`.
- **Then hourly on a low-cost model: 24 runs a day.** After the backfill, the back-end desks run once an hour on Haiku
  for the new and changed CVEs since the last run. The second check stays on Sonnet: in the Library, Haiku alone got about
  half its cards wrong, and the check is what holds the 99%. The daily volume is small (new CVEs only), so the check
  costs little.
- **Billing**: the API key only (`CYBERVIEW_FALLBACK_ANTHROPIC_API_KEY`), never the Max subscription, logged per run in
  `data/usage/` under jobs `match-alias`, `match-range` and `match-gold` so the spend is visible in
  `node scripts/budget.mjs status`.
