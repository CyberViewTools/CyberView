# Handoff: tk-matchers — offline matchers (SBOM / nmap-XML / component list)

Discovery output for the toolkit's offline `match` command. Research and proposal only. Recommendation: **BUILD.**

## Discovery → Design

- **Need / user story:** a defender who has an inventory but cannot or will not run a network scan (change-freeze,
  third-party or air-gapped assets, "scanning is forbidden", or they only hold an SBOM from CI) wants the scanner's
  KEV+NVD matching and CyberView rating on a list they already have. Add a `match` command that takes a CycloneDX/SPDX
  SBOM, nmap `-oX` XML, or a plain component list and produces the scanner's exact findings/outputs — no network, no
  scanning, no credentials, no scope file.
- **Constraints (rails that apply):**
  - Detection-only, keyless, **no-scan**: `match` makes zero connections to any target (never touches `probe.mjs`/
    `udp.mjs`). Its only outbound is the existing read-only allowlisted GET for CyberView's own data (`--online`), or
    nothing (`--data DIR`, air-gapped). No attestation/authorization gate is needed because no host is contacted — the
    input is data the operator already holds.
  - `security-check.mjs` section 7 stays green: no TCP to targets, no `dgram`, no process spawn, no POST/PUT, no `eval`,
    no aggressive mode. Parsers are `JSON.parse` + regex only (no XML lib, no network), mirroring `discover.mjs`.
  - Untrusted input: an SBOM/XML file can be attacker-crafted → bounded parsing with the site's caps
    (`MAX_ITEMS=5000`, 8 MB, `clip()`), defensive field validation.
  - One engine, not a reimplementation: reuse `site/workbench-lib.js` + `site/cvedb-lib.js` unchanged (CLAUDE.md rule 11).
  - NOCODE / AI-labelling data rules hold (reused code is already clean).
- **Prior art / standards (verified against official docs):**
  - CycloneDX JSON — `components[]` (+ nested, `metadata.component`): `name`, `version`, optional `cpe`, `purl`,
    `publisher`/`group`/`supplier.name`.
  - SPDX JSON — `packages[]`: `name`, `versionInfo`, `supplier`, `externalRefs[]` (`SECURITY` + `cpe23Type`/`cpe22Type`,
    `PACKAGE-MANAGER` + `purl`).
  - nmap `-oX` — `<host><address>` → `<ports><port><service name= product= version= …>` + optional child `<cpe>`.
  - Plain list / `inventory.csv` — the CSV the scanner already writes (`report.mjs toInventory`) and the site's "My
    software" view imports; and `product version` lines.
  - Outputs match what the scanner already produces: JSON, CSV (formula-safe), SARIF 2.1.0, inventory CSV, text summary.
- **Data / APIs that exist (reachable + keyless):** the matching engine is already built. `match.mjs findings()`,
  `report.mjs` exports, `data.mjs` (`webSource`/`dirSource`/`cleanFlaws`/`bucketPath`), `workbench-lib.js`
  (`matchFlaw`/`nameHit`/`inRange`/`cmp`, and `parseInventory`, which already parses CycloneDX `components`, SPDX
  `packages`, CSV/TSV and plain lines), `cvedb-lib.js` (`score`/`rate`). **Gap:** `discover.mjs` parses nmap XML but only
  `<address>`/`<hostname>` (host discovery), not `<service product/version/cpe>`; and `parseInventory` ignores
  `cpe`/`purl`. So the only genuinely new matching-adjacent code is a small input→service-record adapter.
- **Feasibility / risks:** high feasibility, ~90% reuse. Adapter maps each format to the engine's inventory/service
  shape, then `candidates()` → load rows → `findings()` → `report.mjs`, all unchanged.
  - nmap maps most naturally (real host/port/product/version; keep public/private → SSVC exposed/internal as scan does;
    low `conf`/missing version → `guessed=true`).
  - SBOM/list have no host → one pseudo-host per file (`address` = filename, `port:null`, `proto:"sbom"|"list"`);
    explicit SBOM version → high confidence when affected.
  - CPE/purl give vendor+product in NVD CPE form → parse first, fall back to name+publisher.
  - Safe-failing: name-only SBOMs with generic names → `nameHit` is conservative → many land `check`/`none`, never a
    false `affected`. Odd version strings → `core()` handles most; note as a limitation. Large SBOMs → `MAX_ITEMS` cap.
  - **Owner decision flagged:** SBOM/list have no address, so SSVC exposure defaults to internal (the rating itself is
    exposure-independent, so still meaningful). Whether to add an optional `--assume-exposed` for internet-facing
    inventories. Recommend: ship internal-default, add the flag later.
  - Minor plumbing: make `scope`/`attestation` optional in `toSarif`/`summarize`; supply a light input envelope
    (`source: "<file>"`, `up:true`, `ports:[]`). Small, additive.
  - Out of scope: generating SBOMs, any live scanning, resolving purls to registries, dependency-graph/transitive
    analysis, OS matching.
  - No `about.json` entry (a scanner subcommand is not a page/view/layer/routine); `scanner/README.md` + `docs/scanner.md`
    must be updated, and it ties into the site's "My software" import as the offline CLI equivalent.
- **Recommendation:** **BUILD.** Clear user value (defenders who can't scan), ~90% reuse of the shipped engine, strong
  safety fit (no target contact at all), small new surface. Proceed to Design with the `--assume-exposed` owner decision.

## Design → Implementation (proposal, to confirm in Design)

- **CLI:**
  ```
  node scanner/cyberview-scan.mjs match --sbom app.cdx.json  (--online | --data DIR) [--out DIR]
  node scanner/cyberview-scan.mjs match --nmap scan.xml       (--online | --data DIR) [--out DIR]
  node scanner/cyberview-scan.mjs match --list software.txt   (--online | --data DIR) [--out DIR]
  ```
  `--sbom` auto-detects CycloneDX (`components`) vs SPDX (`packages`). No scope file, no gate, no
  `--ports/--udp/--rate/--public` (nothing is contacted). Writes the same five report files.
- **Rough PR breakdown:**
  1. **PR1 — adapter lib** `scanner/lib/inputs.mjs`: CycloneDX, SPDX, nmap-XML (incl. `<service>`+`<cpe>`), plain list →
     pseudo-hosts/service records, preferring cpe/purl; bounded/defensive. Fixtures + unit tests. No CLI yet.
  2. **PR2 — wire the `match` command**: extract a shared `loadFlawsAndRows(src)` helper from `scan.mjs`; add `match` to
     `cyberview-scan.mjs` (reuses `findings()` + writers); make `report.mjs` scope/attestation optional. End-to-end tests
     against the test snapshot; assert zero target connections (no `probe`/`udp` import on this path). `security-check` +
     `scanner.test.mjs` green.
  3. **PR3 — docs**: `scanner/README.md` "Match from a list you already have (no scanning)" + `docs/scanner.md`, cross-link
     the site's "My software" import.

## Implementation → Review
- **Decision on `--assume-exposed`:** shipped, default off. A list with no address stays internal. The flag only changes the SSVC exposure answer. An nmap address is classified and still not contacted.
- **Landed in one PR** (the adapter and the command together; the design's three PRs were small enough to review as one continue-in-place change, with `scan-html` and `tk-diff`): `scanner/lib/inputs.mjs`, the `match` command, the same five report files plus `report.html`. `buildReport` takes an optional `sends` so a match report does not claim a scan's bytes were sent.
- **Tests:** CycloneDX/SPDX CPE preference, nmap open/closed and public/private, `match` against the fixture snapshot with the probe uncalled, oversize input refused.
- **Open questions / follow-ups:** `scan-sbom-crypto` can read these same service records later. No registry lookup of a purl.
