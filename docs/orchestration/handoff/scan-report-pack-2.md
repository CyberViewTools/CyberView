# Handoff: scan-report-pack-2 — relationship map, operator imports, local package matching, offline rematch

Wave 3, plan `w3-build`, branch `scanner/report-pack-2`. Manifest: 22 REPORT rows (scan-dep-map, tk-matchers and the
report pack). Everything is computed from a report.json, from files the operator supplies, or from a local data snapshot:
no new connection, request, hello, datagram or DNS query.

## Rows already covered by #114/#115 (verified in code, not rebuilt)
- `certificate-inventory`: `scanner/lib/cert-inventory.mjs` `certInventory()` / `--certs` (certs.csv: leaf, issuer,
  validity window, SANs per TLS service).
- `certificate-reuse-across-hosts`: same file, `reuse` groups (same certificate, same public key in different
  certificates, same issuer+serial).
- `kev-fingerprint-coverage-gap`: `scanner/lib/kev-coverage.mjs`, the `coverage --data DIR` command.
- `change-detection-against-a-prior-scan`: `scanner/lib/diff.mjs`, `--compare PREVIOUS/report.json`.
- `unexpected-tls-certificate-issuer-change`: `diff.mjs` `certificates.issuer_changed` ("review; not evidence of compromise").

## Discovery → Design
- **Need:** see how the scanned services relate (and what a finding sits next to), bring in what the operator already
  knows (manifests, SBOMs, cloud inventory, flow logs, local socket lists, package lists), and re-check an old scan
  against newer data without scanning again.
- **Constraints:** a remote scan can only infer; nothing outside the attested scope is contacted (names are listed);
  imports are parse-only, never collected by the scanner (no command run, no login, no radio); every import is untrusted.
- **Data that exists:** `report.hosts[]` (`names` = the scope's own DNS answers, `ports`, `services`, `http[].redirect`
  = the one recorded Location, `tls[].cert` with `san_dns`/`san_ip`, `observations`), `report.findings[].seen_on`;
  `discover.mjs parseCloud`; the site's `W.parseInventory` / `W.matchFlaw` / `W.score`.

## Design → Implementation
- **Modules (pure, no network):**
  - `scanner/lib/depmap.mjs` — `buildDepmap(report, { imports, inScope })`, `toMermaid`, `depmapText`, `depmapHtml`,
    `scopeFromReport`, `RISK` / `RISK_FORMULA`.
  - `scanner/lib/imports.mjs` — `parseSbom`, `parsePackages`, `parseManifest`, `parseZeek`, `parseSurvey`,
    `parseConnections`, `parseCloudInventory`, `parseImports`, `matchInventory`, `readImportFiles`, `IMPORT_LIMITS`.
  - `scanner/lib/rematch.mjs` — `loadOldReport`, `loadMatchData`, `rematch`, `rematchText`.
  - `scanner/lib/offline-cmds.mjs` — the `import`, `depmap` and `rematch` commands (no scope file: they contact nothing).
- **Hooks in `scanner/cyberview-scan.mjs`:** two imports; `depmap` in the boolean flags; the offline usage appended to
  USAGE; one line dispatching `import`/`depmap`/`rematch`; on `scan`, import files are read and checked before anything is
  scanned (an import flag without `--depmap` is refused), and with `--depmap` the map is computed after the report and
  written as `depmap.json` + `depmap.mmd`, with a section inserted before `</main>` in `report.html` when `--html` is given.
  No other shared file changed.
- **Map edges and confidence:** `runs on` (observed open port); `co-located` (low; services on one host, at most 24 per
  host pairwise); `share a certificate SAN list` (medium; identical SAN sets on different hosts); `certificate names`
  (medium; a SAN names another scanned host's attested name or address); `redirects to` (medium; the recorded Location,
  in scope only, never followed); imported edges `declared` (manifest, SBOM, cloud, listening sockets) or `observed`
  (Zeek, connections file peers). Every edge carries `inferred` and an `evidence` string.
- **Mentions / shadow IT:** a name or address from a SAN or Location that is outside the scope → `mentions[]`
  (`scanned: false`, "NOT scanned or contacted"). Inside the scope but not in the starting inventory (scope targets plus
  every name the scan resolved) → `shadow_it[]` (listed, never scanned; add it to the scope to check it). Without
  `--scope` on the `depmap` command the in-scope test comes from `report.scope.targets/exclude` only (attested discovery
  domains are not in report.json), so more names land in mentions.
- **NAT / split horizon (for review):** `certificate-address-mismatch` (SAN IPs present but not the served address),
  `certificate-names-other-address` (SAN names a name the scope resolved to another address), `name-private-and-public`
  (one name resolved to private and public addresses), plus the existing `tls-name-mismatch` observations. No new DNS query.
- **Per-host risk score (0-100), printed with every point and the formula:** per confirmed finding (version in range,
  high/medium confidence) +25 if KEV, else +15 Critical / +8 High / +4 other; +5 ransomware; +5 past CISA's due date; per
  version-to-check (low confidence) finding +2 (never KEV points); +10 for a public address with any finding;
  observations +4 high / +2 medium / +1 low, at most +15; capped at 100. From this report only; not a prediction.
- **Blast radius:** per finding, the nodes that share its host (co-located services), its certificate (SAN list / SAN
  names) or an imported relationship with it, each labelled with how (`via`), at most 200 per finding.
- **Imports (all optional, all untrusted):** size checked before reading (16 MB; Zeek conn.log 64 MB), at most 200,000
  lines, 5,000 nodes / items, 20,000 edges per file (caps are counted in `dropped` / problems, never silent), strings
  clipped and stripped of control characters, `JSON.parse` only, prototype keys never used as object keys.
  - SBOM: CycloneDX JSON (`components`, nested components as `contains`, `dependencies`) or SPDX JSON (`packages`,
    `relationships` of a fixed set: DEPENDS_ON, DEPENDENCY_OF, CONTAINS, CONTAINED_BY, DYNAMIC_LINK, STATIC_LINK,
    RUNTIME_DEPENDENCY_OF, BUILD_DEPENDENCY_OF). Components go through `W.parseInventory` for matching.
  - Manifests: **JSON only; YAML is not parsed** (stdlib has no YAML parser and a partial one would mis-read files). Save
    with `docker compose config --format json` or `kubectl get ... -o json`. Compose: `depends_on`, `links`. Kubernetes:
    Service `selector` → workload template labels (same namespace), Ingress backend → Service. Secrets' data is never read.
  - Zeek `conn.log`: TSV with `#fields` (or Zeek JSON lines): `id.orig_h → id.resp_h` with port/proto/service, counted.
  - Wi-Fi/Bluetooth survey CSV (WiGLE export or any CSV with a MAC/BSSID column): inventory only.
  - Local connections: `/proc/net/tcp` / `tcp6` (hex), `ss -tunap` / `ss -tlnp`, `netstat -tunap` (Linux), `netstat -ano`
    (Windows): listening sockets and established peers; `--connections-host IP` attaches them to a scanned host.
  - Cloud inventory: `discover.mjs parseCloud` for the addresses, plus resources and relationships (instance → VPC,
    subnet, security group, addresses; load balancer → instances; GCP network; Azure public IP → resource).
  - Packages: `dpkg -l` (installed `ii`/`hi` rows; epoch and Debian revision removed), `rpm -qa` (name-version-release.arch),
    Windows `Get-Package | Export-Csv` or uninstall-key CSV (the PowerShell `#TYPE` line dropped), or any list the
    Vulnerabilities page reads. Matched with `W.matchFlaw` and `W.score` exactly as "My software"; dpkg/rpm versions are
    distribution builds, so an affected match is medium confidence with the backport caveat.
- **Rematch:** the old report must parse as JSON with `tool.name = "CyberView Scanner"` (at most 64 MB); only host
  address/names/public and each service's port, proto, vendor, product, label, version, shown_version, distro, source,
  evidence, guessed are kept (clipped). Matching and rating are the scan's own (`match.mjs findings`), with the snapshot's
  lookup rows; output `rematch.json` (summary, findings, `changes.newly_matched / no_longer_matched / still_matched`) and
  `rematch.txt`.

## Tests (`tests/unit/scanner-reportpack2.test.mjs`, 19; fixtures in `tests/fixtures/scanner/reportpack2/`)
Each import format; hostile imports (bad/deeply nested JSON, prototype keys, 100 KB strings, control characters, wrong
types, oversize files never read, caps reported); package and SBOM matching equal to `W.matchFlaw` / `W.score`; the map's
edge kinds and confidences, mentions, shadow IT, mismatches, risk points and blast radius; `scan --depmap --html` sends
the same probes as a plain scan; `import`, `depmap` and `rematch` run with `net.connect`, `net.createConnection`,
`tls.connect`, `dgram.createSocket`, `dns.lookup`/`resolve`, `http(s).request/get` and `fetch` replaced by traps and
the probe/resolver/fetch stand-ins counted: zero calls; rematch new / no longer / still matched against a modified snapshot.

## Text for docs/scanner.md (new section after "Extra outputs")
> ### Relationship map, imports and offline rematch (no network)
> `scan ... --depmap` also writes `depmap.json` and `depmap.mmd` (Mermaid), and a "Relationship map" section in
> report.html with `--html`. It is computed from what the scan already read: services on one host (co-located, low
> confidence), certificates with the same SAN list or naming another scanned host (medium), and recorded redirects inside
> the scope (medium, never followed). Names and addresses outside the scope that appear in a certificate or a Location
> header are listed as "mentioned, not scanned"; in-scope names the scan did not start from are listed as shadow IT. Both
> are only listed. Certificate and DNS answers that do not match the scanned address are listed for review (NAT or
> split-horizon DNS). Each host gets a 0-100 risk score with every point and the formula printed; each finding gets a
> blast radius (what shares its host, certificate or an imported relationship).
>
> Your own files can add what a remote scan cannot see (all optional, parsed only, never collected by the scanner):
> `--sbom` (CycloneDX or SPDX JSON), `--manifest` (compose or Kubernetes, JSON only: `docker compose config --format
> json`, `kubectl get ... -o json`), `--zeek` (conn.log), `--survey` (Wi-Fi/Bluetooth CSV, inventory only), `--connections`
> (`/proc/net/tcp`, `ss` or `netstat` output you saved on the host itself; `--connections-host IP`), `--cloud` (your cloud
> CLI's describe/list JSON; `--cloud-provider`), `--packages` (`dpkg -l`, `rpm -qa`, `Get-Package | Export-Csv`).
> Use them with `scan --depmap`, or offline:
> `import [files] [--data DIR]` (imports.json; with a snapshot, packages and SBOM components are matched against KEV/NVD
> exactly like the Vulnerabilities page's "My software"; distribution package versions carry the backport caveat),
> `depmap --report R/report.json [--scope scope.json] [files]` and
> `rematch --report OLD/report.json --data NEWER-SNAPSHOT` (re-matches an old scan's recorded services with newer data:
> newly matched, no longer matched, still matched; no target is contacted, so rescan to confirm).

## Text for scanner/README.md ("What it does" list, and the "deliberately does not do" list)
> - `--depmap`: a relationship map from what the scan already read, with per-host risk scores and finding blast radius;
>   names outside the scope are listed, never contacted. `import`, `depmap` and `rematch` work offline on your own files.
>
> Does not: run `ss`, `netstat`, a package manager, a cloud CLI or a radio survey for you, log in to a host to collect
> them, follow a redirect, resolve or scan a name it finds in a certificate, or parse YAML (save manifests as JSON).

## Could not do / limits
- YAML manifests are not parsed (no stdlib YAML; a partial parser would mis-read files). JSON exports only.
- Linux package names do not always match NVD product names (for example `apache2` vs `http_server`); the site's matcher
  is used unchanged, so such packages stay unmatched rather than guessed. Container image tags from manifests are listed,
  not matched.
- The offline `depmap` command cannot know the scope's attested discovery domains unless `--scope` is given.
- Shadow IT from "Host" data: the scanner sends only attested names as Host/SNI and records no other Host values, so
  shadow-IT names come from certificate SANs and Location headers only.
- No graph.html (the roadmap's standalone page): the map goes into report.html's section, depmap.json and depmap.mmd.
