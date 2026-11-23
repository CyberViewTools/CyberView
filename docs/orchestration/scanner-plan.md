# CyberView Scanner: full feature map and plan to lead the market

Written 2026-11-23 by the build lane (CyberView AI, a Claude model) at the owner's request. A planning document, not a
decision record: nothing here changes the design limits in `docs/scanner.md` until the owner approves it, and every
"owner decision" below is listed again at the end. Statements about other products are from general knowledge, not
from pages read for this plan; check them before any of it is used in public text.

---

## 1. Where the scanner stands (v1.1.0, 7,444 lines, Node standard library only)

### 1.1 Feature map

| Area | What it does today | Flags / commands |
|---|---|---|
| **Authorization** | Scope file with an exact attestation, address classes, CIDR caps, public ranges capped at /24 and 1,024 addresses behind an explicit flag; scope advice (typos, duplicates, expiring attestations) | `init`, `check` |
| **Discovery** | CIDR liveness sweep, owned domains + Certificate Transparency, imported asset lists (CSV, nmap XML), the operator's own read-only cloud JSON (AWS EC2/ELB, GCP, Azure); every found host re-gated | scope `discover` |
| **Base probe** | TCP connect, greeting, one root-page GET, one TLS handshake, SSH ident + KEXINIT; filtered/closed/throttled recorded; IPS reset back-off | `scan` |
| **Depth** | Every TCP port (private only); DNS version.bind, NTP mode-6, SNMP sysDescr (`public` only) | `--all-ports`, `--udp` |
| **Fingerprints** | 283 products, 376 rules, 296 catalog rows across 8 packs: services, edge appliances (57), CMS/plugins/JS libraries (15), applications (101), the research pack (55, each rule citing its public source) | always on |
| **Path rail** | 39 frozen, reviewed version-file paths for 51 rows, hint-gated, at most 8 GETs per host, BMC rows separately gated | `--paths`, `--paths-bmc` |
| **Identify hellos** | SMTP EHLO, POP3 CAPA, RTSP/SIP OPTIONS, mDNS, RDP (NLA), SMB2 (signing), LDAP root DSE, IPMI ping, Kafka, Redis (no password), MQTT (anonymous), MongoDB | `--identify`, `--identify-bmc` |
| **Industrial / clinical** | One read-only identification read each: Modbus, S7, EtherNet/IP, BACnet, OPC UA, DICOM; private addresses only | `--ics` |
| **DNS posture** | SPF, DMARC, CAA, BIMI, MTA-STS TXT, DKIM for named selectors | `--dns-records`, `--dkim-selectors` |
| **Hygiene** | TLS protocol/cipher/group/key/signature/expiry/name; security headers, cookies, CORS, redirects, default/debug pages, clock skew; cleartext mail; SSH weak algorithms and PQC note | always on |
| **Matching and rating** | The site's own `matchFlaw` and `score` (one answer on site and CLI); CyberView rating with every point; CISA SSVC priority and BOD timelines; KEV first; confidence high/medium/low with reasons; low confidence kept out of headline counts; backport caveat | always on |
| **Intel tie-in** | Fix versions, workarounds, vendor advisory, CISA action, hunt links (Sigma/YARA/STIX, linked not copied), reviewed CyberView incidents per CVE | `--data-incidents` |
| **Outputs** | report.json, findings.csv (formula-safe), SARIF 2.1.0, inventory.csv, summary.txt; self-contained report.html; certs.csv, mail.csv, dns.csv, diff, depmap (JSON + Mermaid) | `--html`, `--certs`, `--mail`, `--compare`, `--depmap` |
| **Offline** | Snapshot for air-gapped use; match nmap/SBOM/package lists without scanning; one-CVE lookup; rematch an old report against newer data; imports (dpkg, rpm, Get-Package, CycloneDX/SPDX, compose/k8s, Zeek, ss/netstat, Wi-Fi survey, cloud) | `data`, `match`, `lookup`, `rematch`, `import`, `depmap`, `coverage` |
| **Coverage honesty** | Never a silent clean: blind spots listed, exit code 2 when coverage is incomplete | always on |
| **Safety, enforced** | `security-check.mjs` section 7 fails CI on processes, raw sockets, extra UDP sends, non-GET, unreviewed bytes, raised limits; loopback tests prove the bytes each service receives | CI |
| **Distribution** | Single-file deterministic bundle, SHA256SUMS, GitHub Releases (tag not yet pushed) | `scanner-release.yml` |
| **Site** | Scanner page with live counts, browser-only report viewer and diff, scope-file builder; "My software" in the Vulnerabilities page | `scanner.html` |

### 1.2 Measured gap (run for this plan)

`coverage` against today's public snapshot (72 known-exploited CVEs across 60 products):

- **6** CVEs on products whose version the scanner reads, **9** on products it can only name, **57** on products it
  cannot identify. Largest gaps: Plex, SonicWall SMA1000, VMware vCenter, Ahsay, LiteLLM, PaperCut, Log4j2, TeamCity,
  Langflow, React Server Components, Windchill.
- Some of those "gaps" are a **counting fault, not a detection gap**: vCenter and PaperCut are named by `fp-identify.mjs`,
  which `coverage` does not count because it is outside `FINGERPRINT_TABLES` (documented in `docs/scanner.md`). The real
  number is better than 15 of 72, and we cannot currently say by how much. First fix in the plan.
- Part of the rest is client or library software (Log4j2, React Server Components) that no network scan sees; that is
  what the local collector (section 4, N1) is for.

This number is the single most important metric in this document. A scanner is judged by "did it find the thing that
is being exploited this week".

---

## 2. The market, by segment

| Segment | Typical players | Where they are strong | Where they are weak (our opening) |
|---|---|---|---|
| Enterprise VM | Tenable Nessus/VM, Qualys VMDR, Rapid7 InsightVM | Huge check libraries, credentialed and agent scanning, compliance audits, dashboards, integrations | Expensive, heavy, noisy; many "vulnerabilities" are unverified version guesses; active checks can disturb fragile devices; threat context is bolted on; results leave the network (cloud consoles) |
| Open source VM | OpenVAS/Greenbone | Free, broad feed | Slow, hard to run, community feed lags, high false positives, old UX |
| Template scanners | Nuclei, Nmap NSE | Fast new-CVE coverage from community templates | Many templates send exploit-style requests; quality varies; no prioritisation or reporting |
| Asset discovery | runZero, Lansweeper | Excellent safe fingerprinting, inventory | Vulnerability ranking is thin |
| Outside-in / ASM | Censys, Shodan, attack-surface tools | Internet-wide view, no setup | Cannot see inside; data is days old; "your" asset list is guessed |
| OT/ICS | Claroty, Nozomi, Dragos | Passive OT monitoring, deep protocol knowledge | Appliances, six-figure deals, out of reach for small utilities, clinics and factories |
| SBOM / container | Trivy, Grype, Snyk | Package-level accuracy, developer workflow | No network view; no exploitation context |
| Prioritisation | EPSS, CISA KEV, VulnCheck, risk-based VM add-ons | Signal on what is exploited | A feed, not a scanner; must be joined to an inventory |

**What nobody combines:** a scanner that (a) is safe by construction and can prove it byte for byte, (b) ranks by a live,
human-style reviewed picture of what is being exploited this week, and (c) is honest about what it did not see. Every big
vendor has some of each, and none has all three in a free, offline, single-file tool.

---

## 3. Positioning: where we win, and where we refuse to compete

**We do not try to out-plugin Tenable.** 100,000-plus checks built over 20 years by hundreds of people is not a race to
enter. We win on four things the incumbents structurally cannot copy quickly:

1. **Safe enough to run anywhere.** Detection only, frozen bytes, CI-enforced limits, no credentials, no state change, ICS
   reads private-only. The pitch: *"the scanner you can run on a hospital network or a water plant at 2 pm on a Tuesday."*
   Incumbents cannot claim this without removing their own active checks.
2. **Fastest to the exploited flaw.** CyberView already runs a 24/7 pipeline that sees exploitation reports within
   minutes. Turn that into **time from "known exploited" to "the scanner can find it"**, measured and published. Target:
   under 48 hours for any network-visible product. Nobody publishes this number.
3. **Ranking people trust.** Every point of the score shown, confidence stated, low confidence never inflating the
   headline, backports flagged, "being exploited near you / in your sector" from reviewed events. Lower false positives
   is the most common complaint about every incumbent.
4. **No data leaves the building.** Offline snapshot, single file, nothing uploaded, ever. A differentiator for
   governments, defence, health, OT and anyone under data-residency rules, and a large difference in procurement time.

**Where we refuse to compete** (keeps the moat of trust, see section 6): exploit-based checks, credential guessing,
uploads, aggressive modes.

---

## 4. Roadmap

Each item lists what it beats, and whether it stays inside the current design limits or needs an owner decision.
Ids are proposed BACKLOG ids.

### Now (0 to 4 weeks): sharpen what exists

| Id | Item | Why it wins | Limits |
|---|---|---|---|
| **N0 scan-release-tag** | Push `scanner-v1.1.0`. Without a release, nothing else counts | Can't win a market we haven't entered | owner action |
| **N1 cov-count** | `coverage` counts every fingerprint module (register fp-identify and the others in `FINGERPRINT_TABLES`), so the KEV number is true | We need an honest baseline before we publish one | inside |
| **N2 kev-sla** | The **KEV-to-detection loop**: each new KEV entry that is network-visible opens a `scanner-gap` item; a research job drafts a rule from public references with citations (as the research pack did); the lead reviews; CI checks; a release follows. The Scanner page shows "days from KEV to detection" per entry | Our single biggest edge: speed on what matters this week | inside (mechanical rules; AI only drafts, review merges) |
| **N3 ics-match** | Match `--ics` vendor/model/firmware to the ICS advisories CyberView already collects, and show ICS results in summary/inventory/HTML (partly done in #130) | Brings OT vulnerability ranking to sites that cannot buy an OT appliance | inside |
| **N4 watch** | tk-diff "watch" half: `scan --compare --alert-on new-kev,new-critical` exit codes plus a ready cron/Task Scheduler recipe and a one-file "since last week" summary | Continuous monitoring without a server or an upload | inside (no new network behaviour) |
| **N5 fix-bundles** | Group findings into **upgrade bundles**: "upgrade X to 9.4.2 closes 14 findings, 3 known exploited". Rank bundles, not CVEs | Operators patch products, not CVEs. Incumbents mostly list CVEs | inside |
| **N6 sector-context** | With `--data-incidents`, add "exploited in the last 7/30 days", "used by ransomware" and "actors that target your sector (set in the scope file) exploit this" from reviewed events only | Live, sector-aware priority from our own reviewed data; nobody else has the feed | inside (reviewed events only, claims never cited) |

### Next (1 to 3 months): close the depth gap safely

| Id | Item | Why it wins | Limits |
|---|---|---|---|
| **X1 local-collector** | `cyberview-scan local`: run **on the host itself**, read the package databases from disk (dpkg status, rpm db via its export, apk, Windows uninstall entries from an exported .reg/CSV, installed Java/Python/Node libraries from their manifests), produce the same report. No network, no credentials crossing the wire | Closes the biggest gap vs credentialed scanning (most real findings are local packages) without ever taking a password | **owner decision**: a new mode; must not start processes (section 7), so Windows needs exported files or a pure reader |
| **X2 backports** | Resolve "possibly already fixed" with distribution data (Debian security tracker, Ubuntu USN/OVAL, Red Hat CSAF/OVAL, Alpine secdb) as a new no-AI feed | Turns medium-confidence Linux rows into right answers; this is where naive scanners produce most false positives | inside the scanner; a new data feed in the pipeline |
| **X3 vex-sbom** | Emit CycloneDX SBOM and OpenVEX/CycloneDX VEX from any scan; read vendor CSAF VEX ("not affected") to suppress findings, citing the statement | EU CRA, US federal and customer questionnaires ask for exactly these files | inside |
| **X4 sql-prelogin** | Resolve the three [MS-TDS] questions (decision 24) and ship SQL Server build numbers | One of the most common internal services, exact version pre-auth | inside (decision 10 family) |
| **X5 exports** | Export files for Jira/GitHub Issues/ServiceNow CSV, Splunk/Elastic NDJSON, Defender/Sentinel-friendly CSV; still files, never a push | Fits existing workflows without our cloud | inside |
| **X6 attack-paths** | From depmap: internet-facing service with KEV, then what it can reach internally (from imports), ranked as paths | "Fix this one box and three paths close" is the board-level story | inside |
| **X7 dashboard** | The Scanner page viewer becomes a local dashboard: trends over many report.json files, bundles, SLA view, all in the browser, nothing uploaded | Incumbents' main selling point, without their cloud | inside (browser only) |
| **X8 lab-accuracy** | A public accuracy harness: a docker lab of known-version services, measured precision/recall per release, published | Proves rule 3 of section 3 with numbers rather than words | inside |

### Later (3 to 12 months): grow the market we own

| Id | Item | Why it wins | Limits |
|---|---|---|---|
| **L1 fleet** | Self-hosted aggregator: many scanners, many sites, one view; the customer's server, not ours | Teams and MSPs; still "nothing leaves the building" | owner decision (a server component) |
| **L2 container** | Read an exported image tarball's package DBs and manifests offline | Meets Trivy/Grype on their ground with our ranking | inside (files only) |
| **L3 outside-in** | For attested domains: CT, DNS, passive records into an "exposed to the internet" view joined to scan results | Our own attack surface view without Shodan's guessing of whose asset it is | inside (attested names only) |
| **L4 cloud-posture** | Read-only posture checks on the operator's exported cloud JSON (open security groups, public buckets) | Bridges network and cloud views | inside (files only) |
| **L5 assurance** | Independent review of the safety claims; publish the "what is sent" table as a versioned spec; signed releases (Sigstore) | Turns "safe" from a claim into a certificate; procurement asks for it | owner decision (cost, vendor choice) |
| **L6 packaging** | OS binaries, package managers (Homebrew, winget, apt repo), a container image | Lower friction than any incumbent | parked as tk-package; revisit after N0 |
| **L7 business** | Free CLI forever; paid fleet console, SLA on KEV coverage, compliance report packs (open core) | Funds the coverage work | owner decision (parked as `subs`) |

---

## 5. How we measure "beating the market"

| Metric | Today | Target | Where it shows |
|---|---|---|---|
| KEV network-visible coverage (version read or named) | 15 of 72 counted (undercounted, N1) | 80% of network-visible KEV products | Scanner page, per release |
| Days from KEV add to detection | not measured | median under 2 days | Scanner page (N2) |
| Precision of "affected" at high confidence | not measured | 98% or better on the lab | X8, per release |
| Findings per host that are actionable (high/medium) | not measured | majority of rows | report summary |
| Bytes sent per host, default scan | proven in tests | published per release | release notes |
| Time to first report for a new user | not measured | under 5 minutes from download | onboarding test |

---

## 6. What we will not do (and why that is the strategy, not a gap)

No exploitation or test input, no credential guessing or logins, no uploads or telemetry, no aggressive or unlimited
mode, no evasion, nothing outside the attested scope. Each would erase reason 1 of section 3 and put us in a race with
vendors who have twenty years' head start on it. The answer to "but credentialed scanning finds more" is X1 (the
operator reads the host's own package list on the host) and the imports, never a password.

---

## 7. Decisions for the owner

1. **Push the `scanner-v1.1.0` tag** (N0).
2. **Approve the KEV-to-detection loop (N2)**, including an AI job drafting rules for review, and publishing the
   days-to-detection number.
3. **Approve a local collector mode (X1)** and how Windows inventory is read without starting a process.
4. **Approve a new no-AI distribution-security feed (X2)** in the data pipeline.
5. **Fleet / self-hosted server (L1) and the business model (L7)**: yes, no or later.
6. **Independent safety review and signed releases (L5)**: budget and timing.

## 8. Suggested first wave (one PR each, through `budget.mjs can-build`)

1. N1 cov-count (small; makes every later number honest).
2. N5 fix-bundles and N6 sector-context (both from data already loaded).
3. N3 ics-match.
4. N4 watch.
5. N2 kev-sla once approved; X-items after the owner's answers.
