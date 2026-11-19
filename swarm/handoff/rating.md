# Swarm rating-20261119T1941: a best-practice rating for every CVE

Lanes: (1) policy research, three headless researchers, primary sources only; (2) build (planning session); (3) calibration panel, three independent analysts.

## Policy research (plan dbe4dbee4f27)
- Confirmed: CISA SSVC guide (Act: as soon as possible; Attend: sooner than standard update timelines; Track and Track*: standard timelines); BOD 22-01 (now revoked); NIST SP 800-40r4 (no fixed days; risk-based); NCSC update by default (5 days internet-facing, 7 days OS and applications, 14 days internal); FIRST "Using EPSS" (use with CVSS and KEV; never multiply EPSS by CVSS).
- Found and verified: CISA BOD 26-04 (10 June 2026) supersedes BOD 22-01. Table 1 (16 rows: publicly exposed, in KEV, automatable, technical impact -> 3 days with forensic triage / 3 / 14 / 60 days / next upgrade) transcribed by three independent readers; all three agree on every row.
- Not confirmed (sites refused automated readers; nothing published from memory): PCI DSS v4.0.1 6.3.3, ASD Essential Eight 48-hour rule, Cyber Essentials 14 days.

## Rating (site/cvedb-lib.js `rate`)
CISA SSVC coordinator table 2.0.3 (CERT/CC) -> Track / Track* / Attend / Act, from exploitation, automatable, technical impact and the visitor's mission impact (default medium). Inputs carry their source (CISA, CISA KEV, the record's description, an estimate from the CVSS vector, or a default). Additions: EPSS top 5% raises Track to Track*; a KEV flaw is never below its BOD 26-04 timeline (14 days: Attend, 3 days: Act). Fix-by: BOD 26-04 Table 1 for internet-facing and internal systems.

## Calibration (plan 1478d95e9cc3)
45 CVEs (15 KEV, 15 critical not KEV, 15 other recent), three analysts, facts only. Panel unanimous on 40 of 45.
- Pure CISA table: 29/45 equal to the panel majority, 37 within one step, 15 rated lower than the panel.
- Final rule: 33/45 equal, 42 within one step, 11 lower, 1 higher. The 11 lower are unexploited flaws where the panel is more cautious than CISA's table at medium mission impact; with mission set to high only 1 is lower. CISA's table is kept as the standard.

## Corpus audit
Total 429,001 vs NVD 429,005 (4 newer); rejected 19,189 = NVD exactly; KEV 1,786 (CISA catalog) now imported in full; critical was 24,858 vs NVD v3 30,855 because the CVE List lacks NVD's own scores; NVD scores are now added hourly and the audit runs every hour.
