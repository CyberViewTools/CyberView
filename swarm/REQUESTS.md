
## From catch-up (2026-11-19)
- build: analyst plan hands out CVEs already analysed (batches 12, 16, 19, 21, 23, 28 were duplicated in the retry; `swarm.mjs validate` also counted done items as missing). Check freeze/retry against data/analyses.
- review desk: event cert-fr-nginx-http2-rce-2026-11 lists CVE-2026-123634 as HTTP/2 RCE; it is a resolver use-after-free (medium). The nginx event action text implies disabling HTTP/2 covers CVE-2026-121810 (HTTP/3); it does not.
- review desk: SCKit event claims CVE-2026-84869 is used against technicians; Huntress says session cookies.
- build: `q.mjs kev` has no entry for CVE-2026-84869 though CISA's feed lists it (KEV import gap).
- 2026-11-19 improver: review flags actor-unsourced (15) and possible-duplicate (12) behind 36% corrected/flagged; suggest the researcher checklist require a sourced attribution before naming an actor and a dupes run on every new title.
- build: 29 hygiene warnings: tags not on the allowed list (ai, germany, data-exposure, etc.) and 2 over-long summaries (cisa-java4shell..., rakuten-securities...).
