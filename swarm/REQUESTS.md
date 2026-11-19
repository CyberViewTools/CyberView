
## From catch-up (2026-11-19)
- ops (for build): scripts/cve.mjs `site` should list the bucket files per year in site/data/cve/index.json (for example years[].buckets = the thousand numbers that exist). The Vulnerabilities page (site/vulnerabilities.js) currently finds a year's files by probing <year>/0.json, 1.json ... in groups of 4 and stops when a whole group is missing, so 4 or more empty buckets in a row inside a year would cut a year browse short (single-id lookup is not affected). When the list exists, the page should use it and keep the probing only as a fallback.
