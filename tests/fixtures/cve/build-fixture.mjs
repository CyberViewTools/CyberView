// Writes the small test copy of the CVE lookup files (the format scripts/cve.mjs `site` writes: <year>/<thousand>.json,
// index.json, recent.json) next to this file:   node tests/fixtures/cve/build-fixture.mjs
// tests/test_all.py copies this folder to <served site>/data/cve/ for the test run only. Never commit it into site/data
// (that folder is generated). Everything here is made up except that the ids follow the real format.
import { mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import vm from "node:vm";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { FIELDS, toArr, bucket } from "../../../scripts/lib/cve.mjs";

const OUT = dirname(fileURLToPath(import.meta.url));
const VENDORS = [["Acme", "Widget"], ["Zeta", "Mail"], ["Fortinet", "FortiOS"], ["Microsoft", "Windows"], ["Acme", "Gadget"]];
const CWES = ["CWE-79", "CWE-89", "CWE-787", "CWE-22"];
const SEVS = [["C", 9.8], ["H", 7.5], ["M", 5.3], ["L", 3.1], ["N", 0]];
const rec = (year, seq, o = {}) => {
  const k = (year * 7 + seq) % 5, [sev, cvss] = SEVS[k], [vendor, product] = VENDORS[(seq + year) % VENDORS.length];
  const month = String(1 + (seq % 12)).padStart(2, "0"), day = String(1 + (seq % 27)).padStart(2, "0");
  return { id: `CVE-${year}-${String(seq).padStart(4, "0")}`, state: "P", pub: `${year}-${month}-${day}`, upd: `${Math.max(year, 2023)}-${month}-${day}`, cvss, sev, ver: "3.1", cwe: CWES[seq % CWES.length],
    vendor, product, title: `Fixture ${year}-${seq}`, desc: `Fixture record ${year}-${seq}: a flaw in ${vendor} ${product}. ${k === 0 ? "Remote code execution." : ""}`, cna: "acme", expl: "", kev: "", epss: seq % 3 === 0 ? 0.25 : 0.002, pct: 0.5, ...o };
};
const range = (year, from, to, o = {}) => Array.from({ length: to - from + 1 }, (_, n) => rec(year, from + n, o));
const none = { cvss: null, sev: "", ver: "", cwe: "" };

const rows = [
  // 2024: buckets 0, 1 and 2 are contiguous (a year browse reads them); bucket 12 is past a gap, reachable only by looking up one id
  ...range(2024, 1, 38), rec(2024, 1002, { state: "R", ...none, vendor: "", product: "", title: "", desc: "** REJECT ** This candidate was withdrawn.", epss: null, pct: null }),
  ...range(2024, 1100, 1109), rec(2024, 1500, { desc: "<img src=x onerror=alert(1)> markup in a description is shown as text", title: "<script>alert(1)</script>", vendor: "<b>Evil</b>" }),
  ...range(2024, 2001, 2012), rec(2024, 2345, { cvss: 9.8, sev: "C", cwe: "CWE-787", vendor: "Acme", product: "Widget", title: "Needle", desc: "Needle: a memory corruption flaw in Acme Widget used by the lookup test.", epss: 0.9, pct: 0.99 }),
  rec(2024, 12345, { title: "Far bucket", desc: "Far bucket: reachable by lookup only.", cvss: 6.1, sev: "M" }),
  // 2026: the two CVEs the workbench test fixture lists as known exploited; the row itself carries no kev flag, so the browser joins it from CISA's list
  rec(2026, 1001, { cvss: 9.8, sev: "C", vendor: "Fortinet", product: "FortiOS", title: "FortiOS auth bypass", desc: "Authentication bypass in FortiOS (fixture)." }), rec(2026, 1002, { cvss: 7, sev: "H", vendor: "Acme", product: "Widget Server", title: "Widget Server flaw", desc: "Acme Widget Server flaw (fixture)." }), ...range(2026, 1, 12),
  // 2005 and 1999: old ones
  ...range(2005, 1001, 1009), rec(2005, 1234, { ...none, title: "", desc: "An old, unscored flaw from 2005 (fixture).", epss: null, pct: null }),
  rec(1999, 1, { cvss: 5, sev: "M" }), rec(1999, 2, { cvss: 7.5, sev: "H" }), rec(1999, 3, { ...none })
];
// one row that CISA itself marks as exploited (the row carries kev and expl)
rows.push(rec(2021, 44228, { cvss: 10, sev: "C", cwe: "CWE-502", vendor: "Apache Software Foundation", product: "Apache Log4j2", title: "Log4j2 JNDI lookup", desc: "Remote code execution through JNDI.", expl: "active", kev: "2021-12-10", epss: 0.99999, pct: 1 }));

rmSync(join(OUT, "data-tmp"), { recursive: true, force: true });
for (const d of ["1999", "2005", "2021", "2024", "2026"]) rmSync(join(OUT, d), { recursive: true, force: true });
const buckets = new Map(), byYear = {};
for (const r of rows) { const b = bucket(r.id); if (!buckets.has(b)) buckets.set(b, []); buckets.get(b).push(toArr(r)); const y = r.id.split("-")[1]; byYear[y] = (byYear[y] || 0) + 1; }
for (const [b, list] of buckets) { const [y, k] = b.split("/"); mkdirSync(join(OUT, y), { recursive: true }); writeFileSync(join(OUT, y, `${k}.json`), JSON.stringify({ fields: FIELDS, rows: list })); }
const recent = [rec(2026, 1001, { cvss: 9.8, sev: "C", title: "FortiOS auth bypass" }), rec(2026, 5, {}), rec(2021, 44228, { cvss: 10, sev: "C", expl: "active", kev: "2021-12-10", title: "Log4j2 JNDI lookup" })];
writeFileSync(join(OUT, "recent.json"), JSON.stringify({ fields: FIELDS, since: "2026-11-05", rows: recent.map(toArr) }));
// CyberView rating band counts, as scripts/cve.mjs `site` counts them (the page's own rules, run here)
const sb = { window: {} }; vm.runInNewContext(readFileSync(join(OUT, "..", "..", "..", "site", "cvedb-lib.js"), "utf8"), sb);
const ratingBands = {}; for (const r of rows) { const sc = r.state === "R" ? null : sb.window.CVDB.score(r); if (sc) ratingBands[sc.band] = (ratingBands[sc.band] || 0) + 1; }
writeFileSync(join(OUT, "index.json"), JSON.stringify({ built_at: "2026-11-19T03:00:00Z", total: rows.length, rejected: rows.filter((r) => r.state === "R").length, exploited: 1, critical: rows.filter((r) => r.cvss >= 9).length,
  by_year: byYear, buckets: buckets.size, rating_bands: ratingBands, sources: { cvelist: "2026-11-19T02:00:00Z", epss: "2026-11-19" } }) + "\n");
console.log(`fixture: ${rows.length} CVEs in ${buckets.size} lookup files`);
