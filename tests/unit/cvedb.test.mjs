import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { FIELDS, toArr, bucket } from "../../scripts/lib/cve.mjs";
// the browser file attaches itself to window; run it in a sandbox with a stand-in window
const sandbox = { window: {} };
vm.runInNewContext(readFileSync(new URL("../../site/cvedb-lib.js", import.meta.url), "utf8"), sandbox);
const D = sandbox.window.CVDB;
const plain = (x) => JSON.parse(JSON.stringify(x));

test("ids: validation and normalising what a visitor typed", () => {
  assert.ok(D.isId("CVE-2024-12345") && D.isId("CVE-1999-0001"));
  for (const bad of ["cve-2024-1234", "CVE-2024-123", "CVE-24-12345", "CVE-2024-12345 ", "", null, "CVE-2024-1234x"]) assert.ok(!D.isId(bad), String(bad));
  assert.equal(D.normId("  cve-2024-12345 "), "CVE-2024-12345");
  assert.equal(D.normId("cve‑2024‑0123"), "CVE-2024-0123");
  assert.equal(D.normId("log4shell"), "");
});

test("bucketFile matches the files scripts/cve.mjs site writes (thousands)", () => {
  for (const id of ["CVE-2024-3400", "CVE-2021-44228", "CVE-1999-0001", "CVE-2024-999", "CVE-2024-12345", "CVE-2024-100000"]) {
    if (!D.isId(id)) { assert.equal(D.bucketFile(id), ""); continue; }
    assert.equal(D.bucketFile(id), bucket(id) + ".json", id);
  }
  assert.equal(D.bucketFile("CVE-2024-3400"), "2024/3.json");
  assert.equal(D.bucketFile("../../etc/passwd"), "");
  assert.equal(D.bucketFile("CVE-2024-3400/../x"), "");
});

test("cleanIndex reads counts and freshness, orders years newest first, drops junk", () => {
  const ix = D.cleanIndex({ built_at: "2026-11-19T03:00:00Z", total: 9, rejected: 1, exploited: 2, critical: 3, by_year: { 1999: 1, 2024: 8, x: 5, 1500: 1, 2023: "n" }, sources: { cvelist: "2026-11-19T02:00:00Z", epss: "2026-11-19" } });
  assert.deepEqual(plain(ix.years), [{ year: 2024, count: 8, files: null }, { year: 1999, count: 1, files: null }]);
  assert.equal(ix.total, 9); assert.equal(ix.cvelist, "2026-11-19T02:00:00Z");
  assert.equal(D.cleanIndex(null), null);
  assert.equal(D.cleanIndex({ total: "many" }), null);
});

const F = FIELDS;
const row = (o) => toArr(Object.assign({ id: "CVE-2024-1000", state: "P", pub: "2024-03-01", upd: "2024-03-02", cvss: 9.8, sev: "C", ver: "3.1", cwe: "CWE-79", vendor: "Acme", product: "Widget", title: "Widget RCE", desc: "Remote code execution", cna: "acme", expl: "", kev: "", epss: 0.5, pct: 0.9 }, o));

test("cleanRow enforces the format and its limits", () => {
  const long = "x".repeat(900);
  const r = D.cleanRow(F, row({ id: "CVE-2024-12345", pub: "2024-05-01T00", cvss: 11, sev: "X", ver: "bad ver", cwe: "79", vendor: "<b>" + long, desc: "<img src=x onerror=alert(1)> " + long, expl: "weird", kev: "soon", epss: 3, pct: -1 }));
  assert.equal(r.id, "CVE-2024-12345"); assert.equal(r.pub, ""); assert.equal(r.cvss, null); assert.equal(r.sev, ""); assert.equal(r.ver, ""); assert.equal(r.cwe, "");
  assert.ok(r.vendor.length <= 60 && r.desc.length <= 600 && r.title.length <= 160);
  assert.equal(r.expl, ""); assert.equal(r.kev, ""); assert.equal(r.epss, null); assert.equal(r.pct, null);
  assert.equal(D.cleanRow(F, row({ id: "nope" })), null);
  assert.equal(D.cleanRow(F, "x"), null);
  assert.equal(D.cleanRow("x", []), null);
  const k = D.cleanRow(F, row({ state: "R", expl: "active", kev: "2021-12-10" }));
  assert.ok(k.rejected && k.expl === "active" && k.kev === "2021-12-10");
});

test("parseFile drops bad rows and tolerates a non-file", () => {
  assert.equal(D.parseFile({ fields: F, rows: [row({}), null, ["x"], row({ id: "CVE-2024-1001" })] }).length, 2);
  assert.equal(D.parseFile(null).length, 0);
  assert.equal(D.parseFile({ rows: "x" }).length, 0);
});

const S = D.parseFile({ fields: F, rows: [
  row({ id: "CVE-2024-1000", pub: "2024-03-01", cvss: 9.8, sev: "C", cwe: "CWE-79", vendor: "Acme", product: "Widget", desc: "Remote code execution in Widget", epss: 0.5 }),
  row({ id: "CVE-2024-1001", pub: "2024-02-01", cvss: 5, sev: "M", cwe: "CWE-89", vendor: "Acme", product: "Gadget", desc: "SQL injection in Gadget", epss: 0.001 }),
  row({ id: "CVE-2024-1002", pub: "2024-04-01", state: "R", cvss: null, sev: "", cwe: "", vendor: "", product: "", desc: "** REJECT ** duplicate", epss: null }),
  row({ id: "CVE-2024-1003", pub: "2024-01-15", cvss: 7.5, sev: "H", cwe: "CWE-79", vendor: "Acmecorp", product: "Thing", desc: "Cross-site scripting", expl: "active", epss: 0.2 })
] });
const ids = (l) => l.map((r) => r.id);

test("filter: rejected hidden by default, text, rating, EPSS, CWE", () => {
  assert.deepEqual(ids(D.filter(S, {}, {}, "id")), ["CVE-2024-1000", "CVE-2024-1001", "CVE-2024-1003"]);
  assert.equal(D.filter(S, { status: "all" }, {}, "id").length, 4);
  assert.deepEqual(ids(D.filter(S, { status: "R" }, {}, "id")), ["CVE-2024-1002"]);
  assert.deepEqual(ids(D.filter(S, { q: "SQL" }, {}, "id")), ["CVE-2024-1001"]);
  assert.deepEqual(ids(D.filter(S, { q: "cve-2024-1003" }, {}, "id")), ["CVE-2024-1003"]);
  assert.deepEqual(ids(D.filter(S, { sev: "H" }, {}, "id")), ["CVE-2024-1003"]);
  assert.deepEqual(ids(D.filter(S, { minEpss: 0.1 }, {}, "id")), ["CVE-2024-1000", "CVE-2024-1003"]);
  assert.deepEqual(ids(D.filter(S, { cwe: "79" }, {}, "id")), ["CVE-2024-1000", "CVE-2024-1003"]);
  assert.deepEqual(ids(D.filter(S, { cwe: "cwe-89" }, {}, "id")), ["CVE-2024-1001"]);
});

test("filter: vendor matches vendor or product text", () => {
  assert.deepEqual(ids(D.filter(S, { vendor: "gadget" }, {}, "id")), ["CVE-2024-1001"]);
  assert.deepEqual(ids(D.filter(S, { vendor: "Acme" }, {}, "id")), ["CVE-2024-1000", "CVE-2024-1001", "CVE-2024-1003"]);   // substring: Acmecorp too
  assert.deepEqual(ids(D.filter(S, { vendor: "acme widget" }, {}, "id")), ["CVE-2024-1000"]);
});

test("filter: exploited uses the row's own CISA flags and the joined catalog, own keys only", () => {
  assert.deepEqual(ids(D.filter(S, { exploited: true }, {}, "id")), ["CVE-2024-1003"]);
  assert.deepEqual(ids(D.filter(S, { exploited: true }, { "CVE-2024-1001": true }, "id")), ["CVE-2024-1001", "CVE-2024-1003"]);
  assert.deepEqual(ids(D.filter(S, { exploited: true }, null, "id")), ["CVE-2024-1003"]);
  assert.deepEqual(ids(D.filter(S, { exploited: true }, Object.create({ "CVE-2024-1000": 1 }), "id")), ["CVE-2024-1003"]);
});

test("sort orders", () => {
  assert.deepEqual(ids(D.filter(S, { status: "all" }, {}, "pub")), ["CVE-2024-1002", "CVE-2024-1000", "CVE-2024-1001", "CVE-2024-1003"]);
  assert.deepEqual(ids(D.filter(S, { status: "all" }, {}, "old")), ["CVE-2024-1003", "CVE-2024-1001", "CVE-2024-1000", "CVE-2024-1002"]);
  assert.deepEqual(ids(D.filter(S, { status: "all" }, {}, "cvss")), ["CVE-2024-1000", "CVE-2024-1003", "CVE-2024-1001", "CVE-2024-1002"]);   // no score last
  assert.deepEqual(ids(D.filter(S, { status: "all" }, {}, "epss")), ["CVE-2024-1000", "CVE-2024-1003", "CVE-2024-1001", "CVE-2024-1002"]);
  assert.deepEqual(ids(D.filter(S, {}, {}, "nonsense")), ids(D.filter(S, {}, {}, "pub")));
});

test("page slices and clamps; topVendors counts", () => {
  const l = Array.from({ length: 450 }, (_, i) => i);
  assert.equal(D.page(l, 0, 200).items.length, 200);
  assert.equal(D.page(l, 2, 200).items.length, 50);
  assert.equal(D.page(l, 9, 200).page, 2);
  assert.equal(D.page(l, -3, 200).page, 0);
  assert.equal(D.page([], 0, 200).pages, 1);
  assert.deepEqual(plain(D.topVendors(S, 2)), [["Acme", 2], ["Acmecorp", 1]]);
});

test("cleanIndex keeps the per-year file list and drops bad entries; an older index has none", () => {
  const ix = D.cleanIndex({ total: 3, by_year: { 2024: 2, 2021: 1 }, files_by_year: { 2024: [0, 3, -1, 2.5, "7", 120], 2021: [] } });
  const y24 = ix.years.find((y) => y.year === 2024), y21 = ix.years.find((y) => y.year === 2021);
  assert.deepEqual(y24.files, [0, 3, 120]);
  assert.equal(y21.files, null);
  assert.equal(D.cleanIndex({ total: 1, by_year: { 2024: 1 } }).years[0].files, null);
});

test("rating: CISA's SSVC table, inputs with their source, and BOD 26-04 timelines", () => {
  const log4 = { id: "CVE-2021-44228", cvss: 10, sev: "C", kev: "2021-12-10", expl: "active", auto: "yes", ti: "total", epss: 0.99999, pct: 1, ransom: true, due: "2021-12-24" };
  const r = D.rate(log4, { today: "2026-11-19" });
  assert.equal(r.decision, "act"); assert.equal(r.overdue, true);
  assert.deepEqual(plain(r.inputs.map((i) => [i.name, i.value, i.source])), [["Exploitation", "active", "cisa-kev"], ["Automatable", "yes", "cisa"], ["Technical impact", "total", "cisa"], ["Mission and well-being", "medium", "default"]]);
  assert.equal(r.fixBy.exposed.days, 3); assert.equal(r.fixBy.exposed.triage, true); assert.equal(r.fixBy.internal.days, 3);
  assert.ok(r.signals.some((s) => /ransomware/.test(s.text)));
  // every row of CISA's coordinator table (CERT/CC cisa_coordinator_2_0_3.csv), mission low/medium/high
  const want = { "none|no|partial": "T T T", "none|no|total": "T T T*", "none|yes|partial": "T T At", "none|yes|total": "T T At", "poc|no|partial": "T T T*", "poc|no|total": "T T* At",
    "poc|yes|partial": "T T At", "poc|yes|total": "T T* At", "active|no|partial": "T T At", "active|no|total": "T At Ac", "active|yes|partial": "At At Ac", "active|yes|total": "At Ac Ac" };
  const code = { track: "T", "track*": "T*", attend: "At", act: "Ac" };
  for (const [k, v] of Object.entries(want)) { const [e, a, t] = k.split("|"); assert.equal(["low", "medium", "high"].map((m) => code[D.ssvcDecision(e, a, t, m)]).join(" "), v, k); }
  // BOD 26-04 Table 1, all 16 rows
  const bod = [[1, 1, "yes", "total", "3t"], [1, 1, "yes", "partial", "3"], [1, 1, "no", "total", "3t"], [1, 1, "no", "partial", "14"], [1, 0, "yes", "total", "3"], [1, 0, "yes", "partial", "14"], [1, 0, "no", "total", "14"], [1, 0, "no", "partial", "60"],
    [0, 1, "yes", "total", "3t"], [0, 1, "yes", "partial", "14"], [0, 1, "no", "total", "14"], [0, 1, "no", "partial", "14"], [0, 0, "yes", "total", "60"], [0, 0, "yes", "partial", "60"], [0, 0, "no", "total", "up"], [0, 0, "no", "partial", "up"]];
  for (const [x, k, a, t, w] of bod) { const b = D.bodTimeline(!!x, !!k, a, t); assert.equal(b.days === null ? "up" : b.days + (b.triage ? "t" : ""), w, [x, k, a, t].join("|")); }
});
test("rating: estimates from the CVSS vector are labelled, EPSS only raises Track to Track*, rejected CVEs are not rated", () => {
  const rce = { id: "CVE-2026-1", cvss: 9.8, sev: "C", vec: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", epss: 0.3, pct: 0.97 };
  const r = D.rate(rce);
  assert.equal(r.decision, "track*"); assert.equal(r.estimated, true);
  assert.deepEqual(plain(r.inputs.slice(1, 3).map((i) => [i.value, i.source])), [["yes", "estimate"], ["total", "estimate"]]);
  assert.equal(D.rate({ ...rce, pct: 0.5 }).decision, "track");
  assert.equal(D.rate({ ...rce, expl: "active" }, { mission: "high" }).decision, "act");
  assert.equal(D.automatableFromVector("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), "no");
  assert.equal(D.impactFromVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), "total");
  assert.equal(D.rate({ id: "CVE-2020-1", rejected: true }).decision, null);
});

test("rating: the record's own exploitation evidence and the BOD 26-04 floor for known-exploited flaws", () => {
  const seen = { id: "CVE-2026-126755", cvss: 9.8, sev: "C", expl: "poc", auto: "yes", ti: "total", desc: "Auth bypass. Exploitation evidence was first observed by the Shadowserver Foundation on 2026-09-16." };
  const a = D.rate(seen); assert.equal(a.inputs[0].value, "active"); assert.equal(a.inputs[0].source, "description"); assert.equal(a.decision, "act");
  const pub = D.rate({ id: "CVE-2026-132142", cvss: 7.2, vec: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", desc: "Stack overflow. The exploit has been published and may be used." });
  assert.equal(pub.inputs[0].value, "public PoC");
  const plex = { id: "CVE-2026-96652", cvss: 5.3, kev: "2026-10-01", expl: "active", auto: "no", ti: "partial" };
  const p = D.rate(plex); assert.equal(p.decision, "attend"); assert.ok(/BOD 26-04/.test(p.signals[0].text));   // table says Track; KEV is 14 days
  assert.equal(D.rate(plex, { exposed: true }).decision, "attend");
  assert.equal(D.rate({ ...plex, ti: "total" }, { exposed: true }).decision, "act");   // 3 days and forensic triage
});

test("CyberView rating: CVSS base x CVSS v3.1 Exploit Code Maturity, CVSS Roundup and CVSS's bands", () => {
  const v31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
  // exploited in the wild (CISA KEV): E High x 1.00, the base score stands
  const kev = D.score({ id: "CVE-2026-1", cvss: 9.8, sev: "C", ver: "3.1", vec: v31, kev: "2026-10-01", epss: 0.9, pct: 0.99, ransom: true });
  assert.equal(kev.score, 9.8); assert.equal(kev.band, "Critical"); assert.equal(kev.e.label, "High"); assert.equal(kev.e.value, 1); assert.equal(kev.confidence, "High");
  assert.equal(kev.text, "CVSS 9.8 (assigner or CISA, v3.1) x 1.00 Exploit Code Maturity: High (on CISA's Known Exploited Vulnerabilities catalog since 2026-10-01) = 9.8 Critical");
  // CISA reports active exploitation, not in the KEV catalog: still High
  assert.equal(D.score({ id: "CVE-2026-2", cvss: 8.1, expl: "active" }).score, 8.1);
  // the record states exploitation in the wild: High, labelled as the assigner's statement
  const wild = D.score({ id: "CVE-2026-3", cvss: 9.1, desc: "This flaw is being exploited in the wild." });
  assert.equal(wild.score, 9.1); assert.ok(/assigner/.test(wild.eWhy));
  // public proof of concept: x 0.94, Roundup(9.212) = 9.3
  const poc = D.score({ id: "CVE-2026-4", cvss: 9.8, expl: "poc" });
  assert.equal(poc.score, 9.3); assert.equal(poc.band, "Critical"); assert.equal(poc.e.label, "Proof-of-Concept");
  assert.equal(D.score({ id: "CVE-2026-5", cvss: 9.8, desc: "A proof-of-concept exploit is available." }).score, 9.3);
  // unproven, NVD's score: x 0.91, Roundup(8.918) = 9.0, the source and version named on the row
  const nvd = D.score({ id: "CVE-2026-6", cvss: null, ncvss: 9.8, nsev: "C", nvec: v31 });
  assert.equal(nvd.score, 9); assert.equal(nvd.band, "Critical"); assert.equal(nvd.e.label, "Unproven"); assert.equal(nvd.confidence, "Medium");
  assert.equal(nvd.text, "CVSS 9.8 (NVD, v3.1) x 0.91 Exploit Code Maturity: Unproven (no exploitation or public exploit reported) = 9.0 Critical");
  // the boundary: 7.5 x 0.91 = 6.825 -> 6.9 Medium, one band below CVSS High, and the row says why
  const b = D.score({ id: "CVE-2026-7", cvss: 7.5, sev: "H", ver: "3.1" });
  assert.equal(b.score, 6.9); assert.equal(b.band, "Medium"); assert.equal(b.baseBand, "High"); assert.ok(b.notes.some((n) => /One band below its CVSS base rating \(High\)/.test(n)));
  // CISA has seen no exploitation: Unproven, said so
  assert.ok(/CISA has seen no exploitation/.test(D.score({ id: "CVE-2026-8", cvss: 5, expl: "none" }).text));
  // no CVSS score at all: not scored, no number, no band
  const ns = D.score({ id: "CVE-2026-9", epss: 0.5, pct: 0.99, kev: "2026-01-01" });
  assert.equal(ns.score, null); assert.equal(ns.band, "Not scored"); assert.ok(/never invents/.test(ns.text));
  // bands are exactly CVSS's
  assert.deepEqual([0, 0.1, 3.9, 4, 6.9, 7, 8.9, 9, 10].map((s) => D.band(s).band), ["None", "Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"]);
  // CVSS v3.1 Appendix A Roundup, floating point guard included
  assert.equal(D.roundup(4.02), 4.1); assert.equal(D.roundup(4.0), 4); assert.equal(D.roundup(9.8 * 0.91), 9); assert.equal(D.roundup(9.8 * 0.94), 9.3);
  // never above the base score, for every base from 0.0 to 10.0 and every maturity
  for (let i = 0; i <= 100; i++) for (const ev of [{}, { expl: "poc" }, { kev: "yes" }]) {
    const s = D.score({ id: "CVE-2026-10", cvss: i / 10, ...ev }); assert.ok(s.score <= i / 10 && s.score >= 0, `${i / 10} ${JSON.stringify(ev)} -> ${s.score}`);
  }
  // nothing else moves it: EPSS, ransomware, dates and the visitor's settings are not in the rating
  const plainRow = { id: "CVE-2026-11", cvss: 7.2 };
  assert.equal(D.score({ ...plainRow, epss: 0.97, pct: 0.999, ransom: true, due: "2020-01-01", pub: "2026-11-19", auto: "yes", ti: "total" }).score, D.score(plainRow).score);
  // other CVSS versions: the v3.1 multiplier applied and said so
  assert.ok(D.score({ id: "CVE-2026-12", cvss: 10, ver: "4.0" }).notes.some((n) => /CVSS v4\.0/.test(n)));
  assert.equal(D.score({ id: "CVE-2020-1", rejected: true }), null);
});

test("CyberView rating: filters by band floor and by CVSS base rating; default sort is priority, then rating, then EPSS", () => {
  assert.deepEqual(ids(D.filter(S, { minScore: 9 }, {}, "id")), ["CVE-2024-1000"]);                       // 9.8 unproven -> 9.0
  assert.deepEqual(ids(D.filter(S, { minScore: 7 }, {}, "id")), ["CVE-2024-1000", "CVE-2024-1003"]);      // 7.5 exploited stays 7.5
  assert.deepEqual(ids(D.filter(S, { minScore: 4 }, {}, "id")), ["CVE-2024-1000", "CVE-2024-1001", "CVE-2024-1003"]);   // 5.0 -> 4.6
  assert.deepEqual(ids(D.filter(S, { baseSev: "High" }, {}, "id")), ["CVE-2024-1003"]);
  assert.deepEqual(ids(D.filter(S, { baseSev: "unscored" }, {}, "id")), []);
  assert.deepEqual(ids(D.filter(S, { status: "all" }, {}, "score")), ["CVE-2024-1000", "CVE-2024-1003", "CVE-2024-1001", "CVE-2024-1002"]);   // not scored last
  // all three are Track for an organisation's ordinary systems, so the CyberView rating orders them
  assert.deepEqual(ids(D.filter(S, {}, {}, "priority")), ["CVE-2024-1000", "CVE-2024-1003", "CVE-2024-1001"]);
  // a higher priority beats a higher rating: known exploited 5.3 with total impact is Act/Attend, ahead of an unexploited 9.8
  const P = D.parseFile({ fields: F, rows: [row({ id: "CVE-2024-3001", cvss: 9.8, sev: "C", epss: 0.5 }), row({ id: "CVE-2024-3002", cvss: 5.3, sev: "M", kev: "2024-05-01", ti: "total", auto: "yes", epss: 0.01 })] });
  assert.deepEqual(ids(D.filter(P, {}, {}, "priority")), ["CVE-2024-3002", "CVE-2024-3001"]);
  // same priority: the higher CyberView rating first, then EPSS
  const T = D.parseFile({ fields: F, rows: [row({ id: "CVE-2024-2001", cvss: 5, sev: "M", vec: "", epss: 0.9 }), row({ id: "CVE-2024-2002", cvss: 6, sev: "M", vec: "", epss: 0.01 }), row({ id: "CVE-2024-2003", cvss: 6, sev: "M", vec: "", epss: 0.05 })] });
  assert.deepEqual(ids(D.filter(T, {}, {}, "priority")), ["CVE-2024-2003", "CVE-2024-2002", "CVE-2024-2001"]);
});

test("cleanIndex reads the CyberView rating band counts (rating_bands) and ignores the old 0 to 100 bands", () => {
  const ix = D.cleanIndex({ total: 9, by_year: { 2024: 9 }, rating_bands: { Critical: 2, High: 3, Medium: 1, Low: 1, None: 1, "Not scored": 1, Elevated: 5 }, bands: { Elevated: 4 } });
  assert.deepEqual(plain(ix.ratingBands), { Critical: 2, High: 3, Medium: 1, Low: 1, None: 1, "Not scored": 1 });
  assert.equal(D.cleanIndex({ total: 1, by_year: { 2024: 1 }, bands: { Critical: 1 } }).ratingBands, null);
});
