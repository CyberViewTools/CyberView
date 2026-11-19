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

test("CyberView rating: every point listed, ceilings hold, bands and the visitor's context", () => {
  const log4 = { id: "CVE-2021-44228", cvss: 10, sev: "C", vec: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", kev: "2021-12-10", expl: "active", auto: "yes", ti: "total", epss: 0.99999, pct: 1, ransom: true, due: "2021-12-24" };
  const s = D.score(log4, { today: "2026-11-19" });
  assert.equal(s.band, "Critical"); assert.ok(s.score >= 80, String(s.score)); assert.equal(s.confidence, "High");
  const sum = s.factors.reduce((n, f) => n + f.points, 0); assert.equal(s.score, Math.min(100, sum));
  for (const f of s.factors) { assert.ok(f.points <= f.max); assert.equal(f.points, Math.min(f.max, f.items.reduce((n, i) => n + i.points, 0))); }
  assert.equal(s.factors.find((f) => f.factor === "Exploitation").points, 35);
  const low = { id: "CVE-2026-2", cvss: 3.1, sev: "L", vec: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", epss: 0.0004, pct: 0.05 };
  const l = D.score(low, { today: "2026-11-19" }); assert.equal(l.band, "Low");
  assert.ok(D.score(low, { today: "2026-11-19", exposed: true, mission: "high", mine: true }).score - l.score === 15);
  assert.ok(D.score(low, { today: "2026-11-19", exposed: false, mission: "low" }).score <= l.score);
  assert.equal(D.score({ id: "CVE-2020-1", rejected: true }), null);
  assert.equal(D.score({ id: "CVE-2026-3" }).confidence, "Low");
});
