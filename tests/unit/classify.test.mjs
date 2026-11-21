import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SECTORS, SURFACES, KW_LAYERS, KW_SECG, placement, keywordLayer, keywordGroup, sectorsOf, surfaceOf } from "../../scripts/lib/taxonomy.mjs";
import { checkClassification, checkEventQuality, CLASSIFY_FROM } from "../../scripts/lib/validate.mjs";
import { needs, planOf, checkOut, merge, compare, assignmentText } from "../../scripts/classify.mjs";
import { sectorOf, sectorBasis, coverage } from "../../scripts/efficiency.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const APP = readFileSync(join(ROOT, "site", "app.js"), "utf8");
const ok = { sectors: { values: ["healthcare-public-health"], basis: "stated" }, surface: { value: "edge-appliance", basis: "inferred" } };
const codes = (p) => p.map((x) => `${x.level}:${x.code}`);

test("validation: values from the fixed lists with a basis pass; anything else is an error", () => {
  assert.deepEqual(checkClassification(ok), []);
  assert.deepEqual(checkClassification({ sectors: { values: ["cross-sector"], basis: "inferred" }, surface: { value: "unknown", basis: "inferred" } }), []);
  assert.deepEqual(codes(checkClassification({ ...ok, sectors: { values: ["hospitals"], basis: "stated" } })), ["error:sectors-value"]);
  assert.deepEqual(codes(checkClassification({ ...ok, sectors: { values: ["energy"], basis: "likely" } })), ["error:classify-basis"]);
  assert.deepEqual(codes(checkClassification({ ...ok, sectors: ["energy"] })), ["error:sectors-shape"]);
  assert.deepEqual(codes(checkClassification({ ...ok, sectors: { values: [], basis: "stated" } })), ["error:sectors-shape"]);
  assert.deepEqual(codes(checkClassification({ ...ok, sectors: { values: ["energy", "dams", "nuclear", "chemical", "water-wastewater"], basis: "stated" } })), ["error:sectors-shape"]);
  assert.deepEqual(codes(checkClassification({ ...ok, sectors: { values: ["energy", "energy"], basis: "stated" } })), ["error:sectors-value"]);
  assert.deepEqual(codes(checkClassification({ ...ok, sectors: { values: ["energy", "unknown"], basis: "inferred" } })), ["error:sectors-value"]);
  assert.deepEqual(codes(checkClassification({ ...ok, surface: { value: "vpn", basis: "stated" } })), ["error:surface-value"]);
  assert.deepEqual(codes(checkClassification({ ...ok, surface: { value: "web-app" } })), ["error:classify-basis"]);
  assert.deepEqual(codes(checkClassification({ ...ok, surface: "web-app" })), ["error:surface-shape"]);
});

test("validation: a missing field warns only for events first seen from CLASSIFY_FROM; old records never block", () => {
  assert.deepEqual(checkClassification({ first_seen: "2026-11-01T00:00:00Z" }), []);
  assert.deepEqual(codes(checkClassification({ first_seen: CLASSIFY_FROM, sectors: ok.sectors })), ["warn:unclassified"]);
  assert.deepEqual(checkClassification({ first_seen: CLASSIFY_FROM, duplicate_of: "x-y-z" }), []);
  // part of the event quality checks, which the build makes errors only for events first seen from QUALITY_STRICT_FROM
  const q = checkEventQuality({ first_seen: "2026-11-10T00:00:00Z", date: "2026-11-10", sources: [], surface: { value: "nope", basis: "stated" } });
  assert.ok(codes(q).includes("error:surface-value"));
});

test("site/app.js keeps the same lists and keyword rules as scripts/lib/taxonomy.mjs", () => {
  const obj = (name) => JSON.parse(APP.match(new RegExp(`var ${name}=(\\{[\\s\\S]*?\\});\\n`))[1]);
  const sx = obj("SECTOR_TX"), ux = obj("SURFACE_TX");
  assert.deepEqual(Object.keys(sx), SECTORS.map((s) => s.k));
  for (const s of SECTORS) assert.deepEqual(sx[s.k], [s.label, s.g || "", s.ci ? 1 : 0], s.k);
  assert.deepEqual(Object.keys(ux), SURFACES.map((s) => s.k));
  for (const s of SURFACES) assert.deepEqual(ux[s.k], [s.label, s.layer || ""], s.k);
  // every lane and group the lists point at exists in the views
  const lanes = [...APP.matchAll(/(?:^\s*|LAYERS=\[)\["([a-z]+)","[^"]+",\/.*?\/\]/gm)].map((m) => m[1]);
  for (const s of SURFACES) if (s.layer) assert.ok(lanes.includes(s.layer), `lane ${s.layer} missing from LAYERS`);
  const secg = APP.match(/var SECG=(\[[^;]*\]);/)[1];
  for (const s of SECTORS) if (s.g) assert.ok(secg.includes(`["${s.g}",`), `group ${s.g} missing from SECG`);
  // the keyword rules the Node side measures against are the ones the page runs
  for (const [k, re] of KW_LAYERS) assert.ok(APP.includes(`["${k}",`) && APP.includes(`,${re}]`), `LAYERS ${k} differs`);
  for (const [k, re] of KW_SECG) assert.ok(APP.includes(`  ${k}:function(e){return ${re}.test(e.lensHay);}`), `LENS ${k} differs`);
});

test("placement: explicit fields win with their basis; without them, or with unknown, the keyword rule decides and says so", () => {
  const vpn = { category: "incident", title: "Fortinet VPN flaw exploited", sector: "Government", tags: [], products: [], org: "City of X" };
  assert.deepEqual(placement(vpn), { lane: { k: "edge", basis: "keyword" }, group: { k: "gov", basis: "keyword" } });
  assert.deepEqual(placement({ ...vpn, ...ok }), { lane: { k: "edge", basis: "inferred" }, group: { k: "health", basis: "stated" } });
  const unk = { ...vpn, sectors: { values: ["unknown"], basis: "inferred" }, surface: { value: "unknown", basis: "inferred" } };
  assert.deepEqual(placement(unk), { lane: { k: "edge", basis: "keyword" }, group: { k: "gov", basis: "keyword" } });
  assert.equal(placement({ ...vpn, sectors: { values: ["cross-sector"], basis: "inferred" } }).group.k, "cross");
  // policy and business news have no lane, whatever the surface says
  assert.equal(placement({ ...vpn, ...ok, category: "policy" }).lane.k, "org");
  assert.equal(keywordLayer({ category: "policy", title: "VPN law" }), "org");
  assert.equal(keywordGroup({ sector: "Universidade Federal" }), "gov"); // the kind of mistake the explicit field fixes
  assert.equal(sectorsOf({ sectors: { values: ["nope", "energy"], basis: "stated" } }).values.join(), "energy");
  assert.equal(surfaceOf({ surface: { value: "web-app", basis: "guess" } }), null);
});

const ev = (id, date, extra = {}) => ({ id, date, category: "incident", title: id, ...extra });

test("plan: only events lacking a field, duplicates left out, every id in exactly one frozen batch", () => {
  const events = [ev("a-1-x", "2026-11-01"), ev("b-2-x", "2026-11-03"), ev("c-3-x", "2026-11-02", ok), ev("d-4-x", "2026-11-04", { sectors: ok.sectors }), ev("e-5-x", "2026-11-05", { duplicate_of: "a-1-x" }), ev("f-6-x", "2026-11-06")];
  assert.deepEqual(events.filter(needs).map((e) => e.id), ["a-1-x", "b-2-x", "d-4-x", "f-6-x"]);
  const p = planOf(events, 3, "2026-11-21T00:00:00Z");
  assert.equal(p.events, 4);
  assert.deepEqual(p.batches.map((b) => b.ids), [["f-6-x", "d-4-x", "b-2-x"], ["a-1-x"]]);
  assert.deepEqual(p.batches.map((b) => b.out), ["classify-out-1.json", "classify-out-2.json"]);
  assert.match(p.plan_id, /^[0-9a-f]{12}$/);
  assert.equal(planOf(events, 3).plan_id, p.plan_id);
  assert.notEqual(planOf(events, 2).plan_id, p.plan_id);
  const text = assignmentText(1, p, events);
  assert.match(text, /plan_id [0-9a-f]{12}, batch 1, 3 events\. Out file: data\/classify-out-1\.json/);
  assert.match(text, /healthcare-public-health: Healthcare and public health \[CISA critical infrastructure\]/);
  assert.match(text, /- id: f-6-x/);
  assert.match(assignmentText(9, p, events), /nothing assigned/);
});

test("apply checks: plan_id, batch, each assigned id exactly once, values and basis", () => {
  const plan = { plan_id: "abc123abc123", batches: [{ batch: 1, out: "classify-out-1.json", ids: ["a-1-x", "b-2-x"] }] }, b = plan.batches[0];
  const item = (id, x = {}) => ({ id, ...ok, why: "a hospital", ...x });
  assert.deepEqual(checkOut(plan, b, { plan_id: plan.plan_id, batch: 1, items: [item("a-1-x"), item("b-2-x")] }), []);
  assert.match(checkOut(plan, b, { plan_id: "old", batch: 1, items: [item("a-1-x"), item("b-2-x")] })[0], /not the current plan/);
  assert.match(checkOut(plan, b, { plan_id: plan.plan_id, batch: 2, items: [item("a-1-x"), item("b-2-x")] })[0], /batch 2 is not 1/);
  assert.deepEqual(checkOut(plan, b, { plan_id: plan.plan_id, batch: 1, items: [item("a-1-x")] }), ["b-2-x: missing"]);
  assert.deepEqual(checkOut(plan, b, { plan_id: plan.plan_id, batch: 1, items: [item("a-1-x")] }, new Set(["a-1-x"])), []); // b left the files
  assert.ok(checkOut(plan, b, { plan_id: plan.plan_id, batch: 1, items: [item("a-1-x"), item("a-1-x"), item("b-2-x")] }).includes("a-1-x: listed 2 times"));
  assert.match(checkOut(plan, b, { plan_id: plan.plan_id, batch: 1, items: [item("a-1-x"), item("b-2-x"), item("z-9-x")] })[0], /z-9-x is not in batch 1/);
  assert.match(checkOut(plan, b, { plan_id: plan.plan_id, batch: 1, items: [item("a-1-x", { surface: { value: "vpn", basis: "stated" } }), item("b-2-x")] })[0], /a-1-x: surface-value/);
  assert.match(checkOut(plan, b, { plan_id: plan.plan_id, batch: 1, items: [item("a-1-x", { surface: undefined }), item("b-2-x")] })[0], /both sectors and surface are required/);
  assert.deepEqual(checkOut(plan, b, null), ["out file missing or not a JSON object"]);
});

test("merge: adds the fields in the file's own key order and never overwrites one already set", () => {
  const raw = { action: "x", category: "incident", title: "t" };
  const m = merge(raw, ok);
  assert.deepEqual(Object.keys(m), ["action", "category", "sectors", "surface", "title"]);
  assert.deepEqual(m.sectors, ok.sectors);
  const set = { ...raw, surface: { value: "web-app", basis: "stated" } };
  assert.deepEqual(merge(set, ok).surface, { value: "web-app", basis: "stated" });
  assert.equal(merge({ ...raw, ...ok }, ok), null);
  assert.deepEqual(Object.keys(merge({ title: "t", category: "incident" }, ok)), ["title", "category", "sectors", "surface"]);
});

test("compare: counts where the keyword rule and the explicit field disagree", () => {
  const r = compare([
    { category: "incident", title: "University data leak", org: "Universidade Federal", sector: "Education", sectors: { values: ["education"], basis: "stated" }, surface: { value: "unknown", basis: "inferred" } },
    { category: "vuln", title: "PHP flaw", sector: "Multiple", sectors: { values: ["cross-sector"], basis: "inferred" }, surface: { value: "web-app", basis: "inferred" } },
    { category: "incident", title: "Hospital VPN hack", sector: "Healthcare", products: ["FortiGate VPN"], ...ok },
  ]);
  assert.equal(r.group.n, 3); assert.equal(r.group.differ, 2); assert.equal(r.group.pairs["gov -> edu"], 1);
  assert.equal(r.lane.n, 2); assert.equal(r.lane.differ, 1); assert.equal(r.lane.keyword_none, 1); assert.equal(r.lane.pairs["org -> app"], 1);
});

test("status coverage: explicit sectors first, keyword otherwise, and the basis is counted", () => {
  assert.equal(sectorOf({ sector: "Government", sectors: { values: ["water-wastewater"], basis: "stated" } }), "water");
  assert.equal(sectorOf({ sector: "Government", sectors: { values: ["unknown"], basis: "inferred" } }), "government");
  assert.equal(sectorBasis({ sectors: { values: ["unknown"], basis: "inferred" } }), "keyword");
  assert.equal(sectorBasis({ sectors: { values: ["education"], basis: "inferred" } }), "inferred");
  const now = Date.parse("2026-11-20T12:00:00Z"), fs = "2026-11-20T10:00:00Z";
  const c = coverage([{ first_seen: fs, sector: "Hospital" }, { first_seen: fs, ...ok }, { first_seen: fs, sectors: { values: ["energy"], basis: "inferred" } }], new Map(), 7, now);
  assert.deepEqual(c.sector, { health: 2, energy: 1 });
  assert.deepEqual(c.sector_basis, { keyword: 1, stated: 1, inferred: 1 });
});
