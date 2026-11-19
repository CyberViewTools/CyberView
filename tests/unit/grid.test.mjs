// Unit tests for the grid outage tracker (node --test; no dependencies). Fixtures in tests/fixtures/grid/ are real
// responses saved on 2026-11-19 (trimmed); synthetic variants are built from them inside the tests and say so.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, cpSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import {
  parseHqVersion, parseHydroQuebec, hqCause, parseBcHydro, parseUkpn, parseEskom, parseErcot, parseAemoListing,
  parseAemoNotice, aemoItems, zonedToIso, track, triage, applyTriage, contextItems, checkItem, checkLive, checkIncidents,
  checkContext, verifyAll, ownUrl, DEFAULT_CFG, AI_BY, CONTEXT_SOURCE,
} from "../../scripts/grid.mjs";

const HERE = dirname(fileURLToPath(import.meta.url)), ROOT = join(HERE, "..", "..");
const FX = join(HERE, "..", "fixtures", "grid");
const txt = (f) => readFileSync(join(FX, f), "utf8");
const json = (f) => JSON.parse(txt(f));
const cfg = { ...DEFAULT_CFG, levels: { ...DEFAULT_CFG.levels } };
const noErrors = (items) => items.forEach((x) => assert.deepEqual(checkItem(x), [], x.id));

// ---------- parsers ----------
test("zonedToIso: local wall-clock times to UTC, daylight saving included", () => {
  assert.equal(zonedToIso("2026-11-19 13:28:31", "America/Montreal"), "2026-11-19T18:28:31Z");     // EST, UTC-5
  assert.equal(zonedToIso("2026-07-01 12:00:00", "America/Montreal"), "2026-07-01T16:00:00Z");     // EDT, UTC-4
  assert.equal(zonedToIso("2026-07-01T12:00:00.5", "Europe/London"), "2026-07-01T11:00:00Z");      // BST
  assert.equal(zonedToIso("", "Europe/London"), "");
  assert.equal(zonedToIso("0001-01-01T00:00:00", "Europe/London"), "");
});

test("Hydro-Québec: version, positional rows, planned flag, cause codes", () => {
  assert.equal(parseHqVersion(txt("hydroquebec-bisversion.json").replace(/"/g, "")), "20261119165011");
  assert.equal(parseHqVersion(JSON.parse(txt("hydroquebec-bisversion.json"))), "20261119165011");
  assert.throws(() => parseHqVersion("../x"), (e) => e.code === "bad_shape");
  const items = parseHydroQuebec(json("hydroquebec-bismarkers.json"));
  assert.equal(items.length, 16);
  noErrors(items);
  const big = items.find((x) => x.customers === 3357);
  assert.equal(big.started_at, "2026-11-19T20:36:18Z");
  assert.equal(big.restore_est, "2026-11-19T22:45:00Z");
  assert.deepEqual([big.lat, big.lng], [45.55, -73.55]);
  assert.equal(big.planned, false);
  assert.equal(big.cause, "");                                    // no cause code given
  const planned = items.filter((x) => x.planned);
  assert.deepEqual(planned.map((x) => x.customers).sort((a, b) => a - b), [79, 139]);
  assert.ok(planned.every((x) => x.cause === "Power system repair or improvement"));
  assert.equal(items.find((x) => x.customers === 158).cause, "Material wear and tear or breakdown");   // code 33
  assert.equal(items.filter((x) => x.restore_est === "").length, 2);
  assert.equal(hqCause("44"), "Protection of public safety");
  assert.equal(hqCause("99"), "Unknown");
  assert.equal(hqCause(""), "");
  assert.ok(items.every((x) => x.region === "Quebec" && x.country === "CA" && /^hydroquebec:/.test(x.id)));
  assert.equal(new Set(items.map((x) => x.id)).size, items.length);
  assert.throws(() => parseHydroQuebec({ nope: [] }), (e) => e.code === "bad_shape");
});

test("BC Hydro: customers, planned work by cause text, times from epoch ms", () => {
  const items = parseBcHydro(json("bchydro.json"));
  noErrors(items);
  assert.equal(items.length, json("bchydro.json").length);
  const a = items.find((x) => x.id === "bchydro:2869532");
  assert.equal(a.customers, 1399);
  assert.equal(a.planned, true);
  assert.equal(a.started_at, "2026-11-19T14:52:18Z");
  assert.equal(a.restore_est, "2026-11-19T23:00:00Z");
  assert.match(a.area, /^Bowen Island/);
  const inv = items.filter((x) => x.cause === "Under investigation");
  assert.ok(inv.length >= 1 && inv.every((x) => !x.planned));
  assert.throws(() => parseBcHydro({}), (e) => e.code === "bad_shape");
});

test("UK Power Networks: unplanned and planned only, Multiple and restored rows skipped, cause phrase", () => {
  const d = json("ukpn.json");
  const items = parseUkpn(d);
  noErrors(items);
  assert.equal(items.length, d.results.filter((r) => r.powercuttype === "Unplanned" && !r.restoreddatetime).length);
  assert.ok(!items.some((x) => /MULT-/.test(x.id)));
  const a = items.find((x) => x.id === "ukpn:INCD-470356-G");
  assert.equal(a.customers, 153);
  assert.equal(a.cause, "11kV OH Fault");
  assert.deepEqual([a.lat, a.lng], [51.185, 0.383]);
  assert.match(a.area, /^West Kent Zone: ME18 5/);
  const nogeo = items.find((x) => x.id === "ukpn:INCD-107972-V");
  assert.deepEqual([nogeo.lat, nogeo.lng], [null, null]);
  // synthetic: an active planned cut (the saved planned rows were already restored) counts noplannedcustomers
  const p = { ...d.results.find((r) => r.powercuttype === "Planned"), restoreddatetime: null };
  const [pi] = parseUkpn({ results: [p] });
  assert.equal(pi.planned, true);
  assert.equal(pi.customers, p.noplannedcustomers);
  assert.throws(() => parseUkpn([]), (e) => e.code === "bad_shape");
});

test("Eskom: status value minus one is the stage", () => {
  const [x] = parseEskom(txt("eskom.txt"), Date.parse("2026-11-19T22:00:00Z"));
  assert.equal(x.level, 0);
  assert.equal(x.kind, "load_shedding");
  assert.equal(x.customers, null);
  noErrors([x]);
  assert.equal(parseEskom("5")[0].level, 4);
  assert.throws(() => parseEskom("<html>"), (e) => e.code === "bad_shape");
  assert.throws(() => parseEskom("0"), (e) => e.code === "bad_shape");
});

test("ERCOT: EEA level and update time", () => {
  const [x] = parseErcot(json("ercot.json"));
  assert.equal(x.level, 0);
  assert.equal(x.kind, "grid_emergency");
  assert.equal(x.started_at, "2026-11-19T21:58:33Z");
  assert.equal(x.area, "Normal Conditions");
  noErrors([x]);
  const d = json("ercot.json"); d.current_condition.eea_level = 2;
  assert.equal(parseErcot(d)[0].level, 2);
  assert.throws(() => parseErcot({}), (e) => e.code === "bad_shape");
});

test("AEMO: listing newest first, notice fields, regions, forecasts ignored, directions kept", () => {
  const files = parseAemoListing(txt("aemo-listing.html"));
  assert.equal(files[0], "NEMITWEB1_MKTNOTICE_20261120.R146506");
  assert.ok(files.every((f) => /^NEMITWEB1_MKTNOTICE_\d{8}\.R\d+$/.test(f)));
  assert.throws(() => parseAemoListing("<html></html>"), (e) => e.code === "bad_shape");
  const n = (id) => parseAemoNotice(txt(`aemo-NEMITWEB1_MKTNOTICE_${id}`), `NEMITWEB1_MKTNOTICE_${id}`);
  const fc = n("20261117.R146469"), cancel = n("20261118.R146475"), recl = n("20261119.R146504"), dir = n("20261120.R146506");
  assert.equal(fc.id, 146469);
  assert.equal(fc.type, "RESERVE NOTICE");
  assert.equal(fc.region, "TAS1");
  assert.equal(fc.created_at, "2026-11-17T10:56:45Z");     // 20:56:45 market time (UTC+10)
  assert.equal(recl.region, "QLD1");
  assert.equal(dir.region, "SA1");
  const now = Date.parse("2026-11-20T00:00:00Z");
  const items = aemoItems([fc, cancel, recl, dir], now);
  noErrors(items);
  assert.deepEqual(items.map((x) => [x.id, x.kind, x.level]), [["aemo:146506", "supply_warning", null]]);  // forecast LOR2 is not current
  assert.equal(items[0].url, "https://www.nemweb.com.au/Reports/CURRENT/Market_Notice/NEMITWEB1_MKTNOTICE_20261120.R146506");
  assert.throws(() => parseAemoNotice("hello"), (e) => e.code === "bad_shape");
});

test("AEMO: actual LOR opens a level, cancellation clears it, stale conditions drop (synthetic from a real notice)", () => {
  const base = txt("aemo-NEMITWEB1_MKTNOTICE_20261117.R146469");
  const mk = (id, ref, time = "19/11/2026     20:00:00") => parseAemoNotice(base.replace(/Notice ID\s*:\s*\d+/, `Notice ID : ${id}`)
    .replace(/External Reference\s*:.*$/m, `External Reference : ${ref}`).replace(/Creation Date :.*$/m, `Creation Date :     ${time}`),
  `NEMITWEB1_MKTNOTICE_20261119.R${id}`);
  const lor = mk(900001, "Actual Lack Of Reserve Level 3 (LOR3) in the SA Region on 19/11/2026");
  const now = Date.parse("2026-11-19T12:00:00Z");
  let items = aemoItems([lor], now);
  assert.deepEqual(items.map((x) => [x.region, x.kind, x.level]), [["SA1", "supply_warning", 3]]);
  const cancel = mk(900002, "Cancellation of Actual (LOR3) condition in the SA region - 19/11/2026");
  assert.deepEqual(aemoItems([cancel, lor], now), []);                       // order by notice id, not array order
  const shed = mk(900003, "Load shedding in the VIC region");
  assert.deepEqual(aemoItems([shed], now).map((x) => [x.region, x.kind, x.level]), [["VIC1", "load_shedding", 3]]);
  assert.deepEqual(aemoItems([lor], now + 30 * 3600e3), []);                // no cancellation seen for 30 hours
});

test("item urls must be https on the operator's own host", () => {
  assert.equal(ownUrl("bchydro", "https://www.bchydro.com/x"), "https://www.bchydro.com/x");
  assert.equal(ownUrl("bchydro", "http://www.bchydro.com/x"), "");
  assert.equal(ownUrl("bchydro", "https://evil.example/x"), "");
  assert.equal(ownUrl("bchydro", "javascript:alert(1)"), "");
  assert.equal(ownUrl("nope", "https://www.bchydro.com/x"), "");
});

// ---------- tracker ----------
const out = (source, region, customers, extra = {}) => ({ id: `${source}:${region}-${customers}-${Math.random()}`, source,
  country: "CA", region, area: "", lat: 46, lng: -72, customers, kind: "outage", planned: false, cause: "", level: null,
  started_at: "", restore_est: "", url: "", ...extra });
const T0 = Date.parse("2026-11-19T10:00:00Z"), H = 3600e3;

test("tracker: opens at open_customers, tracks peak, closes after 2 quiet collections, keeps 30 days of closed", () => {
  let st = track({ open: [], closed: [] }, [out("hydroquebec", "Quebec", 4000)], cfg, T0);
  assert.equal(st.open.length, 0);                                           // below open_customers
  st = track(st, [out("hydroquebec", "Quebec", 6000, { cause: "High winds" }), out("hydroquebec", "Quebec", 1000, { planned: true })], cfg, T0 + H);
  assert.equal(st.open.length, 1);
  const id = st.open[0].id;
  assert.equal(id, "grid-hydroquebec-quebec-202611191100");
  assert.equal(st.open[0].customers, 7000);
  assert.equal(st.open[0].name, "Hydro-Québec: 7,000 customers without power");
  assert.equal(st.open[0].planned_share, 0.14);
  assert.deepEqual(st.open[0].causes, [{ cause: "High winds", customers: 6000 }]);
  assert.equal(st.open[0].approx, false);
  st = track(st, [out("hydroquebec", "Quebec", 90000)], cfg, T0 + 2 * H);
  assert.equal(st.open[0].peak_customers, 90000);
  assert.equal(st.open[0].peak_at, "2026-11-19T12:00:00Z");
  st = track(st, [out("hydroquebec", "Quebec", 3000)], cfg, T0 + 3 * H);   // still above close_customers
  assert.equal(st.open.length, 1);
  assert.equal(st.open[0].peak_customers, 90000);
  assert.equal(st.open[0].customers, 3000);
  st = track(st, [out("hydroquebec", "Quebec", 1000)], cfg, T0 + 4 * H);   // quiet 1
  assert.equal(st.open.length, 1);
  assert.equal(st.newlyClosed.length, 0);
  st = track(st, [out("hydroquebec", "Quebec", 3000)], cfg, T0 + 5 * H);   // back up: the count restarts
  st = track(st, [], cfg, T0 + 6 * H);                                     // quiet 1
  assert.equal(st.open.length, 1);
  st = track(st, [], cfg, T0 + 7 * H);                                     // quiet 2: closed
  assert.equal(st.open.length, 0);
  assert.equal(st.newlyClosed.length, 1);
  assert.equal(st.newlyClosed[0].id, id);
  assert.equal(st.newlyClosed[0].closed_at, "2026-11-19T17:00:00Z");
  assert.equal(st.closed.length, 1);
  assert.deepEqual(checkIncidents({ updated_at: "2026-11-19T17:00:00Z", open: st.open, closed: st.closed }), []);
  st = track(st, [], cfg, T0 + 7 * H + 31 * 864e5);
  assert.equal(st.closed.length, 0);                                       // older than 30 days
  assert.equal(st.newlyClosed.length, 0);
});

test("tracker: one incident per operator region; signals open at level 1 with a fixed approximate centroid", () => {
  const items = [out("hydroquebec", "Quebec", 3000), out("hydroquebec", "Quebec", 3000), out("bchydro", "British Columbia", 5500),
    ...parseEskom("5", T0), ...parseErcot(json("ercot.json"))];
  const st = track({ open: [], closed: [] }, items, cfg, T0);
  assert.deepEqual(st.open.map((i) => i.source).sort(), ["bchydro", "eskom", "hydroquebec"]);   // ERCOT at EEA 0 does not open
  const esk = st.open.find((i) => i.source === "eskom");
  assert.equal(esk.level, 4);
  assert.equal(esk.customers, null);
  assert.equal(esk.kind, "load_shedding");
  assert.equal(esk.approx, true);
  assert.deepEqual([esk.lat, esk.lng], [-28.5, 25.5]);
  assert.equal(esk.name, "Eskom: load-shedding stage 4");
  const st2 = track(st, [...parseEskom("1", T0)], cfg, T0 + H);
  assert.equal(st2.open.find((i) => i.source === "eskom").level, 0);
  assert.equal(st2.open.find((i) => i.source === "eskom").peak_level, 4);
});

// ---------- triage ----------
const inc = (o) => ({ source: "hydroquebec", peak_customers: 0, level: null, planned_share: 0, causes: [], ...o });
test("triage: reason codes", () => {
  assert.deepEqual(triage(inc({ peak_customers: 60000 }), cfg), { research_needed: true, research_reason: "big" });
  assert.deepEqual(triage(inc({ peak_customers: 12000, causes: [{ cause: "Under investigation", customers: 12000 }] }), cfg),
    { research_needed: true, research_reason: "suspicious_cause" });
  assert.equal(triage(inc({ peak_customers: 9000, causes: [{ cause: "Unknown", customers: 9000 }] }), cfg).research_reason, "small");
  assert.deepEqual(triage(inc({ source: "eskom", peak_customers: null, level: 4 }), cfg), { research_needed: true, research_reason: "grid_level" });
  assert.equal(triage(inc({ source: "eskom", peak_customers: null, level: 3 }), cfg).research_reason, "small");
  assert.equal(triage(inc({ source: "ercot", peak_customers: null, level: 0, peak_level: 1 }), cfg).research_reason, "grid_level");
  assert.deepEqual(triage(inc({ peak_customers: 80000, planned_share: 0.8 }), cfg), { research_needed: false, research_reason: "planned" });
  assert.deepEqual(triage(inc({ peak_customers: 20000, causes: [{ cause: "High winds", customers: 20000 }] }), cfg),
    { research_needed: false, research_reason: "weather" });
  assert.equal(triage(inc({ peak_customers: 20000, causes: [{ cause: "Equipment failure", customers: 9 }, { cause: "Storm", customers: 1 }] }), cfg).research_reason, "small");
  assert.equal(triage(inc({ peak_customers: 20000, causes: [{ cause: "LV Service fault", customers: 9 }] }), cfg).research_reason, "small");  // "service" is not ice
  assert.equal(triage(inc({ peak_customers: 6000 }), cfg).research_reason, "small");
  // once asked, it keeps asking
  const i = inc({ peak_customers: 60000, research_needed: true, research_reason: "big" });
  i.planned_share = 0.9;
  assert.equal(applyTriage(i, cfg).research_reason, "big");
});

// ---------- context ----------
test("contextItems: open only, biggest first, max 60, research merge", () => {
  const mk = (n, customers, extra = {}) => ({ id: `grid-hydroquebec-quebec-2026111910${String(n).padStart(2, "0")}`, source: "hydroquebec",
    country: "CA", region: "Quebec", kind: "outage", name: `x${n}`, opened_at: "2026-11-19T10:00:00Z", closed_at: "", customers,
    level: null, causes: [{ cause: "High winds", customers }], lat: 46, lng: -72, approx: false, url: "https://pannes.hydroquebec.com/pannes/", ...extra });
  const open = Array.from({ length: 70 }, (_, n) => mk(n, 1000 * (n + 1)));
  open.push({ ...mk(99, null), source: "eskom", country: "ZA", kind: "load_shedding", level: 6, url: "https://evil.example/" });
  open.push(mk(98, 10 ** 9, { closed_at: "2026-11-19T11:00:00Z" }));
  const research = { [open[69].id]: { decision: "weather", cause_summary: "Storm damage <b>per</b> the operator.", sources: [], by: "x" },
    [open[68].id]: { decision: "made_up", cause_summary: "no" } };
  const items = contextItems({ open }, research);
  assert.equal(items.length, 60);
  assert.equal(items[0].source, "eskom");                                   // level 6 ranks as 600,000 customers
  assert.equal(items[0].url, "");                                           // not the operator's host
  assert.equal(items[1].customers, 70000);
  assert.deepEqual(items[1].checked, { decision: "weather", summary: "Storm damage b per /b the operator.", by: AI_BY });
  assert.equal(items[2].checked, null);                                     // unknown decision ignored
  assert.equal(items[1].cause, "High winds");
  assert.equal(items[1].since, "2026-11-19T10:00:00Z");
  assert.ok(!items.some((x) => x.customers === 10 ** 9));
  assert.deepEqual(checkContext({ layer: "grid", source: CONTEXT_SOURCE, source_url: "", fetched_at: "2026-11-19T10:00:00Z", ok: true, error: "", items }), []);
});

// ---------- verify ----------
test("verify: catches a broken file and names the field", () => {
  const dir = mkdtempSync(join(tmpdir(), "grid-verify-"));
  mkdirSync(join(dir, "config")); mkdirSync(join(dir, "data", "grid", "history"), { recursive: true }); mkdirSync(join(dir, "data", "context"));
  cpSync(join(ROOT, "config", "grid.json"), join(dir, "config", "grid.json"));
  const items = parseBcHydro(json("bchydro.json"));
  const live = { fetched_at: "2026-11-19T10:00:00Z", sources: { bchydro: { name: "BC Hydro", url: "https://www.bchydro.com/x", ok: true, error: "", fetched_at: "2026-11-19T10:00:00Z", items: items.length } }, items };
  assert.deepEqual(checkLive(live), []);
  const st = track({ open: [], closed: [] }, [out("bchydro", "British Columbia", 9000)], cfg, T0);
  writeFileSync(join(dir, "data", "grid", "live.json"), JSON.stringify(live));
  writeFileSync(join(dir, "data", "grid", "incidents.json"), JSON.stringify({ updated_at: "2026-11-19T10:00:00Z", open: st.open, closed: [] }));
  writeFileSync(join(dir, "data", "context", "grid.json"), JSON.stringify({ layer: "grid", source: CONTEXT_SOURCE, source_url: "", fetched_at: "2026-11-19T10:00:00Z", ok: true, error: "", items: contextItems(st.open) }));
  assert.deepEqual(verifyAll(dir), []);
  // break one field in each file
  live.items[3].url = "https://evil.example/";
  writeFileSync(join(dir, "data", "grid", "live.json"), JSON.stringify(live));
  st.open[0].planned_share = 4;
  writeFileSync(join(dir, "data", "grid", "incidents.json"), JSON.stringify({ updated_at: "2026-11-19T10:00:00Z", open: st.open, closed: [] }));
  writeFileSync(join(dir, "data", "grid", "history", "2026-11.jsonl"), JSON.stringify({ ...st.open[0], planned_share: 0 }) + "\nnot json\n");
  const bad = verifyAll(dir);
  const byFile = Object.fromEntries(bad.map((b) => [b.file, b.errors]));
  assert.deepEqual(byFile["data/grid/live.json"], ["items[3].url: not https on the operator's host"]);
  assert.deepEqual(byFile["data/grid/incidents.json"], ["open[0].planned_share: not 0..1"]);
  assert.ok(byFile["data/grid/history/2026-11.jsonl"].includes("line 1.closed_at: missing"));
  assert.ok(byFile["data/grid/history/2026-11.jsonl"].includes("line 2: not JSON"));
  assert.equal(byFile["data/context/grid.json"], undefined);
  writeFileSync(join(dir, "data", "context", "grid.json"), "{");
  assert.match(verifyAll(dir).find((b) => b.file === "data/context/grid.json").errors[0], /not JSON/);
});
