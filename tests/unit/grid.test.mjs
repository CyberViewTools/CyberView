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

// ---------- keyed sources (phase 2) ----------
// *-nokey.* fixtures are the hosts' real replies to a request without a key, saved on 2026-11-19. cfradar.json and the
// ENTSO-E entsoe-a80.* fixtures are HAND-MADE from the providers' public documentation (no key here), following the
// documented shape exactly: Cloudflare's API reference for /radar/annotations/outages, and the A80 example response in
// ENTSO-E's Postman collection (entsoe-a80.xml is that example verbatim; the zip adds a cancelled and a forced copy).
import { keyMissing, notConnected, parseCfRadar, parseEntsoe, parseEntsoeXml, unzipEntries, ADAPTERS, SOURCES, OPERATORS,
  COUNTRIES, seriesPoints, appendSeries, readLines, rollupDay, rollupSeries, checkSeriesLine, checkMonthly, verifySeries,
  slotIso, REASONS, checkIncident } from "../../scripts/grid.mjs";
import { existsSync, readdirSync } from "node:fs";

test("keyMissing: the real no-key replies of all three hosts read as not connected; other errors do not", () => {
  assert.equal(keyMissing(403, txt("eia-nokey.json")), true);        // {"error":{"code":"API_KEY_MISSING",...}}
  assert.equal(keyMissing(400, txt("cfradar-nokey.json")), true);    // code 9106 "Missing X-Auth-Key, X-Auth-Email or Authorization headers"
  assert.equal(keyMissing(401, txt("entsoe-nokey.xml")), true);      // Acknowledgement, reason 999 "Authentication failed."
  assert.equal(keyMissing(400), true);                               // body not passed on by the fetch layer
  assert.equal(keyMissing(400, '{"success":false,"errors":[{"code":10001,"message":"bad dateRange"}]}'), false);
  assert.equal(keyMissing(500, txt("eia-nokey.json")), false);
  assert.equal(keyMissing(429), false);
  assert.match(notConnected("api.eia.gov").message, /^not connected \(no key saved for api\.eia\.gov\)$/);
});

async function withFetch(fake, fn) {
  const real = globalThis.fetch; globalThis.fetch = fake;
  try { return await fn(); } finally { globalThis.fetch = real; }
}
const reply = (status, body, type = "application/json") => async () => new Response(body, { status, headers: { "content-type": type } });

test("adapters: without a key each keyed host is 'not connected', and no key is ever sent by the code", async () => {
  const seen = [];
  for (const [k, status, f] of [["eia", 403, "eia-nokey.json"], ["cfradar", 400, "cfradar-nokey.json"], ["entsoe", 401, "entsoe-nokey.xml"]]) {
    await withFetch(async (url, init) => { seen.push({ url: String(url), headers: (init && init.headers) || {} }); return reply(status, txt(f))(); }, async () => {
      await assert.rejects(ADAPTERS[k](), (e) => e.code === "not_connected" && e.message === `not connected (no key saved for ${SOURCES[k].host})`);
    });
  }
  assert.equal(seen.length, 3);                                     // ENTSO-E stops at the first zone
  for (const s of seen) {
    assert.doesNotMatch(s.url, /api_key|securityToken|token=/i);
    assert.deepEqual(Object.keys(s.headers).map((h) => h.toLowerCase()), ["user-agent"]);
  }
  // a connected reply: Radar parses; EIA waits for a saved real reply; ENTSO-E is fetched as bytes (net.mjs as:"buffer"),
  // so a reply that is not a real zip is refused as a bad shape, never mistaken for "needs a binary fetch"
  await withFetch(reply(200, txt("cfradar.json")), async () => { assert.ok((await ADAPTERS.cfradar()).every((x) => x.source === "cfradar")); });
  await withFetch(reply(200, txt("eia.json")), async () => { assert.ok(Array.isArray(await ADAPTERS.eia())); });
  await withFetch(reply(200, "PK\u0003\u0004zip", "application/zip"), async () => { await assert.rejects(ADAPTERS.entsoe(), (e) => e.code !== "needs_binary_fetch" && /shape|zip/i.test(`${e.code} ${e.message}`)); });
  assert.deepEqual(OPERATORS, ["hydroquebec", "bchydro", "ukpn", "eskom", "ercot", "aemo"]);
});

test("Cloudflare Radar (hand-made from the docs): power-cause outages only, one item per country, centroid, ended > 24 h dropped", () => {
  const items = parseCfRadar(json("cfradar.json"), Date.parse("2026-11-19T22:00:00Z"));
  noErrors(items);
  assert.deepEqual(items.map((x) => x.id), ["cfradar:1001-ZA", "cfradar:1002-CU"]);   // cable cut and the old one left out, XX1 ignored
  const za = items[0];
  assert.equal(za.country, "ZA");
  assert.deepEqual([za.lat, za.lng], [COUNTRIES.ZA[1], COUNTRIES.ZA[2]]);
  assert.equal(za.kind, "outage");
  assert.equal(za.started_at, "2026-11-19T14:11:19Z");
  assert.equal(za.restore_est, "2026-11-19T20:00:00Z");
  assert.equal(za.area, "Gauteng, Free State");
  assert.equal(za.url, "https://radar.cloudflare.com/outage-center");                 // never the linked third-party page
  assert.equal(items[1].restore_est, "");
  assert.throws(() => parseCfRadar(json("cfradar-nokey.json")), (e) => e.code === "bad_shape");
});

test("ENTSO-E (hand-made from the docs): zip of documents, cancelled skipped, A53 planned, A54 forced, zone to country", () => {
  const entries = unzipEntries(readFileSync(join(FX, "entsoe-a80.zip")));
  assert.equal(entries.length, 3);                                    // two deflated, one stored
  assert.ok(entries.every((e) => e.text.includes("<Unavailability_MarketDocument")));
  const now = Date.parse("2023-01-03T13:00:00Z");
  const items = parseEntsoe(readFileSync(join(FX, "entsoe-a80.zip")), now);
  noErrors(items);
  assert.deepEqual(items.map((x) => [x.country, x.planned, x.kind]), [["BE", true, "supply_warning"], ["FR", false, "supply_warning"]]);
  assert.equal(items[0].area, "COO II T (230 MW)");
  assert.equal(items[0].cause, "Awaiting information");
  assert.equal(items[0].started_at, "2023-01-03T11:54:00Z");
  assert.equal(items[0].restore_est, "2023-01-03T14:00:00Z");
  assert.equal(items[1].cause, "Unit trip & repair");
  assert.deepEqual(parseEntsoeXml(txt("entsoe-a80.xml"), now).map((x) => x.id), ["entsoe:nCYGn4HPvOBiVrWtRFL35g-1"]);
  assert.deepEqual(parseEntsoeXml(txt("entsoe-a80.xml"), now + 24 * 3600e3), []);    // ended more than 6 h ago
  assert.throws(() => parseEntsoe(txt("entsoe-nokey.xml")), (e) => e.code === "entsoe_ack" && /Authentication failed/.test(e.message));
  assert.deepEqual(parseEntsoeXml(txt("entsoe-nokey.xml").replace("Authentication failed.", "No matching data found for Data item ...")), []);
  assert.throws(() => unzipEntries(Buffer.from("not a zip")), (e) => e.code === "bad_shape");
  assert.throws(() => parseEntsoeXml("<html/>"), (e) => e.code === "bad_shape");
});

test("triage: corroborated asks for research below 50,000, after the stronger reasons and never over planned work", () => {
  assert.deepEqual(triage(inc({ peak_customers: 8000 }), cfg, { corroborated: true }), { research_needed: true, research_reason: "corroborated" });
  assert.equal(triage(inc({ peak_customers: 60000 }), cfg, { corroborated: true }).research_reason, "big");
  assert.equal(triage(inc({ peak_customers: 8000, planned_share: 0.9 }), cfg, { corroborated: true }).research_reason, "planned");
  assert.equal(triage(inc({ peak_customers: 8000 }), cfg).research_reason, "small");
  assert.ok(REASONS.includes("corroborated"));
  const st = track({ open: [], closed: [] }, [out("bchydro", "British Columbia", 9000)], cfg, T0);
  applyTriage(st.open[0], cfg, { corroborated: true });
  assert.equal(st.open[0].research_reason, "corroborated");
  assert.deepEqual(checkIncident(st.open[0]), []);
});

// ---------- series ----------
test("seriesPoints: one point per operator region per 15-minute slot, zeros for quiet regions of sources that answered", () => {
  const now = Date.parse("2026-11-19T10:07:00Z");
  const items = [out("hydroquebec", "Quebec", 3000), out("hydroquebec", "Quebec", 1000, { planned: true }), ...parseEskom("3", now),
    ...parseCfRadar(json("cfradar.json"), Date.parse("2026-11-19T22:00:00Z"))];
  const pts = seriesPoints(items, ["hydroquebec", "eskom", "aemo", "cfradar"], now);
  pts.forEach((p) => assert.deepEqual(checkSeriesLine(p), [], JSON.stringify(p)));
  assert.ok(pts.every((p) => p.at === "2026-11-19T10:00:00Z"));
  const by = Object.fromEntries(pts.map((p) => [`${p.source}|${p.region}`, p]));
  assert.deepEqual(by["hydroquebec|Quebec"], { at: "2026-11-19T10:00:00Z", source: "hydroquebec", region: "Quebec", customers: 4000, unplanned: 3000, level: null });
  assert.deepEqual([by["eskom|South Africa"].customers, by["eskom|South Africa"].level], [null, 2]);
  assert.deepEqual([by["aemo|SA1"].unplanned, by["aemo|SA1"].level], [0, 0]);                // AEMO answered, SA quiet
  assert.equal(by["bchydro|British Columbia"], undefined);                                   // did not answer: no point
  assert.ok(!pts.some((p) => p.source === "cfradar"));                                       // keyed sources are signals only
  assert.equal(slotIso(Date.parse("2026-11-19T10:14:59Z")), "2026-11-19T10:00:00Z");
});

test("appendSeries: at most one line per region per slot (two writers), files by UTC day", () => {
  const dir = mkdtempSync(join(tmpdir(), "grid-series-"));
  const p = (at, unplanned) => ({ at, source: "bchydro", region: "British Columbia", customers: unplanned, unplanned, level: null });
  assert.equal(appendSeries(dir, [p("2026-11-19T23:45:00Z", 10), p("2026-11-20T00:00:00Z", 20)]), 2);
  assert.equal(appendSeries(dir, [p("2026-11-19T23:45:00Z", 99), p("2026-11-20T00:15:00Z", 30)]), 1);
  assert.deepEqual(readLines(join(dir, "2026-11-19.jsonl")).map((x) => x.unplanned), [10]);
  assert.deepEqual(readLines(join(dir, "2026-11-20.jsonl")).map((x) => x.unplanned), [20, 30]);
});

test("roll-up: daily max/mean per region, only files older than the kept days (here 90) removed, monthly merged and verified", () => {
  const root = mkdtempSync(join(tmpdir(), "grid-rollup-")), dir = join(root, "data", "grid", "series");
  mkdirSync(dir, { recursive: true });
  const now = Date.parse("2026-11-19T12:00:00Z");
  const p = (day, hh, source, region, unplanned, level = null) => ({ at: `${day}T${hh}:00:00Z`, source, region, customers: level == null ? unplanned : null, unplanned, level });
  const write = (day, pts) => writeFileSync(join(dir, `${day}.jsonl`), pts.map((x) => JSON.stringify(x)).join("\n") + "\n");
  write("2026-08-10", [p("2026-08-10", "01", "bchydro", "British Columbia", 100), p("2026-08-10", "02", "bchydro", "British Columbia", 300),
    p("2026-08-10", "02", "bchydro", "British Columbia", 300), p("2026-08-10", "03", "eskom", "South Africa", 0, 2)]);
  write("2026-08-20", [p("2026-08-20", "01", "ukpn", "London, South East and East of England", 50)]);
  write("2026-08-21", [p("2026-08-21", "01", "ukpn", "London, South East and East of England", 70)]);   // exactly 90 days old: kept
  write("2026-11-19", [p("2026-11-19", "01", "ukpn", "London, South East and East of England", 70)]);
  assert.deepEqual(rollupDay(readLines(join(dir, "2026-08-10.jsonl"))), {
    "bchydro|British Columbia": { max: 300, mean: 200, points: 2, level_max: null },   // the duplicate slot counted once
    "eskom|South Africa": { max: 0, mean: 0, points: 1, level_max: 2 },
  });
  assert.deepEqual(rollupSeries(dir, now, 90), ["2026-08-10", "2026-08-20"]);
  assert.deepEqual(readdirSync(dir).filter((f) => f.endsWith(".jsonl")).sort(), ["2026-08-21.jsonl", "2026-11-19.jsonl"]);
  const m = JSON.parse(readFileSync(join(dir, "monthly", "2026-08.json"), "utf8"));
  assert.deepEqual(Object.keys(m.days), ["2026-08-10", "2026-08-20"]);
  assert.equal(m.days["2026-08-10"]["bchydro|British Columbia"].max, 300);
  assert.deepEqual(rollupSeries(dir, now, 90), []);                                         // idempotent
  assert.deepEqual(verifySeries(root), []);
  writeFileSync(join(dir, "2026-11-19.jsonl"), JSON.stringify(p("2026-11-18", "01", "cfradar", "Cuba", 5)) + "\n{\n");
  const bad = verifySeries(root)[0];
  assert.equal(bad.file, "data/grid/series/2026-11-19.jsonl");
  assert.ok(bad.errors.includes("line 1.source: not an operator source"));
  assert.ok(bad.errors.includes("line 1.at: not on 2026-11-19"));
  assert.ok(bad.errors.includes("line 2: not JSON"));
  assert.deepEqual(checkMonthly({ month: "2026-08", days: { "2026-08-01": { "x|y": { max: 1, mean: 5, points: 1, level_max: null } } } }, "2026-08.json"),
    ["days.2026-08-01.x|y: not { max, mean <= max, points, level_max }"]);
  assert.ok(existsSync(join(dir, "monthly", "2026-08.json")));
});

// EIA: the fixture is a REAL reply (saved 2026-11-19 with the owner's key, 5 balancing authorities, 30 hours). The
// variants change only the values named, to show each rule found on that night's live data.
test("EIA: demand far under both forecast and yesterday for two complete hours is a signal; habits and partial hours are not", async () => {
  const { parseEia } = await import("../../scripts/grid.mjs");
  const real = json("eia.json"), rows = real.response.data;
  const newest = rows.map((r) => r.period).filter((p, i) => rows[i].type === "D").sort().pop();
  const now = Date.parse(newest + ":30:00Z");
  assert.deepEqual(parseEia(real, now), []);                                           // a normal night: nothing
  const hours = [...new Set(rows.filter((r) => r.respondent === "PJM" && r.type === "D").map((r) => r.period))].sort().reverse();
  const cut = (data, ba, periods, f) => ({ response: { data: data.map((r) => r.respondent === ba && r.type === "D" && periods.includes(r.period) ? { ...r, value: String(Math.round(Number(r.value) * f)) } : r) } });
  // the newest reported hour alone collapsing (LDWP 27 vs 2,540 MWh) is a partly filled hour: ignored
  assert.deepEqual(parseEia(cut(rows, "PJM", [hours[0]], 0.01), now), []);
  // one complete hour down 40%: not enough, it must hold for two
  assert.deepEqual(parseEia(cut(rows, "PJM", [hours[1]], 0.6), now), []);
  // two complete hours down 40% against forecast and against the same hours yesterday: a signal
  const sig = parseEia(cut(rows, "PJM", [hours[1], hours[2]], 0.6), now);
  assert.equal(sig.length, 1);
  assert.equal(sig[0].source, "eia"); assert.equal(sig[0].kind, "supply_warning"); assert.equal(sig[0].customers, null);
  assert.match(sig[0].cause, /under forecast, \d+% under the same hour yesterday/);
  // a forecast that is always high (SRP misses 34-38% at this hour every day): demand matches yesterday, so no signal
  const biased = { response: { data: rows.map((r) => r.respondent === "PJM" && r.type === "DF" ? { ...r, value: String(Math.round(Number(r.value) * 1.6)) } : r) } };
  assert.deepEqual(parseEia(biased, now), []);
  // stale data (older than 6 hours) is not a signal
  assert.deepEqual(parseEia(cut(rows, "PJM", [hours[1], hours[2]], 0.6), now + 12 * 3600e3), []);
});

test("Cloudflare Radar, REAL reply (saved 2026-11-19 with the owner's token): power-cause outages only, while current", async () => {
  const { parseCfRadar } = await import("../../scripts/grid.mjs");
  const real = json("cfradar-real.json");
  const items = parseCfRadar(real, Date.parse("2026-11-08T12:00:00Z"));
  assert.ok(items.length >= 1 && items.every((x) => x.source === "cfradar" && x.kind === "outage" && /^[A-Z]{2}$/.test(x.country)));
  assert.ok(items.some((x) => x.country === "UA"));                                  // 8 Nov: strikes on Ukraine's energy grid
  const causes = new Set(real.result.annotations.map((a) => a.outage.outageCause));
  assert.ok(causes.has("CABLE_CUT") || causes.has("MILITARY_ACTION"));                // the fixture holds other causes, all left out
  assert.equal(items.length, new Set(items.map((x) => x.id)).size);
  assert.deepEqual(parseCfRadar(real, Date.parse("2026-11-19T22:00:00Z")), []);       // all ended over a day before: nothing now
});
