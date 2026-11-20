// Unit tests for the "world" grid source file (scripts/grid-sources/world.mjs; node --test, no dependencies). Fixtures in
// tests/fixtures/grid/world/ are real replies saved on 2026-11-19/20 by the world scout (Endeavour trimmed by the scout to
// 25 areas with polygons cut to 8 points); synthetic variants are built from them inside the tests and say so.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { zonedToIso, checkItem, PLUGIN_ERRORS, SOURCES as ALL, REGIONS as ALL_REGIONS, OPERATORS } from "../../scripts/grid.mjs";
import plugin, {
  SOURCES, REGIONS, ringCentre, wktCentre, parseEndeavour, parseTasNetworks, weekdayTimeToIso, parseTaipower, rocToIso,
  TAIPOWER_LIGHT, noticeDay, parseEcgRss, parseJsLiteral, parseEnre, enreTotal, parseOns, ONS_COLUMNS, BR_STATES,
} from "../../scripts/grid-sources/world.mjs";

const FX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "grid", "world");
const txt = (f) => readFileSync(join(FX, f), "utf8");
const json = (f) => JSON.parse(txt(f));
const noErrors = (items) => items.forEach((x) => assert.deepEqual(checkItem(x), [], x.id));
const NOW = Date.parse("2026-11-20T00:00:00Z");

test("world: the file loads into grid.mjs with every source, adapter and region", () => {
  assert.deepEqual(PLUGIN_ERRORS.filter((e) => e.startsWith("world.mjs")), []);
  for (const k of Object.keys(SOURCES)) {
    assert.equal(ALL[k].file, "world.mjs", k);
    assert.ok(OPERATORS.includes(k), k);
    assert.equal(typeof plugin.adapters[k], "function", k);
    for (const f of ["name", "country", "url", "page", "terms_url", "terms_ok"]) assert.ok(SOURCES[k][f], `${k}.${f}`);
    assert.ok(SOURCES[k].hosts.includes(new URL(SOURCES[k].page).host), `${k} page on its own host`);
  }
  for (const k of Object.keys(REGIONS)) assert.ok(ALL_REGIONS[k], k);
  assert.equal(Object.keys(BR_STATES).length, 27);
  assert.match(SOURCES["ons-interrupcao-carga"].attribution, /ONS - Operador Nacional do Sistema Elétrico.*CC-BY/);
  assert.match(SOURCES["taipower-supply"].attribution, /Taiwan Power Company.*Open Government Data License: https:\/\/data\.gov\.tw\/license/);
});

test("ringCentre and wktCentre: mean of the ring's points, closing point left out", () => {
  assert.deepEqual(ringCentre([[0, 0], [2, 0], [2, 2], [0, 2], [0, 0]]), { lng: 1, lat: 1 });
  assert.deepEqual(ringCentre([]), { lat: null, lng: null });
  assert.deepEqual(wktCentre("POLYGON ((0 0, 2 0, 2 2, 0 2, 0 0), (0.5 0.5, 1 0.5, 1 1, 0.5 0.5))"), { lng: 1, lat: 1 });  // hole ignored
  assert.deepEqual(wktCentre("MULTIPOLYGON (((0 0, 2 0, 2 2, 0 0)), ((10 10, 12 10, 12 12, 10 10)))").lng, 6);
  assert.deepEqual(wktCentre("POINT (147.35 -42.93)"), { lng: 147.35, lat: -42.93 });
  assert.deepEqual(wktCentre("LINESTRING (0 0, 1 1)"), { lat: null, lng: null });
});

test("Endeavour Energy: unplanned outages and planned work under way, polygon centres, times", () => {
  const items = parseEndeavour(json("endeavour-energy.json"), NOW);
  noErrors(items);
  assert.equal(items.filter((x) => !x.planned).length, 5);
  // 10 planned areas in the fixture: 8 under way at NOW, 1 finished (HIGH RANGE, 16 Nov), 1 finished (GLENFIELD, 18 Nov)
  assert.equal(items.filter((x) => x.planned).length, 8);
  assert.ok(!items.some((x) => /HIGH RANGE|GLENFIELD/.test(x.area)));
  const big = items.find((x) => x.id === "endeavour-energy:inc-48026617");
  assert.equal(big.customers, 132);
  assert.equal(big.cause, "Defective equipment: Electrical Failure");
  assert.equal(big.started_at, "2026-11-19T03:16:00Z");
  assert.equal(big.restore_est, "2026-11-19T09:00:00Z");   // "2026-11-19 09:00:00+00"
  assert.ok(big.lat < -34.6 && big.lat > -34.8 && big.lng > 150.7 && big.lng < 150.8);
  assert.equal(items.find((x) => x.id === "endeavour-energy:inc-48026683").cause, "");   // "None" is no cause
  // before the planned work starts it is not counted (synthetic: an earlier clock)
  assert.equal(parseEndeavour(json("endeavour-energy.json"), Date.parse("2026-11-19T20:00:00Z")).filter((x) => x.planned).length, 0);
  // no polygon: the feed's own centre (synthetic)
  const d = json("endeavour-energy.json"); delete d.areas[0].polygon_geojson;
  const p = parseEndeavour(d, NOW)[0];
  assert.deepEqual([p.lat, p.lng], [-34.728, 150.764]);
  assert.throws(() => parseEndeavour({}), (e) => e.code === "bad_shape");
});

test("TasNetworks: WKT centres, planned wording, customers 'To be confirmed', weekday restoration times", () => {
  const items = parseTasNetworks(json("tasnetworks.json"), zonedToIso);
  noErrors(items);
  assert.equal(items.length, 5);
  const a = items.find((x) => x.id === "tasnetworks:60005");
  assert.equal(a.customers, 63);
  assert.equal(a.planned, true);
  assert.equal(a.started_at, "2026-11-19T21:38:35Z");
  assert.equal(a.restore_est, "2026-11-20T05:00:00Z");      // "Friday 4:00 PM" Hobart (AEDT, UTC+11) after Fri 20 Nov 08:38
  assert.ok(Math.abs(a.lat - -42.936) < 0.01 && Math.abs(a.lng - 147.356) < 0.01);
  const tbc = items.find((x) => x.id === "tasnetworks:60003");
  assert.equal(tbc.customers, null);
  assert.equal(tbc.planned, false);
  assert.equal(tbc.cause, "Under investigation");
  assert.equal(items.find((x) => x.id === "tasnetworks:60008").restore_est, "");   // "To be confirmed - ..."
  assert.equal(weekdayTimeToIso("Monday 9:30 AM", "2026-11-20T08:38:35+11:00", "Australia/Hobart", zonedToIso), "2026-11-22T22:30:00Z");
  assert.equal(weekdayTimeToIso("Friday 12:15 AM", "2026-11-20T08:38:35+11:00", "Australia/Hobart", zonedToIso), "2026-11-19T13:15:00Z");
  assert.throws(() => parseTasNetworks({}, zonedToIso), (e) => e.code === "bad_shape");
});

test("Taipower: reserve light to level, ROC publish time, units of 10 MW", () => {
  const [x] = parseTaipower(json("taipower-supply.json"), zonedToIso);
  noErrors([x]);
  assert.deepEqual([x.kind, x.level, x.customers, x.lat], ["supply_warning", 0, null, null]);
  assert.equal(x.started_at, "2026-11-19T23:20:00Z");          // 115.11.20(五)07:20 Taiwan time
  assert.match(x.cause, /18\.77% \(green, supply ample\) at 11:00-12:00; load now 25,474 MW/);
  assert.equal(rocToIso("115.1.5(一)13:05", zonedToIso), "2026-01-05T05:05:00Z");
  // synthetic: each letter of the legend
  const withLight = (L, rate = "18.77", cap = "596.9") => { const d = json("taipower-supply.json"); Object.assign(d.records[1], { fore_peak_resv_indicator: L, fore_peak_resv_rate: rate, fore_peak_resv_capacity: cap }); return parseTaipower(d, zonedToIso)[0]; };
  assert.deepEqual(["G", "Y", "O", "R", "B"].map((L) => [withLight(L).kind, withLight(L).level]),
    [["supply_warning", 0], ["supply_warning", 1], ["supply_warning", 2], ["supply_warning", 3], ["load_shedding", 3]]);
  assert.equal(TAIPOWER_LIGHT.B[0], "load_shedding");
  // an unknown letter falls back to the legend's thresholds
  assert.equal(withLight("", "8.1").level, 1);
  assert.equal(withLight("?", "5.0", "80").level, 3);         // 800 MW reserve -> red
  assert.equal(withLight("", "3.0", "40").kind, "load_shedding");
  assert.throws(() => parseTaipower({ records: [] }, zonedToIso), (e) => e.code === "bad_shape");
});

test("ECG Ghana: outage and maintenance notices, current or upcoming only, customers null", () => {
  const xml = txt("ecg-ghana-status.xml");
  assert.equal(parseEcgRss(xml, "accra-west", zonedToIso, NOW).length, 0);        // every notice is from October
  const items = parseEcgRss(xml, "accra-west", zonedToIso, Date.parse("2026-10-21T10:00:00Z"));
  noErrors(items);
  // 21 Oct onwards: emergency maintenance 29 Oct, fault 28 Oct, planned 23, 22 and 21 Oct
  assert.equal(items.length, 5);
  assert.ok(items.every((x) => x.customers === null && x.region === "Accra West" && x.lat === null && x.kind === "outage"));
  const fault = items.find((x) => /FAULT/.test(x.cause));
  assert.equal(fault.planned, false);
  assert.equal(fault.started_at, "2026-10-28T00:00:00Z");
  assert.match(fault.url, /^https:\/\/www\.ecg\.com\.gh\/index\.php\/en\/services\/ecg-status\/.*28th-october-2026-accra-west$/);
  assert.equal(items.filter((x) => x.planned).length, 4);
  assert.equal(new Set(items.map((x) => x.id)).size, items.length);
  const central = parseEcgRss(txt("ecg-ghana-central.xml"), "central", zonedToIso, Date.parse("2026-10-29T06:00:00Z"));
  noErrors(central);
  assert.ok(central.some((x) => /DAMAGED CABLES/.test(x.cause) && !x.planned));
  assert.equal(noticeDay("Planned Maintenance Works In Accra West Region-23RD OCTOBER,2026."), "2026-10-23");
  assert.equal(noticeDay("Planned Maintenance in Eastern Region on Thursday 1st October, 2026"), "2026-10-01");
  assert.equal(noticeDay("POWER OUTAGE - TEMA, 28TH MAY, 2026"), "2026-05-28");
  assert.equal(noticeDay("no date"), "");
  assert.throws(() => parseEcgRss("<html></html>", "accra-west", zonedToIso), (e) => e.code === "bad_shape");
  assert.throws(() => parseEcgRss(xml, "nowhere", zonedToIso), (e) => e.code === "bad_shape");
});

test("parseJsLiteral: the ENRE object literal without eval, and nothing beyond literals", () => {
  const d = parseJsLiteral(txt("enre-edenor.js"));
  assert.equal(d.empresa, "EDENOR");
  assert.equal(d.cortesServicioMedia.length, 4);
  assert.equal(d.cortesServicioMedia[1].normalizacion, "2026-11-19 22:00");
  assert.deepEqual(parseJsLiteral("{a: 'it\\'s', \"b\": [1, -2.5, true, null,], c: {d: 'x'},}"), { a: "it's", b: [1, -2.5, true, null], c: { d: "x" } });
  assert.deepEqual(parseJsLiteral("var x = [ /* c */ 'a', // c\n 'b' ];"), ["a", "b"]);
  assert.equal(Object.getPrototypeOf(parseJsLiteral("{__proto__: {polluted: 'yes'}}")), Object.prototype);
  assert.equal(({}).polluted, undefined);
  for (const bad of ["{a: alert(1)}", "{a: 'x' + 'y'}", "{a: 'x'}; alert(1)", "{a: `x`}", "{a: function(){}}", "{a: 'x'", "[".repeat(30) + "]".repeat(30), "{a: 'line\nbreak'}"]) {
    assert.throws(() => parseJsLiteral(bad), (e) => e.code === "bad_shape", bad);
  }
});

test("ENRE: customers out per district, planned lists, restoration time, totals match the feed", () => {
  for (const [f, key] of [["enre-edenor.js", "enre-edenor"], ["enre-edesur.js", "enre-edesur"]]) {
    const items = parseEnre(txt(f), key, zonedToIso);
    noErrors(items);
    assert.equal(items.reduce((a, x) => a + x.customers, 0), enreTotal(txt(f)), f);   // 933 and 4,074
  }
  const edn = parseEnre(txt("enre-edenor.js"), "enre-edenor", zonedToIso);
  const sm = edn.find((x) => x.id === "enre-edenor:gral-san-martin-unplanned");
  assert.equal(sm.customers, 548);
  assert.equal(sm.restore_est, "2026-11-20T01:00:00Z");   // "2026-11-19 22:00" Buenos Aires (UTC-3)
  assert.equal(edn.find((x) => x.id === "enre-edenor:gral-las-heras-unplanned").restore_est, "");   // "Sin datos"
  const eds = parseEnre(txt("enre-edesur.js"), "enre-edesur", zonedToIso);
  const sv = eds.find((x) => x.id === "enre-edesur:san-vicente-planned");
  assert.equal(sv.customers, 892 + 867 + 750 + 815);
  assert.equal(sv.planned, true);
  assert.equal(sv.restore_est, "2026-11-24T00:00:00Z");   // latest of its rows: "2026-11-23 21:00"
  // "CAPITAL" (low voltage) and "CAPITAL FEDERAL" (medium voltage) are one district
  assert.equal(eds.find((x) => x.id === "enre-edesur:capital-federal-unplanned").customers, 141 + 2 + 19 + 3 + 5 + 7);
  assert.throws(() => parseEnre("var data = {fuente: 'x'}", "enre-edenor", zonedToIso), (e) => e.code === "bad_shape");
  assert.throws(() => parseEnre("<html>", "enre-edenor", zonedToIso), (e) => e.code === "bad_shape");
});

test("ONS: last 7 days only, MW in the cause, state as region, header-less tails", () => {
  const items = parseOns(txt("ons-interrupcao-carga.csv"), zonedToIso, NOW);
  noErrors(items);
  assert.deepEqual(items.map((x) => x.region), ["Roraima", "Mato Grosso", "Goiás"]);   // 14, 15 and 17 Nov
  const go = items[2];
  assert.equal(go.started_at, "2026-11-17T18:57:00Z");          // 15:57 Brasília (UTC-3)
  assert.equal(go.cause, "42 MW of load interrupted, mean 9 min (ONS disturbance 6798/2026)");
  assert.deepEqual([go.customers, go.kind, go.country, go.planned], [null, "outage", "BR", false]);
  // a wider window (synthetic clock) keeps one row per disturbance, state and distributor
  const wide = parseOns(txt("ons-interrupcao-carga.csv"), zonedToIso, Date.parse("2026-11-01T12:00:00Z"));
  assert.equal(wide.length, 11);   // 26 Oct to 1 Nov
  assert.ok(wide.some((x) => /^111 MW/.test(x.cause) && x.region === "Minas Gerais"));
  // a byte-range tail: no header, first line cut
  const lines = txt("ons-interrupcao-carga.csv").split("\n");
  const tail = "SUL;RS;CEEEDIS;20.0;176.0;58.6;S;S\n" + lines.slice(-4).join("\n");
  assert.equal(parseOns(tail, zonedToIso, NOW).length, 3);
  assert.equal(ONS_COLUMNS.join(";"), lines[0].trim());
  assert.throws(() => parseOns("a;b\n1;2", zonedToIso, NOW), (e) => e.code === "bad_shape");
});

test("adapters: fetch with h.get only, pass items through h.item, fail on a refusal", async () => {
  const calls = [];
  const h = (body) => ({ zonedToIso, SOURCES: ALL, item: (x) => ({ ...x, cleaned: true }),
    get: async (url, o = {}) => { calls.push([url, Object.keys(o).sort().join(",")]); if (body instanceof Error) throw body; return typeof body === "function" ? body(url) : body; } });
  const tp = await plugin.adapters["taipower-supply"](h(json("taipower-supply.json")));
  assert.equal(tp[0].cleaned, true);
  assert.equal(calls[0][0], SOURCES["taipower-supply"].url);
  const ecg = await plugin.adapters["ecg-ghana"](h(() => txt("ecg-ghana-status.xml").replace(/2026/g, "2099")));
  assert.equal(calls.filter(([u]) => /ecg\.com\.gh/.test(u)).length, 8);   // one feed per ECG region
  assert.ok(ecg.length > 0);
  const refused = Object.assign(new Error("http_403"), { code: "http_403" });
  await assert.rejects(plugin.adapters["ecg-ghana"](h(refused)), (e) => e.code === "http_403");
  await assert.rejects(plugin.adapters["enre-edenor"](h(refused)), (e) => e.code === "http_403");
  const ons = await plugin.adapters["ons-interrupcao-carga"](h(txt("ons-interrupcao-carga.csv")));
  assert.ok(Array.isArray(ons));
});

// ---------- review findings 2026-11-20 (grid-fixes lane) ----------
test("sources-3/2: ENRE districts must add up to the feed's total; its update time is the data time", async () => {
  const { enreTime } = await import("../../scripts/grid-sources/world.mjs");
  const now = Date.parse("2026-11-19T23:40:00Z");                                   // 20:40 in Buenos Aires
  assert.equal(parseEnre(txt("enre-edenor.js"), "enre-edenor", zonedToIso, now).data_at, "2026-11-19T23:20:00Z");   // "20:20"
  assert.equal(enreTime("23:50", zonedToIso, now), "2026-11-19T02:50:00Z");         // later than now: yesterday's
  // synthetic: the medium-voltage list renamed -> its customers vanish from the sum
  const renamed = txt("enre-edenor.js").replace("cortesServicioMedia", "cortesMediaTension");
  assert.throws(() => parseEnre(renamed, "enre-edenor", zonedToIso, now), (e) => e.code === "bad_shape" && /add up/.test(e.message));
});

test("sources-5: ECG's newest notice is the data time, kept or not (a dormant feed shows); ONS rows end after their mean duration (sources-7)", () => {
  const got = parseEcgRss(txt("ecg-ghana-central.xml"), "central", zonedToIso, NOW);
  assert.equal(got.data_at, "2026-10-29T08:14:19Z");
  assert.equal(SOURCES["ecg-ghana"].dormant_hours, 336);
  const go = parseOns(txt("ons-interrupcao-carga.csv"), zonedToIso, NOW)[2];
  assert.equal(go.restore_est, "2026-11-17T19:06:00Z");                             // 18:57Z + 9 min, never "still out"
});
