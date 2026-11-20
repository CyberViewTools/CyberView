// Unit tests for the European grid sources (scripts/grid-sources/europe.mjs; node --test, no dependencies). Fixtures in
// tests/fixtures/grid/europe/ are real replies saved 2026-11-19/20 (the scout's samples, plus real Elexon history:
// SYSWARN notices from 2025-2026 and the demand control instruction of 9 August 2019). Synthetic variants are built
// inside the tests and say so.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ADAPTERS, PLUGIN_ERRORS, SOURCES, REGIONS, checkItem, zonedToIso, str, summarize } from "../../scripts/grid.mjs";
import europe, {
  parseSsen, parseNged, parseCsv, ngedCategory, parseSyswarn, syswarnPeriod, parseDci, parseLiander, lianderBand,
  parseTauron, parseElvia, SSEN_NORTH, SSEN_SOUTH,
} from "../../scripts/grid-sources/europe.mjs";

const FX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "grid", "europe");
const txt = (f) => readFileSync(join(FX, f), "utf8");
const json = (f) => JSON.parse(txt(f));
const isoOf = (s) => { const t = Date.parse(s || ""); return isFinite(t) ? new Date(Math.floor(t / 1000) * 1000).toISOString().replace(".000Z", "Z") : ""; };
// a plain h for the parsers' logic (item() is grid.mjs's own; the adapter tests below run the real one)
const h = { item: (o) => o, str, isoOf, zonedToIso };
const T = (s) => Date.parse(s);

// The real adapters through grid.mjs (real h.item and checkItem), with fetch answered from the fixtures.
const realFetch = globalThis.fetch;
after(() => { globalThis.fetch = realFetch; });
function serve(body, seen = []) {
  globalThis.fetch = async (url, opts) => {
    seen.push({ url: String(url), headers: (opts && opts.headers) || {} });
    return new Response(body, { status: 200 });
  };
  return seen;
}

test("europe.mjs loads with no plugin errors and every source has the README shape", () => {
  assert.deepEqual(PLUGIN_ERRORS.filter((e) => e.startsWith("europe.mjs")), []);
  for (const [k, s] of Object.entries(europe.sources)) {
    assert.equal(SOURCES[k].file, "europe.mjs", k);
    for (const f of ["name", "country", "url", "page", "hosts", "terms_url", "terms_ok"]) assert.ok(s[f], `${k}.${f}`);
    assert.ok("customers_served" in s, k);
    assert.match(s.url, /^https:\/\//); assert.match(s.page, /^https:\/\//);
    assert.ok(s.hosts.includes(new URL(s.page).host), `${k}: page on its own hosts`);
    assert.ok(["allowed", "silent"].includes(s.terms_ok), k);
    assert.equal(typeof europe.adapters[k], "function", k);
  }
  // open-licence sources carry the attribution their licence asks for
  assert.equal(SOURCES["elexon-system-warnings"].attribution, "Contains BMRS data © Elexon Limited copyright and database right {year}");
  assert.equal(SOURCES["elexon-demand-control"].attribution, "Contains BMRS data © Elexon Limited copyright and database right {year}");
  assert.equal(SOURCES["nged-live-power-cuts"].attribution, "Supported by NGED Open Data");
  assert.match(SOURCES["ssen-powertrack"].attribution, /^SSEN Distribution, Real Time Outage Dataset .*CC BY 4\.0$/);
  assert.match(SOURCES["liander-storingen"].attribution, /^Liander, .*CC BY 4\.0$/);
  for (const rk of Object.keys(europe.regions)) assert.ok(REGIONS[rk], rk);
});

// ---------- SSEN ----------
test("SSEN: faults with customers, planned interruptions, licence area by latitude, UTC times", () => {
  const items = parseSsen(json("ssen-powertrack.json"), h);
  assert.equal(items.length, 13);
  const psi = items.find((x) => x.id === "ssen-powertrack:256431");
  assert.equal(psi.customers, 51); assert.equal(psi.planned, true); assert.equal(psi.cause, "Planned supply interruption");
  assert.equal(psi.region, SSEN_NORTH);   // AB54 (Aberdeenshire)
  const lv = items.find((x) => x.id === "ssen-powertrack:UK2086");
  assert.equal(lv.region, SSEN_SOUTH); assert.equal(lv.planned, false); assert.equal(lv.customers, 18);
  assert.equal(lv.started_at, "2026-11-19T20:31:00Z"); assert.equal(lv.restore_est, "");
  assert.equal(items.find((x) => x.id === "ssen-powertrack:UK0238").area, "SN8: SN8 2DP, SN8 2DR");
  // synthetic: a fault merged into another is not counted twice
  const d = json("ssen-powertrack.json"); d.faults[1].mergedTo = "UK2170";
  assert.equal(parseSsen(d, h).length, 12);
  assert.throws(() => parseSsen({}, h), /unexpected reply/);
});

// ---------- NGED ----------
test("NGED: CSV rows, UK local times, customers = the larger of confirmed and predicted off", () => {
  assert.deepEqual(parseCsv('a,"b, c","d ""q"""\r\n1,2,3\n'), [{ a: "1", "b, c": "2", 'd "q"': "3" }]);
  assert.equal(ngedCategory("LV UNDERGROUND"), "LV underground");
  const items = parseNged(txt("nged-live-power-cuts.csv"), h);
  assert.equal(items.length, 17);
  const x = items.find((i) => i.id === "nged-live-power-cuts:INCD-117276-l");
  assert.equal(x.customers, 32);   // confirmed 2, predicted 32
  assert.equal(x.region, "South West"); assert.equal(x.cause, "LV underground"); assert.equal(x.planned, false);
  assert.equal(x.started_at, "2026-11-19T17:29:00Z");   // GMT in November
  assert.equal(x.restore_est, "2026-11-20T06:00:00Z");
  assert.equal(x.area, "TQ8 8DH, TQ8 8QB, TQ8 8DE");      // postcodes de-duplicated, first three
  assert.ok(items.every((i) => ["West Midlands", "East Midlands", "South Wales", "South West"].includes(i.region)));
  assert.equal(zonedToIso("2026-07-01T12:00:00", "Europe/London"), "2026-07-01T11:00:00Z");   // BST
  // synthetic: restored rows are left out
  const csv = txt("nged-live-power-cuts.csv").replace('"In Progress"', '"Restored"');
  assert.equal(parseNged(csv, h).length, 16);
  assert.throws(() => parseNged("<html>blocked</html>", h), /unexpected reply/);
});

// ---------- Elexon system warnings ----------
test("SYSWARN: the scout's sample (SO-SO trades only) gives no warning", () => {
  assert.deepEqual(parseSyswarn(json("elexon-system-warnings.json"), h, T("2026-11-19T23:40:00Z")), []);
});
test("SYSWARN: electricity margin notice current inside its period, cleared by NESO's cancellation", () => {
  const d = json("elexon-system-warnings-history.json");
  assert.deepEqual(syswarnPeriod("from 06:00 hrs to 11:00 hrs on Monday   09/11/2026", h), { from: "2026-11-09T06:00:00Z", to: "2026-11-09T11:00:00Z" });
  assert.deepEqual(syswarnPeriod("valid for the period from 23:00 hrs on 24/10/2026\\r\\nto 21:00 hrs on 25/10/2026", h),
    { from: "2026-10-24T22:00:00Z", to: "2026-10-25T21:00:00Z" });   // BST until 01:00 UTC on 25 October, then GMT
  assert.deepEqual(syswarnPeriod("from 23:00 hrs to 05:00 hrs on 10/11/2026", h), { from: "2026-11-09T23:00:00Z", to: "2026-11-10T05:00:00Z" });
  // 08:30 on 9 Nov 2026: the 08:24 notice (08:00-11:00, shortfall 200 MW) is in force
  const at = parseSyswarn(d, h, T("2026-11-09T08:30:00Z"));
  assert.equal(at.length, 1);
  assert.deepEqual({ kind: at[0].kind, level: at[0].level, cause: at[0].cause, started_at: at[0].started_at, restore_est: at[0].restore_est },
    { kind: "supply_warning", level: 1, cause: "Electricity margin notice: system margin shortfall 200 MW", started_at: "2026-11-09T08:00:00Z", restore_est: "2026-11-09T11:00:00Z" });
  assert.equal(at[0].region, "Great Britain"); assert.equal(at[0].customers, null);
  // 05:00: the evening-before notice (06:00-11:00) is announced but not current yet
  assert.deepEqual(parseSyswarn(d, h, T("2026-11-09T05:00:00Z")), []);
  // 09:30: NESO cancelled it at 09:11
  assert.deepEqual(parseSyswarn(d, h, T("2026-11-09T09:30:00Z")), []);
  // negative reserve (NRAPM) and the voltage-reduction test are never supply warnings
  assert.deepEqual(parseSyswarn(d, h, T("2026-10-25T12:00:00Z")), []);
  assert.deepEqual(parseSyswarn(d, h, T("2026-06-02T10:30:00Z")), []);
});
test("SYSWARN: capacity market notice active from its commencement time until cancelled", () => {
  const d = json("elexon-system-warnings-history.json");
  // the second 'Currently Active' notice (12:23) is cancelled at 12:35 the same day
  assert.deepEqual(parseSyswarn(d, h, T("2025-01-08T12:30:00Z")), []);   // commencement 16:30: not current yet
  assert.deepEqual(parseSyswarn(d, h, T("2025-01-08T17:00:00Z")), []);   // cancelled at 12:35
  // synthetic: the same notices without the cancellation
  const keep = { data: d.data.filter((x) => !(x.warningType === "CAPACITY MARKET NOTICE" && /Cancelled/.test(x.warningText))) };
  const at = parseSyswarn(keep, h, T("2025-01-08T17:00:00Z"));
  assert.equal(at.length, 1);
  assert.equal(at[0].kind, "supply_warning"); assert.equal(at[0].level, 1); assert.equal(at[0].started_at, "2025-01-08T16:30:00Z");
  assert.deepEqual(parseSyswarn(keep, h, T("2025-01-09T06:00:00Z")), []);   // no period: dropped 12 hours after publication
});
test("SYSWARN: demand-side warnings map to grid_emergency level 2 and 3 (synthetic notices, real wording)", () => {
  const n = (type, text, at) => ({ publishTime: at, warningType: type, warningText: text });
  const d = { data: [
    n("OTHER", "From : Power System Manager – NESO Electricity Control Centre\\r\\n\\r\\nHIGH RISK OF DEMAND REDUCTION\\r\\nfor the period from 16:00 hrs to 19:00 hrs on Thursday 10/12/2026", "2026-12-10T14:00:00Z"),
    n("OTHER", "DEMAND CONTROL IMMINENT\\r\\nfrom 17:00 hrs to 18:00 hrs on 10/12/2026", "2026-12-10T16:55:00Z"),
  ] };
  const at = parseSyswarn(d, h, T("2026-12-10T17:10:00Z")).sort((a, b) => a.level - b.level);
  assert.deepEqual(at.map((x) => [x.kind, x.level]), [["grid_emergency", 2], ["grid_emergency", 3]]);
  // a cancellation that lists other warnings still in force cancels only its own
  d.data.push(n("OTHER", "NOTIFICATION CANCELLATION of GB TRANSMISSION SYSTEM WARNING\\r\\nDEMAND CONTROL IMMINENT has been cancelled\\r\\nThe following GB Transmission System Warnings remain in force\\r\\nHIGH RISK OF DEMAND REDUCTION", "2026-12-10T17:20:00Z"));
  assert.deepEqual(parseSyswarn(d, h, T("2026-12-10T17:30:00Z")).map((x) => x.level), [2]);
});

// ---------- Elexon demand control ----------
test("DCI: the 9 August 2019 low-frequency demand disconnection is a level 3 grid emergency while current", () => {
  assert.deepEqual(parseDci(json("elexon-demand-control.json"), h, T("2026-11-19T23:40:00Z")), []);
  const d = json("elexon-demand-control-2019.json");
  const [x] = parseDci(d, h, T("2019-08-09T16:00:00Z"));
  assert.equal(x.kind, "grid_emergency"); assert.equal(x.level, 3);
  assert.equal(x.cause, "Demand control: low-frequency demand disconnection, 931 MW");
  assert.equal(x.started_at, "2019-08-09T15:54:00Z"); assert.equal(x.restore_est, "2019-08-09T16:40:00Z");
  assert.equal(parseDci(d, h, T("2019-08-09T20:00:00Z")).length, 1);   // ended 3 h 20 min ago: still kept
  assert.deepEqual(parseDci(d, h, T("2019-08-10T00:00:00Z")), []);     // more than 6 hours after the end
  // synthetic: a later revision cancelling it
  const c = { data: [...d.data, { ...d.data[0], revisionNumber: 2, amendmentFlag: "CAN" }] };
  assert.deepEqual(parseDci(c, h, T("2019-08-09T16:00:00Z")), []);
});

// ---------- Liander ----------
test("Liander: customer bands to their lower bound, the band text kept, electricity only", () => {
  assert.equal(lianderBand("< 25"), 1);
  assert.equal(lianderBand("<2"), 1);
  assert.equal(lianderBand("< 50"), 25);
  assert.equal(lianderBand("< 100"), 50);
  assert.equal(lianderBand("< 300"), 100);
  assert.equal(lianderBand("< 1.000"), 100);
  assert.equal(lianderBand("< 30.000"), 10000);
  assert.equal(lianderBand("> 10.000"), 10001);
  assert.equal(lianderBand(""), null);
  const items = parseLiander(json("liander-storingen.json"), h);
  assert.equal(items.length, 13);
  const x = items.find((i) => i.id === "liander-storingen:627969");
  assert.equal(x.customers, 100); assert.equal(x.planned, true); assert.equal(x.cause, "Planned work");
  assert.equal(x.area, "ELST GLD · customers reported as under 300");
  assert.equal(x.started_at, new Date(1795073340000).toISOString().replace(".000Z", "Z"));
  const s = items.find((i) => i.id === "liander-storingen:8512783");
  assert.equal(s.customers, 1); assert.equal(s.cause, "Spontaneous fault"); assert.equal(s.planned, false);
  assert.ok(Math.abs(s.lat - 52.848) < 0.01 && Math.abs(s.lng - 5.021) < 0.01);
  // synthetic: gas and "not in Liander's network" are left out
  const d = json("liander-storingen.json");
  d.features[0].attributes.STORING_ENERGIESOORT = "Gas"; d.features[1].attributes.STORING_OORZAAK = "Niet in net van Liander";
  assert.equal(parseLiander(d, h).length, 11);
});

// ---------- TAURON ----------
test("TAURON: outages under way, planned vs failure from TypeId, no customer counts", () => {
  const d = json("tauron-wylaczenia.json");
  const items = parseTauron(d, h, T("2026-11-19T12:00:00Z"));
  const want = d.filter((x) => T(x.StartDate) <= T("2026-11-19T12:00:00Z") && T(x.EndDate) > T("2026-11-19T12:00:00Z"));
  assert.equal(items.length, want.length);
  assert.ok(items.length > 5);
  assert.ok(items.every((x) => x.customers === null));
  const f = items.find((x) => x.id === "tauron-wylaczenia:554f8b4e-b991-4eb4-9598-13ba5e9f33c2");
  assert.equal(f.planned, false); assert.equal(f.cause, "Failure (awaria)");
  assert.equal(f.started_at, "2026-11-18T18:05:43Z"); assert.equal(f.restore_est, "2026-11-19T13:00:00Z");
  assert.equal(f.area, "5 address points: Pierściec, Iłownica, Rudzica");
  assert.ok(Math.abs(f.lat - 49.8605) < 0.001);
  const p = items.find((x) => x.planned);
  assert.equal(p.cause, "Planned outage (wyłączenie planowane)");
  // after every end time nothing is current
  assert.deepEqual(parseTauron(d, h, T("2026-12-01T00:00:00Z")), []);
  assert.throws(() => parseTauron({}, h), /unexpected reply/);
});

// ---------- Elvia ----------
test("Elvia: one item per substation with exact customers, planned from avbruddstype", () => {
  const items = parseElvia(json("elvia-strombrudd.json"), h);
  assert.equal(items.length, 14);
  assert.equal(items.reduce((a, x) => a + x.customers, 0), 275);
  const o = items.find((x) => x.area.includes("substation 2128"));
  assert.equal(o.customers, 109); assert.equal(o.planned, true); assert.equal(o.area, "0680 Oslo, Oslo, Oslo (substation 2128)");
  assert.equal(o.started_at, new Date(1795129260000).toISOString().replace(".000Z", "Z"));
  const u = items.find((x) => !x.planned);
  assert.equal(u.cause, "Unplanned outage");
  // synthetic: a substation back on is left out
  const d = json("elvia-strombrudd.json"); d.features[0].attributes.statusavbrudd = "energized";
  assert.equal(parseElvia(d, h).length, 13);
});

// ---------- the real adapters, through grid.mjs ----------
const ADAPTER_FX = {
  "ssen-powertrack": "ssen-powertrack.json", "nged-live-power-cuts": "nged-live-power-cuts.csv",
  "liander-storingen": "liander-storingen.json", "elvia-strombrudd": "elvia-strombrudd.json",
  "elexon-system-warnings": "elexon-system-warnings.json", "elexon-demand-control": "elexon-demand-control.json",
};
for (const [k, f] of Object.entries(ADAPTER_FX)) {
  test(`adapter ${k}: valid items, plain request (no key, cookie or browser headers)`, async () => {
    const seen = serve(txt(f));
    const items = await ADAPTERS[k]();
    assert.equal(seen.length, 1);
    assert.equal(new URL(seen[0].url).host, new URL(SOURCES[k].url).host);
    assert.deepEqual(Object.keys(seen[0].headers).map((x) => x.toLowerCase()), ["user-agent"]);
    assert.match(seen[0].headers["user-agent"], /^cyberview-feeds\//);
    items.forEach((x) => assert.deepEqual(checkItem(x), [], x.id));
    assert.ok(items.every((x) => x.url === SOURCES[k].page || SOURCES[k].hosts.includes(new URL(x.url).host)));
  });
}
test("adapter tauron-wylaczenia: asks for [now, now + 1 h] and returns valid items", async () => {
  // synthetic: the fixture's times moved so that every outage is under way now
  const now = Date.now(), d = json("tauron-wylaczenia.json").map((x) => ({ ...x, StartDate: new Date(now - 3600e3).toISOString(), EndDate: new Date(now + 3600e3).toISOString() }));
  const seen = serve(JSON.stringify(d));
  const items = await ADAPTERS["tauron-wylaczenia"]();
  const u = new URL(seen[0].url);
  assert.equal(u.pathname, "/waapi/outages/items");
  assert.ok(Math.abs(Date.parse(u.searchParams.get("toDate")) - Date.parse(u.searchParams.get("fromDate")) - 3600e3) < 1000);
  assert.equal(items.length, d.length);
  items.forEach((x) => assert.deepEqual(checkItem(x), [], x.id));
  const g = summarize(items).get("tauron-wylaczenia|Southern Poland");
  assert.equal(g.total, 0);   // listed, not counted toward thresholds
});
test("adapter elexon-system-warnings: asks for the last 48 hours of notices", async () => {
  const seen = serve(txt("elexon-system-warnings.json"));
  await ADAPTERS["elexon-system-warnings"]();
  const u = new URL(seen[0].url);
  const span = Date.parse(u.searchParams.get("publishDateTimeTo")) - Date.parse(u.searchParams.get("publishDateTimeFrom"));
  assert.ok(span > 47.9 * 3600e3 && span < 48.2 * 3600e3);
});
test("adapter: a refused feed fails the source (no workaround)", async () => {
  globalThis.fetch = async () => new Response("Forbidden", { status: 403 });
  await assert.rejects(() => ADAPTERS["elvia-strombrudd"](), (e) => e.code === "http_403");
});

// ---------- review findings 2026-11-20 (grid-fixes lane) ----------
test("sources-2/3: SSEN and NGED report their own data time; a renamed customers field fails the source", async () => {
  const { needNumbers } = await import("../../scripts/grid-sources/europe.mjs");
  assert.equal(parseSsen(json("ssen-powertrack.json"), h).data_at, "2026-11-19T23:33:59Z");
  assert.equal(parseNged(txt("nged-live-power-cuts.csv"), h).data_at, "2026-11-19T23:30:00Z");     // UK wall-clock = UTC in November
  const d = JSON.parse(txt("ssen-powertrack.json").split('"customerCount"').join('"customers"'));
  assert.throws(() => parseSsen(d, h), (e) => e.code === "bad_shape");
  assert.throws(() => parseNged(txt("nged-live-power-cuts.csv").replace('"Confirmed Off","Predicted Off"', '"Confirmed","Predicted"'), h), (e) => e.code === "bad_shape");
  // TAURON: rows but no TypeId 1 or 2
  assert.throws(() => parseTauron(json("tauron-wylaczenia.json").map((x) => ({ ...x, TypeId: undefined, Type: x.TypeId })), h, T("2026-11-19T12:00:00Z")), (e) => e.code === "bad_shape");
  assert.doesNotThrow(() => needNumbers([], (r) => r.x, "empty"));
});

test("sources-4: Liander's band is kept as words for the map ('under 300'), the count is its floor", () => {
  const x = parseLiander(json("liander-storingen.json"), h).find((i) => i.id === "liander-storingen:627969");
  assert.equal(x.customers, 100);
  assert.equal(x.customers_band, "under 300");
});

test("sources-6: Liander and Elvia follow ArcGIS paging; a cut still there after the last page is reported", async () => {
  const { arcgisPages } = await import("../../scripts/grid-sources/europe.mjs");
  const base = json("liander-storingen.json"), urls = [];
  const page = (feats, more) => ({ ...base, features: feats, exceededTransferLimit: more });
  const hp = { ...h, get: async (u) => { urls.push(u); const n = urls.length; return n === 1 ? page(base.features.slice(0, 5), true) : n === 2 ? page(base.features.slice(5, 9), true) : page(base.features.slice(9), false); } };
  const items = await arcgisPages(hp, "https://x.example/q?f=json", parseLiander);
  assert.equal(items.length, 13);
  assert.deepEqual(urls.map((u) => (u.match(/resultOffset=(\d+)/) || [0, "0"])[1]), ["0", "5", "9"]);
  const always = { ...h, get: async () => page(base.features.slice(0, 2), true) };
  await assert.rejects(arcgisPages(always, "https://x.example/q?f=json", parseLiander, 3), (e) => e.code === "bad_shape");
});
