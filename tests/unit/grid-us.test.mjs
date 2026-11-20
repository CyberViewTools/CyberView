// Unit tests for the US grid source file scripts/grid-sources/us.mjs (node --test; no dependencies). Fixtures in
// tests/fixtures/grid/us/ are real replies saved on 2026-11-19/20 (NYISO: real days from its public monthly archives);
// synthetic variants are built inside the tests and say so. Every adapter runs through scripts/grid.mjs (the real
// helpers h) with fetch stubbed to serve the fixtures, so the URLs, the multi-step fetches and the parsers are all tested.
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SOURCES, REGIONS, ADAPTERS, PLUGIN_ERRORS, OPERATORS, checkItem, track, DEFAULT_CFG } from "../../scripts/grid.mjs";
import us, { caisoLevel, nyisoDay, ODIN_DIRECT, EVERSOURCE_REPORTS } from "../../scripts/grid-sources/us.mjs";
import { stateOfFips, titleCase } from "../../scripts/grid-sources/lib-us-states.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FX = join(HERE, "..", "fixtures", "grid", "us");
const txt = (f) => readFileSync(join(FX, f), "utf8");
const KEYS = ["eversource", "nashville-electric", "rocky-mountain-power", "pacific-power", "ladwp", "doe-odin", "caiso-emergency", "nyiso-realtime-events"];
const noErrors = (items) => items.forEach((x) => assert.deepEqual(checkItem(x), [], x.id));

// fetch stub: routes = [[regex on the url, body string | object | { status }]]; every requested url is recorded
const realFetch = globalThis.fetch;
let asked = [];
function serve(routes) {
  asked = [];
  globalThis.fetch = async (url, opts = {}) => {
    asked.push({ url: String(url), headers: opts.headers || {} });
    const hit = routes.find(([re]) => re.test(String(url)));
    if (!hit) return new Response("not found", { status: 404 });
    const b = hit[1];
    if (b && typeof b === "object" && b.status) return new Response(b.body || "", { status: b.status });
    return new Response(typeof b === "string" ? b : JSON.stringify(b), { status: 200 });
  };
}
afterEach(() => { globalThis.fetch = realFetch; });
const run = (k) => ADAPTERS[k]();

test("us.mjs loads into grid.mjs: every source registered, no plugin errors, regions valid", () => {
  assert.deepEqual(PLUGIN_ERRORS.filter((e) => e.startsWith("us.mjs")), []);
  for (const k of KEYS) {
    const s = SOURCES[k];
    assert.ok(s && s.file === "us.mjs", k);
    assert.ok(OPERATORS.includes(k), k);
    assert.equal(s.country, "US");
    assert.match(s.url, /^https:\/\//); assert.match(s.page, /^https:\/\//); assert.match(s.terms_url, /^https:\/\//);
    assert.ok(["allowed", "silent"].includes(s.terms_ok), k);
    assert.ok(s.hosts.includes(new URL(s.page).host), `${k}: page on its own hosts`);
    assert.equal(typeof ADAPTERS[k], "function");
  }
  assert.match(SOURCES["caiso-emergency"].attribution, /California ISO/);
  assert.equal(SOURCES["caiso-emergency"].kind, "signal");
  assert.equal(SOURCES["nyiso-realtime-events"].kind, "signal");
  assert.ok(SOURCES["doe-odin"].aggregator && /double/i.test(SOURCES["doe-odin"].note));
  for (const [k, r] of Object.entries(us.regions)) {
    assert.ok(KEYS.includes(k.split("|")[0]), k);
    assert.ok(Math.abs(r.lat) <= 90 && Math.abs(r.lng) <= 180 && r.name, k);
    assert.deepEqual(REGIONS[k], r);
  }
  assert.ok(REGIONS["doe-odin|Texas"] && REGIONS["doe-odin|Puerto Rico"]);
});

test("lib-us-states: FIPS to state, title case", () => {
  assert.equal(stateOfFips("06037").name, "California");
  assert.equal(stateOfFips("48").abbr, "TX");
  assert.equal(stateOfFips("72001").country, "PR");
  assert.equal(stateOfFips("99001"), null);
  assert.equal(stateOfFips("6037"), null);
  assert.equal(titleCase("MID-WILSHIRE"), "Mid-Wilshire");
  assert.equal(titleCase("WEST HARTFORD"), "West Hartford");
});

test("Eversource: metadata directory, four territory reports, towns with customers out", async () => {
  const dir = JSON.parse(txt("eversource-metadata.json")).directory;
  serve([[/metadata\.json$/, txt("eversource-metadata.json")],
    ...EVERSOURCE_REPORTS.map((f) => [new RegExp(`/${dir}/${f.replace(".", "\\.")}$`), txt(`eversource-${f}`)])]);
  const items = await run("eversource");
  assert.equal(asked.length, 5);
  assert.ok(asked.every((a) => a.url.startsWith("https://outagemap.eversource.com/resources/data/external/interval_generation_data/")));
  assert.ok(asked.every((a) => !a.headers.cookie && !a.headers.authorization));
  noErrors(items);
  assert.equal(items.length, 9);
  assert.equal(items.reduce((s, x) => s + x.customers, 0), 16);     // CT 14 + MA 1 + NH 1, as the reports' state totals say
  const darien = items.find((x) => x.id === "eversource:CT-darien");
  assert.deepEqual([darien.region, darien.area, darien.customers, darien.lat, darien.planned], ["Connecticut", "Darien, CT", 5, null, false]);
  assert.deepEqual([...new Set(items.map((x) => x.region))].sort(), ["Connecticut", "Massachusetts", "New Hampshire"]);
  assert.equal(new Set(items.map((x) => x.id)).size, items.length);
  // a bad directory name is refused before any report is requested
  serve([[/metadata\.json$/, { directory: "../x" }]]);
  await assert.rejects(run("eversource"), (e) => e.code === "bad_shape");
  assert.equal(asked.length, 1);
});

test("Nashville Electric Service: counties with customers out", async () => {
  serve([[/utilisocial\.io\/datacapable\/v2\/p\/NES\/map\/events\/count\?types=COUNTY$/, txt("nashville-electric.json")]]);
  const items = await run("nashville-electric");
  noErrors(items);
  assert.deepEqual(items.map((x) => [x.area, x.customers]), [["Rutherford County, TN", 23], ["Davidson County, TN", 6]]);
  assert.ok(items.every((x) => x.region === "Nashville" && x.lat === null && x.url === "https://www.nespower.com/outages/"));
  serve([[/utilisocial/, { nope: 1 }]]);
  await assert.rejects(run("nashville-electric"), (e) => e.code === "bad_shape");
});

test("PacifiCorp: Rocky Mountain Power and Pacific Power, three state files each, planned split", async () => {
  serve([[/rockymountainpower\.net\/etc\/pcorp\/datafiles\/outagemap\/list(UT|WY|ID)\.json$/, null]]);
  const rmp = (u) => txt(`rocky-mountain-power-${u.match(/list(\w\w)\.json/)[1]}.json`);
  const pp = (u) => txt(`pacific-power-${u.match(/list(\w\w)\.json/)[1]}.json`);
  globalThis.fetch = async (url) => { asked.push({ url }); return new Response(/rockymountain/.test(url) ? rmp(url) : pp(url)); };
  asked = [];
  const r = await run("rocky-mountain-power");
  assert.deepEqual(asked.map((a) => a.url.match(/list(\w\w)/)[1]), ["UT", "WY", "ID"]);
  noErrors(r);
  // county rows add up to totalState in each file (UT 280, WY 4, ID 9)
  const sum = (xs, reg) => xs.filter((x) => x.region === reg).reduce((s, x) => s + x.customers, 0);
  assert.deepEqual([sum(r, "Utah"), sum(r, "Wyoming"), sum(r, "Idaho")], [280, 4, 9]);
  const davis = r.filter((x) => x.area === "Davis County, UT");
  assert.deepEqual(davis.map((x) => [x.planned, x.customers]).sort(), [[false, 3], [true, 5]]);
  const p = await run("pacific-power");
  noErrors(p);
  assert.deepEqual([sum(p, "Oregon"), sum(p, "Washington"), sum(p, "California")], [45, 23, 1]);
  assert.equal(p.find((x) => x.area === "Jackson County, OR").planned, true);
  assert.ok(p.every((x) => x.url === "https://www.pacificpower.net/outages-safety.html"));
  globalThis.fetch = async () => new Response(JSON.stringify({ count: 1 }));
  await assert.rejects(run("pacific-power"), (e) => e.code === "bad_shape");
  // a state with nothing out (synthetic: the same shape, empty lists)
  globalThis.fetch = async () => new Response(JSON.stringify({ count: 0, totalState: 0, last_upd: "", zips: [], counties: [] }));
  assert.deepEqual(await run("pacific-power"), []);
});

test("LADWP: ArcGIS features, own coordinates, restore estimate read as Pacific time", async () => {
  serve([[/services2\.arcgis\.com\/.*PowerOutages_Data\/FeatureServer\/0\/query\?/, txt("ladwp.json")]]);
  const items = await run("ladwp");
  noErrors(items);
  assert.equal(items.length, 12);
  assert.equal(items.reduce((s, x) => s + x.customers, 0), 4536);
  const big = items.find((x) => x.customers === 1367);
  assert.deepEqual([big.area, big.lat, big.lng], ["Woodland Hills", 34.185, -118.61]);
  assert.equal(big.restore_est, "2026-11-20T08:00:00Z");     // "11/20/2026 00:00" PST, not the epoch field read as UTC
  assert.equal(items.find((x) => x.id === "ladwp:268327").restore_est, "2026-11-20T04:00:00Z");
  assert.ok(items.every((x) => x.cause === "" && x.started_at === "" && !x.planned));
  serve([[/arcgis/, { error: { code: 400, message: "Invalid query" } }]]);
  await assert.rejects(run("ladwp"), (e) => e.code === "bad_shape");
});

test("DOE/ORNL ODIN: county rows, state regions, utility in area, direct utilities dropped", async () => {
  serve([[/^https:\/\/odin\.ornl\.gov\/odi\?view=county$/, txt("doe-odin.json")]]);
  const raw = JSON.parse(txt("doe-odin.json")).outage;
  const items = await run("doe-odin");
  noErrors(items);
  // 24 rows name PacifiCorp, one of them together with Portland General Electric (summed meters): all are dropped
  const pacificorp = raw.filter((r) => r.names.some((n) => n.name === "PACIFICORP"));
  assert.equal(pacificorp.length, 24);
  assert.equal(pacificorp.filter((r) => r.names.length > 2).length, 1);
  assert.equal(items.length, raw.length - pacificorp.length);
  assert.ok(!items.some((x) => /PACIFICORP/.test(x.area)));
  assert.equal(items.reduce((s, x) => s + x.customers, 0), 5993 - 359);
  const cnp = items.find((x) => x.customers === 1313);
  assert.deepEqual([cnp.region, cnp.area, cnp.country, cnp.lat], ["Texas", "County FIPS 48201: CENTERPOINT ENERGY", "US", null]);
  assert.ok(items.every((x) => REGIONS[`doe-odin|${x.region}`]));
  for (const n of ["PACIFICORP", "NASHVILLE ELECTRIC SERVICE", "Los Angeles Department of Water & Power", "CONNECTICUT LIGHT & POWER CO",
    "NSTAR ELECTRIC COMPANY", "PUBLIC SERVICE CO OF NH", "Eversource Energy"]) assert.ok(ODIN_DIRECT.test(n), n);
  for (const n of ["SOUTHERN CALIFORNIA EDISON CO", "PORTLAND GENERAL ELECTRIC CO", "CENTERPOINT ENERGY", "NATIONAL GRID"]) assert.ok(!ODIN_DIRECT.test(n), n);
  // synthetic: a row with cause, times and planned kind filled; a row dropped by EIA id; a row with an unknown FIPS
  const row = (o) => ({ MRID: "m", communityDescriptor: "36061", metersAffected: 10, names: [{ name: "X CO", nameType: "UtilityName" }, { name: "1", nameType: "UtilityId" }], ...o });
  serve([[/odin/, { outage: [
    row({ MRID: "a", cause: "Tree contact", reportedStartTime: "2026-11-19T20:00:00Z", estimatedRestorationTime: "2026-11-19T23:30:00-05:00", outageKind: "PLANNED" }),
    row({ MRID: "b", names: [{ name: "SOMETHING", nameType: "UtilityName" }, { name: "13216", nameType: "UtilityId" }] }),
    row({ MRID: "c", communityDescriptor: "99999" }), row({ MRID: "d", outageKind: "UNPLANNED", metersAffected: 0 }),
    row({ MRID: "e", communityDescriptor: "72127", outageKind: "UNPLANNED" })] }]]);
  const s = await run("doe-odin");
  noErrors(s);
  assert.deepEqual(s.map((x) => x.id), ["doe-odin:a", "doe-odin:e"]);
  assert.equal(items.filter((x) => x.area.includes(";")).length, 3);    // multi-utility rows keep every name
  assert.deepEqual([s[0].cause, s[0].started_at, s[0].restore_est, s[0].planned, s[0].region], ["Tree contact", "2026-11-19T20:00:00Z", "2026-11-20T04:30:00Z", true, "New York"]);
  assert.deepEqual([s[1].country, s[1].region, s[1].planned], ["PR", "Puerto Rico", false]);
});

test("CAISO: level mapping from the notice type", () => {
  assert.deepEqual(caisoLevel("Flex Alert"), { kind: "supply_warning", level: 1 });
  assert.deepEqual(caisoLevel("EEA Watch"), { kind: "supply_warning", level: 1 });
  assert.deepEqual(caisoLevel("Energy Emergency Alert Watch (EEA Watch)"), { kind: "supply_warning", level: 1 });
  assert.deepEqual(caisoLevel("Transmission Emergency"), { kind: "grid_emergency", level: 1 });
  assert.deepEqual(caisoLevel("EEA 1"), { kind: "grid_emergency", level: 1 });
  assert.deepEqual(caisoLevel("Energy Emergency Alert 2 (EEA 2)"), { kind: "grid_emergency", level: 2 });
  assert.deepEqual(caisoLevel("EEA 3 - Preparing for rotating power outages"), { kind: "grid_emergency", level: 3 });
  assert.deepEqual(caisoLevel("EEA 3 - Ordering rotating power outages"), { kind: "load_shedding", level: 3 });
  assert.equal(caisoLevel("Restricted Maintenance Operations"), null);
  assert.equal(caisoLevel("RMO"), null);
  assert.equal(caisoLevel("Something new"), null);
});

test("CAISO: only current notices in effect and not past their end; the real quiet reply gives none", async () => {
  serve([[/^https:\/\/wwwmobile\.caiso\.com\/TodaysOutlookApi\/api\/EmergencyNotices\/v2\/ActiveEvents$/, txt("caiso-emergency.json")]]);
  assert.deepEqual(await run("caiso-emergency"), []);
  // synthetic, in the field names of the page's own script; times are Pacific wall-clock time, far in the future
  const ev = (o) => ({ EventId: "1", EventType: "EEA 2", Region: "CAISO BAA", StartDateTime_PT: "2099-08-01T16:00:00", EndDateTime_PT: "2099-08-01T21:00:00",
    InEffect: true, EventMessages: [{ MessageType: "Issued", PostDate_PT: "2099-08-01T15:30:00", MessageBody: "text" }], ...o });
  serve([[/caiso/, { CurrentEvents: [ev({}), ev({ EventId: "2", EventType: "Restricted Maintenance Operations" }), ev({ EventId: "3", InEffect: false }),
    ev({ EventId: "4", EventType: "Flex Alert", StartDateTime_PT: "2020-08-01T16:00:00", EndDateTime_PT: "2020-08-01T21:00:00" })],
    UpcomingEvents: [ev({ EventId: "5", EventType: "EEA 3" })] }]]);
  const items = await run("caiso-emergency");
  noErrors(items);
  assert.equal(items.length, 1);
  const x = items[0];
  assert.deepEqual([x.id, x.kind, x.level, x.cause, x.area, x.region, x.customers], ["caiso-emergency:1", "grid_emergency", 2, "EEA 2", "CAISO BAA", "California", null]);
  assert.deepEqual([x.started_at, x.restore_est], ["2099-08-01T23:00:00Z", "2099-08-02T04:00:00Z"]);    // PDT, UTC-7
  assert.equal(x.url, "https://www.caiso.com/emergency-notifications");
  // a level-2 notice opens an incident in the tracker (level >= 1)
  const t = track({ open: [], closed: [] }, items, DEFAULT_CFG, Date.parse("2026-11-20T00:00:00Z"));
  assert.equal(t.open.length, 1);
  assert.deepEqual([t.open[0].kind, t.open[0].level, t.open[0].customers, t.open[0].approx], ["grid_emergency", 2, null, true]);
  serve([[/caiso/, { nope: [] }]]);
  await assert.rejects(run("caiso-emergency"), (e) => e.code === "bad_shape");
});

test("NYISO: the newest system state of the day, Eastern time; real normal, alert and major-emergency days", async () => {
  const nyDay = nyisoDay(Date.now());
  assert.match(nyDay, /^\d{8}$/);
  assert.equal(nyisoDay(Date.parse("2026-11-20T03:00:00Z")), "20261119");   // 22:00 EST the day before
  assert.equal(nyisoDay(Date.parse("2026-11-20T06:00:00Z")), "20261120");
  serve([[new RegExp(`^https://mis\\.nyiso\\.com/public/csv/RealTimeEvents/${nyDay}RealTimeEvents\\.csv$`), txt("nyiso-20261119.csv")]]);
  let [x, ...rest] = await run("nyiso-realtime-events");
  assert.equal(rest.length, 0);
  noErrors([x]);
  assert.deepEqual([x.kind, x.level, x.area, x.started_at], ["grid_emergency", 0, "NYISO system state: Normal", "2026-11-19T05:00:00Z"]);
  assert.equal(x.url, `https://mis.nyiso.com/public/csv/RealTimeEvents/${nyDay}RealTimeEvents.csv`);
  // alert state with no return to normal that day (2026-08-19): EDT, UTC-4
  serve([[/nyiso/, txt("nyiso-20260819.csv")]]);
  [x] = await run("nyiso-realtime-events");
  assert.deepEqual([x.kind, x.level, x.started_at, x.cause], ["supply_warning", 2, "2026-08-19T19:27:06Z", "State Change. System now operating in alert state."]);
  // 2025-06-24 ended normal; cut at 18:14:31 (synthetic slice of the real file) it is a major emergency
  const day = txt("nyiso-20250624.csv");
  serve([[/nyiso/, day]]);
  [x] = await run("nyiso-realtime-events");
  assert.deepEqual([x.level, x.started_at], [0, "2025-06-25T01:03:01Z"]);
  serve([[/nyiso/, day.slice(0, day.indexOf("06/24/2025 20:00:19"))]]);
  [x] = await run("nyiso-realtime-events");
  assert.deepEqual([x.kind, x.level, x.started_at], ["grid_emergency", 3, "2025-06-24T22:14:31Z"]);
  // a day that starts with only a thunderstorm line gives no state, so no item (none guessed); a thunderstorm alert in
  // effect is noted in the area (synthetic: the real file with its last line removed)
  const storm = txt("nyiso-20260612.csv");
  serve([[/nyiso/, storm]]);
  assert.deepEqual(await run("nyiso-realtime-events"), []);
  serve([[/nyiso/, txt("nyiso-20261119.csv").trim() + "\n11/19/2026 17:00:00,**System now operating in thunderstorm alert.**\n"]]);
  [x] = await run("nyiso-realtime-events");
  assert.equal(x.area, "NYISO system state: Normal (thunderstorm alert in effect)");
  assert.equal(x.level, 0);
  // today's file not published yet: yesterday's (Eastern) is read
  const yDay = nyisoDay(Date.now() - 864e5);
  serve([[new RegExp(`${nyDay}RealTimeEvents`), { status: 404 }], [new RegExp(`${yDay}RealTimeEvents`), txt("nyiso-20260819.csv")]]);
  [x] = await run("nyiso-realtime-events");
  assert.equal(x.level, 2);
  assert.deepEqual(asked.map((a) => a.url.match(/(\d{8})RealTimeEvents/)[1]), [nyDay, yDay]);
  serve([[/nyiso/, "<html>maintenance</html>"]]);
  await assert.rejects(run("nyiso-realtime-events"), (e) => e.code === "bad_shape");
});

test("adapters send no key, cookie or browser-imitating header", async () => {
  serve([[/caiso/, txt("caiso-emergency.json")], [/odin/, txt("doe-odin.json")], [/utilisocial/, txt("nashville-electric.json")]]);
  for (const k of ["caiso-emergency", "doe-odin", "nashville-electric"]) await run(k);
  for (const a of asked) {
    const keys = Object.keys(a.headers).map((x) => x.toLowerCase());
    assert.deepEqual(keys, ["user-agent"]);
    assert.match(a.headers["user-agent"], /^cyberview-feeds\//);
    assert.ok(!/[?&](api_?key|token|key)=/i.test(a.url));
  }
});
