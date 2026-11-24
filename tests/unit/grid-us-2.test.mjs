// Unit tests for the "us-2" grid source file scripts/grid-sources/us-2.mjs (node --test, no dependencies). Fixtures in
// tests/fixtures/grid/us-2/ are real replies saved on 2026-11-24: spp-conditions.html is SPP's Current Grid Conditions
// page trimmed to its page-content block; riverside-rows.json holds the five newest rows of Riverside Public Utilities'
// outage layer (all closed by then), riverside-rows-2020.json three older rows that still carry a ward and cross street,
// and riverside-active.json the real reply to the source's own active-only query (no active outage at the time). Synthetic
// variants are built inside the tests and say so. Adapters run through scripts/grid.mjs (the real helpers h) with fetch
// stubbed to serve the fixtures.
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SOURCES as ALL, REGIONS as ALL_REGIONS, ADAPTERS, PLUGIN_ERRORS, SIGNAL_SOURCES, checkItem } from "../../scripts/grid.mjs";
import plugin, { SOURCES, REGIONS, parseSpp, sppLevel, parseRiverside } from "../../scripts/grid-sources/us-2.mjs";

const FX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "grid", "us-2");
const raw = (f) => readFileSync(join(FX, f), "utf8");
const json = (f) => JSON.parse(raw(f));
const noErrors = (items) => items.forEach((x) => assert.deepEqual(checkItem(x), [], x.id));

const realFetch = globalThis.fetch;
let asked = [];
function serve(routes) {
  asked = [];
  globalThis.fetch = async (url, opts = {}) => {
    asked.push({ url: String(url), headers: opts.headers || {} });
    const hit = routes.find(([re]) => re.test(String(url)));
    if (!hit) return new Response("not found", { status: 404 });
    const b = hit[1];
    return new Response(typeof b === "string" ? b : JSON.stringify(b), { status: 200 });
  };
}
afterEach(() => { globalThis.fetch = realFetch; });

test("us-2: the file loads into grid.mjs with no plugin errors, every source, adapter and region", () => {
  assert.deepEqual(PLUGIN_ERRORS.filter((e) => e.startsWith("us-2.mjs")), []);
  for (const k of Object.keys(SOURCES)) {
    assert.equal(ALL[k].file, "us-2.mjs", k);
    assert.equal(typeof plugin.adapters[k], "function", k);
    assert.equal(typeof ADAPTERS[k], "function", k);
    for (const f of ["name", "country", "url", "page", "terms_url", "terms_ok"]) assert.ok(SOURCES[k][f], `${k}.${f}`);
    assert.ok(["allowed", "silent"].includes(SOURCES[k].terms_ok), k);
    assert.ok(SOURCES[k].hosts.includes(new URL(SOURCES[k].page).host), `${k} page on its own host`);
    assert.match(SOURCES[k].url, /^https:\/\//);
  }
  for (const k of Object.keys(REGIONS)) assert.ok(ALL_REGIONS[k], k);
  assert.ok(SIGNAL_SOURCES.has("spp-conditions"), "SPP is a signal source");
  assert.ok(!SIGNAL_SOURCES.has("riverside-pu"), "Riverside counts customers");
  assert.ok(!/troubleman|foreman|crew|user_/i.test(SOURCES["riverside-pu"].url), "no staff fields requested");
});

test("SPP: one item per balancing authority area, the condition now, the upcoming advisory kept in cause", () => {
  const items = parseSpp(raw("spp-conditions.html"));
  noErrors(items);
  assert.deepEqual(items.map((x) => x.id), ["spp-conditions:east", "spp-conditions:west"]);
  const [e, w] = items;
  // East: "Currently under Baseline Normal Operating Conditions; Resource Advisory begins Tues., Nov. 24, ..."
  assert.deepEqual([e.region, e.kind, e.level, e.customers, e.planned, e.country], ["East BAA", "grid_emergency", 0, null, false, "US"]);
  assert.equal(e.area, "SPP East BAA: Baseline Normal Operating Conditions");
  assert.match(e.cause, /^Currently under Baseline Normal Operating Conditions; Resource Advisory begins Tues\., Nov\. 24/);
  assert.ok(e.cause.length <= 120);
  assert.deepEqual([w.region, w.kind, w.level, w.area], ["West BAA", "grid_emergency", 0, "SPP West BAA: Baseline Normal Operating Conditions"]);
  assert.equal(w.cause, "Baseline Normal Operating Conditions");
  for (const x of items) {
    assert.equal(x.url, SOURCES["spp-conditions"].page);
    assert.deepEqual([x.lat, x.lng], [REGIONS[`spp-conditions|${x.region}`].lat, REGIONS[`spp-conditions|${x.region}`].lng]);
    assert.deepEqual([x.started_at, x.restore_est], ["", ""], "the page gives no machine-readable time for the condition now");
  }
});

test("SPP: levels follow the page's own wording (synthetic headings in the page's format)", () => {
  assert.deepEqual(sppLevel("Baseline Normal Operating Conditions"), { kind: "grid_emergency", level: 0 });
  assert.deepEqual(sppLevel("Resource Advisory"), { kind: "supply_warning", level: 0 });
  assert.deepEqual(sppLevel("Weather Advisory"), { kind: "supply_warning", level: 0 });
  assert.deepEqual(sppLevel("Conservative Operations Advisory"), { kind: "supply_warning", level: 1 });
  assert.deepEqual(sppLevel("Conservative Operations Advisory begins Wed., Dec. 2"), { kind: "supply_warning", level: 0 });
  assert.deepEqual(sppLevel("Energy Emergency Alert (EEA) Level 2"), { kind: "grid_emergency", level: 2 });
  assert.deepEqual(sppLevel("EEA Level 3; load shed directed"), { kind: "load_shedding", level: 3 });
  assert.deepEqual(sppLevel("Load shed in progress"), { kind: "load_shedding", level: 3 });
  const html = raw("spp-conditions.html").replace(/West BAA:\s+Baseline Normal Operating Conditions/, "West BAA: Currently under Conservative Operations Advisory");
  const w = parseSpp(html).find((x) => x.region === "West BAA");
  assert.deepEqual([w.kind, w.level], ["supply_warning", 1]);
  assert.throws(() => parseSpp("<html><h3>Maintenance</h3></html>"), (e) => e.code === "bad_shape");
});

test("Riverside: each outage with start, estimated restoration, customers, cause, planned flag and point", () => {
  const d = json("riverside-rows.json");
  assert.deepEqual(parseRiverside(d), [], "the five newest rows are closed: none is reported");
  const items = parseRiverside(d, { includeClosed: true });
  noErrors(items);
  assert.equal(items.length, 5);
  const a = items.find((x) => x.id === "riverside-pu:13051");
  // 11/19/2026 7:24 PM Pacific (UTC-8) -> 2026-11-20T03:24Z; ETR "4:24 AM" is the next morning
  assert.deepEqual([a.started_at, a.restore_est], ["2026-11-20T03:24:00Z", "2026-11-20T12:24:00Z"]);
  assert.deepEqual([a.planned, a.cause, a.customers, a.kind, a.level, a.region, a.area], [true, "Planned work", 0, "outage", null, "Riverside", "Riverside"]);
  assert.deepEqual([a.lat, a.lng], [33.937, -117.415]);
  const b = items.find((x) => x.id === "riverside-pu:13050");
  assert.deepEqual([b.started_at, b.restore_est, b.planned, b.cause], ["2026-11-19T21:48:00Z", "2026-11-20T02:48:00Z", false, "Palm Frond"]);
  assert.ok(items.every((x) => x.url === SOURCES["riverside-pu"].page && x.country === "US"));
});

test("Riverside: ward and cross street become the area (older real rows)", () => {
  const items = parseRiverside(json("riverside-rows-2020.json"), { includeClosed: true });
  noErrors(items);
  const x = items.find((i) => i.id === "riverside-pu:9646");
  assert.equal(x.area, "Sandy Ln, Ward 6, Ward 7, Riverside");
  assert.equal(x.cause, "Palm Frond");
  assert.equal(x.started_at, "2020-01-12T16:29:00Z");
  assert.deepEqual([x.lat, x.lng], [33.945, -117.493]);
  assert.equal(items.find((i) => i.id === "riverside-pu:9647").area, "Ward 6, Riverside", "an empty cross street is left out");
});

test("Riverside: an active row is reported (synthetic copy of a real row flagged active), errors are a bad shape", () => {
  const d = json("riverside-rows.json");
  d.features = [{ ...d.features[1], attributes: { ...d.features[1].attributes, outage_active_flag: "True", customers_out_of_power: 212 } }];
  const [x] = parseRiverside(d);
  assert.deepEqual([x.id, x.customers, x.cause], ["riverside-pu:13050", 212, "Palm Frond"]);
  assert.throws(() => parseRiverside({ error: { code: 400, message: "Invalid query" } }), (e) => e.code === "bad_shape");
  assert.throws(() => parseRiverside({}), (e) => e.code === "bad_shape");
});

test("adapters: run through grid.mjs on the real replies, items pass checkItem, CyberView's own user agent", async () => {
  serve([[/www\.spp\.org/, raw("spp-conditions.html")], [/ElectricOutageAGOL1/, json("riverside-active.json")]]);
  const spp = await ADAPTERS["spp-conditions"]();
  noErrors(spp);
  assert.equal(spp.length, 2);
  const rpu = await ADAPTERS["riverside-pu"]();
  assert.deepEqual(rpu, [], "no active outage in the saved reply");
  assert.ok(asked.length >= 2);
  for (const a of asked) assert.match(a.headers["user-agent"] || "", /^cyberview-feeds\//);
  assert.ok(asked.some((a) => /outage_active_flag%3D'True'|outage_active_flag%3D%27True%27/.test(a.url)), "asks only for active outages");
});
