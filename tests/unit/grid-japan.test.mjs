// Unit tests for scripts/grid-sources/japan.mjs (OCCTO wide-area reserve; node --test, no dependencies). The fixture
// tests/fixtures/grid/japan/occto-daily.json is a real dailyData reply saved on 2026-11-21 (21:53 UTC = 2026/11/22 06:53
// Japan time), trimmed to the fields CyberView reads; synthetic variants are built inside the tests and say so.
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SOURCES as ALL, REGIONS as ALL_REGIONS, ADAPTERS, PLUGIN_ERRORS, OPERATORS, SIGNAL_SOURCES, checkItem, track, loadConfig, triage } from "../../scripts/grid.mjs";
import plugin, { SOURCES, REGIONS, OCCTO_AREAS, parseOccto, jstSlot, jstToIso } from "../../scripts/grid-sources/japan.mjs";

const FX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "grid", "japan");
const fx = () => JSON.parse(readFileSync(join(FX, "occto-daily.json"), "utf8"));
const NOW = Date.parse("2026-11-21T21:53:00Z");   // 2026/11/22 06:53 JST: slot 13
const noErrors = (items) => items.forEach((x) => assert.deepEqual(checkItem(x), [], x.id));
const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

test("japan: the file loads into grid.mjs as a signal source with regions and attribution", () => {
  assert.deepEqual(PLUGIN_ERRORS.filter((e) => e.startsWith("japan.mjs")), []);
  const s = ALL["occto-reserve"];
  assert.equal(s.file, "japan.mjs");
  assert.ok(OPERATORS.includes("occto-reserve") && SIGNAL_SOURCES.has("occto-reserve"));
  assert.equal(typeof plugin.adapters["occto-reserve"], "function");
  assert.equal(s.terms_ok, "allowed");
  assert.match(s.attribution, /OCCTO.*Changes: /);
  assert.ok(s.hosts.includes(new URL(s.page).host));
  assert.equal(Object.keys(REGIONS).length, 10);
  for (const k of Object.keys(REGIONS)) assert.ok(ALL_REGIONS[k], k);
  assert.equal(loadConfig().levels["occto-reserve"], 2);
});

test("Japan time helpers", () => {
  assert.deepEqual(jstSlot(NOW), { day: "2026/11/22", slot: 13 });
  assert.deepEqual(jstSlot(Date.parse("2026-11-21T14:59:59Z")), { day: "2026/11/21", slot: 47 });
  assert.equal(jstToIso("2026/11/22 06:28"), "2026-11-21T21:28:00Z");
  assert.equal(jstToIso("nonsense"), "");
});

test("OCCTO: one item per area for the current half hour, level from the reserve rate", () => {
  const items = parseOccto(fx(), NOW);
  noErrors(items);
  assert.equal(items.length, 10);
  assert.equal(items.data_at, "2026-11-21T21:28:00Z");
  const tokyo = items.find((x) => x.region === "Tokyo");
  const raw = fx().todayAreaRsvRateList.find((a) => a.areaCd === "03").areaRsvRateItems[13];
  assert.deepEqual([tokyo.kind, tokyo.level, tokyo.customers, tokyo.started_at], ["supply_warning", raw.koikRsvRate < 5 ? 1 : 0, null, "2026-11-21T21:30:00Z"]);
  assert.ok(tokyo.cause.startsWith(`wide-area reserve ${raw.koikRsvRate}%`));
  assert.ok(items.every((x) => x.level === 0));   // a quiet November morning: every area at 5% or more
  // synthetic: Tokyo at 4.2%, Kansai at 2.5%, Kyushu at 0.8%, Okinawa without a rate
  const d = fx();
  const set = (cd, v) => { d.todayAreaRsvRateList.find((a) => a.areaCd === cd).areaRsvRateItems[13].koikRsvRate = v; };
  set("03", 4.2); set("06", 2.5); set("09", 0.8); set("10", null);
  const s = parseOccto(d, NOW);
  noErrors(s);
  const lv = Object.fromEntries(s.map((x) => [x.region, x.level]));
  assert.deepEqual([lv.Tokyo, lv.Kansai, lv.Kyushu, lv.Okinawa, lv.Hokkaido], [1, 2, 3, undefined, 0]);
  assert.match(s.find((x) => x.region === "Kansai").cause, /警報/);
  // the tracker opens a signal incident for a level of 1 or more, named by level, never "0 customers"
  const r = track({ open: [], closed: [] }, s, loadConfig(), NOW);
  const k = r.open.find((x) => x.region === "Kansai");
  assert.equal(r.open.length, 3);
  assert.deepEqual([k.kind, k.level, k.customers], ["supply_warning", 2, null]);
  assert.match(k.name, /^OCCTO wide-area reserve \(Japan\): supply warning level 2 in Kansai$/);
  // config/grid.json levels["occto-reserve"] = 2: the warning range asks for a check, the advisory range does not
  assert.deepEqual(triage(k, loadConfig()), { research_needed: true, research_reason: "grid_level" });
  assert.equal(triage(r.open.find((x) => x.region === "Tokyo"), loadConfig()).research_needed, false);
});

test("OCCTO: yesterday's reply, a missing list or no rates are a bad shape; the adapter asks for today in Japan time", async () => {
  assert.throws(() => parseOccto(fx(), Date.parse("2026-11-22T16:00:00Z")), (e) => e.code === "bad_shape" && /not 2026\/11\/23/.test(e.message));
  assert.throws(() => parseOccto({ todayRangeItem: { tgtDate: "2026/11/22" } }, NOW), (e) => e.code === "bad_shape");
  const d = fx(); d.todayAreaRsvRateList.forEach((a) => { a.areaRsvRateItems = []; });
  assert.throws(() => parseOccto(d, NOW), (e) => e.code === "bad_shape");
  let asked = "";
  globalThis.fetch = async (url) => { asked = String(url); return new Response(JSON.stringify({ ...fx(), todayRangeItem: { tgtDate: jstSlot(Date.now()).day } }), { status: 200 }); };
  const got = await ADAPTERS["occto-reserve"]();
  assert.match(asked, /^https:\/\/web-kohyo\.occto\.or\.jp\/kks-web-public\/home\/dailyData\?inputDate=\d{4}%2F\d{2}%2F\d{2}$/);
  noErrors(got);
  assert.equal(got.length, 10);
  assert.deepEqual(Object.keys(OCCTO_AREAS).length, 10);
});
