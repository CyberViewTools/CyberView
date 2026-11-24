// Unit tests for the Asia-Pacific and Oceania grid sources (scripts/grid-sources/apac.mjs; node --test, no dependencies).
// Fixtures in tests/fixtures/grid/apac/ are real replies saved on 2026-11-24 (trimmed: fewer records, polygons cut to a
// few points); wem-advisories-2026-05.csv is rows of AEMO's earlier advisories file (ended 2026-05-18), kept because it
// holds a declared Emergency. Variants built inside a test say so.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { PLUGIN_ERRORS, SOURCES, REGIONS, OPERATORS, checkItem } from "../../scripts/grid.mjs";
import apac, {
  zonedMs, nzDmyToIso, nzDateTimeToIso, nzDayMonthToIso, mainpowerJob, parseMainpower, topEnergyOutage, parseTopEnergy,
  tlcEntry, tlcWindow, parseTlc, eaRecord, parseEa, parseCsv, awstMs, wemLevel, parseWem,
} from "../../scripts/grid-sources/apac.mjs";

const FX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "grid", "apac");
const txt = (f) => readFileSync(join(FX, f), "utf8");
const json = (f) => JSON.parse(txt(f));
const at = (iso) => Date.parse(iso);
const noErrors = (items) => items.forEach((x) => assert.deepEqual(checkItem(x), [], x.id));
const KEYS = ["mainpower-nz", "topenergy-nz", "tlc-nz", "ea-networks-nz", "aemo-wem"];

test("apac: the source file loads into grid.mjs with no plugin errors", () => {
  assert.deepEqual(PLUGIN_ERRORS.filter((e) => e.startsWith("apac.mjs")), []);
  for (const k of KEYS) {
    assert.equal(SOURCES[k].file, "apac.mjs", k);
    assert.ok(!SOURCES[k].keyed, `${k} needs no key`);
    assert.ok(OPERATORS.includes(k), k);
    assert.match(SOURCES[k].terms_url, /^https:\/\//);
    assert.ok(["allowed", "silent"].includes(SOURCES[k].terms_ok), k);
  }
  assert.equal(SOURCES["aemo-wem"].kind, "signal");
  for (const r of Object.keys(apac.regions)) assert.ok(REGIONS[r], r);
});

test("time helpers: New Zealand (daylight saving) and Western Australia wall-clock times", () => {
  assert.equal(new Date(zonedMs(2026, 11, 24, 9, 22, "Pacific/Auckland")).toISOString(), "2026-11-23T20:22:00.000Z");   // NZDT
  assert.equal(new Date(zonedMs(2026, 6, 1, 9, 0, "Pacific/Auckland")).toISOString(), "2026-05-31T21:00:00.000Z");      // NZST
  assert.equal(nzDmyToIso("24/11/2026 16:30"), "2026-11-24T03:30:00Z");
  assert.equal(nzDateTimeToIso("2026-11-25", "09:00"), "2026-11-24T20:00:00Z");
  assert.equal(nzDayMonthToIso("25th November 03:00 pm", at("2026-11-24T20:30:00Z")), "2026-11-25T02:00:00Z");
  assert.equal(nzDayMonthToIso("2nd January 09:30 am", at("2026-12-30T00:00:00Z")), "2027-01-01T20:30:00Z");   // year rolls over
  assert.equal(nzDmyToIso("x"), "");
  assert.equal(new Date(awstMs("2026-05-14 17:20:00")).toISOString(), "2026-05-14T09:20:00.000Z");
});

test("MainPower: every field of the outage in progress, with the point of its unrestored step", () => {
  const d = json("mainpower-jobs.json");
  const items = parseMainpower(d);
  assert.equal(items.length, 1);
  const x = items[0];
  assert.equal(x.id, "mainpower-nz:J.26.10.0128");
  assert.equal(x.customers, 2);                          // CustomersOff (10 more already restored)
  assert.equal(x.cause, "Pole Replacement");
  assert.equal(x.planned, true);                         // Type "Outage-Planned"
  assert.equal(x.area, "Glendhu Road, Motunau");
  assert.equal(x.started_at, "2026-11-23T20:22:00Z");    // 24/11/2026 09:22 NZDT
  assert.equal(x.restore_est, "2026-11-24T03:30:00Z");   // 24/11/2026 16:30 NZDT
  const step = Object.values(d.current_outages["J.26.10.0128"].steps).map((f) => f.properties).find((p) => p.Status !== "Restored");
  assert.equal(x.lat, step.Lat); assert.equal(x.lng, step.Lon);
  assert.equal(x.url, "https://outages.mainpower.co.nz/");
  noErrors(items);
  // variant: the same job with nothing off and every step restored is over
  const done = { ...d.current_outages["J.26.10.0128"], CustomersOff: 0 };
  done.steps = Object.fromEntries(Object.entries(done.steps).map(([k, f]) => [k, { ...f, properties: { ...f.properties, Status: "Restored" } }]));
  assert.equal(mainpowerJob(done), null);
  assert.throws(() => parseMainpower({}), /unexpected shape/);
});

test("Top Energy: fields of an outage and its point; only active outages are in progress", () => {
  const r = json("topenergy-regions.json"), o = json("topenergy-outages.json");
  assert.deepEqual([...parseTopEnergy(r, o)], []);   // nothing active when saved
  const p0 = r.planned[0], pt = o.planned.find((p) => p.id === p0.name);
  const x = topEnergyOutage(p0, pt);
  assert.equal(x.id, "topenergy-nz:47558F");
  assert.equal(x.area, "Waima");
  assert.equal(x.customers, 115);
  assert.equal(x.planned, true);
  assert.equal(x.started_at, "2026-11-24T20:30:00Z");   // startTimestamp 1795552200
  assert.equal(x.restore_est, "2026-11-25T02:00:00Z");  // "25th November 03:00 pm" NZDT
  assert.equal(x.lat, pt.lat); assert.equal(x.lng, pt.lng);
  assert.equal(x.cause, "");                           // the reply gives no reason
  // variant: the same planned outage marked active
  const live = parseTopEnergy({ ...r, planned: [{ ...p0, isActive: true }, ...r.planned.slice(1)] }, o);
  assert.deepEqual(live.map((i) => i.id), ["topenergy-nz:47558F"]);
  noErrors(live);
  assert.throws(() => parseTopEnergy({}, o), /unexpected shape/);
});

test("The Lines Company: every field of a shutdown; only shutdowns inside their window are in progress", () => {
  const s = json("tlc-shutdowns.json");
  const x = tlcEntry(s.find((e) => e.unique_id === "DJA0070"));
  assert.equal(x.area, "Ohakune");
  assert.equal(x.customers, 8);
  assert.equal(x.cause, "Routine Maintenance");
  assert.equal(x.planned, true);
  assert.equal(x.started_at, "2026-11-24T20:00:00Z");   // 2026-11-25 09:00 NZDT
  assert.equal(x.restore_est, "2026-11-25T03:30:00Z");  // 16:30
  assert.equal(x.lat, -39.4017766); assert.equal(x.lng, 175.3848142);
  // postponed: the alternate date
  const pp = s.find((e) => e.status === "postponed" && e.scheduled_date === "2026-11-11");
  assert.deepEqual(tlcWindow(pp), { start: "2026-11-24T20:00:00Z", end: "2026-11-25T02:00:00Z" });
  assert.equal(parseTlc([], s, at("2026-11-24T06:00:00Z")).length, 0);
  const live = parseTlc([], s, at("2026-11-24T22:00:00Z"));
  assert.deepEqual(live.map((i) => i.id).sort(), ["tlc-nz:DJA0070", "tlc-nz:TAG3582 - TAG3582A"]);
  noErrors(live);
  assert.throws(() => parseTlc({}, s), /unexpected shape/);
});

test("EA Networks: every field of a record; restored and completed records are not in progress", () => {
  const d = json("ea-recent.json");
  const x = eaRecord(d.outages[0]);
  assert.equal(x.id, "ea-networks-nz:J.E.26.11.0011");
  assert.equal(x.area, "Dobson Rd");
  assert.equal(x.cause, "Tree Trimming");
  assert.equal(x.planned, true);
  assert.equal(x.started_at, "2026-11-23T19:33:22Z");
  assert.equal(x.restore_est, "2026-11-24T03:00:00Z");
  assert.equal(x.lat, d.outages[0].latitude); assert.equal(x.lng, d.outages[0].longitude);
  const u = eaRecord(d.outages[1]);
  assert.equal(u.planned, false);
  assert.equal(u.area, "Chertsey Road,Chertsey Kyle Road");   // no name: the streets it gives
  assert.deepEqual([...parseEa(d)], []);
  assert.deepEqual([...parseEa(json("ea-current.json"))], []);
  // variant: the unplanned record still off
  const live = parseEa({ outages: [{ ...d.outages[1], status: "IN_PROGRESS", energization_status: "DE_ENERGIZED", end_time: null, current_affected_customers: 17 }] }, at("2026-11-23T18:00:00Z"));
  assert.equal(live.length, 1); assert.equal(live[0].customers, 17);
  noErrors(live);
});

test("AEMO WEM: a declared Emergency in effect is a level-3 grid emergency; normal states give nothing", () => {
  assert.deepEqual(parseCsv('a,"b,c",d\r\n1,"x ""y""\nz",3\r\n'), [["a", "b,c", "d"], ["1", 'x "y"\nz', "3"]]);
  assert.equal(wemLevel("Emergency"), 3); assert.equal(wemLevel("High Risk"), 2);
  assert.equal(wemLevel("Reliable, Secure and Satisfactory"), null); assert.equal(wemLevel("Normal"), null);
  const old = txt("wem-advisories-2026-05.csv");
  const items = parseWem(old, at("2026-05-14T09:30:00Z"));
  assert.equal(items.length, 1);
  const x = items[0];
  assert.equal(x.id, "aemo-wem:212780");
  assert.equal(x.kind, "grid_emergency"); assert.equal(x.level, 3); assert.equal(x.customers, null);
  assert.match(x.cause, /^Emergency: AEMO has lost SCADA visibility of the SWIS/);
  assert.equal(x.started_at, "2026-05-14T09:20:00Z"); assert.equal(x.restore_est, "2026-05-14T10:00:00Z");
  noErrors(items);
  assert.equal(parseWem(old, at("2026-05-14T10:30:00Z")).length, 0);   // after its end
  const cur = parseWem(txt("wem-advisories.csv"), at("2026-11-24T06:00:00Z"));
  assert.deepEqual([...cur], []);
  assert.equal(cur.data_at, "2026-11-24T06:00:01Z");   // Extracted At 14:00:01 AWST
  assert.throws(() => parseWem("x,y\n1,2"), /unexpected shape/);
});

test("adapters: fetch with h.get and return items that pass checkItem", async () => {
  const replies = {
    "https://outages.mainpower.co.nz/jobs?source=pcc&view=external": json("mainpower-jobs.json"),
    "https://outages.topenergy.co.nz/api/outages/regions": json("topenergy-regions.json"),
    "https://outages.topenergy.co.nz/api/outages": json("topenergy-outages.json"),
    "https://tlc-outage-website-outage-data-production.s3.ap-southeast-2.amazonaws.com/outages.json": [],
    "https://tlc-outage-website-outage-data-production.s3.ap-southeast-2.amazonaws.com/shutdowns.json": json("tlc-shutdowns.json"),
    "https://outages-eanetworks-co-nz.vercel.app/api/get-outages?tab=current": json("ea-current.json"),
    [SOURCES["aemo-wem"].url]: txt("wem-advisories.csv"),
  };
  const h = { get: async (u) => { assert.ok(u in replies, u); return replies[u]; }, item: (x) => ({ ...x, lat: x.lat == null ? null : Math.round(x.lat * 1000) / 1000, lng: x.lng == null ? null : Math.round(x.lng * 1000) / 1000 }) };
  for (const k of KEYS) {
    const items = await apac.adapters[k](h);
    assert.ok(Array.isArray(items), k);
    noErrors(items);
  }
  assert.equal((await apac.adapters["mainpower-nz"](h)).length, 1);
});
