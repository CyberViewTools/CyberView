// Unit tests for the key-free grid-stress signals (scripts/grid-sources/keyless.mjs; node --test, no dependencies).
// Fixtures in tests/fixtures/grid/keyless/ are real replies saved on 2026-11-20 (trimmed); variants built inside a test
// say so.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { PLUGIN_ERRORS, SOURCES, REGIONS, OPERATORS, checkItem } from "../../scripts/grid.mjs";
import keyless, {
  parseNesoWarnings, nesoPeriod, parseFingrid, parseEcowatt, ecowattVersion, ecowattDay, parseKpx, zonedMs,
} from "../../scripts/grid-sources/keyless.mjs";

const FX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "grid", "keyless");
const txt = (f) => readFileSync(join(FX, f), "utf8");
const json = (f) => JSON.parse(txt(f));
const at = (iso) => Date.parse(iso);
const noErrors = (items) => items.forEach((x) => assert.deepEqual(checkItem(x), [], x.id));
const KEYS = ["neso-warnings", "fingrid", "rte-ecowatt", "kpx"];

test("keyless: the source file loads into grid.mjs with no plugin errors", () => {
  assert.deepEqual(PLUGIN_ERRORS.filter((e) => e.startsWith("keyless.mjs")), []);
  for (const k of KEYS) {
    assert.equal(SOURCES[k].file, "keyless.mjs", k);
    assert.equal(SOURCES[k].kind, "signal", k);
    assert.ok(!SOURCES[k].keyed, `${k} needs no key`);
    assert.ok(OPERATORS.includes(k), k);
    assert.match(SOURCES[k].terms_url, /^https:\/\//);
    assert.ok(["allowed", "silent"].includes(SOURCES[k].terms_ok), k);
  }
  for (const r of Object.keys(keyless.regions)) assert.ok(REGIONS[r], r);
});

test("zonedMs: wall-clock time in a zone, daylight saving included", () => {
  assert.equal(new Date(zonedMs(2026, 10, 6, 16, 0, "Europe/London")).toISOString(), "2026-10-06T15:00:00.000Z");   // BST
  assert.equal(new Date(zonedMs(2026, 11, 9, 8, 0, "Europe/London")).toISOString(), "2026-11-09T08:00:00.000Z");    // GMT
  assert.equal(new Date(zonedMs(2026, 11, 20, 9, 10, "Asia/Seoul")).toISOString(), "2026-11-20T00:10:00.000Z");
  assert.ok(Number.isNaN(zonedMs("x", 1, 1, 0, 0, "Europe/London")));
});

// ---------- NESO system warnings ----------
test("NESO: period of a notice and of its cancellation, UK time", () => {
  const p = nesoPeriod("For the period:\\r\\nfrom 16:00 hrs to 23:00 hrs on Tuesday   06/10/2026");
  assert.equal(new Date(p.start).toISOString(), "2026-10-06T15:00:00.000Z");
  assert.equal(new Date(p.end).toISOString(), "2026-10-06T22:00:00.000Z");
  const night = nesoPeriod("issued for the period from  23:00 hrs to 05:00 hrs on\r\nSaturday  24/10/2026  has been cancelled");
  assert.equal(new Date(night.end).toISOString(), "2026-10-25T05:00:00.000Z");   // ends the next morning (BST ends that night)
  assert.equal(nesoPeriod("no period here"), null);
});

test("NESO: an Electricity Margin Notice is level 1 until its period ends or it is cancelled", () => {
  const d = json("neso-syswarn.json");
  // evening before: the first notice (06:00-11:00, shortfall 1,388 MW)
  let x = parseNesoWarnings(d, at("2026-11-08T20:00:00Z"));
  assert.equal(x.length, 1); noErrors(x);
  assert.equal(x[0].kind, "supply_warning"); assert.equal(x[0].level, 1);
  assert.equal(x[0].started_at, "2026-11-08T19:17:00Z"); assert.equal(x[0].restore_est, "2026-11-09T11:00:00Z");
  assert.match(x[0].cause, /shortfall 1388 MW/);
  // the revised notice (08:00-11:00) replaces the first for the same day
  x = parseNesoWarnings(d, at("2026-11-09T08:30:00Z"));
  assert.equal(x.length, 1); assert.equal(x[0].level, 1); assert.match(x[0].cause, /08:00 to 11:00 UTC, margin shortfall 200 MW/);
  // cancelled at 09:11 ("remain in force: None"): back to level 0
  x = parseNesoWarnings(d, at("2026-11-09T09:30:00Z"));
  assert.deepEqual(x.map((i) => [i.id, i.level]), [["neso-warnings:system", 0]]);
  noErrors(x);
  // British Summer Time: 16:00-23:00 local is 15:00-22:00 UTC
  x = parseNesoWarnings(d, at("2026-10-06T14:00:00Z"));
  assert.equal(x[0].level, 1); assert.equal(x[0].restore_est, "2026-10-06T22:00:00Z");
  // negative reserve warnings (too much generation in Scotland), IT outages, trades: not supply stress
  assert.equal(parseNesoWarnings(d, at("2026-10-25T12:00:00Z"))[0].level, 0);
  // now: nothing in force
  assert.equal(parseNesoWarnings(d, at("2026-11-20T00:00:00Z"))[0].level, 0);
});

test("NESO: a notice whose period has passed with no cancellation seen is not current", () => {
  const d = json("neso-syswarn.json");
  const only = { data: d.data.filter((r) => r.publishTime === "2026-11-09T08:24:00Z") };   // variant: the cancellation removed
  assert.equal(parseNesoWarnings(only, at("2026-11-09T10:59:00Z"))[0].level, 1);
  assert.equal(parseNesoWarnings(only, at("2026-11-09T11:00:00Z"))[0].level, 0);
});

test("NESO: higher warnings, the classes still in force, and bad shapes", () => {
  const mk = (t, type, text) => ({ publishTime: t, warningType: type, warningText: text });
  const per = "For the period:\r\\nfrom 16:00 hrs to 19:00 hrs on Monday   07/12/2026";
  // variant texts built on the real notice layout
  const d = { data: [
    mk("2026-12-07T10:00:00Z", "ELECTRICITY MARGIN NOTICE", `ELECTRICITY MARGIN NOTICE ${per}`),
    mk("2026-12-07T12:00:00Z", "OTHER", `HIGH RISK OF DEMAND REDUCTION ${per}`),
    mk("2026-12-07T14:00:00Z", "OTHER", `NOTIFICATION CANCELLATION of GB TRANSMISSION SYSTEM WARNING HIGH RISK OF DEMAND REDUCTION issued for the period from 16:00 hrs to 19:00 hrs on Monday 07/12/2026 has been cancelled The following GB Transmission System Warnings remain in force ELECTRICITY MARGIN NOTICE`),
  ] };
  assert.deepEqual(parseNesoWarnings(d, at("2026-12-07T13:00:00Z")).map((x) => x.level).sort(), [1, 2]);
  assert.deepEqual(parseNesoWarnings(d, at("2026-12-07T15:00:00Z")).map((x) => x.level), [1]);
  d.data.push(mk("2026-12-07T15:30:00Z", "OTHER", `DEMAND CONTROL IMMINENT ${per}`));
  assert.ok(parseNesoWarnings(d, at("2026-12-07T16:00:00Z")).some((x) => x.level === 3));
  assert.throws(() => parseNesoWarnings({}), (e) => e.code === "bad_shape");
  assert.throws(() => parseNesoWarnings(null), (e) => e.code === "bad_shape");
});

// ---------- Fingrid ----------
test("Fingrid: traffic light and shortage indicator", () => {
  const d = json("fingrid-state.json");
  const now = at("2026-11-20T00:30:00Z");
  let x = parseFingrid(d, now);
  assert.equal(x.length, 1); noErrors(x);
  assert.deepEqual([x[0].id, x[0].kind, x[0].level, x[0].started_at], ["fingrid:state", "grid_emergency", 0, "2026-11-20T00:06:00Z"]);
  // variants on the real reply: each status, and a shortage
  const lv = (s) => parseFingrid({ ...d, Status: s }, now)[0].level;
  assert.deepEqual([1, 2, 3, 4, 5].map(lv), [0, 1, 2, 3, 2]);
  x = parseFingrid({ ...d, Status: 2, Shortage: 2 }, now);
  assert.deepEqual(x.map((i) => [i.kind, i.level]), [["grid_emergency", 1], ["supply_warning", 2]]);
  assert.deepEqual(parseFingrid({ ...d, Shortage: 3 }, now)[1].kind, "load_shedding");
  noErrors(x);
});

test("Fingrid: refuses unknown states, unreadable and stale times", () => {
  const d = json("fingrid-state.json");
  assert.throws(() => parseFingrid({ ...d, Status: 6 }, at("2026-11-20T00:30:00Z")), (e) => e.code === "bad_shape");
  assert.throws(() => parseFingrid({ ...d, Status: "1" }, at("2026-11-20T00:30:00Z")), (e) => e.code === "bad_shape");
  assert.throws(() => parseFingrid({ ...d, LastModified: "2026-11-20 02:06" }, at("2026-11-20T00:30:00Z")), (e) => e.code === "bad_shape");
  assert.throws(() => parseFingrid(d, at("2026-11-20T04:00:00Z")), (e) => e.code === "stale");
});

// ---------- RTE Ecowatt ----------
test("Ecowatt: version file and day codes", () => {
  assert.equal(ecowattVersion(txt("ecowatt-version-2.txt")), "976");
  assert.throws(() => ecowattVersion("<Error>AccessDenied</Error>"), (e) => e.code === "bad_shape");
  const day = ecowattDay("0C1F0J1P0X1");
  assert.equal(day.day, 0);
  assert.deepEqual(day.hours, [1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]);
  assert.throws(() => ecowattDay("0C1F0"), (e) => e.code === "bad_shape");
});

test("Ecowatt: the current hour's value; a file over 3 days old means no signal, as on the site", () => {
  const s = txt("ecowatt-app_signal.txt");   // real file dated 261030
  let x = parseEcowatt(s, at("2026-11-20T00:30:00Z"));
  noErrors(x);
  assert.deepEqual([x[0].level, x[0].started_at], [0, ""]);
  assert.match(x[0].cause, /2026-10-30/);
  x = parseEcowatt(s, at("2026-10-31T13:30:00Z"));   // day 2 (31 Oct), 14:30 Paris -> hour 14 of "0C1G0I1R0X1" = 0
  assert.deepEqual([x[0].level, x[0].started_at], [0, "2026-10-31T13:00:00Z"]);
  // variant on the real layout: today red 08:00-12:00, orange 17:00-20:00
  const red = "261207|2H1L3Q1T2X12X11X11X1|Système électrique très tendu||||";
  assert.deepEqual([9, 18, 22].map((h) => parseEcowatt(red, zonedMs(2026, 12, 7, h, 30, "Europe/Paris"))[0].level), [2, 1, 0]);
  noErrors(parseEcowatt(red, zonedMs(2026, 12, 7, 9, 30, "Europe/Paris")));
  assert.throws(() => parseEcowatt("<html>", at("2026-12-07T00:00:00Z")), (e) => e.code === "bad_shape");
  assert.throws(() => parseEcowatt("261207|2H1L3Q|x", at("2026-12-07T00:00:00Z")), (e) => e.code === "bad_shape");
});

// ---------- KPX ----------
test("KPX: supply reserve table and the KPX emergency thresholds", () => {
  const h = txt("kpx-supply.html");
  const x = parseKpx(h, at("2026-11-20T00:30:00Z"));
  noErrors(x);
  assert.deepEqual([x[0].id, x[0].kind, x[0].level, x[0].started_at], ["kpx:national", "supply_warning", 0, "2026-11-20T00:10:00Z"]);
  assert.match(x[0].cause, /supply reserve 24,738 MW/);
  // variants on the real table: reserve at each threshold (capacity adjusted so the table stays consistent)
  const withReserve = (r) => h.replace("100,316 MW", `${(75578 + r).toLocaleString("en-US")} MW`).replace("24,738 MW", `${r.toLocaleString("en-US")} MW`);
  const lv = (r) => parseKpx(withReserve(r), at("2026-11-20T00:30:00Z"))[0].level;
  assert.deepEqual([5500, 5499, 4499, 3499, 2499, 1499, 0].map(lv), [0, 1, 2, 3, 4, 5, 5]);
});

test("KPX: refuses a changed, inconsistent or stale table", () => {
  const h = txt("kpx-supply.html"), now = at("2026-11-20T00:30:00Z");
  assert.throws(() => parseKpx(h.replace('id="supPow"', 'id="x"'), now), (e) => e.code === "bad_shape");
  assert.throws(() => parseKpx(h.replace("24,738 MW", "4,738 MW"), now), (e) => e.code === "bad_shape");
  assert.throws(() => parseKpx(h.replace('class="info_top"', 'class="x"'), now), (e) => e.code === "bad_shape");
  assert.throws(() => parseKpx(h, at("2026-11-20T04:00:00Z")), (e) => e.code === "stale");
  assert.throws(() => parseKpx("", now), (e) => e.code === "bad_shape");
});
