// Unit tests for the grid analysis (node --test; no dependencies). Series, incidents, IODA, GDACS and lead fixtures are
// synthetic, built here in the shapes the real files have (data/grid/series, data/context/ioda.json and gdacs.json as
// written by scripts/context.mjs, data/leads/<day>.jsonl); they say so where they are made.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  baseline, anomaly, anomalies, corroborate, placeNames, POWER_WORDS, trends, feedback, applyFeedback, analyze, checkAnalysis,
  verifyAnalysis, readSeries, WINDOW_H,
} from "../../scripts/grid-analysis.mjs";
import { DEFAULT_CFG } from "../../scripts/grid.mjs";

const H = 3600e3, D = 864e5, SLOT = 15 * 6e4;
const NOW = Date.parse("2026-11-19T15:00:00Z");      // a Thursday, 15:00 UTC
const iso = (t) => new Date(t).toISOString().replace(/\.\d+Z$/, "Z");
const pt = (t, unplanned, o = {}) => ({ at: iso(t), source: "bchydro", region: "British Columbia", customers: unplanned, unplanned, level: null, ...o });

/** Synthetic 4 weeks of 15-minute points: `f(t)` gives the unplanned customers at time t. */
const fourWeeks = (f, o = {}) => { const out = []; for (let t = NOW - 28 * D; t < NOW; t += SLOT) out.push(pt(t, f(t), o)); return out; };

// ---------- baseline and anomaly ----------
test("baseline: same hour of the week over 4 weeks, median and MAD", () => {
  // Thursdays 15:xx: 1000, 1200, 1400, 1600 by week, the four slots of each hour equal; every other hour 100
  const series = fourWeeks((t) => (new Date(t).getUTCDay() === 4 && new Date(t).getUTCHours() === 15 ? 1000 + 200 * Math.floor((t - (NOW - 28 * D)) / (7 * D)) : 100));
  const b = baseline(series, "bchydro|British Columbia", NOW);
  assert.equal(b.basis, "hour_of_week");
  assert.equal(b.points, 16);
  assert.equal(b.median, 1300);
  assert.equal(b.mad, 200);
  assert.equal(baseline(series, "ukpn|London, South East and East of England", NOW), null);
  // the robust z: (x - median) / (1.4826 * MAD)
  assert.deepEqual(anomaly(1300 + 4 * 1.4826 * 200, b, DEFAULT_CFG), { z: 4, flagged: false });    // z 4 but below 5,000 customers
  assert.deepEqual(anomaly(9000, b, DEFAULT_CFG), { z: 26, flagged: true });
  assert.deepEqual(anomaly(5000, { median: 4000, mad: 1000, points: 9 }, DEFAULT_CFG), { z: 0.7, flagged: false });
  assert.deepEqual(anomaly(6000, { median: 0, mad: 0, points: 20 }, DEFAULT_CFG), { z: 6000, flagged: true });   // MAD 0 read as 1
  assert.deepEqual(anomaly(null, b), { z: null, flagged: false });
  assert.deepEqual(anomaly(9000, null), { z: null, flagged: false });
});

test("baseline: fewer than 8 points at this hour of the week falls back to all hours", () => {
  // only 3 days of hourly points (not 4 weeks): the same hour-of-week has 0 points before NOW
  const series = []; for (let t = NOW - 3 * D; t < NOW; t += H) series.push(pt(t, new Date(t).getUTCHours() < 12 ? 10 : 30));
  const b = baseline(series, "bchydro|British Columbia", NOW);
  assert.equal(b.basis, "all_hours");
  assert.equal(b.points, 72);
  assert.equal(b.median, 20);
  assert.equal(b.mad, 10);
  // points older than 4 weeks and at or after now are not used
  assert.equal(baseline([pt(NOW - 29 * D, 5), pt(NOW, 5)], "bchydro|British Columbia", NOW), null);
});

test("anomalies: latest point per region, flagged against its baseline; signal levels above 0 are notable", () => {
  const quiet = fourWeeks(() => 200);
  const series = [...quiet, pt(NOW, 12000), pt(NOW - SLOT, 300, { source: "ukpn", region: "London, South East and East of England" }),
    { at: iso(NOW), source: "eskom", region: "South Africa", customers: null, unplanned: 0, level: 2 },
    { at: iso(NOW), source: "ercot", region: "Texas", customers: null, unplanned: 0, level: 0 },
    pt(NOW - 2 * H, 50000, { source: "hydroquebec", region: "Quebec" })];                      // older than an hour: not current
  const open = [{ id: "grid-bchydro-british-columbia-202611191500", source: "bchydro", region: "British Columbia", closed_at: "" }];
  const a = anomalies(series, NOW, DEFAULT_CFG, open);
  assert.deepEqual(a.map((x) => [x.source, x.kind, x.value]), [["bchydro", "customers", 12000], ["eskom", "level", 2]]);
  assert.equal(a[0].id, "grid-bchydro-british-columbia-202611191500");
  assert.equal(a[0].median, 200);
  assert.equal(a[0].basis, "hour_of_week");
  assert.equal(a[0].name, "British Columbia");
  assert.equal(a[1].name, "South Africa");
});

// ---------- corroboration ----------
const INC = { id: "grid-hydroquebec-quebec-202611191200", source: "hydroquebec", country: "CA", region: "Quebec", kind: "outage",
  name: "Hydro-Québec: 82,000 customers without power", opened_at: "2026-11-19T12:00:00Z", closed_at: "", lat: 46.8, lng: -71.2,
  peak_customers: 82000, planned_share: 0, causes: [{ cause: "Equipment failure", customers: 80000 }], url: "https://pannes.hydroquebec.com/pannes/" };
// synthetic context files in the shape scripts/context.mjs writes
const IODA = { layer: "ioda", fetched_at: "2026-11-19T14:00:00Z", ok: true, error: "", items: [
  { code: "CA", name: "Canada", map_name: "Canada", score: 9000, events: 2, signals: ["bgp", "ping-slash24"], url: "https://ioda.inetintel.cc.gatech.edu/country/CA" },
  { code: "ZA", name: "South Africa", map_name: "South Africa", score: 100, events: 1, signals: ["bgp"], url: "https://ioda.inetintel.cc.gatech.edu/country/ZA" }] };
const GDACS = { layer: "gdacs", fetched_at: "2026-11-19T14:00:00Z", ok: true, error: "", items: [
  { id: "WF-1", type: "wildfire", level: "orange", name: "Wildfire near Quebec City", country: "Canada", from: "2026-11-19T06:00:00", to: "2026-11-20T00:00:00", lat: 46.9, lng: -71.3, url: "https://www.gdacs.org/report.aspx?eventid=1" },
  { id: "TC-2", type: "tropical cyclone", level: "red", name: "Cyclone far away", country: "India", from: "2026-11-19T06:00:00", to: "2026-11-20T00:00:00", lat: 15, lng: 80, url: "https://www.gdacs.org/report.aspx?eventid=2" },
  { id: "FL-3", type: "flood", level: "orange", name: "Old flood", country: "Canada", from: "2026-11-10T00:00:00", to: "2026-11-12T00:00:00", lat: 46, lng: -72, url: "https://www.gdacs.org/report.aspx?eventid=3" }] };
// synthetic leads in the data/leads/<day>.jsonl shape
const lead = (title, published, o = {}) => ({ seen_at: published, source: "CBC News", tier: "news", via: "rss", title, url: "https://www.cbc.ca/news/x", published, summary: "", ...o });
const LEADS = [
  lead("Panne majeure : 80 000 clients d'Hydro-Québec privés de courant", "2026-11-19T13:00:00Z", { source: "Radio-Canada", url: "https://ici.radio-canada.ca/x" }),
  lead("Power outage hits Quebec City as crews work overnight", "2026-11-19T14:30:00Z", { url: "https://news.google.com/rss/articles/abc" }),
  lead("Power outage hits Quebec City as crews work overnight", "2026-11-19T14:40:00Z"),                // same title: counted once
  lead("Quebec election debate tonight", "2026-11-19T13:00:00Z"),                                        // no power word
  lead("Blackout in Texas after storm", "2026-11-19T13:00:00Z"),                                         // other place
  lead("Hydro-Québec blackout last week", "2026-11-18T23:00:00Z"),                                       // more than 6 h before opening
];

test("corroborate: one signal per independent kind, matched by country / region and the +-6 h window", () => {
  // an 82,000-customer outage in Quebec is not national: Canada-wide IODA says nothing about it (logic-2)
  const c0 = corroborate(INC, { ioda: IODA, gdacs: GDACS, leads: LEADS, items: [], now: NOW });
  assert.deepEqual(c0.signals.map((s) => [s.kind, s.source]), [["operator", "hydroquebec"], ["disaster", "gdacs"], ["news", "Radio-Canada"], ["news", "CBC News"]]);
  // a nationally significant one (250,000 or more) takes it, labelled nationwide
  const big = { ...INC, peak_customers: 300000 };
  const c = corroborate(big, { ioda: IODA, gdacs: GDACS, leads: LEADS, items: [], now: NOW });
  assert.equal(c.id, INC.id);
  assert.deepEqual(c.signals.map((s) => [s.kind, s.source]), [["operator", "hydroquebec"], ["internet", "ioda"], ["disaster", "gdacs"], ["news", "Radio-Canada"], ["news", "CBC News"]]);
  assert.equal(c.score, 4);
  assert.match(c.signals[1].detail, /nationwide internet disruption signal in Canada \(bgp, ping-slash24\)/);
  assert.match(c.signals[2].detail, /orange alert: wildfire, Wildfire near Quebec City/);
  assert.equal(c.signals[4].url, "");                                                    // a news.google.com redirect is never cited
  assert.equal(c.signals[3].url, "https://ici.radio-canada.ca/x");
  assert.deepEqual(checkAnalysis({ updated_at: iso(NOW), anomalies: [], corroboration: [c], trends: { regions: {} }, research: [], sources: {} }), []);
});

test("corroborate: keyed signals (Radar internet, EIA demand, ENTSO-E operator) by country and time; nothing elsewhere", () => {
  const item = (source, country, started_at, o = {}) => ({ id: `${source}:1`, source, country, region: "x", area: "Area", lat: null, lng: null,
    customers: null, kind: "outage", planned: false, cause: "Power outage", level: null, started_at, restore_est: "", url: "", ...o });
  const za = { ...INC, id: "grid-eskom-south-africa-202611191200", source: "eskom", country: "ZA", region: "South Africa", kind: "load_shedding",
    name: "Eskom: load-shedding stage 4", lat: -28.5, lng: 25.5, causes: [] };
  const items = [item("cfradar", "ZA", "2026-11-19T11:00:00Z"), item("cfradar", "ZA", "2026-11-18T00:00:00Z", { restore_est: "2026-11-18T03:00:00Z" }),
    item("cfradar", "CU", "2026-11-19T11:00:00Z"), item("eia", "ZA", "2026-11-19T13:00:00Z"),
    item("entsoe", "ZA", "2026-11-19T13:00:00Z"), item("entsoe", "ZA", "2026-11-19T13:00:00Z"), item("entsoe", "ZA", "2026-11-19T13:00:00Z"), item("entsoe", "ZA", "2026-11-19T13:00:00Z")];
  const c = corroborate(za, { ioda: { fetched_at: "2026-11-18T00:00:00Z", items: IODA.items }, gdacs: GDACS, leads: [], items, now: NOW });
  // IODA fetched too long ago; ENTSO-E capped at 3; an EIA item of no known balancing authority never counts (logic-2)
  assert.deepEqual(c.signals.map((s) => s.source), ["eskom", "cfradar", "entsoe", "entsoe", "entsoe"]);
  assert.equal(c.score, 2);                                                              // operator, internet (Eskom covers the country)
  assert.match(c.signals[1].detail, /nationwide signal/);
  // the window: an incident closed at 13:00 accepts signals up to 19:00, not after
  const closed = { ...INC, closed_at: "2026-11-19T13:00:00Z" };
  assert.equal(corroborate(closed, { leads: [lead("Hydro-Québec power outage update", "2026-11-19T18:59:00Z")], now: NOW }).score, 2);
  assert.equal(corroborate(closed, { leads: [lead("Hydro-Québec power outage update", "2026-11-19T19:01:00Z")], now: NOW }).score, 1);
  assert.equal(WINDOW_H, 6);
});

test("placeNames and power words: region parts, operator and country; several languages", () => {
  assert.deepEqual(placeNames({ source: "ukpn", region: "London, South East and East of England", country: "GB" }).slice(0, 3), ["London", "South East", "East of England"]);
  assert.ok(placeNames({ source: "ercot", region: "Texas", country: "US" }).includes("Texas"));
  assert.ok(placeNames({ source: "aemo", region: "SA1", country: "AU" }).includes("South Australia"));
  assert.ok(!placeNames({ source: "aemo", region: "SA1", country: "AU" }).includes("SA1"));
  for (const t of ["Apagón en Madrid", "Stromausfall in Berlin", "Coupure de courant à Paris", "Eskom load shedding stage 6", "UK power cut", "National grid fault"])
    assert.ok(POWER_WORDS.test(t), t);
  assert.ok(!POWER_WORDS.test("Gridlock on the highway"));
});

// ---------- trends ----------
test("trends: incidents, customer-hours (unplanned x 0.25 per 15-minute point), largest, causes mix, week over week", () => {
  const series = [
    pt(NOW - 2 * D, 4000), pt(NOW - 2 * D + SLOT, 4000), pt(NOW - 2 * D + SLOT, 4000),     // the duplicate slot counted once
    pt(NOW - 10 * D, 1000), pt(NOW - 40 * D, 99999),                                       // previous week; outside 30 days
    pt(NOW - D, 0, { source: "ukpn", region: "London, South East and East of England" }),
  ];
  const mk = (id, opened, peak, causes, extra = {}) => ({ id, source: "bchydro", region: "British Columbia", name: id, opened_at: iso(opened), closed_at: "", peak_customers: peak, causes, ...extra });
  const history = [
    mk("grid-bchydro-british-columbia-a", NOW - 2 * D, 9000, [{ cause: "Tree contact", customers: 6000 }, { cause: "Under investigation", customers: 3000 }], { closed_at: iso(NOW - D) }),
    mk("grid-bchydro-british-columbia-a", NOW - 2 * D, 9000, [], { closed_at: "" }),           // the same incident, open copy: merged
    mk("grid-bchydro-british-columbia-b", NOW - 9 * D, 30000, [{ cause: "Tree contact", customers: 20000 }]),
    mk("grid-bchydro-british-columbia-c", NOW - 45 * D, 900000, []),
    { ...mk("grid-cfradar-x-1", NOW - D, 1, []), source: "cfradar" },
  ];
  const t = trends(history, series, NOW);
  assert.equal(t.window_days, 30);
  const bc = t.regions["bchydro|British Columbia"];
  assert.equal(bc.incidents, 2);
  assert.equal(bc.customer_hours, 2250);                                                  // (4000 + 4000 + 1000) x 0.25
  assert.deepEqual(bc.week, { customer_hours: 2000, prev_customer_hours: 250, change_pct: 700, incidents: 1, prev_incidents: 1 });
  assert.deepEqual(bc.largest, { id: "grid-bchydro-british-columbia-b", name: "grid-bchydro-british-columbia-b", peak_customers: 30000, peak_level: null, opened_at: iso(NOW - 9 * D) });
  assert.deepEqual(bc.causes, [{ cause: "Tree contact", customers: 26000 }, { cause: "Under investigation", customers: 3000 }]);
  const uk = t.regions["ukpn|London, South East and East of England"];
  assert.deepEqual([uk.incidents, uk.customer_hours, uk.week.change_pct, uk.largest], [0, 0, null, null]);
  assert.equal(Object.keys(t.regions).length, 2);                                          // keyed sources have no trends
});

// ---------- feed-back ----------
test("feedback: anomaly with score >= 3, or internet without a weather cause; load shedding and planned work left out", () => {
  const cor = (id, kinds) => ({ id, signals: kinds.map((kind) => ({ kind, source: "x", detail: "", url: "" })), score: new Set(kinds).size });
  const i = (id, o = {}) => ({ ...INC, id, ...o });
  const incidents = [i("grid-a-1"), i("grid-b-1", { region: "Elsewhere" }), i("grid-c-1", { causes: [{ cause: "High winds", customers: 1 }] }),
    i("grid-d-1", { kind: "load_shedding" }), i("grid-e-1", { planned_share: 0.8 }), i("grid-f-1", { region: "Elsewhere" })];
  const anoms = [{ source: "hydroquebec", region: "Quebec" }];
  const c = [cor("grid-a-1", ["operator", "disaster", "news"]), cor("grid-b-1", ["operator", "internet"]), cor("grid-c-1", ["operator", "internet"]),
    cor("grid-d-1", ["operator", "internet"]), cor("grid-e-1", ["operator", "internet"]), cor("grid-f-1", ["operator", "disaster", "news"])];
  const r = feedback(incidents, anoms, c);
  assert.deepEqual(r.map((x) => x.id), ["grid-a-1", "grid-b-1"]);
  assert.match(r[0].why, /unusual for this hour, 3 kinds/);
  // weather-caused incident with an anomaly and 3 kinds still counts
  assert.deepEqual(feedback([i("grid-c-1", { causes: [{ cause: "Storm", customers: 1 }] })], anoms, [cor("grid-c-1", ["operator", "internet", "news"])]).map((x) => x.id), ["grid-c-1"]);
  const doc = { open: [{ id: "grid-a-1", research_needed: false, research_reason: "small" }, { id: "grid-b-1", research_needed: true, research_reason: "big" }] };
  assert.deepEqual(applyFeedback(doc, r), ["grid-a-1"]);
  assert.deepEqual(doc.open.map((x) => x.research_reason), ["corroborated", "big"]);
});

// ---------- the whole document, verify, files ----------
test("analyze -> analysis.json shape; verify names the broken field; readSeries skips bad lines", () => {
  const series = [...fourWeeks(() => 100, { source: "hydroquebec", region: "Quebec" }), pt(NOW, 82000, { source: "hydroquebec", region: "Quebec" })];
  const live = { sources: { hydroquebec: { ok: true, error: "" }, eia: { ok: false, error: "not connected (no key saved for api.eia.gov)" } }, items: [] };
  const a = analyze({ incidents: { open: [{ ...INC, peak_customers: 300000 }], closed: [] }, series, live, ioda: IODA, gdacs: GDACS, leads: LEADS, now: NOW });
  assert.deepEqual(checkAnalysis(a), []);
  assert.equal(a.anomalies[0].id, INC.id);
  assert.equal(a.corroboration[0].score, 4);
  assert.deepEqual(a.research.map((r) => r.id), [INC.id]);
  assert.deepEqual(a.sources.eia, { ok: false, error: "not connected (no key saved for api.eia.gov)" });
  assert.deepEqual(a.sources.ioda, { ok: true, error: "" });
  assert.ok(a.trends.regions["hydroquebec|Quebec"].customer_hours > 0);

  const root = mkdtempSync(join(tmpdir(), "grid-analysis-"));
  mkdirSync(join(root, "data", "grid", "series"), { recursive: true });
  assert.deepEqual(verifyAnalysis(root).map((b) => b.errors[0]), ["file: missing"]);
  assert.deepEqual(verifyAnalysis(root, false), []);
  const bad = JSON.parse(JSON.stringify(a));
  bad.corroboration[0].score = 9;
  bad.corroboration[0].signals[1].url = "http://insecure.example/";
  writeFileSync(join(root, "data", "grid", "analysis.json"), JSON.stringify(bad));
  assert.deepEqual(verifyAnalysis(root)[0].errors, ["corroboration[0].signals[1]: not { kind, source, detail, url (https or \"\") }", "corroboration[0].score: not the number of kinds"]);
  writeFileSync(join(root, "data", "grid", "analysis.json"), JSON.stringify(a));
  writeFileSync(join(root, "data", "grid", "series", "2026-11-19.jsonl"), JSON.stringify(pt(NOW, 5)) + "\nnot json\n" + JSON.stringify({ ...pt(NOW, 5), at: "2026-11-19T15:07:00Z" }) + "\n");
  const v = verifyAnalysis(root);
  assert.equal(v[0].file, "data/grid/series/2026-11-19.jsonl");
  assert.deepEqual(v[0].errors, ["line 2: not JSON", "line 3.at: not the ISO start of a 15-minute slot"]);
  assert.deepEqual(readSeries(join(root, "data", "grid", "series"), 3, NOW).map((p) => p.at), [iso(NOW)]);
  assert.deepEqual(checkAnalysis(null), ["root: not an object"]);
});

// ---------- review findings 2026-11-20 (grid-fixes lane) ----------
const LADWP = { id: "grid-ladwp-los-angeles-202611200028", source: "ladwp", country: "US", region: "Los Angeles", kind: "outage",
  name: "LADWP: 5,451 customers without power", opened_at: "2026-11-20T00:28:00Z", closed_at: "", lat: 34.05, lng: -118.35,
  peak_customers: 5451, planned_share: 0, causes: [], url: "https://www.ladwp.com/outages/power-outage-map" };
const eia = (ba, name, o = {}) => ({ id: `eia:${ba}-2026-11-19T23`, source: "eia", country: "US", region: name, area: `${name} (${ba})`, lat: null, lng: null,
  customers: null, kind: "supply_warning", planned: false, cause: "demand 2292 MWh: 36% under forecast, 28% under the same hour yesterday", level: null,
  started_at: "2026-11-19T23:00:00Z", restore_est: "", url: "https://www.eia.gov/electricity/gridmonitor/", ...o });
test("logic-2/sources-1: an Arizona EIA drop does not corroborate Los Angeles; LADWP's own authority and a near one do", () => {
  const now = Date.parse("2026-11-20T01:40:00Z");
  const srp = corroborate(LADWP, { items: [eia("SRP", "Salt River Project Agricultural Improvement and Power District")], now });
  assert.deepEqual(srp.signals.map((s) => s.kind), ["operator"]);                 // SRP is Phoenix, ~590 km away
  assert.equal(corroborate(LADWP, { items: [eia("LDWP", "Los Angeles Department of Water and Power")], now }).score, 2);
  assert.equal(corroborate(LADWP, { items: [eia("CISO", "California Independent System Operator")], now }).score, 1);   // CAISO's centre is 400 km off
  // a state region of DOE ODIN takes every authority serving that state
  const tx = { ...LADWP, id: "grid-doe-odin-texas-202611200028", source: "doe-odin", region: "Texas", lat: 31.5, lng: -99.3 };
  assert.equal(corroborate(tx, { items: [eia("ERCO", "ERCOT")], now }).score, 2);
  // country-wide internet signals and the country name in a headline do not reach a regional US incident
  const radar = { id: "cfradar:a-US", source: "cfradar", country: "US", region: "United States", area: "United States", lat: 39.8, lng: -98.6, customers: null,
    kind: "outage", planned: false, cause: "Power outage", level: null, started_at: "2026-11-20T00:00:00Z", restore_est: "", url: "" };
  const ioda = { fetched_at: "2026-11-20T01:00:00Z", items: [{ code: "US", name: "United States", signals: ["bgp"], url: "" }] };
  const c = corroborate(LADWP, { items: [radar], ioda, leads: [lead("United States blackout", "2026-11-20T00:40:00Z")], now });
  assert.equal(c.score, 1);
  // a Radar annotation that names the region does count
  assert.equal(corroborate(LADWP, { items: [{ ...radar, area: "Los Angeles" }], now }).score, 2);
});

test("logic-2: EIA demand signals sit at their balancing authority, not the US centroid", async () => {
  const { parseEia, EIA_BA } = await import("../../scripts/grid.mjs");
  const { readFileSync } = await import("node:fs");
  const d = JSON.parse(readFileSync(new URL("../fixtures/grid/eia.json", import.meta.url), "utf8"));
  // synthetic from the real reply (as in grid.test.mjs): PJM's two complete hours cut by 40%
  const rows = d.response.data, newest = rows.filter((r) => r.type === "D").map((r) => r.period).sort().pop();
  const hours = [...new Set(rows.filter((r) => r.respondent === "PJM" && r.type === "D").map((r) => r.period))].sort().reverse();
  const cut = { response: { data: rows.map((r) => r.respondent === "PJM" && r.type === "D" && [hours[1], hours[2]].includes(r.period) ? { ...r, value: String(Math.round(Number(r.value) * 0.6)) } : r) } };
  const x = parseEia(cut, Date.parse(newest + ":30:00Z")).find((i) => /^eia:PJM-/.test(i.id));
  assert.ok(x, "a PJM signal");
  assert.deepEqual([x.lat, x.lng], [EIA_BA.PJM[0], EIA_BA.PJM[1]]);
});

test("logic-6: grid-news reports count without power words (already classified), by country and nearness; others widened", () => {
  const now = Date.parse("2026-11-20T01:40:00Z");
  const oak = { ...LADWP, id: "grid-pge-oakland-1", source: "doe-odin", region: "California", lat: 37.8, lng: -122.27, opened_at: "2026-11-19T22:00:00Z" };
  const gn = (title, o = {}) => ({ seen_at: "2026-11-19T23:00:00Z", published: "2026-11-19T23:00:00Z", source: "SFGATE", title, url: "https://www.sfgate.com/x", via: "grid-news",
    country: "US", lat: 37.8, lng: -122.27, how: "place", ...o });
  assert.equal(corroborate(oak, { leads: [gn("Winter storm knocks out power in downtown Oakland")], now }).score, 2);
  assert.equal(corroborate(oak, { leads: [gn("Over 5,545 Bay Area Customers Without Power", { lat: 37.77, lng: -122.42 })], now }).score, 2);
  assert.equal(corroborate(oak, { leads: [gn("Outage in Phoenix", { lat: 33.4, lng: -112 })], now }).score, 1);              // same country, far
  assert.equal(corroborate(oak, { leads: [gn("Oakland outage", { country: "GB" })], now }).score, 1);                     // another country
  for (const t of ["Winter storm knocks out power in downtown Oakland", "5,545 customers without power", "Корти: знеструмлення в Києві", "ไฟดับ กรุงเทพ", "停電 東京", "انقطاع الكهرباء في بغداد", "Apagão em São Paulo", "Corte de luz en Lima"])
    assert.ok(POWER_WORDS.test(t), t);
});
