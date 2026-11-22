// Unit tests for the context-layer parsers (node --test; no dependencies).
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseIoda, parseGdacsRss, parseGdacsArchive, toMapName } from "../../scripts/context.mjs";

test("IODA: maps names, sorts by score, drops junk", () => {
  const out = parseIoda({ data: [
    { entity: { code: "CD", name: "Democratic Republic Of The Congo" }, scores: { "bgp.median": 5, overall: 5 }, event_cnt: 1 },
    { entity: { code: "TM", name: "Turkmenistan" }, scores: { "bgp.median": 9, "ping-slash24.median": 9, overall: 900 }, event_cnt: 4 },
    { entity: { code: "XX1", name: "bad code" }, scores: { overall: 99 } },
    { entity: { code: "NR", name: "Nauru<script>" }, scores: { "gtr.sarima": 3, overall: 3 } },
    { entity: { code: "ZZ", name: "zero" }, scores: { overall: 0 } },
  ] });
  assert.deepEqual(out.map((x) => x.code), ["TM", "CD", "NR"]);
  assert.deepEqual(out[0].signals, ["bgp", "ping-slash24"]);
  assert.equal(out[1].map_name, "Dem. Rep. Congo");
  assert.equal(out[2].map_name, "");                 // too small for the 110m map: listed, not drawn
  assert.ok(!/[<>]/.test(out[2].name));
  assert.match(out[0].url, /^https:\/\/ioda\.inetintel\.cc\.gatech\.edu\/country\/TM$/);
});

test("IODA: wrong shape throws a coded error", () => {
  assert.throws(() => parseIoda({ nope: 1 }), (e) => e.code === "bad_shape");
});

test("GDACS RSS: keeps orange and red points, drops green and junk, dedupes, builds https link", () => {
  const item = (level, { type = "TC", id = 1, lat = "13.6", long = "86.5", pt = null, title = "Cyclone X", country = "India" } = {}) =>
    `<item><title>${title}</title><gdacs:alertlevel>${level}</gdacs:alertlevel><gdacs:eventtype>${type}</gdacs:eventtype>` +
    `<gdacs:eventid>${id}</gdacs:eventid><gdacs:country>${country}</gdacs:country>` +
    (pt == null ? `<geo:lat>${lat}</geo:lat><geo:long>${long}</geo:long>` : `<georss:point>${pt}</georss:point>`) + `</item>`;
  const xml = `<?xml version="1.0"?><rss version="2.0"><channel>` +
    item("Orange", { type: "DR", id: 1027450, lat: "6.5", long: "39.5", title: "Drought is on going in Burundi &amp; DRC", country: "Burundi &amp; DRC" }) +
    item("Green", { type: "WF", id: 2 }) +                                   // dropped: green
    item("Red", { type: "FL", id: 3, pt: "18.3 -95.1" }) +                   // kept via georss:point
    item("Red", { type: "EQ", id: 4, lat: "500", long: "0" }) +             // dropped: out of range
    item("Orange", { type: "TC", id: "", lat: "1", long: "1" }) +           // dropped: no numeric eventid
    item("Red", { type: "FL", id: 3, pt: "18.3 -95.1" }) +                   // dropped: duplicate eventid
    `</channel></rss>`;
  const out = parseGdacsRss(xml);
  assert.equal(out.length, 2);
  const dr = out.find((x) => x.id === "DR-1027450");
  assert.equal(dr.level, "orange");
  assert.equal(dr.type, "drought");
  assert.equal(dr.name, "Drought is on going in Burundi & DRC");             // entity decoded
  assert.equal(dr.country, "Burundi & DRC");
  assert.equal(dr.lat, 6.5); assert.equal(dr.lng, 39.5);
  assert.equal(dr.url, "https://www.gdacs.org/report.aspx?eventtype=DR&eventid=1027450");
  const fl = out.find((x) => x.id === "FL-3");
  assert.equal(fl.level, "red"); assert.equal(fl.lat, 18.3); assert.equal(fl.lng, -95.1);   // georss:point parsed
});

test("GDACS RSS: wrong shape throws a coded error", () => {
  assert.throws(() => parseGdacsRss("not xml"), (e) => e.code === "bad_shape");
});

test("GDACS ARCHIVE: dates + recency, keeps 30 days, dedupes, freshest first, builds https link", () => {
  const NOW = Date.parse("2026-11-22T12:00:00Z");
  const feat = (level, { type = "TC", id = 1, from = "2026-11-20T00:00:00", to = "2026-11-21T00:00:00", coords = [80.2, 15.8], name = "Cyclone X", country = "India" } = {}) =>
    ({ geometry: { type: "Point", coordinates: coords }, properties: { eventtype: type, eventid: id, alertlevel: level, name, country, fromdate: from, todate: to, url: { report: "https://x/" } } });
  const out = parseGdacsArchive({ features: [
    feat("Orange", { type: "EQ", id: 15731, from: "2026-11-15T00:00:00", to: "2026-11-15T00:00:00", name: "Earthquake in China" }), // 7d ago
    feat("Red", { type: "TC", id: 1001346, from: "2026-11-21T00:00:00", to: "2026-11-21T00:00:00", name: "Cyclone MURASU" }),        // 1d ago
    feat("Orange", { type: "DR", id: 1018332, from: "2026-05-01T00:00:00", to: "2026-11-22T00:00:00", name: "Drought" }),            // ongoing: 0d
    feat("Red", { type: "TC", id: 1001346, from: "2026-11-21T00:00:00" }),                 // dropped: duplicate id
    feat("Green", { type: "WF", id: 2 }),                                                  // dropped: green
    feat("Orange", { type: "FL", id: 500, from: "2026-09-01T00:00:00", to: "2026-09-10T00:00:00" }), // dropped: >30 days old
    { geometry: { type: "Polygon", coordinates: [] }, properties: { eventtype: "FL", eventid: 9, alertlevel: "Red" } }, // dropped: not a point
    feat("Red", { type: "EQ", id: 7, coords: [0, 500] }),                                  // dropped: out of range
  ] }, NOW);
  assert.equal(out.length, 3);                                   // EQ(7d), TC(1d), DR(0d); FL dropped as >30d
  assert.deepEqual(out.map((x) => x.id), ["DR-1018332", "TC-1001346", "EQ-15731"]);   // freshest first
  assert.deepEqual(out.map((x) => x.days), [0, 1, 7]);
  assert.equal(out[1].level, "red");
  assert.equal(out[1].type, "tropical cyclone");
  assert.equal(out[1].url, "https://www.gdacs.org/report.aspx?eventtype=TC&eventid=1001346");
  assert.equal(out[0].type, "drought");                          // ongoing drought kept (active today)
});

test("GDACS ARCHIVE: wrong shape throws a coded error", () => {
  assert.throws(() => parseGdacsArchive({ nope: 1 }), (e) => e.code === "bad_shape");
});

test("map names: aliases resolve only to names on the map", () => {
  assert.equal(toMapName("Russian Federation"), "Russia");
  assert.equal(toMapName("France"), "France");
  assert.equal(toMapName("Atlantis"), "");
});
