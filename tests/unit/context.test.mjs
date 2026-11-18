// Unit tests for the context-layer parsers (node --test; no dependencies).
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseIoda, parseGdacs, toMapName } from "../../scripts/context.mjs";

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

test("GDACS: keeps current orange and red points only, cleans links", () => {
  const f = (alertlevel, extra = {}, geometry = { type: "Point", coordinates: [86.5, 13.6] }) =>
    ({ geometry, properties: { eventtype: "TC", eventid: 1, alertlevel, name: "Cyclone X", country: "India", url: { report: "https://www.gdacs.org/report.aspx?eventid=1" }, ...extra } });
  const out = parseGdacs({ features: [
    f("Orange"), f("Green"), f("Red", { iscurrent: "false" }), f("Red", { url: { report: "javascript:alert(1)" } }),
    f("Red", {}, { type: "Polygon", coordinates: [] }), f("Red", {}, { type: "Point", coordinates: [500, 0] }),
  ] });
  assert.equal(out.length, 2);
  assert.equal(out[0].level, "orange");
  assert.equal(out[0].type, "tropical cyclone");
  assert.equal(out[1].url, "");
});

test("map names: aliases resolve only to names on the map", () => {
  assert.equal(toMapName("Russian Federation"), "Russia");
  assert.equal(toMapName("France"), "France");
  assert.equal(toMapName("Atlantis"), "");
});
