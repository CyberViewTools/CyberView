// Unit tests for the Canada grid sources (scripts/grid-sources/canada.mjs; node --test, no dependencies).
// Fixtures in tests/fixtures/grid/canada/ are the real responses the scout saved on 2026-11-19 (London Hydro KML with no
// outage, IESO Critical and Day 0 with no advisory, IESO Day 1-34 with one routine "Generation Biasing" notice, AESO's
// "no feed items" placeholder). No live outage or alert was available, so every positive case below is SYNTHETIC: built
// inside the test from a real fixture (the KML's own schema field names, the IESO item's own element layout) and says so.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import plugin, { parseLondonHydro, parseIeso, parseAeso, iesoClass, localToIso, ownLink, xmlText } from "../../scripts/grid-sources/canada.mjs";
import { checkItem, summarize, track, DEFAULT_CFG, SOURCES, REGIONS, ADAPTERS, PLUGIN_ERRORS } from "../../scripts/grid.mjs";

const FX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "grid", "canada");
const txt = (f) => readFileSync(join(FX, f), "utf8");
const noErrors = (items) => items.forEach((x) => assert.deepEqual(checkItem(x), [], x.id));
const KEYS = ["london-hydro", "ieso-critical", "ieso-day0", "ieso-day1-34", "aeso-grid-alert"];

// ---------- the source file ----------
test("canada.mjs loads into grid.mjs: five sources with terms, regions and adapters, no plugin error", () => {
  assert.deepEqual(PLUGIN_ERRORS.filter((e) => e.startsWith("canada.mjs")), []);
  for (const k of KEYS) {
    const s = SOURCES[k];
    assert.ok(s && s.file === "canada.mjs", k);
    assert.equal(s.country, "CA");
    assert.match(s.url, /^https:\/\//); assert.match(s.page, /^https:\/\//); assert.match(s.terms_url, /^https:\/\//);
    assert.ok(s.hosts.includes(new URL(s.page).host), `${k}: page on its own host`);
    assert.ok(["allowed", "silent"].includes(s.terms_ok));
    assert.equal(typeof ADAPTERS[k], "function");
  }
  assert.equal(SOURCES["london-hydro"].customers_served, 169000);
  assert.equal(SOURCES["london-hydro"].terms_ok, "silent");
  for (const k of ["ieso-critical", "ieso-day0", "ieso-day1-34"]) {
    // IESO's Terms of Use: this line on all reproductions, exactly
    assert.equal(SOURCES[k].attribution, "Copyright © 2004-2026 Independent Electricity System Operator, all rights reserved. This information is subject to the Terms of Use set out in the IESO’s website (www.ieso.ca)");
    assert.ok(REGIONS[`${k}|Ontario`]);
  }
  assert.match(SOURCES["aeso-grid-alert"].attribution, /unmodified, non-commercial use\. Copyright © 2016 – 2026 Alberta Electric System Operator\. All rights reserved\.$/);
  assert.ok(REGIONS["aeso-grid-alert|Alberta"] && REGIONS["london-hydro|London"]);
  assert.deepEqual(Object.keys(plugin.adapters).sort(), [...KEYS].sort());
});

// ---------- helpers ----------
test("localToIso: Toronto wall-clock time to UTC; the map's 2001-01-01 'TBD' and junk read as none", () => {
  assert.equal(localToIso("2026-11-19T13:28:00"), "2026-11-19T18:28:00Z");   // EST
  assert.equal(localToIso("2026-07-01 12:00"), "2026-07-01T16:00:00Z");      // EDT
  assert.equal(localToIso("2026/11/19 13:28:00"), "2026-11-19T18:28:00Z");
  assert.equal(localToIso("2026-11-19T13:28:00Z"), "2026-11-19T13:28:00Z");
  assert.equal(localToIso("2001-01-01T00:00:00"), "");
  assert.equal(localToIso("TBD"), "");
  assert.equal(localToIso(""), "");
});

test("ownLink: https on the operator's own host (http upgraded on the same host), else the source page", () => {
  assert.equal(ownLink("ieso-day0", "http://www.ieso.ca/a?b=1&amp;c=2"), "https://www.ieso.ca/a?b=1&c=2");
  assert.equal(ownLink("ieso-day0", "https://iesoqa-public.sharepoint.com/Pages/x.aspx"), SOURCES["ieso-day0"].page);
  assert.equal(ownLink("aeso-grid-alert", "javascript:alert(1)"), SOURCES["aeso-grid-alert"].page);
  assert.equal(xmlText("A &amp; B &#233; <![CDATA[x<y]]>"), "A & B é x<y");
});

// ---------- London Hydro ----------
const T0 = Date.parse("2026-11-20T12:00:00Z");
// SYNTHETIC placemarks in the layout of the real KML's Schema1 (field names from the fixture), placed in its first Folder
const pm = (name, fields, coords, style = "#Style1") => `<Placemark><name>${name}</name><styleUrl>${style}</styleUrl>
<ExtendedData><SchemaData schemaUrl="#Schema1">${Object.entries(fields).map(([k, v]) => `<SimpleData name="${k}">${v}</SimpleData>`).join("")}</SchemaData></ExtendedData>
<Polygon><outerBoundaryIs><LinearRing><coordinates>${coords}</coordinates></LinearRing></outerBoundaryIs></Polygon></Placemark>`;
const withPlacemarks = (...p) => txt("london-hydro.kml").replace(/<Folder>\s*<name \/>/, (m) => `${m}${p.join("\n")}`);   // the real file has CRLF line ends

test("London Hydro (real KML, no outage): parses to no items; a non-KML reply is a bad shape", () => {
  assert.deepEqual(parseLondonHydro(txt("london-hydro.kml")), []);
  assert.throws(() => parseLondonHydro("<html>Not found</html>"), (e) => e.code === "bad_shape");
  assert.throws(() => parseLondonHydro(""), (e) => e.code === "bad_shape");
});

test("London Hydro (synthetic placemarks): one item per placemark, polygon centre, customers, times, planned, restored left out", () => {
  const kml = withPlacemarks(
    pm("1", { ID1: 1, CUSTOMERS_OUT: 340, EVENT_NUMBER: "E-100", OFF_DATETIME: "2026-11-20T06:15:00", ESTIMATED_RESTORE: "2026-11-20T09:00:00",
      STATUS: "ACTIVE", AFFECTEDWARDS: "Ward 5", CAUSE_CODE: "TREE CONTACT" }, "-81.30,42.90,0 -81.20,42.90,0 -81.20,43.00,0 -81.30,43.00,0 -81.30,42.90,0"),
    pm("2", { ID1: 2, EVENT_NUMBER: "E-101", OFF_DATETIME: "2026-11-20T07:00:00", ESTIMATED_RESTORE: "2001-01-01T00:00:00",
      RESTORE_DATETIME: "2026-11-20T10:30:00", AFFECTEDWARDS: "Ward 12", CAUSE_CODE: "17" }, "-81.10,42.95 -81.00,42.95 -81.05,43.05 -81.10,42.95"),
    pm("3", { ID1: 3, OUTAGE_CUSTOMERS: 900, EVENT_NUMBER: "E-102", OFF_DATETIME: "2026-11-20T08:00:00", AFFECTEDWARDS: "Ward 1" }, "-81.2,43.0 -81.1,43.0 -81.1,43.1 -81.2,43.0"),
    pm("4", { ID1: 4, OUTAGE_CUSTOMERS: 900, EVENT_NUMBER: "E-102", OFF_DATETIME: "2026-11-20T08:00:00", AFFECTEDWARDS: "Ward 2" }, "-81.3,43.0 -81.2,43.0 -81.2,43.1 -81.3,43.0"),
    pm("5", { ID1: 5, CUSTOMERS_OUT: 60, EVENT_NUMBER: "P-7", WO: "WO-55", START_DATE: "2026-11-20T09:00:00", END_DATE: "2026-11-20T15:00:00",
      DESCRIPTION: "Planned work" }, "-81.25,42.98 -81.24,42.98 -81.24,42.99 -81.25,42.98"),
    pm("6", { ID1: 6, CUSTOMERS_OUT: 5000, EVENT_NUMBER: "E-099", STATUS: "RESTORED" }, "-81.2,42.9 -81.1,42.9 -81.1,43.0 -81.2,42.9"),
  );
  const items = parseLondonHydro(kml);
  noErrors(items);
  assert.equal(items.length, 5);                                           // the restored one is left out
  const [a, b, c, d, e] = items;
  assert.equal(a.id, "london-hydro:E-100-1");
  assert.deepEqual([a.lat, a.lng], [42.95, -81.25]);                      // average of the four distinct ring points
  assert.equal(a.customers, 340);
  assert.equal(a.region, "London"); assert.equal(a.area, "Ward 5"); assert.equal(a.kind, "outage"); assert.equal(a.level, null);
  assert.equal(a.cause, "TREE CONTACT"); assert.equal(a.planned, false);
  assert.equal(a.started_at, "2026-11-20T11:15:00Z"); assert.equal(a.restore_est, "2026-11-20T14:00:00Z");
  assert.equal(a.url, "https://www.londonhydro.com/outages/outage-map");
  // no customer field at all: customers null (listed, never counted toward a threshold); TBD estimate -> RESTORE_DATETIME
  assert.equal(b.customers, null); assert.equal(b.cause, "cause code 17"); assert.equal(b.restore_est, "2026-11-20T15:30:00Z");
  assert.deepEqual([b.lat, b.lng], [42.983, -81.05]);        // triangle, closing point not repeated
  // one event over two polygons with the same event-level OUTAGE_CUSTOMERS: counted once
  assert.equal(c.customers, 900); assert.equal(d.customers, null);
  assert.equal(e.planned, true); assert.equal(e.started_at, "2026-11-20T14:00:00Z"); assert.equal(e.restore_est, "2026-11-20T20:00:00Z");
  // through the tracker: 900 + 340 unplanned customers < 5,000 opens nothing; null-customer items add nothing
  const s = summarize(items).get("london-hydro|London");
  assert.equal(s.unplanned, 1240); assert.equal(s.planned, 60);
  assert.equal(track({ open: [], closed: [] }, items, DEFAULT_CFG, T0).open.length, 0);
});

// ---------- IESO ----------
test("IESO (real feeds): empty Critical and Day 0 give no item; the routine Day 1-34 notice (Generation Biasing) is left out", () => {
  assert.deepEqual(parseIeso(txt("ieso-critical.xml"), "ieso-critical", T0), []);
  assert.deepEqual(parseIeso(txt("ieso-day0.xml"), "ieso-day0", T0), []);
  assert.deepEqual(parseIeso(txt("ieso-day1-34.xml"), "ieso-day1-34", T0), []);
  assert.throws(() => parseIeso("<html></html>", "ieso-day0", T0), (e) => e.code === "bad_shape");
  assert.throws(() => parseIeso(txt("ieso-day0.xml"), "ieso-other", T0), (e) => e.code === "bad_shape");
});

test("iesoClass: the documented advisory -> kind and level mapping", () => {
  assert.deepEqual(iesoClass("Emergency Operating State declared"), { kind: "grid_emergency", level: 3 });
  assert.deepEqual(iesoClass("Energy Emergency Alert 3"), { kind: "grid_emergency", level: 3 });
  assert.deepEqual(iesoClass("NERC EEA2 in effect"), { kind: "grid_emergency", level: 2 });
  assert.deepEqual(iesoClass("EEA Level 1"), { kind: "grid_emergency", level: 1 });
  assert.deepEqual(iesoClass("Energy Emergency Alert issued"), { kind: "grid_emergency", level: 2 });
  assert.deepEqual(iesoClass("High-Risk Operating State"), { kind: "grid_emergency", level: 2 });
  assert.deepEqual(iesoClass("Rotating load shedding"), { kind: "load_shedding", level: 3 });
  assert.deepEqual(iesoClass("Capacity Margin Alert"), { kind: "supply_warning", level: 1 });
  assert.deepEqual(iesoClass("Severe Weather Alert"), { kind: "supply_warning", level: 1 });
  assert.equal(iesoClass("Generation Biasing"), null);
  assert.equal(iesoClass("Planned outage of circuit L2M"), null);
});

// SYNTHETIC: the real Day 1-34 item with its title (and type) changed; its dates stay Mon 23 Nov 2026 09:00-10:00 EST
const day134 = (title) => txt("ieso-day1-34.xml").replace(/Generation Biasing/g, title);
const asFeed = (title, feed) => day134(title).replace("<title>IESO Day 1-34", `<title>IESO ${feed}`);
const BEFORE = Date.parse("2026-11-20T12:00:00Z"), DURING = Date.parse("2026-11-23T14:30:00Z"), AFTER = Date.parse("2026-11-23T16:00:00Z");

test("IESO (synthetic items): forecasts are supply_warning level 0, current advisories get their level, ended ones drop", () => {
  const [f] = parseIeso(day134("Capacity Margin Alert"), "ieso-day1-34", BEFORE);
  noErrors([f]);
  assert.equal(f.id, "ieso-day1-34:261787");
  assert.equal(f.kind, "supply_warning"); assert.equal(f.level, 0);                       // a forecast: never opens an incident
  assert.equal(f.started_at, "2026-11-23T14:00:00Z"); assert.equal(f.restore_est, "2026-11-23T15:00:00Z");
  assert.equal(f.customers, null); assert.equal(f.region, "Ontario"); assert.equal(f.lat, null);
  assert.match(f.url, /^https:\/\/www\.ieso\.ca\/sector-participants\/rss-feeds\/day-1-to-34-advisory-notices-summary\/advisory-notice\?cid=/);
  // an Emergency Operating State forecast is still level 0 until it starts
  assert.deepEqual(parseIeso(day134("Emergency Operating State"), "ieso-day1-34", BEFORE).map((x) => [x.kind, x.level]), [["supply_warning", 0]]);
  // a Day 1-34 advisory that declares a current condition (started, not ended) gets the mapped level
  assert.deepEqual(parseIeso(day134("Capacity Margin Alert"), "ieso-day1-34", DURING).map((x) => [x.kind, x.level]), [["supply_warning", 1]]);
  // Critical feed: in force -> mapped level; unknown title -> grid_emergency 1; over -> nothing
  assert.deepEqual(parseIeso(asFeed("Energy Emergency Alert 2", "Critical"), "ieso-critical", DURING).map((x) => [x.kind, x.level]), [["grid_emergency", 2]]);
  assert.deepEqual(parseIeso(asFeed("Emergency Operating State", "Critical"), "ieso-critical", DURING).map((x) => [x.kind, x.level]), [["grid_emergency", 3]]);
  assert.deepEqual(parseIeso(asFeed("System notice", "Critical"), "ieso-critical", DURING).map((x) => [x.kind, x.level]), [["grid_emergency", 1]]);
  assert.deepEqual(parseIeso(asFeed("Energy Emergency Alert 2", "Critical"), "ieso-critical", AFTER), []);
  // Day 0: a routine notice is left out, a severe weather alert in force is a level-1 supply warning
  assert.deepEqual(parseIeso(asFeed("Generation Biasing", "Day 0"), "ieso-day0", DURING), []);
  const [w] = parseIeso(asFeed("Severe Weather Alert", "Day 0"), "ieso-day0", DURING);
  assert.equal(w.id, "ieso-day0:261787"); assert.equal(w.kind, "supply_warning"); assert.equal(w.level, 1);
  // a level-2 emergency opens an Ontario incident through the tracker; the forecast does not
  const open = track({ open: [], closed: [] }, parseIeso(asFeed("EEA 2", "Critical"), "ieso-critical", DURING), DEFAULT_CFG, DURING).open;
  assert.equal(open.length, 1); assert.equal(open[0].kind, "grid_emergency"); assert.equal(open[0].level, 2); assert.equal(open[0].lat, 44.5);
  assert.equal(track({ open: [], closed: [] }, [f], DEFAULT_CFG, BEFORE).open.length, 0);
});

test("IESO (synthetic): an undated item older than 24 hours is stale and left out", () => {
  const undated = txt("ieso-day1-34.xml").replace(/Generation Biasing/g, "Severe Weather Alert")
    .replace(/<message:(start|end|issue|update)_date>[^<]*<\/message:\1_date>/g, "").replace("ieso-day1-34", "x");
  const pub = Date.parse("2026-11-18T19:27:00Z");
  assert.equal(parseIeso(undated, "ieso-day0", pub + 3600e3).length, 1);
  assert.deepEqual(parseIeso(undated, "ieso-day0", pub + 30 * 3600e3), []);
});

// ---------- AESO ----------
// SYNTHETIC alerts in the real feed's layout (the placeholder <item> replaced)
const aeso = (...items) => txt("aeso-grid-alert.xml").replace(/<item>[\s\S]*<\/item>/, items.map(([t, d, pub, link]) =>
  `<item><title>${t}</title>${d ? `<description>${d}</description>` : ""}${pub ? `<pubDate>${pub}</pubDate>` : ""}${link ? `<link>${link}</link>` : ""}</item>`).join("\n"));

test("AESO (real feed): the 'no feed items were found' placeholder means no alert", () => {
  assert.deepEqual(parseAeso(txt("aeso-grid-alert.xml"), T0), []);
  assert.throws(() => parseAeso("{}", T0), (e) => e.code === "bad_shape");
});

test("AESO (synthetic alerts): Grid Alert -> grid_emergency 1, EEA n -> level n, ended or stale left out, text unmodified", () => {
  const now = Date.parse("2026-11-20T01:00:00Z");
  const items = parseAeso(aeso(
    ["Grid Alert in effect", "The AESO has issued a Grid Alert.", "Fri, 20 Nov 2026 00:15:00 +0000", "https://www.aeso.ca/grid/alerts/123"],
    ["Energy Emergency Alert 3", "", "Fri, 20 Nov 2026 00:40:00 +0000", "https://evil.example/x"],
    ["Grid Alert has ended", "", "Fri, 20 Nov 2026 00:50:00 +0000", ""],
    ["Grid Alert in effect", "", "Mon, 16 Nov 2026 00:15:00 +0000", ""],
    ["Grid Alert: " + "x".repeat(130), "", "Fri, 20 Nov 2026 00:55:00 +0000", ""],
  ), now);
  noErrors(items);
  assert.equal(items.length, 3);
  const [a, b, c] = items;
  assert.deepEqual([a.kind, a.level, a.area, a.region, a.customers], ["grid_emergency", 1, "Grid Alert in effect", "Alberta", null]);
  assert.equal(a.started_at, "2026-11-20T00:15:00Z");
  assert.equal(a.url, "https://www.aeso.ca/grid/alerts/123");
  assert.deepEqual([b.kind, b.level], ["grid_emergency", 3]);
  assert.equal(b.url, SOURCES["aeso-grid-alert"].page);                                   // a link off AESO's host is not used
  assert.equal(c.area, "");                                                              // too long to keep whole: left out, never cut
  const open = track({ open: [], closed: [] }, items, DEFAULT_CFG, now).open;
  assert.equal(open.length, 1); assert.equal(open[0].level, 3); assert.equal(open[0].region, "Alberta");
});

// ---------- adapters ----------
async function withFetch(fake, fn) {
  const real = globalThis.fetch; globalThis.fetch = fake;
  try { return await fn(); } finally { globalThis.fetch = real; }
}

test("adapters: fetch each feed's own url as text with only the user-agent header, and parse it", async () => {
  const seen = [];
  const body = { "london-hydro": "london-hydro.kml", "ieso-critical": "ieso-critical.xml", "ieso-day0": "ieso-day0.xml",
    "ieso-day1-34": "ieso-day1-34.xml", "aeso-grid-alert": "aeso-grid-alert.xml" };
  for (const k of KEYS) {
    await withFetch(async (url, init) => { seen.push({ k, url: String(url), headers: (init && init.headers) || {} });
      return new Response(txt(body[k]), { status: 200, headers: { "content-type": "text/xml" } }); }, async () => {
      assert.deepEqual(await ADAPTERS[k](), []);
    });
  }
  assert.equal(seen.length, KEYS.length);
  for (const s of seen) {
    assert.equal(s.url, SOURCES[s.k].url);
    assert.deepEqual(Object.keys(s.headers).map((h) => h.toLowerCase()), ["user-agent"]);
    assert.doesNotMatch(s.headers["user-agent"], /Mozilla|Chrome|Safari/);
  }
  // a refusal fails the source (reported by collect), never worked around
  await withFetch(async () => new Response("Forbidden", { status: 403 }), async () => {
    await assert.rejects(ADAPTERS["aeso-grid-alert"]());
  });
});
