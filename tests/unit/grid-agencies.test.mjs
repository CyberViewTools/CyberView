// Unit tests for the "agencies" grid source file scripts/grid-sources/agencies.mjs (node --test, no dependencies). Fixtures
// in tests/fixtures/grid/agencies/ are real replies saved on 2026-11-21 (sec-layer.json trimmed to the layer's name,
// fields and editingInfo); synthetic variants are built inside the tests and say so. Adapters run through
// scripts/grid.mjs (the real helpers h) with fetch stubbed to serve the fixtures.
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SOURCES as ALL, REGIONS as ALL_REGIONS, ADAPTERS, PLUGIN_ERRORS, OPERATORS, checkItem, track, DEFAULT_CFG, contextItems } from "../../scripts/grid.mjs";
import plugin, { SOURCES, REGIONS, CL_REGIONS, parsePema, parseMdem, parseSecChile, SMALLINT_MAX } from "../../scripts/grid-sources/agencies.mjs";

const FX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "grid", "agencies");
const json = (f) => JSON.parse(readFileSync(join(FX, f), "utf8"));
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
    if (b && typeof b === "object" && b.status) return new Response(b.body || "", { status: b.status });
    return new Response(typeof b === "string" ? b : JSON.stringify(b), { status: 200 });
  };
}
afterEach(() => { globalThis.fetch = realFetch; });

test("agencies: the file loads into grid.mjs with every source, adapter and region", () => {
  assert.deepEqual(PLUGIN_ERRORS.filter((e) => e.startsWith("agencies.mjs")), []);
  for (const k of Object.keys(SOURCES)) {
    assert.equal(ALL[k].file, "agencies.mjs", k);
    assert.ok(OPERATORS.includes(k), `${k} is an operator feed (incidents, series)`);
    assert.equal(typeof plugin.adapters[k], "function", k);
    for (const f of ["name", "country", "url", "page", "terms_url", "terms_ok"]) assert.ok(SOURCES[k][f], `${k}.${f}`);
    assert.ok(["allowed", "silent"].includes(SOURCES[k].terms_ok), k);
    assert.ok(SOURCES[k].hosts.includes(new URL(SOURCES[k].page).host), `${k} page on its own host`);
    assert.ok(!SOURCES[k].keyed && !SOURCES[k].signal, `${k} counts customers`);
  }
  for (const k of Object.keys(REGIONS)) assert.ok(ALL_REGIONS[k], k);
  assert.equal(Object.keys(CL_REGIONS).length, 16);
});

test("PEMA: customers out per Pennsylvania county, quiet counties left out, the agency's update time", () => {
  const d = json("pema.json");
  const items = parsePema(d);
  noErrors(items);
  const out = d.features.filter((f) => f.attributes.CUSTOMERS_OUT > 0);
  assert.equal(d.features.length, 67);
  assert.equal(items.length, out.length);
  assert.equal(items.reduce((s, x) => s + x.customers, 0), out.reduce((s, f) => s + f.attributes.CUSTOMERS_OUT, 0));
  const al = items.find((x) => x.id === "pema-pa:42003");
  assert.deepEqual([al.region, al.customers, al.country, al.planned], ["Pennsylvania", 2500, "US", false]);
  assert.match(al.area, /^Allegheny County \(about 487,381 customers served\)$/);
  assert.ok(Math.abs(al.lat - 40.469) < 0.01 && Math.abs(al.lng + 79.981) < 0.01);
  assert.equal(items.data_at, "2026-11-21T21:32:00Z");
  assert.ok(items.every((x) => x.url === SOURCES["pema-pa"].page && x.cause === ""));
  // synthetic: ArcGIS errors come as HTTP 200 with { error }; a renamed count field; an empty reply
  assert.throws(() => parsePema({ error: { code: 400, message: "Invalid query" } }), (e) => e.code === "bad_shape");
  assert.throws(() => parsePema({ features: [{ attributes: { NAME: "X", OUT: 5 } }] }), (e) => e.code === "bad_shape");
  assert.throws(() => parsePema({ features: [] }), (e) => e.code === "bad_shape");
});

test("MDEM: Maryland's 'outages' are customers out per county; Baltimore City keeps its name", () => {
  const d = json("mdem.json");
  const items = parseMdem(d);
  noErrors(items);
  assert.equal(d.features.length, 24);
  const out = d.features.filter((f) => f.attributes.outages > 0);
  assert.equal(items.length, out.length);
  assert.equal(items.reduce((s, x) => s + x.customers, 0), 113);
  const bc = items.find((x) => x.id === "mdem-md:baltimore-city");
  assert.deepEqual([bc.customers, bc.region, bc.area], [49, "Maryland", "Baltimore City (285,859 customers served)"]);
  assert.ok(items.find((x) => x.id === "mdem-md:anne-arundel").area.startsWith("Anne Arundel County"));
  assert.ok(items.every((x) => x.lat != null && x.lng != null));
  assert.match(items.data_at, /^2026-11-21T21:\d\d:\d\dZ$/);
});

test("SEC Chile via SENAPRED: customers without supply per region, the unmarked zone left out, the 16-bit ceiling named", () => {
  const items = parseSecChile(json("sec.json"), json("sec-layer.json"));
  noErrors(items);
  assert.equal(items.length, 15);   // 16 regions and the "Zona sin demarcar" row; O'Higgins and the zone have 0
  assert.ok(!items.some((x) => /sin demarcar/i.test(x.area)));
  const ll = items.find((x) => x.id === "sec-chile-senapred:10");
  assert.deepEqual([ll.region, ll.area, ll.customers, ll.country], ["Los Lagos", "Región de Los Lagos", 1099, "CL"]);
  assert.equal(items.reduce((s, x) => s + x.customers, 0), 6602);
  assert.equal(items.data_at, "2026-11-21T21:46:24Z");
  assert.ok(items.every((x) => ALL_REGIONS[`sec-chile-senapred|${x.region}`]));
  // synthetic: a region at the field's ceiling, an unknown code, no layer description
  const s = parseSecChile({ features: [
    { attributes: { codregion: 13, NOM_REG: "Región Metropolitana de Santiago", CLIENTES_AFECTADOS: SMALLINT_MAX }, centroid: { x: -70.6, y: -33.6 } },
    { attributes: { codregion: 17, NOM_REG: "Región de Nueva Prueba", CLIENTES_AFECTADOS: 12 } }] }, null);
  noErrors(s);
  assert.deepEqual([s[0].customers, s[0].customers_band], [32767, "32,767 or more"]);
  assert.deepEqual([s[1].region, s[1].lat], ["Nueva Prueba", null]);
  assert.equal(s.data_at, "");
});

test("agencies adapters: the real URLs through grid.mjs; SEC still counts when its layer description fails", async () => {
  serve([[/gis\.penndot\.gov.*FeatureServer\/0\/query/, json("pema.json")], [/PowerOutage_CountiesGeneralDEV_Join\/FeatureServer\/0\/query/, json("mdem.json")],
    [/cortes_de_luz_regiones_chile_sec_new\/FeatureServer\/0\/query/, json("sec.json")], [/cortes_de_luz_regiones_chile_sec_new\/FeatureServer\/0\?f=json$/, json("sec-layer.json")]]);
  const pa = await ADAPTERS["pema-pa"](), md = await ADAPTERS["mdem-md"](), cl = await ADAPTERS["sec-chile-senapred"]();
  for (const x of [pa, md, cl]) noErrors(x);
  assert.deepEqual([pa.length > 0, md.length > 0, cl.length], [true, true, 15]);
  assert.equal(cl.data_at, "2026-11-21T21:46:24Z");
  assert.ok(asked.every((a) => /^https:\/\//.test(a.url) && !Object.keys(a.headers).some((h) => /authorization|cookie/i.test(h))));
  serve([[/cortes_de_luz_regiones_chile_sec_new\/FeatureServer\/0\/query/, json("sec.json")], [/\?f=json$/, { status: 503 }]]);
  const cl2 = await ADAPTERS["sec-chile-senapred"]();
  assert.deepEqual([cl2.length, cl2.data_at], [15, ""]);
});

test("agencies feed the tracker: a big county outage opens one statewide incident; Chile opens per region", () => {
  const big = parsePema({ features: [{ attributes: { NAME: "Philadelphia", FIPS: "42101", CUSTOMERS_OUT: 61000, UPDATE_DATE: Date.parse("2026-11-21T20:00:00Z") }, geometry: { x: -75.13, y: 40.0 } },
    { attributes: { NAME: "Delaware", FIPS: "42045", CUSTOMERS_OUT: 9000, UPDATE_DATE: 1 }, geometry: { x: -75.4, y: 39.9 } }] });
  const cl = parseSecChile({ features: [{ attributes: { codregion: 8, NOM_REG: "Región del Bío-Bío", CLIENTES_AFECTADOS: 7000 }, centroid: { x: -72.4, y: -37.5 } }] }, null);
  const r = track({ open: [], closed: [] }, [...big, ...cl], DEFAULT_CFG, Date.parse("2026-11-21T20:05:00Z"));
  assert.equal(r.open.length, 2);
  const pa = r.open.find((x) => x.source === "pema-pa"), ch = r.open.find((x) => x.source === "sec-chile-senapred");
  assert.deepEqual([pa.region, pa.customers, pa.name], ["Pennsylvania", 70000, "Pennsylvania (PEMA): 70,000 customers without power"]);
  assert.deepEqual([ch.region, ch.customers, ch.country], ["Biobío", 7000, "CL"]);
  const ctx = contextItems(r.open, {}, [...big, ...cl], DEFAULT_CFG);
  assert.ok(Array.isArray(ctx) || (ctx && typeof ctx === "object"));
});
