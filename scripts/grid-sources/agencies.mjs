// Grid sources, lane "agencies" (2026-11-21): power outage counts that government emergency agencies publish for a whole
// state or country, gathered from every utility there. Loaded by scripts/grid.mjs (see the comment above PLUGIN_ERRORS
// there). Every parser is pure and exported, tested on real replies saved on 2026-11-21 in tests/fixtures/grid/agencies/
// (tests/unit/grid-agencies.test.mjs). Nothing here sends a key, a cookie or a browser header: h.get sends CyberView's own
// user agent, and a refusal fails the source, which grid.mjs reports. Figures are passed on as the agency states them
// (customers, that is accounts or meters, never converted to people).
//
// Each route was checked on 2026-11-21: public ArcGIS layers shared by the agency itself, answered a plain request with
// no key, cookie, challenge or login; robots.txt does not disallow the path (gis.penndot.gov and services*.arcgis.com
// publish none; mdem.maryland.gov disallows only SharePoint system folders).
//   pema-pa       Pennsylvania Emergency Management Agency (PEMA), layer hosted by PennDOT: customers out per county, all
//                 electric utilities in the state, with the agency's update time. Terms silent (pa.gov privacy policy and
//                 disclaimers: "intended to allow for access to public information"; the layer carries no licence).
//   mdem-md       Maryland Department of Emergency Management (MDEM): customers out ("outages") and customers served per
//                 county, from the utilities' reports to the state, with the time stamp of each update. The layer's licence
//                 is a disclaimer only ("provided as is"); terms silent.
//   sec-chile-senapred  Chile: customers without supply per region, the Superintendencia de Electricidad y Combustibles'
//                 (SEC) figures as published by SENAPRED (the national disaster prevention and response service) in a
//                 public ArcGIS layer (no licence stated: silent). SEC's own app could not be reached from CyberView
//                 (config/data-access.json, sec-chile). The layer has no time field: the data time is the layer's own
//                 dataLastEditDate (a second, small request). Its count field is a 16-bit integer: a region showing 32,767
//                 is "32,767 or more" (customers_band), never a measured figure.
// Overlap: the DOE/ORNL ODIN aggregator (us.mjs) also reports some utilities in Pennsylvania and Maryland; ODIN's rows in
// those two states are dropped there (ODIN_STATE_AGENCIES) so one outage is never counted twice.
// Looked at and left out (2026-11-21), with the reason:
//   Cal OES statewide power outages (California): its licence limits use to "Cal OES personnel and supporting partners"
//     (config/data-access.json, caloes-power-outages); NJ OEM outage dashboard: no data time, so a frozen feed could not be
//     told from a quiet one; Oregon OEM: a copy of poweroutage.us, which blocks automated readers; Powerco (New Zealand)
//     ArcGIS outages: no customer counts (one record per outage).
import { US_STATES } from "./lib-us-states.mjs";

const str = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const int = (x) => (x === null || x === undefined || x === "" || !isFinite(Number(x)) ? null : Math.max(0, Math.round(Number(x))));
const isoS = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
const slug = (s) => String(s || "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "x";
const badShape = (why = "") => Object.assign(new Error(`unexpected shape${why ? `: ${why}` : ""}`), { code: "bad_shape" });
// the agency's own data time travels with the items (scripts/grid.mjs collect marks a source stale when it is old)
export const stamp = (arr, at) => Object.defineProperty(arr, "data_at", { value: at || "", enumerable: false, configurable: true });
const pt = (g) => (g && isFinite(Number(g.y)) && isFinite(Number(g.x)) && Math.abs(g.y) <= 90 && Math.abs(g.x) <= 180 ? { lat: Number(g.y), lng: Number(g.x) } : { lat: null, lng: null });
/** Newest epoch-ms value -> ISO, or "" (ArcGIS dates are epoch milliseconds). */
const newest = (vals) => { const t = Math.max(...vals.map(Number).filter((x) => isFinite(x) && x > 0)); return isFinite(t) ? isoS(t) : ""; };
/** An ArcGIS query reply: { features: [...] }. ArcGIS answers errors with HTTP 200 and { error }, which is a bad shape. */
function features(d, what) {
  if (d && d.error) throw badShape(`${what}: ${str(d.error.message || d.error.code, 80)}`);
  if (!d || !Array.isArray(d.features)) throw badShape(what);
  const rows = d.features.filter((f) => f && f.attributes);
  if (!rows.length) throw badShape(`${what}: no rows`);   // every layer here lists every county or region, quiet or not
  return rows;
}

// ---------- sources ----------
const PEMA_LAYER = "https://gis.penndot.gov/arcgis/rest/services/poweroutages/papoweroutages/FeatureServer/0";
const MDEM_LAYER = "https://services.arcgis.com/njFNhDsUCentVYJW/arcgis/rest/services/PowerOutage_CountiesGeneralDEV_Join/FeatureServer/0";
const SEC_LAYER = "https://services5.arcgis.com/i7S5PSnIJAUcWvSE/arcgis/rest/services/cortes_de_luz_regiones_chile_sec_new/FeatureServer/0";
export const SOURCES = {
  "pema-pa": { name: "Pennsylvania (PEMA)", country: "US", kind: "outages", aggregator: true,
    url: `${PEMA_LAYER}/query?where=1%3D1&outFields=NAME,FIPS,CUSTOMERS_OUT,EST_CUST_SERVED,UPDATE_DATE&returnGeometry=true&outSR=4326&f=json`,
    page: "https://www.arcgis.com/apps/dashboards/0ad5f6f9a213444d8ba2f2e74e7ffc7d", hosts: ["www.arcgis.com", "gis.penndot.gov", "www.pa.gov"],
    terms_url: "https://www.pa.gov/privacy-policy", terms_ok: "silent", customers_served: 5122821,  // sum of EST_CUST_SERVED, 2026-11-21
    note: "Statewide count from every electric utility in Pennsylvania, published by the state's emergency management agency; ODIN's Pennsylvania rows are dropped to avoid double counting." },
  "mdem-md": { name: "Maryland (MDEM)", country: "US", kind: "outages", aggregator: true,
    url: `${MDEM_LAYER}/query?where=1%3D1&outFields=COUNTY,outages,customers,dt_stamp&returnGeometry=false&returnCentroid=true&outSR=4326&f=json`,
    page: "https://mdem.maryland.gov/Pages/Power-Outages-Data.aspx", hosts: ["mdem.maryland.gov", "services.arcgis.com"],
    terms_url: "https://mdem.maryland.gov/Pages/Power-Outages-Data.aspx", terms_ok: "silent", customers_served: 2704926,  // sum of `customers`, 2026-11-21
    note: "Statewide count from Maryland's electric utilities, published by the state's emergency management department; ODIN's Maryland rows are dropped to avoid double counting." },
  "sec-chile-senapred": { name: "SEC Chile (via SENAPRED)", country: "CL", kind: "outages", aggregator: true,
    url: `${SEC_LAYER}/query?where=1%3D1&outFields=codregion,NOM_REG,CLIENTES_AFECTADOS&returnGeometry=false&returnCentroid=true&outSR=4326&f=json`,
    meta_url: `${SEC_LAYER}?f=json`,
    page: "https://www.arcgis.com/home/item.html?id=6cfc6313f3214b7d953f38fe5857bd4d", hosts: ["www.arcgis.com", "services5.arcgis.com"],
    terms_url: "https://www.arcgis.com/home/item.html?id=6cfc6313f3214b7d953f38fe5857bd4d", terms_ok: "silent", customers_served: null,
    note: "Customers without supply per region: the figures of Chile's electricity regulator (SEC) as published by SENAPRED." },
};

// ---------- regions (approximate centres, used only when an item has no point of its own) ----------
const state = (abbr) => Object.values(US_STATES).find((s) => s[0] === abbr);
// Chile's regions by their official code (codregion): English-friendly name and the centre SENAPRED's layer returns
export const CL_REGIONS = {
  15: ["Arica y Parinacota", -18.5, -69.63], 1: ["Tarapacá", -20.22, -69.39], 2: ["Antofagasta", -23.55, -69.12], 3: ["Atacama", -27.41, -69.91],
  4: ["Coquimbo", -30.63, -70.86], 5: ["Valparaíso", -32.74, -71.36], 13: ["Santiago Metropolitan", -33.61, -70.63],
  6: ["O'Higgins", -34.44, -71.05], 7: ["Maule", -35.62, -71.45], 16: ["Ñuble", -36.65, -71.97], 8: ["Biobío", -37.5, -72.4],
  9: ["La Araucanía", -38.65, -72.27], 14: ["Los Ríos", -40.01, -72.57], 10: ["Los Lagos", -42.07, -72.9], 11: ["Aysén", -46.47, -73.25],
  12: ["Magallanes", -52.55, -71.81],
};
export const REGIONS = {
  "pema-pa|Pennsylvania": { name: "Pennsylvania", lat: state("PA")[2], lng: state("PA")[3] },
  "mdem-md|Maryland": { name: "Maryland", lat: state("MD")[2], lng: state("MD")[3] },
  ...Object.fromEntries(Object.values(CL_REGIONS).map(([name, lat, lng]) => [`sec-chile-senapred|${name}`, { name, lat, lng }])),
};

// ---------- Pennsylvania (PEMA) ----------
// Reply: { features: [{ attributes: { NAME (county), FIPS (5 digits), CUSTOMERS_OUT, EST_CUST_SERVED, UPDATE_DATE (ms) },
// geometry: { x, y } (county point, WGS84) }] }, all 67 counties every time. Counties with nobody out are left out.
export function parsePema(d) {
  const rows = features(d, "pema");
  if (!rows.some((f) => int(f.attributes.CUSTOMERS_OUT) !== null)) throw badShape("pema: no row has CUSTOMERS_OUT");
  const out = [];
  for (const f of rows) {
    const a = f.attributes, c = int(a.CUSTOMERS_OUT);
    if (!c) continue;
    const county = str(a.NAME, 40), served = int(a.EST_CUST_SERVED);
    out.push({ source: "pema-pa", id: `pema-pa:${str(a.FIPS, 8) || slug(county)}`, country: "US", region: "Pennsylvania",
      area: str(`${county} County${served ? ` (about ${served.toLocaleString("en-US")} customers served)` : ""}`, 120), ...pt(f.geometry),
      customers: c, kind: "outage", planned: false, cause: "", level: null, started_at: "", restore_est: "", url: SOURCES["pema-pa"].page });
  }
  return stamp(out, newest(rows.map((f) => f.attributes.UPDATE_DATE)));
}

// ---------- Maryland (MDEM) ----------
// Reply: { features: [{ attributes: { COUNTY, outages (customers out), customers (customers served), dt_stamp (ms) },
// centroid: { x, y } }] }, all 24 counties (Baltimore City included) every time. "outages" counts customers: Baltimore
// City's 49 of 285,859 is the 0.0171 the layer gives as percent_out.
export function parseMdem(d) {
  const rows = features(d, "mdem");
  if (!rows.some((f) => int(f.attributes.outages) !== null)) throw badShape("mdem: no row has outages");
  const out = [];
  for (const f of rows) {
    const a = f.attributes, c = int(a.outages);
    if (!c) continue;
    const county = str(a.COUNTY, 40), served = int(a.customers);
    const name = /city$/i.test(county) ? county : `${county} County`;
    out.push({ source: "mdem-md", id: `mdem-md:${slug(county)}`, country: "US", region: "Maryland",
      area: str(`${name}${served ? ` (${served.toLocaleString("en-US")} customers served)` : ""}`, 120), ...pt(f.centroid),
      customers: c, kind: "outage", planned: false, cause: "", level: null, started_at: "", restore_est: "", url: SOURCES["mdem-md"].page });
  }
  return stamp(out, newest(rows.map((f) => f.attributes.dt_stamp)));
}

// ---------- Chile (SEC via SENAPRED) ----------
// Reply: { features: [{ attributes: { codregion, NOM_REG, CLIENTES_AFECTADOS }, centroid: { x, y } }] }: the 16 regions and
// a "Zona sin demarcar" row (code 0, left out). meta = the layer's own description ({ editingInfo: { dataLastEditDate } }).
export const SMALLINT_MAX = 32767;
export function parseSecChile(d, meta) {
  const rows = features(d, "sec-chile");
  if (!rows.some((f) => int(f.attributes.CLIENTES_AFECTADOS) !== null)) throw badShape("sec-chile: no row has CLIENTES_AFECTADOS");
  const out = [];
  for (const f of rows) {
    const a = f.attributes, code = int(a.codregion), c = int(a.CLIENTES_AFECTADOS);
    if (!code || !c) continue;
    const known = CL_REGIONS[code], full = str(a.NOM_REG, 80);
    const region = known ? known[0] : str(full.replace(/^Regi[oó]n\s+(de\s+los\s+|de\s+la\s+|del\s+|de\s+)?/i, ""), 60);
    if (!region) continue;
    out.push({ source: "sec-chile-senapred", id: `sec-chile-senapred:${code}`, country: "CL", region,
      area: str(full || region, 120), ...pt(f.centroid), customers: c, kind: "outage", planned: false, cause: "", level: null,
      started_at: "", restore_est: "", url: SOURCES["sec-chile-senapred"].page,
      ...(c >= SMALLINT_MAX ? { customers_band: `${SMALLINT_MAX.toLocaleString("en-US")} or more` } : {}) });
  }
  const e = meta && meta.editingInfo;
  return stamp(out, e ? newest([e.dataLastEditDate, e.lastEditDate]) : "");
}

// ---------- adapters ----------
export const ADAPTERS = {
  "pema-pa": async (h) => parsePema(await h.get(h.SOURCES["pema-pa"].url, { timeoutMs: 40000 })),
  "mdem-md": async (h) => parseMdem(await h.get(h.SOURCES["mdem-md"].url, { timeoutMs: 40000 })),
  // the counts, then the layer's own edit time (the counts have no time field); without the time the counts still count
  "sec-chile-senapred": async (h) => {
    const d = await h.get(h.SOURCES["sec-chile-senapred"].url, { timeoutMs: 40000 });
    let meta = null;
    try { meta = await h.get(h.SOURCES["sec-chile-senapred"].meta_url, { timeoutMs: 20000, retries: 1 }); } catch { meta = null; }
    return parseSecChile(d, meta);
  },
};

export default {
  sources: SOURCES,
  regions: REGIONS,
  adapters: Object.fromEntries(Object.entries(ADAPTERS).map(([k, fn]) => [k, async (h) => { const got = await fn(h); return stamp(got.map((x) => h.item(x)), got.data_at); }])),
};
