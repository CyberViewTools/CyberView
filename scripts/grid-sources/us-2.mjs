// Grid sources, lane "us-2" (2026-11-24): United States grid operators and utilities not connected elsewhere. Loaded by
// scripts/grid.mjs (see the comment above PLUGIN_ERRORS there). Every parser is pure and exported, tested on real replies
// saved on 2026-11-24 in tests/fixtures/grid/us-2/ (tests/unit/grid-us-2.test.mjs). Nothing here sends a key, a cookie or
// a browser header: h.get sends CyberView's own user agent, and a refusal fails the source, which grid.mjs reports.
//
// Each route was checked on 2026-11-24 (terms, robots.txt, a plain request answered with no challenge):
//   spp-conditions  Southwest Power Pool (SPP), the regional transmission organisation for 14 central US states: the
//                   current operating condition of its East and West balancing authority areas, from its public "Current
//                   Grid Conditions" page (HTML). Terms allow reuse with citation: "Permission is implicitly granted to
//                   copy and distribute ... (with appropriate citation)" except commercial publication
//                   (https://www.spp.org/terms-conditions/). robots.txt: none (404). A signal source: levels, no customers.
//   riverside-pu    Riverside Public Utilities (City of Riverside, California): each active electric outage on the
//                   public ArcGIS layer behind the city's outage map (https://www.riversideca.gov/outages/), with its
//                   start, estimated restoration, customers out, cause, planned flag and point. Terms silent (city
//                   website disclaimer, https://riversideca.gov/website-disclaimer-limit-liability); robots.txt disallows
//                   only named paths and bots. Crew and staff fields on the layer are never requested.
// Level convention (as ERCOT, CAISO and NYISO in us.mjs): 0 is shown but never opens an incident; 1 and above opens one.
// Looked at and left out on 2026-11-24 (reasons in the lane's rejected list): PJM, MISO and ISO-NE (already in
// config/data-access.json), Tacoma Power (its copyright notice reads "may not be reproduced in any form"), Lodi Electric
// and Rochester Public Utilities (layers empty at every check, so no real row to test on; Rochester's carries crew names),
// GOHSEP Louisiana's outage layer (a nationwide copy of an unnamed outage API, not the agency's own figures), and many
// utilities whose terms restrict reuse or automated reading.

const str = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const int = (x) => (x === null || x === undefined || x === "" || !isFinite(Number(x)) ? null : Math.max(0, Math.round(Number(x))));
const isoS = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
const slug = (s) => String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "x";
const badShape = (why = "") => Object.assign(new Error(`unexpected shape${why ? `: ${why}` : ""}`), { code: "bad_shape" });
const pt = (g) => (g && isFinite(Number(g.y)) && isFinite(Number(g.x)) && Math.abs(g.y) <= 90 && Math.abs(g.x) <= 180 && !(g.x === 0 && g.y === 0) ? { lat: Math.round(Number(g.y) * 1000) / 1000, lng: Math.round(Number(g.x) * 1000) / 1000 } : { lat: null, lng: null });
const ENT = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", rsquo: "’", lsquo: "‘", ldquo: "“", rdquo: "”", ndash: "–", mdash: "—" };
const text = (h) => String(h || "").replace(/<[^>]*>/g, " ").replace(/&(#\d+|#x[0-9a-f]+|[a-z]+);/gi, (m, e) =>
  e[0] === "#" ? String.fromCodePoint(e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : +e.slice(1)) : (ENT[e.toLowerCase()] ?? m)).replace(/\s+/g, " ").trim();

function zoneOffset(ms, tz) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit",
    day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).formatToParts(new Date(ms)).map((x) => [x.type, x.value]));
  return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour % 24, +p.minute, +p.second) - Math.floor(ms / 1000) * 1000;
}
/** Wall-clock parts in zone tz -> epoch ms (NaN when unreadable). */
function zoned(y, mo, d, hh, mm, tz) {
  const guess = Date.UTC(y, mo - 1, d, hh, mm, 0);
  let t = guess - zoneOffset(guess, tz);
  t = guess - zoneOffset(t, tz);  // second pass settles daylight-saving edges
  return y > 1900 ? t : NaN;
}
/** "7:24 PM" -> [19, 24], or null. */
const clock = (s) => { const m = String(s || "").trim().match(/^(\d{1,2}):(\d{2})\s*([AP])\.?M\.?$/i); if (!m || +m[1] > 12 || +m[2] > 59) return null; return [(+m[1] % 12) + (/p/i.test(m[3]) ? 12 : 0), +m[2]]; };

// ---------- sources ----------
const SPP_PAGE = "https://www.spp.org/markets-operations/current-grid-conditions/";
const RPU_LAYER = "https://services.arcgis.com/Fu2oOWg1Aw7azh41/arcgis/rest/services/ElectricOutageAGOL1/FeatureServer/0";
// only the public outage fields: the layer also carries crew and staff fields, which are never requested
const RPU_FIELDS = "outage_id,outage_active_flag,outage_date,outage_time,customers_out_of_power,outage_cause,outage_etr,outage_planned_flag,outage_ward,outage_location_cross_street";
export const SOURCES = {
  "spp-conditions": { name: "Southwest Power Pool", country: "US", kind: "signal", signal: true,
    url: SPP_PAGE, page: SPP_PAGE, hosts: ["www.spp.org"],
    terms_url: "https://www.spp.org/terms-conditions/", terms_ok: "allowed", customers_served: null,
    attribution: "Source: Southwest Power Pool (SPP), www.spp.org",
    note: "Operating condition of SPP's East and West balancing authority areas (normal, advisories, conservative operations, energy emergency alerts)." },
  "riverside-pu": { name: "Riverside Public Utilities", country: "US",
    url: `${RPU_LAYER}/query?where=${encodeURIComponent("outage_active_flag='True'")}&outFields=${RPU_FIELDS}&returnGeometry=true&outSR=4326&f=json`,
    page: "https://www.riversideca.gov/outages/index.html", hosts: ["www.riversideca.gov", "riversideca.gov"],
    terms_url: "https://riversideca.gov/website-disclaimer-limit-liability", terms_ok: "silent",
    note: "Active electric outages in the City of Riverside, California, from the layer behind the city's own outage map." },
};

// ---------- regions (approximate centres, used only when an item has no point of its own) ----------
export const REGIONS = {
  // SPP East BAA: Kansas, Oklahoma, Nebraska and neighbours; West BAA: Wyoming, western Dakotas, eastern Colorado and Montana
  "spp-conditions|East BAA": { name: "SPP East balancing authority area", lat: 37.5, lng: -97.5 },
  "spp-conditions|West BAA": { name: "SPP West balancing authority area", lat: 43.5, lng: -104.5 },
  "riverside-pu|Riverside": { name: "Riverside, California", lat: 33.953, lng: -117.396 },
};

// ---------- SPP current grid conditions ----------
/** One condition text -> { kind, level }. A condition that only begins later (forecast) is level 0. Never an outage. */
export function sppLevel(cond) {
  const c = String(cond || "");
  if (/\b(begins?|will (take|go into) effect|to take effect|is expected)\b/i.test(c)) return { kind: "supply_warning", level: 0 };
  if (/load shed|rotating (outages|blackouts)|controlled outages/i.test(c)) return { kind: "load_shedding", level: 3 };
  const eea = c.match(/\b(?:EEA|Energy Emergency Alert)\W{0,3}(?:level\s*)?([123])\b/i);
  if (eea) return { kind: "grid_emergency", level: +eea[1] };
  if (/conservative operations/i.test(c)) return { kind: "supply_warning", level: 1 };
  if (/advisory|alert|watch/i.test(c)) return { kind: "supply_warning", level: 0 };   // SPP: advisories "are still considered normal operating conditions"
  if (/normal/i.test(c)) return { kind: "grid_emergency", level: 0 };
  return { kind: "supply_warning", level: null };
}
/** The page's status headings: "<h3>East BAA: Currently under Baseline Normal Operating Conditions; Resource Advisory begins
 *  Tues., Nov. 24, ...</h3>" and "<h3>West BAA: ...</h3>". The part before the first ";" is the condition now; the rest
 *  (an upcoming advisory) travels in cause, word for word. One item per BAA; no customers (a signal). */
export function parseSpp(html) {
  const out = [];
  for (const m of String(html || "").matchAll(/<h3[^>]*>([\s\S]*?)<\/h3>/gi)) {
    const t = text(m[1]);
    const b = t.match(/^(East|West)\s+BAA\s*:\s*(.+)$/i);
    if (!b) continue;
    const baa = `${b[1][0].toUpperCase()}${b[1].slice(1).toLowerCase()} BAA`;
    if (out.some((x) => x.region === baa)) continue;
    const now = b[2].split(";")[0].replace(/^currently under\s+/i, "").trim();
    const lv = sppLevel(now);
    const r = REGIONS[`spp-conditions|${baa}`];
    out.push({ id: `spp-conditions:${slug(b[1])}`, source: "spp-conditions", country: "US", region: baa,
      area: str(`SPP ${baa}: ${now}`, 120), lat: r.lat, lng: r.lng, customers: null, kind: lv.kind, planned: false,
      cause: str(b[2], 120), level: lv.level, started_at: "", restore_est: "", url: SPP_PAGE });
  }
  if (!out.length) throw badShape("spp: no East/West BAA status headings");
  return out;
}

// ---------- Riverside Public Utilities ----------
/** "11/19/2026" + "7:24 PM" (Pacific time) -> epoch ms, or NaN. */
const rpuMs = (date, time) => { const d = String(date || "").match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/), c = clock(time);
  return d && c ? zoned(+d[3], +d[1], +d[2], c[0], c[1], "America/Los_Angeles") : NaN; };
/** ArcGIS reply { features: [{ attributes: { outage_id, outage_active_flag "True"|"False", outage_date "11/19/2026",
 *  outage_time "7:24 PM", customers_out_of_power, outage_cause, outage_etr "4:24 AM" (a time of day only),
 *  outage_planned_flag, outage_ward, outage_location_cross_street }, geometry: { x, y } }] }. The source query asks only
 *  for active outages; closed ones are dropped here too unless includeClosed (tests). The estimated restoration is a time
 *  of day with no date: it is placed on the outage's own date, or the next day when that time is not after the start. */
export function parseRiverside(d, { includeClosed = false } = {}) {
  if (d && d.error) throw badShape(`riverside: ${str(d.error.message || d.error.code, 80)}`);
  if (!d || !Array.isArray(d.features)) throw badShape("riverside: no features");
  const out = [];
  for (const f of d.features) {
    const a = f && f.attributes; if (!a) continue;
    if (!includeClosed && String(a.outage_active_flag).toLowerCase() !== "true") continue;
    const id = str(a.outage_id, 40); if (!id) continue;
    const start = rpuMs(a.outage_date, a.outage_time);
    let etr = rpuMs(a.outage_date, a.outage_etr);
    if (isFinite(etr) && isFinite(start) && etr <= start) etr += 86400e3;
    const p = pt(f.geometry);
    const where = [str(a.outage_location_cross_street, 70), str(a.outage_ward, 40)].filter(Boolean).join(", ");
    out.push({ id: `riverside-pu:${id}`, source: "riverside-pu", country: "US", region: "Riverside",
      area: str(where ? `${where}, Riverside` : "Riverside", 120), lat: p.lat, lng: p.lng,
      customers: int(a.customers_out_of_power), kind: "outage", planned: String(a.outage_planned_flag).toLowerCase() === "true",
      cause: str(a.outage_cause, 120), level: null, started_at: isFinite(start) ? isoS(start) : "",
      restore_est: isFinite(etr) ? isoS(etr) : "", url: SOURCES["riverside-pu"].page });
  }
  return out;
}

// ---------- adapters ----------
export const ADAPTERS = {
  "spp-conditions": async (h) => parseSpp(await h.get(SOURCES["spp-conditions"].url, { as: "text", timeoutMs: 30000 })),
  "riverside-pu": async (h) => parseRiverside(await h.get(SOURCES["riverside-pu"].url, { timeoutMs: 30000 })),
};

export default {
  sources: SOURCES,
  regions: REGIONS,
  adapters: Object.fromEntries(Object.entries(ADAPTERS).map(([k, fn]) => [k, async (h) => (await fn(h)).map((x) => h.item(x))])),
};
