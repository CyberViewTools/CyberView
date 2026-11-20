// Grid sources, lane "world": Australia (Endeavour Energy, TasNetworks), Taiwan (Taipower supply light), Ghana (ECG notices),
// Argentina (ENRE for Edenor and Edesur) and Brazil (ONS load interruptions). Loaded by scripts/grid.mjs (see the comment
// above PLUGIN_ERRORS there). Every parser is pure and exported, tested on real saved replies in tests/fixtures/grid/world/
// (tests/unit/grid-world.test.mjs). Parsers return complete Items (the grid contract's shape); the adapters still pass
// each one through h.item, which cleans it again. Times in local wall-clock form go through zonedToIso (h.zonedToIso at run
// time, the same function imported from scripts/grid.mjs in the tests). Nothing here sends a key, a cookie or a browser
// header: h.get sends CyberView's own user agent, and a refusal fails the source, which grid.mjs reports.
//
// Sources the world scout recorded as "connect" (swarm/grid-sources-20261119/out/world.json), with what each one's terms say:
//   endeavour-energy  terms silent (no terms page, copyright line only), robots allow; JSON with polygons and customers
//   tasnetworks       terms silent (disclaimer: copyright only), robots allow; JSON with WKT polygons and customers
//   taipower-supply   Open Government Data License, Taiwan v1.0 (data.gov.tw dataset 162595): any use with attribution
//   ecg-ghana         terms silent (no terms page), robots allow; one Joomla RSS per ECG region, no customer counts
//   enre-edenor/-edesur  the regulator's feed; national portal content is CC BY 4.0; robots allow
//   ons-interrupcao-carga  CC-BY with credit to ONS and a note of the changes made (Aviso Legal on dados.ons.org.br)

// ---------- local helpers (same rules as scripts/grid.mjs item(), so h.item leaves the result unchanged) ----------
const str = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const round3 = (x) => Math.round(x * 1000) / 1000;
const okLat = (x) => typeof x === "number" && isFinite(x) && Math.abs(x) <= 90;
const okLng = (x) => typeof x === "number" && isFinite(x) && Math.abs(x) <= 180;
const intOrNull = (x) => (x === null || x === undefined || x === "" || !isFinite(Number(x)) ? null : Math.max(0, Math.round(Number(x))));
const isoS = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
const isoOf = (s) => { const t = Date.parse(s || ""); return isFinite(t) ? isoS(t) : ""; };
const slug = (s, n = 50) => String(s || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, n).replace(/-$/, "") || "x";
const fmt = (n) => Number(n || 0).toLocaleString("en-US");
const badShape = (why = "") => Object.assign(new Error(`unexpected shape${why ? `: ${why}` : ""}`), { code: "bad_shape" });
const ownHost = (key, u) => {
  const s = String(u || "");
  if (!/^https:\/\/[^\s"'<>\\]+$/.test(s) || s.length > 300) return "";
  try { return SOURCES[key].hosts.includes(new URL(s).host) ? s : ""; } catch { return ""; }
};

/** A complete Item (swarm/handoff/grid-contract.md). */
function mk(o) {
  const src = o.source, has = okLat(o.lat) && okLng(o.lng);
  return {
    id: str(o.id, 120), source: src, country: o.country || SOURCES[src].country, region: str(o.region, 60), area: str(o.area, 120),
    lat: has ? round3(o.lat) : null, lng: has ? round3(o.lng) : null, customers: intOrNull(o.customers), kind: o.kind || "outage",
    planned: !!o.planned, cause: str(o.cause, 120), level: o.level == null ? null : intOrNull(o.level),
    started_at: o.started_at || "", restore_est: o.restore_est || "", url: ownHost(src, o.url) || SOURCES[src].page,
  };
}

/** Mean of a ring's points ([[lng, lat], ...]); the closing point (a repeat of the first) is left out. */
export function ringCentre(ring) {
  const pts = (Array.isArray(ring) ? ring : []).map((p) => (Array.isArray(p) ? [Number(p[0]), Number(p[1])] : null))
    .filter((p) => p && okLng(p[0]) && okLat(p[1]));
  if (pts.length > 1 && pts[0][0] === pts[pts.length - 1][0] && pts[0][1] === pts[pts.length - 1][1]) pts.pop();
  if (!pts.length) return { lat: null, lng: null };
  return { lng: pts.reduce((a, p) => a + p[0], 0) / pts.length, lat: pts.reduce((a, p) => a + p[1], 0) / pts.length };
}
/** WKT POLYGON / MULTIPOLYGON -> the mean of the points of its outer ring(s); POINT -> that point. */
export function wktCentre(wkt) {
  const s = String(wkt || "").slice(0, 200000);
  const pair = (t) => t.trim().split(/\s+/).map(Number);
  if (/^\s*POINT\s*\(/i.test(s)) { const m = s.match(/\(([^()]+)\)/); if (!m) return { lat: null, lng: null }; const [lng, lat] = pair(m[1]); return okLat(lat) && okLng(lng) ? { lat, lng } : { lat: null, lng: null }; }
  if (!/^\s*(MULTI)?POLYGON\s*\(/i.test(s)) return { lat: null, lng: null };
  // outer rings are the groups right after "((" (holes follow "), (" inside the same polygon)
  const rings = [...s.matchAll(/\(\(\s*([^()]+)\)/g)].map((m) => m[1].split(",").map(pair));
  return ringCentre(rings.flat());
}

// ---------- sources ----------
export const SOURCES = {
  "endeavour-energy": { name: "Endeavour Energy", country: "AU", kind: "outages",
    url: "https://www.endeavourenergy.com.au/api/public/outage-list?filterFutureMaintenance=false",
    page: "https://www.endeavourenergy.com.au/power-outages/outage-map", hosts: ["www.endeavourenergy.com.au"],
    terms_url: "https://www.endeavourenergy.com.au/privacy-policy", terms_ok: "silent", customers_served: 1200000 },  // about-us: "1.2 million customers"
  tasnetworks: { name: "TasNetworks", country: "AU", kind: "outages", url: "https://www.tasnetworks.com.au/api/odata/GetPowerOutages",
    page: "https://www.tasnetworks.com.au/outages", hosts: ["www.tasnetworks.com.au"],
    terms_url: "https://www.tasnetworks.com.au/disclaimer", terms_ok: "silent", customers_served: 300000 },
  "taipower-supply": { name: "Taiwan Power Company", country: "TW", kind: "signal",
    url: "https://service.taipower.com.tw/data/opendata/apply/file/d006020/001.json",
    page: "https://data.gov.tw/dataset/162595", hosts: ["service.taipower.com.tw", "www.taipower.com.tw", "data.gov.tw"],
    terms_url: "https://data.gov.tw/license", terms_ok: "allowed", customers_served: null,
    // the licence's Exhibit (attribution statement): provider, year, dataset name, then the fixed English sentence
    attribution: "Taiwan Power Company 2026, 台灣電力公司今日系統供需狀況 (Taipower today's system supply and demand). The Open Data is made available to the public under the Open Government Data License, User can make use of it when complying to the condition and obligation of its terms. Open Government Data License: https://data.gov.tw/license" },
  "ecg-ghana": { name: "Electricity Company of Ghana", country: "GH", kind: "signal",
    url: "https://www.ecg.com.gh/index.php/en/services/ecg-status/current-system-status/current-status-accra-west?format=feed&type=rss",
    page: "https://www.ecg.com.gh/index.php/en/services/ecg-status/current-system-status", hosts: ["www.ecg.com.gh"],
    terms_url: "https://www.ecg.com.gh/", terms_ok: "silent", customers_served: null },
  "enre-edenor": { name: "ENRE (Edenor area)", country: "AR", kind: "outages", url: "https://www.enre.gov.ar/paginacorte/js/data_EDN.js",
    page: "https://www.enre.gov.ar/paginacorte/tabla_cortes_edenor.html", hosts: ["www.enre.gov.ar"],
    terms_url: "https://www.argentina.gob.ar/terminos-y-condiciones", terms_ok: "silent", customers_served: 3506094 },
  "enre-edesur": { name: "ENRE (Edesur area)", country: "AR", kind: "outages", url: "https://www.enre.gov.ar/paginacorte/js/data_EDS.js",
    page: "https://www.enre.gov.ar/paginacorte/tabla_cortes_edesur.html", hosts: ["www.enre.gov.ar"],
    terms_url: "https://www.argentina.gob.ar/terminos-y-condiciones", terms_ok: "silent", customers_served: 2826884 },
  "ons-interrupcao-carga": { name: "ONS (Brazil grid operator)", country: "BR", kind: "signal",
    url: "https://ons-aws-prod-opendata.s3.amazonaws.com/dataset/interrupcao_carga/INTERRUPCAO_CARGA.csv",
    page: "https://dados.ons.org.br/dataset/interrupcao_carga", hosts: ["dados.ons.org.br", "ons-aws-prod-opendata.s3.amazonaws.com"],
    terms_url: "https://dados.ons.org.br/dataset/interrupcao_carga", terms_ok: "allowed", customers_served: null,
    attribution: "Source: ONS - Operador Nacional do Sistema Elétrico, dataset Interrupção de Carga (CC-BY). Changes: CyberView keeps only the last 7 days and restates each row as MW of load interrupted per state." },
};

// ---------- regions (approximate centres, used only when items carry no point of their own) ----------
const ECG_REGIONS = {  // slug in the feed URL -> name and approximate centre of the ECG operational region
  "accra-east": ["Accra East", 5.62, -0.17], "accra-west": ["Accra West", 5.58, -0.27], ashanti: ["Ashanti", 6.69, -1.62],
  central: ["Central", 5.25, -1.3], eastern: ["Eastern", 6.2, -0.4], tema: ["Tema", 5.67, 0.0], volta: ["Volta", 6.6, 0.47],
  western: ["Western", 5.0, -1.9],
};
export const BR_STATES = {
  AC: ["Acre", -9.0, -70.5], AL: ["Alagoas", -9.6, -36.6], AP: ["Amapá", 1.4, -51.8], AM: ["Amazonas", -4.0, -63.0],
  BA: ["Bahia", -12.5, -41.7], CE: ["Ceará", -5.2, -39.5], DF: ["Distrito Federal", -15.8, -47.9], ES: ["Espírito Santo", -19.6, -40.6],
  GO: ["Goiás", -16.0, -49.6], MA: ["Maranhão", -5.0, -45.3], MT: ["Mato Grosso", -13.0, -56.0], MS: ["Mato Grosso do Sul", -20.5, -54.6],
  MG: ["Minas Gerais", -18.5, -44.6], PA: ["Pará", -4.0, -52.5], PB: ["Paraíba", -7.1, -36.8], PR: ["Paraná", -24.6, -51.6],
  PE: ["Pernambuco", -8.4, -37.9], PI: ["Piauí", -7.7, -42.7], RJ: ["Rio de Janeiro", -22.3, -42.7], RN: ["Rio Grande do Norte", -5.8, -36.6],
  RS: ["Rio Grande do Sul", -29.8, -53.2], RO: ["Rondônia", -10.9, -62.8], RR: ["Roraima", 2.0, -61.4], SC: ["Santa Catarina", -27.3, -50.5],
  SP: ["São Paulo", -22.2, -48.7], SE: ["Sergipe", -10.6, -37.4], TO: ["Tocantins", -10.2, -48.3],
};
const EE_REGION = "Endeavour Energy area";
export const REGIONS = {
  [`endeavour-energy|${EE_REGION}`]: { name: "Western Sydney, Illawarra and South Coast (NSW)", lat: -34.1, lng: 150.6 },
  "tasnetworks|Tasmania": { name: "Tasmania", lat: -42.0, lng: 146.6 },
  "taipower-supply|Taiwan": { name: "Taiwan", lat: 23.7, lng: 121.0 },
  "enre-edenor|Buenos Aires": { name: "Buenos Aires (Edenor area)", lat: -34.55, lng: -58.65 },
  "enre-edesur|Buenos Aires": { name: "Buenos Aires (Edesur area)", lat: -34.75, lng: -58.4 },
  ...Object.fromEntries(Object.values(ECG_REGIONS).map(([n, lat, lng]) => [`ecg-ghana|${n}`, { name: `${n} (ECG region)`, lat, lng }])),
  ...Object.fromEntries(Object.values(BR_STATES).map(([n, lat, lng]) => [`ons-interrupcao-carga|${n}`, { name: `${n}, Brazil`, lat, lng }])),
};

// ---------- Endeavour Energy ----------
// outage-list: { areas: [...], singlePremise: [...] }. areas[]: incident_id, outage_type PLANNED | UNPLANNED, incident_status,
// customers_affected (int), center_lat/center_lng, polygon_geojson (a GeoJSON Polygon or MultiPolygon object),
// start_date_time (ISO with offset), end_date_time (1970-01-01 when none), etr ("2026-11-19 09:00:00+00"), cause, sub_cause
// ("None" when not given), cityname, cityname_list. singlePremise rows are one premise each and carry a GUID in
// customers_affected, so they are left out. Planned work counts only while it is under way (start <= now < end): the
// feed also lists work days ahead and work that has finished. Unplanned outages are all current.
const eeTime = (s) => { const t = String(s || "").trim().replace(" ", "T").replace(/([+-]\d{2})$/, "$1:00"); const iso = isoOf(t); return /^1970/.test(iso) ? "" : iso; };
export function parseEndeavour(d, now = Date.now()) {
  if (!d || !Array.isArray(d.areas)) throw badShape("endeavour areas");
  const out = [];
  for (const r of d.areas) {
    if (!r || !r.incident_id) continue;
    const planned = /^PLANNED$/i.test(r.outage_type || ""), start = eeTime(r.start_date_time), end = eeTime(r.end_date_time);
    if (planned && (!start || Date.parse(start) > now || (end && Date.parse(end) <= now))) continue;
    const g = r.polygon_geojson && typeof r.polygon_geojson === "object" ? r.polygon_geojson : null;
    const ring = g && Array.isArray(g.coordinates) ? (g.type === "MultiPolygon" ? g.coordinates.map((p) => (p && p[0]) || []).flat() : g.coordinates[0]) : null;
    let c = ringCentre(ring);
    if (c.lat == null) c = { lat: Number(r.center_lat), lng: Number(r.center_lng) };
    const cause = [r.cause, r.sub_cause].filter((x) => x && !/^none$/i.test(String(x).trim())).map((x) => str(x, 60));
    const towns = (Array.isArray(r.cityname_list) && r.cityname_list.length ? r.cityname_list : [r.cityname]).filter(Boolean);
    out.push(mk({ source: "endeavour-energy", id: `endeavour-energy:${slug(r.incident_id)}`, region: EE_REGION,
      area: towns.slice(0, 4).map((x) => str(x, 40)).join(", ") + (towns.length > 4 ? ` and ${towns.length - 4} more` : ""),
      lat: c.lat, lng: c.lng, customers: r.customers_affected, kind: "outage", planned,
      cause: [...new Set(cause)].join(": "), level: null, started_at: start, restore_est: eeTime(r.etr) || end }));
  }
  return out;
}

// ---------- TasNetworks ----------
// GetPowerOutages: an array; messageId, reason ("Planned maintenance work", "Emergency repairs", "Under investigation"),
// affectedAreas, affectedRegions (South, North, King Island ...), customersAffected (a string; "To be confirmed" when not
// known), createdOn (ISO with offset), estimatedTimeOfRestoration (text: "Friday 4:00 PM", or "To be confirmed - Please
// check back after 12:00 PM"), outagePolygon_WKT, outageCentroid_WKT.
const DAYS = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"];
/** "Friday 4:00 PM" -> that weekday on or after the reference instant's local date, in zone tz, as ISO UTC; else "". */
export function weekdayTimeToIso(text, refIso, tz, zonedToIso) {
  const m = String(text || "").trim().match(/^(sunday|monday|tuesday|wednesday|thursday|friday|saturday)\s+(\d{1,2}):(\d{2})\s*([AP]M)$/i);
  const ref = Date.parse(refIso || "");
  if (!m || !isFinite(ref)) return "";
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", weekday: "long" })
    .formatToParts(new Date(ref)).map((x) => [x.type, x.value]));
  const add = (DAYS.indexOf(m[1].toLowerCase()) - DAYS.indexOf(p.weekday.toLowerCase()) + 7) % 7;
  const day = new Date(Date.UTC(+p.year, +p.month - 1, +p.day + add)).toISOString().slice(0, 10);
  const hh = (+m[2] % 12) + (/pm/i.test(m[4]) ? 12 : 0);
  return zonedToIso(`${day} ${String(hh).padStart(2, "0")}:${m[3]}:00`, tz);
}
export function parseTasNetworks(d, zonedToIso) {
  if (!Array.isArray(d)) throw badShape("tasnetworks");
  return d.filter((r) => r && r.messageId != null).map((r) => {
    let c = wktCentre(r.outagePolygon_WKT);
    if (c.lat == null) c = wktCentre(r.outageCentroid_WKT);
    const started = isoOf(r.createdOn);
    return mk({ source: "tasnetworks", id: `tasnetworks:${slug(r.messageId)}`, region: "Tasmania",
      area: [str(r.affectedAreas, 80), str(r.affectedRegions, 30)].filter(Boolean).join(" (") + (str(r.affectedRegions, 30) && str(r.affectedAreas, 80) ? ")" : ""),
      lat: c.lat, lng: c.lng, customers: /^\s*\d+\s*$/.test(String(r.customersAffected ?? "")) ? +r.customersAffected : null,
      kind: "outage", planned: /\bplanned\b/i.test(r.reason || ""), cause: r.reason, level: null, started_at: started,
      restore_est: weekdayTimeToIso(r.estimatedTimeOfRestoration, r.createdOn, "Australia/Hobart", zonedToIso) });
  });
}

// ---------- Taipower ----------
// d006020/001.json: records[] = [ { curr_load, curr_util_rate }, { fore_maxi_sply_capacity, fore_peak_dema_load,
// fore_peak_resv_capacity, fore_peak_resv_rate, fore_peak_resv_indicator, fore_peak_hour_range, publish_time },
// { yday_* }, { real_hr_* } ]; loads in units of 10 MW; publish_time in the ROC calendar ("115.11.20(五)07:20" = 2026-11-20
// 07:20 Taiwan time). The indicator is Taipower's operating-reserve light for today's forecast peak. Taipower's own legend
// (今日電力資訊, www.taipower.com.tw; that host reset connections from here on 2026-11-20, so it was not re-read):
//   G 綠燈 供電充裕 supply ample, reserve margin >= 10%          -> supply_warning level 0
//   Y 黃燈 供電吃緊 supply tight, reserve margin 6% to 10%       -> supply_warning level 1
//   O 橘燈 供電警戒 supply warning, reserve margin <= 6%         -> supply_warning level 2
//   R 紅燈 限電警戒 rationing warning, reserve <= 900 MW         -> supply_warning level 3
//   B 黑燈 限電準備 rationing (preparing to ration), reserve <= 500 MW -> load_shedding level 3
// The fixture (2026-11-20) has G with an 18.77% margin. An unknown letter falls back to the same thresholds on the
// reported margin and reserve.
export const TAIPOWER_LIGHT = { G: ["supply_warning", 0, "green, supply ample"], Y: ["supply_warning", 1, "yellow, supply tight"],
  O: ["supply_warning", 2, "orange, supply warning"], R: ["supply_warning", 3, "red, rationing warning"],
  B: ["load_shedding", 3, "black, rationing"], K: ["load_shedding", 3, "black, rationing"] };
export function rocToIso(s, zonedToIso) {
  const m = String(s || "").match(/^(\d{2,3})\.(\d{1,2})\.(\d{1,2})(?:\([^)]*\))?\s*(\d{1,2}):(\d{2})/);
  if (!m) return "";
  return zonedToIso(`${+m[1] + 1911}-${m[2].padStart(2, "0")}-${m[3].padStart(2, "0")} ${m[4].padStart(2, "0")}:${m[5]}:00`, "Asia/Taipei");
}
export function parseTaipower(d, zonedToIso) {
  const recs = d && Array.isArray(d.records) ? d.records : null;
  if (!recs) throw badShape("taipower records");
  const all = Object.assign({}, ...recs.filter((x) => x && typeof x === "object"));
  const rate = Number(all.fore_peak_resv_rate), resvMw = Number(all.fore_peak_resv_capacity) * 10;
  let light = TAIPOWER_LIGHT[String(all.fore_peak_resv_indicator || "").trim().toUpperCase()];
  if (!light) {
    if (!isFinite(rate)) throw badShape("taipower indicator");
    light = isFinite(resvMw) && resvMw <= 500 ? TAIPOWER_LIGHT.B : isFinite(resvMw) && resvMw <= 900 ? TAIPOWER_LIGHT.R
      : rate <= 6 ? TAIPOWER_LIGHT.O : rate < 10 ? TAIPOWER_LIGHT.Y : TAIPOWER_LIGHT.G;
  }
  const load = Number(all.curr_load) * 10;
  const cause = `Forecast peak reserve ${isFinite(rate) ? `${rate}%` : "n/a"} (${light[2]})${all.fore_peak_hour_range ? ` at ${str(all.fore_peak_hour_range, 12)}` : ""}`
    + (isFinite(load) ? `; load now ${fmt(Math.round(load))} MW` : "");
  return [mk({ source: "taipower-supply", id: "taipower-supply:system", region: "Taiwan", area: "Taiwan power system",
    lat: null, lng: null, customers: null, kind: light[0], planned: false, cause, level: light[1],
    started_at: rocToIso(all.publish_time, zonedToIso), restore_est: "" })];
}

// ---------- ECG Ghana ----------
// One RSS per ECG region (current-status-<slug>): items with title, link, pubDate; the description holds only an image of
// the notice. Titles name the kind of notice and its day, e.g. "Planned Maintenance Works In Accra West Region-23RD
// OCTOBER,2026.", "POWER OUTAGE DUE TO A FAULT IN OUR NETWORK - 28TH OCTOBER, 2026 - ACCRA WEST", "Emergency Maintenance
// works in Central Region on Thursday, 29th October 2026". Kept: outage or maintenance notices whose day (from the title,
// else the pubDate) is today or later in Ghana (UTC+0, no daylight saving). Maintenance notices are planned (announced
// before the work); fault notices are not. No customer counts: customers null, so they are listed but never count toward
// the thresholds. started_at is the start of the day the notice names (Africa/Accra).
const MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
const xmlText = (s) => String(s || "").replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
  .replace(/&quot;/g, "\"").replace(/&apos;|&#0?39;/g, "'").replace(/&amp;/g, "&");
export function noticeDay(title) {
  const m = String(title || "").match(/(\d{1,2})\s*(?:st|nd|rd|th)?\s*,?\s*(january|february|march|april|may|june|july|august|september|october|november|december)\s*,?\s*(\d{4})/i);
  if (!m) return "";
  const mo = MONTHS.indexOf(m[2].toLowerCase()) + 1, dd = +m[1];
  return dd >= 1 && dd <= 31 ? `${m[3]}-${String(mo).padStart(2, "0")}-${String(dd).padStart(2, "0")}` : "";
}
export function parseEcgRss(xml, regionSlug, zonedToIso, now = Date.now()) {
  const s = String(xml || "");
  if (!/<rss[\s>]/.test(s) || !/<channel>/.test(s)) throw badShape("ecg rss");
  const reg = ECG_REGIONS[regionSlug];
  if (!reg) throw badShape(`ecg region ${regionSlug}`);
  const today = zonedToIso(new Date(now).toISOString().slice(0, 10) + " 00:00:00", "Africa/Accra").slice(0, 10);
  const out = [];
  for (const block of s.split(/<item>/).slice(1)) {
    const field = (t) => xmlText((block.match(new RegExp(`<${t}>([\\s\\S]*?)</${t}>`)) || [])[1] || "").trim();
    const title = str(field("title"), 200), link = field("link"), pub = isoOf(field("pubDate"));
    const outage = /\b(outage|fault|power cut|interruption|damaged|broken)\b/i.test(title), maint = /\b(maintenance|planned)\b/i.test(title);
    if (!outage && !maint) continue;
    const day = noticeDay(title) || pub.slice(0, 10);
    if (!day || day < today) continue;
    const planned = maint && !outage;
    out.push(mk({ source: "ecg-ghana", id: `ecg-ghana:${regionSlug}-${slug(link.split("/").pop() || title, 90)}`, region: reg[0],
      area: `${reg[0]} region`, lat: null, lng: null, customers: null, kind: "outage", planned, cause: title, level: null,
      started_at: zonedToIso(`${day} 00:00:00`, "Africa/Accra"), restore_est: "", url: link }));
  }
  return out;
}

// ---------- ENRE (Argentina's electricity regulator), Edenor and Edesur ----------
// data_EDN.js / data_EDS.js are JavaScript, not JSON: `var data = { fuente: 'Web Service', empresa: 'EDENOR',
// totalUsuariosSinSuministro: '933', totalUsuariosConSuministro: '3.505.161', ultimaActualizacion: '20:20', ...,
// cortesPreventivos: [], cortesProgramados: [], cortesServicioMedia: [{ partido, localidad, subestacion_alimentador,
// usuarios, normalizacion }], cortesComunicados: [], cortesServicioBaja: [{ partido, localidad, usuarios }] }`, with
// unquoted keys and single-quoted values. It is read with parseJsLiteral (a small parser for that literal syntax only;
// nothing is evaluated). Numbers use "." for thousands. normalizacion is the expected restoration (Buenos Aires time,
// "YYYY-MM-DD HH:MM") or "Sin datos". Programados, Preventivos and Comunicados are announced work (planned); ServicioMedia
// (medium-voltage faults) and ServicioBaja (low-voltage) are not. One item per district (partido) and planned flag, with
// the latest restoration time of its rows; the per-district sums add up to totalUsuariosSinSuministro.

/** A JavaScript object/array literal (optionally after `var <name> =`, optional trailing `;`) -> plain data. Strings in
 *  single or double quotes, unquoted keys, numbers, true/false/null, trailing commas. Anything else throws bad_shape. */
export function parseJsLiteral(text, maxLen = 2e6) {
  let s = String(text == null ? "" : text);
  if (s.length > maxLen) throw badShape("js literal too long");
  s = s.replace(/^\uFEFF/, "").trim().replace(/^var\s+[A-Za-z_$][\w$]*\s*=\s*/, "").replace(/;\s*$/, "").trim();
  let i = 0, depth = 0;
  const err = (w) => badShape(`js literal: ${w} at ${i}`);
  const ws = () => { for (;;) { while (i < s.length && /\s/.test(s[i])) i++; if (s.startsWith("//", i)) { while (i < s.length && s[i] !== "\n") i++; } else if (s.startsWith("/*", i)) { const e = s.indexOf("*/", i + 2); if (e < 0) throw err("comment"); i = e + 2; } else return; } };
  const string = () => {
    const q = s[i++]; let o = "";
    while (i < s.length && s[i] !== q) {
      if (s[i] === "\\") { const c = s[i + 1]; i += 2;
        if (c === "u" && /^[0-9a-fA-F]{4}$/.test(s.slice(i, i + 4))) { o += String.fromCharCode(parseInt(s.slice(i, i + 4), 16)); i += 4; }
        else o += { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", 0: "\0" }[c] ?? (c === "\n" ? "" : c);
      } else if (s[i] === "\n") throw err("newline in string"); else o += s[i++];
    }
    if (s[i] !== q) throw err("unterminated string");
    i++; return o;
  };
  const value = () => {
    ws();
    const c = s[i];
    if (c === "{" || c === "[") {
      if (++depth > 20) throw err("too deep");
      i++; const arr = c === "[", o = arr ? [] : {};
      for (;;) {
        ws();
        if (s[i] === (arr ? "]" : "}")) { i++; break; }
        if (arr) o.push(value());
        else {
          let k;
          if (s[i] === "'" || s[i] === "\"") k = string();
          else { const m = /^[A-Za-z_$][\w$]*|^\d+/.exec(s.slice(i, i + 100)); if (!m) throw err("key"); k = m[0]; i += k.length; }
          ws(); if (s[i] !== ":") throw err("colon"); i++;
          const v = value();
          if (k !== "__proto__" && k !== "constructor" && k !== "prototype") o[k] = v;
        }
        ws();
        if (s[i] === ",") { i++; continue; }
        if (s[i] === (arr ? "]" : "}")) { i++; break; }
        throw err("separator");
      }
      depth--; return o;
    }
    if (c === "'" || c === "\"") return string();
    const m = /^-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?|^(?:true|false|null)\b/.exec(s.slice(i, i + 40));
    if (!m) throw err("value");
    i += m[0].length;
    return m[0] === "true" ? true : m[0] === "false" ? false : m[0] === "null" ? null : Number(m[0]);
  };
  const v = value(); ws();
  if (i !== s.length) throw err("trailing text");
  return v;
}
const arInt = (x) => { const t = String(x == null ? "" : x).trim().replace(/\./g, ""); return /^\d+$/.test(t) ? +t : null; };
const ENRE_LISTS = [["cortesServicioMedia", false], ["cortesServicioBaja", false], ["cortesProgramados", true], ["cortesPreventivos", true], ["cortesComunicados", true]];
export function parseEnre(text, key, zonedToIso) {
  if (!SOURCES[key] || !/^enre-/.test(key)) throw badShape("enre key");
  const d = parseJsLiteral(text);
  if (!d || typeof d !== "object" || Array.isArray(d) || !("totalUsuariosSinSuministro" in d)) throw badShape("enre data");
  const groups = new Map();
  for (const [list, planned] of ENRE_LISTS) {
    if (d[list] != null && !Array.isArray(d[list])) throw badShape(`enre ${list}`);
    for (const r of d[list] || []) {
      if (!r || typeof r !== "object") continue;
      const n = arInt(r.usuarios); if (n == null) continue;
      let partido = str(r.partido, 60).toUpperCase(); if (partido === "CAPITAL") partido = "CAPITAL FEDERAL";
      if (!partido) continue;
      const gk = `${partido}|${planned}`, g = groups.get(gk) || { partido, planned, customers: 0, places: new Set(), restore: "", lists: new Set() };
      g.customers += n; if (r.localidad) g.places.add(str(r.localidad, 40));
      const rest = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(String(r.normalizacion || "")) ? zonedToIso(String(r.normalizacion), "America/Argentina/Buenos_Aires") : "";
      if (rest && rest > g.restore) g.restore = rest;
      g.lists.add(list);
      groups.set(gk, g);
    }
  }
  const what = { cortesServicioMedia: "medium-voltage fault", cortesServicioBaja: "low-voltage fault", cortesProgramados: "scheduled work",
    cortesPreventivos: "preventive work", cortesComunicados: "announced work" };
  const title = (s) => s.toLowerCase().replace(/(^|[\s(.-])([a-z\u00e0-\u00ff])/g, (m, a, b) => a + b.toUpperCase());
  return [...groups.values()].map((g) => mk({ source: key, id: `${key}:${slug(g.partido)}-${g.planned ? "planned" : "unplanned"}`,
    region: "Buenos Aires", area: str(`${title(g.partido)}: ${[...g.places].slice(0, 4).map(title).join(", ")}${g.places.size > 4 ? ` and ${g.places.size - 4} more` : ""}`, 120),
    lat: null, lng: null, customers: g.customers, kind: "outage", planned: g.planned, cause: [...g.lists].map((l) => what[l]).join(", "),
    level: null, started_at: "", restore_est: g.restore }));
}
/** The feed's own total of customers without supply (for checks). */
export const enreTotal = (text) => arInt(parseJsLiteral(text).totalUsuariosSinSuministro);

// ---------- ONS (Brazil's national grid operator), load interruptions ----------
// INTERRUPCAO_CARGA.csv: semicolon-separated, header cod_perturbacao;din_interrupcaocarga;id_subsistema;nom_subsistema;
// id_estado;nom_agente;val_cargainterrompida_mw;val_tempomedio_minutos;val_energianaosuprida_mwh;flg_envolveuredebasica;
// flg_envolveuredeoperacao. The file is the whole history since 2007 (about 770 KB), oldest first, refreshed twice a day
// with a lag of a few days. One row per disturbance, state and distributor; the time is Brasília time (America/Sao_Paulo).
// Kept: rows from the last 7 days. Each becomes an outage with customers null (ONS reports MW, not customers), the MW
// interrupted and the mean duration in the cause, region = the state. A text that does not start with the header (a tail
// read by byte range) is read with the same column order and its first, possibly cut, line is dropped.
export const ONS_COLUMNS = ["cod_perturbacao", "din_interrupcaocarga", "id_subsistema", "nom_subsistema", "id_estado", "nom_agente",
  "val_cargainterrompida_mw", "val_tempomedio_minutos", "val_energianaosuprida_mwh", "flg_envolveuredebasica", "flg_envolveuredeoperacao"];
export const ONS_KEEP_DAYS = 7;
export function parseOns(text, zonedToIso, now = Date.now()) {
  const lines = String(text || "").replace(/^\uFEFF/, "").split(/\r?\n/);
  let cols = ONS_COLUMNS;
  if (/^cod_perturbacao;/i.test(lines[0] || "")) cols = lines.shift().trim().toLowerCase().split(";");
  else lines.shift();  // a byte-range tail starts inside a line
  const at = (k) => cols.indexOf(k);
  const iT = at("din_interrupcaocarga"), iS = at("id_estado"), iA = at("nom_agente"), iMw = at("val_cargainterrompida_mw"), iMin = at("val_tempomedio_minutos"), iC = at("cod_perturbacao");
  if ([iT, iS, iA, iMw, iC].some((x) => x < 0)) throw badShape("ons header");
  const out = [], seen = new Set(), from = now - ONS_KEEP_DAYS * 864e5;
  let rows = 0;
  for (const line of lines) {
    if (!line.trim()) continue;
    const f = line.split(";");
    if (f.length < cols.length) continue;
    rows++;
    const started = zonedToIso(f[iT], "America/Sao_Paulo"), t = Date.parse(started);
    if (!isFinite(t) || t < from || t > now + 3600e3) continue;
    const uf = f[iS].trim().toUpperCase(), st = BR_STATES[uf];
    if (!st) continue;
    const mw = Number(f[iMw]), min = Number(f[iMin]), agent = str(f[iA], 60);
    const id = `ons-interrupcao-carga:${slug(f[iC])}-${uf.toLowerCase()}-${slug(agent)}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(mk({ source: "ons-interrupcao-carga", id, country: "BR", region: st[0], area: `${agent} (${uf})`, lat: null, lng: null,
      customers: null, kind: "outage", planned: false, level: null, started_at: started, restore_est: "",
      cause: `${isFinite(mw) ? `${Math.round(mw * 10) / 10} MW` : "Load"} of load interrupted${isFinite(min) ? `, mean ${Math.round(min)} min` : ""} (ONS disturbance ${str(f[iC], 20)})` }));
  }
  if (!rows) throw badShape("ons rows");
  return out;
}

// ---------- adapters ----------
export const ADAPTERS = {
  "endeavour-energy": async (h) => parseEndeavour(await h.get(h.SOURCES["endeavour-energy"].url, { timeoutMs: 40000 })),
  tasnetworks: async (h) => parseTasNetworks(await h.get(h.SOURCES.tasnetworks.url), h.zonedToIso),
  "taipower-supply": async (h) => parseTaipower(await h.get(h.SOURCES["taipower-supply"].url), h.zonedToIso),
  // one feed per ECG region; the source fails only when no region's feed can be read
  "ecg-ghana": async (h) => {
    const out = [], errs = [];
    for (const r of Object.keys(ECG_REGIONS)) {
      const u = `https://www.ecg.com.gh/index.php/en/services/ecg-status/current-system-status/current-status-${r}?format=feed&type=rss`;
      try { out.push(...parseEcgRss(await h.get(u, { as: "text", retries: 1 }), r, h.zonedToIso)); } catch (e) { errs.push(e); }
    }
    if (errs.length === Object.keys(ECG_REGIONS).length) throw errs[0];
    return out;
  },
  "enre-edenor": async (h) => parseEnre(await h.get(h.SOURCES["enre-edenor"].url, { as: "text" }), "enre-edenor", h.zonedToIso),
  "enre-edesur": async (h) => parseEnre(await h.get(h.SOURCES["enre-edesur"].url, { as: "text" }), "enre-edesur", h.zonedToIso),
  // the whole file (about 770 KB): scripts/lib/net.mjs get() sends no Range header yet (asked in swarm/REQUESTS.md); the
  // server answers byte ranges (206), and parseOns already reads a header-less tail, so a `range` option is passed for when
  // get() learns it (an unknown option is ignored today)
  "ons-interrupcao-carga": async (h) => parseOns(await h.get(h.SOURCES["ons-interrupcao-carga"].url, { as: "text", timeoutMs: 60000, range: "bytes=-65536" }), h.zonedToIso),
};

export default {
  sources: SOURCES,
  regions: REGIONS,
  adapters: Object.fromEntries(Object.entries(ADAPTERS).map(([k, fn]) => [k, async (h) => (await fn(h)).map((x) => h.item(x))])),
};
