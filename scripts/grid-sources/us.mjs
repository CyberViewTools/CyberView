// United States grid sources (lane "us" of swarm/grid-sources-20261119): six utility outage feeds, the DOE/ORNL ODIN
// aggregator, and two grid-operator signal feeds (CAISO emergency notices, NYISO real-time events). Each was recorded as
// "connect" by the scout (public, no key, terms allowed or silent, robots.txt not disallowing). Every parser is pure
// (data + h -> items, h = the helpers scripts/grid.mjs passes in) and tested on real saved replies in
// tests/fixtures/grid/us/ (tests/unit/grid-us.test.mjs). Adapters send no key, cookie or browser-imitating header; a
// refusal fails the source and is reported, never worked around.
//
// An outage is context, never an attack: causes are passed on only as the operator reports them, and planned work is
// marked planned only when the feed says so.
import { US_STATES, BY_ABBR, stateOfFips, titleCase } from "./lib-us-states.mjs";

const badShape = (why = "") => Object.assign(new Error(`unexpected shape${why ? `: ${why}` : ""}`), { code: "bad_shape" });
const int = (x) => (x === null || x === undefined || x === "" || !isFinite(Number(x)) ? null : Math.max(0, Math.round(Number(x))));
const slug = (s) => String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "x";
/** "MM/DD/YYYY HH:MM[:SS]" -> "YYYY-MM-DD HH:MM:SS" (for h.zonedToIso), or "". */
const usLocal = (s) => { const m = String(s || "").trim().match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
  return m ? `${m[3]}-${m[1].padStart(2, "0")}-${m[2].padStart(2, "0")} ${m[4].padStart(2, "0")}:${m[5]}:${m[6] || "00"}` : ""; };

// ---------- sources ----------
const PACIFICORP_TERMS = "https://www.pacificorp.com/terms-of-use.html";
export const SOURCES = {
  // metadata.json names the newest directory; four per-territory reports in it give customers out per town
  eversource: { name: "Eversource", country: "US", kind: "outages",
    url: "https://outagemap.eversource.com/resources/data/external/interval_generation_data/metadata.json",
    page: "https://outagemap.eversource.com/", hosts: ["outagemap.eversource.com", "www.eversource.com"],
    terms_url: "https://www.eversource.com/residential/about/terms-and-conditions", terms_ok: "silent", customers_served: 3344480 },
  // the county counts behind NES's own outage map (hosted for NES by its map vendor, utilisocial.io)
  "nashville-electric": { name: "Nashville Electric Service", country: "US", kind: "outages",
    url: "https://utilisocial.io/datacapable/v2/p/NES/map/events/count?types=COUNTY",
    page: "https://www.nespower.com/outages/", hosts: ["www.nespower.com"],
    terms_url: "https://www.nespower.com/legal/terms-of-service/", terms_ok: "silent", customers_served: null },
  "rocky-mountain-power": { name: "Rocky Mountain Power", country: "US", kind: "outages",
    url: "https://www.rockymountainpower.net/etc/pcorp/datafiles/outagemap/listUT.json",
    page: "https://www.rockymountainpower.net/outages-safety.html", hosts: ["www.rockymountainpower.net"],
    terms_url: PACIFICORP_TERMS, terms_ok: "silent", customers_served: null, states: ["UT", "WY", "ID"] },
  "pacific-power": { name: "Pacific Power", country: "US", kind: "outages",
    url: "https://www.pacificpower.net/etc/pcorp/datafiles/outagemap/listOR.json",
    page: "https://www.pacificpower.net/outages-safety.html", hosts: ["www.pacificpower.net"],
    terms_url: PACIFICORP_TERMS, terms_ok: "silent", customers_served: null, states: ["OR", "WA", "CA"] },
  // the public ArcGIS layer behind the map on ladwp.com/outages/power-outage-map
  ladwp: { name: "LADWP", country: "US", kind: "outages",
    url: "https://services2.arcgis.com/v0bIBBLIiGigCimX/ArcGIS/rest/services/PowerOutages_Data/FeatureServer/0/query?where=1%3D1&outFields=*&returnGeometry=true&outSR=4326&f=json",
    page: "https://www.ladwp.com/outages/power-outage-map", hosts: ["www.ladwp.com"],
    terms_url: "https://www.ladwp.com/terms-conditions", terms_ok: "silent", customers_served: 1500000 },
  // ODIN aggregates ~159 participating utilities at county level. It can double-count utilities read directly here
  // (PacifiCorp, NES, LADWP, Eversource): their rows are dropped (ODIN_DIRECT).
  "doe-odin": { name: "DOE/ORNL ODIN", country: "US", kind: "outages", aggregator: true,
    url: "https://odin.ornl.gov/odi?view=county", page: "https://odin.ornl.gov/", hosts: ["odin.ornl.gov"],
    terms_url: "https://odin.ornl.gov/swagger-ui/index.html", terms_ok: "silent", customers_served: null,
    note: "Aggregator of participating US utilities (county level); rows of utilities CyberView reads directly are dropped to avoid double counting." },
  "caiso-emergency": { name: "California ISO", country: "US", kind: "signal",
    url: "https://wwwmobile.caiso.com/TodaysOutlookApi/api/EmergencyNotices/v2/ActiveEvents",
    page: "https://www.caiso.com/emergency-notifications", hosts: ["www.caiso.com"],
    terms_url: "https://www.caiso.com/privacy-terms-of-use", terms_ok: "allowed", customers_served: null,
    attribution: "Source: California ISO (CAISO), www.caiso.com" },
  "nyiso-realtime-events": { name: "NYISO", country: "US", kind: "signal",
    url: "https://mis.nyiso.com/public/csv/RealTimeEvents/", page: "https://www.nyiso.com/system-conditions",
    hosts: ["www.nyiso.com", "mis.nyiso.com"], terms_url: "https://www.nyiso.com/legal-notice", terms_ok: "silent", customers_served: null },
};

// ---------- regions (one coarse region per state or service area; approximate centres) ----------
const state = (abbr, lat, lng) => { const s = BY_ABBR[abbr]; return { name: s.name, lat: lat ?? s.lat, lng: lng ?? s.lng }; };
export const REGIONS = {
  "eversource|Connecticut": state("CT"), "eversource|Massachusetts": state("MA"), "eversource|New Hampshire": state("NH", 43.2, -71.5),
  "nashville-electric|Nashville": { name: "Nashville and Middle Tennessee (NES)", lat: 36.17, lng: -86.78 },
  "rocky-mountain-power|Utah": state("UT", 40.6, -111.9), "rocky-mountain-power|Wyoming": state("WY"),
  "rocky-mountain-power|Idaho": { name: "Idaho (south-east)", lat: 43.0, lng: -112.2 },
  "pacific-power|Oregon": state("OR", 44.3, -122.0), "pacific-power|Washington": { name: "Washington (south-central)", lat: 46.4, lng: -119.6 },
  "pacific-power|California": { name: "California (far north)", lat: 41.5, lng: -122.6 },
  "ladwp|Los Angeles": { name: "Los Angeles", lat: 34.05, lng: -118.35 },
  "caiso-emergency|California": { name: "California (CAISO)", lat: 37.2, lng: -119.5 },
  "nyiso-realtime-events|New York": { name: "New York (NYISO)", lat: 42.9, lng: -75.5 },
};
for (const [, [, name, lat, lng]] of Object.entries(US_STATES)) REGIONS[`doe-odin|${name}`] = { name, lat, lng };

// ---------- Eversource ----------
// metadata.json -> { directory: "2026_11_19_23_59_30" }; in that directory report_conn.json (CT), report_east.json and
// report_west.json (eastern and western MA), report_hampshire.json (NH) are { file_data: { areas: [EVERSOURCE ->
// state ("CT") -> territory ("CTE") -> towns] } }, each node { area_name, cust_a: { val, masked? }, cust_s }. The four
// territories' cust_s add up to data.json's total_cust_s (3,344,480 on 2026-11-19). Small counts carry masked:true
// (the map shows a floor instead of the real number); the value is kept as published. No times or causes at town level.
export const EVERSOURCE_REPORTS = ["report_conn.json", "report_east.json", "report_west.json", "report_hampshire.json"];
const EVERSOURCE_BASE = "https://outagemap.eversource.com/resources/data/external/interval_generation_data/";
export function eversourceDir(meta) {
  const d = meta && meta.directory;
  if (!/^\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}$/.test(String(d || ""))) throw badShape("eversource directory");
  return d;
}
export function parseEversourceReport(d, h) {
  const top = d && d.file_data && Array.isArray(d.file_data.areas) ? d.file_data.areas : null;
  if (!top) throw badShape("eversource report");
  const out = [];
  for (const co of top) for (const st of (co && co.areas) || []) {
    const s = BY_ABBR[String(st.area_name || "").toUpperCase()];
    if (!s) continue;
    const walk = (nodes) => { for (const n of nodes || []) {
      if (Array.isArray(n.areas)) { walk(n.areas); continue; }
      const c = int(n.cust_a && n.cust_a.val);
      if (!c) continue;
      out.push(h.item({ source: "eversource", id: `eversource:${s.abbr}-${slug(n.area_name)}`, region: s.name,
        area: h.str(`${titleCase(n.area_name)}, ${s.abbr}`, 120), lat: null, lng: null, customers: c, kind: "outage",
        planned: false, cause: "", level: null, started_at: "", restore_est: "" }));
    } };
    walk(st.areas);
  }
  return out;
}

// ---------- Nashville Electric Service ----------
// [{ name: county, type: "COUNTY", customersAffected, customersServed (0 in every row seen) }]. Counties with nobody out
// are left out. No times or causes.
export function parseNes(d, h) {
  if (!Array.isArray(d)) throw badShape("nes");
  return d.filter((r) => r && r.name && int(r.customersAffected) > 0).map((r) => h.item({
    source: "nashville-electric", id: `nashville-electric:${slug(r.name)}`, region: "Nashville",
    area: h.str(`${titleCase(r.name)} County, TN`, 120), lat: null, lng: null, customers: int(r.customersAffected), kind: "outage",
    planned: false, cause: "", level: null, started_at: "", restore_est: "" }));
}

// ---------- PacifiCorp (Rocky Mountain Power, Pacific Power) ----------
// list<ST>.json: { count (outages), totalState (customers out), last_upd, zips: [...], counties: [{ countyName,
// outCountPlan, outCountUnplan, custOutPlan, custOutUnplan }] }. The county rows add up to totalState (the zip rows can
// fall short), so items are per county, split into planned and unplanned as the feed reports them.
export function parsePacifiCorp(d, src, abbr, h) {
  const s = BY_ABBR[abbr];
  if (!s || !d || typeof d !== "object" || !isFinite(Number(d.totalState))) throw badShape("pacificorp list");
  const out = [];
  for (const c of Array.isArray(d.counties) ? d.counties : []) {
    if (!c || !c.countyName) continue;
    for (const [planned, n] of [[false, c.custOutUnplan], [true, c.custOutPlan]]) {
      if (!(int(n) > 0)) continue;
      out.push(h.item({ source: src, id: `${src}:${abbr}-${slug(c.countyName)}-${planned ? "p" : "u"}`, region: s.name,
        area: h.str(`${titleCase(c.countyName)} County, ${abbr}`, 120), lat: null, lng: null, customers: int(n), kind: "outage",
        planned, cause: "", level: null, started_at: "", restore_est: "" }));
    }
  }
  return out;
}

// ---------- LADWP ----------
// ArcGIS FeatureServer query (f=json): features[].attributes { OBJECTID, CITY_NAM (neighbourhood), OUTAGE_RANK,
// COUNT_IN_RANK (customers in this outage), FAC_JOB_STATUS_NAM (crew status: REPORTED OUTAGE, ASSIGNED, EN ROUTE,
// CREWS WORKING), ETR_DATETIME, ETR_DATETIME_CHAR, CENTROID_LAT, CENTROID_LNG }. ETR_DATETIME is the Pacific wall-clock
// time stored as if it were UTC (1795118400000 = 2026-11-19T20:00Z beside ETR_DATETIME_CHAR "11/19/2026 20:00", seen
// 2026-11-19 at 15:38 PT), so the restore estimate is read from ETR_DATETIME_CHAR as America/Los_Angeles time.
// The crew status is not a cause and is not reported as one. No start times. An ArcGIS error comes as { error }.
export function parseLadwp(d, h) {
  if (!d || d.error || !Array.isArray(d.features)) throw badShape(d && d.error ? `arcgis ${int(d.error.code) ?? ""}` : "ladwp");
  return d.features.filter((f) => f && f.attributes && f.attributes.OBJECTID != null).map((f) => {
    const a = f.attributes, g = f.geometry || {};
    const lat = Number(a.CENTROID_LAT ?? g.y), lng = Number(a.CENTROID_LNG ?? g.x);
    return h.item({ source: "ladwp", id: `ladwp:${int(a.OBJECTID)}`, region: "Los Angeles", area: h.str(titleCase(a.CITY_NAM), 120),
      lat: isFinite(lat) ? lat : null, lng: isFinite(lng) ? lng : null, customers: int(a.COUNT_IN_RANK), kind: "outage",
      planned: false, cause: "", level: null, started_at: "", restore_est: h.zonedToIso(usLocal(a.ETR_DATETIME_CHAR), "America/Los_Angeles") });
  });
}

// ---------- DOE/ORNL ODIN ----------
// /odi?view=county -> { outage: [{ MRID, communityDescriptor (county FIPS), metersAffected, names: [{ name, nameType:
// "UtilityName" | "UtilityId", nameTypeAuthority: "EIA" }], cause, causeKind, estimatedRestorationTime,
// reportedStartTime, outageKind, ... }] }. In the samples of 2026-11-19 only MRID, the FIPS code, metersAffected and
// names were filled; cause, start and restoration are passed on when a utility fills them. Meters affected are read as
// customers. Region: the state of the county (no county centres in this view: lat/lng null). The reporting utility goes
// in `area` (all of them when a row names several). Rows of utilities CyberView reads directly are dropped (ODIN_DIRECT: names, and the EIA ids seen in
// /odi/status on 2026-11-19: PacifiCorp 14354, Nashville Electric Service 13216).
export const ODIN_DIRECT = /\b(PACIFICORP|ROCKY MOUNTAIN POWER|PACIFIC POWER|NASHVILLE ELECTRIC|LOS ANGELES DEP(?:T|ARTMENT)? OF WATER|LADWP|EVERSOURCE|CONNECTICUT LIGHT|NSTAR|PUBLIC SERVICE CO(?:MPANY)? OF (?:NH|NEW HAMPSHIRE)|WESTERN MASSACHUSETTS ELEC)/i;
const ODIN_DIRECT_IDS = new Set(["14354", "13216"]);
export function parseOdin(d, h) {
  if (!d || !Array.isArray(d.outage)) throw badShape("odin");
  const out = [];
  for (const r of d.outage) {
    if (!r) continue;
    // a county row can name several utilities (their meters summed); it cannot be split, so a row naming any utility
    // read directly is dropped whole
    const names = (Array.isArray(r.names) ? r.names : []).filter((n) => n && n.name != null);
    const utilities = names.filter((n) => n.nameType === "UtilityName").map((n) => String(n.name));
    const ids = names.filter((n) => n.nameType === "UtilityId").map((n) => String(n.name));
    if (utilities.some((u) => ODIN_DIRECT.test(u)) || ids.some((i) => ODIN_DIRECT_IDS.has(i))) continue;
    const utility = utilities.join("; "), eia = ids.join("-");
    const s = stateOfFips(r.communityDescriptor), c = int(r.metersAffected);
    if (!s || !c) continue;
    const kind = String(r.outageKind || "");
    out.push(h.item({ source: "doe-odin", id: `doe-odin:${h.str(r.MRID || r.mrid || `${eia}-${r.communityDescriptor}`, 60)}`, country: s.country,
      region: s.name, area: h.str(`County FIPS ${r.communityDescriptor}: ${utility || "utility not named"}`, 120), lat: null, lng: null,
      customers: c, kind: "outage", planned: /planned/i.test(kind) && !/unplanned/i.test(kind),
      cause: h.str(r.cause || r.causeKind || "", 120), level: null, started_at: h.isoOf(r.reportedStartTime),
      restore_est: h.isoOf(r.estimatedRestorationTime) }));
  }
  return out;
}

// ---------- CAISO emergency notices ----------
// ActiveEvents -> { CurrentEvents: [...], UpcomingEvents: [...], *Count }; an event is { EventId, EventType, Region,
// StartDateTime_PT, EndDateTime_PT ("YYYY-MM-DDTHH:MM:SS", Pacific time), InEffect, EventMessages: [{ MessageType,
// PostDate_PT, MessageBody }] } (field names from the script on www.caiso.com/emergency-notifications, 2026-11-19).
// Only current events that are in effect and not past their end are read; upcoming ones are forecasts. Levels, from
// CAISO's Emergency Notifications Fact Sheet (www.caiso.com/documents/emergency-notifications-fact-sheet.pdf):
//   Restricted Maintenance Operations           -> skipped (a maintenance caution, not a shortage)
//   Flex Alert (voluntary conservation)          -> supply_warning 1
//   EEA Watch (shortfall forecast)               -> supply_warning 1
//   Transmission Emergency                       -> grid_emergency 1
//   EEA 1 / EEA 2 / EEA 3                         -> grid_emergency 1 / 2 / 3
//   EEA 3 with rotating outages ordered          -> load_shedding 3
//   any other type                               -> skipped (not guessed)
export function caisoLevel(type) {
  const t = String(type || "");
  if (/restricted maintenance|\bRMO\b/i.test(t)) return null;
  if (/flex alert/i.test(t)) return { kind: "supply_warning", level: 1 };
  if (/\bwatch\b/i.test(t) && /\bEEA\b|energy emergency/i.test(t)) return { kind: "supply_warning", level: 1 };
  if (/transmission emergency/i.test(t)) return { kind: "grid_emergency", level: 1 };
  const m = t.match(/(?:\bEEA|energy emergency alert)\s*([123])\b/i);
  if (!m) return null;
  if (m[1] === "3" && /rotating/i.test(t) && /order/i.test(t)) return { kind: "load_shedding", level: 3 };
  return { kind: "grid_emergency", level: +m[1] };
}
export function parseCaiso(d, h, now = Date.now()) {
  if (!d || !Array.isArray(d.CurrentEvents)) throw badShape("caiso");
  const out = [];
  for (const e of d.CurrentEvents) {
    if (!e || e.InEffect !== true) continue;
    const lv = caisoLevel(e.EventType);
    if (!lv) continue;
    const end = h.zonedToIso(e.EndDateTime_PT, "America/Los_Angeles");
    if (end && Date.parse(end) < now) continue;
    out.push(h.item({ source: "caiso-emergency", id: `caiso-emergency:${h.str(e.EventId, 60) || slug(`${e.EventType}-${e.StartDateTime_PT}`)}`,
      region: "California", area: h.str(e.Region || "CAISO balancing area", 120), lat: null, lng: null, customers: null,
      kind: lv.kind, planned: false, cause: h.str(e.EventType, 120), level: lv.level,
      started_at: h.zonedToIso(e.StartDateTime_PT, "America/Los_Angeles"), restore_est: end, url: SOURCES["caiso-emergency"].page }));
  }
  return out;
}

// ---------- NYISO real-time events ----------
// <YYYYMMDD>RealTimeEvents.csv (Eastern time): "Timestamp,Message" rows, e.g. "Start of day system state is NORMAL",
// "**State Change. System now operating in alert state.**", thunderstorm alerts, reserve pick-ups and capacity requests
// (real days in tests/fixtures/grid/us/nyiso-*.csv). The newest state message is the current system state; a state lasts
// until the next change (a new day's file starts with its start-of-day state). Levels, from NYISO's operating states
// (Normal < Warning < Alert < Major Emergency; Restoration after load was lost):
//   normal          -> grid_emergency 0 (one item, like ERCOT's EEA 0, so the series records the normal state)
//   warning         -> supply_warning 1
//   alert           -> supply_warning 2
//   major emergency -> grid_emergency 3
//   restoration     -> grid_emergency 3
// Thunderstorm alerts (a weather operating posture) are noted in `area` and do not change the level; reserve pick-ups
// and capacity requests are not states and are not read. A file with no state message gives no item.
const NY_LEVEL = { normal: ["grid_emergency", 0], warning: ["supply_warning", 1], alert: ["supply_warning", 2],
  "major emergency": ["grid_emergency", 3], restoration: ["grid_emergency", 3] };
export function nyisoDay(ms) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: "America/New_York", year: "numeric", month: "2-digit", day: "2-digit" })
    .formatToParts(new Date(ms)).map((x) => [x.type, x.value]));
  return `${p.year}${p.month}${p.day}`;
}
export function parseNyiso(text, h, url = "") {
  const lines = String(text || "").split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (!/^Timestamp,Message$/i.test(lines[0] || "")) throw badShape("nyiso csv");
  let st = null, storm = false;
  for (const line of lines.slice(1)) {
    const i = line.indexOf(","), ts = line.slice(0, i), msg = line.slice(i + 1).replace(/^"|"$/g, "").replace(/\*+/g, "").trim();
    if (i < 0) continue;
    if (/thunderstorm alert/i.test(msg)) { storm = /\bno longer\b/i.test(msg) ? false : /now operating in|is ACTIVE/i.test(msg) ? true : storm; continue; }
    const m = msg.match(/system state is ([a-z ]+?)\s*$/i) || msg.match(/system now operating in ([a-z ]+?) state\b/i)
      || msg.match(/start of the day is ([a-z ]+?)\s*$/i);
    const name = m && m[1].toLowerCase().trim();
    if (name && NY_LEVEL[name]) st = { name, msg, at: h.zonedToIso(usLocal(ts), "America/New_York") };
  }
  if (!st) return [];   // a day can start with only a thunderstorm-alert line (seen 2026-06-12): no state given, none guessed
  const [kind, level] = NY_LEVEL[st.name];
  return [h.item({ source: "nyiso-realtime-events", id: "nyiso-realtime-events:system", region: "New York",
    area: h.str(`NYISO system state: ${titleCase(st.name)}${storm ? " (thunderstorm alert in effect)" : ""}`, 120), lat: null, lng: null,
    customers: null, kind, planned: false, cause: h.str(st.msg, 120), level, started_at: st.at, restore_est: "", url })];
}

// ---------- adapters ----------
export const adapters = {
  eversource: async (h) => {
    const dir = eversourceDir(await h.get(SOURCES.eversource.url));
    const out = [];
    for (const f of EVERSOURCE_REPORTS) out.push(...parseEversourceReport(await h.get(`${EVERSOURCE_BASE}${dir}/${f}`), h));
    return out;
  },
  "nashville-electric": async (h) => parseNes(await h.get(SOURCES["nashville-electric"].url), h),
  "rocky-mountain-power": async (h) => pacifiCorp("rocky-mountain-power", h),
  "pacific-power": async (h) => pacifiCorp("pacific-power", h),
  ladwp: async (h) => {
    // ArcGIS pages large replies (exceededTransferLimit): follow with resultOffset, at most 5 pages
    const out = [];
    for (let page = 0, offset = 0; page < 5; page++) {
      const d = await h.get(offset ? `${SOURCES.ladwp.url}&resultOffset=${offset}` : SOURCES.ladwp.url);
      const got = parseLadwp(d, h);
      out.push(...got);
      if (!d.exceededTransferLimit || !got.length) break;
      offset += d.features.length;
    }
    return out;
  },
  "doe-odin": async (h) => parseOdin(await h.get(SOURCES["doe-odin"].url), h),
  "caiso-emergency": async (h) => parseCaiso(await h.get(SOURCES["caiso-emergency"].url), h),
  "nyiso-realtime-events": async (h) => {
    // today's file (Eastern date); just after midnight it may not exist yet, then yesterday's last state still holds
    const base = SOURCES["nyiso-realtime-events"].url, now = Date.now();
    for (const day of [nyisoDay(now), nyisoDay(now - 864e5)]) {
      const url = `${base}${day}RealTimeEvents.csv`;
      try { return parseNyiso(await h.get(url, { as: "text", retries: 1 }), h, url); }
      catch (e) { if (!(e && e.code === "http_404") || day !== nyisoDay(now)) throw e; }
    }
    return [];
  },
};
async function pacifiCorp(src, h) {
  const out = [];
  for (const abbr of SOURCES[src].states) {
    out.push(...parsePacifiCorp(await h.get(`https://${SOURCES[src].hosts[0]}/etc/pcorp/datafiles/outagemap/list${abbr}.json`), src, abbr, h));
  }
  return out;
}

export default { sources: SOURCES, regions: REGIONS, adapters };
