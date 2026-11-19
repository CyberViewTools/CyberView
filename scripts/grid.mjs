// Electrical grid outages as map context, no AI model. Run: node scripts/grid.mjs collect | verify | status [--json]
// (behind a proxy: NODE_USE_ENV_PROXY=1). Contract: swarm/handoff/grid-contract.md.
//
//   collect  fetch six public operator feeds -> data/grid/live.json (items) -> incidents (open, update, close)
//            -> data/grid/incidents.json, closed ones appended to data/grid/history/<YYYY-MM>.jsonl
//            -> data/context/grid.json (the map layer) -> status last_grid_at, run log with counts and reason codes
//   verify   shape-check every grid file; exit 1 naming the file and the field
//   status   one-line summary (JSON with --json)
//
// An outage is context, never an attack: nothing here says why the power went out beyond what the operator reports.
// The rule pass (triage) only decides which incidents a grid researcher should check (scripts/grid-desk.mjs, lane B).
// A failing source keeps its previous items (ok:false) for up to KEEP_STALE_HOURS, so the map shows it as stale.
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { existsSync, readdirSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { DATA, ROOT, readJson, writeJson, nowIso, writeRunLog, readStatus } from "./lib/store.mjs";
import { get } from "./lib/net.mjs";

export const AI_BY = "CyberView AI (a Claude model)";
const KEEP_STALE_HOURS = 6;
const CLOSED_KEEP_DAYS = 30;
const CONTEXT_MAX = 60;
const AEMO_NOTICES = 40;          // newest market notices read each run (about a day of notices)
const AEMO_MAX_AGE_HOURS = 24;    // an actual LOR or load shedding with no cancellation seen in this time is dropped

export const DEFAULT_CFG = {
  open_customers: 5000, close_customers: 2000, close_after: 2, research_customers: 50000,
  research_suspicious_customers: 10000, levels: { eskom: 4, ercot: 1, aemo: 3 }, retry_hours: 6, max_tries: 3,
};
export function loadConfig(p = join(ROOT, "config", "grid.json")) {
  const c = readJson(p, {}) || {};
  return { ...DEFAULT_CFG, ...c, levels: { ...DEFAULT_CFG.levels, ...(c.levels || {}) } };
}

// ---------- small helpers ----------
export const str = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const round3 = (x) => Math.round(x * 1000) / 1000;
const okLat = (x) => typeof x === "number" && isFinite(x) && Math.abs(x) <= 90;
const okLng = (x) => typeof x === "number" && isFinite(x) && Math.abs(x) <= 180;
const intOrNull = (x) => (x === null || x === undefined || x === "" || !isFinite(Number(x)) ? null : Math.max(0, Math.round(Number(x))));
const badShape = (why = "") => Object.assign(new Error(`unexpected shape${why ? `: ${why}` : ""}`), { code: "bad_shape" });
const isoS = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
export const slug = (s) => String(s || "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "x";

/** Offset (ms) of an IANA zone from UTC at instant `ms`. */
function zoneOffset(ms, tz) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit",
    day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).formatToParts(new Date(ms)).map((x) => [x.type, x.value]));
  return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour % 24, +p.minute, +p.second) - Math.floor(ms / 1000) * 1000;
}
/** "2026-11-19 13:28:31" (or with a T, optional fraction) wall-clock time in zone tz -> ISO UTC, or "" when unreadable. */
export function zonedToIso(local, tz) {
  const m = String(local || "").match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/);
  if (!m) return "";
  const guess = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
  let t = guess - zoneOffset(guess, tz);
  t = guess - zoneOffset(t, tz);  // second pass settles daylight-saving edges
  return isFinite(t) && +m[1] > 1900 ? isoS(t) : "";
}

// ---------- sources ----------
// hosts: the operator's own hosts; an item url must be https on one of them. page: the operator's public outage page.
export const SOURCES = {
  hydroquebec: { name: "Hydro-Québec", country: "CA", url: "https://pannes.hydroquebec.com/pannes/donnees/v3_0/bisversion.json",
    page: "https://pannes.hydroquebec.com/pannes/", hosts: ["pannes.hydroquebec.com", "www.hydroquebec.com", "infopannes.solutions.hydroquebec.com"] },
  bchydro: { name: "BC Hydro", country: "CA", url: "https://www.bchydro.com/power-outages/app/outages-map-data.json",
    page: "https://www.bchydro.com/power-outages/app/outage-map.html", hosts: ["www.bchydro.com"] },
  ukpn: { name: "UK Power Networks", country: "GB", url: "https://ukpowernetworks.opendatasoft.com/api/explore/v2.1/catalog/datasets/ukpn-live-faults/records",
    page: "https://www.ukpowernetworks.co.uk/power-cut/map", hosts: ["www.ukpowernetworks.co.uk", "ukpowernetworks.opendatasoft.com"] },
  eskom: { name: "Eskom", country: "ZA", url: "https://loadshedding.eskom.co.za/LoadShedding/GetStatus",
    page: "https://loadshedding.eskom.co.za/", hosts: ["loadshedding.eskom.co.za", "www.eskom.co.za"] },
  ercot: { name: "ERCOT", country: "US", url: "https://www.ercot.com/api/1/services/read/dashboards/daily-prc.json",
    page: "https://www.ercot.com/gridmktinfo/dashboards/gridconditions", hosts: ["www.ercot.com"] },
  aemo: { name: "AEMO", country: "AU", url: "https://www.nemweb.com.au/REPORTS/CURRENT/Market_Notice/",
    page: "https://www.aemo.com.au/energy-systems/electricity/national-electricity-market-nem/data-nem/market-notices", hosts: ["www.nemweb.com.au", "www.aemo.com.au"] },
};

/** The url if it is https on one of the source's own hosts, else "". */
export function ownUrl(source, u) {
  const s = String(u || "");
  if (!/^https:\/\/[^\s"'<>\\]+$/.test(s) || s.length > 300) return "";
  try { return (SOURCES[source] && SOURCES[source].hosts.includes(new URL(s).host)) ? s : ""; } catch { return ""; }
}

// Coarse operator regions (one incident per region). Centroids are approximate and used only when the items have no
// coordinates of their own (signal-only sources, or outages without points): approx:true.
export const REGIONS = {
  "hydroquebec|Quebec": { name: "Quebec", lat: 46.5, lng: -72.5 },
  "bchydro|British Columbia": { name: "British Columbia", lat: 49.6, lng: -123.0 },
  "ukpn|London, South East and East of England": { name: "London, South East and East of England", lat: 51.6, lng: 0.2 },
  "eskom|South Africa": { name: "South Africa", lat: -28.5, lng: 25.5 },
  "ercot|Texas": { name: "Texas (ERCOT)", lat: 31.0, lng: -97.5 },
  "aemo|NSW1": { name: "New South Wales", lat: -33.0, lng: 147.0 },
  "aemo|QLD1": { name: "Queensland", lat: -22.5, lng: 144.5 },
  "aemo|VIC1": { name: "Victoria", lat: -37.0, lng: 144.5 },
  "aemo|SA1": { name: "South Australia", lat: -32.0, lng: 136.0 },
  "aemo|TAS1": { name: "Tasmania", lat: -42.0, lng: 146.6 },
};

function item(o) {
  const src = o.source;
  return {
    id: str(o.id, 120), source: src, country: SOURCES[src].country, region: str(o.region, 60), area: str(o.area, 120),
    lat: okLat(o.lat) && okLng(o.lng) ? round3(o.lat) : null, lng: okLat(o.lat) && okLng(o.lng) ? round3(o.lng) : null,
    customers: intOrNull(o.customers), kind: o.kind || "outage", planned: !!o.planned, cause: str(o.cause, 120),
    level: o.level === null || o.level === undefined ? null : intOrNull(o.level), started_at: o.started_at || "",
    restore_est: o.restore_est || "", url: ownUrl(src, o.url || SOURCES[src].page),
  };
}

// --- Hydro-Québec ---
// bismarkers<version>.json is { messages: {}, pannes: [row] } and each row is a positional array. What each index is,
// established on 2026-11-19 from the live data (tests/fixtures/grid/hydroquebec-bismarkers.json) and the public map's
// code (infopannes.solutions.hydroquebec.com main.*.js: the panneCause pipe, the StatutInterruption / equipe enums, and
// the English labels in assets/signalerpanne/i18n/en.json):
//   [0] customers affected (int: 1 .. 3357 in the sample; the map shows it as "clients affected")
//   [1] start, local time America/Montreal "YYYY-MM-DD HH:MM:SS"
//   [2] estimated restoration, same format, "" when not yet estimated
//   [3] "P" = outage (panne) or "I" = planned interruption: both "I" rows carry maintenance cause codes (61, 67 =
//       "Power system repair or improvement") and morning starts; every "P" row is an outage
//   [4] "[lng, lat]" as a JSON string
//   [5] crew status: A assigned, R en route, L on site, N none (the app's equipe enum: ATTRIBUE, ROUTE, SUR_LIEUX, AUCUNE)
//   [6] cause group (always the first digit of [7]); [7] cause code, mapped below with the app's own panneCause table;
//       "" when no cause is given (the app then shows no cause line)
//   [8] a 4-digit location code (Montreal points all carry 1000); its exact meaning is not documented -> not used
//   [9] always "" in the sample -> not used
const HQ_CAUSE_LABEL = {
  DEFAILLANCE: "Equipment malfunction", SURCHARGE: "Grid overload", EQUIPEMENT: "Equipment failure", FOUDRE: "Lightning",
  PRECIPITATIONS: "Precipitation", SINISTRE: "Natural disaster", VENTS: "High winds", TEMPERATURE: "Extreme temperatures",
  ACCIDENT: "Accident or incident", USURE: "Material wear and tear or breakdown", INCENDIE: "Fire or gas leak",
  ACCIDENTEL: "Accidental contact with the power system", PUBLIQUE: "Protection of public safety",
  VEGETATION: "Damage caused by vegetation", OISEAUX: "Damage caused by birds", ANIMAL: "Damage caused by animals",
  POTEAU: "Collision with a pole", URGENT: "Emergency work on the power system", ENTRETIEN: "Power system repair or improvement",
  SECURITE: "Safety during work", PROTECTION: "System protection measure", ELAGAGE: "Vegetation control work", INDETERMINE: "Unknown",
};
const HQ_CODES = {
  11: "DEFAILLANCE", 12: "SURCHARGE", 13: "EQUIPEMENT", 14: "EQUIPEMENT", 15: "EQUIPEMENT", 72: "EQUIPEMENT", 79: "EQUIPEMENT",
  21: "FOUDRE", 22: "PRECIPITATIONS", 24: "SINISTRE", 25: "VENTS", 26: "TEMPERATURE",
  31: "ACCIDENT", 32: "ACCIDENT", 41: "ACCIDENT", 43: "ACCIDENT", 56: "ACCIDENT", 57: "ACCIDENT",
  33: "USURE", 34: "INCENDIE", 42: "ACCIDENTEL", 55: "ACCIDENTEL", 44: "PUBLIQUE", 51: "VEGETATION", 52: "OISEAUX",
  53: "ANIMAL", 54: "POTEAU", 60: "URGENT", 70: "URGENT", 61: "ENTRETIEN", 62: "ENTRETIEN", 63: "ENTRETIEN", 64: "ENTRETIEN",
  65: "ENTRETIEN", 67: "ENTRETIEN", 68: "ENTRETIEN", 69: "ENTRETIEN", 71: "ENTRETIEN", 66: "SECURITE", 73: "PROTECTION",
  74: "PROTECTION", 77: "ELAGAGE", 78: "ELAGAGE",
};
export const hqCause = (code) => { const c = String(code || "").trim(); return c ? HQ_CAUSE_LABEL[HQ_CODES[c] || "INDETERMINE"] : ""; };

export function parseHqVersion(v) {
  const s = String(v == null ? "" : v).trim();
  if (!/^\d{14}$/.test(s)) throw badShape("version");
  return s;
}
export function parseHydroQuebec(d) {
  if (!d || !Array.isArray(d.pannes)) throw badShape();
  const out = [];
  for (const r of d.pannes) {
    if (!Array.isArray(r) || r.length < 8) continue;
    let lng = null, lat = null;
    try { const c = JSON.parse(r[4]); if (Array.isArray(c)) [lng, lat] = c.map(Number); } catch {}
    const started = zonedToIso(r[1], "America/Montreal");
    out.push(item({
      source: "hydroquebec", id: `hydroquebec:${started.replace(/\D/g, "").slice(0, 14)}-${lng == null ? "x" : round3(lng)},${lat == null ? "x" : round3(lat)}`,
      region: "Quebec", area: "", lat, lng, customers: r[0], kind: "outage", planned: r[3] === "I", cause: hqCause(r[7]),
      level: null, started_at: started, restore_est: zonedToIso(r[2], "America/Montreal"),
    }));
  }
  return out;
}

// --- BC Hydro --- an array of outages: id, municipality, area, cause (text), numCustomersOut, dateOff (epoch ms),
// crewEtr (epoch ms, shown when showEtr), latitude, longitude. Planned work says so in the cause text.
export function parseBcHydro(d) {
  if (!Array.isArray(d)) throw badShape();
  return d.filter((r) => r && r.id != null).map((r) => item({
    source: "bchydro", id: `bchydro:${str(r.id, 40)}`, region: "British Columbia",
    area: [r.municipality, r.area].filter(Boolean).map((x) => str(x, 60)).join(": "),
    lat: Number(r.latitude), lng: Number(r.longitude), customers: r.numCustomersOut, kind: "outage",
    planned: /\bplanned\b/i.test(r.cause || ""), cause: r.cause, level: null,
    started_at: isFinite(r.dateOff) && r.dateOff > 0 ? isoS(r.dateOff) : "",
    restore_est: r.showEtr && isFinite(r.crewEtr) && r.crewEtr > 0 ? isoS(r.crewEtr) : "",
  }));
}

// --- UK Power Networks --- Opendatasoft records. powercuttype: Unplanned | Planned | Restored | Multiple ("Multiple"
// rows only group other rows' references, so they are skipped to avoid counting twice). Customers: nocustomeraffected
// for unplanned, noplannedcustomers for planned. Cause: the "incident caused by X affecting" phrase of mainmessage.
// Times carry no zone; they are read as UK wall-clock time (identical to UTC in winter, when they were checked).
export function parseUkpn(d) {
  if (!d || !Array.isArray(d.results)) throw badShape();
  return d.results.filter((r) => r && /^(Unplanned|Planned)$/.test(r.powercuttype) && !r.restoreddatetime).map((r) => {
    const planned = r.powercuttype === "Planned", g = r.geopoint || {};
    const cause = (String(r.mainmessage || "").match(/incident caused by (.+?) affecting/i) || [])[1] || "";
    const created = /^0001/.test(r.creationdatetime || "") ? r.receiveddate : r.creationdatetime || r.receiveddate;
    return item({
      source: "ukpn", id: `ukpn:${str(r.incidentreference, 60)}`, region: "London, South East and East of England",
      area: [r.operatingzone, String(r.postcodesaffected || "").split(";").slice(0, 3).join(", ")].filter(Boolean).join(": "),
      lat: g.lat == null ? null : Number(g.lat), lng: g.lon == null ? null : Number(g.lon),
      customers: planned ? r.noplannedcustomers : r.nocustomeraffected, kind: "outage", planned, cause, level: null,
      started_at: zonedToIso(created, "Europe/London"), restore_est: zonedToIso(r.estimatedrestorationdate, "Europe/London"),
    });
  });
}

// --- Eskom --- GetStatus returns a bare number: load-shedding stage + 1 (1 = not load shedding).
export function parseEskom(text, now = Date.now()) {
  const s = String(text == null ? "" : text).trim();
  if (!/^\d{1,2}$/.test(s) || +s < 1 || +s > 9) throw badShape("eskom status");
  const stage = +s - 1;
  return [item({ source: "eskom", id: "eskom:national", region: "South Africa", area: "National grid", lat: null, lng: null,
    customers: null, kind: "load_shedding", planned: false, cause: "", level: stage, started_at: isoS(now), restore_est: "" })];
}

// --- ERCOT --- daily-prc.json: current_condition.eea_level (0 = no energy emergency), title, state, lastUpdated.
export function parseErcot(d) {
  const c = d && d.current_condition;
  if (!c || !isFinite(Number(c.eea_level))) throw badShape();
  const m = String(d.lastUpdated || "").match(/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})([+-]\d{2})(\d{2})$/);
  const t = m ? Date.parse(`${m[1]}T${m[2]}${m[3]}:${m[4]}`) : NaN;
  return [item({ source: "ercot", id: "ercot:system", region: "Texas", area: str(c.title, 120), lat: null, lng: null,
    customers: null, kind: "grid_emergency", planned: false, cause: "", level: Number(c.eea_level),
    started_at: isFinite(t) ? isoS(t) : "", restore_est: "" })];
}

// --- AEMO --- the Market_Notice directory listing, then each notice as plain text.
const AEMO_BASE = "https://www.nemweb.com.au/Reports/CURRENT/Market_Notice/";
/** Directory listing -> notice file names, newest (highest notice number) first. */
export function parseAemoListing(html) {
  const names = [...String(html || "").matchAll(/HREF="\/Reports\/CURRENT\/Market_Notice\/(NEMITWEB1_MKTNOTICE_\d{8}\.R(\d+))"/gi)]
    .map((m) => ({ file: m[1], n: +m[2] }));
  if (!names.length) throw badShape("aemo listing");
  return [...new Map(names.map((x) => [x.file, x])).values()].sort((a, b) => b.n - a.n).map((x) => x.file);
}
const AEMO_REGION = { NSW: "NSW1", QLD: "QLD1", VIC: "VIC1", SA: "SA1", TAS: "TAS1" };
/** One market notice -> { id, type, ref, created_at, region, reason, file }. Times are market time (AEST, UTC+10). */
export function parseAemoNotice(text, file = "") {
  const s = String(text || "");
  const field = (k) => (s.match(new RegExp(`^${k}\\s*:\\s*(.*)$`, "mi")) || [])[1] || "";
  const id = field("Notice ID").trim();
  if (!/^\d+$/.test(id)) throw badShape("aemo notice");
  const cd = field("Creation Date").match(/(\d{2})\/(\d{2})\/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})/);
  const reason = (s.split(/^Reason\s*:/m)[1] || "").split(/^-{10,}/m)[0];
  const ref = field("External Reference");
  const rm = (ref + " " + reason).match(/\b(NSW|QLD|VIC|SA|TAS)\b(?:1)?\s+region/i) || (ref + " " + reason).match(/Region\s*:\s*(NSW|QLD|VIC|SA|TAS)\b/i);
  return {
    id: +id, type: str(field("Notice Type ID"), 60), ref: str(ref, 200),
    created_at: cd ? isoS(Date.UTC(+cd[3], +cd[2] - 1, +cd[1], +cd[4], +cd[5], +cd[6]) - 10 * 3600e3) : "",
    region: rm ? AEMO_REGION[rm[1].toUpperCase()] : "", reason: str(reason, 600),
    file: /^NEMITWEB1_MKTNOTICE_\d{8}\.R\d+$/.test(file) ? file : "",
  };
}
/** Notices -> the current condition per region: actual LOR1-3 (supply_warning, level n), load shedding (level 3),
 *  directions (supply_warning, level null). Forecast LORs (PASA) are not current conditions and are left out. A later
 *  cancellation clears the condition; conditions older than AEMO_MAX_AGE_HOURS with no cancellation seen are dropped. */
export function aemoItems(notices, now = Date.now()) {
  const state = {};   // region -> { lor: notice+level, shed: notice, dir: notice }
  for (const n of [...notices].filter(Boolean).sort((a, b) => a.id - b.id)) {
    if (!n.region) continue;
    const st = state[n.region] || (state[n.region] = {});
    const ref = n.ref, cancel = /\bcancel/i.test(ref);
    if (/load shed/i.test(ref) && !/forecast|PASA/i.test(ref)) {
      st.shed = cancel || /restor/i.test(ref) ? null : { n, level: 3 };
    } else if (/RESERVE NOTICE/i.test(n.type) && !/forecast|PASA/i.test(ref)) {
      const lv = ref.match(/\bactual\b.*?(?:LOR\s*([123])|Lack Of Reserve Level\s*([123]))/i);
      if (lv) st.lor = cancel ? null : { n, level: +(lv[1] || lv[2]) };
    } else if (/MARKET INTERVENTION/i.test(n.type) && /\bdirection/i.test(ref)) {
      st.dir = cancel ? null : { n, level: null };
    }
  }
  const out = [];
  for (const [region, st] of Object.entries(state)) {
    for (const [kind, x] of [["load_shedding", st.shed], ["supply_warning", st.lor], ["supply_warning", st.dir]]) {
      if (!x || !x.n.created_at || now - Date.parse(x.n.created_at) > AEMO_MAX_AGE_HOURS * 3600e3) continue;
      out.push(item({ source: "aemo", id: `aemo:${x.n.id}`, region, area: (REGIONS[`aemo|${region}`] || {}).name || region,
        lat: null, lng: null, customers: null, kind, planned: false, cause: x.n.ref, level: x.level,
        started_at: x.n.created_at, restore_est: "", url: x.n.file ? AEMO_BASE + x.n.file : "" }));
    }
  }
  return out;
}

async function pool(list, n, fn) {
  const out = []; let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, list.length) }, async () => { while (i < list.length) { const k = i++; out[k] = await fn(list[k]); } }));
  return out;
}

export const ADAPTERS = {
  async hydroquebec() {
    const v = parseHqVersion(await get(SOURCES.hydroquebec.url));
    return parseHydroQuebec(await get(`https://pannes.hydroquebec.com/pannes/donnees/v3_0/bismarkers${v}.json`));
  },
  async bchydro() { return parseBcHydro(await get(SOURCES.bchydro.url)); },
  async ukpn() {
    const items = [], where = encodeURIComponent('powercuttype="Unplanned" or powercuttype="Planned"');
    for (let offset = 0, total = 1; offset < total && offset < 1000; offset += 100) {
      const d = await get(`${SOURCES.ukpn.url}?where=${where}&limit=100&offset=${offset}`);
      total = Number(d && d.total_count) || 0;
      items.push(...parseUkpn(d));
    }
    return items;
  },
  async eskom() { return parseEskom(await get(SOURCES.eskom.url, { as: "text" })); },
  async ercot() { return parseErcot(await get(SOURCES.ercot.url)); },
  async aemo() {
    const files = parseAemoListing(await get(SOURCES.aemo.url, { as: "text" })).slice(0, AEMO_NOTICES);
    const notices = await pool(files, 6, async (f) => {
      try { return parseAemoNotice(await get(AEMO_BASE + f, { as: "text", retries: 1, key: "nemweb-notice" }), f); } catch { return null; }
    });
    if (!notices.some(Boolean)) throw Object.assign(new Error("no notice could be read"), { code: "notices_unreadable" });
    return aemoItems(notices);
  },
};

// ---------- incidents ----------
/** Items -> one summary per operator region. */
export function summarize(items) {
  const g = new Map();
  for (const it of items || []) {
    if (!it || !SOURCES[it.source]) continue;
    const key = `${it.source}|${it.region}`;
    const s = g.get(key) || { key, source: it.source, country: it.country, region: it.region, unplanned: 0, planned: 0,
      level: null, kind: "outage", url: "", causes: new Map(), wx: 0, wy: 0, w: 0, signal: false };
    const c = it.customers || 0;
    if (it.planned) s.planned += c; else s.unplanned += c;
    if (it.level != null) {
      s.signal = true;
      if (s.level == null || it.level > s.level) { s.level = it.level; s.kind = it.kind; s.url = it.url; }
    }
    if (it.cause) s.causes.set(it.cause, (s.causes.get(it.cause) || 0) + c);
    if (it.lat != null && it.lng != null) { const w = Math.max(c, 1); s.wx += it.lng * w; s.wy += it.lat * w; s.w += w; }
    g.set(key, s);
  }
  for (const s of g.values()) {
    if (!s.url) s.url = SOURCES[s.source].page;
    const r = REGIONS[s.key];
    if (s.w) { s.lat = round3(s.wy / s.w); s.lng = round3(s.wx / s.w); s.approx = false; }
    else if (r) { s.lat = r.lat; s.lng = r.lng; s.approx = true; }
    else { s.lat = null; s.lng = null; s.approx = true; }
    s.total = s.unplanned + s.planned;
    s.topCauses = [...s.causes].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([cause, customers]) => ({ cause, customers }));
  }
  return g;
}

const fmt = (n) => Number(n || 0).toLocaleString("en-US");
const LEVEL_WORD = { load_shedding: "load shedding", grid_emergency: "energy emergency", supply_warning: "supply warning" };
function incidentName(source, s) {
  const op = SOURCES[source].name, where = (REGIONS[`${source}|${s.region}`] || {}).name || s.region;
  if (source === "eskom") return str(`${op}: load-shedding stage ${s.level ?? 0}`, 120);
  if (source === "ercot") return str(`${op}: energy emergency (EEA) level ${s.level ?? 0}`, 120);
  if (source === "aemo") return str(s.kind === "load_shedding" ? `${op}: load shedding in ${where}`
    : s.level ? `${op}: actual lack of reserve (LOR${s.level}) in ${where}` : `${op}: ${LEVEL_WORD[s.kind] || "notice"} in ${where}`, 120);
  return str(`${op}: ${fmt(s.total)} customers without power`, 120);
}
const stamp = (iso) => iso.replace(/\D/g, "").slice(0, 12);
const active = (s, cfg) => s.unplanned >= cfg.open_customers || (s.level || 0) >= 1;
const above = (s, cfg) => !!s && (s.unplanned >= cfg.close_customers || (s.level || 0) >= 1);

function applySummary(inc, s, at) {
  const customers = s.signal && !s.total ? null : s.total;
  Object.assign(inc, { kind: s.signal ? s.kind : "outage", name: incidentName(inc.source, s), updated_at: at, customers,
    level: s.level, causes: s.topCauses, lat: s.lat, lng: s.lng, approx: s.approx, url: ownUrl(inc.source, s.url) || SOURCES[inc.source].page });
  // the peak is the most customers out, or for a signal the highest level
  const metric = customers == null ? (s.level || 0) : customers;
  const was = inc.peak_customers != null ? inc.peak_customers : (inc.peak_level || 0);
  if (!inc.peak_at || metric > was) {
    inc.peak_customers = customers; inc.peak_at = at;
    inc.planned_share = s.total ? Math.round((s.planned / s.total) * 100) / 100 : 0;
  }
  if (s.level != null && (inc.peak_level == null || s.level > inc.peak_level)) inc.peak_level = s.level;
}

/** Pure tracker. prev = { open, closed } (incidents.json), items = live items, now = ms or ISO.
 *  Returns { open, closed (last 30 days, newest first), newlyClosed }. */
export function track(prev, items, cfg = DEFAULT_CFG, now = Date.now()) {
  const t = typeof now === "number" ? now : Date.parse(now), at = isoS(t);
  const groups = summarize(items), open = [], newlyClosed = [], seen = new Set();
  for (const old of (prev && prev.open) || []) {
    const key = `${old.source}|${old.region}`; seen.add(key);
    const inc = { ...old, causes: [...(old.causes || [])] };
    const s = groups.get(key);
    if (s) applySummary(inc, s, at);
    else Object.assign(inc, { updated_at: at, customers: inc.customers == null ? null : 0, level: inc.level == null ? null : 0 });
    inc.below_count = above(s, cfg) ? 0 : (inc.below_count || 0) + 1;
    if (inc.below_count >= cfg.close_after) { inc.closed_at = at; newlyClosed.push(inc); } else open.push(inc);
  }
  for (const [key, s] of groups) {
    if (seen.has(key) || !active(s, cfg)) continue;
    const inc = { id: `grid-${s.source}-${slug(s.region)}-${stamp(at)}`, source: s.source, country: s.country, region: s.region,
      kind: "outage", name: "", opened_at: at, updated_at: at, closed_at: "", customers: null, peak_customers: null, peak_at: "",
      level: null, peak_level: null, planned_share: 0, causes: [], lat: null, lng: null, approx: true, url: "",
      research_needed: false, research_reason: "", below_count: 0 };
    applySummary(inc, s, at);
    open.push(inc);
  }
  const cutoff = t - CLOSED_KEEP_DAYS * 864e5, ids = new Set();
  const closed = [...newlyClosed, ...((prev && prev.closed) || [])]
    .filter((c) => c && Date.parse(c.closed_at) >= cutoff && !ids.has(c.id) && ids.add(c.id))
    .sort((a, b) => (b.closed_at > a.closed_at ? 1 : -1));
  return { open, closed, newlyClosed };
}

// ---------- rule pass ----------
const SUSPICIOUS = /cyber|hack|malware|ransom|unknown|investigat/i;
const WEATHER = /\b(storm|wind|weather|snow|ice|tree|lightning|wildfire|heat|flood)/i;
/** Which incidents a grid researcher should check, with a reason code. Research reasons first (suspicious_cause,
 *  grid_level, big), except that an incident that is mostly planned work closes as planned before `big`;
 *  then closures: planned, weather (the operator's top cause is weather), small. */
export function triage(inc, cfg = DEFAULT_CFG) {
  const peak = inc.peak_customers || 0, causes = (inc.causes || []).map((c) => c.cause || "");
  const need = (r) => ({ research_needed: true, research_reason: r }), close = (r) => ({ research_needed: false, research_reason: r });
  if (peak >= cfg.research_suspicious_customers && causes.some((c) => SUSPICIOUS.test(c))) return need("suspicious_cause");
  const lv = (cfg.levels || {})[inc.source];
  if (lv != null && Math.max(inc.level || 0, inc.peak_level || 0) >= lv) return need("grid_level");
  if ((inc.planned_share || 0) > 0.5) return close("planned");
  if (peak >= cfg.research_customers) return need("big");
  if (causes[0] && WEATHER.test(causes[0])) return close("weather");
  return close("small");
}
/** triage, but once an incident has asked for research it keeps asking (the desk leases it by that flag). */
export function applyTriage(inc, cfg) {
  const t = triage(inc, cfg);
  return inc.research_needed && !t.research_needed ? inc : Object.assign(inc, t);
}

// ---------- context layer ----------
export const DECISIONS = ["weather", "equipment", "planned", "supply_shortfall", "wildfire_safety", "third_party",
  "cyber_official", "cyber_reported", "under_investigation", "unknown"];
const rank = (i) => (i.customers != null ? i.customers : (i.level || 0) * 100000);
/** Open incidents -> context items, biggest first (a signal ranks as level x 100,000 customers), max 60, with the grid
 *  desk's result (data/grid/research.json, lane B) when there is one. */
export function contextItems(incidents, research = {}) {
  const open = Array.isArray(incidents) ? incidents : (incidents && incidents.open) || [];
  return open.filter((i) => i && i.id && i.closed_at === "").sort((a, b) => rank(b) - rank(a)).slice(0, CONTEXT_MAX).map((i) => {
    const r = research && typeof research === "object" ? research[i.id] : null;
    const checked = r && DECISIONS.includes(r.decision)
      ? { decision: r.decision, summary: str(r.cause_summary, 300), by: AI_BY } : null;
    return { id: i.id, source: i.source, kind: i.kind, name: str(i.name, 120), country: i.country,
      region: str((REGIONS[`${i.source}|${i.region}`] || {}).name || i.region, 60), customers: i.customers, level: i.level,
      lat: i.lat, lng: i.lng, approx: !!i.approx, since: i.opened_at, cause: str((i.causes && i.causes[0] && i.causes[0].cause) || "", 120),
      checked, url: ownUrl(i.source, i.url) };
  });
}

// ---------- verify ----------
const KINDS = ["outage", "load_shedding", "grid_emergency", "supply_warning"];
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const isStr = (x, n) => typeof x === "string" && x.length <= n;
const isInt = (x) => Number.isInteger(x) && x >= 0;
function checkLatLng(o, e, p) {
  if (!(o.lat === null || okLat(o.lat))) e.push(`${p}.lat: not a latitude or null`);
  if (!(o.lng === null || okLng(o.lng))) e.push(`${p}.lng: not a longitude or null`);
  if ((o.lat === null) !== (o.lng === null)) e.push(`${p}.lat/lng: one is null and the other is not`);
}
export function checkItem(o, p = "item") {
  const e = [];
  if (!o || typeof o !== "object") return [`${p}: not an object`];
  if (!SOURCES[o.source]) e.push(`${p}.source: unknown source`);
  if (!isStr(o.id, 120) || !String(o.id).startsWith(`${o.source}:`)) e.push(`${p}.id: must be "<source>:<id>"`);
  if (!/^[A-Z]{2}$/.test(o.country || "")) e.push(`${p}.country: not ISO-2`);
  if (!isStr(o.region, 60) || !o.region) e.push(`${p}.region: missing`);
  if (!isStr(o.area, 120)) e.push(`${p}.area: not a string <= 120`);
  checkLatLng(o, e, p);
  if (!(o.customers === null || isInt(o.customers))) e.push(`${p}.customers: not an int or null`);
  if (!KINDS.includes(o.kind)) e.push(`${p}.kind: unknown kind`);
  if (typeof o.planned !== "boolean") e.push(`${p}.planned: not a boolean`);
  if (!isStr(o.cause, 120)) e.push(`${p}.cause: not a string <= 120`);
  if (!(o.level === null || isInt(o.level))) e.push(`${p}.level: not an int or null`);
  if (!(o.started_at === "" || ISO.test(o.started_at))) e.push(`${p}.started_at: not ISO`);
  if (!(o.restore_est === "" || ISO.test(o.restore_est))) e.push(`${p}.restore_est: not ISO or ""`);
  if (!(o.url === "" || ownUrl(o.source, o.url) === o.url)) e.push(`${p}.url: not https on the operator's host`);
  return e;
}
export function checkLive(d) {
  const e = [];
  if (!d || typeof d !== "object") return ["root: not an object"];
  if (!ISO.test(d.fetched_at || "")) e.push("fetched_at: not ISO");
  if (!d.sources || typeof d.sources !== "object") e.push("sources: missing");
  else for (const [k, s] of Object.entries(d.sources)) {
    if (!SOURCES[k]) e.push(`sources.${k}: unknown source`);
    if (!s || typeof s.ok !== "boolean") e.push(`sources.${k}.ok: not a boolean`);
    if (!s || !isStr(s.name, 60) || !isStr(s.error, 200) || !isStr(s.url, 300)) e.push(`sources.${k}: name, url or error not a string`);
    if (!s || !(s.fetched_at === "" || ISO.test(s.fetched_at))) e.push(`sources.${k}.fetched_at: not ISO or ""`);
    if (!s || !isInt(s.items)) e.push(`sources.${k}.items: not a count`);
  }
  if (!Array.isArray(d.items)) e.push("items: not an array");
  else d.items.forEach((x, i) => e.push(...checkItem(x, `items[${i}]`)));
  return e;
}
export function checkIncident(o, p = "incident") {
  const e = [];
  if (!o || typeof o !== "object") return [`${p}: not an object`];
  if (!/^grid-[a-z]+-[a-z0-9-]+-\d{12}$/.test(o.id || "")) e.push(`${p}.id: not grid-<source>-<region>-<YYYYMMDDHHmm>`);
  if (!SOURCES[o.source]) e.push(`${p}.source: unknown source`);
  if (!/^[A-Z]{2}$/.test(o.country || "")) e.push(`${p}.country: not ISO-2`);
  if (!isStr(o.region, 60) || !o.region) e.push(`${p}.region: missing`);
  if (!KINDS.includes(o.kind)) e.push(`${p}.kind: unknown kind`);
  if (!isStr(o.name, 120) || !o.name) e.push(`${p}.name: missing or longer than 120`);
  for (const k of ["opened_at", "updated_at"]) if (!ISO.test(o[k] || "")) e.push(`${p}.${k}: not ISO`);
  if (!(o.closed_at === "" || ISO.test(o.closed_at))) e.push(`${p}.closed_at: not ISO or ""`);
  if (!(o.peak_at === "" || ISO.test(o.peak_at))) e.push(`${p}.peak_at: not ISO or ""`);
  for (const k of ["customers", "peak_customers", "level"]) if (!(o[k] === null || isInt(o[k]))) e.push(`${p}.${k}: not an int or null`);
  if (!(typeof o.planned_share === "number" && o.planned_share >= 0 && o.planned_share <= 1)) e.push(`${p}.planned_share: not 0..1`);
  if (!Array.isArray(o.causes) || o.causes.length > 3 || o.causes.some((c) => !c || !isStr(c.cause, 120) || !isInt(c.customers)))
    e.push(`${p}.causes: not up to 3 { cause, customers }`);
  checkLatLng(o, e, p);
  if (typeof o.approx !== "boolean") e.push(`${p}.approx: not a boolean`);
  if (!(o.url === "" || ownUrl(o.source, o.url) === o.url)) e.push(`${p}.url: not https on the operator's host`);
  if (typeof o.research_needed !== "boolean") e.push(`${p}.research_needed: not a boolean`);
  if (!["", "big", "suspicious_cause", "grid_level", "planned", "weather", "small"].includes(o.research_reason)) e.push(`${p}.research_reason: unknown code`);
  return e;
}
export function checkIncidents(d) {
  const e = [];
  if (!d || typeof d !== "object") return ["root: not an object"];
  if (!ISO.test(d.updated_at || "")) e.push("updated_at: not ISO");
  for (const k of ["open", "closed"]) {
    if (!Array.isArray(d[k])) { e.push(`${k}: not an array`); continue; }
    d[k].forEach((x, i) => e.push(...checkIncident(x, `${k}[${i}]`)));
  }
  if (Array.isArray(d.open) && d.open.some((x) => x && x.closed_at !== "")) e.push("open: an open incident has closed_at");
  if (Array.isArray(d.closed) && d.closed.some((x) => x && !x.closed_at)) e.push("closed: a closed incident has no closed_at");
  return e;
}
export function checkContext(d) {
  const e = [];
  if (!d || typeof d !== "object") return ["root: not an object"];
  if (d.layer !== "grid") e.push("layer: not \"grid\"");
  if (!isStr(d.source, 200) || d.source_url !== "") e.push("source/source_url: wrong");
  if (!(d.fetched_at === "" || ISO.test(d.fetched_at || ""))) e.push("fetched_at: not ISO");
  if (typeof d.ok !== "boolean" || !isStr(d.error, 400)) e.push("ok/error: wrong type");
  if (!Array.isArray(d.items) || d.items.length > CONTEXT_MAX) { e.push(`items: not an array of at most ${CONTEXT_MAX}`); return e; }
  d.items.forEach((x, i) => {
    const p = `items[${i}]`;
    if (!x || typeof x !== "object") { e.push(`${p}: not an object`); return; }
    if (!/^grid-/.test(x.id || "")) e.push(`${p}.id: not a grid incident id`);
    if (!SOURCES[x.source]) e.push(`${p}.source: unknown source`);
    if (!KINDS.includes(x.kind)) e.push(`${p}.kind: unknown kind`);
    if (!isStr(x.name, 120) || !x.name) e.push(`${p}.name: missing`);
    if (!(x.customers === null || isInt(x.customers)) || !(x.level === null || isInt(x.level))) e.push(`${p}.customers/level: not int or null`);
    checkLatLng(x, e, p);
    if (typeof x.approx !== "boolean") e.push(`${p}.approx: not a boolean`);
    if (!ISO.test(x.since || "")) e.push(`${p}.since: not ISO`);
    if (!isStr(x.cause, 120)) e.push(`${p}.cause: not a string <= 120`);
    if (!(x.url === "" || ownUrl(x.source, x.url) === x.url)) e.push(`${p}.url: not https on the operator's host`);
    if (x.checked !== null && !(x.checked && DECISIONS.includes(x.checked.decision) && isStr(x.checked.summary, 300) && x.checked.by === AI_BY))
      e.push(`${p}.checked: not null or { decision, summary, by }`);
  });
  return e;
}
export function checkConfig(c) {
  const e = [];
  if (!c || typeof c !== "object") return ["root: not an object"];
  for (const k of ["open_customers", "close_customers", "close_after", "research_customers", "research_suspicious_customers", "retry_hours", "max_tries"])
    if (!(typeof c[k] === "number" && c[k] >= 0)) e.push(`${k}: not a number >= 0`);
  if (c.close_customers > c.open_customers) e.push("close_customers: greater than open_customers");
  if (!c.levels || ["eskom", "ercot", "aemo"].some((k) => !Number.isInteger(c.levels[k]))) e.push("levels: needs eskom, ercot, aemo integers");
  return e;
}

/** Every grid file -> [{ file, errors }] (only files with errors). A missing data file is an error only when `strict`. */
export function verifyAll(root = ROOT, strict = true) {
  const out = [], rel = (p) => p.slice(root.length + 1);
  const check = (p, fn, required = strict) => {
    if (!existsSync(p)) { if (required) out.push({ file: rel(p), errors: ["file: missing"] }); return; }
    let d; try { d = JSON.parse(readFileSync(p, "utf8")); } catch (err) { out.push({ file: rel(p), errors: [`file: not JSON (${str(err.message, 80)})`] }); return; }
    const e = fn(d); if (e.length) out.push({ file: rel(p), errors: e });
  };
  check(join(root, "config", "grid.json"), checkConfig, true);
  check(join(root, "data", "grid", "live.json"), checkLive);
  check(join(root, "data", "grid", "incidents.json"), checkIncidents);
  check(join(root, "data", "context", "grid.json"), checkContext);
  const hd = join(root, "data", "grid", "history");
  if (existsSync(hd)) for (const f of readdirSync(hd).filter((f) => f.endsWith(".jsonl"))) {
    const errors = [];
    if (!/^\d{4}-\d{2}\.jsonl$/.test(f)) errors.push("file: name is not <YYYY-MM>.jsonl");
    readFileSync(join(hd, f), "utf8").split("\n").forEach((line, i) => {
      if (!line.trim()) return;
      let o; try { o = JSON.parse(line); } catch { errors.push(`line ${i + 1}: not JSON`); return; }
      errors.push(...checkIncident(o, `line ${i + 1}`));
      if (!o.closed_at) errors.push(`line ${i + 1}.closed_at: missing`);
    });
    if (errors.length) out.push({ file: `data/grid/history/${f}`, errors });
  }
  return out;
}

// ---------- CLI ----------
const P = {
  live: join(DATA, "grid", "live.json"), incidents: join(DATA, "grid", "incidents.json"), research: join(DATA, "grid", "research.json"),
  history: join(DATA, "grid", "history"), context: join(DATA, "context", "grid.json"),
};
export const CONTEXT_SOURCE = "Grid operators: Hydro-Québec, BC Hydro, UK Power Networks, Eskom, ERCOT, AEMO";

async function collect() {
  const cfg = loadConfig(), started = nowIso(), now = Date.now();
  const old = readJson(P.live, {}) || {}, oldItems = Array.isArray(old.items) ? old.items : [], oldSources = old.sources || {};
  const sources = {}, items = [], failed = [];
  const results = await Promise.all(Object.keys(SOURCES).map(async (k) => {
    try { return [k, await ADAPTERS[k](), null]; } catch (e) { return [k, null, str(e.code || e.message, 60)]; }
  }));
  for (const [k, got, err] of results) {
    const def = SOURCES[k], prev = oldSources[k] || {};
    if (got) {
      const clean = got.filter((x) => checkItem(x).length === 0);
      sources[k] = { name: def.name, url: def.url, ok: true, error: "", fetched_at: nowIso(), items: clean.length };
      items.push(...clean);
    } else {
      const fresh = prev.fetched_at && now - Date.parse(prev.fetched_at) < KEEP_STALE_HOURS * 3600e3;
      const kept = fresh ? oldItems.filter((x) => x && x.source === k && checkItem(x).length === 0) : [];
      sources[k] = { name: def.name, url: def.url, ok: false, error: err, fetched_at: prev.fetched_at || "", items: kept.length };
      items.push(...kept);
      failed.push(`${k}: ${err}`);
    }
  }
  writeJson(P.live, { fetched_at: nowIso(), sources, items });

  const prev = readJson(P.incidents, { open: [], closed: [] }) || { open: [], closed: [] };
  const { open, closed, newlyClosed } = track(prev, items, cfg, now);
  for (const inc of [...open, ...newlyClosed]) applyTriage(inc, cfg);
  writeJson(P.incidents, { updated_at: nowIso(), open, closed });
  if (newlyClosed.length) {
    mkdirSync(P.history, { recursive: true });
    // one line per incident id: the flow and the collect.yml backup can both close the same incident (two writers)
    for (const inc of newlyClosed) {
      const hf = join(P.history, `${inc.closed_at.slice(0, 7)}.jsonl`);
      const ids = new Set((existsSync(hf) ? readFileSync(hf, "utf8") : "").split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l).id; } catch { return ""; } }));
      if (!ids.has(inc.id)) appendFileSync(hf, JSON.stringify(inc) + "\n");
    }
  }
  const research = readJson(P.research, {}) || {};
  const okCount = Object.values(sources).filter((s) => s.ok).length;
  writeJson(P.context, { layer: "grid", source: CONTEXT_SOURCE, source_url: "", fetched_at: nowIso(), ok: okCount > 0,
    error: str(failed.join("; "), 400), items: contextItems(open, research) });

  const st = readStatus(); st.last_grid_at = nowIso(); writeJson(join(DATA, "status.json"), st);
  const prevIds = new Set((prev.open || []).map((i) => i.id)), reasons = {};
  for (const i of [...open, ...newlyClosed]) reasons[i.research_reason] = (reasons[i.research_reason] || 0) + 1;
  const log = { started_at: started, sources: Object.fromEntries(Object.entries(sources).map(([k, s]) => [k, { ok: s.ok, items: s.items, error: s.error }])),
    items: items.length, opened: open.filter((i) => !prevIds.has(i.id)).map((i) => i.id), closed: newlyClosed.map((i) => i.id),
    open: open.length, research: open.filter((i) => i.research_needed).map((i) => ({ id: i.id, reason: i.research_reason })),
    reasons, failed, finished_at: nowIso() };
  writeRunLog("grid", log);
  console.log(`grid: ${Object.entries(sources).map(([k, s]) => `${k} ${s.ok ? s.items : "failed"}`).join(", ")}; ${open.length} open, `
    + `${log.opened.length} opened, ${newlyClosed.length} closed, ${log.research.length} for research` + (failed.length ? `; failed: ${failed.join("; ")}` : ""));
  return okCount ? 0 : 1;
}

function status(asJson) {
  const live = readJson(P.live, null), inc = readJson(P.incidents, null);
  const s = {
    fetched_at: (live && live.fetched_at) || "", sources: live ? Object.fromEntries(Object.entries(live.sources || {}).map(([k, v]) => [k, { ok: v.ok, items: v.items, error: v.error }])) : {},
    items: live && Array.isArray(live.items) ? live.items.length : 0, open: inc && Array.isArray(inc.open) ? inc.open.length : 0,
    closed_30d: inc && Array.isArray(inc.closed) ? inc.closed.length : 0,
    research_needed: inc && Array.isArray(inc.open) ? inc.open.filter((i) => i.research_needed).map((i) => ({ id: i.id, reason: i.research_reason })) : [],
  };
  if (asJson) { console.log(JSON.stringify(s, null, 2)); return 0; }
  const bad = Object.entries(s.sources).filter(([, v]) => !v.ok).map(([k, v]) => `${k} (${v.error})`);
  console.log(`grid: ${Object.keys(s.sources).length - bad.length}/${Object.keys(s.sources).length} sources ok${bad.length ? `, failing: ${bad.join(", ")}` : ""}; `
    + `${s.items} items, ${s.open} open incidents (${s.research_needed.length} for research), ${s.closed_30d} closed in 30 days; fetched ${s.fetched_at || "never"}`);
  return 0;
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "collect") process.exit(await collect());
  if (cmd === "verify") {
    const bad = verifyAll(ROOT, !rest.includes("--lenient"));
    for (const b of bad) for (const e of b.errors.slice(0, 20)) console.error(`${b.file}: ${e}`);
    if (!bad.length) console.log("grid verify: all grid files have the expected shape");
    process.exit(bad.length ? 1 : 0);
  }
  if (cmd === "status") process.exit(status(rest.includes("--json")));
  console.error("usage: node scripts/grid.mjs collect | verify [--lenient] | status [--json]");
  process.exit(2);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
