// Electrical grid outages as map context, no AI model. Run: node scripts/grid.mjs collect | verify | status [--json]
// (behind a proxy: NODE_USE_ENV_PROXY=1). Contract: swarm/handoff/grid-contract.md.
//
//   collect  fetch six public operator feeds and three keyed sources -> data/grid/live.json (items) -> incidents (open,
//            update, close) -> data/grid/incidents.json, closed ones appended to data/grid/history/<YYYY-MM>.jsonl
//            -> data/grid/series/<YYYY-MM-DD>.jsonl (one point per region per 15 minutes; days older than 35 are rolled
//            into data/grid/series/monthly/<YYYY-MM>.json and removed) -> data/context/grid.json (the map layer)
//            -> status last_grid_at, run log with counts and reason codes
//            Keyed sources (EIA, Cloudflare Radar, ENTSO-E): the network proxy adds the key; this code never reads,
//            stores or sends one. Without a key the host answers 400/401/403 and the source is "not connected", which is
//            reported but is not a failure. Contract: swarm/handoff/grid-analysis-contract.md.
//   verify   shape-check every grid file; exit 1 naming the file and the field
//   status   one-line summary (JSON with --json)
//
// An outage is context, never an attack: nothing here says why the power went out beyond what the operator reports.
// The rule pass (triage) only decides which incidents a grid researcher should check (scripts/grid-desk.mjs, lane B).
// A failing source keeps its previous items (ok:false) for up to KEEP_STALE_HOURS, so the map shows it as stale.
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { existsSync, readdirSync, readFileSync, appendFileSync, mkdirSync, unlinkSync } from "node:fs";
import { inflateRawSync } from "node:zlib";
import { DATA, ROOT, readJson, writeJson, nowIso, writeRunLog, readStatus } from "./lib/store.mjs";
import { get } from "./lib/net.mjs";

export const AI_BY = "CyberView AI (a Claude model)";
const KEEP_STALE_HOURS = 6;
const CLOSED_KEEP_DAYS = 30;
const CONTEXT_MAX = 60, OUTAGE_MAX = 400, COLLECT_PARALLEL = 8, SOURCE_TIMEOUT_S = 60;          // incidents, then single outages of show_customers or more
const AEMO_NOTICES = 40;          // newest market notices read each run (about a day of notices)
const AEMO_MAX_AGE_HOURS = 24;    // an actual LOR or load shedding with no cancellation seen in this time is dropped

export const DEFAULT_CFG = {
  open_customers: 5000, close_customers: 2000, close_after: 2, research_customers: 50000,
  research_suspicious_customers: 10000, levels: { eskom: 4, ercot: 1, aemo: 3 }, retry_hours: 6, max_tries: 3, show_customers: 100,
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
  // paused 2026-11-19: the portal's robots.txt (ukpowernetworks.opendatasoft.com) says "Disallow: /api/" for all agents and
  // this feed is under /api/; CyberView skips sources whose robots.txt disallows the feed path until the owner decides
  ukpn: { paused: "robots.txt disallows /api/ on the portal; waiting for the owner's decision", name: "UK Power Networks", country: "GB", url: "https://ukpowernetworks.opendatasoft.com/api/explore/v2.1/catalog/datasets/ukpn-live-faults/records",
    page: "https://www.ukpowernetworks.co.uk/power-cut/map", hosts: ["www.ukpowernetworks.co.uk", "ukpowernetworks.opendatasoft.com"] },
  eskom: { name: "Eskom", country: "ZA", url: "https://loadshedding.eskom.co.za/LoadShedding/GetStatus",
    page: "https://loadshedding.eskom.co.za/", hosts: ["loadshedding.eskom.co.za", "www.eskom.co.za"] },
  ercot: { name: "ERCOT", country: "US", url: "https://www.ercot.com/api/1/services/read/dashboards/daily-prc.json",
    page: "https://www.ercot.com/gridmktinfo/dashboards/gridconditions", hosts: ["www.ercot.com"] },
  aemo: { name: "AEMO", country: "AU", url: "https://www.nemweb.com.au/REPORTS/CURRENT/Market_Notice/",
    page: "https://www.aemo.com.au/energy-systems/electricity/national-electricity-market-nem/data-nem/market-notices", hosts: ["www.nemweb.com.au", "www.aemo.com.au"] },
  // keyed: the environment's network proxy adds the key for `host` (never this code). Signals only: their items are used
  // by scripts/grid-analysis.mjs to corroborate operator incidents and do not open incidents themselves.
  eia: { name: "EIA hourly electric grid monitor", country: "US", keyed: true, host: "api.eia.gov",
    url: "https://api.eia.gov/v2/electricity/rto/region-data/data/?frequency=hourly&data[0]=value&facets[type][]=D&facets[type][]=DF&sort[0][column]=period&sort[0][direction]=desc&length=5000",
    page: "https://www.eia.gov/electricity/gridmonitor/", hosts: ["www.eia.gov"] },
  cfradar: { name: "Cloudflare Radar outage center", country: "", keyed: true, host: "api.cloudflare.com",
    url: "https://api.cloudflare.com/client/v4/radar/annotations/outages?dateRange=7d&format=JSON&limit=200",
    page: "https://radar.cloudflare.com/outage-center", hosts: ["radar.cloudflare.com"] },
  entsoe: { name: "ENTSO-E Transparency Platform", country: "", keyed: true, host: "web-api.tp.entsoe.eu",
    url: "https://web-api.tp.entsoe.eu/api", page: "https://transparency.entsoe.eu/", hosts: ["transparency.entsoe.eu"] },
};

// Approximate country centroids and English names (for keyed sources' items, which come per country, and for matching
// GDACS and news by country name in scripts/grid-analysis.mjs). approx: these are rough points, never a location claim.
export const COUNTRIES = {
  AE: ["United Arab Emirates", 24, 54], AF: ["Afghanistan", 34, 66], AL: ["Albania", 41, 20], AM: ["Armenia", 40.2, 45],
  AO: ["Angola", -12.3, 17.5], AR: ["Argentina", -35, -65], AT: ["Austria", 47.5, 14.5], AU: ["Australia", -25, 134],
  AZ: ["Azerbaijan", 40.3, 47.7], BA: ["Bosnia and Herzegovina", 44, 17.8], BD: ["Bangladesh", 23.7, 90.3], BE: ["Belgium", 50.6, 4.6],
  BG: ["Bulgaria", 42.7, 25.3], BO: ["Bolivia", -16.7, -64.7], BR: ["Brazil", -10, -52], BY: ["Belarus", 53.7, 28],
  CA: ["Canada", 56, -106], CH: ["Switzerland", 46.8, 8.2], CL: ["Chile", -33, -71], CN: ["China", 35, 103],
  CO: ["Colombia", 4, -73], CU: ["Cuba", 21.5, -79], CY: ["Cyprus", 35, 33], CZ: ["Czechia", 49.8, 15.5],
  DE: ["Germany", 51, 10.4], DK: ["Denmark", 56, 9.5], DO: ["Dominican Republic", 18.8, -70.2], DZ: ["Algeria", 28, 2.6],
  EC: ["Ecuador", -1.5, -78.4], EE: ["Estonia", 58.7, 25.5], EG: ["Egypt", 26.7, 30], ES: ["Spain", 40.2, -3.6],
  ET: ["Ethiopia", 8.6, 39.6], FI: ["Finland", 64.5, 26], FR: ["France", 46.6, 2.4], GB: ["United Kingdom", 54, -2.5],
  GE: ["Georgia", 42.2, 43.5], GH: ["Ghana", 7.9, -1], GR: ["Greece", 39, 22], HR: ["Croatia", 45.1, 15.5],
  HT: ["Haiti", 19, -72.7], HU: ["Hungary", 47.2, 19.4], ID: ["Indonesia", -2.5, 118], IE: ["Ireland", 53.2, -8],
  IL: ["Israel", 31.4, 35], IN: ["India", 22, 79], IQ: ["Iraq", 33, 43.7], IR: ["Iran", 32.5, 54], IT: ["Italy", 42.8, 12.5],
  JM: ["Jamaica", 18.1, -77.3], JO: ["Jordan", 31.2, 36.5], JP: ["Japan", 36.5, 138], KE: ["Kenya", 0.2, 37.9],
  KG: ["Kyrgyzstan", 41.5, 74.5], KR: ["South Korea", 36.4, 127.9], KZ: ["Kazakhstan", 48, 67], LB: ["Lebanon", 33.9, 35.9],
  LK: ["Sri Lanka", 7.8, 80.7], LT: ["Lithuania", 55.3, 23.9], LU: ["Luxembourg", 49.8, 6.1], LV: ["Latvia", 56.9, 24.9],
  LY: ["Libya", 27, 17], MA: ["Morocco", 31.8, -6.8], MD: ["Moldova", 47.2, 28.5], MK: ["North Macedonia", 41.6, 21.7],
  MM: ["Myanmar", 21, 96], MX: ["Mexico", 23.6, -102.5], MY: ["Malaysia", 4.2, 102], MZ: ["Mozambique", -18.7, 35.5],
  NG: ["Nigeria", 9.1, 8.7], NL: ["Netherlands", 52.2, 5.5], NO: ["Norway", 61, 9], NP: ["Nepal", 28.4, 84.1],
  NZ: ["New Zealand", -41.5, 172.5], OM: ["Oman", 21, 57], PA: ["Panama", 8.5, -80], PE: ["Peru", -9.2, -75],
  PH: ["Philippines", 12.9, 122], PK: ["Pakistan", 30, 70], PL: ["Poland", 52, 19.4], PR: ["Puerto Rico", 18.2, -66.5],
  PT: ["Portugal", 39.6, -8], PY: ["Paraguay", -23.4, -58.4], QA: ["Qatar", 25.3, 51.2], RO: ["Romania", 45.9, 24.9],
  RS: ["Serbia", 44, 20.9], RU: ["Russia", 61.5, 99], SA: ["Saudi Arabia", 24, 45], SD: ["Sudan", 15.5, 30.2],
  SE: ["Sweden", 62, 15], SG: ["Singapore", 1.35, 103.8], SI: ["Slovenia", 46.1, 14.8], SK: ["Slovakia", 48.7, 19.7],
  SN: ["Senegal", 14.5, -14.4], SY: ["Syria", 35, 38.5], TH: ["Thailand", 15.8, 101], TN: ["Tunisia", 34, 9.5],
  TR: ["Turkey", 39, 35], TW: ["Taiwan", 23.7, 121], TZ: ["Tanzania", -6.4, 34.9], UA: ["Ukraine", 49, 31.5],
  US: ["United States", 39.8, -98.6], UY: ["Uruguay", -32.8, -56], UZ: ["Uzbekistan", 41.4, 64.6], VE: ["Venezuela", 7, -66],
  VN: ["Vietnam", 16, 107.8], YE: ["Yemen", 15.6, 48], ZA: ["South Africa", -29, 25], ZM: ["Zambia", -13.1, 27.8],
  ZW: ["Zimbabwe", -19, 29.8],
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

// ---------- source files (scripts/grid-sources/*.mjs) ----------
// Each file adds sources without touching this one, so builders can work in parallel:
//   export default { sources: { <key>: { name, country, url, page, hosts: [operator hosts], keyed?, signal?: true (reports a grid
//                                        level, not customers: its series points carry level, customers null), attribution?,
//                                        terms_url, terms_ok, customers_served } },
//                    regions: { "<key>|<region>": { name, lat, lng } },
//                    adapters: { <key>: async (h) => [items] } }
// h = { get, item, str, isoOf, zonedToIso (local time + IANA zone -> ISO), centroid, SOURCES }: an adapter fetches with h.get (scripts/lib/net.mjs) and
// returns items built with h.item(...) (the Item shape in swarm/handoff/grid-contract.md). Files whose names start with
// "lib-" hold shared parsers (e.g. a vendor map platform) and are not loaded as sources. A file that fails to load is
// reported in PLUGIN_ERRORS and left out: one broken source file never stops the others.
export const PLUGIN_ERRORS = [];
export const PLUGIN_ADAPTERS = {};
{
  const dir = join(ROOT, "scripts", "grid-sources");
  const files = existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith(".mjs") && !f.startsWith("lib-")).sort() : [];
  for (const f of files) {
    try {
      const m = (await import(pathToFileURL(join(dir, f)).href)).default || {};
      for (const [k, def] of Object.entries(m.sources || {})) {
        if (!/^[a-z0-9-]{2,40}$/.test(k) || SOURCES[k]) { PLUGIN_ERRORS.push(`${f}: source key ${k} invalid or taken`); continue; }
        if (!def || !def.name || !Array.isArray(def.hosts) || !def.hosts.length || !/^https:\/\//.test(def.url || "") || !/^https:\/\//.test(def.page || "")) { PLUGIN_ERRORS.push(`${f}: source ${k} needs name, url, page, hosts`); continue; }
        if (typeof (m.adapters || {})[k] !== "function") { PLUGIN_ERRORS.push(`${f}: source ${k} has no adapter`); continue; }
        SOURCES[k] = { ...def, file: f };
        PLUGIN_ADAPTERS[k] = m.adapters[k];
      }
      for (const [rk, r] of Object.entries(m.regions || {})) if (!REGIONS[rk] && r && r.name && okLat(r.lat) && okLng(r.lng)) REGIONS[rk] = r;
    } catch (e) { PLUGIN_ERRORS.push(`${f}: ${String(e && e.message || e).slice(0, 120)}`); }
  }
}

/** Public operator feeds (incidents, series): built-in and source files; keyed sources and "signal" sources from files
 *  are signals for the analysis only. */
export const OPERATORS = Object.keys(SOURCES).filter((k) => !SOURCES[k].keyed);

function item(o) {
  const src = o.source;
  return {
    id: str(o.id, 120), source: src, country: /^[A-Z]{2}$/.test(o.country || "") ? o.country : SOURCES[src].country, region: str(o.region, 60), area: str(o.area, 120),
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

// ---------- keyed sources ----------
/** Did a keyed host refuse for want of a key? status: HTTP status; body: the reply text when known (null when the fetch
 *  layer does not pass it on, then any 400/401/403 counts). Real no-key replies: tests/fixtures/grid/*-nokey.* */
export function keyMissing(status, body = null) {
  if (![400, 401, 403].includes(Number(status))) return false;
  if (body == null) return true;
  return /API_KEY_MISSING|api[_ ]?key|missing [^.]{0,40}(key|authori[sz]ation|header)|authenticat|unauthori[sz]ed|token/i.test(String(body).slice(0, 2000));
}
export const notConnected = (host) => Object.assign(new Error(`not connected (no key saved for ${host})`), { code: "not_connected" });
/** Run a keyed adapter: a 400/401/403 that reads as "no key" becomes not_connected; anything else stays an error. */
async function keyed(k, fn) {
  try { return await fn(); } catch (e) {
    const m = /^http_(\d{3})$/.exec((e && e.code) || "");
    if (m && keyMissing(+m[1], e.body == null ? null : e.body)) throw notConnected(SOURCES[k].host);
    throw e;
  }
}
const isoOf = (s) => { const t = Date.parse(s || ""); return isFinite(t) ? isoS(t) : ""; };
const centroid = (cc) => (COUNTRIES[cc] ? { lat: COUNTRIES[cc][1], lng: COUNTRIES[cc][2] } : { lat: null, lng: null });

// --- Cloudflare Radar --- GET /radar/annotations/outages, documented at
// https://developers.cloudflare.com/api/resources/radar/subresources/annotations/subresources/outages/methods/get/ (read
// 2026-11-19): { success, result: { annotations: [{ id, dataSource, description, startDate, endDate, eventType,
// linkedUrl, locations: [alpha-2], locationsDetails: [{ code, name }], outage: { outageCause, outageType }, scope, ... }] } }.
// outageCause is one of 17 values; only "POWER_OUTAGE" is a grid signal. One item per location, at the country centroid.
const RADAR_KEEP_ENDED_HOURS = 24;
export function parseCfRadar(d, now = Date.now()) {
  if (!d || d.success === false || !d.result || !Array.isArray(d.result.annotations)) throw badShape("radar");
  const out = [];
  for (const a of d.result.annotations) {
    if (!a || !a.outage || a.outage.outageCause !== "POWER_OUTAGE") continue;
    if (a.eventType && a.eventType !== "OUTAGE") continue;
    const end = isoOf(a.endDate);
    if (end && now - Date.parse(end) > RADAR_KEEP_ENDED_HOURS * 3600e3) continue;
    const names = Object.fromEntries((a.locationsDetails || []).filter((x) => x && x.code).map((x) => [x.code, x.name]));
    const codes = [...new Set([...(a.locations || []), ...Object.keys(names)])].filter((c) => /^[A-Z]{2}$/.test(c));
    for (const cc of codes) {
      out.push(item({ source: "cfradar", id: `cfradar:${str(a.id, 60)}-${cc}`, country: cc,
        region: str(names[cc] || (COUNTRIES[cc] || [])[0] || cc, 60), area: str(a.scope || names[cc] || cc, 120), ...centroid(cc),
        customers: null, kind: "outage", planned: false, cause: str(a.description, 120) || "Power outage", level: null,
        started_at: isoOf(a.startDate), restore_est: end, url: SOURCES.cfradar.page }));
    }
  }
  return out;
}

// ENTSO-E's token can also come from the environment variable ENTSOE_TOKEN (the owner's environment settings offer no
// network secret with the header name SECURITY_TOKEN that ENTSO-E needs). It is read only here, sent only to
// web-api.tp.entsoe.eu as the documented securityToken parameter, and never logged or written: the source's url in
// live.json, run logs and every error message are built without it (net.mjs errors carry a code and the reply, not the url).
export function entsoeToken(env = process.env) {
  const t = String(env.ENTSOE_TOKEN || "").trim();
  return /^[A-Za-z0-9-]{20,100}$/.test(t) && !/^proxy-injected$/i.test(t) ? t : "";
}

// --- EIA --- api.eia.gov/v2/electricity/rto/region-data (Hourly Electric Grid Monitor). Shape read from a real reply
// (tests/fixtures/grid/eia.json, saved 2026-11-19): response.data[] = { period "YYYY-MM-DDTHH" (UTC), respondent,
// respondent-name, type "D" (demand) | "DF" (day-ahead demand forecast), value (string, MWh) }. Per balancing authority:
// the newest complete hours (the newest reported hour is skipped); demand at least EIA_DROP below its forecast AND below the same
// hour a day earlier, for two complete hours in a row, in an authority that carries at
// least EIA_MIN_MWH, is a signal (lost load, or a data fault: EIA's data are preliminary). Signals only: they corroborate
// incidents and never open one. The key is added by the network proxy (header X-Api-Key, tested 2026-11-19).
export const EIA_DROP = 0.25;     // weather moves demand 15-20% day to day (AECI, 2026-11-19); lost load is bigger
export const EIA_MIN_MWH = 500, EIA_MAX_AGE_H = 6, EIA_WINDOW_H = 30;
export function parseEia(d, now = Date.now()) {
  if (!d || !d.response || !Array.isArray(d.response.data)) throw badShape("eia");
  const by = new Map();
  for (const r of d.response.data) {
    if (!r || !/^[A-Z0-9_-]{2,12}$/.test(r.respondent || "") || !/^\d{4}-\d{2}-\d{2}T\d{2}$/.test(r.period || "")) continue;
    const v = Number(r.value); if (!isFinite(v) || (r.type !== "D" && r.type !== "DF")) continue;
    const b = by.get(r.respondent) || { name: str(r["respondent-name"], 100), hours: new Map() };
    const h = b.hours.get(r.period) || {}; h[r.type] = v; b.hours.set(r.period, h); by.set(r.respondent, b);
  }
  const out = [];
  for (const [ba, b] of by) {
    // the newest reported hour is still being filled in (seen 2026-11-19: LDWP 27 vs 2,540 MWh, normal the hour before),
    // so it is skipped, and the drop must hold in the two complete hours before it
    const all = [...b.hours.entries()].filter(([, h]) => h.D != null && h.DF != null).sort((x, y) => (x[0] < y[0] ? 1 : -1));
    const both = all.slice(1, 3);
    if (both.length < 2) continue;
    const [period, h] = both[0], at = Date.parse(period + ":00:00Z");
    if (!isFinite(at) || now - at > EIA_MAX_AGE_H * 3600e3) continue;
    // lost load shows in actual demand, not in the forecast's habits (seen 2026-11-19: SRP misses its forecast by 34-38% at
    // this hour every day; SWPW sat 18% under for 15 hours after a forecast change): a drop counts only when demand is at
    // least EIA_DROP below the forecast AND below the same hour a day earlier, in both complete hours
    const yesterday = (p) => b.hours.get(new Date(Date.parse(p + ":00:00Z") - 864e5).toISOString().slice(0, 13));
    const fall = (p, x) => { const y = yesterday(p); if (!(x.DF >= EIA_MIN_MWH) || !y || !(y.D >= EIA_MIN_MWH) || x.D < 0) return null;
      return { vsForecast: (x.DF - x.D) / x.DF, vsYesterday: (y.D - x.D) / y.D, yD: y.D }; };
    const f0 = fall(period, h), f1 = fall(both[1][0], both[1][1]);
    if (!f0 || !f1 || [f0, f1].some((f) => f.vsForecast < EIA_DROP || f.vsYesterday < EIA_DROP)) continue;
    const drop = f0.vsForecast;
    out.push(item({ source: "eia", id: `eia:${ba}-${period}`, country: "US", region: str(b.name || ba, 60), area: str(`${b.name || ba} (${ba})`, 120),
      ...centroid("US"), customers: null, kind: "supply_warning", planned: false,
      cause: str(`demand ${Math.round(h.D)} MWh: ${Math.round(drop * 100)}% under forecast, ${Math.round(f0.vsYesterday * 100)}% under the same hour yesterday`, 120),
      level: null, started_at: isoS(at), restore_est: "", url: SOURCES.eia.page }));
  }
  return out;
}

// --- ENTSO-E --- documentType A80 (generation unavailability, article 15.1.A&B), documented in the Transparency
// Platform's Postman collection https://documenter.getpostman.com/view/7009892/2s93JtP3F6 (read 2026-11-19): the reply
// is a ZIP of up to 200 Unavailability_MarketDocument XML files; BusinessType A53 = planned maintenance, A54 = forced
// unavailability (unplanned outage); DocStatus A05 active, A09 cancelled, A13 withdrawn; SECURITY_TOKEN may go in a header.
// Errors and empty answers come as an Acknowledgement_MarketDocument (Reason code + text; real reply saved in
// tests/fixtures/grid/entsoe-nokey.xml). Bidding zones read: the EIC codes used in that collection's examples.
export const ENTSOE_ZONES = {
  "10YBE----------2": "BE", "10YAT-APG------L": "AT", "10YFR-RTE------C": "FR", "10YNL----------L": "NL",
  "10Y1001A1001A82H": "DE", "10YCZ-CEPS-----N": "CZ", "10YES-REE------0": "ES", "10YHU-MAVIR----U": "HU",
  "10YSK-SEPS-----K": "SK", "10YCH-SWISSGRIDZ": "CH", "10YFI-1--------U": "FI", "10YHR-HEP------M": "HR", "10YCA-BULGARIA-R": "BG",
};
/** Entries of a ZIP archive (stored or deflated) -> [{ name, text }]. Pure; no dependencies (node:zlib). */
export function unzipEntries(buf, max = 200) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || []);
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 65557); i--) if (b.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw badShape("zip");
  const n = b.readUInt16LE(eocd + 10), out = [];
  let p = b.readUInt32LE(eocd + 16);
  for (let k = 0; k < n && out.length < max; k++) {
    if (p + 46 > b.length || b.readUInt32LE(p) !== 0x02014b50) throw badShape("zip directory");
    const method = b.readUInt16LE(p + 10), csize = b.readUInt32LE(p + 20), nl = b.readUInt16LE(p + 28), xl = b.readUInt16LE(p + 30),
      cl = b.readUInt16LE(p + 32), off = b.readUInt32LE(p + 42), name = b.toString("utf8", p + 46, p + 46 + nl);
    p += 46 + nl + xl + cl;
    if (off + 30 > b.length || b.readUInt32LE(off) !== 0x04034b50) throw badShape("zip entry");
    const start = off + 30 + b.readUInt16LE(off + 26) + b.readUInt16LE(off + 28), raw = b.subarray(start, start + csize);
    if (name.endsWith("/")) continue;
    const data = method === 0 ? raw : method === 8 ? inflateRawSync(raw, { maxOutputLength: 8 << 20 }) : null;
    if (data) out.push({ name, text: data.toString("utf8") });
  }
  return out;
}
const tag = (x, t) => { const m = String(x).match(new RegExp(`<${t.replace(/\./g, "\\.")}(?:\\s[^>]*)?>([^<]*)</${t.replace(/\./g, "\\.")}>`)); return m ? m[1].trim() : ""; };
const xmlText = (s) => String(s || "").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&apos;/g, "'").replace(/&amp;/g, "&");
/** One ENTSO-E XML document -> unavailability items (active, not cancelled or withdrawn, not ended more than 6 h ago).
 *  An Acknowledgement that says there is no matching data -> []; any other Acknowledgement throws its reason. */
export function parseEntsoeXml(xml, now = Date.now()) {
  const s = String(xml || "");
  if (/<Acknowledgement_MarketDocument/.test(s)) {
    const why = xmlText(tag(s.split("<Reason>")[1] || "", "text"));
    if (/no matching data/i.test(why)) return [];
    throw Object.assign(new Error(`entsoe: ${str(why, 80)}`), { code: "entsoe_ack" });
  }
  if (!/<Unavailability_MarketDocument/.test(s)) throw badShape("entsoe document");
  const status = (s.match(/<docStatus>\s*<value>(\w+)<\/value>/) || [])[1] || "A05";
  if (status === "A09" || status === "A13") return [];
  const mrid = tag(s, "mRID"), reason = xmlText(tag((s.split("<Reason>").pop() || ""), "text"));
  const out = [];
  for (const ts of s.split("<TimeSeries>").slice(1)) {
    const zone = tag(ts, "biddingZone_Domain.mRID"), cc = ENTSOE_ZONES[zone] || "";
    const start = isoOf(`${tag(ts, "start_DateAndOrTime.date")}T${tag(ts, "start_DateAndOrTime.time").replace(/Z?$/, "Z")}`);
    const end = isoOf(`${tag(ts, "end_DateAndOrTime.date")}T${tag(ts, "end_DateAndOrTime.time").replace(/Z?$/, "Z")}`);
    if (!cc || !start || (end && now - Date.parse(end) > 6 * 3600e3)) continue;
    const bt = tag(ts, "businessType"), unit = xmlText(tag(ts, "production_RegisteredResource.name"));
    const mw = intOrNull(tag(ts, "production_RegisteredResource.pSRType.powerSystemResources.nominalP"));
    out.push(item({ source: "entsoe", id: `entsoe:${str(mrid, 60)}-${tag(ts, "mRID") || "1"}`, country: cc,
      region: COUNTRIES[cc] ? COUNTRIES[cc][0] : cc, area: str(`${unit || "Generation unit"}${mw != null ? ` (${fmt(mw)} MW)` : ""}`, 120),
      ...centroid(cc), customers: null, kind: "supply_warning", planned: bt === "A53",
      cause: str(reason || (bt === "A54" ? "Forced unavailability" : bt === "A53" ? "Planned maintenance" : ""), 120), level: null,
      started_at: start, restore_est: end, url: SOURCES.entsoe.page }));
  }
  return out;
}
/** A reply body (Buffer: ZIP or XML) -> items from every document in it. */
export function parseEntsoe(body, now = Date.now()) {
  const b = Buffer.isBuffer(body) ? body : Buffer.from(String(body || ""), "utf8");
  const docs = b.length > 4 && b.readUInt32LE(0) === 0x04034b50 ? unzipEntries(b).filter((e) => /\.xml$/i.test(e.name)).map((e) => e.text) : [b.toString("utf8")];
  return docs.flatMap((x) => parseEntsoeXml(x, now));
}
const ymdhm = (ms) => new Date(ms).toISOString().replace(/\D/g, "").slice(0, 12);

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
  // EIA: hourly demand (D) against EIA's own day-ahead forecast (DF) per balancing authority; see parseEia.
  async eia() {
    return keyed("eia", async () => {
      const start = new Date(Date.now() - EIA_WINDOW_H * 3600e3).toISOString().slice(0, 13);
      return parseEia(await get(`${SOURCES.eia.url}&start=${start}`, { retries: 1, timeoutMs: 40000 }));
    });
  },
  async cfradar() { return keyed("cfradar", async () => parseCfRadar(await get(SOURCES.cfradar.url, { retries: 1 }))); },
  async entsoe() {
    return keyed("entsoe", async () => {
      try { return await entsoeFetch(); } catch (e) {
        // a token is set but refused: say so (access not enabled yet, or a wrong token), not "no key saved"
        if (entsoeToken() && /^http_(401|403)$/.test((e && e.code) || "")) throw Object.assign(new Error("token refused by ENTSO-E (API access not enabled yet, or a wrong token)"), { code: "token_refused" });
        throw e;
      }
    });
    async function entsoeFetch() {
      const now = Date.now(), from = ymdhm(now - 24 * 3600e3).slice(0, 10) + "00", to = ymdhm(now + 24 * 3600e3).slice(0, 10) + "00", out = [];
      const tok = entsoeToken();
      for (const zone of Object.keys(ENTSOE_ZONES)) {
        // the reply is a ZIP, fetched as bytes (net.mjs as:"buffer")
        const body = await get(`${SOURCES.entsoe.url}?documentType=A80&BusinessType=A54&BiddingZone_Domain=${encodeURIComponent(zone)}&periodStart=${from}&periodEnd=${to}${tok ? `&securityToken=${tok}` : ""}`,
          { as: "buffer", retries: 1, key: "entsoe" }).catch((e) => { if (e && e.code === "bad_json") e.code = "needs_binary_fetch"; throw e; });
        if (!Buffer.isBuffer(body) && !(body instanceof ArrayBuffer)) throw Object.assign(new Error("needs a binary fetch"), { code: "needs_binary_fetch" });
        out.push(...parseEntsoe(Buffer.from(body), now));
      }
      return out;
    }
  },
};
const HELPERS = { get, item, str, isoOf, zonedToIso, centroid, SOURCES };
for (const [k, fn] of Object.entries(PLUGIN_ADAPTERS)) ADAPTERS[k] = () => fn(HELPERS);

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
  // any other signal source (source files): name the condition and its level, never "0 customers"
  if (SIGNAL_SOURCES.has(source) || (s.signal && !s.total)) return str(`${op}: ${LEVEL_WORD[s.kind] || "grid notice"} level ${s.level ?? 0}${where ? ` in ${where}` : ""}`, 120);
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
export const WEATHER = /\b(storm|wind|weather|snow|ice|tree|lightning|wildfire|heat|flood)/i;
/** Which incidents a grid researcher should check, with a reason code. Research reasons first (suspicious_cause,
 *  grid_level, big), except that an incident that is mostly planned work closes as planned before `big`;
 *  then `corroborated` (scripts/grid-analysis.mjs found an anomaly with three kinds of signal, or an internet outage
 *  without a weather cause: extra.corroborated), then closures: planned, weather (the operator's top cause is weather), small. */
export function triage(inc, cfg = DEFAULT_CFG, extra = {}) {
  const peak = inc.peak_customers || 0, causes = (inc.causes || []).map((c) => c.cause || "");
  const need = (r) => ({ research_needed: true, research_reason: r }), close = (r) => ({ research_needed: false, research_reason: r });
  if (peak >= cfg.research_suspicious_customers && causes.some((c) => SUSPICIOUS.test(c))) return need("suspicious_cause");
  const lv = (cfg.levels || {})[inc.source];
  if (lv != null && Math.max(inc.level || 0, inc.peak_level || 0) >= lv) return need("grid_level");
  if ((inc.planned_share || 0) > 0.5) return close("planned");
  if (peak >= cfg.research_customers) return need("big");
  if (extra && extra.corroborated) return need("corroborated");
  if (causes[0] && WEATHER.test(causes[0])) return close("weather");
  return close("small");
}
/** triage, but once an incident has asked for research it keeps asking (the desk leases it by that flag). */
export function applyTriage(inc, cfg, extra = {}) {
  const t = triage(inc, cfg, extra);
  return inc.research_needed && !t.research_needed ? inc : Object.assign(inc, t);
}

// ---------- context layer ----------
export const DECISIONS = ["weather", "equipment", "planned", "supply_shortfall", "wildfire_safety", "third_party",
  "cyber_official", "cyber_reported", "under_investigation", "unknown"];
const rank = (i) => (i.customers != null ? i.customers : (i.level || 0) * 100000);
/** Open incidents -> context items, biggest first (a signal ranks as level x 100,000 customers), max 60, with the grid
 *  desk's result (data/grid/research.json, lane B) when there is one. */
export function contextItems(incidents, research = {}, live = [], cfg = DEFAULT_CFG) {
  const open = Array.isArray(incidents) ? incidents : (incidents && incidents.open) || [];
  const inc = open.filter((i) => i && i.id && i.closed_at === "").sort((a, b) => rank(b) - rank(a)).slice(0, CONTEXT_MAX).map((i) => {
    const r = research && typeof research === "object" ? research[i.id] : null;
    const checked = r && DECISIONS.includes(r.decision)
      ? { decision: r.decision, summary: str(r.cause_summary, 300), by: AI_BY } : null;
    return { id: i.id, scope: "incident", source: i.source, kind: i.kind, name: str(i.name, 120), country: i.country,
      region: str((REGIONS[`${i.source}|${i.region}`] || {}).name || i.region, 60), customers: i.customers, level: i.level,
      lat: i.lat, lng: i.lng, approx: !!i.approx, since: i.opened_at, cause: str((i.causes && i.causes[0] && i.causes[0].cause) || "", 120),
      planned: false, checked, url: ownUrl(i.source, i.url) };
  });
  // single outages (owner, 2026-11-19: show anything over 100): every operator outage with a location and at least
  // show_customers customers, biggest first; planned work is kept and labelled as planned
  const min = Math.max(1, Number(cfg && cfg.show_customers) || 100);
  const outs = (Array.isArray(live) ? live : []).filter((x) => x && x.kind === "outage" && OPERATORS.includes(x.source)
      && Number.isInteger(x.customers) && x.customers >= min && x.lat !== null && x.lng !== null && okLat(x.lat) && okLng(x.lng))
    .sort((a, b) => b.customers - a.customers).slice(0, OUTAGE_MAX).map((x) => ({
      id: str(`grid-o-${String(x.id).toLowerCase().replace(/[^a-z0-9]+/g, "-")}`, 120), scope: "outage", source: x.source, kind: "outage",
      name: str(`${SOURCES[x.source].name}: ${x.customers.toLocaleString("en-US")} customers without power${x.planned ? " (planned work)" : ""}`, 120),
      country: x.country, region: str((x.area || x.region), 60), customers: x.customers, level: null, lat: x.lat, lng: x.lng, approx: false,
      since: ISO.test(x.started_at || "") ? x.started_at : "", cause: str(x.cause, 120), planned: !!x.planned, checked: null,
      url: ownUrl(x.source, x.url) }));
  return [...inc, ...outs];
}

// ---------- verify ----------
export const REASONS = ["", "big", "suspicious_cause", "grid_level", "corroborated", "planned", "weather", "small"];
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
  if (!REASONS.includes(o.research_reason)) e.push(`${p}.research_reason: unknown code`);
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
  if (!Array.isArray(d.items) || d.items.length > CONTEXT_MAX + OUTAGE_MAX) { e.push(`items: not an array of at most ${CONTEXT_MAX + OUTAGE_MAX}`); return e; }
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
    if (!["incident", "outage", undefined].includes(x.scope)) e.push(`${p}.scope: not incident or outage`);
    if (!(ISO.test(x.since || "") || (x.scope === "outage" && x.since === ""))) e.push(`${p}.since: not ISO`);
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

// ---------- time series ----------
// data/grid/series/<YYYY-MM-DD>.jsonl: { at (start of the 15-minute slot), source, region, customers, unplanned, level },
// one line per operator region per slot. Regions an ok source did not report are written as zero, so a quiet hour counts.
export const SERIES_KEEP_DAYS = 35;          // the baseline reads 4 weeks; older days live on in the monthly roll-up (about 3.5 MB in git, not 9)
const SLOT = 15 * 6e4;
export const slotIso = (ms) => isoS(Math.floor(ms / SLOT) * SLOT);
// signal sources report a grid level, not customers: built-in ones plus any source file entry with signal: true
const SIGNAL_SOURCES = new Set(["eskom", "ercot", "aemo", ...Object.keys(SOURCES).filter((k) => SOURCES[k].signal === true || SOURCES[k].kind === "signal")]);
/** Live items of the sources that answered (okSources: their keys) -> one point per operator region for the slot of `now`. */
export function seriesPoints(items, okSources, now = Date.now()) {
  const at = slotIso(now), ok = new Set(okSources || []), groups = summarize((items || []).filter((x) => x && ok.has(x.source) && OPERATORS.includes(x.source)));
  const out = new Map();
  for (const s of groups.values()) out.set(s.key, { at, source: s.source, region: s.region, customers: s.signal && !s.total ? null : s.total, unplanned: s.unplanned, level: s.level });
  for (const key of Object.keys(REGIONS)) {
    const [source, region] = key.split("|");
    if (!ok.has(source) || out.has(key)) continue;
    const sig = SIGNAL_SOURCES.has(source);
    out.set(key, { at, source, region, customers: sig ? null : 0, unplanned: 0, level: sig ? 0 : null });
  }
  return [...out.values()];
}
const seriesKey = (p) => `${p.source}|${p.region}|${p.at}`;
/** Append points to their day files, skipping a region+slot that is already there (two writers: the flow and collect.yml). */
export function appendSeries(dir, points) {
  let n = 0;
  const byDay = new Map();
  for (const p of points || []) { const d = p.at.slice(0, 10); (byDay.get(d) || byDay.set(d, []).get(d)).push(p); }
  for (const [day, ps] of byDay) {
    mkdirSync(dir, { recursive: true });
    const f = join(dir, `${day}.jsonl`), have = new Set(readLines(f).map(seriesKey));
    const add = ps.filter((p) => !have.has(seriesKey(p)) && have.add(seriesKey(p)));
    if (add.length) { appendFileSync(f, add.map((p) => JSON.stringify(p)).join("\n") + "\n"); n += add.length; }
  }
  return n;
}
/** A jsonl file -> parsed objects (bad lines skipped; missing file -> []). */
export function readLines(f) {
  if (!existsSync(f)) return [];
  return readFileSync(f, "utf8").split("\n").filter((l) => l.trim()).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter((x) => x && typeof x === "object");
}
/** One day's points -> { "<source>|<region>": { max, mean, points, level_max } } (max/mean of unplanned customers). */
export function rollupDay(points) {
  const g = {}, seen = new Set();
  for (const p of points || []) {
    if (!p || !p.source || seen.has(seriesKey(p))) continue;
    seen.add(seriesKey(p));
    const k = `${p.source}|${p.region}`, r = g[k] || (g[k] = { max: 0, sum: 0, points: 0, level_max: null });
    const u = Number(p.unplanned) || 0;
    r.max = Math.max(r.max, u); r.sum += u; r.points++;
    if (p.level != null) r.level_max = Math.max(r.level_max == null ? 0 : r.level_max, p.level);
  }
  return Object.fromEntries(Object.entries(g).map(([k, r]) => [k, { max: r.max, mean: Math.round(r.sum / r.points), points: r.points, level_max: r.level_max }]));
}
/** Days older than keepDays (by file name, UTC) -> folded into monthly/<YYYY-MM>.json { month, days: { <date>: rollupDay } }
 *  and the day file removed (derived numbers: the roll-up keeps them). Returns the dates rolled up. */
export function rollupSeries(dir, now = Date.now(), keepDays = SERIES_KEEP_DAYS) {
  if (!existsSync(dir)) return [];
  const cutoff = new Date(now - keepDays * 864e5).toISOString().slice(0, 10), rolled = [];
  for (const f of readdirSync(dir).filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f)).sort()) {
    const day = f.slice(0, 10);
    if (day >= cutoff) continue;
    const mf = join(dir, "monthly", `${day.slice(0, 7)}.json`), m = readJson(mf, null) || { month: day.slice(0, 7), days: {} };
    m.days = { ...(m.days || {}), [day]: rollupDay(readLines(join(dir, f))) };
    writeJson(mf, m);
    unlinkSync(join(dir, f));
    rolled.push(day);
  }
  return rolled;
}
export function checkSeriesLine(o, p = "point") {
  const e = [];
  if (!o || typeof o !== "object") return [`${p}: not an object`];
  if (!ISO.test(o.at || "") || Date.parse(o.at) % SLOT) e.push(`${p}.at: not the ISO start of a 15-minute slot`);
  if (!OPERATORS.includes(o.source)) e.push(`${p}.source: not an operator source`);
  if (!isStr(o.region, 60) || !o.region) e.push(`${p}.region: missing`);
  for (const k of ["customers", "level"]) if (!(o[k] === null || isInt(o[k]))) e.push(`${p}.${k}: not an int or null`);
  if (!isInt(o.unplanned)) e.push(`${p}.unplanned: not a count`);
  return e;
}
export function checkMonthly(d, name = "") {
  const e = [];
  if (!d || typeof d !== "object" || !d.days || typeof d.days !== "object") return ["root: not { month, days }"];
  if (!/^\d{4}-\d{2}$/.test(d.month || "") || (name && name !== `${d.month}.json`)) e.push("month: not <YYYY-MM> matching the file name");
  for (const [day, regions] of Object.entries(d.days)) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || day.slice(0, 7) !== d.month) e.push(`days.${day}: not a date in this month`);
    for (const [k, r] of Object.entries(regions || {})) {
      if (!r || !isInt(r.max) || !isInt(r.mean) || !isInt(r.points) || r.mean > r.max || !(r.level_max === null || isInt(r.level_max)))
        e.push(`days.${day}.${k}: not { max, mean <= max, points, level_max }`);
    }
  }
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
  out.push(...verifySeries(root));
  return out;
}
/** Series day files and monthly roll-ups -> [{ file, errors }]. */
export function verifySeries(root = ROOT) {
  const out = [], sd = join(root, "data", "grid", "series");
  if (!existsSync(sd)) return out;
  for (const f of readdirSync(sd).filter((f) => f.endsWith(".jsonl"))) {
    const errors = [], day = f.slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f)) errors.push("file: name is not <YYYY-MM-DD>.jsonl");
    readFileSync(join(sd, f), "utf8").split("\n").forEach((line, i) => {
      if (!line.trim()) return;
      let o; try { o = JSON.parse(line); } catch { errors.push(`line ${i + 1}: not JSON`); return; }
      errors.push(...checkSeriesLine(o, `line ${i + 1}`));
      if (o && typeof o.at === "string" && o.at.slice(0, 10) !== day) errors.push(`line ${i + 1}.at: not on ${day}`);
    });
    if (errors.length) out.push({ file: `data/grid/series/${f}`, errors });
  }
  const md = join(sd, "monthly");
  if (existsSync(md)) for (const f of readdirSync(md).filter((f) => f.endsWith(".json"))) {
    let d; try { d = JSON.parse(readFileSync(join(md, f), "utf8")); } catch { out.push({ file: `data/grid/series/monthly/${f}`, errors: ["file: not JSON"] }); continue; }
    const e = checkMonthly(d, f); if (e.length) out.push({ file: `data/grid/series/monthly/${f}`, errors: e });
  }
  return out;
}

/** A source's attribution as its licence asks for it, with {year} and {date} (UTC) filled in. */
export const attributionText = (a, now = Date.now()) => str(String(a).replace(/\{year\}/g, new Date(now).toISOString().slice(0, 4)).replace(/\{date\}/g, new Date(now).toISOString().slice(0, 10)), 400);

// ---------- CLI ----------
const P = {
  live: join(DATA, "grid", "live.json"), incidents: join(DATA, "grid", "incidents.json"), research: join(DATA, "grid", "research.json"),
  history: join(DATA, "grid", "history"), context: join(DATA, "context", "grid.json"), series: join(DATA, "grid", "series"),
  analysis: join(DATA, "grid", "analysis.json"),
};
export const CONTEXT_SOURCE = str(`Grid operators (${OPERATORS.length}): ${OPERATORS.map((k) => SOURCES[k].name).join(", ")}`, 200);

async function collect() {
  const cfg = loadConfig(), started = nowIso(), now = Date.now();
  const old = readJson(P.live, {}) || {}, oldItems = Array.isArray(old.items) ? old.items : [], oldSources = old.sources || {};
  const sources = {}, items = [], failed = [], unkeyed = [];
  // at most COLLECT_PARALLEL sources at once, each capped at SOURCE_TIMEOUT_S, so one slow utility never holds up a cycle
  const cap = (k) => new Promise((_, rej) => setTimeout(() => rej(Object.assign(new Error("timeout"), { code: "source_timeout" })), SOURCE_TIMEOUT_S * 1000).unref());
  const results = await pool(Object.keys(SOURCES), COLLECT_PARALLEL, async (k) => {
    if (SOURCES[k].paused) return [k, null, str(`paused: ${SOURCES[k].paused}`, 120)];
    try { return [k, await Promise.race([ADAPTERS[k](), cap(k)]), null]; } catch (e) { return [k, null, e && e.code === "not_connected" ? str(e.message, 120) : str((e && (e.code || e.message)) || "error", 60)]; }
  });
  for (const [k, got, err] of results) {
    const def = SOURCES[k], prev = oldSources[k] || {};
    if (got) {
      const clean = got.filter((x) => checkItem(x).length === 0);
      sources[k] = { name: def.name, url: def.url, ok: true, error: "", fetched_at: nowIso(), items: clean.length, country: def.country || "", ...(def.paused ? { paused: true } : {}), ...(def.attribution ? { attribution: attributionText(def.attribution) } : {}) };
      items.push(...clean);
    } else {
      const fresh = prev.fetched_at && now - Date.parse(prev.fetched_at) < KEEP_STALE_HOURS * 3600e3;
      const kept = fresh && !def.paused ? oldItems.filter((x) => x && x.source === k && checkItem(x).length === 0) : [];
      sources[k] = { name: def.name, url: def.url, ok: false, error: err, fetched_at: prev.fetched_at || "", items: kept.length, country: def.country || "", ...(def.paused ? { paused: true } : {}), ...(def.attribution ? { attribution: attributionText(def.attribution) } : {}) };
      items.push(...kept);
      // a keyed source without a key is reported, not counted as a failure
      if (/^not connected/.test(err)) unkeyed.push(k); else failed.push(`${k}: ${err}`);
    }
  }
  writeJson(P.live, { fetched_at: nowIso(), sources, items });

  const prev = readJson(P.incidents, { open: [], closed: [] }) || { open: [], closed: [] };
  const { open, closed, newlyClosed } = track(prev, items, cfg, now);
  // the analysis (scripts/grid-analysis.mjs, previous run) names incidents its signals corroborate
  const corroborated = new Set(((readJson(P.analysis, {}) || {}).research || []).map((r) => r && r.id));
  for (const inc of [...open, ...newlyClosed]) applyTriage(inc, cfg, { corroborated: corroborated.has(inc.id) });
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
  let seriesAdded = 0, rolled = [];
  try {
    seriesAdded = appendSeries(P.series, seriesPoints(items, Object.keys(sources).filter((k) => sources[k].ok), now));
    rolled = rollupSeries(P.series, now);
  } catch (e) { failed.push(`series: ${str(e.message, 60)}`); }
  const research = readJson(P.research, {}) || {};
  const okCount = Object.values(sources).filter((s) => s.ok).length;
  writeJson(P.context, { layer: "grid", source: CONTEXT_SOURCE, source_url: "", fetched_at: nowIso(), ok: okCount > 0,
    error: str(failed.join("; "), 400), items: contextItems(open, research, items, cfg) });

  const st = readStatus(); st.last_grid_at = nowIso(); writeJson(join(DATA, "status.json"), st);
  const prevIds = new Set((prev.open || []).map((i) => i.id)), reasons = {};
  for (const i of [...open, ...newlyClosed]) reasons[i.research_reason] = (reasons[i.research_reason] || 0) + 1;
  const log = { started_at: started, sources: Object.fromEntries(Object.entries(sources).map(([k, s]) => [k, { ok: s.ok, items: s.items, error: s.error }])),
    items: items.length, opened: open.filter((i) => !prevIds.has(i.id)).map((i) => i.id), closed: newlyClosed.map((i) => i.id),
    open: open.length, research: open.filter((i) => i.research_needed).map((i) => ({ id: i.id, reason: i.research_reason })),
    reasons, failed, not_connected: unkeyed, series_points: seriesAdded, rolled_up: rolled, finished_at: nowIso() };
  writeRunLog("grid", log);
  console.log(`grid: ${Object.entries(sources).map(([k, s]) => `${k} ${s.ok ? s.items : unkeyed.includes(k) ? "not connected" : "failed"}`).join(", ")}; ${open.length} open, `
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
  const bad = Object.entries(s.sources).filter(([, v]) => !v.ok && !/^not connected/.test(v.error)).map(([k, v]) => `${k} (${v.error})`);
  const unkeyed = Object.entries(s.sources).filter(([, v]) => !v.ok && /^not connected/.test(v.error)).map(([k]) => k);
  console.log(`grid: ${Object.keys(s.sources).length - bad.length - unkeyed.length}/${Object.keys(s.sources).length} sources ok${bad.length ? `, failing: ${bad.join(", ")}` : ""}${unkeyed.length ? `, not connected: ${unkeyed.join(", ")}` : ""}; `
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
