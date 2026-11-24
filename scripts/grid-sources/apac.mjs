// Grid sources, lane "apac" (2026-11-24): Asia-Pacific and Oceania. Four New Zealand distribution networks' own outage
// feeds (MainPower, Top Energy, The Lines Company, EA Networks) and AEMO's Western Australian market advisories (a signal:
// the declared operating state of the South West Interconnected System). Loaded by scripts/grid.mjs (see the comment above
// PLUGIN_ERRORS there). Parsers are pure and exported, tested on real replies saved on 2026-11-24
// (tests/fixtures/grid/apac/, trimmed; tests/unit/grid-apac.test.mjs).
//
// Every item carries what the operator's reply gives for that outage: customers off, the operator's reason, planned or not,
// start and estimated restoration, the operator's own area name and the outage's own point (or the centre of its polygon).
// Nothing is inferred: a field the reply does not give is left empty.
//
// Routes checked 2026-11-24 (plain GET, no key, cookie or login; robots.txt allows or is absent; terms below):
//  - MainPower: outages.mainpower.co.nz/jobs (the JSON its outage map reads). No robots.txt on that host (404);
//    www.mainpower.co.nz robots allows all. The site publishes a privacy policy and no website terms of use: silent.
//  - Top Energy: outages.topenergy.co.nz/api/outages and /api/outages/regions (its outage map's JSON). robots.txt "Allow: /".
//    No website terms, only a privacy policy: silent.
//  - The Lines Company: outages.thelinescompany.co.nz reads outages.json and shutdowns.json from its own S3 bucket
//    (tlc-outage-website-outage-data-production). robots.txt allows. Its "Standard Terms" cover the network agreement and
//    say nothing about the website: silent. "We've around 18,000 customers and 24,000 connection points" (about-us page).
//  - EA Networks: www.eanetworks.co.nz/power/outages embeds its outage app (outages-eanetworks-co-nz.vercel.app), whose
//    /api/get-outages?tab=current answers JSON. robots.txt on eanetworks.co.nz "Allow: /"; none on the app host. No website
//    terms, only a privacy policy: silent.
//  - AEMO (WA): data.wa.aemo.com.au market-advisories.csv, updated about every 30 minutes. No robots.txt (404). The data
//    portal's notice says only that AEMO publishes the data to inform about the WEM and is not liable for it: silent.
//    (www.aemo.com.au's copyright page answers 403 to automated readers and could not be read.)

const str = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const isoS = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
const badShape = (why = "") => Object.assign(new Error(`unexpected shape${why ? `: ${why}` : ""}`), { code: "bad_shape" });
export const stamp = (arr, at) => Object.defineProperty(arr, "data_at", { value: at || "", enumerable: false, configurable: true });
const num = (x) => (x === null || x === undefined || x === "" || !isFinite(Number(x)) ? null : Number(x));
const okLat = (x) => typeof x === "number" && isFinite(x) && Math.abs(x) <= 90 && x !== 0;
const okLng = (x) => typeof x === "number" && isFinite(x) && Math.abs(x) <= 180 && x !== 0;
const pt = (lat, lng) => { const a = num(lat), b = num(lng); return okLat(a) && okLng(b) ? { lat: a, lng: b } : { lat: null, lng: null }; };
const mean = (pts) => {
  const ok = pts.filter((p) => p && p.lat != null && p.lng != null);
  return ok.length ? { lat: ok.reduce((a, p) => a + p.lat, 0) / ok.length, lng: ok.reduce((a, p) => a + p.lng, 0) / ok.length } : { lat: null, lng: null };
};
const ENT = { amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'", apos: "'", nbsp: " " };
const unent = (s) => String(s || "").replace(/&(amp|lt|gt|quot|#39|apos|nbsp);/g, (_, k) => ENT[k]);

/** Milliseconds of the wall-clock time y-mo-d h:mi in IANA zone tz (daylight saving included), or NaN. */
export function zonedMs(y, mo, d, h, mi, tz) {
  const guess = Date.UTC(+y, +mo - 1, +d, +h, +mi);
  if (!isFinite(guess)) return NaN;
  const off = (t) => {
    const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit",
      day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).formatToParts(new Date(t)).map((x) => [x.type, x.value]));
    return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour % 24, +p.minute, +p.second) - t;
  };
  let t = guess - off(guess);
  t = guess - off(t);   // second pass settles daylight-saving edges
  return t;
}
const NZ = "Pacific/Auckland";
const nzIso = (y, mo, d, h, mi) => { const t = zonedMs(y, mo, d, h, mi, NZ); return isFinite(t) ? isoS(t) : ""; };
/** "24/11/2026 09:22" New Zealand time -> ISO UTC, or "". */
export const nzDmyToIso = (s) => { const m = String(s || "").match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}):(\d{2})/); return m ? nzIso(m[3], m[2], m[1], m[4], m[5]) : ""; };
/** "2026-11-25" + "09:00" New Zealand time -> ISO UTC, or "". */
export const nzDateTimeToIso = (date, time) => {
  const d = String(date || "").match(/^(\d{4})-(\d{2})-(\d{2})$/), t = String(time || "").match(/^(\d{1,2}):(\d{2})/);
  return d && t ? nzIso(d[1], d[2], d[3], t[1], t[2]) : "";
};
const MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
/** "25th November 03:00 pm" New Zealand time (no year: the year is the one of refMs in New Zealand, or the next when the
 *  date would fall more than 180 days before refMs) -> ISO UTC, or "". */
export function nzDayMonthToIso(s, refMs) {
  const m = String(s || "").trim().toLowerCase().match(/^(\d{1,2})(?:st|nd|rd|th)?\s+([a-z]+)\s+(\d{1,2}):(\d{2})\s*(am|pm)$/);
  if (!m || !isFinite(refMs)) return "";
  const mo = MONTHS.indexOf(m[2]) + 1;
  if (!mo) return "";
  const h = (+m[3] % 12) + (m[5] === "pm" ? 12 : 0);
  const y0 = +new Intl.DateTimeFormat("en-US", { timeZone: NZ, year: "numeric" }).format(new Date(refMs));
  let t = zonedMs(y0, mo, +m[1], h, +m[4], NZ);
  if (t < refMs - 180 * 864e5) t = zonedMs(y0 + 1, mo, +m[1], h, +m[4], NZ);
  return isFinite(t) ? isoS(t) : "";
}
const isoMs = (s) => { const t = Date.parse(s || ""); return isFinite(t) ? t : NaN; };

export const SOURCES = {
  "mainpower-nz": { name: "MainPower (North Canterbury)", country: "NZ", url: "https://outages.mainpower.co.nz/jobs?source=pcc&view=external",
    page: "https://outages.mainpower.co.nz/", hosts: ["outages.mainpower.co.nz", "www.mainpower.co.nz"],
    terms_url: "https://www.mainpower.co.nz/privacy-policy/", terms_ok: "silent" },
  "topenergy-nz": { name: "Top Energy (Far North)", country: "NZ", url: "https://outages.topenergy.co.nz/api/outages/regions",
    page: "https://outages.topenergy.co.nz/", hosts: ["outages.topenergy.co.nz", "topenergy.co.nz", "www.topenergy.co.nz"],
    terms_url: "https://topenergy.co.nz/tell-me-about/top-energy-group/publications-and-disclosures/privacy-policy", terms_ok: "silent" },
  "tlc-nz": { name: "The Lines Company (King Country)", country: "NZ",
    url: "https://tlc-outage-website-outage-data-production.s3.ap-southeast-2.amazonaws.com/outages.json",
    page: "https://outages.thelinescompany.co.nz/", hosts: ["outages.thelinescompany.co.nz", "www.thelinescompany.co.nz"],
    terms_url: "https://www.thelinescompany.co.nz/about-us/the-lines-company/", terms_ok: "silent", customers_served: 18000 },
  "ea-networks-nz": { name: "EA Networks (Ashburton)", country: "NZ", url: "https://outages-eanetworks-co-nz.vercel.app/api/get-outages?tab=current",
    page: "https://www.eanetworks.co.nz/power/outages", hosts: ["www.eanetworks.co.nz", "outages-eanetworks-co-nz.vercel.app"],
    terms_url: "https://www.eanetworks.co.nz/privacy-policy", terms_ok: "silent" },
  "aemo-wem": { name: "AEMO market advisories (Western Australia)", country: "AU", kind: "signal", signal: true,
    url: "https://data.wa.aemo.com.au/public/market-data/wemde/marketAdvisory/marketAdvisoryReport/market-advisories.csv",
    page: "https://data.wa.aemo.com.au/", hosts: ["data.wa.aemo.com.au"], terms_url: "https://data.wa.aemo.com.au/", terms_ok: "silent",
    customers_served: null, data_stale_min: 3 * 60,
    attribution: "Source: AEMO, Wholesale Electricity Market (WA) market advisories. CyberView shows advisories in effect whose declared operating state is not normal." },
};

export const REGIONS = {
  "mainpower-nz|North Canterbury": { name: "North Canterbury", lat: -42.8, lng: 172.9 },
  "topenergy-nz|Far North": { name: "Far North", lat: -35.2, lng: 173.7 },
  "tlc-nz|King Country": { name: "King Country and Ruapehu", lat: -38.6, lng: 175.2 },
  "ea-networks-nz|Ashburton": { name: "Ashburton District", lat: -43.9, lng: 171.75 },
  "aemo-wem|SWIS": { name: "South West Interconnected System (WA)", lat: -32.5, lng: 116.2 },
};

// ---------- MainPower ----------
/** One current_outages job -> an item, or null when it has no customers off and every step is restored. */
export function mainpowerJob(j) {
  if (!j || typeof j !== "object" || !j.JobId) return null;
  const steps = Object.values(j.steps && typeof j.steps === "object" ? j.steps : {}).map((f) => (f && f.properties) || {});
  const open = steps.filter((p) => str(p.Status, 20).toLowerCase() !== "restored");
  const off = num(j.CustomersOff);
  if (!(off > 0) && !open.length) return null;
  const at = mean((open.length ? open : steps).map((p) => pt(p.Lat, p.Lon)));
  return { id: `mainpower-nz:${str(j.JobId, 60)}`, source: "mainpower-nz", country: "NZ", region: "North Canterbury",
    area: str(j.Area, 120), lat: at.lat, lng: at.lng, customers: off, kind: "outage", planned: /planned/i.test(j.Type || ""),
    cause: str(j.Reason, 120), level: null, started_at: nzDmyToIso(j.StartTime), restore_est: nzDmyToIso(j.EndTime),
    url: "https://outages.mainpower.co.nz/" };
}
/** /jobs reply -> the outages in progress (current_outages; planned_jobs are announcements, not outages). */
export function parseMainpower(d) {
  if (!d || typeof d !== "object" || !d.current_outages || typeof d.current_outages !== "object") throw badShape("mainpower");
  const jobs = Array.isArray(d.current_outages) ? d.current_outages : Object.values(d.current_outages);
  return stamp(jobs.map(mainpowerJob).filter(Boolean), "");
}

// ---------- Top Energy ----------
/** One outage (regions reply) + its point from /api/outages -> an item. */
export function topEnergyOutage(x, point) {
  const startMs = num(x.startTimestamp) != null ? num(x.startTimestamp) * 1000 : NaN;
  const p = point ? pt(point.lat, point.lng) : { lat: null, lng: null };
  return { id: `topenergy-nz:${str(x.name || x.id, 60)}`, source: "topenergy-nz", country: "NZ", region: "Far North",
    area: str(x.circuitName || x.name, 120), lat: p.lat, lng: p.lng, customers: num(x.customersCurrentlyOff), kind: "outage",
    planned: x.type === "planned", cause: str(x.cause || x.reason, 120), level: null,
    started_at: isFinite(startMs) ? isoS(startMs) : "",
    restore_est: nzDayMonthToIso(x.endDateTime, isFinite(startMs) ? startMs : Date.now()), url: "https://outages.topenergy.co.nz/" };
}
/** regions reply + outages reply -> the outages in progress: the active list and planned outages marked isActive. */
export function parseTopEnergy(regions, outages) {
  if (!regions || !Array.isArray(regions.planned) || !Array.isArray(regions.active)) throw badShape("topenergy regions");
  const pts = new Map();
  for (const k of ["unplanned", "planned", "plannedActive"]) for (const p of (outages && Array.isArray(outages[k]) ? outages[k] : [])) if (p && p.id) pts.set(String(p.id), p);
  const live = [...regions.active, ...regions.planned.filter((x) => x && x.isActive === true)];
  return stamp(live.filter((x) => x && (x.name || x.id)).map((x) => topEnergyOutage(x, pts.get(String(x.name || x.id)))), "");
}

// ---------- The Lines Company ----------
/** The window an entry gives (the alternate date when postponed), in ISO. */
export function tlcWindow(x) {
  const alt = x.status === "postponed";
  const date = alt ? x.alternate_date : x.scheduled_date;
  const start = nzDateTimeToIso(date, alt ? x.alternate_start_time : x.start_time);
  const end = nzDateTimeToIso((alt ? x.alternate_end_date : x.end_date) || date, alt ? x.alternate_end_time : x.end_time);
  return { start, end };
}
/** One outages.json or shutdowns.json entry -> an item. */
export function tlcEntry(x) {
  const w = tlcWindow(x);
  const ll = String(x.lat_long || "").split(",");
  const p = pt(ll[0], ll[1]);
  const etr = isoMs(x.etr);
  return { id: `tlc-nz:${str(x.unique_id || x.uuid, 100)}`, source: "tlc-nz", country: "NZ", region: "King Country",
    area: str((Array.isArray(x.location) ? x.location.join(", ") : x.location) || x.feeder, 120), lat: p.lat, lng: p.lng,
    customers: num(x.customers), kind: "outage", planned: x.type === "planned", cause: str(x.reason, 120), level: null,
    started_at: w.start, restore_est: isFinite(etr) ? isoS(etr) : w.end, url: "https://outages.thelinescompany.co.nz/" };
}
/** outages.json (unplanned, in progress until closed) + shutdowns.json (planned: in progress inside its window) -> items. */
export function parseTlc(outages, shutdowns, now = Date.now()) {
  if (!Array.isArray(outages)) throw badShape("tlc outages");
  const live = outages.filter((x) => x && !x.closed_date && !/^(closed|cancel)/i.test(x.status || ""));
  const sd = (Array.isArray(shutdowns) ? shutdowns : []).filter((x) => {
    if (!x || x.closed_date || !["scheduled", "postponed"].includes(x.status)) return false;
    const w = tlcWindow(x), a = isoMs(w.start), b = isoMs(w.end);
    return isFinite(a) && isFinite(b) && a <= now && now <= b;
  });
  return stamp([...live, ...sd].map(tlcEntry), "");
}

// ---------- EA Networks ----------
const eaIso = (s) => { const m = String(s || "").match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/); return m ? isoMs(`${m[1]}Z`) : NaN; };  // the app's times are UTC
/** One get-outages record -> an item. */
export function eaRecord(r) {
  const s = eaIso(r.start_time), e = eaIso(r.estimated_end_time);
  const p = pt(r.latitude, r.longitude);
  return { id: `ea-networks-nz:${str(r.incident_id || r.outage_id, 100)}`, source: "ea-networks-nz", country: "NZ", region: "Ashburton",
    area: str(r.name || r.streets_affected, 120), lat: p.lat, lng: p.lng, customers: num(r.current_affected_customers), kind: "outage",
    planned: r.outage_type === "PLANNED_OUTAGE", cause: str(r.reason, 120), level: null,
    started_at: isFinite(s) ? isoS(s) : "", restore_est: isFinite(e) ? isoS(e) : "", url: "https://www.eanetworks.co.nz/power/outages" };
}
/** get-outages reply -> outages in progress: started, not restored, not complete, cancelled or postponed. */
export function parseEa(d, now = Date.now()) {
  if (!d || !Array.isArray(d.outages)) throw badShape("ea networks");
  return stamp(d.outages.filter((r) => r && r.energization_status !== "RESTORED" && !/^(COMPLETE|CANCELLED)/.test(r.status || "")
    && !r.postponed && !r.end_time && eaIso(r.start_time) <= now).map(eaRecord), "");
}

// ---------- AEMO WEM market advisories ----------
/** CSV text -> array of rows (quoted fields, doubled quotes and newlines inside quotes handled). */
export function parseCsv(text) {
  const rows = []; let row = [], f = "", q = false;
  const s = String(text || "");
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === '"') { if (s[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; continue; }
    if (c === '"') q = true;
    else if (c === ",") { row.push(f); f = ""; }
    else if (c === "\n" || c === "\r") { if (c === "\r" && s[i + 1] === "\n") i++; row.push(f); rows.push(row); row = []; f = ""; }
    else f += c;
  }
  if (f || row.length) { row.push(f); rows.push(row); }
  return rows.filter((r) => r.length > 1 || r[0]);
}
const AWST = 8 * 3600e3;   // Western Australia has no daylight-saving time
/** "2026-05-14 17:20:00" Western Australia time -> ms, or NaN. */
export const awstMs = (s) => { const m = String(s || "").match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/); return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)) - AWST : NaN; };
const NORMAL = /^(normal|reliable, secure and satisfactory|not applicable|no state change|)$/i;
/** Declared operating state -> level, or null when normal. */
export const wemLevel = (state) => { const s = str(state, 60); if (NORMAL.test(s)) return null; return /emergency/i.test(s) ? 3 : /high risk/i.test(s) ? 2 : 1; };
/** market-advisories.csv (current or the pre-2026-05 header) -> advisories in effect at now with a non-normal operating state. */
export function parseWem(text, now = Date.now()) {
  const rows = parseCsv(text);
  if (!rows.length) throw badShape("wem: empty");
  const h = rows[0].map((x) => x.trim().toLowerCase());
  const col = (n) => h.indexOf(n);
  const I = { id: col("id"), start: col("start interval"), end: col("end interval"), ver: col("version"), det: col("details"),
    wd: col("withdrawn"), wdAt: col("withdrawn at"), state: col("operating state"), ext: col("extracted at") };
  if (I.id < 0 || I.start < 0 || I.state < 0 || I.det < 0) throw badShape("wem: header");
  const latest = new Map(); let ext = NaN;
  for (const r of rows.slice(1)) {
    const id = str(r[I.id], 20); if (!id) continue;
    const e = I.ext >= 0 ? awstMs(r[I.ext]) : NaN; if (isFinite(e) && !(e <= ext)) ext = e;
    const v = I.ver >= 0 ? Number(r[I.ver]) || 0 : 0, prev = latest.get(id);
    if (!prev || v >= prev.v) latest.set(id, { v, r });
  }
  const out = [];
  for (const [id, { r }] of latest) {
    const level = wemLevel(r[I.state]); if (level == null) continue;
    const a = awstMs(r[I.start]), b = I.end >= 0 ? awstMs(r[I.end]) : NaN;
    const wd = I.wd >= 0 && /^y/i.test(r[I.wd] || ""), wdAt = I.wdAt >= 0 ? awstMs(r[I.wdAt]) : NaN;
    if (!(a <= now) || (isFinite(b) && now > b) || (wd && !(now < wdAt))) continue;
    out.push({ id: `aemo-wem:${id}`, source: "aemo-wem", country: "AU", region: "SWIS", area: "South West Interconnected System",
      lat: null, lng: null, customers: null, kind: "grid_emergency", planned: false, level,
      cause: str(`${str(r[I.state], 40)}: ${unent(r[I.det])}`, 120), started_at: isoS(a), restore_est: isFinite(b) ? isoS(b) : "",
      url: "https://data.wa.aemo.com.au/" });
  }
  return stamp(out, isFinite(ext) ? isoS(ext) : "");
}

const TLC_BASE = "https://tlc-outage-website-outage-data-production.s3.ap-southeast-2.amazonaws.com/";
export const ADAPTERS = {
  "mainpower-nz": async (h) => parseMainpower(await h.get(SOURCES["mainpower-nz"].url, { timeoutMs: 40000 })),
  "topenergy-nz": async (h) => {
    const regions = await h.get("https://outages.topenergy.co.nz/api/outages/regions", { timeoutMs: 30000 });
    const outages = await h.get("https://outages.topenergy.co.nz/api/outages", { timeoutMs: 30000 });
    return parseTopEnergy(regions, outages);
  },
  "tlc-nz": async (h) => {
    const outages = await h.get(`${TLC_BASE}outages.json`, { timeoutMs: 30000 });
    const shutdowns = await h.get(`${TLC_BASE}shutdowns.json`, { timeoutMs: 30000 });
    return parseTlc(outages, shutdowns);
  },
  "ea-networks-nz": async (h) => parseEa(await h.get(SOURCES["ea-networks-nz"].url, { timeoutMs: 30000 })),
  "aemo-wem": async (h) => parseWem(await h.get(SOURCES["aemo-wem"].url, { as: "text", timeoutMs: 40000 })),
};

export default {
  sources: SOURCES,
  regions: REGIONS,
  adapters: Object.fromEntries(Object.entries(ADAPTERS).map(([k, fn]) => [k, async (h) => { const got = await fn(h); return stamp(got.map((x) => h.item(x)), got.data_at); }])),
};
