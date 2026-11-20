// Grid sources for Europe (lane "europe" of swarm/grid-sources-20261119): SSEN Distribution, NGED, Elexon (NESO system
// warnings and demand control instructions), Liander, TAURON Dystrybucja and Elvia. Loaded by scripts/grid.mjs (see the
// comment above PLUGIN_ERRORS there). This file must not import scripts/grid.mjs (it is imported BY it): every parser
// takes the helpers `h` (item, str, isoOf, zonedToIso) as an argument, so it stays pure and testable.
//
// robots.txt, checked again 2026-11-20 for every feed path below:
//   external.distribution.prd.ssen.co.uk  404 (no robots.txt)
//   connecteddata.nationalgrid.co.uk      disallows /api/, /*?*, /revision/, /dataset/rate/, /dataset/*/history for all
//                                         agents (and everything for a list of named AI crawlers, which our fetcher is
//                                         not); the resource download path used here (/dataset/<id>/resource/<id>/
//                                         download/power_outage_ext.csv, no query string) is not disallowed. Crawl-Delay
//                                         10: one request per collection.
//   data.elexon.co.uk                     404 (no robots.txt)
//   services1.arcgis.com, services-eu1.arcgis.com   403 "Invalid URL" (no robots.txt)
//   www.tauron-dystrybucja.pl             /waapi/ is not disallowed (only /szukaj, /search, /sitecore, /App_*, /temp/,
//                                         /upload/, /xsl/ and some /assets/ folders)
// No source sends a key, a cookie or a browser-imitating header: h.get sends only CyberView's own user agent.

const msIso = (h, ms) => (Number.isFinite(ms) && ms > 0 ? h.isoOf(new Date(ms).toISOString()) : "");
const badShape = (what) => Object.assign(new Error(`unexpected reply shape (${what})`), { code: "bad_shape" });
// the operator's own data time travels with the items (scripts/grid.mjs collect marks a source stale when it is old)
export const stamp = (arr, at) => Object.defineProperty(arr, "data_at", { value: at || "", enumerable: false, configurable: true });
/** Rows exist but none carries the customers field as a number: the feed changed its fields (sources-3). */
export function needNumbers(rows, get, what) {
  if (rows.length && !rows.some((r) => { const v = get(r); return v !== null && v !== undefined && v !== "" && Number.isFinite(Number(v)); })) throw badShape(`${what}: no row has a customer count`);
}
/** ArcGIS layers cap a reply (maxRecordCount 2,000): follow resultOffset; a cut that is still there after `max` pages is
 *  reported (bad_shape), never silent (sources-6). */
export async function arcgisPages(h, url, parse, max = 5) {
  const out = [];
  for (let page = 0, offset = 0; page < max; page++) {
    const d = await h.get(offset ? `${url}&resultOffset=${offset}` : url, { retries: 1 });
    out.push(...parse(d, h));
    if (!d || !d.exceededTransferLimit) return out;
    if (!Array.isArray(d.features) || !d.features.length) break;
    offset += d.features.length;
  }
  throw badShape(`arcgis: more than ${max} pages`);
}

// ---------- SSEN Distribution (Power Track) ----------
// getallfaults: { timestampUtc, faults: [{ reference, type (LV | HV | PSI = planned supply interruption), loggedAtUtc,
// estimatedRestorationTimeUtc, location { latitude, longitude }, affectedAreas [postcodes], customerCount, mergedTo,
// title ("RG27 Area"), message }] }. Times are UTC. A fault with mergedTo set has been merged into another one and is
// skipped so its customers are not counted twice. Licence areas: SHEPD (north of Scotland) and SEPD (central southern
// England); a point north of 55.5° is SHEPD.
const SSEN_TYPE = { LV: "Low-voltage fault", HV: "High-voltage fault", PSI: "Planned supply interruption" };
export const SSEN_NORTH = "North of Scotland", SSEN_SOUTH = "Central southern England";
export function parseSsen(d, h) {
  if (!d || !Array.isArray(d.faults)) throw badShape("ssen");
  const rows = d.faults.filter((f) => f && f.reference != null && !f.mergedTo);
  needNumbers(rows, (f) => f.customerCount, "ssen");
  return stamp(rows.map((f) => {
    const loc = f.location || {}, lat = loc.latitude == null ? null : Number(loc.latitude), lng = loc.longitude == null ? null : Number(loc.longitude);
    const areas = Array.isArray(f.affectedAreas) ? f.affectedAreas.slice(0, 3).join(", ") : "";
    return h.item({
      source: "ssen-powertrack", id: `ssen-powertrack:${h.str(f.reference, 60)}`,
      region: lat != null && lat > 55.5 ? SSEN_NORTH : SSEN_SOUTH,
      area: [String(f.title || "").replace(/\s+Area$/, ""), areas].filter(Boolean).join(": "),
      lat, lng, customers: f.customerCount, kind: "outage", planned: f.type === "PSI",
      cause: SSEN_TYPE[f.type] || h.str(f.type, 40), level: null,
      started_at: h.isoOf(f.loggedAtUtc), restore_est: h.isoOf(f.estimatedRestorationTimeUtc),
    });
  }), h.isoOf(d.timestampUtc));
}

// ---------- National Grid Electricity Distribution (Live Power Cuts CSV) ----------
// Columns: Upload Date, Region (West Midlands | East Midlands | South Wales | South West = the four licence areas),
// Incident ID, Confirmed Off, Predicted Off, Restored, Status, Planned (true/false), Category, Resource Status,
// Start Time, ETR, Voltage, Location Latitude, Location Longitude, Postcodes. Times carry no zone: UK wall-clock time
// (Europe/London). NGED does not say whether "Predicted Off" includes "Confirmed Off", so customers is the larger of
// the two (a lower bound either way), never their sum.
export function parseCsv(text) {
  const rows = [], s = String(text || "").replace(/^﻿/, "");
  let row = [], cell = "", q = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (c === '"') { if (s[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += c;
    } else if (c === '"') q = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && s[i + 1] === "\n") i++;
      row.push(cell); cell = ""; if (row.length > 1 || row[0] !== "") rows.push(row); row = [];
    } else cell += c;
  }
  if (cell !== "" || row.length) { row.push(cell); rows.push(row); }
  if (!rows.length) return [];
  const head = rows[0].map((x) => x.trim());
  return rows.slice(1).map((r) => Object.fromEntries(head.map((k, i) => [k, (r[i] ?? "").trim()])));
}
/** "LV UNDERGROUND" -> "LV underground". */
export const ngedCategory = (c) => String(c || "").trim().split(/\s+/).filter(Boolean)
  .map((w, i) => (/^E?[HL]V$/i.test(w) ? w.toUpperCase() : i ? w.toLowerCase() : w[0].toUpperCase() + w.slice(1).toLowerCase())).join(" ").slice(0, 120);
const intOf = (x) => { const n = Number(String(x ?? "").replace(/,/g, "")); return Number.isFinite(n) && n >= 0 ? Math.round(n) : null; };
export function parseNged(text, h) {
  const rows = parseCsv(text);
  if (!rows.length || !("Incident ID" in rows[0]) || !("Confirmed Off" in rows[0])) throw badShape("nged csv");
  // every row carries the time NGED uploaded the file (UK wall-clock time): the newest is the data time
  const up = rows.map((r) => String(r["Upload Date"] || "")).filter((x) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(x)).sort().pop() || "";
  const live = rows.filter((r) => r["Incident ID"] && !/restored|closed|complete|cancel/i.test(r.Status || ""));
  needNumbers(live, (r) => (intOf(r["Confirmed Off"]) ?? intOf(r["Predicted Off"])), "nged");
  return stamp(live.map((r) => {
    const conf = intOf(r["Confirmed Off"]), pred = intOf(r["Predicted Off"]);
    const customers = conf == null && pred == null ? null : Math.max(conf || 0, pred || 0);
    const lat = r["Location Latitude"] === "" ? null : Number(r["Location Latitude"]);
    const lng = r["Location Longitude"] === "" ? null : Number(r["Location Longitude"]);
    const pcs = [...new Set(String(r.Postcodes || "").split(/\s*,\s*/).filter(Boolean))].slice(0, 3).join(", ");
    return h.item({
      source: "nged-live-power-cuts", id: `nged-live-power-cuts:${h.str(r["Incident ID"], 60)}`,
      region: h.str(r.Region || "NGED area", 60), area: pcs, lat, lng, customers, kind: "outage",
      planned: /^true$/i.test(r.Planned || ""), cause: ngedCategory(r.Category),
      level: null, started_at: h.zonedToIso(r["Start Time"], "Europe/London"), restore_est: h.zonedToIso(r.ETR, "Europe/London"),
    });
  }), up ? h.zonedToIso(up, "Europe/London") : "");
}

// ---------- Elexon BMRS: NESO system warnings (SYSWARN) ----------
// /system/warnings?publishDateTimeFrom&publishDateTimeTo -> { data: [{ publishTime (UTC), warningType, warningText }] }.
// Mapping (only GB Transmission System Warnings that are about supply; a later cancellation of the same warning clears
// it; a warning is current while its stated period covers now, or, when no period can be read, for
// SYSWARN_NO_PERIOD_HOURS after it was published):
//   ELECTRICITY MARGIN NOTICE                   -> supply_warning, level 1
//   CAPACITY MARKET NOTICE ("Currently Active") -> supply_warning, level 1
//   HIGH RISK OF DEMAND REDUCTION               -> grid_emergency, level 2
//   RISK OF SYSTEM DISTURBANCE                  -> grid_emergency, level 2
//   DEMAND CONTROL IMMINENT                     -> grid_emergency, level 3
// Left out: SO-SO TRADES (interconnector prices), IT SYSTEMS OUTAGE, DEMAND FLEXIBILITY SERVICE, NEGATIVE RESERVE
// ACTIVE POWER MARGIN (too much generation in a local area, not a supply shortage), "DEMAND CONTROL BY VR TEST"
// (announced voltage-reduction tests) and every other OTHER notice. Periods are UK local time (Europe/London).
export const SYSWARN_NO_PERIOD_HOURS = 12;
export const SYSWARN_WINDOW_HOURS = 48;
const SYSWARN_RULES = [
  { re: /DEMAND CONTROL IMMINENT/i, cat: "dci", kind: "grid_emergency", level: 3, label: "Demand control imminent" },
  { re: /HIGH RISK OF DEMAND REDUCTION/i, cat: "hrdr", kind: "grid_emergency", level: 2, label: "High risk of demand reduction" },
  { re: /RISK OF SYSTEM DISTURBANCE/i, cat: "rsd", kind: "grid_emergency", level: 2, label: "Risk of system disturbance" },
  { re: /ELECTRICITY MARGIN NOTICE/i, cat: "emn", kind: "supply_warning", level: 1, label: "Electricity margin notice" },
  { re: /CAPACITY MARKET NOTICE/i, cat: "cmn", kind: "supply_warning", level: 1, label: "Capacity market notice" },
];
const flat = (s) => String(s || "").replace(/\\[rn]/g, " ").replace(/\s+/g, " ").trim();
const ukDate = (d, m, y) => `${y.length === 2 ? "20" + y : y}-${m}-${d}`;
/** "from 06:00 hrs to 11:00 hrs on Monday 09/11/2026" or "from 23:00 hrs on 24/10/2026 to 21:00 hrs on 25/10/2026"
 *  (UK local time) -> { from, to } ISO UTC, or null. */
export function syswarnPeriod(text, h) {
  const m = flat(text).match(/from\s+(\d{1,2}):(\d{2})\s*hrs?(?:\s+on\s+(?:[A-Za-z]+\s+)?(\d{2})\/(\d{2})\/(\d{2,4}))?\s+to\s+(\d{1,2}):(\d{2})\s*hrs?\s+on\s+(?:[A-Za-z]+\s+)?(\d{2})\/(\d{2})\/(\d{2,4})/i);
  if (!m) return null;
  const p2 = (x) => String(x).padStart(2, "0");
  const endDay = ukDate(m[8], m[9], m[10]);
  let startDay = m[3] ? ukDate(m[3], m[4], m[5]) : endDay;
  if (!m[3] && `${p2(m[1])}${m[2]}` > `${p2(m[6])}${m[7]}`) {   // "from 23:00 to 05:00 on <day>": starts the day before
    const t = Date.parse(`${endDay}T12:00:00Z`) - 864e5; startDay = new Date(t).toISOString().slice(0, 10);
  }
  const from = h.zonedToIso(`${startDay} ${p2(m[1])}:${m[2]}:00`, "Europe/London"), to = h.zonedToIso(`${endDay} ${p2(m[6])}:${m[7]}:00`, "Europe/London");
  return from && to ? { from, to } : null;
}
/** "Commencement time of notice : 16:30 on 08/01/2025" (Capacity Market Notice) -> ISO UTC or "". */
function cmnStart(text, h) {
  const m = flat(text).match(/Commencement time of notice\s*:\s*(\d{1,2}):(\d{2})\s+on\s+(\d{2})\/(\d{2})\/(\d{4})/i);
  return m ? h.zonedToIso(`${ukDate(m[3], m[4], m[5])} ${m[1].padStart(2, "0")}:${m[2]}:00`, "Europe/London") : "";
}
export function parseSyswarn(d, h, now = Date.now()) {
  if (!d || !Array.isArray(d.data)) throw badShape("syswarn");
  const state = {};   // category -> the latest notice still in force
  const rows = d.data.filter((x) => x && x.publishTime).map((x) => ({ ...x, at: h.isoOf(x.publishTime) })).filter((x) => x.at && Date.parse(x.at) <= now)
    .sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
  for (const x of rows) {
    const text = flat(x.warningText), head = `${x.warningType || ""} ${text.split(/remain in force/i)[0]}`;
    if (/SO-SO TRADES|IT SYSTEMS OUTAGE|DEMAND FLEXIBILITY|NEGATIVE RESERVE/i.test(x.warningType || "") || /\bTEST\b/i.test(head)) continue;
    const rule = SYSWARN_RULES.find((r) => r.re.test(head));
    if (!rule) continue;
    if (/CANCELL?(ED|ATION)/i.test(head)) { state[rule.cat] = null; continue; }
    if (rule.cat === "cmn" && !/Currently Active/i.test(text)) continue;
    state[rule.cat] = { x, rule, text };
  }
  const out = [];
  for (const st of Object.values(state)) {
    if (!st) continue;
    const { x, rule, text } = st;
    const per = syswarnPeriod(text, h), start = per ? per.from : rule.cat === "cmn" ? cmnStart(text, h) || x.at : x.at;
    const end = per ? per.to : "";
    if (Date.parse(start) > now) continue;                                     // announced for later: not current yet
    if (end ? Date.parse(end) <= now : now - Date.parse(x.at) > SYSWARN_NO_PERIOD_HOURS * 3600e3) continue;
    const short = (text.match(/shortfall\s+(\d+)\s*MW/i) || [])[1];
    out.push(h.item({
      source: "elexon-system-warnings", id: `elexon-system-warnings:${rule.cat}-${x.at.replace(/\D/g, "").slice(0, 12)}`,
      region: "Great Britain", area: "GB transmission system (NESO)", lat: null, lng: null, customers: null,
      kind: rule.kind, planned: false, cause: h.str(`${rule.label}${short ? `: system margin shortfall ${short} MW` : ""}`, 120),
      level: rule.level, started_at: start, restore_est: end, url: "https://bmrs.elexon.co.uk/system-warnings",
    }));
  }
  return out;
}

// ---------- Elexon BMRS: demand control instructions (DCI) ----------
// /system/demand-control-instructions?from&to -> { data: [{ mRID, revisionNumber, publishTime, affectedDso,
// demandControlId, instructionSequence, demandControlEventFlag, timeFrom, timeTo, volume (MW),
// systemManagementActionFlag, amendmentFlag }] } (UTC). Real example: the 9 August 2019 low-frequency demand
// disconnection, flag "L", 931 MW (tests/fixtures/grid/europe/elexon-demand-control-2019.json). Demand control means
// customers were actually disconnected: grid_emergency, level 3. The highest revision of each mRID wins; an amendment
// flag starting "CAN" cancels it. Current = not ended, or ended less than DCI_KEEP_ENDED_HOURS ago (a short event
// between two collections is still seen; restore_est is then its end time).
export const DCI_KEEP_ENDED_HOURS = 6;
export const DCI_WINDOW_HOURS = 24;
const DCI_FLAG = { L: "low-frequency demand disconnection", I: "demand control instructed by NESO" };
export function parseDci(d, h, now = Date.now()) {
  if (!d || !Array.isArray(d.data)) throw badShape("dci");
  const best = new Map();
  for (const x of d.data) {
    if (!x || !x.timeFrom) continue;
    const k = x.mRID || `${x.demandControlId}-${x.instructionSequence}`, o = best.get(k);
    if (!o || (x.revisionNumber || 0) >= (o.revisionNumber || 0)) best.set(k, x);
  }
  const out = [];
  for (const [k, x] of best) {
    if (/^CAN/i.test(x.amendmentFlag || "")) continue;
    const start = h.isoOf(x.timeFrom), end = h.isoOf(x.timeTo);
    if (!start || Date.parse(start) > now) continue;
    if (end && now - Date.parse(end) > DCI_KEEP_ENDED_HOURS * 3600e3) continue;
    const what = DCI_FLAG[String(x.demandControlEventFlag || "").toUpperCase()] || "demand control";
    const mw = Number.isFinite(Number(x.volume)) && x.volume != null ? `, ${Math.round(Number(x.volume))} MW` : "";
    out.push(h.item({
      source: "elexon-demand-control", id: `elexon-demand-control:${h.str(k, 80)}`, region: "Great Britain",
      area: x.affectedDso ? h.str(`Distribution network: ${x.affectedDso}`, 120) : "GB (NESO)", lat: null, lng: null,
      customers: null, kind: "grid_emergency", planned: false, cause: h.str(`Demand control: ${what}${mw}`, 120), level: 3,
      started_at: start, restore_est: end, url: "https://bmrs.elexon.co.uk/demand-control-instructions",
    }));
  }
  return out;
}

// ---------- Liander (Storingsdata, ArcGIS) ----------
// attributes: STORING_NUMMER, STORING_TYPE (S = storing/fault, P = planned work), STORING_ENERGIESOORT (Elektriciteit |
// Gas), STORING_STATUS, STORING_DATUM_GEMELD (epoch ms, start), STORING_DATUM_SCHATTING (estimate), STORING_OORZAAK,
// STORING_GETROFFEN_KLANTEN (a band: "< 25", "< 100", "< 1.000", "> 10.000", "<2"; Dutch thousands separator),
// STORING_GETROFFEN_PLAATSEN / _POSTCODES; centroid {x: lng, y: lat}. Only electricity. Customers: the band's lower
// bound, never a guessed figure: "> N" -> N + 1; "< N" -> the largest step of the band ladder below N (1, 25, 50, 100,
// 1,000, 10,000; each of these steps is itself a band in the feed, so a "< 300" outage is above the "< 100" band);
// the band stays in the area in words ("customers reported as under 300": grid.mjs str() strips "<" and ">"). Faults Liander marks as not in its network are left out.
export const LIANDER_STEPS = [1, 25, 50, 100, 1000, 10000];
export function lianderBand(s) {
  const m = String(s || "").replace(/\s+/g, "").match(/^([<>])(\d[\d.]*)$/);
  if (!m) return null;
  const n = Number(m[2].replace(/\./g, ""));
  if (!Number.isFinite(n) || n < 1) return null;
  if (m[1] === ">") return n + 1;
  return LIANDER_STEPS.filter((x) => x < n).pop() ?? 1;
}
export const bandWords = (b) => String(b || "").trim().replace(/^<\s*/, "under ").replace(/^>\s*/, "over ");
/** The band as words for the map ("under 200", "over 10,000"): the count is a floor, never shown as exact (sources-4). */
export const bandLabel = (b) => (/^[<>]\s*\d/.test(String(b || "").trim()) ? bandWords(b).replace(/(\d)\.(\d{3})/g, "$1,$2") : "");
const LIANDER_CAUSE = {
  "spontane storing": "Spontaneous fault", "geplande werkzaamheden": "Planned work", "graafwerkzaamheden": "Excavation damage",
  "weersinvloed": "Weather", "bodemverzakking": "Ground subsidence", "nog niet bekend": "Cause not yet known",
};
const lianderCause = (s) => [...new Set(String(s || "").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean).map((x) => LIANDER_CAUSE[x] || x))].join(", ");
export function parseLiander(d, h) {
  if (!d || !Array.isArray(d.features)) throw badShape("liander");
  return d.features.map((f) => ({ a: (f && f.attributes) || {}, c: (f && (f.centroid || f.geometry)) || {} }))
    .filter(({ a }) => a.STORING_NUMMER != null && /^elektriciteit$/i.test(a.STORING_ENERGIESOORT || "") && !/dummy/i.test(a.STORING_TYPE || "")
      && !/niet in net|niet voor netbeheerder|^test$/i.test(a.STORING_OORZAAK || "") && !/opgelost/i.test(a.STORING_STATUS || "") && !a.STORING_DATUM_EIND)
    .map(({ a, c }) => {
      const band = String(a.STORING_GETROFFEN_KLANTEN || "").trim(), places = String(a.STORING_GETROFFEN_PLAATSEN || "").split(";").filter(Boolean).slice(0, 3).join(", ");
      const planned = /^p$/i.test(a.STORING_TYPE || "") || /geplande/i.test(a.STORING_OORZAAK || "");
      return h.item({
        source: "liander-storingen", id: `liander-storingen:${h.str(a.STORING_NUMMER, 40)}`, region: "Liander area",
        area: h.str([places, band ? `customers reported as ${bandWords(band)}` : ""].filter(Boolean).join(" · "), 120),
        lat: c.y == null ? null : Number(c.y), lng: c.x == null ? null : Number(c.x), customers: lianderBand(band), customers_band: bandLabel(band),
        kind: "outage", planned, cause: h.str(lianderCause(a.STORING_OORZAAK) || (planned ? "Planned work" : ""), 120), level: null,
        started_at: msIso(h, a.STORING_DATUM_GEMELD), restore_est: msIso(h, a.STORING_DATUM_SCHATTING),
      });
    });
}

// ---------- TAURON Dystrybucja (wyłączenia) ----------
// /waapi/outages/items?fromDate&toDate -> [{ OutageId, TypeId, StartDate, EndDate (UTC ISO), Message (streets and
// house numbers), AddressPointIds, Center { lat, lng }, IsActive }]. TypeId 1 = planned, 2 = failure: the public map's
// own code says so (waweb/js/wa.web.js: IsPlannedOutageItem = TypeId == 1, IsFailureOutageItem = TypeId == 2, and an
// active failure is IsActive and now < EndDate). The feed lists addresses, not customers: customers null (listed, not
// counted toward thresholds); the area says how many address points. Only outages under way (start <= now < end).
export function parseTauron(d, h, now = Date.now()) {
  if (!Array.isArray(d)) throw badShape("tauron");
  if (d.some((x) => x && x.OutageId) && !d.some((x) => x && (x.TypeId === 1 || x.TypeId === 2))) throw badShape("tauron: no row has TypeId 1 or 2");
  return d.filter((x) => x && x.OutageId && (x.TypeId === 1 || x.TypeId === 2) && x.IsActive !== false).filter((x) => {
    const s = Date.parse(x.StartDate || ""), e = Date.parse(x.EndDate || "");
    return Number.isFinite(s) && s <= now && (!Number.isFinite(e) || e > now);
  }).map((x) => {
    const c = x.Center || (Array.isArray(x.Coordinates) && x.Coordinates[0]) || {}, n = Array.isArray(x.AddressPointIds) ? x.AddressPointIds.length : 0;
    return h.item({
      source: "tauron-wylaczenia", id: `tauron-wylaczenia:${h.str(x.OutageId, 60)}`, region: "Southern Poland",
      area: h.str(`${n ? `${n} address point${n === 1 ? "" : "s"}: ` : ""}${String(x.Message || "").replace(/[\s,]+$/, "")}`, 120),
      lat: c.lat == null ? null : Number(c.lat), lng: c.lng == null ? null : Number(c.lng), customers: null, kind: "outage",
      planned: x.TypeId === 1, cause: x.TypeId === 1 ? "Planned outage (wyłączenie planowane)" : "Failure (awaria)", level: null,
      started_at: h.isoOf(x.StartDate), restore_est: h.isoOf(x.EndDate),
    });
  });
}

// ---------- Elvia (strømbrudd, ArcGIS layer 0: one point per substation) ----------
// attributes: nettstasjon (substation), postnummer, poststed, kommune, fylke, antallkunder (customers), avbruddstype
// (Planned | Unplanned), statusavbrudd (deenergized while out), utkoblingstart / strombruddoppdaget (start, epoch ms),
// utkoblingslutt (planned or estimated end); geometry x/y = lng/lat (outSR=4326).
export function parseElvia(d, h) {
  if (!d || !Array.isArray(d.features)) throw badShape("elvia");
  return d.features.map((f) => ({ a: (f && f.attributes) || {}, g: (f && f.geometry) || {} }))
    .filter(({ a }) => a.OBJECTID != null && (!a.statusavbrudd || /deenergi[sz]ed/i.test(a.statusavbrudd)))
    .map(({ a, g }) => {
      const start = a.utkoblingstart || a.strombruddoppdaget, planned = /^planned$/i.test(a.avbruddstype || "");
      return h.item({
        source: "elvia-strombrudd", id: `elvia-strombrudd:${h.str(a.nettstasjon || a.OBJECTID, 30)}-${Number(start) || 0}`,
        region: "Eastern Norway (Elvia area)",
        area: h.str([[a.postnummer, a.poststed].filter(Boolean).join(" "), a.kommune, a.fylke].filter(Boolean).join(", ") + (a.nettstasjon ? ` (substation ${a.nettstasjon})` : ""), 120),
        lat: g.y == null ? null : Number(g.y), lng: g.x == null ? null : Number(g.x), customers: a.antallkunder,
        kind: "outage", planned, cause: planned ? "Planned outage" : "Unplanned outage", level: null,
        started_at: msIso(h, Number(start)), restore_est: msIso(h, Number(a.utkoblingslutt)),
      });
    });
}

// ---------- sources ----------
const ELEXON_LICENCE = "https://www.elexon.co.uk/bsc/data/balancing-mechanism-reporting-agent/copyright-licence-bmrs-data/";
const SOURCES = {
  "ssen-powertrack": {
    name: "SSEN Distribution", country: "GB", kind: "outages",
    url: "https://external.distribution.prd.ssen.co.uk/opendataportal-prd/v4/api/getallfaults",
    page: "https://powertrack.ssen.co.uk/powertrack", hosts: ["powertrack.ssen.co.uk", "www.ssen.co.uk"],
    terms_url: "https://data.ssen.co.uk/terms-and-conditions", terms_ok: "allowed", customers_served: 3900000,
    // the portal's terms: publisher; data asset title; identifier; date (of the last update: the time of the collection)
    attribution: "SSEN Distribution, Real Time Outage Dataset (realtime_outage_dataset); {date}. CC BY 4.0",
    licence: "CC BY 4.0",
  },
  "nged-live-power-cuts": {
    name: "National Grid Electricity Distribution", country: "GB", kind: "outages",
    url: "https://connecteddata.nationalgrid.co.uk/dataset/d6672e1e-c684-4cea-bb78-c7e5248b62a2/resource/292f788f-4339-455b-8cc0-153e14509d4d/download/power_outage_ext.csv",
    page: "https://powercuts.nationalgrid.co.uk/", hosts: ["powercuts.nationalgrid.co.uk", "connecteddata.nationalgrid.co.uk"],
    terms_url: "https://www.nationalgrid.co.uk/open-data-licence", terms_ok: "allowed", customers_served: 8000000,
    attribution: "Supported by NGED Open Data", licence: "NGED Open Data Licence",
  },
  "elexon-system-warnings": {
    name: "NESO system warnings (Elexon BMRS)", country: "GB", kind: "signal",
    url: "https://data.elexon.co.uk/bmrs/api/v1/system/warnings",
    page: "https://bmrs.elexon.co.uk/system-warnings", hosts: ["bmrs.elexon.co.uk"],
    terms_url: ELEXON_LICENCE, terms_ok: "allowed", customers_served: null,
    attribution: "Contains BMRS data © Elexon Limited copyright and database right {year}", licence_url: ELEXON_LICENCE,
  },
  "elexon-demand-control": {
    name: "NESO demand control instructions (Elexon BMRS)", country: "GB", kind: "signal",
    url: "https://data.elexon.co.uk/bmrs/api/v1/system/demand-control-instructions",
    page: "https://bmrs.elexon.co.uk/demand-control-instructions", hosts: ["bmrs.elexon.co.uk"],
    terms_url: ELEXON_LICENCE, terms_ok: "allowed", customers_served: null,
    attribution: "Contains BMRS data © Elexon Limited copyright and database right {year}", licence_url: ELEXON_LICENCE,
  },
  "liander-storingen": {
    name: "Liander", country: "NL", kind: "outages",
    url: "https://services1.arcgis.com/v6W5HAVrpgSg3vts/ArcGIS/rest/services/IStoringen_Productie_V7/FeatureServer/0/query?where=STORING_STATUS%3C%3E%27opgelost%27%20AND%20STORING_DATUM_EIND%20IS%20NULL&outFields=*&returnGeometry=false&returnCentroid=true&outSR=4326&f=json",
    page: "https://www.liander.nl/storingen-en-onderhoud", hosts: ["www.liander.nl"],
    terms_url: "https://data.overheid.nl/dataset/storingsdata-liander-actuele-storingen", terms_ok: "allowed", customers_served: 3000000,
    attribution: "Liander, Storingsdata (actuele storingen). CC BY 4.0", licence: "CC BY 4.0",
  },
  "tauron-wylaczenia": {
    name: "TAURON Dystrybucja", country: "PL", kind: "outages",
    url: "https://www.tauron-dystrybucja.pl/waapi/outages/items",
    page: "https://www.tauron-dystrybucja.pl/wylaczenia", hosts: ["www.tauron-dystrybucja.pl"],
    terms_url: "https://www.tauron-dystrybucja.pl/regulamin-swiadczenia-uslug", terms_ok: "silent", customers_served: 5920000,
  },
  "elvia-strombrudd": {
    name: "Elvia", country: "NO", kind: "outages",
    url: "https://services-eu1.arcgis.com/AcdYbPzrkOfBOQDL/arcgis/rest/services/avbrudd2_offentlig_visning/FeatureServer/0/query?where=1%3D1&outFields=*&outSR=4326&f=json",
    page: "https://www.elvia.no/strombruddskart/", hosts: ["www.elvia.no"],
    terms_url: "https://www.elvia.no/strombruddskart/", terms_ok: "silent", customers_served: null,
  },
};

// Approximate centres, used only when items have no coordinates of their own.
const REGIONS = {
  [`ssen-powertrack|${SSEN_NORTH}`]: { name: "North of Scotland (SSEN, SHEPD)", lat: 57.4, lng: -4.6 },
  [`ssen-powertrack|${SSEN_SOUTH}`]: { name: "Central southern England (SSEN, SEPD)", lat: 51.2, lng: -1.3 },
  "nged-live-power-cuts|West Midlands": { name: "West Midlands (NGED)", lat: 52.5, lng: -2.2 },
  "nged-live-power-cuts|East Midlands": { name: "East Midlands (NGED)", lat: 52.9, lng: -1.1 },
  "nged-live-power-cuts|South Wales": { name: "South Wales (NGED)", lat: 51.7, lng: -3.6 },
  "nged-live-power-cuts|South West": { name: "South West England (NGED)", lat: 50.7, lng: -3.8 },
  "elexon-system-warnings|Great Britain": { name: "Great Britain", lat: 54.0, lng: -2.5 },
  "elexon-demand-control|Great Britain": { name: "Great Britain", lat: 54.0, lng: -2.5 },
  "liander-storingen|Liander area": { name: "Liander area (Gelderland, Noord-Holland, Flevoland, Friesland)", lat: 52.3, lng: 5.3 },
  "tauron-wylaczenia|Southern Poland": { name: "Southern Poland (TAURON)", lat: 50.3, lng: 19.0 },
  "elvia-strombrudd|Eastern Norway (Elvia area)": { name: "Eastern Norway (Elvia area)", lat: 60.2, lng: 10.9 },
};

const isoMin = (ms) => new Date(ms).toISOString().slice(0, 16) + "Z";
const adapters = {
  "ssen-powertrack": async (h) => parseSsen(await h.get(h.SOURCES["ssen-powertrack"].url, { retries: 1 }), h),
  "nged-live-power-cuts": async (h) => parseNged(await h.get(h.SOURCES["nged-live-power-cuts"].url, { as: "text", retries: 1 }), h),
  "elexon-system-warnings": async (h) => {
    const now = Date.now();
    const u = `${h.SOURCES["elexon-system-warnings"].url}?publishDateTimeFrom=${isoMin(now - SYSWARN_WINDOW_HOURS * 3600e3)}&publishDateTimeTo=${isoMin(now + 60e3)}`;
    return parseSyswarn(await h.get(u, { retries: 1, key: "data.elexon.co.uk" }), h, now);
  },
  "elexon-demand-control": async (h) => {
    const now = Date.now();
    const u = `${h.SOURCES["elexon-demand-control"].url}?from=${isoMin(now - DCI_WINDOW_HOURS * 3600e3)}&to=${isoMin(now + 3600e3)}`;
    return parseDci(await h.get(u, { retries: 1, key: "data.elexon.co.uk" }), h, now);
  },
  "liander-storingen": async (h) => arcgisPages(h, h.SOURCES["liander-storingen"].url, parseLiander),
  // the public map asks for [now, now + 5 days]; outages under way overlap any window that starts now, so one hour is enough
  "tauron-wylaczenia": async (h) => {
    const now = Date.now();
    const u = `${h.SOURCES["tauron-wylaczenia"].url}?fromDate=${new Date(now).toISOString()}&toDate=${new Date(now + 3600e3).toISOString()}`;
    return parseTauron(await h.get(u, { retries: 1 }), h, now);
  },
  "elvia-strombrudd": async (h) => arcgisPages(h, h.SOURCES["elvia-strombrudd"].url, parseElvia),
};

export default { sources: SOURCES, regions: REGIONS, adapters };
