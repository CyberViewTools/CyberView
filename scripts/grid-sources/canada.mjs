// Grid sources, Canada lane: London Hydro (outage polygons, KML), IESO (Ontario system advisories, three RSS feeds) and
// AESO (Alberta Grid Alert RSS). Loaded by scripts/grid.mjs (see the comment above PLUGIN_ERRORS there and
// scripts/grid-sources/README.md). Scouted as "connect" in swarm/grid-sources-20261119/out/canada.json.
//
// The parsers are pure and exported (tests/unit/grid-canada.test.mjs). They return finished items in the grid item shape
// (the same fields scripts/grid.mjs item() builds) so the tests can check them with checkItem; the adapters still pass
// them through h.item, which normalises them again. This file imports nothing from scripts/grid.mjs: grid.mjs loads it
// while it is itself still loading.
//
// Advisory level mapping (IESO and AESO). Levels follow the ERCOT/AEMO convention: 0 = shown, never opens an incident;
// 1 and up opens one (scripts/grid.mjs active()).
//   load shedding / rotating outages                                  -> load_shedding  3
//   IESO "Emergency Operating State"                                  -> grid_emergency 3
//   "Energy Emergency Alert" / EEA with a number 1, 2, 3              -> grid_emergency 1, 2, 3
//   IESO EEA without a number, "High-Risk Operating State"            -> grid_emergency 2
//   IESO "Capacity Margin" / capacity advisory, supply or reserve
//     shortfall, "Severe Weather" (also cold/hot weather alerts),
//     "Conservative Operations"                                       -> supply_warning 1
//   any other item of the IESO Critical (emergency) feed              -> grid_emergency 1
//   any other item of the IESO Day 0 or Day 1-34 feeds (routine
//     operating notices such as "Generation Biasing")                 -> left out
//   AESO "Grid Alert" (or any other alert the feed carries)           -> grid_emergency 1
//   AESO "Sorry, no feed items were found." placeholder               -> no item (no alert)
// Current, not forecast: an IESO advisory whose end_date has passed is left out; one whose start_date is still ahead
// (and every Day 1-34 advisory without a start date) is a forecast: supply_warning level 0, shown but never opening an
// incident. An item with no dates whose pubDate is more than STALE_HOURS old is left out (also AESO items). An AESO item
// that says the alert ended, was cancelled or lifted is left out.

const STALE_HOURS = 24;
const TZ = "America/Toronto";       // London Hydro's KML times carry no zone (its map reads them as local time)

const IESO_TERMS = "https://www.ieso.ca/Terms-of-Use";
// The line IESO's Terms of Use require on every reproduction (https://www.ieso.ca/Terms-of-Use, read 2026-11-20).
const IESO_ATTRIBUTION = "Copyright © 2004-2026 Independent Electricity System Operator, all rights reserved. This information is subject to the Terms of Use set out in the IESO’s website (www.ieso.ca)";
// AESO (https://www.aeso.ca/legal/): "may be used and copied for non-commercial, personal or educational purposes,
// provided that the material is not modified and that copyright notices are not deleted". The alert title is kept as
// AESO wrote it (never rewritten; left out rather than cut when longer than an item field) with AESO's own notice.
const AESO_ATTRIBUTION = "Grid Alert text from the AESO (www.aeso.ca), unmodified, non-commercial use. Copyright © 2016 – 2026 Alberta Electric System Operator. All rights reserved.";

const IESO_FEEDS = {
  "ieso-critical": { signal: true, name: "IESO emergency advisories", feed: "Critical", page: "Emergency-Advisory-Notices" },
  "ieso-day0": { signal: true, name: "IESO same-day advisories", feed: "Day0", page: "Day-0-Advisory-Notices-Summary" },
  "ieso-day1-34": { signal: true, name: "IESO advisories, days 1-34", feed: "Day1To34", page: "Day-1-to-34-Advisory-Notices-Summary" },
};
const HOSTS = { "london-hydro": ["www.londonhydro.com"], aeso: ["www.aeso.ca"], ieso: ["www.ieso.ca"] };
const PAGES = {
  "london-hydro": "https://www.londonhydro.com/outages/outage-map",
  "aeso-grid-alert": "https://www.aeso.ca/grid/understanding-grid-conditions/",
};
for (const [k, f] of Object.entries(IESO_FEEDS)) PAGES[k] = `https://www.ieso.ca/Sector-Participants/RSS-Feeds/${f.page}`;
const hostsOf = (src) => (src === "london-hydro" ? HOSTS["london-hydro"] : src === "aeso-grid-alert" ? HOSTS.aeso : HOSTS.ieso);
const REGION = { "london-hydro": "London", "aeso-grid-alert": "Alberta", "ieso-critical": "Ontario", "ieso-day0": "Ontario", "ieso-day1-34": "Ontario" };

// ---------- small helpers (mirrors of scripts/grid.mjs, which this file cannot import) ----------
const str = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const round3 = (x) => Math.round(x * 1000) / 1000;
const okLat = (x) => typeof x === "number" && isFinite(x) && Math.abs(x) <= 90;
const okLng = (x) => typeof x === "number" && isFinite(x) && Math.abs(x) <= 180;
const isoS = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
const isoOf = (s) => { const t = Date.parse(s || ""); return isFinite(t) && t > Date.UTC(1990, 0, 1) ? isoS(t) : ""; };
const badShape = (why) => Object.assign(new Error(`unexpected shape: ${why}`), { code: "bad_shape" });
const intOrNull = (x) => (x === null || x === undefined || String(x).trim() === "" || !isFinite(Number(x)) ? null : Math.max(0, Math.round(Number(x))));

function zoneOffset(ms, tz) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit",
    day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).formatToParts(new Date(ms)).map((x) => [x.type, x.value]));
  return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour % 24, +p.minute, +p.second) - Math.floor(ms / 1000) * 1000;
}
/** A local wall-clock time ("2026-11-19T13:28:00", "2026-11-19 13:28", "2026/11/19 13:28:00") in tz -> ISO UTC, or "".
 *  A time that carries its own zone (Z or an offset) is read as such. */
export function localToIso(s, tz = TZ) {
  const v = String(s || "").trim();
  if (/(Z|[+-]\d{2}:?\d{2})$/.test(v) && /\d{4}-\d{2}-\d{2}T/.test(v)) return isoOf(v);
  const m = v.match(/^(\d{4})[-/](\d{2})[-/](\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/);
  if (!m || +m[1] < 2010) return "";        // London Hydro's map treats 2001-01-01T00:00:00 as "no estimate"
  const guess = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
  let t = guess - zoneOffset(guess, tz);
  t = guess - zoneOffset(t, tz);
  return isFinite(t) ? isoS(t) : "";
}

const ENT = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'", nbsp: " " };
export const xmlText = (s) => String(s == null ? "" : s)
  .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
  .replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (all, e) => {
    if (e[0] === "#") { const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : ""; }
    return ENT[e.toLowerCase()] ?? all;
  });
const esc = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** Text of the first <tag> in x (CDATA and entities decoded, other markup removed), or "". */
const tag = (x, t) => {
  const m = String(x).match(new RegExp(`<${esc(t)}(?:\\s[^>]*)?>([\\s\\S]*?)</${esc(t)}>`, "i"));
  return m ? xmlText(m[1].replace(/<(?!!\[CDATA\[)[^>]*>/g, " ")).trim() : "";
};
const blocks = (x, t) => [...String(x).matchAll(new RegExp(`<${esc(t)}(?:\\s[^>]*)?>([\\s\\S]*?)</${esc(t)}>`, "gi"))].map((m) => m[1]);

/** An https url on the source's own hosts (an http link on the same host is upgraded), else the source page. */
export function ownLink(source, u) {
  let s = xmlText(u).trim();
  if (/^http:\/\//i.test(s)) s = "https://" + s.slice(7);
  if (!/^https:\/\/[^\s"'<>\\]+$/.test(s) || s.length > 300) return PAGES[source];
  try { return hostsOf(source).includes(new URL(s).host) ? s : PAGES[source]; } catch { return PAGES[source]; }
}

function mk(o) {
  const ll = okLat(o.lat) && okLng(o.lng);
  return {
    id: str(o.id, 120), source: o.source, country: "CA", region: REGION[o.source], area: str(o.area, 120),
    lat: ll ? round3(o.lat) : null, lng: ll ? round3(o.lng) : null, customers: intOrNull(o.customers), kind: o.kind,
    planned: !!o.planned, cause: str(o.cause, 120), level: o.level == null ? null : intOrNull(o.level),
    started_at: o.started_at || "", restore_est: o.restore_est || "", url: ownLink(o.source, o.url || ""),
  };
}

// ---------- London Hydro ----------
// The public map (www.londonhydro.com/outages/outage-map) loads outage_polygons_live.kml from Google Cloud Storage
// (drupalSettings baseUrl + layerUrl) and reads each Placemark's ExtendedData SimpleData fields. Its own code
// (parseKml, clickOnKmlLayerEventHandler) shows: EVENT_NUMBER, OFF_DATETIME (outage time, local, read with moment()),
// ESTIMATED_RESTORE (2001-01-01T00:00:00 = "TBD"; else RESTORE_DATETIME is shown), AFFECTEDWARDS (area), and for
// planned work WO (project id), START_DATE, END_DATE, DESCRIPTION. The schema also declares CUSTOMERS_OUT and
// OUTAGE_CUSTOMERS (the map never displays either), STATUS, CAUSE_CODE.
//   customers: CUSTOMERS_OUT of the placemark, else OUTAGE_CUSTOMERS; null when the KML carries neither (such an item is
//   listed but adds nothing to the incident thresholds). When several placemarks of one EVENT_NUMBER repeat the same
//   OUTAGE_CUSTOMERS and no CUSTOMERS_OUT, the number is counted once (on the first), so one event is not counted twice.
//   planned: a WO or START_DATE is present, or STATUS says planned. STATUS restored/closed/cancelled: left out.
//   centre: average of the polygon's outer-ring points (the closing point not repeated); a Point is used as is.
// No placemark has been seen live yet (the live file and the saved fixture, 2026-11-19 and -20, had empty Folders), so
// the field reading above is from the schema and the map code, and is tested on a placemark built from that schema.
export function parseLondonHydro(kml) {
  const x = String(kml || "");
  if (!/<kml[\s>]/i.test(x) || !/<Document[\s>]/i.test(x)) throw badShape("not a KML document");
  const out = [], counted = new Set();
  blocks(x, "Placemark").forEach((pm, i) => {
    const d = {};
    for (const m of pm.matchAll(/<SimpleData\s+name="([^"]+)"\s*(?:\/>|>([\s\S]*?)<\/SimpleData>)/gi)) d[m[1].toUpperCase()] = xmlText(m[2] || "").trim();
    for (const m of pm.matchAll(/<Data\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/Data>/gi)) d[m[1].toUpperCase()] = tag(m[2], "value");
    const status = d.STATUS || "";
    if (/restor|closed|cancel/i.test(status)) return;
    const rings = blocks(pm, "outerBoundaryIs");
    const pts = [];
    for (const c of (rings.length ? rings : [pm]).flatMap((r) => blocks(r, "coordinates"))) {
      const ring = c.trim().split(/\s+/).map((t) => t.split(",").map(Number)).filter((p) => p.length >= 2 && okLng(p[0]) && okLat(p[1]));
      if (ring.length > 1 && ring[0][0] === ring.at(-1)[0] && ring[0][1] === ring.at(-1)[1]) ring.pop();
      pts.push(...ring);
    }
    const lng = pts.length ? pts.reduce((a, p) => a + p[0], 0) / pts.length : null;
    const lat = pts.length ? pts.reduce((a, p) => a + p[1], 0) / pts.length : null;
    const ev = str(d.EVENT_NUMBER, 40);
    let customers = intOrNull(d.CUSTOMERS_OUT);
    if (customers == null) {
      customers = intOrNull(d.OUTAGE_CUSTOMERS);
      const k = `${ev}|${customers}`;
      if (customers != null && ev) { if (counted.has(k)) customers = null; else counted.add(k); }
    }
    const planned = !!(d.WO || d.START_DATE) || /plan/i.test(status);
    const code = str(d.CAUSE_CODE, 60);
    const ert = localToIso(d.ESTIMATED_RESTORE) || localToIso(d.RESTORE_DATETIME);
    const part = str(d.ID1, 20) || str(tag(pm, "name"), 40) || String(i);
    out.push(mk({
      source: "london-hydro", id: `london-hydro:${ev || "x"}-${part}`, area: d.AFFECTEDWARDS || "", lat, lng, customers,
      kind: "outage", planned, cause: /^\d+$/.test(code) ? `cause code ${code}` : code, level: null,
      started_at: localToIso(d.OFF_DATETIME) || (planned ? localToIso(d.START_DATE) : ""),
      restore_est: ert || (planned ? localToIso(d.END_DATE) : ""), url: PAGES["london-hydro"],
    }));
  });
  return out;
}

// ---------- IESO ----------
/** Advisory text -> { kind, level } by the mapping at the top of this file, or null (not a supply or emergency notice). */
export function iesoClass(text) {
  const t = String(text || "");
  if (/load[- ]?shed|rotating (power )?(outage|load|blackout)|rotational load/i.test(t)) return { kind: "load_shedding", level: 3 };
  if (/emergency operating state/i.test(t)) return { kind: "grid_emergency", level: 3 };
  const n = t.match(/\bEEA\s*-?\s*(?:level\s*)?([123])\b|energy emergency alert\s*(?:\(EEA\)\s*)?(?:level\s*)?-?\s*([123])\b/i);
  if (n) return { kind: "grid_emergency", level: +(n[1] || n[2]) };
  if (/\bEEA\b|energy emergency alert|high[- ]risk operating state/i.test(t)) return { kind: "grid_emergency", level: 2 };
  if (/capacity (margin|advisory|deficien|shortfall)|(supply|reserve) (shortfall|deficien)|insufficient (supply|capacity|reserve)|severe weather|(cold|hot|extreme) weather alert|conservative operations/i.test(t)) return { kind: "supply_warning", level: 1 };
  return null;
}

/** One IESO advisory RSS feed (source = ieso-critical | ieso-day0 | ieso-day1-34) -> signal items (see the header). */
export function parseIeso(xml, source, now = Date.now()) {
  if (!IESO_FEEDS[source]) throw badShape(`unknown IESO feed ${source}`);
  const x = String(xml || "");
  if (!/<rss[\s>]/i.test(x) || !/<channel[\s>]/i.test(x)) throw badShape("not an RSS feed");
  const out = [];
  for (const it of blocks(x, "item")) {
    const title = tag(it, "message:title") || tag(it, "title");
    const comment = tag(it, "message:comment") || tag(it, "description");
    let c = iesoClass(`${title} ${tag(it, "message:advisory_type")} ${comment}`);
    if (!c && source === "ieso-critical") c = { kind: "grid_emergency", level: 1 };
    if (!c) continue;
    const start = Date.parse(tag(it, "message:start_date")), end = Date.parse(tag(it, "message:end_date"));
    const pub = Date.parse(tag(it, "message:update_date") || tag(it, "pubDate") || tag(it, "message:issue_date"));
    if (isFinite(end) && end < now) continue;                                          // over
    if (!isFinite(start) && !isFinite(end) && isFinite(pub) && now - pub > STALE_HOURS * 3600e3) continue;
    const forecast = isFinite(start) ? start > now : source === "ieso-day1-34";
    if (forecast) c = { kind: "supply_warning", level: 0 };
    const id = str(tag(it, "message:message_id"), 30) || str(tag(it, "message:record_id"), 30) || str(`${title}-${isFinite(pub) ? isoS(pub) : ""}`, 80);
    out.push(mk({
      source, id: `${source}:${id}`, area: title, lat: null, lng: null, customers: null, kind: c.kind, planned: false,
      cause: "", level: c.level, started_at: isFinite(start) ? isoS(start) : isFinite(pub) ? isoS(pub) : "",
      restore_est: isFinite(end) ? isoS(end) : "", url: tag(it, "link"),
    }));
  }
  return out;
}

// ---------- AESO ----------
/** AESO Grid Alert RSS -> grid_emergency / load_shedding items; the "no feed items" placeholder means no alert ([]). */
export function parseAeso(xml, now = Date.now()) {
  const x = String(xml || "");
  if (!/<rss[\s>]/i.test(x) || !/<channel[\s>]/i.test(x)) throw badShape("not an RSS feed");
  const out = [];
  for (const it of blocks(x, "item")) {
    const title = tag(it, "title"), desc = tag(it, "description"), text = `${title} ${desc}`;
    if (/no feed items were found/i.test(title)) continue;
    if (!title && !desc) continue;
    if (/\b(has ended|ended|is over|cancell?ed|lifted|rescinded|no longer in effect|terminated)\b/i.test(text)) continue;
    const pub = Date.parse(tag(it, "pubDate") || tag(it, "dc:date"));
    if (isFinite(pub) && now - pub > STALE_HOURS * 3600e3) continue;
    const n = text.match(/\bEEA\s*-?\s*(?:level\s*)?([123])\b|energy emergency alert\s*(?:level\s*)?-?\s*([123])\b/i);
    const c = /load[- ]?shed|rotating (power )?outage/i.test(text) ? { kind: "load_shedding", level: 3 }
      : n ? { kind: "grid_emergency", level: +(n[1] || n[2]) } : { kind: "grid_emergency", level: 1 };
    // AESO's text is kept unmodified: the title goes in whole or not at all (the link carries it)
    const area = title.length <= 120 && !/[\u0000-\u001f\u007f<>]/.test(title) ? title : "";
    const key = str(tag(it, "guid"), 80) || str(tag(it, "link"), 80) || (isFinite(pub) ? isoS(pub) : str(title, 60));
    out.push(mk({
      source: "aeso-grid-alert", id: `aeso-grid-alert:${key}`, area, lat: null, lng: null, customers: null, kind: c.kind,
      planned: false, cause: "", level: c.level, started_at: isFinite(pub) ? isoS(pub) : isoS(now), restore_est: "",
      url: tag(it, "link"),
    }));
  }
  return out;
}

// ---------- the source file ----------
const sources = {
  "london-hydro": {
    name: "London Hydro", country: "CA", kind: "outages",
    url: "https://storage.googleapis.com/londonhydro-website-prod-www/outagemap/outage_polygons_live.kml",
    page: PAGES["london-hydro"], hosts: HOSTS["london-hydro"],
    terms_url: "https://www.londonhydro.com/privacy", terms_ok: "silent", customers_served: 169000,
  },
  "aeso-grid-alert": { signal: true,
    name: "AESO Grid Alert", country: "CA", url: "https://www.aeso.ca/rss/grid-alert/", page: PAGES["aeso-grid-alert"],
    hosts: HOSTS.aeso, terms_url: "https://www.aeso.ca/legal/", terms_ok: "allowed", customers_served: null,
    attribution: AESO_ATTRIBUTION,
  },
};
for (const [k, f] of Object.entries(IESO_FEEDS)) {
  sources[k] = { signal: true, name: f.name, country: "CA", url: `https://www.ieso.ca/-/media/Files/IESO/Rss/${f.feed}`, page: PAGES[k],
    hosts: HOSTS.ieso, terms_url: IESO_TERMS, terms_ok: "allowed", customers_served: null, attribution: IESO_ATTRIBUTION };
}

const regions = {
  "london-hydro|London": { name: "London, Ontario", lat: 42.98, lng: -81.25 },
  "aeso-grid-alert|Alberta": { name: "Alberta (AESO)", lat: 52.5, lng: -114.0 },
};
for (const k of Object.keys(IESO_FEEDS)) regions[`${k}|Ontario`] = { name: "Ontario (IESO)", lat: 44.5, lng: -79.7 };

const adapters = {
  "london-hydro": async (h) => parseLondonHydro(await h.get(h.SOURCES["london-hydro"].url, { as: "text" })).map(h.item),
  "aeso-grid-alert": async (h) => parseAeso(await h.get(h.SOURCES["aeso-grid-alert"].url, { as: "text" })).map(h.item),
};
for (const k of Object.keys(IESO_FEEDS)) adapters[k] = async (h) => parseIeso(await h.get(h.SOURCES[k].url, { as: "text" }), k).map(h.item);

export default { sources, regions, adapters };
