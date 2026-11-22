// Context layers for the map, no AI model. Run: node scripts/context.mjs   (behind a proxy: NODE_USE_ENV_PROXY=1)
// Fetched here, at build time, and served from the site itself, so the page never calls third parties
// (the CSP allows connect-src 'self' only).
//   data/context/ioda.json    internet disruption signals by country, last 24 h (IODA, Georgia Tech)
//   data/context/gdacs.json   orange and red disaster alerts now current (GDACS, EU JRC and UN OCHA)
// Each file: { layer, source, source_url, fetched_at, ok, error, items[] }. When a source fails, the old items are
// kept with ok:false and the error, so the map shows the layer as stale instead of empty.
// Neither layer is an attack report: outages are shown as outages (see CLAUDE.md).
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, ROOT, readJson, writeJson, nowIso, writeRunLog, readStatus } from "./lib/store.mjs";
import { get } from "./lib/net.mjs";

// IODA's country names -> the short names in site/world-110m.json (only where they differ)
const MAP_NAME = {
  "united states": "United States of America", "democratic republic of the congo": "Dem. Rep. Congo", "republic of the congo": "Congo",
  "central african republic": "Central African Rep.", "equatorial guinea": "Eq. Guinea", "south sudan": "S. Sudan",
  "lao peoples democratic republic": "Laos", "brunei darussalam": "Brunei", "swaziland": "eSwatini", "solomon islands": "Solomon Is.",
  "bosnia and herzegovina": "Bosnia and Herz.", "dominican republic": "Dominican Rep.", "czech republic": "Czechia",
  "ivory coast": "Côte d'Ivoire", "cote d'ivoire": "Côte d'Ivoire", "korea, republic of": "South Korea", "republic of korea": "South Korea",
  "korea, democratic people's republic of": "North Korea", "russian federation": "Russia", "viet nam": "Vietnam",
  "iran, islamic republic of": "Iran", "syrian arab republic": "Syria", "moldova, republic of": "Moldova", "tanzania, united republic of": "Tanzania",
  "bolivia, plurinational state of": "Bolivia", "venezuela, bolivarian republic of": "Venezuela", "palestinian territory": "Palestine",
  "macedonia, the former yugoslav republic of": "Macedonia", "north macedonia": "Macedonia", "falkland islands (malvinas)": "Falkland Is.",
  "taiwan, province of china": "Taiwan", "east timor": "Timor-Leste", "western sahara": "W. Sahara",
};
const mapNames = new Set(readJson(join(ROOT, "site", "world-110m.json"), { objects: { countries: { geometries: [] } } })
  .objects.countries.geometries.map((g) => g.properties.name));
export const toMapName = (n) => { const m = MAP_NAME[String(n).toLowerCase()] || n; return mapNames.has(m) ? m : ""; };
const str = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const badShape = () => Object.assign(new Error("unexpected shape"), { code: "bad_shape" });
const GDACS_TYPE = { EQ: "earthquake", TC: "tropical cyclone", FL: "flood", VO: "volcano", DR: "drought", WF: "wildfire", TS: "tsunami" };

/** IODA /v2/outages/summary (entityType=country) -> the strongest 40 country signals. */
export function parseIoda(d) {
  if (!d || !Array.isArray(d.data)) throw badShape();
  return d.data
    .filter((x) => x && x.entity && /^[A-Z]{2}$/.test(x.entity.code) && x.scores && Number(x.scores.overall) > 0)
    .map((x) => ({
      code: x.entity.code,
      name: str(x.entity.name, 60),
      map_name: toMapName(x.entity.name),
      score: Math.round(Number(x.scores.overall)),
      events: Number(x.event_cnt) || 0,
      // which measurements saw it: bgp (routing), ping-slash24 (active probing), gtr (Google traffic), merit-nt (telescope)
      signals: [...new Set(Object.keys(x.scores).filter((k) => k !== "overall").map((k) => k.split(".")[0]))].slice(0, 4),
      url: `https://ioda.inetintel.cc.gatech.edu/country/${x.entity.code}`,
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 40);
}

// the five XML entities GDACS uses in titles and country lists
const unent = (s) => String(s || "").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#0*39;/g, "'").replace(/&amp;/g, "&");
const rssTag = (block, name) => { const m = block.match(new RegExp(`<${name}>([\\s\\S]*?)</${name}>`, "i")); return m ? m[1].trim() : ""; };

/** GDACS GeoRSS (https://www.gdacs.org/xml/rss.xml) -> current orange and red alerts with a point.
 *  Was the EVENTS4APP endpoint, but that returns only the ~100 most recent events and silently dropped the ongoing
 *  orange drought alerts (2026-11-22: it answered 100 all-green while GDACS had 4 current orange events). The RSS feed
 *  carries every current alert with its level and a representative point. `gdacs:iscurrent` is not a severity signal
 *  here (its "true" items are green wildfires, the orange alerts are "false"), so the alert level plus a valid point
 *  decide, and each event is kept once. */
export function parseGdacsRss(xml) {
  if (typeof xml !== "string" || !/<rss[\s>]/i.test(xml)) throw badShape();
  const seen = new Set(), out = [];
  for (const it of xml.match(/<item\b[\s\S]*?<\/item>/gi) || []) {
    const level = rssTag(it, "gdacs:alertlevel");
    if (!/^(Orange|Red)$/.test(level)) continue;
    const eventtype = rssTag(it, "gdacs:eventtype"), eventid = rssTag(it, "gdacs:eventid");
    const num = (s) => (String(s).trim() === "" ? NaN : Number(s));   // Number("") is 0, which would plot at (0,0)
    let lat = num(rssTag(it, "geo:lat")), lng = num(rssTag(it, "geo:long"));
    if (!(isFinite(lat) && isFinite(lng))) { const p = rssTag(it, "georss:point").split(/\s+/).map(num); if (p.length === 2) [lat, lng] = p; }
    if (!(isFinite(lat) && isFinite(lng)) || Math.abs(lat) > 90 || Math.abs(lng) > 180) continue;
    if (!/^\d+$/.test(eventid)) continue;
    const id = str(`${eventtype}-${eventid}`, 40);
    if (seen.has(id)) continue; seen.add(id);
    out.push({
      id,
      type: GDACS_TYPE[eventtype] || "other",
      level: level.toLowerCase(),
      name: str(unent(rssTag(it, "title")), 120),
      country: str(unent(rssTag(it, "gdacs:country")), 80),
      from: str(rssTag(it, "gdacs:fromdate"), 32), to: str(rssTag(it, "gdacs:todate"), 32),
      lat: Math.round(lat * 1e4) / 1e4, lng: Math.round(lng * 1e4) / 1e4,
      // build the report link from the ids so a mangled <link> can never inject a non-GDACS or non-https URL
      url: /^[A-Z]{2}$/.test(eventtype) ? `https://www.gdacs.org/report.aspx?eventtype=${eventtype}&eventid=${eventid}` : "",
    });
    if (out.length >= 60) break;
  }
  return out;
}

/** GDACS ARCHIVE GeoJSON -> recent significant orange and red alerts of EVERY hazard type, with a point.
 *  The current-alerts RSS only keeps what is active this minute, so a passed earthquake or cyclone vanishes and the
 *  layer can read near-empty. The ARCHIVE endpoint carries GDACS's recent notable orange/red events across all types
 *  (earthquakes, cyclones, floods, volcanoes, wildfires, droughts). Same output shape as the RSS parser; newest
 *  first, capped. The report link is built from the ids so a mangled url field cannot inject a non-GDACS URL. */
export function parseGdacsArchive(d) {
  if (!d || !Array.isArray(d.features)) throw badShape();
  const seen = new Set(), out = [];
  for (const f of d.features) {
    const p = f && f.properties, g = f && f.geometry;
    if (!p || !/^(Orange|Red)$/.test(p.alertlevel) || !g || g.type !== "Point" || !Array.isArray(g.coordinates)) continue;
    const [lng, lat] = g.coordinates.map(Number);
    if (!(isFinite(lat) && isFinite(lng)) || Math.abs(lat) > 90 || Math.abs(lng) > 180) continue;
    if (!/^\d+$/.test(String(p.eventid))) continue;
    const id = str(`${p.eventtype}-${p.eventid}`, 40);
    if (seen.has(id)) continue; seen.add(id);
    out.push({
      id,
      type: GDACS_TYPE[p.eventtype] || "other",
      level: String(p.alertlevel).toLowerCase(),
      name: str(p.name || p.description, 120),
      country: str(p.country, 80),
      from: str(p.fromdate, 32), to: str(p.todate, 32),
      lat: Math.round(lat * 1e4) / 1e4, lng: Math.round(lng * 1e4) / 1e4,
      url: /^[A-Z]{2}$/.test(String(p.eventtype)) ? `https://www.gdacs.org/report.aspx?eventtype=${p.eventtype}&eventid=${p.eventid}` : "",
    });
  }
  out.sort((a, b) => String(b.from).localeCompare(String(a.from)));   // newest first
  return out.slice(0, 80);
}

// No query params on purpose. The endpoint returns the full recent notable set (every hazard type, all orange/red);
// an `alertlevel` filter paradoxically narrows it to a handful, and a semicolon `eventlist` does not survive Node's
// fetch path (only the first type is honoured). The parser keeps orange/red and every type itself.
const GDACS_ARCHIVE = "https://www.gdacs.org/gdacsapi/api/events/geteventlist/ARCHIVE";

export const LAYERS = {
  ioda: {
    source: "IODA, Georgia Tech Internet Intelligence Lab",
    source_url: "https://ioda.inetintel.cc.gatech.edu/",
    async fetch() {
      const until = Math.floor(Date.now() / 1000), from = until - 86400;
      return parseIoda(await get(`https://api.ioda.inetintel.cc.gatech.edu/v2/outages/summary?from=${from}&until=${until}&entityType=country`));
    },
  },
  gdacs: {
    source: "GDACS, Global Disaster Alert and Coordination System",
    source_url: "https://www.gdacs.org/",
    async fetch() {
      // ARCHIVE carries recent significant orange/red events of every type; the "current" RSS is the fallback if it ever returns nothing
      const a = parseGdacsArchive(await get(GDACS_ARCHIVE, { timeoutMs: 30000 }));
      return a.length ? a : parseGdacsRss(await get("https://www.gdacs.org/xml/rss.xml", { as: "text", timeoutMs: 30000 }));
    },
  },
};

async function main() {
  const log = { started_at: nowIso(), layers: {}, failed: [] };
  for (const [layer, def] of Object.entries(LAYERS)) {
    const p = join(DATA, "context", `${layer}.json`), old = readJson(p, {});
    const base = { layer, source: def.source, source_url: def.source_url };
    try {
      const items = await def.fetch();
      writeJson(p, { ...base, fetched_at: nowIso(), ok: true, error: "", items });
      log.layers[layer] = items.length;
    } catch (e) {
      const code = str(e.code || e.message, 60);
      writeJson(p, { ...base, fetched_at: old.fetched_at || "", ok: false, error: code, items: Array.isArray(old.items) ? old.items : [] });
      log.failed.push(`${layer}: ${code}`);
    }
  }
  const sp = join(DATA, "status.json"), st = readStatus();
  st.last_context_at = nowIso();
  writeJson(sp, st);
  log.finished_at = nowIso();
  writeRunLog("context", log);
  console.log(`context: ${Object.entries(log.layers).map(([k, v]) => `${k} ${v}`).join(", ") || "nothing"}` + (log.failed.length ? `; failed: ${log.failed.join("; ")}` : ""));
  process.exit(Object.keys(log.layers).length ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
