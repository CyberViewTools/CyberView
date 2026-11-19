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
const httpsOnly = (u) => (/^https:\/\/[^\s"'<>]+$/.test(String(u || "")) ? String(u) : "");
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

/** GDACS EVENTS4APP GeoJSON -> current orange and red alerts with a point. */
export function parseGdacs(d) {
  if (!d || !Array.isArray(d.features)) throw badShape();
  return d.features
    .filter((f) => f && f.properties && /^(Orange|Red)$/.test(f.properties.alertlevel) && f.properties.iscurrent !== "false"
      && f.geometry && f.geometry.type === "Point" && Array.isArray(f.geometry.coordinates))
    .map((f) => {
      const p = f.properties, [lng, lat] = f.geometry.coordinates.map(Number);
      return {
        id: str(`${p.eventtype}-${p.eventid}`, 40),
        type: GDACS_TYPE[p.eventtype] || "other",
        level: p.alertlevel.toLowerCase(),
        name: str(p.name || p.description, 120),
        country: str(p.country, 80),
        from: str(p.fromdate, 19), to: str(p.todate, 19),
        lat: Math.round(lat * 1e4) / 1e4, lng: Math.round(lng * 1e4) / 1e4,
        url: httpsOnly(p.url && p.url.report),
      };
    })
    .filter((x) => isFinite(x.lat) && isFinite(x.lng) && Math.abs(x.lat) <= 90 && Math.abs(x.lng) <= 180)
    .slice(0, 60);
}

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
    async fetch() { return parseGdacs(await get("https://www.gdacs.org/gdacsapi/api/events/geteventlist/EVENTS4APP")); },
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
