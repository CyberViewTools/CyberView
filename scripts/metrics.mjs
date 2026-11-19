// Pipeline metrics, no AI model. Run: node scripts/metrics.mjs [--json]
// What the research pipeline did in the last 7 days: which sources and collectors produce leads that become events,
// which only make noise, how long a story takes to reach the map, how much rests on one source, and which regions are thin.
// The editor job reads this every week to tune config/queries.json and config/feeds.json; the build puts a summary on the status page.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, readJson, listEventFiles, dayAgo } from "./lib/store.mjs";
import { forEachSkipped } from "./lib/store.mjs";

const REGION = { "united states": "north-america", canada: "north-america", mexico: "latin-america", brazil: "latin-america", argentina: "latin-america", colombia: "latin-america", chile: "latin-america", peru: "latin-america",
  "united kingdom": "europe", ireland: "europe", france: "europe", germany: "europe", netherlands: "europe", belgium: "europe", spain: "europe", portugal: "europe", italy: "europe", switzerland: "europe", austria: "europe", poland: "europe", ukraine: "europe", norway: "europe", sweden: "europe", finland: "europe", denmark: "europe", czechia: "europe", romania: "europe", greece: "europe", russia: "europe",
  turkey: "middle-east", israel: "middle-east", iran: "middle-east", "saudi arabia": "middle-east", "united arab emirates": "middle-east", qatar: "middle-east", egypt: "middle-east", jordan: "middle-east", iraq: "middle-east", kuwait: "middle-east",
  nigeria: "africa", kenya: "africa", "south africa": "africa", ghana: "africa", ethiopia: "africa", morocco: "africa", senegal: "africa", tanzania: "africa", uganda: "africa", algeria: "africa", tunisia: "africa",
  india: "south-asia", pakistan: "south-asia", bangladesh: "south-asia", "sri lanka": "south-asia", nepal: "south-asia",
  singapore: "southeast-asia", indonesia: "southeast-asia", malaysia: "southeast-asia", thailand: "southeast-asia", vietnam: "southeast-asia", philippines: "southeast-asia",
  japan: "east-asia", "south korea": "east-asia", china: "east-asia", taiwan: "east-asia", "hong kong": "east-asia", australia: "oceania", "new zealand": "oceania" };
export const regionOf = (country) => REGION[String(country || "").toLowerCase().trim()] || (country ? "other" : "unplaced");
const median = (a) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

/** Pure: leads [{source,via,url,seen_at}], events [{sources,first_seen,country,validation,status}], skipped {url: reason} -> metrics. */
export function compute(leads, events, skipped) {
  const srcOf = new Map(leads.map((l) => [l.url, l])), bySource = {}, byVia = {};
  const row = (o, k) => (o[k] ||= { leads: 0, used: 0, skipped: 0 });
  for (const l of leads) { row(bySource, l.source).leads++; row(byVia, l.via || "rss").leads++; if (skipped[l.url]) { row(bySource, l.source).skipped++; row(byVia, l.via || "rss").skipped++; } }
  const lat = [], regions = {}; let single = 0, fromLeads = 0;
  for (const e of events) {
    regions[regionOf(e.country)] = (regions[regionOf(e.country)] || 0) + 1;
    if (e.validation && e.validation.state === "single_source") single++;
    const hits = (e.sources || []).map((s) => srcOf.get(s.url)).filter(Boolean);
    if (hits.length) fromLeads++;
    for (const l of hits) { row(bySource, l.source).used++; row(byVia, l.via || "rss").used++; }
    const first = Math.min(...hits.map((l) => Date.parse(l.seen_at)).filter(isFinite)), added = Date.parse(e.first_seen);
    if (isFinite(first) && isFinite(added) && added >= first) lat.push((added - first) / 36e5);
  }
  const rank = (o) => Object.entries(o).map(([name, v]) => ({ name, ...v, yield: v.leads ? Math.round((v.used / v.leads) * 100) : 0 })).sort((a, b) => b.used - a.used || b.leads - a.leads);
  return { events: events.length, leads: leads.length, events_from_leads: fromLeads, single_source: single, median_hours_lead_to_event: lat.length ? Math.round(median(lat) * 10) / 10 : null,
    regions, sources: rank(bySource), collectors: rank(byVia),
    noisy: rank(bySource).filter((s) => s.leads >= 15 && s.used === 0).map((s) => s.name), silent: [] };
}

export function load(days = 7) {
  const leads = [], dir = join(DATA, "leads");
  if (existsSync(dir)) for (const f of readdirSync(dir).filter((f) => f.endsWith(".jsonl") && f.slice(0, 10) >= dayAgo(days)))
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) { try { const l = JSON.parse(line); if (l.url) leads.push(l); } catch {} }
  const skipped = {}, runsDir = join(DATA, "runs");
  forEachSkipped(days, (u, why) => { skipped[u] = String(why || "").slice(0, 60); });
  const events = listEventFiles().map((f) => f.e).filter((e) => e && !e.duplicate_of && String(e.first_seen || e.date) >= dayAgo(days));
  const m = compute(leads, events, skipped), osint = readJson(join(DATA, "osint.json"), { sources: {} }), st = readJson(join(DATA, "status.json"), {});
  m.failing = Object.entries(osint.sources || {}).filter(([, v]) => !v.ok).map(([k, v]) => `${k}: ${v.error}`).concat(st.collect_failed || []);
  m.stories = { open: st.stories_open ?? null, corroborated: st.stories_corroborated ?? null, claims: st.stories_claims ?? null };
  return m;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const m = load();
  if (process.argv.includes("--json")) { console.log(JSON.stringify(m)); process.exit(0); }
  console.log(`Last 7 days: ${m.leads} leads -> ${m.events} events (${m.events_from_leads} traced to a lead; ${m.single_source} rest on a single source). Median ${m.median_hours_lead_to_event ?? "n/a"} h from first lead to event.`);
  console.log(`Open stories: ${m.stories.open} (${m.stories.corroborated} with two or more publishers, ${m.stories.claims} claims only).`);
  console.log("Events by region: " + Object.entries(m.regions).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", "));
  console.log("Collectors (leads, became events, cleared): " + m.collectors.map((c) => `${c.name} ${c.leads}/${c.used}/${c.skipped}`).join("; "));
  console.log("Top sources by events: " + m.sources.slice(0, 15).map((s) => `${s.name} ${s.used}/${s.leads}`).join("; "));
  console.log("Many leads, no events (noise candidates): " + (m.noisy.join("; ") || "none"));
  console.log("Failing: " + (m.failing.join("; ") || "none"));
}
