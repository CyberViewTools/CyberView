// Pipeline metrics, no AI model. Run: node scripts/metrics.mjs [--json]
// What the research pipeline did in the last 7 days (or as many days as the lead files cover; the output says which): which sources and collectors produce leads that become events,
// which only make noise, how long a story takes to reach the map, how much rests on one source, and which regions are thin.
// The editor job reads this every week to tune config/queries.json and config/feeds.json; the build puts a summary on the status page.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, readJson, listEventFiles, dayAgo } from "./lib/store.mjs";
import { forEachSkipped } from "./lib/store.mjs";
import { cluster } from "./fuse.mjs";

const REGION = { "united states": "north-america", canada: "north-america", mexico: "latin-america", brazil: "latin-america", argentina: "latin-america", colombia: "latin-america", chile: "latin-america", peru: "latin-america",
  "united kingdom": "europe", ireland: "europe", france: "europe", germany: "europe", netherlands: "europe", belgium: "europe", spain: "europe", portugal: "europe", italy: "europe", switzerland: "europe", austria: "europe", poland: "europe", ukraine: "europe", norway: "europe", sweden: "europe", finland: "europe", denmark: "europe", czechia: "europe", romania: "europe", greece: "europe", russia: "europe",
  turkey: "middle-east", israel: "middle-east", iran: "middle-east", "saudi arabia": "middle-east", "united arab emirates": "middle-east", qatar: "middle-east", egypt: "middle-east", jordan: "middle-east", iraq: "middle-east", kuwait: "middle-east",
  nigeria: "africa", kenya: "africa", "south africa": "africa", ghana: "africa", ethiopia: "africa", morocco: "africa", senegal: "africa", tanzania: "africa", uganda: "africa", algeria: "africa", tunisia: "africa",
  india: "south-asia", pakistan: "south-asia", bangladesh: "south-asia", "sri lanka": "south-asia", nepal: "south-asia",
  singapore: "southeast-asia", indonesia: "southeast-asia", malaysia: "southeast-asia", thailand: "southeast-asia", vietnam: "southeast-asia", philippines: "southeast-asia",
  japan: "east-asia", "south korea": "east-asia", china: "east-asia", taiwan: "east-asia", "hong kong": "east-asia", australia: "oceania", "new zealand": "oceania",
  // more countries and the spellings events use (2026-11-21): without them an event in Türkiye, Lebanon, Trinidad or
  // Uzbekistan counted as "other" and the coverage report understated exactly the regions it is meant to watch. Central
  // Asia and the Caucasus go with the Middle East, as the feeds label them (UzCERT).
  us: "north-america", usa: "north-america", "united states of america": "north-america", uk: "europe", "great britain": "europe", uae: "middle-east",
  türkiye: "middle-east", turkiye: "middle-east", lebanon: "middle-east", syria: "middle-east", yemen: "middle-east", oman: "middle-east", bahrain: "middle-east",
  palestine: "middle-east", cyprus: "middle-east", kazakhstan: "middle-east", uzbekistan: "middle-east", kyrgyzstan: "middle-east", tajikistan: "middle-east",
  turkmenistan: "middle-east", azerbaijan: "middle-east", armenia: "middle-east", georgia: "middle-east", afghanistan: "south-asia", maldives: "south-asia", bhutan: "south-asia",
  libya: "africa", sudan: "africa", "south sudan": "africa", mauritania: "africa", mali: "africa", niger: "africa", chad: "africa", "burkina faso": "africa",
  "côte d'ivoire": "africa", "cote d'ivoire": "africa", "ivory coast": "africa", benin: "africa", togo: "africa", guinea: "africa", "sierra leone": "africa", liberia: "africa",
  gambia: "africa", "cabo verde": "africa", "cape verde": "africa", cameroon: "africa", gabon: "africa", congo: "africa", "democratic republic of the congo": "africa", "dr congo": "africa",
  angola: "africa", zambia: "africa", zimbabwe: "africa", malawi: "africa", mozambique: "africa", namibia: "africa", botswana: "africa", lesotho: "africa", eswatini: "africa",
  madagascar: "africa", mauritius: "africa", seychelles: "africa", rwanda: "africa", burundi: "africa", somalia: "africa", djibouti: "africa", eritrea: "africa",
  venezuela: "latin-america", ecuador: "latin-america", bolivia: "latin-america", paraguay: "latin-america", uruguay: "latin-america", guatemala: "latin-america",
  honduras: "latin-america", "el salvador": "latin-america", nicaragua: "latin-america", "costa rica": "latin-america", panama: "latin-america", cuba: "latin-america",
  "dominican republic": "latin-america", haiti: "latin-america", jamaica: "latin-america", "trinidad and tobago": "latin-america", barbados: "latin-america", bahamas: "latin-america",
  guyana: "latin-america", suriname: "latin-america", belize: "latin-america", "puerto rico": "latin-america",
  belgium: "europe", luxembourg: "europe", iceland: "europe", estonia: "europe", latvia: "europe", lithuania: "europe", slovakia: "europe", slovenia: "europe", croatia: "europe",
  serbia: "europe", bosnia: "europe", "bosnia and herzegovina": "europe", montenegro: "europe", albania: "europe", "north macedonia": "europe", kosovo: "europe", bulgaria: "europe",
  hungary: "europe", moldova: "europe", belarus: "europe", malta: "europe", "czech republic": "europe",
  "north korea": "east-asia", mongolia: "east-asia", macau: "east-asia", cambodia: "southeast-asia", laos: "southeast-asia", myanmar: "southeast-asia", brunei: "southeast-asia",
  "timor-leste": "southeast-asia", fiji: "oceania", "papua new guinea": "oceania", samoa: "oceania", tonga: "oceania", vanuatu: "oceania" };
// collectors that no longer run (scripts/osint.mjs): their old leads stay in every count, but the status page lists them
// as retired, never as a current source
export const RETIRED_COLLECTORS = { "google-news": { retired: "2026-11-20", why: "Not collected since 2026-11-20: news.google.com/robots.txt disallows /rss/ and its links are redirects that cannot be cited. Bing News and GDELT run the same standing searches." } };
export const regionOf = (country) => REGION[String(country || "").toLowerCase().trim()] || (country ? "other" : "unplaced");
const median = (a) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

/** Pure: what a story closure's reason says it ended as. "event" when the reason is (or starts with) an event id,
 *  "update" when it says the story updated an event; "" for everything else (not an event, could not confirm, and
 *  "already on file", a duplicate of an event that added nothing unless one of its pages was cited, see storyCredit). */
export function closureOutcome(reason, ids = new Set()) {
  const r = String(reason || "").trim();
  if (/^updated\b/i.test(r)) return "update";
  const first = r.split(/[\s:;,()]/)[0];
  return first && ids.has(first) ? "event" : "";
}

/** Pure: which leads were USED, credited by story, not by URL: a lead counts when the story it was fused into ended as
 *  an event or an update. Stories are fuse's own, as their closures recorded them (closures.jsonl: {at, story, reason,
 *  urls}); leads no closure names are grouped the way fuse groups them (clusterFn, fuse.mjs cluster). A story also counts
 *  when one of its pages is cited by an event (an "already on file" story whose page was added to that event).
 *  leads [{url,title}], events [{id,sources,duplicate_of}], closures [...] -> Map(url -> "event"|"update"|"cited").
 *  out (optional object): receives `storyOf`, Map(url -> story key), so a caller can count stories without grouping twice. */
export const MAX_STORY = 30;
export function storyCredit(leads, events, closures = [], clusterFn = cluster, out = null) {
  const ids = new Set(events.map((e) => e && e.id).filter(Boolean)), storyOf = new Map(), good = new Map();
  const sorted = closures.filter((c) => c && Array.isArray(c.urls)).slice().sort((a, b) => String(a.at || "").localeCompare(String(b.at || "")));
  sorted.forEach((c, i) => c.urls.forEach((u) => storyOf.set(u, "s:" + (c.story || "i" + i))));
  const rest = [], seen = new Set();
  for (const l of leads) if (l && l.url && !storyOf.has(l.url) && !seen.has(l.url)) { seen.add(l.url); rest.push(l); }
  const titled = rest.filter((l) => l.title);
  rest.filter((l) => !l.title).forEach((l) => storyOf.set(l.url, "u:" + l.url));
  // grouped one day of leads at a time, as fuse sees them; a group larger than MAX_STORY is word-chaining across unrelated
  // reports (one Java advisory linking hundreds of headlines), so its leads are credited one by one instead
  const byDay = new Map(); titled.forEach((l) => { const d = String(l.seen_at || "").slice(0, 10); (byDay.get(d) || byDay.set(d, []).get(d)).push(l); });
  let gi = 0;
  for (const day of byDay.values()) for (const g of clusterFn ? clusterFn(day) : day.map((l) => [l])) {
    if (g.length > MAX_STORY) g.forEach((l) => storyOf.set(l.url, "u:" + l.url)); else { gi++; g.forEach((l) => storyOf.set(l.url, "c:" + gi)); }
  }
  const mark = (k, how) => { if (k && (!good.has(k) || good.get(k) === "cited")) good.set(k, how); };
  for (const c of sorted) { const how = closureOutcome(c.reason, ids); if (how) c.urls.forEach((u) => mark(storyOf.get(u), how)); }
  for (const e of events) if (e && !e.duplicate_of) for (const s of e.sources || []) { const k = storyOf.get((s && s.url) || s); if (k && !good.has(k)) good.set(k, "cited"); }
  const used = new Map();
  for (const l of leads) if (l && l.url && good.has(storyOf.get(l.url))) used.set(l.url, good.get(storyOf.get(l.url)));
  if (out && typeof out === "object") out.storyOf = storyOf;
  return used;
}

/** Pure: how many days the lead files really cover: from the first lead seen to now, never more than asked for. */
export function coveredDays(leads, days, now = Date.now()) {
  const t = Math.min(...leads.map((l) => Date.parse(l.seen_at)).filter(isFinite));
  return isFinite(t) ? Math.max(0, Math.min(days, Math.round(((now - t) / 864e5) * 10) / 10)) : 0;
}

/** Pure: leads [{source,via,url,seen_at,title}], events [{sources,first_seen,country,validation,status}], skipped {url: reason},
 *  closures [{at,story,reason,urls}] (optional), allEvents (events of any date, for the story credit; defaults to events)
 *  -> metrics. A lead is "used" when its story became an event or an update (storyCredit); "skipped" counts the rest
 *  that a run log or a closure ruled out. */
export function compute(leads, events, skipped, closures = [], allEvents = events, clusterFn = cluster) {
  const srcOf = new Map(leads.map((l) => [l.url, l])), bySource = {}, byVia = {}, used = storyCredit(leads, allEvents, closures, clusterFn);
  const row = (o, k) => (o[k] ||= { leads: 0, used: 0, skipped: 0 });
  for (const l of leads) {
    const v = l.via || "rss";
    row(bySource, l.source).leads++; row(byVia, v).leads++;
    if (used.has(l.url)) { row(bySource, l.source).used++; row(byVia, v).used++; }
    else if (skipped[l.url]) { row(bySource, l.source).skipped++; row(byVia, v).skipped++; }
  }
  const lat = [], regions = {}; let single = 0, fromLeads = 0;
  for (const e of events) {
    regions[regionOf(e.country)] = (regions[regionOf(e.country)] || 0) + 1;
    if (e.validation && e.validation.state === "single_source") single++;
    const hits = (e.sources || []).map((s) => srcOf.get(s.url)).filter(Boolean);
    if (hits.length) fromLeads++;
    const first = Math.min(...hits.map((l) => Date.parse(l.seen_at)).filter(isFinite)), added = Date.parse(e.first_seen);
    if (isFinite(first) && isFinite(added) && added >= first) lat.push((added - first) / 36e5);
  }
  const rank = (o) => Object.entries(o).map(([name, v]) => ({ name, ...v, yield: v.leads ? Math.round((v.used / v.leads) * 100) : 0 })).sort((a, b) => b.used - a.used || b.leads - a.leads);
  return { events: events.length, leads: leads.length, leads_used: used.size, events_from_leads: fromLeads, single_source: single, median_hours_lead_to_event: lat.length ? Math.round(median(lat) * 10) / 10 : null,
    regions, sources: rank(bySource), collectors: rank(byVia),
    noisy: rank(bySource).filter((s) => s.leads >= 15 && s.used === 0).map((s) => s.name), silent: [] };
}

/** Every story closure (closures.jsonl) of the last `days` days. */
export function loadClosures(days = 7) {
  const out = [], rd = join(DATA, "runs");
  if (existsSync(rd)) for (const d of readdirSync(rd).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d) && d >= dayAgo(days))) {
    const p = join(rd, d, "closures.jsonl"); if (!existsSync(p)) continue;
    for (const line of readFileSync(p, "utf8").split("\n")) { if (!line) continue; try { const c = JSON.parse(line); if (c && Array.isArray(c.urls)) out.push(c); } catch {} }
  }
  return out;
}

export function load(days = 7) {
  const leads = [], dir = join(DATA, "leads");
  if (existsSync(dir)) for (const f of readdirSync(dir).filter((f) => f.endsWith(".jsonl") && f.slice(0, 10) >= dayAgo(days)))
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) { try { const l = JSON.parse(line); if (l.url) leads.push(l); } catch {} }
  const skipped = {}, runsDir = join(DATA, "runs");
  forEachSkipped(days, (u, why) => { skipped[u] = String(why || "").slice(0, 60); });
  const all = listEventFiles().map((f) => f.e).filter(Boolean), events = all.filter((e) => !e.duplicate_of && String(e.first_seen || e.date) >= dayAgo(days));
  // closures from a few days before the window too: a lead seen on day one may sit in a story closed the day before
  const m = compute(leads, events, skipped, loadClosures(days + 3), all), osint = readJson(join(DATA, "osint.json"), { sources: {} }), st = readJson(join(DATA, "status.json"), {});
  m.failing = Object.entries(osint.sources || {}).filter(([, v]) => !v.ok).map(([k, v]) => `${k}: ${v.error}`).concat(st.collect_failed || []);
  m.window = { days, days_covered: coveredDays(leads, days), from: leads.map((l) => l.seen_at).filter(Boolean).sort()[0] || null };
  m.stories = { open: st.stories_open ?? null, corroborated: st.stories_corroborated ?? null, claims: st.stories_claims ?? null };
  return m;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const m = load();
  if (process.argv.includes("--json")) { console.log(JSON.stringify(m)); process.exit(0); }
  console.log(`Last ${m.window.days_covered} days of leads (asked for 7; the lead files start ${String(m.window.from || "nowhere").slice(0, 10)}): ${m.leads} leads, ${m.leads_used} in stories that became or updated an event -> ${m.events} events (${m.events_from_leads} traced to a lead; ${m.single_source} rest on a single source). Median ${m.median_hours_lead_to_event ?? "n/a"} h from first lead to event.`);
  console.log(`Open stories: ${m.stories.open} (${m.stories.corroborated} with two or more publishers, ${m.stories.claims} claims only).`);
  console.log("Events by region: " + Object.entries(m.regions).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", "));
  console.log("Collectors (leads, used by story, cleared): " + m.collectors.map((c) => `${c.name} ${c.leads}/${c.used}/${c.skipped}`).join("; "));
  console.log("Top sources by events: " + m.sources.slice(0, 15).map((s) => `${s.name} ${s.used}/${s.leads}`).join("; "));
  console.log("Many leads, no events (noise candidates): " + (m.noisy.join("; ") || "none"));
  console.log("Failing: " + (m.failing.join("; ") || "none"));
}
