// Builds the site's data from data/. Run: node scripts/build.mjs
// Writes:
//   site/data/bundle.json            what the map reads: the last 9 days of events, 45 days of known-exploited entries
//   site/data/archive/index.json     every month on file with counts
//   site/data/archive/<YYYY-MM>.json full events of one month
//   site/data/archive/search.json    one compact row per event ever stored, for the archive page's search
//   site/data/archive/events.jsonl   everything, one event per line, for download and analysis
//   site/data/archive/kev.json       every known-exploited entry on file
//   site/data/feed.xml, feed.json    RSS and JSON Feed of high-severity and known-exploited events
//   site/data/trends.json            this week against last week by category, sector, country, actor, product, tag
//   site/data/ops.json               routines (routines.json) with their last run, recent run logs, lead queue
// Every record is validated first. Errors fail the build (exit 1) so bad data never reaches the site;
// warnings are hygiene faults the jobs should fix (front-page sources, long summaries, missing lists).
import { writeFileSync, mkdirSync, existsSync, rmSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { ROOT, DATA, readJson, listEventFiles, listDir, monthOf, dayAgo } from "./lib/store.mjs";

const OUT = join(ROOT, "site", "data"), ARCH = join(OUT, "archive");
const WINDOW_DAYS = 9, KEV_DAYS = 45;
const CATS = ["incident", "outage", "vuln", "report", "policy", "investment", "enforcement"];
const STATUS = ["confirmed", "official", "developing", "claimed"];
const TAGS = ["ransomware","data-breach","supply-chain","zero-day","ddos","espionage","critical-infrastructure","ai-enabled","third-party","phishing","insider","hacktivism","ot-ics","cloud","identity","fraud","takedown","regulation","funding","acquisition"];
const errors = [], warnings = [];
const strict = process.argv.includes("--strict");   // CI can turn hygiene warnings into errors

function checkEvent(e, path) {
  const where = path.slice(DATA.length + 1);
  if (!/^[a-z0-9][a-z0-9-]{2,119}$/.test(e.id)) errors.push(`${where}: file name must be lowercase letters, digits and hyphens`);
  if (typeof e.title !== "string" || !e.title.trim()) errors.push(`${where}: missing title`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(e.date || "")) errors.push(`${where}: date must be YYYY-MM-DD`);
  else if (!path.includes(`/events/${monthOf(e)}/`)) errors.push(`${where}: stored in the wrong month folder; it belongs in events/${monthOf(e)}/`);
  if (!CATS.includes(e.category)) errors.push(`${where}: category "${e.category}" is not one of ${CATS.join(", ")}`);
  if (![1, 2, 3].includes(e.severity)) errors.push(`${where}: severity must be 1, 2 or 3`);
  if (e.status && !STATUS.includes(e.status)) errors.push(`${where}: status "${e.status}" is not one of ${STATUS.join(", ")}`);
  if (e.lat != null && (typeof e.lat !== "number" || e.lat < -90 || e.lat > 90)) errors.push(`${where}: lat out of range`);
  if (e.lng != null && (typeof e.lng !== "number" || e.lng < -180 || e.lng > 180)) errors.push(`${where}: lng out of range`);
  for (const k of ["sources", "tags", "cves", "products", "attack"]) {
    if (e[k] == null) warnings.push(`${where}: "${k}" is missing; write [] when empty`);
    else if (!Array.isArray(e[k])) errors.push(`${where}: ${k} must be a list`);
  }
  (e.sources || []).forEach((s) => {
    if (!s || !/^https?:\/\//.test(s.url || "")) { errors.push(`${where}: every source needs an http(s) url`); return; }
    try { const u = new URL(s.url); if ((u.pathname === "/" || u.pathname === "") && !u.search) warnings.push(`${where}: source ${u.host} is a front page, not a specific article`); } catch { errors.push(`${where}: source url is not valid`); }
  });
  (e.tags || []).forEach((t) => { if (!TAGS.includes(t)) warnings.push(`${where}: tag "${t}" is not on the list and will be ignored`); });
  if (e.date > dayAgo(-1)) errors.push(`${where}: date is in the future`);
  if (e.status === "claimed" && e.severity !== 1) warnings.push(`${where}: unverified claims should be severity 1`);
  const words = String(e.summary || "").trim().split(/\s+/).filter(Boolean).length;
  if (words > 75) warnings.push(`${where}: summary is ${words} words; the limit is 75`);
  if (e.duplicate_of && typeof e.duplicate_of !== "string") errors.push(`${where}: duplicate_of must be an event id`);
}

const files = listEventFiles();
const seen = new Map();
for (const f of files) {
  if (!f.e) { errors.push(`${f.path.slice(DATA.length + 1)}: not valid JSON (${f.error})`); continue; }
  if (seen.has(f.id)) errors.push(`events: id "${f.id}" is stored twice (${seen.get(f.id)} and ${f.path.slice(DATA.length + 1)})`);
  seen.set(f.id, f.path.slice(DATA.length + 1));
  checkEvent(f.e, f.path);
}
const allEvents = files.filter((f) => f.e).map((f) => f.e);
const kevAll = listDir("kev").filter((x) => x.r).map((x) => x.r);
listDir("kev").filter((x) => !x.r).forEach((x) => errors.push(`kev/${x.id}.json: not valid JSON (${x.error})`));
const corrAll = listDir("corrections").filter((x) => x.r).map((x) => x.r);

const events = allEvents.filter((e) => e.date >= dayAgo(WINDOW_DAYS) && !e.duplicate_of);
const kev = kevAll.filter((k) => (k.added || "") >= dayAgo(KEV_DAYS));
const corrections = corrAll.sort((a, b) => (a.at < b.at ? 1 : -1)).slice(0, 50);
const docs = {};
for (const [path, file] of [["meta/status", "status.json"], ["analysis/latest", "analysis.json"], ["analysis/ripples", "ripples.json"], ["brief/latest", "brief.json"], ["stats/history", "history.json"]]) {
  const p = join(DATA, file);
  if (!existsSync(p)) continue;
  const d = readJson(p); if (d) docs[path] = d; else errors.push(`${file}: not valid JSON`);
}

const shown = warnings.slice(0, 40);
shown.forEach((w) => console.warn("warning: " + w));
if (warnings.length > shown.length) console.warn(`warning: ...and ${warnings.length - shown.length} more`);
if (strict && warnings.length) errors.push(`${warnings.length} hygiene warning(s) in --strict mode`);
if (errors.length) { errors.forEach((e) => console.error("error: " + e)); console.error(`\nBuild failed: ${errors.length} problem(s). Nothing was written.`); process.exit(1); }

// the map's bundle
mkdirSync(OUT, { recursive: true });
const built_at = new Date().toISOString();
writeFileSync(join(OUT, "bundle.json"), JSON.stringify({ built_at, events, kev, corrections, docs }));

// the archive
if (existsSync(ARCH)) rmSync(ARCH, { recursive: true });
mkdirSync(ARCH, { recursive: true });
const live = allEvents.filter((e) => !e.duplicate_of).sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : a.id < b.id ? -1 : 1));
const months = {};
for (const e of live) (months[monthOf(e)] ||= []).push(e);
const index = { built_at, total: live.length, kev_total: kevAll.length, months: [] };
for (const [m, list] of Object.entries(months).sort((a, b) => (a[0] < b[0] ? 1 : -1))) {
  writeFileSync(join(ARCH, `${m}.json`), JSON.stringify({ month: m, events: list }));
  const by = {}; list.forEach((e) => (by[e.category] = (by[e.category] || 0) + 1));
  index.months.push({ month: m, count: list.length, by_category: by, high: list.filter((e) => e.severity === 3).length });
}
writeFileSync(join(ARCH, "index.json"), JSON.stringify(index));
// compact search rows: [id, date, category, severity, status, title, org, country, cves, tags, actor]
const s = (v, n) => String(v || "").slice(0, n);
writeFileSync(join(ARCH, "search.json"), JSON.stringify({ built_at, fields: ["id", "date", "category", "severity", "status", "title", "org", "country", "cves", "tags", "actor"],
  rows: live.map((e) => [e.id, e.date, e.category, e.severity, s(e.status, 12), s(e.title, 160), s(e.org, 80), s(e.country, 60), (e.cves || []).slice(0, 12), (e.tags || []).slice(0, 5), s(e.actor, 60)]) }));
writeFileSync(join(ARCH, "events.jsonl"), live.map((e) => JSON.stringify(e)).join("\n") + "\n");
writeFileSync(join(ARCH, "kev.json"), JSON.stringify(kevAll.sort((a, b) => (a.added < b.added ? 1 : -1))));

// trends: this 7 days against the 7 before, by category, sector, country, actor, product and tag (claims excluded)
{
  const known = live.filter((e) => e.status !== "claimed");
  const curFrom = dayAgo(6), prevFrom = dayAgo(13), prevTo = dayAgo(7), to = dayAgo(0);
  const inCur = (e) => e.date >= curFrom && e.date <= to, inPrev = (e) => e.date >= prevFrom && e.date <= prevTo;
  // collection start = the earliest first_seen; before then, a week is a backfill, not a like-for-like count
  const started = known.map((e) => String(e.first_seen || "").slice(0, 10)).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort()[0] || to;
  const norm = (v) => String(v || "").replace(/\s+/g, " ").trim();
  const DIMS = {
    category: (e) => [e.category],
    sector: (e) => norm(e.sector).split(/[,;/]| and /i).map((x) => norm(x)).filter((x) => x && x.length < 40),
    country: (e) => [norm(e.country)].filter((x) => x && !/^(global|worldwide|multiple|international)/i.test(x)),
    actor: (e) => [norm(String(e.actor || "").split(/[;(]/)[0])].filter((x) => x && !/^(unknown|unattributed|none|n\/a)/i.test(x)),
    product: (e) => (e.products || []).map((x) => norm(x)).filter((x) => x && x.length < 50),
    tag: (e) => (e.tags || []).filter((t) => TAGS.includes(t)),
  };
  const dims = {};
  for (const [name, get] of Object.entries(DIMS)) {
    const m = new Map();
    for (const e of known) {
      const w = inCur(e) ? "cur" : inPrev(e) ? "prev" : null; if (!w) continue;
      for (const k of new Set(get(e))) { const key = k.toLowerCase(); const r = m.get(key) || { k, cur: 0, prev: 0 }; r[w]++; m.set(key, r); }
    }
    dims[name] = [...m.values()].filter((r) => r.cur + r.prev >= 2).sort((a, b) => (b.cur - b.prev) - (a.cur - a.prev) || b.cur - a.cur).slice(0, 60);
  }
  const daily = [];
  for (let i = 27; i >= 0; i--) { const d = dayAgo(i); daily.push({ date: d, total: known.filter((e) => e.date === d).length }); }
  const trends = {
    built_at, cur: { from: curFrom, to, total: known.filter(inCur).length },
    prev: { from: prevFrom, to: prevTo, total: known.filter(inPrev).length, complete: started <= prevFrom },
    collection_started: started,
    dims, daily,
  };
  writeFileSync(join(OUT, "trends.json"), JSON.stringify(trends));
  console.log(`Trends: ${trends.cur.total} events this week, ${trends.prev.total} the week before${trends.prev.complete ? "" : " (partly recorded)"}.`);
}

// operations: the routines registry, each routine's last run, recent run logs and the lead queue (site/data/ops.json)
{
  const reg = readJson(join(ROOT, "routines.json"), null);
  if (!reg || !Array.isArray(reg.routines)) { console.error("error: routines.json is missing or not valid JSON"); process.exit(1); }
  const keys = new Set(), aiYml = existsSync(join(ROOT, ".github", "workflows", "ai-jobs.yml")) ? readFileSync(join(ROOT, ".github", "workflows", "ai-jobs.yml"), "utf8") : "";
  const bad = [];
  for (const r of reg.routines) {
    if (!r.key || keys.has(r.key)) bad.push(`routines.json: missing or repeated key "${r.key}"`); keys.add(r.key);
    if (r.cron && r.cron.trim().split(/\s+/).length !== 5) bad.push(`routines.json: ${r.key} cron "${r.cron}" is not 5 fields`);
    if (r.tier === "ai" && aiYml) {
      if (!aiYml.includes(`cron: "${r.cron}"`)) bad.push(`routines.json: ${r.key} cron "${r.cron}" is not scheduled in ai-jobs.yml`);
      if (!new RegExp(`"${r.cron.replace(/[*]/g, "\\*")}"\\)\\s+job=${r.key}\\b`).test(aiYml)) bad.push(`routines.json: ai-jobs.yml does not map "${r.cron}" to job ${r.key}`);
    }
  }
  if (bad.length) { bad.forEach((b) => console.error("error: " + b)); console.error("\nBuild failed: routines.json and the workflows disagree."); process.exit(1); }
  const st = docs["meta/status"] || {};
  const routines = reg.routines.map((r) => ({ ...r, last_at: (r.status_key && st[r.status_key]) || null }));
  const runsDir = join(DATA, "runs"), runs = [];
  if (existsSync(runsDir)) for (const d of readdirSync(runsDir).filter((d) => d >= dayAgo(7)).sort().reverse())
    for (const f of readdirSync(join(runsDir, d)).sort().reverse()) {
      const r = readJson(join(runsDir, d, f), {}); if (runs.length >= 40) break;
      runs.push({ at: `${d}T${f.slice(0, 2)}:${f.slice(2, 4)}:00Z`, job: String(r.job || f.slice(5, -5)).slice(0, 40),
        added: (r.added || r.kev_added || []).length, updated: (r.updated || r.events_updated || []).length,
        failed: (r.failed || r.failed_sites || []).length, note: String(r.notes || r.mode || "").slice(0, 200) });
    }
  const leadsDir = join(DATA, "leads"), byTier = { gov: 0, vendor: 0, news: 0 }; let leads24 = 0;
  if (existsSync(leadsDir)) for (const f of readdirSync(leadsDir).filter((f) => f.endsWith(".jsonl") && f.slice(0, 10) >= dayAgo(1)))
    for (const line of readFileSync(join(leadsDir, f), "utf8").split("\n")) { try { const l = JSON.parse(line); if (Date.now() - Date.parse(l.seen_at) < 864e5) { leads24++; byTier[l.tier] = (byTier[l.tier] || 0) + 1; } } catch {} }
  writeFileSync(join(OUT, "ops.json"), JSON.stringify({ built_at, routines, runs, leads: { last_24h: leads24, by_tier: byTier, failed_feeds: st.collect_failed || [] } }));
}

// subscribable feeds: high-severity and known-exploited events, newest first (unverified claims never included)
const SITE = (process.env.SITE_URL || "https://xanderhutch.github.io/CyberView").replace(/\/$/, "");
const link = (id) => `${SITE}/#e=${encodeURIComponent(id)}`;
const isKev = (e) => Array.isArray(e.cve_meta) && e.cve_meta.some((c) => c && c.kev);
const when = (e) => (/^\d{4}-\d{2}-\d{2}T/.test(e.first_seen || "") ? e.first_seen : `${e.date}T12:00:00Z`);
const picks = live.filter((e) => e.status !== "claimed" && (e.severity === 3 || isKev(e)))
  .sort((a, b) => (when(a) < when(b) ? 1 : -1)).slice(0, 60);
const text = (e) => [e.summary, e.action ? `What to do: ${e.action}` : "", (e.cves || []).length ? `CVEs: ${e.cves.join(", ")}` : ""].filter(Boolean).join("\n\n");
const xml = (v) => String(v == null ? "" : v).replace(/[<>&'"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" }[c])).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "");
const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>CyberView: high-priority cyber events</title>
<link>${SITE}/</link>
<atom:link href="${SITE}/data/feed.xml" rel="self" type="application/rss+xml"/>
<description>High-severity incidents, exploited vulnerabilities and urgent advisories from CyberView, with what to do. Unverified claims are left out.</description>
<language>en</language>
<lastBuildDate>${new Date(built_at).toUTCString()}</lastBuildDate>
${picks.map((e) => `<item>
<title>${xml(e.title)}</title>
<link>${xml(link(e.id))}</link>
<guid isPermaLink="false">cyberview:${xml(e.id)}</guid>
<pubDate>${new Date(when(e)).toUTCString()}</pubDate>
<category>${xml(e.category)}</category>
<description>${xml(text(e))}</description>
</item>`).join("\n")}
</channel>
</rss>
`;
writeFileSync(join(OUT, "feed.xml"), rss);
writeFileSync(join(OUT, "feed.json"), JSON.stringify({
  version: "https://jsonfeed.org/version/1.1",
  title: "CyberView: high-priority cyber events",
  home_page_url: `${SITE}/`,
  feed_url: `${SITE}/data/feed.json`,
  description: "High-severity incidents, exploited vulnerabilities and urgent advisories, with what to do. Unverified claims are left out.",
  items: picks.map((e) => ({
    id: `cyberview:${e.id}`, url: link(e.id), title: e.title, content_text: text(e), date_published: when(e),
    date_modified: /^\d{4}-\d{2}-\d{2}T/.test(e.updated_at || "") ? e.updated_at : undefined,
    tags: [e.category, ...(e.tags || [])], external_url: (e.sources && e.sources[0] && e.sources[0].url) || undefined,
  })),
}));

console.log(`Built site/data/bundle.json: ${events.length} events (of ${allEvents.length} on file), ${kev.length} known-exploited, ${corrections.length} corrections, docs: ${Object.keys(docs).join(", ") || "none"}.`);
console.log(`Feeds: ${picks.length} high-priority items in data/feed.xml and data/feed.json.`);
console.log(`Archive: ${live.length} events in ${index.months.length} month(s), ${kevAll.length} known-exploited entries. ${warnings.length} hygiene warning(s).`);
