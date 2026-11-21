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
//   site/data/workbench.json         known-exploited flaws with affected versions, fix guides and detection resources
//   site/data/chat.json              reviewed community posts (newest 300)
//   site/data/tabletop.json          the weekly tabletop exercise and past ones
//   site/data/health.json            records left out by --quarantine, and the pipeline's last timestamps
//   site/data/manifest.json          counts and a SHA-256 of every data file, for scripts/verify-build.mjs
//   site/data/ops.json               routines (routines.json) with their last run, recent run logs, lead queue
// Every record is validated first. Errors fail the build (exit 1) so bad data never reaches the site;
// warnings are hygiene faults the jobs should fix (front-page sources, long summaries, missing lists).
import { buildPages } from "./pages.mjs";
import { writeFileSync, mkdirSync, existsSync, rmSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { ROOT, DATA, readJson, listEventFiles, listDir, monthOf, dayAgo } from "./lib/store.mjs";
import { load as pipelineMetrics, RETIRED_COLLECTORS } from "./metrics.mjs";
import { measure as speedOf } from "./lib/latency.mjs";
import { dataCommit } from "./lib/data-commit-id.mjs";
import { STAGES, lastRuns, limits as stageLimits } from "./lib/stages.mjs";
import { sectorsOf, surfaceOf, SECTOR, SURFACE } from "./lib/taxonomy.mjs";
import { checkAttribution, checkLinks, checkTabletop, checkHunt, checkGuide, checkChat, checkAnalysis, checkEventQuality, sharedSourceProblems, QUALITY_STRICT_FROM, TAGS } from "./lib/validate.mjs";

const OUT = join(ROOT, "site", "data"), ARCH = join(OUT, "archive");
const WINDOW_DAYS = 9, KEV_DAYS = 45;
const CATS = ["incident", "outage", "vuln", "report", "policy", "investment", "enforcement"];
const STATUS = ["confirmed", "official", "developing", "claimed"];
const errors = [], warnings = [];
const strict = process.argv.includes("--strict");   // CI can turn hygiene warnings into errors
// --quarantine (the deploy and the data workflows use it): a record that breaks a rule is LEFT OUT and reported in
// site/data/health.json instead of stopping the build, so one bad record can never keep fresh data off the site.
// Without the flag (what the jobs run before they commit) any broken record still fails the build.
const quarantine = process.argv.includes("--quarantine");
const badEvents = new Set();

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
  if (e.review != null && (typeof e.review !== "object" || !["passed", "corrected", "flagged"].includes(e.review.state) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(e.review.at || ""))) errors.push(`${where}: review must be {state: passed|corrected|flagged, at, note} (written by scripts/review.mjs)`);
}

const files = listEventFiles();
const seen = new Map();
for (const f of files) {
  if (!f.e) { errors.push(`${f.path.slice(DATA.length + 1)}: not valid JSON (${f.error})`); continue; }
  const before = errors.length;
  // the id lives in the file name; an "id" inside the file must match it (a duplicate marker saved under the original's
  // name once made two files with one id, and both were quarantined)
  if (f.e.id !== f.id) errors.push(`${f.path.slice(DATA.length + 1)}: the id inside the file ("${String(f.e.id).slice(0, 120)}") differs from its file name; rename the file to ${String(f.e.id).slice(0, 120)}.json (in the month folder of its date) or remove the inner id`);
  if (seen.has(f.id)) errors.push(`events: id "${f.id}" is stored twice (${seen.get(f.id)} and ${f.path.slice(DATA.length + 1)})`);
  seen.set(f.id, f.path.slice(DATA.length + 1));
  checkEvent(f.e, f.path);
  if (errors.length > before) badEvents.add(f.path);
}
// attribution and stated links (drawn as arcs on the globe); links must point at events on file
{
  const ids = new Set(files.filter((f) => f.e).map((f) => f.id));
  for (const f of files) {
    if (!f.e) continue;
    const where = f.path.slice(DATA.length + 1);
    const before = errors.length;
    checkHunt(f.e.hunt).forEach((m) => errors.push(`${where}: ${m}`));
    checkAttribution(f.e.attribution).forEach((m) => errors.push(`${where}: ${m}`));
    checkLinks(f.e.links, f.id, ids).forEach((m) => errors.push(`${where}: ${m}`));
    if (errors.length > before) badEvents.add(f.path);
  }
}
// quality checks from what the second review kept correcting (scripts/lib/validate.mjs): errors only for events first seen
// from QUALITY_STRICT_FROM, warnings otherwise. Warnings about events first seen or updated in the last 3 days are printed
// first, so the 40-line cap never hides them; older ones are counted in one line (the data steward can list them with
// `node scripts/lib/validate.mjs <id>`), so history does not drown what a job can still fix
{
  const recent = dayAgo(3), fresh = [], old = new Map();
  const live = files.filter((f) => f.e && !f.e.duplicate_of), shared = sharedSourceProblems(live.map((f) => ({ ...f.e, id: f.id })));
  for (const f of live) {
    const where = f.path.slice(DATA.length + 1), strictQ = String(f.e.first_seen || "") >= QUALITY_STRICT_FROM;
    const isFresh = String(f.e.first_seen || "") >= recent || String(f.e.updated_at || "") >= recent;
    for (const x of checkEventQuality(f.e).concat(shared.get(f.id) || [])) {
      if (x.level === "error" && strictQ) { errors.push(`${where}: ${x.code}: ${x.text}`); badEvents.add(f.path); }
      else if (isFresh) fresh.push(`${where}: ${x.code}: ${x.text}`);
      else old.set(x.code, (old.get(x.code) || 0) + 1);
    }
  }
  warnings.unshift(...fresh);
  if (old.size) warnings.push(`quality checks on older events: ${[...old].map(([k, n]) => `${k} ${n}`).join(", ")}`);
  // sectors and surface: the analysis views fall back to keywords without them (one line, not one per event)
  const bare = live.filter((f) => f.e.sectors == null || f.e.surface == null).length;
  if (bare) warnings.push(`classification: ${bare} of ${live.length} events have no sectors or surface yet; the analysis views place them by keyword (backfill: node scripts/classify.mjs plan)`);
}
const allEvents = files.filter((f) => f.e && !(quarantine && badEvents.has(f.path))).map((f) => f.e);
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

// community posts: only reviewed ones are on file; removed ones stay on file but are not published
const chat = [];
{
  const ids = new Set(allEvents.map((e) => e.id));
  for (const x of listDir("chat")) {
    if (x.id === "pending") continue;
    const bad = x.r ? checkChat({ ...x.r, id: x.r.id === x.id ? Number(x.id) : x.r.id }, ids) : ["not valid JSON"];
    if (bad.length) { bad.forEach((m) => errors.push(`${x.path.slice(DATA.length + 1)}: ${m}`)); continue; }
    if (!x.r.removed) chat.push({ id: Number(x.id), at: x.r.at, author: x.r.author, kind: x.r.kind, text: x.r.text, event_id: x.r.event_id || "", links: x.r.links, reviewed_at: x.r.reviewed_at, note: x.r.note || "" });
  }
  chat.sort((a, b) => (a.at < b.at ? 1 : -1));
}

// fix guides (the advisory desk): one per CVE, from the vendor's own advisory
const guides = {};
for (const x of listDir("guides")) {
  const bad = x.r ? checkGuide(x.r, x.id) : ["not valid JSON"];
  if (bad.length) { bad.forEach((m) => errors.push(`guides/${x.id}.json: ${m}`)); continue; }
  const { id, ...g } = x.r; guides[x.id] = g;
}

// the weekly tabletop exercise (the tabletop job): current one plus every past one from the snapshots
const tabletop = { current: null, past: [] };
{
  const ids = new Set(allEvents.map((e) => e.id));
  const cur = join(DATA, "tabletop.json");
  if (existsSync(cur)) {
    const t = readJson(cur);
    const bad = t ? checkTabletop(t, ids) : ["not valid JSON"];
    if (bad.length) bad.forEach((m) => errors.push(`tabletop.json: ${m}`)); else tabletop.current = t;
  }
  for (const x of listDir("snapshots/tabletop")) {
    const bad = x.r ? checkTabletop(x.r, ids) : ["not valid JSON"];
    if (bad.length) { bad.forEach((m) => errors.push(`snapshots/tabletop/${x.id}.json: ${m}`)); continue; }
    tabletop.past.push(x.r);
  }
  tabletop.past.sort((a, b) => (a.date < b.date ? 1 : -1));
}

// context layers (scripts/context.mjs): validated loosely, a broken file only drops that layer
const context = {};
for (const x of listDir("context")) {
  const c = x.r;
  if (!c || !Array.isArray(c.items) || typeof c.source !== "string") { warnings.push(`context/${x.id}.json: unreadable, layer left out`); continue; }
  context[x.id] = { source: c.source, source_url: c.source_url, fetched_at: c.fetched_at || "", ok: !!c.ok, error: c.error || "", items: c.items };
}
// the outage desk (scripts/outage-desk.mjs): AI checks of outage reports nobody had checked (data/outages/checks.json).
// Each check is shown next to the report it checked: an IODA country (its newest check of the last 48 hours) here, a
// news-reported power outage below. Optional: a fault here leaves every report labelled as unchecked, never the build.
let outageDesk = null, outageChecks = {};
try {
  outageDesk = await import("./outage-desk.mjs");
  const oc = existsSync(join(DATA, "outages", "checks.json")) ? readJson(join(DATA, "outages", "checks.json")) : {};
  if (oc && typeof oc === "object" && !Array.isArray(oc)) outageChecks = oc; else warnings.push("outages/checks.json: not readable, outage checks left out");
  if (context.ioda) context.ioda.items = context.ioda.items.map((x) => {
    const v = x && /^[A-Z]{2}$/.test(x.code || "") ? outageDesk.siteCheck(outageDesk.latestFor(outageChecks, `net-${x.code.toLowerCase()}`)) : null;
    return v ? { ...x, verified: v } : x;
  });
} catch (e) { warnings.push(`outage checks: ${String((e && e.message) || e).slice(0, 80)}`); }
// the claims desk (scripts/claims-desk.mjs): AI checks of leak-site claims (data/claims/checks.json). The newest check that
// names an event is shown on it as claim_check (bundle and archive). Optional: a fault here leaves the events as they are.
let claimsDesk = null;
try {
  claimsDesk = await import("./claims-desk.mjs");
  const cc = existsSync(join(DATA, "claims", "checks.json")) ? readJson(join(DATA, "claims", "checks.json")) : {};
  if (cc && typeof cc === "object" && !Array.isArray(cc)) { const by = claimsDesk.checksByEvent(cc); for (const e of allEvents) { const v = by[e.id] ? claimsDesk.siteCheck(by[e.id]) : null; if (v) e.claim_check = v; } }
  else warnings.push("claims/checks.json: not readable, claim checks left out");
} catch (e) { warnings.push(`claim checks: ${String((e && e.message) || e).slice(0, 80)}`); }

// power grid analysis (scripts/grid-analysis.mjs, no AI model): corroboration, anomalies and 30-day trends per region.
// Validated loosely like the context layers: a broken file only drops the grid analysis (with a warning), never the build.
// Bundled as docs["grid/analysis"] for the map and copied into trends.json for the trends page.
const gridAnalysis = (() => {
  const p = join(DATA, "grid", "analysis.json");
  if (!existsSync(p)) return null;
  const a = readJson(p);
  const obj = (v) => v && typeof v === "object" && !Array.isArray(v);
  if (!obj(a)) { warnings.push("grid/analysis.json: not valid JSON, grid analysis left out"); return null; }
  for (const k of ["anomalies", "corroboration"]) if (a[k] != null && !Array.isArray(a[k])) { warnings.push(`grid/analysis.json: ${k} must be a list, grid analysis left out`); return null; }
  for (const k of ["trends", "sources"]) if (a[k] != null && !obj(a[k])) { warnings.push(`grid/analysis.json: ${k} must be an object, grid analysis left out`); return null; }
  return { updated_at: String(a.updated_at || "").slice(0, 30), anomalies: (a.anomalies || []).filter(obj).slice(0, 200),
    corroboration: (a.corroboration || []).filter(obj).slice(0, 200).map((c) => ({ ...c, signals: Array.isArray(c.signals) ? c.signals.filter(obj).slice(0, 20) : [] })),
    trends: a.trends || {}, sources: a.sources || {} };
})();
if (gridAnalysis) docs["grid/analysis"] = gridAnalysis;
// power outages reported in the news (scripts/grid-news.mjs, no AI model): publishers' headlines, unchecked, for the Grid
// view's third tier. Validated loosely: a broken file only drops the list (with a warning), never the build.
const gridNews = (() => {
  const p = join(DATA, "grid", "news.json");
  if (!existsSync(p)) return null;
  const d = readJson(p);
  if (!d || typeof d !== "object" || !Array.isArray(d.items)) { warnings.push("grid/news.json: not readable, news-reported outages left out"); return null; }
  // a big or nationwide news-reported outage can get a cause check from the grid desk (scripts/grid-desk.mjs, research
  // id grid-news-<id>); its result is shown on the news row, labelled as written by CyberView AI
  const research = existsSync(join(DATA, "grid", "research.json")) ? readJson(join(DATA, "grid", "research.json")) || {} : {};
  const DEC = ["weather", "equipment", "planned", "supply_shortfall", "wildfire_safety", "third_party", "cyber_official", "cyber_reported", "under_investigation", "unknown"];
  const checked = (id) => { const r = research && typeof research === "object" ? research[`grid-news-${id}`] : null;
    return r && DEC.includes(r.decision) ? { decision: r.decision, summary: String(r.cause_summary || "").slice(0, 300), by: "CyberView AI (a Claude model)" } : null; };
  return { updated_at: String(d.updated_at || "").slice(0, 30), items: d.items.filter((x) => x && typeof x === "object" && !Array.isArray(x) && Array.isArray(x.publishers)).slice(0, 300)
    .map((x) => { const c = checked(x.id), v = outageDesk ? outageDesk.siteCheck(outageChecks[`pw-${x.id}`]) : null; return { ...x, ...(c ? { checked: c } : {}), ...(v ? { verified: v } : {}) }; }) };
})();
if (gridNews) docs["grid/news"] = gridNews;
// service status (scripts/status-pages.mjs, no AI model): major or long incidents on the providers' own status pages, for
// the map page's "Service status" list (each labelled the provider's own status page, not a cyber event), with the outage
// desk's check when there is one (its item id is svc-<sha1 of the incident's url>). A broken file only drops the list.
const services = (() => {
  const p = join(DATA, "services", "status.json");
  if (!existsSync(p)) return null;
  const d = readJson(p);
  if (!d || typeof d !== "object" || !Array.isArray(d.incidents)) { warnings.push("services/status.json: not readable, service status left out"); return null; }
  const prov = d.providers && typeof d.providers === "object" ? Object.values(d.providers) : [];
  return { updated_at: String(d.updated_at || "").slice(0, 30), pages: prov.length, pages_ok: prov.filter((v) => v && v.ok).length,
    items: d.incidents.filter((x) => x && typeof x === "object" && !Array.isArray(x) && /^https:\/\//.test(x.url || "")).slice(0, 60).map((x) => {
      const v = outageDesk ? outageDesk.siteCheck(outageChecks[`svc-${createHash("sha1").update(x.url).digest("hex").slice(0, 12)}`]) : null;
      return { provider: String(x.provider || "").slice(0, 40), name: String(x.name || "").slice(0, 60), category: String(x.category || "").slice(0, 20), page: String(x.page || "").slice(0, 200),
        title: String(x.title || "").slice(0, 200), impact: String(x.impact || "").slice(0, 40), level: String(x.level || "").slice(0, 10), components: Array.isArray(x.components) ? x.components.slice(0, 6).map((c) => String(c).slice(0, 80)) : [],
        status: String(x.status || "").slice(0, 40), started_at: String(x.started_at || "").slice(0, 20), resolved_at: String(x.resolved_at || "").slice(0, 20), minutes: Number.isFinite(x.minutes) ? x.minutes : null,
        url: String(x.url).slice(0, 400), ...(v ? { verified: v } : {}) };
    }) };
})();
if (services) docs["services/status"] = services;
// official scam and phishing warnings by country (scripts/scams.mjs, no AI model): their own list on the map page, never
// events, never on the globe. The issuers and their own hosts come from config/scams.json (code); the page links an item
// only to its issuer's hosts. Validated loosely: a broken file only drops the list (with a warning), never the build.
const scamWarnings = (() => {
  const p = join(DATA, "scams", "warnings.json");
  if (!existsSync(p)) return null;
  const d = readJson(p), cfg = readJson(join(ROOT, "config", "scams.json"), { sources: [] }) || { sources: [] };
  if (!d || typeof d !== "object" || !Array.isArray(d.items)) { warnings.push("scams/warnings.json: not readable, scam warnings left out"); return null; }
  const issuers = {}, health = d.sources && typeof d.sources === "object" ? d.sources : {};
  for (const s of cfg.sources || []) issuers[s.key] = { name: s.name, kind: s.kind, country: s.country, lang: s.lang, home: s.home, hosts: s.hosts,
    ok: !!(health[s.key] && health[s.key].ok), error: String((health[s.key] && health[s.key].error) || "").slice(0, 60), last_ok: String((health[s.key] && health[s.key].last_ok) || "").slice(0, 30) };
  return { updated_at: String(d.updated_at || "").slice(0, 30), types_by: "keyword", issuers,
    items: d.items.filter((x) => x && typeof x === "object" && !Array.isArray(x) && Object.hasOwn(issuers, x.issuer)).slice(0, 600) };
})();
if (scamWarnings) docs["scams/warnings"] = scamWarnings;
// each grid source's own hosts (the page accepts an item's link only on its own operator's hosts) and the attribution its
// licence requires, from scripts/grid.mjs SOURCES (code, not data); a failure leaves the page on its built-in allowlist
try {
  const { SOURCES, attributionText } = await import("./grid.mjs");
  const gs = {};
  for (const [k, v] of Object.entries(SOURCES)) {
    const hosts = (v.hosts || []).filter((h) => /^[a-z0-9.-]{3,80}$/.test(h)).slice(0, 8);
    if (/^[a-z0-9-]{2,40}$/.test(k)) gs[k] = { name: String(v.name || "").slice(0, 60), hosts, attribution: v.attribution ? attributionText(v.attribution) : "" };
  }
  docs["grid/sources"] = gs;
} catch (e) { warnings.push(`grid sources for the page: ${String(e.message).slice(0, 80)}`); }
// each grid source's last fetch (data/grid/live.json, then analysis.json for the keyed ones), for the status page
const gridSources = (() => {
  const live = existsSync(join(DATA, "grid", "live.json")) ? readJson(join(DATA, "grid", "live.json")) : null;
  // the grid audit's flags per source (scripts/grid-audit.mjs: failing, stale_data, dormant, customers_missing ...)
  const audit = existsSync(join(DATA, "grid", "audit.json")) ? readJson(join(DATA, "grid", "audit.json")) || {} : {};
  const flagsOf = (k) => { const f = audit.sources && audit.sources[k] && audit.sources[k].flags; return Array.isArray(f) ? f.filter((x) => /^[a-z0-9_]{1,40}$/.test(x)).slice(0, 10) : []; };
  // the context sources the grid analysis reads carry no name of their own
  const NAMES = { ioda: "IODA internet outages", gdacs: "GDACS disaster alerts" };
  const out = {}, add = (k, v) => { if (!/^[a-z0-9_-]{1,40}$/.test(k) || out[k] || !v || typeof v !== "object") return;
    out[k] = { name: String(v.name || NAMES[k] || "").slice(0, 60), ok: v.ok === true, error: String(v.error || "").slice(0, 120), at: String(v.fetched_at || v.at || "").slice(0, 30),
      items: Number.isInteger(v.items) && v.items >= 0 ? v.items : null,
      country: /^[A-Z]{2}$/.test(v.country || "") ? v.country : "", paused: v.paused === true,
      ...(v.stale === true ? { stale: true } : {}), ...(v.dormant === true ? { dormant: true } : {}),
      ...(/^\d{4}-\d{2}-\d{2}T/.test(v.data_at || "") ? { data_at: String(v.data_at).slice(0, 30) } : {}), flags: flagsOf(k) }; };
  for (const [k, v] of Object.entries((live && live.sources) || {})) add(k, v);
  for (const [k, v] of Object.entries((gridAnalysis && gridAnalysis.sources) || {})) add(k, v);
  return Object.keys(out).length ? out : null;
})();
// the grid pipeline's later stages, for the status page and the guard (ops-6): incidents waiting for a cause check, and
// the audit's pipeline flags (collect_late, news_late, analysis_late, research_waiting_over_2h, series_large)
const gridStages = (() => {
  const inc = existsSync(join(DATA, "grid", "incidents.json")) ? readJson(join(DATA, "grid", "incidents.json")) || {} : {};
  const research = existsSync(join(DATA, "grid", "research.json")) ? readJson(join(DATA, "grid", "research.json")) || {} : {};
  const audit = existsSync(join(DATA, "grid", "audit.json")) ? readJson(join(DATA, "grid", "audit.json")) || {} : {};
  const waiting = (Array.isArray(inc.open) ? inc.open : []).filter((i) => i && i.research_needed === true && !(research[i.id] && research[i.id].final));
  const oldest = waiting.reduce((m, i) => { const t = Date.parse(i.opened_at || ""); return isFinite(t) ? Math.max(m, Math.round((Date.now() - t) / 6e4)) : m; }, 0);
  const pf = audit.pipeline && Array.isArray(audit.pipeline.flags) ? audit.pipeline.flags.filter((x) => /^[a-z0-9_]{1,40}$/.test(x)).slice(0, 10) : [];
  return { waiting: { count: waiting.length, oldest_min: oldest }, audit_at: String(audit.updated_at || "").slice(0, 30), audit_flags: pf };
})();
// the outage desk's queue, for the status page: waiting now, checked in the last 24 hours, the oldest wait
// the claims desk's queue, for the status page: waiting now, checked in the last 24 hours by decision, the oldest wait
const claimsQueue = (() => { try { if (!claimsDesk) return null; const d = claimsDesk.load(); return claimsDesk.stats(claimsDesk.queue(d.items, d.checks, {}, Date.now(), d.cfg), d.checks); } catch (e) { warnings.push(`claims queue: ${String((e && e.message) || e).slice(0, 80)}`); return null; } })();
const outageQueue = (() => { try { if (!outageDesk) return null; const d = outageDesk.load(); return outageDesk.stats(outageDesk.queue(d.lists, d.checks, {}, Date.now(), d.cfg), d.checks); } catch (e) { warnings.push(`outage queue: ${String((e && e.message) || e).slice(0, 80)}`); return null; } })();

// exploitation analyses (the exploit analyst job): how a flaw is used and the remediation path, from public sources, no code.
// One that breaks a rule is left out of the workbench and reported here (first, so the 40-line cap never hides it). This
// check used to run after the error report, so a broken analysis vanished silently and the swarm kept handing it out.
// It is a warning, not an error, so one long field cannot hold back every job's commit; `node scripts/analyst.mjs check`
// fails on it, and the analyst queue hands it back as FIX ONLY.
const analyses = {}, analysisWarnings = [];
for (const x of listDir("analyses")) {
  const bad = x.r ? checkAnalysis(x.r, x.id) : ["not valid JSON"];
  if (bad.length) { bad.forEach((m) => analysisWarnings.push(`analyses/${x.id}.json: ${m} (left out of the workbench until fixed)`)); continue; }
  const { id, ...a } = x.r; analyses[x.id] = a;
}
warnings.unshift(...analysisWarnings);

const shown = warnings.slice(0, 40);
shown.forEach((w) => console.warn("warning: " + w));
if (warnings.length > shown.length) console.warn(`warning: ...and ${warnings.length - shown.length} more`);
if (strict && warnings.length) errors.push(`${warnings.length} hygiene warning(s) in --strict mode`);
const quarantined = quarantine ? errors.splice(0).map((e) => String(e).slice(0, 300)) : [];
if (quarantined.length) { quarantined.forEach((e) => console.error("quarantined: " + e)); console.error(`\n${quarantined.length} problem(s) quarantined: those records are left out of this build and listed in site/data/health.json. Everything else is published.`); }
if (quarantine && allEvents.length === 0) errors.push("no valid events at all: refusing to publish an empty map");
if (errors.length) { errors.forEach((e) => console.error("error: " + e)); console.error(`\nBuild failed: ${errors.length} problem(s). Nothing was written.`); process.exit(1); }

let backlogNow = null;   // how many stories are waiting for a decision (scripts/backlog.mjs); null when it could not be computed
// reports the collectors have seen but research has not reached yet (no AI model; the app labels them "being checked").
// Optional: a fault here must never hold back the events.
try {
  const { build: fuseBuild, developing } = await import("./fuse.mjs");
  const fused = fuseBuild();
  docs["wire/latest"] = { built_at: new Date().toISOString(), items: developing(fused.stories) };
  backlogNow = (await import("./backlog.mjs")).summary(fused.stories);
} catch (e) { console.warn("warning: developing-reports list skipped: " + String(e && e.message || e).slice(0, 160)); }

// the map's bundle
mkdirSync(OUT, { recursive: true });
const built_at = new Date().toISOString();
writeFileSync(join(OUT, "bundle.json"), JSON.stringify({ built_at, events, kev, corrections, docs, context }));

// the workbench (site/data/workbench.json): every known-exploited entry on file with its affected-version ranges, recent
// high-risk flaws that are not on CISA's list, the fix guides, and detection resources named by advisories and reports
{
  const s = (v, n) => String(v || "").slice(0, n);
  const expl = (readJson(join(DATA, "exploits.json"), { cves: {} }).cves) || {};
  const repoOf = (cve) => { const x = expl[cve]; return x && x.repos > 0 ? { repos: x.repos, top: (x.top || []).slice(0, 3).filter((r) => /^https:\/\/github\.com\//.test(r.url || "")).map((r) => ({ name: s(r.name, 100), url: r.url, stars: r.stars || 0 })) } : null; };
  const wbKev = kevAll.map((k) => ({ repo: repoOf(k.cve), cve: k.cve, vendor: k.vendor, product: k.product, name: k.name, added: k.added, due: k.due, ransomware: !!k.ransomware,
    desc: s(k.desc, 300), cvss: k.cvss ?? null, epss: k.epss ?? null, av: k.av || "", required: s(k.required, 700), refs: (k.refs || []).slice(0, 4), affected: (k.affected || []).slice(0, 60) }));
  const inKev = new Set(kevAll.map((k) => k.cve)), seenCve = new Set(), wbVulns = [];
  for (const e of allEvents.filter((e) => !e.duplicate_of && e.category === "vuln" && e.status !== "claimed" && e.severity >= 2 && e.date >= dayAgo(30)).sort((a, b) => (a.date < b.date ? 1 : -1))) {
    for (const c of (e.cves || []).slice(0, 6)) {
      if (inKev.has(c) || seenCve.has(c) || !/^CVE-\d{4}-\d{4,}$/.test(c)) continue; seenCve.add(c);
      const m = (e.cve_meta || []).find((x) => x && x.id === c) || {};
      wbVulns.push({ repo: repoOf(c), cve: c, event_id: e.id, title: s(e.title, 160), date: e.date, severity: e.severity, vendor: s(e.org, 80), products: (e.products || []).slice(0, 6).map((x) => s(x, 60)),
        desc: s(e.plain || e.summary, 300), action: s(e.action, 300), cvss: m.cvss ?? null, epss: m.epss ?? null });
    }
  }
  const eventOf = {}; for (const e of allEvents) if (!e.duplicate_of) for (const c of e.cves || []) (eventOf[c] ||= e.id);
  const hunt = [], detection = (h) => h && !/csaf|cvrf|\bvex\b/i.test(`${h.url} ${h.name}`);   // machine-readable advisories are not detection content
  for (const e of allEvents.filter((e) => !e.duplicate_of && Array.isArray(e.hunt) && e.hunt.length && e.date >= dayAgo(60)).sort((a, b) => (a.date < b.date ? 1 : -1)))
    for (const h of e.hunt.filter(detection)) hunt.push({ ...h, about: s(e.title, 140), event_id: e.id, date: e.date });
  for (const [cve, g] of Object.entries(guides)) for (const h of (g.hunt || []).filter(detection)) hunt.push({ ...h, about: cve, cve, date: s(g.read_at, 10) });
  writeFileSync(join(OUT, "workbench.json"), JSON.stringify({ built_at, kev: wbKev, vulns: wbVulns.slice(0, 80), guides, analyses, event_of: eventOf, hunt: hunt.slice(0, 200) }));
}
// industrial (ICS/OT) advisories (scripts/ics.mjs, no AI model) for the Vulnerabilities page's Industrial view; a broken or
// missing file only leaves that view empty, with a warning, never the build
try {
  const p = join(DATA, "ics", "advisories.json"), d = existsSync(p) ? readJson(p) : null;
  const sd = d ? (await import("./ics.mjs")).siteData(d, built_at) : null;
  if (sd) writeFileSync(join(OUT, "ics.json"), JSON.stringify(sd)); else if (d) warnings.push("ics/advisories.json: not readable, industrial advisories left out");
} catch (e) { warnings.push(`ics/advisories.json: ${String(e.message).slice(0, 80)}`); }
writeFileSync(join(OUT, "chat.json"), JSON.stringify({ built_at, posts: chat.slice(0, 300) }));
// tabletop exercises: the current one and an index of past ones (site/data/tabletop.json)
writeFileSync(join(OUT, "tabletop.json"), JSON.stringify({ built_at, current: tabletop.current,
  past: tabletop.past.map((t) => ({ date: t.date, title: t.title })), exercises: tabletop.past.slice(0, 26) }));

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
// compact search rows: [id, date, category, severity, status, title, org, country, cves, tags, actor, first_seen]
const s = (v, n) => String(v || "").slice(0, n);
writeFileSync(join(ARCH, "search.json"), JSON.stringify({ built_at, fields: ["id", "date", "category", "severity", "status", "title", "org", "country", "cves", "tags", "actor", "first_seen"],
  rows: live.map((e) => [e.id, e.date, e.category, e.severity, s(e.status, 12), s(e.title, 160), s(e.org, 80), s(e.country, 60), (e.cves || []).slice(0, 12), (e.tags || []).slice(0, 5), s(e.actor, 60), s(e.first_seen, 20)]) }));
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
    // the explicit sectors (fixed list) when an event has them, else the free-text sector field
    sector: (e) => { const se = sectorsOf(e), v = se ? se.values.filter((k) => k !== "unknown") : []; return v.length ? v.map((k) => SECTOR[k].label) : norm(e.sector).split(/[,;/]| and /i).map((x) => norm(x)).filter((x) => x && x.length < 40); },
    surface: (e) => { const su = surfaceOf(e); return su && su.value !== "unknown" ? [SURFACE[su.value].label] : []; },
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
    // where the sector and surface rows came from, over both weeks: the source, CyberView AI, or the free-text sector field
    basis: (() => {
      const b = { sector: { stated: 0, inferred: 0, free: 0 }, surface: { stated: 0, inferred: 0, none: 0 } };
      for (const e of known.filter((x) => inCur(x) || inPrev(x))) {
        const se = sectorsOf(e), su = surfaceOf(e);
        b.sector[se && se.values.some((k) => k !== "unknown") ? se.basis : "free"]++;
        b.surface[su && su.value !== "unknown" ? su.basis : "none"]++;
      }
      return b;
    })(),
    grid: gridAnalysis ? { updated_at: gridAnalysis.updated_at, trends: gridAnalysis.trends, anomalies: gridAnalysis.anomalies.length, corroborated: gridAnalysis.corroboration.filter((c) => (c.score || 0) >= 2).length } : null,
  };
  writeFileSync(join(OUT, "trends.json"), JSON.stringify(trends));
  console.log(`Trends: ${trends.cur.total} events this week, ${trends.prev.total} the week before${trends.prev.complete ? "" : " (partly recorded)"}.`);
}

// threat actor profiles (scripts/actors.mjs, no AI model): attributed, named and claimed events per group, aliases only on a
// stated basis (MITRE ATT&CK, the event's own text). A failure never fails the build: the page says the profiles are missing.
try {
  const { buildActors, loadAttack } = await import("./actors.mjs");
  const act = buildActors(live, loadAttack(), built_at);
  writeFileSync(join(OUT, "actors.json"), JSON.stringify(act));
  console.log(`Actors: ${act.counts.profiles} profiles (${act.counts.checked} named or attributed, ${act.counts.claims_only} only in claims).`);
} catch (err) {
  writeFileSync(join(OUT, "actors.json"), JSON.stringify({ built_at, error: "The actor profiles could not be built.", profiles: [] }));
  console.warn("warning: actor profiles not built: " + String((err && err.message) || err).slice(0, 200));
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
    if (r.tier === "ai" && aiYml && r.workflow === "ai-jobs.yml") {
      if (!aiYml.includes(`cron: "${r.cron}"`)) bad.push(`routines.json: ${r.key} cron "${r.cron}" is not scheduled in ai-jobs.yml`);
      if (!new RegExp(`"${r.cron.replace(/[*]/g, "\\*")}"\\)\\s+job=${r.key}\\b`).test(aiYml)) bad.push(`routines.json: ai-jobs.yml does not map "${r.cron}" to job ${r.key}`);
    }
  }
  if (bad.length) { bad.forEach((b) => console.error("error: " + b)); console.error("\nBuild failed: routines.json and the workflows disagree."); process.exit(1); }
  const st = docs["meta/status"] || {};
  const routines = reg.routines.map((r) => ({ ...r, last_at: (r.status_key && st[r.status_key]) || null }));
  const runsDir = join(DATA, "runs"), runs = [];
  if (existsSync(runsDir)) for (const d of readdirSync(runsDir).filter((d) => d >= dayAgo(7)).sort().reverse())
    for (const f of readdirSync(join(runsDir, d)).filter((f) => f.endsWith(".json")).sort().reverse()) {
      const r = readJson(join(runsDir, d, f), {}); if (runs.length >= 40) break;
      runs.push({ at: `${d}T${f.slice(0, 2)}:${f.slice(2, 4)}:00Z`, job: String(r.job || f.slice(5, -5)).slice(0, 40),
        added: (r.added || r.kev_added || []).length, updated: (r.updated || r.events_updated || []).length,
        failed: (r.failed || r.failed_sites || []).length, note: String(r.notes || r.mode || "").slice(0, 200) });
    }
  const leadsDir = join(DATA, "leads"), byTier = { gov: 0, vendor: 0, news: 0 }; let leads24 = 0;
  if (existsSync(leadsDir)) for (const f of readdirSync(leadsDir).filter((f) => f.endsWith(".jsonl") && f.slice(0, 10) >= dayAgo(1)))
    for (const line of readFileSync(join(leadsDir, f), "utf8").split("\n")) { try { const l = JSON.parse(line); if (Date.now() - Date.parse(l.seen_at) < 864e5) { leads24++; byTier[l.tier] = (byTier[l.tier] || 0) + 1; } } catch {} }
  // open-source collectors: each one's health, and what the pipeline did with their leads this week
  const osint = readJson(join(DATA, "osint.json"), { sources: {} }), pm = pipelineMetrics(7);
  const sources = Object.entries({ ...(osint.sources || {}), ...((readJson(join(DATA, "breaches.json"), {}) || {}).sources || {}) }).map(([name, v]) => ({ name, ok: !!v.ok, error: String(v.error || "").slice(0, 90), items: v.items || 0, at: v.at || "", last_ok: v.last_ok || "" }));
  // leads "used" are credited by story (scripts/metrics.mjs storyCredit); days_covered is how much of the 7 days the lead files hold
  const pipeline = { feeds: st.collect_feeds || null, leads_7d: pm.leads, leads_used_7d: pm.leads_used, days_covered: pm.window ? pm.window.days_covered : null, events_7d: pm.events, single_source: pm.single_source, median_hours: pm.median_hours_lead_to_event, regions: pm.regions,
    collectors: pm.collectors.filter((c) => !RETIRED_COLLECTORS[c.name]).slice(0, 12),
    retired_collectors: pm.collectors.filter((c) => RETIRED_COLLECTORS[c.name]).map((c) => ({ name: c.name, leads: c.leads, used: c.used, retired: RETIRED_COLLECTORS[c.name].retired, why: RETIRED_COLLECTORS[c.name].why })), stories: { open: st.stories_open ?? null, corroborated: st.stories_corroborated ?? null, claims: st.stories_claims ?? null, leads_72h: st.leads_72h ?? null } };
  // continuous improvement: the improver's latest report (cost, yield, quality, guard) and its last changes, for the status page
  const imp = readJson(join(DATA, "improve", "latest.json"), null), chP = join(DATA, "improve", "changes.jsonl");
  const changes = existsSync(chP) ? readFileSync(chP, "utf8").trim().split("\n").filter(Boolean).slice(-10).reverse().map((l) => { try { const x = JSON.parse(l); return { at: String(x.at).slice(0, 20), key: String(x.key).slice(0, 80), from: String(x.from).slice(0, 20), to: String(x.to).slice(0, 20), reason: String(x.reason).slice(0, 300) }; } catch { return null; } }).filter(Boolean) : [];
  const improve = imp ? { at: imp.at, days: imp.days, events_added: imp.events_added, cost_usd: imp.cost_usd, cost_per_event: imp.cost_per_event, review: imp.review, guard: imp.guard,
    roles: Object.fromEntries(Object.entries(imp.roles || {}).slice(0, 30)), changes } : { changes };
  writeFileSync(join(OUT, "ops.json"), JSON.stringify({ built_at, routines, runs, leads: { last_24h: leads24, by_tier: byTier, failed_feeds: st.collect_failed || [] }, sources, pipeline, improve, speed: (() => { try { return speedOf(24); } catch { return null; } })() }));
}

// efficiency: every routine and feed against the owner's four targets (scripts/efficiency.mjs, no AI model), for the
// status page (flow, sources, usage, feeds, coverage, accuracy; it no longer shows the targets) and the improver and guard. A failure here never fails the build or the deploy: the page gets a note saying the report is missing.
try {
  const eff = await (await import("./efficiency.mjs")).build(7);
  writeFileSync(join(OUT, "efficiency.json"), JSON.stringify({ built_at, ...eff }));
  console.log("Efficiency: " + eff.targets.map((t) => `${t.key} ${t.state}`).join(", ") + `; ${eff.note}`);
} catch (err) {
  writeFileSync(join(OUT, "efficiency.json"), JSON.stringify({ built_at, error: "The efficiency report could not be built: " + String((err && err.message) || err).slice(0, 200) }));
  console.warn("warning: efficiency report not built: " + String((err && err.message) || err).slice(0, 200));
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
const AI_BY = "CyberView AI (a Claude model)";   // who writes every summary: the site's AI agents, which are Claude models
const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>CyberView: high-priority cyber events</title>
<link>${SITE}/</link>
<atom:link href="${SITE}/data/feed.xml" rel="self" type="application/rss+xml"/>
<description>High-severity incidents, exploited vulnerabilities and urgent advisories from CyberView, with what to do, researched and written by ${AI_BY}. Unverified claims are left out.</description>
<language>en</language>
<lastBuildDate>${new Date(built_at).toUTCString()}</lastBuildDate>
${picks.map((e) => `<item>
<title>${xml(e.title)}</title>
<link>${xml(link(e.id))}</link>
<guid isPermaLink="false">cyberview:${xml(e.id)}</guid>
<pubDate>${new Date(when(e)).toUTCString()}</pubDate>
<category>${xml(e.category)}</category>
<description>${xml(text(e) + " (Written by " + AI_BY + ".)")}</description>
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
  description: `High-severity incidents, exploited vulnerabilities and urgent advisories, with what to do, researched and written by ${AI_BY}. Unverified claims are left out.`,
  authors: [{ name: AI_BY, url: `${SITE}/about.html` }],
  items: picks.map((e) => ({
    id: `cyberview:${e.id}`, url: link(e.id), title: e.title, content_text: text(e), date_published: when(e),
    date_modified: /^\d{4}-\d{2}-\d{2}T/.test(e.updated_at || "") ? e.updated_at : undefined,
    tags: [e.category, ...(e.tags || [])], external_url: (e.sources && e.sources[0] && e.sources[0].url) || undefined,
  })),
}));

console.log(`Built site/data/bundle.json: ${events.length} events (of ${allEvents.length} on file), ${kev.length} known-exploited, ${corrections.length} corrections, docs: ${Object.keys(docs).join(", ") || "none"}.`);
console.log(`Feeds: ${picks.length} high-priority items in data/feed.xml and data/feed.json.`);
console.log(`Archive: ${live.length} events in ${index.months.length} month(s), ${kevAll.length} known-exploited entries. ${warnings.length} hygiene warning(s).`);

// legal pages and security.txt from legal/ and config/site.json
console.log("Pages: " + (await buildPages()).join(", "));

/** data/quality.json (scripts/pipecheck.mjs), cut to what the status page and the guard show; null when missing or broken.
 *  A late stage that is a routine is left out: the routines table already lists it (and its attention line). */
function pipelineQuality() {
  const q = readJson(join(DATA, "quality.json"), null);
  if (!q || typeof q !== "object" || !Array.isArray(q.problems)) return null;
  const shown = new Set(STAGES.filter((s) => s.routine).map((s) => `stage-${s.key}`));
  const iso = (v) => (typeof v === "string" && /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(v) ? v : "");
  return { checked_at: iso(q.checked_at), problems: q.problems.filter((p) => p && typeof p.id === "string" && typeof p.text === "string" && p.page !== false && !shown.has(p.id)).slice(0, 30)
    .map((p) => ({ id: p.id.slice(0, 60), level: ["bad", "warn", "info"].includes(p.level) ? p.level : "info", text: p.text.slice(0, 300), since: iso(p.since), over: p.over === true })) };
}

// health and manifest, written last: what was left out, and a fingerprint of every data file so the deploy can prove
// that what is live is exactly what was built (scripts/verify-build.mjs)
{
  const st = docs["meta/status"] || {};
  writeFileSync(join(OUT, "health.json"), JSON.stringify({ built_at, ok: quarantined.length === 0, quarantined: quarantined.slice(0, 100), quarantined_count: quarantined.length, warnings: warnings.length,
    last_sweep_at: st.last_sweep_at || "", last_collect_at: st.last_collect_at || "", last_feeds_at: st.last_feeds_at || "", last_backlog_at: st.last_backlog_at || "", backlog: backlogNow,
    last_cve_at: st.last_cve_at || "", last_review_at: st.last_review_at || "", last_analyst_at: st.last_analyst_at || "", last_brief_at: st.last_brief_at || "", last_analysis_at: st.last_analysis_at || "",
    last_grid_at: st.last_grid_at || "", last_grid_research_at: st.last_grid_research_at || "",
    grid_open: context.grid ? context.grid.items.filter((x) => x && x.scope !== "outage").length : null,
    grid_sources: gridSources, grid_analysis_at: gridAnalysis ? gridAnalysis.updated_at : "", last_grid_news_at: st.last_grid_news_at || "",
    grid_waiting: gridStages.waiting, grid_audit_at: gridStages.audit_at, grid_audit_flags: gridStages.audit_flags,
    last_outage_at: st.last_outage_at || "", outage_queue: outageQueue,
    // every pipeline stage's last run and limit (scripts/lib/stages.mjs; limits from routines.json), for the guard
    stages: lastRuns(st, { "grid/analysis.json": gridAnalysis || {} }), stage_limits: stageLimits((readJson(join(ROOT, "routines.json"), {}) || {}).routines || []),
    // the pipeline check's problems (scripts/pipecheck.mjs, data/quality.json), for the status page and the guard
    quality: pipelineQuality(),
    last_claims_at: st.last_claims_at || "", claims_queue: claimsQueue }));

  const filesOut = {}, walk = (dir, rel) => { for (const n of readdirSync(dir, { withFileTypes: true })) { const p = join(dir, n.name), r = rel ? `${rel}/${n.name}` : n.name; if (n.isDirectory()) walk(p, r); else if (r !== "manifest.json") { const b = readFileSync(p); filesOut[r] = { bytes: b.length, sha256: createHash("sha256").update(b).digest("hex") }; } } };
  walk(OUT, "");
  writeFileSync(join(OUT, "manifest.json"), JSON.stringify({ built_at, commit: process.env.GITHUB_SHA || "", data_commit: dataCommit(ROOT), counts: { events_bundle: events.length, events_total: live.length, kev_bundle: kev.length, kev_total: kevAll.length, guides: Object.keys(guides).length, chat: chat.length, quarantined: quarantined.length }, files: filesOut }));
}

