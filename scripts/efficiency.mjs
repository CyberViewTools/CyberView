// Efficiency report, no AI model. Run: node scripts/efficiency.mjs [--json] [--days 7]
// One honest report on every routine and every feed against the owner's four targets (2026-11-20):
//   1. speed:     from lead to a published AND second-reviewed event under 15 minutes, nine times in ten
//   2. accuracy:  the second review corrects under 10% of the events it checks
//   3. usage:     never run out of the Max plan's 5-hour and weekly usage windows
//   4. earns its place: every feed and routine produced something useful in the last 14 days (else fix or remove)
// Per routine: runs, idle runs, tokens and cost, what it added, updated, reviewed and closed, failures, last run.
// Per feed (an RSS feed by its site's host, or a collector such as bing-news, gdelt, nvd): leads, leads USED (credited by
// story: the story the lead was fused into became an event or updated one, scripts/metrics.mjs storyCredit), leads
// closed by rule, yield, and days since its last useful lead. Coverage by region, language and sector; corrections by week.
// Every window says how many days of data it really holds: the lead files start 2026-11-18, and a 7-day figure from
// 2.5 days of data is never shown as a 7-day figure. Jobs run as subagents in the ops session write no data/usage line:
// their usage is reported as "usage not logged", never as zero.
// The build writes the result to site/data/efficiency.json for the status page (scripts/build.mjs).
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, listEventFiles } from "./lib/store.mjs";
import { regionOf, storyCredit, closureOutcome, RETIRED_COLLECTORS } from "./metrics.mjs";
import { measure as speedOf } from "./lib/latency.mjs";
import { errorReport, writersFrom, firstRunLogAt } from "./review.mjs";
import { sectorsOf, SECTOR } from "./lib/taxonomy.mjs";
import { fallbackSpend, fallbackConfig, budgetConfig } from "./lib/usage.mjs";

// routines whose work is a document or a check, not a list in a run log: their idle share is not measured.
// scams is here because its output is the page of warnings (data/scams/warnings.json), not run-log lists: it files a lead
// only on an incident match, so "leads: 0" in its logs is normal and must not read as an idle routine

export const DOC_ROUTINES = new Set(["brief", "analysis", "tabletop", "improver", "watchdog", "guardian", "editor", "security-review", "monitor", "link-check", "security-check", "exploit-watch", "scams"]);
export const TARGETS = { speed_p90_min: 15, corrected_pct: 10, idle_days: 14 };
const DAY = 864e5;
const iso = (t) => new Date(t).toISOString().replace(/\.\d+Z$/, "Z");
const num = (v) => (typeof v === "number" && isFinite(v) ? v : 0);
const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : null);
const days1 = (ms) => Math.round((ms / DAY) * 10) / 10;

/* ---------------- routines ---------------- */

/** Pure: the routine (routines.json key) a run log or usage line belongs to. job: the run log's name after the time
 *  ("sweep-r1", "review-r2", "analyst-3", "backlog-auto"), keys: Set of routine keys, model: the log's model (a
 *  triage log written by the rules has model null and belongs to the lead-triage automation, not the AI triage job). */
export function routineOf(job, keys, model) {
  const j = String(job || "").toLowerCase().trim();
  if (!j) return "other";
  if (j === "backlog-auto" || (j === "triage" && model === null)) return keys.has("lead-triage") ? "lead-triage" : "other";
  if (/^backlog/.test(j)) return "backlog";
  if (/^(sweep|update|stories|gap)(-|$)/.test(j)) return "sweep";
  if (/^(review|reviewer)(-|$)/.test(j)) return "review";
  if (j === "context") return "feeds";
  if (j === "reports") return keys.has("report-review") ? "report-review" : "other";
  if (keys.has(j)) return j;
  // "analyst-28", "grid-2", "deep-sweep-latin-america": drop trailing parts until a routine key is left
  for (let k = j.replace(/-[a-z]?\d+[a-z]?$/, ""); k; k = k.includes("-") ? k.slice(0, k.lastIndexOf("-")) : "") if (keys.has(k)) return k;
  return "other";
}

/** Pure: what one run log produced. Lists only; a field missing is zero. */
// what a routine's "closed" counts: lead-triage closes leads (one by one, by rule); every other routine closes fuse stories
export const CLOSED_UNIT = { "lead-triage": "leads" };
export const closedUnit = (key) => CLOSED_UNIT[key] || "stories";
export function logOutput(r) {
  const n = (k) => (Array.isArray(r && r[k]) ? r[k].length : 0);
  const out = { added: n("added") + n("kev_added") + n("opened"), updated: n("updated") + n("events_updated") + n("closed") + n("rerated"), reviewed: n("reviewed"), closed: n("skipped") };
  out.total = out.added + out.updated + out.reviewed + out.closed;
  return out;
}

/** Pure: one row per routine.
 *  registry: routines.json's routines; usage: data/usage lines; logs: [{at, job, model, out}] (run logs, out = logOutput);
 *  jobruns: [{job, started_at, finished_at, workers, cost}]; status: data/status.json; since/now: ms. */
export function routineReport(registry, usage, logs, jobruns, status, since, now = Date.now(), leads = []) {
  const keys = new Set(registry.map((r) => r.key)), rows = new Map(), hbKey = new Map(registry.filter((r) => r.status_key).map((r) => [r.key, r.status_key]));
  for (const r of registry) rows.set(r.key, { key: r.key, name: String(r.name || r.key), tier: r.tier === "ai" ? "ai" : "automation", model: r.model || null, active: r.active !== false, retired: r.active === false && !!r.retired, merged_into: r.active === false && r.retired && typeof r.merged_into === "string" ? r.merged_into.slice(0, 40) : null,
    runs: 0, idle: 0, idle_tokens: 0, worker_runs: 0, logs: 0, idle_logs: 0, tokens: 0, cost: 0, usage_lines: 0, failures: 0, added: 0, updated: 0, reviewed: 0, closed: 0, last_run: (r.status_key && status[r.status_key]) || null, last_useful: null });
  const row = (k) => rows.get(k) || rows.get("other") || rows.set("other", { key: "other", name: "Not in routines.json", tier: "ai", model: null, active: true, runs: 0, idle: 0, idle_tokens: 0, worker_runs: 0, logs: 0, idle_logs: 0, tokens: 0, cost: 0, usage_lines: 0, failures: 0, added: 0, updated: 0, reviewed: 0, closed: 0, last_run: null, last_useful: null }).get("other");
  const usageBy = new Map(), uKey = (u) => (keys.has(u.job) ? u.job : routineOf(u.job, keys, u.model));
  const later = (a, b) => (!a ? b : !b ? a : a > b ? a : b);
  const inWin = (t) => { const x = Date.parse(t); return isFinite(x) && x >= since && x <= now + 6e4; };
  for (const u of usage) {
    if (!inWin(u.at)) continue;
    const r = row(uKey(u)); (usageBy.get(r.key) || usageBy.set(r.key, []).get(r.key)).push(u);
    r.usage_lines++; r.worker_runs++; r.tokens += num(u.in) + num(u.out) + num(u.cache_read) + num(u.cache_write); r.cost += num(u.cost);
    if (u.ok === false || u.error) r.failures++;
    r.last_run = later(r.last_run, u.at);
  }
  const byRoutine = new Map();
  for (const l of logs) {
    if (!inWin(l.at)) continue;
    const k = routineOf(l.job, keys, l.model), r = row(k);
    r.logs++; r.added += l.out.added; r.updated += l.out.updated; r.reviewed += l.out.reviewed; r.closed += l.out.closed;
    if (!l.out.total) r.idle_logs++; else r.last_useful = later(r.last_useful, l.at);
    r.last_run = later(r.last_run, l.at);
    (byRoutine.get(r.key) || byRoutine.set(r.key, []).get(r.key)).push(l);
  }
  const counted = new Set();
  for (const j of jobruns) {
    if (!inWin(j.started_at)) continue;
    const r = row(keys.has(j.job) ? j.job : routineOf(j.job, keys, undefined)); counted.add(r.key);
    r.runs++;
    // idle: no worker started, or none of the run logs written during the run produced anything
    const a = Date.parse(j.started_at), b = Date.parse(j.finished_at || j.started_at) + 12e4;
    // a worker's own times are not always exact: its log belongs to the run when its start, file time or end falls inside
    const mine = (byRoutine.get(r.key) || []).filter((l) => [l.start, l.file, l.at].some((x) => { const t = Date.parse(x); return t >= a - 12e4 && t <= b; }));
    if (!num(j.workers) || !mine.some((l) => l.out.total)) {
      r.idle++;
      // what the idle run spent: its workers' usage lines (each is written when the worker ends, inside the run)
      for (const u of usageBy.get(r.key) || []) { const t = Date.parse(u.at); if (t >= a - 6e4 && t <= b) r.idle_tokens += num(u.in) + num(u.out) + num(u.cache_read) + num(u.cache_write); }
    }
    r.last_run = later(r.last_run, j.finished_at || j.started_at);
  }
  // routines with no run record of their own (subagent jobs, scripts): a run is a run log
  for (const r of rows.values()) if (!counted.has(r.key)) { r.runs = r.logs; r.idle = r.idle_logs; }
  // a script routine writes no run log and no job record: an advance of its heartbeat inside the window is one run
  // (a lower bound, status.json keeps only the latest advance), so "0 runs" means it never ran
  for (const r of rows.values()) if (!counted.has(r.key) && !r.logs && !r.runs && hbKey.has(r.key) && inWin(status[hbKey.get(r.key)])) { r.runs = 1; r.runs_basis = "heartbeat"; }
  // the collectors write no run log: their output is the leads they filed (runs stay unknown)
  const filed = { collect: (l) => (l.via || "rss") === "rss", osint: (l) => !["rss", "cvelist"].includes(l.via || "rss"), cve: (l) => l.via === "cvelist" };
  for (const [k, f] of Object.entries(filed)) if (rows.has(k)) { const r = rows.get(k), mine = leads.filter((l) => Date.parse(l.seen_at) >= since && f(l)); r.filed = mine.length; r.added += mine.length; if (mine.length) { r.last_useful = mine.map((l) => l.seen_at).sort().pop(); if (!r.logs) r.runs = null; } }
  const workers = new Map(); for (const j of jobruns) if (inWin(j.started_at)) { const k = keys.has(j.job) ? j.job : routineOf(j.job, keys, undefined); workers.set(k, (workers.get(k) || 0) + num(j.workers)); }
  return [...rows.values()].map((r) => {
    r.closed_unit = closedUnit(r.key);
    // a headless job that started no worker used nothing: that is logged, not unknown
    const usage = r.tier !== "ai" ? "none (script)" : r.usage_lines ? (r.logs > r.usage_lines && !counted.has(r.key) ? "partly logged" : "logged") : counted.has(r.key) && !workers.get(r.key) ? "logged" : r.runs || r.last_run ? "not logged" : "no runs";
    if (usage === "logged" && !r.usage_lines) r.usage_lines = -1;
    const logged = r.usage_lines !== 0; if (r.usage_lines < 0) r.usage_lines = 0;
    return { ...r, tokens: logged ? r.tokens : null, cost: logged ? Math.round(r.cost * 100) / 100 : null, usage,
      idle_pct: r.runs && !DOC_ROUTINES.has(r.key) ? Math.round((r.idle / r.runs) * 100) : null, idle_tokens: logged && !DOC_ROUTINES.has(r.key) ? r.idle_tokens : null, output: r.added + r.updated + r.reviewed + r.closed, closed_stories: r.closed_unit === "stories" ? r.closed : 0, closed_leads: r.closed_unit === "leads" ? r.closed : 0,
      tokens_per_output: logged && r.tokens && r.added + r.updated + r.reviewed ? Math.round(r.tokens / (r.added + r.updated + r.reviewed)) : null };
  }).sort((a, b) => num(b.tokens) - num(a.tokens) || b.runs - a.runs);
}

/* ---------------- feeds ---------------- */

/** Pure: the feed a lead came from: an RSS feed by its site's host ("rss:bleepingcomputer.com"), else the collector. */
export function feedOf(l) {
  const via = String((l && l.via) || "rss");
  if (via !== "rss") return via;
  try { return "rss:" + new URL(l.url).hostname.replace(/^www\./, ""); } catch { return "rss:unknown"; }
}

/** Pure: one row per feed. leads [{url, via, source, seen_at}], used Map(url -> how) from storyCredit, byRule Set(url)
 *  of leads a rule closed, osint data/osint.json ({feeds: {name: {ok,error}}, sources: {collector: {ok,error}}}). */
export function feedReport(leads, used, byRule, osint = {}, now = Date.now()) {
  const rows = new Map(), feedsByName = (osint && osint.feeds) || {}, coll = (osint && osint.sources) || {};
  for (const l of leads) {
    const k = feedOf(l);
    const r = rows.get(k) || rows.set(k, { name: k, via: String(l.via || "rss"), sources: [], leads: 0, used: 0, by_rule: 0, last_lead: null, last_useful: null, ok: true, error: "" }).get(k);
    r.leads++;
    // a feed's first collection dumps its whole backlog into one day: that day is kept in the totals, never in the ranking
    const day = String(l.seen_at || "").slice(0, 10); if (day && (!r.first_day || day < r.first_day)) r.first_day = day;
    (r.days ||= new Map()).set(day, (r.days.get(day) || 0) + 1);
    if (l.source && r.sources.length < 3 && !r.sources.includes(String(l.source))) r.sources.push(String(l.source));
    if (!r.last_lead || l.seen_at > r.last_lead) r.last_lead = l.seen_at;
    if (used.has(l.url)) { r.used++; if (!r.last_useful || l.seen_at > r.last_useful) r.last_useful = l.seen_at; }
    else if (byRule.has(l.url)) r.by_rule++;
  }
  // configured feeds that filed no lead at all in the window are rows too: they cost a request every 30 minutes
  const named = new Set(leads.map((l) => String(l.source || "")));
  for (const [name, f] of Object.entries(feedsByName)) if (!named.has(name)) rows.set("feed:" + name, { name: "feed:" + name, via: "rss", sources: [name], leads: 0, used: 0, by_rule: 0, last_lead: null, last_useful: null, ok: !!(f && f.ok), error: String((f && f.error) || "").slice(0, 120) });
  for (const r of rows.values()) {
    if (r.via !== "rss" && coll[r.via]) { r.ok = !!coll[r.via].ok; r.error = r.ok ? "" : String(coll[r.via].error || "").slice(0, 120); }
    if (r.via === "rss" && r.sources.some((s) => feedsByName[s] && feedsByName[s].ok === false)) { r.ok = false; r.error = String(feedsByName[r.sources.find((s) => feedsByName[s] && feedsByName[s].ok === false)].error || "").slice(0, 120); }
  }
  for (const [name, v] of Object.entries(coll)) if (!rows.has(name)) rows.set(name, { name, via: name, sources: [], leads: 0, used: 0, by_rule: 0, last_lead: null, last_useful: null, ok: !!(v && v.ok), error: String((v && v.error) || "").slice(0, 120) });
  return [...rows.values()].map(({ days, ...r }) => ({ ...r, first_day: r.first_day || null, leads_after_first_day: days ? r.leads - (days.get(r.first_day) || 0) : 0, yield: r.leads ? Math.round((r.used / r.leads) * 1000) / 10 : null,
    days_since_useful: r.last_useful ? days1(now - Date.parse(r.last_useful)) : null,
    verdict: r.used ? "useful" : r.leads >= 15 ? "noise" : r.leads ? "nothing used yet" : "silent" }))
    .sort((a, b) => b.leads - a.leads || a.name.localeCompare(b.name));
}

/** Pure: marks the feeds that are no longer collected: a collector in RETIRED_COLLECTORS, or an RSS feed whose every
 *  source name is in config/feeds.json `retired` ([{name, retired, why}]). Their leads stay in every count and target;
 *  the status page lists them apart, never as a current feed. Returns the same rows. */
export function markRetired(feeds, retiredCfg = [], collectors = RETIRED_COLLECTORS) {
  const byName = new Map((Array.isArray(retiredCfg) ? retiredCfg : []).filter((r) => r && r.name).map((r) => [String(r.name).toLowerCase(), r]));
  for (const f of feeds) {
    const c = collectors[f.name], names = (f.sources || []).map((x) => String(x).toLowerCase()), cfg = f.via === "rss" && names.length && names.every((n) => byName.has(n)) ? byName.get(names[0]) : null;
    if (c) Object.assign(f, { retired: true, retired_at: String(c.retired || "").slice(0, 10), retired_why: String(c.why || "").slice(0, 300) });
    else if (cfg) Object.assign(f, { retired: true, retired_at: String(cfg.retired || "").slice(0, 10), retired_why: String(cfg.why || "").slice(0, 300) });
  }
  return feeds;
}

/* ---------------- coverage and accuracy ---------------- */

const SECTORS = [["water", /\b(water|wastewater)\b/i], ["energy", /\b(energy|power|electric\w*|utilit(y|ies)|oil|gas|nuclear|grid|pipeline|refiner\w*)\b/i], ["health", /\b(health\w*|hospital\w*|medical|clinic\w*|pharma\w*|patient\w*)\b/i],
  ["transport", /\b(transport\w*|airline\w*|airport\w*|aviation|rail\w*|port|ports|shipping|maritime|logistics|transit)\b/i], ["telecom", /\b(telecom\w*|telco\w*|mobile operator|carrier|isp|broadband)\b/i],
  ["government", /\b(government|ministry|municipal\w*|public sector|council|parliament|federal|state agency|agency|military|defen[cs]e|city of|county)\b/i]];
/** Pure: where an event's coverage sector comes from: its explicit "sectors" ("stated" or "inferred"), else "keyword". */
export function sectorBasis(e) {
  const se = sectorsOf(e);
  return se && se.values.some((k) => SECTOR[k].cov) ? se.basis : "keyword";
}
/** Pure: the critical-infrastructure sector an event is in: from its explicit "sectors" when it has them (the first with a
 *  coverage key), else from its sector field and tags by keyword (can be wrong; sectorBasis says which). */
export function sectorOf(e) {
  const se = sectorsOf(e), c = se && se.values.map((k) => SECTOR[k].cov).find(Boolean);
  if (c) return c;
  const text = [e.sector, ...(Array.isArray(e.tags) ? e.tags : [])].filter(Boolean).join(" ");
  for (const [k, re] of SECTORS) if (re.test(text)) return k;
  return "other";
}
const TLD_LANG = { de: "de", at: "de", ch: "de", fr: "fr", be: "fr", es: "es", mx: "es", ar: "es", cl: "es", co: "es", it: "it", jp: "ja", kr: "ko", cn: "zh", tw: "zh", br: "pt", pt: "pt", ru: "ru", ua: "uk", tr: "tr", nl: "nl", pl: "pl", id: "id", vn: "vi", th: "th", il: "he", ir: "fa", sa: "ar", ae: "ar", eg: "ar", se: "sv", no: "no", dk: "da", fi: "fi", cz: "cs", gr: "el", ro: "ro", hu: "hu" };
/** Pure: the language an event was found in: a non-English source language first (from the lead that carried the page,
 *  RSS feeds without a language are English by the collector's convention), else the site's country domain, else "en"
 *  for an English feed, else "not recorded". */
export function languageOf(e, leadByUrl) {
  const langs = new Set();
  for (const s of e.sources || []) {
    const u = (s && s.url) || "", l = leadByUrl.get(u);
    if (l && /^[a-z]{2}$/.test(String(l.lang || ""))) langs.add(l.lang);
    else if (l && (l.via || "rss") === "rss") langs.add("en");
    else { const m = String(u).match(/^https?:\/\/[^/]*\.([a-z]{2})(?::\d+)?(\/|$)/i); if (m && TLD_LANG[m[1].toLowerCase()]) langs.add(TLD_LANG[m[1].toLowerCase()]); }
  }
  return [...langs].find((x) => x !== "en") || (langs.has("en") ? "en" : "not recorded");
}

/** Pure: events by region, language and sector over the last `days` days (by first_seen), duplicates left out. */
export function coverage(events, leadByUrl, days, now = Date.now()) {
  const since = iso(now - days * DAY), ev = events.filter((e) => e && !e.duplicate_of && String(e.first_seen || "") >= since);
  const add = (o, k) => { o[k] = (o[k] || 0) + 1; };
  const out = { days, events: ev.length, claimed: ev.filter((e) => e.status === "claimed").length, region: {}, language: {}, sector: {}, sector_basis: {} };
  for (const e of ev) { add(out.region, regionOf(e.country)); add(out.language, languageOf(e, leadByUrl)); add(out.sector, sectorOf(e)); add(out.sector_basis, sectorBasis(e)); }
  return out;
}

const weekOf = (t) => { const d = new Date(Date.parse(t)); d.setUTCHours(0, 0, 0, 0); d.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 6) % 7)); return d.toISOString().slice(0, 10); };
/** Pure: the second review's verdicts by week (Monday, by the first review's time) and its categories (flags, or the
 *  review's own categories when it records them). Rate = corrected / reviewed; flagged is shown beside it. */
export function accuracy(events, now = Date.now(), days = 7) {
  const weeks = {}, cats = {}, since = iso(now - days * DAY); let rev = 0, cor = 0, fl = 0;
  for (const e of events) {
    const r = e && !e.duplicate_of && e.review; if (!r || !r.state) continue;
    const at = r.first_at || r.at; if (!at || !isFinite(Date.parse(at))) continue;
    const w = weekOf(at), x = (weeks[w] ||= { week: w, reviewed: 0, corrected: 0, flagged: 0 });
    x.reviewed++; if (r.state === "corrected") x.corrected++; if (r.state === "flagged") x.flagged++;
    if (at >= since) {
      rev++; if (r.state === "corrected") cor++; if (r.state === "flagged") fl++;
      if (r.state !== "passed") for (const c of [].concat(Array.isArray(r.categories) ? r.categories : [], Array.isArray(r.flags) ? r.flags : [])) if (typeof c === "string" && c) cats[c.slice(0, 40)] = (cats[c.slice(0, 40)] || 0) + 1;
    }
  }
  return { days, reviewed: rev, corrected: cor, flagged: fl, corrected_pct: pct(cor, rev), corrected_or_flagged_pct: pct(cor + fl, rev),
    weeks: Object.values(weeks).sort((a, b) => a.week.localeCompare(b.week)).map((w) => ({ ...w, corrected_pct: pct(w.corrected, w.reviewed) })),
    categories: Object.entries(cats).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([name, n]) => ({ name, n })) };
}

/* ---------------- usage windows ---------------- */

/** Pure: tokens and cost logged in data/usage in the `hours` before now (the fallback when scripts/lib/usage.mjs is absent). */
export function sumWindow(usage, now, hours) {
  const from = now - hours * 36e5; let runs = 0, tokens = 0, cost = 0;
  for (const u of usage) { const t = Date.parse(u.at); if (!isFinite(t) || t < from || t > now + 6e4) continue; runs++; tokens += num(u.in) + num(u.out) + num(u.cache_read) + num(u.cache_write); cost += num(u.cost); }
  return { from: iso(from), to: iso(now), runs, tokens, cost: Math.round(cost * 100) / 100 };
}
const cleanWin = (w) => (w && typeof w === "object" ? { from: String(w.from || "").slice(0, 25), to: String(w.to || "").slice(0, 25), runs: num(w.runs), tokens: num(w.tokens), cost: Math.round(num(w.cost) * 100) / 100 } : null);
/** The current 5-hour window and the last 7 days. From scripts/lib/usage.mjs (windowUsage, budgetState) when it exists;
 *  else a plain sum over data/usage, marked "estimate". Either way only headless workers are counted. */
export async function usageWindows(usage, now = Date.now(), lib = null) {
  try {
    const m = lib || (await import("./lib/usage.mjs"));
    if (m && typeof m.windowUsage === "function") {
      const five = cleanWin(await m.windowUsage(now, 5)), week = cleanWin(await m.windowUsage(now, 168));
      let budget = null;
      if (typeof m.budgetState === "function") { const b = await m.budgetState(now); if (b && typeof b === "object") budget = { window_pct: typeof b.window_pct === "number" ? Math.round(b.window_pct) : null, week_pct: typeof b.week_pct === "number" ? Math.round(b.week_pct) : null, level: ["ok", "tight", "stop"].includes(b.level) ? b.level : null,
        limited_until: typeof b.limited_until === "string" ? b.limited_until.slice(0, 25) : null, reason: String(b.reason || "").slice(0, 200) }; }
      if (five && week) return { source: "usage.mjs", estimate: false, five_hour: five, week, budget };
    }
  } catch {}
  return { source: "data/usage", estimate: true, five_hour: sumWindow(usage, now, 5), week: sumWindow(usage, now, 168), budget: null };
}

/** Pure: the research loop's cycles in the window (data/runs/<date>/jobruns.jsonl, flow records). An idle cycle leaves no
 *  record of its own: newer records carry `idle_before` (idle cycles since the last record); for older ones the gaps in
 *  the cycle numbers of one loop run are counted instead. Each record's `budget` is the plan-usage level that cycle saw.
 *  leases: data/leases.json (flow:leader carries the level the running loop last saw). */
export function loopCycles(jobruns, since, leases = {}) {
  const out = { recorded: 0, worked: 0, idle_recorded: 0, idle_unrecorded: 0, idle_from_gaps: 0, budget: { ok: 0, tight: 0, stop: 0, unknown: 0 }, last_budget: null, leader_budget: null };
  const byRun = new Map();
  for (const j of jobruns) {
    if (!j || !j.flow || !(Date.parse(j.started_at) >= since)) continue;
    out.recorded++;
    if (num(j.workers)) out.worked++; else out.idle_recorded++;
    const lv = j.budget && ["ok", "tight", "stop"].includes(j.budget.level) ? j.budget.level : "unknown"; out.budget[lv]++;
    if (lv !== "unknown" && (!out.last_budget || j.started_at > out.last_budget.at)) out.last_budget = { at: j.started_at, level: lv, window_pct: typeof j.budget.window_pct === "number" ? j.budget.window_pct : null, week_pct: typeof j.budget.week_pct === "number" ? j.budget.week_pct : null };
    const run = String(j.run || "").replace(/-c\d+$/, "");
    (byRun.get(run) || byRun.set(run, []).get(run)).push(j);
  }
  for (const list of byRun.values()) {
    list.sort((a, b) => num(a.cycle) - num(b.cycle));
    list.forEach((j, i) => {
      if (typeof j.idle_before === "number" && j.idle_before > 0) out.idle_unrecorded += j.idle_before;
      else if (j.idle_before === undefined && i > 0 && num(j.cycle) - num(list[i - 1].cycle) > 1) { const g = num(j.cycle) - num(list[i - 1].cycle) - 1; out.idle_unrecorded += g; out.idle_from_gaps += g; }
    });
  }
  const L = leases && leases["flow:leader"];
  if (L && ["ok", "tight", "stop"].includes(L.budget)) out.leader_budget = { level: L.budget, cycle: num(L.cycle), until: String(L.until || "").slice(0, 25) };
  out.cycles = out.recorded + out.idle_unrecorded;
  out.idle = out.idle_recorded + out.idle_unrecorded;
  out.idle_pct = out.cycles ? Math.round((out.idle / out.cycles) * 100) : null;
  return out;
}

/* ---------------- how the data flows, and where it comes from (the status page's flow and sources blocks) ---------------- */

/** Pure: a rule closure's reason cut to its rule ("story ab12cd34: already on file: <id>" -> "already on file"). */
export function ruleReason(r) {
  return String(r || "").replace(/^story [0-9a-f]{6,12}: /, "").split(/[:;(]/)[0].replace(/\s+/g, " ").trim().toLowerCase().slice(0, 120) || "no reason recorded";
}
const DB_KINDS = new Set(["cve", "breach-db", "status", "exploited"]);
/** Pure: the tier of one lead as the status page names it: a database row (CVE, breach or status record) whatever its
 *  feed, else the feed's own tier (gov, vendor, news). */
export function leadTier(l) {
  if (l && DB_KINDS.has(l.kind)) return "database";
  return l && ["gov", "vendor", "news"].includes(l.tier) ? l.tier : "news";
}
const FAMILY = { rss: "rss", "bing-news": "bing-news", gdelt: "gdelt", "gdelt-gkg": "gdelt", "google-news": "google-news", cvelist: "cve-kev", nvd: "cve-kev", euvd: "cve-kev", kev: "cve-kev", "ransomware-live": "claims", "grid-desk": "grid" };
/** Pure: the collector family a lead came through (agency, vendor and news RSS; Bing News; GDELT; CVE corpus, NVD and
 *  KEV; leak-site claims; grid operators; other open sources). */
export function familyOf(l) { return FAMILY[String((l && l.via) || "rss")] || "other"; }

/** Pure: the numbers for each stage of the pipeline over the last `hours` (24, or the report's 7 days). Every figure is a
 *  count already defined elsewhere: leads (data/leads, by seen_at), stories (fuse's grouping: storyOf from storyCredit),
 *  stories closed by a rule (the rule closures) and read by AI agents (closures.jsonl), how many of those ended as an
 *  event or an update (closureOutcome), events published (first_seen) and updated (updated_at), and the second review
 *  (accuracy(), by the first review's time). */
export function flowWindow(inp, storyOf, hours, now = Date.now()) {
  const since = now - hours * 36e5, sinceIso = iso(since), inW = (t) => { const x = Date.parse(t); return isFinite(x) && x >= since && x <= now + 6e4; };
  const leads = (inp.leads || []).filter((l) => l && inW(l.seen_at)), stories = new Set();
  for (const l of leads) stories.add((storyOf && storyOf.get(l.url)) || "u:" + l.url);
  const events = (inp.events || []).filter(Boolean), ids = new Set(events.map((e) => e.id).filter(Boolean));
  const ruleIds = new Set(), aiIds = new Set(), toEvent = new Set(), reasons = {};
  for (const c of inp.closures || []) {
    if (!c || !inW(c.at)) continue;
    const k = String(c.story || c.title || c.at);
    if (c.rule) { if (!ruleIds.has(k)) { ruleIds.add(k); const r = ruleReason(c.reason); reasons[r] = (reasons[r] || 0) + 1; } }
    else { aiIds.add(k); if (closureOutcome(c.reason, ids)) toEvent.add(k); }
  }
  const live = events.filter((e) => !e.duplicate_of);
  const added = live.filter((e) => inW(e.first_seen)).length;
  const updated = live.filter((e) => inW(e.updated_at) && !(String(e.first_seen || "") >= sinceIso) && e.updated_at !== e.first_seen).length;
  const a = accuracy(live, now, hours / 24);
  return { hours, leads: leads.length, stories: stories.size, rule: ruleIds.size, researched: aiIds.size, to_event: toEvent.size,
    reasons: Object.entries(reasons).sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1)).slice(0, 3).map(([reason, n]) => ({ reason, n })),
    added, updated, reviewed: a.reviewed, passed: Math.max(0, a.reviewed - a.corrected - a.flagged), corrected: a.corrected, flagged: a.flagged };
}

/** Pure: what feeds the pipeline: RSS feeds by tier, the other collectors and how many of them load, and the languages
 *  and regions the feeds and standing searches cover. feeds [{tier, lang, region}], queries [{hl, region}],
 *  osint data/osint.json, status data/status.json (collect_feeds_ok). */
export function sourceSummary(feeds = [], queries = [], osint = {}, status = {}) {
  const tier = { gov: 0, vendor: 0, news: 0 }, langs = new Set(), regions = new Set();
  for (const f of feeds) { if (!f) continue; if (tier[f.tier] !== undefined) tier[f.tier]++; langs.add(String(f.lang || "en").slice(0, 8)); if (f.region) regions.add(String(f.region).slice(0, 30)); }
  for (const q of queries) { if (!q) continue; if (q.hl) langs.add(String(q.hl).slice(0, 8)); if (q.region && q.region !== "global") regions.add(String(q.region).slice(0, 30)); }
  const coll = Object.entries((osint && osint.sources) || {}).filter(([k]) => !RETIRED_COLLECTORS[k]);
  return { feeds: feeds.length, feeds_ok: status && typeof status.collect_feeds_ok === "number" ? status.collect_feeds_ok : null, by_tier: tier, queries: queries.length,
    collectors: coll.length, collectors_ok: coll.filter(([, v]) => v && v.ok).length, languages: langs.size, regions: regions.size };
}

/** Pure: where the events first seen since `since` (ms) came from. Each event is traced to the leads that carried it: the
 *  leads whose page it cites, and the leads of a story whose closure names it. Tier: the highest of those leads
 *  (government or CERT, vendor, news, database row); collector family: the lead seen first. An event no lead carried
 *  (found by an agent's own search, or written from a feed sync) is "untraced"; one first seen before the lead files
 *  start is "before-leads". URLs are compared without scheme, www, query, fragment and trailing slash. Publishers: the sites the events cite,
 *  each counted once per event. */
export const urlKey = (u) => String(u || "").trim().replace(/^https?:\/\/(www\.)?/i, "").replace(/[?#].*$/, "").replace(/\/+$/, "").toLowerCase();
export function sourcesReport(events, leads, closures, since) {
  const byUrl = new Map(); let first = Infinity;
  for (const l of leads || []) { if (!l || !l.url) continue; const k = urlKey(l.url); if (!byUrl.has(k)) byUrl.set(k, l); const t = Date.parse(l.seen_at); if (t < first) first = t; }
  const ev = (events || []).filter((e) => e && !e.duplicate_of && Date.parse(e.first_seen) >= since), ids = new Set(ev.map((e) => e.id));
  const viaStory = new Map();
  for (const c of closures || []) {
    if (!c || c.rule || !Array.isArray(c.urls)) continue;
    const id = String(c.reason || "").trim().split(/[\s:;,()]/)[0];
    if (ids.has(id)) (viaStory.get(id) || viaStory.set(id, []).get(id)).push(...c.urls);
  }
  const RANK = { gov: 0, vendor: 1, news: 2, database: 3 }, tier = {}, family = {}, pubs = new Map(), add = (o, k) => { o[k] = (o[k] || 0) + 1; };
  for (const e of ev) {
    const urls = (e.sources || []).map((s) => (s && s.url) || "").concat(viaStory.get(e.id) || []);
    const mine = [...new Set(urls.map(urlKey))].map((u) => byUrl.get(u)).filter(Boolean);
    // an event first seen before the lead files start cannot be traced to a lead: it is counted apart, not as "untraced"
    if (!mine.length) { const k = Date.parse(e.first_seen) < first ? "before-leads" : "untraced"; add(tier, k); add(family, k); }
    else {
      add(tier, mine.map(leadTier).sort((a, b) => RANK[a] - RANK[b])[0]);
      add(family, familyOf(mine.slice().sort((a, b) => String(a.seen_at).localeCompare(String(b.seen_at)))[0]));
    }
    const hosts = new Set();
    for (const s of e.sources || []) {
      let h = ""; try { h = new URL(s.url).hostname.replace(/^www\./, "").toLowerCase(); } catch { continue; }
      if (!h || hosts.has(h)) continue; hosts.add(h);
      const p = pubs.get(h) || pubs.set(h, { host: h, n: 0, names: {} }).get(h); p.n++;
      const nm = String((s && s.name) || "").trim().slice(0, 60); if (nm) p.names[nm] = (p.names[nm] || 0) + 1;
    }
  }
  const publishers = [...pubs.values()].sort((a, b) => b.n - a.n || a.host.localeCompare(b.host)).slice(0, 10)
    .map((p) => ({ host: p.host, name: (Object.entries(p.names).sort((a, b) => b[1] - a[1])[0] || [p.host])[0], events: p.n }));
  return { events: ev.length, tier, family, publishers };
}

/* ---------------- targets ---------------- */

/** Pure: the four targets with their current value and pass, fail or unknown. */
export function targets({ speed, acc, windows, routines, feeds, days, loop = null }) {
  const out = [];
  const p90 = speed && speed.review ? speed.review.p90 : null, n = speed && speed.review ? speed.review.n : 0;
  out.push({ key: "speed", title: "Speed", goal: "under 15 min, nine times in ten", figure: p90 == null ? "not measured" : `${p90} min`,
    detail: p90 == null ? "no event has gone from lead to second review in the window yet" : `nine in ten events, from the first lead to published and second-reviewed (${n} events, last ${speed.hours} h)`,
    target: "Lead to a published and second-reviewed event in under 15 minutes, nine times in ten",
    value: p90 == null ? "not measured" : `${p90} min for nine in ten (${n} events, last ${speed.hours} h)`, state: p90 == null ? "unknown" : p90 < TARGETS.speed_p90_min ? "pass" : "fail" });
  out.push({ key: "accuracy", title: "Accuracy", goal: "second review corrects under 10%", figure: acc.corrected_pct == null ? "nothing reviewed" : `${acc.corrected_pct}%`,
    detail: acc.corrected_pct == null ? "no event has had its second review yet" : `corrected ${acc.corrected} of ${acc.reviewed} events reviewed in the last ${acc.days} days; ${acc.flagged} more flagged`,
    target: "Second review corrects under 10% of events",
    value: acc.corrected_pct == null ? "nothing reviewed" : `${acc.corrected_pct}% corrected (${acc.corrected} of ${acc.reviewed}, last ${acc.days} days); ${acc.flagged} more flagged`, state: acc.corrected_pct == null ? "unknown" : acc.corrected_pct < TARGETS.corrected_pct ? "pass" : "fail" });
  // the level now: scripts/lib/usage.mjs when it exists, else what the running loop last saw (its lease, then its last cycle)
  const b = (windows && windows.budget && windows.budget.level ? windows.budget : null) || (loop && loop.leader_budget ? { level: loop.leader_budget.level, window_pct: null, week_pct: null } : null) || (loop && loop.last_budget) || null, unlogged = routines.filter((r) => r.usage === "not logged" || r.usage === "partly logged").map((r) => r.key);
  out.push({ key: "usage", title: "Usage", goal: "never run out of the 5-hour or weekly window", figure: b && b.level ? `${b.window_pct ?? "?"}%` : "not known",
    detail: b && b.level ? `of the estimated 5-hour window; ${b.week_pct ?? "?"}% of the week, level ${b.level}${loop && loop.budget.stop ? `; ${loop.budget.stop} loop cycle(s) stopped for usage` : ""}` : "the plan's limits are not known here; only headless workers are logged",
    target: "Never run out of the 5-hour or weekly usage window",
    value: b && b.level ? `${b.window_pct ?? "?"}% of the estimated 5-hour window, ${b.week_pct ?? "?"}% of the estimated week (level ${b.level}), headless workers only (the dispatcher and interactive sessions share the window and are not counted)${loop && loop.budget.stop ? `; ${loop.budget.stop} loop cycle(s) stopped for usage` : ""}` : `${windows.five_hour.tokens.toLocaleString("en")} tokens in the last 5 hours, ${windows.week.tokens.toLocaleString("en")} in 7 days (headless workers only; the plan's limits are not known here)`,
    state: b && b.level ? (b.level === "stop" || (loop && loop.budget.stop) ? "fail" : "pass") : "unknown", note: unlogged.length ? `usage not logged for ${unlogged.join(", ")}` : "" });
  const idleR = routines.filter((r) => r.active && !r.retired && r.key !== "other" && r.runs && !r.output).map((r) => r.key), idleF = feeds.filter((f) => f.verdict !== "useful").map((f) => f.name);
  out.push({ key: "earns", title: "Earns its place", goal: "every feed and routine useful within 14 days", figure: `${idleR.length + idleF.length} ${days < TARGETS.idle_days ? "candidates" : "idle"}`,
    detail: `${idleR.length} routine(s) and ${idleF.length} feed(s) with nothing useful yet in ${days} day(s) of data`,
    target: "Every feed and routine useful at least once in 14 days",
    value: `${idleR.length} routine(s) and ${idleF.length} feed(s) with nothing useful in ${days} day(s) of data`, state: days < TARGETS.idle_days ? "unknown" : idleR.length || idleF.length ? "fail" : "pass",
    note: days < TARGETS.idle_days ? `needs ${TARGETS.idle_days} days of data; ${days} so far, so these are candidates, not verdicts` : "" });
  return out;
}

/* ---------------- loading (read-only) ---------------- */

const jsonl = (p) => { const out = []; if (!existsSync(p)) return out; for (const line of readFileSync(p, "utf8").split("\n")) { if (!line) continue; try { out.push(JSON.parse(line)); } catch {} } return out; };

export async function loadInputs(days = 30, now = Date.now()) {
  const sinceDay = iso(now - days * DAY).slice(0, 10), ud = join(DATA, "usage"), ld = join(DATA, "leads"), rd = join(DATA, "runs");
  const usage = existsSync(ud) ? readdirSync(ud).filter((f) => /^\d{4}-\d{2}\.jsonl$/.test(f) && f.slice(0, 7) >= sinceDay.slice(0, 7)).sort().flatMap((f) => jsonl(join(ud, f))) : [];
  const leads = existsSync(ld) ? readdirSync(ld).filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f) && f.slice(0, 10) >= sinceDay).sort().flatMap((f) => jsonl(join(ld, f))).filter((l) => l && l.url && l.seen_at) : [];
  const logs = [], jobruns = [], closures = [], byRule = new Set(), writerLogs = [];
  for (const d of existsSync(rd) ? readdirSync(rd).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d) && d >= sinceDay).sort() : []) {
    for (const f of readdirSync(join(rd, d))) {
      if (f === "jobruns.jsonl") { jobruns.push(...jsonl(join(rd, d, f))); continue; }
      if (f === "closures.jsonl") { closures.push(...jsonl(join(rd, d, f))); continue; }
      const m = f.match(/^(\d{2})(\d{2})-(.+)\.json$/); if (!m) continue;
      const r = readJson(join(rd, d, f), null); if (!r || typeof r !== "object") continue;
      const at = /^\d{4}-\d{2}-\d{2}T/.test(String(r.finished_at || "")) ? r.finished_at : `${d}T${m[1]}:${m[2]}:00Z`;
      logs.push({ at, start: String(r.started_at || ""), file: `${d}T${m[1]}:${m[2]}:00Z`, job: m[3], model: r.model === undefined ? undefined : r.model, out: logOutput(r) });
      if (Array.isArray(r.added) || Array.isArray(r.updated) || Array.isArray(r.events_updated)) writerLogs.push({ at, job: m[3], model: r.model, worker_role: r.worker_role, worker_model: r.worker_model, added: r.added, updated: r.updated, events_updated: r.events_updated });
      // fuse's stories closed by a rule or a triager, logged as "story <id>: <why>": their grouping is fuse's own
      const rule = m[3] === "backlog-auto" || (m[3] === "triage" && r.model === null), groups = new Map();
      for (const s of Array.isArray(r.skipped) ? r.skipped : []) {
        if (!s || !s.url) continue;
        if (rule) byRule.add(s.url);
        const sm = String(s.reason || "").match(/^story ([0-9a-f]{6,12}): (.*)$/);
        if (sm) { const g = groups.get(sm[1]) || groups.set(sm[1], { at, story: sm[1], reason: sm[2], urls: [], rule }).get(sm[1]); g.urls.push(s.url); }
      }
      closures.push(...groups.values());
    }
  }
  writerLogs.logStart = firstRunLogAt();
  const events = listEventFiles().map((f) => f.e).filter(Boolean);
  const registry = (readJson(join(ROOT, "routines.json"), { routines: [] }).routines || []).filter((r) => r && r.key);
  return { usage, leads, logs, writerLogs, jobruns, closures, byRule, events, registry, status: readJson(join(DATA, "status.json"), {}) || {}, osint: readJson(join(DATA, "osint.json"), {}) || {}, gridAudit: readJson(join(DATA, "grid", "audit.json"), null), leases: readJson(join(DATA, "leases.json"), {}) || {},
    retiredFeeds: (readJson(join(ROOT, "config", "feeds.json"), {}) || {}).retired || [], feedList: await feedList(),
    queries: ((readJson(join(ROOT, "config", "queries.json"), {}) || {}).queries || []).filter((q) => q && typeof q === "object").map((q) => ({ hl: q.hl, region: q.region })) };
}
// every RSS feed collected (scripts/collect.mjs activeFeeds), as {tier, lang, region}; none when it cannot be read
async function feedList() {
  try { const m = await import("./collect.mjs"); return m.activeFeeds(readJson(join(ROOT, "config", "feeds.json"), {}) || {}).map((f) => ({ tier: f.tier, lang: f.lang || "en", region: f.region || "" })); } catch { return []; }
}

/** Pure: how many days a list of timestamps really covers before now (never more than `max`). */
export function spanDays(times, max, now = Date.now()) {
  const t = Math.min(...times.map((x) => Date.parse(x)).filter(isFinite));
  return isFinite(t) ? Math.min(max, days1(now - t)) : 0;
}

/** Pure: the whole report from loaded inputs. speed comes from scripts/lib/latency.mjs (passed in, so tests need no files). */
export function report(inp, { now = Date.now(), days = 7, speed = null, windows = null, clusterFn } = {}) {
  const since = now - days * DAY;
  const leadsWin = inp.leads.filter((l) => Date.parse(l.seen_at) >= since);
  const grouped = {}, used = storyCredit(inp.leads, inp.events, inp.closures, clusterFn, grouped);
  const covered = { leads: spanDays(inp.leads.map((l) => l.seen_at), days, now), usage: spanDays(inp.usage.map((u) => u.at), days, now), runs: spanDays(inp.logs.map((l) => l.at).concat(inp.jobruns.map((j) => j.started_at)), days, now) };
  const routines = routineReport(inp.registry, inp.usage, inp.logs, inp.jobruns, inp.status, since, now, inp.leads);
  // the research loop's idle cycles that left no record of their own count as runs of the sweep, and idle ones
  const loop = loopCycles(inp.jobruns, since, inp.leases || {}), sw = routines.find((r) => r.key === "sweep");
  if (sw && loop.idle_unrecorded) { sw.runs = num(sw.runs) + loop.idle_unrecorded; sw.idle = num(sw.idle) + loop.idle_unrecorded; sw.idle_pct = sw.runs ? Math.round((sw.idle / sw.runs) * 100) : null; }
  // feeds are judged over everything on file (up to 30 days), so "days since last useful" can reach the 14-day test
  const feeds = markRetired(feedReport(inp.leads, used, inp.byRule, inp.osint, now), inp.retiredFeeds);
  const feeds7 = feedReport(leadsWin, used, inp.byRule, {}, now), f7 = new Map(feeds7.map((f) => [f.name, f]));
  feeds.forEach((f) => { const x = f7.get(f.name); f.leads_7d = x ? x.leads : 0; f.used_7d = x ? x.used : 0; });
  const leadByUrl = new Map(); for (const l of inp.leads) if (!leadByUrl.has(l.url)) leadByUrl.set(l.url, l);
  const acc = accuracy(inp.events, now, days);
  // what the second review corrects, by type and by who wrote the event (role and model), for the improver and the owner
  try { const er = errorReport(inp.events, writersFrom(inp.writerLogs || []), now, days); acc.errors = { pre_logging: er.pre_logging, types: er.types.map((t) => ({ key: t.key, label: t.label, n: t.n, pct_of_corrected: t.pct_of_corrected })), by_writer: er.by_writer.slice(0, 12).map((b) => ({ role: b.role, model: b.model, reviewed: b.reviewed, corrected: b.corrected, corrected_pct: b.corrected_pct, types: b.types })) }; }
  catch (err) { acc.errors = { error: "The correction types could not be worked out: " + String((err && err.message) || err).slice(0, 160) }; }
  const win = windows || { source: "data/usage", estimate: true, five_hour: sumWindow(inp.usage, now, 5), week: sumWindow(inp.usage, now, 168), budget: null };
  const allLeadDays = spanDays(inp.leads.map((l) => l.seen_at), 3650, now);
  const grid = inp.gridAudit && inp.gridAudit.sources ? Object.entries(inp.gridAudit.sources).slice(0, 80).map(([k, v]) => ({ name: String((v && v.name) || k).slice(0, 60), ok: !!(v && v.ok), flags: Array.isArray(v && v.flags) ? v.flags.filter((x) => typeof x === "string").slice(0, 6) : [] })) : [];
  const ev7 = inp.events.filter((e) => !e.duplicate_of && Date.parse(e.first_seen) >= since);
  return {
    at: iso(now), days, covered,
    note: `Windows are ${days} days but hold only the data that exists: leads ${covered.leads} days, worker usage ${covered.usage} days, run logs ${covered.runs} days.`,
    totals: { leads: leadsWin.length, leads_used: leadsWin.filter((l) => used.has(l.url)).length, leads_by_rule: leadsWin.filter((l) => !used.has(l.url) && inp.byRule.has(l.url)).length, events: ev7.length,
      closed: { stories: routines.reduce((s, r) => s + r.closed_stories, 0), leads: routines.reduce((s, r) => s + r.closed_leads, 0) },
      tokens: routines.reduce((s, r) => s + num(r.tokens), 0), cost: Math.round(routines.reduce((s, r) => s + num(r.cost), 0) * 100) / 100 },
    targets: targets({ speed, acc, windows: win, routines, feeds, days: allLeadDays, loop }),
    windows: win, loop, speed, accuracy: acc, routines, feeds: feeds.filter((f) => !f.retired).slice(0, 300), grid,
    // the status page's "How the data flows" and "Where the data comes from"; a failure here leaves a note, never a broken report
    flow: (() => { try { return { lead_days: allLeadDays, sources: sourceSummary(inp.feedList || [], inp.queries || [], inp.osint, inp.status), d1: flowWindow(inp, grouped.storyOf, 24, now), d7: flowWindow(inp, grouped.storyOf, days * 24, now) }; } catch (err) { return { error: "The flow figures could not be worked out: " + String((err && err.message) || err).slice(0, 160) }; } })(),
    sources: (() => { try { return sourcesReport(inp.events, inp.leads, inp.closures, since); } catch (err) { return { error: "The source breakdown could not be worked out: " + String((err && err.message) || err).slice(0, 160) }; } })(),
    retired_feeds: feeds.filter((f) => f.retired).slice(0, 40).map((f) => ({ name: f.name, leads: f.leads, used: f.used, last_lead: f.last_lead, retired_at: f.retired_at, why: f.retired_why })),
    coverage: { d7: coverage(inp.events, leadByUrl, 7, now), d30: coverage(inp.events, leadByUrl, 30, now), events_from: inp.events.map((e) => e.first_seen).filter((t) => isFinite(Date.parse(t))).sort()[0] || null,
      // how many of the 30 days the event files really hold (first_seen), so the page never shows a 2-day count as a 30-day one
      days_of_data: spanDays(inp.events.map((e) => e.first_seen).filter((t) => isFinite(Date.parse(t))), 30, now) },
    gaps: ["Jobs run as subagents in the ops session write no data/usage line: their usage is unknown and shown as \"usage not logged\", never as zero.",
      "Cost is the API-equivalent price data/usage records; on the Max plan the limit is the usage window, not money.",
      "Second reviews run both inside the research loop and in the hourly review desk; their run logs are counted under review, their usage under the job that started them.",
      "A lead counts as used when the story it was fused into became or updated an event; stories larger than 30 leads are credited lead by lead."],
  };
}

/** Pure: how the workers of the window ended, from data/usage lines: finished, reached their turn cap (`capped`), were
 *  refused by the plan's usage limit (`limit`), or failed otherwise. */
export function workerEnds(usage, since, now = Date.now()) {
  const out = { runs: 0, ok: 0, capped: 0, usage_limit: 0, failed: 0, last_limit_at: null, last_limit_until: null };
  for (const u of usage || []) {
    const t = Date.parse(u && u.at); if (!isFinite(t) || t < since || t > now + 6e4) continue;
    out.runs++;
    if (u.ok) out.ok++; else if (u.capped) out.capped++;
    else if (u.limit || /hit your (?:usage )?limit|usage limit|(?:5-hour|weekly|session) limit/i.test(String(u.error || ""))) { out.usage_limit++; if (!out.last_limit_at || u.at > out.last_limit_at) { out.last_limit_at = u.at; out.last_limit_until = u.limit_until || null; } }
    else out.failed++;
  }
  return out;
}
/** Pure: the API-key fallback telemetry for the status page (scripts/lib/usage.mjs). The subscription is primary; the
 *  Anthropic API bills only while the subscription window is exhausted. cycles_on_fallback is the number of worker lines
 *  that ran on the API key, est_usd_this_month their estimated API-list cost this calendar month, last_fallback_at the most
 *  recent one. The key value is never read or shown; only the dials and the ledger's `served` marks are used. */
export function apiFallbackReport(usage, cfg = fallbackConfig(budgetConfig()), now = Date.now()) {
  const fb = cfg || { enabled: true, monthly_usd_cap: 150 }, spend = fallbackSpend(usage || [], now);
  return { enabled: fb.enabled !== false, monthly_usd_cap: num(fb.monthly_usd_cap), month: spend.month,
    cycles_on_fallback: spend.workers, est_usd_this_month: spend.usd, last_fallback_at: spend.last_at,
    cap_reached: num(fb.monthly_usd_cap) > 0 && spend.usd >= num(fb.monthly_usd_cap) };
}
/** What the no-result gates hold back right now (scripts/lib/gates.mjs): for each desk, what is due and what is skipped
 *  because nothing is new since its last look, with the time the next one is due. Skipped is never dropped: every item
 *  stays in its queue. A desk that cannot be read leaves an `error`, never a broken report. */
export async function gateSummary(now = Date.now()) {
  const out = { note: "Skipped means: nothing new since the item's last check, so no worker is started for it; it is due again at the time shown, or at once when something new arrives." };
  const part = async (key, fn) => { try { out[key] = await fn(); } catch (err) { out[key] = { error: String((err && err.message) || err).slice(0, 160) }; } };
  await part("followup", async () => (await import("./followup-desk.mjs")).stats(now));
  await part("claims", async () => { const m = await import("./claims-desk.mjs"), d = m.load(now), hb = m.heldBack(d.items, d.checks, {}, now, d.cfg); return { due: m.queue(d.items, d.checks, {}, now, d.cfg).length, skipped: hb.waiting.length, final_until_new_report: hb.final, next_due_at: hb.next_due_at }; });
  await part("outage", async () => { const m = await import("./outage-desk.mjs"), d = m.load(now), hb = m.heldBack(d.lists, d.checks, {}, now, d.cfg); return { due: m.queue(d.lists, d.checks, {}, now, d.cfg).length, skipped: hb.waiting.length, next_due_at: hb.next_due_at }; });
  await part("updater", async () => { const m = await import("./updates.mjs"), kept = m.current(), red = m.redirectOnly(m.current({ redirects: true }), kept); return { due: kept.length, skipped_redirect_only: red.events }; });
  await part("gap", async () => {
    const g = await import("./lib/gates.mjs"), dir = join(DATA, "runs"), runs = [];
    if (existsSync(dir)) for (const d of readdirSync(dir).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort().slice(-4)) for (const f of readdirSync(join(dir, d)).filter((f) => /^\d{4}-sweep-gap(-\d+)?\.json$/.test(f))) { const r = readJson(join(dir, d, f), null); if (r) runs.push({ at: r.finished_at || r.started_at, added: (r.added || []).length, updated: (r.updated || []).length }); }
    const dry = g.gapDryRun(runs), sc = (readJson(join(ROOT, "config", "pipeline.json"), {}) || {}).sweep || {};
    return { runs_in_a_row_without_an_event: dry, every_minutes: g.gapEveryMinutes(dry, sc), base_every_minutes: g.gapEveryMinutes(0, sc) };
  });
  return out;
}
export async function build(days = 7, now = Date.now()) {
  const inp = await loadInputs(30, now);
  let speed = null; try { speed = speedOf(Math.max(1, Math.round(Math.min(days * 24, spanDays(inp.leads.map((l) => l.seen_at), days, now) * 24 || 24))), now); } catch {}
  const windows = await usageWindows(inp.usage, now);
  const r = report(inp, { now, days, speed, windows });
  r.gates = await gateSummary(now);
  r.worker_ends = workerEnds(inp.usage, now - days * DAY, now);
  try { r.api_fallback = apiFallbackReport(inp.usage, fallbackConfig(budgetConfig()), now); } catch {}
  return r;
}

/* ---------------- CLI ---------------- */

function wasteful(r) {
  const routines = r.routines.filter((x) => x.runs || x.tokens).sort((a, b) => num(b.idle_tokens) - num(a.idle_tokens) || num(b.idle) - num(a.idle)).slice(0, 5);
  // ranked on leads after each feed's first day (the backlog dump), so a feed that is now quiet is not blamed; a feed with none is quiet, not wasteful
  const feeds = r.feeds.filter((f) => f.verdict !== "useful" && num(f.leads_after_first_day) > 0).sort((a, b) => num(b.leads_after_first_day) - num(a.leads_after_first_day) || b.leads - a.leads).slice(0, 5);
  return { routines, feeds };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const i = process.argv.indexOf("--days"), days = i > 0 ? Math.max(1, Math.min(30, Number(process.argv[i + 1]) || 7)) : 7;
  const r = await build(days);
  if (process.argv.includes("--json")) { console.log(JSON.stringify(r)); process.exit(0); }
  console.log(`EFFICIENCY (${r.at}). ${r.note}`);
  for (const t of r.targets) console.log(`  [${t.state.toUpperCase().padEnd(7)}] ${t.target}: ${t.value}${t.note ? ` (${t.note})` : ""}`);
  console.log(`Usage (${r.windows.estimate ? "estimate from data/usage" : "from lib/usage.mjs"}): 5 h ${r.windows.five_hour.tokens.toLocaleString("en")} tokens in ${r.windows.five_hour.runs} worker runs; 7 days ${r.windows.week.tokens.toLocaleString("en")} tokens, $${r.windows.week.cost}.`);
  console.log(`Leads (${r.covered.leads} days): ${r.totals.leads}, ${r.totals.leads_used} used by story, ${r.totals.leads_by_rule} closed by rule; ${r.totals.events} events.`);
  console.log("Routines (runs, idle %, tokens, output added/updated/reviewed/closed, usage):");
  for (const x of r.routines.filter((x) => x.runs || x.tokens || x.active)) console.log(`  ${x.key.padEnd(15)} ${String(x.runs).padStart(4)} ${String(x.idle_pct ?? "-").padStart(4)}% ${String(x.tokens ?? "-").padStart(12)} ${x.added}/${x.updated}/${x.reviewed}/${x.closed} ${x.closed_unit}  ${x.usage}${x.runs_basis ? " (runs from heartbeat)" : ""}`);
  console.log(`Closed, by unit (not additive): ${r.totals.closed.stories} stories, ${r.totals.closed.leads} leads.`);
  const w = wasteful(r);
  console.log("Most wasteful routines: " + w.routines.map((x) => `${x.key} (${x.idle}/${x.runs} runs idle, ${num(x.idle_tokens).toLocaleString("en")} of ${num(x.tokens).toLocaleString("en")} tokens spent in idle runs)`).join("; "));
  console.log("Most wasteful feeds: " + w.feeds.map((f) => `${f.name} (${f.leads_after_first_day} leads after day one, ${f.leads} in all, 0 used, ${f.by_rule} closed by rule)`).join("; ") + " [each feed's first day, its backlog dump, is left out of the ranking]");
  console.log("Coverage, 7 days by region: " + Object.entries(r.coverage.d7.region).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", "));
  console.log("  by language: " + Object.entries(r.coverage.d7.language).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", "));
  console.log("  by sector: " + Object.entries(r.coverage.d7.sector).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", "));
  if (r.accuracy.errors && r.accuracy.errors.types) console.log("Correction types: " + r.accuracy.errors.types.map((t) => `${t.key} ${t.n}`).join(", ") + "; by writer: " + (r.accuracy.errors.by_writer || []).map((b) => `${b.role}/${b.model} ${b.corrected}/${b.reviewed}`).join(", ") + (r.accuracy.errors.pre_logging ? `; before the first run log (writer unknowable, left out of the table): ${r.accuracy.errors.pre_logging.corrected}/${r.accuracy.errors.pre_logging.reviewed}` : ""));
  console.log("Corrections by week: " + r.accuracy.weeks.map((x) => `${x.week} ${x.corrected_pct}% of ${x.reviewed}`).join("; ") + (r.accuracy.categories.length ? "; categories: " + r.accuracy.categories.map((c) => `${c.name} ${c.n}`).join(", ") : ""));
  if (r.gates) console.log("Gates (due / skipped: nothing new since the last check): " + ["followup", "claims", "outage", "updater"].map((k) => { const g = r.gates[k] || {}; return g.error ? `${k} ?` : `${k} ${g.due}/${g.skipped ?? g.skipped_redirect_only ?? 0}${g.next_due_at ? ` (next due ${String(g.next_due_at).slice(5, 16).replace("T", " ")})` : ""}`; }).join("; ") + (r.gates.gap && !r.gates.gap.error ? `; gap pass every ${r.gates.gap.every_minutes} min (${r.gates.gap.runs_in_a_row_without_an_event} run(s) in a row added nothing)` : ""));
  if (r.worker_ends) console.log(`Workers (${r.days} days): ${r.worker_ends.ok} of ${r.worker_ends.runs} finished, ${r.worker_ends.capped} reached their turn cap, ${r.worker_ends.usage_limit} refused by the usage limit${r.worker_ends.last_limit_at ? ` (last ${r.worker_ends.last_limit_at}${r.worker_ends.last_limit_until ? ", reset " + r.worker_ends.last_limit_until : ""})` : ""}, ${r.worker_ends.failed} failed otherwise.`);
  if (r.api_fallback) console.log(`API fallback: ${r.api_fallback.enabled ? "enabled" : "disabled"}, cap $${r.api_fallback.monthly_usd_cap}/month; ${r.api_fallback.cycles_on_fallback} worker line(s) on the API this month, est $${r.api_fallback.est_usd_this_month}${r.api_fallback.last_fallback_at ? ", last " + r.api_fallback.last_fallback_at : ""}${r.api_fallback.cap_reached ? " — CAP REACHED" : ""}.`);
  r.gaps.forEach((g) => console.log("Gap: " + g));
}
