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
import { regionOf, storyCredit, RETIRED_COLLECTORS } from "./metrics.mjs";
import { measure as speedOf } from "./lib/latency.mjs";

// routines whose work is a document or a check, not a list in a run log: their idle share is not measured
export const DOC_ROUTINES = new Set(["brief", "analysis", "tabletop", "improver", "watchdog", "guardian", "editor", "security-review", "monitor", "link-check", "security-check", "exploit-watch"]);
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
  const keys = new Set(registry.map((r) => r.key)), rows = new Map();
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
  // the collectors write no run log: their output is the leads they filed (runs stay unknown)
  const filed = { collect: (l) => (l.via || "rss") === "rss", osint: (l) => !["rss", "cvelist"].includes(l.via || "rss"), cve: (l) => l.via === "cvelist" };
  for (const [k, f] of Object.entries(filed)) if (rows.has(k)) { const r = rows.get(k), mine = leads.filter((l) => Date.parse(l.seen_at) >= since && f(l)); r.filed = mine.length; r.added += mine.length; if (mine.length) { r.last_useful = mine.map((l) => l.seen_at).sort().pop(); if (!r.logs) r.runs = null; } }
  const workers = new Map(); for (const j of jobruns) if (inWin(j.started_at)) { const k = keys.has(j.job) ? j.job : routineOf(j.job, keys, undefined); workers.set(k, (workers.get(k) || 0) + num(j.workers)); }
  return [...rows.values()].map((r) => {
    // a headless job that started no worker used nothing: that is logged, not unknown
    const usage = r.tier !== "ai" ? "none (script)" : r.usage_lines ? (r.logs > r.usage_lines && !counted.has(r.key) ? "partly logged" : "logged") : counted.has(r.key) && !workers.get(r.key) ? "logged" : r.runs || r.last_run ? "not logged" : "no runs";
    if (usage === "logged" && !r.usage_lines) r.usage_lines = -1;
    const logged = r.usage_lines !== 0; if (r.usage_lines < 0) r.usage_lines = 0;
    return { ...r, tokens: logged ? r.tokens : null, cost: logged ? Math.round(r.cost * 100) / 100 : null, usage,
      idle_pct: r.runs && !DOC_ROUTINES.has(r.key) ? Math.round((r.idle / r.runs) * 100) : null, idle_tokens: logged && !DOC_ROUTINES.has(r.key) ? r.idle_tokens : null, output: r.added + r.updated + r.reviewed + r.closed,
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
  return [...rows.values()].map((r) => ({ ...r, yield: r.leads ? Math.round((r.used / r.leads) * 1000) / 10 : null,
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
/** Pure: the critical-infrastructure sector an event is in, from its sector field and tags (by keyword, can be wrong). */
export function sectorOf(e) {
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
  const out = { days, events: ev.length, claimed: ev.filter((e) => e.status === "claimed").length, region: {}, language: {}, sector: {} };
  for (const e of ev) { add(out.region, regionOf(e.country)); add(out.language, languageOf(e, leadByUrl)); add(out.sector, sectorOf(e)); }
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
    value: b && b.level ? `${b.window_pct ?? "?"}% of the estimated 5-hour window, ${b.week_pct ?? "?"}% of the estimated week (level ${b.level})${loop && loop.budget.stop ? `; ${loop.budget.stop} loop cycle(s) stopped for usage` : ""}` : `${windows.five_hour.tokens.toLocaleString("en")} tokens in the last 5 hours, ${windows.week.tokens.toLocaleString("en")} in 7 days (headless workers only; the plan's limits are not known here)`,
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

export function loadInputs(days = 30, now = Date.now()) {
  const sinceDay = iso(now - days * DAY).slice(0, 10), ud = join(DATA, "usage"), ld = join(DATA, "leads"), rd = join(DATA, "runs");
  const usage = existsSync(ud) ? readdirSync(ud).filter((f) => /^\d{4}-\d{2}\.jsonl$/.test(f) && f.slice(0, 7) >= sinceDay.slice(0, 7)).sort().flatMap((f) => jsonl(join(ud, f))) : [];
  const leads = existsSync(ld) ? readdirSync(ld).filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f) && f.slice(0, 10) >= sinceDay).sort().flatMap((f) => jsonl(join(ld, f))).filter((l) => l && l.url && l.seen_at) : [];
  const logs = [], jobruns = [], closures = [], byRule = new Set();
  for (const d of existsSync(rd) ? readdirSync(rd).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d) && d >= sinceDay).sort() : []) {
    for (const f of readdirSync(join(rd, d))) {
      if (f === "jobruns.jsonl") { jobruns.push(...jsonl(join(rd, d, f))); continue; }
      if (f === "closures.jsonl") { closures.push(...jsonl(join(rd, d, f))); continue; }
      const m = f.match(/^(\d{2})(\d{2})-(.+)\.json$/); if (!m) continue;
      const r = readJson(join(rd, d, f), null); if (!r || typeof r !== "object") continue;
      const at = /^\d{4}-\d{2}-\d{2}T/.test(String(r.finished_at || "")) ? r.finished_at : `${d}T${m[1]}:${m[2]}:00Z`;
      logs.push({ at, start: String(r.started_at || ""), file: `${d}T${m[1]}:${m[2]}:00Z`, job: m[3], model: r.model === undefined ? undefined : r.model, out: logOutput(r) });
      // fuse's stories closed by a rule or a triager, logged as "story <id>: <why>": their grouping is fuse's own
      const rule = m[3] === "backlog-auto" || (m[3] === "triage" && r.model === null), groups = new Map();
      for (const s of Array.isArray(r.skipped) ? r.skipped : []) {
        if (!s || !s.url) continue;
        if (rule) byRule.add(s.url);
        const sm = String(s.reason || "").match(/^story ([0-9a-f]{6,12}): (.*)$/);
        if (sm) { const g = groups.get(sm[1]) || groups.set(sm[1], { at, story: sm[1], reason: sm[2], urls: [] }).get(sm[1]); g.urls.push(s.url); }
      }
      closures.push(...groups.values());
    }
  }
  const events = listEventFiles().map((f) => f.e).filter(Boolean);
  const registry = (readJson(join(ROOT, "routines.json"), { routines: [] }).routines || []).filter((r) => r && r.key);
  return { usage, leads, logs, jobruns, closures, byRule, events, registry, status: readJson(join(DATA, "status.json"), {}) || {}, osint: readJson(join(DATA, "osint.json"), {}) || {}, gridAudit: readJson(join(DATA, "grid", "audit.json"), null), leases: readJson(join(DATA, "leases.json"), {}) || {},
    retiredFeeds: (readJson(join(ROOT, "config", "feeds.json"), {}) || {}).retired || [] };
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
  const used = storyCredit(inp.leads, inp.events, inp.closures, clusterFn);
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
  const win = windows || { source: "data/usage", estimate: true, five_hour: sumWindow(inp.usage, now, 5), week: sumWindow(inp.usage, now, 168), budget: null };
  const allLeadDays = spanDays(inp.leads.map((l) => l.seen_at), 3650, now);
  const grid = inp.gridAudit && inp.gridAudit.sources ? Object.entries(inp.gridAudit.sources).slice(0, 80).map(([k, v]) => ({ name: String((v && v.name) || k).slice(0, 60), ok: !!(v && v.ok), flags: Array.isArray(v && v.flags) ? v.flags.filter((x) => typeof x === "string").slice(0, 6) : [] })) : [];
  const ev7 = inp.events.filter((e) => !e.duplicate_of && Date.parse(e.first_seen) >= since);
  return {
    at: iso(now), days, covered,
    note: `Windows are ${days} days but hold only the data that exists: leads ${covered.leads} days, worker usage ${covered.usage} days, run logs ${covered.runs} days.`,
    totals: { leads: leadsWin.length, leads_used: leadsWin.filter((l) => used.has(l.url)).length, leads_by_rule: leadsWin.filter((l) => !used.has(l.url) && inp.byRule.has(l.url)).length, events: ev7.length,
      tokens: routines.reduce((s, r) => s + num(r.tokens), 0), cost: Math.round(routines.reduce((s, r) => s + num(r.cost), 0) * 100) / 100 },
    targets: targets({ speed, acc, windows: win, routines, feeds, days: allLeadDays, loop }),
    windows: win, loop, speed, accuracy: acc, routines, feeds: feeds.filter((f) => !f.retired).slice(0, 300), grid,
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

export async function build(days = 7, now = Date.now()) {
  const inp = loadInputs(30, now);
  let speed = null; try { speed = speedOf(Math.max(1, Math.round(Math.min(days * 24, spanDays(inp.leads.map((l) => l.seen_at), days, now) * 24 || 24))), now); } catch {}
  const windows = await usageWindows(inp.usage, now);
  return report(inp, { now, days, speed, windows });
}

/* ---------------- CLI ---------------- */

function wasteful(r) {
  const routines = r.routines.filter((x) => x.runs || x.tokens).sort((a, b) => num(b.idle_tokens) - num(a.idle_tokens) || num(b.idle) - num(a.idle)).slice(0, 5);
  const feeds = r.feeds.filter((f) => f.verdict !== "useful").sort((a, b) => b.leads - a.leads).slice(0, 5);
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
  for (const x of r.routines.filter((x) => x.runs || x.tokens || x.active)) console.log(`  ${x.key.padEnd(15)} ${String(x.runs).padStart(4)} ${String(x.idle_pct ?? "-").padStart(4)}% ${String(x.tokens ?? "-").padStart(12)} ${x.added}/${x.updated}/${x.reviewed}/${x.closed}  ${x.usage}`);
  const w = wasteful(r);
  console.log("Most wasteful routines: " + w.routines.map((x) => `${x.key} (${x.idle}/${x.runs} runs idle, ${num(x.idle_tokens).toLocaleString("en")} of ${num(x.tokens).toLocaleString("en")} tokens spent in idle runs)`).join("; "));
  console.log("Most wasteful feeds: " + w.feeds.map((f) => `${f.name} (${f.leads} leads, 0 used, ${f.by_rule} closed by rule)`).join("; "));
  console.log("Coverage, 7 days by region: " + Object.entries(r.coverage.d7.region).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", "));
  console.log("  by language: " + Object.entries(r.coverage.d7.language).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", "));
  console.log("  by sector: " + Object.entries(r.coverage.d7.sector).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", "));
  console.log("Corrections by week: " + r.accuracy.weeks.map((x) => `${x.week} ${x.corrected_pct}% of ${x.reviewed}`).join("; ") + (r.accuracy.categories.length ? "; categories: " + r.accuracy.categories.map((c) => `${c.name} ${c.n}`).join(", ") : ""));
  r.gaps.forEach((g) => console.log("Gap: " + g));
}
