// Plan usage, read from the headless workers' ledger (data/usage/<YYYY-MM>.jsonl, one line per worker, written by
// scripts/run-job.mjs: at, job, role, batch, model, ms, ok, turns, cost, in, out, cache_read, cache_write, error, last).
// No AI model, no network.
// CyberView runs on a Max plan: no dollar limit, but a 5-hour and a weekly usage window, and running out of either stalls
// the research loop (the worst outcome). The plan does not publish its limits, so the budget is twofold:
//   - estimates in config/pipeline.json usage_budget (window_tokens, week_tokens, window_cost, week_cost), derived from
//     the observed peaks x 1.5; the loop slows down ("tight") as usage nears them
//   - real limit hits: a worker that failed with a rate-limit or usage-limit error means the plan said no; the loop then
//     starts no workers ("stop") until the reset time the error gives, else for limit_backoff_minutes (60)
// The ledger only counts headless workers: the ops session and interactive sessions use the same plan and are not in it,
// which is one more reason the estimates keep a margin.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, ROOT, readJson } from "./store.mjs";

const HOUR = 36e5;
const iso = (t) => new Date(t).toISOString().replace(/\.\d+Z$/, "Z");

/** The ledger lines of every month that overlaps [from, to]. Never throws (a missing or broken line is skipped). */
export function readUsage(from, to = Date.now(), dir = join(DATA, "usage")) {
  const months = new Set(); for (let t = Date.UTC(new Date(from).getUTCFullYear(), new Date(from).getUTCMonth(), 1); t <= to; t = Date.UTC(new Date(t).getUTCFullYear(), new Date(t).getUTCMonth() + 1, 1)) months.add(iso(t).slice(0, 7));
  const out = [];
  for (const m of months) {
    let txt = ""; try { txt = readFileSync(join(dir, `${m}.jsonl`), "utf8"); } catch { continue; }
    for (const l of txt.split("\n")) { if (!l.trim()) continue; try { const j = JSON.parse(l); if (j && typeof j.at === "string") out.push(j); } catch {} }
  }
  return out;
}
/** Pure: totals of the lines whose `at` lies in (from, to]. */
export function sumUsage(lines, from, to) {
  const r = { from: iso(from), to: iso(to), runs: 0, tokens: 0, in: 0, out: 0, cache_read: 0, cache_write: 0, cost: 0 };
  for (const l of lines || []) {
    const t = Date.parse(l.at); if (!(t > from && t <= to)) continue;
    r.runs++; for (const k of ["in", "out", "cache_read", "cache_write"]) r[k] += Number(l[k]) || 0;
    r.cost += Number(l.cost) || 0;
  }
  r.tokens = r.in + r.out + r.cache_read + r.cache_write; r.cost = +r.cost.toFixed(4);
  return r;
}
/** Usage in the `hours` before now: { from, to, runs, tokens, in, out, cache_read, cache_write, cost }. lines: optional ledger lines (tests). */
export function windowUsage(now = Date.now(), hours = 5, lines = null) {
  const from = now - hours * HOUR;
  return sumUsage(lines || readUsage(from, now), from, now);
}
/** Usage in the 7 days before now, same shape. */
export function weekUsage(now = Date.now(), lines = null) { return windowUsage(now, 24 * 7, lines); }

// What the claude CLI and the API say when the plan or the rate limit says no. Matched only on workers that FAILED, so a
// researcher whose last line mentions a website's "429" never stops the loop. "overloaded" (529) is not a limit.
export const LIMIT_RE = /usage limit|rate[ _-]?limit|limit reached|hit your (?:usage )?limit|\b429\b|too many requests|out of (?:extra )?usage|(?:5-hour|weekly|session) limit/i;
const DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
/** UTC offset in ms of an IANA zone at time t (0 when the zone is unknown). */
function zoneOffset(zone, t) {
  try {
    const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: zone, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).formatToParts(new Date(t)).map((x) => [x.type, x.value]));
    return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour % 24, +p.minute, +p.second) - Math.floor(t / 1000) * 1000;
  } catch { return null; }
}
/** Pure: the reset time an error text gives, as ms, or null. Understands "…|1763650800" (unix seconds), an ISO time, and
 *  "resets 3pm", "resets at 3:30 pm (Europe/London)", "resets Mon 9am (UTC)". A clock time is the next one after `at`. */
export function resetFrom(text, at) {
  const s = String(text || "");
  const unix = /\|\s*(\d{10})\b/.exec(s); if (unix) return +unix[1] * 1000;
  const isoT = /\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))/.exec(s); if (isoT && isFinite(Date.parse(isoT[1]))) return Date.parse(isoT[1]);
  const m = /resets?\s+(?:at\s+|on\s+)?(?:(sun|mon|tue|wed|thu|fri|sat)[a-z]*\.?,?\s+(?:at\s+)?)?(\d{1,2})(?::(\d{2}))?\s*(am|pm)?(?:\s*\(([^)]+)\))?/i.exec(s);
  if (!m) return null;
  let h = +m[2]; const min = +(m[3] || 0), ap = (m[4] || "").toLowerCase();
  if (ap === "pm" && h < 12) h += 12; if (ap === "am" && h === 12) h = 0;
  if (h > 23 || min > 59) return null;
  const zone = m[5] && !/^utc$|^gmt$/i.test(m[5].trim()) ? m[5].trim() : "UTC", off = zone === "UTC" ? 0 : zoneOffset(zone, at);
  if (off === null) return null;
  const local = at + off, d = new Date(local);
  let t = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), h, min) - off;
  if (m[1]) { const want = DAYS.indexOf(m[1].toLowerCase().slice(0, 3)); while (new Date(t + off).getUTCDay() !== want || t <= at) t += 24 * HOUR; }
  else while (t <= at) t += 24 * HOUR;
  return t;
}
/** Pure: the limit hits in the ledger: [{ at, until, text }] (until = the reset time, else at + backoff). */
export function limitHits(lines, backoffMin = 60) {
  const out = [];
  for (const l of lines || []) {
    if (l.ok || !l.error || !LIMIT_RE.test(String(l.error))) continue;
    const at = Date.parse(l.at); if (!isFinite(at)) continue;
    const r = resetFrom(l.error, at), until = r && r > at && r - at <= 8 * 24 * HOUR ? r : at + backoffMin * 6e4;
    out.push({ at, until, text: String(l.error).slice(0, 160) });
  }
  return out;
}
export const DEFAULT_BUDGET = { window_hours: 5, window_tokens: 0, week_tokens: 0, window_cost: 0, week_cost: 0, tight_pct: 80, stop_pct: 120, limit_backoff_minutes: 60, pipeline_reserve_pct: 35 };
export function budgetConfig() { return { ...DEFAULT_BUDGET, ...((readJson(join(ROOT, "config", "pipeline.json"), {}) || {}).usage_budget || {}) }; }
const pct = (used, cap) => (Number(cap) > 0 ? Math.round((used / cap) * 1000) / 10 : 0);
/** Where the plan's usage stands: { window_pct, week_pct, level: "ok"|"tight"|"stop", limited_until, reason, window, week }.
 *  pct: the larger of the token and cost shares of the estimate (0 when no estimate is set).
 *  stop:  a worker hit a real limit and its reset time has not come (limited_until), or the 5-hour window passed stop_pct
 *         of its estimate (the estimate is 1.5 x the observed peak, so 120% of it is far past anything seen without a limit).
 *         The weekly estimate never stops the loop on its own: a stop there would idle research for days on a guess.
 *  tight: either window at or above tight_pct of its estimate, or a real limit hit inside the last window (recovering).
 *  lines: optional ledger lines (tests); read from data/usage otherwise. */
export function budgetState(now = Date.now(), cfg = budgetConfig(), lines = null) {
  const c = { ...DEFAULT_BUDGET, ...(cfg || {}) }, wh = Math.max(1, Number(c.window_hours) || 5);
  const L = lines || readUsage(now - 7 * 24 * HOUR, now);
  const w = windowUsage(now, wh, L), k = weekUsage(now, L);
  const window_pct = Math.max(pct(w.tokens, c.window_tokens), pct(w.cost, c.window_cost)), week_pct = Math.max(pct(k.tokens, c.week_tokens), pct(k.cost, c.week_cost));
  const hits = limitHits(L.filter((l) => Date.parse(l.at) <= now), Number(c.limit_backoff_minutes) || 60), live = hits.filter((h) => h.until > now).sort((a, b) => b.until - a.until)[0];
  const recent = hits.some((h) => h.at > now - wh * HOUR);
  const tight = Number(c.tight_pct) || 80, stop = Number(c.stop_pct) || 120;
  let level = "ok", reason = "";
  if (live) { level = "stop"; reason = `a worker hit the plan's limit at ${iso(live.at)}: ${live.text}`; }
  else if (window_pct >= stop) { level = "stop"; reason = `5-hour usage at ${window_pct}% of the estimate (stop at ${stop}%)`; }
  else if (window_pct >= tight || week_pct >= tight) { level = "tight"; reason = `usage at ${window_pct}% of the 5-hour and ${week_pct}% of the weekly estimate (tight at ${tight}%)`; }
  else if (recent) { level = "tight"; reason = "recovering from a limit hit inside the last window"; }
  // a stop on the window estimate lasts until enough of the window's oldest usage has rolled out; the loop rechecks every cycle
  return { window_pct, week_pct, level, limited_until: live ? iso(live.until) : null, reason, window: w, week: k };
}
/** Pure: may work that is NOT the pipeline (a code build, a swarm of build agents) start more agents now?
 *  The 5-hour window is shared by everything on the plan. On 2026-11-22 a code-build swarm used all of it and the pipeline
 *  published nothing for 2.5 hours, so usage_budget.pipeline_reserve_pct (35) of the window estimate is kept for the
 *  pipeline: other work may run only while the window stands at or under (100 - reserve)% of the estimate, and not at all
 *  for an hour after the plan refused a pipeline worker (or until the reset time it gave, when that is later).
 *  lines: the pipeline's ledger (data/usage); buildLines: what build work recorded of its own usage with
 *  `node scripts/budget.mjs spent` (same line shape; a local file, never in data/). Build agents that record nothing are
 *  invisible here, which is why the real-limit rule exists.
 *  -> { ok, reason, window_pct, pipeline_pct, build_pct, ceiling_pct, reserve_pct, limited_until, level } */
export function canBuild(now = Date.now(), cfg = budgetConfig(), lines = null, buildLines = []) {
  const c = { ...DEFAULT_BUDGET, ...(cfg || {}) }, wh = Math.max(1, Number(c.window_hours) || 5);
  const r = Number(c.pipeline_reserve_pct), reserve = Math.max(0, Math.min(90, Number.isFinite(r) ? r : 35)), ceiling = 100 - reserve;
  const L = lines || readUsage(now - 7 * 24 * HOUR, now), b = budgetState(now, c, L);
  const bu = sumUsage(buildLines || [], now - wh * HOUR, now);
  const window_pct = Math.max(pct(b.window.tokens + bu.tokens, c.window_tokens), pct(b.window.cost + bu.cost, c.window_cost));
  const build_pct = Math.max(pct(bu.tokens, c.window_tokens), pct(bu.cost, c.window_cost));
  const hits = limitHits(L.filter((l) => Date.parse(l.at) <= now), Number(c.limit_backoff_minutes) || 60);
  const hit = hits.filter((h) => h.until > now || h.at > now - HOUR).sort((x, y) => y.at - x.at)[0];
  const until = hit ? Math.max(hit.until, hit.at + HOUR) : 0;
  let ok = true, reason = `the 5-hour window stands at ${window_pct}% of the estimate (pipeline ${b.window_pct}%, build work ${build_pct}%); build work may run up to ${ceiling}% (${reserve}% is kept for the pipeline)`;
  if (hit) { ok = false; reason = `usage limit reached: the plan refused a pipeline worker at ${iso(hit.at)} (${hit.text}); no build work until ${iso(until)}`; }
  else if (window_pct > ceiling) { ok = false; reason = `the 5-hour window stands at ${window_pct}% of the estimate (pipeline ${b.window_pct}%, build work ${build_pct}%), above the ${ceiling}% that build work may use (${reserve}% is kept for the pipeline)`; }
  return { ok, reason, window_pct, pipeline_pct: b.window_pct, build_pct, ceiling_pct: ceiling, reserve_pct: reserve, limited_until: hit ? iso(until) : null, level: b.level };
}
/** Pure: does the "tight" level cut work? Owner, 2026-11-21: "use whatever it needs"; only the stop level holds work back.
 *  usage_budget.tight_cuts_work (default false) restores the old tight behaviour (fewer workers, tight_skip_jobs wait). */
export const tightCuts = (cfg = budgetConfig()) => !!(cfg && cfg.tight_cuts_work === true);
/** One line for logs and the loop's heartbeat. */
export const budgetLine = (b) => `budget ${b.level}: 5 h ${b.window_pct}%, week ${b.week_pct}%${b.limited_until ? `, limited until ${b.limited_until}` : ""}${b.reason ? ` (${b.reason})` : ""}`;
/** Pure: the highest usage in any rolling `hours` within lines: { tokens, cost, at } (at: the end of that span). */
export function peakUsage(lines, hours) {
  const L = (lines || []).map((l) => ({ t: Date.parse(l.at), tok: (Number(l.in) || 0) + (Number(l.out) || 0) + (Number(l.cache_read) || 0) + (Number(l.cache_write) || 0), cost: Number(l.cost) || 0 })).filter((x) => isFinite(x.t)).sort((a, b) => a.t - b.t);
  const best = { tokens: 0, cost: 0, at: null }; let j = 0, tok = 0, cost = 0;
  for (const x of L) {
    tok += x.tok; cost += x.cost;
    while (L[j].t <= x.t - hours * HOUR) { tok -= L[j].tok; cost -= L[j].cost; j++; }
    if (tok > best.tokens) { best.tokens = tok; best.at = iso(x.t); }
    if (cost > best.cost) best.cost = +cost.toFixed(2);
  }
  return best;
}
// node scripts/lib/usage.mjs   prints the level now and the peaks the estimates in config/pipeline.json usage_budget come from
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const now = Date.now(), L = readUsage(now - 35 * 24 * HOUR, now), b = budgetState(now, budgetConfig(), L.filter((l) => Date.parse(l.at) > now - 7 * 24 * HOUR));
  console.log(budgetLine(b));
  console.log(`last 5 h: ${b.window.runs} worker(s), ${(b.window.tokens / 1e6).toFixed(1)} M tokens, $${b.window.cost}; last 7 days: ${b.week.runs} worker(s), ${(b.week.tokens / 1e6).toFixed(1)} M tokens, $${b.week.cost}`);
  for (const h of [5, 24, 168]) { const p = peakUsage(L, h); console.log(`peak rolling ${h} h (last 35 days): ${(p.tokens / 1e6).toFixed(1)} M tokens (ending ${p.at || "-"}), $${p.cost}`); }
}
