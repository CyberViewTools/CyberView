// Continuous improvement: measure the pipeline, then let the improver job tune it within fixed bounds. No AI model here.
// Run: node scripts/improve.mjs <command>
//   report [--days 7]       what each role and job costs and yields, quality and speed; writes data/improve/latest.json
//   apply <proposal.json>   applies at most 3 bounded changes (config/pipeline.json, config/models.json) and logs each one
//                           with its reason in data/improve/changes.jsonl; anything out of bounds is refused, not clipped
//   history                 the changes made so far
// The improver job (docs/jobs.md, "Improver") reads the report, decides, and writes the proposal. This script enforces:
//   - one step per key per day (a number by at most a quarter or one unit, a model by one tier)
//   - quality guard: no cost-cutting change while second-review corrections+flags exceed 15% or the research queue is
//     over its limit
//   - min_tier in config/models.json: those roles never drop below their tier
import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, writeJson, listEventFiles, nowIso, dayAgo } from "./lib/store.mjs";
import { errorReport, writersFrom, loadRunLogs } from "./review.mjs";

const TIERS = ["haiku", "sonnet", "opus"];
/** Bounds for every key the improver may change: [min, max] for numbers. */
export const BOUNDS = {
  "pipeline.sweep.researchers": [1, 16], "pipeline.sweep.review_workers": [0, 8], "pipeline.sweep.stories_per_researcher": [4, 12], "pipeline.sweep.gap_workers": [0, 3],
  "pipeline.backlog.triagers": [1, 6], "pipeline.backlog.researchers": [1, 6], "pipeline.backlog.leave_for_sweep": [16, 96],
  "pipeline.analyst.workers": [1, 4], "pipeline.analyst.per_worker": [1, 5], "pipeline.review.reviewers": [1, 8], "pipeline.review.events_per_reviewer": [5, 15],
  "pipeline.max_parallel": [2, 12],
};
const getPath = (o, p) => p.split(".").reduce((x, k) => (x == null ? x : x[k]), o);
const setPath = (o, p, v) => { const ks = p.split("."); let x = o; ks.slice(0, -1).forEach((k) => { x[k] = x[k] && typeof x[k] === "object" ? x[k] : {}; x = x[k]; }); x[ks.at(-1)] = v; };

/** Pure: is this one change allowed? Returns "" or the reason it is refused. */
export function checkChange(c, cfg, models, guard, changedToday = new Set()) {
  if (!c || typeof c.key !== "string" || !c.reason || String(c.reason).length < 12) return "every change needs a key and a reason of a sentence";
  if (changedToday.has(c.key)) return `${c.key} was already changed today`;
  const m = c.key.match(/^models\.roles\.([a-z-]+)\.(model|max_turns)$/);
  if (m) {
    const role = models.roles[m[1]]; if (!role) return `no role ${m[1]}`;
    if (m[2] === "model") {
      const from = TIERS.indexOf(role.model), to = TIERS.indexOf(c.to); if (to < 0) return "model must be haiku, sonnet or opus";
      if (Math.abs(to - from) !== 1) return "a model moves one tier at a time";
      const min = TIERS.indexOf((models.min_tier || {})[m[1]] || "haiku"); if (to < min) return `${m[1]} never goes below ${models.min_tier[m[1]]}`;
      if (to < from && guard.blocked) return `quality guard: ${guard.why}`;
      return "";
    }
    const from = role.max_turns, to = Number(c.to); if (!Number.isInteger(to) || to < 10 || to > 80) return "max_turns must be 10 to 80";
    if (Math.abs(to - from) > Math.max(1, Math.ceil(from / 4))) return "max_turns moves by at most a quarter";
    if (to < from && guard.blocked) return `quality guard: ${guard.why}`;
    return "";
  }
  const b = BOUNDS[c.key]; if (!b) return `${c.key} is not a key the improver may change`;
  const from = Number(getPath(cfg, c.key.replace(/^pipeline\./, ""))), to = Number(c.to);
  if (!Number.isFinite(to) || to < b[0] || to > b[1]) return `${c.key} must be between ${b[0]} and ${b[1]}`;
  if (Number.isFinite(from) && Math.abs(to - from) > Math.max(1, Math.ceil(Math.abs(from) / 4))) return `${c.key} moves by at most a quarter or one`;
  if (Number.isFinite(from) && to < from && guard.blocked && !/leave_for_sweep/.test(c.key)) return `quality guard: ${guard.why}`;
  return "";
}

function readUsage(days) {
  const dir = join(DATA, "usage"), out = []; if (!existsSync(dir)) return out;
  const since = new Date(Date.now() - days * 864e5).toISOString();
  for (const f of readdirSync(dir).filter((f) => f.endsWith(".jsonl")).sort().slice(-2))
    for (const l of readFileSync(join(dir, f), "utf8").split("\n")) { if (!l) continue; try { const x = JSON.parse(l); if (x.at >= since) out.push(x); } catch {} }
  return out;
}
function runLogs(days) {
  const dir = join(DATA, "runs"), out = []; if (!existsSync(dir)) return out;
  for (const d of readdirSync(dir).filter((d) => d >= dayAgo(days))) for (const f of readdirSync(join(dir, d)).filter((f) => f.endsWith(".json"))) {
    const r = readJson(join(dir, d, f), {}); out.push({ job: String(r.job || f.slice(5, -5)), added: (r.added || []).length, updated: (r.updated || []).length, skipped: (r.skipped || []).map((s) => String(s && s.reason || "")) });
  }
  return out;
}
const bucket = (why) => /older than|six days|7 days|map window/i.test(why) ? "too old" : /already on file|on file|duplicate/i.test(why) ? "already on file" : /403|could not|unreadable|not load|timeout|failed/i.test(why) ? "source unreadable"
  : /opinion|commentary|explainer|advice|marketing|product|podcast/i.test(why) ? "not an event (commentary or marketing)" : /no exploitation|routine|low|niche|moderate/i.test(why) ? "minor advisory" : "other";

export function report(days = 7) {
  const use = readUsage(days), logs = runLogs(days), evs = listEventFiles().map((x) => x.e).filter((e) => e && !e.duplicate_of);
  const byRole = {}, byJob = {};
  for (const u of use) {
    const r = (byRole[u.role] ||= { runs: 0, ok: 0, cost: 0, turns: 0, ms: 0, timeouts: 0, model: u.model });
    r.runs++; r.ok += u.ok ? 1 : 0; r.cost += u.cost || 0; r.turns += u.turns || 0; r.ms += u.ms || 0; r.timeouts += u.error === "timeout" ? 1 : 0; r.model = u.model;
    const j = (byJob[u.job] ||= { cost: 0, workers: 0 }); j.cost += u.cost || 0; j.workers++;
  }
  const yieldBy = {}, skip = {};
  for (const l of logs) { const k = l.job.replace(/-(r\d+|\d+|gap(-\d+)?)$/, "").replace(/^sweep-.*/, "sweep"); const y = (yieldBy[k] ||= { runs: 0, added: 0, updated: 0, skipped: 0 }); y.runs++; y.added += l.added; y.updated += l.updated; y.skipped += l.skipped.length; l.skipped.forEach((w) => { const b = bucket(w); skip[b] = (skip[b] || 0) + 1; }); }
  const recent = evs.filter((e) => String(e.first_seen || "") >= dayAgo(days)), reviewed = recent.filter((e) => e.review && e.review.state);
  const bad = reviewed.filter((e) => e.review.state === "corrected" || e.review.state === "flagged").length;
  const h = readJson(join(ROOT, "site", "data", "health.json"), {}), bl = h.backlog || null;
  const qualityRate = reviewed.length ? bad / reviewed.length : null;
  const guard = { blocked: (qualityRate !== null && qualityRate > 0.15) || !!(bl && (bl.waiting > 60 || bl.oldest_incident_hours > 2)), why: "" };
  guard.why = guard.blocked ? [qualityRate !== null && qualityRate > 0.15 ? `second review corrected or flagged ${Math.round(qualityRate * 100)}% of events` : "", bl && bl.waiting > 60 ? `${bl.waiting} reports waiting` : "", bl && bl.oldest_incident_hours > 2 ? `an incident has waited ${bl.oldest_incident_hours} h` : ""].filter(Boolean).join("; ") : "";
  const cost = use.reduce((s, u) => s + (u.cost || 0), 0), added = recent.length;
  const out = { at: nowIso(), days, events_added: added, cost_usd: +cost.toFixed(2), cost_per_event: added && cost ? +(cost / added).toFixed(3) : null,
    review: { reviewed: reviewed.length, corrected_or_flagged: bad, rate: qualityRate === null ? null : +qualityRate.toFixed(3) }, backlog: bl, guard,
    roles: Object.fromEntries(Object.entries(byRole).map(([k, r]) => [k, { model: r.model, runs: r.runs, ok_rate: +(r.ok / r.runs).toFixed(2), cost: +r.cost.toFixed(2), cost_per_run: +(r.cost / r.runs).toFixed(3), turns_per_run: Math.round(r.turns / r.runs), min_per_run: +(r.ms / r.runs / 6e4).toFixed(1), timeouts: r.timeouts }])),
    jobs: Object.fromEntries(Object.entries(yieldBy).map(([k, y]) => [k, { ...y, cost: byJob[k] ? +byJob[k].cost.toFixed(2) : null, add_rate: y.added + y.updated + y.skipped ? +((y.added + y.updated) / (y.added + y.updated + y.skipped)).toFixed(2) : null }])),
    skip_reasons: Object.fromEntries(Object.entries(skip).sort((a, b) => b[1] - a[1])),
    // what the second review keeps fixing: the improver turns repeated causes into instruction requests
    review_notes: reviewed.filter((e) => e.review.state !== "passed").sort((a, b) => String(b.review.at).localeCompare(String(a.review.at))).slice(0, 12).map((e) => ({ id: e.id, state: e.review.state, flags: (e.review.flags || []).slice(0, 4), note: String(e.review.note || "").slice(0, 200) })),
    // the corrections by type and by the role and model that wrote the event (scripts/review.mjs errors): which type to
    // attack, and whether a role's model (researcher vs researcher-deep) earns its cost
    review_errors: (() => { try { const r = errorReport(evs, writersFrom(loadRunLogs(days)), Date.now(), days); return { types: r.types.map((t) => ({ key: t.key, n: t.n, pct_of_corrected: t.pct_of_corrected, checks: t.checks })), by_writer: r.by_writer.slice(0, 12) }; } catch (err) { return { error: String((err && err.message) || err).slice(0, 160) }; } })(),
    flag_counts: reviewed.reduce((m, e) => { (e.review.flags || []).forEach((f) => { m[f] = (m[f] || 0) + 1; }); return m; }, {}) };
  return out;
}

function main() {
  const [cmd, arg] = process.argv.slice(2), dir = join(DATA, "improve"); mkdirSync(dir, { recursive: true });
  if (cmd === "report" || !cmd) {
    const days = Number(process.argv[process.argv.indexOf("--days") + 1]) || 7, r = report(days); writeJson(join(dir, "latest.json"), r);
    console.log(`IMPROVE (last ${days} days): ${r.events_added} events added; worker cost $${r.cost_usd}${r.cost_per_event ? `, $${r.cost_per_event} per event` : ""}; second review corrected or flagged ${r.review.rate === null ? "n/a" : Math.round(r.review.rate * 100) + "%"} of ${r.review.reviewed}; ${r.guard.blocked ? "QUALITY GUARD ON: " + r.guard.why : "quality guard off"}.`);
    for (const [k, x] of Object.entries(r.roles).sort((a, b) => b[1].cost - a[1].cost)) console.log(`  role ${k.padEnd(18)} ${x.model.padEnd(6)} runs ${String(x.runs).padStart(3)}  ok ${Math.round(x.ok_rate * 100)}%  $${x.cost_per_run}/run  ${x.turns_per_run} turns  ${x.min_per_run} min${x.timeouts ? `  ${x.timeouts} timeouts` : ""}`);
    for (const [k, x] of Object.entries(r.jobs).sort((a, b) => b[1].runs - a[1].runs).slice(0, 10)) console.log(`  job  ${k.padEnd(18)} runs ${String(x.runs).padStart(3)}  added ${x.added}  updated ${x.updated}  skipped ${x.skipped}${x.add_rate !== null ? `  yield ${Math.round(x.add_rate * 100)}%` : ""}${x.cost !== null ? `  $${x.cost}` : ""}`);
    console.log("  skips: " + Object.entries(r.skip_reasons).map(([k, n]) => `${k} ${n}`).join(", "));
    if (r.review_errors && r.review_errors.types) console.log("  correction types: " + r.review_errors.types.map((t) => `${t.key} ${t.n}`).join(", ") + "; by writer: " + (r.review_errors.by_writer || []).map((b) => `${b.role}/${b.model} ${b.corrected}/${b.reviewed}`).join(", "));
    console.log("  review flags: " + Object.entries(r.flag_counts).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k} ${n}`).join(", "));
    r.review_notes.slice(0, 8).forEach((x) => console.log(`  ${x.state.padEnd(9)} ${x.id.slice(0, 50).padEnd(50)} ${x.note.slice(0, 110)}`));
    return;
  }
  if (cmd === "apply") {
    const prop = readJson(arg || "", null); if (!prop || !Array.isArray(prop.changes)) { console.error("usage: improve.mjs apply <proposal.json with {changes:[{key,to,reason}]}>"); process.exit(1); }
    const pPath = join(ROOT, "config", "pipeline.json"), mPath = join(ROOT, "config", "models.json"), cfg = readJson(pPath, {}), models = readJson(mPath, { roles: {} });
    const guard = (readJson(join(dir, "latest.json"), {}).guard) || { blocked: false }, today = nowIso().slice(0, 10), changedToday = new Set();
    if (existsSync(join(dir, "changes.jsonl"))) readFileSync(join(dir, "changes.jsonl"), "utf8").split("\n").forEach((l) => { try { const x = JSON.parse(l); if (String(x.at).startsWith(today)) changedToday.add(x.key); } catch {} });
    let n = 0;
    for (const c of prop.changes.slice(0, 3)) {
      const why = checkChange(c, cfg, models, guard, changedToday);
      if (why) { console.log(`REFUSED ${c && c.key}: ${why}`); continue; }
      const isModel = c.key.startsWith("models."), path = c.key.replace(/^(pipeline|models)\./, ""), target = isModel ? models : cfg, from = getPath(target, path);
      setPath(target, path, isModel && /\.model$/.test(c.key) ? c.to : Number(c.to)); changedToday.add(c.key); n++;
      appendFileSync(join(dir, "changes.jsonl"), JSON.stringify({ at: nowIso(), key: c.key, from, to: getPath(target, path), reason: String(c.reason).slice(0, 300) }) + "\n");
      console.log(`APPLIED ${c.key}: ${from} -> ${getPath(target, path)}`);
    }
    if (n) { writeJson(pPath, cfg); writeJson(mPath, models); }
    if (prop.changes.length > 3) console.log(`ignored ${prop.changes.length - 3} change(s) beyond the 3 allowed per run`);
    return;
  }
  if (cmd === "history") { const p = join(dir, "changes.jsonl"); console.log(existsSync(p) ? readFileSync(p, "utf8").trim().split("\n").slice(-20).join("\n") : "no changes yet"); return; }
  console.error("usage: improve.mjs report [--days N] | apply <proposal.json> | history"); process.exit(1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
