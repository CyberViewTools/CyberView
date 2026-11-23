// The follow-up desk's planner: which events a follow-up worker looks at now, and which wait. No AI model.
// Run: node scripts/followup-desk.mjs plan [--max W] [--per N] [--file F] [--skip id,id] [--dry-run] | status [--json]
//      (--skip: events an updater has in the same cycle; they are skipped with that reason and taken by the next run)
// Until 2026-11-23 the desk was one worker that chose up to five events itself, every time it ran: measured over three
// days it ran 74 times (every 15 minutes at the end, not every 2 hours: the loop's clock was lost at each restart), at
// 44 turns and $1.63 a run on the deep model, and 155 of its 267 looks at an event changed nothing, many of them the
// same event an hour after the last look. Now a script plans it (scripts/lib/gates.mjs followupGate):
//   - an event is planned only when there is something new to read since its last follow-up (a lead that matches it,
//     from a page it does not cite: scripts/updates.mjs matching), or when nobody has updated or followed it up for a
//     wait that doubles with every follow-up in a row that changed nothing (followup_desk.base_hours 6, 12, 24, 48 ...
//     up to max_hours 168; severity 3, exploited and developing events never wait longer than urgent_max_hours 24)
//   - every other candidate is skipped WITH its reason and the time it is due next (the plan file's `skipped`, the plan
//     line, status.json followup_note, efficiency.json gates.followup): nothing is dropped
//   - the planned events go out in small batches (per_worker 2, at most `workers` batches a run): a short run re-reads
//     far less context than one long one; severity 3 and exploited events get their own batches, which run as
//     followup-deep (scripts/lib/routing.mjs deepEvent), the rest as followup
// What a look found comes from the workers' run logs (data/runs/<day>/<HHMM>-followup*.json: updated,
// unchanged_checked, skipped, unfinished), so the planner needs no file of its own.
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, writeJson, nowIso, dayAgo, listEventFiles } from "./lib/store.mjs";
import { leased } from "./lib/lease.mjs";
import { deepEvent } from "./lib/routing.mjs";
import { FOLLOWUP_DEFAULTS, followupGate, followupUrgent } from "./lib/gates.mjs";
import { candidates, recentLeads } from "./updates.mjs";

export const PLAN_FILE = /^followup-plan(-[A-Za-z0-9-]+)?\.json$/;
export const cfgOf = (c) => ({ ...FOLLOWUP_DEFAULTS, ...(c || {}) });
export const readCfg = () => cfgOf((readJson(join(ROOT, "config", "pipeline.json"), {}) || {}).followup_desk);
const ID = /^[a-z0-9][a-z0-9-]{2,119}$/;
const idOf = (x) => (typeof x === "string" ? x : x && typeof x === "object" ? x.id || x.event || x.event_id || "" : "");

/** Pure: the desk's pool (docs/jobs.md, Follow-up desk): events of the last window_days that are developing, claimed,
 *  single-source, carry a date_note, or are severity 3. Duplicates are never followed up. */
export function pool(events, now = Date.now(), cfg = {}) {
  const since = new Date(now - cfgOf(cfg).window_days * 864e5).toISOString().slice(0, 10);
  return (events || []).filter((e) => e && e.id && !e.duplicate_of && String(e.date || "") >= since
    && (["developing", "claimed"].includes(e.status) || (e.validation && e.validation.state === "single_source") || e.date_note || Number(e.severity) >= 3));
}
/** Pure: follow-up run logs -> event id -> [{ at, outcome }]. A log's `updated` ids are "updated"; `unchanged_checked`
 *  and `skipped` entries that name an event id are "unchanged" (looked at, nothing to change); `unfinished` (written by
 *  scripts/run-job.mjs when a worker hit its turn cap or failed before logging) is "unfinished": the event was handed
 *  out but not looked at, so it comes back after the base wait without its wait growing (gates.mjs noChangeRun). */
export function historyFrom(logs) {
  const by = new Map(), add = (id, at, outcome) => { if (!ID.test(id || "") || !at) return; (by.get(id) || by.set(id, []).get(id)).push({ at, outcome }); };
  for (const r of logs || []) {
    if (!r || typeof r !== "object") continue;
    const at = String(r.finished_at || r.started_at || ""); if (!/^\d{4}-\d{2}-\d{2}T/.test(at)) continue;
    const upd = new Set((Array.isArray(r.updated) ? r.updated : []).map(idOf).filter(Boolean));
    for (const id of upd) add(id, at, "updated");
    for (const k of ["unchanged_checked", "skipped"]) for (const x of Array.isArray(r[k]) ? r[k] : []) { const id = idOf(x); if (id && !upd.has(id)) add(id, at, "unchanged"); }
    for (const x of Array.isArray(r.unfinished) ? r.unfinished : []) { const id = idOf(x); if (id && !upd.has(id)) add(id, at, "unfinished"); }
  }
  return by;
}
const SEV = (e) => Number(e.severity) || 1, ST = { developing: 0, claimed: 1 };
/** Pure: every pool event through the gate. newLeads: Map id -> [{ url, title, source, published }] (updates.mjs
 *  candidates); held: Set of event ids another worker holds (an updater this cycle).
 *  -> { due: [{ id, title, severity, status, deep, why, reason, last_at, leads }], skipped: [{ id, reason, next_at }] }
 *  due order: something new to read first, then developing, claimed and the rest, each highest severity first, then
 *  the one that has been due longest. */
export function gateAll(events, history = new Map(), newLeads = new Map(), now = Date.now(), cfg = {}, held = new Set()) {
  const due = [], skipped = [];
  for (const e of pool(events, now, cfg)) {
    const deep = deepEvent(e), leads = newLeads.get(e.id) || [], newest = leads.map((l) => String(l.published || "")).sort().pop() || "";
    // in the pool only for its severity (a settled advisory or report): its first follow-up waits sev3_quiet_hours
    const onlySev = !["developing", "claimed"].includes(e.status) && !(e.validation && e.validation.state === "single_source") && !e.date_note;
    const g = followupGate(e, history.get(e.id) || [], newest, now, cfg, followupUrgent(e, deep), onlySev ? cfgOf(cfg).sev3_quiet_hours : 0);
    if (!g.plan) { skipped.push({ id: e.id, reason: g.reason, next_at: g.next_at }); continue; }
    if (held.has(e.id)) { skipped.push({ id: e.id, reason: "skipped: another worker holds this event in this cycle (an updater); the next run takes it", next_at: nowIsoOf(now) }); continue; }
    due.push({ id: e.id, title: String(e.title || "").slice(0, 160), severity: SEV(e), status: String(e.status || ""), deep, why: g.why, reason: g.reason, last_at: g.last_at, next_at: g.next_at,
      leads: g.why === "new-lead" ? leads.slice(0, 4).map((l) => ({ url: l.url, title: String(l.title || "").slice(0, 200), source: String(l.source || "").slice(0, 80), published: String(l.published || "").slice(0, 20) })) : [] });
  }
  const W = (d) => (d.why === "new-lead" ? 0 : 1);
  due.sort((a, b) => W(a) - W(b) || (ST[a.status] ?? 2) - (ST[b.status] ?? 2) || b.severity - a.severity || String(a.next_at).localeCompare(String(b.next_at)) || a.id.localeCompare(b.id));
  skipped.sort((a, b) => String(a.next_at).localeCompare(String(b.next_at)) || a.id.localeCompare(b.id));
  return { due, skipped };
}
const nowIsoOf = (t) => new Date(t).toISOString().replace(/\.\d+Z$/, "Z");
/** Pure: the due events -> batches of at most `per`, at most W of them; deep events (severity 3, exploited) in their own
 *  batches, taken first. -> { batches: [{ batch, deep, events }], deep: [batch numbers], left: [events not planned this run] } */
export function makePlan(due, W = 2, per = 2) {
  const w = Math.max(1, W), p = Math.max(1, per), groups = [];
  for (const deep of [true, false]) { const xs = due.filter((d) => !!d.deep === deep); for (let i = 0; i < xs.length; i += p) groups.push({ deep, events: xs.slice(i, i + p), first: due.indexOf(xs[i]) }); }
  // batches in the order of their best event, so one kind never starves the other
  groups.sort((a, b) => a.first - b.first);
  const take = groups.slice(0, w), batches = take.map((g, i) => ({ batch: i + 1, deep: g.deep, events: g.events }));
  const planned = new Set(batches.flatMap((b) => b.events.map((e) => e.id)));
  return { batches, deep: batches.filter((b) => b.deep).map((b) => b.batch), left: due.filter((d) => !planned.has(d.id)) };
}
/** Pure: the one line the loop logs and status.json keeps. */
export function planLine(p, g) {
  const n = p.batches.reduce((s, b) => s + b.events.length, 0), next = g.skipped.map((s) => s.next_at).filter(Boolean).sort()[0];
  return `FOLLOW-UP PLAN: ${n} event(s) for ${p.batches.length} worker(s), ${p.deep.length} on the deep model; ${p.left.length} due and left for the next run; ${g.skipped.length} skipped: nothing new since their last follow-up${next ? ` (the next is due ${next.slice(0, 16).replace("T", " ")} UTC)` : ""}.`;
}

// ---------- files ----------
/** The follow-up run logs of the last `days` days. */
export function readLogs(days = 12) {
  const out = [], runs = join(DATA, "runs");
  if (existsSync(runs)) for (const d of readdirSync(runs).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d) && d >= dayAgo(days))) {
    for (const f of readdirSync(join(runs, d)).filter((f) => /-followup(-[A-Za-z0-9-]+)?\.json$/.test(f))) { const r = readJson(join(runs, d, f), null); if (r) out.push(r); }
  }
  return out;
}
/** Everything the desk needs from disk, through the gate. */
export function load(now = Date.now(), held = null, extra = null) {
  const cfg = readCfg(), events = listEventFiles().map((f) => f.e).filter(Boolean), mine = pool(events, now, cfg);
  let newLeads = new Map();
  try { newLeads = new Map(candidates(recentLeads(3), events.filter((e) => e && e.date >= dayAgo(30)), new Set(), now, 72).map((c) => [c.id, c.leads])); } catch {}
  const h = held instanceof Set && !extra ? held : new Set([...(held || leased("event", mine.map((e) => e.id), process.env.CYBERVIEW_RUN || "")), ...(extra || [])]);
  return { cfg, ...gateAll(events, historyFrom(readLogs(cfg.window_days + 2)), newLeads, now, cfg, h), pool: mine.length };
}
/** The numbers for the status page and efficiency.json: { pool, due, skipped, next_due_at }. */
export function stats(now = Date.now()) {
  const g = load(now, new Set());
  return { pool: g.pool, due: g.due.length, skipped: g.skipped.length, next_due_at: g.skipped.map((s) => s.next_at).filter(Boolean).sort()[0] || null, by_why: g.due.reduce((o, d) => { o[d.why] = (o[d.why] || 0) + 1; return o; }, {}) };
}

function main() {
  const [cmd, ...rest] = process.argv.slice(2), arg = (k, d) => { const i = rest.indexOf("--" + k); return i >= 0 ? rest[i + 1] : d; };
  const now = Date.now();
  if (cmd === "plan") {
    const skip = String(arg("skip", "")).split(",").map((x) => x.trim()).filter((x) => ID.test(x));
    const g = load(now, null, skip), cfg = g.cfg, dry = rest.includes("--dry-run");
    const W = Math.max(1, Math.min(4, Number(arg("max", cfg.workers)) || 2)), per = Math.max(1, Math.min(5, Number(arg("per", cfg.per_worker)) || 2));
    const file = PLAN_FILE.test(arg("file", "")) ? arg("file") : "followup-plan.json", p = makePlan(g.due, W, per), line = planLine(p, g);
    if (dry) {
      console.log(line.replace("FOLLOW-UP PLAN:", "FOLLOW-UP PLAN (dry run, nothing written):") + ` Pool: ${g.pool} event(s).`);
      p.batches.forEach((b) => b.events.forEach((e) => console.log(`  batch ${b.batch}${b.deep ? " (deep)" : ""}  ${e.id}  [severity ${e.severity}, ${e.status}] ${e.reason}`)));
      p.left.slice(0, 15).forEach((e) => console.log(`  next run  ${e.id}  ${e.reason}`));
      g.skipped.slice(0, 15).forEach((s) => console.log(`  ${s.id}  ${s.reason}`));
      return;
    }
    // the skipped list is kept short in the file (the count is exact): the reason and the next time of the soonest 60
    writeJson(join(DATA, file), { planned_at: nowIso(), batches: p.batches, deep: p.deep, left: p.left.map((e) => e.id), skipped_count: g.skipped.length, skipped: g.skipped.slice(0, 60), pool: g.pool });
    console.log(line);
    return;
  }
  if (cmd === "status") {
    const st = stats(now);
    if (rest.includes("--json")) { console.log(JSON.stringify(st)); return; }
    console.log(`FOLLOW-UP DESK: ${st.pool} event(s) in the pool, ${st.due} due now, ${st.skipped} skipped: nothing new since their last follow-up${st.next_due_at ? ` (next due ${st.next_due_at})` : ""}.`);
    return;
  }
  console.error("usage: followup-desk.mjs plan [--max W] [--per N] [--file F] [--skip id,id] [--dry-run] | status [--json]"); process.exit(1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
