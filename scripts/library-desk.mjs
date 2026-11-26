// The Library's desk runner: each time it is called it decides how much reading, writing, reviewing and auditing to do, and does it.
//   Pilot first: until the pilot is complete (a computed predicate on stored state, pilotComplete) work is limited to the pilot set
//   (data/orkl/pilot.json, chosen once: the 200 newest reports plus every report of the 10 biggest actors, 40 per actor at most;
//   those 10 actors, 5 actors with one or no report and 5 loose subjects) and the audit checks every card.
//   Then only new records and stale stories (mode "steady"); the backlog (library.backfill, the OWNER's switch, ships false).
//   Never while the map pipeline needs the usage window: canBuild (scripts/lib/usage.mjs) is asked first, and the shared 35% reserve holds.
// `run` order: review, audit, write, read (finish what is closest to publishing first), each in waves of one worker batch; a wave starts
// only with the time left that a worker of its role needs (reserveMs). The desk commits nothing: scripts/run-job.mjs library runs it and
// then scripts/finish.mjs library, the same path as every headless job. It stamps last_library_at and library_note in status.json.
// Usage: node scripts/library-desk.mjs run | status | pilot-report   (behind a proxy: NODE_USE_ENV_PROXY=1)
import { join } from "node:path";
import { existsSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, writeJson, readStatus, nowIso } from "./lib/store.mjs";
import { DIR, loadLibrary } from "./orkl.mjs";
import { loadCards, readQueue, loadReadState, parkedRecords, READ_STATE_FILE, run as readRun, statusLine as readStatusLine } from "./library-read.mjs";
import { loadStories, writeQueue, run as writeRun, statusLine as writeStatusLine } from "./library-write.mjs";
import { reviewQueue, auditPick, run as reviewRun, runAudit, statusLine as reviewStatusLine } from "./library-review.mjs";
import { loadConfig, auditState, auditFailed, paused, wrongCards, retiredAfterAudit, DEFAULTS as AUDIT_DEFAULTS } from "./lib/library-audit.mjs";
import { actorIndex, actorSubjects, looseSubjects, nameKey } from "./lib/library-subjects.mjs";
import { canBuild, estimateCost, readUsage, budgetConfig, PRICES } from "./lib/usage.mjs";
import { readBuild, BUILD_LEDGER } from "./budget.mjs";

export const PILOT_FILE = join(DIR, "pilot.json");
export const DESK_DEFAULTS = { enabled: true, backfill: false, pilot: { reports: 200, top_actors: 10, thin_actors: 5, loose: 5 }, wave: { read: 40, write: 6, review: 6, audit: 4 }, ...AUDIT_DEFAULTS };
const PER_ACTOR = 40;                          // reports of one actor read for the pilot: the writer shows at most 40 cards per story anyway
const CHUNK = { review: 2, audit: 2, write: 3, read: 4 };   // one worker batch = the concurrency of the desk's own run
const ROLES = { review: "library-reviewer", audit: "library-auditor", write: "library-writer", read: "library-reader" };
const ORDER = ["review", "audit", "write", "read"];
const MODELS = readJson(join(ROOT, "config", "models.json"), { roles: {} });
const num = (x) => Math.max(0, Number(x) || 0);
const stampOf = (r) => String((r && (r.created || r.file_date)) || "");

/** config/pipeline.json `library` over the defaults: numbers and the two switches only. The audit dials come from library-audit. */
export function deskConfig(file = join(ROOT, "config", "pipeline.json")) {
  const lib = (readJson(file, {}) || {}).library, out = { ...DESK_DEFAULTS, ...loadConfig(file), pilot: { ...DESK_DEFAULTS.pilot }, wave: { ...DESK_DEFAULTS.wave } };
  if (lib && typeof lib === "object") {
    if (typeof lib.enabled === "boolean") out.enabled = lib.enabled;
    if (typeof lib.backfill === "boolean") out.backfill = lib.backfill;
    for (const g of ["pilot", "wave"]) if (lib[g] && typeof lib[g] === "object") for (const k of Object.keys(out[g])) if (Number.isFinite(lib[g][k]) && lib[g][k] >= 0) out[g][k] = lib[g][k];
  }
  return out;
}

/** Pure: the time that must be left before a wave of this role starts (a worker started with less is cut off and writes nothing; the same
 *  reasoning as minStartMs in scripts/run-job.mjs: measured calls take 1 to 2.5 minutes, the role's own timeout is the ceiling). */
export function reserveMs(role) {
  const t = Number(((MODELS.roles || {})[role] || {}).timeout_min) * 60000 || 360000;
  return Math.min(t, role === "library-reader" ? 90000 : 150000);
}

/** Pure: what to do this run. `state` = deskState().state; canBuildOk = the pipeline can spare the window. */
export function plan(state, cfg, canBuildOk) {
  const s = state || {}, w = { ...DESK_DEFAULTS.wave, ...((cfg && cfg.wave) || {}) }, cap = (a, b) => Math.min(num(a), num(b));
  if (!canBuildOk || (cfg && cfg.enabled === false)) return { read: 0, write: 0, review: 0, audit: 0, auditPct: 0, mode: "wait" };
  const share = num(cfg && cfg.audit_pct != null ? cfg.audit_pct : DESK_DEFAULTS.audit_pct);
  if (s.paused) return { read: cap(w.read, s.failedCards), write: 0, review: 0, audit: cap(w.audit, s.auditable), auditPct: 100, mode: !s.pilotDone ? "pilot" : cfg && cfg.backfill ? "backfill" : "steady" };
  const p = s.pilot || {};
  if (!s.pilotDone) return { read: cap(w.read, p.read), write: cap(w.write, p.write), review: cap(w.review, s.drafts), audit: cap(w.audit, s.auditable), auditPct: 100, mode: "pilot" };
  const back = !!(cfg && cfg.backfill);
  return { read: cap(w.read, num(s.newRecords) + (back ? num(s.backlog) : 0)), write: cap(w.write, num(s.writeNew) + (back ? num(s.writeBacklog) : 0)),
    review: cap(w.review, s.drafts), audit: cap(w.audit, s.auditable), auditPct: share, mode: back ? "backfill" : "steady" };
}

/* ---------------- the pilot set ---------------- */
const byNewest = (a, b) => stampOf(b).localeCompare(stampOf(a)) || String(a.sha1).localeCompare(String(b.sha1));
const byName = (a, b) => String(a.name).toLowerCase().localeCompare(String(b.name).toLowerCase()) || String(a.key).localeCompare(String(b.key));
/** The actor ids a report names (resolvable ones only). */
function actorIds(report, ix) {
  const ids = new Set();
  for (const n of Array.isArray(report && report.actors) ? report.actors : []) { const id = ix.byKey.get(nameKey(n && typeof n === "object" ? n.name : n)); if (id != null) ids.add(id); }
  return ids;
}
/** Pure: reports newest first per actor id, from the whole library. */
function reportsByActor(reports, ix) {
  const m = new Map();
  for (const r of [...reports].sort(byNewest)) for (const id of actorIds(r, ix)) (m.get(id) || m.set(id, []).get(id)).push(r);
  return m;
}
export const pilotSha1s = (p) => [...((p && p.newest) || []), ...((p && p.extra) || [])];
export const pilotKeys = (p) => [...((p && p.actors) || []).map((a) => a.key), ...((p && p.loose) || []).map((a) => a.key)];

/** Pure and deterministic: the pilot set from the library and the config. `at` is only stamped on it. Loose subjects are added later
 *  (pilotLoose), when the cards that decide them exist. */
export function selectPilot(reports, actors, pcfg, at) {
  const c = { ...DESK_DEFAULTS.pilot, ...(pcfg || {}) }, ix = actorIndex(actors), sorted = [...(reports || [])].sort(byNewest);
  const subj = new Map(actorSubjects(actors, [], new Map()).map((s) => [s.actor.id, s]));
  const newest = sorted.slice(0, c.reports), inNewest = new Set(newest.map((r) => r.sha1)), by = reportsByActor(reports || [], ix);
  const ranked = [...subj.values()].map((s) => ({ s, n: (by.get(s.actor.id) || []).length })).sort((a, b) => b.n - a.n || a.s.key.localeCompare(b.s.key));
  const top = ranked.filter((x) => x.n > 0).slice(0, c.top_actors);
  const extra = [], seen = new Set(inNewest);
  for (const t of top) for (const r of (by.get(t.s.actor.id) || []).slice(0, PER_ACTOR)) if (!seen.has(r.sha1)) { seen.add(r.sha1); extra.push(r.sha1); }
  const isTop = new Set(top.map((t) => t.s.key));
  // ORKL placeholder entries ("[Unnamed group ...]") are not actors, so never thin actors
  const rest = ranked.filter((x) => !isTop.has(x.s.key) && !/^\[/.test(String(x.s.name))).map((x) => ({ key: x.s.key, name: x.s.name, n: x.n, one: x.n === 1 && inNewest.has(by.get(x.s.actor.id)[0].sha1) }));
  const thin = [...rest.filter((x) => x.one).sort(byName), ...rest.filter((x) => x.n === 0).sort(byName)].slice(0, c.thin_actors);
  const actorsOut = [...top.map((t) => ({ key: t.s.key, name: t.s.name, group: "top" })), ...thin.map((t) => ({ key: t.key, name: t.name, group: "thin" }))];
  return { version: 1, chosen_at: at, newest_at: newest.length ? stampOf(newest[0]) : "", config: c, newest: newest.map((r) => r.sha1), extra,
    actors: actorsOut, loose: [], counts: { reports: newest.length + extra.length, newest: newest.length, top_extra: extra.length, top_actors: top.length, thin_actors: thin.length, loose: 0 } };
}

const resolved = (c) => !!c && (c.status === "read" || c.status === "no-text" || (c.status === "unread" && (Number(c.tries) || 0) >= 2));
/** Pure: the loose subjects to add to the pilot: only once every one of the newest reports is resolved, from the newest reports'
 *  eligible cards, most reports first. Never removes one; fills up to `want`. -> [{ key, name }] */
export function pilotLoose(pilot, reports, actors, cards, want) {
  const have = new Set((pilot.loose || []).map((x) => x.key)), slots = num(want) - have.size;
  if (slots <= 0 || !(pilot.newest || []).every((s) => resolved(cards.get(s)))) return [];
  const inN = new Set(pilot.newest), pool = (reports || []).filter((r) => inN.has(r.sha1));
  return looseSubjects(pool, cards, actorIndex(actors)).filter((s) => !have.has(s.key))
    .sort((a, b) => b.sha1s.length - a.sha1s.length || a.key.localeCompare(b.key)).slice(0, slots).map((s) => ({ key: s.key, name: s.name }));
}

/** Pure: is the pilot complete NOW (the live predicate; the mode itself uses the latch, `completed_at` in pilot.json), and if not what is
 *  missing. Every report has a card that is read, no-text or unread with tries spent; every read pilot card has a current auditor verdict;
 *  every pilot subject has a published live story or a parked next; at least half the pilot reports are read; every published top-actor
 *  pilot story cites at least one card. A pilot subject key that no longer resolves to a subject
 *  (`subjectKeys` given) cannot be written, so it does not block: it is counted as finished-unresolved and named. */
export function pilotComplete(pilot, cards, stories, subjectKeys = null, { parked: parkedSet = new Set() } = {}) {
  const why = [], shas = pilotSha1s(pilot), keys = pilotKeys(pilot);
  // a record the reader parked after repeated failures counts as resolved (unread), and is named
  const parked = shas.filter((s) => !resolved(cards.get(s)) && parkedSet.has(s));
  const unread = shas.filter((s) => !resolved(cards.get(s)) && !parkedSet.has(s)).length;
  if (unread) why.push(`${unread} pilot report(s) not read yet`);
  const unaudited = shas.filter((s) => { const c = cards.get(s); return c && c.status === "read" && !(c.audit && c.audit.by === "auditor" && c.audit.ok === true); }).length;
  if (unaudited) why.push(`${unaudited} read pilot card(s) without the auditor's verdict`);
  const unresolved = subjectKeys ? keys.filter((k) => !subjectKeys.has(k)) : [];
  const unfinished = keys.filter((k) => !unresolved.includes(k) && !((f) => f && ((f.live && f.live.status === "published") || (f.next && f.next.status === "parked")))(stories.get(k))).length;
  if (unfinished) why.push(`${unfinished} pilot subject(s) without a published or parked story`);
  // the pilot measures reading: it cannot latch with most reports unread (no-text, retired or parked), and a top actor's published story
  // must rest on at least one card, not on the catalogue alone
  const readN = shas.filter((s) => { const c = cards.get(s); return c && c.status === "read" && c.withdrawn !== true; }).length;
  if (shas.length && readN * 2 < shas.length) why.push(`only ${readN} of ${shas.length} pilot reports read: at least half must be read before the pilot can complete`);
  const bare = ((pilot && pilot.actors) || []).filter((a) => a && a.group === "top").map((a) => a.key).filter((k) => {
    const f = stories.get(k), l = f && f.live;
    return l && l.status === "published" && !(l.sections || []).some((sec) => (sec.sentences || []).some((x) => (x.cites || []).some((c) => /^[0-9a-f]{40}$/.test(c))));
  });
  if (bare.length) why.push(`${bare.length} top-actor pilot stor${bare.length === 1 ? "y" : "ies"} cites no report (${bare.join(", ")})`);
  return { done: !why.length, why, counts: { unread, unaudited, unfinished, unresolved: unresolved.length, read: readN, bare: bare.length, parked: parked.length }, unresolved, parked };
}
/** Pure: the lines `status` and `pilot-report` print about the pilot: the mode, the latch time and, while the live predicate is false, why. */
export function describePilot({ latched = "", live, mode = "" }) {
  const out = [latched ? `pilot: mode ${mode || "after the pilot"}, latched at ${latched} (it stays complete)` : `pilot: mode pilot, not latched`];
  if (live && !live.done) { out.push(`pilot incomplete now: ${live.why.join("; ")}`); if (live.counts) out.push(`  counts: unread reports ${live.counts.unread || 0}, unaudited cards ${live.counts.unaudited || 0}, unfinished subjects ${live.counts.unfinished || 0}, unresolved keys ${live.counts.unresolved || 0}`); }
  else if (live && !latched) out.push("the pilot predicate holds now: the next run latches it");
  if (live && live.unresolved && live.unresolved.length) out.push(`unresolved pilot subject key(s): ${live.unresolved.join(", ")} (no longer a subject; counted as finished)`);
  if (live && live.parked && live.parked.length) out.push(`parked pilot report(s) after repeated failures (counted as resolved, unread): ${live.parked.map((s) => String(s).slice(0, 8)).join(", ")}`);
  return out.join("\n");
}
/** Is the Library switched off with nothing stored? Then nothing needs the whole library loaded (the pipeline check, efficiency). */
export const libraryIdle = (routines, cards) => ((routines || []).find((r) => r.key === "library") || {}).active === false && cards.size === 0;

/** The stored pilot: { state: "none" | "ok" | "bad", pilot }. A file that exists but cannot be read is "bad" and is never overwritten. */
export function loadPilot(file = PILOT_FILE) {
  if (!existsSync(file)) return { state: "none", pilot: null };
  const j = readJson(file, null);
  return j && typeof j === "object" && Array.isArray(j.newest) && Array.isArray(j.extra) && Array.isArray(j.actors) ? { state: "ok", pilot: { ...j, loose: Array.isArray(j.loose) ? j.loose : [] } } : { state: "bad", pilot: null };
}
/** Store the pilot once. An existing file (readable or not) is never replaced. */
export function savePilot(file, pilot) {
  if (existsSync(file)) return false;
  writeJson(file, pilot); return true;
}
/** Set `completed_at` once (the latch): never changed or removed afterwards. True when this call set it. */
export function latchPilot(file, at) {
  const cur = loadPilot(file);
  if (cur.state !== "ok" || cur.pilot.completed_at) return false;
  writeJson(file, { ...cur.pilot, completed_at: at });
  return true;
}
/** Add loose subjects to the stored pilot (additive; the file is re-read first). */
export function addLoose(file, entries) {
  const cur = loadPilot(file);
  if (cur.state !== "ok") return false;
  const have = new Map(cur.pilot.loose.map((x) => [x.key, x]));
  for (const e of entries || []) if (e && e.key && !have.has(e.key)) have.set(e.key, { key: String(e.key), name: String(e.name || "").slice(0, 120) });
  const loose = [...have.values()];
  writeJson(file, { ...cur.pilot, loose, counts: { ...(cur.pilot.counts || {}), loose: loose.length } });
  return true;
}

/** Pure: report sha1s for the backfill: reports of actors first (the actor with most reports first, newest first within it), then the
 *  rest newest first. A report naming several actors ranks by its biggest actor. */
export function backfillOrder(reports, actors) {
  const ix = actorIndex(actors), by = reportsByActor(reports || [], ix), size = (r) => Math.max(0, ...[...actorIds(r, ix)].map((id) => (by.get(id) || []).length));
  return (reports || []).map((r) => ({ r, n: size(r) })).sort((a, b) => (b.n > 0) - (a.n > 0) || (b.n - a.n) || byNewest(a.r, b.r)).map((x) => x.r.sha1);
}

/* ---------------- the desk's picture of the Library ---------------- */
/** Pure: counts for plan() and the reader's and writer's orders, from stored state. */
export function deskState({ reports, actors, cards, stories, pilot, cfg, failures = {}, now = Date.now() }) {
  const ix = actorIndex(actors), c = { ...DESK_DEFAULTS, ...(cfg || {}) };
  const subjects = [...actorSubjects(actors, reports, cards), ...looseSubjects(reports, cards, ix)], subjectKeys = new Set(subjects.map((s) => s.key));
  const live = pilotComplete(pilot, cards, stories, subjectKeys, { parked: new Set(parkedRecords(failures, now)) }), latched = String(pilot.completed_at || ""), pilotDone = !!latched, isPaused = paused(cards, c);
  const todo = readQueue(reports, cards, { failures, now }), pset = new Set(pilotSha1s(pilot)), isNew = (r) => stampOf(r) > String(pilot.newest_at || "");
  // a new record: a report created after the pilot's newest, or a card an audit sent back for a re-read
  const inPilot = todo.filter((r) => pset.has(r.sha1)), fresh = todo.filter((r) => !pset.has(r.sha1) && (isNew(r) || auditFailed(cards.get(r.sha1)))), old = todo.filter((r) => !pset.has(r.sha1) && !isNew(r) && !auditFailed(cards.get(r.sha1)));
  const reportBy = new Map(reports.map((r) => [r.sha1, r]));
  const newCard = (s) => s.sha1s.some((x) => { const k = cards.get(x), r = reportBy.get(x); return k && k.status === "read" && r && isNew(r); });
  const wq = writeQueue(subjects, stories, cards, {}), pk = new Set(pilotKeys(pilot));
  const hasStory = (k) => { const f = stories.get(k); return !!(f && (f.live || f.next)); };
  const pilotQ = wq.filter((s) => pk.has(s.key)), steadyQ = wq.filter((s) => pk.has(s.key) || hasStory(s.key) || newCard(s));
  const pct = !pilotDone || isPaused ? 100 : c.audit_pct;
  let readOrder;
  if (isPaused) readOrder = todo.filter((r) => auditFailed(cards.get(r.sha1))).map((r) => r.sha1);
  else if (!pilotDone) readOrder = inPilot.map((r) => r.sha1);
  else if (c.backfill) { const q = new Set(todo.map((r) => r.sha1)); readOrder = backfillOrder(reports, actors).filter((s) => q.has(s)); }
  else readOrder = fresh.map((r) => r.sha1);
  const state = { pilotDone, paused: isPaused, failedCards: todo.filter((r) => auditFailed(cards.get(r.sha1))).length,
    pilot: { read: inPilot.length, write: pilotQ.length }, newRecords: fresh.length, backlog: old.length,
    writeNew: steadyQ.length, writeBacklog: wq.length - steadyQ.length, drafts: reviewQueue(stories).filter((k) => subjectKeys.has(k) && (pilotDone || pk.has(k))).length, auditable: auditPick(cards, pct).length };
  const writeOrder = !pilotDone ? pilotQ.map((s) => s.key) : steadyQ.map((s) => s.key);
  // review: before the latch only the pilot's stories are reviewed (null = every draft)
  return { state, orders: { read: readOrder, write: writeOrder, review: pilotDone ? null : [...pk] }, subjectKeys, pilotStatus: { ...live, latched } };
}

/* ---------------- the stage loop ---------------- */
const progress = {
  read: (t) => num(t.read) + num(t["no-text"]) + num(t.unread),
  write: (t) => num(t.drafted) + num(t.rejected) + num(t.parked),
  review: (t) => num(t.published) + num(t.corrected) + num(t.rejected) + num(t.parked) + num(t.cardsFlagged),
  audit: (t) => num(t.ok) + num(t.wrong),
};
const WINDOW_STOP = "the pipeline needs the usage window";
const roleMs = (role) => (Number(((MODELS.roles || {})[role] || {}).timeout_min) || 6) * 60000;
/** Run the stages in order, each in waves. Before EVERY wave: `canStart()` (the usage window; false ends the whole run, reason
 *  WINDOW_STOP) and at least `reserveMs(role)` before `deadline`; a stage may not use more than its fair share of the time left once it
 *  has done one wave. Each call gets `timeoutMs` = the smaller of the role's own timeout and the time left minus 20 s, so no model
 *  call outlives the deadline. A stage ends when its quota is spent, a wave made no progress, or it stopped itself (an unreachable ORKL,
 *  failed calls); a usage limit ends the whole run (`halt`), no later stage makes a call. What a wave tried is not listed again. A stage
 *  that throws does not stop the others. deps: { review, audit, write, read }: ({ max, order, pilot, timeoutMs }) -> tally.
 *  -> { stage: { done, stopped, error, skipped }, halt } */
export async function runStages({ plan: p, orders = {}, deps, now = Date.now, deadline, chunk = CHUNK, pilot = false, canStart = null, log = console.log }) {
  const out = {}, isPilot = pilot || p.mode === "pilot";
  let left = ORDER.filter((k) => num(p[k]) > 0).length;
  stages: for (const k of ORDER) {
    const r = out[k] = { done: 0, stopped: "", error: "", skipped: "" };
    const quota = num(p[k]);
    if (!quota) continue;
    const reserve = reserveMs(ROLES[k]), t0 = now(), share = (deadline - t0) / left--;
    let order = k === "read" ? [...(orders.read || [])] : k === "write" ? [...(orders.write || [])] : null;
    const allow = k === "review" && Array.isArray(orders.review) ? [...orders.review] : null;   // review: an allow-list, never used up
    while (r.done < quota) {
      const t = now();
      if (deadline - t < reserve) { r.skipped = "no time left"; break; }
      if (r.done > 0 && t - t0 >= share) { r.skipped = "its share of the time is used"; break; }
      if (canStart && !canStart()) { out.halt = WINDOW_STOP; log(`library-desk: ${WINDOW_STOP}; the run ends`); break stages; }
      const n = Math.min(num(chunk[k]) || 1, quota - r.done), timeoutMs = Math.max(1000, Math.min(roleMs(ROLES[k]), deadline - t - 20000));
      let tally;
      try { tally = (await deps[k]({ max: n, order: order ? [...order] : allow ? [...allow] : undefined, pilot: isPilot, timeoutMs })) || {}; }
      catch (e) { r.error = String((e && e.name) || "Error").slice(0, 40); log(`library-desk: ${k} failed (${r.error})`); break; }
      r.done += n; if (order) order = order.slice(n);
      if (tally.stopped) {
        r.stopped = String(tally.stopped);
        if (/usage limit/i.test(r.stopped)) { out.halt = r.stopped; log(`library-desk: ${r.stopped}; the run ends`); break stages; }
        break;
      }
      if (!progress[k](tally)) { r.skipped = "no progress"; break; }
    }
  }
  return out;
}

/* ---------------- reports ---------------- */
const lib = (usage) => (usage || []).filter((l) => l && l.job === "library" && String(l.role || "").startsWith("library-"));
const tokensOf = (l) => num(l.in) + num(l.out) + num(l.cache_read) + num(l.cache_write);
/** Pure: calls, tokens and estimated USD of the Library's ledger lines by role. */
function byRole(lines) {
  const m = {};
  for (const l of lines) { const b = m[l.role] ||= { runs: 0, tokens: 0, est_usd: 0 }; b.runs++; b.tokens += tokensOf(l); b.est_usd = Math.round((b.est_usd + estimateCost(l, PRICES)) * 1e4) / 1e4; }
  return m;
}
const money = (x) => `$${(Math.round(x * 1000) / 1000).toFixed(3)}`;
function storyCounts(stories) {
  const n = { published: 0, stale: 0, draft: 0, rejected: 0, parked: 0 };
  for (const f of stories.values()) { if (f.live && (f.live.status === "published" || f.live.status === "stale")) n[f.live.status]++; if (f.next && n[f.next.status] != null && f.next.status !== "published" && f.next.status !== "stale") n[f.next.status]++; }
  return n;
}
function cardCounts(cards) {
  const n = { read: 0, "no-text": 0, unread: 0 };
  for (const c of cards.values()) if (c && n[c.status] != null) n[c.status]++;
  return { ...n, total: n.read + n["no-text"] + n.unread };
}
/** Pure: the `library` block of efficiency.json: cards by status, the reader audit, stories by status, and the last 7 days' tokens and estimated cost by role. */
export function libraryBlock({ cards, stories, usage, cfg, now = Date.now() }) {
  const a = auditState(cards, { ...DESK_DEFAULTS, ...(cfg || {}) }), since = now - 7 * 864e5;
  return { cards: cardCounts(cards), audit: { audited: a.audited, wrong: a.wrong, pct: Math.round(a.pct * 10) / 10, paused: a.paused }, stories: storyCounts(stories),
    usage: { days: 7, by_role: byRole(lib(usage).filter((l) => Date.parse(l.at) > since)) } };
}
/** The pilot report: counts, the audited error rate, tokens and estimated cost per card and per story from the usage ledger, the pilot's story keys. */
export function pilotReport(cards, stories, { pilot = null, usage = [], cfg = DESK_DEFAULTS } = {}) {
  const cc = cardCounts(cards), a = auditState(cards, { ...DESK_DEFAULTS, ...cfg }), sc = storyCounts(stories), roles = byRole(lib(usage)), out = [];
  const c = (pilot && pilot.counts) || {};
  out.push("Library pilot report");
  if (pilot) out.push(`Pilot set: ${c.reports || pilotSha1s(pilot).length} reports (${c.newest || (pilot.newest || []).length} newest + ${c.top_extra || (pilot.extra || []).length} of the top actors), ${c.top_actors ?? pilot.actors.filter((x) => x.group === "top").length} top actors, ${c.thin_actors ?? pilot.actors.filter((x) => x.group === "thin").length} thin actors, ${(pilot.loose || []).length} loose subjects`);
  out.push(`Cards: ${cc.total} in all: read ${cc.read}, no-text ${cc["no-text"]}, unread ${cc.unread}`);
  out.push(`Reader accuracy: audited ${a.audited}, wrong ${a.wrong} (${a.pct.toFixed(1)}%)${a.paused ? ", PAUSED" : ""}`);
  out.push(`Stories: published ${sc.published}, stale ${sc.stale}, drafts ${sc.draft}, rejected ${sc.rejected}, parked ${sc.parked}`);
  for (const [role, b] of Object.entries(roles).sort()) out.push(`  ${role}: ${b.runs} call(s), ${b.tokens} tokens, ${money(b.est_usd)} estimated`);
  const usd = (role) => (roles[role] || {}).est_usd || 0, cardCost = usd("library-reader") + usd("library-auditor"), storyCost = usd("library-writer") + usd("library-reviewer");
  // the denominators are the pilot's own cards and stories when a pilot is given
  const pk = pilot ? new Set(pilotKeys(pilot)) : null, readCards = pilot ? pilotSha1s(pilot).filter((x) => (cards.get(x) || {}).status === "read").length : cc.read;
  const published = pk ? [...pk].filter((k) => { const f = stories.get(k); return f && f.live && f.live.status === "published"; }).length : sc.published;
  out.push(`Cost per card (estimate) ${readCards ? money(cardCost / readCards) : "n/a"} (ledger cost of the reader and auditor over the ${readCards} read pilot card(s)); cost per story (estimate) ${published ? money(storyCost / published) : "n/a"} (writer and reviewer over the ${published} published pilot stor${published === 1 ? "y" : "ies"})`);
  if (pilot) {
    out.push("Pilot stories:");
    for (const k of pilotKeys(pilot)) { const f = stories.get(k), st = f ? (f.live ? f.live.status : f.next ? f.next.status : "empty") : "no story yet", nm = [...pilot.actors, ...pilot.loose].find((x) => x.key === k); out.push(`  ${k} (${nm ? nm.name : "?"}): ${st}`); }
  }
  return out.join("\n");
}

const routinesFile = () => (readJson(join(ROOT, "routines.json"), { routines: [] }) || {}).routines || [];
/** The `library` block of efficiency.json from what is stored now and the usage ledger lines (never loads the report library). */
export async function efficiencyBlock(usage, now = Date.now()) {
  return libraryBlock({ cards: loadCards(), stories: loadStories(), usage, cfg: deskConfig(), now });
}
/** The Library's health for the pipeline check: { paused, wrong (card sha1s), parked, orphans }. While the routine is off and no card
 *  exists, nothing is loaded. */
export async function libraryHealth() {
  const cards = loadCards(), none = { paused: false, wrong: [], parked: 0, orphans: 0, retired: 0 };
  if (libraryIdle(routinesFile(), cards)) return none;
  const lb = loadLibrary(), stories = loadStories(), cfg = deskConfig();
  if (!lb.reports.length) return none;
  const keys = new Set([...actorSubjects(lb.actors, lb.reports, cards), ...looseSubjects(lb.reports, cards, actorIndex(lb.actors))].map((s) => s.key));
  return { paused: paused(cards, cfg), wrong: wrongCards(cards), parked: storyCounts(stories).parked, orphans: reviewQueue(stories).filter((k) => !keys.has(k)).length, retired: retiredAfterAudit(cards).length };
}

/* ---------------- the run ---------------- */
function realDeps(library) {
  return {
    // the queues are restricted to the desk's orders (only: true), so a gate is never filled from outside it; review gets the allowed keys
    review: ({ max, order, timeoutMs }) => reviewRun({ max, keys: order, library, concurrency: CHUNK.review, timeoutMs }),
    audit: ({ max, pilot, timeoutMs }) => runAudit({ max, pilot, library, concurrency: CHUNK.audit, timeoutMs }),
    write: ({ max, order, timeoutMs }) => writeRun({ max, order, only: true, library, concurrency: CHUNK.write, timeoutMs }),
    read: ({ max, order, timeoutMs }) => readRun({ max, order, only: true, library, concurrency: CHUNK.read, timeoutMs }),
  };
}
const summary = (r) => ORDER.map((k) => `${k} ${r[k] ? r[k].done : 0}${r[k] && (r[k].stopped || r[k].error) ? ` (${r[k].stopped || r[k].error})` : ""}`).join(", ");

/** One desk run. Stamps last_library_at and library_note in status.json when it ends, whatever it did (also when the deadline ended it).
 *  deadlineMs: the absolute time (ms) by which every model call must have ended; run-job.mjs passes its own cut-off minus 30 s.
 *  can: the usage-window answer for the plan (tests); canStart: asked before every wave (default: the usage ledger and canBuild, re-read each time). */
export async function run({ cfg = deskConfig(), library = null, deps = null, now = Date.now, deadlineMs = null, can = null, canStart = null, log = console.log, statusFile = join(DATA, "status.json"), pilotFile = PILOT_FILE, readStateFile = READ_STATE_FILE } = {}) {
  const stamp = (note) => { try { const st = readStatus(); st.last_library_at = nowIso(); st.library_note = String(note).slice(0, 300); writeJson(statusFile, st); } catch (e) { log(`library-desk: status not written (${String((e && e.name) || "Error")})`); } return note; };
  const end = (note, p = null, results = {}) => { stamp(note); log(`CyberView library: ${note}`); return { note, plan: p, results }; };
  if (cfg.enabled === false) return end("off (library.enabled is false in config/pipeline.json)");
  const lb = library || loadLibrary();
  if (!(lb.reports || []).length || !(lb.actors || []).length) return end("library not loaded (no reports or no actors): nothing done");
  const bad = [], cards = loadCards(undefined, bad);
  if (bad.length) return end(`card shards unreadable (${bad.join(", ")}): nothing done`);
  let pf = loadPilot(pilotFile);
  if (pf.state === "bad") return end("data/orkl/pilot.json cannot be read: nothing done, it is never overwritten");
  if (pf.state === "none") { savePilot(pilotFile, selectPilot(lb.reports, lb.actors, cfg.pilot, nowIso())); pf = loadPilot(pilotFile); }
  const loose = pilotLoose(pf.pilot, lb.reports, lb.actors, cards, cfg.pilot.loose);
  if (loose.length) { addLoose(pilotFile, loose); pf = loadPilot(pilotFile); }
  const badS = [], stories = loadStories(undefined, badS), failures = loadReadState(readStateFile).failures;
  let ds = deskState({ reports: lb.reports, actors: lb.actors, cards, stories, pilot: pf.pilot, cfg, failures });
  if (!pf.pilot.completed_at && ds.pilotStatus.done && latchPilot(pilotFile, nowIso())) {      // the first time the predicate holds: latched for good
    pf = loadPilot(pilotFile); ds = deskState({ reports: lb.reports, actors: lb.actors, cards, stories, pilot: pf.pilot, cfg, failures });
    log(`library-desk: the pilot is complete (latched ${pf.pilot.completed_at})`);
  }
  const canNow = () => { try { const t = now(); return canBuild(t, budgetConfig(), readUsage(t - 7 * 864e5, t), readBuild(BUILD_LEDGER(), t)).ok; } catch { return false; } };
  const gate = canStart || (can != null ? () => !!can : canNow), ok = can != null ? !!can : canStart ? true : canNow();
  const p = plan(ds.state, cfg, ok), tail = badS.length ? `; ${badS.length} story file(s) unreadable, left alone` : "";
  log(`library-desk: mode ${p.mode}; ${ds.state.pilotDone ? "pilot complete" : "pilot not complete: " + ds.pilotStatus.why.join("; ")}; plan read ${p.read}, write ${p.write}, review ${p.review}, audit ${p.audit}${ok ? "" : "; the pipeline needs the usage window"}`);
  if (p.mode === "wait") return end((ok ? "waiting (library.enabled is false)" : "waiting: the pipeline needs the usage window") + tail, p);
  const hm = Math.max(2, Math.min(9, Number(readJson(join(ROOT, "config", "pipeline.json"), {}).headless_foreground_minutes) || 8));
  const hard = Number(process.env.FLOW_HARD_AT) || 0, own = now() + hm * 60000 - 120000;
  const deadline = deadlineMs != null ? deadlineMs : hard ? Math.min(hard - 30000, own) : own;
  const results = await runStages({ plan: p, orders: ds.orders, deps: deps || realDeps(lb), now, deadline, canStart: gate, log });
  const late = ORDER.some((k) => results[k] && results[k].skipped === "no time left");
  return end(`${p.mode}: ${summary(results)}; pilot ${ds.state.pilotDone ? "complete" : "not complete"}${results.halt ? `; stopped: ${results.halt}` : ""}${late ? "; stopped at the deadline" : ""}${tail}`, p, results);
}

function loadAll() {
  const lb = loadLibrary(), cards = loadCards(), stories = loadStories(), cfg = deskConfig(), pf = loadPilot(), failures = loadReadState().failures;
  return { lb, cards, stories, cfg, pilot: pf.pilot, pstate: pf.state, failures };
}
async function main() {
  const cmd = process.argv[2];
  if (cmd === "run") { await run({ deadlineMs: Number(process.env.LIBRARY_DEADLINE_MS) || null }); return; }
  if (cmd === "status") {
    const x = loadAll(), t = Date.now();
    console.log(readStatusLine(x.lb.reports, x.cards, x.failures));
    console.log(`${writeStatusLine([...actorSubjects(x.lb.actors, x.lb.reports, x.cards), ...looseSubjects(x.lb.reports, x.cards, actorIndex(x.lb.actors))], x.stories, x.cards)}`);
    console.log(reviewStatusLine(x.stories, x.cards, x.cfg));
    if (!x.pilot) { console.log(`pilot: ${x.pstate === "bad" ? "data/orkl/pilot.json cannot be read" : "not chosen yet (the first run chooses it)"}`); return; }
    const ds = deskState({ reports: x.lb.reports, actors: x.lb.actors, cards: x.cards, stories: x.stories, pilot: x.pilot, cfg: x.cfg, failures: x.failures });
    let ok = false; try { ok = canBuild(t, budgetConfig(), readUsage(t - 7 * 864e5, t), readBuild(BUILD_LEDGER(), t)).ok; } catch {}
    const p = plan(ds.state, x.cfg, ok);
    console.log(describePilot({ latched: ds.pilotStatus.latched, live: ds.pilotStatus, mode: p.mode }));
    console.log(`backfill ${x.cfg.backfill ? "ON" : "off"}; next run: mode ${p.mode}, read ${p.read}, write ${p.write}, review ${p.review}, audit ${p.audit}`);
    return;
  }
  if (cmd === "pilot-report") {
    const x = loadAll(), t = Date.now();
    let usage = []; try { usage = readUsage(t - 30 * 864e5, t); } catch {}
    console.log(pilotReport(x.cards, x.stories, { pilot: x.pilot, usage, cfg: x.cfg }));
    if (x.pilot) { const ds = deskState({ reports: x.lb.reports, actors: x.lb.actors, cards: x.cards, stories: x.stories, pilot: x.pilot, cfg: x.cfg, failures: x.failures }); console.log(describePilot({ latched: ds.pilotStatus.latched, live: ds.pilotStatus, mode: ds.state.pilotDone ? (x.cfg.backfill ? "backfill" : "steady") : "pilot" })); }
    return;
  }
  console.error("usage: library-desk.mjs run | status | pilot-report"); process.exit(1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
