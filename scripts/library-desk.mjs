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
import { loadCards, readQueue, run as readRun, statusLine as readStatusLine } from "./library-read.mjs";
import { loadStories, writeQueue, run as writeRun, statusLine as writeStatusLine } from "./library-write.mjs";
import { reviewQueue, auditPick, run as reviewRun, runAudit, statusLine as reviewStatusLine } from "./library-review.mjs";
import { loadConfig, auditState, auditFailed, paused, wrongCards, DEFAULTS as AUDIT_DEFAULTS } from "./lib/library-audit.mjs";
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
  if (s.paused) return { read: cap(w.read, s.failedCards), write: 0, review: 0, audit: cap(w.audit, s.auditable), auditPct: 100, mode: !s.pilotDone ? "pilot" : cfg.backfill ? "backfill" : "steady" };
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
  const rest = ranked.filter((x) => !isTop.has(x.s.key)).map((x) => ({ key: x.s.key, name: x.s.name, n: x.n, one: x.n === 1 && inNewest.has(by.get(x.s.actor.id)[0].sha1) }));
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

/** Pure: is the pilot complete, and if not what is missing. Every report has a card that is read, no-text or unread with tries spent;
 *  every read pilot card has the auditor's current verdict; every pilot subject has a published live story or a parked next. */
export function pilotComplete(pilot, cards, stories) {
  const why = [], shas = pilotSha1s(pilot);
  const open = shas.filter((s) => !resolved(cards.get(s))).length;
  if (open) why.push(`${open} report(s) not read yet`);
  const unaudited = shas.filter((s) => { const c = cards.get(s); return c && c.status === "read" && !(c.audit && c.audit.by === "auditor" && c.audit.ok === true); }).length;
  if (unaudited) why.push(`${unaudited} read card(s) without the auditor's verdict`);
  const nostory = pilotKeys(pilot).filter((k) => { const f = stories.get(k); return !(f && ((f.live && f.live.status === "published") || (f.next && f.next.status === "parked"))); });
  if (nostory.length) why.push(`${nostory.length} pilot subject(s) without a published or parked story`);
  return { done: !why.length, why };
}

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
export function deskState({ reports, actors, cards, stories, pilot, cfg }) {
  const ix = actorIndex(actors), c = { ...DESK_DEFAULTS, ...(cfg || {}) };
  const subjects = [...actorSubjects(actors, reports, cards), ...looseSubjects(reports, cards, ix)], subjectKeys = new Set(subjects.map((s) => s.key));
  const done = pilotComplete(pilot, cards, stories), isPaused = paused(cards, c);
  const todo = readQueue(reports, cards, {}), pset = new Set(pilotSha1s(pilot)), isNew = (r) => stampOf(r) > String(pilot.newest_at || "");
  const inPilot = todo.filter((r) => pset.has(r.sha1)), fresh = todo.filter((r) => !pset.has(r.sha1) && isNew(r)), old = todo.filter((r) => !pset.has(r.sha1) && !isNew(r));
  const wq = writeQueue(subjects, stories, cards, {}), pk = new Set(pilotKeys(pilot));
  const hasStory = (k) => { const f = stories.get(k); return !!(f && (f.live || f.next)); };
  const readAfter = (s) => s.sha1s.some((x) => { const k = cards.get(x); return k && k.status === "read" && String(k.read_at || "") >= String(pilot.chosen_at || ""); });
  const pilotQ = wq.filter((s) => pk.has(s.key)), steadyQ = wq.filter((s) => pk.has(s.key) || hasStory(s.key) || readAfter(s));
  const pct = !done.done || isPaused ? 100 : c.audit_pct;
  let readOrder;
  if (isPaused) readOrder = todo.filter((r) => auditFailed(cards.get(r.sha1))).map((r) => r.sha1);
  else if (!done.done) readOrder = inPilot.map((r) => r.sha1);
  else if (c.backfill) { const q = new Set(todo.map((r) => r.sha1)); readOrder = backfillOrder(reports, actors).filter((s) => q.has(s)); }
  else readOrder = fresh.map((r) => r.sha1);
  const state = { pilotDone: done.done, paused: isPaused, failedCards: todo.filter((r) => auditFailed(cards.get(r.sha1))).length,
    pilot: { read: inPilot.length, write: pilotQ.length }, newRecords: fresh.length, backlog: old.length,
    writeNew: steadyQ.length, writeBacklog: wq.length - steadyQ.length, drafts: reviewQueue(stories).filter((k) => subjectKeys.has(k)).length, auditable: auditPick(cards, pct).length };
  const writeOrder = !done.done ? pilotQ.map((s) => s.key) : steadyQ.map((s) => s.key);
  return { state, orders: { read: readOrder, write: writeOrder }, subjectKeys, pilotStatus: done };
}

/* ---------------- the stage loop ---------------- */
const progress = {
  read: (t) => num(t.read) + num(t["no-text"]) + num(t.unread),
  write: (t) => num(t.drafted) + num(t.rejected) + num(t.parked),
  review: (t) => num(t.published) + num(t.corrected) + num(t.rejected) + num(t.parked) + num(t.cardsFlagged),
  audit: (t) => num(t.ok) + num(t.wrong),
};
/** Run the stages in order, each in waves. A wave starts only with `reserveMs(role)` left before `deadline`, and a stage may not use
 *  more than its fair share of the time left once it has done one wave. A stage ends when its quota is spent, a wave made no progress,
 *  or it stopped itself (usage limit, outage). What a wave tried is not listed again. A stage that throws does not stop the others.
 *  deps: { review, audit, write, read }: ({ max, order, pilot }) -> tally. -> { stage: { done, stopped, error, skipped } } */
export async function runStages({ plan: p, orders = {}, deps, now = Date.now, deadline, chunk = CHUNK, pilot = false, log = console.log }) {
  const out = {}, isPilot = pilot || p.mode === "pilot";
  let left = ORDER.filter((k) => num(p[k]) > 0).length;
  for (const k of ORDER) {
    const r = out[k] = { done: 0, stopped: "", error: "", skipped: "" };
    const quota = num(p[k]);
    if (!quota) continue;
    const reserve = reserveMs(ROLES[k]), t0 = now(), share = (deadline - t0) / left--;
    let order = k === "read" ? [...(orders.read || [])] : k === "write" ? [...(orders.write || [])] : null;
    while (r.done < quota) {
      const t = now();
      if (deadline - t < reserve) { r.skipped = "no time left"; break; }
      if (r.done > 0 && t - t0 >= share) { r.skipped = "its share of the time is used"; break; }
      const n = Math.min(num(chunk[k]) || 1, quota - r.done);
      let tally;
      try { tally = (await deps[k]({ max: n, order: order ? [...order] : undefined, pilot: isPilot })) || {}; }
      catch (e) { r.error = String((e && e.name) || "Error").slice(0, 40); log(`library-desk: ${k} failed (${r.error})`); break; }
      r.done += n; if (order) order = order.slice(n);
      if (tally.stopped) { r.stopped = String(tally.stopped); break; }
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
  const cardCost = (roles["library-reader"] || {}).est_usd + (roles["library-auditor"] || {}).est_usd || 0, storyCost = ((roles["library-writer"] || {}).est_usd || 0) + ((roles["library-reviewer"] || {}).est_usd || 0);
  out.push(`Cost per card ${cc.read ? money(cardCost / cc.read) : "n/a"} (per card read, reader and auditor); cost per story ${sc.published ? money(storyCost / sc.published) : "n/a"} (per published story, writer and reviewer)`);
  if (pilot) {
    out.push("Pilot stories:");
    for (const k of pilotKeys(pilot)) { const f = stories.get(k), st = f ? (f.live ? f.live.status : f.next ? f.next.status : "empty") : "no story yet", nm = [...pilot.actors, ...pilot.loose].find((x) => x.key === k); out.push(`  ${k} (${nm ? nm.name : "?"}): ${st}`); }
  }
  return out.join("\n");
}

/** The `library` block of efficiency.json from what is stored now and the usage ledger lines. */
export async function efficiencyBlock(usage, now = Date.now()) {
  const x = loadAll();
  return libraryBlock({ cards: x.cards, stories: x.stories, usage, cfg: x.cfg, now });
}
/** The Library's health for the pipeline check: { paused, wrong (card sha1s), parked, orphans }. */
export async function libraryHealth() {
  const x = loadAll();
  if (!x.lb.reports.length) return { paused: false, wrong: [], parked: 0, orphans: 0 };
  const keys = new Set([...actorSubjects(x.lb.actors, x.lb.reports, x.cards), ...looseSubjects(x.lb.reports, x.cards, actorIndex(x.lb.actors))].map((s) => s.key));
  return { paused: paused(x.cards, x.cfg), wrong: wrongCards(x.cards), parked: storyCounts(x.stories).parked, orphans: reviewQueue(x.stories).filter((k) => !keys.has(k)).length };
}

/* ---------------- the run ---------------- */
function realDeps(library) {
  return {
    review: ({ max }) => reviewRun({ max, library, concurrency: CHUNK.review }),
    audit: ({ max, pilot }) => runAudit({ max, pilot, library, concurrency: CHUNK.audit }),
    write: ({ max, order }) => writeRun({ max, order, library, concurrency: CHUNK.write }),
    read: ({ max, order }) => readRun({ max, order, library, concurrency: CHUNK.read }),
  };
}
const summary = (r) => ORDER.map((k) => `${k} ${r[k] ? r[k].done : 0}${r[k] && (r[k].stopped || r[k].error) ? ` (${r[k].stopped || r[k].error})` : ""}`).join(", ");

/** One desk run. Stamps last_library_at and library_note in status.json when it ends, whatever it did. -> { note, plan, results } */
export async function run({ cfg = deskConfig(), library = null, deps = null, now = Date.now, deadline = null, can = null, log = console.log, statusFile = join(DATA, "status.json"), pilotFile = PILOT_FILE, usageLines = null } = {}) {
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
  const badS = [], stories = loadStories(undefined, badS);
  const ds = deskState({ reports: lb.reports, actors: lb.actors, cards, stories, pilot: pf.pilot, cfg });
  let ok = can;
  if (ok == null) { try { const t = now(), lines = readUsage(t - 7 * 864e5, t); ok = canBuild(t, budgetConfig(), lines, readBuild(BUILD_LEDGER(), t)).ok; } catch { ok = false; } }
  const p = plan(ds.state, cfg, !!ok);
  log(`library-desk: mode ${p.mode}; pilot ${ds.state.pilotDone ? "complete" : "not complete: " + ds.pilotStatus.why.join("; ")}; plan read ${p.read}, write ${p.write}, review ${p.review}, audit ${p.audit}${ok ? "" : "; the pipeline needs the usage window"}`);
  if (p.mode === "wait") return end(ok ? "waiting (library.enabled is false)" : "waiting: the pipeline needs the usage window", p);
  const hm = Math.max(2, Math.min(9, Number(readJson(join(ROOT, "config", "pipeline.json"), {}).headless_foreground_minutes) || 8));
  const hard = Number(process.env.FLOW_HARD_AT) || 0, own = now() + hm * 60000 - 120000;
  const results = await runStages({ plan: p, orders: ds.orders, deps: deps || realDeps(lb), now, deadline: deadline != null ? deadline : hard ? Math.min(hard, own) : own, log });
  return end(`${p.mode}: ${summary(results)}; pilot ${ds.state.pilotDone ? "complete" : "not complete"}`, p, results);
}

function loadAll() {
  const lb = loadLibrary(), cards = loadCards(), stories = loadStories(), cfg = deskConfig(), pf = loadPilot();
  return { lb, cards, stories, cfg, pilot: pf.pilot, pstate: pf.state };
}
async function main() {
  const cmd = process.argv[2];
  if (cmd === "run") { await run(); return; }
  if (cmd === "status") {
    const x = loadAll(), t = Date.now();
    console.log(readStatusLine(x.lb.reports, x.cards));
    console.log(`${writeStatusLine([...actorSubjects(x.lb.actors, x.lb.reports, x.cards), ...looseSubjects(x.lb.reports, x.cards, actorIndex(x.lb.actors))], x.stories, x.cards)}`);
    console.log(reviewStatusLine(x.stories, x.cards, x.cfg));
    if (!x.pilot) { console.log(`pilot: ${x.pstate === "bad" ? "data/orkl/pilot.json cannot be read" : "not chosen yet (the first run chooses it)"}`); return; }
    const ds = deskState({ reports: x.lb.reports, actors: x.lb.actors, cards: x.cards, stories: x.stories, pilot: x.pilot, cfg: x.cfg });
    let ok = false; try { ok = canBuild(t, budgetConfig(), readUsage(t - 7 * 864e5, t), readBuild(BUILD_LEDGER(), t)).ok; } catch {}
    const p = plan(ds.state, x.cfg, ok);
    console.log(`pilot: ${ds.state.pilotDone ? "complete" : "not complete (" + ds.pilotStatus.why.join("; ") + ")"}; backfill ${x.cfg.backfill ? "ON" : "off"}; next run: mode ${p.mode}, read ${p.read}, write ${p.write}, review ${p.review}, audit ${p.audit}`);
    return;
  }
  if (cmd === "pilot-report") {
    const x = loadAll(), t = Date.now();
    let usage = []; try { usage = readUsage(t - 30 * 864e5, t); } catch {}
    console.log(pilotReport(x.cards, x.stories, { pilot: x.pilot, usage, cfg: x.cfg }));
    return;
  }
  console.error("usage: library-desk.mjs run | status | pilot-report"); process.exit(1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
