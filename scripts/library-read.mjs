// The Library's reader desk: each ORKL report's text is fetched, Haiku turns it into a fact card (scripts/lib/library-prompts.mjs),
// the card is checked against the text (scripts/lib/library-check.mjs) and ONLY the card is stored, in data/orkl/cards/<shard>.json
// keyed by the report's sha1. The report text lives in one local variable inside readOne() and is never written, logged or returned
// by run(). Run: node scripts/library-read.mjs run [--max N] --owner-override | status (the desk calls run() in-process; the CLI run refuses without the override)   (behind a proxy: NODE_USE_ENV_PROXY=1)
// A card is `read`, `no-text` (ORKL has no text, or under TEXT_MIN characters) or `unread` (the model's card failed the check; it
// is tried once more, tries < 2). ORKL unreachable, a usage limit, or a failed model call (CLI missing, API error, timeout) writes
// nothing: the record stays queued with its tries unchanged, but its failure count in data/orkl/read-state.json goes up (FAIL_LAST failures:
// it goes last in the queue; FAIL_PARK: parked for PARK_DAYS; a written card clears it). A no-text card is read once more after 30 days.
// A run where ORKL answered for 5 or more reports and 80% or more had no text writes no no-text card (stopped "ORKL text missing").
import { join } from "node:path";
import { existsSync, readdirSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { ROOT, readJson, writeJson, nowIso } from "./lib/store.mjs";
import { DIR, loadLibrary, shardOf } from "./orkl.mjs";
import { prepText, fetchText, TEXT_MIN } from "./lib/orkl-text.mjs";
import { cleanCard, cardProblems } from "./lib/library-check.mjs";
import { readerPrompt } from "./lib/library-prompts.mjs";
import { oneShot, withTimeout } from "./lib/oneshot.mjs";
import { loadConfig, paused, auditFailed, PAUSE_NOTICE, PAUSE_MESSAGE } from "./lib/library-audit.mjs";

export const CARDS_DIR = join(DIR, "cards");
export const READ_STATE_FILE = join(DIR, "read-state.json");   // per-record failure counts: { failures: { sha1: { n, last_at, parked_until? } } }
export const FAIL_LAST = 3, FAIL_PARK = 6, PARK_DAYS = 7;
const ROLE = "library-reader";
export const MAX_TRIES = 2;
const STOP_AFTER_ERRORS = 3;
const STOP_AFTER_UNREACHABLE = 5;
// a run in which ORKL answered for at least SYSTEMIC_MIN reports and SYSTEMIC_SHARE or more of them had no text is treated as ORKL's text
// missing everywhere (an outage that answers), not as that many reports without text: no no-text card is written and the run stops
const SYSTEMIC_MIN = 5, SYSTEMIC_SHARE = 0.8;
const modelName = () => { const r = ((readJson(join(ROOT, "config", "models.json"), {}) || {}).roles || {})[ROLE]; return (r && r.model) || ""; };

/** One shard file: {} when it does not exist yet; null when it exists but is not a JSON object (unreadable: never write over it). */
export function readShard(dir, sh) {
  const p = join(dir, `${sh}.json`);
  if (!existsSync(p)) return {};
  const j = readJson(p, null);
  return j && typeof j === "object" && !Array.isArray(j) ? j : null;
}
/** The stored cards by shard: {shard: {sha1: card}}. An unreadable shard is left out and its name pushed onto `bad`. */
export function loadStore(dir = CARDS_DIR, bad = []) {
  const store = {};
  if (!existsSync(dir)) return store;
  for (const f of readdirSync(dir)) {
    if (!/^[0-9a-f]{2}\.json$/.test(f)) continue;
    const sh = f.slice(0, 2), s = readShard(dir, sh);
    if (s) store[sh] = s; else bad.push(sh);
  }
  return store;
}
/** Every stored card by sha1. Unreadable shards are named in `bad`, not read as empty. */
export function loadCards(dir = CARDS_DIR, bad = []) {
  const m = new Map();
  for (const shard of Object.values(loadStore(dir, bad))) for (const [k, c] of Object.entries(shard)) m.set(k, c);
  return m;
}
/** Pure: fold cards into the sharded store, additively (a card is replaced by its newer version; nothing else is dropped). */
export function mergeCards(store, cards) {
  const out = {};
  for (const [k, v] of Object.entries(store || {})) out[k] = { ...(v || {}) };
  for (const c of cards || []) {
    if (!c || !/^[0-9a-f]{40}$/.test(String(c.sha1 || ""))) continue;
    (out[shardOf(c.sha1)] || (out[shardOf(c.sha1)] = {}))[c.sha1] = c;
  }
  return out;
}

const stamp = (r) => String(r.created || r.file_date || "");
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");

/** The reader's per-record failure counts: { state: "none" | "ok" | "bad", failures }. A file that exists but cannot be read is "bad" and is never written over. */
export function loadReadState(file = READ_STATE_FILE) {
  if (!existsSync(file)) return { state: "none", failures: {} };
  const j = readJson(file, null);
  return j && typeof j === "object" && !Array.isArray(j) && j.failures && typeof j.failures === "object" && !Array.isArray(j.failures) ? { state: "ok", failures: j.failures } : { state: "bad", failures: {} };
}
/** Pure: the failure counts after a run: each failed sha1 (ORKL unreachable or a failed model call) + 1, parked for PARK_DAYS from FAIL_PARK
 *  failures on; each cleared sha1 (a card was written) dropped. Nothing else changes. */
export function bumpFailures(failures, { failed = [], cleared = [] } = {}, now = Date.now()) {
  const out = { ...(failures || {}) };
  for (const s of failed) {
    const n = (Number(out[s] && out[s].n) || 0) + 1, e = { n, last_at: iso(now) };
    if (n >= FAIL_PARK) e.parked_until = iso(now + PARK_DAYS * 864e5);
    out[s] = e;
  }
  for (const s of cleared) delete out[s];
  return out;
}
const failN = (failures, s) => Number(failures && failures[s] && failures[s].n) || 0;
const isParked = (failures, s, now) => { const e = failures && failures[s]; return !!e && !!e.parked_until && Date.parse(e.parked_until) > now; };
/** Pure: the sha1s parked now (FAIL_PARK failures, their PARK_DAYS not over). */
export const parkedRecords = (failures, now = Date.now()) => Object.keys(failures || {}).filter((s) => isParked(failures, s, now)).sort();
/** Re-read the state file just before writing and apply this run's outcomes (additive). An unreadable file is left alone. */
export function saveReadState(file, outcome, now = Date.now()) {
  const cur = loadReadState(file);
  if (cur.state === "bad") return false;
  if (!outcome.failed.length && !outcome.cleared.some((s) => cur.failures[s])) return true;
  writeJson(file, { failures: bumpFailures(cur.failures, outcome, now) });
  return true;
}
export const NO_TEXT_RETRY_DAYS = 30;
/** Pure: a no-text card is read once more, NO_TEXT_RETRY_DAYS after its read_at (ORKL may have added the text); the retry's card says
 *  `retried`, so it is never retried again. */
export const noTextDue = (c, now = Date.now()) => !!c && c.status === "no-text" && c.retried !== true && Date.parse(c.read_at) + NO_TEXT_RETRY_DAYS * 864e5 <= now;
/** Pure: the records still to read: no card, or an `unread` card tried fewer than MAX_TRIES times. order "newest" or a sha1 list (listed first, in that order, then newest).
 *  only: true with a sha1 list restricts the queue to that list (the desk always passes it, so its gates are never filled from elsewhere). */
export function readQueue(reports, cards, { order = "newest", max = Infinity, only = false, now = Date.now(), failures = {} } = {}) {
  const rank = Array.isArray(order) ? new Map(order.map((s, i) => [s, i])) : new Map();
  const todo = (reports || []).filter((r) => {
    if (only && Array.isArray(order) && !rank.has(r.sha1)) return false;
    if (isParked(failures, r.sha1, now)) return false;                   // FAIL_PARK failures: left alone for PARK_DAYS
    const c = cards.get ? cards.get(r.sha1) : cards[r.sha1];
    return !c || (c.status === "unread" && (Number(c.tries) || 0) < MAX_TRIES) || noTextDue(c, now);
  });
  // a record that failed FAIL_LAST times or more goes last, so it cannot hold the queue (and the pilot) up
  todo.sort((a, b) => (failN(failures, a.sha1) >= FAIL_LAST) - (failN(failures, b.sha1) >= FAIL_LAST)
    || (rank.has(a.sha1) ? rank.get(a.sha1) : 1e9) - (rank.has(b.sha1) ? rank.get(b.sha1) : 1e9)
    || stamp(b).localeCompare(stamp(a)) || a.sha1.localeCompare(b.sha1));
  return todo.slice(0, max);
}

/** Pure: the whole outcome table. { card, retry }: card null = nothing is written; retry = the record stays queued untouched.
 *  `ctx` carries the previous card (for tries), the time and the model name. */
export function decide(report, fetched, reply, ctx = {}) {
  const d = decideNow(report, fetched, reply, ctx), p = ctx.prev || {};
  // the one retry of a no-text card is recorded on whatever card it produces, so it is not retried again
  if (d.card && p.status === "no-text") d.card = { ...d.card, retried: true };
  // a card read again: its old audit moves into audit_history (last 5) and the new card has no current audit, so it is audited afresh
  const hist = [...(Array.isArray(p.audit_history) ? p.audit_history : []), ...(p.audit ? [p.audit] : [])].slice(-5);
  if (d.card && hist.length) d.card = { ...d.card, audit_history: hist };
  // the owner's withdrawal (library-review.mjs withdraw) stays on the card whatever a later read makes of the report
  if (d.card && p.withdrawn === true) d.card = { ...d.card, withdrawn: true, withdrawn_at: String(p.withdrawn_at || "").slice(0, 40), withdrawn_reason: String(p.withdrawn_reason || "").slice(0, 200) };
  return d;
}
function decideNow(report, fetched, reply, ctx) {
  const sha1 = report.sha1, at = ctx.at || nowIso(), model = ctx.model == null ? modelName() : ctx.model;
  const tries = (ctx.prev && ctx.prev.status === "unread" ? Number(ctx.prev.tries) || 0 : 0) + 1;
  const f = fetched || {};
  if (f.error === "unreachable") return { card: null, retry: true };
  if (f.error === "none" || String(f.text == null ? "" : f.text).trim().length < TEXT_MIN) {
    return { card: cleanCard({ status: "no-text", reason: f.error === "none" ? "no text at ORKL" : "text too short", read_at: at, model }, sha1), retry: false };
  }
  if (!reply || reply.limit || reply.error) return { card: null, retry: true };
  const unread = (reason) => ({ card: { ...cleanCard({ status: "unread", reason, read_at: at, model }, sha1), tries }, retry: false });
  if (!reply.ok || !reply.json) return unread("bad-reply");
  const card = cleanCard({ ...reply.json, status: "read", partial: f.partial === true, read_at: at, model, reason: "" }, sha1);
  if (!card) return unread("bad-reply");
  const problems = cardProblems(card, f.text);
  if (problems.length) return unread([...new Set(problems.map((p) => p.split(":")[0]).filter((c) => /^[a-z][a-z-]{0,39}$/.test(c)))].slice(0, 3).join(", "));
  return { card, retry: false };
}

/** One report: fetch, ask, decide. The text exists only inside this function. `why` says why nothing was written: "unreachable", "limit" or "error". */
async function readOne(report, prev, deps) {
  const fetched = await deps.fetch(report);
  const ctx = { prev, model: deps.model };
  if (fetched.error) return { ...decide(report, fetched, null, ctx), why: fetched.error === "unreachable" ? "unreachable" : "" };
  const { text, partial } = prepText(fetched.text);
  const f = { text, partial: fetched.partial === true || partial };
  if (text.trim().length < TEXT_MIN) return { ...decide(report, f, null, ctx), why: "" };
  const reply = await deps.call(ROLE, readerPrompt(report, text), { job: "library", batch: report.sha1.slice(0, 8) });
  const d = decide(report, f, reply, ctx);
  return { ...d, why: d.card ? "" : reply.limit ? "limit" : "error" };
}

/** Write cards into their shards, additively: each shard is re-read from disk just before its write; a shard that cannot be read is
 *  never written (its name goes onto `bad`). Returns the cards written. */
export function saveCards(dir, fresh, bad = new Set()) {
  const written = [];
  for (const sh of new Set(fresh.map((c) => shardOf(c.sha1)))) {
    const mine = fresh.filter((c) => shardOf(c.sha1) === sh);
    const onDisk = readShard(dir, sh);
    if (!onDisk) { bad.add(sh); continue; }
    writeJson(join(dir, `${sh}.json`), mergeCards({ [sh]: onDisk }, mine)[sh]);
    written.push(...mine);
  }
  return written;
}

const tallyZero = () => ({ read: 0, "no-text": 0, unread: 0, held: 0, requeued: 0, stopped: "", unreadableShards: [] });

/** The no-text guard's counter: how many reports ORKL answered for, how many of them had no text, whether the systemic rule
 *  (SYSTEMIC_MIN answered, SYSTEMIC_SHARE or more of them none) was ever met, and the no-text cards held in memory until the rule is settled.
 *  One `run` makes its own. The desk reads CHUNK.read (4) at a time, fewer than SYSTEMIC_MIN, so it makes ONE for all the reader calls
 *  of a desk run and passes it into each: the count then spans the whole read stage, and the desk settles it at the stage's end. */
export const noTextGuard = () => ({ answered: 0, none: 0, met: false, pending: [] });
const MISSING = "ORKL text missing";
/** Settle a guard: when the rule was never met, write its held no-text cards (additively, as saveCards does); when it was met, write
 *  none of them, so the records stay queued. The guard is emptied either way. -> { missing, written, held, unreadableShards } */
export function settleNoText(guard, { dir = CARDS_DIR, stateFile = dir === CARDS_DIR ? READ_STATE_FILE : join(dir, "read-state.json"), log = console.log } = {}) {
  const held = guard.pending.splice(0), bad = new Set();
  if (guard.met) {
    log(`library-read: ${guard.none} of ${guard.answered} answered reports had no text: ORKL's text looks missing, no no-text card written, the records stay queued`);
    return { missing: true, written: [], held: held.length, unreadableShards: [] };
  }
  const written = held.length ? saveCards(dir, held, bad) : [];
  if (written.length) saveReadState(stateFile, { failed: [], cleared: written.map((c) => c.sha1) });   // saveReadState never writes over a file it cannot read
  return { missing: false, written, held: held.length, unreadableShards: [...bad].sort() };
}

/** Read up to `max` records. `guard`: a shared noTextGuard (the desk's): this call adds to its counts, leaves its no-text cards held
 *  in it (tally.held) and does not settle it; the caller does, once, with settleNoText. Without one the run settles its own at the end.
 *  Cards are written per shard after each wave of `concurrency` reports: the shard is re-read from disk
 *  just before the write and the wave's cards merged into it, so another run's cards survive; a shard that cannot be read is never written. */
export async function run({ max = 10, order = "newest", only = false, concurrency = 4, dir = CARDS_DIR, stateFile = dir === CARDS_DIR ? READ_STATE_FILE : join(dir, "read-state.json"), library = null, fetch = fetchText, call = oneShot, model = modelName(), cfg = loadConfig(), timeoutMs = 0, guard = null, log = console.log } = {}) {
  call = withTimeout(call, timeoutMs);
  const g = guard || noTextGuard();
  const { reports } = library || loadLibrary();
  const bad = new Set();
  const badList = [];
  const cards = loadCards(dir, badList);
  badList.forEach((b) => bad.add(b));
  const isPaused = paused(cards, cfg);
  if (isPaused) log(PAUSE_NOTICE);                      // while paused only the cards an audit found wrong are read again
  const rs = loadReadState(stateFile);
  if (rs.state === "bad") log("library-read: read-state.json cannot be read; failure counts are not kept this run");
  const queue = readQueue(reports.filter((r) => !bad.has(shardOf(r.sha1)) && (!isPaused || auditFailed(cards.get(r.sha1)))), cards, { order, max, only, failures: rs.failures });
  const tally = tallyZero();
  let failedCalls = 0, outage = 0;
  for (let i = 0; i < queue.length && !tally.stopped; i += concurrency) {
    const wave = queue.slice(i, i + concurrency);
    const results = await Promise.all(wave.map((r) => readOne(r, cards.get(r.sha1), { fetch, call, model }).catch((e) => {
      log(`${r.sha1.slice(0, 8)} crashed ${String((e && e.name) || "Error").slice(0, 40)} ${String((e && e.code) || "").slice(0, 40)}`.trim());
      return { card: null, retry: true, why: "error", crashed: true };
    })));
    const fresh = [], failed = [];
    results.forEach((d, j) => {
      if (!d.card && (d.why === "unreachable" || d.why === "error")) failed.push(wave[j].sha1);
      const id = wave[j].sha1.slice(0, 8);
      if (d.why !== "unreachable" && !d.crashed) g.answered++;        // ORKL answered for this report (text or none)
      if (d.card && d.card.status === "no-text") { g.none++; g.pending.push(d.card); tally.held++; log(`${id} no-text${d.card.reason ? " " + d.card.reason : ""} (held until the no-text rule is settled)`); }
      else if (d.card) { fresh.push(d.card); log(`${id} ${d.card.status}${d.card.reason ? " " + d.card.reason : ""}`); }
      else { tally.requeued++; log(`${id} not read (${d.why || "retry"}), stays queued`); }
      if (d.why === "limit") tally.stopped = "usage limit";
      failedCalls = d.why === "error" ? failedCalls + 1 : d.why === "unreachable" ? failedCalls : 0;
      outage = d.why === "unreachable" ? outage + 1 : 0;
    });
    const written = saveCards(dir, fresh, bad);
    for (const c of written) { tally[c.status]++; cards.set(c.sha1, c); }
    tally.requeued += fresh.length - written.length;
    if (rs.state !== "bad") saveReadState(stateFile, { failed, cleared: written.map((c) => c.sha1) });
    if (!tally.stopped && outage >= STOP_AFTER_UNREACHABLE) tally.stopped = "ORKL unreachable";
    if (!tally.stopped && failedCalls >= STOP_AFTER_ERRORS) tally.stopped = `${failedCalls} failed model calls in a row`;
    // the rule, over the guard's whole count (every reader call of a desk run): once met it stays met. It stops this call, but an
    // earlier stop reason (a usage limit above all, which ends the whole desk run) is never overwritten
    if (g.answered >= SYSTEMIC_MIN && g.none >= SYSTEMIC_SHARE * g.answered) { g.met = true; if (!tally.stopped) tally.stopped = MISSING; }
  }
  if (!guard) {                                               // this run's own guard: settled here; a shared one is the caller's to settle
    const s = settleNoText(g, { dir, stateFile, log });
    for (const c of s.written) { tally[c.status]++; cards.set(c.sha1, c); }
    tally.requeued += s.held - s.written.length; tally.held = 0;
    s.unreadableShards.forEach((b) => bad.add(b));
  }
  tally.unreadableShards = [...bad].sort();
  if (bad.size) log(`library-read: ${bad.size} shard(s) unreadable, left untouched: ${tally.unreadableShards.join(", ")}`);
  log(`library-read: ${tally.read} read, ${tally["no-text"]} no-text, ${tally.unread} unread, ${tally.held ? `${tally.held} no-text held, ` : ""}${tally.requeued} left queued${tally.stopped ? `; stopped: ${tally.stopped}` : ""}`);
  return tally;
}

export function statusLine(reports, cards, failures = {}, now = Date.now()) {
  const n = { read: 0, "no-text": 0, unread: 0 };
  for (const r of reports) { const c = cards.get(r.sha1); if (c && n[c.status] != null) n[c.status]++; }
  const queued = readQueue(reports, cards, { max: Infinity, failures, now }).length, parked = parkedRecords(failures, now);
  return `reports ${reports.length}, read ${n.read}, no-text ${n["no-text"]}, unread ${n.unread}, queued ${queued}, share read ${reports.length ? (100 * n.read / reports.length).toFixed(1) : "0.0"}%, parked after ${FAIL_PARK} failures ${parked.length}${parked.length ? ` (${parked.slice(0, 10).map((s) => s.slice(0, 8)).join(", ")})` : ""}`;
}

const OWNER_OVERRIDE = "--owner-override";
/** The stage CLIs bypass the desk's pilot, backfill and usage-window gates, so they refuse unless the owner passes --owner-override. */
const refuseOutsideDesk = (name) => { if (process.argv.includes(OWNER_OVERRIDE)) return false; console.error(`${name}: refused. The Library desk (node scripts/library-desk.mjs run) runs this stage with its pilot, backfill and usage-window gates; to run it by hand anyway, pass ${OWNER_OVERRIDE}.`); process.exitCode = 1; return true; };
async function main() {
  const cmd = process.argv[2];
  if (cmd === "status") { console.log(statusLine(loadLibrary().reports, loadCards(), loadReadState().failures)); return; }
  if (cmd !== "run") { console.error("usage: library-read.mjs run [--max N] [--owner-override] | status"); process.exit(1); }
  if (refuseOutsideDesk("library-read run")) return;
  const mi = process.argv.indexOf("--max");
  await run({ max: mi >= 0 ? Number(process.argv[mi + 1]) || 10 : 10 });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
