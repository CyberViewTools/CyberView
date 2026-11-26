// The Library's reader desk: each ORKL report's text is fetched, Haiku turns it into a fact card (scripts/lib/library-prompts.mjs),
// the card is checked against the text (scripts/lib/library-check.mjs) and ONLY the card is stored, in data/orkl/cards/<shard>.json
// keyed by the report's sha1. The report text lives in one local variable inside readOne() and is never written, logged or returned
// by run(). Run: node scripts/library-read.mjs run [--max N] | status   (behind a proxy: NODE_USE_ENV_PROXY=1)
// A card is `read`, `no-text` (ORKL has no text, or under TEXT_MIN characters) or `unread` (the model's card failed the check; it
// is tried once more, tries < 2). ORKL unreachable, a usage limit, or a failed model call (CLI missing, API error, timeout) writes
// nothing: the record stays queued with its tries unchanged.
import { join } from "node:path";
import { existsSync, readdirSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { ROOT, readJson, writeJson, nowIso } from "./lib/store.mjs";
import { DIR, loadLibrary, shardOf } from "./orkl.mjs";
import { prepText, fetchText, TEXT_MIN } from "./lib/orkl-text.mjs";
import { cleanCard, cardProblems } from "./lib/library-check.mjs";
import { readerPrompt } from "./lib/library-prompts.mjs";
import { oneShot } from "./lib/oneshot.mjs";
import { loadConfig, paused, auditFailed, PAUSE_NOTICE, PAUSE_MESSAGE } from "./lib/library-audit.mjs";

export const CARDS_DIR = join(DIR, "cards");
const ROLE = "library-reader";
const MAX_TRIES = 2;
const STOP_AFTER_ERRORS = 3;
const STOP_AFTER_UNREACHABLE = 5;
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
/** Pure: the records still to read: no card, or an `unread` card tried fewer than MAX_TRIES times. order "newest" or a sha1 list (listed first, in that order, then newest). */
export function readQueue(reports, cards, { order = "newest", max = Infinity } = {}) {
  const todo = (reports || []).filter((r) => {
    const c = cards.get ? cards.get(r.sha1) : cards[r.sha1];
    return !c || (c.status === "unread" && (Number(c.tries) || 0) < MAX_TRIES);
  });
  const rank = Array.isArray(order) ? new Map(order.map((s, i) => [s, i])) : new Map();
  todo.sort((a, b) => (rank.has(a.sha1) ? rank.get(a.sha1) : 1e9) - (rank.has(b.sha1) ? rank.get(b.sha1) : 1e9)
    || stamp(b).localeCompare(stamp(a)) || a.sha1.localeCompare(b.sha1));
  return todo.slice(0, max);
}

/** Pure: the whole outcome table. { card, retry }: card null = nothing is written; retry = the record stays queued untouched.
 *  `ctx` carries the previous card (for tries), the time and the model name. */
export function decide(report, fetched, reply, ctx = {}) {
  const d = decideNow(report, fetched, reply, ctx), p = ctx.prev || {};
  // a card read again: its old audit moves into audit_history (last 5) and the new card has no current audit, so it is audited afresh
  const hist = [...(Array.isArray(p.audit_history) ? p.audit_history : []), ...(p.audit ? [p.audit] : [])].slice(-5);
  if (d.card && hist.length) d.card = { ...d.card, audit_history: hist };
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

const tallyZero = () => ({ read: 0, "no-text": 0, unread: 0, requeued: 0, stopped: "", unreadableShards: [] });

/** Read up to `max` records. Cards are written per shard after each wave of `concurrency` reports: the shard is re-read from disk
 *  just before the write and the wave's cards merged into it, so another run's cards survive; a shard that cannot be read is never written. */
export async function run({ max = 10, order = "newest", concurrency = 4, dir = CARDS_DIR, library = null, fetch = fetchText, call = oneShot, model = modelName(), cfg = loadConfig(), log = console.log } = {}) {
  const { reports } = library || loadLibrary();
  const bad = new Set();
  const badList = [];
  const cards = loadCards(dir, badList);
  badList.forEach((b) => bad.add(b));
  const isPaused = paused(cards, cfg);
  if (isPaused) log(PAUSE_NOTICE);                      // while paused only the cards an audit found wrong are read again
  const queue = readQueue(reports.filter((r) => !bad.has(shardOf(r.sha1)) && (!isPaused || auditFailed(cards.get(r.sha1)))), cards, { order, max });
  const tally = tallyZero();
  let failedCalls = 0, outage = 0;
  for (let i = 0; i < queue.length && !tally.stopped; i += concurrency) {
    const wave = queue.slice(i, i + concurrency);
    const results = await Promise.all(wave.map((r) => readOne(r, cards.get(r.sha1), { fetch, call, model }).catch((e) => {
      log(`${r.sha1.slice(0, 8)} crashed ${String((e && e.name) || "Error").slice(0, 40)} ${String((e && e.code) || "").slice(0, 40)}`.trim());
      return { card: null, retry: true, why: "error" };
    })));
    const fresh = [];
    results.forEach((d, j) => {
      const id = wave[j].sha1.slice(0, 8);
      if (d.card) { fresh.push(d.card); log(`${id} ${d.card.status}${d.card.reason ? " " + d.card.reason : ""}`); }
      else { tally.requeued++; log(`${id} not read (${d.why || "retry"}), stays queued`); }
      if (d.why === "limit") tally.stopped = "usage limit";
      failedCalls = d.why === "error" ? failedCalls + 1 : d.why === "unreachable" ? failedCalls : 0;
      outage = d.why === "unreachable" ? outage + 1 : 0;
    });
    const written = saveCards(dir, fresh, bad);
    for (const c of written) { tally[c.status]++; cards.set(c.sha1, c); }
    tally.requeued += fresh.length - written.length;
    if (!tally.stopped && outage >= STOP_AFTER_UNREACHABLE) tally.stopped = "ORKL unreachable";
    if (!tally.stopped && failedCalls >= STOP_AFTER_ERRORS) tally.stopped = `${failedCalls} failed model calls in a row`;
  }
  tally.unreadableShards = [...bad].sort();
  if (bad.size) log(`library-read: ${bad.size} shard(s) unreadable, left untouched: ${tally.unreadableShards.join(", ")}`);
  log(`library-read: ${tally.read} read, ${tally["no-text"]} no-text, ${tally.unread} unread, ${tally.requeued} left queued${tally.stopped ? `; stopped: ${tally.stopped}` : ""}`);
  return tally;
}

export function statusLine(reports, cards) {
  const n = { read: 0, "no-text": 0, unread: 0 };
  for (const r of reports) { const c = cards.get(r.sha1); if (c && n[c.status] != null) n[c.status]++; }
  const queued = readQueue(reports, cards, { max: Infinity }).length;
  return `reports ${reports.length}, read ${n.read}, no-text ${n["no-text"]}, unread ${n.unread}, queued ${queued}, share read ${reports.length ? (100 * n.read / reports.length).toFixed(1) : "0.0"}%`;
}

async function main() {
  const cmd = process.argv[2];
  if (cmd === "status") { console.log(statusLine(loadLibrary().reports, loadCards())); return; }
  if (cmd !== "run") { console.error("usage: library-read.mjs run [--max N] | status"); process.exit(1); }
  const mi = process.argv.indexOf("--max");
  await run({ max: mi >= 0 ? Number(process.argv[mi + 1]) || 10 : 10 });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
