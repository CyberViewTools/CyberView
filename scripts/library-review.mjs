// The Library's review desk and the reader audit. NOTHING becomes `live` except through settle() here.
//   run   : for each draft story, the reviewer (Sonnet, library-reviewer, a separate call from the writer's) checks it against its
//           fact cards and against freshly re-read original reports (the most-cited ones, DEFAULTS.reread of them). The report text
//           exists only inside reviewOne(); it is never stored or logged. A verdict is only advice: settle() takes the reviewer's
//           corrected story as text, carries every script-owned field from the draft and runs the same script checks as the writer.
//   audit : Sonnet (library-auditor) re-checks a share of the Haiku reader's cards against the report text. A card found wrong (by the
//           auditor or the reviewer) keeps `audit: { ok: false }`, goes back to `unread` to be read again, and every story that rests on
//           it goes stale (the writer's basedOn counts read cards only). The reader's error rate over the last 500 audits pauses the
//           reader and the writer (library-audit.mjs auditState/paused) and this desk's `run`; `audit` always runs, so the rate can recover.
//   corrections: data/orkl/corrections/<story key or card sha1>.json, a list of { at, role, model, code, note }: role "library-writer"
//           for story corrections and "library-reader" for cards, with the model that wrote the thing corrected (counted by
//           `node scripts/review.mjs errors`). Kept apart from data/corrections/, which holds event corrections.
// A usage limit stops new work and changes nothing; a failed call changes nothing (three in a row stop); an unreachable original means
// the story is not reviewed this run. Usage: node scripts/library-review.mjs run [--max N] | audit [--max N] | status
import { join } from "node:path";
import { existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { ROOT, readJson, writeJson, nowIso } from "./lib/store.mjs";
import { NOCODE } from "./lib/validate.mjs";
import { loadLibrary } from "./orkl.mjs";
import { CARDS_DIR, loadCards, saveCards } from "./library-read.mjs";
import { STORIES_DIR, MAX_TRIES, loadStories, readStory, buildStory, cardsFor, codesOf } from "./library-write.mjs";
import { cleanStory, storyProblems } from "./lib/library-check.mjs";
import { reviewerPrompt, auditorPrompt } from "./lib/library-prompts.mjs";
import { fetchText } from "./lib/orkl-text.mjs";
import { oneShot } from "./lib/oneshot.mjs";
import { actorIndex, actorSubjects, looseSubjects, basedOn } from "./lib/library-subjects.mjs";
import { DEFAULTS, auditState, paused, loadConfig, PAUSE_MESSAGE, CORRECTIONS_DIR } from "./lib/library-audit.mjs";

export { DEFAULTS, auditState, paused };
const ROLE = "library-reviewer", AUDIT_ROLE = "library-auditor";
const STOP_AFTER_ERRORS = 3, STOP_AFTER_UNREACHABLE = 5, CORRECTIONS_KEEP = 200;
const CODES = ["unsupported", "wrong", "attribution", "hedge-lost", "tone", "other"];
const HEX40 = /^[0-9a-f]{40}$/;
const modelOf = (role) => { const r = ((readJson(join(ROOT, "config", "models.json"), {}) || {}).roles || {})[role]; return (r && r.model) || ""; };

/** Keys of the story files that hold a draft waiting for review. */
export const reviewQueue = (stories) => [...stories].filter(([, f]) => f && f.next && f.next.status === "draft").map(([k]) => k).sort();

/** Pure: the card sha1s a story cites most (ties: first appearance), at most `max`. */
export function rereadPick(story, max) {
  const n = new Map();
  for (const sec of (story && story.sections) || []) for (const s of sec.sentences || []) for (const c of s.cites || []) if (HEX40.test(c)) n.set(c, (n.get(c) || 0) + 1);
  return [...n.keys()].map((k, i) => ({ k, i, n: n.get(k) })).sort((a, b) => b.n - a.n || a.i - b.i).slice(0, Math.max(0, max)).map((x) => x.k);
}

/** A note as stored: one line, 300 characters, and "" when it looks like code (the build's NOCODE rule). */
export function cleanNote(s) {
  const t = String(s == null ? "" : s).replace(/<[^>]*>/g, " ").replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, 300);
  return NOCODE.test(t) ? "" : t;
}
const cleanChanges = (list) => (Array.isArray(list) ? list : []).filter((c) => c && typeof c === "object").slice(0, 10)
  .map((c) => ({ code: CODES.includes(c.code) ? c.code : "other", note: cleanNote(c.note) }));

/** Pure: apply a reviewer's verdict to a story file. Returns { file, corrections }. `verdict` null (no usable reply) changes nothing.
 *  `cards` is the card set the writer used (read cards only, same cap and order); `actor` the catalogue record or null. */
export function settle(file, verdict, cards, actor, now, model) {
  const next = file && file.next;
  if (!next || next.status !== "draft" || !verdict || typeof verdict !== "object") return { file, corrections: [] };
  const changes = cleanChanges(verdict.changes), tries = (Number(next.tries) || 0) + 1;
  const subject = { key: next.key, kind: next.kind, name: next.name, actor: actor || null };
  const cm = cards instanceof Map ? cards : new Map();
  const writerFault = changes.length ? changes.map((c) => ({ at: now, role: "library-writer", model: next.writer_model || "", code: c.code, note: c.note })) : [{ at: now, role: "library-writer", model: next.writer_model || "", code: "other", note: "" }];
  const refuse = (reasons, corrections) => ({ file: { live: file.live, next: { ...next, status: tries >= MAX_TRIES ? "parked" : "rejected", tries, reasons: reasons.slice(0, 10) } }, corrections });
  const publish = (story, corrections) => {
    const s = cleanStory({ ...story, status: "published", tries: 0, reviewed_at: now, reviewer_model: model });
    return { file: { live: s, next: null }, corrections };
  };
  if (verdict.verdict === "pass") {
    const problems = storyProblems(next, cm, subject.actor);
    return problems.length ? refuse(codesOf(problems), []) : publish(next, []);
  }
  if (verdict.verdict === "corrected") {
    const built = buildStory(subject, { ok: true, json: verdict.story }, cm, { tries, basedOn: next.based_on, at: next.written_at, model: next.writer_model, run: next.written_run });
    return built.status === "draft" ? publish(built, writerFault) : refuse(built.reasons || ["bad-reply"], writerFault);
  }
  if (verdict.verdict === "reject") return refuse(["review-reject", ...new Set(changes.map((c) => c.code))], writerFault);
  return refuse(["bad-reply"], []);          // a real reply with no usable verdict counts as a try, like the writer's bad-reply
}

/** Pure: a card the reviewer or auditor found wrong goes back to the reader's queue. */
export const markCardWrong = (card, note, at) => ({ ...card, status: "unread", tries: 0, reason: "audit-wrong", audit: { at, ok: false, note: cleanNote(note) } });

/** Pure: the cards to audit now: a fixed share by sha1, never one already audited or in `seen`, never one that is not `read`. */
export function auditPick(cards, pct, seen = new Set()) {
  const all = cards instanceof Map ? [...cards.values()] : Array.isArray(cards) ? cards : Object.values(cards || {});
  return all.filter((c) => c && HEX40.test(String(c.sha1)) && !c.audit && !seen.has(c.sha1) && (!c.status || c.status === "read")
    && parseInt(String(c.sha1).slice(0, 8), 16) % 100 < pct).map((c) => c.sha1).sort();
}

/** Append to <dir>/<key>.json (a list). A file that exists but cannot be read is never written over. Returns whether it was written. */
export function appendCorrections(dir, key, entries) {
  if (!entries.length || !/^[A-Za-z0-9-]{1,70}$/.test(key)) return false;
  const p = join(dir, `${key}.json`);
  const old = existsSync(p) ? readJson(p, null) : [];
  if (!Array.isArray(old)) return false;
  writeJson(p, [...old, ...entries].slice(-CORRECTIONS_KEEP));
  return true;
}

const subjectsOf = (library, cards) => {
  const { reports, actors } = library;
  return new Map([...actorSubjects(actors, reports, cards), ...looseSubjects(reports, cards, actorIndex(actors))].map((s) => [s.key, s]));
};

/** Fetch the originals; { originals } or { why }. why "unreachable" means no review. */
async function reread(shas, reportBy, fetch) {
  const originals = [];
  for (const sha1 of shas) {
    const r = reportBy.get(sha1), f = r ? await fetch(r) : { error: "none" };
    if (f.error === "unreachable") return { why: "unreachable" };
    if (!f.error && typeof f.text === "string" && f.text.trim()) originals.push({ sha1, text: f.text });
  }
  return { originals };
}

async function reviewOne(key, draft, subj, all, deps) {
  const cs = cardsFor(subj, all), cardMap = new Map(cs.map((c) => [c.sha1, c]));
  const picks = rereadPick(draft, deps.cfg.reread).filter((x) => cardMap.has(x));
  const got = await reread(picks, deps.reportBy, deps.fetch);
  if (got.why) return { why: got.why };
  if (picks.length && !got.originals.length) return { why: "no-original" };
  const reply = await deps.call(ROLE, reviewerPrompt(draft, cs, got.originals), { job: "library", batch: key });
  if (reply.limit) return { why: "limit" };
  if (reply.error) return { why: "error" };
  const j = reply.ok && reply.json && typeof reply.json === "object" ? reply.json : { verdict: "unusable" };
  const cp = (Array.isArray(j.card_problems) ? j.card_problems : []).filter((p) => p && cardMap.has(String(p.sha1).toLowerCase())).slice(0, 10);
  return cp.length ? { cardProblems: cp.map((p) => ({ sha1: String(p.sha1).toLowerCase(), note: p.note })), cardMap } : { verdict: j, cardMap };
}

/** Mark cards wrong: stored through the reader's shard write, with a correction on each. Returns the sha1s written. */
function flagCards(items, all, deps, bad) {
  const at = nowIso(), marked = items.map((p) => all.get(p.sha1) && markCardWrong(all.get(p.sha1), p.note, at)).filter(Boolean);
  const written = saveCards(deps.cardsDir, marked, bad);
  for (const c of written) {
    all.set(c.sha1, c);
    const p = items.find((x) => x.sha1 === c.sha1);
    appendCorrections(deps.corrDir, c.sha1, [{ at, role: "library-reader", model: c.model || "", code: "card-wrong", note: cleanNote(p && p.note) }]);
  }
  return written.map((c) => c.sha1);
}

/** Review up to `max` draft stories. */
export async function run({ max = 10, concurrency = 2, dir = STORIES_DIR, cardsDir = CARDS_DIR, corrDir = CORRECTIONS_DIR, library = null, cards = null, fetch = fetchText, call = oneShot, model = modelOf(ROLE), cfg = loadConfig(), log = console.log } = {}) {
  const tally = { published: 0, rejected: 0, parked: 0, cardsFlagged: 0, skipped: 0, stopped: "", unreadable: [] };
  const badCards = [], all = cards || loadCards(cardsDir, badCards);
  if (badCards.length) { tally.stopped = `unreadable card shards: ${badCards.join(", ")}`; log(`library-review: ${tally.stopped}; nothing written`); return tally; }
  if (paused(all, cfg)) { log(PAUSE_MESSAGE); tally.stopped = PAUSE_MESSAGE.toLowerCase(); return tally; }
  const lib = library || loadLibrary(), subjects = subjectsOf(lib, all);
  const badStories = [], stories = loadStories(dir, badStories);
  tally.unreadable = badStories.sort();
  const queue = reviewQueue(stories).filter((k) => !badStories.includes(k) && subjects.has(k)).slice(0, max);
  const runId = randomBytes(4).toString("hex"), badShards = new Set();
  const deps = { cfg, fetch, call, cardsDir, corrDir, reportBy: new Map((lib.reports || []).map((r) => [r.sha1, r])) };
  let failed = 0, unreachable = 0;
  for (let i = 0; i < queue.length && !tally.stopped; i += concurrency) {
    const wave = queue.slice(i, i + concurrency);
    const results = await Promise.all(wave.map((key) => {
      const draft = stories.get(key).next, subj = subjects.get(key);
      if (draft.written_run && draft.written_run === runId) return { why: "same-run" };
      if (draft.based_on !== basedOn(subj, all)) return { why: "stale" };           // its cards changed: the writer rewrites it first
      return reviewOne(key, draft, subj, all, deps).catch((e) => { log(`${key} crashed ${String((e && e.name) || "Error").slice(0, 40)}`); return { why: "error" }; });
    }));
    for (const [j, d] of results.entries()) {
      const key = wave[j], draft = stories.get(key).next, subj = subjects.get(key);
      if (d.why) {
        tally.skipped++; log(`${key} not reviewed (${d.why}), stays a draft`);
        if (d.why === "limit") tally.stopped = "usage limit";
        failed = d.why === "error" ? failed + 1 : d.why === "unreachable" ? failed : 0;
        unreachable = d.why === "unreachable" ? unreachable + 1 : 0;
        continue;
      }
      failed = 0; unreachable = 0;
      if (d.cardProblems) {
        const n = flagCards(d.cardProblems, all, { cardsDir, corrDir }, badShards);
        tally.cardsFlagged += n.length; log(`${key} not settled: ${n.length} card(s) sent back to be read again`);
        continue;
      }
      const onDisk = readStory(dir, key);
      if (!onDisk) { tally.unreadable.push(key); log(`${key} story file unreadable, left untouched`); continue; }
      const n = onDisk.next;
      if (!n || n.status !== "draft" || n.written_at !== draft.written_at || n.written_run !== draft.written_run || n.based_on !== basedOn(subj, all)) { tally.skipped++; log(`${key} changed meanwhile, not settled`); continue; }
      const r = settle(onDisk, d.verdict, d.cardMap, subj.actor, nowIso(), model);
      if (r.file === onDisk) { tally.skipped++; continue; }
      writeJson(join(dir, `${key}.json`), r.file);
      stories.set(key, r.file);
      const wrote = appendCorrections(corrDir, key, r.corrections);
      const st = r.file.next ? r.file.next.status : "published";
      tally[st === "published" ? "published" : st]++;
      log(`${key} ${st}${r.file.next && r.file.next.reasons ? " " + r.file.next.reasons.join(",") : ""}${r.corrections.length && !wrote ? " (corrections file unreadable, not written)" : ""}`);
    }
    if (!tally.stopped && unreachable >= STOP_AFTER_UNREACHABLE) tally.stopped = "ORKL unreachable";
    if (!tally.stopped && failed >= STOP_AFTER_ERRORS) tally.stopped = `${failed} failed model calls in a row`;
  }
  log(`library-review: ${tally.published} published, ${tally.rejected} rejected, ${tally.parked} parked, ${tally.cardsFlagged} cards sent back, ${tally.skipped} left as drafts${tally.stopped ? `; stopped: ${tally.stopped}` : ""}`);
  return tally;
}

/** Audit up to `max` of the reader's cards against freshly fetched report text. Pilot: every card is picked until audit_min are audited. */
export async function runAudit({ max = 10, concurrency = 2, cardsDir = CARDS_DIR, corrDir = CORRECTIONS_DIR, library = null, fetch = fetchText, call = oneShot, cfg = loadConfig(), log = console.log } = {}) {
  const tally = { ok: 0, wrong: 0, skipped: 0, stopped: "" };
  const badCards = [], all = loadCards(cardsDir, badCards);
  if (badCards.length) { tally.stopped = `unreadable card shards: ${badCards.join(", ")}`; log(`library-audit: ${tally.stopped}; nothing written`); return tally; }
  const lib = library || loadLibrary(), reportBy = new Map((lib.reports || []).map((r) => [r.sha1, r]));
  const pct = auditState(all, cfg).audited < cfg.audit_min ? 100 : cfg.audit_pct;
  const queue = auditPick(all, pct, new Set()).filter((s) => reportBy.has(s)).slice(0, max);
  const badShards = new Set();
  let failed = 0, unreachable = 0;
  const one = async (sha1) => {
    const f = await fetch(reportBy.get(sha1));
    if (f.error === "unreachable") return { why: "unreachable" };
    if (f.error || !f.text || !String(f.text).trim()) return { why: "no-text" };
    const reply = await call(AUDIT_ROLE, auditorPrompt(all.get(sha1), f.text), { job: "library", batch: sha1.slice(0, 8) });
    if (reply.limit) return { why: "limit" };
    if (reply.error) return { why: "error" };
    const j = reply.ok && reply.json && typeof reply.json === "object" ? reply.json : null;
    if (!j || typeof j.ok !== "boolean" || !Array.isArray(j.wrong)) return { why: "bad-reply" };
    const wrong = j.wrong.filter((w) => w && typeof w === "object").slice(0, 10);
    return { ok: j.ok && !wrong.length, note: wrong.map((w) => `${String(w.path || "").slice(0, 40)}: ${String(w.note || "")}`).join("; ") };
  };
  for (let i = 0; i < queue.length && !tally.stopped; i += concurrency) {
    const wave = queue.slice(i, i + concurrency);
    const results = await Promise.all(wave.map((s) => one(s).catch((e) => { log(`${s.slice(0, 8)} crashed ${String((e && e.name) || "Error").slice(0, 40)}`); return { why: "error" }; })));
    const at = nowIso(), good = [], bad = [];
    results.forEach((d, j) => {
      const sha1 = wave[j];
      if (d.why) {
        tally.skipped++; log(`${sha1.slice(0, 8)} not audited (${d.why})`);
        if (d.why === "limit") tally.stopped = "usage limit";
        failed = d.why === "error" ? failed + 1 : d.why === "unreachable" ? failed : 0;
        unreachable = d.why === "unreachable" ? unreachable + 1 : 0;
      } else { failed = 0; unreachable = 0; (d.ok ? good : bad).push({ sha1, note: d.note }); }
    });
    const okCards = good.map((g) => ({ ...all.get(g.sha1), audit: { at, ok: true, note: "" } }));
    for (const c of saveCards(cardsDir, okCards, badShards)) { all.set(c.sha1, c); tally.ok++; }
    tally.wrong += flagCards(bad, all, { cardsDir, corrDir }, badShards).length;
    for (const b of bad) log(`${b.sha1.slice(0, 8)} audit: wrong`);
    if (!tally.stopped && unreachable >= STOP_AFTER_UNREACHABLE) tally.stopped = "ORKL unreachable";
    if (!tally.stopped && failed >= STOP_AFTER_ERRORS) tally.stopped = `${failed} failed model calls in a row`;
  }
  const st = auditState(all, cfg);
  log(`library-audit: ${tally.ok} ok, ${tally.wrong} wrong, ${tally.skipped} not audited${tally.stopped ? `; stopped: ${tally.stopped}` : ""}; reader error rate ${st.pct.toFixed(1)}% of ${st.audited} audited${st.paused ? " (PAUSED)" : ""}`);
  return tally;
}

export function statusLine(stories, cards, cfg = DEFAULTS) {
  const st = auditState(cards, cfg);
  return `drafts waiting ${reviewQueue(stories).length}, audited ${st.audited} cards, wrong ${st.wrong} (${st.pct.toFixed(1)}%), ${st.paused ? "PAUSED: " + PAUSE_MESSAGE : "not paused"}`;
}

async function main() {
  const cmd = process.argv[2];
  if (cmd === "status") { console.log(statusLine(loadStories(), loadCards(), loadConfig())); return; }
  if (cmd !== "run" && cmd !== "audit") { console.error("usage: library-review.mjs run [--max N] | audit [--max N] | status"); process.exit(1); }
  const i = process.argv.indexOf("--max"), v = i >= 0 ? process.argv[i + 1] : undefined, max = v != null && /^\d+$/.test(v) ? Number(v) : 10;
  await (cmd === "run" ? run({ max }) : runAudit({ max }));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
