// The Library's writer desk: for each subject (every ORKL actor, plus unattributed reports with enough detail) Sonnet drafts a
// story from the fact cards (never from report text), the draft is checked (library-check.mjs storyProblems) and stored in
// data/orkl/stories/<key>.json as { live, next }. The writer NEVER publishes and never changes `live` except to mark it `stale`:
// a draft or rejected rewrite goes only to `next`. Run: node scripts/library-write.mjs run [--max N] | status
// A usage limit or a failed model call writes nothing; a real reply that is unusable or fails the check is a `rejected` draft
// (tries + 1, `parked` after two). A story file that cannot be read is never written over.
import { join } from "node:path";
import { existsSync, readdirSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { ROOT, readJson, writeJson, nowIso } from "./lib/store.mjs";
import { DIR, loadLibrary } from "./orkl.mjs";
import { loadCards } from "./library-read.mjs";
import { BY, cleanStory, storyProblems } from "./lib/library-check.mjs";
import { writerPrompt } from "./lib/library-prompts.mjs";
import { oneShot } from "./lib/oneshot.mjs";
import { loadConfig, paused, PAUSE_NOTICE, PAUSE_MESSAGE } from "./lib/library-audit.mjs";
import { actorIndex, actorSubjects, looseSubjects, basedOn } from "./lib/library-subjects.mjs";

export const STORIES_DIR = join(DIR, "stories");
const ROLE = "library-writer";
export const MAX_TRIES = 2;
const STOP_AFTER_ERRORS = 3;
export const MAX_CARDS = 40;                                   // cards given to one prompt, newest reports first (basedOn still covers them all)
const KEY = /^[A-Za-z0-9-]{1,70}$/;
const modelName = () => { const r = ((readJson(join(ROOT, "config", "models.json"), {}) || {}).roles || {})[ROLE]; return (r && r.model) || ""; };

/** One story file: {live:null,next:null} when it does not exist; null when it exists but cannot be read (never write over it). */
export function readStory(dir, key) {
  if (!KEY.test(key)) return null;
  const p = join(dir, `${key}.json`);
  if (!existsSync(p)) return { live: null, next: null };
  const j = readJson(p, null);
  if (!j || typeof j !== "object" || Array.isArray(j)) return null;
  const part = (x) => (x == null ? null : cleanStory(x) || undefined);
  const live = part(j.live), next = part(j.next);
  return live === undefined || next === undefined ? null : { live, next };
}
/** The stored stories by key. An unreadable file is left out and its key pushed onto `bad`. */
export function loadStories(dir = STORIES_DIR, bad = []) {
  const m = new Map();
  if (!existsSync(dir)) return m;
  for (const f of readdirSync(dir)) {
    const key = f.replace(/\.json$/, "");
    if (!f.endsWith(".json") || !KEY.test(key)) continue;
    const s = readStory(dir, key);
    if (s) m.set(key, s); else bad.push(key);
  }
  return m;
}

/** Pure: the subjects to write now. Order: `order` (a key list) first, then those with most read cards, then key. */
export function writeQueue(subjects, stories, cards, { order = null, max = Infinity } = {}) {
  const todo = (subjects || []).filter((s) => {
    const readN = (s.sha1s || []).filter((x) => { const c = cards.get(x); return c && c.status === "read"; }).length;
    if (s.kind === "subject" && !readN) return false;
    const f = stories.get(s.key);
    if (!f || (!f.live && !f.next)) return true;
    const b = basedOn(s, cards);
    if (f.next && f.next.status === "parked" && f.next.based_on === b) return false;   // parked stays parked until its cards change
    if (f.next && f.next.status === "rejected" && (Number(f.next.tries) || 0) < MAX_TRIES) return true;
    return (!f.live || f.live.based_on !== b) && (!f.next || f.next.based_on !== b);
  });
  const rank = new Map((Array.isArray(order) ? order : []).map((k, i) => [k, i]));
  todo.sort((a, b) => (rank.has(a.key) ? rank.get(a.key) : 1e9) - (rank.has(b.key) ? rank.get(b.key) : 1e9)
    || b.sha1s.length - a.sha1s.length || a.key.localeCompare(b.key));
  return todo.slice(0, max);
}

/** Pure: a new draft (or rejected, or parked) goes to `next`; `live` is untouched except that a published one whose cards changed becomes stale. */
export function placeDraft(file, story) {
  const live = file && file.live ? { ...file.live } : null;
  if (live && live.status === "published" && live.based_on !== story.based_on) live.status = "stale";
  return { live, next: story };
}

/** Problem codes only (the part before ":"; bare codes such as `code` and `no-byline` have no colon). Never empty. */
export function codesOf(problems) {
  const c = [...new Set(problems.map((p) => String(p).split(":")[0].trim()).filter((x) => /^[a-z][a-z-]{0,39}$/.test(x)))].slice(0, 10);
  return c.length ? c : ["unknown"];
}

/** Pure: the cards a story is written and checked from: the subject's read cards, newest report first, at most MAX_CARDS. */
export const cardsFor = (subject, all) => (subject.sha1s || []).map((x) => all.get(x)).filter((c) => c && c.status === "read").slice(0, MAX_CARDS);

/** Pure: a model reply -> the story to store. Every system field is set here, never taken from the reply. */
export function buildStory(subject, reply, readCards, ctx) {
  const tries = ctx.tries;
  const base = { key: subject.key, kind: subject.kind, name: subject.name, based_on: ctx.basedOn, by: BY, written_at: ctx.at, writer_model: ctx.model, written_run: ctx.run };
  const reject = (reasons, extra = {}) => ({ ...(cleanStory({ headline: "", in_short: "", sections: [], ...extra, ...base, status: "rejected", tries, reasons })), status: tries >= MAX_TRIES ? "parked" : "rejected" });
  const j = reply && reply.ok && reply.json && typeof reply.json === "object" ? reply.json : null;
  const story = j ? cleanStory({ headline: j.headline, in_short: j.in_short, sections: j.sections, ...base, status: "draft", tries: Math.max(0, tries - 1) }) : null;   // a draft carries the failed attempts before it
  if (!story) return reject(["bad-reply"]);
  const problems = storyProblems(story, readCards, subject.actor);
  if (problems.length) return reject(codesOf(problems), { headline: j.headline, in_short: j.in_short, sections: j.sections });
  return story;
}

/** Draft up to `max` stories. Each is written after its wave: the file is re-read just before the write, and an unreadable one is left alone. */
export async function run({ max = 10, order = null, concurrency = 3, dir = STORIES_DIR, library = null, cards = null, cardsDir = undefined, call = oneShot, model = modelName(), cfg = loadConfig(), log = console.log } = {}) {
  const tally = { drafted: 0, rejected: 0, parked: 0, requeued: 0, stopped: "", unreadable: [] };
  const badCards = [];
  const all = cards || loadCards(cardsDir, badCards);
  if (badCards.length) {                                  // a missing shard would look like cards that vanished and mark live stories stale
    tally.stopped = `unreadable card shards: ${badCards.join(", ")}`;
    log(`library-write: ${tally.stopped}; nothing written`);
    return tally;
  }
  if (paused(all, cfg)) { log(PAUSE_NOTICE); tally.stopped = PAUSE_MESSAGE.toLowerCase(); return tally; }
  const { reports, actors } = library || loadLibrary();
  const subjects = [...actorSubjects(actors, reports, all), ...looseSubjects(reports, all, actorIndex(actors))];
  const badStories = [];
  const stories = loadStories(dir, badStories);
  tally.unreadable = badStories.sort();
  const queue = writeQueue(subjects.filter((s) => !badStories.includes(s.key)), stories, all, { order, max });
  const runId = randomBytes(4).toString("hex");
  let failed = 0;
  const one = async (s) => {
    const cs = cardsFor(s, all);
    const reply = await call(ROLE, writerPrompt(s, cs), { job: "library", batch: s.key });
    if (reply.limit) return { why: "limit" };
    if (reply.error) return { why: "error" };
    const prev = stories.get(s.key), b = basedOn(s, all);
    const tries = (prev && prev.next && prev.next.status === "rejected" && prev.next.based_on === b ? Number(prev.next.tries) || 0 : 0) + 1;
    const story = buildStory(s, reply, new Map(cs.map((c) => [c.sha1, c])), { tries, basedOn: b, at: nowIso(), model, run: runId });
    return { story };
  };
  for (let i = 0; i < queue.length && !tally.stopped; i += concurrency) {
    const wave = queue.slice(i, i + concurrency);
    const results = await Promise.all(wave.map((s) => one(s).catch((e) => {
      log(`${s.key} crashed ${String((e && e.name) || "Error").slice(0, 40)}`);
      return { why: "error" };
    })));
    results.forEach((d, j) => {
      const key = wave[j].key;
      if (!d.story) {
        tally.requeued++; log(`${key} not written (${d.why}), stays queued`);
        if (d.why === "limit") tally.stopped = "usage limit";
        failed = d.why === "error" ? failed + 1 : 0;
        return;
      }
      failed = 0;
      const onDisk = readStory(dir, key);
      if (!onDisk) { tally.unreadable.push(key); tally.requeued++; log(`${key} story file unreadable, left untouched`); return; }
      writeJson(join(dir, `${key}.json`), placeDraft(onDisk, d.story));
      stories.set(key, placeDraft(onDisk, d.story));
      const st = d.story.status;
      tally[st === "draft" ? "drafted" : st]++;
      log(`${key} ${st}${d.story.reasons ? " " + d.story.reasons.join(",") : ""}`);
    });
    if (!tally.stopped && failed >= STOP_AFTER_ERRORS) tally.stopped = `${failed} failed model calls in a row`;
  }
  log(`library-write: ${tally.drafted} drafted, ${tally.rejected} rejected, ${tally.parked} parked, ${tally.requeued} left queued${tally.stopped ? `; stopped: ${tally.stopped}` : ""}`);
  return tally;
}

export function statusLine(subjects, stories, cards) {
  const n = { published: 0, draft: 0, stale: 0, rejected: 0, parked: 0 };
  for (const f of stories.values()) { if (f.live && n[f.live.status] != null) n[f.live.status]++; if (f.next && !f.live) n[f.next.status]++; }
  const queued = writeQueue(subjects, stories, cards, {}).length;
  return `subjects ${subjects.length}, stories ${stories.size}, live published ${n.published} stale ${n.stale}, first drafts ${n.draft} rejected ${n.rejected} parked ${n.parked}, queued ${queued}`;
}

/** --max N from argv: 0 means 0; missing or not a whole number >= 0 means 10. */
export function parseMax(argv) {
  const i = argv.indexOf("--max"), v = i >= 0 ? argv[i + 1] : undefined;
  return v != null && /^\d+$/.test(String(v)) ? Number(v) : 10;
}

async function main() {
  const cmd = process.argv[2];
  if (cmd === "status") {
    const { reports, actors } = loadLibrary(), cards = loadCards();
    console.log(statusLine([...actorSubjects(actors, reports, cards), ...looseSubjects(reports, cards, actorIndex(actors))], loadStories(), cards));
    return;
  }
  if (cmd !== "run") { console.error("usage: library-write.mjs run [--max N] | status"); process.exit(1); }
  await run({ max: parseMax(process.argv) });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
