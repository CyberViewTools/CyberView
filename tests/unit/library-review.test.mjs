import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync, readdirSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BY } from "../../scripts/lib/library-check.mjs";
import { basedOn } from "../../scripts/lib/library-subjects.mjs";
import { writeQueue, STORIES_DIR } from "../../scripts/library-write.mjs";
import * as W from "../../scripts/library-write.mjs";
import * as R from "../../scripts/library-read.mjs";
import { readQueue } from "../../scripts/library-read.mjs";
import { DEFAULTS, reviewQueue, rereadPick, settle, auditPick, auditState, paused, markCardWrong, run, runAudit } from "../../scripts/library-review.mjs";
import { errorReport, libraryErrorReport } from "../../scripts/review.mjs";

const h = (c) => c.repeat(40);
const NOW = "2026-11-26T00:00:00Z";
const facts = (o = {}) => ({ tools: [], techniques: [], sectors: [], countries: [], dates: [], cves: [], actors: [], figures: [], ...o });
const card = (c, o = {}) => ({ sha1: h(c), status: "read", kind: "malware-analysis", summary: "s", subject: null, hedges: [], read_at: "2026-11-01T00:00:00Z", model: "haiku",
  facts: facts({ tools: [{ v: "Mimikatz", q: "the operators used Mimikatz on hosts" }] }), ...o });
const CARDS = new Map([[h("a"), card("a")]]);
const sent = (t, ...cites) => ({ t, cites });
const body = (o = {}) => ({ headline: "Thing uses Mimikatz", in_short: "A short note.", sections: [{ h: "methods", sentences: [sent("The operators used Mimikatz.", h("a"))] }], ...o });
const story = (o = {}) => ({ key: "a-7", kind: "actor", name: "TT", status: "draft", based_on: "b0", tries: 0, by: BY, written_at: "2026-11-25T00:00:00Z", writer_model: "sonnet", written_run: "aaaa1111", ...body(), ...o });
const DRAFT = story(), PUBLISHED = story({ status: "published", headline: "Old", reviewed_at: "2026-11-01T00:00:00Z" });
const UNCITED = body({ sections: [{ h: "methods", sentences: [sent("The operators used Mimikatz.")] }] });

test("settle: pass publishes and stamps the review; the old live story is replaced only then", () => {
  const r = settle({ live: PUBLISHED, next: DRAFT }, { verdict: "pass", changes: [] }, CARDS, null, NOW, "sonnet");
  assert.equal(r.file.next, null);
  assert.equal(r.file.live.status, "published"); assert.equal(r.file.live.headline, DRAFT.headline);
  assert.equal(r.file.live.reviewed_at, NOW); assert.equal(r.file.live.reviewer_model, "sonnet"); assert.deepEqual(r.corrections, []);
});
test("settle: a 'corrected' story that fails the script checks is rejected, and live stays up", () => {
  const f = settle({ live: PUBLISHED, next: DRAFT }, { verdict: "corrected", story: UNCITED, changes: [] }, CARDS, null, NOW, "sonnet");
  assert.equal(f.file.live, PUBLISHED); assert.equal(f.file.next.status, "rejected"); assert.equal(f.file.next.tries, 1);
  assert.ok(f.file.next.reasons.includes("uncited"));
});
test("settle: a clean 'corrected' story is published, with script-owned fields taken from the draft, never from the reviewer", () => {
  const evil = { ...body({ headline: "Thing, corrected" }), key: "evil", kind: "actor", name: "Evil", based_on: "evil", by: "someone", status: "draft", tries: 7, written_run: "ffff", writer_model: "x", written_at: "t" };
  const r = settle({ live: null, next: DRAFT }, { verdict: "corrected", story: evil, changes: [{ code: "wrong", note: "fixed a name" }] }, CARDS, null, NOW, "sonnet");
  const l = r.file.live;
  assert.equal(l.headline, "Thing, corrected"); assert.equal(l.status, "published");
  for (const k of ["key", "kind", "name", "based_on", "by", "written_at", "writer_model", "written_run"]) assert.equal(l[k], DRAFT[k], k);
  assert.equal(l.tries, 0);
  assert.deepEqual(r.corrections.map((c) => [c.role, c.model, c.code, c.at]), [["library-writer", "sonnet", "wrong", NOW]]);
});
test("settle: a pass on a draft that itself fails the checks does not publish", () => {
  const r = settle({ live: PUBLISHED, next: story(UNCITED) }, { verdict: "pass", changes: [] }, CARDS, null, NOW, "sonnet");
  assert.equal(r.file.live, PUBLISHED); assert.equal(r.file.next.status, "rejected");
});
test("settle: reject rejects, counts a try, and a second one parks; live is untouched", () => {
  let r = settle({ live: PUBLISHED, next: DRAFT }, { verdict: "reject", changes: [{ code: "unsupported", note: "no card says it" }] }, CARDS, null, NOW, "sonnet");
  assert.equal(r.file.next.status, "rejected"); assert.equal(r.file.next.tries, 1); assert.equal(r.file.live, PUBLISHED);
  assert.ok(r.file.next.reasons.includes("unsupported"));
  assert.equal(r.corrections[0].code, "unsupported");
  r = settle({ live: PUBLISHED, next: { ...DRAFT, tries: 1 } }, { verdict: "reject", changes: [] }, CARDS, null, NOW, "sonnet");
  assert.equal(r.file.next.status, "parked"); assert.equal(r.file.next.tries, 2);
});
test("settle: a failed reviewer reply changes nothing", () => {
  const file = { live: PUBLISHED, next: DRAFT };
  const r = settle(file, null, CARDS, null, NOW, "sonnet");
  assert.deepEqual(r.file, file); assert.deepEqual(r.corrections, []);
});
test("settle: correction notes are clipped, kept free of code, and unknown codes become other", () => {
  const r = settle({ live: null, next: DRAFT }, { verdict: "reject", changes: [{ code: "zzz", note: "x".repeat(900) }, { code: "wrong", note: "run `rm -rf /` now" }] }, CARDS, null, NOW, "sonnet");
  assert.equal(r.corrections[0].code, "other"); assert.ok(r.corrections[0].note.length <= 300);
  assert.equal(r.corrections[1].note, "");
});

test("reviewQueue: only drafts; rereadPick: most-cited first, ties by first appearance", () => {
  const m = new Map([["a", { live: null, next: story({ status: "draft" }) }], ["b", { live: story(), next: story({ status: "rejected" }) }], ["c", { live: story({ status: "published" }), next: null }]]);
  assert.deepEqual(reviewQueue(m), ["a"]);
  const s = story({ sections: [{ h: "who", sentences: [sent("x", h("c")), sent("y", h("a"), h("b")), sent("z", h("b"), "catalogue")] }] });
  assert.deepEqual(rereadPick(s, 3), [h("b"), h("c"), h("a")]);
  assert.deepEqual(rereadPick(s, 1), [h("b")]);
});

const audited = (n, wrong) => new Map(Array.from({ length: n }, (_, i) => [`${i}`.padStart(40, "0"), { sha1: `${i}`.padStart(40, "0"), status: "read", audit: { at: `2026-11-${10 + (i % 9)}T00:00:00Z`, ok: i >= wrong, note: "" } }]));
test("auditState: pauses above 5% once 50 cards are audited, not before", () => {
  assert.equal(auditState(audited(40, 4), DEFAULTS).paused, false);
  assert.equal(auditState(audited(100, 6), DEFAULTS).paused, true);
  assert.equal(auditState(audited(100, 5), DEFAULTS).paused, false);
  assert.equal(paused(audited(100, 6), DEFAULTS), true);
  assert.deepEqual(DEFAULTS, { reread: 3, audit_pct: 10, audit_pause_pct: 5, audit_min: 50 });
});
test("auditState: counts only the most recent 500 audits", () => {
  const m = new Map();
  for (let i = 0; i < 600; i++) m.set(`${i}`.padStart(40, "0"), { audit: { at: `2026-01-01T00:${String(Math.floor(i / 60)).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}Z`, ok: i >= 100, note: "" } });
  const s = auditState(m, DEFAULTS);
  assert.equal(s.audited, 500); assert.equal(s.wrong, 0); assert.equal(s.paused, false);
});
test("auditPick: deterministic, about the configured share, never re-picks an audited card", () => {
  const cards = new Map();
  for (let i = 0; i < 1000; i++) { const s = (i * 2654435761 >>> 0).toString(16).padStart(8, "0") + `${i}`.padStart(32, "0"); cards.set(s, { sha1: s, status: "read" }); }
  const a = auditPick(cards, 10, new Set());
  assert.ok(a.length >= 60 && a.length <= 140, String(a.length));
  assert.deepEqual(auditPick(cards, 10, new Set()), a);
  cards.set(a[0], { sha1: a[0], status: "read", audit: { at: NOW, ok: true, note: "" } });
  assert.ok(!auditPick(cards, 10, new Set()).includes(a[0]));
  assert.ok(!auditPick(cards, 10, new Set([a[1]])).includes(a[1]));
  assert.equal(auditPick(cards, 100, new Set()).length, 999);
  cards.set(a[2], { sha1: a[2], status: "unread" });
  assert.ok(!auditPick(cards, 100, new Set()).includes(a[2]));
});

test("a card found wrong is queued for re-reading and its stories go stale", () => {
  const two = new Map([[h("a"), card("a")], [h("b"), card("b")]]);
  const subj = { key: "a-7", kind: "actor", name: "TT", actor: null, sha1s: [h("a"), h("b")] };
  const files = new Map([["a-7", { live: story({ status: "published", based_on: basedOn(subj, two) }), next: null }]]);
  assert.equal(writeQueue([subj], files, two, {}).length, 0);
  const bad = markCardWrong(two.get(h("b")), "the figure is wrong", NOW);
  assert.equal(bad.status, "unread"); assert.equal(bad.tries, 0); assert.deepEqual(bad.audit, { at: NOW, ok: false, note: "the figure is wrong" });
  const after = new Map([[h("a"), two.get(h("a"))], [h("b"), bad]]);
  assert.equal(readQueue([{ sha1: h("b") }], after).length, 1);
  assert.equal(writeQueue([subj], files, after, {}).length, 1);
});

test("review.mjs errors: Library corrections are counted by role and model", () => {
  const files = { "s-1": [{ at: "2026-11-25T01:00:00Z", role: "library-writer", model: "sonnet", code: "wrong", note: "n" }, { at: "2026-11-25T02:00:00Z", role: "library-writer", model: "sonnet", code: "tone", note: "n" }],
    [h("a")]: [{ at: "2026-11-25T03:00:00Z", role: "library-reader", model: "haiku", code: "card-wrong", note: "n" }, { at: "2026-10-01T03:00:00Z", role: "library-reader", model: "haiku", code: "card-wrong", note: "old" }] };
  const r = libraryErrorReport(files, Date.parse("2026-11-26T00:00:00Z"), 7);
  assert.equal(r.corrections, 3);
  const w = r.by_writer.find((x) => x.role === "library-writer");
  assert.deepEqual([w.model, w.corrected, w.types], ["sonnet", 2, { wrong: 1, tone: 1 }]);
  assert.equal(r.by_writer.find((x) => x.role === "library-reader").corrected, 1);
  assert.equal(errorReport([], new Map(), Date.parse("2026-11-26T00:00:00Z"), 7).library, undefined);
});

// ---- run ----
const mk = () => mkdtempSync(join(tmpdir(), "lib-review-"));
const SUBJ_CARD = (c) => card(c);
const ACTOR = { id: "7", name: "TT", aliases: [], tools: [] };
const LIB = { reports: [{ sha1: h("a"), id: 1, title: "t", created: "2024-01-01", actors: ["TT"], txt_url: "" }], actors: [ACTOR] };
const setup = (dir, { f = { live: null, next: DRAFT }, cards = CARDS } = {}) => {
  mkdirSync(join(dir, "stories"), { recursive: true }); mkdirSync(join(dir, "cards"), { recursive: true }); mkdirSync(join(dir, "corr"), { recursive: true });
  const subj = { key: "a-7", kind: "actor", name: "TT", actor: ACTOR, sha1s: [h("a")] };
  const next = f.next ? { ...f.next, based_on: basedOn(subj, cards) } : null;
  writeFileSync(join(dir, "stories", "a-7.json"), JSON.stringify({ live: f.live, next }));
  const sh = {}; for (const c of cards.values()) (sh[c.sha1.slice(0, 2)] ||= {})[c.sha1] = c;
  for (const [k, v] of Object.entries(sh)) writeFileSync(join(dir, "cards", `${k}.json`), JSON.stringify(v));
};
// one report card that loads as a looseSubject: needs a subject name and 3 facts
const LOOSE = card("a", { subject: { type: "malware", name: "Thing" }, facts: facts({ tools: [{ v: "Mimikatz", q: "the operators used Mimikatz on hosts" }, { v: "Cobalt", q: "q" }, { v: "Rubeus", q: "q" }] }) });
const TEXT = "x".repeat(500);
const deps = (dir, call, extra = {}) => ({ dir: join(dir, "stories"), cardsDir: join(dir, "cards"), corrDir: join(dir, "corr"), library: LIB, fetch: async () => ({ text: TEXT, partial: false }), call, model: "sonnet", cfg: DEFAULTS, log: () => {}, concurrency: 1, ...extra });
const reply = (json) => async () => ({ ok: true, json, limit: false, error: false });
const files = (dir) => JSON.parse(readFileSync(join(dir, "stories", "a-7.json"), "utf8"));
const loose = () => new Map([[h("a"), card("a")]]);

test("run: a pass publishes, and the reviewer saw the freshly re-read original", async () => {
  const dir = mk(); let prompt = "";
  try {
    setup(dir, { cards: loose() });
    const t = await run({ ...deps(dir, async (_r, p) => { prompt = p; return { ok: true, json: { verdict: "pass", changes: [], card_problems: [] }, limit: false, error: false }; }), max: 5 });
    assert.equal(t.published, 1); assert.equal(files(dir).live.status, "published"); assert.equal(files(dir).next, null);
    assert.ok(prompt.includes(TEXT)); assert.ok(readdirSync(join(dir, "corr")).length === 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: an unreachable original means no review; a 'none' original is reviewed on the rest; no call is made without one", async () => {
  const dir = mk(); let calls = 0;
  try {
    setup(dir, { cards: loose() });
    const t = await run({ ...deps(dir, async () => { calls++; return { ok: true, json: { verdict: "pass", changes: [] } }; }), fetch: async () => ({ error: "unreachable" }), max: 5 });
    assert.equal(calls, 0); assert.equal(files(dir).next.status, "draft"); assert.equal(t.published, 0);
    await run({ ...deps(dir, async () => { calls++; return { ok: true, json: { verdict: "pass", changes: [] } }; }), fetch: async () => ({ error: "none" }), max: 5 });
    assert.equal(calls, 0); assert.equal(files(dir).next.status, "draft");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: a limit stops and changes nothing; failed calls change nothing and three in a row stop", async () => {
  const dir = mk();
  try {
    setup(dir, { cards: loose() });
    const before = readFileSync(join(dir, "stories", "a-7.json"), "utf8");
    const t = await run({ ...deps(dir, async () => ({ ok: false, json: null, limit: true, error: false })), max: 5 });
    assert.equal(t.stopped, "usage limit"); assert.equal(readFileSync(join(dir, "stories", "a-7.json"), "utf8"), before);
    const t2 = await run({ ...deps(dir, async () => ({ ok: false, json: null, limit: false, error: true })), max: 5 });
    assert.equal(readFileSync(join(dir, "stories", "a-7.json"), "utf8"), before); assert.equal(t2.published, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: a reject is recorded as a writer correction with the writer's model; card problems requeue the card and publish nothing", async () => {
  const dir = mk();
  try {
    setup(dir, { cards: loose() });
    await run({ ...deps(dir, reply({ verdict: "reject", changes: [{ code: "unsupported", note: "n" }], card_problems: [] })), max: 5 });
    assert.equal(files(dir).next.status, "rejected");
    const c = JSON.parse(readFileSync(join(dir, "corr", "a-7.json"), "utf8"));
    assert.deepEqual(c.map((x) => [x.role, x.model, x.code]), [["library-writer", "sonnet", "unsupported"]]);
    setup(dir, { cards: loose() });
    await run({ ...deps(dir, reply({ verdict: "pass", changes: [], card_problems: [{ sha1: h("a"), note: "figure differs" }] })), max: 5 });
    assert.equal(files(dir).live, null); assert.equal(files(dir).next.status, "draft");
    const stored = JSON.parse(readFileSync(join(dir, "cards", `${h("a").slice(0, 2)}.json`), "utf8"))[h("a")];
    assert.equal(stored.status, "unread"); assert.equal(stored.tries, 0); assert.equal(stored.audit.ok, false);
    const cc = JSON.parse(readFileSync(join(dir, "corr", `${h("a")}.json`), "utf8"));
    assert.deepEqual([cc[0].role, cc[0].model], ["library-reader", "haiku"]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: a story whose own writer run is this run is not reviewed; a corrections file that cannot be read is not overwritten", async () => {
  const dir = mk();
  try {
    setup(dir, { cards: loose() });
    writeFileSync(join(dir, "corr", "a-7.json"), "{broken");
    await run({ ...deps(dir, reply({ verdict: "reject", changes: [{ code: "wrong", note: "n" }] })), max: 5 });
    assert.equal(readFileSync(join(dir, "corr", "a-7.json"), "utf8"), "{broken");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("runAudit: ok cards get audit ok, wrong cards are requeued, and the audit uses a fresh re-read", async () => {
  const dir = mk();
  try {
    setup(dir, { cards: loose() });
    const t = await runAudit({ ...deps(dir, reply({ ok: false, wrong: [{ path: "tools[0]", note: "not in text" }] })), cfg: { ...DEFAULTS, audit_pct: 100 }, max: 5 });
    assert.equal(t.wrong, 1);
    const stored = JSON.parse(readFileSync(join(dir, "cards", `${h("a").slice(0, 2)}.json`), "utf8"))[h("a")];
    assert.equal(stored.status, "unread"); assert.equal(stored.audit.ok, false); assert.match(stored.audit.note, /tools\[0\]/);
    setup(dir, { cards: loose() });
    const t2 = await runAudit({ ...deps(dir, reply({ ok: true, wrong: [] })), cfg: { ...DEFAULTS, audit_pct: 100 }, max: 5 });
    assert.equal(t2.ok, 1);
    const s2 = JSON.parse(readFileSync(join(dir, "cards", `${h("a").slice(0, 2)}.json`), "utf8"))[h("a")];
    assert.equal(s2.status, "read"); assert.deepEqual(s2.audit, { at: s2.audit.at, ok: true, note: "" });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("pause: the reader and the writer return without calling a model while the reader's accuracy is below target", async () => {
  const dir = mk(); const logs = []; let calls = 0;
  try {
    const cards = audited(100, 10); mkdirSync(join(dir, "c")); const sh = {}; for (const c of cards.values()) (sh[c.sha1.slice(0, 2)] ||= {})[c.sha1] = c; for (const [k, v] of Object.entries(sh)) writeFileSync(join(dir, "c", `${k}.json`), JSON.stringify(v)); const call = async () => { calls++; return { ok: false, limit: false, error: true }; };
    const t1 = await R.run({ dir: join(dir, "c"), library: { reports: [{ sha1: h("a"), created: "2024" }], actors: [] }, call, fetch: async () => ({ text: TEXT }), log: (m) => logs.push(m), cfg: DEFAULTS });
    const t2 = await W.run({ dir: join(dir, "s"), library: { reports: [], actors: [{ id: "7", name: "TT" }] }, cards, call, log: (m) => logs.push(m), cfg: DEFAULTS });
    assert.equal(calls, 0); assert.ok(t1.stopped && t2.stopped);
    assert.ok(logs.some((m) => /Library reader accuracy below target/.test(m)));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("tries: write, reject, rewrite, reject parks the story; the rewrite draft carries the earlier failed attempt", () => {
  const r1 = settle({ live: null, next: DRAFT }, { verdict: "reject", changes: [] }, CARDS, null, NOW, "sonnet").file;
  assert.equal(r1.next.status, "rejected");
  const subj = { key: "a-7", kind: "actor", name: "TT", actor: null, sha1s: [h("a")] };
  const f = new Map([["a-7", { live: null, next: { ...r1.next, based_on: basedOn(subj, CARDS) } }]]);
  assert.equal(writeQueue([subj], f, CARDS, {}).length, 1);
  const rewrite = W.buildStory(subj, { ok: true, json: body() }, CARDS, { tries: r1.next.tries + 1, basedOn: "b0", at: NOW, model: "sonnet", run: "bbbb2222" });
  assert.equal(rewrite.status, "draft"); assert.equal(rewrite.tries, 1);
  const r2 = settle({ live: null, next: rewrite }, { verdict: "reject", changes: [] }, CARDS, null, NOW, "sonnet").file;
  assert.equal(r2.next.status, "parked");
});
test("the reader keeps a failed audit on the card when it reads it again", () => {
  const prev = { ...card("a"), status: "unread", audit: { at: NOW, ok: false, note: "n" } };
  const text = "the operators used Mimikatz on hosts. ".repeat(20);
  const reply = { ok: true, json: { summary: "s", kind: "malware-analysis", subject: null, hedges: [], facts: facts({ tools: [{ v: "Mimikatz", q: "the operators used Mimikatz on hosts" }] }) } };
  const d = R.decide({ sha1: h("a") }, { text, partial: false }, reply, { prev, model: "haiku", at: NOW });
  assert.equal(d.card.status, "read"); assert.deepEqual(d.card.audit, prev.audit);
});
