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
import { pauseHelp, wrongCards, PAUSE_NOTICE } from "../../scripts/lib/library-audit.mjs";
import { DEFAULTS, cleanNote, reviewQueue, rereadPick, statusLine, settle, auditPick, auditState, paused, markCardWrong, run, runAudit } from "../../scripts/library-review.mjs";
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
test("settle: a clean 'corrected' story is never published: it becomes a new draft for a later run, script-owned fields from the draft", () => {
  const evil = { ...body({ headline: "Thing, corrected" }), key: "evil", kind: "actor", name: "Evil", based_on: "evil", by: "someone", status: "published", tries: 7, written_run: "ffff", writer_model: "x", written_at: "t", corrections: 0 };
  const r = settle({ live: PUBLISHED, next: DRAFT }, { verdict: "corrected", story: evil, changes: [{ code: "wrong", note: "fixed a name" }] }, CARDS, null, NOW, "sonnet", "rrrr9999");
  assert.equal(r.file.live, PUBLISHED);
  const n = r.file.next;
  assert.equal(n.headline, "Thing, corrected"); assert.equal(n.status, "draft"); assert.equal(n.written_run, "rrrr9999"); assert.equal(n.corrected_by, "sonnet"); assert.equal(n.corrections, 1);
  for (const k of ["key", "kind", "name", "based_on", "by", "written_at", "writer_model", "tries"]) assert.equal(n[k], DRAFT[k], k);
  assert.deepEqual(r.corrections.map((c) => [c.role, c.model, c.code, c.at]), [["library-writer", "sonnet", "wrong", NOW]]);
  // a later run passes it and it goes live
  const p = settle(r.file, { verdict: "pass", changes: [] }, CARDS, null, NOW, "sonnet", "later000");
  assert.equal(p.file.live.headline, "Thing, corrected"); assert.equal(p.file.live.status, "published"); assert.equal(p.file.next, null);
});
test("settle: the third correction in a row is a rejection (correction-loop)", () => {
  const c = (f) => settle(f, { verdict: "corrected", story: body({ headline: "Again" }), changes: [] }, CARDS, null, NOW, "sonnet", "r1");
  let f = c({ live: null, next: DRAFT }).file; assert.equal(f.next.corrections, 1);
  f = c(f).file; assert.equal(f.next.corrections, 2); assert.equal(f.next.status, "draft");
  f = c(f).file; assert.equal(f.next.status, "rejected"); assert.deepEqual(f.next.reasons, ["correction-loop"]); assert.equal(f.next.tries, 1);
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
test("settle: a failed reviewer reply or an unusable verdict changes nothing", () => {
  const file = { live: PUBLISHED, next: DRAFT };
  const r = settle(file, null, CARDS, null, NOW, "sonnet");
  assert.deepEqual(r.file, file); assert.deepEqual(r.corrections, []);
  assert.deepEqual(settle(file, { verdict: "unusable" }, CARDS, null, NOW, "sonnet").file, file);
});
test("settle: correction notes are clipped, kept free of code, and unknown codes become other", () => {
  const r = settle({ live: null, next: DRAFT }, { verdict: "reject", changes: [{ code: "zzz", note: "x".repeat(900) }, { code: "wrong", note: "run `rm -rf /` now" }] }, CARDS, null, NOW, "sonnet");
  assert.equal(r.corrections[0].code, "other"); assert.ok(r.corrections[0].note.length <= 160);
  assert.equal(r.corrections[1].note, "");
});

test("reviewQueue: only drafts; rereadPick: most-cited first, ties by first appearance", () => {
  const m = new Map([["a", { live: null, next: story({ status: "draft" }) }], ["b", { live: story(), next: story({ status: "rejected" }) }], ["c", { live: story({ status: "published" }), next: null }]]);
  assert.deepEqual(reviewQueue(m), ["a"]);
  const s = story({ sections: [{ h: "who", sentences: [sent("x", h("c")), sent("y", h("a"), h("b")), sent("z", h("b"), "catalogue")] }] });
  assert.deepEqual(rereadPick(s, 3), [h("b"), h("c"), h("a")]);
  assert.deepEqual(rereadPick(s, 1), [h("b")]);
});

const audited = (n, wrong) => new Map(Array.from({ length: n }, (_, i) => [`${i}`.padStart(40, "0"), { sha1: `${i}`.padStart(40, "0"), status: "read", audit: { at: `2026-11-${10 + (i % 9)}T00:00:00Z`, ok: i >= wrong, note: "", by: "auditor" } }]));
test("auditState: pauses above 5% once 50 cards are audited, not before", () => {
  assert.equal(auditState(audited(40, 4), DEFAULTS).paused, false);
  assert.equal(auditState(audited(100, 6), DEFAULTS).paused, true);
  assert.equal(auditState(audited(100, 5), DEFAULTS).paused, false);
  assert.equal(paused(audited(100, 6), DEFAULTS), true);
  assert.deepEqual(DEFAULTS, { reread: 3, audit_pct: 10, audit_pause_pct: 5, audit_min: 50 });
});
test("auditState: counts only the most recent 500 audits", () => {
  const m = new Map();
  for (let i = 0; i < 600; i++) m.set(`${i}`.padStart(40, "0"), { audit: { at: `2026-01-01T00:${String(Math.floor(i / 60)).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}Z`, ok: i >= 100, note: "", by: "auditor" } });
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
  assert.equal(bad.status, "unread"); assert.equal(bad.tries, 0); assert.deepEqual(bad.audit, { at: NOW, ok: false, note: "the figure is wrong", by: "auditor" });
  assert.equal(markCardWrong(two.get(h("b")), "n", NOW, "reviewer").audit.by, "reviewer");
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
    assert.equal(calls, 0); assert.equal(files(dir).next.status, "parked");        // every original gone: it can never be reviewed
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
    assert.equal(s2.status, "read"); assert.deepEqual(s2.audit, { at: s2.audit.at, ok: true, note: "", by: "auditor" });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("pause: the reader and the writer return without calling a model while the reader's accuracy is below target", async () => {
  const dir = mk(); const logs = []; let calls = 0;
  try {
    const cards = audited(100, 10); mkdirSync(join(dir, "c")); const sh = {}; for (const c of cards.values()) (sh[c.sha1.slice(0, 2)] ||= {})[c.sha1] = c; for (const [k, v] of Object.entries(sh)) writeFileSync(join(dir, "c", `${k}.json`), JSON.stringify(v)); const call = async () => { calls++; return { ok: false, limit: false, error: true }; };
    const t1 = await R.run({ dir: join(dir, "c"), library: { reports: [{ sha1: h("a"), created: "2024" }], actors: [] }, call, fetch: async () => ({ text: TEXT }), log: (m) => logs.push(m), cfg: DEFAULTS });
    const t2 = await W.run({ dir: join(dir, "s"), library: { reports: [], actors: [{ id: "7", name: "TT" }] }, cards, call, log: (m) => logs.push(m), cfg: DEFAULTS });
    assert.equal(calls, 0); assert.ok(t2.stopped); assert.equal(t1.read, 0);
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
test("a re-read card moves its old audit into audit_history (capped at 5) and has no current audit", () => {
  const prev = { ...card("a"), status: "unread", audit: { at: NOW, ok: false, note: "n", by: "auditor" }, audit_history: Array.from({ length: 5 }, (_, i) => ({ at: `2026-01-0${i + 1}T00:00:00Z`, ok: true, note: "" })) };
  const text = "the operators used Mimikatz on hosts. ".repeat(20);
  const rep = { ok: true, json: { summary: "s", kind: "malware-analysis", subject: null, hedges: [], facts: facts({ tools: [{ v: "Mimikatz", q: "the operators used Mimikatz on hosts" }] }) } };
  const d = R.decide({ sha1: h("a") }, { text, partial: false }, rep, { prev, model: "haiku", at: "2026-11-27T00:00:00Z" });
  assert.equal(d.card.status, "read"); assert.equal(d.card.audit, undefined);
  assert.equal(d.card.audit_history.length, 5); assert.equal(d.card.audit_history[4].ok, false); assert.equal(d.card.audit_history[0].at, "2026-01-02T00:00:00Z");
});
test("auditPick: a card with audit history and no current audit is always picked; one with a current audit never", () => {
  const sha = (i) => i.toString(16).padStart(8, "0") + "0".repeat(32);
  const withHist = { sha1: sha(99), status: "read", audit_history: [{ at: NOW, ok: false, note: "" }] };      // 99 % 100 is not under pct 0
  const cur = { sha1: sha(5), status: "read", audit: { at: NOW, ok: true, note: "", by: "auditor" }, audit_history: [{ at: NOW, ok: false, note: "" }] };
  const cards = new Map([[withHist.sha1, withHist], [cur.sha1, cur], [sha(98), { sha1: sha(98), status: "read" }]]);
  assert.deepEqual(auditPick(cards, 0, new Set()), [withHist.sha1]);
});
test("audit: pilot audits every unaudited read card; otherwise the configured share", async () => {
  const dir = mk();
  try {
    mkdirSync(join(dir, "cards"), { recursive: true });
    const sh = {}, reports = [];
    for (let i = 0; i < 200; i++) { const s = i.toString(16).padStart(8, "0") + "0".repeat(32); (sh[s.slice(0, 2)] ||= {})[s] = { ...card("a"), sha1: s }; reports.push({ sha1: s, id: i }); }
    for (const [k, v] of Object.entries(sh)) writeFileSync(join(dir, "cards", `${k}.json`), JSON.stringify(v));
    const d = (extra) => ({ ...deps(dir, reply({ ok: true, wrong: [] })), library: { reports, actors: [] }, concurrency: 20, max: 500, ...extra });
    const t0 = await runAudit(d({}));                       // not pilot, nothing audited yet: still only the share (i % 100 < 10 -> 20 cards)
    assert.equal(t0.ok, 20);
    const t1 = await runAudit(d({ pilot: true }));
    assert.equal(t1.ok, 180);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("auditState: only auditor verdicts count; a reviewer flag alone never changes it", () => {
  const m = audited(60, 0);
  const first = [...m.values()][0];
  m.set(first.sha1, { ...first, status: "unread", audit: { at: NOW, ok: false, note: "x", by: "reviewer" } });
  const s = auditState(m, DEFAULTS);
  assert.equal(s.wrong, 0); assert.equal(s.audited, 59);
});
test("auditState: 3 wrong of 50 pauses; re-read and audited ok clears it; counted once by the latest auditor verdict", () => {
  const m = audited(50, 3);
  assert.equal(auditState(m, DEFAULTS).paused, true);
  const text = "the operators used Mimikatz on hosts. ".repeat(20);
  const rep = { ok: true, json: { summary: "s", kind: "malware-analysis", subject: null, hedges: [], facts: facts({ tools: [{ v: "Mimikatz", q: "the operators used Mimikatz on hosts" }] }) } };
  for (const c of [...m.values()].slice(0, 3)) {
    const d = R.decide({ sha1: c.sha1 }, { text, partial: false }, rep, { prev: { ...c, status: "unread" }, model: "haiku", at: "2026-12-01T00:00:00Z" });
    m.set(c.sha1, d.card);
  }
  assert.equal(auditState(m, DEFAULTS).wrong, 3);             // read again but not yet audited: still counted wrong
  assert.equal(auditState(m, DEFAULTS).paused, true);
  for (const c of [...m.values()].slice(0, 3)) m.set(c.sha1, { ...c, audit: { at: "2026-12-02T00:00:00Z", ok: true, note: "", by: "auditor" } });
  const s = auditState(m, DEFAULTS);
  assert.equal(s.audited, 50); assert.equal(s.wrong, 0); assert.equal(s.paused, false);
});
test("pause: the reader while paused touches only audit-failed cards; the review run stays paused; pauseHelp is exported", async () => {
  const dir = mk(), logs = []; const called = [];
  try {
    const cards = audited(60, 6); mkdirSync(join(dir, "c"));
    const hex = [...cards.keys()];
    const reports = hex.map((s) => ({ sha1: s, created: "2024" }));
    const mine = new Map(cards);
    const failed = mine.get(hex[0]); mine.set(hex[0], { ...failed, status: "unread", tries: 0 });
    const extra = "e".repeat(40); mine.set(extra, { sha1: extra, status: "unread", tries: 0 }); reports.push({ sha1: extra, created: "2025" });
    const sh = {}; for (const c of mine.values()) (sh[c.sha1.slice(0, 2)] ||= {})[c.sha1] = c;
    for (const [k, v] of Object.entries(sh)) writeFileSync(join(dir, "c", `${k}.json`), JSON.stringify(v));
    const call = async (_r, p) => { called.push(p); return { ok: false, limit: false, error: true }; };
    await R.run({ dir: join(dir, "c"), library: { reports: [...reports, ...[]], actors: [] }, call, fetch: async (r) => { called.push(r.sha1); return { text: TEXT }; }, log: (m) => logs.push(m), cfg: DEFAULTS });
    assert.deepEqual(called.filter((x) => /^[0-9a-f]{40}$/.test(x)), [hex[0]]);
    assert.ok(logs.some((m) => /Library reader accuracy below target/.test(m)));
    const lg = []; let n = 0;
    await run({ ...deps(dir, async () => { n++; return {}; }), cards: audited(100, 10), log: (m) => lg.push(m) });
    assert.equal(n, 0); assert.ok(lg.some((m) => /Library reader accuracy below target/.test(m)));
    assert.match(pauseHelp, /audit_pause_pct/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a flagged card makes the published story stale at once, with no writer run", async () => {
  const dir = mk();
  try {
    setup(dir, { f: { live: story({ status: "published", based_on: "old" }), next: DRAFT }, cards: loose() });
    const t = await runAudit({ ...deps(dir, reply({ ok: false, wrong: [{ path: "tools[0]", note: "no" }] })), cfg: { ...DEFAULTS, audit_pct: 100 }, max: 5 });
    assert.equal(t.wrong, 1);
    assert.equal(files(dir).live.status, "stale");
    setup(dir, { f: { live: story({ status: "published", based_on: "old" }), next: DRAFT }, cards: loose() });
    await run({ ...deps(dir, reply({ verdict: "pass", changes: [], card_problems: [{ sha1: h("a"), note: "differs" }] })), max: 5 });
    assert.equal(files(dir).live.status, "stale");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("an audit result is dropped when the reader re-read the card meanwhile", async () => {
  const dir = mk();
  try {
    setup(dir, { cards: loose() });
    const p = join(dir, "cards", `${h("a").slice(0, 2)}.json`);
    const call = async () => { const j = JSON.parse(readFileSync(p, "utf8")); j[h("a")].read_at = "2026-12-05T00:00:00Z"; writeFileSync(p, JSON.stringify(j)); return { ok: true, json: { ok: false, wrong: [{ path: "tools[0]", note: "x" }] }, limit: false, error: false }; };
    await runAudit({ ...deps(dir, call), cfg: { ...DEFAULTS, audit_pct: 100 }, max: 5 });
    const c = JSON.parse(readFileSync(p, "utf8"))[h("a")];
    assert.equal(c.status, "read"); assert.equal(c.audit, undefined);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: an unusable reviewer reply changes nothing and a note is clipped to 160", async () => {
  const dir = mk();
  try {
    setup(dir, { cards: loose() });
    const before = readFileSync(join(dir, "stories", "a-7.json"), "utf8");
    await run({ ...deps(dir, async () => ({ ok: false, json: null, limit: false, error: false })), max: 5 });
    assert.equal(readFileSync(join(dir, "stories", "a-7.json"), "utf8"), before);
    assert.ok(cleanNote("x ".repeat(200)).length <= 160);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: originals all 'none' parks the draft (no-original)", async () => {
  const dir = mk();
  try {
    setup(dir, { cards: loose() });
    await run({ ...deps(dir, reply({ verdict: "pass", changes: [] })), fetch: async () => ({ error: "none" }), max: 5 });
    assert.deepEqual([files(dir).next.status, files(dir).next.reasons], ["parked", ["no-original"]]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: the same-run refusal; some originals none and the rest reviewed; a catalogue-only story is reviewed with no originals", async () => {
  const dir = mk(); let calls = 0, prompt = "";
  try {
    setup(dir, { cards: loose() });
    await run({ ...deps(dir, async () => { calls++; return {}; }), runId: DRAFT.written_run, max: 5 });
    assert.equal(calls, 0); assert.equal(files(dir).next.status, "draft");
    // two cards, one original gone
    const two = new Map([[h("a"), card("a")], [h("b"), card("b")]]);
    const subj = { key: "a-7", kind: "actor", name: "TT", actor: ACTOR, sha1s: [h("b"), h("a")] };
    setup(dir, { cards: two });
    writeFileSync(join(dir, "stories", "a-7.json"), JSON.stringify({ live: null, next: story({ based_on: basedOn(subj, two), sections: [{ h: "who", sentences: [sent("The operators used Mimikatz.", h("a"))] }, { h: "targets", sentences: [sent("They used Mimikatz again.", h("b"))] }, { h: "methods", sentences: [sent("Mimikatz was used.", h("a"), h("b"))] }] }) }));
    const lib = { reports: [{ sha1: h("b"), id: 2, actors: ["TT"], created: "2024-01-02" }, ...LIB.reports], actors: [ACTOR] };
    const t = await run({ ...deps(dir, async (_r, p) => { calls++; prompt = p; return { ok: true, json: { verdict: "pass", changes: [] } }; }), library: lib, fetch: async (r) => (r.sha1 === h("b") ? { error: "none" } : { text: TEXT, partial: false }), max: 5 });
    assert.equal(calls, 1); assert.equal(t.published, 1); assert.ok(prompt.includes(TEXT));
    // catalogue only
    const cat = story({ based_on: basedOn({ ...subj, sha1s: [] }, new Map()), sections: [{ h: "who", sentences: [sent("TT is a tracked actor.", "catalogue"), sent("No public report in this library describes its operations.", "catalogue")] }], headline: "TT", in_short: "Little is known." });
    writeFileSync(join(dir, "stories", "a-7.json"), JSON.stringify({ live: null, next: cat }));
    rmSync(join(dir, "cards"), { recursive: true }); mkdirSync(join(dir, "cards"));
    calls = 0;
    const t2 = await run({ ...deps(dir, async () => { calls++; return { ok: true, json: { verdict: "pass", changes: [] } }; }), library: { reports: [{ sha1: h("z"), actors: [] }], actors: [ACTOR] }, fetch: async () => { throw new Error("no fetch expected"); }, max: 5 });
    assert.equal(calls, 1); assert.equal(t2.published, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("run: a draft whose subject is missing is skipped and counted, never parked; an empty library stops the run", async () => {
  const dir = mk(), logs = []; let calls = 0;
  try {
    setup(dir, { cards: loose() });
    const before = readFileSync(join(dir, "stories", "a-7.json"), "utf8");
    const t = await run({ ...deps(dir, async () => { calls++; return {}; }), library: { reports: LIB.reports, actors: [{ id: "9", name: "Other" }] }, log: (m) => logs.push(m), max: 5 });
    assert.equal(calls, 0); assert.equal(t.orphans, 1); assert.equal(readFileSync(join(dir, "stories", "a-7.json"), "utf8"), before);
    assert.ok(logs.some((m) => /a-7.*no-subject/.test(m)));
    const t2 = await run({ ...deps(dir, async () => { calls++; return {}; }), library: { reports: [], actors: [] }, max: 5 });
    assert.match(t2.stopped, /library not loaded/); assert.equal(calls, 0);
    const t3 = await run({ ...deps(dir, async () => { calls++; return {}; }), library: { reports: LIB.reports, actors: [] }, max: 5 });
    assert.match(t3.stopped, /library not loaded/);
    assert.match(statusLine(new Map([["a-7", { live: null, next: DRAFT }]]), new Map(), DEFAULTS, new Set()), /orphan drafts 1/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: a JSON reply without a valid verdict is a bad-reply: story untouched, three in a row stop", async () => {
  const dir = mk(); let calls = 0;
  try {
    mkdirSync(join(dir, "stories")); mkdirSync(join(dir, "cards")); mkdirSync(join(dir, "corr"));
    const actors = [], reports = [], cards = new Map();
    ["a", "b", "c", "d"].forEach((c, i) => {
      const a = { id: String(i + 1), name: `Act${c}`, aliases: [], tools: [] }; actors.push(a);
      reports.push({ sha1: h(c), id: i, actors: [a.name], created: "2024-01-0" + (i + 1) }); cards.set(h(c), card(c));
      const subj = { key: "a-" + a.id, kind: "actor", name: a.name, actor: a, sha1s: [h(c)] };
      writeFileSync(join(dir, "stories", `a-${a.id}.json`), JSON.stringify({ live: null, next: story({ key: "a-" + a.id, name: a.name, based_on: basedOn(subj, cards) }) }));
    });
    const sh = {}; for (const c of cards.values()) (sh[c.sha1.slice(0, 2)] ||= {})[c.sha1] = c;
    for (const [k, v] of Object.entries(sh)) writeFileSync(join(dir, "cards", `${k}.json`), JSON.stringify(v));
    const before = readFileSync(join(dir, "stories", "a-1.json"), "utf8");
    const t = await run({ ...deps(dir, async () => { calls++; return { ok: true, json: { verdict: "maybe" }, limit: false, error: false }; }), library: { reports, actors }, max: 9 });
    assert.equal(calls, 3); assert.match(t.stopped, /failed model calls/);
    assert.equal(readFileSync(join(dir, "stories", "a-1.json"), "utf8"), before);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("audit: a reply whose ok is not a boolean writes nothing", async () => {
  const dir = mk();
  try {
    setup(dir, { cards: loose() });
    const before = readFileSync(join(dir, "cards", `${h("a").slice(0, 2)}.json`), "utf8");
    await runAudit({ ...deps(dir, reply({ ok: "yes", wrong: [] })), cfg: { ...DEFAULTS, audit_pct: 100 }, max: 5 });
    assert.equal(readFileSync(join(dir, "cards", `${h("a").slice(0, 2)}.json`), "utf8"), before);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

const rep2 = { ok: true, json: { summary: "s", kind: "malware-analysis", subject: null, hedges: [], facts: facts({ tools: [{ v: "Mimikatz", q: "the operators used Mimikatz on hosts" }] }) } };
const TXT = "the operators used Mimikatz on hosts. ".repeat(20);
const reread = (c, fetched, reply2) => R.decide({ sha1: c.sha1 }, fetched, reply2, { prev: { ...c, status: "unread" }, model: "haiku", at: "2026-12-01T00:00:00Z" }).card;
test("auditState: the rate measures cards in use: no-text and spent-unread cards are retired, awaiting ones count wrong", () => {
  const m = audited(50, 3), three = [...m.values()].slice(0, 3);
  assert.equal(auditState(m, DEFAULTS).paused, true);
  const awaiting = new Map(m); for (const c of three) awaiting.set(c.sha1, { ...c, status: "unread", tries: 0 });
  assert.equal(auditState(awaiting, DEFAULTS).wrong, 3); assert.equal(auditState(awaiting, DEFAULTS).paused, true);
  const gone = new Map(m); for (const c of three) gone.set(c.sha1, reread(c, { error: "none" }, null));
  assert.equal(gone.get(three[0].sha1).status, "no-text");
  assert.equal(auditState(gone, DEFAULTS).paused, false); assert.equal(auditState(gone, DEFAULTS).wrong, 0);
  const mix = new Map(m);
  mix.set(three[0].sha1, { ...reread(three[0], { text: TXT, partial: false }, rep2), audit: { at: "2026-12-02T00:00:00Z", ok: true, note: "", by: "auditor" } });
  mix.set(three[1].sha1, reread(three[1], { error: "none" }, null));
  mix.set(three[2].sha1, { ...three[2], status: "unread", tries: 2 });
  const s = auditState(mix, DEFAULTS);
  assert.equal(s.wrong, 0); assert.equal(s.paused, false); assert.equal(s.audited, 48);
  assert.deepEqual(wrongCards(awaiting, DEFAULTS).sort(), three.map((c) => c.sha1).sort());
});
test("auditPick: cards read again after a failed audit come first, ahead of the sha1 order", () => {
  const sha = (i) => i.toString(16).padStart(8, "0") + "0".repeat(32);
  const cards = new Map([[sha(1), { sha1: sha(1), status: "read" }], [sha(2), { sha1: sha(2), status: "read" }], [sha(90), { sha1: sha(90), status: "read", audit_history: [{ at: NOW, ok: false, note: "" }] }]]);
  assert.deepEqual(auditPick(cards, 100, new Set()), [sha(90), sha(1), sha(2)]);
});
test("pause notices carry pauseHelp; status lists the wrong cards; a flag makes the story stale with the writer paused", async () => {
  const dir = mk(), logs = [];
  try {
    setup(dir, { f: { live: story({ status: "published", based_on: "old" }), next: DRAFT }, cards: loose() });
    const extra = audited(100, 10);
    const p = join(dir, "cards", "00.json"); const only00 = {};
    for (const c of extra.values()) if (c.sha1.startsWith("00")) only00[c.sha1] = c;
    writeFileSync(p, JSON.stringify(only00));
    const all = new Map([...extra, [h("a"), card("a")]]);
    assert.equal(paused(all, DEFAULTS), true);
    // the 100 audited cards all sit in shard 00 (their sha1s start with zeros)
    const lg = []; let wcalls = 0;
    const w = await W.run({ dir: join(dir, "stories"), cards: all, library: LIB, call: async () => { wcalls++; return {}; }, log: (m) => lg.push(m), cfg: DEFAULTS });
    assert.equal(wcalls, 0); assert.ok(lg.some((m) => m.includes(pauseHelp)));
    const t = await runAudit({ ...deps(dir, reply({ ok: false, wrong: [{ path: "tools[0]", note: "no" }] })), cfg: DEFAULTS, max: 5, log: (m) => logs.push(m) });
    assert.equal(t.wrong, 1); assert.equal(files(dir).live.status, "stale");
    assert.ok(logs.some((m) => m.includes(pauseHelp)));
    assert.match(statusLine(new Map(), all, DEFAULTS), new RegExp(`${PAUSE_NOTICE.slice(0, 30)}`));
    assert.match(statusLine(new Map(), all, DEFAULTS), /wrong: 0{8}/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("settle: a correction against a reviewer-authored draft is recorded against the reviewer", () => {
  const d = { ...DRAFT, corrected_by: "opus-x", corrections: 1 };
  const r = settle({ live: null, next: d }, { verdict: "reject", changes: [{ code: "wrong", note: "n" }] }, CARDS, null, NOW, "sonnet");
  assert.deepEqual([r.corrections[0].role, r.corrections[0].model], ["library-reviewer", "opus-x"]);
});
