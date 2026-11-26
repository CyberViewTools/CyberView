import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BY, cleanStory } from "../../scripts/lib/library-check.mjs";
import { basedOn } from "../../scripts/lib/library-subjects.mjs";
import { placeDraft, writeQueue, loadStories, run, STORIES_DIR } from "../../scripts/library-write.mjs";

const h = (c) => c.repeat(40);
const story = (o = {}) => ({ key: "a-7", kind: "actor", name: "TT Group", headline: "h", in_short: "i", sections: [], status: "draft", based_on: "x", tries: 0, by: BY, written_at: "t", writer_model: "sonnet", ...o });
const TT = { id: "7", name: "TT Group", aliases: [], tools: [] };
const QUIET = { id: "8", name: "QuietActor", aliases: [], tools: [] };
const sub = (o = {}) => ({ key: "a-7", kind: "actor", name: "TT Group", actor: TT, sha1s: [], ...o });
const card = (c) => ({ sha1: h(c), status: "read", kind: "actor-campaign", summary: "s", subject: null, facts: { tools: [], techniques: [], sectors: [], countries: [], dates: [], cves: [], actors: [], figures: [] }, read_at: "2026-11-01T00:00:00Z" });
const cards = new Map([[h("a"), card("a")]]);
const subA = sub({ sha1s: [h("a")] });
const bA = () => basedOn(subA, cards);

test("placeDraft: a rewrite never replaces the live story; a changed card set marks it stale", () => {
  const f = placeDraft({ live: story({ status: "published", based_on: "old" }), next: null }, story({ based_on: "new" }));
  assert.equal(f.live.status, "stale"); assert.equal(f.next.status, "draft"); assert.equal(f.live.based_on, "old");
});
test("placeDraft: the same card set leaves live published", () => {
  const f = placeDraft({ live: story({ status: "published", based_on: "same" }), next: null }, story({ based_on: "same" }));
  assert.equal(f.live.status, "published");
});
test("placeDraft: first draft has no live", () => {
  const f = placeDraft({ live: null, next: null }, story());
  assert.equal(f.live, null); assert.equal(f.next.status, "draft");
});
test("writeQueue: unchanged published stories are skipped; a parked story is not retried", () => {
  const pub = new Map([["a-7", { live: story({ status: "published", based_on: bA() }), next: null }]]);
  assert.equal(writeQueue([subA], pub, cards, {}).length, 0);
  const parked = new Map([["a-7", { live: null, next: story({ status: "parked", tries: 2, based_on: "old" }) }]]);
  assert.equal(writeQueue([subA], parked, cards, {}).length, 0);
});
test("writeQueue: no file, changed cards, and rejected under two tries are queued", () => {
  assert.equal(writeQueue([subA], new Map(), cards, {}).length, 1);
  const changed = new Map([["a-7", { live: story({ status: "published", based_on: "old" }), next: null }]]);
  assert.equal(writeQueue([subA], changed, cards, {}).length, 1);
  const rej = new Map([["a-7", { live: null, next: story({ status: "rejected", tries: 1, based_on: bA() }) }]]);
  assert.equal(writeQueue([subA], rej, cards, {}).length, 1);
  const rej2 = new Map([["a-7", { live: null, next: story({ status: "rejected", tries: 2, based_on: bA() }) }]]);
  assert.equal(writeQueue([subA], rej2, cards, {}).length, 0);
});
test("writeQueue: a waiting draft for the current cards is not written again; a stale live with a current draft waits", () => {
  const f = new Map([["a-7", { live: story({ status: "stale", based_on: "old" }), next: story({ status: "draft", based_on: bA() }) }]]);
  assert.equal(writeQueue([subA], f, cards, {}).length, 0);
});
test("writeQueue: a subject-kind story with no read cards is never queued; a catalogue-only actor is", () => {
  assert.equal(writeQueue([sub({ key: "s-1", kind: "subject", actor: null })], new Map(), cards, {}).length, 0);
  assert.equal(writeQueue([sub({ key: "a-8", name: "QuietActor", actor: QUIET })], new Map(), cards, {}).length, 1);
});
test("writeQueue: a card marked unread changes basedOn and so queues a rewrite of the live story", () => {
  const c = new Map([[h("a"), card("a")], [h("b"), card("b")]]);
  const s = sub({ sha1s: [h("a"), h("b")] });
  const files = new Map([["a-7", { live: story({ status: "published", based_on: basedOn(s, c) }), next: null }]]);
  assert.equal(writeQueue([s], files, c, {}).length, 0);
  c.get(h("b")).status = "unread";
  assert.equal(writeQueue([s], files, c, {}).length, 1);
});
test("writeQueue: order list first, then max", () => {
  const ss = ["a-1", "a-2", "a-3"].map((k) => sub({ key: k }));
  assert.deepEqual(writeQueue(ss, new Map(), cards, { order: ["a-3"], max: 2 }).map((s) => s.key)[0], "a-3");
  assert.equal(writeQueue(ss, new Map(), cards, { max: 2 }).length, 2);
});
test("cleanStory keeps reasons and written_run", () => {
  const s = cleanStory({ ...story(), reasons: ["unbacked", "x".repeat(99)], written_run: "abcd1234" });
  assert.deepEqual(s.reasons.length, 2); assert.equal(s.written_run, "abcd1234");
});

// ---- run ----
const LIB = { reports: [{ sha1: h("a"), actors: ["TT Group"], created: "2024-01-01", title: "t" }], actors: [TT, QUIET] };
const catalogueReply = () => ({ ok: true, limit: false, error: false, json: {
  headline: "Quiet", in_short: "Little is known.", by: "someone else", status: "published", key: "evil", based_on: "evil", tries: 0,
  sections: [{ h: "who", sentences: [{ t: "QuietActor is a tracked actor.", cites: ["catalogue"] }, { t: "No public report in this library describes its operations.", cites: ["catalogue"] }] }] } });
const bad = { ok: true, limit: false, error: false, json: { headline: "x", in_short: "y", sections: [{ h: "who", sentences: [{ t: "Claims.", cites: [h("f")] }] }] } };
const mk = () => mkdtempSync(join(tmpdir(), "lib-write-"));
const deps = (dir, call, extra = {}) => ({ dir, library: LIB, cards, call, model: "sonnet", log: () => {}, concurrency: 1, ...extra });
const file = (dir, key) => JSON.parse(readFileSync(join(dir, `${key}.json`), "utf8"));

test("run: a good reply is stored as a draft with every system field set by the script", async () => {
  const dir = mk();
  try {
    const only8 = { ...LIB, actors: [QUIET] };
    const t = await run({ ...deps(dir, async () => catalogueReply()), library: only8, max: 5 });
    const n = file(dir, "a-8").next;
    assert.equal(n.status, "draft"); assert.equal(n.key, "a-8"); assert.equal(n.kind, "actor"); assert.equal(n.name, "QuietActor");
    assert.equal(n.by, BY); assert.equal(n.writer_model, "sonnet"); assert.equal(n.tries, 0);
    assert.notEqual(n.based_on, "evil"); assert.match(n.written_at, /^\d{4}-\d{2}-\d{2}T/); assert.match(n.written_run, /^[0-9a-f]{8}$/);
    assert.equal(file(dir, "a-8").live, null); assert.equal(t.drafted, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: an unusable reply is a rejected draft with problem codes only and tries + 1; two tries park it", async () => {
  const dir = mk();
  try {
    await run({ ...deps(dir, async () => bad), library: { ...LIB, actors: [TT] }, max: 5 });
    let n = file(dir, "a-7").next;
    assert.equal(n.status, "rejected"); assert.equal(n.tries, 1);
    assert.ok(n.reasons.length && n.reasons.length <= 10 && n.reasons.every((r) => /^[a-z][a-z-]*$/.test(r)), JSON.stringify(n.reasons));
    await run({ ...deps(dir, async () => ({ ok: false, json: null, limit: false, error: false })), library: { ...LIB, actors: [TT] }, max: 5 });
    n = file(dir, "a-7").next;
    assert.equal(n.status, "parked"); assert.equal(n.tries, 2); assert.deepEqual(n.reasons, ["bad-reply"]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: only read cards reach the prompt and the checks", async () => {
  const dir = mk(); let prompt = "";
  try {
    const c = new Map([[h("a"), card("a")], [h("b"), { ...card("b"), status: "unread" }]]);
    const lib = { reports: [...LIB.reports, { sha1: h("b"), actors: ["TT Group"], created: "2024-01-02" }], actors: [TT] };
    await run({ ...deps(dir, async (_r, p) => { prompt = p; return bad; }), cards: c, library: lib, max: 1 });
    assert.ok(prompt.includes(h("a"))); assert.ok(!prompt.includes(h("b")));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: a usage limit stops and writes nothing; failed calls leave tries unchanged and three in a row stop", async () => {
  const dir = mk();
  try {
    const two = { ...LIB, actors: [TT, QUIET, { id: "9", name: "Third" }, { id: "10", name: "Fourth" }] };
    let calls = 0;
    const t = await run({ ...deps(dir, async () => { calls++; return { ok: false, json: null, limit: true, error: false }; }), library: two, max: 9 });
    assert.equal(t.stopped, "usage limit"); assert.equal(calls, 1); assert.deepEqual(readdirSync(dir), []);
    calls = 0;
    const t2 = await run({ ...deps(dir, async () => { calls++; return { ok: false, json: null, limit: false, error: true }; }), library: { ...two, actors: [...two.actors, { id: "11", name: "Fifth" }] }, max: 9 });
    assert.equal(calls, 3); assert.match(t2.stopped, /failed model calls/); assert.deepEqual(readdirSync(dir), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: an unreadable story file is never written over; the live story is kept when a draft is placed", async () => {
  const dir = mk();
  try {
    writeFileSync(join(dir, "a-8.json"), "{not json");
    await run({ ...deps(dir, async () => catalogueReply()), library: { ...LIB, actors: [QUIET] }, max: 5 });
    assert.equal(readFileSync(join(dir, "a-8.json"), "utf8"), "{not json");
    rmSync(join(dir, "a-8.json"));
    writeFileSync(join(dir, "a-8.json"), JSON.stringify({ live: story({ key: "a-8", name: "QuietActor", status: "published", based_on: "old" }), next: null }));
    await run({ ...deps(dir, async () => catalogueReply()), library: { ...LIB, actors: [QUIET] }, max: 5 });
    const f = file(dir, "a-8");
    assert.equal(f.live.based_on, "old"); assert.equal(f.live.status, "stale"); assert.equal(f.next.status, "draft");
    const m = loadStories(dir);
    assert.equal(m.get("a-8").next.status, "draft");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: unreadable card shards stop the run before any call", async () => {
  const dir = mk(), cdir = mk(); let calls = 0;
  try {
    writeFileSync(join(cdir, "ab.json"), "{broken");
    const t = await run({ ...deps(dir, async () => { calls++; return bad; }), cards: undefined, cardsDir: cdir, max: 5 });
    assert.equal(calls, 0); assert.match(t.stopped, /unreadable/); assert.deepEqual(readdirSync(dir), []);
  } finally { rmSync(dir, { recursive: true, force: true }); rmSync(cdir, { recursive: true, force: true }); }
});
