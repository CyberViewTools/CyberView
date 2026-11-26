import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decide, readQueue, mergeCards, run, loadCards, statusLine } from "../../scripts/library-read.mjs";
import { prepText, fetchText, TEXT_CAP, TEXT_MIN } from "../../scripts/lib/orkl-text.mjs";

const h = (c) => c.repeat(40);
const [A, B, C, D, E] = ["a", "b", "c", "d", "e"].map(h);
const rep = (sha1, created) => ({ id: "id-" + sha1.slice(0, 4), sha1, title: "T " + sha1.slice(0, 4), created, txt_url: `https://archive.orkl.eu/${sha1}.txt` });
const [rA, rB, rC, rD, rE] = [rep(A, "2020-01-01"), rep(B, "2020-01-02"), rep(C, "2020-01-03"), rep(D, "2020-01-04"), rep(E, "2020-01-05")];

const TEXT = "The group APT-Example, assessed by the vendor to be state-sponsored, exploited CVE-2024-12345 in March 2024 against energy firms. ".repeat(1) + "x".repeat(500);
const good = () => ({ ok: true, limit: false, error: false, json: {
  summary: "A campaign by APT-Example using CVE-2024-12345.", kind: "actor-campaign", subject: null, hedges: [],
  facts: { actors: [{ v: "APT-Example", q: "The group APT-Example, assessed by the vendor", by: "the vendor" }], cves: [{ v: "CVE-2024-12345", q: "exploited CVE-2024-12345 in March 2024" }] },
} });
const ctx = { at: "2026-11-25T10:00:00Z", model: "haiku" };
const f = (text = TEXT, partial = false) => ({ text, partial });

test("decide: unreachable ORKL leaves the record queued and untouched", () => {
  const d = decide(rA, { error: "unreachable" }, null, ctx);
  assert.equal(d.card, null); assert.equal(d.retry, true);
});
test("decide: none and short text are no-text with read_at and model", () => {
  for (const fx of [{ error: "none" }, f("short")]) {
    const d = decide(rA, fx, null, ctx);
    assert.equal(d.card.status, "no-text"); assert.equal(d.retry, false);
    assert.equal(d.card.read_at, ctx.at); assert.equal(d.card.model, "haiku");
  }
});
test("decide: a usage limit writes no card and retries", () => {
  const d = decide(rA, f(), { ok: false, json: null, limit: true }, ctx);
  assert.equal(d.card, null); assert.equal(d.retry, true);
});
test("decide: a failed model call (error) is not a failed read: no card, tries unchanged", () => {
  const d = decide(rA, f(), { ok: false, json: null, limit: false, error: true }, { ...ctx, prev: { status: "unread", tries: 1 } });
  assert.equal(d.card, null); assert.equal(d.retry, true);
});
test("decide: not ok, not JSON or a shape cleanCard refuses is unread bad-reply, tries + 1", () => {
  assert.equal(decide(rA, f(), { ok: false, json: null, limit: false, error: false }, ctx).card.reason, "bad-reply");
  assert.equal(decide(rA, f(), { ok: true, json: null }, ctx).card.reason, "bad-reply");
  const d = decide(rA, f(), { ok: false, json: null, limit: false }, { ...ctx, prev: { status: "unread", tries: 1 } });
  assert.equal(d.card.status, "unread"); assert.equal(d.card.tries, 2); assert.equal(d.retry, false);
  assert.equal(decide(rA, f(), { ok: false, json: null }, ctx).card.tries, 1);
});
test("decide: a card that fails the check is unread with the first three codes", () => {
  const r = good(); r.json.facts.actors[0].q = "a quote that the report never contains at all";
  r.json.kind = "nonsense"; r.json.summary = "";
  const d = decide(rA, f(), r, ctx);
  assert.equal(d.card.status, "unread"); assert.equal(d.card.tries, 1);
  assert.deepEqual(d.card.reason.split(", "), ["empty-summary", "bad-kind", "quote-not-in-text"]);
});
test("decide: a checked card is read, carries partial, read_at and model", () => {
  const d = decide(rA, f(TEXT, true), good(), ctx);
  assert.equal(d.card.status, "read"); assert.equal(d.card.partial, true); assert.equal(d.card.sha1, A);
  assert.equal(d.card.read_at, ctx.at); assert.equal(d.card.model, "haiku"); assert.equal(d.retry, false);
});
test("readQueue: every record is reached; read and no-text are not re-read; unread retries once", () => {
  const cards = new Map([[A, { status: "read" }], [B, { status: "no-text" }], [C, { status: "unread", tries: 1 }], [D, { status: "unread", tries: 2 }]]);
  assert.deepEqual(readQueue([rA, rB, rC, rD, rE], cards, { order: "newest", max: 10 }).map((r) => r.sha1), [E, C]);
  assert.deepEqual(readQueue([rA, rC, rE], new Map(), { order: [A], max: 2 }).map((r) => r.sha1), [A, E]);
});
test("mergeCards: additive; a second run never drops an earlier card", () => {
  const s1 = mergeCards({}, [{ sha1: A, status: "read" }]);
  const s2 = mergeCards(s1, [{ sha1: B, status: "no-text" }, { sha1: A, status: "unread", tries: 1 }]);
  assert.equal(s2.aa[A].status, "unread"); assert.equal(s2.bb[B].status, "no-text");
  assert.equal(s1.aa[A].status, "read");
});
test("prepText: capped text is marked partial; control characters removed", () => {
  const p = prepText("a\u0000b" + "x".repeat(TEXT_CAP + 5));
  assert.equal(p.partial, true); assert.equal(p.text.length, TEXT_CAP); assert.ok(!p.text.includes("\u0000"));
  assert.equal(prepText("a\nb\tc").text, "a\nb\tc");
});
const fe = (code) => Object.assign(new Error(code), { code });
test("fetchText: the archive file first, then the API entry; any 4xx falls through; none only when every source answered empty", async () => {
  const body = "y".repeat(TEXT_MIN + 1);
  const calls = [];
  const mk = (arch, api) => async (u) => { calls.push(u); const x = u.includes("/library/entry/") ? api : arch; if (x instanceof Error) throw x; return x; };
  const hit = await fetchText(rA, { getter: mk(body, new Error("never")) });
  assert.equal(hit.text, body); assert.ok(calls.every((u) => !u.includes("/library/entry/")), "archive hit: API never called");
  assert.equal((await fetchText(rA, { getter: mk(fe("http_404"), { data: { plain_text: body } }) })).text, body);
  assert.equal((await fetchText(rA, { getter: mk(fe("http_403"), { data: { plain_text: body } }) })).text, body);
  assert.deepEqual(await fetchText(rA, { getter: mk(fe("http_404"), fe("http_404")) }), { error: "none" });
  assert.deepEqual(await fetchText(rA, { getter: mk("", { data: {} }) }), { error: "none" });
  assert.deepEqual(await fetchText(rA, { getter: mk(fe("http_503"), fe("http_404")) }), { error: "unreachable" });
  assert.deepEqual(await fetchText(rA, { getter: mk(fe("http_404"), fe("timeout")) }), { error: "unreachable" });
  assert.deepEqual(await fetchText(rA, { getter: mk(fe("http_429"), fe("http_404")) }), { error: "unreachable" });
  assert.equal((await fetchText(rA, { getter: mk(fe("network"), { data: { plain_text: body } }) })).text, body);
  assert.deepEqual(await fetchText({ ...rA, txt_url: "", id: "" }, { getter: mk(body, body) }), { error: "none" });
  for (const c of ["http_503", "timeout", "network", "circuit_open"]) assert.deepEqual(await fetchText(rA, { getter: mk(fe(c), fe(c)) }), { error: "unreachable" });
});
test("loadCards: an unreadable shard is reported, not read as empty; run leaves it byte for byte and skips its records", async () => {
  const dir = mkdtempSync(join(tmpdir(), "lib-read-"));
  try {
    writeFileSync(join(dir, "aa.json"), "{ not json");
    writeFileSync(join(dir, "bb.json"), "[1,2]");
    const bad = []; const m = loadCards(dir, bad);
    assert.equal(m.size, 0); assert.deepEqual(bad.sort(), ["aa", "bb"]);
    const lines = [];
    const t = await run({ max: 10, dir, library: { reports: [rA, rB, rC] }, fetch: async () => ({ text: TEXT, partial: false }), model: "haiku", log: (l) => lines.push(l), call: async () => good() });
    assert.equal(readFileSync(join(dir, "aa.json"), "utf8"), "{ not json");
    assert.equal(readFileSync(join(dir, "bb.json"), "utf8"), "[1,2]");
    assert.equal(t.read, 1); assert.equal(t.unreadableShards.length, 2);
    assert.ok(lines.some((l) => /2 shard\(s\) unreadable, left untouched: aa, bb/.test(l)));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: a card another run wrote to the shard meanwhile survives the write", async () => {
  const dir = mkdtempSync(join(tmpdir(), "lib-read-"));
  try {
    const other = { sha1: "a1" + "0".repeat(38), status: "read", summary: "other run" };
    const fetch = async () => { writeFileSync(join(dir, "aa.json"), JSON.stringify({ [other.sha1]: other })); return { text: TEXT, partial: false }; };
    await run({ max: 1, dir, library: { reports: [rA] }, fetch, model: "haiku", log: () => {}, call: async () => good() });
    const got = JSON.parse(readFileSync(join(dir, "aa.json"), "utf8"));
    assert.equal(got[other.sha1].summary, "other run"); assert.equal(got[A].status, "read");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: five unreachable outcomes in a row stop it; a thrown exception is logged by name and code only", async () => {
  const dir = mkdtempSync(join(tmpdir(), "lib-read-"));
  try {
    const many = Array.from({ length: 12 }, (_, i) => rep(String(i).repeat(40), `2020-02-${10 + i}`));
    const t = await run({ max: 12, concurrency: 2, dir, library: { reports: many }, fetch: async () => ({ error: "unreachable" }), log: () => {}, call: async () => good() });
    assert.equal(t.stopped, "ORKL unreachable"); assert.ok(t.requeued < 12 && t.requeued >= 5);
    const lines = [];
    await run({ max: 1, dir, library: { reports: [rA] }, fetch: async () => { throw Object.assign(new TypeError("SECRET REPORT TEXT"), { code: "E_X" }); }, log: (l) => lines.push(l), call: async () => good() });
    assert.ok(lines.some((l) => /TypeError E_X/.test(l))); assert.ok(!lines.join("\n").includes("SECRET"));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("decide: reason holds only problem codes, short", () => {
  const r = good(); r.json.facts.actors[0].q = "SECRET quote that the report never contains"; r.json.summary = "";
  const d = decide(rA, f(), r, ctx);
  assert.match(d.card.reason, /^[a-z][a-z-]*(, [a-z][a-z-]*){0,2}$/); assert.ok(d.card.reason.length <= 200); assert.ok(!/SECRET|\[/.test(d.card.reason));
});
test("run: stores only cards, never the report text; stops after 3 failed calls in a row; a limit stops it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "lib-read-"));
  try {
    const lines = [], library = { reports: [rA, rB, rC, rD, rE] };
    const fetch = async (r) => (r.sha1 === B ? { error: "none" } : { text: TEXT, partial: false });
    const t = await run({ max: 10, dir, library, fetch, model: "haiku", log: (l) => lines.push(l), call: async () => good() });
    assert.equal(t.read, 4); assert.equal(t["no-text"], 1);
    assert.equal(loadCards(dir).size, 5);
    for (const f of readdirSync(dir)) assert.ok(!readFileSync(join(dir, f), "utf8").includes("x".repeat(100)), "no report text on disk");
    assert.match(statusLine(library.reports, loadCards(dir)), /read 4, no-text 1, unread 0, queued 0/);
    const dir2 = mkdtempSync(join(tmpdir(), "lib-read-"));
    const many = Array.from({ length: 8 }, (_, i) => rep(String(i).repeat(40), `2020-02-0${i + 1}`));
    const bad = await run({ max: 8, concurrency: 2, dir: dir2, library: { reports: many }, fetch, log: () => {}, call: async () => ({ ok: false, json: null, limit: false, error: true }) });
    assert.match(bad.stopped, /failed model calls/); assert.equal(loadCards(dir2).size, 0); assert.ok(bad.requeued < 8);
    const lim = await run({ max: 8, concurrency: 2, dir: dir2, library: { reports: many }, fetch, log: () => {}, call: async () => ({ ok: false, json: null, limit: true }) });
    assert.equal(lim.stopped, "usage limit"); assert.equal(lim.requeued, 2);
    rmSync(dir2, { recursive: true, force: true });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// B-I2: short archive text is not an answer; a run where ORKL's text is missing everywhere writes no no-text cards; a no-text card is retried once after 30 days
test("fetchText: archive text shorter than TEXT_MIN falls through to the API entry", async () => {
  const body = "y".repeat(TEXT_MIN + 1);
  const mk = (arch, api) => async (u) => { const x = u.includes("/library/entry/") ? api : arch; if (x instanceof Error) throw x; return x; };
  assert.equal((await fetchText(rA, { getter: mk("short text", { data: { plain_text: body } }) })).text, body);
  assert.deepEqual(await fetchText(rA, { getter: mk("short text", fe("timeout")) }), { error: "unreachable" }, "the API did not answer: not none");
  const both = await fetchText(rA, { getter: mk("short text", fe("http_404")) });
  assert.equal(both.error, undefined); assert.equal(both.text, "short text", "every source answered: the short text is the answer (no-text, too short)");
});
test("run: five or more finished fetches with 80% or more none is systemic: no no-text cards, records stay queued", async () => {
  const dir = mkdtempSync(join(tmpdir(), "lib-read-"));
  try {
    const many = Array.from({ length: 6 }, (_, i) => rep(String(i).repeat(40), `2020-03-0${i + 1}`));
    const fetch = async (r) => (r.sha1 === many[0].sha1 ? { text: TEXT, partial: false } : { error: "none" });
    const t = await run({ max: 6, concurrency: 3, dir, library: { reports: many }, fetch, model: "haiku", log: () => {}, call: async () => good() });
    assert.equal(t.stopped, "ORKL text missing"); assert.equal(t["no-text"], 0);
    assert.ok([...loadCards(dir).values()].every((c) => c.status !== "no-text"), "no no-text card written");
    // four fetches, all none: too few to call it systemic
    const dir2 = mkdtempSync(join(tmpdir(), "lib-read-"));
    const t2 = await run({ max: 4, concurrency: 4, dir: dir2, library: { reports: many.slice(0, 4).map((r, i) => (i === 0 ? { ...r, sha1: "f".repeat(40) } : r)) }, fetch: async () => ({ error: "none" }), model: "haiku", log: () => {}, call: async () => good() });
    assert.equal(t2.stopped, ""); assert.equal(t2["no-text"], 4);
    rmSync(dir2, { recursive: true, force: true });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("readQueue: a no-text card is retried once, 30 days after read_at; the retry is recorded", () => {
  const now = Date.parse("2026-11-25T00:00:00Z");
  const nt = (at, o = {}) => ({ sha1: A, status: "no-text", read_at: at, ...o });
  assert.equal(readQueue([rA], new Map([[A, nt("2026-11-01T00:00:00Z")]]), { now }).length, 0, "not yet 30 days");
  assert.equal(readQueue([rA], new Map([[A, nt("2026-10-01T00:00:00Z")]]), { now }).length, 1, "30 days on: once more");
  assert.equal(readQueue([rA], new Map([[A, nt("2026-01-01T00:00:00Z", { retried: true })]]), { now }).length, 0, "retried already");
  const d = decide(rA, { error: "none" }, null, { ...ctx, prev: nt("2026-10-01T00:00:00Z") });
  assert.equal(d.card.status, "no-text"); assert.equal(d.card.retried, true);
});

// B-I10: a record that keeps failing (unreachable, failed call) sorts last after 3 failures and is parked for 7 days at 6
import { bumpFailures, loadReadState, parkedRecords, FAIL_LAST, FAIL_PARK } from "../../scripts/library-read.mjs";
test("bumpFailures and readQueue: failing records sort last, then are parked for 7 days; a success clears the count", () => {
  const now = Date.parse("2026-11-25T00:00:00Z");
  let f = {};
  for (let i = 0; i < FAIL_LAST; i++) f = bumpFailures(f, { failed: [A] }, now);
  assert.equal(f[A].n, 3); assert.equal(f[A].parked_until, undefined);
  assert.deepEqual(readQueue([rA, rB], new Map(), { order: [A, B], failures: f, now }).map((r) => r.sha1), [B, A], "three failures: last, even when listed first");
  for (let i = FAIL_LAST; i < FAIL_PARK; i++) f = bumpFailures(f, { failed: [A] }, now);
  assert.equal(f[A].n, 6); assert.equal(f[A].parked_until, "2026-12-02T00:00:00Z");
  assert.deepEqual(readQueue([rA, rB], new Map(), { failures: f, now }).map((r) => r.sha1), [B], "parked: skipped");
  assert.deepEqual(readQueue([rA, rB], new Map(), { failures: f, now: now + 8 * 864e5 }).map((r) => r.sha1), [B, A], "after 7 days it is tried again, last");
  assert.deepEqual(parkedRecords(f, now), [A]);
  assert.equal(bumpFailures(f, { cleared: [A] }, now)[A], undefined, "a success clears it");
});
test("run: unreachable and failed calls are counted in read-state.json; a written card clears its count", async () => {
  const dir = mkdtempSync(join(tmpdir(), "lib-read-"));
  try {
    const fetch = async (r) => (r.sha1 === A ? { error: "unreachable" } : { text: TEXT, partial: false });
    await run({ max: 2, dir, library: { reports: [rA, rB] }, fetch, model: "haiku", log: () => {}, call: async () => ({ ok: false, json: null, limit: false, error: true }) });
    const st = loadReadState(join(dir, "read-state.json"));
    assert.equal(st.state, "ok"); assert.equal(st.failures[A].n, 1); assert.equal(st.failures[B].n, 1);
    await run({ max: 2, dir, library: { reports: [rA, rB] }, fetch, model: "haiku", log: () => {}, call: async () => good() });
    const st2 = loadReadState(join(dir, "read-state.json"));
    assert.equal(st2.failures[A].n, 2); assert.equal(st2.failures[B], undefined);
    writeFileSync(join(dir, "read-state.json"), "{ bad");
    await run({ max: 1, dir, library: { reports: [rA] }, fetch, model: "haiku", log: () => {}, call: async () => good() });
    assert.equal(readFileSync(join(dir, "read-state.json"), "utf8"), "{ bad", "an unreadable state file is never written over");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// Open item 3 (final review): the owner's withdrawal stays on a card that is read (again) later
test("decide: a withdrawn card that is read later keeps its withdrawn flag, time and reason", () => {
  const W = { withdrawn: true, withdrawn_at: "2026-11-26T03:00:00Z", withdrawn_reason: "the vendor retracted it" };
  for (const prev of [{ sha1: A, status: "unread", tries: 1, ...W }, { sha1: A, status: "no-text", read_at: "2026-01-01T00:00:00Z", ...W }]) {
    const read = decide(rA, f(), good(), { ...ctx, prev }).card;
    assert.equal(read.status, "read"); assert.equal(read.withdrawn, true);
    assert.equal(read.withdrawn_at, W.withdrawn_at); assert.equal(read.withdrawn_reason, W.withdrawn_reason);
    const none = decide(rA, { error: "none" }, null, { ...ctx, prev }).card;
    assert.equal(none.status, "no-text"); assert.equal(none.withdrawn, true);
  }
  assert.equal(decide(rA, f(), good(), { ...ctx, prev: { sha1: A, status: "unread", tries: 1 } }).card.withdrawn, undefined);
});
