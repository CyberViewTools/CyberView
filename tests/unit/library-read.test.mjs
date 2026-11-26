import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, readdirSync } from "node:fs";
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
test("fetchText: plain_text first, then the archive file; 404 is none, an outage is unreachable", async () => {
  const body = "y".repeat(TEXT_MIN + 1);
  assert.equal((await fetchText(rA, { getter: async () => ({ data: { plain_text: body } }) })).text, body);
  const viaArchive = async (u) => { if (u.includes("/library/entry/")) return { data: {} }; return body; };
  assert.equal((await fetchText(rA, { getter: viaArchive })).text, body);
  assert.deepEqual(await fetchText(rA, { getter: async () => { throw fe("http_404"); } }), { error: "none" });
  assert.deepEqual(await fetchText({ ...rA, txt_url: "" }, { getter: async () => ({ data: {} }) }), { error: "none" });
  for (const c of ["http_503", "timeout", "network", "circuit_open"]) assert.deepEqual(await fetchText(rA, { getter: async () => { throw fe(c); } }), { error: "unreachable" });
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
