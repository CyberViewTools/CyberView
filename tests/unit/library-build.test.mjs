// Library build output (scripts/orkl.mjs): only reviewed stories and read cards reach site/data, never a quote or a draft.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync, renameSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BY as CHECK_BY } from "../../scripts/lib/library-check.mjs";
import { siteCard, siteStory, storyIndex, libraryIndex, siteData, writeLibrarySite, publishLibrary, STORY_BY } from "../../scripts/orkl.mjs";

const h = (c) => c.repeat(40);
const BY = "CyberView AI (a Claude model)";
const rep = (c, extra = {}) => ({ id: "0000000" + c + "-0000-0000-0000-000000000000", sha1: h(c), title: "Report " + c, authors: ["Jane"], lang: "en", created: "2024-0" + (c === "a" ? 1 : 2) + "-01", file_date: "2023-05-01", sources: ["Malpedia"], actors: ["TT Group"], url: "https://orkl.eu/libraryEntry/0000000" + c + "-0000-0000-0000-000000000000", ...extra });
const R = [rep("a"), rep("b")];
const card = (c, extra = {}) => ({ sha1: h(c), status: "read", partial: false, read_at: "2026-11-01T00:00:00Z", model: "haiku", summary: "A summary", kind: "actor-campaign",
  facts: { actors: [{ v: "TT Group", q: "SECRET-QUOTE-TEXT here", by: "Vendor X" }], sectors: [{ v: "Energy", q: "q1" }], countries: [], dates: [{ v: "2023", q: "q2", what: "first seen" }], tools: [{ v: "Manuscrypt", q: "SECRET-QUOTE-TEXT here in the report" }], techniques: [], cves: [{ v: "CVE-2024-0001", q: "q3" }], figures: [] },
  subject: { type: "malware", name: "Manuscrypt" }, hedges: ["HEDGE-TEXT"], audit: { at: "x", ok: true, note: "AUDIT-NOTE", by: "auditor" }, audit_history: [{ at: "y", ok: false, note: "OLD", by: "reviewer" }], reason: "REASON-TEXT", tries: 1, ...extra });
const S = { key: "a-1", kind: "actor", name: "TT Group", headline: "TT Group in short", in_short: "Short.", status: "published", reviewed_at: "2026-11-02T00:00:00Z", reviewer_model: "sonnet", written_at: "w", writer_model: "sonnet", written_run: "run1", reasons: ["r"], corrected_by: "library-writer", corrections: 1, based_on: "BASEDON", tries: 1, by: BY,
  sections: [{ h: "who", sentences: [{ t: "Reported by Vendor X.", cites: [h("a"), h("b")] }] }, { h: "takeaway", sentences: [{ t: "Patch.", cites: [] }] }] };
const DRAFT = { ...S, status: "draft", reviewed_at: undefined };

test("siteCard: no evidence quote, hedge, audit or reason ever reaches the site", () => {
  const out = JSON.stringify(siteCard(card("a")));
  assert.ok(out.includes("Manuscrypt")); assert.ok(out.includes("Vendor X")); assert.ok(out.includes("first seen"));
  for (const s of ["SECRET-QUOTE-TEXT", "HEDGE-TEXT", "AUDIT-NOTE", "REASON-TEXT", "auditor", "haiku", "tries", "q1"]) assert.ok(!out.includes(s), s);
  const c = siteCard(card("a"));
  assert.equal(c.sm, "A summary"); assert.equal(c.k, "actor-campaign"); assert.equal(c.p, false);
  assert.deepEqual(c.f.t, ["Manuscrypt"]); assert.deepEqual(c.f.v, ["CVE-2024-0001"]); assert.deepEqual(c.f.a, [{ v: "TT Group", by: "Vendor X" }]); assert.deepEqual(c.f.d, [{ v: "2023", what: "first seen" }]);
  assert.deepEqual(c.su, { type: "malware", name: "Manuscrypt" });
});
test("siteCard: unread and no-text cards publish nothing", () => {
  assert.equal(siteCard(card("a", { status: "unread" })), null); assert.equal(siteCard(card("a", { status: "no-text" })), null); assert.equal(siteCard(null), null);
});
test("siteStory: a draft, a rejected rewrite and an unreviewed story are never published", () => {
  assert.equal(siteStory({ live: null, next: DRAFT }, R), null);
  assert.equal(siteStory({ live: { ...S, reviewed_at: "" }, next: null }, R), null);
  assert.equal(siteStory({ live: { ...S, status: "rejected" }, next: null }, R), null);
});
test("siteStory: a stale story stays up while its rewrite waits, flagged stale", () => {
  const s = siteStory({ live: { ...S, status: "stale" }, next: DRAFT }, R);
  assert.ok(s); assert.equal(s.stale, true); assert.equal(siteStory({ live: S, next: null }, R).stale, undefined);
});
test("siteStory: only public fields; sources resolved from the reports", () => {
  const s = siteStory({ live: S, next: DRAFT }, R);
  assert.deepEqual(Object.keys(s).sort(), ["by", "headline", "in_short", "key", "kind", "n", "name", "reviewed_at", "sections", "src"]);
  const out = JSON.stringify(s);
  for (const x of ["BASEDON", "sonnet", "run1", "library-writer", "reasons", "corrections", "based_on", "tries"]) assert.ok(!out.includes(x), x);
  assert.equal(s.n, 2); assert.deepEqual(s.src.map((x) => x.sha1), [h("a"), h("b")]);
  assert.deepEqual(s.src[0], { sha1: h("a"), title: "Report a", authors: ["Jane"], year: "2023" });
});
test("siteStory: a cite that does not resolve is dropped; an uncited factual sentence stops publication with a warning", () => {
  const w = [];
  const one = { ...S, sections: [{ h: "who", sentences: [{ t: "X.", cites: [h("a"), h("9")] }] }] };
  assert.deepEqual(siteStory({ live: one }, R, (m) => w.push(m)).sections[0].sentences[0].cites, [h("a")]);
  const none = { ...S, sections: [{ h: "who", sentences: [{ t: "X.", cites: [h("9")] }] }] };
  assert.equal(siteStory({ live: none }, R, (m) => w.push(m)), null);
  assert.ok(w.some((m) => m.includes("a-1")));
  const cat = { ...S, sections: [{ h: "who", sentences: [{ t: "X.", cites: ["catalogue"] }] }] };
  assert.deepEqual(siteStory({ live: cat }, R).sections[0].sentences[0].cites, ["catalogue"]);
});
test("storyIndex: newest review first", () => {
  const a = siteStory({ live: S }, R), b = siteStory({ live: { ...S, key: "a-2", reviewed_at: "2026-11-05T00:00:00Z" } }, R);
  assert.deepEqual(storyIndex([a, b]).map((x) => x.key), ["a-2", "a-1"]);
  assert.deepEqual(Object.keys(storyIndex([a])[0]).sort(), ["headline", "in_short", "key", "kind", "n", "name", "reviewed_at"]);
});
test("libraryIndex: existing keys unchanged; k and st added only when given", () => {
  const actors = [{ id: "1", name: "TT Group", aliases: [], tools: [] }];
  const plain = libraryIndex(R, actors, "t");
  assert.ok(plain.reports.every((r) => !("k" in r)) && plain.actors.every((a) => !("st" in a)));
  const ix = libraryIndex(R, actors, "t", { read: new Set([h("a")]), actorStory: new Map([["1\0TT Group", "a-1"]]), looseStory: new Map([[h("b"), "s-xyz"]]) });
  assert.equal(ix.reports.find((r) => r.s === h("a")).k, 1); assert.ok(!("k" in ix.reports.find((r) => r.s === h("b"))));
  assert.equal(ix.reports.find((r) => r.s === h("b")).st, "s-xyz"); assert.equal(ix.actors[0].st, "a-1");
});
test("siteData: gains the card and story counts", () => {
  const d = siteData({ reports_total: 3 }, "t", { cards_read: 2, stories: 1 });
  assert.equal(d.cards_read, 2); assert.equal(d.stories_published, 1); assert.equal(d.reports, 3);
});

const tmp = () => mkdtempSync(join(tmpdir(), "libsite-"));
const files = (d) => (existsSync(d) ? readdirSync(d).sort() : []);
const cardsMap = (...cs) => new Map(cs.map((c) => [c.sha1, c]));
const actors = [{ id: "1", name: "TT Group", aliases: [], tools: [] }];
test("writeLibrarySite: writes shards, stories and the index; clears stale files; one bad story warns, not fails", () => {
  const out = tmp(), warns = [];
  mkdirSync(join(out, "library", "cards"), { recursive: true }); mkdirSync(join(out, "library", "stories"), { recursive: true });
  writeFileSync(join(out, "library", "cards", "zz.json"), "{}"); writeFileSync(join(out, "library", "stories", "old.json"), "{}");
  const stories = new Map([["a-1", { live: S, next: DRAFT }], ["a-2", { live: { ...S, key: "a-2", sections: [{ h: "who", sentences: [{ t: "X.", cites: [h("9")] }] }] }, next: null }], ["a-3", { live: null, next: DRAFT }]]);
  const r = writeLibrarySite({ reports: R, actors, cards: cardsMap(card("a"), card("b", { status: "unread" })), stories, outDir: out, builtAt: "t", warn: (m) => warns.push(m) });
  assert.deepEqual(files(join(out, "library", "cards")), ["aa.json"]); assert.deepEqual(files(join(out, "library", "stories")), ["a-1.json"]);
  const shard = JSON.parse(readFileSync(join(out, "library", "cards", "aa.json"), "utf8")); assert.deepEqual(Object.keys(shard), [h("a")]);
  assert.ok(!readFileSync(join(out, "library", "cards", "aa.json"), "utf8").includes("SECRET-QUOTE"));
  const idx = JSON.parse(readFileSync(join(out, "library", "stories.json"), "utf8")); assert.deepEqual(idx.stories.map((x) => x.key), ["a-1"]);
  assert.equal(r.counts.cards_read, 1); assert.equal(r.counts.stories, 1);
  assert.ok(warns.some((m) => m.includes("a-2")));
  assert.equal(r.links.actorStory.get("1\0TT Group"), "a-1"); assert.ok(r.links.read.has(h("a")));
  rmSync(out, { recursive: true });
});
test("writeLibrarySite: no stories gives an empty index and no story folder files", () => {
  const out = tmp();
  const r = writeLibrarySite({ reports: R, actors, cards: new Map(), stories: new Map(), outDir: out, builtAt: "t", warn() {} });
  assert.deepEqual(JSON.parse(readFileSync(join(out, "library", "stories.json"), "utf8")).stories, []); assert.equal(r.counts.stories, 0);
  assert.deepEqual(files(join(out, "library", "cards")), []);
  rmSync(out, { recursive: true });
});

test("byline: the published byline is the constant and a different stored byline is not published", () => {
  assert.equal(STORY_BY, CHECK_BY); assert.equal(siteStory({ live: S }, R).by, CHECK_BY);
  const w = [];
  assert.equal(siteStory({ live: { ...S, by: "A human" } }, R, (m) => w.push(m)), null);
  assert.ok(w.some((m) => m.includes("a-1")));
});
test("publishLibrary: a failure in the new story/card code is a warning and the index is still written", () => {
  const out = tmp(), warns = [];
  const r = publishLibrary({ reports: R, actors, loadCards: () => { throw new Error("cards exploded"); }, loadStories: () => new Map(), outDir: out, builtAt: "t", warn: (m) => warns.push(m) });
  assert.ok(warns.some((m) => m.includes("cards exploded"))); assert.equal(r.indexed, true);
  const ix = JSON.parse(readFileSync(join(out, "orkl-index.json"), "utf8"));
  assert.equal(ix.reports_total, 2); assert.ok(ix.reports.every((x) => !("k" in x)) && ix.actors.every((a) => !("st" in a)));
  rmSync(out, { recursive: true });
});

const snapDir = (d) => { const o = {}; const walk = (p, r) => { for (const n of readdirSync(p, { withFileTypes: true })) { const q = join(p, n.name), k = r + "/" + n.name; if (n.isDirectory()) walk(q, k); else o[k] = readFileSync(q, "utf8"); } }; if (existsSync(d)) walk(d, ""); return o; };
const firstBuild = (out, over = {}) => writeLibrarySite({ reports: R, actors, cards: cardsMap(card("a")), stories: new Map([["a-1", { live: S, next: null }]]), outDir: out, builtAt: "first", warn() {}, ...over });
const second = (out, over = {}) => writeLibrarySite({ reports: R, actors, cards: cardsMap(card("a"), card("b")), stories: new Map(), outDir: out, builtAt: "second", ...over });
const strays = (out) => readdirSync(out).filter((f) => /^library\.(tmp|old)-/.test(f));
const failNth = (name, n) => { let i = 0; return { ...fsReal, [name]: (...a) => { if (++i === n) throw new Error(name + " failed"); return fsReal[name](...a); } }; };
const fsReal = { writeFileSync, renameSync, rmSync, mkdirSync };

test("writeLibrarySite (a): a write failure in the temp phase leaves the previous library folder intact and no temp folder", () => {
  const out = tmp(), warns = []; firstBuild(out); const before = snapDir(join(out, "library"));
  const r = second(out, { warn: (m) => warns.push(m), io: failNth("writeFileSync", 2) });
  assert.deepEqual(snapDir(join(out, "library")), before); assert.deepEqual(strays(out), []);
  assert.ok(warns.some((m) => m.includes("writeFileSync failed"))); assert.deepEqual(r, { counts: {}, links: {} });
  rmSync(out, { recursive: true });
});
test("writeLibrarySite (b): a failure of the second rename restores the previous folder", () => {
  const out = tmp(), warns = []; firstBuild(out); const before = snapDir(join(out, "library"));
  second(out, { warn: (m) => warns.push(m), io: failNth("renameSync", 2) });
  assert.deepEqual(snapDir(join(out, "library")), before); assert.deepEqual(strays(out), []);
  assert.ok(warns.some((m) => m.includes("renameSync failed") && !/missing/.test(m)));
  rmSync(out, { recursive: true });
});
test("writeLibrarySite (c): on a first-ever build a rename failure leaves no library, no temp folder, and warns", () => {
  const out = tmp(), warns = [];
  const r = second(out, { warn: (m) => warns.push(m), io: failNth("renameSync", 1) });
  assert.equal(existsSync(join(out, "library")), false); assert.deepEqual(strays(out), []);
  assert.ok(warns.length >= 1); assert.deepEqual(r, { counts: {}, links: {} });
  rmSync(out, { recursive: true });
});
test("writeLibrarySite: if the restore also fails the warning says the Library output is missing", () => {
  const out = tmp(), warns = []; firstBuild(out);
  let n = 0; const io = { ...fsReal, renameSync: (a, b) => { if (++n >= 2) throw new Error("rename failed"); return renameSync(a, b); } };
  second(out, { warn: (m) => warns.push(m), io });
  assert.ok(warns.some((m) => /missing/.test(m)));
  rmSync(out, { recursive: true, force: true });
});
test("writeLibrarySite (d): leftovers from any pid, and the previous layout, are removed", () => {
  const out = tmp(); firstBuild(out);
  for (const n of ["library.tmp-111", "library.old-222", "orkl-cards", "orkl-stories", "orkl-cards.tmp-9", "orkl-stories.old.tmp-9"]) mkdirSync(join(out, n));
  writeFileSync(join(out, "orkl-stories.json"), "{}"); writeFileSync(join(out, "orkl-stories.json.tmp-9"), "{}"); writeFileSync(join(out, "library.tmp-5"), "x");
  second(out, { warn() {} });
  assert.deepEqual(readdirSync(out).sort(), ["library"]);
  rmSync(out, { recursive: true });
});
test("writeLibrarySite (e): a crash between the two renames is recovered from the one .old folder", () => {
  const out = tmp(); firstBuild(out); const before = snapDir(join(out, "library"));
  renameSync(join(out, "library"), join(out, "library.old-777"));
  const r = second(out, { warn() {}, io: failNth("writeFileSync", 1) });   // the new publish fails, so what remains is the recovered folder
  assert.deepEqual(snapDir(join(out, "library")), before); assert.deepEqual(strays(out), []); assert.deepEqual(r.counts, {});
  rmSync(out, { recursive: true });
});
test("writeLibrarySite (f): storyLinks throwing still leaves the swapped-in files and returns links {}", () => {
  const out = tmp(), warns = [];
  const r = second(out, { warn: (m) => warns.push(m), linksFn: () => { throw new Error("links exploded"); } });
  assert.deepEqual(r.links, {}); assert.equal(r.counts.cards_read, 2);
  assert.deepEqual(files(join(out, "library", "cards")), ["aa.json", "bb.json"]); assert.ok(warns.some((m) => m.includes("links exploded")));
  rmSync(out, { recursive: true });
});
