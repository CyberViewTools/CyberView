import { test } from "node:test";
import assert from "node:assert/strict";
import { nameKey, actorIndex, actorSubjects, eligibleLoose, looseSubjects, basedOn } from "../../scripts/lib/library-subjects.mjs";

const h = (c) => c.repeat(40);
const TT = { id: "7", name: "TT Group", aliases: ["Tee Tee"], tools: ["PlugX"] };
const QUIET = { id: "8", name: "QuietActor", aliases: [], tools: [] };
const rep = (c, actors, created = "2024-01-01") => ({ sha1: h(c), actors, created, title: "t" });
const repTT1 = rep("a", ["TT Group"]), repTT2 = rep("b", ["tee  tee"]);
const facts = (n) => ({ tools: Array.from({ length: n }, (_, i) => ({ v: "tool" + i, q: "q" })), techniques: [], sectors: [], countries: [], dates: [], cves: [] });
const card = (r, extra = {}) => ({ sha1: r.sha1, status: "read", kind: "actor-campaign", summary: "s", subject: null, facts: facts(0), read_at: "2026-11-01T00:00:00Z", ...extra });
const cardsFor = (...rs) => new Map(rs.map((r) => [r.sha1, card(r)]));
const richCard = (r, type, name) => card(r, { kind: "malware-analysis", subject: { type, name }, facts: facts(4) });
const thinCard = (r) => card(r, { kind: "malware-analysis", subject: { type: "malware", name: "Thin" }, facts: facts(1) });
const EMPTY_IX = actorIndex([]);

test("nameKey: case, spacing, punctuation and compatibility forms are ignored", () => {
  assert.equal(nameKey("APT-38 "), "apt38"); assert.equal(nameKey("ＡＰＴ 38"), "apt38");
});
test("actorSubjects: every actor gets a subject, with or without reports", () => {
  const s = actorSubjects([TT, QUIET], [repTT1, repTT2], cardsFor(repTT1, repTT2));
  assert.equal(s.length, 2);
  assert.equal(s.find((x) => x.name === "QuietActor").sha1s.length, 0);
  const t = s.find((x) => x.name === "TT Group");
  assert.equal(t.key, "a-7"); assert.equal(t.kind, "actor"); assert.deepEqual([...t.sha1s].sort(), [h("a"), h("b")]);
});
test("actorSubjects: only read cards count", () => {
  const c = cardsFor(repTT1, repTT2); c.get(h("b")).status = "unread";
  assert.deepEqual(actorSubjects([TT], [repTT1, repTT2], c)[0].sha1s, [h("a")]);
});
test("actorIndex: an alias shared by two actors resolves to neither; case and spacing are ignored", () => {
  const ix = actorIndex([{ id: "1", name: "APT 38", aliases: ["Bluenoroff"] }, { id: "2", name: "Stardust", aliases: ["BlueNoroff"] }]);
  assert.equal(ix.byKey.get(nameKey("bluenoroff")), null);
  assert.equal(ix.byKey.get(nameKey("apt38")), "1");
});
test("actorIndex: one actor listing a name twice is not ambiguous", () => {
  assert.equal(actorIndex([{ id: "1", name: "Foo", aliases: ["foo", "FOO"] }]).byKey.get("foo"), "1");
});
test("actorSubjects: a report naming an ambiguous alias joins neither actor", () => {
  const a = [{ id: "1", name: "A", aliases: ["Shared"] }, { id: "2", name: "B", aliases: ["shared"] }];
  const r = rep("c", ["Shared"]);
  assert.ok(actorSubjects(a, [r], cardsFor(r)).every((x) => x.sha1s.length === 0));
});
test("actorSubjects: an actor id unsafe as a file name gets a hashed key", () => {
  assert.match(actorSubjects([{ id: "../x", name: "Odd" }], [], new Map())[0].key, /^a-[0-9a-f]{16}$/);
});
test("eligibleLoose: needs read status, a real kind, a subject name and three facts", () => {
  const r = rep("d", []);
  assert.equal(eligibleLoose(richCard(r, "malware", "PlugX")), true);
  assert.equal(eligibleLoose(thinCard(r)), false);
  assert.equal(eligibleLoose({ ...richCard(r, "malware", "PlugX"), status: "unread" }), false);
  assert.equal(eligibleLoose({ ...richCard(r, "malware", "PlugX"), kind: "overview" }), false);
  assert.equal(eligibleLoose({ ...richCard(r, "malware", "PlugX"), kind: "not-a-threat-report" }), false);
  assert.equal(eligibleLoose(richCard(r, "malware", "AB")), false);
  assert.equal(eligibleLoose({ ...richCard(r, "malware", "PlugX"), subject: null }), false);
});
test("looseSubjects: enough detail makes a story, two cards on one malware combine, thin cards do not", () => {
  const [r1, r2, r3] = [rep("1", []), rep("2", []), rep("3", [])];
  const out = looseSubjects([r1, r2, r3], new Map([[r1.sha1, richCard(r1, "malware", "PlugX")], [r2.sha1, richCard(r2, "malware", "plugx")], [r3.sha1, thinCard(r3)]]), EMPTY_IX);
  assert.equal(out.length, 1); assert.equal(out[0].sha1s.length, 2);
  assert.equal(out[0].kind, "subject"); assert.equal(out[0].actor, null); assert.match(out[0].key, /^s-[0-9a-f]{16}$/);
});
test("looseSubjects: a report that names a known actor is not a loose subject", () => {
  const ix = actorIndex([TT]), r = rep("4", ["TT Group"]);
  assert.equal(looseSubjects([r], new Map([[r.sha1, richCard(r, "malware", "PlugX")]]), ix).length, 0);
});
test("looseSubjects: a report naming only an unknown actor still counts as unattributed", () => {
  const r = rep("5", ["Nobody Known"]);
  assert.equal(looseSubjects([r], new Map([[r.sha1, richCard(r, "malware", "PlugX")]]), EMPTY_IX).length, 1);
});
test("basedOn: changes with a card's read_at, the actor's aliases and tools; ignores order", () => {
  const c = cardsFor(repTT1, repTT2), s = actorSubjects([TT], [repTT1, repTT2], c)[0];
  const b = basedOn(s, c);
  assert.match(b, /^[0-9a-f]{40}$/);
  assert.equal(basedOn({ ...s, sha1s: [...s.sha1s].reverse() }, c), b);
  const c2 = cardsFor(repTT1, repTT2); c2.get(h("a")).read_at = "2026-11-02T00:00:00Z";
  assert.notEqual(basedOn(s, c2), b);
  assert.notEqual(basedOn({ ...s, actor: { ...TT, tools: ["PlugX", "ShadowPad"] } }, c), b);
  assert.notEqual(basedOn({ ...s, actor: { ...TT, aliases: [] } }, c), b);
});
test("basedOn: a card marked unread later drops out and changes it", () => {
  const c = cardsFor(repTT1, repTT2), s = actorSubjects([TT], [repTT1, repTT2], c)[0];
  const b = basedOn(s, c);
  c.get(h("b")).status = "unread";
  assert.notEqual(basedOn(s, c), b);                                    // same subject, the card is no longer read
  assert.equal(basedOn(s, c), basedOn(actorSubjects([TT], [repTT1, repTT2], c)[0], c));
});
