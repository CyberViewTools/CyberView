import { test } from "node:test";
import assert from "node:assert/strict";
import { pick, split, score } from "../../scripts/sweep-plan.mjs";

const S = (id, sc, o = {}) => ({ id, title: "T " + id, score: sc, open: 1, event: "", claim_only: false, regions: [], langs: [], publishers: 1, urls: ["https://x.example/" + id], ...o });
test("pick: strong stories first, thin regions always included, claims and handled stories left out", () => {
  const stories = [S("a", 22), S("b", 15), S("c", 9), S("d", 8), S("claim", 2, { claim_only: true }), S("done", 30, { open: 0 }), S("onfile", 25, { event: "x-y-z" }),
    S("afr", 5, { regions: ["africa"] }), S("ja", 4, { langs: ["ja"] })];
  const p = pick(stories, 5).map((s) => s.id);
  assert.deepEqual(p.slice(0, 2), ["a", "b"]);
  assert.ok(p.includes("afr") && p.includes("ja"), "thin-region and non-English stories get a place even with low scores");
  assert.ok(!p.includes("claim") && !p.includes("done") && !p.includes("onfile"));
  assert.equal(p.length, 5);
});
test("split: every researcher gets a share, strongest dealt round-robin", () => {
  const b = split([S("a", 9), S("b", 8), S("c", 7), S("d", 6), S("e", 5), S("f", 4), S("g", 3)], 3);
  assert.equal(b.length, 3); assert.deepEqual(b.map((x) => x.map((s) => s.id)), [["a", "d", "g"], ["b", "e"], ["c", "f"]]);
  assert.equal(split([S("a", 9), S("b", 8)], 3).length, 1, "two stories do not need three researchers");
  assert.deepEqual(split([], 3), []);
});
test("scorecard: handled means closed, matched to an event, or cited by one", () => {
  const plan = { planned_at: "2026-11-19T00:10:00Z", stories: [{ id: "a", title: "A", score: 9, batch: 1, urls: ["https://x.example/a"] }, { id: "b", title: "B", score: 8, batch: 2, urls: ["https://x.example/b"] },
    { id: "c", title: "C", score: 7, batch: 1, urls: ["https://x.example/c"] }, { id: "gone", title: "G", score: 6, batch: 2, urls: [] }] };
  const now = [S("a", 9, { open: 0 }), S("b", 8), S("c", 7)];   // a closed; b untouched; c cited by a new event; "gone" no longer a story
  const r = score(plan, now, [{ id: "new-event-2026-11", first_seen: "2026-11-19T00:20:00Z", sources: [{ url: "https://x.example/c" }] }, { id: "old-one", first_seen: "2026-11-18T10:00:00Z", sources: [] }]);
  assert.equal(r.planned, 4); assert.equal(r.handled, 3); assert.deepEqual(r.untouched.map((u) => u.id), ["b"]); assert.deepEqual(r.added, ["new-event-2026-11"]);
  assert.ok(r.share < 0.8);
});
