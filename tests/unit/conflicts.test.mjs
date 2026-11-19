import { test } from "node:test";
import assert from "node:assert/strict";
import { hasMarkers, sides, healText } from "../../scripts/lib/conflicts.mjs";

const M = (a, b) => `<<<<<<< Updated upstream\n${a}\n=======\n${b}\n>>>>>>> Stashed changes`;

test("finds markers only when all three are present", () => {
  assert.equal(hasMarkers(`x\n${M("a", "b")}\ny`), true);
  assert.equal(hasMarkers("======= just a line\n"), false);
  assert.equal(hasMarkers("a\n=======\nb\n"), false);
});

test("splits a marked text into its two whole versions", () => {
  assert.deepEqual(sides(`top\n${M("u1\nu2", "m1")}\nend`), ["top\nu1\nu2\nend", "top\nm1\nend"]);
});

test("line files heal to the union of both sides, no duplicates, no markers", () => {
  const t = `{"a":1}\n${M('{"b":2}', '{"b":2}\n{"c":3}')}\n{"d":4}\n`;
  const h = healText("data/leads/x.jsonl", t);
  assert.equal(hasMarkers(h), false);
  assert.deepEqual(h.trim().split("\n"), ['{"a":1}', '{"b":2}', '{"d":4}', '{"c":3}']);
});

test("JSON objects heal by key, this run's keys win, nothing is lost", () => {
  const t = `{\n  "keep": 1,\n${M('  "at": "old",\n  "up_only": true', '  "at": "new",\n  "mine_only": true')}\n}\n`;
  const h = JSON.parse(healText("data/osint.json", t));
  assert.deepEqual(h, { keep: 1, at: "new", up_only: true, mine_only: true });
});

test("anything else is refused, never guessed", () => {
  assert.equal(healText("scripts/x.mjs", M("a", "b")), null);
  assert.equal(healText("data/bad.json", M("[1", "2]")), null);
  assert.equal(healText("data/ok.json", '{"a":1}\n'), '{"a":1}\n');
});
