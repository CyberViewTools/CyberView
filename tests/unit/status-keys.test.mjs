// status.json never loses other jobs' keys (2026-11-20: a writer that fell back to {} wiped 18 keys on the data branch)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mergeJson } from "../../scripts/lib/merge.mjs";

test("mergeJson keepKeys: a key this commit lost is kept from main", () => {
  const base = { a: 1, b: 2, c: 3 }, up = { a: 1, b: 5, c: 3 }, mine = { a: 9 };
  assert.deepEqual(mergeJson(base, up, mine, { keepKeys: true }), { a: 9, b: 5, c: 3 });
});
test("mergeJson without keepKeys still deletes what this commit deleted", () => {
  assert.deepEqual(mergeJson({ a: 1, b: 2 }, { a: 1, b: 2 }, { a: 1 }), { a: 1 });
});
test("readStatus falls back to the data branch's last commit, not only main's old layout", () => {
  const src = readFileSync(new URL("../../scripts/lib/store.mjs", import.meta.url), "utf8");
  assert.match(src, /\[DATA, "HEAD:status\.json"\]/);
});
test("git-sync merges status.json with keepKeys", () => {
  const src = readFileSync(new URL("../../scripts/git-sync.mjs", import.meta.url), "utf8");
  assert.match(src, /keepKeys: \/\(\^\|\\\/\)status\\\.json\$\/\.test\(f\)/);
});
