// Two writers of grid line files (the research loop and collect.yml) merge by key, and JSON writes are atomic.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mergeKeyed } from "../../scripts/lib/merge.mjs";
import { dedupeSeries, dedupeHistory } from "../../scripts/grid.mjs";
import { writeJson } from "../../scripts/lib/store.mjs";

const lines = (...o) => o.map((x) => JSON.stringify(x)).join("\n") + "\n";
const parse = (t) => t.trim().split("\n").map((l) => JSON.parse(l));

test("grid series: one point per source|region|slot, slot lines merge their ok lists", () => {
  const up = lines({ at: "2026-11-20T03:00:00Z", ok: ["a"] }, { source: "a", region: "r", at: "2026-11-20T03:00:00Z", customers: 10 });
  const mine = lines({ at: "2026-11-20T03:00:00Z", ok: ["b"] }, { source: "a", region: "r", at: "2026-11-20T03:00:00Z", customers: 12 });
  const out = parse(mergeKeyed(up, mine, dedupeSeries));
  assert.deepEqual(out.filter((x) => x.ok), [{ at: "2026-11-20T03:00:00Z", ok: ["a", "b"] }]);
  assert.equal(out.filter((x) => x.source === "a").length, 1, "a whole-line union would keep both points");
});

test("grid history: one line per closed incident, earliest closure wins, a reopened one wins over its old closure", () => {
  const up = lines({ id: "x", closed_at: "2026-11-20T03:10:00Z" }, { id: "y", closed_at: "2026-11-20T01:00:00Z" });
  const mine = lines({ id: "x", closed_at: "2026-11-20T03:05:00Z" }, { id: "y", closed_at: "2026-11-20T04:00:00Z", reopened_at: "2026-11-20T02:00:00Z" });
  const out = Object.fromEntries(parse(mergeKeyed(up, mine, dedupeHistory)).map((x) => [x.id, x]));
  assert.equal(out.x.closed_at, "2026-11-20T03:05:00Z");
  assert.equal(out.y.reopened_at, "2026-11-20T02:00:00Z");
});

test("keyed merge keeps lines that do not parse", () => {
  assert.match(mergeKeyed('{"id":"a","closed_at":"1"}\nnot json\n', "", dedupeHistory), /not json/);
});

test("writeJson writes atomically and leaves no temporary file", () => {
  const d = mkdtempSync(join(tmpdir(), "cv-wj-")), p = join(d, "x.json");
  writeJson(p, { a: 1 }); writeJson(p, { a: 2 });
  assert.deepEqual(JSON.parse(readFileSync(p, "utf8")), { a: 2 });
  assert.deepEqual(readdirSync(d), ["x.json"]);
});
