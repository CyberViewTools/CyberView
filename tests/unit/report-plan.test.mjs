import { test } from "node:test";
import assert from "node:assert/strict";
import { planReports } from "../../scripts/report-plan.mjs";

const NOW = Date.parse("2026-11-24T12:00:00Z");
const day = (n) => new Date(NOW - n * 864e5).toISOString().slice(0, 10);
const ev = (id, o = {}) => ({ id, date: day(1), first_seen: "2026-11-23T10:00:00Z", report: { read_depth: "summary" }, severity: 1, ...o });

test("report plan keeps only summary or secondary reports from the last 8 days", () => {
  const events = [
    ev("ok"),
    ev("full", { report: { read_depth: "full" } }),
    ev("none", { report: undefined }),
    ev("old", { date: day(9) }),
    ev("dup", { duplicate_of: "ok" }),
    ev("sec", { report: { read_depth: "secondary" } }),
  ];
  const { candidates, items } = planReports(events, NOW, 10);
  assert.equal(candidates, 2);
  assert.deepEqual(items.map((e) => e.id).sort(), ["ok", "sec"]);
});

test("report plan orders critical, then high, then routine, newest first inside a tier", () => {
  const events = [
    ev("r-old", { first_seen: "2026-11-22T10:00:00Z" }),
    ev("r-new", { first_seen: "2026-11-23T20:00:00Z" }),
    ev("h", { severity: 2, status: "claimed" }),
    ev("c", { severity: 3 }),
  ];
  const { items } = planReports(events, NOW, 10);
  assert.deepEqual(items.map((e) => e.id), ["c", "h", "r-new", "r-old"]);
});

test("report plan caps the list at max_items, keeping tier order", () => {
  const events = [ev("r1"), ev("c1", { severity: 3 }), ev("r2"), ev("c2", { severity: 3 })];
  const { candidates, items } = planReports(events, NOW, 2);
  assert.equal(candidates, 4);
  assert.equal(items.length, 2);
  assert.ok(items.every((e) => e.id.startsWith("c")), "critical items fill the cap first");
});

test("report plan returns nothing for an empty or unread set", () => {
  assert.deepEqual(planReports([], NOW, 10), { candidates: 0, items: [] });
  assert.deepEqual(planReports([ev("x", { report: undefined })], NOW, 10).items, []);
});
