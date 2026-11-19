// scripts/swarm.mjs: frozen plans and reconciliation. Run: node --test tests/unit/
import test from "node:test";
import assert from "node:assert/strict";
import { planBatches, reconcile } from "../../scripts/swarm.mjs";

test("a plan is frozen: same items give the same plan_id; moving one item changes it", () => {
  const items = ["a", "b", "c", "d", "e"].map((id) => ({ id }));
  const p = planBatches(items, 2);
  assert.deepEqual(p.batches.map((b) => b.ids), [["a", "b"], ["c", "d"], ["e"]]);
  assert.equal(planBatches(items, 2).plan_id, p.plan_id);
  assert.notEqual(planBatches([items[1], items[0], ...items.slice(2)], 2).plan_id, p.plan_id);
});

test("reconcile counts every item exactly once, by batch", () => {
  const p = planBatches(["a", "b", "c"].map((id) => ({ id })), 2), r = reconcile(p, (id) => id !== "b");
  assert.equal(r.done, 2); assert.equal(r.missing, 1);
  assert.deepEqual(r.rows.map((x) => x.missing), [["b"], []]);
});
