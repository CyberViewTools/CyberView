// scripts/improve.mjs: the improver can only make small, bounded, explained changes. Run: node --test tests/unit/
import test from "node:test";
import assert from "node:assert/strict";
import { checkChange } from "../../scripts/improve.mjs";

const cfg = { sweep: { researchers: 6, stories_per_researcher: 8, gap_workers: 2 }, max_parallel: 6 };
const models = { min_tier: { "exploit-analyst": "sonnet" }, roles: { researcher: { model: "sonnet", max_turns: 60 }, "exploit-analyst": { model: "sonnet", max_turns: 50 }, "backlog-triager": { model: "haiku", max_turns: 15 } } };
const off = { blocked: false }, on = { blocked: true, why: "second review corrected 44%" };
const why = "the queue stayed above 60 for six hours this week";

test("bounded numbers: one step at a time, inside the bounds, with a reason", () => {
  assert.equal(checkChange({ key: "pipeline.sweep.researchers", to: 7, reason: why }, cfg, models, off), "");
  assert.match(checkChange({ key: "pipeline.sweep.researchers", to: 9, reason: why }, cfg, models, off), /between/);
  assert.match(checkChange({ key: "pipeline.sweep.stories_per_researcher", to: 12, reason: why }, cfg, models, off), /at most a quarter/);
  assert.match(checkChange({ key: "pipeline.sweep.researchers", to: 7, reason: "more" }, cfg, models, off), /reason/);
  assert.match(checkChange({ key: "pipeline.headless", to: 1, reason: why }, cfg, models, off), /not a key/);
});

test("models move one tier, never below a role's floor, and never down while the quality guard is on", () => {
  assert.equal(checkChange({ key: "models.roles.backlog-triager.model", to: "sonnet", reason: why }, cfg, models, off), "");
  assert.match(checkChange({ key: "models.roles.backlog-triager.model", to: "opus", reason: why }, cfg, models, off), /one tier/);
  assert.match(checkChange({ key: "models.roles.exploit-analyst.model", to: "haiku", reason: why }, cfg, models, off), /never goes below/);
  assert.match(checkChange({ key: "models.roles.researcher.model", to: "haiku", reason: why }, cfg, models, on), /quality guard/);
  assert.equal(checkChange({ key: "models.roles.researcher.model", to: "opus", reason: why }, cfg, models, on), "");
  assert.match(checkChange({ key: "models.roles.researcher.max_turns", to: 40, reason: why }, cfg, models, off), /a quarter/);
  assert.match(checkChange({ key: "pipeline.sweep.researchers", to: 5, reason: why }, cfg, models, on), /quality guard/);
  assert.match(checkChange({ key: "pipeline.sweep.researchers", to: 7, reason: why }, cfg, models, off, new Set(["pipeline.sweep.researchers"])), /already changed today/);
});
