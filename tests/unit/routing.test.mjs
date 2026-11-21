// Opus where it counts (owner, 2026-11-21): which researcher, updater and follow-up batches run on the deep roles.
// scripts/lib/routing.mjs, scripts/sweep-plan.mjs route, scripts/updates.mjs planUpdates, scripts/run-job.mjs researcherRole.
// Run: node --test tests/unit/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { deepReason, deepEvent, followupDeep, followupCandidates, roleFor, baseRole } from "../../scripts/lib/routing.mjs";
import { route } from "../../scripts/sweep-plan.mjs";
import { planUpdates } from "../../scripts/updates.mjs";
import { researcherRole, runLogPattern, workerArgs } from "../../scripts/run-job.mjs";

const st = (o = {}) => ({ id: o.id || "s", title: "t", score: 10, publishers: 1, kinds: [], tiers: ["news"], leads: [{ tier: "news" }], incident: false, routine: false, explainer: false, claim_only: false, ...o });
const MODELS = JSON.parse(readFileSync(new URL("../../config/models.json", import.meta.url)));

test("stories that need judgment go deep; routine bulletins and single-source headlines do not", () => {
  assert.equal(deepReason(st({ kinds: ["exploited"], routine: true })), "exploited flaw");
  assert.equal(deepReason(st({ incident: true })), "incident");
  assert.equal(deepReason(st({ leads: [{ tier: "gov" }] })), "official report");
  assert.equal(deepReason(st({ leads: [{ tier: "gov", kind: "cve" }] })), "", "a database row is not an official report");
  assert.equal(deepReason(st({ publishers: 3 })), "3 publishers");
  assert.equal(deepReason(st({ publishers: 3, routine: true })), "", "a routine bulletin stays on the base model");
  assert.equal(deepReason(st()), "");
  assert.equal(deepReason(st({ incident: true, explainer: true })), "");
  assert.equal(deepReason(st({ incident: true, claim_only: true })), "");
});

test("events: severity 3 or exploited go to the deep updater and follow-up desk", () => {
  assert.equal(deepEvent({ severity: 3 }), true);
  assert.equal(deepEvent({ severity: 2, cve_meta: [{ id: "CVE-2026-1", kev: true }] }), true);
  assert.equal(deepEvent({ severity: 2, tags: ["zero-day"] }), true);
  assert.equal(deepEvent({ severity: 2, title: "Flaw exploited in the wild" }), true);
  assert.equal(deepEvent({ severity: 2, title: "Acme breach" }), false);
  const now = Date.parse("2026-11-22T12:00:00Z");
  const evs = [{ id: "a", date: "2026-11-20", status: "developing", severity: 2, updated_at: "2026-11-20T00:00:00Z" }, { id: "b", date: "2026-11-20", status: "confirmed", severity: 3, updated_at: "2026-11-22T11:00:00Z" }];
  assert.deepEqual(followupCandidates(evs, now).map((e) => e.id), ["a"], "b was updated in the last 24 hours");
  assert.equal(followupDeep(evs, now), false);
  assert.equal(followupDeep(evs.concat([{ id: "c", date: "2026-11-19", status: "confirmed", severity: 3, updated_at: "2026-11-19T00:00:00Z" }]), now), true);
});

test("roleFor: the deep role only when it is configured; the prompt is the base role's", () => {
  assert.equal(roleFor("researcher", true, MODELS), "researcher-deep");
  assert.equal(roleFor("researcher", false, MODELS), "researcher");
  assert.equal(roleFor("researcher", true, { roles: { researcher: {} } }), "researcher", "no deep role configured: the base role");
  assert.equal(baseRole("followup-deep"), "followup");
  for (const r of ["researcher-deep", "updater-deep", "followup-deep"]) {
    assert.equal(MODELS.roles[r].model, "opus"); assert.equal(MODELS.min_tier[r], "opus");
    assert.equal(workerArgs(r, "p", MODELS).model, "opus");
  }
  assert.equal(MODELS.roles.reviewer.model, "sonnet", "reviewers stay on Sonnet");
});

test("sweep plan: deep and routine stories in separate batches, within the researcher cap", () => {
  const deep = Array.from({ length: 10 }, (_, i) => st({ id: "d" + i, incident: true })), plain = Array.from({ length: 5 }, (_, i) => st({ id: "p" + i }));
  const r = route(deep.concat(plain), 8, 8);
  assert.deepEqual(r.map((b) => [b.deep, b.stories.length]), [[true, 5], [true, 5], [false, 5]]);
  assert.ok(r.every((b) => b.stories.every((s) => !!deepReason(s) === b.deep)), "never mixed");
  const capped = route(deep.concat(plain), 2, 4);
  assert.equal(capped.length, 2); assert.deepEqual(capped.map((b) => b.deep), [true, false]);
  assert.equal(capped.flatMap((b) => b.stories).length, 15, "every chosen story keeps a batch");
  assert.deepEqual(route(plain, 8, 8).map((b) => b.deep), [false]);
  assert.deepEqual(route([], 8, 8), []);
});

test("researcherRole follows the plan's deep batches, also for a retry", () => {
  const plan = { deep: [1], stories: [{ id: "a", batch: 1, deep: "incident" }, { id: "b", batch: 2 }], retry: ["a"] };
  assert.equal(researcherRole(plan, 1, MODELS), "researcher-deep");
  assert.equal(researcherRole(plan, 2, MODELS), "researcher");
  assert.equal(researcherRole(plan, "retry", MODELS), "researcher-deep");
  assert.equal(researcherRole({ ...plan, retry: ["b"] }, "retry", MODELS), "researcher");
  assert.equal(researcherRole({ backlog: true, stories: [{ id: "x", batch: 1, deep: "incident" }] }, 1, MODELS), "researcher-deep", "a backlog plan marks stories only");
  assert.equal(researcherRole({}, 1, MODELS), "researcher");
});

test("update plan: severity 3 and exploited events get their own (deep) updaters", () => {
  const c = (id, deep) => ({ id, deep });
  const r = planUpdates([c("a", true), c("b", false), c("c", false), c("d", true), c("e", false)], 2, 3);
  assert.deepEqual(r.batches.map((b) => b.map((x) => x.id)), [["a", "d"], ["b", "c", "e"]]);
  assert.deepEqual(r.deep, [1]);
  const one = planUpdates([c("a", true), c("b", false), c("c", false)], 1, 3);
  assert.deepEqual(one.batches.map((b) => b.map((x) => x.id)), [["a"]], "one updater: the deep events first, the rest wait for the next cycle");
  assert.deepEqual(one.deep, [1]);
  assert.deepEqual(planUpdates([], 2, 3), { batches: [], deep: [] });
});

test("run logs are stamped by the worker's role: the file names each role writes", () => {
  assert.ok(runLogPattern("researcher-deep", 3).test("1015-sweep-r3.json"));
  assert.ok(!runLogPattern("researcher", 1).test("1015-sweep-r10.json"));
  assert.ok(runLogPattern("updater-deep", 2).test("1015-update-u2-2.json"));
  assert.ok(runLogPattern("followup-deep", null).test("0900-followup.json"));
  assert.equal(runLogPattern("reviewer", 1), null);
});
