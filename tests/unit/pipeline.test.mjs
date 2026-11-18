import { test } from "node:test";
import assert from "node:assert/strict";
import { checkOutputs, checkShrink } from "../../scripts/verify-build.mjs";
import { assess, LIMITS } from "../../scripts/guard.mjs";

const NOW = Date.parse("2026-11-18T23:30:00Z"), ago = (m) => new Date(NOW - m * 6e4).toISOString();
const ev = (id) => ({ id, title: "T", date: "2026-11-18", category: "incident", severity: 2 });
const good = () => ({ "bundle.json": { built_at: ago(1), events: [ev("a-b-c"), ev("d-e-f")], kev: [], docs: {} }, "archive/index.json": { total: 5 }, "archive/search.json": { rows: [1, 2, 3, 4, 5] },
  "workbench.json": { kev: [], guides: {} }, "ops.json": { routines: [{}] }, "chat.json": { posts: [] }, "trends.json": {}, "tabletop.json": {}, "health.json": {}, "feed.json": {} });

test("build outputs: a good build passes", () => { assert.deepEqual(checkOutputs(good(), NOW), []); });
test("build outputs: empty, malformed, duplicated, stale or unreviewed content is refused", () => {
  let f = good(); f["bundle.json"].events = []; assert.ok(checkOutputs(f, NOW).some((m) => /no events/.test(m)));
  f = good(); f["bundle.json"].events.push({ id: "x", title: "" }); assert.ok(checkOutputs(f, NOW).some((m) => /lack an id, title/.test(m)));
  f = good(); f["bundle.json"].events.push(ev("a-b-c")); assert.ok(checkOutputs(f, NOW).some((m) => /twice/.test(m)));
  f = good(); f["bundle.json"].built_at = ago(300); assert.ok(checkOutputs(f, NOW).some((m) => /not fresh/.test(m)));
  f = good(); f["chat.json"].posts = [{ id: 1, text: "x" }]; assert.ok(checkOutputs(f, NOW).some((m) => /without a review/.test(m)));
  f = good(); delete f["workbench.json"]; assert.ok(checkOutputs(f, NOW).some((m) => /workbench\.json is missing/.test(m)));
  f = good(); f["archive/index.json"].total = 1; assert.ok(checkOutputs(f, NOW).length >= 1);
});
test("shrink guard: a build that lost events on file is refused; normal movement is fine", () => {
  assert.deepEqual(checkShrink({ events_total: 210, events_bundle: 190, kev_total: 49 }, { events_total: 208, events_bundle: 207, kev_total: 49 }), []);
  assert.ok(checkShrink({ events_total: 150, events_bundle: 140, kev_total: 49 }, { events_total: 208, events_bundle: 207, kev_total: 49 })[0].includes("events_total fell from 208"));
  assert.ok(checkShrink({ events_total: 208, events_bundle: 60, kev_total: 49 }, { events_total: 208, events_bundle: 207, kev_total: 49 })[0].includes("events_bundle"));
  assert.deepEqual(checkShrink({ events_total: 3 }, { events_total: 5 }), [], "tiny datasets are not judged");
  assert.deepEqual(checkShrink({ events_total: 3 }, null), []);
});

const live = (o = {}) => ({ manifest: { built_at: ago(10), commit: "abc1234567" }, health: { last_sweep_at: ago(40), last_collect_at: ago(20), last_feeds_at: ago(60), quarantined_count: 0 }, bundle: { events: new Array(50).fill(ev("a-b-c")) },
  head: { sha: "abc1234567", date: ago(12) }, deploy: { conclusion: "success" }, ...o });
test("guard: healthy when everything is recent and live matches main", () => { assert.deepEqual(assess(live(), NOW), { fails: [], warns: [], heal: [] }); });
test("guard: stale data, a stuck sweep and an undeployed commit are failures with a repair", () => {
  let r = assess(live({ manifest: { built_at: ago(LIMITS.build_min + 30), commit: "abc1234567" } }), NOW); assert.ok(r.fails[0].includes("minutes ago")); assert.ok(r.heal.includes("collect"));
  r = assess(live({ health: { last_sweep_at: ago(400), last_collect_at: ago(20), last_feeds_at: ago(60) } }), NOW); assert.ok(r.fails.some((m) => /the sweep/.test(m))); assert.ok(r.heal.includes("sweep"));
  r = assess(live({ head: { sha: "fff9999", date: ago(45) } }), NOW); assert.ok(r.fails.some((m) => /main is at fff9999/.test(m))); assert.ok(r.heal.includes("deploy"));
  r = assess(live({ head: { sha: "fff9999", date: ago(3) } }), NOW); assert.deepEqual(r.fails, [], "a commit pushed minutes ago is still deploying");
  r = assess({ manifest: null, health: null, bundle: null }, NOW); assert.ok(r.fails[0].includes("could not be read"));
});
test("guard: late mechanical jobs and quarantined records are warnings", () => {
  let r = assess(live({ health: { last_sweep_at: ago(40), last_collect_at: ago(300), last_feeds_at: ago(60), quarantined_count: 2, quarantined: ["events/x.json: missing title"] } }), NOW);
  assert.deepEqual(r.fails, []); assert.equal(r.warns.length, 2); assert.ok(r.heal.includes("collect"));
});
