// The no-result gates (scripts/lib/gates.mjs) and the follow-up desk's planner (scripts/followup-desk.mjs): which items
// get a worker now, which wait, and that every skipped item keeps a reason and the time it is due next.
// Owner, 2026-11-23: "make this highly efficient"; accuracy first; no event lost; no silent drops.
// Run: node --test tests/unit/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { backoffHours, waitText, noChangeRun, followupGate, followupUrgent, claimRecheck, outageRecheck, outageStronger, outageSeen, gapDryRun, gapEveryMinutes, lastRunOf, FOLLOWUP_DEFAULTS } from "../../scripts/lib/gates.mjs";
import { pool, historyFrom, gateAll, makePlan, planLine, cfgOf } from "../../scripts/followup-desk.mjs";

const NOW = Date.parse("2026-11-23T12:00:00Z"), iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z"), h = (n) => iso(NOW - n * 36e5);
const ev = (o = {}) => ({ id: "acme-breach-2026-11", title: "Acme breach", date: "2026-11-20", status: "claimed", severity: 2, first_seen: h(70), updated_at: h(70), ...o });

test("backoff: base, doubling with every look that changed nothing, never above the cap", () => {
  assert.deepEqual([0, 1, 2, 3, 4, 5, 9].map((n) => backoffHours(n, 6, 168)), [6, 12, 24, 48, 96, 168, 168]);
  assert.deepEqual([0, 1, 2, 3].map((n) => backoffHours(n, 24, 168)), [24, 48, 96, 168]);
  assert.equal(backoffHours(3, 6, 24), 24, "a shorter cap");
  assert.equal(backoffHours(0, 72, 24), 72, "a cap under the base never shortens the base");
  assert.equal(backoffHours(-2, 6, 168), 6); assert.equal(backoffHours("x", 0, 0), 6, "bad input falls back to 6 h");
  assert.equal(waitText(Date.parse("2026-11-22T14:05:00Z"), Date.parse("2026-11-23T02:05:00Z")), "nothing new since 2026-11-22 14:05 UTC; due again 2026-11-23 02:05 UTC");
});

test("follow-up gate: an event is planned only when its wait is over", () => {
  // never followed up: due once nobody has touched it for the base (6 h)
  assert.equal(followupGate(ev({ updated_at: h(2) }), [], 0, NOW).plan, false, "written 2 h ago");
  const never = followupGate(ev({ updated_at: h(7) }), [], 0, NOW);
  assert.deepEqual([never.plan, never.why, never.reason], [true, "never", "never followed up"]);
  // one follow-up that changed nothing: 12 h; two: 24 h; three: 48 h
  const un = (...hrs) => hrs.map((x) => ({ at: h(x), outcome: "unchanged" }));
  assert.equal(followupGate(ev(), un(10), 0, NOW).plan, false);
  assert.equal(followupGate(ev(), un(13), 0, NOW).plan, true);
  assert.equal(followupGate(ev(), un(20, 40), 0, NOW).plan, false, "two in a row: 24 h");
  assert.equal(followupGate(ev(), un(25, 40), 0, NOW).plan, true);
  assert.equal(followupGate(ev(), un(30, 50, 60), 0, NOW).plan, false, "three in a row: 48 h");
  const g = followupGate(ev(), un(30, 50, 60), 0, NOW);
  assert.equal(g.why, "wait"); assert.equal(g.next_at, iso(NOW - 30 * 36e5 + 48 * 36e5)); assert.equal(g.n, 3);
  assert.match(g.reason, /^skipped: nothing new since 2026-11-22 06:00 UTC; due again 2026-11-24 06:00 UTC \(3 follow-ups in a row without a change\)$/, "a skip always carries its reason and the next time");
  // never longer than the cap (7 days)
  assert.equal(followupGate(ev({ updated_at: h(400), first_seen: h(400) }), un(169, 200, 230, 260, 290, 320, 350), 0, NOW).plan, true);
});

test("follow-up gate: an update ends the run of no-change looks; an unfinished hand-out does not lengthen the wait", () => {
  // the last follow-up updated the event: back to the base
  assert.deepEqual(noChangeRun([{ at: h(8), outcome: "updated" }, { at: h(30), outcome: "unchanged" }]), { n: 0, last: NOW - 8 * 36e5 });
  assert.equal(followupGate(ev({ updated_at: h(8) }), [{ at: h(8), outcome: "updated" }, { at: h(30), outcome: "unchanged" }], 0, NOW).plan, true);
  // somebody else (an updater, a researcher) updated it after the last look: the story moved, the count starts again
  assert.equal(noChangeRun([{ at: h(30), outcome: "unchanged" }, { at: h(50), outcome: "unchanged" }], h(10)).n, 0);
  assert.equal(followupGate(ev({ updated_at: h(10) }), [{ at: h(30), outcome: "unchanged" }, { at: h(50), outcome: "unchanged" }], 0, NOW).plan, true, "10 h since the update, base 6 h");
  assert.equal(followupGate(ev({ updated_at: h(3) }), [{ at: h(30), outcome: "unchanged" }], 0, NOW).plan, false, "updated 3 h ago: leave it");
  // unfinished (the worker was cut off): handed out again after the base wait, and the wait does not grow
  const cut = [{ at: h(4), outcome: "unfinished" }, { at: h(20), outcome: "unchanged" }];
  assert.equal(noChangeRun(cut).n, 1);
  assert.equal(followupGate(ev(), cut, 0, NOW).plan, false, "4 h after it was handed out: not in the very next run");
  assert.equal(followupGate(ev(), [{ at: h(13), outcome: "unfinished" }, { at: h(20), outcome: "unchanged" }], 0, NOW).plan, true, "12 h (one no-change look), not 24");
});

test("follow-up gate: something new to read cuts the wait to zero; urgent events keep a shorter cap", () => {
  const checks = [{ at: h(5), outcome: "unchanged" }, { at: h(30), outcome: "unchanged" }, { at: h(50), outcome: "unchanged" }];
  assert.equal(followupGate(ev(), checks, 0, NOW).plan, false);
  const g = followupGate(ev(), checks, h(2), NOW);
  assert.deepEqual([g.plan, g.why], [true, "new-lead"]); assert.match(g.reason, /^new reporting since the last follow-up/);
  assert.equal(followupGate(ev(), checks, h(9), NOW).plan, false, "that page was already there at the last follow-up");
  // severity 3, exploited and developing events: never longer than urgent_max_hours (24)
  const many = [26, 60, 90, 120, 150].map((x) => ({ at: h(x), outcome: "unchanged" }));
  assert.equal(followupGate(ev(), many, 0, NOW).plan, false, "routine: 5 in a row -> 7 days");
  assert.equal(followupGate(ev({ status: "developing" }), many, 0, NOW).plan, true, "developing: 24 h at most");
  assert.equal(followupGate(ev({ severity: 3 }), many, 0, NOW).plan, true);
  assert.equal(followupGate(ev(), many, 0, NOW, {}, true).plan, true, "exploited (the caller passes deepEvent)");
  assert.equal(followupUrgent({ severity: 2, status: "claimed" }), false); assert.equal(followupUrgent({ severity: 2, status: "claimed" }, true), true);
  // dials: config/pipeline.json followup_desk
  assert.equal(followupGate(ev({ updated_at: h(7) }), [], 0, NOW, { base_hours: 12 }).plan, false);
  // an event in the pool only for its severity waits longer for its FIRST follow-up
  assert.equal(followupGate(ev({ severity: 3, status: "official", updated_at: h(30) }), [], 0, NOW, {}, true, 72).plan, false);
  assert.equal(followupGate(ev({ severity: 3, status: "official", updated_at: h(73) }), [], 0, NOW, {}, true, 72).plan, true);
});

test("follow-up desk: the pool, the history from run logs, and every candidate either planned or skipped with a reason", () => {
  const events = [
    ev({ id: "dev-incident-2026-11", status: "developing", severity: 3, updated_at: h(30) }),
    ev({ id: "claim-fresh-2026-11", updated_at: h(1) }),
    ev({ id: "claim-checked-2026-11" }),
    ev({ id: "claim-moved-2026-11" }),
    ev({ id: "advisory-sev3-2026-11", status: "official", severity: 3, updated_at: h(20) }),
    ev({ id: "settled-2026-11", status: "confirmed", severity: 2 }),                      // not in the pool
    ev({ id: "old-2026-10", date: "2026-11-01" }),                                        // older than window_days
    ev({ id: "dupe-2026-11", duplicate_of: "claim-checked-2026-11" }),
    ev({ id: "held-2026-11", status: "developing", updated_at: h(30) }),
  ];
  assert.deepEqual(pool(events, NOW).map((e) => e.id), ["dev-incident-2026-11", "claim-fresh-2026-11", "claim-checked-2026-11", "claim-moved-2026-11", "advisory-sev3-2026-11", "held-2026-11"]);
  const logs = [
    { job: "followup", finished_at: h(8), updated: ["dev-incident-2026-11"], unchanged_checked: [{ id: "claim-checked-2026-11", url: "https://x.example/a" }, { id: "claim-moved-2026-11", url: "https://x.example/b" }], skipped: [{ title: "a page", url: "https://x.example/c", reason: "no id" }] },
    { job: "followup", finished_at: h(40), updated: [{ id: "dev-incident-2026-11" }], unchanged_checked: [{ id: "claim-checked-2026-11", url: "https://x.example/a" }] },
    { job: "followup-1-unfinished", finished_at: h(3), unfinished: ["held-2026-11"], updated: [] },
    { job: "followup", updated: ["no-time-2026-11"] }, null,
  ];
  const hist = historyFrom(logs);
  assert.deepEqual(hist.get("claim-checked-2026-11").map((x) => x.outcome), ["unchanged", "unchanged"]);
  assert.deepEqual(hist.get("dev-incident-2026-11").map((x) => x.outcome), ["updated", "updated"]);
  assert.deepEqual(hist.get("held-2026-11"), [{ at: h(3), outcome: "unfinished" }]);
  assert.equal(hist.has("no-time-2026-11"), false, "a log without a time is not a look");
  const leads = new Map([["claim-moved-2026-11", [{ url: "https://news.example/n", title: "Acme confirms", source: "Example", published: h(2) }]]]);
  const g = gateAll(events, hist, leads, NOW, {}, new Set(["dev-incident-2026-11"]));
  assert.deepEqual(g.due.map((d) => [d.id, d.why]), [["claim-moved-2026-11", "new-lead"]], "only the event with something new to read");
  assert.equal(g.due[0].leads[0].url, "https://news.example/n");
  const why = Object.fromEntries(g.skipped.map((s) => [s.id, s.reason]));
  assert.equal(g.due.length + g.skipped.length, 6, "every pool event is either planned or skipped: none is dropped");
  assert.match(why["claim-fresh-2026-11"], /^skipped: nothing new since/);
  assert.match(why["claim-checked-2026-11"], /2 follow-ups in a row without a change/);
  assert.match(why["advisory-sev3-2026-11"], /^skipped: nothing new since/, "a settled severity 3 advisory waits sev3_quiet_hours for its first follow-up");
  assert.match(why["held-2026-11"], /^skipped: nothing new since/);
  assert.match(why["dev-incident-2026-11"], /another worker holds this event/, "due (8 h since its update), but an updater has it this cycle");
  assert.ok(g.skipped.every((s) => s.next_at), "each with the time it is due next");
  assert.equal(cfgOf({ base_hours: 3 }).base_hours, 3); assert.equal(cfgOf().per_worker, FOLLOWUP_DEFAULTS.per_worker);
});

test("follow-up desk: small batches, deep events in their own, the rest left for the next run and counted", () => {
  const d = (id, deep, o = {}) => ({ id, title: id, severity: deep ? 3 : 2, status: "developing", deep, why: "due", reason: "r", next_at: h(1), leads: [], ...o });
  const due = [d("a", true), d("b", false), d("c", true), d("d", false), d("e", false), d("f", true)];
  const p = makePlan(due, 2, 2);
  assert.deepEqual(p.batches.map((b) => [b.batch, b.deep, b.events.map((e) => e.id)]), [[1, true, ["a", "c"]], [2, false, ["b", "d"]]]);
  assert.deepEqual(p.deep, [1]); assert.deepEqual(p.left.map((e) => e.id), ["e", "f"]);
  assert.deepEqual(makePlan(due, 4, 2).batches.map((b) => b.deep), [true, false, false, true], "batches in the order of their best event");
  assert.deepEqual(makePlan([], 2, 2), { batches: [], deep: [], left: [] }, "nothing due: no batch, so no worker is started");
  assert.equal(planLine(p, { skipped: [{ id: "x", next_at: "2026-11-23T14:30:00Z" }, { id: "y", next_at: "2026-11-24T00:00:00Z" }] }),
    "FOLLOW-UP PLAN: 4 event(s) for 2 worker(s), 1 on the deep model; 2 due and left for the next run; 2 skipped: nothing new since their last follow-up (the next is due 2026-11-23 14:30 UTC).");
  // the dials in config/pipeline.json exist and the turn caps match a batch of two events
  const pipe = JSON.parse(readFileSync(new URL("../../config/pipeline.json", import.meta.url))), models = JSON.parse(readFileSync(new URL("../../config/models.json", import.meta.url)));
  for (const k of ["window_days", "base_hours", "max_hours", "urgent_max_hours", "sev3_quiet_hours", "workers", "per_worker"]) assert.ok(Number(pipe.followup_desk[k]) > 0, k);
  assert.ok(pipe.followup_desk.urgent_max_hours < pipe.followup_desk.max_hours);
  assert.ok(models.roles["followup-deep"].max_turns <= 20, "the follow-up desk on the deep model has a hard turn cap");
  assert.equal(models.roles["followup-deep"].model, "opus"); assert.equal(models.roles.followup.model, "sonnet");
});

test("claims gate: 24 h, 48 h, 96 h, capped; a new report re-opens at once; an exhausted claim only by a new report", () => {
  const r = (hrs, same, o = {}) => ({ decision: "unconfirmed", checked_at: h(hrs), tries: same, same, ...o });
  assert.equal(claimRecheck(null, 0, NOW).due, true, "never checked");
  assert.deepEqual([claimRecheck(r(23, 1), 0, NOW).due, claimRecheck(r(25, 1), 0, NOW).due], [false, true]);
  assert.deepEqual([claimRecheck(r(47, 2), 0, NOW).due, claimRecheck(r(49, 2), 0, NOW).due], [false, true]);
  assert.deepEqual([claimRecheck(r(95, 3), 0, NOW).due, claimRecheck(r(97, 3), 0, NOW).due], [false, true]);
  assert.deepEqual([claimRecheck(r(167, 6), 0, NOW).due, claimRecheck(r(169, 6), 0, NOW).due], [false, true], "capped at 7 days");
  assert.equal(claimRecheck(r(13, 1), 0, NOW, { recheck_hours: 12 }).due, true, "claims_desk.recheck_hours stays the base");
  const w = claimRecheck(r(30, 2), 0, NOW);
  assert.equal(w.why, "wait"); assert.equal(w.next_at, iso(NOW - 30 * 36e5 + 48 * 36e5)); assert.match(w.reason, /^skipped: nothing new since .*\(unconfirmed 2 times in a row\)$/);
  assert.deepEqual([claimRecheck(r(3, 2), h(1), NOW).due, claimRecheck(r(3, 2), h(1), NOW).why], [true, "new-report"]);
  assert.equal(claimRecheck(r(3, 2), h(5), NOW).due, false, "the report was already there");
  const nf = { decision: "not_found", checked_at: h(300), tries: 1 };
  assert.deepEqual([claimRecheck(nf, 0, NOW, {}, true).due, claimRecheck(nf, 0, NOW, {}, true).why], [false, "final"], "final: no timer brings it back");
  assert.equal(claimRecheck(nf, h(2), NOW, {}, true).due, true, "a report that names the victim does");
});

test("outage gate: same key not confirmed again and again waits longer; stronger reports are checked at once", () => {
  const it = { id: "net-xx-3", key: "net-xx", score: 12000 }, nc = (hrs, tries = 1, seen) => ({ decision: "not_confirmed", checked_at: h(hrs), tries, ...(seen ? { seen } : {}) });
  assert.equal(outageRecheck(it, [], NOW).due, true);
  assert.deepEqual([outageRecheck(it, [nc(11)], NOW).due, outageRecheck(it, [nc(13)], NOW).due], [false, true], "one: 12 h, as before");
  assert.deepEqual([outageRecheck(it, [nc(23, 2)], NOW).due, outageRecheck(it, [nc(25, 2)], NOW).due], [false, true], "two: 24 h");
  assert.deepEqual([outageRecheck(it, [nc(47, 2), nc(80, 1)], NOW).due, outageRecheck(it, [nc(49, 2), nc(80, 1)], NOW).due], [false, true], "three: 48 h");
  assert.equal(outageRecheck(it, [nc(20, 2), { decision: "confirmed", checked_at: h(60), tries: 1 }, nc(90, 2)], NOW).n, 2, "a confirmed check ends the run");
  assert.equal(outageRecheck(it, [{ decision: "confirmed", checked_at: h(13), tries: 1 }], NOW).due, true, "after a confirmed check: the base wait");
  assert.equal(outageRecheck(it, [{ decision: "confirmed", checked_at: h(5), tries: 1 }], NOW).due, false);
  assert.equal(outageRecheck(it, [nc(169, 2), nc(200, 2), nc(240, 2), nc(300, 2)], NOW).due, true, "capped at recheck_max_hours");
  const seen = outageSeen({ score: 5000, publishers: [1, 2], figure: { n: 4000 }, cyber_headline: "" });
  assert.deepEqual(seen, { score: 5000, publishers: 2, figure: 4000, cyber: false, last_seen: "" });
  assert.equal(outageStronger({ score: 10000 }, seen), true); assert.equal(outageStronger({ score: 9000 }, seen), false);
  assert.equal(outageStronger({ publishers: [1, 2, 3] }, seen), true, "one more publisher");
  assert.equal(outageStronger({ publishers: [1, 2], figure: { n: 9000 } }, seen), true); assert.equal(outageStronger({ publishers: [1, 2], cyber_headline: "Hackers cut power" }, seen), true);
  assert.equal(outageStronger({ score: 99999 }, undefined), false, "nothing to compare with");
  assert.deepEqual([outageRecheck(it, [nc(2, 2, seen)], NOW).due, outageRecheck(it, [nc(2, 2, seen)], NOW).why], [true, "stronger"]);
  assert.match(outageRecheck(it, [nc(2, 2)], NOW).reason, /^skipped: nothing new since .*\(not confirmed 2 times in a row\)$/);
});

test("gap searchers: the interval doubles with every four runs in a row that added nothing; one event resets it", () => {
  const run = (hrs, added = 0, updated = 0) => ({ at: h(hrs), added, updated });
  assert.equal(gapDryRun([run(1), run(2), run(3, 1), run(4)]), 2); assert.equal(gapDryRun([run(1, 0, 1), run(2)]), 0); assert.equal(gapDryRun([]), 0);
  const sc = { gap_every_minutes: 60, gap_max_every_minutes: 480 };
  assert.deepEqual([0, 3, 4, 8, 12, 16, 400].map((d) => gapEveryMinutes(d, sc)), [60, 60, 120, 240, 480, 480, 480]);
  assert.equal(gapEveryMinutes(100, { gap_every_minutes: 60, gap_max_every_minutes: 30 }), 60, "the cap never undercuts the base");
  assert.equal(gapEveryMinutes(0, {}), 60); assert.equal(gapEveryMinutes(0, { gap_every_minutes: 5 }), 15);
});

test("clocks survive a restart: the last run of a role comes from the usage ledger", () => {
  const lines = [{ at: "2026-11-22T20:00:00Z", role: "followup-deep" }, { at: "2026-11-22T21:00:00Z", role: "followup" }, { at: "2026-11-22T22:00:00Z", role: "gap" }, { at: "2026-11-22T23:00:00Z", role: "researcher" }, null, { role: "gap" }];
  assert.equal(lastRunOf(lines, "followup"), Date.parse("2026-11-22T21:00:00Z"), "the deep role counts as the same desk");
  assert.equal(lastRunOf(lines, "gap"), Date.parse("2026-11-22T22:00:00Z"));
  assert.equal(lastRunOf(lines, "claims"), 0); assert.equal(lastRunOf(null, "gap"), 0);
});
