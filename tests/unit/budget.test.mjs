// The pipeline's reserve of the shared usage window (scripts/budget.mjs, scripts/lib/usage.mjs canBuild), usage-limit
// failures recorded as what they are, and turn caps that end cleanly (scripts/run-job.mjs).
// Why: on 2026-11-22 a code-build swarm used the whole 5-hour window; 29 pipeline workers failed one after another with
// "You've hit your 5-hour limit" and nothing was published for 2.5 hours.
// Run: node --test tests/unit/
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { canBuild, budgetState, DEFAULT_BUDGET } from "../../scripts/lib/usage.mjs";
import { spentLine, verdict, readBuild } from "../../scripts/budget.mjs";
import { ledgerLine, limitHolds, unfinishedLog, turnBudgetNote, gapCount, workerArgs } from "../../scripts/run-job.mjs";
import { usageProblem, THRESHOLD } from "../../scripts/pipecheck.mjs";
import { workerEnds } from "../../scripts/efficiency.mjs";

const NOW = Date.parse("2026-11-23T12:00:00Z"), iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z"), m = (min) => iso(NOW - min * 6e4);
const CFG = { window_hours: 5, window_tokens: 100e6, window_cost: 100, week_tokens: 0, week_cost: 0, tight_pct: 80, stop_pct: 120, limit_backoff_minutes: 60, pipeline_reserve_pct: 35 };
const line = (minAgo, cost, o = {}) => ({ at: m(minAgo), job: "sweep", role: "researcher", ok: true, cost, in: 0, out: 0, cache_read: cost * 1e6, cache_write: 0, error: null, ...o });
const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("can-build: build work may use the window only up to (100 - reserve)%", () => {
  assert.equal(DEFAULT_BUDGET.pipeline_reserve_pct, 35, "the default reserve");
  const a = canBuild(NOW, CFG, [line(60, 30)], []);
  assert.deepEqual([a.ok, a.window_pct, a.pipeline_pct, a.build_pct, a.ceiling_pct, a.reserve_pct], [true, 30, 30, 0, 65, 35]);
  assert.equal(canBuild(NOW, CFG, [line(60, 65)], []).ok, true, "at the ceiling");
  const b = canBuild(NOW, CFG, [line(60, 66)], []);
  assert.equal(b.ok, false); assert.match(b.reason, /stands at 66% .* above the 65% that build work may use \(35% is kept for the pipeline\)/);
  // what a build swarm recorded of its own usage counts against the same window
  const c = canBuild(NOW, CFG, [line(60, 30)], [spentLine(40e6, 0, "wave 1", NOW - 30 * 6e4)]);
  assert.deepEqual([c.ok, c.window_pct, c.build_pct], [false, 70, 40]);
  assert.equal(canBuild(NOW, CFG, [line(60, 30)], [spentLine(40e6, 0, "old wave", NOW - 6 * 36e5)]).ok, true, "usage older than the window has rolled out");
  // the dial
  assert.equal(canBuild(NOW, { ...CFG, pipeline_reserve_pct: 50 }, [line(60, 55)], []).ok, false);
  assert.equal(canBuild(NOW, { ...CFG, pipeline_reserve_pct: 0 }, [line(60, 99)], []).ok, true);
  assert.equal(canBuild(NOW, { ...CFG, pipeline_reserve_pct: "x" }, [line(60, 66)], []).ok, false, "a broken dial falls back to 35");
  assert.equal(canBuild(NOW, CFG, [], []).ok, true, "no ledger: nothing counted, and it says so");
});

test("can-build: never for an hour after the plan refused a pipeline worker, or until the reset it gave", () => {
  const hit = (minAgo, text) => line(minAgo, 1, { ok: false, error: text });
  const a = canBuild(NOW, CFG, [hit(20, "You've hit your 5-hour limit · resets 1:30pm (UTC)")], []);
  assert.equal(a.ok, false); assert.equal(a.limited_until, "2026-11-23T13:30:00Z"); assert.match(a.reason, /^usage limit reached: the plan refused a pipeline worker at 2026-11-23T11:40:00Z/);
  const b = canBuild(NOW, CFG, [hit(20, "You've hit your 5-hour limit · resets 11:50am (UTC)")], []);
  assert.equal(b.ok, false, "the reset has come, but the hit was in the last hour"); assert.equal(b.limited_until, "2026-11-23T12:40:00Z");
  assert.equal(canBuild(NOW, CFG, [hit(90, "You've hit your 5-hour limit · resets 11:00am (UTC)")], []).ok, true, "over an hour ago and reset");
  assert.equal(canBuild(NOW, CFG, [line(20, 1, { ok: true, last: "the site answered 429 rate limit" })], []).ok, true, "only a FAILED worker's limit error counts");
  // the pipeline's own stop logic is unchanged by the reserve
  assert.equal(budgetState(NOW, CFG, [line(60, 70)]).level, "ok"); assert.equal(budgetState(NOW, CFG, [line(60, 121)]).level, "stop");
});

test("budget.mjs: the verdict, the build ledger line, and the command's exit code", () => {
  assert.deepEqual(verdict({ ok: true, reason: "r" }), { code: 0, line: "BUILD OK: r." });
  assert.deepEqual(verdict({ ok: false, reason: "r" }), { code: 1, line: "BUILD WAIT: r." });
  const l = spentLine(1234.6, 2.5, "wave 2", NOW);
  assert.deepEqual([l.at, l.job, l.in, l.cost, l.ok, l.note], [iso(NOW), "build", 1235, 2.5, true, "wave 2"]);
  assert.deepEqual(readBuild("/nonexistent/file.jsonl"), []);
  // end to end in a copy of the repository with its own ledger
  const t = mkdtempSync(join(tmpdir(), "budget-")), now = Date.now(), at = (min) => iso(now - min * 6e4);
  mkdirSync(join(t, "scripts", "lib"), { recursive: true }); mkdirSync(join(t, "config")); mkdirSync(join(t, "data", "usage"), { recursive: true });
  for (const f of ["scripts/budget.mjs", "scripts/lib/usage.mjs", "scripts/lib/store.mjs"]) copyFileSync(join(repo, f), join(t, f));
  writeFileSync(join(t, "config", "pipeline.json"), JSON.stringify({ usage_budget: CFG }));
  const month = (min) => join(t, "data", "usage", `${at(min).slice(0, 7)}.jsonl`), env = { ...process.env, CYBERVIEW_BUILD_LEDGER: join(t, "build.jsonl") };
  const run = (...a) => spawnSync("node", ["scripts/budget.mjs", ...a], { cwd: t, encoding: "utf8", env });
  writeFileSync(month(90), JSON.stringify({ at: at(90), role: "researcher", ok: true, cost: 20, cache_read: 20e6 }) + "\n");
  let r = run("can-build"); assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /^BUILD OK: the 5-hour window stands at 20%/);
  r = run("spent", "--tokens", "50000000", "--note", "wave 1"); assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(readFileSync(join(t, "build.jsonl"), "utf8").trim()).in, 50000000);
  r = run("can-build"); assert.equal(r.status, 1, "20% pipeline + 50% build is above 65%"); assert.match(r.stdout, /^BUILD WAIT: .*70%/);
  r = run("status", "--json"); assert.equal(r.status, 0, "status never fails"); assert.deepEqual([JSON.parse(r.stdout).ok, JSON.parse(r.stdout).build_pct], [false, 50]);
  writeFileSync(join(t, "build.jsonl"), "");
  appendFileSync(month(10), JSON.stringify({ at: at(10), role: "followup-deep", ok: false, cost: 1, error: "You've hit your 5-hour limit · resets 12:10am (UTC)" }) + "\n");
  r = run("can-build"); assert.equal(r.status, 1); assert.match(r.stdout, /^BUILD WAIT: usage limit reached/);
  assert.equal(run("nonsense").status, 2); assert.equal(run("spent").status, 2);
});

test("ledger: a usage-limit failure and a turn cap are recorded as what they are", () => {
  const lim = ledgerLine("sweep", "followup-deep", null, "opus", 1000, JSON.stringify({ is_error: true, result: "You've hit your 5-hour limit · resets 12:10am (UTC)", num_turns: 46, total_cost_usd: 1.4 }), null);
  assert.equal(lim.ok, false); assert.equal(lim.limit, true); assert.ok(!lim.capped);
  assert.ok(Date.parse(lim.limit_until) > Date.parse(lim.at) && Date.parse(lim.limit_until) - Date.parse(lim.at) <= 24 * 36e5, "the reset time the message gives");
  assert.equal(lim.limit_until.slice(11), "00:10:00Z");
  // what claude prints when --max-turns is reached (checked against the CLI on 2026-11-23)
  const cap = ledgerLine("sweep", "followup-deep", 1, "opus", 1000, JSON.stringify({ type: "result", subtype: "error_max_turns", is_error: true, num_turns: 19, total_cost_usd: 0.5, errors: ["Reached maximum number of turns (18)"] }), null);
  assert.deepEqual([cap.ok, cap.capped, cap.error, cap.turns], [false, true, "turn cap reached (19 turns)", 19]); assert.ok(!cap.limit);
  const ok = ledgerLine("sweep", "researcher", 1, "sonnet", 1000, JSON.stringify({ is_error: false, result: "researcher 1: 2 added", num_turns: 12, total_cost_usd: 0.2 }), null);
  assert.equal(ok.ok, true); assert.ok(!("limit" in ok) && !("capped" in ok), "an ordinary line is unchanged");
  const site = ledgerLine("sweep", "researcher", 1, "sonnet", 1000, JSON.stringify({ is_error: false, result: "the site answered 429 too many requests" }), null);
  assert.ok(!site.limit, "a website's 429 in a successful run is not the plan's limit");
  assert.ok(!ledgerLine("sweep", "researcher", 1, "sonnet", 1000, "", "timeout").limit);
});

test("after a usage limit no further worker is started until the reset; the pipeline check says what it is", () => {
  assert.equal(limitHolds(null, NOW), false);
  assert.equal(limitHolds({ limit: true, at: m(5), limit_until: iso(NOW + 30 * 6e4) }, NOW), true);
  assert.equal(limitHolds({ limit: true, at: m(50), limit_until: m(10) }, NOW), false, "the reset has come");
  assert.equal(limitHolds({ limit: true, at: m(30) }, NOW), true, "no reset time given: an hour");
  assert.equal(limitHolds({ limit: true, at: m(61) }, NOW), false);
  assert.equal(limitHolds({ ok: false, at: m(5) }, NOW), false, "an ordinary failure holds nothing");
  assert.equal(usageProblem({ level: "ok" }), null); assert.equal(usageProblem({ level: "tight" }), null);
  const p = usageProblem({ level: "stop", limited_until: "2026-11-23T00:10:00Z", reason: "a worker hit the plan's limit" });
  assert.equal(p.id, "usage-limit"); assert.equal(p.threshold_min, THRESHOLD["usage-limit"]);
  assert.match(p.text, /^usage limit reached, resets 2026-11-23 00:10 UTC: no AI worker starts until then/);
  assert.match(usageProblem({ level: "stop", limited_until: null, reason: "5-hour usage at 121% of the estimate (stop at 120%)" }).text, /^usage limit: 5-hour usage at 121%/);
  const ends = workerEnds([{ at: m(10), ok: true }, { at: m(9), ok: false, capped: true }, { at: m(8), ok: false, limit: true, limit_until: "2026-11-23T13:00:00Z" }, { at: m(7), ok: false, error: "You've hit your 5-hour limit · resets 1pm (UTC)" }, { at: m(6), ok: false, error: "timeout" }, { at: m(9999), ok: false }], NOW - 864e5, NOW);
  assert.deepEqual([ends.runs, ends.ok, ends.capped, ends.usage_limit, ends.failed], [5, 1, 1, 2, 1], "lines written before the `limit` flag are recognised by their message");
});

test("turn caps: every worker is told its budget, and a capped run leaves its unfinished work on file as open leads", () => {
  const models = { roles: { "followup-deep": { model: "opus", max_turns: 18 }, x: { max_turns: 10 } }, toolsets: {}, deny: [] };
  assert.match(turnBudgetNote("followup-deep", models), /^TURN BUDGET: this run ends after 18 turns .* By turn 14 at the latest stop researching/);
  assert.match(turnBudgetNote("x", models), /By turn 7 /); assert.match(turnBudgetNote("unknown", models), /after 40 turns/);
  assert.deepEqual(workerArgs("followup-deep", "p", models).args.slice(4, 6), ["--max-turns", "18"]);
  const l = { at: "2026-11-23T12:00:00Z", ms: 120000, role: "followup-deep", batch: 2, model: "opus", ok: false, capped: true, turns: 19, error: "turn cap reached (19 turns)" };
  const log = unfinishedLog(l, [{ id: "a-2026-11", title: "Event A" }, { id: "b-2026-11", title: "Event B" }], new Set(["a-2026-11"]));
  assert.deepEqual(log.unfinished, ["b-2026-11"], "what the worker did finish is not handed out again");
  assert.equal(log.open_leads.length, 1); assert.equal(log.open_leads[0].title, "Event B"); assert.match(log.open_leads[0].note, /followup-deep 2 stopped at its turn cap \(19 turns\) before it got to this \(b-2026-11\)/);
  assert.deepEqual([log.started_at, log.finished_at, log.worker_role, log.worker_model], ["2026-11-23T11:58:00Z", "2026-11-23T12:00:00Z", "followup-deep", "opus"]);
  assert.match(log.notes, /1 of 2 assigned item\(s\) were not finished and stay in their queue/);
  assert.match(unfinishedLog({ ...l, capped: false, error: "timeout" }, [{ id: "a-2026-11" }]).open_leads[0].note, /ran out of time/);
  // the caps in config/models.json: loop roles are capped near what their productive runs use (see its _note)
  const real = JSON.parse(readFileSync(join(repo, "config", "models.json"), "utf8")).roles;
  for (const [role, max] of Object.entries({ researcher: 40, "researcher-deep": 48, reviewer: 40, gap: 24, updater: 28, "updater-deep": 34, outage: 16, claims: 16, grid: 16, followup: 22, "followup-deep": 20 }))
    assert.ok(real[role].max_turns >= 10 && real[role].max_turns <= max, `${role}: ${real[role].max_turns}`);
});

test("gap searchers: the pass waits for its (possibly doubled) interval, counted from the ledger's clock", () => {
  const sc = { gap_pass: true, gap_workers: 1, gap_every_minutes: 60, gap_max_every_minutes: 480, gap_spare_workers: 1, gap_spare_below_pct: 60 }, ok = { level: "ok", window_pct: 10 };
  assert.equal(gapCount(NOW, NOW - 61 * 6e4, sc, ok, false, 0), 2, "an hour since the last pass");
  assert.equal(gapCount(NOW, NOW - 30 * 6e4, sc, ok, false, 0), 0);
  assert.equal(gapCount(NOW, NOW - 61 * 6e4, sc, ok, false, 4), 0, "four runs in a row added nothing: every 2 hours");
  assert.equal(gapCount(NOW, NOW - 121 * 6e4, sc, ok, false, 4), 2);
  assert.equal(gapCount(NOW, NOW - 7 * 36e5, sc, ok, false, 130), 0, "capped at 8 hours");
  assert.equal(gapCount(NOW, NOW - 9 * 36e5, sc, ok, false, 130), 2);
  assert.equal(gapCount(NOW, 0, sc, { level: "stop", window_pct: 130 }, false, 0), 0);
});
