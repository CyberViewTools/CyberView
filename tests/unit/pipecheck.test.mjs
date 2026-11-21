// The reliability checks: source backoff (scripts/lib/backoff.mjs), the stage table (scripts/lib/stages.mjs), the pipeline
// check (scripts/pipecheck.mjs), its alert open/close plan, the guard's stage and quality warnings, and Retry-After.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { nextHealth, due, backoffMin, failingDays, feedProposals, FAIL_RUNS, MAX_MIN, PROPOSE_DAYS, RETIRE_DAYS } from "../../scripts/lib/backoff.mjs";
import { STAGES, stageStates, lastRuns, limits } from "../../scripts/lib/stages.mjs";
import { stageProblems, statusKeys, missedDuplicates, unreviewed, leadsGrowth, sizeGrowth, carry, planAlerts, planHeal, targetProblems, LABEL, THRESHOLD } from "../../scripts/pipecheck.mjs";
import { assess, LIMITS, HEAL } from "../../scripts/guard.mjs";
import { retryAfterMs } from "../../scripts/lib/net.mjs";

const ROOT = join(import.meta.dirname, "..", "..");
const REG = JSON.parse(readFileSync(join(ROOT, "routines.json"), "utf8")).routines;
const NOW = Date.parse("2026-11-21T22:00:00Z"), iso = (t) => new Date(t).toISOString().replace(/\.\d+Z$/, "Z"), ago = (m) => iso(NOW - m * 6e4);

/* ---------- backoff ---------- */
test("backoff: three failures in a row make a source failing, then it waits longer each time, at most 12 hours", () => {
  let h = {};
  for (let i = 1; i <= FAIL_RUNS; i++) h = nextHealth(h, { ok: false, error: "HTTP 403" }, NOW + i * 6e4);
  assert.equal(h.state, "failing"); assert.equal(h.fails, 3); assert.equal(h.failing_since, iso(NOW + 6e4));
  assert.equal(due(h, NOW + 4 * 6e4), false, "a failing source is not asked again at once");
  assert.equal(due(h, Date.parse(h.next_try_at)), true);
  assert.equal(backoffMin(2), 0); assert.equal(backoffMin(3), 30); assert.equal(backoffMin(4), 60); assert.equal(backoffMin(40), MAX_MIN);
  const ok = nextHealth(h, { ok: true, items: 5 }, NOW + 9e6);
  assert.deepEqual([ok.ok, ok.state, ok.fails, ok.next_try_at], [true, "ok", 0, undefined], "one success brings it straight back");
});
test("backoff: a Retry-After longer than the backoff wins, and a source under three failures stays due", () => {
  const h = nextHealth({}, { ok: false, error: "HTTP 429", retryAfterMs: 3 * 36e5 }, NOW);
  assert.equal(h.state, "ok"); assert.equal(h.next_try_at, iso(NOW + 3 * 36e5)); assert.equal(due(h, NOW + 60e3), false);
  assert.equal(due(nextHealth({}, { ok: false, error: "x" }, NOW), NOW), true);
  assert.equal(due(undefined, NOW), true);
});
test("backoff: an entry written before this existed keeps its first failure from last_ok", () => {
  const h = nextHealth({ ok: false, error: "HTTP 403", at: ago(5), last_ok: ago(600), fails: 158 }, { ok: false, error: "HTTP 403" }, NOW);
  assert.equal(h.fails, 159); assert.equal(h.failing_since, ago(600)); assert.equal(h.state, "failing");
});
test("backoff: failing 7 days proposes the watch list, 28 days on it proposes retirement, never twice", () => {
  const feeds = { A: { ok: false, state: "failing", fails: 300, failing_since: iso(NOW - (PROPOSE_DAYS + 1) * 864e5), error: "HTTP 403" },
    B: { ok: false, state: "failing", fails: 900, failing_since: iso(NOW - (RETIRE_DAYS + 1) * 864e5), error: "HTTP 404" },
    C: { ok: false, state: "failing", fails: 9, failing_since: ago(600), error: "timeout" }, D: { ok: true, state: "ok", fails: 0 } };
  const cfg = { watch: [{ name: "B", since: "2026-10-20", reason: "failing" }], retired: [] };
  const p = feedProposals(feeds, cfg, NOW);
  assert.deepEqual(p.watch.map((x) => x.name), ["A"]); assert.equal(p.watch[0].reason, "failing"); assert.match(p.watch[0].evidence, /HTTP 403/);
  assert.deepEqual(p.retire.map((x) => x.name), ["B"]);
  assert.deepEqual(feedProposals(feeds, { watch: [{ name: "A", reason: "failing", since: "2026-11-21" }], retired: [{ name: "B" }] }, NOW), { watch: [], retire: [] });
  assert.equal(failingDays(feeds.D, NOW), 0);
});

/* ---------- stages ---------- */
test("stages: every stage names a heartbeat and a limit; routine limits come from routines.json", () => {
  const keys = new Set(REG.map((r) => r.key)), lim = limits(REG);
  for (const s of STAGES) {
    assert.ok(s.status || (s.file && s.field), `${s.key} has no heartbeat`);
    if (s.routine) { assert.ok(keys.has(s.routine), `${s.key}: no routine ${s.routine}`); assert.equal(lim[s.key], REG.find((r) => r.key === s.routine).max_age_hours * 60); }
    assert.ok(lim[s.key] > 0);
  }
  assert.equal(new Set(STAGES.map((s) => s.key)).size, STAGES.length);
});
test("stages: late, never, ok, and idle only for work-driven stages without work", () => {
  const last = { collect: ago(10), osint: ago(500), researchers: "", reviewers: "" };
  const st = stageStates(last, REG, NOW, { reviewers: true }), by = Object.fromEntries(st.map((s) => [s.key, s.state]));
  assert.equal(by.collect, "ok"); assert.equal(by.osint, "late"); assert.equal(by.researchers, "idle"); assert.equal(by.reviewers, "never");
  const pr = stageProblems(st);
  assert.ok(pr.some((p) => p.id === "stage-osint" && p.threshold_min === THRESHOLD.stage && p.heal === "collect.yml"));
  assert.ok(pr.some((p) => p.id === "stage-reviewers" && p.threshold_min === THRESHOLD.stage_never));
  assert.ok(!pr.some((p) => p.id === "stage-researchers"));
  assert.equal(lastRuns({ last_collect_at: "X" }, { "grid/analysis.json": { updated_at: "Y" } })["grid-analysis"], "Y");
});
test("routines: every active routine with a heartbeat has a max age longer than its schedule's interval", () => {
  const every = (c) => { const p = String(c || "").trim().split(/\s+/); if (p.length !== 5) return null; const [m, h, , , d] = p;
    if (d !== "*") return 168 / d.split(",").length; if (h === "*") return 1 / m.split(",").length; const e = h.match(/^\*\/(\d+)$/); return e ? +e[1] : 24 / h.split(",").length; };
  for (const r of REG.filter((r) => r.active && r.status_key)) {
    assert.ok(r.max_age_hours > 0, `${r.key}: a status key but no max_age_hours`);
    const iv = every(r.cron); if (iv) assert.ok(r.max_age_hours >= iv * 1.15, `${r.key}: max age ${r.max_age_hours} h is not longer than its interval ${iv} h`);
  }
});
test("guard: its limits for the brief, analysis and analyst are the routines' own max ages", () => {
  const m = (k) => REG.find((r) => r.key === k).max_age_hours * 60;
  assert.equal(LIMITS.brief_min, m("brief")); assert.equal(LIMITS.analysis_min, m("analysis")); assert.equal(LIMITS.analyst_min, m("analyst"));
  for (const s of STAGES) if (s.heal) assert.ok(Object.values(HEAL).includes(s.heal), `guard cannot heal ${s.key} (${s.heal})`);
});

/* ---------- data checks ---------- */
test("status keys: a key that vanished is reported once, a returning key is seen again, old memory is dropped", () => {
  const known = { a: ago(30), b: ago(30), c: iso(NOW - 20 * 864e5), d: iso(NOW - 5 * 864e5) };
  const r = statusKeys(known, { a: 1 }, NOW);
  assert.deepEqual(r.vanished, ["b"]); assert.equal(r.problem.id, "status-keys"); assert.equal(r.problem.level, "bad"); assert.match(r.problem.text, /now 1\)/);
  assert.ok(!("c" in r.known) && "d" in r.known && !("b" in r.known));
  assert.equal(statusKeys(r.known, { a: 1 }, NOW + 6e4).problem, null, "reported once per disappearance");
  assert.equal(statusKeys({ a: ago(5) }, { a: 1, b: 2 }, NOW).problem, null);
});
test("duplicates: same words or same CVEs and organisation, not two victims of one gang or a settled pair", () => {
  const ev = (id, o) => ({ id, category: "incident", date: "2026-11-20", title: "", org: "", ...o });
  const evs = [ev("a", { title: "Infoblox confirms breach via SharePoint migration vendor", org: "Infoblox" }), ev("b", { title: "Infoblox confirms breach via SharePoint migration vendor data", org: "Infoblox" }),
    ev("c", { title: "Inception ransomware group claims AMD", org: "AMD" }), ev("d", { title: "Inception ransomware group claims Paychex", org: "Paychex" }),
    ev("e", { category: "vuln", cves: ["CVE-2026-1"], org: "X", title: "one" }), ev("f", { category: "vuln", cves: ["CVE-2026-1"], org: "X", title: "two" }),
    ev("g", { title: "Hospital in Lyon hit by ransomware attack today", org: "HCL" }), ev("h", { title: "Hospital in Lyon hit by ransomware attack again", org: "HCL", review: { note: "not a duplicate of g: a second attack" } }),
    ev("i", { title: "Infoblox confirms breach via SharePoint migration vendor", org: "Infoblox", duplicate_of: "a" })];
  const d = missedDuplicates(evs, NOW);
  assert.deepEqual(d.map((x) => x.a + x.b).sort(), ["ab", "ef"]);
  assert.deepEqual(missedDuplicates([ev("a", { title: "Infoblox confirms breach via SharePoint migration vendor", date: "2026-10-01" }), ev("b", { title: "Infoblox confirms breach via SharePoint migration vendor", date: "2026-10-01" })], NOW), [], "older than 14 days");
});
test("unreviewed: events past 2 hours without a second review, oldest first; reviewed and duplicates left out", () => {
  const r = unreviewed([{ id: "a", first_seen: ago(300) }, { id: "b", first_seen: ago(30) }, { id: "c", first_seen: ago(500), review: { at: ago(400) }, updated_at: ago(450) },
    { id: "d", first_seen: ago(900), duplicate_of: "a" }, { id: "e", first_seen: ago(200) }], NOW);
  assert.deepEqual([r.count, r.oldest_min, r.ids], [2, 300, ["a", "e"]]);
});
test("leads growth: today's pace against the week's median, judged after 3 hours", () => {
  const days = ["2026-11-15", "2026-11-16", "2026-11-17", "2026-11-18", "2026-11-19", "2026-11-20"].map((date) => ({ date, lines: 1500 }));
  assert.equal(leadsGrowth(days.concat([{ date: "2026-11-21", lines: 1400 }]), NOW).abnormal, false);
  const r = leadsGrowth(days.concat([{ date: "2026-11-21", lines: 9000 }]), NOW);
  assert.equal(r.abnormal, true); assert.equal(r.median, 1500);
  assert.equal(leadsGrowth(days.concat([{ date: "2026-11-21", lines: 900 }]), Date.parse("2026-11-21T01:00:00Z")).abnormal, false, "too early in the day");
  assert.equal(leadsGrowth([{ date: "2026-11-21", lines: 9000 }], NOW).abnormal, false, "no history yet");
});
test("data size: one entry a day, alert on a jump of more than 25 MB and 15%", () => {
  const h = [{ date: "2026-11-19", bytes: 40e6 }, { date: "2026-11-20", bytes: 45e6 }, { date: "2026-11-21", bytes: 46e6 }];
  const ok = sizeGrowth(h, 47e6, NOW); assert.equal(ok.abnormal, false); assert.equal(ok.history.length, 3); assert.equal(ok.history[2].bytes, 47e6);
  assert.equal(sizeGrowth(h, 90e6, NOW).abnormal, true);
  assert.equal(sizeGrowth([], 90e6, NOW).abnormal, false);
});
test("targets: a failing target becomes a problem kept off the status page", () => {
  const p = targetProblems([{ key: "speed", title: "Speed", state: "fail", value: "214 min", goal: "under 15 min" }, { key: "usage", state: "pass" }, { key: "<x>", state: "fail" }]);
  assert.deepEqual(p.map((x) => [x.id, x.page]), [["target-speed", false]]); assert.match(p[0].text, /speed target fails: 214 min/);
});

/* ---------- alerts and healing ---------- */
test("carry: a problem keeps its first-seen time and is over once it outlasts its threshold", () => {
  const prev = { problems: [{ id: "unreviewed", since: ago(90) }] };
  const c = carry([{ id: "unreviewed", level: "warn", threshold_min: 60, text: "t" }, { id: "duplicates", level: "warn", threshold_min: 60, text: "t" }, { id: "broken-links", level: "info", threshold_min: 0, text: "t" }], prev, NOW);
  assert.deepEqual(c.map((p) => [p.id, p.since, p.over]), [["unreviewed", ago(90), true], ["duplicates", iso(NOW), false], ["broken-links", iso(NOW), false]]);
});
test("alerts: open one issue per problem over its threshold, remind once a day, close what recovered", () => {
  const P = [{ id: "unreviewed", level: "warn", over: true, text: "21 events wait", since: ago(200) }, { id: "status-keys", level: "bad", over: true, text: "keys vanished", since: ago(1) },
    { id: "duplicates", level: "warn", over: false, text: "2 pairs" }, { id: "broken-links", level: "info", over: true, text: "1 link" }];
  const issues = [{ number: 7, body: `<!-- ${LABEL}:unreviewed -->\nx`, updated_at: ago(30) }, { number: 8, body: `<!-- ${LABEL}:stage-osint -->`, updated_at: ago(30) }, { number: 9, body: "no marker", updated_at: ago(30) }];
  const a = planAlerts(P, issues, NOW);
  assert.deepEqual(a.open.map((o) => o.id), ["status-keys"]); assert.match(a.open[0].body, new RegExp(`<!-- ${LABEL}:status-keys -->`)); assert.ok(a.open[0].title.length <= 120);
  assert.deepEqual(a.comment, [], "no reminder within a day");
  assert.deepEqual(a.close.map((c) => c.number), [8], "recovered stage closed; an issue without a marker is left alone");
  assert.deepEqual(planAlerts(P, [{ number: 7, body: `<!-- ${LABEL}:unreviewed -->`, updated_at: ago(25 * 60) }], NOW).comment.map((c) => c.number), [7]);
  assert.deepEqual(planAlerts([], [{ number: 7, body: `<!-- ${LABEL}:unreviewed -->`, updated_at: ago(5) }], NOW).close.map((c) => c.number), [7], "healthy: every alert closes");
  const many = Array.from({ length: 9 }, (_, i) => ({ id: `stage-s${i}`, level: "warn", over: true, text: "late" }));
  assert.equal(planAlerts(many, [], NOW).open.length, 5, "at most 5 new issues a run");
});
test("heal: each late stage's workflow once an hour at most, never for data problems", () => {
  const P = [{ id: "stage-collect", heal: "collect.yml" }, { id: "stage-osint", heal: "collect.yml" }, { id: "stage-linkcheck", heal: "linkcheck.yml" }, { id: "stage-sweep", heal: "" }, { id: "duplicates", heal: "x.yml" }];
  const a = planHeal(P, { "linkcheck.yml": ago(20) }, NOW);
  assert.deepEqual(a.start, ["collect.yml"]); assert.equal(a.healed["collect.yml"], iso(NOW));
  assert.deepEqual(planHeal(P, { "linkcheck.yml": ago(61) }, NOW).start, ["collect.yml", "linkcheck.yml"]);
});
test("guard: late stages, pipeline-check problems and a silent monitor are warnings with their heal", () => {
  const base = { manifest: { built_at: ago(5), commit: "a" }, bundle: { events: Array(9).fill({}) }, head: { sha: "a", date: ago(60) },
    health: { built_at: ago(5), last_sweep_at: ago(5), last_collect_at: ago(5), last_feeds_at: ago(5),
      stages: { linkcheck: iso(NOW - 300 * 36e5), osint: ago(5), collect: "", researchers: "" }, stage_limits: { linkcheck: 12000, osint: 180, collect: 180, researchers: 1440 },
      quality: { problems: [{ id: "unreviewed", level: "warn", over: true, text: "21 events wait" }, { id: "dup", level: "warn", over: false, text: "not yet" }, { id: "bl", level: "info", over: true, text: "info only" }] } } };
  const r = assess({ ...base, monitor: { created_at: ago(400) } }, NOW);
  assert.deepEqual(r.fails, []);
  assert.ok(r.warns.some((w) => /source link check last ran/.test(w)), r.warns);
  assert.ok(r.warns.includes("pipeline check: 21 events wait")); assert.ok(!r.warns.some((w) => /not yet|info only/.test(w)));
  assert.ok(r.warns.some((w) => /live site monitor last ran 400 minutes ago/.test(w)));
  assert.ok(!r.warns.some((w) => /lead collector \(RSS|researchers/.test(w)), "collect is judged by the fail check, researchers are work-driven");
  assert.deepEqual(r.heal.sort(), ["linkcheck", "monitor"]);
});

/* ---------- the class of bug: writers that start from {} ---------- */
test("every status.json read-modify-write goes through readStatus (never readJson(..., {}))", () => {
  for (const f of ["run-job.mjs", "backlog.mjs", "triage.mjs", "pipecheck.mjs", "collect.mjs", "osint.mjs"]) {
    const src = readFileSync(join(ROOT, "scripts", f), "utf8");
    const bad = src.split("\n").filter((l) => /status\.json/.test(l) && /writeJson\(/.test(l) && /readJson\([^()]*(\([^()]*\))?[^()]*,\s*\{\}\)/.test(l));
    assert.deepEqual(bad, [], `${f} writes status.json after reading it with an empty fallback`);
  }
});

/* ---------- Retry-After ---------- */
test("Retry-After: seconds or an HTTP date, 0 when absent or unreadable", () => {
  assert.equal(retryAfterMs("120"), 120000);
  assert.equal(retryAfterMs(new Date(NOW + 90e3).toUTCString(), NOW), 90000);
  assert.equal(retryAfterMs(null), 0); assert.equal(retryAfterMs("soon"), 0); assert.equal(retryAfterMs(new Date(NOW - 9e3).toUTCString(), NOW), 0);
});
