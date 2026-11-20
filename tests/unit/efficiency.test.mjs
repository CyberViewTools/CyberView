import { test } from "node:test";
import assert from "node:assert/strict";
import { routineOf, logOutput, routineReport, feedOf, feedReport, sectorOf, languageOf, coverage, accuracy, sumWindow, usageWindows, targets, report, spanDays } from "../../scripts/efficiency.mjs";
import { storyCredit, closureOutcome, compute, coveredDays, MAX_STORY } from "../../scripts/metrics.mjs";

const NOW = Date.parse("2026-11-20T12:00:00Z");
const h = (x) => new Date(NOW - x * 36e5).toISOString().replace(/\.\d+Z$/, "Z");
const KEYS = new Set(["sweep", "review", "triage", "lead-triage", "backlog", "analyst", "grid", "feeds", "deep-sweep", "brief", "collect", "osint", "cve"]);
const noCluster = (ls) => ls.map((l) => [l]);

test("closure outcome: an event id or an update is a use; already on file and not an event are not", () => {
  const ids = new Set(["acme-breach-2026-11"]);
  assert.equal(closureOutcome("acme-breach-2026-11", ids), "event");
  assert.equal(closureOutcome("acme-breach-2026-11 (two publishers)", ids), "event");
  assert.equal(closureOutcome("updated acme-breach-2026-11", ids), "update");
  assert.equal(closureOutcome("already on file: acme-breach-2026-11", ids), "");
  assert.equal(closureOutcome("not an event: commentary", ids), "");
});

test("leads are credited by story, not by URL equality", () => {
  const leads = [{ url: "https://a/1", title: "x" }, { url: "https://b/1", title: "y" }, { url: "https://c/1", title: "z" }, { url: "https://d/1", title: "w" }];
  const events = [{ id: "acme-breach-2026-11", sources: [{ url: "https://publisher/elsewhere" }] }];
  // a/1 and b/1 were one story that became the event; neither URL is cited by it
  const closures = [{ at: h(2), story: "s1", reason: "acme-breach-2026-11", urls: ["https://a/1", "https://b/1"] }, { at: h(2), story: "s2", reason: "not an event", urls: ["https://c/1"] }];
  const used = storyCredit(leads, events, closures, noCluster);
  assert.deepEqual([...used.keys()].sort(), ["https://a/1", "https://b/1"]);
  // a story never closed is grouped like fuse; one of its pages cited by an event credits every lead in it
  const used2 = storyCredit([{ url: "u1", title: "t" }, { url: "u2", title: "t" }], [{ id: "e", sources: [{ url: "u2" }] }], [], (ls) => [ls]);
  assert.equal(used2.get("u1"), "cited"); assert.equal(used2.get("u2"), "cited");
  // a group larger than MAX_STORY is word chaining: only the cited lead counts
  const big = Array.from({ length: MAX_STORY + 1 }, (_, i) => ({ url: "g" + i, title: "t", seen_at: h(1) }));
  const used3 = storyCredit(big, [{ id: "e", sources: [{ url: "g0" }] }], [], (ls) => [ls]);
  assert.deepEqual([...used3.keys()], ["g0"]);
  // a duplicate event credits nothing
  assert.equal(storyCredit([{ url: "u1", title: "t" }], [{ id: "e", duplicate_of: "f", sources: [{ url: "u1" }] }], [], noCluster).size, 0);
});

test("metrics: used by story and an honest window", () => {
  const leads = [{ url: "https://a/1", title: "Acme hit", source: "A", via: "rss", seen_at: h(30) }, { url: "https://a/2", title: "Other", source: "A", via: "rss", seen_at: h(30) }];
  const m = compute(leads, [], {}, [{ at: h(20), story: "s", reason: "updated acme-x", urls: ["https://a/1"] }], [], noCluster);
  assert.equal(m.leads_used, 1); assert.equal(m.collectors[0].used, 1);
  assert.equal(coveredDays(leads, 7, NOW), 1.3);
  assert.equal(coveredDays([], 7, NOW), 0);
});

test("routine of a run log or usage line", () => {
  assert.equal(routineOf("sweep-r1", KEYS), "sweep"); assert.equal(routineOf("sweep-gap-2", KEYS), "sweep"); assert.equal(routineOf("update-u1", KEYS), "sweep");
  assert.equal(routineOf("review-r12", KEYS), "review"); assert.equal(routineOf("analyst-28", KEYS), "analyst"); assert.equal(routineOf("grid-2", KEYS), "grid");
  assert.equal(routineOf("deep-sweep-latin-america", KEYS), "deep-sweep"); assert.equal(routineOf("backlog-auto", KEYS), "lead-triage");
  assert.equal(routineOf("triage", KEYS, null), "lead-triage"); assert.equal(routineOf("triage", KEYS, "claude-haiku-5-5"), "triage");
  assert.equal(routineOf("backlog-triage", KEYS), "backlog"); assert.equal(routineOf("context", KEYS), "feeds"); assert.equal(routineOf("mystery", KEYS), "other");
});

test("log output counts lists only", () => {
  assert.deepEqual(logOutput({ added: ["a"], updated: ["b", "c"], reviewed: [{}], skipped: [{}, {}], kev_added: ["k"], notes: "x" }), { added: 2, updated: 2, reviewed: 1, closed: 2, total: 7 });
  assert.equal(logOutput({}).total, 0); assert.equal(logOutput(null).total, 0);
});

test("routine report: usage, idle runs, unlogged subagent jobs", () => {
  const reg = [{ key: "sweep", name: "Sweep", tier: "ai", model: "m" }, { key: "brief", name: "Brief", tier: "ai", status_key: "last_brief_at" }, { key: "backlog", name: "Backlog", tier: "ai" },
    { key: "deep-sweep", name: "Deep", tier: "ai" }, { key: "grid", name: "Grid", tier: "automation" }, { key: "collect", name: "Collect", tier: "automation" }];
  const usage = [{ at: h(1), job: "sweep", ok: true, in: 10, out: 20, cache_read: 100, cache_write: 0, cost: 0.5 }, { at: h(3), job: "sweep", ok: false, error: "timeout", in: 1, out: 1, cost: 0.1 }];
  const logs = [{ at: h(1), job: "sweep-r1", out: logOutput({ added: ["e"] }) }, { at: h(5), job: "deep-sweep-a", out: logOutput({}) }, { at: h(2), job: "grid", out: logOutput({ opened: [] }) }];
  const jobruns = [{ job: "sweep", started_at: h(1.05), finished_at: h(0.98), workers: 1 }, { job: "sweep", started_at: h(3.1), finished_at: h(2.95), workers: 1 }, { job: "backlog", started_at: h(4), finished_at: h(4), workers: 0 }];
  const rows = Object.fromEntries(routineReport(reg, usage, logs, jobruns, { last_brief_at: h(6) }, NOW - 7 * 864e5, NOW, [{ url: "x", via: "rss", seen_at: h(1) }]).map((r) => [r.key, r]));
  assert.equal(rows.sweep.runs, 2); assert.equal(rows.sweep.idle, 1); assert.equal(rows.sweep.idle_pct, 50); assert.equal(rows.sweep.tokens, 132); assert.equal(rows.sweep.idle_tokens, 2);
  assert.equal(rows.sweep.failures, 1); assert.equal(rows.sweep.cost, 0.6); assert.equal(rows.sweep.added, 1); assert.equal(rows.sweep.usage, "logged");
  assert.equal(rows["deep-sweep"].usage, "not logged"); assert.equal(rows["deep-sweep"].tokens, null); assert.equal(rows["deep-sweep"].runs, 1); assert.equal(rows["deep-sweep"].idle, 1);
  assert.equal(rows.brief.usage, "not logged"); assert.equal(rows.brief.last_run, h(6)); assert.equal(rows.brief.idle_pct, null);
  assert.equal(rows.backlog.usage, "logged"); assert.equal(rows.backlog.tokens, 0); assert.equal(rows.backlog.idle, 1);
  assert.equal(rows.grid.usage, "none (script)"); assert.equal(rows.grid.idle, 1);
  assert.equal(rows.collect.filed, 1); assert.equal(rows.collect.runs, null);
});

test("feeds: rss by host, collectors by name, used, closed by rule, silent feeds", () => {
  assert.equal(feedOf({ url: "https://www.bleepingcomputer.com/x" }), "rss:bleepingcomputer.com");
  assert.equal(feedOf({ via: "bing-news", url: "https://x" }), "bing-news");
  const leads = [{ url: "https://news.example/1", source: "Ex", seen_at: h(48) }, { url: "https://news.example/2", source: "Ex", seen_at: h(2) }, { url: "https://g/1", via: "gdelt", seen_at: h(3) }];
  const rows = feedReport(leads, new Map([["https://news.example/1", "event"]]), new Set(["https://g/1"]), { feeds: { Ex: { ok: true }, Quiet: { ok: false, error: "HTTP 404" } }, sources: { gdelt: { ok: false, error: "HTTP 429" }, hibp: { ok: true } } }, NOW);
  const by = Object.fromEntries(rows.map((r) => [r.name, r]));
  assert.equal(by["rss:news.example"].leads, 2); assert.equal(by["rss:news.example"].used, 1); assert.equal(by["rss:news.example"].yield, 50); assert.equal(by["rss:news.example"].days_since_useful, 2);
  assert.equal(by.gdelt.by_rule, 1); assert.equal(by.gdelt.used, 0); assert.equal(by.gdelt.ok, false); assert.equal(by.gdelt.verdict, "nothing used yet");
  assert.equal(by["feed:Quiet"].leads, 0); assert.equal(by["feed:Quiet"].verdict, "silent"); assert.equal(by["feed:Quiet"].error, "HTTP 404");
  assert.equal(by.hibp.verdict, "silent");
});

test("coverage by region, language and critical-infrastructure sector", () => {
  assert.equal(sectorOf({ sector: "Healthcare" }), "health"); assert.equal(sectorOf({ sector: "Energy / oil and gas" }), "energy"); assert.equal(sectorOf({ sector: "Retail" }), "other");
  assert.equal(sectorOf({ sector: "Government advisory" }), "government"); assert.equal(sectorOf({ sector: "", tags: ["water"] }), "water");
  const leadByUrl = new Map([["https://x.jp/1", { via: "google-news", lang: "ja" }], ["https://feed/1", { via: "rss" }]]);
  assert.equal(languageOf({ sources: [{ url: "https://x.jp/1" }, { url: "https://feed/1" }] }, leadByUrl), "ja");
  assert.equal(languageOf({ sources: [{ url: "https://feed/1" }] }, leadByUrl), "en");
  assert.equal(languageOf({ sources: [{ url: "https://www.heise.de/a" }] }, leadByUrl), "de");
  assert.equal(languageOf({ sources: [{ url: "https://example.com/a" }] }, leadByUrl), "not recorded");
  const c = coverage([{ first_seen: h(5), country: "Kenya", sector: "Water utility" }, { first_seen: h(24 * 10), country: "France" }, { first_seen: h(1), duplicate_of: "x" }], leadByUrl, 7, NOW);
  assert.equal(c.events, 1); assert.deepEqual(c.region, { africa: 1 }); assert.deepEqual(c.sector, { water: 1 });
});

test("accuracy: corrected share by week and the review's categories", () => {
  const ev = [{ review: { state: "passed", at: h(2) } }, { review: { state: "corrected", at: h(3), flags: ["actor-unsourced"] } }, { review: { state: "flagged", first_at: h(4), at: h(1), flags: ["possible-duplicate"] } },
    { review: { state: "corrected", at: h(24 * 9) } }, { duplicate_of: "x", review: { state: "corrected", at: h(1) } }, {}];
  const a = accuracy(ev, NOW, 7);
  assert.equal(a.reviewed, 3); assert.equal(a.corrected, 1); assert.equal(a.flagged, 1); assert.equal(a.corrected_pct, 33.3); assert.equal(a.corrected_or_flagged_pct, 66.7);
  assert.equal(a.weeks.length, 2); assert.equal(a.weeks[1].week, "2026-11-16"); assert.equal(a.weeks[1].reviewed, 3);
  assert.deepEqual(a.categories.map((c) => c.name).sort(), ["actor-unsourced", "possible-duplicate"]);
});

test("usage windows: from lib/usage.mjs when present, else an estimate", async () => {
  const usage = [{ at: h(1), in: 1, out: 2, cache_read: 3, cache_write: 4, cost: 0.1 }, { at: h(6), in: 10, cost: 1 }, { at: h(24 * 8), in: 100 }];
  assert.deepEqual(sumWindow(usage, NOW, 5), { from: h(5), to: h(0), runs: 1, tokens: 10, cost: 0.1 });
  assert.equal(sumWindow(usage, NOW, 168).tokens, 20);
  const est = await usageWindows(usage, NOW, {});
  assert.equal(est.estimate, true); assert.equal(est.five_hour.tokens, 10); assert.equal(est.budget, null);
  const lib = { windowUsage: (now, hours) => ({ from: "a", to: "b", runs: hours, tokens: hours * 10, cost: 1 }), budgetState: () => ({ window_pct: 41.6, week_pct: 12, level: "tight" }) };
  const w = await usageWindows(usage, NOW, lib);
  assert.equal(w.estimate, false); assert.equal(w.five_hour.tokens, 50); assert.equal(w.week.tokens, 1680); assert.deepEqual(w.budget, { window_pct: 42, week_pct: 12, level: "tight", limited_until: null, reason: "" });
  const bad = await usageWindows(usage, NOW, { windowUsage: () => { throw new Error("x"); } });
  assert.equal(bad.estimate, true);
});

test("targets: pass, fail, and unknown while there are fewer than 14 days of data", () => {
  const win = { five_hour: { tokens: 5 }, week: { tokens: 9 }, budget: null };
  const t = Object.fromEntries(targets({ speed: { hours: 24, review: { p90: 12, n: 10 } }, acc: { days: 7, reviewed: 20, corrected: 3, flagged: 1, corrected_pct: 15 }, windows: win,
    routines: [{ key: "brief", active: true, runs: 2, output: 0, usage: "not logged" }], feeds: [{ name: "rss:x", verdict: "noise" }], days: 2.5 }).map((x) => [x.key, x]));
  assert.equal(t.speed.state, "pass"); assert.equal(t.accuracy.state, "fail"); assert.equal(t.usage.state, "unknown"); assert.match(t.usage.note, /usage not logged for brief/);
  assert.equal(t.earns.state, "unknown"); assert.match(t.earns.note, /2.5 so far/);
  const t2 = Object.fromEntries(targets({ speed: null, acc: { corrected_pct: null }, windows: { ...win, budget: { window_pct: 99, week_pct: 50, level: "stop" } }, routines: [], feeds: [], days: 20 }).map((x) => [x.key, x]));
  assert.equal(t2.speed.state, "unknown"); assert.equal(t2.usage.state, "fail"); assert.equal(t2.earns.state, "pass");
});

test("loop cycles: idle_before, gaps in older records, budget per cycle and the leader lease", async () => {
  const { loopCycles } = await import("../../scripts/efficiency.mjs");
  const J = (c, extra = {}) => ({ run: "run-A-c" + c, job: "sweep", flow: true, cycle: c, started_at: h(10 - c / 10), workers: 1, ...extra });
  const l = loopCycles([J(1), J(4), J(5, { idle_before: 2, budget: { level: "tight", window_pct: 85, week_pct: 20 } }), J(6, { workers: 0, budget: { level: "stop" } }), { run: "x", job: "triage", started_at: h(1) }], NOW - 864e5, { "flow:leader": { budget: "ok", cycle: 6 } });
  assert.equal(l.recorded, 4); assert.equal(l.idle_from_gaps, 2); assert.equal(l.idle_unrecorded, 4); assert.equal(l.idle_recorded, 1);
  assert.equal(l.cycles, 8); assert.equal(l.idle, 5); assert.deepEqual(l.budget, { ok: 0, tight: 1, stop: 1, unknown: 2 });
  assert.equal(l.last_budget.level, "stop"); assert.equal(l.leader_budget.level, "ok");
  const t = Object.fromEntries(targets({ speed: null, acc: { corrected_pct: null }, windows: { five_hour: { tokens: 0 }, week: { tokens: 0 }, budget: null }, routines: [], feeds: [], days: 1, loop: l }).map((x) => [x.key, x]));
  assert.equal(t.usage.state, "fail"); assert.match(t.usage.value, /1 loop cycle\(s\) stopped/);
});

test("retired routines are marked and left out of the earns-its-place count", () => {
  const reg = [{ key: "steward", tier: "ai", active: false, retired: "no output in 14 days", merged_into: "sweep" }, { key: "brief", tier: "ai" }];
  const rows = routineReport(reg, [], [{ at: h(1), job: "steward", out: logOutput({}) }, { at: h(1), job: "brief", out: logOutput({}) }], [], {}, NOW - 864e5, NOW);
  const st = rows.find((r) => r.key === "steward");
  assert.equal(st.retired, true); assert.equal(st.merged_into, "sweep");
  const t = targets({ speed: null, acc: { corrected_pct: null }, windows: { five_hour: { tokens: 0 }, week: { tokens: 0 }, budget: null }, routines: rows.map((r) => ({ ...r, active: true })), feeds: [], days: 20 }).find((x) => x.key === "earns");
  assert.match(t.value, /^1 routine/);
});

test("report: never presents fewer days of data as a full window", () => {
  const inp = { usage: [{ at: h(10), job: "sweep", in: 5 }], leads: [{ url: "u", title: "t", seen_at: h(60), via: "rss" }], logs: [], jobruns: [], closures: [], byRule: new Set(), events: [], registry: [{ key: "sweep", tier: "ai" }], status: {}, osint: {}, gridAudit: null };
  const r = report(inp, { now: NOW, days: 7, clusterFn: noCluster });
  assert.equal(r.covered.leads, 2.5); assert.equal(r.covered.usage, 0.4); assert.match(r.note, /leads 2\.5 days/);
  assert.equal(r.targets.find((t) => t.key === "earns").state, "unknown");
  assert.ok(r.gaps.some((g) => /usage not logged/.test(g)));
  assert.equal(spanDays([], 7, NOW), 0);
});
