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
  assert.equal(r.gaps, undefined, "internal method notes are never published");
  assert.equal(spanDays([], 7, NOW), 0);
});

test("retired feeds: a retired collector and an RSS feed retired in config/feeds.json are listed apart, still counted", async () => {
  const { markRetired } = await import("../../scripts/efficiency.mjs");
  const rows = markRetired([{ name: "google-news", via: "google-news", sources: [] }, { name: "rss:theregister.com", via: "rss", sources: ["The Register"] }, { name: "rss:x.com", via: "rss", sources: ["The Register", "X"] }, { name: "bing-news", via: "bing-news", sources: [] }],
    [{ name: "the register", retired: "2026-11-20", why: "robots.txt" }]);
  assert.deepEqual(rows.map((r) => !!r.retired), [true, true, false, false]);
  assert.equal(rows[1].retired_at, "2026-11-20"); assert.equal(rows[1].retired_why, "robots.txt"); assert.match(rows[0].retired_why, /robots\.txt/);
  const inp = { usage: [], leads: [{ url: "u1", title: "t", seen_at: h(5), via: "google-news" }, { url: "https://www.theregister.com/a", title: "t", seen_at: h(5), via: "rss", source: "The Register" }], logs: [], jobruns: [], closures: [], byRule: new Set(), events: [],
    registry: [], status: {}, osint: {}, gridAudit: null, retiredFeeds: [{ name: "The Register", retired: "2026-11-20", why: "w" }] };
  const r = report(inp, { now: NOW, days: 7, clusterFn: noCluster });
  assert.equal(r.feeds.length, 0); assert.deepEqual(r.retired_feeds.map((f) => f.name).sort(), ["google-news", "rss:theregister.com"]);
  assert.equal(r.totals.leads, 2);
});

test("targets: short title, figure and detail for the status page cards", () => {
  const t = Object.fromEntries(targets({ speed: { hours: 50, review: { p90: 1220, n: 152 } }, acc: { days: 7, reviewed: 412, corrected: 141, flagged: 17, corrected_pct: 34.2 },
    windows: { five_hour: { tokens: 0 }, week: { tokens: 0 }, budget: { window_pct: 49, week_pct: 17, level: "ok" } }, routines: [], feeds: [{ name: "rss:x", verdict: "noise" }], days: 2.1 }).map((x) => [x.key, x]));
  assert.equal(t.speed.figure, "1220 min"); assert.match(t.speed.detail, /152 events, last 50 h/); assert.equal(t.speed.title, "Speed");
  assert.equal(t.accuracy.figure, "34.2%"); assert.equal(t.usage.figure, "49%"); assert.equal(t.earns.figure, "1 candidates");
  assert.ok(Object.values(t).every((x) => x.title && x.goal && x.figure && x.detail));
});

test("flow: each stage counts what happened in its window; rule and AI closures are told apart; reasons cut to the rule", async () => {
  const { flowWindow, ruleReason } = await import("../../scripts/efficiency.mjs");
  assert.equal(ruleReason("story ab12cd34: already on file: acme-2026-11 (headline adds nothing)"), "already on file");
  assert.equal(ruleReason("a bare database row with no report of exploitation"), "a bare database row with no report of exploitation");
  assert.equal(ruleReason(""), "no reason recorded");
  const leads = [{ url: "a", seen_at: h(2) }, { url: "b", seen_at: h(3) }, { url: "c", seen_at: h(30) }, { url: "d", seen_at: h(200) }];
  const storyOf = new Map([["a", "s:1"], ["b", "s:1"], ["c", "s:2"]]);
  const closures = [{ at: h(1), story: "1", reason: "acme-2026-11", urls: ["a", "b"] }, { at: h(1), story: "9", reason: "not an event", urls: [] },
    { at: h(5), story: "7", reason: "commentary, advice or an explainer, not an event", urls: [], rule: true }, { at: h(5), story: "7", reason: "commentary, advice or an explainer, not an event", urls: [], rule: true },
    { at: h(40), story: "8", reason: "a bare database row with no report of exploitation", urls: [], rule: true }];
  const events = [{ id: "acme-2026-11", first_seen: h(1), updated_at: h(1), review: { state: "corrected", at: h(0.5), first_at: h(0.5) } },
    { id: "old-2026-11", first_seen: h(50), updated_at: h(4), review: { state: "passed", at: h(4), first_at: h(49) } }, { id: "dup", duplicate_of: "acme-2026-11", first_seen: h(1) }];
  const d1 = flowWindow({ leads, closures, events }, storyOf, 24, NOW);
  assert.deepEqual([d1.leads, d1.stories, d1.rule, d1.researched, d1.to_event, d1.added, d1.updated], [2, 1, 1, 2, 1, 1, 1]);
  assert.deepEqual([d1.reviewed, d1.passed, d1.corrected, d1.flagged], [1, 0, 1, 0]);
  assert.deepEqual(d1.reasons, [{ reason: "commentary, advice or an explainer, not an event", n: 1 }]);
  const d7 = flowWindow({ leads, closures, events }, storyOf, 168, NOW);
  assert.deepEqual([d7.leads, d7.stories, d7.rule, d7.added, d7.updated, d7.reviewed], [3, 2, 2, 2, 0, 2]);
  // nothing on file: every count is zero, nothing throws
  const empty = flowWindow({}, null, 24, NOW);
  assert.deepEqual([empty.leads, empty.stories, empty.rule, empty.researched, empty.added, empty.reviewed, empty.reasons.length], [0, 0, 0, 0, 0, 0, 0]);
});

test("sources: feeds by tier, languages and regions; events traced to their leads by tier and collector family; top publishers", async () => {
  const { sourceSummary, sourcesReport, leadTier, familyOf, urlKey } = await import("../../scripts/efficiency.mjs");
  const s = sourceSummary([{ tier: "gov", lang: "fr", region: "europe" }, { tier: "news" }, { tier: "vendor", lang: "en" }], [{ hl: "ja", region: "east-asia" }, { hl: "en", region: "global" }],
    { sources: { "bing-news": { ok: true }, gdelt: { ok: false }, "google-news": { ok: true } } }, { collect_feeds_ok: 2 });
  assert.deepEqual(s, { feeds: 3, feeds_ok: 2, by_tier: { gov: 1, vendor: 1, news: 1 }, queries: 2, collectors: 2, collectors_ok: 1, languages: 3, regions: 2 });
  assert.equal(leadTier({ tier: "gov", kind: "cve" }), "database"); assert.equal(leadTier({ tier: "vendor" }), "vendor"); assert.equal(leadTier({}), "news");
  assert.equal(familyOf({ via: "nvd" }), "cve-kev"); assert.equal(familyOf({}), "rss"); assert.equal(familyOf({ via: "ransomware-live" }), "claims"); assert.equal(familyOf({ via: "hibp" }), "other");
  assert.equal(urlKey("https://www.Example.com/a/?utm=1#x"), "example.com/a");
  const leads = [{ url: "https://gov.example/advisory?at_medium=RSS", tier: "gov", via: "rss", seen_at: h(20) }, { url: "https://news.example/a", tier: "news", via: "bing-news", seen_at: h(10) },
    { url: "https://redirect.example/x", tier: "news", via: "google-news", seen_at: h(9) }];
  const events = [
    { id: "e1", first_seen: h(5), sources: [{ name: "News", url: "https://news.example/a" }, { name: "Gov", url: "https://gov.example/advisory" }] },
    { id: "e2", first_seen: h(5), sources: [{ name: "Vendor", url: "https://vendor.example/b" }] },
    { id: "e3", first_seen: h(5), sources: [{ name: "News", url: "https://www.news.example/c" }, { name: "News again", url: "https://news.example/d" }] },
    { id: "e4", first_seen: h(30), sources: [{ name: "Old", url: "https://old.example/" }] },
    { id: "e5", first_seen: h(500), sources: [] }, { id: "e6", duplicate_of: "e1", first_seen: h(5), sources: [] }];
  const closures = [{ at: h(5), story: "1", reason: "e3", urls: ["https://redirect.example/x"] }, { at: h(5), story: "2", reason: "e2", urls: ["https://news.example/a"], rule: true }];
  const r = sourcesReport(events, leads, closures, NOW - 168 * 36e5);
  assert.equal(r.events, 4);
  // e1: gov beats news, first lead seen is the gov RSS one; e2: a rule closure never traces; e3: via its story's closure; e4: before the leads
  assert.deepEqual(r.tier, { gov: 1, untraced: 1, news: 1, "before-leads": 1 });
  assert.deepEqual(r.family, { rss: 1, untraced: 1, "google-news": 1, "before-leads": 1 });
  assert.deepEqual(r.publishers[0], { host: "news.example", name: "News", events: 2 });
  assert.equal(r.publishers.length, 4);
  assert.deepEqual(sourcesReport([], [], [], 0), { events: 0, tier: {}, family: {}, publishers: [] });
});

test("report: carries the flow and source blocks, and a broken input leaves a note instead of failing the report", () => {
  const inp = { usage: [], leads: [{ url: "u", title: "t", seen_at: h(3), via: "rss", tier: "gov" }], logs: [], jobruns: [], closures: [], byRule: new Set(), events: [{ id: "x", first_seen: h(2), sources: [{ name: "G", url: "u" }] }],
    registry: [], status: {}, osint: {}, gridAudit: null, feedList: [{ tier: "gov" }], queries: [] };
  const r = report(inp, { now: NOW, days: 7, clusterFn: noCluster });
  assert.equal(r.flow.d1.leads, 1); assert.equal(r.flow.d7.added, 1); assert.equal(r.flow.sources.feeds, 1); assert.equal(r.flow.lead_days, 0.1);
  assert.deepEqual(r.sources.tier, { gov: 1 });
  const bad = report({ ...inp, feedList: 42 }, { now: NOW, days: 7, clusterFn: noCluster });
  assert.match(bad.flow.error, /could not be worked out/);
});

test("feeds: a feed's first day is left out of the waste ranking, kept in the totals", () => {
  const mk = (n, day, host) => Array.from({ length: n }, (_, i) => ({ url: `https://${host}/${day}/${i}`, source: host, seen_at: `${day}T10:00:00Z` }));
  // msrc: 114 of 129 on 11-19 (its first day), 15 since; zdi: 28 of 31 on 11-18, 3 since; noisy: steady
  const leads = [...mk(114, "2026-11-19", "msrc.microsoft.com"), ...mk(15, "2026-11-20", "msrc.microsoft.com"), ...mk(28, "2026-11-18", "zerodayinitiative.com"), ...mk(3, "2026-11-20", "zerodayinitiative.com"),
    ...mk(20, "2026-11-19", "noisy.example"), ...mk(20, "2026-11-20", "noisy.example"), ...mk(20, "2026-11-21", "noisy.example"), ...mk(9, "2026-11-19", "quiet.example")];
  const by = Object.fromEntries(feedReport(leads, new Map(), new Set(), {}, NOW).map((r) => [r.name, r]));
  assert.equal(by["rss:msrc.microsoft.com"].leads, 129); assert.equal(by["rss:msrc.microsoft.com"].leads_after_first_day, 15);
  assert.equal(by["rss:zerodayinitiative.com"].leads, 31); assert.equal(by["rss:zerodayinitiative.com"].leads_after_first_day, 3);
  assert.equal(by["rss:noisy.example"].leads_after_first_day, 40); assert.equal(by["rss:quiet.example"].leads_after_first_day, 0);
  assert.equal(by["rss:msrc.microsoft.com"].first_day, "2026-11-19");
  // the ranking sorts on leads after day one: noisy first, msrc ahead of zdi, quiet (nothing since day one) not ranked at all
  const rank = Object.values(by).filter((f) => f.verdict !== "useful" && f.leads_after_first_day > 0).sort((a, b) => b.leads_after_first_day - a.leads_after_first_day).map((f) => f.name);
  assert.deepEqual(rank, ["rss:noisy.example", "rss:msrc.microsoft.com", "rss:zerodayinitiative.com"]);
});

test("routines: a script routine with no run log counts a heartbeat advance as a run", () => {
  const reg = [{ key: "gdelt-gkg", name: "GDELT", tier: "automation", status_key: "last_gdelt_at" }, { key: "psirt", name: "PSIRT", tier: "automation", status_key: "last_psirt_at" }, { key: "old", name: "Old", tier: "automation", status_key: "last_old_at" }, { key: "none", name: "None", tier: "automation", status_key: "last_none_at" }];
  const rows = Object.fromEntries(routineReport(reg, [], [], [], { last_gdelt_at: h(1), last_psirt_at: h(20), last_old_at: h(24 * 30) }, NOW - 7 * 864e5, NOW).map((r) => [r.key, r]));
  assert.equal(rows["gdelt-gkg"].runs, 1); assert.equal(rows["gdelt-gkg"].runs_basis, "heartbeat"); assert.equal(rows.psirt.runs, 1);
  // a heartbeat from before the window, or none at all, is still "never ran" in this window
  assert.equal(rows.old.runs, 0); assert.equal(rows.none.runs, 0);
});

test("routines: scams is a document routine, its idle share is not measured", () => {
  const reg = [{ key: "scams", name: "Scams", tier: "automation", status_key: "last_scams_at" }];
  const logs = Array.from({ length: 23 }, (_, i) => ({ at: h(i + 1), job: "scams", out: logOutput({ items: Array(52).fill({}), leads: [] }) }));
  const row = routineReport(reg, [], logs, [], {}, NOW - 7 * 864e5, NOW)[0];
  assert.equal(row.runs, 23); assert.equal(row.idle, 23); assert.equal(row.idle_pct, null);
});

test("closed is reported per unit: stories and leads are never added", () => {
  const reg = [{ key: "backlog", name: "B", tier: "ai" }, { key: "sweep", name: "S", tier: "ai" }, { key: "lead-triage", name: "LT", tier: "automation" }];
  const sk = (n) => Array.from({ length: n }, (_, i) => ({ url: "u" + i }));
  const logs = [{ at: h(1), job: "backlog-b1", model: "m", out: logOutput({ skipped: sk(1955) }) }, { at: h(2), job: "sweep-r1", model: "m", out: logOutput({ skipped: sk(2680) }) }, { at: h(3), job: "backlog-auto", model: null, out: logOutput({ skipped: sk(113073) }) }];
  const rows = Object.fromEntries(routineReport(reg, [], logs, [], {}, NOW - 7 * 864e5, NOW).map((r) => [r.key, r]));
  assert.deepEqual([rows.backlog.closed_stories, rows.backlog.closed_leads, rows.backlog.closed_unit], [1955, 0, "stories"]);
  assert.deepEqual([rows.sweep.closed_stories, rows.sweep.closed_leads], [2680, 0]);
  assert.deepEqual([rows["lead-triage"].closed_stories, rows["lead-triage"].closed_leads, rows["lead-triage"].closed_unit], [0, 113073, "leads"]);
  const rep = report({ usage: [], leads: [], logs, jobruns: [], closures: [], byRule: new Set(), events: [], registry: reg, status: {}, osint: {} }, { now: NOW, days: 7, speed: null });
  assert.deepEqual(rep.totals.closed, { stories: 4635, leads: 113073 });
});
