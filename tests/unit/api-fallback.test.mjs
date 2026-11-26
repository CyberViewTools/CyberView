// The API-key fallback (owner-approved 2026-11-23): the Max subscription stays primary and the Anthropic API bills ONLY
// while the subscription's usage window is exhausted, so publishing never stalls. The key lives under the non-standard env
// var CYBERVIEW_FALLBACK_ANTHROPIC_API_KEY and is injected into a worker only in fallback mode; it is never logged or
// committed. Run: node --test tests/unit/
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { fallbackDecision, actionsServed, fallbackConfig, fallbackSpend, estimateCost, PRICES, FALLBACK_ENV, DEFAULT_FALLBACK, apiPrimaryLive, apiTestReport, budgetState, limitHits } from "../../scripts/lib/usage.mjs";
import { workerEnv, ledgerLine, planLevelFor } from "../../scripts/run-job.mjs";
import { fallbackProblems, THRESHOLD } from "../../scripts/pipecheck.mjs";
import { apiFallbackReport } from "../../scripts/efficiency.mjs";
import { fallbackStatus, fallbackLine, apiTestLines } from "../../scripts/budget.mjs";

const NOW = Date.parse("2026-11-23T12:00:00Z"), iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z"), m = (min) => iso(NOW - min * 6e4);
const SECRET = "FAKEKEY-cyberview-fallback-must-not-leak-0001";   // deliberately NOT sk-ant-shaped so the secret scanner does not flag the test; masking is value-agnostic
const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("decision table: subscription stays primary; the API key bills only while the window is exhausted", () => {
  const live = iso(NOW + 30 * 6e4), base = { now: NOW, fallbackKeyPresent: true, enabled: true, monthSpendUsd: 0, cap: 150, fallbackKeyLimited: false };
  // not limited -> always the subscription (no key), whatever the dials say
  assert.equal(fallbackDecision({ ...base, limited_until: null }), "subscription");
  assert.equal(fallbackDecision({ ...base, limited_until: m(10) }), "subscription", "a reset in the past = usable");
  assert.equal(fallbackDecision({ limited_until: null }), "subscription", "defaults: no key, not limited");
  // the window is exhausted (a live reset time)
  assert.equal(fallbackDecision({ ...base, limited_until: live }), "api-fallback", "key present, enabled, under cap");
  assert.equal(fallbackDecision({ ...base, limited_until: NOW + 30 * 6e4 }), "api-fallback", "limited_until as ms works too");
  assert.equal(fallbackDecision({ ...base, limited_until: live, fallbackKeyPresent: false }), "park", "no key -> park (exactly #126)");
  assert.equal(fallbackDecision({ ...base, limited_until: live, enabled: false }), "park", "disabled -> park");
  assert.equal(fallbackDecision({ ...base, limited_until: live, fallbackKeyLimited: true }), "park", "the fallback key itself hit a limit -> park");
  assert.equal(fallbackDecision({ ...base, limited_until: live, monthSpendUsd: 150 }), "park", "at the cap -> park");
  assert.equal(fallbackDecision({ ...base, limited_until: live, monthSpendUsd: 149.99 }), "api-fallback", "just under the cap");
  assert.equal(fallbackDecision({ ...base, limited_until: live, cap: 0, monthSpendUsd: 0 }), "park", "cap 0 = off");
});

test("env injection: only fallback mode gets ANTHROPIC_API_KEY, and a stray ambient key never makes the API primary", () => {
  // the normal (subscription) worker env has NO ANTHROPIC_API_KEY
  const sub = workerEnv("subscription", SECRET, { PATH: "/bin" });
  assert.ok(!("ANTHROPIC_API_KEY" in sub), "subscription: no ANTHROPIC_API_KEY");
  assert.equal(sub.CYBERVIEW_WORKER, "1");
  // the fallback worker env has it set to the fallback value
  const fb = workerEnv("api-fallback", SECRET, { PATH: "/bin" });
  assert.equal(fb.ANTHROPIC_API_KEY, SECRET, "api-fallback: the key is injected");
  // an ambient ANTHROPIC_API_KEY is stripped in subscription mode (subscription must stay primary)
  const strayed = workerEnv("subscription", SECRET, { ANTHROPIC_API_KEY: "sk-ambient-stray" });
  assert.ok(!("ANTHROPIC_API_KEY" in strayed), "an ambient key is removed in subscription mode");
  // "park" never spawns, but if asked it carries no key either; an empty key leaves fallback mode keyless
  assert.ok(!("ANTHROPIC_API_KEY" in workerEnv("park", SECRET, {})));
  assert.ok(!("ANTHROPIC_API_KEY" in workerEnv("api-fallback", "", {})), "no key value -> none injected");
});

test("masking: the key value never appears in a worker env dump, a ledger line, or any report", () => {
  // the subscription env dumped to a log would not contain the key
  assert.ok(!JSON.stringify(workerEnv("subscription", SECRET, {})).includes(SECRET));
  // a ledger line carries only served, never the key
  const sub = ledgerLine("sweep", "researcher", 1, "sonnet", 1000, JSON.stringify({ is_error: false, result: "ok", num_turns: 5, total_cost_usd: 0.2 }), null, "subscription");
  const fb = ledgerLine("sweep", "researcher", 1, "sonnet", 1000, JSON.stringify({ is_error: false, result: "ok", num_turns: 5, total_cost_usd: 0.2 }), null, "api-fallback");
  assert.equal(sub.served, "subscription"); assert.equal(fb.served, "api-fallback");
  assert.ok(!JSON.stringify(fb).includes(SECRET));
  // the config helper reads only the env var NAME, never the value
  assert.equal(fallbackConfig({ api_fallback: { enabled: true, monthly_usd_cap: 150 } }).env_var, FALLBACK_ENV);
  assert.ok(!JSON.stringify(fallbackConfig()).includes(SECRET));
  // budget.mjs status: with the key set in the environment it reports "present", never the value (spawned in a temp repo)
  const t = mkdtempSync(join(tmpdir(), "fb-")), now = Date.now();
  mkdirSync(join(t, "scripts", "lib"), { recursive: true }); mkdirSync(join(t, "config")); mkdirSync(join(t, "data", "usage"), { recursive: true });
  for (const f of ["scripts/budget.mjs", "scripts/lib/usage.mjs", "scripts/lib/store.mjs"]) copyFileSync(join(repo, f), join(t, f));
  writeFileSync(join(t, "config", "pipeline.json"), JSON.stringify({ usage_budget: { window_tokens: 100e6, window_cost: 100, api_fallback: { enabled: true, monthly_usd_cap: 150 } } }));
  const env = { ...process.env, [FALLBACK_ENV]: SECRET, CYBERVIEW_BUILD_LEDGER: join(t, "build.jsonl") };
  const r = spawnSync("node", ["scripts/budget.mjs", "status"], { cwd: t, encoding: "utf8", env });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /API fallback: enabled, cap \$150\/month, key present/);
  assert.ok(!`${r.stdout}${r.stderr}`.includes(SECRET), "the key value is never printed");
  // the json form also masks
  const j = spawnSync("node", ["scripts/budget.mjs", "status", "--json"], { cwd: t, encoding: "utf8", env });
  assert.ok(!`${j.stdout}${j.stderr}`.includes(SECRET));
  assert.equal(JSON.parse(j.stdout).fallback.key_present, true);
});

test("cap accrual: fallback USD is estimated from each api-fallback worker's tokens x PRICES, this calendar month only", () => {
  assert.deepEqual([PRICES.sonnet.in, PRICES.sonnet.out, PRICES.opus.in, PRICES.opus.out, PRICES.haiku.in, PRICES.haiku.out], [2, 10, 5, 25, 0.1, 0.5]);
  // 1M input + 1M output on sonnet = $2 + $10
  assert.equal(estimateCost({ model: "sonnet", in: 1e6, out: 1e6 }), 12);
  assert.equal(estimateCost({ model: "opus", in: 1e6 }), 5);
  // cache read 0.1x input, cache write 1.25x input
  assert.equal(estimateCost({ model: "sonnet", cache_read: 1e6 }), 0.2);
  assert.equal(estimateCost({ model: "sonnet", cache_write: 1e6 }), 2.5);
  assert.equal(estimateCost({ model: "mystery", in: 1e6 }), 2, "an unknown model is priced as sonnet, never zero");
  // only api-fallback lines of the current month count
  const lines = [
    { at: m(10), served: "api-fallback", model: "sonnet", in: 1e6, out: 1e6 },   // $12
    { at: m(20), served: "api-fallback", model: "opus", in: 2e6 },               // $10
    { at: m(30), served: "subscription", model: "opus", in: 10e6 },              // ignored (subscription)
    { at: "2026-10-15T00:00:00Z", served: "api-fallback", model: "opus", in: 10e6 }, // ignored (last month)
  ];
  const s = fallbackSpend(lines, NOW);
  assert.deepEqual([s.month, s.usd, s.workers], ["2026-11", 22, 2]);
  assert.equal(s.last_at, m(10));
  assert.deepEqual(fallbackSpend([], NOW), { month: "2026-11", usd: 0, workers: 0, last_at: null });
});

test("plan level: a real-limit stop lifts to ok on the fallback; an estimate-only stop still parks", () => {
  const stopReal = { level: "stop", limited_until: iso(NOW + 30 * 6e4) }, stopEst = { level: "stop", limited_until: null };
  assert.equal(planLevelFor(stopReal, "api-fallback"), "ok", "window exhausted + fallback -> plan a normal cycle");
  assert.equal(planLevelFor(stopReal, "park"), "stop");
  assert.equal(planLevelFor(stopReal, "subscription"), "stop");
  assert.equal(planLevelFor(stopEst, "api-fallback"), "stop", "estimate-only stop is left to park");
  assert.equal(planLevelFor({ level: "tight" }, "api-fallback"), "tight");
  assert.equal(planLevelFor({ level: "ok" }, "subscription"), "ok");
});

test("config: the dials default, and a broken cap falls back to 150; the env var name is fixed", () => {
  assert.deepEqual(DEFAULT_FALLBACK, { enabled: true, monthly_usd_cap: 150 });
  assert.equal(fallbackConfig({ api_fallback: {} }).monthly_usd_cap, 150);
  assert.equal(fallbackConfig({ api_fallback: { monthly_usd_cap: "oops" } }).monthly_usd_cap, 150);
  assert.equal(fallbackConfig({ api_fallback: { monthly_usd_cap: 0 } }).monthly_usd_cap, 0);
  assert.equal(fallbackConfig({ api_fallback: { enabled: false } }).enabled, false);
  assert.equal(fallbackConfig({}).env_var, "CYBERVIEW_FALLBACK_ANTHROPIC_API_KEY");
  // the real config carries the dials
  const real = JSON.parse(readFileSync(join(repo, "config", "pipeline.json"), "utf8")).usage_budget.api_fallback;
  assert.equal(real.enabled, true); assert.ok(real.monthly_usd_cap > 0); assert.ok(typeof real._note === "string" && real._note.includes("CYBERVIEW_FALLBACK_ANTHROPIC_API_KEY"));
});

test("config: api_on_actions parses to a strict boolean, and the real config turns it on", () => {
  assert.equal(fallbackConfig({ api_fallback: {} }).api_on_actions, false, "absent -> false");
  assert.equal(fallbackConfig({ api_fallback: { api_on_actions: false } }).api_on_actions, false);
  assert.equal(fallbackConfig({ api_fallback: { api_on_actions: "yes" } }).api_on_actions, false, "only strict true counts");
  assert.equal(fallbackConfig({ api_fallback: { api_on_actions: true } }).api_on_actions, true);
  const real = JSON.parse(readFileSync(join(repo, "config", "pipeline.json"), "utf8")).usage_budget.api_fallback;
  assert.equal(fallbackConfig({ api_fallback: real }).api_on_actions, true, "the shipped config bills the API on Actions");
});

test("pipecheck: an info problem while on the API fallback, a needs-attention problem at the cap; both via health.json", () => {
  const fb = { enabled: true, monthly_usd_cap: 150 };
  assert.deepEqual(fallbackProblems([], fb, NOW), [], "nothing on fallback: no problem");
  // currently on fallback (the most recent worker line ran on the API key)
  const on = fallbackProblems([{ at: m(40), served: "api-fallback", model: "sonnet", in: 1e6 }, { at: m(5), served: "api-fallback", model: "opus", in: 1e6 }], fb, NOW);
  assert.equal(on.length, 1); assert.equal(on[0].id, "api-fallback"); assert.equal(on[0].level, "info"); assert.equal(on[0].threshold_min, THRESHOLD["api-fallback"]);
  assert.match(on[0].text, /running on the API fallback since .*subscription 5-hour window is exhausted/);
  // a recent subscription line means the window recovered: no info problem
  assert.deepEqual(fallbackProblems([{ at: m(5), served: "subscription", model: "opus", in: 1e6 }], fb, NOW), []);
  // the cap: a needs-attention problem (plus the info one, since it is also on fallback)
  const capped = fallbackProblems([{ at: m(5), served: "api-fallback", model: "opus", in: 40e6, out: 2e6 }], fb, NOW);
  const cap = capped.find((p) => p.id === "api-fallback-cap");
  assert.ok(cap, "cap problem present"); assert.equal(cap.level, "warn"); assert.equal(cap.threshold_min, THRESHOLD["api-fallback-cap"]);
  assert.match(cap.text, /API fallback monthly cap reached/);
  assert.equal(fallbackProblems([{ at: m(5), served: "api-fallback", model: "opus", in: 40e6, out: 2e6 }], { enabled: false, monthly_usd_cap: 150 }, NOW).find((p) => p.id === "api-fallback-cap"), undefined, "disabled: no cap problem");
});

test("efficiency: the api_fallback block for the status page", () => {
  const lines = [{ at: m(10), served: "api-fallback", model: "sonnet", in: 1e6, out: 1e6 }, { at: m(20), served: "subscription", model: "opus", in: 1e6 }];
  const r = apiFallbackReport(lines, { enabled: true, monthly_usd_cap: 150 }, NOW);
  assert.deepEqual([r.enabled, r.monthly_usd_cap, r.cycles_on_fallback, r.est_usd_this_month, r.cap_reached], [true, 150, 1, 12, false]);
  assert.equal(r.last_fallback_at, m(10));
  assert.equal(apiFallbackReport([{ at: m(5), served: "api-fallback", model: "opus", in: 40e6 }], { enabled: true, monthly_usd_cap: 150 }, NOW).cap_reached, true);
});

test("budget.mjs: the fallback status line never contains the key value", () => {
  const f = fallbackStatus(NOW, { window_tokens: 100e6, api_fallback: { enabled: true, monthly_usd_cap: 150 } }, [{ at: m(10), served: "api-fallback", model: "sonnet", in: 1e6, out: 1e6 }], true);
  assert.deepEqual([f.enabled, f.cap_usd, f.key_present, f.usd, f.workers], [true, 150, true, 12, 1]);
  const line = fallbackLine(f);
  assert.match(line, /API fallback: enabled, cap \$150\/month, key present; now (subscription|api-fallback|park); \$12 billed/);
  assert.ok(!line.includes(SECRET));
  assert.match(fallbackLine(fallbackStatus(NOW, {}, [], false)), /key not set \(CYBERVIEW_FALLBACK_ANTHROPIC_API_KEY\)/);
});

test("workers never inherit the fallback key under its own name or cloud credentials", () => {
  const base = { PATH: "/bin", CYBERVIEW_FALLBACK_ANTHROPIC_API_KEY: "sk-x", AWS_ACCESS_KEY_ID: "a", AWS_SECRET_ACCESS_KEY: "b", CLOUDSDK_AUTH_ACCESS_TOKEN: "c" };
  for (const mode of ["subscription", "api-fallback", "park"]) {
    const e = workerEnv(mode, "sk-x", base);
    assert.ok(!("CYBERVIEW_FALLBACK_ANTHROPIC_API_KEY" in e), `${mode}: fallback key`);
    for (const k of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "CLOUDSDK_AUTH_ACCESS_TOKEN"]) assert.equal(e[k], "", `${mode}: ${k} blank`);
    assert.equal(e.GH_TOKEN, "proxy-supplied"); assert.equal(e.GITHUB_TOKEN, "proxy-supplied");
    assert.equal(e.PATH, "/bin");
  }
});

test("on a GitHub Actions runner workers get the job token handed over as CYBERVIEW_WORKER_GH_TOKEN, nothing else", () => {
  const base = { PATH: "/bin", GH_TOKEN: "ghs_parent", CYBERVIEW_WORKER_GH_TOKEN: "ghs_job_scoped", CLAUDE_CODE_OAUTH_TOKEN: "oauth-x" };
  const e = workerEnv("subscription", "", base);
  assert.equal(e.GH_TOKEN, "ghs_job_scoped"); assert.equal(e.GITHUB_TOKEN, "ghs_job_scoped");
  assert.ok(!("CYBERVIEW_WORKER_GH_TOKEN" in e));
  assert.equal(e.CLAUDE_CODE_OAUTH_TOKEN, "oauth-x");        // the worker signs in to the subscription with it
  assert.ok(!("ANTHROPIC_API_KEY" in e));
  // without the hand-over (a cloud session) the placeholder stays: the proxy supplies GitHub's credentials there
  assert.equal(workerEnv("subscription", "", { GH_TOKEN: "ghs_parent" }).GH_TOKEN, "proxy-supplied");
});

test("workers never inherit the launcher's early-compaction settings", () => {
  const e = workerEnv("subscription", "", { PATH: "/bin", CLAUDE_CODE_AUTO_COMPACT_WINDOW: "200000", CLAUDE_AUTOCOMPACT_PCT_OVERRIDE: "20" });
  assert.ok(!("CLAUDE_CODE_AUTO_COMPACT_WINDOW" in e)); assert.ok(!("CLAUDE_AUTOCOMPACT_PCT_OVERRIDE" in e));
  assert.equal(e.PATH, "/bin");
});

// ---------- API-primary window (owner, 2026-11-25: measure 24 hours of the pipeline on the API) ----------
test("api_primary: parsed only when from < until, both ISO; live only inside the window", () => {
  assert.equal(fallbackConfig({ api_fallback: {} }).api_primary, null);
  assert.equal(fallbackConfig({ api_fallback: { api_primary: { from: "2026-11-25T16:00:00Z" } } }).api_primary, null, "no until");
  assert.equal(fallbackConfig({ api_fallback: { api_primary: { from: "2026-11-26T16:00:00Z", until: "2026-11-25T16:00:00Z" } } }).api_primary, null, "until before from");
  assert.equal(fallbackConfig({ api_fallback: { api_primary: { from: "tomorrow", until: "2026-11-25T16:00:00Z" } } }).api_primary, null, "not ISO");
  const fb = fallbackConfig({ api_fallback: { api_primary: { from: "2026-11-25T16:00:00Z", until: "2026-11-26T16:00:00Z" } } });
  assert.deepEqual(fb.api_primary, { from: "2026-11-25T16:00:00Z", until: "2026-11-26T16:00:00Z" });
  assert.equal(apiPrimaryLive(fb, Date.parse("2026-11-25T15:59:00Z")), false);
  assert.equal(apiPrimaryLive(fb, Date.parse("2026-11-25T16:00:00Z")), true);
  assert.equal(apiPrimaryLive(fb, Date.parse("2026-11-26T15:59:00Z")), true);
  assert.equal(apiPrimaryLive(fb, Date.parse("2026-11-26T16:00:00Z")), false, "ends at until");
  assert.equal(apiPrimaryLive(fallbackConfig({}), NOW), false);
});

test("api_primary decision: the key bills first; without it (no key, disabled, cap, its own limit) the old rules apply", () => {
  const base = { now: NOW, fallbackKeyPresent: true, enabled: true, monthSpendUsd: 0, cap: 400, fallbackKeyLimited: false, apiPrimary: true };
  const live = new Date(NOW + 3600e3).toISOString();
  assert.equal(fallbackDecision({ ...base, limited_until: null }), "api");
  assert.equal(fallbackDecision({ ...base, limited_until: live }), "api", "a subscription limit does not matter");
  assert.equal(fallbackDecision({ ...base, fallbackKeyPresent: false }), "subscription", "no key: subscription");
  assert.equal(fallbackDecision({ ...base, enabled: false }), "subscription", "disabled: subscription");
  assert.equal(fallbackDecision({ ...base, monthSpendUsd: 400 }), "subscription", "cap reached: subscription");
  assert.equal(fallbackDecision({ ...base, fallbackKeyLimited: true }), "subscription", "the key hit its limit: subscription");
  assert.equal(fallbackDecision({ ...base, fallbackKeyLimited: true, limited_until: live }), "park", "both limited: park");
  assert.equal(fallbackDecision({ ...base, apiPrimary: false }), "subscription", "outside the window: unchanged");
});

test("api_primary: the worker gets the key, the ledger says served api, the plan level is ok, spend counts toward the cap", () => {
  const env = workerEnv("api", "sk-test-not-real", { PATH: "/bin", ANTHROPIC_API_KEY: "stray", CYBERVIEW_FALLBACK_ANTHROPIC_API_KEY: "sk-test-not-real" });
  assert.equal(env.ANTHROPIC_API_KEY, "sk-test-not-real"); assert.equal(env.CYBERVIEW_FALLBACK_ANTHROPIC_API_KEY, undefined);
  assert.equal(workerEnv("subscription", "sk-test-not-real", { PATH: "/bin", ANTHROPIC_API_KEY: "stray" }).ANTHROPIC_API_KEY, undefined);
  const l = ledgerLine("sweep", "researcher", 1, "sonnet", 1000, JSON.stringify({ is_error: false, num_turns: 3, total_cost_usd: 0.5, usage: {} }), null, "api");
  assert.equal(l.served, "api");
  assert.equal(ledgerLine("sweep", "researcher", 1, "sonnet", 1, "{}", null, "bogus").served, "subscription");
  assert.equal(planLevelFor({ level: "stop", limited_until: null }, "api"), "ok");
  const mk = new Date(NOW).toISOString().slice(0, 7);
  assert.ok(fallbackSpend([{ at: mk + "-02T00:00:00Z", served: "api", model: "sonnet", in: 1e6 }], NOW).usd > 0);
});

test("api_primary: API-billed lines leave the subscription estimate and limit hits alone", () => {
  const at = new Date(NOW - 600e3).toISOString();
  const lim = { at, ok: false, error: "Claude AI usage limit reached", served: "api" };
  assert.deepEqual(limitHits([lim]), [], "the key's own limit is not the plan's");
  const cfg = { window_hours: 5, window_cost: 10, week_cost: 100, stop_pct: 120, tight_pct: 80 };
  const b = budgetState(NOW, cfg, [{ at, ok: true, served: "api", cost: 50, in: 1 }]);
  assert.equal(b.level, "ok"); assert.equal(b.window.cost, 0);
});

test("api-test report: CLI cost first, the estimate for unpriced lines, scaled to 24 hours", () => {
  const w = { from: "2026-11-25T16:00:00Z", until: "2026-11-26T16:00:00Z" };
  const lines = [
    { at: "2026-11-25T16:10:00Z", served: "api", job: "sweep", model: "sonnet", ok: true, cost: 1.5, in: 1e6 },
    { at: "2026-11-25T17:10:00Z", served: "api", job: "analysis", model: "opus", ok: true, cost: 2.5 },
    { at: "2026-11-25T18:10:00Z", served: "api", job: "sweep", model: "sonnet", ok: false, cost: null, in: 1e6 },
    { at: "2026-11-25T17:00:00Z", served: "subscription", job: "sweep", model: "sonnet", ok: true, cost: 9 },
    { at: "2026-11-25T15:00:00Z", served: "api", job: "sweep", model: "sonnet", ok: true, cost: 9 },
  ];
  const r = apiTestReport(lines, w, Date.parse("2026-11-25T18:10:00Z"));
  assert.equal(r.workers, 3); assert.equal(r.ok, 2); assert.equal(r.unpriced, 1);
  assert.equal(r.cost_usd, 6); assert.equal(r.hours, 2); assert.equal(r.per_24h_usd, 72);
  assert.deepEqual(r.by_model, { sonnet: 3.5, opus: 2.5 }); assert.deepEqual(r.by_job, { sweep: 3.5, analysis: 2.5 });
  const txt = apiTestLines(r, Date.parse("2026-11-25T18:10:00Z")).join("\n");
  assert.match(txt, /running/); assert.match(txt, /About \$72 per 24 hours/); assert.doesNotMatch(txt, /sk-/);
  assert.equal(apiTestReport([], w, NOW).workers, 0);
  assert.match(apiTestLines(apiTestReport([], w, NOW), NOW).join(" "), /No worker/);
  assert.equal(apiTestReport(lines, null), null);
});

test("pipecheck: an info problem during the API cost test", () => {
  const fb = { enabled: true, monthly_usd_cap: 400, api_primary: { from: "2026-11-25T16:00:00Z", until: "2026-11-26T16:00:00Z" } };
  const p = fallbackProblems([{ at: m(5), served: "api", model: "sonnet", in: 1e5 }], fb, NOW);
  const i = p.find((x) => x.id === "api-primary");
  assert.ok(i); assert.equal(i.level, "info"); assert.equal(i.threshold_min, THRESHOLD["api-primary"]); assert.match(i.text, /API cost test/);
});

test("Actions with the API key alone: no subscription to fall back to, so a worker parks instead of failing to sign in", () => {
  const A = { onActions: true, hasSubscription: false };
  assert.equal(actionsServed("api", A), "api", "the key bills as usual");
  assert.equal(actionsServed("subscription", A), "park", "key missing, capped or limited: park");
  assert.equal(actionsServed("park", A), "park");
  assert.equal(actionsServed("subscription", { onActions: true, hasSubscription: true }), "subscription", "with the token, the subscription is the fallback");
  assert.equal(actionsServed("subscription", { onActions: false, hasSubscription: false }), "subscription", "the cloud launcher is untouched");
  assert.equal(actionsServed("subscription"), "subscription", "defaults change nothing");
});
