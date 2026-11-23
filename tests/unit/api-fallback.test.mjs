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
import { fallbackDecision, fallbackConfig, fallbackSpend, estimateCost, PRICES, FALLBACK_ENV, DEFAULT_FALLBACK } from "../../scripts/lib/usage.mjs";
import { workerEnv, ledgerLine, planLevelFor } from "../../scripts/run-job.mjs";
import { fallbackProblems, THRESHOLD } from "../../scripts/pipecheck.mjs";
import { apiFallbackReport } from "../../scripts/efficiency.mjs";
import { fallbackStatus, fallbackLine } from "../../scripts/budget.mjs";

const NOW = Date.parse("2026-11-23T12:00:00Z"), iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z"), m = (min) => iso(NOW - min * 6e4);
const SECRET = "sk-ant-SECRET-DO-NOT-LEAK-0001";
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
  assert.equal(real.enabled, true); assert.equal(real.monthly_usd_cap, 150); assert.ok(typeof real._note === "string" && real._note.includes("CYBERVIEW_FALLBACK_ANTHROPIC_API_KEY"));
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
