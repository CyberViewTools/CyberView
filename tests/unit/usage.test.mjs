// Plan usage from the workers' ledger (scripts/lib/usage.mjs): windows, levels, real limit hits and their reset times.
import { test } from "node:test";
import assert from "node:assert/strict";
import { windowUsage, weekUsage, budgetState, limitHits, resetFrom, peakUsage, sumUsage } from "../../scripts/lib/usage.mjs";

const NOW = Date.parse("2026-11-20T12:00:00Z");
const at = (h) => new Date(NOW - h * 36e5).toISOString().replace(/\.\d+Z$/, "Z");
const line = (h, o = {}) => ({ at: at(h), job: "sweep", role: "researcher", ok: true, cost: 0.25, in: 10, out: 1000, cache_read: 9000, cache_write: 990, error: null, last: "", ...o });
const CFG = { window_hours: 5, window_tokens: 100000, week_tokens: 1000000, window_cost: 0, week_cost: 0, tight_pct: 80, stop_pct: 120, limit_backoff_minutes: 60 };

test("windowUsage sums the last 5 hours only, with every token part and the total", () => {
  const L = [line(1), line(4.9), line(5.1), line(30)];
  const w = windowUsage(NOW, 5, L);
  assert.equal(w.runs, 2);
  assert.equal(w.tokens, 2 * 11000); assert.equal(w.in, 20); assert.equal(w.out, 2000); assert.equal(w.cache_read, 18000); assert.equal(w.cache_write, 1980);
  assert.equal(w.cost, 0.5); assert.equal(w.to, "2026-11-20T12:00:00Z"); assert.equal(w.from, "2026-11-20T07:00:00Z");
  assert.equal(weekUsage(NOW, L).runs, 4);
  assert.equal(weekUsage(NOW, [line(24 * 7 + 1)]).runs, 0, "older than a week is out");
});

test("levels: ok under tight_pct, tight from 80% of either window, stop from 120% of the 5-hour window", () => {
  assert.equal(budgetState(NOW, CFG, [line(1)]).level, "ok");
  const tight = budgetState(NOW, CFG, Array.from({ length: 8 }, () => line(1)));       // 88,000 of 100,000
  assert.equal(tight.level, "tight"); assert.equal(tight.window_pct, 88);
  assert.equal(budgetState(NOW, CFG, Array.from({ length: 12 }, () => line(1))).level, "stop");
  // the weekly estimate alone never stops the loop: a stop would idle research for days on a guess
  const week = budgetState(NOW, CFG, Array.from({ length: 100 }, (_, i) => line(10 + i)));
  assert.equal(week.level, "tight"); assert.ok(week.week_pct >= 100);
  // cost estimates count too: the larger share wins
  assert.equal(budgetState(NOW, { ...CFG, window_tokens: 0, window_cost: 1 }, Array.from({ length: 4 }, () => line(1))).level, "tight");
  // no estimate at all: only real limit hits matter
  assert.equal(budgetState(NOW, { window_tokens: 0, week_tokens: 0 }, Array.from({ length: 500 }, () => line(1))).level, "ok");
});

test("a worker that failed on the plan's limit stops the loop until the reset time it gives", () => {
  const reset = Math.floor(Date.parse("2026-11-20T14:00:00Z") / 1000);
  const b = budgetState(NOW, CFG, [line(0.5, { ok: false, error: `Claude AI usage limit reached|${reset}` })]);
  assert.equal(b.level, "stop"); assert.equal(b.limited_until, "2026-11-20T14:00:00Z");
  // after the reset it is tight for the rest of that window (recovering), then ok
  assert.equal(budgetState(Date.parse("2026-11-20T14:30:00Z"), CFG, [line(0.5, { ok: false, error: `Claude AI usage limit reached|${reset}` })]).level, "tight");
  assert.equal(budgetState(Date.parse("2026-11-20T23:00:00Z"), CFG, [line(0.5, { ok: false, error: `Claude AI usage limit reached|${reset}` })]).level, "ok");
});

test("a limit error without a reset time stops for limit_backoff_minutes", () => {
  const b = budgetState(NOW, CFG, [line(0.25, { ok: false, error: "API Error: 429 rate_limit_error" })]);
  assert.equal(b.level, "stop"); assert.equal(b.limited_until, "2026-11-20T12:45:00Z");
  assert.equal(budgetState(NOW, CFG, [line(1.5, { ok: false, error: "Too Many Requests" })]).level, "tight", "60 minutes later: recovering");
});

test("only FAILED workers count: a researcher whose last line mentions a site's 429 never stops the loop", () => {
  assert.equal(limitHits([line(0.1, { ok: true, last: "the site returned 429 Too Many Requests; rate limit", error: null })]).length, 0);
  assert.equal(limitHits([line(0.1, { ok: false, error: "timeout" })]).length, 0);
  assert.equal(limitHits([line(0.1, { ok: false, error: "API Error: 529 overloaded_error" })]).length, 0, "overloaded is not a limit");
  for (const e of ["You've hit your limit · resets 3pm (UTC)", "5-hour limit reached ∙ resets 5am", "Claude usage limit reached. Your limit will reset at 7pm", "rate_limit_error", "weekly limit reached"])
    assert.equal(limitHits([line(0.1, { ok: false, error: e })]).length, 1, e);
});

test("reset times: unix seconds, ISO, a clock time (next after the hit), a weekday, a named zone", () => {
  const hit = Date.parse("2026-11-20T11:40:00Z");                                       // a Friday
  assert.equal(resetFrom("limit reached|1763650800", hit), 1763650800000);
  assert.equal(resetFrom("resets at 2026-11-20T15:00:00Z", hit), Date.parse("2026-11-20T15:00:00Z"));
  assert.equal(new Date(resetFrom("resets 3pm (UTC)", hit)).toISOString(), "2026-11-20T15:00:00.000Z");
  assert.equal(new Date(resetFrom("resets 11am", hit)).toISOString(), "2026-11-21T11:00:00.000Z", "a clock time already past is tomorrow's");
  assert.equal(new Date(resetFrom("resets at 3:30 pm", hit)).toISOString(), "2026-11-20T15:30:00.000Z");
  assert.equal(new Date(resetFrom("resets Mon 9am (UTC)", hit)).toISOString(), "2026-11-23T09:00:00.000Z");
  assert.equal(new Date(resetFrom("resets 3pm (America/New_York)", hit)).toISOString(), "2026-11-20T20:00:00.000Z");
  assert.equal(resetFrom("usage limit reached", hit), null);
  assert.equal(resetFrom("resets 3pm (Not/AZone)", hit), null);
});

test("an absurd reset time falls back to the backoff", () => {
  const h = limitHits([line(0.1, { ok: false, error: "usage limit reached|4102444800" })], 60);   // year 2100
  assert.equal(h[0].until - h[0].at, 60 * 6e4);
});

test("peakUsage finds the busiest rolling span", () => {
  const L = [line(10), line(9), line(8.5), line(2)];
  const p = peakUsage(L, 5);
  assert.equal(p.tokens, 3 * 11000); assert.equal(p.cost, 0.75); assert.equal(p.at, at(8.5));
  assert.equal(sumUsage([], 0, 1).tokens, 0);
});
