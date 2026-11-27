// The Library bills only the API key, within its own monthly cap (config/pipeline.json library.api; owner, 2026-11-26)
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { libraryDecision, librarySpend, libraryApiConfig, fallbackSpend, DEFAULT_LIBRARY_API } from "../../scripts/lib/usage.mjs";
import { libraryMinutes } from "../../scripts/run-job.mjs";
import { chunkFor, deskConfig } from "../../scripts/library-desk.mjs";

const now = Date.parse("2026-11-26T18:00:00Z");
const line = (o) => ({ at: "2026-11-26T17:00:00Z", job: "library", served: "api", model: "sonnet", in: 0, out: 0, ...o });

test("libraryDecision: api only with a key, switched on, under the cap and not limited; never the subscription", () => {
  assert.equal(libraryDecision({ keyPresent: true, monthSpendUsd: 10, cap: 75 }), "api");
  assert.equal(libraryDecision({ keyPresent: false, monthSpendUsd: 0, cap: 75 }), "park");
  assert.equal(libraryDecision({ keyPresent: true, enabled: false }), "park");
  assert.equal(libraryDecision({ keyPresent: true, monthSpendUsd: 75, cap: 75 }), "park");
  assert.equal(libraryDecision({ keyPresent: true, monthSpendUsd: 80, cap: 75 }), "park");
  assert.equal(libraryDecision({ keyPresent: true, keyLimited: true }), "park");
  for (const o of [{}, { keyPresent: true }, { keyPresent: true, monthSpendUsd: 1e9 }]) assert.notEqual(libraryDecision(o), "subscription");
});

test("librarySpend counts only this month's Library API lines, the CLI's cost first; fallbackSpend leaves them out", () => {
  const lines = [
    line({ cost: 1.5 }),
    line({ cost: null, model: "haiku", in: 1e6, out: 0 }),          // no CLI cost: the PRICES estimate
    line({ at: "2026-10-31T23:00:00Z", cost: 50 }),                  // last month
    line({ job: "sweep", cost: 9 }),                                 // another job
    line({ served: "subscription", cost: 9 }),                       // not billed to the key
    { at: "2026-11-26T17:00:00Z", job: "sweep", served: "api-fallback", model: "sonnet", in: 1e6, out: 0 },
  ];
  const s = librarySpend(lines, now);
  assert.equal(s.workers, 2); assert.ok(s.usd > 1.5 && s.usd < 1.8, String(s.usd));
  const f = fallbackSpend(lines, now);
  assert.equal(f.workers, 2, "the pipeline's fallback cap counts the sweep lines only");
});

test("libraryApiConfig and the shipped config: $75 a month, switched on", () => {
  assert.deepEqual(libraryApiConfig({}), DEFAULT_LIBRARY_API);
  assert.equal(libraryApiConfig({ api: { monthly_usd_cap: "x" } }).monthly_usd_cap, 75);
  assert.equal(libraryApiConfig({ api: { monthly_usd_cap: 0 } }).monthly_usd_cap, 0);
  const lib = JSON.parse(readFileSync(new URL("../../config/pipeline.json", import.meta.url), "utf8")).library;
  const nov = Date.parse("2026-11-27T22:00:00Z"), dec = Date.parse("2026-12-01T00:00:00Z");
  assert.deepEqual(libraryApiConfig(lib, nov), { enabled: true, monthly_usd_cap: 88 }, "owner, 2026-11-27: $15 more for November (88 leaves room for calls in flight)");
  assert.deepEqual(libraryApiConfig(lib, dec), { enabled: true, monthly_usd_cap: 75 }, "December is back on the monthly $75");
  assert.equal(lib.backfill, true);
});

test("libraryApiConfig: a month_caps entry replaces the cap for that UTC month only; a bad entry is ignored", () => {
  const lib = { api: { monthly_usd_cap: 75, month_caps: { "2026-11": 88, "2026-12": "x", "2027-01": -5 } } };
  assert.equal(libraryApiConfig(lib, Date.parse("2026-11-30T23:59:59Z")).monthly_usd_cap, 88);
  assert.equal(libraryApiConfig(lib, Date.parse("2026-12-15T00:00:00Z")).monthly_usd_cap, 75);
  assert.equal(libraryApiConfig(lib, Date.parse("2027-01-15T00:00:00Z")).monthly_usd_cap, 75);
  assert.equal(libraryApiConfig(lib, Date.parse("2026-10-15T00:00:00Z")).monthly_usd_cap, 75);
  assert.equal(libraryApiConfig({ api: { month_caps: { "2026-11": 0 } } }, Date.parse("2026-11-02T00:00:00Z")).monthly_usd_cap, 0, "0 parks the month");
});

test("libraryMinutes: run_minutes only on a GitHub Actions runner, bounded; the launcher keeps its 10-minute cap", () => {
  const pipe = { headless_foreground_minutes: 8, library: { run_minutes: 18 } };
  assert.equal(libraryMinutes(pipe, { GITHUB_ACTIONS: "true" }), 18);
  assert.equal(libraryMinutes(pipe, {}), 8);
  assert.equal(libraryMinutes({ ...pipe, library: { run_minutes: 90 } }, { GITHUB_ACTIONS: "true" }), 22);
  assert.equal(libraryMinutes({ headless_foreground_minutes: 8 }, { GITHUB_ACTIONS: "true" }), 8);
});

test("chunkFor: library.concurrency over the defaults, whole numbers 1 to 10 only; the shipped config is read", () => {
  assert.deepEqual(chunkFor(null), { review: 2, audit: 2, write: 3, read: 4 });
  assert.deepEqual(chunkFor({ read: 8, audit: 0, write: 11, review: 2.5 }), { review: 2, audit: 2, write: 3, read: 8 });
  assert.deepEqual(deskConfig().concurrency, { review: 4, audit: 6, write: 4, read: 8 });
});
