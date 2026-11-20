import { test } from "node:test";
import assert from "node:assert/strict";
import { checkItems, flagsFor } from "../../scripts/grid-audit.mjs";

const C = { US: ["United States", 39.8, -98.6], GB: ["United Kingdom", 54, -2.5] };
const base = { source: "x", country: "US", kind: "outage", planned: false, customers: 10, url: "https://op.example/a" };
const def = { hosts: ["op.example"] };

test("audit: item checks catch far-away points, future and old starts, duplicates, off-host links", () => {
  const now = Date.parse("2026-11-20T00:00:00Z");
  const r = checkItems([
    { ...base, id: "x:1", lat: 34, lng: -118, started_at: "2026-11-19T20:00:00Z" },          // Los Angeles: fine
    { ...base, id: "x:2", lat: 51.5, lng: -0.1, started_at: "2026-11-19T20:00:00Z" },        // London tagged US: far
    { ...base, id: "x:3", lat: 34, lng: -118, started_at: "2026-11-21T00:00:00Z" },          // a day ahead
    { ...base, id: "x:4", lat: 34, lng: -118, started_at: "2026-08-01T00:00:00Z" },          // months old, unplanned
    { ...base, id: "x:4", lat: null, lng: null, customers: null, url: "https://evil.test/" }, // dup id, no location, no count, off host
  ], def, C, now);
  assert.deepEqual([r.items, r.far_from_country, r.future_start, r.old_start, r.dup_ids, r.no_location, r.no_customers, r.off_host_links], [5, 1, 1, 1, 1, 1, 1, 1]);
  assert.ok(r.examples.length >= 4);
});

test("audit: flags from state and history", () => {
  const now = Date.parse("2026-11-20T00:00:00Z"), ok = { ok: true }, chk = (n) => ({ items: n, far_from_country: 0, future_start: 0, dup_ids: 0, off_host_links: 0 });
  const hist = Array.from({ length: 24 }, () => ({ n: 20 }));
  assert.deepEqual(flagsFor("x", { paused: true }, chk(0), hist, now), ["paused"]);
  assert.deepEqual(flagsFor("x", { ok: false, error: "not connected (no key saved for h)" }, chk(0), hist, now), ["not_connected"]);
  assert.deepEqual(flagsFor("x", { ok: false, error: "http_500", fetched_at: "2026-11-18T00:00:00Z" }, chk(0), hist, now), ["failing_over_24h"]);
  assert.deepEqual(flagsFor("x", ok, chk(0), hist, now), ["suddenly_empty"]);
  assert.deepEqual(flagsFor("x", ok, chk(500), hist, now), ["surge"]);
  assert.deepEqual(flagsFor("x", ok, chk(18), hist, now), []);
  assert.deepEqual(flagsFor("x", ok, chk(0), hist.slice(0, 5), now), [], "too little history to judge");
});
