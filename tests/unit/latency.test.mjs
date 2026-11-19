import { test } from "node:test";
import assert from "node:assert/strict";
import { latency } from "../../scripts/lib/latency.mjs";

test("minutes from the first lead to publish and to review", () => {
  const seen = new Map([["https://a/1", "2026-11-19T10:00:00Z"], ["https://a/2", "2026-11-19T09:50:00Z"]]);
  const ev = [
    { first_seen: "2026-11-19T10:12:00Z", sources: [{ url: "https://a/1" }, { url: "https://a/2" }], review: { at: "2026-11-19T10:20:00Z" } },
    { first_seen: "2026-11-19T08:00:00Z", sources: [{ url: "https://a/1" }] },
  ];
  const r = latency(seen, ev, "2026-11-19T00:00:00Z");
  assert.equal(r.n, 1); assert.equal(r.publish.p50, 22); assert.equal(r.review.p50, 30);
});
