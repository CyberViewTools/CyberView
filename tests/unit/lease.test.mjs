import { test } from "node:test";
import assert from "node:assert/strict";
import { heldBy, withClaims } from "../../scripts/lib/lease.mjs";

const now = Date.parse("2026-11-19T10:00:00Z");
test("a live lease of another run holds the item", () => {
  const l = { "story:a": { run: "r1", until: "2026-11-19T10:30:00Z" }, "story:b": { run: "r1", until: "2026-11-19T09:00:00Z" } };
  assert.deepEqual([...heldBy(l, "story", ["a", "b", "c"], "r2", now)], ["a"]);
  assert.equal(heldBy(l, "story", ["a"], "r1", now).size, 0, "own lease does not block");
  assert.equal(heldBy(l, "event", ["a"], "r2", now).size, 0, "kinds are separate");
});
test("claiming drops expired leases and sets the expiry", () => {
  const out = withClaims({ "story:old": { run: "x", until: "2026-11-19T09:00:00Z" } }, "cve", ["CVE-1"], "r", 45, now);
  assert.deepEqual(out, { "cve:CVE-1": { run: "r", until: "2026-11-19T10:45:00Z" } });
});
