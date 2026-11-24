// The public run list's times (scripts/lib/runlog.mjs): never a made-up, malformed or future time.
import { test } from "node:test";
import assert from "node:assert/strict";
import { runLogAt } from "../../scripts/lib/runlog.mjs";

const NOW = Date.parse("2026-11-23T23:00:00Z");
test("run-log time: the log's own time, else the HHMM file prefix, else left out", () => {
  assert.equal(runLogAt("2026-11-23", "sweep-r1.json", { finished_at: "2026-11-23T21:14:07Z" }, NOW), "2026-11-23T21:14:07Z");
  assert.equal(runLogAt("2026-11-23", "2105-sweep.json", {}, NOW), "2026-11-23T21:05:00Z");
  assert.equal(runLogAt("2026-11-23", "sweep-r1.json", {}, NOW), "", "was 2026-11-23Tsw:ee:00Z");
  assert.equal(runLogAt("2026-11-23", "update-u1.json", { started_at: "approx" }, NOW), "");
  assert.equal(runLogAt("2026-11-23", "x.json", { finished_at: "2026-11-24T00:00:00Z" }, NOW), "", "another day / the future");
  assert.equal(runLogAt("2026-11-23", "2359-late.json", {}, NOW), "", "after now");
  assert.equal(runLogAt("2026-11-23", "x.json", { at: "2026-11-23T10:00Z" }, NOW), "2026-11-23T10:00:00Z");
});
