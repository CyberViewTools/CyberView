// Every site script parses. A syntax error in sw.js (2026-11-24) did not fail a unit test: the service worker simply
// never installed and the browser suite hung on navigator.serviceWorker.ready until CI's 15-minute limit.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

test("every site/*.js parses (node --check)", () => {
  const dir = join(import.meta.dirname, "..", "..", "site");
  const bad = readdirSync(dir).filter((f) => f.endsWith(".js"))
    .map((f) => [f, spawnSync(process.execPath, ["--check", join(dir, f)], { encoding: "utf8" })])
    .filter(([, r]) => r.status !== 0).map(([f, r]) => `${f}: ${String(r.stderr).split("\n").find((l) => /Error/.test(l)) || "syntax error"}`);
  assert.deepEqual(bad, []);
});
