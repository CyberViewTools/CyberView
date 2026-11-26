// New event files with an invalid name are renamed before the build (finish.mjs); committed ones are never touched
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { validId, fixNewEventNames, ID_RE } from "../../scripts/lib/event-names.mjs";

test("validId: lowercase letters, digits and hyphens, or null", () => {
  assert.equal(validId("gh0strat-oCam-lure-silver-fox-watchguard-2026-11"), "gh0strat-ocam-lure-silver-fox-watchguard-2026-11");
  assert.equal(validId("Équipe  Hack_Attack!! 2026"), "equipe-hack-attack-2026");
  assert.equal(validId("--a--"), null, "too short once trimmed");
  assert.equal(validId(""), null);
  assert.ok(ID_RE.test(validId("x".repeat(300))));
  assert.ok(!/-$/.test(validId("a".repeat(119) + "-b")));
});

test("fixNewEventNames renames bad new files, never overwrites, skips good names and non-events", () => {
  const root = mkdtempSync(join(tmpdir(), "names-"));
  try {
    mkdirSync(join(root, "events", "2026-11"), { recursive: true });
    for (const f of ["Bad-Name-2026-11.json", "good-name-2026-11.json", "Taken-2026-11.json", "taken-2026-11.json"]) writeFileSync(join(root, "events", "2026-11", f), "{}");
    const r = fixNewEventNames(root, ["events/2026-11/Bad-Name-2026-11.json", "events/2026-11/good-name-2026-11.json", "events/2026-11/Taken-2026-11.json", "leads/X.json"]);
    assert.deepEqual(r, [{ from: "events/2026-11/Bad-Name-2026-11.json", to: "events/2026-11/bad-name-2026-11.json" }, { from: "events/2026-11/Taken-2026-11.json", to: null }]);
    assert.ok(existsSync(join(root, "events", "2026-11", "bad-name-2026-11.json")));
    assert.ok(existsSync(join(root, "events", "2026-11", "Taken-2026-11.json")), "a clash is left for the build to report");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
