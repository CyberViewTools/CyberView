// The guard's data-branch checks (scripts/guard.mjs assess): data deploy lag, old deploys without data_commit, the
// forwarder during the switch. Fixtures only, no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { assess, LIMITS } from "../../scripts/guard.mjs";

const NOW = Date.parse("2026-11-20T12:00:00Z"), ago = (m) => new Date(NOW - m * 6e4).toISOString();
const ev = { id: "a-b-c", title: "T", date: "2026-11-20", category: "incident", severity: 2 };
const lease = { "flow:leader": { run: "r", until: new Date(NOW + 10 * 6e4).toISOString() } };
const MAIN = "a".repeat(40), DATA = "d".repeat(40);
const live = (o = {}) => ({ manifest: { built_at: ago(10), commit: MAIN, data_commit: DATA }, health: { last_sweep_at: ago(10), last_collect_at: ago(20), last_feeds_at: ago(60), quarantined_count: 0 },
  bundle: { events: new Array(50).fill(ev) }, head: { sha: MAIN, date: ago(60) }, deploy: { conclusion: "success" }, leases: lease, dataHead: { sha: DATA, date: ago(12) }, ...o });

test("data branch: healthy when both the code and the data commit are live", () => {
  assert.deepEqual(assess(live(), NOW), { fails: [], warns: [], heal: [] });
});
test("data branch: data not deployed within the limit fails and asks for a deploy; a fresh push is still deploying", () => {
  const r = assess(live({ dataHead: { sha: "e".repeat(40), date: ago(LIMITS.deploy_lag_min + 15) } }), NOW);
  assert.ok(r.fails.some((f) => /data branch is at eeeeeee/.test(f) && /live site has data ddddddd/.test(f)), r.fails); assert.deepEqual(r.heal, ["deploy"]);
  assert.deepEqual(assess(live({ dataHead: { sha: "e".repeat(40), date: ago(5) } }), NOW).fails, []);
});
test("data branch: code lag is judged on its own, with the same limit", () => {
  const r = assess(live({ head: { sha: "b".repeat(40), date: ago(45) } }), NOW);
  assert.ok(r.fails.some((f) => /main is at bbbbbbb/.test(f))); assert.ok(!r.fails.some((f) => /data branch/.test(f))); assert.ok(r.heal.includes("deploy"));
});
test("data branch: commits that need no deploy (leases, usage) are not lag; anything else among them is", () => {
  const behind = { dataHead: { sha: "e".repeat(40), date: ago(60) } };
  assert.deepEqual(assess(live({ ...behind, dataLagFiles: ["leases.json", "usage/2026-11.jsonl"] }), NOW).fails, []);
  assert.equal(assess(live({ ...behind, dataLagFiles: ["leases.json", "events/2026-11/x.json"] }), NOW).fails.length, 1);
  assert.equal(assess(live({ ...behind, dataLagFiles: [] }), NOW).fails.length, 1, "an empty or unknown file list is not proof of a no-deploy commit");
  assert.equal(assess(live(behind), NOW).fails.length, 1);
});
test("data branch: an old deploy without data_commit is a warning, not a failure", () => {
  const r = assess(live({ manifest: { built_at: ago(10), commit: MAIN }, dataHead: { sha: "e".repeat(40), date: ago(90) } }), NOW);
  assert.deepEqual(r.fails, []); assert.ok(r.warns.some((w) => /does not record which data commit/.test(w)));
});
test("before the data branch exists: only main is judged, as before", () => {
  const r = assess(live({ manifest: { built_at: ago(10), commit: MAIN }, dataHead: null, forward: { mark: { sha: MAIN, date: ago(500) }, main: [{ sha: "c".repeat(40), date: ago(100) }] } }), NOW);
  assert.deepEqual(r, { fails: [], warns: [], heal: [] });
});
test("forwarder: data pushed to main and not forwarded for over 30 minutes is a warning with a forward heal", () => {
  const mark = { sha: MAIN, date: ago(120) };
  const late = assess(live({ forward: { mark, main: [{ sha: "c".repeat(40), date: ago(10) }, { sha: "f".repeat(40), date: ago(LIMITS.forward_min + 5) }, { sha: MAIN, date: ago(120) }] } }), NOW);
  assert.deepEqual(late.fails, []); assert.ok(late.warns.some((w) => /data is still being pushed to main; the forwarder is not keeping up/.test(w) && /2 data commit/.test(w)), late.warns); assert.deepEqual(late.heal, ["forward"]);
  // only recent pushes waiting: the forwarder has time yet
  assert.deepEqual(assess(live({ forward: { mark, main: [{ sha: "c".repeat(40), date: ago(10) }] } }), NOW).warns, []);
  // everything on main is at or before the mark: forwarded
  assert.deepEqual(assess(live({ forward: { mark: { sha: "c".repeat(40), date: ago(5) }, main: [{ sha: "c".repeat(40), date: ago(5) }, { sha: "f".repeat(40), date: ago(90) }] } }), NOW).warns, []);
  // no mark read (network, or no forwarding set up): nothing is claimed
  assert.deepEqual(assess(live({ forward: { mark: null, main: [{ sha: "f".repeat(40), date: ago(90) }] } }), NOW).warns, []);
  assert.equal(LIMITS.forward_min, 30);
});
test("leases and the forward mark are read from the data branch once it exists, else from main's data/", async () => {
  const { rawDataUrl, HEAL } = await import("../../scripts/guard.mjs");
  assert.equal(rawDataUrl("o/r", true, "leases.json"), "https://raw.githubusercontent.com/o/r/data/leases.json");
  assert.equal(rawDataUrl("o/r", false, "leases.json"), "https://raw.githubusercontent.com/o/r/main/data/leases.json");
  assert.equal(HEAL.deploy, "pages.yml"); assert.equal(HEAL.forward, "data-forward.yml");
});
