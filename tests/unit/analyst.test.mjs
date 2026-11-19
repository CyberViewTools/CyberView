// The exploit analyst's queue and the analyst swarm agree on what is done: only an analysis that passes checkAnalysis().
// Run: node --test tests/unit/
import test from "node:test";
import assert from "node:assert/strict";
import { queue, splitAnalyses } from "../../scripts/analyst.mjs";
import { analystDone, planBatches, reconcile } from "../../scripts/swarm.mjs";

const d = (n) => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);
const today = d(0);
const analysis = (cve) => ({ id: cve, cve, analyzed_at: new Date().toISOString().slice(0, 19) + "Z", model: "claude-opus-5-5", exploitation_status: "Exploited in the wild per CISA.",
  how_exploited: "An unauthenticated attacker sends a crafted request to the management interface and runs code as the service account.",
  preconditions: ["Management interface reachable"], attack_path: ["Find an exposed interface", "Run code"], exposure: "internet", who_is_exposed: [], detect: ["Unexpected child processes"],
  remediation: { priority: "immediate", steps: ["Apply the fix"], fixed_versions: ["9.1.2"], workarounds: [], verify: ["Version shows 9.1.2"], if_compromised: [] }, confidence: "high", caveats: "",
  sources: [{ name: "Vendor advisory", url: "https://vendor.example/sa/1", kind: "vendor", read_depth: "full" }, { name: "Write-up", url: "https://lab.example/blog/x", kind: "research", read_depth: "full" }] });
// rows as scripts/lib/store.mjs listDir("analyses") returns them: { id from the file name, r: { id, ...file } }
const row = (cve, edit = (x) => x) => ({ id: cve, path: `/data/analyses/${cve}.json`, r: edit(analysis(cve)) });
const rows = [
  row("CVE-2026-0001"),
  row("CVE-2026-0002", (x) => ({ ...x, exploitation_status: "x".repeat(275) })),                   // too long: what the swarm workers wrote
  row("CVE-2026-0003", (x) => ({ ...x, remediation: { ...x.remediation, fixed_versions: ["y".repeat(170)] } })),
  { id: "CVE-2026-0004", path: "/data/analyses/CVE-2026-0004.json", r: null, error: "Unexpected token" },
  row("CVE-2026-105432"),                                                                            // 6-digit sequence numbers are valid ids
];

test("splitAnalyses: only records that pass checkAnalysis are done; the others carry their problems", () => {
  const { done, bad } = splitAnalyses(rows);
  assert.deepEqual(Object.keys(done).sort(), ["CVE-2026-0001", "CVE-2026-105432"]);
  assert.deepEqual(Object.keys(bad).sort(), ["CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"]);
  assert.match(bad["CVE-2026-0002"][0], /exploitation_status/);
  assert.match(bad["CVE-2026-0004"][0], /not valid JSON/);
});

test("analyst queue leaves out a valid analysis and hands an invalid one back with fix, never as new work", () => {
  const kev = ["0001", "0002", "0003", "0004", "105432", "0009"].map((n, i) => ({ cve: `CVE-2026-${n}`, added: d(-2 - i), due: d(10) }));
  const { done, bad } = splitAnalyses(rows), q = queue(kev, [], done, today, bad);
  const ids = q.map((x) => x.cve);
  assert.ok(!ids.includes("CVE-2026-0001") && !ids.includes("CVE-2026-105432"), "valid analyses leave the queue");
  for (const c of ["CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"]) assert.ok(q.find((x) => x.cve === c).fix.length, `${c} comes back to be fixed`);
  assert.equal(q.find((x) => x.cve === "CVE-2026-0009").fix, undefined, "a flaw with no file is plain new work");
});

test("analyst queue: an old catalog entry named by a severe event is still queued, marked known exploited", () => {
  const kev = [{ cve: "CVE-2026-84869", added: d(-70), due: d(-67) }];
  const q = queue(kev, [{ cve: "CVE-2026-84869", vendor: "ConnectWise", product: "ScreenConnect", rank: 50 }], {}, today);
  assert.deepEqual(q.map((x) => [x.cve, x.kev]), [["CVE-2026-84869", true]]);
  assert.deepEqual(queue([{ cve: "CVE-2026-84869", added: d(-3), due: d(5) }], [{ cve: "CVE-2026-84869", rank: 50 }], {}, today).length, 1, "a recent entry is queued once, not twice");
});

test("swarm validate/retry: a valid analysis is done, so retry never hands it out again", () => {
  const { isDone, bad } = analystDone(rows, [{ skipped: [{ cve: "CVE-2026-0007", why: "no advisory" }, "CVE-2026-0008: no page readable"] }]);
  const plan = planBatches(["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-105432", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009"].map((id) => ({ id })), 3);
  const r = reconcile(plan, isDone);
  assert.deepEqual(r.rows.map((x) => x.missing), [["CVE-2026-0002"], ["CVE-2026-0009"]]);
  assert.ok(bad["CVE-2026-0002"], "the missing item with a file is reported as needing a fix");
  assert.equal(bad["CVE-2026-0009"], undefined);
});
