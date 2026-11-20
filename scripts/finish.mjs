// Mechanical end of a job, no AI model. Run: node scripts/finish.mjs <job> [--force]
// The dispatcher runs this after the workers have finished, so committing never depends on an agent remembering to:
//   1. timestamp in data/status.json (the job's status_key from routines.json)
//   2. node scripts/build.mjs (strict). If a record is broken it prints the errors and exits 1 WITHOUT committing, so the
//      dispatcher can have them fixed. With --force it commits anyway: the deploy quarantines a broken record and reports it,
//      which is better than holding back everyone else's good work.
//   3. git add data config docs, commit ("data: <job>, N new, M updated"), pull --rebase, push (three tries)
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { ROOT, DATA, readJson, writeJson, nowIso, readStatus } from "./lib/store.mjs";
import { heal, marked } from "./lib/conflicts.mjs";
import { dataMode } from "./lib/repo.mjs";
// code and data on separate branches (scripts/lib/repo.mjs): data is committed to the data branch at ./data; anything a
// job changed outside data/ (config/, docs/) is proposed to main as a pull request (scripts/propose.mjs), never pushed
const BRANCH = dataMode(ROOT) === "branch", DDIR = BRANCH ? join(ROOT, "data") : ROOT;

const job = process.argv[2], force = process.argv.includes("--force");
if (!job || !/^[a-z-]+$/.test(job)) { console.error("usage: finish.mjs <job> [--force]"); process.exit(1); }
const run = (cmd, args) => spawnSync(cmd, args, { cwd: ROOT, encoding: "utf8", timeout: 300000 });
const git = (...a) => run("git", a);
const dgit = (...a) => spawnSync("git", a, { cwd: DDIR, encoding: "utf8", timeout: 300000 });

const reg = readJson(join(ROOT, "routines.json"), { routines: [] }), r = reg.routines.find((x) => x.key === job);
const st = readStatus(), key = (r && r.status_key) || `last_${job.replace(/-/g, "_")}_at`;
const porcelain = dgit("status", "--porcelain", BRANCH ? "events" : "data/events").stdout.split("\n").filter(Boolean);
const added = porcelain.filter((l) => l.startsWith("??") || l.startsWith("A ")).length, updated = porcelain.filter((l) => /^ ?M/.test(l)).length;
st[key] = nowIso();
if (job === "sweep") { st.last_sweep_added = added; st.last_sweep_updated = updated; }
writeJson(join(DATA, "status.json"), st);

const b = run("node", ["scripts/build.mjs"]);
if (b.status !== 0) {
  const errs = `${b.stdout}${b.stderr}`.split("\n").filter((l) => /^error:/.test(l)).slice(0, 20);
  console.log(`BUILD FAILED (${errs.length} error(s)):`); errs.forEach((e) => console.log("  " + e));
  if (!force) { console.log("Nothing was committed. Have these fixed, then run finish again (add --force if they cannot be fixed)."); process.exit(1); }
  console.log("Committing anyway (--force): the deploy leaves broken records out and reports them.");
}
heal(DDIR);                                                                   // a pull --autostash may have left conflict markers
let proposed = "";
if (BRANCH) {
  // config/ and docs/ changes made by the job go to main as a pull request, then are put back here until it merges
  if (git("status", "--porcelain", "--", "config", "docs").stdout.trim()) {
    const pr = run("node", ["scripts/propose.mjs", job]);
    proposed = (pr.stdout || "").trim().split("\n").pop() || "";
    if (pr.status === 0) git("checkout", "--", "config", "docs");
  }
  dgit("add", "-A", ".");
} else git("add", "-A", "data", "config", "docs");
{ const bad = marked(DDIR); if (bad.length) { dgit("reset", "-q", "--", ...bad); console.log(`NOT COMMITTED (conflict markers): ${bad.join(", ")}`); } }
if (dgit("diff", "--cached", "--quiet").status === 0) { console.log(`CyberView ${job}: nothing to commit${proposed ? "; " + proposed : ""}`); process.exit(0); }
const msg = `data: ${job}, ${added} new, ${updated} updated`;
const c = dgit("commit", "-q", "-m", msg);
if (c.status !== 0) { console.log(`COMMIT FAILED: ${(c.stderr || c.stdout).trim().split("\n")[0]}`); process.exit(1); }
// git-sync merges the files every job writes (status.json, leads) instead of failing on them, and asks for a deploy
const sy = run("node", ["scripts/git-sync.mjs"]), pushed = sy.status === 0, why = `${sy.stderr || ""}`.trim().split("\n").pop();
console.log(pushed ? `CyberView ${job}: ${added} new, ${updated} updated; committed and pushed${proposed ? "; " + proposed : ""}` : `PUSH FAILED after 3 tries (${why}). The commit is local; the next job will push it.`);
process.exit(pushed ? 0 : 1);
