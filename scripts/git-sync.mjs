// Push the commit just made, merging the files every job writes instead of failing on them. No AI model.
// Run after `git commit`: node scripts/git-sync.mjs
// Several jobs (lead collection, feeds, research, review) commit to main within minutes of each other, and they all touch
// data/status.json; a plain `pull --rebase` then stops on a conflict and the job fails, losing its run. Here:
//   - data/status.json and other JSON objects: a three-way merge by key (keys this commit changed win; every other key
//     comes from what is already on main), so two jobs' timestamps both survive
//   - data/leads/*.jsonl, data/runs-style line files: the union of both sides' lines
//   - any other conflict: the rebase is aborted and the script exits 1, so nothing is ever merged blindly
// Up to 5 attempts with backoff. Exit 0 = pushed.
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = process.cwd();
const git = (...a) => spawnSync("git", a, { cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
const show = (stage, f) => { const r = git("show", `:${stage}:${f}`); return r.status === 0 ? r.stdout : null; };
const sleep = (s) => spawnSync("sleep", [String(s)]);

/** Pure: three-way merge of two JSON objects by key. base = common ancestor, up = what is on main, mine = this commit. */
export function mergeJson(base, up, mine) {
  const out = { ...up };
  for (const k of new Set([...Object.keys(base || {}), ...Object.keys(mine || {})])) {
    const b = JSON.stringify((base || {})[k]), m = JSON.stringify((mine || {})[k]);
    if (b === m) continue;                                                         // this commit did not touch the key: main's value stands
    if (!(k in (mine || {}))) { delete out[k]; continue; }
    const u = (up || {})[k];
    out[k] = u && mine[k] && typeof u === "object" && typeof mine[k] === "object" && !Array.isArray(u) && !Array.isArray(mine[k]) ? mergeJson((base || {})[k], u, mine[k]) : mine[k];
  }
  return out;
}
/** Pure: union of two line files, main's order first, then lines only this commit has. */
export function mergeLines(up, mine) {
  const seen = new Set(), out = [];
  for (const l of `${up || ""}\n${mine || ""}`.split("\n")) if (l.trim() && !seen.has(l)) { seen.add(l); out.push(l); }
  return out.join("\n") + "\n";
}

function resolve() {
  const files = git("diff", "--name-only", "--diff-filter=U").stdout.split("\n").filter(Boolean);
  for (const f of files) {
    // during a rebase, stage 2 is main (the side being rebased onto) and stage 3 is this commit
    const base = show(1, f), up = show(2, f), mine = show(3, f);
    let merged = null;
    if (/\.jsonl$/.test(f)) merged = mergeLines(up, mine);
    else if (/\.json$/.test(f)) {
      try {
        const u = JSON.parse(up || "{}"), m = JSON.parse(mine || "{}"), b = base ? JSON.parse(base) : {};
        if ([u, m, b].every((x) => x && typeof x === "object" && !Array.isArray(x))) merged = JSON.stringify(mergeJson(b, u, m), null, 1) + "\n";
      } catch { merged = null; }
    }
    if (merged === null) { console.error(`git-sync: cannot merge ${f} automatically`); return false; }
    writeFileSync(join(ROOT, f), merged); git("add", f);
  }
  return true;
}

function main() {
  for (let i = 1, max = Number(process.env.GIT_SYNC_TRIES) || 5; i <= max; i++) {
    const p = git("pull", "--rebase", "-q", "origin", "main");
    if (p.status !== 0) {
      let ok = true;
      for (let n = 0; n < 50 && ok; n++) {                                         // one round per commit being replayed
        if (!git("diff", "--name-only", "--diff-filter=U").stdout.trim()) break;
        ok = resolve();
        if (ok) { const c = spawnSync("git", ["-c", "core.editor=true", "rebase", "--continue"], { cwd: ROOT, encoding: "utf8", env: { ...process.env, GIT_EDITOR: "true" } }); if (c.status === 0) break; }
      }
      if (!ok || git("status").stdout.includes("rebase in progress")) { git("rebase", "--abort"); console.error(`git-sync: attempt ${i}: ${(p.stderr || "").trim().split("\n")[0]}`); sleep(Number(process.env.GIT_SYNC_TRIES) ? 0 : i * 10); continue; }
    }
    const r = git("push", "-q", "origin", "HEAD:main");
    if (r.status === 0) { console.log(`git-sync: pushed (attempt ${i})`); process.exit(0); }
    console.error(`git-sync: push attempt ${i} failed: ${(r.stderr || "").trim().split("\n").pop()}`); sleep(i * 10);
  }
  console.error("git-sync: could not push after 5 attempts"); process.exit(1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
