// Commit data/ paths and push them, in whichever layout this checkout uses (data branch at ./data, or the old data/
// inside main), then ask for a deploy. Used by the GitHub workflows; jobs use scripts/finish.mjs. No AI model.
// Run: node scripts/data-commit.mjs "<message>" data/leads data/status.json ...   (no paths = every change under data/)
import { commitData } from "./lib/repo.mjs";
const [msg, ...paths] = process.argv.slice(2);
if (!msg) { console.log('usage: data-commit.mjs "<message>" [data/paths...]'); process.exit(1); }
const r = commitData(msg, paths);
console.log(r.committed ? (r.pushed ? "data-commit: committed and pushed" : "data-commit: committed; the push failed (the next run pushes it)") : "data-commit: nothing to commit");
process.exit(r.pushed ? 0 : 1);
