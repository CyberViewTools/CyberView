// The distributions' own fix records (Debian, Ubuntu) for the scanner's signed-in checks, from OSV's public exports. No AI model.
//   node scripts/distro.mjs <osv dir> <out dir>
// <osv dir> holds OSV's Debian/ and Ubuntu/ folders (all.zip unpacked: one JSON record per file). Writes <out dir>/index.json and
// one <distro>-<release>.json per release, the shape scanner/lib/distro.mjs reads: { src: { "<source package>": [["CVE-...", "<fixed
// build>" or ""], ...] } }. Kernel flavour packages (linux-*, except linux itself) are left out: a package list names the running
// kernel's build, not these, and they would make the files several times larger. Ubuntu Pro (ESM) records are left out.
import { readdirSync, readFileSync, writeFileSync, mkdirSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";
import { addOsv, releaseFiles } from "../scanner/lib/distro.mjs";

export const FILE_CAP = 40 * 1024 * 1024;
export function keepPackage(src) { return !/^linux-/.test(src); }
export function build(osvDir, outDir, { now = new Date().toISOString(), log = console.log } = {}) {
  const acc = {}; let records = 0, bad = 0;
  for (const d of ["Debian", "Ubuntu"]) {
    const dir = join(osvDir, d); if (!existsSync(dir)) { log(`no ${dir}: skipped`); continue; }
    for (const f of readdirSync(dir)) {
      if (!f.endsWith(".json")) continue;
      let rec; try { rec = JSON.parse(readFileSync(join(dir, f), "utf8")); } catch { bad++; continue; }
      records++; addOsv(acc, rec);
    }
  }
  for (const k of Object.keys(acc)) { if (/^ubuntu-pro-/.test(k)) { delete acc[k]; continue; } for (const p of Object.keys(acc[k])) if (!keepPackage(p)) delete acc[k][p]; if (!Object.keys(acc[k]).length) delete acc[k]; }
  const { index, files } = releaseFiles(acc, now);
  if (!Object.keys(files).length) throw new Error(`no release could be built from ${records} record(s)`);
  mkdirSync(outDir, { recursive: true });
  for (const [f, j] of Object.entries(files)) {
    const text = JSON.stringify(j);
    if (text.length > FILE_CAP) throw new Error(`${f} would be ${(text.length / 1048576).toFixed(1)} MB, over the ${FILE_CAP / 1048576} MB cap`);
    writeFileSync(join(outDir, f), text);
  }
  writeFileSync(join(outDir, "index.json"), JSON.stringify(index));
  const total = Object.keys(files).reduce((n, f) => n + statSync(join(outDir, f)).size, 0);
  log(`distro: ${records} OSV record(s) (${bad} unreadable) -> ${Object.keys(files).length} release file(s), ${(total / 1048576).toFixed(1)} MB: ` +
    Object.entries(index.releases).map(([k, r]) => `${k} ${r.packages} pkg/${r.entries}`).join(", "));
  return index;
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const [osvDir, outDir] = process.argv.slice(2);
  if (!osvDir || !outDir) { console.error("usage: node scripts/distro.mjs <osv dir> <out dir>"); process.exit(2); }
  try { build(osvDir, outDir); } catch (e) { console.error("distro: " + e.message); process.exit(1); }
}
