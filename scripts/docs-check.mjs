// The documentation kept current with the code. No AI model.
// Documentation is part of every change (CLAUDE.md, "Rules for changing code"). This check fails, naming each gap, when
//   - a script (scripts/, scripts/lib/, scripts/grid-sources/), a config file (config/*.json) or a workflow
//     (.github/workflows/*.yml) is not described in docs/layout.md (named by path or file name, or under a glob line
//     such as `config/feeds.d/*.json`),
//   - an active routine in routines.json is not in docs/jobs.md (by key or name),
//   - a figure the docs, routines.json, the About text or the status page state ("about 5,900 feeds", "Reads 131 ...
//     feeds", "hundreds of feeds", "60 grid sources") is more than DRIFT off the live count.
// The About page (config/about.json) has its own check, scripts/about.mjs check. Both run in npm run ci and build.yml.
// Run: node scripts/docs-check.mjs
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = join(import.meta.dirname, "..");
export const DRIFT = 0.2;
export const SCANNED = [["scripts", ".mjs"], ["scripts/lib", ".mjs"], ["scripts/grid-sources", ".mjs"], ["config", ".json"], [".github/workflows", ".yml"]];
export const STATED_IN = ["README.md", "CLAUDE.md", "docs/layout.md", "docs/jobs.md", "routines.json", "config/about.json", "site/status.html"];

/** Files that must be described in docs/layout.md, as repository paths. */
export function codeFiles(root = ROOT) {
  const out = [];
  for (const [dir, ext] of SCANNED) {
    const d = join(root, dir);
    if (!existsSync(d)) continue;
    for (const f of readdirSync(d).sort()) if (f.endsWith(ext)) out.push(`${dir}/${f}`);
  }
  return out;
}

const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** True when the layout names the file: its full path, its file name standing alone, or a `dir/*.ext` glob over it. */
export function described(layout, path) {
  const standsAlone = (s) => new RegExp(`(^|[\\s/(\`,])${reEsc(s)}(?![\\w-])`, "m").test(layout);
  if (standsAlone(path)) return true;
  const slash = path.lastIndexOf("/"), dir = path.slice(0, slash), name = path.slice(slash + 1), ext = name.slice(name.lastIndexOf("."));
  if (layout.includes(`${dir}/*${ext}`)) return true;
  return standsAlone(name);
}

const num = (s) => Number(String(s).replace(/,/g, ""));
/** Figures the docs state about live counts: [{file, said, kind}]. */
export function statedFigures(file, text) {
  const out = [];
  for (const m of text.matchAll(/\b(?:about|[Rr]eads) ([\d,]{3,}) (?:RSS and Atom |agency, vendor and news )?feeds\b/g)) out.push({ file, said: num(m[1]), kind: "feeds" });
  // "hundreds of ... feeds" stands for a few hundred: compared as 500, so it fails once there are thousands.
  for (const m of text.matchAll(/\bhundreds of (?:[\w-]+,? ){0,6}feeds\b/g)) out.push({ file, said: 500, kind: "feeds" });
  for (const m of text.matchAll(/\b(\d{2,}) (?:public )?(?:grid sources|operator and agency feeds)\b/g)) out.push({ file, said: num(m[1]), kind: "grid" });
  return out;
}

/** Pure: every gap, as a sentence naming the file to fix. */
export function problems({ files, layout, jobs, routines, figures, live }) {
  const p = [];
  for (const f of files) if (!described(layout, f)) p.push(`docs/layout.md does not describe ${f}: add a line saying what it does`);
  for (const r of routines) {
    if (r.active === false) continue;
    if (!jobs.includes(r.key) && !(r.name && jobs.includes(r.name))) p.push(`docs/jobs.md does not list the routine "${r.key}" (${r.name || "no name"}): add a row for it`);
  }
  for (const f of figures) {
    const now = live[f.kind];
    if (!(now > 0)) continue;
    if (Math.abs(f.said - now) / now > DRIFT) p.push(`${f.file} says ${f.said.toLocaleString("en-US")} ${f.kind === "grid" ? "grid sources" : "feeds"}; there are ${now.toLocaleString("en-US")} now: update the figure`);
  }
  return p;
}

export async function liveCounts() {
  const live = { feeds: 0, grid: 0 };
  try { const c = await import("./collect.mjs"); live.feeds = c.activeFeeds(c.loadFeedConfig()).length; } catch { /* not counted */ }
  try { const { SOURCES } = await import("./grid.mjs"); live.grid = Object.values(SOURCES).filter((s) => !s.paused).length; } catch { /* not counted */ }
  return live;
}

async function main() {
  const read = (f) => (existsSync(join(ROOT, f)) ? readFileSync(join(ROOT, f), "utf8") : "");
  const r = JSON.parse(read("routines.json") || "[]");
  const routines = Array.isArray(r) ? r : r.routines || Object.values(r);
  const figures = STATED_IN.flatMap((f) => statedFigures(f, read(f)));
  const live = await liveCounts();
  const p = problems({ files: codeFiles(), layout: read("docs/layout.md"), jobs: read("docs/jobs.md"), routines, figures, live });
  if (p.length) { console.error(`docs-check: ${p.length} gap(s); documentation is updated in the same change as the code:\n- ${p.join("\n- ")}`); process.exit(1); }
  console.log(`docs-check: ok (${codeFiles().length} files described, ${routines.filter((x) => x.active !== false).length} routines listed, ${figures.length} stated figures within ${DRIFT * 100}% of live: ${live.feeds} feeds, ${live.grid} grid sources)`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
