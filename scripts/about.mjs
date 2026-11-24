// The description of CyberView, kept current. No AI model.
// config/about.json is the one description (tagline, intro, one entry per capability). This script
//   - fills {feeds} {events} {cves} {grid} from live data, so the numbers are right at every build
//   - renders the About page's "What CyberView is" section (scripts/pages.mjs calls aboutSection())
//   - `check`: fails when a page, view, map layer or active routine is not covered by an entry, when an entry covers
//     something that does not exist, or when site/index.html's description drifts from about.json. Run in CI (npm run ci)
//     so a new feature cannot ship undescribed.
// Run: node scripts/about.mjs check | show
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, readStatus } from "./lib/store.mjs";

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
export const about = () => JSON.parse(readFileSync(join(ROOT, "config", "about.json"), "utf8"));
const fmt = (n) => (Number.isFinite(n) && n > 0 ? n.toLocaleString("en-US") : "");

/** Live numbers. Each falls back to "" (and its sentence still reads) when the data is missing. */
export async function numbers() {
  let feeds = 0;
  try { feeds = (await import("./collect.mjs")).FEEDS.length; } catch { feeds = 0; }
  try { const c = await import("./collect.mjs"); feeds = c.activeFeeds(c.loadFeedConfig()).length; } catch { /* counted above */ }
  let events = 0;
  const ed = join(DATA, "events");
  if (existsSync(ed)) for (const m of readdirSync(ed)) { try { events += readdirSync(join(ed, m)).filter((f) => f.endsWith(".json")).length; } catch { /* not a month */ } }
  const cves = Number(readStatus().cve_total) || 0;
  let grid = 0;
  try {
    const { SOURCES } = await import("./grid.mjs"), live = readJson(join(DATA, "grid", "live.json"), {}) || {};
    grid = Object.keys(SOURCES).filter((k) => !SOURCES[k].paused && !/^not connected/.test(((live.sources || {})[k] || {}).error || "")).length;
  } catch { grid = 0; }
  return { feeds: fmt(feeds) || "more than 130", events: fmt(events) || "hundreds of", cves: fmt(cves) || "every published", grid: fmt(grid) || "several" };
}
export const fill = (text, n) => String(text).replace(/\{(\w+)\}/g, (m, k) => (k in n ? n[k] : m));

/** The About page's generated section (HTML, every value escaped). */
export function aboutSection(a, n) {
  const caps = a.capabilities.map((c) => `    <li><strong><a href="${esc(c.link)}">${esc(c.title)}</a>:</strong> ${esc(fill(c.text, n))}</li>`).join("\n");
  return `<section class="panel legal" id="what">
  <h2>What CyberView is</h2>
${a.intro.map((p) => `  <p>${esc(fill(p, n))}</p>`).join("\n")}
  <ul>
${caps}
  </ul>
</section>`;
}

/** What exists in the code: pages, views, map layers, active routines. */
export async function inventory() {
  const { NAV } = await import("./pages.mjs");
  const index = readFileSync(join(ROOT, "site", "index.html"), "utf8"), app = readFileSync(join(ROOT, "site", "app.js"), "utf8");
  const block = (name) => { const i = app.indexOf(`var ${name}={`); if (i < 0) return []; const j = app.indexOf("\n};", i); return [...app.slice(i, j).matchAll(/^\s{2}([a-z]+):\{label:/gm)].map((m) => m[1]); };
  return {
    pages: NAV.map((x) => x[2]),
    views: [...new Set([...index.matchAll(/data-view="([a-z]+)"/g)].map((m) => m[1]))],
    layers: [...block("CTX_DEFS"), ...block("ARC_DEFS")],
    routines: (readJson(join(ROOT, "routines.json"), { routines: [] }).routines || []).filter((r) => r.active !== false).map((r) => r.key),
  };
}

/** Pure: problems with the description against the inventory. */
export function problems(a, inv, indexHtml = "") {
  const out = [], covered = { pages: new Set(), views: new Set(), layers: new Set(), routines: new Set() };
  if (!a || !a.tagline || !Array.isArray(a.intro) || !Array.isArray(a.capabilities)) return ["config/about.json: needs tagline, intro and capabilities"];
  for (const c of a.capabilities) {
    if (!c.key || !c.title || !c.text || !c.link) out.push(`capability ${c.key || "?"}: needs key, title, text and link`);
    for (const [kind, list] of Object.entries(c.covers || {})) {
      if (!covered[kind]) { out.push(`capability ${c.key}: unknown covers kind "${kind}"`); continue; }
      for (const k of list) { if (!inv[kind].includes(k)) out.push(`capability ${c.key}: covers ${kind} "${k}", which does not exist`); covered[kind].add(k); }
    }
  }
  for (const kind of Object.keys(covered)) for (const k of inv[kind]) if (!covered[kind].has(k)) out.push(`${kind} "${k}" is not described in config/about.json: add it to a capability's covers (or a new capability)`);
  const m = /<meta name="description" content="([^"]*)">/.exec(indexHtml);
  if (indexHtml && a.pages && a.pages.index && (!m || m[1] !== a.pages.index.replace(/&/g, "&amp;"))) out.push("site/index.html: meta description differs from config/about.json pages.index");
  return out;
}

async function main() {
  const cmd = process.argv[2] || "check", a = about();
  if (cmd === "show") { const n = await numbers(); console.log(a.tagline + "\n"); a.intro.forEach((p) => console.log(fill(p, n) + "\n")); a.capabilities.forEach((c) => console.log(`- ${c.title}: ${fill(c.text, n)}`)); return; }
  const p = problems(a, await inventory(), readFileSync(join(ROOT, "site", "index.html"), "utf8"));
  if (p.length) { console.log(`about: ${p.length} problem(s)`); p.forEach((x) => console.log("  " + x)); process.exit(1); }
  console.log(`about: every page, view, map layer and routine is described (${a.capabilities.length} capabilities)`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
