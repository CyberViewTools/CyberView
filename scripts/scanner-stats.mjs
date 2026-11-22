// Live numbers for the Scanner page (site/scanner.html), no AI model. Called by scripts/build.mjs, which writes
// site/data/scanner.json. It reads the scanner's own modules READ-ONLY (imports their exported tables, and scans their
// source text for vendor and product names); it never runs a probe, opens a connection or changes anything under scanner/.
// Only counts, the version and the opt-in flags are published: no rule text, pattern or catalog id leaves this script.
//
// Defensive by design: modules are detected by file existence, so new ones (fp-apps.mjs, fp-apps2.mjs, fp-identify.mjs,
// paths.mjs, cert-inventory.mjs, a FINGERPRINT_TABLES export) are counted when they land, and a module that is missing or
// fails to load leaves its numbers null ("—" on the page). scannerStats() never throws.
//
// Run: node scripts/scanner-stats.mjs   (prints the JSON it would write)
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT as REPO } from "./lib/store.mjs";

const norm = (s) => String(s || "").toLowerCase().replace(/[_\s]+/g, " ").replace(/[^a-z0-9 ]/g, "").replace(/\s+/g, " ").trim();
const text = (p) => { try { return readFileSync(p, "utf8"); } catch { return ""; } };
const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, n);

/** The fingerprint modules present in scanner/lib (file names only). */
export function fingerprintFiles(lib) {
  let names = [];
  try { names = readdirSync(lib).filter((f) => f.endsWith(".mjs")); } catch { return []; }
  return names.filter((f) => f === "fingerprint.mjs" || /^fp-[a-z0-9-]+\.mjs$/.test(f) || f === "paths.mjs" || f === "cert-inventory.mjs").sort();
}

/** Rows a module's exported tables build: rule rows (RULES, RAIL, *_RULES, FINGERPRINT_TABLES ...) and the catalog ids they name. */
export function tableRows(mod) {
  const ids = new Set(); let rules = 0;
  const addIds = (r) => {
    if (typeof r === "string") { ids.add(r); return; }
    if (!r || typeof r !== "object") return;
    for (const x of [].concat(r.ids || [], r.id || [], r.row ? String(r.row).split(", ") : [])) if (typeof x === "string" && x) ids.add(x);
  };
  const table = (v) => { if (!Array.isArray(v)) return; rules += v.length; v.forEach(addIds); };
  for (const [k, v] of Object.entries(mod || {})) {
    if (k === "FINGERPRINT_TABLES" && v && typeof v === "object") {
      for (const t of Array.isArray(v) ? v : Object.values(v)) {
        if (Array.isArray(t)) table(t);
        else if (t && typeof t === "object") table(t.rules || t.rows || t.table || []);
      }
      continue;
    }
    if (!Array.isArray(v)) continue;
    if (/_ROWS$/.test(k)) { v.forEach((x) => typeof x === "string" && ids.add(x)); continue; }
    if (/^(RULES|RAIL|SIGNATURES|FINGERPRINTS|[A-Z_]+_RULES|[A-Z_]+_TABLE)$/.test(k)) table(v);
  }
  return { rules, ids };
}

/** Entries in fingerprint.mjs's built-in banner, header and certificate tables (counted from the source text). */
export function baseTableRows(src) {
  let n = 0;
  for (const name of ["GREET", "SERVER", "CERT_HINTS"]) {
    const i = src.indexOf(`const ${name} = [`); if (i < 0) continue;
    const j = src.indexOf("\n];", i); if (j < 0) continue;
    n += (src.slice(i, j).match(/\[\/(?!\])/g) || []).length;
  }
  return n;
}

/** Distinct vendor/product pairs the fingerprint sources name (NVD CPE names), from the source text. */
export function productsIn(src) {
  const out = new Set(), add = (v, p) => { if (!p || /\{/.test(p) || /\{/.test(v)) return; const k = norm(v) + "|" + norm(p); if (norm(p)) out.add(k); };
  for (const m of src.matchAll(/vendor:\s*"([^"]*)",\s*product:\s*"([^"]+)"/g)) add(m[1], m[2]);
  for (const m of src.matchAll(/\/[dgimsuy]*,\s*"([^"]*)",\s*"([^"]+)"/g)) add(m[1], m[2]);
  for (const m of src.matchAll(/\b(?:tok|jsonVersion)\(\s*"([^"]+)",\s*"([^"]+)"/g)) add(m[1], m[2]);
  return out;
}

/** KEV products (vendor|product as CISA lists them) the scanner can name, matched by normalised product name. */
export function kevCoverage(kev, products) {
  if (!Array.isArray(kev) || !kev.length) return { total: null, covered: null, gap: null };
  const names = new Set(), pairs = new Set();
  for (const k of products) { const [v, p] = k.split("|"); names.add(p); pairs.add(`${v} ${p}`); }
  const seen = new Map();
  for (const r of kev) {
    if (!r || typeof r !== "object" || !r.product) continue;
    const key = norm(r.vendor) + "|" + norm(r.product); if (seen.get(key)) continue;
    const cands = [norm(r.product), `${norm(r.vendor)} ${norm(r.product)}`];
    for (const a of Array.isArray(r.affected) ? r.affected.slice(0, 50) : []) if (a && a.product) cands.push(norm(a.product), `${norm(a.vendor)} ${norm(a.product)}`);
    seen.set(key, cands.some((c) => c && (names.has(c) || pairs.has(c))));
  }
  const total = seen.size, covered = [...seen.values()].filter(Boolean).length;
  return { total, covered, gap: total - covered };
}

// opt-in flags the page explains when the scanner's command-line code accepts them (detected in its source text)
const OPT_INS = [
  ["--html", "also writes report.html, one self-contained page with no script and nothing loaded from the network"],
  ["--data-incidents", "cites reviewed CyberView incidents that name each finding's CVE (attackers' claims are never cited)"],
  ["--udp", "adds the read-only DNS, NTP and SNMP service checks, one datagram per service per host"],
  ["--all-ports", "scans every TCP port (1-65535), allowed only for private ranges you own"],
  ["--paths", "turns on the bounded HTTP path rail: a few reviewed version paths, only for products the root page already pointed to"],
  ["--full", "with the data command, also downloads every CVE lookup file for offline use"],
];

/** Shipped-feature list from config/scanner-page.json, validated (public text, length-limited). */
export function cleanRecent(cfg) {
  const list = cfg && Array.isArray(cfg.recent) ? cfg.recent : [];
  return list.slice(0, 40).map((r) => {
    if (!r || typeof r !== "object") return null;
    const title = clip(r.title, 100), line = clip(r.line, 300), date = /^\d{4}-\d{2}-\d{2}$/.test(r.date || "") ? r.date : "";
    const pr = Number.isInteger(r.pr) && r.pr > 0 && r.pr < 100000 ? r.pr : null;
    return title && date ? { title, line, date, pr } : null;
  }).filter(Boolean);
}

/** Everything the Scanner page shows from the code. Never throws; missing parts are null. */
export async function scannerStats({ root = REPO, kev = [], built_at = new Date().toISOString() } = {}) {
  const lib = join(root, "scanner", "lib");
  const out = { built_at, version: null, modules: [], products: null, rules: null, catalog_rows: null,
    kev_products: null, kev_covered: null, kev_gap: null, rail_entries: null, rail_paths: null, paths_per_host: null,
    areas: { services: null, edge: null, cms: null, apps: null, rail: null }, cert_inventory: false, opt_ins: [], recent: [], errors: [] };
  const load = async (f) => { try { return await import(pathToFileURL(join(lib, f)).href); } catch (e) { out.errors.push(`${f}: ${clip(e && e.message, 120)}`); return null; } };
  try {
    if (existsSync(join(lib, "probe.mjs"))) {
      const m = /export const VERSION = "([\w.+-]{1,20})"/.exec(text(join(lib, "probe.mjs")));
      out.version = m ? m[1] : null;
    }
    const files = fingerprintFiles(lib);
    out.modules = files;
    out.cert_inventory = files.includes("cert-inventory.mjs");
    const products = new Set(), ids = new Set(); let rules = 0;
    for (const f of files) {
      const src = text(join(lib, f));
      for (const p of productsIn(src)) products.add(p);
      const mod = await load(f);
      const t = tableRows(mod); rules += t.ids.size || t.rules; t.ids.forEach((x) => ids.add(x));
      if (f === "fingerprint.mjs") { const b = baseTableRows(src); rules += b; out.areas.services = b || null; }
      else if (f === "fp-edge.mjs") out.areas.edge = t.ids.size || t.rules || null;
      else if (/^fp-cms/.test(f)) out.areas.cms = (out.areas.cms || 0) + (t.ids.size || t.rules) || out.areas.cms;
      else if (/^fp-(apps|identify)/.test(f)) out.areas.apps = (out.areas.apps || 0) + (t.ids.size || t.rules) || out.areas.apps;
      if (f === "paths.mjs" && mod) {
        out.rail_entries = Array.isArray(mod.RAIL) ? mod.RAIL.length : null;
        out.rail_paths = Array.isArray(mod.RAIL_PATHS) ? mod.RAIL_PATHS.length : null;
        out.paths_per_host = Number.isInteger(mod.PATHS_PER_HOST) ? mod.PATHS_PER_HOST : null;
        out.areas.rail = out.rail_entries;
      }
    }
    if (files.length) { out.products = products.size || null; out.rules = rules || null; out.catalog_rows = ids.size || null; }
    const cov = kevCoverage(kev, products);
    out.kev_products = cov.total; out.kev_covered = cov.covered; out.kev_gap = cov.gap;
    const cli = text(join(root, "scanner", "cyberview-scan.mjs"));
    out.opt_ins = OPT_INS.filter(([flag]) => new RegExp(`${flag.replace(/-/g, "\\-")}(?![\\w-])`).test(cli)).map(([flag, what]) => ({ flag, what }));
  } catch (e) { out.errors.push(clip(e && e.message, 160)); }
  try { out.recent = cleanRecent(JSON.parse(text(join(root, "config", "scanner-page.json")) || "{}")); } catch (e) { out.errors.push("config/scanner-page.json: " + clip(e && e.message, 120)); }
  out.errors = out.errors.slice(0, 10);
  return out;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) console.log(JSON.stringify(await scannerStats(), null, 1));
