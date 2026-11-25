// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// CyberView's public data, read-only: from the live site (online) or from a snapshot folder (offline, air-gapped).
// The scanner downloads ONLY these files, with plain GET requests and no key, cookie or account:
//   data/workbench.json      known-exploited flaws (CISA's KEV catalog as CyberView holds it) with NVD's affected-version
//                            ranges, CISA's due dates and required actions, EPSS, and CyberView's fix guides
//   data/psirt.json          vendors' own security advisories joined on CVE (a vendor's "exploited" statement)
//   data/cve/index.json      the CVE lookup files' index
//   data/cve/<year>/<n>.json the CVE lookup files (CVSS, CISA's SSVC assessment, KEV date, EPSS score) for the CVEs matched
//   data/archive/search.json, data/archive/<YYYY-MM>.json   the event archive, ONLY with --data-incidents (scanner/lib/cite.mjs)
// KEV and EPSS arrive inside these files: the scanner never contacts CISA, FIRST or NVD itself, and it never uploads
// anything: no findings, no scope, no addresses, no telemetry.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { USER_AGENT } from "./probe.mjs";

export const DEFAULT_SOURCE = "https://cyberview.tools/";
/** The only paths the scanner will ever ask for. */
export const ALLOWED = /^data\/(workbench\.json|psirt\.json|cve\/index\.json|cve\/\d{4}\/\d{1,5}\.json|archive\/search\.json|archive\/\d{4}-\d{2}\.json|distro\/index\.json|distro\/(?:debian|ubuntu)-[\d.]{1,8}\.json)$/;

/** A base URL must be https, or plain http on this machine (for a local mirror or a test). */
export function checkBase(u) {
  let x; try { x = new URL(u); } catch { return ""; }
  if (x.username || x.password || x.search || x.hash) return "";
  if (x.protocol === "https:" || (x.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(x.hostname))) return x.href.endsWith("/") ? x.href : x.href + "/";
  return "";
}

/** Online source: GET requests to the CyberView site, one at a time, each retried once. */
/**
 * known: { rel: { etag, lm } } from an earlier download, and reuse(rel) -> that download's JSON (or null). With both, a file is
 * asked for with If-None-Match / If-Modified-Since and a 304 answer reuses the earlier copy: a daily refresh, or a download
 * that was cut off, then only transfers what changed. seen collects the validators of this run for the next one.
 */
export function webSource(base = DEFAULT_SOURCE, { fetchImpl = globalThis.fetch, timeoutMs = 60000, known = {}, reuse = null } = {}) {
  const b = checkBase(base);
  if (!b) throw new Error(`the data source must be an https address (or http on localhost): ${base}`);
  const log = [], seen = {}, stats = { fetched: 0, reused: 0 };
  return {
    kind: "online", where: b, log, seen, stats,
    async json(rel, { optional = false } = {}) {
      if (!ALLOWED.test(rel)) throw new Error(`not a CyberView data file: ${rel}`);
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const k = known[rel], old = k && reuse && attempt === 0 ? reuse(rel) : null, cond = {};
          if (old && k.etag) cond["If-None-Match"] = k.etag; else if (old && k.lm) cond["If-Modified-Since"] = k.lm;
          const r = await fetchImpl(b + rel, { method: "GET", headers: { "User-Agent": USER_AGENT, Accept: "application/json", ...cond }, redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
          log.push({ path: rel, status: r.status });
          if (r.status === 304 && old) { seen[rel] = k; stats.reused++; return old; }
          if (r.status === 404 && optional) return null;
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          const j = await r.json(), h = r.headers && r.headers.get ? { etag: r.headers.get("etag") || "", lm: r.headers.get("last-modified") || "" } : null;
          if (h && (h.etag || h.lm)) seen[rel] = h;
          stats.fetched++;
          return j;
        } catch (e) {
          if (attempt === 1) { if (optional) return null; throw new Error(`could not read ${b + rel}: ${e.message}`); }
          await new Promise((res) => setTimeout(res, 2000));
        }
      }
      return null;
    },
  };
}

/** Offline source: a snapshot folder written by `data` (the same paths, under the folder). */
export function dirSource(dir) {
  if (!existsSync(join(dir, "data", "workbench.json"))) throw new Error(`${dir} is not a CyberView snapshot (no data/workbench.json); make one with: node scanner/cyberview-scan.mjs data --out ${dir}`);
  const manifest = (() => { try { return JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")); } catch { return {}; } })();
  return {
    kind: "offline", where: dir, manifest, log: [],
    async json(rel, { optional = false } = {}) {
      if (!ALLOWED.test(rel)) throw new Error(`not a CyberView data file: ${rel}`);
      const p = join(dir, rel);
      if (!existsSync(p)) { if (optional) return null; throw new Error(`the snapshot has no ${rel}`); }
      return JSON.parse(readFileSync(p, "utf8"));
    },
  };
}

/** Where a snapshot keeps the HTTP validators of its files, and how a later download reads them back (newest folder first). */
export const HTTP_STATE = ".http.json";
export function earlier(dirs) {
  const known = {}, where = {};
  for (const d of dirs.filter(Boolean).reverse()) { try { const k = JSON.parse(readFileSync(join(d, HTTP_STATE), "utf8")); for (const rel of Object.keys(k)) { known[rel] = k[rel]; where[rel] = d; } } catch { /* none */ } }
  return { known, reuse: (rel) => { try { return where[rel] && ALLOWED.test(rel) ? JSON.parse(readFileSync(join(where[rel], rel), "utf8")) : null; } catch { return null; } } };
}

/** The lookup file that holds a CVE id ("CVE-2024-3400" -> "data/cve/2024/3.json"), as cvedb-lib.js bucketFile. */
export const bucketPath = (D, id) => (D.bucketFile(id) ? "data/cve/" + D.bucketFile(id) : "");

/**
 * Download a snapshot for offline use: workbench, vendor advisories, the CVE index and the lookup files of every
 * known-exploited CVE (or, with full, every lookup file the index lists). Polite: one request at a time.
 */
export async function snapshot(src, out, D, { full = false, log = () => {} } = {}) {
  const save = (rel, j) => { const p = join(out, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(j)); };
  const wb = await src.json("data/workbench.json"); save("data/workbench.json", wb); log("data/workbench.json");
  const ps = await src.json("data/psirt.json", { optional: true }); if (ps) { save("data/psirt.json", ps); log("data/psirt.json"); }
  const idx = await src.json("data/cve/index.json", { optional: true }); if (idx) { save("data/cve/index.json", idx); log("data/cve/index.json"); }
  const files = new Set();
  if (full && idx && idx.files_by_year) for (const [y, list] of Object.entries(idx.files_by_year)) if (/^\d{4}$/.test(y) && Array.isArray(list)) list.forEach((n) => Number.isInteger(n) && files.add(`data/cve/${y}/${n}.json`));
  // the distributions' own fix records (Debian, Ubuntu): what a signed-in check needs to tell a backported fix from a missing one
  const dx = full ? await src.json("data/distro/index.json", { optional: true }) : null;
  if (dx) { save("data/distro/index.json", dx); log("data/distro/index.json"); for (const k of Object.keys(dx.releases || {})) if (/^(debian|ubuntu)-[\d.]{1,8}$/.test(k)) files.add(`data/distro/${k}.json`); }
  for (const k of (wb && wb.kev) || []) { const p = k && bucketPath(D, k.cve); if (p) files.add(p); }
  for (const v of (wb && wb.vulns) || []) { const p = v && bucketPath(D, v.cve); if (p) files.add(p); }
  let got = 0, missing = 0;
  const keep = () => { if (src.seen) { try { writeFileSync(join(out, HTTP_STATE), JSON.stringify(src.seen)); } catch { /* best effort */ } } };
  for (const rel of [...files].sort()) {
    const j = await src.json(rel, { optional: true });
    if (j) { save(rel, j); got++; } else missing++;
    if ((got + missing) % 50 === 0) { log(`${got + missing} of ${files.size} lookup files`); keep(); }
  }
  keep();
  const manifest = { cyberview_snapshot: 1, fetched_at: new Date().toISOString(), source: src.where, full, workbench_built_at: (wb && wb.built_at) || "", cve_index_built_at: (idx && idx.built_at) || "", lookup_files: got, lookup_files_missing: missing, ...(src.stats ? { transferred: src.stats.fetched, unchanged: src.stats.reused } : {}) };
  writeFileSync(join(out, "manifest.json"), JSON.stringify(manifest, null, 2));
  return manifest;
}
