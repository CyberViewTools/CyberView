// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// CyberView's public data, read-only: from the live site (online) or from a snapshot folder (offline, air-gapped).
// The scanner downloads ONLY these files, with plain GET requests and no key, cookie or account:
//   data/workbench.json      known-exploited flaws (CISA's KEV catalog as CyberView holds it) with NVD's affected-version
//                            ranges, CISA's due dates and required actions, EPSS, and CyberView's fix guides
//   data/psirt.json          vendors' own security advisories joined on CVE (a vendor's "exploited" statement)
//   data/cve/index.json      the CVE lookup files' index
//   data/cve/<year>/<n>.json the CVE lookup files (CVSS, CISA's SSVC assessment, KEV date, EPSS score) for the CVEs matched
// KEV and EPSS arrive inside these files: the scanner never contacts CISA, FIRST or NVD itself, and it never uploads
// anything: no findings, no scope, no addresses, no telemetry.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { USER_AGENT } from "./probe.mjs";

export const DEFAULT_SOURCE = "https://xanderhutch.github.io/CyberView/";
/** The only paths the scanner will ever ask for. */
export const ALLOWED = /^data\/(workbench\.json|psirt\.json|cve\/index\.json|cve\/\d{4}\/\d{1,5}\.json)$/;

/** A base URL must be https, or plain http on this machine (for a local mirror or a test). */
export function checkBase(u) {
  let x; try { x = new URL(u); } catch { return ""; }
  if (x.username || x.password || x.search || x.hash) return "";
  if (x.protocol === "https:" || (x.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(x.hostname))) return x.href.endsWith("/") ? x.href : x.href + "/";
  return "";
}

/** Online source: GET requests to the CyberView site, one at a time, each retried once. */
export function webSource(base = DEFAULT_SOURCE, { fetchImpl = globalThis.fetch, timeoutMs = 60000 } = {}) {
  const b = checkBase(base);
  if (!b) throw new Error(`the data source must be an https address (or http on localhost): ${base}`);
  const log = [];
  return {
    kind: "online", where: b, log,
    async json(rel, { optional = false } = {}) {
      if (!ALLOWED.test(rel)) throw new Error(`not a CyberView data file: ${rel}`);
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const r = await fetchImpl(b + rel, { method: "GET", headers: { "User-Agent": USER_AGENT, Accept: "application/json" }, redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
          log.push({ path: rel, status: r.status });
          if (r.status === 404 && optional) return null;
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          return await r.json();
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
  for (const k of (wb && wb.kev) || []) { const p = k && bucketPath(D, k.cve); if (p) files.add(p); }
  for (const v of (wb && wb.vulns) || []) { const p = v && bucketPath(D, v.cve); if (p) files.add(p); }
  let got = 0, missing = 0;
  for (const rel of [...files].sort()) {
    const j = await src.json(rel, { optional: true });
    if (j) { save(rel, j); got++; } else missing++;
    if ((got + missing) % 50 === 0) log(`${got + missing} of ${files.size} lookup files`);
  }
  const manifest = { cyberview_snapshot: 1, fetched_at: new Date().toISOString(), source: src.where, full, workbench_built_at: (wb && wb.built_at) || "", cve_index_built_at: (idx && idx.built_at) || "", lookup_files: got, lookup_files_missing: missing };
  writeFileSync(join(out, "manifest.json"), JSON.stringify(manifest, null, 2));
  return manifest;
}
