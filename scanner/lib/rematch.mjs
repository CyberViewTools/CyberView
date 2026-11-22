// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Offline rematch (tk-matchers): re-run matching on an OLD report.json's recorded services with a NEWER local data
// snapshot, and say which CVEs are newly matched or no longer matched. No network at all: no target is contacted (the
// services are as the old scan recorded them, which may be out of date) and the data comes from a local snapshot directory.
// Also matches the operator's imported package lists / SBOMs (imports.mjs) with the same data loader.
// The old report is UNTRUSTED input: only a CyberView Scanner report is accepted, and only the fields matching needs are
// kept, type-checked and clipped.
import { isIP } from "node:net";
import { cleanFlaws, candidates, findings as matchFindings } from "./match.mjs";
import { bucketPath } from "./data.mjs";
import { summarize } from "./report.mjs";
import { D } from "./shared.mjs";
import { VERSION } from "./probe.mjs";

export const REMATCH_LIMITS = Object.freeze({ maxBytes: 64 * 1024 * 1024, hosts: 100000, servicesPerHost: 2000, findings: 20000 });
const clip = (s, n) => (typeof s === "string" ? s : "").replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n);
const arr = (x) => (Array.isArray(x) ? x : []);
const isCve = (s) => /^CVE-\d{4}-\d{4,}$/.test(s || "");

/** The old report's text -> { report: { started_at, workbench_built_at, hosts: [{address, names, public, services}], findings: [cve] } } | { error } */
export function loadOldReport(text) {
  const s = String(text || "");
  if (!s.trim()) return { error: "the report file is empty" };
  if (s.length > REMATCH_LIMITS.maxBytes) return { error: `the report file is over ${REMATCH_LIMITS.maxBytes / 1048576} MB` };
  let j; try { j = JSON.parse(s); } catch { return { error: "the report file is not JSON" }; }
  if (!j || typeof j !== "object" || !j.tool || j.tool.name !== "CyberView Scanner" || !Array.isArray(j.hosts)) return { error: "not a CyberView Scanner report.json (tool.name and hosts are missing)" };
  const hosts = j.hosts.slice(0, REMATCH_LIMITS.hosts).filter((h) => h && typeof h === "object" && isIP(clip(h.address, 45))).map((h) => ({
    address: clip(h.address, 45), names: arr(h.names).slice(0, 20).map((n) => clip(n, 253)).filter(Boolean), public: h.public === true, up: h.up !== false, ports: [], observations: [],
    services: arr(h.services).slice(0, REMATCH_LIMITS.servicesPerHost).filter((x) => x && typeof x === "object" && clip(x.product, 120)).map((x) => ({
      port: Number.isInteger(x.port) && x.port >= 0 && x.port <= 65535 ? x.port : 0, proto: clip(x.proto, 20), vendor: clip(x.vendor, 80), product: clip(x.product, 120), label: clip(x.label, 160),
      version: clip(x.version, 40).replace(/[^\w.+\-~:]/g, ""), shown_version: clip(x.shown_version || x.version, 60), distro: clip(x.distro, 60), source: clip(x.source, 80), evidence: clip(x.evidence, 300), guessed: x.guessed === true })),
  }));
  const findings = [...new Set(arr(j.findings).slice(0, REMATCH_LIMITS.findings).map((f) => clip(f && f.cve, 30)).filter(isCve))];
  return { report: { started_at: clip(j.run && j.run.started_at, 40), workbench_built_at: clip(j.run && j.run.data && j.run.data.workbench_built_at, 40), hosts, findings } };
}

/** Load the snapshot's flaws, and a function that loads lookup rows for a set of CVEs. src: data.mjs dirSource (local only). */
export async function loadMatchData(src) {
  const wb = await src.json("data/workbench.json");
  const ps = await src.json("data/psirt.json", { optional: true });
  D.vendorIndex = ps ? D.cleanVendorIndex(ps) : {};
  const rowsFor = async (ids) => {
    const rows = new Map(), files = new Map();
    for (const id of ids) {
      const p = bucketPath(D, id); if (!p) continue;
      if (!files.has(p)) files.set(p, await src.json(p, { optional: true }).then((j) => (j ? D.parseFile(j) : []), () => []));
      const r = files.get(p).find((x) => x.id === id); if (r) rows.set(id, r);
    }
    return rows;
  };
  return { wb, flaws: cleanFlaws(wb), rowsFor, built_at: (wb && wb.built_at) || "" };
}

/** old: loadOldReport(...).report; data: loadMatchData(src) -> the rematch result. */
export async function rematch(old, data, { today = new Date().toISOString().slice(0, 10), reportFile = "", dataDir = "" } = {}) {
  const hosts = old.hosts;
  const rows = await data.rowsFor(candidates(hosts, data.flaws));
  const found = matchFindings(hosts, data.flaws, rows, { today });
  const now = new Set(found.map((f) => f.cve)), before = new Set(old.findings);
  return {
    tool: { name: "CyberView Scanner", version: VERSION, detection_only: true, command: "rematch" },
    rematch: { report_file: clip(reportFile, 300), report_started_at: old.started_at, report_workbench_built_at: old.workbench_built_at, data_dir: clip(dataDir, 300), data_workbench_built_at: data.built_at, at: new Date().toISOString(), network: "none: no target was contacted and no data was downloaded" },
    summary: summarize(hosts, found),
    changes: { newly_matched: found.filter((f) => !before.has(f.cve)).map((f) => ({ cve: f.cve, title: f.title, kev: f.kev, state: f.state, confidence: f.confidence, hosts: [...new Set(f.seen_on.map((s) => s.host))].slice(0, 50) })),
      no_longer_matched: [...before].filter((c) => !now.has(c)).sort(), still_matched: [...before].filter((c) => now.has(c)).sort() },
    findings: found,
    notes: [
      `Services are as the scan of ${old.started_at || "an earlier date"} recorded them; a host may have changed since. Rescan to confirm.`,
      "A CVE no longer matched may have left CyberView's data (for example a range corrected by NVD) rather than been fixed on the host.",
      "Matching uses the site's own matcher (site/workbench-lib.js) and rating (site/cvedb-lib.js), unchanged.",
    ],
  };
}

export function rematchText(r) {
  const c = r.changes, s = r.summary;
  const L = [`Offline rematch of the scan from ${r.rematch.report_started_at || "?"} against data built ${r.rematch.data_workbench_built_at || "?"} (no network).`,
    `  ${s.findings} finding(s) now (${s.known_exploited} known exploited, ${s.low_confidence} low confidence). ${c.newly_matched.length} newly matched, ${c.no_longer_matched.length} no longer matched, ${c.still_matched.length} still matched.`];
  for (const f of c.newly_matched.slice(0, 20)) L.push(`  NEW ${f.cve}${f.kev ? " (known exploited)" : ""} [${f.confidence}] on ${f.hosts.slice(0, 4).join(", ")}: ${f.title}`);
  if (c.no_longer_matched.length) L.push(`  No longer matched: ${c.no_longer_matched.slice(0, 30).join(", ")}`);
  return L.join("\n");
}
