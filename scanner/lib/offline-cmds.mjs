// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// The offline commands (lookup, match, import, depmap, rematch). None of them takes a scope file, because none of
// them contacts anything: they read files on this machine (a report.json, the operator's own import files, a local data
// snapshot) and write their output next to them. No probe, no DNS lookup, no fetch: this module imports neither probe.mjs's
// probe functions nor data.mjs's web source.
import { writeFileSync, mkdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { dirSource } from "./data.mjs";
import { readImportFiles, parseImports, matchInventory, IMPORT_LIMITS } from "./imports.mjs";
import { parseNmapXml, inventoryHost, INPUT_LIMITS } from "./inputs.mjs";
import { lookup, lookupText, cveId } from "./lookup.mjs";
import { buildReport } from "./scan.mjs";
import { toCsv, toSarif, toInventory, summaryText } from "./report.mjs";
import { buildDepmap, toMermaid, depmapText, scopeFromReport } from "./depmap.mjs";
import { loadOldReport, loadMatchData, rematch, rematchText, REMATCH_LIMITS } from "./rematch.mjs";
import { checkScope, hostInScope, inScope as ipInScope } from "./scope.mjs";
import { isIP } from "node:net";

export const OFFLINE_CMDS = new Set(["lookup", "match", "import", "depmap", "rematch"]);
export const IMPORT_USAGE = `Offline (no network; nothing is sent to any host):
  node scanner/cyberview-scan.mjs lookup  CVE-2026-1234 --data DIR [--version 8.2p1] [--out DIR]
  node scanner/cyberview-scan.mjs match   --data DIR (--nmap F | --sbom F | --packages F | --manifest F) [--assume-exposed] [--out DIR]
  node scanner/cyberview-scan.mjs import  [--packages F] [--sbom F] [--manifest F] [--zeek F] [--survey F] [--connections F [--connections-host IP]]
                                          [--cloud F [--cloud-provider aws-ec2|aws-elb|gcp|azure]] [--data DIR] [--out DIR]
  node scanner/cyberview-scan.mjs depmap  --report R/report.json [--scope scope.json] [import flags] [--out DIR]
  node scanner/cyberview-scan.mjs rematch --report OLD/report.json --data NEWER-SNAPSHOT [--out DIR]
  scan ... --depmap [import flags]   also writes depmap.json and depmap.mmd (and a section in report.html with --html)
Import files are your own exports (dpkg -l, rpm -qa, Get-Package CSV, CycloneDX/SPDX JSON, compose/Kubernetes as JSON,
Zeek conn.log, a Wi-Fi/Bluetooth survey CSV, ss/netstat or /proc/net/tcp text captured on the host itself, a cloud CLI's
describe/list JSON). The scanner never runs those commands, logs in, or drives a radio.
lookup answers "what does CyberView know about this CVE?" from the same snapshot: the rating with every point, CISA's
deadline for both exposure answers, the affected ranges from NVD, the fix, and whether this scanner can find the product
at all. With --version it checks a version you hold against the ranges. It is a reader: it writes no report unless --out
is given, and the analysis, check steps and signs of compromise stay on CyberView's page, linked, never copied.
match writes the same five report files as a scan (report.json, findings.csv, report.sarif, inventory.csv, summary.txt) from
a list you already hold, for assets you cannot scan (change freeze, third-party, air-gapped, "scanning is forbidden"). Run
the data command first for --data DIR; no scope file and no attestation are needed, because no host is contacted. An nmap
file needs -sV, or nmap states no product or version. An SBOM or package list has no address: it is rated as internal
unless you state --assume-exposed, which only moves CISA's deadline (the CyberView rating does not depend on exposure).`;

const stamp = (cmd) => `cyberview-${cmd}-${new Date().toISOString().replace(/[-:]/g, "").slice(0, 15)}Z`;
const sizeOf = (f) => statSync(f).size;

/** Load the import flags (shared with scan --depmap). -> { imports, given } | { error } */
export function loadImports(a, io) {
  const r = readImportFiles(a, { readFile: io.readFile, sizeOf: io.sizeOf || sizeOf });
  if (r.error) return r;
  return { given: r.given, imports: r.given.length ? parseImports(r.files, { cloudProvider: a["cloud-provider"] || "aws-ec2", connectionsHost: a["connections-host"] || "" }) : null };
}

/** Run one offline command. -> exit code (0 done, 1 error). */
export async function offlineCommand(cmd, a, io) {
  const fail = (msg) => { io.err("REFUSED: " + msg); return 1; };
  if (a.online || a.source) return fail(`${cmd} works offline only: it takes no --online/--source and contacts nothing`);
  const out = resolve(a.out || stamp(cmd));
  const write = (files) => { mkdirSync(out, { recursive: true, mode: 0o700 }); for (const [f, s] of files) writeFileSync(join(out, f), s, { mode: 0o600 }); return files.map(([f]) => f).join(", "); };
  const today = new Date().toISOString().slice(0, 10);

  if (cmd === "rematch") {
    if (!a.report) return fail("--report OLD/report.json is required");
    if (!a.data) return fail("--data DIR is required (a newer local snapshot from the data command); rematch never downloads");
    let size; try { size = (io.sizeOf || sizeOf)(a.report); } catch { return fail(`cannot read ${a.report}`); }
    if (size > REMATCH_LIMITS.maxBytes) return fail(`${a.report} is over ${REMATCH_LIMITS.maxBytes / 1048576} MB`);
    let text; try { text = io.readFile(a.report); } catch { return fail(`cannot read ${a.report}`); }
    const old = loadOldReport(text); if (old.error) return fail(`${a.report}: ${old.error}`);
    let src; try { src = dirSource(a.data); } catch (e) { return fail(e.message); }
    const r = await rematch(old.report, await loadMatchData(src), { today, reportFile: a.report, dataDir: a.data });
    const t = rematchText(r);
    const files = write([["rematch.json", JSON.stringify(r, null, 2) + "\n"], ["rematch.txt", t + "\n"]]);
    io.out(t + `\n\nWritten to ${out}/ (${files}). Nothing was sent to any host.`);
    return 0;
  }

  const im = loadImports(a, io);
  if (im.error) return fail(im.error);

  if (cmd === "lookup") {
    // A reader, not a matcher: the same snapshot the scan reads, nothing contacted, nothing new fetched.
    const id = cveId(a._[1] || a.cve);
    if (!id) return fail(`give the CVE number, e.g. lookup CVE-2026-1234${a._[1] ? ` (${String(a._[1]).slice(0, 40)} is not one)` : ""}`);
    if (!a.data) return fail("--data DIR is required (a local snapshot from the data command); lookup never downloads");
    if (a.version !== undefined && (typeof a.version !== "string" || !a.version)) return fail("--version needs a version, e.g. --version 8.2p1");
    let src; try { src = dirSource(a.data); } catch (e) { return fail(e.message); }
    const doc = await lookup(src, id, { version: a.version || "", today });
    const text = lookupText(doc);
    let where = "";
    if (a.out) where = `\n\nWritten to ${out}/ (${write([["lookup.json", JSON.stringify(doc, null, 2) + "\n"], ["lookup.txt", text + "\n"]])}).`;
    io.out(text + where);
    return 0;
  }

  if (cmd === "match") {
    // The operator's own files instead of a probe: nmap -oX gives real hosts, ports, products and versions; an SBOM or
    // package list has no address, so it becomes one pseudo-host named after the file. Nothing is contacted, so there is
    // no scope file and no attestation; the matching, rating, priority and the five outputs are the scan's own code.
    if (!a.data) return fail("--data DIR is required (a local snapshot from the data command); match never downloads");
    const nmapFile = a.nmap;
    if (nmapFile !== undefined && (typeof nmapFile !== "string" || !nmapFile)) return fail("--nmap needs a file name");
    if (!nmapFile && !im.given.length) return fail("give --nmap scan.xml (nmap -oX, run with -sV) or an inventory (--sbom, --packages or --manifest)");
    const inputs = [], hosts = [], problems = [...im.imports ? im.imports.problems : []];
    if (nmapFile) {
      let size; try { size = (io.sizeOf || sizeOf)(nmapFile); } catch { return fail(`--nmap: cannot read ${nmapFile}`); }
      if (!(size <= INPUT_LIMITS.maxBytes)) return fail(`--nmap ${nmapFile}: over the ${INPUT_LIMITS.maxBytes / 1048576} MB cap; split the file`);
      let text; try { text = io.readFile(nmapFile); } catch { return fail(`--nmap: cannot read ${nmapFile}`); }
      const r = parseNmapXml(text);
      if (!r.hosts.length) return fail(`--nmap ${nmapFile}: ${(r.problems[0] || "no usable host").replace(/^--nmap: /, "")}`);
      hosts.push(...r.hosts); problems.push(...r.problems); inputs.push(`${nmapFile} (nmap -oX: ${r.stats.hosts} host(s), ${r.stats.services} service(s))`);
    }
    if (im.given.length) {
      const items = im.imports.inventory;
      if (!items.length) return fail(`${im.given.map((k) => "--" + k).join(", ")}: no software item with a name was read`);
      hosts.push(inventoryHost(items, { file: im.given.map((k) => a[k]).join(", "), assumeExposed: !!a["assume-exposed"], proto: im.given.includes("sbom") ? "sbom" : "list" }));
      inputs.push(`${im.given.map((k) => `${a[k]} (--${k})`).join(", ")}: ${items.length} software item(s)`);
    }
    if (hosts.length > INPUT_LIMITS.hosts) hosts.length = INPUT_LIMITS.hosts;
    let src; try { src = dirSource(a.data); } catch (e) { return fail(e.message); }
    const startedAt = new Date().toISOString();
    const report = await buildReport({
      src, scope: { owner: "", contact: "", attestation: null, targets: [], exclude: [], publicCount: hosts.filter((h) => h.public).length },
      scopeFile: "", scopeHash: "", allowPublic: false, ports: [], settings: { note: "no probe settings: nothing was contacted" },
      probed: { hosts, interrupted: false, stop_reason: "", stats: {}, udp: [], paths: { enabled: false }, ics: { enabled: false } },
      refused: [], startedAt, today, matched: { inputs, assume_exposed: !!a["assume-exposed"], has_inventory: im.given.length > 0 },
    });
    report.tool.command = "match";
    report.notes.unshift("Nothing was contacted: every host, port and product here was read from the files you supplied, so this covers exactly what they list and no more. A host, port or product the files do not mention is absent, not clean.");
    if (problems.length) report.notes.push(...problems.slice(0, 20).map((p) => "input: " + p.replace(/^--\w+: /, "")));
    const text = summaryText(report);
    const files = write([["report.json", JSON.stringify(report, null, 2) + "\n"], ["findings.csv", toCsv(report)], ["report.sarif", JSON.stringify(toSarif(report), null, 2) + "\n"],
      ["inventory.csv", toInventory(report)], ["summary.txt", text + "\n"]]);
    io.out(`Matched ${inputs.join("; ")} against the snapshot in ${a.data} (data built ${report.run.data.workbench_built_at || "?"}).\n\n` + text +
      `\n\nWritten to ${out}/ (${files}). Nothing was sent to any host.`);
    return 0;
  }

  if (cmd === "import") {
    if (!im.given.length) return fail("give at least one import file (--packages, --sbom, --manifest, --zeek, --survey, --connections or --cloud)");
    let matched = null, built = "";
    if (a.data) {
      let src; try { src = dirSource(a.data); } catch (e) { return fail(e.message); }
      const d = await loadMatchData(src); built = d.built_at;
      matched = matchInventory(im.imports.inventory, d.flaws, { today });
    }
    const doc = { tool: { name: "CyberView Scanner", command: "import", detection_only: true }, at: new Date().toISOString(), network: "none: parsed from local files only",
      given: im.given, problems: im.imports.problems, inventory: im.imports.inventory, graphs: im.imports.graphs,
      survey: im.imports.sources.survey || null, connections: im.imports.sources.connections ? { kind: im.imports.sources.connections.kind, listening: im.imports.sources.connections.listening, peers: im.imports.sources.connections.peers, note: im.imports.sources.connections.note } : null,
      cloud_addresses: (im.imports.sources.cloud && im.imports.sources.cloud.addresses) || [],
      ...(matched ? { matched: { data_workbench_built_at: built, how: "the Vulnerabilities page's \"My software\" matcher (site/workbench-lib.js matchFlaw and score), unchanged", findings: matched } } : {}) };
    const lines = [`Imported ${im.given.join(", ")}: ${im.imports.inventory.length} software item(s), ${im.imports.graphs.reduce((n, g) => n + g.nodes.length, 0)} node(s), ${im.imports.graphs.reduce((n, g) => n + g.edges.length, 0)} relationship(s).`];
    if (matched) lines.push(`Matched against data built ${built || "?"}: ${matched.length} CVE(s) (${matched.filter((f) => f.kev && f.confidence !== "low").length} known exploited, version-confirmed; ${matched.filter((f) => f.confidence === "low").length} to check by hand).`,
      ...matched.slice(0, 15).map((f) => `  ${f.cve}${f.kev ? " (KEV)" : ""} [${f.confidence}] ${f.items.map((i) => `${i.name} ${i.version || "(no version)"}`).slice(0, 3).join(", ")}: ${f.points.list.map((p) => `${p.why} +${p.points}`).join("; ")}`));
    im.imports.problems.slice(0, 20).forEach((p) => lines.push("  note: " + p));
    const files = write([["imports.json", JSON.stringify(doc, null, 2) + "\n"]]);
    io.out(lines.join("\n") + `\n\nWritten to ${out}/ (${files}). Nothing was sent to any host.`);
    return 0;
  }

  if (cmd === "depmap") {
    if (!a.report) return fail("--report R/report.json is required");
    let size; try { size = (io.sizeOf || sizeOf)(a.report); } catch { return fail(`cannot read ${a.report}`); }
    if (size > REMATCH_LIMITS.maxBytes) return fail(`${a.report} is over ${REMATCH_LIMITS.maxBytes / 1048576} MB`);
    let report; try { report = JSON.parse(io.readFile(a.report)); } catch { return fail(`${a.report} is not JSON`); }
    if (!report || typeof report !== "object" || !report.tool || report.tool.name !== "CyberView Scanner" || !Array.isArray(report.hosts)) return fail(`${a.report} is not a CyberView Scanner report.json`);
    let inScope = scopeFromReport(report).inScope;
    if (a.scope) {   // the scope file only sharpens the in-scope test (attested domains); nothing is scanned
      let t; try { t = io.readFile(a.scope); } catch { return fail(`cannot read ${a.scope}`); }
      const sc = checkScope(t, { today }); if (!sc.ok) return fail(`the scope file does not pass its checks: ${(sc.problems || []).slice(0, 3).join("; ")}`);
      inScope = (h) => (isIP(h) ? ipInScope(sc.scope, h) : hostInScope(sc.scope, h));
    }
    const m = buildDepmap(report, { imports: im.imports, inScope });
    const files = write([["depmap.json", JSON.stringify(m, null, 2) + "\n"], ["depmap.mmd", toMermaid(m)]]);
    io.out(depmapText(m) + `\n\nWritten to ${out}/ (${files}). Nothing was sent to any host.`);
    return 0;
  }
  return 1;
}
