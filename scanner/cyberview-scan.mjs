#!/usr/bin/env node
// CyberView Scanner: finds known-vulnerable software on YOUR OWN network and ranks what to patch first, using CyberView's
// published CVE, KEV and EPSS data and the CyberView rating. Detection only: it reads the versions services state about
// themselves and matches them; it never exploits, logs in, guesses passwords, floods or hides. No AI model.
// Read scanner/README.md first. Commands:
//   init  [--out scope.json]                  write a scope file to fill in (targets, owner, your attestation)
//   check --scope FILE [--i-am-authorized-for-public-ranges]   check the scope file and show what a scan would do; no network
//   data  --out DIR [--source URL] [--full]   download CyberView's data for offline (air-gapped) scans
//   scan  --scope FILE (--data DIR | --online [--source URL]) [--ports LIST] [--out DIR] [--assume-up]
//         [--http-ports LIST] [--https-ports LIST] (web services on non-standard ports)
//         [--rate N] [--concurrency N] [--host-concurrency N] [--host-budget N] [--budget N] [--max-minutes N]
//         [--i-am-authorized-for-public-ranges]
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { checkScope, template, PUBLIC_FLAG, LIMITS } from "./lib/scope.mjs";
import { settings as checkSettings, CAPS } from "./lib/limits.mjs";
import { DEFAULT_PORTS, SENDS, VERSION } from "./lib/probe.mjs";
import { webSource, dirSource, snapshot, DEFAULT_SOURCE } from "./lib/data.mjs";
import { parsePorts, resolveScope, probeAll, buildReport } from "./lib/scan.mjs";
import { header, toCsv, toSarif, toInventory, summaryText } from "./lib/report.mjs";
import { D } from "./lib/shared.mjs";

const BOOL = new Set(["online", "full", "assume-up", "help", PUBLIC_FLAG.slice(2)]);
export function parseArgs(argv) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) { o._.push(a); continue; }
    const [k, v] = a.slice(2).split(/=(.*)/s);
    if (BOOL.has(k)) o[k] = true; else o[k] = v !== undefined ? v : argv[++i];
  }
  return o;
}
const USAGE = `CyberView Scanner ${VERSION} (detection only; scan only what you own or are authorized to test)
  node scanner/cyberview-scan.mjs init  [--out scope.json]
  node scanner/cyberview-scan.mjs check --scope scope.json
  node scanner/cyberview-scan.mjs data  --out cyberview-data [--full]
  node scanner/cyberview-scan.mjs scan  --scope scope.json --data cyberview-data      (offline)
  node scanner/cyberview-scan.mjs scan  --scope scope.json --online                   (reads CyberView's public data)
Limits can be lowered, never raised: --rate (max ${CAPS.rate}/s), --concurrency (max ${CAPS.concurrency}), --host-concurrency (max ${CAPS.hostConcurrency}),
--host-budget (max ${CAPS.hostBudget}), --budget (max ${CAPS.budget}), --max-minutes (default 60, max ${CAPS.minutes}).
Public (non-private) addresses also need ${PUBLIC_FLAG}. See scanner/README.md.`;

function loadScope(file, today) {
  if (!file) return { error: "a scope file is required (--scope FILE). There is no default target. Start one with: node scanner/cyberview-scan.mjs init" };
  if (!existsSync(file)) return { error: `scope file not found: ${file}` };
  const text = readFileSync(file, "utf8"), r = checkScope(text, { today });
  return { ...r, hash: createHash("sha256").update(text).digest("hex") };
}
const fail = (io, lines, code = 2) => { io.err(["REFUSED: " + lines[0], ...lines.slice(1).map((l) => "  - " + l)].join("\n")); return code; };

/**
 * The command line. io: { out, err, sleep, probe, resolve, fetchImpl, signal } so tests can run it without a terminal.
 * Exit codes: 0 done, 1 error, 2 refused (scope, authorization or limits), 3 the scan stopped early (report still written).
 */
export async function main(argv, io = {}) {
  io = { out: (s) => process.stdout.write(s + "\n"), err: (s) => process.stderr.write(s + "\n"), sleep: (ms) => new Promise((r) => setTimeout(r, ms)), publicWaitMs: 10000, ...io };
  const a = parseArgs(argv), cmd = a._[0], today = new Date().toISOString().slice(0, 10);
  if (!cmd || a.help || cmd === "help") { io.out(USAGE); return cmd ? 0 : 1; }

  if (cmd === "init") {
    const out = a.out || "scope.json";
    if (existsSync(out)) return fail(io, [`${out} already exists; choose another name with --out`], 1);
    writeFileSync(out, JSON.stringify(template(today), null, 2) + "\n", { mode: 0o600 });
    io.out(`Wrote ${out}. Fill in owner, contact and targets (only what you own or are authorized to test), then attest: set attestation.agreed to true and attestation.name to your name. Then: node scanner/cyberview-scan.mjs check --scope ${out}`);
    return 0;
  }

  if (cmd === "data") {
    if (!a.out) return fail(io, ["--out DIR is required (where the snapshot is written)"], 1);
    const src = webSource(a.source || DEFAULT_SOURCE, { fetchImpl: io.fetchImpl });
    io.out(`Downloading CyberView's public data from ${src.where} into ${a.out}${a.full ? " (every CVE lookup file)" : ""}. Read-only GET requests; nothing is uploaded.`);
    const m = await snapshot(src, a.out, D, { full: !!a.full, log: (s) => io.out("  " + s) });
    io.out(`Snapshot ready: ${m.lookup_files} lookup file(s), workbench built ${m.workbench_built_at || "?"}. Scan offline with --data ${a.out}`);
    return 0;
  }

  if (cmd !== "scan" && cmd !== "check") { io.err(USAGE); return 1; }
  // ---- the authorization gate: nothing below runs without a valid scope file and attestation ----
  const sc = loadScope(a.scope, today);
  if (sc.error) return fail(io, [sc.error]);
  if (!sc.ok) return fail(io, ["the scope file does not pass its checks; nothing was scanned", ...sc.problems]);
  const scope = sc.scope, allowPublic = !!a[PUBLIC_FLAG.slice(2)];
  if (scope.needsPublic && !allowPublic) return fail(io, [`the scope includes ${scope.publicCount} public (non-private) address(es); nothing was scanned`,
    `scanning public addresses needs ${PUBLIC_FLAG}: use it only for addresses you own or hold written permission to test`,
    `private ranges (10/8, 172.16/12, 192.168/16, loopback, link-local, IPv6 fc00::/7) run with the scope file alone`]);
  const lim = checkSettings({ rate: a.rate, concurrency: a.concurrency, hostConcurrency: a["host-concurrency"], hostBudget: a["host-budget"], budget: a.budget, minutes: a["max-minutes"] });
  if (!lim.ok) return fail(io, ["limits", ...lim.problems]);
  let ports = scope.ports || DEFAULT_PORTS;
  if (a.ports) { const p = parsePorts(a.ports); if (p.error) return fail(io, ["--ports: " + p.error]); ports = p.ports; }
  const extra = {};
  for (const k of ["http-ports", "https-ports"]) if (a[k]) { const p = parsePorts(a[k]); if (p.error) return fail(io, [`--${k}: ${p.error}`]); extra[k] = p.ports; ports = [...new Set([...ports, ...p.ports])].sort((x, y) => x - y); }
  if (ports.length > 1024) return fail(io, ["at most 1024 ports in one scan"]);
  if (a.data && a.online) return fail(io, ["choose one data source: --data DIR (offline) or --online"], 1);
  if (cmd === "scan" && !a.data && !a.online) return fail(io, ["choose the data source: --data DIR (a snapshot from the data command; nothing but the targets is contacted) or --online (reads CyberView's public data files)"], 1);
  let src = null;
  try { src = a.data ? dirSource(a.data) : a.online ? webSource(a.source || DEFAULT_SOURCE, { fetchImpl: io.fetchImpl }) : null; } catch (e) { return fail(io, [e.message], 1); }
  const dataLine = src ? (src.kind === "offline" ? `offline snapshot ${src.where} (fetched ${(src.manifest && src.manifest.fetched_at) || "?"}); no data request is made` : `online: read-only GET requests to ${src.where} for CyberView's data files`) : "none (check only)";
  io.out(header({ scope, scopeFile: a.scope, scopeHash: sc.hash, settings: lim.settings, allowPublic, ports, data: dataLine, sends: SENDS }));
  if (cmd === "check") { io.out(`\nThe scope file passes its checks (${scope.addressCount} address(es); at most ${LIMITS.maxAddresses}). Nothing was scanned.`); return 0; }

  if (scope.needsPublic) {
    io.err(`\n${"!".repeat(78)}\nWARNING: this scan includes ${scope.publicCount} PUBLIC address(es). Scanning systems you do not own or are not\nauthorized to test may be unlawful. You attested that you are authorized. Starting in ${Math.round(io.publicWaitMs / 1000)} seconds; press Ctrl-C to cancel.\n${"!".repeat(78)}`);
    await io.sleep(io.publicWaitMs);
  }
  // Ctrl-C stops new connections, lets open ones finish and still writes the report; a second Ctrl-C exits at once
  const ac = new AbortController(); let sigs = 0;
  const onSig = () => { sigs++; if (sigs > 1) process.exit(130); io.err("\nStopping: no new connections; writing the report for what was checked. Press Ctrl-C again to quit now."); ac.abort("interrupted (Ctrl-C)"); };
  if (!io.signal) process.on("SIGINT", onSig); else io.signal.addEventListener("abort", () => ac.abort(String(io.signal.reason || "interrupted")), { once: true });
  const startedAt = new Date().toISOString();
  try {
    const { targets, refused } = await resolveScope(scope, { allowPublic, resolve: io.resolve });
    refused.forEach((r) => io.err(`skipped ${r.target}: ${r.why}`));
    io.out(`\nScanning ${targets.length} address(es) on ${ports.length} port(s) ...`);
    const probed = await probeAll(targets, { ports, settings: lim.settings, probe: io.probe, signal: ac.signal, log: (s) => io.out("  " + s), assumeUp: !!a["assume-up"], httpPorts: extra["http-ports"] || [], httpsPorts: extra["https-ports"] || [] });
    const report = await buildReport({ src, scope, scopeFile: a.scope, scopeHash: sc.hash, allowPublic, ports, settings: lim.settings, probed, refused, startedAt, today });
    const out = resolve(a.out || `cyberview-scan-${startedAt.replace(/[-:]/g, "").slice(0, 15)}Z`);
    mkdirSync(out, { recursive: true, mode: 0o700 });
    const w = (f, s) => writeFileSync(join(out, f), s, { mode: 0o600 });
    w("report.json", JSON.stringify(report, null, 2) + "\n"); w("findings.csv", toCsv(report)); w("report.sarif", JSON.stringify(toSarif(report), null, 2) + "\n");
    w("inventory.csv", toInventory(report)); const text = summaryText(report); w("summary.txt", text + "\n");
    io.out("\n" + text + `\n\nReport written to ${out}/ (report.json, findings.csv, report.sarif, inventory.csv, summary.txt). Nothing was uploaded.`);
    return report.run.interrupted ? 3 : 0;
  } finally { if (!io.signal) process.removeListener("SIGINT", onSig); }
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) main(process.argv.slice(2)).then((c) => process.exit(c), (e) => { process.stderr.write(`error: ${e && e.message || e}\n`); process.exit(1); });
