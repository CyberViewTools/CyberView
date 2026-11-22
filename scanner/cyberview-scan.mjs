#!/usr/bin/env node
// CyberView Scanner: finds known-vulnerable software on YOUR OWN network and ranks what to patch first, using CyberView's
// published CVE, KEV and EPSS data and the CyberView rating. Detection only: it reads the versions services state about
// themselves and matches them; it never exploits, logs in, guesses passwords, floods or hides. No AI model.
// Copyright (c) 2026 xanderhutch. All rights reserved. Proprietary licence (scanner/LICENSE), not the
// repository's MIT licence. Download and use on systems you own or are authorised to test; no redistribution.
// Read scanner/README.md first. Commands:
//   init  [--out scope.json]                  write a scope file to fill in (targets, owner, your attestation)
//   check --scope FILE [--i-am-authorized-for-public-ranges]   check the scope file and show what a scan would do; no network
//   data  --out DIR [--source URL] [--full]   download CyberView's data for offline (air-gapped) scans
//   match (--sbom FILE | --nmap FILE | --list FILE) (--data DIR | --online) [--out DIR] [--assume-exposed]
//   diff  --before report.json --after report.json [--out DIR]
//   scan  --scope FILE (--data DIR | --online [--source URL]) [--ports LIST] [--out DIR] [--assume-up]
//         [--http-ports LIST] [--https-ports LIST] (web services on non-standard ports)
//         [--rate N] [--concurrency N] [--host-concurrency N] [--host-budget N] [--budget N] [--max-minutes N]
//         [--i-am-authorized-for-public-ranges]
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { checkScope, template, PUBLIC_FLAG, LIMITS, hostInScope, inScope as ipInScope } from "./lib/scope.mjs";
import { isIP } from "node:net";
import { settings as checkSettings, CAPS } from "./lib/limits.mjs";
import { DEFAULT_PORTS, SENDS, VERSION } from "./lib/probe.mjs";
import { UDP_SERVICES, UDP_SENDS } from "./lib/udp.mjs";
import { webSource, dirSource, snapshot, DEFAULT_SOURCE } from "./lib/data.mjs";
import { parsePorts, resolveScope, probeAll, buildReport, allPorts } from "./lib/scan.mjs";
import { PATH_SEND } from "./lib/paths.mjs";
import { runDiscovery } from "./lib/discover.mjs";
import { header, toCsv, toSarif, toInventory, summaryText } from "./lib/report.mjs";
import { toCertsCsv } from "./lib/certs.mjs";
import { toCbom } from "./lib/cbom.mjs";
import { cryptoNotes } from "./lib/sbom-crypto.mjs";
import { pqcCurveAvailable } from "./lib/probe.mjs";
import { toHtml, diffHtml } from "./lib/html.mjs";
import { readInventory, MAX_BYTES } from "./lib/inputs.mjs";
import { diffReports, diffText } from "./lib/diff.mjs";
import { D } from "./lib/shared.mjs";

const BOOL = new Set(["online", "full", "assume-up", "assume-exposed", "help", "all-ports", "udp", "paths", "well-known", "data-incidents", "tls-legacy", PUBLIC_FLAG.slice(2)]);
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
  node scanner/cyberview-scan.mjs match --list software.txt --data cyberview-data   (no target is contacted)
  node scanner/cyberview-scan.mjs diff  --before old/report.json --after new/report.json
  node scanner/cyberview-scan.mjs scan  --scope scope.json --data cyberview-data      (offline)
  node scanner/cyberview-scan.mjs scan  --scope scope.json --online                   (reads CyberView's public data)
Depth: --all-ports (every TCP port 1-65535, private ranges only), --udp (read-only DNS, NTP and SNMP service checks).
Discovery (optional, in the scope file's "discover"): cidr sweep, owned domains (with Certificate Transparency), an imported
asset list (host/IP list, CSV, nmap -oX XML), and your own read-only cloud inventory JSON; every host found is re-checked
against the scope before it is scanned.
Limits can be lowered, never raised: --rate (max ${CAPS.rate}/s), --concurrency (max ${CAPS.concurrency}), --host-concurrency (max ${CAPS.hostConcurrency}),
--host-budget, --budget (both scale for owned private ranges), --max-minutes (default 60, max ${CAPS.minutes}).
Public (non-private) addresses also need ${PUBLIC_FLAG} and stay capped at ${LIMITS.maxPublicAddresses}. See scanner/README.md.`;

function loadScope(file, today) {
  if (!file) return { error: "a scope file is required (--scope FILE). There is no default target. Start one with: node scanner/cyberview-scan.mjs init" };
  if (!existsSync(file)) return { error: `scope file not found: ${file}` };
  const text = readFileSync(file, "utf8"), r = checkScope(text, { today });
  return { ...r, hash: createHash("sha256").update(text).digest("hex") };
}
const fail = (io, lines, code = 2) => { io.err(["REFUSED: " + lines[0], ...lines.slice(1).map((l) => "  - " + l)].join("\n")); return code; };

/** Opt-in incidents index inside an offline snapshot. Absent file -> { missing: true }, never a network request. */
function readIncidents(dir, io) {
  const p = join(dir, "data", "incidents.json");
  if (!existsSync(p)) return { events: [], missing: true };
  try {
    const j = JSON.parse(io.readFile(p));
    return j && typeof j === "object" ? j : { events: [] };
  } catch { return { events: [], missing: true }; }
}

function writeReportFiles(dir, report) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const w = (f, s) => writeFileSync(join(dir, f), s, { mode: 0o600 });
  w("report.json", JSON.stringify(report, null, 2) + "\n");
  w("findings.csv", toCsv(report));
  w("report.sarif", JSON.stringify(toSarif(report), null, 2) + "\n");
  w("inventory.csv", toInventory(report));
  w("summary.txt", summaryText(report) + "\n");
  w("report.html", toHtml(report));
  w("certs.csv", toCertsCsv(report.hosts));
  w("cbom.json", JSON.stringify(toCbom(report), null, 2) + "\n");
  if (Array.isArray(report.crypto)) w("crypto.json", JSON.stringify(report.crypto, null, 2) + "\n");
}

/** `match` reads a file the operator already has. It never calls the probe. */
async function matchCmd(a, io, today) {
  const which = [["sbom", a.sbom], ["nmap", a.nmap], ["list", a.list]].filter(([, v]) => v);
  if (which.length !== 1) return fail(io, ["name exactly one input: --sbom FILE, --nmap FILE or --list FILE"], 1);
  if (a.data && a.online) return fail(io, ["choose one data source: --data DIR (offline) or --online"], 1);
  if (!a.data && !a.online) return fail(io, ["choose the data source: --data DIR or --online. No target is contacted either way."], 1);
  const [kind, file] = which[0];
  if (!existsSync(file)) return fail(io, [`input not found: ${file}`], 1);
  const text = io.readFile(file);
  if (String(text || "").length > MAX_BYTES) return fail(io, [`${file} is larger than ${MAX_BYTES} bytes; split it`], 1);
  let src = null;
  try { src = a.data ? dirSource(a.data) : webSource(a.source || DEFAULT_SOURCE, { fetchImpl: io.fetchImpl }); }
  catch (e) { return fail(io, [e.message], 1); }
  const read = readInventory(text, { file, assumeExposed: !!a["assume-exposed"], format: kind === "list" ? "list" : kind });
  const hosts = read.hosts;
  const startedAt = new Date().toISOString();
  const scope = {
    owner: "offline match (no target contacted)", contact: "",
    attestation: { statement: "No target was contacted. The input is a file the operator already holds.", name: "match", date: today, expires: "", authorization_ref: "" },
    targets: [{ text: file }], exclude: [], hosts: [],
    publicCount: hosts.filter((h) => h.public).length, addressCount: hosts.length, needsPublic: false,
  };
  const probed = { hosts, interrupted: false, stop_reason: "", udp: [], stats: { connections: 0, max_open_at_once: 0, skipped_host_budget: 0, skipped_global_budget: 0, stopped: "" } };
  const report = await buildReport({
    src, scope, scopeFile: file, scopeHash: createHash("sha256").update(String(text)).digest("hex"), allowPublic: !!a["assume-exposed"],
    ports: [], settings: { match: true }, probed, refused: [], startedAt, today,
    sends: { match: "nothing: the match command reads a local file and contacts no target" },
  });
  report.crypto = cryptoNotes(hosts.flatMap((h) => h.services || []));
  if (report.crypto.some((n) => n.past_support)) report.notes.unshift("An imported component names OpenSSL or libssl below 3.0, which is past the project's published end of support (11 September 2023).");
  report.notes.unshift("Match read a local file only. No address was resolved and no target was contacted.");
  if (a["assume-exposed"]) report.notes.unshift("--assume-exposed: every component is treated as internet-facing for the SSVC exposure answer. The rating itself does not change.");
  read.problems.forEach((p) => report.notes.push(p));
  if (!hosts.some((h) => (h.services || []).length)) report.notes.push("No named product was read from the input.");
  const out = resolve(a.out || `cyberview-match-${startedAt.replace(/[-:]/g, "").slice(0, 15)}Z`);
  writeReportFiles(out, report);
  const textOut = summaryText(report);
  io.out(textOut + `\n\nReport written to ${out}/ (report.json, report.html, findings.csv, report.sarif, inventory.csv, summary.txt). Nothing was contacted and nothing was uploaded.`);
  return 0;
}

/** `diff` compares two reports already on disk. It does not scan again and it sends nothing. */
function diffCmd(a, io) {
  if (!a.before || !a.after) return fail(io, ["--before FILE and --after FILE are required (two report.json files)"], 1);
  const load = (f) => {
    if (!existsSync(f)) return { error: `not found: ${f}` };
    const text = io.readFile(f);
    if (String(text || "").length > MAX_BYTES) return { error: `${f} is larger than ${MAX_BYTES} bytes` };
    try { return { report: JSON.parse(text) }; } catch { return { error: `${f} is not JSON` }; }
  };
  const b = load(a.before), c = load(a.after);
  if (b.error) return fail(io, [b.error], 1);
  if (c.error) return fail(io, [c.error], 1);
  if (!b.report || typeof b.report !== "object" || !c.report || typeof c.report !== "object") return fail(io, ["each file must be a scanner report object"], 1);
  const diff = diffReports(b.report, c.report);
  const out = resolve(a.out || ".");
  mkdirSync(out, { recursive: true, mode: 0o700 });
  const w = (f, s) => writeFileSync(join(out, f), s, { mode: 0o600 });
  w("diff.json", JSON.stringify(diff, null, 2) + "\n");
  const text = diffText(diff);
  w("diff.txt", text + "\n");
  w("diff.html", diffHtml(diff));
  io.out(text + `\n\nDiff written to ${out}/ (diff.json, diff.txt, diff.html). Nothing was contacted.`);
  return 0;
}

/**
 * The command line. io: { out, err, sleep, probe, resolve, fetchImpl, signal } so tests can run it without a terminal.
 * Exit codes: 0 done, 1 error, 2 refused (scope, authorization or limits), 3 the scan stopped early (report still written).
 */
export async function main(argv, io = {}) {
  io = { out: (s) => process.stdout.write(s + "\n"), err: (s) => process.stderr.write(s + "\n"), sleep: (ms) => new Promise((r) => setTimeout(r, ms)), readFile: (f) => readFileSync(f, "utf8"), publicWaitMs: 10000, ...io };
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

  if (cmd === "match") return matchCmd(a, io, today);
  if (cmd === "diff") return diffCmd(a, io);

  if (cmd !== "scan" && cmd !== "check") { io.err(USAGE); return 1; }
  // ---- the authorization gate: nothing below runs without a valid scope file and attestation ----
  const sc = loadScope(a.scope, today);
  if (sc.error) return fail(io, [sc.error]);
  if (!sc.ok) return fail(io, ["the scope file does not pass its checks; nothing was scanned", ...sc.problems]);
  const scope = sc.scope, allowPublic = !!a[PUBLIC_FLAG.slice(2)];
  if (scope.needsPublic && !allowPublic) return fail(io, [`the scope includes ${scope.publicCount} public (non-private) address(es); nothing was scanned`,
    `scanning public addresses needs ${PUBLIC_FLAG}: use it only for addresses you own or hold written permission to test`,
    `private ranges (10/8, 172.16/12, 192.168/16, loopback, link-local, IPv6 fc00::/7) run with the scope file alone`]);
  const lim = checkSettings({ rate: a.rate, concurrency: a.concurrency, hostConcurrency: a["host-concurrency"], hostBudget: a["host-budget"], budget: a.budget, minutes: a["max-minutes"] }, { hasPublic: allowPublic });
  if (!lim.ok) return fail(io, ["limits", ...lim.problems]);
  const udp = a.udp ? Object.keys(UDP_SERVICES) : [];
  let ports = scope.ports || DEFAULT_PORTS;
  const extra = {};
  if (a["all-ports"]) {
    if (allowPublic) return fail(io, ["--all-ports scans every TCP port and is allowed only for owned private ranges; it refuses a scope with public addresses"]);
    if (a.ports) return fail(io, ["choose either --all-ports or --ports, not both"]);
    ports = allPorts();
  } else if (a.ports) { const p = parsePorts(a.ports); if (p.error) return fail(io, ["--ports: " + p.error]); ports = p.ports; }
  for (const k of ["http-ports", "https-ports"]) if (a[k]) { const p = parsePorts(a[k]); if (p.error) return fail(io, [`--${k}: ${p.error}`]); extra[k] = p.ports; if (!a["all-ports"]) ports = [...new Set([...ports, ...p.ports])].sort((x, y) => x - y); }
  if (!a["all-ports"] && ports.length > 1024) return fail(io, ["at most 1024 ports in one scan (use --all-ports for a full TCP sweep of owned private ranges)"]);
  if (a.data && a.online) return fail(io, ["choose one data source: --data DIR (offline) or --online"], 1);
  if (cmd === "scan" && !a.data && !a.online) return fail(io, ["choose the data source: --data DIR (a snapshot from the data command; nothing but the targets is contacted) or --online (reads CyberView's public data files)"], 1);
  let src = null;
  try { src = a.data ? dirSource(a.data) : a.online ? webSource(a.source || DEFAULT_SOURCE, { fetchImpl: io.fetchImpl }) : null; } catch (e) { return fail(io, [e.message], 1); }
  const dataLine = src ? (src.kind === "offline" ? `offline snapshot ${src.where} (fetched ${(src.manifest && src.manifest.fetched_at) || "?"}); no data request is made` : `online: read-only GET requests to ${src.where} for CyberView's data files`) : "none (check only)";
  const sends = { ...SENDS };
  if (a.paths || a["well-known"]) sends.paths = PATH_SEND;
  if (a["tls-legacy"]) sends.legacy = "one extra TLS 1.0-only handshake per TLS port that answered, off unless this flag is set; a failure is not proof the server refuses TLS 1.0";
  io.out(header({ scope, scopeFile: a.scope, scopeHash: sc.hash, settings: lim.settings, allowPublic, ports, allPorts: !!a["all-ports"], udp, udpSends: UDP_SENDS, data: dataLine, sends }));
  if (cmd === "check") {
    if (scope.discover) io.out(`\nDiscovery is configured (${[scope.discover.cidr ? "cidr sweep" : "", scope.discover.domains.length ? `${scope.discover.domains.length} domain(s)${scope.discover.ct ? " + Certificate Transparency" : ""}` : "", scope.discover.import.length ? `${scope.discover.import.length} import file(s)` : "", scope.discover.cloud.length ? `${scope.discover.cloud.length} cloud inventory file(s)` : ""].filter(Boolean).join(", ") || "nothing"}). Every host it finds is re-checked against this scope at scan time; anything outside it is dropped.`);
    io.out(`\nThe scope file passes its checks (${scope.addressCount} directly listed address(es); at most ${LIMITS.maxAddresses}). Nothing was scanned.`); return 0;
  }

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
    let discovered = null;
    if (scope.discover) {
      io.out("\nDiscovery: finding hosts within the attested scope ...");
      discovered = await runDiscovery(scope, { fetchImpl: io.fetchImpl, readFile: io.readFile, log: (s) => io.out("  " + s) });
      discovered.notes.forEach((n) => io.out("  " + n));
      discovered.problems.forEach((p) => io.err("  discovery: " + p));
    }
    const { targets, refused, stop, publicCount } = await resolveScope(scope, { allowPublic, resolve: io.resolve, discovered });
    if (stop) { io.err("REFUSED: " + stop); return 2; }   // the public cap is the hard stop for public space; nothing was scanned
    refused.forEach((r) => io.err(`skipped ${r.target}: ${r.why}`));
    io.out(`\nScanning ${targets.length} address(es)${publicCount ? ` (${publicCount} public)` : ""} on ${a["all-ports"] ? "all 65535 TCP ports" : ports.length + " port(s)"}${udp.length ? ` plus UDP ${udp.join(", ")}` : ""} ...`);
    const probed = await probeAll(targets, { ports, settings: lim.settings, probe: io.probe, probePath: io.probePath, probeLegacy: io.probeLegacy, udpProbe: io.udpProbe, signal: ac.signal, log: (s) => io.out("  " + s), assumeUp: !!a["assume-up"], httpPorts: extra["http-ports"] || [], httpsPorts: extra["https-ports"] || [], udp,
      paths: !!(a.paths || a["well-known"]), wellKnown: !!a["well-known"], legacy: !!a["tls-legacy"],
      inScope: (host) => (isIP(host) ? ipInScope(scope, host) : hostInScope(scope, host)) });
    let incidents = null;
    if (a["data-incidents"] && a.data) incidents = readIncidents(a.data, io);
    const report = await buildReport({ src, scope, scopeFile: a.scope, scopeHash: sc.hash, allowPublic, ports, settings: lim.settings, probed, refused, startedAt, today, incidents, sends });
    if (a["data-incidents"] && !a.data) report.notes.push("Incident citations need an offline snapshot (--data and --data-incidents). The live site was not asked for them.");
    if (incidents && incidents.missing) report.notes.push("No data/incidents.json in the snapshot, so no incident citations were attached.");
    report.notes.push(pqcCurveAvailable()
      ? "This runtime can name the group X25519MLKEM768. A classical group on the one handshake is not proof the server lacks a post-quantum key exchange."
      : "This runtime cannot offer X25519MLKEM768. A classical group on the one handshake is not proof the server lacks a post-quantum key exchange.");
    const out = resolve(a.out || `cyberview-scan-${startedAt.replace(/[-:]/g, "").slice(0, 15)}Z`);
    writeReportFiles(out, report);
    const text = summaryText(report);
    io.out("\n" + text + `\n\nReport written to ${out}/ (report.json, report.html, findings.csv, report.sarif, inventory.csv, summary.txt). Nothing was uploaded.`);
    // exit codes: 0 clean and complete, 2 coverage incomplete (blind spots — see the COVERAGE section), 3 stopped early
    if (report.run.interrupted) return 3;
    if (report.coverage && !report.coverage.complete) { io.err("\nCoverage incomplete: some hosts or ports could not be checked (see COVERAGE in summary.txt). A clean result does not cover them. Exit 2."); return 2; }
    return 0;
  } finally { if (!io.signal) process.removeListener("SIGINT", onSig); }
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) main(process.argv.slice(2)).then((c) => process.exit(c), (e) => { process.stderr.write(`error: ${e && e.message || e}\n`); process.exit(1); });
