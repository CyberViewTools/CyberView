// One scan: resolve the scope, gate every address, probe politely, fingerprint, match, rate, report.
// The probe and the resolver are passed in so tests can run the whole path on loopback or with stand-ins.
import { lookup } from "node:dns/promises";
import { gate, listAddresses, classify, isPrivateKind } from "./scope.mjs";
import { Limiter, pool } from "./limits.mjs";
import { probePort as realProbe, DEFAULT_PORTS, VERSION, USER_AGENT, SENDS } from "./probe.mjs";
import { fromSsh, fromGreeting, fromMysql, fromHttp, fromCert, httpInfo, certInfo, observations } from "./fingerprint.mjs";
import { cleanFlaws, candidates, findings as matchFindings, named } from "./match.mjs";
import { bucketPath } from "./data.mjs";
import { summarize } from "./report.mjs";
import { D } from "./shared.mjs";

/** "22,80,8000-8010" -> sorted unique ports, or { error } */
export function parsePorts(s) {
  const out = new Set();
  for (const part of String(s || "").split(",").map((x) => x.trim()).filter(Boolean)) {
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(part);
    if (!m) return { error: `"${part}" is not a port or a port range` };
    const a = +m[1], b = m[2] ? +m[2] : a;
    if (a < 1 || b > 65535 || b < a) return { error: `"${part}" is outside 1-65535` };
    for (let p = a; p <= b; p++) { out.add(p); if (out.size > 1024) return { error: "at most 1024 ports in one scan" }; }
  }
  return out.size ? { ports: [...out].sort((x, y) => x - y) } : { error: "no ports given" };
}

/** Ports that tell whether a host is there before the rest are tried. */
export function discoveryPorts(ports) { const d = [22, 80, 443, 3389].filter((p) => ports.includes(p)); return d.length ? d : ports.slice(0, 3); }

/** The services one probed port revealed. */
export function servicesOf(r) {
  const out = [];
  if (r.tls && r.tls.cert) out.push(...fromCert(r.tls.cert, r.port));
  if (r.http) out.push(...fromHttp(r.http, r.port, !!r.tls));
  if (r.raw) out.push(...fromMysql(r.raw, r.port));
  if (!out.length && r.banner) out.push(...(/^SSH-/.test(r.banner) ? fromSsh(r.banner, r.port) : fromGreeting(r.banner, r.port)));
  // a product stated with a version wins over the same product inferred from a certificate
  return out.filter((s, i) => !(s.guessed && out.some((o, j) => j !== i && !o.guessed && o.product === s.product)));
}

/**
 * Resolve and gate the scope. -> { targets: [{ address, names[], kind, public }], refused: [{ target, why }] }
 */
export async function resolveScope(scope, { allowPublic = false, resolve = (h) => lookup(h, { all: true, verbatim: true }) } = {}) {
  const map = new Map(), refused = [];
  const add = (ip, name) => { const g = gate(scope, ip, { allowPublic, viaHost: name }); if (!g.ok) { refused.push({ target: name ? `${name} (${ip})` : ip, why: g.why }); return; }
    if (!map.has(ip)) map.set(ip, { address: ip, names: [], kind: g.kind, public: !isPrivateKind(g.kind) }); if (name && !map.get(ip).names.includes(name)) map.get(ip).names.push(name); };
  for (const ip of listAddresses(scope)) add(ip, "");
  for (const h of scope.hosts) {
    let res = [];
    try { res = await resolve(h); } catch (e) { refused.push({ target: h, why: `could not be resolved (${String(e.code || e.message).slice(0, 40)})` }); continue; }
    for (const r of (res || []).slice(0, 16)) add(r.address, h);
  }
  return { targets: [...map.values()], refused };
}

/**
 * Probe every target. -> { hosts, stats, interrupted, stop_reason }
 * opts: { ports, settings, probe, signal (an AbortSignal the caller aborts on Ctrl-C), log, clock, assumeUp }
 */
export async function probeAll(targets, { ports = DEFAULT_PORTS, settings, probe = realProbe, signal = null, log = () => {}, clock, assumeUp = false, httpPorts = [], httpsPorts = [] }) {
  const lim = new Limiter(settings, clock), ac = new AbortController();
  const stopAll = (why) => { lim.stop(why); ac.abort(); };
  if (signal) { if (signal.aborted) stopAll(String(signal.reason || "interrupted")); signal.addEventListener("abort", () => stopAll(String(signal.reason || "interrupted")), { once: true }); }
  const timer = setTimeout(() => stopAll("time limit reached"), Math.max(0, lim.remainingMs()));
  const hosts = targets.map((t) => ({ ...t, up: false, ports: [], services: [], observations: [], http: [], tls: [] }));
  const one = async (h, port) => {
    const release = await lim.acquire(h.address);
    if (!release) return false;
    try {
      const r = await probe(h.address, port, { servername: h.names[0] || "", hostHeader: h.names[0] || "", signal: ac.signal, httpPorts, httpsPorts });
      if (r.state === "open" || r.state === "closed") h.up = true;
      if (r.state !== "open") return true;
      const svcs = servicesOf(r);
      h.ports.push({ port, state: "open", services: svcs.length, banner: r.banner ? r.banner.split(/\r?\n/)[0].replace(/[^ -~]/g, "?").slice(0, 160) : "" });
      h.services.push(...svcs);
      if (r.http) h.http.push({ port, ...httpInfo(r.http) });
      if (r.tls) h.tls.push({ port, protocol: r.tls.protocol, cipher: r.tls.cipher, cert: certInfo(r.tls.cert) });
      h.observations.push(...observations(port, { banner: r.banner, cert: r.tls && r.tls.cert }));
      return true;
    } finally { release(); }
  };
  try {
    await pool(hosts, settings.concurrency, async (h) => {
      const first = assumeUp ? [] : discoveryPorts(ports);
      for (const p of first) { if (!(await one(h, p))) return; }
      if (!assumeUp && !h.up) { log(`${h.address}: no answer on ${first.join(", ")}; treated as down`); return; }
      const rest = ports.filter((p) => !first.includes(p));
      await pool(rest, settings.hostConcurrency, async (p) => { await one(h, p); });
      h.ports.sort((a, b) => a.port - b.port); h.services.sort((a, b) => a.port - b.port);
      log(`${h.address}${h.names.length ? ` (${h.names.join(", ")})` : ""}: ${h.ports.length} open port(s), ${h.services.length} service(s) identified`);
    });
  } finally { clearTimeout(timer); }
  const st = lim.stats();
  return { hosts, stats: st, interrupted: !!st.stopped, stop_reason: st.stopped };
}

/** Load CyberView's data, match, rate and assemble the report. */
export async function buildReport({ src, scope, scopeFile, scopeHash, allowPublic, ports, settings, probed, refused, startedAt, today = new Date().toISOString().slice(0, 10) }) {
  const wb = await src.json("data/workbench.json");
  const ps = await src.json("data/psirt.json", { optional: true });
  D.vendorIndex = ps ? D.cleanVendorIndex(ps) : {};
  const flaws = cleanFlaws(wb), hosts = probed.hosts;
  const want = candidates(hosts, flaws), rows = new Map(), files = new Map();
  for (const id of want) {
    const p = bucketPath(D, id); if (!p) continue;
    if (!files.has(p)) files.set(p, await src.json(p, { optional: true }).then((j) => (j ? D.parseFile(j) : []), () => []));
    const r = files.get(p).find((x) => x.id === id); if (r) rows.set(id, r);
  }
  const found = matchFindings(hosts, flaws, rows, { today });
  // the whole CVE List, only from a full offline snapshot: other CVEs that name a detected product (versions not checked)
  let namedList = [];
  if (src.kind === "offline" && src.manifest && src.manifest.full) {
    const idx = await src.json("data/cve/index.json", { optional: true }), all = [];
    for (const [y, list] of Object.entries((idx && idx.files_by_year) || {})) for (const n of list || []) { const j = await src.json(`data/cve/${y}/${n}.json`, { optional: true }); if (j) all.push(...D.parseFile(j)); }
    namedList = named(hosts, all, { skip: new Set(found.map((f) => f.cve)) });
  }
  const notes = [
    "Detection only: versions were read from what each service states about itself. A service can hide or misstate its version, and a Linux distribution's package can carry a backported fix under an old version number; confidence says which.",
    "Matching uses CyberView's known-exploited flaws (CISA's KEV catalog with NVD's affected-version ranges) and recent high-risk flaws; a flaw outside them is not reported. A clean result is not proof that a host has no vulnerabilities.",
    "The CyberView rating is the CVSS base score adjusted for exploitation evidence (CVSS v3.1 Exploit Code Maturity), the same calculation as the Vulnerabilities page; every point is listed with each finding.",
    "Exploitation analyses and fix guides on the linked pages are written by CyberView AI (a Claude model) from vendor and government sources.",
  ];
  if (rows.size < want.length) notes.push(`${want.length - rows.size} matched CVE(s) had no CVE lookup row in the data used; their rating is computed from the KEV entry alone (marked in each finding).`);
  return {
    tool: { name: "CyberView Scanner", version: VERSION, user_agent: USER_AGENT, detection_only: true },
    run: { started_at: startedAt, finished_at: new Date().toISOString(), interrupted: probed.interrupted, stop_reason: probed.stop_reason, settings, ports,
      network: { ...probed.stats, sends: SENDS }, data: { mode: src.kind, source: src.where, workbench_built_at: (wb && wb.built_at) || "", requests: (src.log || []).length, snapshot: src.manifest || null } },
    scope: { file: scopeFile, sha256: scopeHash, owner: scope.owner, contact: scope.contact, attestation: scope.attestation, targets: scope.targets.map((t) => t.text), exclude: scope.exclude.map((t) => t.text),
      public_addresses: scope.publicCount, public_confirmed: !!allowPublic, refused },
    summary: summarize(hosts, found),
    hosts: hosts.map((h) => ({ address: h.address, names: h.names, kind: h.kind, public: h.public, up: h.up, ports: h.ports, services: h.services, http: h.http, tls: h.tls, observations: h.observations })),
    findings: found, named: namedList, notes,
  };
}
export { classify };
