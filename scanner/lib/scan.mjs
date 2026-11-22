// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// One scan: resolve the scope, gate every address, probe politely, fingerprint, match, rate, report.
// The probe and the resolver are passed in so tests can run the whole path on loopback or with stand-ins.
import { lookup } from "node:dns/promises";
import { gate, listAddresses, classify, isPrivateKind, LIMITS, parseTarget, addresses } from "./scope.mjs";
import { Limiter, pool } from "./limits.mjs";
import { probePort as realProbe, DEFAULT_PORTS, VERSION, USER_AGENT, SENDS } from "./probe.mjs";
import { udpProbe as realUdpProbe, UDP_SERVICES, UDP_SENDS } from "./udp.mjs";
import { fromSsh, fromGreeting, fromMysql, fromHttp, fromCert, fromUdp, httpInfo, certInfo, tlsInfo, observations, httpObservations, mailObservations, udpObservations } from "./fingerprint.mjs";
import { cleanFlaws, candidates, findings as matchFindings, named } from "./match.mjs";
import { withPack2 } from "./fp-apps2.mjs";
import { bucketPath } from "./data.mjs";
import { summarize, coverage, isTruncatedBanner } from "./report.mjs";
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

/** The full 65,535-port TCP list for --all-ports (the budgets, not a port cap, bound the work). */
export function allPorts() { return Array.from({ length: 65535 }, (_, i) => i + 1); }

/** The services one probed port revealed. */
export function servicesOf(r) {
  const out = [];
  if (r.tls && r.tls.cert) out.push(...fromCert(r.tls.cert, r.port));
  if (r.http) out.push(...fromHttp(r.http, r.port, !!r.tls));
  if (r.raw) out.push(...fromMysql(r.raw, r.port));
  if (!out.length && r.banner) out.push(...(/^SSH-/.test(r.banner) ? fromSsh(r.banner, r.port) : fromGreeting(r.banner, r.port)));
  out.splice(0, out.length, ...withPack2(out, r));   // scan-app-versions pack 2: passive, from data already collected (fp-apps2.mjs)
  // a product stated with a version wins over the same product inferred from a certificate
  return out.filter((s, i) => !(s.guessed && out.some((o, j) => j !== i && !o.guessed && o.product === s.product)));
}

/**
 * Resolve and gate the scope, then any hosts/addresses discovery proposed. EVERY address goes through the scope gate, so a
 * discovered IP, subdomain, swept address or cloud asset outside the attested scope (or public without the flag) is dropped
 * and logged, never scanned. The public cap is the hard stop for public space: if the gated set would hold more than
 * LIMITS.maxPublicAddresses public addresses, the scan STOPS (stop is set) rather than silently scanning fewer.
 * discovered: { hosts: [{host, source}], ips: [{ip, source}], ranges: [{cidr, source}] } from discover.runDiscovery (optional).
 * -> { targets: [{ address, names[], kind, public, source }], refused: [{ target, why }], stop }
 */
export async function resolveScope(scope, { allowPublic = false, resolve = (h) => lookup(h, { all: true, verbatim: true }), discovered = null } = {}) {
  const map = new Map(), refused = [];
  const add = (ip, name, source) => {
    const g = gate(scope, ip, { allowPublic, viaHost: name });
    if (!g.ok) { refused.push({ target: name ? `${name} (${ip})` : ip, why: g.why + (source && source !== "scope" ? ` [${source}]` : "") }); return; }
    if (!map.has(ip)) map.set(ip, { address: ip, names: [], kind: g.kind, public: !isPrivateKind(g.kind), source: source || "scope" });
    const e = map.get(ip); if (name && !e.names.includes(name)) e.names.push(name);
  };
  for (const ip of listAddresses(scope)) add(ip, "", "scope");
  const hostSeeds = [...scope.hosts.map((h) => ({ host: h, source: "scope" })), ...((discovered && discovered.hosts) || [])];
  const seen = new Set();
  for (const { host, source } of hostSeeds) {
    if (seen.has(host)) continue; seen.add(host);
    let res = [];
    try { res = await resolve(host); } catch (e) { refused.push({ target: host, why: `could not be resolved (${String(e.code || e.message).slice(0, 40)})${source && source !== "scope" ? ` [${source}]` : ""}` }); continue; }
    for (const r of (res || []).slice(0, 16)) add(r.address, host, source);
  }
  for (const { ip, source } of (discovered && discovered.ips) || []) add(ip, "", source);
  for (const { cidr, source } of (discovered && discovered.ranges) || []) { const t = parseTarget(cidr); if (!t.error) for (const ip of addresses(t)) add(ip, "", source); }
  // the public cap: the hard stop for public space, counted AFTER discovery
  const targets = [...map.values()], publicCount = targets.filter((t) => t.public).length;
  let stop = "";
  if (publicCount > LIMITS.maxPublicAddresses) stop = `discovery would scan ${publicCount} public addresses, over the hard cap of ${LIMITS.maxPublicAddresses}; narrow the scope or the discovery sources. Nothing was scanned.`;
  return { targets, refused, stop, publicCount };
}

/**
 * Probe every target. -> { hosts, stats, interrupted, stop_reason }
 * opts: { ports, settings, probe, signal (an AbortSignal the caller aborts on Ctrl-C), log, clock, assumeUp,
 *         inScope (host -> bool: is a redirect target inside the attested scope? used only to label it, never to follow it) }
 */
// throttle handling: how many connection resets on an already-answering host trigger a single back-off and gentle retry
const THROTTLE = { minResets: 3, backoffMs: 8000, maxRetry: 50 };
// observations kept per host (the rest are counted in observations_dropped, never silently lost)
export const OBS_PER_HOST = 60;

export async function probeAll(targets, { ports = DEFAULT_PORTS, settings, probe = realProbe, signal = null, log = () => {}, clock, assumeUp = false, httpPorts = [], httpsPorts = [], udp = [], udpProbe = realUdpProbe, inScope = () => false }) {
  const lim = new Limiter(settings, clock), ac = new AbortController();
  const udpKeys = (Array.isArray(udp) ? udp : udp ? Object.keys(UDP_SERVICES) : []).filter((k) => UDP_SERVICES[k]);
  const stopAll = (why) => { lim.stop(why); ac.abort(); };
  if (signal) { if (signal.aborted) stopAll(String(signal.reason || "interrupted")); signal.addEventListener("abort", () => stopAll(String(signal.reason || "interrupted")), { once: true }); }
  const timer = setTimeout(() => stopAll("time limit reached"), Math.max(0, lim.remainingMs()));
  const hosts = targets.map((t) => ({ ...t, up: false, ports: [], services: [], observations: [], http: [], tls: [], udp: [], outcomes: [] }));
  const one = async (h, port) => {
    const release = await lim.acquire(h.address);
    if (!release) return false;   // budget or time ran out: the port is left unchecked (coverage counts it)
    try {
      const r = await probe(h.address, port, { servername: h.names[0] || "", hostHeader: h.names[0] || "", signal: ac.signal, httpPorts, httpsPorts });
      // record EVERY outcome, not just open ports, so a filtered/errored/truncated probe can never read as "nothing here"
      h.outcomes.push({ port, state: r.state, error: r.error || "", truncated: r.state === "open" && isTruncatedBanner(r.banner) });
      if (r.state === "open" || r.state === "closed") h.up = true;
      if (r.state !== "open") return true;
      const svcs = servicesOf(r);
      h.ports.push({ port, state: "open", services: svcs.length, banner: r.banner ? r.banner.split(/\r?\n/)[0].replace(/[^ -~]/g, "?").slice(0, 160) : "" });
      h.services.push(...svcs);
      if (r.http) h.http.push({ port, ...httpInfo(r.http) });
      if (r.tls) h.tls.push({ port, ...tlsInfo(r.tls), cert: certInfo(r.tls.cert) });
      // capped per host so one noisy host cannot bury the rest of the report (the cap is noted when reached)
      const obs = [...observations(port, { banner: r.banner, cert: r.tls && r.tls.cert, tls: r.tls, names: h.names }),
        ...(r.http ? httpObservations(port, r.http, { tls: !!r.tls, inScope: (host) => host === h.address || h.names.includes(host.toLowerCase()) || inScope(host) }) : []),
        ...mailObservations(port, r.banner, { tls: !!r.tls })];
      const room = OBS_PER_HOST - h.observations.length;
      if (room > 0) h.observations.push(...obs.slice(0, room));
      if (obs.length > room) h.observations_dropped = (h.observations_dropped || 0) + obs.length - Math.max(0, room);
      return true;
    } finally { release(); }
  };
  // one benign UDP query per service per host (the single datagram lives in udp.mjs); it takes a Limiter slot like a connection
  const oneUdp = async (h, key) => {
    const release = await lim.acquire(h.address);
    if (!release) return false;
    try {
      const r = await udpProbe(h.address, key, { signal: ac.signal });
      h.udp.push({ port: r.port, proto: r.proto, state: r.state, parsed: r.parsed, error: r.error });
      if (r.state === "open") { h.up = true; h.services.push(...fromUdp(r)); h.observations.push(...udpObservations(r)); }
      return true;
    } finally { release(); }
  };
  try {
    await pool(hosts, settings.concurrency, async (h) => {
      const first = assumeUp ? [] : discoveryPorts(ports);
      for (const p of first) { await one(h, p); }
      // Probe the rest even when the discovery ports gave no answer: a firewall or IPS that drops the first few ports
      // must not let a host be written off after only 3-4 probes. A host that answers nowhere is reported as an
      // unreachable coverage gap, never as a clean result. (The Limiter still caps probes by host/total budget and time.)
      const rest = ports.filter((p) => !first.includes(p));
      await pool(rest, settings.hostConcurrency, async (p) => { await one(h, p); });
      // Throttle (IPS/fail2ban): a host that answered, then reset several connections, is likely blocking the scan. Back
      // off once (the Limiter's clock, so an injected clock makes tests instant) and re-probe those ports one at a time;
      // a throttled host must not silently hide the services behind the block.
      if (h.up && !assumeUp) {
        const resets = [...new Set(h.outcomes.filter((o) => /reset|ECONNRESET/i.test(o.error || "")).map((o) => o.port))];
        if (resets.length >= THROTTLE.minResets) {
          h.throttled = resets.length;
          const retry = resets.slice(0, THROTTLE.maxRetry);
          log(`${h.address}: ${resets.length} connection reset(s) after the host answered — likely throttling (IPS/fail2ban); backing off, then re-probing ${retry.length} port(s) one at a time`);
          if (!lim.stopped) await lim.clock.sleep(Math.min(THROTTLE.backoffMs, lim.remainingMs()));
          const before = h.ports.length;
          await pool(retry, 1, async (p) => { await one(h, p); });
          h.throttle_recovered = h.ports.length - before;
          if (h.throttle_recovered > 0) log(`${h.address}: ${h.throttle_recovered} service(s) found after backing off — the first pass was being throttled`);
        }
      }
      // UDP checks run even when TCP found nothing: a host can answer only on UDP (one benign datagram per service)
      if (udpKeys.length) await pool(udpKeys, settings.hostConcurrency, async (k) => { await oneUdp(h, k); });
      if (!h.up) { const filtered = h.outcomes.filter((o) => o.state === "filtered").length;
        log(`${h.address}: no answer on ${h.outcomes.length} TCP port(s) (${filtered} filtered/dropped)${udpKeys.length ? " or UDP" : ""}; unreachable — a coverage gap, not a clean result`); return; }
      h.ports.sort((a, b) => a.port - b.port); h.services.sort((a, b) => a.port - b.port); h.udp.sort((a, b) => a.port - b.port);
      log(`${h.address}${h.names.length ? ` (${h.names.join(", ")})` : ""}: ${h.ports.length} open TCP port(s)${udpKeys.length ? `, ${h.udp.filter((u) => u.state === "open").length} UDP service(s)` : ""}, ${h.services.length} service(s) identified`);
    });
  } finally { clearTimeout(timer); }
  const st = lim.stats();
  return { hosts, stats: st, interrupted: !!st.stopped, stop_reason: st.stopped, udp: udpKeys };
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
      udp: probed.udp || [], network: { ...probed.stats, sends: { ...SENDS, ...((probed.udp || []).length ? Object.fromEntries((probed.udp).map((k) => [`udp-${k}`, UDP_SENDS[k]])) : {}) } },
      data: { mode: src.kind, source: src.where, workbench_built_at: (wb && wb.built_at) || "", requests: (src.log || []).length, snapshot: src.manifest || null } },
    scope: { file: scopeFile, sha256: scopeHash, owner: scope.owner, contact: scope.contact, attestation: scope.attestation, targets: scope.targets.map((t) => t.text), exclude: scope.exclude.map((t) => t.text),
      public_addresses: scope.publicCount, public_confirmed: !!allowPublic, refused },
    summary: summarize(hosts, found),
    coverage: coverage(hosts, { ports, interrupted: probed.interrupted, stop_reason: probed.stop_reason }),
    hosts: hosts.map((h) => ({ address: h.address, names: h.names, kind: h.kind, public: h.public, up: h.up, source: h.source || "scope", ports: h.ports, services: h.services, http: h.http, tls: h.tls, udp: h.udp || [], observations: h.observations, ...(h.observations_dropped ? { observations_dropped: h.observations_dropped } : {}) })),
    findings: found, named: namedList, notes,
  };
}
export { classify };
