// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Scan diff (tk-diff): this report against a previous report.json the operator names with --compare FILE. PURE: the file is
// read by the command line from the operator's own disk; nothing here touches the network. The previous report is
// untrusted input: only the fields compared are kept, each type-checked and length-limited (cleanReport).
//
// What "fixed" means: a finding is fixed only when the same host and port answered again in this scan and the CVE no longer
// matches. A finding on a port that no longer answers is "gone" (closed or filtered, not proof of a fix), and one on a host
// or port this scan did not reach is "not rechecked". A certificate whose issuer changed is flagged for review, never as a
// compromise. UDP services (--udp) are compared by port number alongside TCP ones.
import { UDP_SERVICES } from "./udp-codec.mjs";

const clip = (s, n) => (typeof s === "string" ? s.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n) : "");
const int = (v, lo, hi) => (Number.isInteger(v) && v >= lo && v <= hi ? v : null);
const arr = (a, n) => (Array.isArray(a) ? a.slice(0, n) : []);
export const DIFF_LIMITS = Object.freeze({ maxBytes: 64 * 1024 * 1024, hosts: 100000, portsPerHost: 65535, perHost: 2000, findings: 20000, seenOn: 2000 });

/** report.json (ours or the previous one) -> the compared fields only. */
export function cleanReport(r) {
  const o = r && typeof r === "object" ? r : {};
  const run = o.run && typeof o.run === "object" ? o.run : {}, cov = o.coverage && typeof o.coverage === "object" ? o.coverage : {};
  const hosts = arr(o.hosts, DIFF_LIMITS.hosts).filter((h) => h && typeof h === "object" && clip(h.address, 45)).map((h) => ({
    address: clip(h.address, 45), names: arr(h.names, 20).map((n) => clip(n, 253).toLowerCase()).filter(Boolean), up: h.up === true,
    ports: [...arr(h.ports, DIFF_LIMITS.portsPerHost), ...arr(h.udp, 10).filter((u) => u && u.state === "open")].map((p) => int(p && p.port, 1, 65535)).filter((p) => p != null),
    services: arr(h.services, DIFF_LIMITS.perHost).filter((s) => s && typeof s === "object" && int(s.port, 0, 65535) != null).map((s) => ({
      port: s.port, product: clip(s.label || [s.vendor, s.product].filter((x) => typeof x === "string" && x).join(" ") || s.product, 120), version: clip(s.shown_version, 40) })).filter((s) => s.product),
    tls: arr(h.tls, DIFF_LIMITS.perHost).filter((t) => t && int(t.port, 1, 65535) != null && t.cert && typeof t.cert === "object").map((t) => ({
      port: t.port, fingerprint256: clip(t.cert.fingerprint256, 95), issuer: clip(t.cert.issuer, 200), subject: clip(t.cert.subject, 200), valid_to: clip(t.cert.valid_to, 10), spki_sha256: clip(t.cert.spki_sha256, 95) })),
    observations: arr(h.observations, DIFF_LIMITS.perHost).filter((x) => x && int(x.port, 0, 65535) != null && clip(x.kind, 60)).map((x) => ({ port: x.port, kind: clip(x.kind, 60), severity: clip(x.severity, 10), text: clip(x.text, 300) })),
  }));
  const findings = arr(o.findings, DIFF_LIMITS.findings).filter((f) => f && /^CVE-\d{4}-\d{4,}$/.test(f.cve || "")).map((f) => ({
    cve: f.cve, title: clip(f.title, 160), kev: f.kev === true,
    seen_on: arr(f.seen_on, DIFF_LIMITS.seenOn).filter((s) => s && clip(s.host, 45) && int(s.port, 0, 65535) != null).map((s) => ({ host: clip(s.host, 45), port: s.port, product: clip(s.product, 120), version: clip(s.shown_version, 40), confidence: clip(s.confidence, 10) })) }));
  const udpPorts = arr(run.udp, 10).map((k) => UDP_SERVICES[k] && UDP_SERVICES[k].port).filter(Boolean);
  return { started_at: clip(run.started_at, 30), ports: [...arr(run.ports, 65535).filter((p) => int(p, 1, 65535) != null), ...udpPorts], interrupted: run.interrupted === true,
    scope_sha256: clip(o.scope && o.scope.sha256, 64),
    not_checked: new Set(arr(cov.ports_not_checked, DIFF_LIMITS.hosts).map((x) => clip(x && x.address, 45)).filter(Boolean)), hosts, findings };
}

/** The text of a previous report.json -> { report } or { error }. Refuses anything that is not a CyberView Scanner report. */
export function loadPrevious(text) {
  const s = typeof text === "string" ? text : Buffer.isBuffer(text) ? text.toString("utf8") : "";
  if (!s) return { error: "the file is empty" };
  if (s.length > DIFF_LIMITS.maxBytes) return { error: `the file is larger than ${DIFF_LIMITS.maxBytes / 1048576} MB` };
  let j; try { j = JSON.parse(s); } catch { return { error: "the file is not JSON (pass a report.json written by this scanner)" }; }
  if (!j || typeof j !== "object" || !j.tool || j.tool.name !== "CyberView Scanner" || !Array.isArray(j.hosts) || !Array.isArray(j.findings)) return { error: "the file is not a CyberView Scanner report.json" };
  return { report: cleanReport(j) };
}

/** Where a host:port stands in a (clean) report: open | not-open | host-down | host-absent | port-not-scanned | not-checked */
function stateIn(rep, host, port) {
  const h = rep.hosts.find((x) => x.address === host);
  if (!h) return "host-absent";
  if (h.ports.includes(port)) return "open";
  if (!h.up) return "host-down";
  if (port && rep.ports.length && !rep.ports.includes(port)) return "port-not-scanned";
  if (rep.interrupted || rep.not_checked.has(host)) return "not-checked";
  return "not-open";
}
const WHY = { "host-absent": "the host was not in this scan", "host-down": "the host did not answer in this scan", "port-not-scanned": "the port was not in this scan's port list",
  "not-checked": "a limit or an interruption left this host's ports partly unchecked", "not-open": "the port no longer answers (closed or filtered): not proof of a fix" };

/**
 * previous, current: report.json objects (raw or cleaned). -> the differences, each list capped, with counts.
 */
export function diffReports(previous, current) {
  const P = previous && previous.not_checked instanceof Set ? previous : cleanReport(previous), C = current && current.not_checked instanceof Set ? current : cleanReport(current);
  const cap = (a) => a.slice(0, 500);
  const hostsP = new Map(P.hosts.map((h) => [h.address, h])), hostsC = new Map(C.hosts.map((h) => [h.address, h]));
  const d = { previous: { started_at: P.started_at, scope_sha256: P.scope_sha256 }, current: { started_at: C.started_at, scope_sha256: C.scope_sha256 }, same_scope: !!P.scope_sha256 && P.scope_sha256 === C.scope_sha256,
    hosts: { new_up: [], no_longer_up: [] }, ports: { opened: [], no_longer_open: [], not_rechecked: [] },
    services: { new: [], gone: [], changed: [], not_rechecked: [] },
    findings: { new: [], fixed: [], gone: [], still_open: [], not_rechecked: [] },
    certificates: { changed: [], issuer_changed: [], key_changed: [] }, observations: { new: [], resolved: [], not_rechecked: [] } };
  // hosts and ports
  for (const h of C.hosts) if (h.up && !(hostsP.get(h.address) || {}).up) d.hosts.new_up.push(h.address);
  for (const h of P.hosts) if (h.up && !(hostsC.get(h.address) || {}).up) d.hosts.no_longer_up.push({ host: h.address, why: hostsC.has(h.address) ? WHY["host-down"] : WHY["host-absent"] });
  for (const h of C.hosts) { const p = hostsP.get(h.address); for (const port of h.ports) if (!p || !p.ports.includes(port)) d.ports.opened.push({ host: h.address, port }); }
  for (const h of P.hosts) for (const port of h.ports) { const st = stateIn(C, h.address, port); if (st === "open") continue; (st === "not-open" ? d.ports.no_longer_open : d.ports.not_rechecked).push({ host: h.address, port, why: WHY[st] }); }
  // services: host|port|product, version compared
  const svcKey = (host, s) => `${host}|${s.port}|${s.product}`;
  const svcP = new Map(), svcC = new Map();
  for (const h of P.hosts) for (const s of h.services) svcP.set(svcKey(h.address, s), { host: h.address, ...s });
  for (const h of C.hosts) for (const s of h.services) svcC.set(svcKey(h.address, s), { host: h.address, ...s });
  for (const [k, s] of svcC) { const p = svcP.get(k); if (!p) d.services.new.push(s); else if (p.version !== s.version) d.services.changed.push({ host: s.host, port: s.port, product: s.product, before: p.version, after: s.version }); }
  for (const [k, s] of svcP) if (!svcC.has(k)) { const st = stateIn(C, s.host, s.port); (st === "open" || st === "not-open" ? d.services.gone : d.services.not_rechecked).push({ ...s, why: st === "open" ? "the port answers, but this product was not identified on it" : WHY[st] }); }
  // findings, per place seen (cve|host|port)
  const fP = new Map(), fC = new Map();
  for (const f of P.findings) for (const s of f.seen_on) fP.set(`${f.cve}|${s.host}|${s.port}`, { cve: f.cve, title: f.title, kev: f.kev, ...s });
  for (const f of C.findings) for (const s of f.seen_on) fC.set(`${f.cve}|${s.host}|${s.port}`, { cve: f.cve, title: f.title, kev: f.kev, ...s });
  for (const [k, x] of fC) (fP.has(k) ? d.findings.still_open : d.findings.new).push(x);
  for (const [k, x] of fP) {
    if (fC.has(k)) continue;
    const st = stateIn(C, x.host, x.port);
    if (st === "open") { const now = [...svcC.values()].filter((s) => s.host === x.host && s.port === x.port).map((s) => `${s.product} ${s.version || "(no version)"}`).slice(0, 3);
      d.findings.fixed.push({ ...x, why: `the service answered again and this CVE no longer matches${now.length ? `; now seen: ${now.join("; ")}` : "; no product identified on the port now"}` }); }
    else (st === "not-open" ? d.findings.gone : d.findings.not_rechecked).push({ ...x, why: WHY[st] });
  }
  // certificates, per host:port present in both
  for (const h of C.hosts) { const p = hostsP.get(h.address); if (!p) continue;
    for (const t of h.tls) { const o = p.tls.find((x) => x.port === t.port); if (!o || !o.fingerprint256 || !t.fingerprint256 || o.fingerprint256 === t.fingerprint256) continue;
      const row = { host: h.address, port: t.port, before: { fingerprint256: o.fingerprint256, issuer: o.issuer, subject: o.subject, valid_to: o.valid_to }, after: { fingerprint256: t.fingerprint256, issuer: t.issuer, subject: t.subject, valid_to: t.valid_to },
        issuer_changed: !!o.issuer && !!t.issuer && o.issuer !== t.issuer, key_changed: o.spki_sha256 && t.spki_sha256 ? o.spki_sha256 !== t.spki_sha256 : null };
      d.certificates.changed.push(row);
      if (row.issuer_changed) d.certificates.issuer_changed.push({ host: row.host, port: row.port, before: o.issuer, after: t.issuer, note: "issuer changed: review it (a CA switch or renewal through another CA is common); not evidence of compromise" });
      if (row.key_changed) d.certificates.key_changed.push({ host: row.host, port: row.port });
    } }
  // observations: host|port|kind
  const oKey = (host, x) => `${host}|${x.port}|${x.kind}`, oP = new Map(), oC = new Map();
  for (const h of P.hosts) for (const x of h.observations) oP.set(oKey(h.address, x), { host: h.address, ...x });
  for (const h of C.hosts) for (const x of h.observations) oC.set(oKey(h.address, x), { host: h.address, ...x });
  for (const [k, x] of oC) if (!oP.has(k)) d.observations.new.push(x);
  for (const [k, x] of oP) if (!oC.has(k)) { const st = stateIn(C, x.host, x.port); (st === "open" ? d.observations.resolved : d.observations.not_rechecked).push({ ...x, ...(st === "open" ? {} : { why: WHY[st] }) }); }
  // counts first, then cap every list
  const counts = {};
  for (const [sec, v] of Object.entries(d)) if (v && typeof v === "object" && !Array.isArray(v) && !["previous", "current"].includes(sec)) for (const [k, list] of Object.entries(v)) if (Array.isArray(list)) { counts[`${sec}.${k}`] = list.length; v[k] = cap(list); }
  d.counts = counts;
  d.notes = ["Fixed means the same host and port answered again and the CVE no longer matched; gone means the port no longer answers; not rechecked means this scan did not reach it.",
    ...(d.same_scope ? [] : ["The two reports come from different scope files (or the previous one has none): hosts outside either scope show as new or not rechecked."]),
    "Compared with a previous report.json read from this machine; nothing was sent for the comparison."];
  return d;
}

/** The plain-text diff (diff.txt and the terminal). */
export function diffText(d) {
  const c = d.counts, L = [];
  L.push(`Compared with the scan of ${d.previous.started_at || "?"}${d.same_scope ? " (same scope file)" : " (different scope file)"}:`);
  L.push(`  Findings: ${c["findings.new"]} new, ${c["findings.fixed"]} fixed, ${c["findings.still_open"]} still open, ${c["findings.gone"]} gone with their port, ${c["findings.not_rechecked"]} not rechecked.`);
  L.push(`  Hosts: ${c["hosts.new_up"]} newly up, ${c["hosts.no_longer_up"]} no longer up. Ports: ${c["ports.opened"]} newly open, ${c["ports.no_longer_open"]} no longer open, ${c["ports.not_rechecked"]} not rechecked.`);
  L.push(`  Services: ${c["services.new"]} new, ${c["services.changed"]} version changed, ${c["services.gone"]} gone. Certificates: ${c["certificates.changed"]} changed (${c["certificates.issuer_changed"]} with a new issuer, ${c["certificates.key_changed"]} with a new key).`);
  L.push(`  Observations: ${c["observations.new"]} new, ${c["observations.resolved"]} resolved.`);
  const list = (title, rows, f) => { if (!rows.length) return; L.push(""); L.push(title); rows.slice(0, 25).forEach((r) => L.push(`   ${f(r)}`)); if (rows.length > 25) L.push(`   ... ${rows.length - 25} more in diff.json`); };
  list("New findings:", d.findings.new, (x) => `${x.cve} on ${x.host}:${x.port} ${x.product} ${x.version || "(no version)"}${x.kev ? " (known exploited)" : ""}`);
  list("Fixed:", d.findings.fixed, (x) => `${x.cve} on ${x.host}:${x.port}: ${x.why}`);
  list("Gone with their port (not proof of a fix):", d.findings.gone, (x) => `${x.cve} on ${x.host}:${x.port}`);
  list("Not rechecked:", d.findings.not_rechecked, (x) => `${x.cve} on ${x.host}:${x.port}: ${x.why}`);
  list("Version changes:", d.services.changed, (x) => `${x.host}:${x.port} ${x.product} ${x.before || "?"} -> ${x.after || "?"}`);
  list("Certificate issuer changed (review; not evidence of compromise):", d.certificates.issuer_changed, (x) => `${x.host}:${x.port} ${x.before} -> ${x.after}`);
  d.notes.forEach((n) => { L.push(""); L.push(`Note: ${n}`); });
  return L.join("\n");
}
