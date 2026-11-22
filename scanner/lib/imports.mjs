// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Imports (scan-dep-map Stages B and C, tk-matchers): parse files the OPERATOR supplies from their own machines, offline.
// Nothing here opens a socket, runs a command, logs in or reads anything but the text it is handed: the operator runs their
// own tools (docker compose config, kubectl get -o json, a cloud CLI's describe/list, Zeek, a Wi-Fi survey app, ss/netstat,
// dpkg -l, rpm -qa, Get-Package) and points the scanner at the saved file. Every file is UNTRUSTED input: size caps,
// strict parsing (JSON.parse, fixed TSV/CSV/text grammars; YAML is NOT parsed), type checks, row caps and clipped strings.
// Package lists and SBOMs are matched with the site's own parser and matcher (site/workbench-lib.js parseInventory and
// matchFlaw, the Vulnerabilities page's "My software" path), never a fork.
import { parseCloud } from "./discover.mjs";
import { parseTarget } from "./scope.mjs";
import { W } from "./shared.mjs";

export const IMPORT_LIMITS = Object.freeze({
  maxBytes: 16 * 1024 * 1024,        // any one import file (Zeek conn.log: zeekMaxBytes)
  zeekMaxBytes: 64 * 1024 * 1024,
  rows: 200000,                      // lines/rows read from one file
  nodes: 5000, edges: 20000,         // per import
  items: 5000,                       // inventory items (the page's own cap is W.MAX_ITEMS)
  str: 200,
});
export const IMPORT_KINDS = Object.freeze(["sbom", "packages", "manifest", "zeek", "survey", "connections", "cloud"]);

// a clipped, control-character-free string from untrusted input
export const clip = (v, n = IMPORT_LIMITS.str) => (typeof v === "string" || typeof v === "number" ? String(v) : "").replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, " ").trim().slice(0, n);
const arr = (x) => (Array.isArray(x) ? x : []);
const obj = (x) => (x && typeof x === "object" && !Array.isArray(x) ? x : null);
const own = (o, k) => (o && Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined);
function json(text) { try { return { j: JSON.parse(String(text)) }; } catch (e) { return { error: `not valid JSON (${clip(e && e.message, 60)})` }; } }
const ipOf = (s) => { const t = parseTarget(clip(s, 60).replace(/^\[|\]$/g, "")); return !t.error && t.kind === "ip" ? t.text : ""; };

/** One imported graph: nodes keyed by id, edges deduplicated and counted, both capped (the cap is reported, never silent). */
function graph(source) {
  const nodes = new Map(), edges = new Map(), g = { source, dropped: 0 };
  g.node = (id, n) => { id = clip(id, 300); if (!id) return ""; if (!nodes.has(id)) { if (nodes.size >= IMPORT_LIMITS.nodes) { g.dropped++; return ""; } nodes.set(id, { id, ...n }); } return id; };
  g.edge = (from, to, kind, extra = {}) => {
    if (!from || !to || from === to) return; const k = `${from}\u0000${to}\u0000${kind}`;
    if (edges.has(k)) { edges.get(k).count++; return; }
    if (edges.size >= IMPORT_LIMITS.edges) { g.dropped++; return; }
    edges.set(k, { from, to, kind, count: 1, ...extra });
  };
  g.done = (more = {}) => ({ source, nodes: [...nodes.values()], edges: [...edges.values()], dropped: g.dropped, ...more });
  return g;
}

/* ---- SBOM: CycloneDX JSON (components, dependencies) or SPDX JSON (packages, relationships) ---- */
const SPDX_REL = Object.freeze({ DEPENDS_ON: ["a", "depends on"], DEPENDENCY_OF: ["b", "depends on"], CONTAINS: ["a", "contains"], CONTAINED_BY: ["b", "contains"],
  DYNAMIC_LINK: ["a", "links dynamically to"], STATIC_LINK: ["a", "links statically to"], RUNTIME_DEPENDENCY_OF: ["b", "depends on at runtime"], BUILD_DEPENDENCY_OF: ["b", "depends on to build"] });
export function parseSbom(text) {
  const { j, error } = json(text), g = graph("sbom");
  if (error) return { ...g.done({ kind: "unreadable" }), problems: [`SBOM: ${error}`], items: [] };
  const problems = [];
  let kind = "";
  if (obj(j) && Array.isArray(j.components)) {
    kind = "CycloneDX";
    const walk = (list, parent, depth) => {
      if (depth > 16) return;
      for (const c of arr(list).slice(0, IMPORT_LIMITS.items)) {
        if (!obj(c)) continue;
        const ref = clip(own(c, "bom-ref") || `${clip(c.name, 120)}@${clip(c.version, 40)}`, 300), name = clip(c.name, 120);
        if (!name) continue;
        const id = g.node(`sbom:${ref}`, { kind: "component", name, version: clip(c.version, 40), purl: clip(c.purl, 300) });
        if (parent) g.edge(parent, id, "contains", { declared: true });
        walk(c.components, id, depth + 1);
      }
    };
    const root = obj(j.metadata) && obj(j.metadata.component);
    const rootId = root && clip(root.name, 120) ? g.node(`sbom:${clip(own(root, "bom-ref") || root.name, 300)}`, { kind: "component", name: clip(root.name, 120), version: clip(root.version, 40), root: true }) : "";
    walk(j.components, "", 0);
    for (const d of arr(j.dependencies).slice(0, IMPORT_LIMITS.edges)) {
      if (!obj(d)) continue;
      const from = clip(d.ref, 300); if (!from) continue;
      for (const to of arr(d.dependsOn).slice(0, 500)) { const t = clip(to, 300); if (t) g.edge(g.node(`sbom:${from}`, { kind: "component", name: from }), g.node(`sbom:${t}`, { kind: "component", name: t }), "depends on", { declared: true }); }
    }
    if (rootId && !arr(j.dependencies).length) problems.push("SBOM: no dependencies section; components are listed without relationships");
  } else if (obj(j) && Array.isArray(j.packages)) {
    kind = "SPDX";
    for (const p of j.packages.slice(0, IMPORT_LIMITS.items)) { if (!obj(p) || !clip(p.SPDXID, 300)) continue; g.node(`sbom:${clip(p.SPDXID, 300)}`, { kind: "component", name: clip(p.name, 120), version: clip(p.versionInfo, 40) }); }
    for (const r of arr(j.relationships).slice(0, IMPORT_LIMITS.edges)) {
      if (!obj(r)) continue;
      const rule = Object.prototype.hasOwnProperty.call(SPDX_REL, r.relationshipType) ? SPDX_REL[r.relationshipType] : null; if (!rule) continue;
      const a = clip(r.spdxElementId, 300), b = clip(r.relatedSpdxElement, 300); if (!a || !b || /^NOASSERTION|NONE$/.test(b)) continue;
      const [x, y] = rule[0] === "a" ? [a, b] : [b, a];
      g.edge(g.node(`sbom:${x}`, { kind: "component", name: x }), g.node(`sbom:${y}`, { kind: "component", name: y }), rule[1], { declared: true });
    }
  } else return { ...g.done({ kind: "unknown" }), problems: ["SBOM: neither CycloneDX (components) nor SPDX (packages) JSON"], items: [] };
  // the inventory side goes through the page's own parser, exactly as an SBOM dropped on "My software"
  const inv = W.parseInventory("sbom.json", String(text));
  return { ...g.done({ kind }), problems, items: Array.from(inv.items.slice(0, IMPORT_LIMITS.items), (x) => ({ ...x, from: kind })) };
}

/* ---- local package inventories: dpkg -l, rpm -qa, Windows Get-Package / uninstall-key CSV (or any list the page reads) ---- */
const RPM_ARCH = /\.(x86_64|noarch|i[3-6]86|aarch64|armv7hl|ppc64le|s390x|src)$/;
const VER = /^\d[\w.+~]*$/;
/** dpkg version "1:2.4.52-1ubuntu4.6" -> upstream "2.4.52" (epoch and Debian revision removed). */
export function dpkgUpstream(v) {
  let s = clip(v, 80).replace(/^\d+:/, ""); const i = s.lastIndexOf("-"); if (i > 0) s = s.slice(0, i);
  s = s.replace(/[+~](dfsg|ds|really|deb|ubuntu|build|nmu)[\w.]*$/i, "");
  return VER.test(s) ? s.slice(0, 40) : "";
}
export function parsePackages(text) {
  const s = String(text || "").replace(/^\uFEFF/, ""), lines = s.split(/\r?\n/).slice(0, IMPORT_LIMITS.rows), items = [], problems = [];
  const push = (name, version, vendor, distro, raw) => { name = clip(name, 120); if (name.length < 2 || items.length >= IMPORT_LIMITS.items) return; items.push({ name, vendor: clip(vendor, 80), version: clip(version, 40), count: 1, distro, raw_version: clip(raw, 80) }); };
  const dpkg = lines.filter((l) => /^(ii|hi|rc|iU|iF|un|pn|hn)\s+\S+\s+\S+/.test(l));
  if (dpkg.length) {
    for (const l of dpkg) { if (!/^(ii|hi)\s/.test(l)) continue; const p = l.trim().split(/\s+/); const name = p[1].replace(/:(amd64|arm64|i386|armhf|all)$/, ""); push(name, dpkgUpstream(p[2]), "", "Debian/Ubuntu package (dpkg)", p[2]); }
    return { kind: "dpkg -l", items, problems: items.length ? problems : ["packages: dpkg -l output with no installed (ii) package"] };
  }
  const rpm = lines.map((l) => l.trim()).filter((l) => l && !/\s/.test(l) && /^[A-Za-z0-9_.+-]+-\d[\w.+~^]*-[\w.+~^]+$/.test(l.replace(RPM_ARCH, "")));
  if (rpm.length && rpm.length >= lines.filter((l) => l.trim()).length * 0.8) {
    for (const l of rpm) { const m = /^(.+)-([^-]+)-([^-]+)$/.exec(l.replace(RPM_ARCH, "")); if (m) push(m[1], VER.test(m[2]) ? m[2] : "", "", "RPM package (rpm -qa)", `${m[2]}-${m[3]}`); }
    return { kind: "rpm -qa", items, problems };
  }
  // Windows (Get-Package | Export-Csv, or the uninstall registry keys' DisplayName/DisplayVersion/Publisher) and any other
  // list: the page's own parser. A PowerShell 5 "#TYPE ..." first line is dropped.
  const body = lines.filter((l, i) => !(i === 0 && /^#TYPE\s/i.test(l))).join("\n");
  const inv = W.parseInventory("packages.csv", body);
  const win = /(^|,|")\s*(ProviderName|DisplayName|DisplayVersion|FastPackageReference)\s*("|,|$)/i.test(body.split("\n")[0] || "");
  for (const x of inv.items) push(x.name, x.version, x.vendor, "", x.version);
  if (!items.length) problems.push(`packages: no packages found (read as ${inv.kind}); give dpkg -l, rpm -qa, Get-Package CSV or a product,version list`);
  return { kind: win ? "Windows package list (CSV)" : inv.kind, items, problems };
}

/* ---- compose / Kubernetes manifests: JSON only (docker compose config --format json, kubectl get ... -o json) ---- */
export function parseManifest(text) {
  const t = String(text || "").trim(), g = graph("manifest");
  if (t && t[0] !== "{" && t[0] !== "[") return { ...g.done({ kind: "unreadable" }), problems: ["manifest: only JSON is read (YAML is not parsed): save it with `docker compose config --format json` or `kubectl get ... -o json`"] };
  const { j, error } = json(t);
  if (error) return { ...g.done({ kind: "unreadable" }), problems: [`manifest: ${error}`] };
  const problems = [];
  if (obj(j) && obj(j.services) && !j.kind) {   // docker compose
    const svcs = Object.keys(j.services).slice(0, IMPORT_LIMITS.nodes), id = (n) => `compose:${clip(n, 120)}`;
    for (const n of svcs) { const s = obj(j.services[n]) || {}; g.node(id(n), { kind: "compose service", name: clip(n, 120), image: clip(s.image, 200), ports: arr(s.ports).slice(0, 20).map((p) => clip(obj(p) ? `${clip(p.published, 10)}:${clip(p.target, 10)}` : p, 30)).filter(Boolean) }); }
    for (const n of svcs) {
      const s = obj(j.services[n]) || {}, deps = Array.isArray(s.depends_on) ? s.depends_on : obj(s.depends_on) ? Object.keys(s.depends_on) : [];
      for (const d of deps.slice(0, 100)) if (svcs.includes(clip(d, 120))) g.edge(id(n), id(d), "depends on", { declared: true });
      for (const l of arr(s.links).slice(0, 100)) { const d = clip(l, 120).split(":")[0]; if (svcs.includes(d)) g.edge(id(n), id(d), "links to", { declared: true }); }
    }
    return { ...g.done({ kind: "docker compose (JSON)" }), problems };
  }
  const items = obj(j) && Array.isArray(j.items) ? j.items : Array.isArray(j) ? j : obj(j) && j.kind ? [j] : null;
  if (!items) return { ...g.done({ kind: "unknown" }), problems: ["manifest: neither a compose file (services) nor Kubernetes objects (kind, or a List with items)"] };
  const key = (o) => { const m = obj(o.metadata) || {}; return `k8s:${clip(o.kind, 40)}/${clip(m.namespace, 63) || "default"}/${clip(m.name, 253)}`; };
  const workloads = [], services = [];
  for (const o of items.slice(0, IMPORT_LIMITS.nodes)) {
    if (!obj(o) || !clip(o.kind, 40) || !obj(o.metadata) || !clip(o.metadata.name, 253)) continue;
    const spec = obj(o.spec) || {}, tpl = obj(spec.template) || (o.kind === "Pod" ? o : {}), pod = obj(tpl.spec) || (o.kind === "Pod" ? spec : {});
    const images = [...arr(pod.containers), ...arr(pod.initContainers)].slice(0, 20).map((c) => clip(obj(c) && c.image, 200)).filter(Boolean);
    const id = g.node(key(o), { kind: `kubernetes ${clip(o.kind, 40)}`, name: clip(o.metadata.name, 253), namespace: clip(o.metadata.namespace, 63) || "default", ...(images.length ? { images } : {}) });
    const labels = obj(obj(tpl.metadata) && tpl.metadata.labels) || (o.kind === "Pod" ? obj(o.metadata.labels) : null);
    if (labels && id) workloads.push({ id, ns: clip(o.metadata.namespace, 63) || "default", labels });
    if (o.kind === "Service" && obj(spec.selector) && id) services.push({ id, ns: clip(o.metadata.namespace, 63) || "default", sel: spec.selector });
    if (o.kind === "Ingress" && id) for (const r of arr(spec.rules).slice(0, 100)) for (const p of arr(obj(r) && obj(r.http) && r.http.paths).slice(0, 100)) {
      const b = obj(p) && obj(p.backend), name = clip((b && obj(b.service) && b.service.name) || (b && b.serviceName), 253);
      if (name) g.edge(id, g.node(`k8s:Service/${clip(o.metadata.namespace, 63) || "default"}/${name}`, { kind: "kubernetes Service", name, namespace: clip(o.metadata.namespace, 63) || "default" }), "routes to", { declared: true, host: clip(obj(r) && r.host, 253) });
    }
  }
  for (const s of services) {
    const sel = Object.entries(s.sel).slice(0, 20).map(([k, v]) => [clip(k, 100), clip(v, 100)]); if (!sel.length) continue;
    for (const w of workloads) if (w.ns === s.ns && sel.every(([k, v]) => clip(own(w.labels, k), 100) === v)) g.edge(s.id, w.id, "selects", { declared: true });
  }
  return { ...g.done({ kind: "Kubernetes objects (JSON)" }), problems };
}

/* ---- Zeek conn.log: TSV with #fields, or Zeek JSON lines ---- */
export function parseZeek(text) {
  const g = graph("zeek"), lines = String(text || "").split(/\r?\n/), problems = [];
  let fields = null, sep = "\t", rows = 0, bad = 0;
  const take = (r) => {
    const o = ipOf(r["id.orig_h"]), resp = ipOf(r["id.resp_h"]), port = Number(r["id.resp_p"]), proto = clip(r.proto, 8).toLowerCase();
    if (!o || !resp || !(port >= 0 && port <= 65535) || !/^(tcp|udp|icmp)$/.test(proto)) { bad++; return; }
    rows++;
    g.edge(g.node(`ip:${o}`, { kind: "address", address: o }), g.node(`ip:${resp}`, { kind: "address", address: resp }), "connected to", { observed: true, port, proto, service: clip(r.service, 40).replace(/^-$/, "") });
  };
  for (const raw of lines.slice(0, IMPORT_LIMITS.rows)) {
    const l = raw.replace(/\r$/, ""); if (!l) continue;
    if (l.startsWith("#separator")) { const m = /\\x([0-9a-f]{2})/i.exec(l); sep = m ? String.fromCharCode(parseInt(m[1], 16)) : "\t"; continue; }
    if (l.startsWith("#fields")) { fields = l.split(sep).slice(1).slice(0, 64).map((f) => clip(f, 40)); continue; }
    if (l[0] === "#") continue;
    if (l[0] === "{") { try { const r = JSON.parse(l); if (obj(r)) take(r); else bad++; } catch { bad++; } continue; }
    if (!fields) { bad++; continue; }
    const v = l.split(sep), r = Object.create(null); fields.forEach((f, i) => { r[f] = v[i]; }); take(r);
  }
  if (!rows) problems.push("zeek: no connection rows read (expected conn.log with a #fields header, or Zeek JSON lines)");
  if (bad) problems.push(`zeek: ${bad} line(s) skipped (not a conn.log row)`);
  return { ...g.done({ kind: "Zeek conn.log", rows }), problems };
}

/* ---- Wi-Fi / Bluetooth survey CSV (WiGLE export, Kismet-style or any CSV with a MAC/BSSID column): inventory only ---- */
const MAC = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;
export function parseSurvey(text) {
  const lines = String(text || "").replace(/^\uFEFF/, "").split(/\r?\n/).slice(0, IMPORT_LIMITS.rows), problems = [], radios = [];
  const hi = lines.findIndex((l) => /(^|,)\s*"?(mac|bssid|address|device ?address)"?\s*(,|$)/i.test(l));
  if (hi < 0) return { source: "survey", kind: "unknown", radios, problems: ["survey: no header with a MAC, BSSID or address column"] };
  const cells = (l) => { const out = []; let cur = "", q = false; for (const c of l) { if (q) { if (c === '"') q = false; else cur += c; } else if (c === '"') q = true; else if (c === ",") { out.push(cur); cur = ""; } else cur += c; } out.push(cur); return out; };
  const head = cells(lines[hi]).map((h) => clip(h, 40).toLowerCase());
  const col = (re) => head.findIndex((h) => re.test(h));
  const ci = { mac: col(/^(mac|bssid|address|device ?address)$/), name: col(/^(ssid|name|device ?name|essid)$/), sec: col(/^(authmode|security|encryption|auth|privacy)$/), ch: col(/^(channel|frequency|freq)$/), sig: col(/^(rssi|signal|power|dbm)$/), type: col(/^(type|kind|radio)$/) };
  let bad = 0; const seen = new Set();
  for (const l of lines.slice(hi + 1)) {
    if (!l.trim()) continue;
    const r = cells(l), mac = clip(r[ci.mac], 17).toLowerCase().replace(/-/g, ":");
    if (!MAC.test(mac)) { bad++; continue; }
    const type = ci.type >= 0 ? clip(r[ci.type], 10).toUpperCase() : "";
    const kind = /^(BT|BLE|BLUETOOTH)/.test(type) ? "bluetooth" : "wifi";
    if (seen.has(kind + mac) || radios.length >= IMPORT_LIMITS.items) continue; seen.add(kind + mac);
    radios.push({ kind, id: mac, name: ci.name >= 0 ? clip(r[ci.name], 64) : "", security: ci.sec >= 0 ? clip(r[ci.sec], 80) : "", channel: ci.ch >= 0 ? clip(r[ci.ch], 10) : "", signal: ci.sig >= 0 ? clip(r[ci.sig], 10) : "" });
  }
  if (bad) problems.push(`survey: ${bad} row(s) skipped (no valid MAC address)`);
  return { source: "survey", kind: "Wi-Fi / Bluetooth survey (CSV)", radios, counts: { wifi: radios.filter((x) => x.kind === "wifi").length, bluetooth: radios.filter((x) => x.kind === "bluetooth").length }, problems,
    note: "Inventory only, from the operator's own survey file. The scanner never drives a radio, joins a network or pairs with a device." };
}

/* ---- local connections: /proc/net/tcp{,6}, ss, or netstat text the operator saved ON the host itself ---- */
const PROC_STATE = { "01": "ESTABLISHED", "0A": "LISTEN" };
function procAddr(hex) {
  const [a, p] = String(hex || "").split(":"); const port = parseInt(p, 16); if (!a || !(port >= 0 && port <= 65535)) return null;
  if (a.length === 8) { const b = a.match(/../g).map((x) => parseInt(x, 16)).reverse(); return { ip: b.join("."), port }; }
  if (a.length === 32) { const words = a.match(/.{8}/g).map((w) => w.match(/../g).reverse().join("")); const groups = words.join("").match(/.{4}/g); const ip = ipOf(groups.join(":")); return ip ? { ip, port } : null; }
  return null;
}
function splitHostPort(s) {
  const t = clip(s, 80).replace(/%[\w.-]+(?=[:\]])/, ""); const m = /^\[?([0-9a-fA-F:.*]+|\*)\]?[:.](\d{1,5}|\*)$/.exec(t);
  if (!m) return null; const port = m[2] === "*" ? 0 : Number(m[2]); const ip = m[1] === "*" ? "*" : ipOf(m[1]);
  return ip && port <= 65535 ? { ip, port } : null;
}
export function parseConnections(text) {
  const lines = String(text || "").split(/\r?\n/).slice(0, IMPORT_LIMITS.rows), listening = [], peers = [], problems = [];
  const proc = (s) => { const m = /users:\(\("([^"]{1,40})"/.exec(s) || /\d+\/([\w.@:-]{1,40})\s*$/.exec(s); return m ? clip(m[1], 40) : ""; };
  const add = (proto, state, l, r, process) => {
    if (!l || listening.length + peers.length >= IMPORT_LIMITS.edges) return;
    if (/^LISTEN/i.test(state) || (proto === "udp" && (!r || r.ip === "*" || r.port === 0))) listening.push({ proto, address: l.ip, port: l.port, process });
    else if (r && r.ip !== "*" && /^(ESTAB|ESTABLISHED)$/i.test(state || (proto === "udp" ? "ESTAB" : ""))) peers.push({ proto, local: l.ip, local_port: l.port, peer: r.ip, peer_port: r.port, process });
  };
  let kind = "", bad = 0;
  for (const raw of lines) {
    const l = raw.trim(); if (!l) continue;
    let m;
    if ((m = /^\d+:\s+([0-9A-F]{8,32}:[0-9A-F]{4})\s+([0-9A-F]{8,32}:[0-9A-F]{4})\s+([0-9A-F]{2})\s/i.exec(l))) {   // /proc/net/tcp
      kind ||= "/proc/net/tcp"; const st = PROC_STATE[m[3].toUpperCase()]; if (st) add("tcp", st, procAddr(m[1]), procAddr(m[2]), ""); continue;
    }
    const p = l.split(/\s+/);
    if (/^(tcp|udp)6?$/i.test(p[0]) && /^(ESTAB|LISTEN|UNCONN|TIME-WAIT|CLOSE-WAIT|SYN-SENT|FIN-WAIT-\d|LAST-ACK|CLOSING)$/i.test(p[1]) && p.length >= 6) {   // ss -tunap
      kind ||= "ss"; const proto = p[0].toLowerCase().replace("6", ""); add(proto, p[1].toUpperCase() === "UNCONN" ? "LISTEN" : p[1], splitHostPort(p[4]), splitHostPort(p[5]), proc(l)); continue;
    }
    if (/^(LISTEN|ESTAB|UNCONN)$/i.test(p[0]) && p.length >= 5) { kind ||= "ss"; add("tcp", p[0], splitHostPort(p[3]), splitHostPort(p[4]), proc(l)); continue; }   // ss -tlnp (no Netid)
    if (/^(tcp|udp)[46]?$/i.test(p[0]) && /^\d+$/.test(p[1]) && p.length >= 5) {   // netstat -tunap (Linux)
      kind ||= "netstat"; const proto = p[0].toLowerCase().replace(/[46]/, ""); add(proto, proto === "udp" ? (p[4] === "0.0.0.0:*" || /:\*$/.test(p[4]) ? "LISTEN" : "ESTABLISHED") : p[5] || "", splitHostPort(p[3]), splitHostPort(p[4]), proc(l)); continue;
    }
    if (/^(TCP|UDP)$/.test(p[0]) && p.length >= 3) {   // netstat -ano (Windows)
      kind ||= "netstat (Windows)"; const proto = p[0].toLowerCase(); add(proto, proto === "udp" ? "LISTEN" : (p[3] || "").replace("LISTENING", "LISTEN"), splitHostPort(p[1]), splitHostPort(p[2]), ""); continue;
    }
    if (/^(sl|Netid|State|Proto|Active|Recv-Q)\b/i.test(l)) continue;
    bad++;
  }
  if (!kind) problems.push("connections: not /proc/net/tcp, ss or netstat output");
  else if (bad) problems.push(`connections: ${bad} line(s) not read`);
  return { source: "connections", kind: kind || "unknown", listening, peers, problems,
    note: "From a file the operator captured on the attested host itself. The scanner never logs in, runs ss/netstat, or reads another machine." };
}

/* ---- cloud inventory JSON (the read-only describe/list output the operator saved): resources and relationships ---- */
export function parseCloudInventory(text, provider = "aws-ec2") {
  const g = graph("cloud"), addrs = parseCloud(text, provider);   // the addresses: discover.mjs's own parser
  const { j, error } = json(text);
  if (error) return { ...g.done({ kind: provider }), addresses: [], problems: addrs.problems.length ? addrs.problems : [`cloud: ${error}`] };
  const res = (type, id, extra = {}) => g.node(`cloud:${type}:${clip(id, 200)}`, { kind: `cloud ${type}`, name: clip(id, 200), ...extra });
  const ip = (a) => { const x = ipOf(a); return x ? g.node(`ip:${x}`, { kind: "address", address: x }) : ""; };
  try {
    if (provider === "aws-ec2") for (const r of arr(obj(j) && j.Reservations)) for (const i of arr(obj(r) && r.Instances)) {
      if (!obj(i) || !clip(i.InstanceId, 40)) continue;
      const id = res("instance", i.InstanceId);
      if (clip(i.VpcId, 40)) g.edge(id, res("network", i.VpcId), "in network", { declared: true });
      if (clip(i.SubnetId, 40)) g.edge(id, res("subnet", i.SubnetId), "in subnet", { declared: true });
      for (const sg of arr(i.SecurityGroups).slice(0, 20)) if (obj(sg) && clip(sg.GroupId, 40)) g.edge(id, res("security group", sg.GroupId), "uses", { declared: true });
      for (const a of [i.PrivateIpAddress, i.PublicIpAddress]) { const n = ip(a); if (n) g.edge(id, n, "has address", { declared: true }); }
    }
    if (provider === "aws-elb") for (const lb of arr(obj(j) && j.LoadBalancers)) {
      if (!obj(lb)) continue; const id = res("load balancer", lb.LoadBalancerName || lb.LoadBalancerArn || lb.DNSName); if (!id) continue;
      if (clip(lb.VpcId, 40)) g.edge(id, res("network", lb.VpcId), "in network", { declared: true });
      for (const i of arr(lb.Instances).slice(0, 500)) if (obj(i) && clip(i.InstanceId, 40)) g.edge(id, res("instance", i.InstanceId), "load balances", { declared: true });
    }
    if (provider === "gcp") for (const i of arr(j)) {
      if (!obj(i) || !clip(i.name, 100)) continue; const id = res("instance", i.name);
      for (const ni of arr(i.networkInterfaces).slice(0, 8)) { if (!obj(ni)) continue; const net = clip(ni.network, 300).split("/").pop(); if (net) g.edge(id, res("network", net), "in network", { declared: true });
        const n = ip(ni.networkIP); if (n) g.edge(id, n, "has address", { declared: true }); for (const ac of arr(ni.accessConfigs).slice(0, 4)) { const p = ip(obj(ac) && ac.natIP); if (p) g.edge(id, p, "has address", { declared: true }); } }
    }
    if (provider === "azure") for (const o of arr(Array.isArray(j) ? j : [j])) {
      if (!obj(o)) continue;
      const cfg = obj(o.ipConfiguration), owner = cfg && clip(cfg.id, 400).split("/providers/")[1];
      if (clip(o.name, 100) && clip(o.ipAddress, 60)) { const id = res("public address", o.name); const n = ip(o.ipAddress); if (n) g.edge(id, n, "has address", { declared: true }); if (owner) g.edge(id, res("resource", owner.split("/").slice(0, 4).join("/")), "attached to", { declared: true }); }
      const vm = obj(o.virtualMachine); if (vm && clip(vm.name, 100)) { const id = res("vm", vm.name); for (const p of arr(obj(vm.network) && vm.network.publicIpAddresses)) { const n = ip(obj(p) && p.ipAddress); if (n) g.edge(id, n, "has address", { declared: true }); }
        for (const p of arr(obj(vm.network) && vm.network.privateIpAddresses)) { const n = ip(p); if (n) g.edge(id, n, "has address", { declared: true }); } }
    }
  } catch (e) { addrs.problems.push(`cloud: could not read the ${provider} inventory: ${clip(e && e.message, 80)}`); }
  return { ...g.done({ kind: `cloud inventory (${provider})` }), addresses: addrs.candidates.map((c) => c.ip || c.host || c.cidr).filter(Boolean).slice(0, IMPORT_LIMITS.nodes), problems: addrs.problems };
}

/**
 * Parse every supplied import. files: { sbom, packages, manifest, zeek, survey, connections, cloud: text } (any subset),
 * opts: { cloudProvider, connectionsHost }. -> { sources: {kind: parsed}, graphs: [...], inventory: [...items], problems }
 */
export function parseImports(files, { cloudProvider = "aws-ec2", connectionsHost = "" } = {}) {
  const out = { sources: {}, graphs: [], inventory: [], problems: [] };
  const P = { sbom: parseSbom, packages: parsePackages, manifest: parseManifest, zeek: parseZeek, survey: parseSurvey, connections: parseConnections, cloud: (t) => parseCloudInventory(t, cloudProvider) };
  for (const k of IMPORT_KINDS) {
    if (files[k] == null) continue;
    const r = P[k](files[k]); out.sources[k] = r; out.problems.push(...(r.problems || []));
    if (r.nodes) out.graphs.push(r);
    if (r.items) out.inventory.push(...r.items.map((x) => ({ ...x, from: k })));
  }
  const c = out.sources.connections;
  if (c) {   // the connections file describes one host: the operator names it (an address in the report), or it stays "local host"
    const host = ipOf(connectionsHost), g = graph("connections"), me = host ? g.node(`ip:${host}`, { kind: "address", address: host }) : g.node("local:host", { kind: "local host (connections file)" });
    for (const l of c.listening) g.node(`listen:${l.proto}:${l.port}`, { kind: "listening socket", proto: l.proto, port: l.port, bound: l.address, process: l.process });
    for (const l of c.listening) g.edge(me, `listen:${l.proto}:${l.port}`, "listens on", { declared: true });
    for (const p of c.peers) g.edge(me, g.node(`ip:${p.peer}`, { kind: "address", address: p.peer }), "connected to", { observed: true, port: p.peer_port, proto: p.proto, process: p.process });
    out.graphs.push(g.done({ kind: c.kind, host: host || "" }));
  }
  if (out.inventory.length > IMPORT_LIMITS.items) { out.problems.push(`inventory: ${out.inventory.length - IMPORT_LIMITS.items} item(s) over the cap of ${IMPORT_LIMITS.items} were not matched`); out.inventory.length = IMPORT_LIMITS.items; }
  return out;
}

/**
 * Imported packages/SBOM components against CyberView's flaws, exactly as the page's "My software" view judges them:
 * W.matchFlaw per flaw, W.score for the points (every point listed). A version from a distribution package (dpkg/rpm) is the
 * distribution's build: the fix may be backported, so those matches carry the backport caveat.
 */
export function matchInventory(items, flaws, { today = new Date().toISOString().slice(0, 10) } = {}) {
  const inv = items.map((x) => ({ name: x.name, vendor: x.vendor || "", version: x.version || "", count: Math.max(1, Number(x.count) || 1) }));
  const out = [];
  if (!inv.length) return out;
  for (const f of flaws) {
    const m = W.matchFlaw(f, inv);
    if (!m || (m.state !== "affected" && m.state !== "check")) continue;
    const pts = W.score(f, m, today);
    const via = Array.from(m.items, (it) => { const src = items.find((x) => x.name === it.name && (x.version || "") === (it.version || "")) || {}; return { name: it.name, version: it.version, state: it.state, from: src.from || "", distro: src.distro || "", raw_version: src.raw_version || "" }; });
    out.push({ cve: f.cve, title: f.name || f.desc.slice(0, 120), vendor: f.vendor, product: f.product, state: m.state, kev: f.kev, cisa_due: f.due, overdue: !!(f.due && f.due < today), ransomware: f.ransomware, epss: f.epss,
      confidence: m.state !== "affected" ? "low" : via.some((v) => v.state === "affected" && v.distro) ? "medium" : "high",
      confidence_why: m.state !== "affected" ? "the product is in the list, but the version could not be compared; check it by hand"
        : via.some((v) => v.state === "affected" && v.distro) ? "the version is a distribution package build: the distribution may have backported the fix; check the package changelog" : "the version in the supplied list is inside the affected range",
      items: via, fixed_in: Array.from(m.fixed), points: { total: pts.total, list: Array.from(pts.points, ([n, why]) => ({ points: n, why })) } });
  }
  return out.sort((a, b) => (b.kev - a.kev) || (a.state === b.state ? 0 : a.state === "affected" ? -1 : 1) || b.points.total - a.points.total || (a.cve < b.cve ? -1 : 1));
}

/**
 * The import flags given on the command line -> { files: {kind: text}, given: [kind] } | { error }. Each file is
 * size-checked BEFORE it is read (sizeOf) and read as text (readFile); both are passed in, so this module does no I/O itself.
 */
export function readImportFiles(a, { readFile, sizeOf }) {
  const files = {}, given = [];
  for (const k of IMPORT_KINDS) {
    if (a[k] === undefined) continue;
    const f = a[k];
    if (typeof f !== "string" || !f) return { error: `--${k} needs a file name` };
    const cap = k === "zeek" ? IMPORT_LIMITS.zeekMaxBytes : IMPORT_LIMITS.maxBytes;
    let size; try { size = sizeOf(f); } catch { return { error: `--${k}: cannot read ${f}` }; }
    if (!(size <= cap)) return { error: `--${k} ${f}: over the ${cap / 1048576} MB import cap; export fewer columns or split it` };
    try { files[k] = readFile(f); } catch { return { error: `--${k}: cannot read ${f}` }; }
    given.push(k);
  }
  if (a["cloud-provider"] !== undefined && !["aws-ec2", "aws-elb", "gcp", "azure"].includes(a["cloud-provider"])) return { error: "--cloud-provider must be aws-ec2, aws-elb, gcp or azure" };
  if (a["connections-host"] !== undefined && !ipOf(a["connections-host"])) return { error: "--connections-host must be the IP address of the host the connections file was captured on" };
  return { files, given };
}
