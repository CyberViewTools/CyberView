// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Offline inputs for `match`: a CycloneDX or SPDX SBOM, an nmap -oX XML file, or a plain component list,
// turned into the same service records a scan would have produced. No network, no probe, no process.
// Parsing is bounded (8 MB, 5,000 components). CPE and purl are preferred over a free-text name because
// matching uses NVD's CPE product names. An input with no address is one pseudo-host; it is not exposed
// unless the operator passes --assume-exposed. An nmap address is classified with scope.mjs (public or
// private) and is never contacted.
import { basename } from "node:path";
import { classify, isPrivateKind } from "./scope.mjs";
import { W } from "./shared.mjs";

export const MAX_ITEMS = 5000;
export const MAX_BYTES = 8 * 1024 * 1024;

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").slice(0, n);
const nice = (s) => clip(String(s || "").replace(/_/g, " ").replace(/^Organization:\s*|^Person:\s*/i, "").replace(/NOASSERTION/i, ""), 120).trim();
const coreVer = (v) => {
  const s = clip(v, 40).trim().replace(/^v(?=\d)/i, "");
  const bare = s.replace(/p\d+$/i, "");
  return (/^\d+(?:\.\d+)*/.exec(bare) || [""])[0];
};
function distroOf(s) {
  const t = String(s || "");
  if (/ubuntu/i.test(t)) return "Ubuntu";
  if (/debian/i.test(t)) return "Debian";
  if (/red ?hat|rhel|\.el\d/i.test(t)) return "Red Hat";
  if (/centos/i.test(t)) return "CentOS";
  if (/rocky/i.test(t)) return "Rocky Linux";
  if (/alma/i.test(t)) return "AlmaLinux";
  if (/suse/i.test(t)) return "SUSE";
  if (/alpine/i.test(t)) return "Alpine";
  if (/amazon|amzn/i.test(t)) return "Amazon Linux";
  if (/freebsd/i.test(t)) return "FreeBSD";
  return "";
}

/** Split a CPE 2.3 string on unescaped colons. */
function splitCpe23(s) {
  const out = []; let cur = "";
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "\\" && i + 1 < s.length) { cur += s[i + 1]; i++; continue; }
    if (s[i] === ":") { out.push(cur); cur = ""; continue; }
    cur += s[i];
  }
  out.push(cur);
  return out;
}

/** cpe:2.3:a:vendor:product:version or cpe:/a:vendor:product:version -> { part, vendor, product, version } or null. */
export function parseCpe(raw) {
  const s = clip(raw, 300).trim();
  if (s.startsWith("cpe:2.3:")) {
    const p = splitCpe23(s);
    if (p.length < 6 || !p[4]) return null;
    const version = p[5] === "*" || p[5] === "-" ? "" : p[5];
    return { part: p[2] || "", vendor: nice(p[3]), product: nice(p[4]), version: clip(version, 40) };
  }
  if (s.startsWith("cpe:/")) {
    const p = s.slice(5).split(":");
    if (p.length < 3 || !p[2]) return null;
    const version = !p[3] || p[3] === "*" || p[3] === "-" ? "" : p[3];
    return { part: p[0] || "", vendor: nice(p[1]), product: nice(p[2]), version: clip(version, 40) };
  }
  return null;
}

/** pkg:type/namespace/name@version -> { type, namespace, name, version } or null. */
export function parsePurl(raw) {
  const s = clip(raw, 400).trim();
  const m = /^pkg:([a-z0-9.+-]+)\/([^?#\s]+)/i.exec(s);
  if (!m) return null;
  let rest = m[2];
  const at = rest.lastIndexOf("@");
  let version = "";
  if (at >= 0) { version = rest.slice(at + 1); rest = rest.slice(0, at); }
  let name = rest;
  try { name = decodeURIComponent(rest); } catch { /* keep the raw name */ }
  const segs = name.split("/");
  const leaf = segs.pop() || "";
  if (!leaf) return null;
  return { type: m[1].toLowerCase(), namespace: nice(segs.join(" ")), name: nice(leaf), version: clip(version, 40) };
}

function svc({ port, proto, vendor, product, version, distro, source, evidence, guessed }) {
  const shown = clip(version, 40).trim();
  const match = coreVer(shown);
  return {
    port: port == null || port === "" ? null : Math.max(0, Math.min(65535, Number(port) || 0)) || null,
    proto: clip(proto || "list", 16),
    vendor: nice(vendor),
    product: nice(product),
    label: [nice(vendor), nice(product)].filter(Boolean).join(" "),
    version: match,
    shown_version: shown,
    distro: distro || "",
    source: clip(source, 40),
    evidence: clip(evidence, 200),
    guessed: guessed || !match,
  };
}

function componentService(c, source) {
  if (!c || typeof c !== "object") return null;
  const cpeRaw = [c.cpe].concat(Array.isArray(c.cpes) ? c.cpes : []).filter((x) => typeof x === "string");
  const cpe = cpeRaw.map(parseCpe).find((x) => x && x.product) || null;
  const purl = parsePurl(typeof c.purl === "string" ? c.purl : "");
  const product = (cpe && cpe.product) || (purl && purl.name) || c.name || "";
  if (!product) return null;
  const vendor = (cpe && cpe.vendor) || (purl && purl.namespace) || c.publisher || (c.supplier && c.supplier.name) || c.group || "";
  const version = (cpe && cpe.version) || (purl && purl.version) || c.version || "";
  const id = cpe ? cpeRaw[0] : (typeof c.purl === "string" ? c.purl : `${product} ${version}`);
  return svc({ proto: "sbom", vendor, product, version, source, evidence: `${source}: ${clip(id, 160)}`, guessed: !version });
}

function walkComponents(list, source, out, cap, depth) {
  if (!Array.isArray(list) || depth > 8) return;
  for (const c of list) {
    if (out.length >= cap) return;
    const s = componentService(c, source);
    if (s) out.push(s);
    if (c && Array.isArray(c.components)) walkComponents(c.components, source, out, cap, depth + 1);
  }
}

function spdxServices(j, cap) {
  const out = [];
  for (const p of (Array.isArray(j.packages) ? j.packages : []).slice(0, cap)) {
    if (!p || typeof p !== "object" || out.length >= cap) break;
    const refs = Array.isArray(p.externalRefs) ? p.externalRefs : [];
    const cpeRef = refs.find((r) => r && /cpe/i.test(String(r.referenceType || "")) && parseCpe(r.referenceLocator));
    const purlRef = refs.find((r) => r && /purl/i.test(String(r.referenceType || "")));
    const cpe = cpeRef ? parseCpe(cpeRef.referenceLocator) : null;
    const purl = purlRef ? parsePurl(purlRef.referenceLocator) : null;
    const product = (cpe && cpe.product) || (purl && purl.name) || p.name || "";
    if (!product) continue;
    const vendor = (cpe && cpe.vendor) || (purl && purl.namespace) || p.supplier || "";
    const version = (cpe && cpe.version) || (purl && purl.version) || p.versionInfo || "";
    const id = cpeRef ? cpeRef.referenceLocator : (purlRef ? purlRef.referenceLocator : `${product} ${version}`);
    out.push(svc({ proto: "sbom", vendor, product, version, source: "SPDX", evidence: `SPDX: ${clip(id, 160)}`, guessed: !version }));
  }
  return out;
}

function host(address, { names = [], source, services, exposed, kind, up }) {
  const k = kind || (exposed ? "public" : "private");
  return {
    address: clip(address, 200) || "inventory",
    names: names.map((n) => clip(n, 200)).filter(Boolean).slice(0, 8),
    kind: k, public: !!exposed, up: up !== undefined ? !!up : services.length > 0, source,
    ports: [], services, http: [], tls: [], udp: [], observations: [], outcomes: [],
  };
}

function listServices(file, raw, cap) {
  const parsed = W.parseInventory(file, raw);
  return {
    format: parsed.kind,
    services: (parsed.items || []).slice(0, cap).filter((it) => it && it.name).map((it) => svc({
      proto: "list", vendor: it.vendor, product: it.name, version: it.version, source: parsed.kind,
      evidence: `${parsed.kind}: ${it.name}${it.version ? " " + it.version : ""}`, guessed: !it.version,
    })),
  };
}

function jsonDoc(raw) {
  const t = raw.trim();
  if (t[0] !== "{" && t[0] !== "[") return null;
  try { return JSON.parse(t); } catch { return null; }
}

/** nmap -oX text -> hosts with open-port service records. Closed ports are skipped. */
export function fromNmapXml(raw, { assumeExposed = false, limit = MAX_ITEMS } = {}) {
  const cap = Math.max(1, Math.min(MAX_ITEMS, limit | 0));
  const xml = String(raw || "").slice(0, MAX_BYTES);
  const hosts = [];
  for (const chunk of xml.split(/<host\b/i).slice(1)) {
    if (hosts.length >= cap) break;
    const addr = /<address\b[^>]*\baddr="([^"]+)"[^>]*\baddrtype="ipv[46]"/i.exec(chunk)
      || /<address\b[^>]*\baddrtype="ipv[46]"[^>]*\baddr="([^"]+)"/i.exec(chunk);
    const ip = addr ? clip(addr[1], 80) : "";
    const names = [...chunk.matchAll(/<hostname\b[^>]*\bname="([^"]+)"/gi)].map((m) => m[1]).slice(0, 8);
    const services = [];
    for (const p of chunk.split(/<port\b/i).slice(1)) {
      if (services.length >= 64) break;
      const state = /<state\b[^>]*\bstate="([^"]+)"/i.exec(p);
      if (state && state[1].toLowerCase() !== "open") continue;
      const pid = /\bportid="(\d{1,5})"/i.exec(p);
      const proto = /\bprotocol="([a-z0-9]{1,8})"/i.exec(p);
      const product = /\bproduct="([^"]*)"/i.exec(p);
      const version = /\bversion="([^"]*)"/i.exec(p);
      const extra = /\bextrainfo="([^"]*)"/i.exec(p);
      const cpe = [...p.matchAll(/<cpe>([^<]{1,300})<\/cpe>/gi)].map((m) => parseCpe(m[1])).find((x) => x && x.product) || null;
      const prod = (cpe && cpe.product) || (product && product[1]) || "";
      if (!prod) continue;
      const ver = (version && version[1]) || (cpe && cpe.version) || "";
      services.push(svc({
        port: pid ? Number(pid[1]) : null, proto: proto ? proto[1].toLowerCase() : "tcp",
        vendor: (cpe && cpe.vendor) || "", product: prod, version: ver, distro: distroOf(extra && extra[1]),
        source: "nmap service", evidence: `nmap service: ${clip(prod, 60)} ${clip(ver, 40)}`.trim(), guessed: !ver,
      }));
    }
    if (!ip && !services.length) continue;
    const status = /<status\b[^>]*\bstate="([^"]+)"/i.exec(chunk);
    const kind = ip ? classify(ip) : "private";
    const exposed = !!assumeExposed || isPublicKind(kind);
    hosts.push(host(ip || "nmap", {
      names, source: "nmap", services, exposed, up: (status && status[1].toLowerCase() === "up") || services.length > 0,
      kind: exposed ? "public" : (isPrivateKind(kind) ? kind : "private"),
    }));
  }
  return hosts;
}

function isPublicKind(kind) { return kind === "public"; }

/**
 * Read one inventory file.
 * format: "sbom" | "nmap" | "list" | "auto"
 * -> { format, problems, hosts }
 */
export function readInventory(text, { file = "inventory", assumeExposed = false, format = "auto", limit = MAX_ITEMS } = {}) {
  const cap = Math.max(1, Math.min(MAX_ITEMS, limit | 0));
  const full = String(text || "");
  const problems = [];
  if (full.length > MAX_BYTES) problems.push(`input longer than ${MAX_BYTES} bytes was cut`);
  const raw = full.slice(0, MAX_BYTES);
  const name = basename(String(file || "inventory")).slice(0, 200) || "inventory";
  const want = format === "nmap" || format === "sbom" || format === "list" ? format : "auto";
  const looksNmap = /^\s*</.test(raw) && /<(nmaprun|host)\b/i.test(raw);
  if (want === "nmap" || (want === "auto" && looksNmap)) return { format: "nmap", problems, hosts: fromNmapXml(raw, { assumeExposed, limit: cap }) };
  const doc = jsonDoc(raw);
  if (doc && !Array.isArray(doc) && Array.isArray(doc.components) && want !== "list") {
    const services = [];
    if (doc.metadata && doc.metadata.component) walkComponents([doc.metadata.component], "CycloneDX", services, cap, 0);
    walkComponents(doc.components, "CycloneDX", services, cap, 0);
    return { format: "CycloneDX", problems, hosts: services.length ? [host(name, { source: "CycloneDX", services, exposed: !!assumeExposed })] : [] };
  }
  if (doc && !Array.isArray(doc) && Array.isArray(doc.packages) && want !== "list") {
    const services = spdxServices(doc, cap);
    return { format: "SPDX", problems, hosts: services.length ? [host(name, { source: "SPDX", services, exposed: !!assumeExposed })] : [] };
  }
  if (want === "sbom") problems.push("the file is not a CycloneDX or SPDX document; it was read as a component list");
  const listed = listServices(name, raw, cap);
  return { format: listed.format, problems, hosts: listed.services.length ? [host(name, { source: "list", services: listed.services, exposed: !!assumeExposed })] : [] };
}
