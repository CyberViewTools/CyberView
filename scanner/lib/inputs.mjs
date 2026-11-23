// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
//
// Adapters for inputs the operator ALREADY HOLDS, so a defender who cannot scan (change freeze, third-party or
// air-gapped assets, "scanning is forbidden", or they only have an SBOM from CI) still gets the scanner's matching
// and rating. Nothing here contacts any host: these are file parsers only, and they return the same host/service
// records that fingerprint.mjs builds from a real probe, so match.mjs findings() judges them identically.
//
//   nmap -oX XML   real host/port/product/version, plus <cpe> when nmap states one
//   CPE / purl     vendor and product in the form NVD's affected ranges use
//   inventory      an SBOM or package list has no address: it becomes ONE pseudo-host named after the file
//
// Untrusted input: an XML or SBOM file can be attacker-crafted, so every field is clipped and control characters
// stripped (clip/cleanVersion), every list is capped (INPUT_LIMITS), and parsing is JSON.parse + regex only (no XML
// library, no network, no spawn) — the same rails as discover.mjs, so security-check.mjs section 7 stays green.
import { svc, distroOf } from "./fingerprint.mjs";
import { classify, isPrivateKind } from "./scope.mjs";

export const INPUT_LIMITS = Object.freeze({
  maxBytes: 16 * 1024 * 1024,   // any one input file
  hosts: 5000,                  // hosts read from one nmap file
  portsPerHost: 200,            // open ports read for one host
  services: 20000,              // service records in total
  names: 20,                    // hostnames kept per host
  items: 5000,                  // inventory items (IMPORT_LIMITS.items)
  str: 200,
});

const clip = (v, n = INPUT_LIMITS.str) => (typeof v === "string" || typeof v === "number" ? String(v) : "")
  .replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, " ").trim().slice(0, n);

// XML entities, numeric ones included; bounded so a crafted file cannot blow up the string
const unxml = (s) => clip(s, 400)
  .replace(/&#x([0-9a-f]{1,6});/gi, (_, h) => cp(parseInt(h, 16)))
  .replace(/&#(\d{1,7});/g, (_, d) => cp(parseInt(d, 10)))
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
const cp = (n) => (Number.isFinite(n) && n >= 32 && n !== 127 && n <= 0x10ffff ? String.fromCodePoint(n) : " ");

/** One attribute of an XML start tag, unescaped. */
export function attr(tag, name) {
  const m = new RegExp(`\\s${name}="([^"]*)"`, "i").exec(String(tag || ""));
  return m ? unxml(m[1]) : "";
}

/* ---- CPE and purl: vendor and product in the form NVD's affected ranges use ---- */

// cpe:/a:openbsd:openssh:8.2p1  (2.2)   cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*  (2.3)
export function parseCpe(cpe) {
  const s = clip(cpe, 300);
  const m23 = /^cpe:2\.3:([aho*-]):([^:]*):([^:]*):([^:]*)/i.exec(s);
  const m22 = /^cpe:\/([aho*-]):([^:]*):([^:]*)(?::([^:]*))?/i.exec(s);
  const m = m23 || m22;
  if (!m) return null;
  const part = (v) => clip(v, 80).replace(/\\(.)/g, "$1").replace(/%([0-9a-f]{2})/gi, (_, h) => cp(parseInt(h, 16))).replace(/_/g, " ").trim();
  const any = (v) => (v === "*" || v === "-" || v === "" ? "" : v);
  const vendor = any(part(m[2])), product = any(part(m[3])), version = any(part(m[4] || ""));
  if (!product) return null;
  return { kind: m[1].toLowerCase(), vendor, product, version };
}

// pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1   pkg:npm/%40scope/name@1.2.3
export function parsePurl(purl) {
  const s = clip(purl, 300);
  const m = /^pkg:([a-z0-9.+-]+)\/(.+)$/i.exec(s);
  if (!m) return null;
  const type = m[1].toLowerCase();
  const [path, version = ""] = m[2].split("@", 2);
  const segs = path.split("/").map((x) => clip(decodeOnce(x), 80)).filter(Boolean);
  if (!segs.length) return null;
  const product = segs[segs.length - 1];
  const vendor = segs.length > 1 ? segs[segs.length - 2].replace(/^@/, "") : "";
  if (!product) return null;
  return { type, vendor, product, version: clip(version.split("?")[0].split("#")[0], 40) };
}
const decodeOnce = (s) => String(s).replace(/%([0-9a-f]{2})/gi, (_, h) => cp(parseInt(h, 16)));

/**
 * The name the matcher sees. nmap's own product string is the label; a CPE product that adds words the label does not
 * have is appended, because workbench-lib nameHit needs every word of the range's product to appear in the name.
 */
export function mergeName(product, cpeProduct) {
  const base = clip(product, 120), extra = clip(cpeProduct, 120);
  if (!base) return extra;
  if (!extra) return base;
  const words = new Set(base.toLowerCase().split(/[^a-z0-9]+/i).filter(Boolean));
  const missing = extra.toLowerCase().split(/[^a-z0-9]+/i).filter(Boolean).some((w) => !words.has(w));
  return missing ? clip(`${base} ${extra}`, 120) : base;
}

/* ---- nmap -oX XML ---- */

const OPEN = /\bstate="open(?:\|filtered)?"/i;

/** One <port>...</port> block -> a service record (fingerprint.mjs shape), or null. */
export function serviceFromPort(block) {
  const open = /<state\b[^>]*>/i.exec(block);
  if (!open || !OPEN.test(open[0])) return null;                      // closed and filtered ports say nothing
  const tag = /<port\b[^>]*>/i.exec(block);
  const port = Number(attr(tag ? tag[0] : "", "portid"));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  const proto = (attr(tag ? tag[0] : "", "protocol") || "tcp").toLowerCase() === "udp" ? "udp" : "tcp";
  const svcTag = /<service\b[^>]*>/i.exec(block);
  if (!svcTag) return null;                                           // an open port with no service line is not a product
  const t = svcTag[0];
  const name = attr(t, "name"), product = attr(t, "product"), version = attr(t, "version");
  const extrainfo = attr(t, "extrainfo"), ostype = attr(t, "ostype"), method = attr(t, "method").toLowerCase();
  const conf = Number(attr(t, "conf"));
  const cpes = [];
  for (const m of String(block).matchAll(/<cpe>([^<]{0,300})<\/cpe>/gi)) { const c = parseCpe(unxml(m[1])); if (c) cpes.push(c); if (cpes.length >= 8) break; }
  const app = cpes.find((c) => c.kind === "a") || cpes.find((c) => c.kind !== "o") || null;
  const label = product || (app && app.product) || "";
  if (!label) return null;                                            // nmap named the port only (ssh, http): no product
  // nmap's version attribute often carries descriptive text after the number ("8.2p1 Ubuntu 4ubuntu0.5"):
  // the leading version token is what the ranges are compared with, the rest names the distribution build
  const raw = version || (app && app.version) || "";
  const vm = /^v?(\d[\w.+~]*)/.exec(raw);
  const ver = vm ? vm[1] : "";
  const rest = vm ? raw.slice(vm[0].length) : raw;
  // "table" means nmap read the port number out of nmap-services and never spoke to the service
  const guessed = !ver || method === "table" || (Number.isFinite(conf) && conf < 8);
  const stated = [product, version, extrainfo && `(${extrainfo})`].filter(Boolean).join(" ");
  return svc(port, proto, (app && app.vendor) || "", mergeName(label, app && app.product), ver, {
    label: clip(product || label, 120),
    distro: distroOf(`${rest} ${extrainfo} ${ostype}`),
    source: `nmap -oX service line${method ? ` (${method === "table" ? "port table, not probed" : method})` : ""}`,
    evidence: clip(`nmap: ${name || proto}/${port} ${stated || label}${app ? ` ${app.vendor ? app.vendor + ":" : ""}${app.product}` : ""}`, 200),
    guessed,
  });
}

/**
 * nmap -oX output -> { hosts, problems, stats }. hosts carry the same shape resolveScope/probeAll produce, so
 * match.mjs findings() needs no change. Hosts nmap reported as down, and ports it reported as closed, are skipped.
 */
export function parseNmapXml(text) {
  const s = String(text || ""), problems = [];
  if (!/<(?:nmaprun|host)\b/i.test(s)) return { hosts: [], problems: ["--nmap: not nmap -oX XML (no <nmaprun> or <host> element)"], stats: { hosts: 0, services: 0, skipped_down: 0 } };
  const hosts = [];
  let services = 0, down = 0, over = 0;
  for (const hm of s.matchAll(/<host\b[\s\S]{0,400000}?<\/host>/gi)) {
    if (hosts.length >= INPUT_LIMITS.hosts) { over++; continue; }
    const block = hm[0];
    const st = /<status\b[^>]*>/i.exec(block);
    if (st && /state="(down|unknown|skipped)"/i.test(st[0])) { down++; continue; }
    const am = /<address\b[^>]*addrtype="ipv[46]"[^>]*>/i.exec(block) || /<address\b[^>]*>/i.exec(block);
    const address = am ? attr(am[0], "addr") : "";
    if (!address || classify(address) === "invalid") { problems.push("--nmap: a <host> with no usable IP address was skipped"); continue; }
    const names = [];
    for (const nm of block.matchAll(/<hostname\b[^>]*>/gi)) { const n = attr(nm[0], "name"); if (n && !names.includes(n)) names.push(clip(n, 253)); if (names.length >= INPUT_LIMITS.names) break; }
    const kind = classify(address), list = [], ports = [];
    for (const pm of block.matchAll(/<port\b[\s\S]{0,20000}?<\/port>/gi)) {
      if (ports.length >= INPUT_LIMITS.portsPerHost || services >= INPUT_LIMITS.services) { over++; break; }  
      const sv = serviceFromPort(pm[0]);
      const tag = /<port\b[^>]*>/i.exec(pm[0]);
      const open = /<state\b[^>]*>/i.exec(pm[0]);
      const p = Number(attr(tag ? tag[0] : "", "portid"));
      if (open && OPEN.test(open[0]) && Number.isInteger(p) && p >= 1 && p <= 65535 && !ports.some((x) => x.port === p)) {
        ports.push({ port: p, state: "open", services: sv ? 1 : 0, banner: sv ? clip(sv.evidence, 160) : "" });
      }
      if (!sv) continue;
      list.push(sv); services++;
    }
    hosts.push({ address, names, kind, public: !isPrivateKind(kind), up: true, source: "nmap -oX import", ports, services: list, http: null, tls: null, udp: [], observations: [] });
  }
  if (over) problems.push(`--nmap: the file is over the caps (${INPUT_LIMITS.hosts} hosts, ${INPUT_LIMITS.portsPerHost} ports per host, ${INPUT_LIMITS.services} services); the rest was not read`);
  if (down) problems.push(`--nmap: ${down} host(s) nmap reported as down were skipped`);
  if (!hosts.length && !problems.length) problems.push("--nmap: no host with an open port and a service line; run nmap with -sV so it states products and versions");
  return { hosts, problems, stats: { hosts: hosts.length, services, skipped_down: down } };
}

/**
 * An SBOM, package list or component list has no address, so it becomes ONE pseudo-host named after the file.
 * assumeExposed is the operator's own statement that this inventory is internet-facing (--assume-exposed); without it
 * the inventory is rated as internal, which is the safe default — the CyberView rating itself is exposure-independent,
 * only CISA's SSVC deadline changes.
 */
export function inventoryHost(items, { file = "inventory", assumeExposed = false, proto = "list" } = {}) {
  const address = clip(file, 120) || "inventory";
  const services = [];
  for (const x of (Array.isArray(items) ? items : []).slice(0, INPUT_LIMITS.items)) {
    const name = clip(x && x.name, 120);
    if (!name) continue;
    const version = clip(x && x.version, 40);
    const from = clip(x && x.from, 40);
    services.push(svc(null, proto, clip(x && x.vendor, 80), name, version, {
      label: name,
      distro: clip(x && x.distro, 40) || distroOf(clip(x && x.raw_version, 80)),
      source: from ? `imported ${from}` : "imported list",
      evidence: clip(`${from || "import"}: ${name}${version ? " " + version : " (no version stated)"}`, 200),
      guessed: !version,
    }));
  }
  return {
    address, names: [], kind: assumeExposed ? "public" : "private", public: !!assumeExposed, up: true,
    source: assumeExposed ? "imported inventory (operator states it is internet-facing)" : "imported inventory (rated as internal; --assume-exposed to rate it as internet-facing)",
    ports: [], services, http: null, tls: null, udp: [], observations: [],
  };
}
