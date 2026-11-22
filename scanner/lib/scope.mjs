// The scope file and the authorization gate. Pure functions (no network) so the gate can be tested on its own.
// A scan never starts without a scope file that (1) lists the hosts and ranges the operator may scan, (2) records the
// operator's attestation that they own them or are authorized to test them, in the exact words below, and (3) stays inside
// the size limits. Public (non-private) addresses also need --i-am-authorized-for-public-ranges and are capped hard.
import { isIP } from "node:net";

export const SCOPE_VERSION = 1;
/** The attestation the operator must copy, unchanged, into the scope file. */
export const STATEMENT = "I own the systems listed in targets, or I hold written permission from their owner to scan them for known vulnerabilities, and this scan stays within that permission.";
export const PUBLIC_FLAG = "--i-am-authorized-for-public-ranges";
/** Hard limits. None of them can be raised from the command line. */
export const LIMITS = Object.freeze({
  maxEntries: 1024,          // lines in targets
  maxAddresses: 65536,       // addresses after expansion (one /16 at most)
  minPrefix4: 16,            // an IPv4 range may not be wider than a /16
  minPrefix6: 120,           // an IPv6 range may not be wider than a /120 (256 addresses)
  minPublicPrefix4: 24,      // a public IPv4 range may not be wider than a /24
  maxPublicAddresses: 1024,  // public addresses in one scan, even with the confirmation (the hard stop for public space)
  attestationDays: 365,      // an attestation without "expires" must be renewed after a year
  maxDiscoverDomains: 64,    // attested owned domains the discovery step may resolve/expand
  maxDiscoverFiles: 64,      // import/cloud inventory files the discovery step may read
});

const HOST_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.?$/i;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

/* ---- addresses ---- */
function v4ToBig(s) { return s.split(".").reduce((a, p) => (a << 8n) + BigInt(Number(p)), 0n); }
function bigToV4(n) { return [24n, 16n, 8n, 0n].map((k) => String((n >> k) & 255n)).join("."); }
function v6ToBig(s) {
  let t = s.toLowerCase();
  const m4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(t);
  if (m4) { const n = v4ToBig(m4[1]); t = t.slice(0, -m4[1].length) + ((n >> 16n) & 0xffffn).toString(16) + ":" + (n & 0xffffn).toString(16); }
  const [head, tail] = t.split("::"), h = head ? head.split(":") : [], tl = tail !== undefined && tail ? tail.split(":") : [];
  const parts = tail !== undefined ? [...h, ...Array(8 - h.length - tl.length).fill("0"), ...tl] : h;
  return parts.reduce((a, p) => (a << 16n) + BigInt(parseInt(p || "0", 16)), 0n);
}
// the canonical (compressed) form, as the URL parser writes it
function bigToV6(n) { const p = []; for (let i = 7; i >= 0; i--) p.push(((n >> BigInt(i * 16)) & 0xffffn).toString(16)); return new URL(`http://[${p.join(":")}]/`).hostname.slice(1, -1); }
export function toBig(ip) { const v = isIP(ip); return v === 4 ? { v: 4, n: v4ToBig(ip) } : v === 6 ? { v: 6, n: v6ToBig(ip) } : null; }
export function fromBig(v, n) { return v === 4 ? bigToV4(n) : bigToV6(n); }
const inNet = (n, base, bits, width) => (n >> BigInt(width - bits)) === (base >> BigInt(width - bits));

/** What kind of address: loopback, private, link-local, public; or a refused kind (unspecified, multicast, reserved). */
export function classify(ip) {
  const b = toBig(ip); if (!b) return "invalid";
  if (b.v === 4) {
    const n = b.n, at = (s, bits) => inNet(n, v4ToBig(s), bits, 32);
    if (at("0.0.0.0", 8)) return "unspecified";
    if (at("127.0.0.0", 8)) return "loopback";
    if (at("10.0.0.0", 8) || at("172.16.0.0", 12) || at("192.168.0.0", 16)) return "private";
    if (at("169.254.0.0", 16)) return "link-local";
    if (at("224.0.0.0", 4)) return "multicast";
    if (at("240.0.0.0", 4)) return "reserved";   // includes 255.255.255.255
    return "public";
  }
  const n = b.n, at = (s, bits) => inNet(n, v6ToBig(s), bits, 128);
  if (n === 0n) return "unspecified";
  if (n === 1n) return "loopback";
  if (at("::ffff:0:0", 96)) return classify(bigToV4(n & 0xffffffffn));
  if (at("fc00::", 7)) return "private";       // unique local addresses, IPv6's private ranges
  if (at("fe80::", 10)) return "link-local";
  if (at("ff00::", 8)) return "multicast";
  return "public";
}
export const isPrivateKind = (k) => k === "loopback" || k === "private" || k === "link-local";
const REFUSED = { unspecified: "an unspecified address", multicast: "a multicast address", reserved: "a reserved or broadcast address", invalid: "not an address" };

/** One targets/exclude line -> { kind: ip | cidr | host, ... } or { error } */
export function parseTarget(raw) {
  const s = String(raw == null ? "" : raw).trim();
  if (!s) return { error: "empty entry" };
  if (s.length > 260) return { error: "entry too long" };
  const slash = s.indexOf("/");
  if (slash > 0) {
    const ip = s.slice(0, slash), bits = Number(s.slice(slash + 1)), b = toBig(ip);
    if (!b || !/^\d{1,3}$/.test(s.slice(slash + 1))) return { error: `"${s}" is not a CIDR range` };
    const width = b.v === 4 ? 32 : 128;
    if (bits > width) return { error: `"${s}": prefix longer than the address` };
    const base = (b.n >> BigInt(width - bits)) << BigInt(width - bits);
    return { kind: "cidr", v: b.v, base, bits, size: 1n << BigInt(width - bits), text: `${fromBig(b.v, base)}/${bits}` };
  }
  const b = toBig(s);
  if (b) return { kind: "ip", v: b.v, n: b.n, text: fromBig(b.v, b.n) };
  if (HOST_RE.test(s) && /[a-z]/i.test(s)) return { kind: "host", text: s.toLowerCase().replace(/\.$/, "") };
  return { error: `"${s}" is not an address, a CIDR range or a host name` };
}

/** Every address of a parsed target (network and broadcast left out of IPv4 ranges wider than /31). */
export function* addresses(t) {
  if (t.kind === "ip") { yield fromBig(t.v, t.n); return; }
  if (t.kind !== "cidr") return;
  const edge = t.v === 4 && t.bits <= 30;
  for (let i = edge ? 1n : 0n; i < (edge ? t.size - 1n : t.size); i++) yield fromBig(t.v, t.base + i);
}

/** Does a parsed target contain this address? */
export function contains(t, ip) {
  const b = toBig(ip); if (!b || b.v !== t.v) return false;
  if (t.kind === "ip") return b.n === t.n;
  if (t.kind === "cidr") return inNet(b.n, t.base, t.bits, t.v === 4 ? 32 : 128);
  return false;
}

/**
 * Read and check a scope file. text: the file's contents. Returns { ok, problems[], scope }.
 * scope = { owner, contact, attestation, targets[], exclude[], hosts[], ports?, publicCount, addressCount, needsPublic }
 */
export function checkScope(text, { today = new Date().toISOString().slice(0, 10) } = {}) {
  const problems = [];
  let j;
  try { j = JSON.parse(String(text)); } catch { return { ok: false, problems: ["the scope file is not valid JSON"], scope: null }; }
  if (!j || typeof j !== "object" || Array.isArray(j)) return { ok: false, problems: ["the scope file must be a JSON object"], scope: null };
  if (j.cyberview_scope !== SCOPE_VERSION) problems.push(`"cyberview_scope" must be ${SCOPE_VERSION} (start from: node scanner/cyberview-scan.mjs init)`);
  const str = (v, n) => (typeof v === "string" ? v.trim().slice(0, n) : "");
  const owner = str(j.owner, 160), contact = str(j.contact, 160);
  if (owner.length < 2) problems.push(`"owner" must name the organisation or person that owns the targets`);
  // the attestation
  const a = j.attestation && typeof j.attestation === "object" ? j.attestation : {};
  const att = { statement: str(a.statement, 400), agreed: a.agreed === true, name: str(a.name, 120), date: str(a.date, 10), expires: str(a.expires, 10), authorization_ref: str(a.authorization_ref, 200) };
  if (att.statement !== STATEMENT) problems.push(`"attestation.statement" must be exactly: ${STATEMENT}`);
  if (!att.agreed) problems.push(`"attestation.agreed" must be true: you attest that you own the targets or are authorized to scan them`);
  if (att.name.length < 2) problems.push(`"attestation.name" must name the person who attests`);
  if (!DAY_RE.test(att.date)) problems.push(`"attestation.date" must be the date of the attestation (YYYY-MM-DD)`);
  else if (att.date > today) problems.push(`"attestation.date" is in the future`);
  if (att.expires) { if (!DAY_RE.test(att.expires)) problems.push(`"attestation.expires" must be YYYY-MM-DD`); else if (att.expires < today) problems.push(`the attestation expired on ${att.expires}: renew the authorization and the attestation`); }
  else if (DAY_RE.test(att.date)) { const age = (Date.parse(today) - Date.parse(att.date)) / 864e5; if (age > LIMITS.attestationDays) problems.push(`the attestation is more than ${LIMITS.attestationDays} days old: renew it, or set "attestation.expires"`); }
  // targets
  const list = Array.isArray(j.targets) ? j.targets : [], exList = Array.isArray(j.exclude) ? j.exclude : [];
  if (!list.length) problems.push(`"targets" must list at least one host, address or CIDR range; there is no default and nothing is scanned without it`);
  if (list.length > LIMITS.maxEntries) problems.push(`"targets" has ${list.length} entries; at most ${LIMITS.maxEntries}`);
  const targets = [], exclude = [];
  let addressCount = 0n, publicCount = 0n;
  for (const raw of list.slice(0, LIMITS.maxEntries)) {
    const t = parseTarget(raw);
    if (t.error) { problems.push(`targets: ${t.error}`); continue; }
    if (t.kind !== "host") {
      const first = t.kind === "ip" ? fromBig(t.v, t.n) : fromBig(t.v, t.base), last = t.kind === "ip" ? first : fromBig(t.v, t.base + t.size - 1n);
      const k1 = classify(first), k2 = classify(last);
      if (REFUSED[k1] || REFUSED[k2]) { problems.push(`targets: "${t.text}" is or contains ${REFUSED[k1] || REFUSED[k2]}; it cannot be scanned`); continue; }
      if (t.kind === "cidr" && t.v === 4 && t.bits < LIMITS.minPrefix4) { problems.push(`targets: "${t.text}" is wider than a /${LIMITS.minPrefix4}; split it into the ranges you actually own`); continue; }
      if (t.kind === "cidr" && t.v === 6 && t.bits < LIMITS.minPrefix6) { problems.push(`targets: "${t.text}" is wider than a /${LIMITS.minPrefix6}; list the IPv6 addresses you want checked`); continue; }
      t.kinds = [k1, k2]; t.public = !isPrivateKind(k1) || !isPrivateKind(k2);
      if (t.public && t.kind === "cidr" && t.v === 4 && t.bits < LIMITS.minPublicPrefix4) { problems.push(`targets: "${t.text}" is a public range wider than a /${LIMITS.minPublicPrefix4}; the scanner does not sweep public space that wide`); continue; }
      const n = t.kind === "ip" ? 1n : t.size;
      addressCount += n; if (t.public) publicCount += n;
    }
    targets.push(t);
  }
  for (const raw of exList.slice(0, LIMITS.maxEntries)) { const t = parseTarget(raw); if (t.error) problems.push(`exclude: ${t.error}`); else exclude.push(t); }
  if (addressCount > BigInt(LIMITS.maxAddresses)) problems.push(`the targets expand to ${addressCount} addresses; at most ${LIMITS.maxAddresses} in one scan`);
  if (publicCount > BigInt(LIMITS.maxPublicAddresses)) problems.push(`the targets include ${publicCount} public addresses; at most ${LIMITS.maxPublicAddresses} in one scan`);
  // optional port list
  let ports = null;
  if (j.ports !== undefined) {
    if (!Array.isArray(j.ports) || !j.ports.length || j.ports.length > 1024 || j.ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) problems.push(`"ports" must be a list of 1 to 1024 port numbers`);
    else ports = [...new Set(j.ports)];
  }
  // optional discovery block: "find the hosts for me" within the attested scope (see scanner/lib/discover.mjs). Every host it
  // yields is still re-checked by gate() below, so discovery can only ever narrow down the attested scope, never widen it.
  let discover = null;
  if (j.discover !== undefined) {
    const d = j.discover && typeof j.discover === "object" && !Array.isArray(j.discover) ? j.discover : null;
    if (!d) problems.push(`"discover" must be an object (cidr, domains, ct, import, cloud)`);
    else {
      const domains = [];
      for (const raw of (Array.isArray(d.domains) ? d.domains : []).slice(0, LIMITS.maxDiscoverDomains)) {
        const t = parseTarget(raw);
        if (t.kind === "host" && /\./.test(t.text)) domains.push(t.text);
        else problems.push(`discover.domains: "${raw}" is not a domain name you own`);
      }
      const fileList = (key) => {
        const out = [];
        for (const e of (Array.isArray(d[key]) ? d[key] : []).slice(0, LIMITS.maxDiscoverFiles)) {
          const file = typeof e === "string" ? e : e && typeof e === "object" ? str(e.file, 300) : "";
          if (!file) { problems.push(`discover.${key}: each entry needs a "file"`); continue; }
          out.push(key === "cloud" ? { file, provider: str((e && e.provider) || "aws-ec2", 20) } : { file, format: str((e && e.format) || "auto", 20) });
        }
        return out;
      };
      if (d.ct && !(Array.isArray(d.domains) && d.domains.length)) problems.push(`discover.ct needs discover.domains (the domains you own) to expand`);
      discover = { cidr: d.cidr === true, domains, ct: d.ct === true, import: fileList("import"), cloud: fileList("cloud") };
    }
  }
  const scope = { owner, contact, attestation: att, targets, exclude, ports, discover, addressCount: Number(addressCount), publicCount: Number(publicCount),
    hosts: targets.filter((t) => t.kind === "host").map((t) => t.text), needsPublic: publicCount > 0n };
  return { ok: problems.length === 0, problems, scope };
}

/** Is a host name inside the attested scope? A listed host target, an attested discovery domain, or a subdomain of one. */
export function hostInScope(scope, host) {
  const h = String(host || "").toLowerCase();
  if (!h) return false;
  if (scope.hosts.includes(h)) return true;
  const domains = (scope.discover && scope.discover.domains) || [];
  return domains.some((d) => h === d || h.endsWith("." + d));
}

/** Is a resolved address inside the scope (and not excluded)? A listed or discovered host name covers the addresses it resolves to. */
export function inScope(scope, ip, viaHost = "") {
  if (scope.exclude.some((t) => contains(t, ip) || (t.kind === "host" && viaHost && t.text === viaHost))) return false;
  if (viaHost && hostInScope(scope, viaHost)) return true;
  return scope.targets.some((t) => contains(t, ip));
}

/**
 * The gate for one address about to be probed: { ok, why }. Refuses anything outside the scope, any refused kind, and
 * public addresses unless the operator gave the public-range confirmation.
 */
export function gate(scope, ip, { allowPublic = false, viaHost = "" } = {}) {
  const k = classify(ip);
  if (REFUSED[k]) return { ok: false, why: `${ip} is ${REFUSED[k]}` };
  if (!inScope(scope, ip, viaHost)) return { ok: false, why: `${ip}${viaHost ? ` (${viaHost})` : ""} is not in the scope file` };
  if (!isPrivateKind(k) && !allowPublic) return { ok: false, why: `${ip} is a public address: scanning it needs ${PUBLIC_FLAG}` };
  return { ok: true, why: "", kind: k };
}

/** Every address the scope lists directly (host names are resolved by the caller), exclusions removed. */
export function listAddresses(scope) {
  const out = [], seen = new Set();
  for (const t of scope.targets) for (const ip of addresses(t)) {
    if (seen.has(ip) || scope.exclude.some((x) => contains(x, ip))) continue;
    seen.add(ip); out.push(ip);
    if (out.length > LIMITS.maxAddresses) return out;
  }
  return out;
}

/** A new scope file for the operator to fill in: nothing is agreed and no target is listed. */
export function template(today = new Date().toISOString().slice(0, 10)) {
  return {
    cyberview_scope: SCOPE_VERSION,
    owner: "",
    contact: "",
    attestation: { statement: STATEMENT, agreed: false, name: "", date: today, expires: "", authorization_ref: "" },
    targets: [],
    exclude: [],
    discover: { cidr: true, domains: [], ct: false, import: [], cloud: [] },
    _help: "List only hosts, addresses and CIDR ranges you own or are authorized in writing to scan. Set attestation.agreed to true and fill in your name to attest. Private ranges (10/8, 172.16/12, 192.168/16, loopback) run with this file alone; a public address also needs " + PUBLIC_FLAG + " on the command line. Optional 'discover' finds the hosts for you WITHIN this attested scope: cidr sweeps your ranges, domains (that you own) are resolved and, with ct, expanded from Certificate Transparency, import reads an asset list (host/IP list, CSV or nmap -oX XML, as {\"file\":\"assets.csv\"}), cloud reads the JSON your own read-only aws/az/gcloud command printed (as {\"file\":\"ec2.json\",\"provider\":\"aws-ec2\"}). Anything discovered outside this scope is dropped. See scanner/README.md.",
  };
}
