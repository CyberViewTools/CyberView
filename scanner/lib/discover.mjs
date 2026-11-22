// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Discovery: turn the "find the hosts for me" entries in the scope file into candidate host names and addresses, so the
// operator never hand-lists every host. NOTHING here decides what is scanned: every candidate is handed back with its
// provenance and then re-checked against the attested scope by the gate in scope.mjs (an address or name outside the scope,
// or a public one without the confirmation and under the public cap, is dropped and logged, never scanned).
//
//   cidr     the attested CIDR ranges are swept for live hosts (expanded by scope.mjs, liveness-checked by scan.mjs): no code here
//   domains  attested owned domains are resolved; with ct, subdomains are read from Certificate Transparency logs (read-only GET)
//   import   an asset list (plain host/IP list, CSV, or nmap -oX XML) is parsed
//   cloud    the operator's OWN read-only cloud inventory (the JSON their aws/az/gcloud CLI prints) is parsed for public IPs/DNS
// The scanner never runs the cloud CLI itself and never asks for or stores cloud keys: the operator runs the read-only
// describe/list command with their own local credentials and points `cloud` at the saved JSON. See docs/scanner.md.
import { parseTarget } from "./scope.mjs";
import { USER_AGENT } from "./probe.mjs";

const clip = (s, n) => String(s == null ? "" : s).slice(0, n);
const HOSTISH = /^[a-z0-9.\-:_]+$/i;             // for CT names (already bare host names)
export const MAX_DISCOVERED = 65536;            // a discovery run may not propose more than one /16's worth of hosts
export const CT_HOST = "crt.sh";                // the Certificate Transparency source (its documented JSON endpoint)

/** A token from a file -> { ip } | { cidr } | { host } (lower-cased), or null. parseTarget validates; CIDR/IPv6 are kept as-is. */
function asCandidate(tok, source) {
  const raw = clip(String(tok || "").trim().replace(/^https?:\/\//i, ""), 260);
  // try the token as-is first (so a CIDR or an IPv6 address with colons parses), then fall back to stripping a URL path and/or :port
  for (const s of [raw, raw.replace(/\/.*$/, ""), raw.replace(/:\d+$/, ""), raw.replace(/\/.*$/, "").replace(/:\d+$/, "")]) {
    if (!s) continue;
    const t = parseTarget(s);
    if (t.error) continue;
    if (t.kind === "ip") return { ip: t.text, source };
    if (t.kind === "host") return { host: t.text, source };
    if (t.kind === "cidr") return { cidr: t.text, source };   // a range in the file is passed through for the gate to expand
  }
  return null;
}

/* ---- asset files: plain list, CSV, nmap -oX XML ---- */
const IPCOL = /^(ip|ip_?address|address|public_?ip|publicip|private_?ip|host|hostname|fqdn|dns|dns_?name|name)$/i;
export function parseAssetFile(text, format = "auto") {
  const s = String(text || ""), out = [], problems = [];
  const fmt = format === "auto" ? (/^\s*</.test(s) && /<(nmaprun|host)\b/.test(s) ? "nmap-xml" : /,/.test(s.split(/\r?\n/).find((l) => l.trim()) || "") ? "csv" : "list") : format;
  const push = (c) => { if (c) out.push(c); };
  if (fmt === "nmap-xml") {
    for (const m of s.matchAll(/<address\s+addr="([^"]+)"\s+addrtype="ipv[46]"/gi)) push(asCandidate(m[1], "import:nmap"));
    for (const m of s.matchAll(/<hostname\s+name="([^"]+)"/gi)) push(asCandidate(m[1], "import:nmap"));
  } else if (fmt === "csv") {
    const rows = s.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => l.split(",").map((x) => x.trim().replace(/^"|"$/g, "")));
    if (!rows.length) return { candidates: [], problems };
    const header = rows[0].map((h) => h.toLowerCase());
    const cols = header.map((h, i) => (IPCOL.test(h) ? i : -1)).filter((i) => i >= 0);
    const hasHeader = cols.length > 0 || header.some((h) => IPCOL.test(h));
    const take = cols.length ? cols : [0];
    for (const r of rows.slice(hasHeader ? 1 : 0)) for (const i of take) if (r[i]) push(asCandidate(r[i], "import:csv"));
  } else {
    for (const line of s.split(/\r?\n/)) { const t = line.replace(/#.*$/, "").trim(); if (t) push(asCandidate(t, "import:list")); }
  }
  return { candidates: dedupe(out), problems };
}

/* ---- cloud: parse the JSON a read-only describe/list command prints (no CLI is run here) ---- */
const AWS = (j) => {   // aws ec2 describe-instances
  const out = [];
  for (const r of arr(j.Reservations)) for (const i of arr(r.Instances)) {
    if (i.PublicIpAddress) out.push(asCandidate(i.PublicIpAddress, "cloud:aws-ec2"));
    if (i.PublicDnsName) out.push(asCandidate(i.PublicDnsName, "cloud:aws-ec2"));
    for (const ni of arr(i.NetworkInterfaces)) if (ni.Association && ni.Association.PublicIp) out.push(asCandidate(ni.Association.PublicIp, "cloud:aws-ec2"));
  }
  return out;
};
const AWS_ELB = (j) => arr(j.LoadBalancers).map((lb) => asCandidate(lb.DNSName, "cloud:aws-elb"));
const GCP = (j) => {   // gcloud compute instances list --format=json
  const out = [];
  for (const i of arr(j)) for (const ni of arr(i.networkInterfaces)) for (const ac of arr(ni.accessConfigs)) if (ac.natIP) out.push(asCandidate(ac.natIP, "cloud:gcp"));
  return out;
};
const AZURE = (j) => {  // az network public-ip list  OR  az vm list-ip-addresses
  const out = [];
  for (const o of arr(Array.isArray(j) ? j : [j])) {
    if (o.ipAddress) out.push(asCandidate(o.ipAddress, "cloud:azure"));
    const vm = o.virtualMachine && o.virtualMachine.network;
    for (const p of arr(vm && vm.publicIpAddresses)) if (p.ipAddress) out.push(asCandidate(p.ipAddress, "cloud:azure"));
  }
  return out;
};
const CLOUD = { "aws-ec2": AWS, "aws-elb": AWS_ELB, gcp: GCP, azure: AZURE };
export function parseCloud(text, provider = "aws-ec2") {
  const problems = [];
  let j; try { j = JSON.parse(String(text || "")); } catch { return { candidates: [], problems: [`cloud inventory for ${provider} is not valid JSON`] }; }
  const fn = CLOUD[provider]; if (!fn) return { candidates: [], problems: [`unknown cloud provider "${provider}" (use aws-ec2, aws-elb, gcp or azure)`] };
  let got = []; try { got = fn(j).filter(Boolean); } catch (e) { problems.push(`could not read the ${provider} inventory: ${clip(e.message, 80)}`); }
  return { candidates: dedupe(got), problems };
}

/* ---- Certificate Transparency: read subdomains of an attested owned domain (read-only GET) ---- */
function validDomain(d) { const t = parseTarget(String(d || "")); return t.kind === "host" && /\./.test(t.text) ? t.text : ""; }
export function parseCtJson(text, domain) {
  const out = new Set(); let rows;
  try { rows = JSON.parse(String(text || "")); } catch { return []; }
  for (const r of arr(rows)) for (const nv of String((r && r.name_value) || "").split(/\s+/)) {
    const name = nv.replace(/^\*\./, "").toLowerCase().trim();
    if (name && name.endsWith("." + domain) && !name.includes("*") && HOSTISH.test(name)) out.add(name);   // the domain's own subdomains (the apex is resolved separately)
  }
  return [...out].slice(0, MAX_DISCOVERED);
}
/** Read subdomains for one domain from crt.sh, read-only GET, retried once. The caller must have the operator's attestation. */
export async function ctSubdomains(domain, { fetchImpl = globalThis.fetch, timeoutMs = 30000, log = () => {} } = {}) {
  const d = validDomain(domain);
  if (!d) return { subdomains: [], problems: [`"${domain}" is not a domain name for Certificate Transparency lookup`] };
  const url = `https://${CT_HOST}/?q=${encodeURIComponent("%." + d)}&output=json`;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const r = await fetchImpl(url, { method: "GET", headers: { "User-Agent": USER_AGENT, Accept: "application/json" }, redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const subs = parseCtJson(await r.text(), d);
      log(`Certificate Transparency (${CT_HOST}) for ${d}: ${subs.length} name(s)`);
      return { subdomains: subs, problems: [] };
    } catch (e) { if (attempt === 1) return { subdomains: [], problems: [`Certificate Transparency lookup for ${d} failed: ${clip(e.message, 80)}`] }; await new Promise((res) => setTimeout(res, 2000)); }
  }
  return { subdomains: [], problems: [] };
}

/**
 * Run every configured discovery source and return the candidate names/addresses with provenance (NOT yet gated).
 * opts: { fetchImpl (CT), readFile (import/cloud; path -> text), log }. Pure except CT (fetchImpl) and readFile.
 * -> { hosts: [{host, source}], ips: [{ip, source}], ranges: [{cidr, source}], notes[], problems[] }
 */
export async function runDiscovery(scope, { fetchImpl = globalThis.fetch, readFile, log = () => {} } = {}) {
  const d = scope.discover || {}, hosts = [], ips = [], ranges = [], notes = [], problems = [];
  const take = (c) => { if (!c) return; if (c.host) hosts.push({ host: c.host, source: c.source }); else if (c.ip) ips.push({ ip: c.ip, source: c.source }); else if (c.cidr) ranges.push({ cidr: c.cidr, source: c.source }); };
  if (d.cidr && scope.targets.some((t) => t.kind === "cidr")) notes.push("cidr: the attested CIDR ranges are swept for live hosts");
  for (const dom of d.domains || []) {
    hosts.push({ host: dom, source: "domain" });
    if (d.ct) { const { subdomains, problems: p } = await ctSubdomains(dom, { fetchImpl, log }); subdomains.forEach((s) => hosts.push({ host: s, source: "CT log" })); problems.push(...p); }
  }
  for (const entry of d.import || []) {
    const file = typeof entry === "string" ? entry : entry && entry.file;
    if (!file || !readFile) { problems.push(`import: cannot read "${file || entry}"`); continue; }
    let text; try { text = readFile(file); } catch (e) { problems.push(`import: could not read ${file}: ${clip(e.message, 80)}`); continue; }
    const { candidates, problems: p } = parseAssetFile(text, (entry && entry.format) || "auto");
    candidates.forEach(take); problems.push(...p);
    notes.push(`import ${file}: ${candidates.length} host(s)/address(es)`);
  }
  for (const entry of d.cloud || []) {
    const file = entry && entry.file, provider = (entry && entry.provider) || "aws-ec2";
    if (!file || !readFile) { problems.push(`cloud: cannot read "${file}"`); continue; }
    let text; try { text = readFile(file); } catch (e) { problems.push(`cloud: could not read ${file}: ${clip(e.message, 80)}`); continue; }
    const { candidates, problems: p } = parseCloud(text, provider);
    candidates.forEach(take); problems.push(...p);
    notes.push(`cloud ${provider} (${file}): ${candidates.length} public asset(s)`);
  }
  return { hosts: dedupeBy(hosts, "host"), ips: dedupeBy(ips, "ip"), ranges: dedupeBy(ranges, "cidr"), notes, problems };
}

function arr(x) { return Array.isArray(x) ? x : []; }
function dedupe(list) { const seen = new Set(), out = []; for (const c of list) if (c) { const k = c.ip || c.host || c.cidr; if (!seen.has(k)) { seen.add(k); out.push(c); } } return out; }
function dedupeBy(list, key) { const seen = new Set(), out = []; for (const c of list) if (!seen.has(c[key])) { seen.add(c[key]); out.push(c); } return out; }
