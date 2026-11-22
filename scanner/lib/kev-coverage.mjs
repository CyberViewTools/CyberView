// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// KEV fingerprint coverage gap (scan-kev-coverage): which vendor/product pairs in the local KEV snapshot (data/workbench.json
// from a `data` snapshot) the scanner can identify, and which it cannot, so later fingerprint work can be aimed. PURE and
// offline: no target, no network, no scan; it compares two local lists with the site's own name matcher (W.matchFlaw).
// Many KEV products are client or desktop software that no network scanner identifies from a greeting; a gap is a fact
// about this scanner's fingerprints, not a claim that the product is exposed or detectable at all.
import { W } from "./shared.mjs";
import { FINGERPRINT_TABLES } from "./fingerprint.mjs";
import { cleanFlaws } from "./match.mjs";

/**
 * Products fingerprint.mjs names outside its tables (in fromSsh, fromMysql, fromHttp, fromUdp). version: true when the
 * parser reads a version that is matched against the ranges. tests/unit/scanner-reportpack.test.mjs proves each one is
 * really produced by the parser it names, so this list cannot drift silently from the code.
 */
export const INLINE = Object.freeze([
  { vendor: "OpenBSD", product: "OpenSSH", version: true, via: "SSH banner" },
  { vendor: "Dropbear SSH Project", product: "Dropbear SSH", version: true, via: "SSH banner" },
  { vendor: "libssh", product: "libssh", version: true, via: "SSH banner" },
  { vendor: "MariaDB", product: "MariaDB", version: true, via: "MySQL handshake" },
  { vendor: "Oracle", product: "MySQL", version: true, via: "MySQL handshake" },
  { vendor: "Eclipse", product: "Jetty", version: true, via: "HTTP Server header" },
  { vendor: "Microsoft", product: "Exchange Server", version: true, via: "HTTP X-OWA-Version header" },
  { vendor: "WordPress", product: "WordPress", version: true, via: "page generator tag" },
  { vendor: "Drupal", product: "Drupal", version: false, via: "page generator tag" },
  { vendor: "Joomla", product: "Joomla!", version: false, via: "page generator tag" },
  { vendor: "ISC", product: "BIND", version: true, via: "DNS version.bind (--udp)" },
  { vendor: "NTP Project", product: "NTP", version: true, via: "NTP mode-6 read (--udp)" },
]);

const groups = (re) => new RegExp(`${re.source}|`).exec("").length - 1;   // capture groups in a fixed table regex (version read when > 0)

/** Every product the scanner can name -> [{ vendor, product, version, via }] (one entry per product, version wins). */
export function fingerprintProducts() {
  const m = new Map(), add = (x) => { const k = `${x.vendor}|${x.product}`; const o = m.get(k); if (!o || (!o.version && x.version)) m.set(k, x); };
  for (const [re, vendor, product, proto] of FINGERPRINT_TABLES.GREET) add({ vendor, product, version: groups(re) > 0, via: `${proto.toUpperCase()} greeting` });
  for (const [, vendor, product, flag] of FINGERPRINT_TABLES.SERVER) if (product) add({ vendor, product, version: flag !== "no-version", via: "HTTP Server / X-Powered-By header" });
  for (const [, vendor, product] of FINGERPRINT_TABLES.CERT_HINTS) add({ vendor, product, version: false, via: "TLS certificate (product inferred)" });
  INLINE.forEach(add);
  return [...m.values()];
}

/**
 * workbench.json -> { kev_total, products, covered_version, covered_name_only, gaps[], covered[] }
 *   coverage per KEV vendor/product: "version" (a fingerprint reads a version the ranges can be checked against),
 *   "name only" (the product can be named but its version is not read: findings stay low confidence), "none" (a gap).
 */
export function kevCoverage(wb, { products = fingerprintProducts() } = {}) {
  const kev = cleanFlaws(wb).filter((f) => f.kev), by = new Map();
  for (const f of kev) {
    const k = `${f.vendor}|${f.product}`;
    if (!by.has(k)) {
      const hit = products.filter((p) => { const r = W.matchFlaw(f, [{ name: p.product, vendor: p.vendor, version: "", count: 1 }]); return r && r.state !== "none"; });
      by.set(k, { vendor: f.vendor, product: f.product, kev_cves: 0, ransomware_cves: 0, cves: [], coverage: hit.some((p) => p.version) ? "version" : hit.length ? "name only" : "none",
        fingerprints: hit.map((p) => `${p.vendor} ${p.product} (${p.via})`.trim()).slice(0, 4) });
    }
    const g = by.get(k); g.kev_cves++; if (f.ransomware) g.ransomware_cves++; if (g.cves.length < 8) g.cves.push(f.cve);
  }
  const all = [...by.values()].sort((a, b) => b.kev_cves - a.kev_cves || b.ransomware_cves - a.ransomware_cves || `${a.vendor} ${a.product}`.localeCompare(`${b.vendor} ${b.product}`));
  const sum = (c) => all.filter((g) => g.coverage === c).reduce((n, g) => n + g.kev_cves, 0);
  return { kev_total: kev.length, products: all.length, fingerprints: products.length,
    covered_version: sum("version"), covered_name_only: sum("name only"), not_covered: sum("none"),
    gaps: all.filter((g) => g.coverage === "none"), covered: all.filter((g) => g.coverage !== "none"),
    note: "Computed from the local KEV snapshot and this scanner's fingerprint tables only; no network. A gap says the scanner cannot name the product, not that the product is exposed; much of the KEV catalog is client software no network scan can identify." };
}

const cell = (v) => { let s = v == null ? "" : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
export const COVERAGE_HEAD = ["vendor", "product", "kev_cves", "ransomware_cves", "coverage", "fingerprints", "example_cves"];
export function toCoverageCsv(c) {
  return [COVERAGE_HEAD, ...[...c.gaps, ...c.covered].map((g) => [g.vendor, g.product, g.kev_cves, g.ransomware_cves, g.coverage, g.fingerprints.join("; "), g.cves.join(" ")])].map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}
export function coverageText(c) {
  const L = [`KEV coverage: ${c.kev_total} known-exploited CVE(s) across ${c.products} vendor/product pair(s); the scanner has ${c.fingerprints} fingerprint(s).`,
    `  ${c.covered_version} CVE(s) on products whose version the scanner reads, ${c.covered_name_only} on products it can only name, ${c.not_covered} on products it cannot identify (${c.gaps.length} pair(s)).`];
  if (c.gaps.length) { L.push("  Largest gaps (KEV CVEs):"); c.gaps.slice(0, 15).forEach((g) => L.push(`   ${g.vendor} ${g.product}: ${g.kev_cves}${g.ransomware_cves ? ` (${g.ransomware_cves} used by ransomware)` : ""}`)); }
  L.push(`  ${c.note}`);
  return L.join("\n");
}
