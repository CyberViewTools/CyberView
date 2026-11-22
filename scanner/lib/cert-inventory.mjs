// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Certificate inventory (scan-cert-inventory): a table of the leaf certificates this scan's one TLS handshake per port
// already returned, with certificate and key reuse across hosts, internal names and wildcards in the subject alternative
// name, SCTs, OCSP must-staple and short validity. PURE: no network, nothing is sent; it reads only what probe.mjs already
// recorded (the certificate's own DER, parsed with a bounded reader and never trusted) and what report.json holds.
// Inventory, not findings: nothing here enters the headline counts or the observations.
import { createHash } from "node:crypto";
import { certInfo, nameMatches } from "./fingerprint.mjs";
import { classify, isPrivateKind } from "./scope.mjs";

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n);

// fixed, documented thresholds and name lists (docs/orchestration/handoff/scan-report-pack.md)
export const CERT_RULES = Object.freeze({
  shortLivedDays: 10,   // a validity window of 10 days or less: the range short-lived ACME certificates are issued in
  // names that only resolve inside a private network (RFC 6762 .local, RFC 6761 .localhost, RFC 8375 .home.arpa, the
  // reserved .internal, and the common private suffixes); a name with no dot at all is a single-label (internal) name
  internalSuffixes: [".local", ".localhost", ".localdomain", ".internal", ".intranet", ".lan", ".corp", ".private", ".home.arpa"],
  maxSanDns: 100, maxSanIp: 50,
});
const OID = { san: "2.5.29.17", sct: "1.3.6.1.4.1.11129.2.4.2", tlsFeature: "1.3.6.1.5.5.7.1.24" };

/* ---- a bounded ASN.1 DER reader: one TLV at a time, every length checked against the buffer ---- */
function tlv(b, i) {
  if (!b || i + 2 > b.length) return null;
  const tag = b[i]; let len = b[i + 1], o = i + 2;
  if (len & 0x80) { const n = len & 0x7f; if (n < 1 || n > 4 || o + n > b.length) return null; len = 0; for (let k = 0; k < n; k++) len = len * 256 + b[o + k]; o += n; }
  return o + len > b.length ? null : { tag, at: i, start: o, end: o + len, next: o + len };
}
const kids = (b, t, max = 64) => { const out = []; for (let i = t.start; i < t.end && out.length < max;) { const c = tlv(b, i); if (!c) break; out.push(c); i = c.next; } return out; };
function oid(b, t) {
  if (!t || t.tag !== 0x06 || t.end - t.start > 32 || t.end <= t.start) return "";
  const v = b.subarray(t.start, t.end), out = [Math.floor(v[0] / 40), v[0] % 40]; let n = 0;
  for (let k = 1; k < v.length; k++) { n = n * 128 + (v[k] & 0x7f); if (!(v[k] & 0x80)) { out.push(n); n = 0; } }
  return out.join(".");
}
const hex = (buf) => [...buf].map((x) => x.toString(16).padStart(2, "0").toUpperCase()).join(":");
function ipText(buf) {
  if (buf.length === 4) return [...buf].join(".");
  if (buf.length !== 16) return "";
  const full = []; for (let k = 0; k < 16; k += 2) full.push(((buf[k] << 8) | buf[k + 1]).toString(16));
  try { return new URL(`http://[${full.join(":")}]/`).hostname.replace(/^\[|\]$/g, ""); } catch { return full.join(":"); }   // compressed form; URL parses, it does not connect
}

/**
 * The certificate's own DER -> { serial, spki_sha256, san_dns[], san_ip[], sct, must_staple }. Pure.
 * sct / must_staple are true or false when the extensions were read, null when the certificate could not be read.
 * SCTs delivered in the TLS handshake (the signed_certificate_timestamp extension) or by OCSP stapling are not visible to
 * Node's TLS client without asking for them, so only SCTs embedded in the certificate are reported.
 */
export function certDer(raw) {
  const out = { serial: "", spki_sha256: "", san_dns: [], san_ip: [], sct: null, must_staple: null };
  try {
    const b = Buffer.isBuffer(raw) ? raw : null; if (!b || b.length > 65536) return out;
    const top = tlv(b, 0); if (!top || top.tag !== 0x30) return out;
    const tbs = kids(b, top, 1)[0]; if (!tbs || tbs.tag !== 0x30) return out;
    const f = kids(b, tbs, 12), base = f[0] && f[0].tag === 0xa0 ? 1 : 0;
    const serial = f[base]; if (serial && serial.tag === 0x02 && serial.end - serial.start <= 40) out.serial = hex(b.subarray(serial.start, serial.end));
    const spki = f[base + 5]; if (spki && spki.tag === 0x30) out.spki_sha256 = hex(createHash("sha256").update(b.subarray(spki.at, spki.end)).digest());
    out.sct = false; out.must_staple = false;
    const extWrap = f.slice(base + 6).find((t) => t.tag === 0xa3), exts = extWrap ? kids(b, extWrap, 1)[0] : null;
    if (!exts || exts.tag !== 0x30) return out;
    for (const e of kids(b, exts, 64)) {
      const p = kids(b, e, 3), id = oid(b, p[0]), val = p[p.length - 1];
      if (!val || val.tag !== 0x04) continue;
      if (id === OID.sct) out.sct = true;
      else if (id === OID.tlsFeature) { const seq = tlv(b, val.start); if (seq && seq.tag === 0x30) out.must_staple = kids(b, seq, 16).some((x) => x.tag === 0x02 && x.end - x.start === 1 && b[x.start] === 5); }   // status_request (5)
      else if (id === OID.san) {
        const seq = tlv(b, val.start); if (!seq || seq.tag !== 0x30) continue;
        for (const g of kids(b, seq, 400)) {
          if (g.tag === 0x82 && out.san_dns.length < CERT_RULES.maxSanDns) { const d = clip(b.subarray(g.start, g.end).toString("latin1"), 253).toLowerCase(); if (d) out.san_dns.push(d); }
          else if (g.tag === 0x87 && out.san_ip.length < CERT_RULES.maxSanIp) { const ip = ipText(b.subarray(g.start, g.end)); if (ip) out.san_ip.push(ip); }
        }
      }
    }
  } catch { /* unreadable: leave what was read */ }
  return out;
}

/** The certificate record report.json keeps for each TLS port: certInfo plus the identifiers the inventory and the diff use. */
export function certRecord(cert, now) {
  const info = now === undefined ? certInfo(cert) : certInfo(cert, now);
  if (!info) return null;
  return { ...info, ...certDer(cert && cert.raw) };
}

/** Why a SAN name or address is internal ("" when it is not). */
export function internalName(n) {
  const s = String(n || "").toLowerCase().replace(/\.$/, "").replace(/^\*\./, "");
  if (!s) return "";
  if (!s.includes(".")) return "single-label name";
  const suf = CERT_RULES.internalSuffixes.find((x) => s.endsWith(x) || s === x.slice(1));
  return suf ? `${suf} name` : "";
}
export function internalIp(ip) {
  const k = classify(String(ip || ""));
  return isPrivateKind(k) ? (k === "private" ? "private address (RFC 1918 / unique local)" : `${k} address`) : "";
}

// a record from report.json that may predate the DER fields (an older report, or --compare input): fall back to the SAN text
function sanOf(c) {
  const dns = Array.isArray(c.san_dns) ? c.san_dns : [...String(c.san || "").matchAll(/DNS:([^,\s]+)/g)].map((m) => m[1].toLowerCase());
  const ip = Array.isArray(c.san_ip) ? c.san_ip : [...String(c.san || "").matchAll(/IP Address:([^,\s]+)/g)].map((m) => m[1]);
  return { dns: dns.slice(0, CERT_RULES.maxSanDns).map((x) => clip(x, 253)), ip: ip.slice(0, CERT_RULES.maxSanIp).map((x) => clip(x, 45)) };
}
const days = (a, b) => { const x = Date.parse(a || ""), y = Date.parse(b || ""); return isFinite(x) && isFinite(y) ? Math.round((y - x) / 86400000) : null; };
const yn = (v) => (v === true ? "yes" : v === false ? "no" : "unknown");

/**
 * report -> { rows, reuse, summary }. Pure; reads report.hosts[].tls[].cert and each host's attested names.
 *   reuse: certificates (same SHA-256 fingerprint), public keys (same SubjectPublicKeyInfo in different certificates) and
 *          issuer+serial pairs (different certificates) seen on more than one address. one_name marks a group whose
 *          addresses all share an attested name: likely one host with several addresses, not reuse across machines.
 *   beyond_attested / wildcards[].covers_attested are filled only when the host was scanned by name (h.names known).
 */
export function certInventory(report) {
  const rows = [];
  for (const h of (report && report.hosts) || []) {
    const names = (h.names || []).map((n) => String(n).toLowerCase());
    for (const t of h.tls || []) {
      const c = t && t.cert; if (!c) continue;
      const san = sanOf(c), validity = days(c.valid_from, c.valid_to);
      const wild = san.dns.filter((n) => n.startsWith("*."));
      const internal = [...san.dns.map((n) => [n, internalName(n)]), ...san.ip.map((ip) => [ip, internalIp(ip)])].filter(([, why]) => why).map(([n, why]) => ({ name: n, why }));
      rows.push({ host: h.address, names, port: t.port, subject: clip(c.subject, 200), issuer: clip(c.issuer, 200), valid_from: c.valid_from || "", valid_to: c.valid_to || "",
        validity_days: validity, days_left: c.days_left ?? null, short_lived: validity != null && validity <= CERT_RULES.shortLivedDays,
        key_type: c.key_type || "", key_bits: Number(c.key_bits) || 0, curve: c.curve || "", sig_alg: c.sig_alg || "", self_signed: !!c.self_signed,
        fingerprint256: c.fingerprint256 || "", serial: c.serial || "", spki_sha256: c.spki_sha256 || "",
        san_dns: san.dns, san_ip: san.ip, san_count: san.dns.length + san.ip.length,
        wildcards: wild.map((w) => ({ name: w, covers_attested: names.length ? names.filter((n) => nameMatches([w], n)) : null })),
        internal_names: internal,
        beyond_attested: names.length ? san.dns.filter((n) => !n.startsWith("*.") && !names.includes(n)) : null,
        sct: c.sct === undefined ? null : c.sct, must_staple: c.must_staple === undefined ? null : c.must_staple, reused_on: 0 });
    }
  }
  // reuse across addresses
  const reuse = [];
  const group = (kind, keyOf, keep = () => true) => {
    const m = new Map();
    for (const r of rows) { const k = keyOf(r); if (!k) continue; if (!m.has(k)) m.set(k, []); m.get(k).push(r); }
    for (const [k, list] of m) {
      const addrs = [...new Set(list.map((r) => r.host))];
      if (addrs.length < 2 || !keep(list)) continue;
      const shared = list.every((r) => r.names.length) && list[0].names.some((n) => list.every((r) => r.names.includes(n)));
      reuse.push({ kind, key: k, addresses: addrs.length, one_name: shared, seen_on: list.slice(0, 50).map((r) => ({ host: r.host, port: r.port, names: r.names.slice(0, 5) })) });
      for (const r of list) r.reused_on = Math.max(r.reused_on, addrs.length - 1);
    }
  };
  const fps = (list) => new Set(list.map((r) => r.fingerprint256 || `${r.host}:${r.port}`)).size > 1;   // only when the certificates differ
  group("same certificate", (r) => r.fingerprint256);
  group("same public key in different certificates", (r) => r.spki_sha256, fps);
  group("same issuer and serial in different certificates", (r) => (r.serial && r.issuer ? `${r.issuer} / serial ${r.serial}` : ""), fps);
  const count = (p) => rows.filter(p).length;
  return { rows, reuse,
    summary: { certificates: rows.length, distinct: new Set(rows.map((r) => r.fingerprint256 || `${r.host}:${r.port}`)).size, reused_groups: reuse.length,
      with_internal_names: count((r) => r.internal_names.length > 0), wildcard: count((r) => r.wildcards.length > 0), short_lived: count((r) => r.short_lived),
      with_sct: count((r) => r.sct === true), without_sct: count((r) => r.sct === false), must_staple: count((r) => r.must_staple === true), self_signed: count((r) => r.self_signed) },
    note: "Inventory from the one TLS handshake per port (no extra connection). Reuse means the same certificate, key or issuer+serial on more than one address; one_name marks addresses that share an attested name. SCTs are those embedded in the certificate; SCTs sent in the handshake or by OCSP are not read. Wildcards are recorded as inventory; nothing outside the attested scope is checked." };
}

/* ---- certs.csv ---- */
const cell = (v) => { let s = v == null ? "" : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };   // a leading = + - @ is quoted so a spreadsheet never runs it
export const CERTS_HEAD = ["host", "names", "port", "subject", "issuer", "valid_from", "valid_to", "validity_days", "days_left", "short_lived", "key_type", "key_bits", "sig_alg", "self_signed",
  "fingerprint256", "serial", "spki_sha256", "reused_on_other_addresses", "san_count", "wildcards", "internal_names", "names_beyond_attested", "sct_in_certificate", "ocsp_must_staple"];
export function toCertsCsv(inv) {
  const out = [CERTS_HEAD];
  for (const r of inv.rows) out.push([r.host, r.names.join(" "), r.port, r.subject, r.issuer, r.valid_from, r.valid_to, r.validity_days ?? "", r.days_left ?? "", r.short_lived ? "yes" : "no",
    r.key_type, r.key_bits || "", r.sig_alg, r.self_signed ? "yes" : "no", r.fingerprint256, r.serial, r.spki_sha256, r.reused_on,
    r.san_count, r.wildcards.map((w) => w.name + (w.covers_attested && w.covers_attested.length ? ` (covers attested ${w.covers_attested.slice(0, 3).join(" ")})` : "")).join(" "),
    r.internal_names.map((x) => `${x.name} (${x.why})`).slice(0, 10).join(" "), r.beyond_attested == null ? "" : r.beyond_attested.slice(0, 10).join(" "), yn(r.sct), yn(r.must_staple)]);
  return out.map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}

/** A few lines for the terminal. */
export function certText(inv) {
  const s = inv.summary, L = [`Certificates: ${s.certificates} read (${s.distinct} distinct); ${s.reused_groups} reuse group(s); ${s.with_internal_names} with internal names; ${s.wildcard} wildcard; ${s.short_lived} short-lived (<= ${CERT_RULES.shortLivedDays} days); ${s.with_sct} with embedded SCTs; ${s.must_staple} must-staple.`];
  for (const g of inv.reuse.slice(0, 10)) L.push(`   ${g.kind} on ${g.addresses} addresses${g.one_name ? " (they share an attested name: likely one host)" : ""}: ${g.seen_on.slice(0, 4).map((x) => `${x.host}:${x.port}`).join(", ")}`);
  return L.join("\n");
}
