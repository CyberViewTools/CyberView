// Test-only DER certificates for tests/unit/scanner-reportpack.test.mjs, built at test time (no key is committed).
// Only the fields the certificate inventory reads are meaningful: serial, issuer, subject, validity, the public key, and
// the subjectAltName / embedded-SCT / TLS Feature (must-staple) extensions. The signature is filler: these certificates
// are parsed, never verified or served.
import { generateKeyPairSync } from "node:crypto";

const len = (n) => n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]);
const tlv = (tag, ...parts) => { const b = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), len(b.length), b]); };
const seq = (...p) => tlv(0x30, ...p), set = (...p) => tlv(0x31, ...p);
const oid = (s) => { const n = s.split(".").map(Number), out = [40 * n[0] + n[1]];
  for (const v of n.slice(2)) { const b = [v & 0x7f]; let x = v >>> 7; while (x) { b.unshift((x & 0x7f) | 0x80); x >>>= 7; } out.push(...b); }
  return tlv(0x06, Buffer.from(out)); };
const utf8 = (s) => tlv(0x0c, Buffer.from(s, "utf8"));
const time = (d) => tlv(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z"));
const name = (cn) => seq(set(seq(oid("2.5.4.3"), utf8(cn))));
const ipBytes = (ip) => ip.includes(":") ? Buffer.from(ip.split(":").flatMap((g) => [parseInt(g, 16) >> 8, parseInt(g, 16) & 0xff])) : Buffer.from(ip.split(".").map(Number));

/** A fresh public key (SubjectPublicKeyInfo DER). */
export const newSpki = () => generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ type: "spki", format: "der" });

/** opts: { serial (hex), cn, issuer, spki, dns[], ip[] (IPv4 dotted or IPv6 with all 8 groups), sct, mustStaple, from, to } -> DER Buffer */
export function makeDer({ serial = "0a1b2c", cn = "fixture.test", issuer = "Fixture CA", spki = newSpki(), dns = [], ip = [], sct = false, mustStaple = false,
  from = new Date(Date.UTC(2026, 0, 1)), to = new Date(Date.UTC(2027, 0, 1)) } = {}) {
  const exts = [];
  if (dns.length || ip.length) exts.push(seq(oid("2.5.29.17"), tlv(0x04, seq(...dns.map((d) => tlv(0x82, Buffer.from(d))), ...ip.map((x) => tlv(0x87, ipBytes(x)))))));
  if (sct) exts.push(seq(oid("1.3.6.1.4.1.11129.2.4.2"), tlv(0x04, tlv(0x04, Buffer.from([0, 0])))));
  if (mustStaple) exts.push(seq(oid("1.3.6.1.5.5.7.1.24"), tlv(0x04, seq(tlv(0x02, Buffer.from([5]))))));
  const alg = seq(oid("1.2.840.10045.4.3.2"));
  const tbs = seq(tlv(0xa0, tlv(0x02, Buffer.from([2]))), tlv(0x02, Buffer.from(serial, "hex")), alg, name(issuer), seq(time(from), time(to)), name(cn), spki,
    ...(exts.length ? [tlv(0xa3, seq(...exts))] : []));
  return seq(tbs, alg, tlv(0x03, Buffer.from([0, 1, 2, 3])));
}

/** The certificate object probe.mjs records, for a DER made above. */
export function probeCert(der, { cn = "fixture.test", issuer = "Fixture CA", fingerprint = "", from = "Jan  1 00:00:00 2026 GMT", to = "Jan  1 00:00:00 2027 GMT", san = "" } = {}) {
  return { subject: { CN: cn }, issuer: { CN: issuer }, valid_from: from, valid_to: to, subjectaltname: san, bits: 256, curve: "prime256v1", fingerprint256: fingerprint, raw: der };
}
