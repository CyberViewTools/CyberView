// Test-only certificates, made at test time so no private key is ever committed (scripts/security-check.mjs refuses
// them). Node can make keys and signatures but not X.509 certificates, so this encodes a minimal self-signed DER
// certificate by hand: version 3, a serial, the signature algorithm, issuer = subject (CN, O), validity (UTCTime, so 2049 at the latest), the public key,
// and a subjectAltName extension. Used only by tests/unit/scanner.test.mjs and the loopback stand-in TLS service.
import { generateKeyPairSync, sign, randomBytes } from "node:crypto";

const len = (n) => n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]);
const tlv = (tag, ...parts) => { const b = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), len(b.length), b]); };
const seq = (...p) => tlv(0x30, ...p), set = (...p) => tlv(0x31, ...p);
const oid = (s) => { const n = s.split(".").map(Number), out = [40 * n[0] + n[1]];
  for (const v of n.slice(2)) { const b = [v & 0x7f]; let x = v >>> 7; while (x) { b.unshift((x & 0x7f) | 0x80); x >>>= 7; } out.push(...b); }
  return tlv(0x06, Buffer.from(out)); };
const utf8 = (s) => tlv(0x0c, Buffer.from(s, "utf8"));
const time = (d) => { const s = d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z"; return tlv(0x17, Buffer.from(s)); };
const name = (cn, o) => seq(set(seq(oid("2.5.4.3"), utf8(cn))), set(seq(oid("2.5.4.10"), utf8(o))));
const SIG = { "rsa:sha1": "1.2.840.113549.1.1.5", "rsa:sha256": "1.2.840.113549.1.1.11", "ec:sha256": "1.2.840.10045.4.3.2" };

/** -> { key, cert } in PEM. opts: { type: "rsa" | "ec", bits, curve, hash, cn, san: [dns], from, to } */
export function makeCert({ type = "rsa", bits = 2048, curve = "P-256", hash = "sha256", cn = "fixture.test", san = [], from = new Date(Date.UTC(2020, 0, 1)), to = new Date(Date.UTC(2049, 11, 31)) } = {}) {
  const { publicKey, privateKey } = type === "ec" ? generateKeyPairSync("ec", { namedCurve: curve }) : generateKeyPairSync("rsa", { modulusLength: bits });
  const algOid = SIG[`${type}:${hash}`], alg = type === "ec" ? seq(oid(algOid)) : seq(oid(algOid), Buffer.from([0x05, 0x00]));
  const sanExt = san.length ? tlv(0xa3, seq(seq(oid("2.5.29.17"), tlv(0x04, seq(...san.map((d) => tlv(0x82, Buffer.from(d)))))))) : Buffer.alloc(0);
  const serial = randomBytes(8); serial[0] &= 0x7f;
  const tbs = seq(tlv(0xa0, tlv(0x02, Buffer.from([2]))), tlv(0x02, serial), alg, name(cn, "CyberView test fixture"), seq(time(from), time(to)),
    name(cn, "CyberView test fixture"), publicKey.export({ type: "spki", format: "der" }), sanExt);
  const sig = sign(hash, tbs, privateKey), der = seq(tbs, alg, tlv(0x03, Buffer.concat([Buffer.from([0]), sig])));
  const pem = (label, b) => `-----BEGIN ${label}-----\n${b.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END ${label}-----\n`;
  return { key: privateKey.export({ type: "pkcs8", format: "pem" }), cert: pem("CERTIFICATE", der), der };
}

/** The two fixtures the tests use (made once per process). */
let cache = null;
export function fixtureCerts() {
  return cache || (cache = {
    weak: makeCert({ type: "rsa", bits: 1024, hash: "sha1", cn: "weak.fixture.test", san: ["weak.fixture.test"] }),
    good: makeCert({ type: "ec", curve: "P-256", hash: "sha256", cn: "good.fixture.test", san: ["good.fixture.test", "*.apps.fixture.test"] }),
  });
}
