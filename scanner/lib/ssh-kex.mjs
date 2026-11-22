// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// SSH algorithm audit (scan-ssh-kex): a pure parser of the server's SSH_MSG_KEXINIT (RFC 4253 section 7.1), the packet an
// SSH server sends right after its identification line. probe.mjs reads it on the SAME connection after sending only the
// scanner's identification line; the scanner never sends a KEXINIT of its own, never starts a key exchange, never logs in.
// Everything here works on bytes already received: no network, no state.
//
// Observations come from a FROZEN list (below): algorithms the server OFFERS. Offering is not the same as a client using
// it (a modern client picks a strong one first), so the text says "offers". Post-quantum / hybrid key exchanges are recorded
// as information only.
// Detection catalog rows: ssh-algorithm-advertisement (the weak-set observations and the per-port algorithm record) and
// post-quantum-ssh-kex (the ssh-pqc-kex information). ssh-host-key-reuse is NOT built here: the host key is only sent in
// the server's key-exchange reply, which needs a client KEXINIT and KEX init the scanner never sends.

export const SSH_MSG_KEXINIT = 20;
// the most bytes one KEXINIT packet may claim (RFC 4253 6.1 lets a server refuse packets over 35000; a KEXINIT is ~1-2 KB)
export const MAX_PACKET = 16384;
const MAX_NAMES = 64, MAX_NAME = 64, MAX_LIST = 4096;
const LISTS = ["kex", "hostkey", "cipher_c2s", "cipher_s2c", "mac_c2s", "mac_s2c", "compression_c2s", "compression_s2c", "lang_c2s", "lang_s2c"];

/**
 * The frozen weak set: exact algorithm names (no patterns), with the severity of offering it and why.
 * Changing this list changes what reports say; add to it only with a source (RFC 9142, RFC 8758, RFC 9212, OpenSSH release notes).
 */
export const WEAK = Object.freeze({
  kex: Object.freeze({
    "diffie-hellman-group1-sha1": ["high", "1024-bit Oakley group 2 with SHA-1 (RFC 9142: MUST NOT)"],
    "diffie-hellman-group14-sha1": ["medium", "SHA-1 key-exchange hash (RFC 9142: SHOULD NOT)"],
    "diffie-hellman-group-exchange-sha1": ["medium", "SHA-1 key-exchange hash (RFC 9142: MUST NOT)"],
    "rsa1024-sha1": ["high", "1024-bit RSA key exchange with SHA-1 (RFC 9142: MUST NOT)"],
    "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==": ["high", "GSS-API with Oakley group 2 and SHA-1"],
    "gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==": ["medium", "GSS-API group exchange with SHA-1"],
    "gss-group14-sha1-toWM5Slw5Ew8Mqkay+al2g==": ["medium", "GSS-API group 14 with SHA-1"],
  }),
  hostkey: Object.freeze({
    "ssh-dss": ["high", "DSA host key (1024-bit, removed from OpenSSH 10.0)"],
    "ssh-dss-cert-v01@openssh.com": ["high", "DSA host certificate"],
    "ssh-rsa": ["medium", "RSA host-key signatures with SHA-1 (RFC 8332; disabled by default since OpenSSH 8.8)"],
    "ssh-rsa-cert-v01@openssh.com": ["medium", "RSA host certificate signed with SHA-1"],
  }),
  cipher: Object.freeze({
    "none": ["high", "no encryption"],
    "des-cbc": ["high", "single DES"],
    "3des-cbc": ["high", "3DES, a 64-bit block cipher (Sweet32)"],
    "blowfish-cbc": ["high", "Blowfish, a 64-bit block cipher"],
    "cast128-cbc": ["high", "CAST-128, a 64-bit block cipher"],
    "arcfour": ["high", "RC4 (RFC 8758: MUST NOT)"],
    "arcfour128": ["high", "RC4 (RFC 8758: MUST NOT)"],
    "arcfour256": ["high", "RC4 (RFC 8758: MUST NOT)"],
    "aes128-cbc": ["medium", "CBC mode (plaintext-recovery attacks, CVE-2008-5161)"],
    "aes192-cbc": ["medium", "CBC mode (plaintext-recovery attacks, CVE-2008-5161)"],
    "aes256-cbc": ["medium", "CBC mode (plaintext-recovery attacks, CVE-2008-5161)"],
    "rijndael-cbc@lysator.liu.se": ["medium", "CBC mode, pre-standard AES name"],
  }),
  mac: Object.freeze({
    "none": ["high", "no integrity protection"],
    "hmac-md5": ["medium", "MD5-based MAC"],
    "hmac-md5-96": ["medium", "MD5-based MAC truncated to 96 bits"],
    "hmac-md5-etm@openssh.com": ["medium", "MD5-based MAC"],
    "hmac-md5-96-etm@openssh.com": ["medium", "MD5-based MAC truncated to 96 bits"],
    "hmac-sha1-96": ["low", "SHA-1 MAC truncated to 96 bits"],
    "hmac-sha1-96-etm@openssh.com": ["low", "SHA-1 MAC truncated to 96 bits"],
  }),
});

/** Known post-quantum / hybrid key-exchange names (exact). Recorded as information, never as a finding. */
export const PQC_KEX = Object.freeze([
  "mlkem768x25519-sha256", "mlkem768nistp256-sha256", "mlkem1024nistp384-sha384",
  "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "sntrup4591761x25519-sha512@tinyssh.org",
]);

const SEV = { high: 3, medium: 2, low: 1 };
const CATEGORY = { kex: ["ssh-weak-kex", "key exchange"], hostkey: ["ssh-weak-hostkey", "host-key algorithm"], cipher: ["ssh-weak-cipher", "cipher"], mac: ["ssh-weak-mac", "MAC"] };

/**
 * Bytes as received on an SSH port (the identification line, maybe more) -> the server's KEXINIT.
 * -> { kex } when a whole, valid KEXINIT follows the identification line; { need: true } when more bytes are needed
 *    (nothing after the line yet, or a packet cut short); { error } when what follows is not a KEXINIT. Never throws.
 */
export function kexinitFrom(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 4 || buf.subarray(0, 4).toString("latin1") !== "SSH-") return { error: "not an SSH identification" };
  const lf = buf.indexOf(0x0a);
  if (lf < 0) return buf.length > 255 ? { error: "identification line longer than 255 bytes" } : { need: true };
  return parsePacket(buf.subarray(lf + 1));
}

/** One unencrypted binary packet (uint32 packet_length, byte padding_length, payload, padding; no MAC before NEWKEYS). */
export function parsePacket(b) {
  if (b.length < 5) return { need: true };
  const len = b.readUInt32BE(0), pad = b[4];
  if (len < 1 + 17 + 10 * 4 + 5 + 4 || len > MAX_PACKET) return { error: `packet length ${len} is not a KEXINIT` };
  if (b.length >= 6 && b[5] !== SSH_MSG_KEXINIT) return { error: `first packet is message ${b[5]}, not KEXINIT` };
  if (b.length < 4 + len) return { need: true };
  if (pad < 4 || pad >= len) return { error: "bad padding length" };
  return parsePayload(b.subarray(5, 4 + len - pad));
}

/** The KEXINIT message body = byte 20, 16-byte cookie, ten name-lists, boolean first_kex_packet_follows, uint32 reserved. */
export function parsePayload(p) {
  if (!p || p.length < 17 || p[0] !== SSH_MSG_KEXINIT) return { error: "not a KEXINIT payload" };
  let o = 17;
  const kex = {};
  for (const key of LISTS) {
    if (o + 4 > p.length) return { error: "KEXINIT cut short" };
    const n = p.readUInt32BE(o); o += 4;
    if (n > MAX_LIST || o + n > p.length) return { error: "name-list too long" };
    const s = p.subarray(o, o + n).toString("latin1"); o += n;
    if (s && !/^[!-~]+$/.test(s)) return { error: "name-list is not printable ASCII" };
    kex[key] = s ? [...new Set(s.split(",").filter(Boolean).map((x) => x.slice(0, MAX_NAME)))].slice(0, MAX_NAMES) : [];
  }
  if (o + 5 > p.length) return { error: "KEXINIT cut short" };
  kex.first_kex_follows = p[o] !== 0;
  return { kex };
}

/** The algorithms worth keeping per port in the report (short names only) plus what was flagged. */
export function sshKexInfo(k) {
  if (!k || !Array.isArray(k.kex)) return null;
  const uniq = (...ls) => [...new Set(ls.flat())];
  const kexNames = k.kex.filter((n) => !isMarker(n));
  return { kex: kexNames, hostkey: k.hostkey || [], ciphers: uniq(k.cipher_c2s || [], k.cipher_s2c || []), macs: uniq(k.mac_c2s || [], k.mac_s2c || []),
    compression: uniq(k.compression_c2s || [], k.compression_s2c || []), strict_kex: k.kex.includes("kex-strict-s-v00@openssh.com"),
    pqc: kexNames.filter((n) => PQC_KEX.includes(n)), weak: weakOf(k).map((w) => w.name) };
}

/** -> [{ category, name, severity, why }] from the frozen weak set, in list order. */
export function weakOf(k) {
  const out = [];
  const check = (cat, names) => { for (const n of [...new Set(names)]) { const w = WEAK[cat][n]; if (w) out.push({ category: cat, name: n, severity: w[0], why: w[1] }); } };
  check("kex", k.kex || []); check("hostkey", k.hostkey || []);
  check("cipher", [...(k.cipher_c2s || []), ...(k.cipher_s2c || [])]); check("mac", [...(k.mac_c2s || []), ...(k.mac_s2c || [])]);
  return out;
}

/** Observations for one SSH port: one per weak category (highest severity, every name listed) and one PQC note. */
export function sshKexObservations(port, k) {
  if (!k || !Array.isArray(k.kex)) return [];
  const out = [], weak = weakOf(k);
  for (const [cat, [kind, label]] of Object.entries(CATEGORY)) {
    const ws = weak.filter((w) => w.category === cat);
    if (!ws.length) continue;
    const sev = ws.reduce((s, w) => (SEV[w.severity] > SEV[s] ? w.severity : s), "low");
    out.push({ port, kind, severity: sev, text: `The SSH server offers weak ${label} algorithm(s): ${ws.map((w) => `${w.name} (${w.why})`).join("; ")}`.slice(0, 600) });
  }
  const pq = k.kex.filter((n) => PQC_KEX.includes(n));
  if (pq.length) out.push({ port, kind: "ssh-pqc-kex", severity: "info", text: `The SSH server offers post-quantum hybrid key exchange: ${pq.join(", ")}` });
  return out;
}

// pseudo-algorithms in the kex list that signal extensions, not key exchanges (RFC 8308 ext-info, OpenSSH strict kex)
const isMarker = (n) => /^ext-info-[cs]$|^kex-strict-[cs]-v00@openssh\.com$/.test(n);
