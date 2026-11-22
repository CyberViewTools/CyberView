// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// UDP query builders and response parsers. PURE: no sockets, no datagram module, no network. Every function builds one benign,
// read-only diagnostic datagram or parses a response the service sent back; the actual single send lives in udp.mjs.
// Loops here are fine (they only format or walk bytes); udp.mjs, which opens the socket, contains none and sends exactly once.
//
// The three checks, one standard benign query each, read-only, version/banner only (no writes, no credential guessing):
//   DNS  (53/udp)  the "version.bind" CHAOS TXT query (RFC-era diagnostic): asks the resolver its software version
//   NTP  (123/udp) a mode-6 (control) read-variables request: asks ntpd for its version/system string
//   SNMP (161/udp) one SNMPv1 GET of sysDescr (1.3.6.1.2.1.1.1.0) with the standard read community "public" ONLY
// None of them iterates communities, guesses anything, or sends more than the one datagram udp.mjs sends.

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").slice(0, n);
export const SNMP_COMMUNITY = "public";   // the single, standard read-only community; no other community is ever tried

/** Each UDP service: its port, protocol label, the query builder and the response parser. */
export const UDP_SERVICES = Object.freeze({
  dns: { port: 53, proto: "dns", label: "DNS", build: dnsVersionQuery, parse: parseDnsVersion, sends: 'a DNS query for "version.bind" (type TXT, class CHAOS)' },
  ntp: { port: 123, proto: "ntp", label: "NTP", build: ntpReadVarQuery, parse: parseNtpReadVar, sends: "an NTP mode-6 read-variables request (read only)" },
  snmp: { port: 161, proto: "snmp", label: "SNMP", build: snmpGetSysDescr, parse: parseSnmpSysDescr, sends: `one SNMPv1 GET of sysDescr with the community "${SNMP_COMMUNITY}" (the standard read community; no other is tried)` },
});

/* ---- DNS: version.bind CHAOS TXT ---- */
function encodeName(labels) {
  const parts = [];
  for (const l of labels) { const b = Buffer.from(l, "ascii").subarray(0, 63); parts.push(Buffer.from([b.length]), b); }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}
export function dnsVersionQuery(id = 0x2607) {
  const head = Buffer.alloc(12);
  head.writeUInt16BE(id & 0xffff, 0); head.writeUInt16BE(0x0100, 2); head.writeUInt16BE(1, 4);   // RD=1, QDCOUNT=1
  const q = Buffer.concat([encodeName(["version", "bind"]), Buffer.from([0, 16, 0, 3])]);          // QTYPE=TXT(16), QCLASS=CHAOS(3)
  return Buffer.concat([head, q]);
}
// walk to the first answer and read its TXT rdata; defensive, never throws
export function parseDnsVersion(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || []);
  if (b.length < 12) return { version: "", text: "" };
  const qd = b.readUInt16BE(4), an = b.readUInt16BE(6);
  let p = 12;
  const skipName = () => { while (p < b.length) { const len = b[p]; if (len === 0) { p++; break; } if ((len & 0xc0) === 0xc0) { p += 2; break; } p += 1 + len; } };
  for (let i = 0; i < qd && p < b.length; i++) { skipName(); p += 4; }
  for (let i = 0; i < an && p + 10 <= b.length; i++) {
    skipName();
    const type = b.readUInt16BE(p), rdlen = b.readUInt16BE(p + 8); p += 10;
    const rd = b.subarray(p, p + rdlen); p += rdlen;
    if (type === 16 && rd.length) { const tlen = rd[0], txt = clip(rd.subarray(1, 1 + Math.min(tlen, rd.length - 1)).toString("latin1"), 120); return { version: txt, text: txt }; }
  }
  return { version: "", text: "" };
}

/* ---- NTP: mode-6 control, read variables (op=2) ---- */
export function ntpReadVarQuery() {
  const b = Buffer.alloc(12);
  b[0] = (0 << 6) | (2 << 3) | 6;   // LI=0, VN=2, Mode=6 (control)
  b[1] = 2;                          // R=0 E=0 M=0, opcode=2 (read variables)
  return b;                          // sequence, status, assoc id, offset, count all zero: a read with no payload
}
// the payload after the 12-byte control header is ASCII "version=...,processor=...,system=..."
export function parseNtpReadVar(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || []);
  if (b.length <= 12) return { version: "", system: "", text: "" };
  const payload = clip(b.subarray(12).toString("latin1").replace(/\u0000+$/, ""), 400);
  const get = (k) => { const m = new RegExp(`${k}="?([^",]+)"?`, "i").exec(payload); return m ? clip(m[1].trim(), 120) : ""; };
  return { version: get("version"), system: get("system") || get("processor"), text: payload };
}

/* ---- SNMPv1 GET sysDescr: a tiny BER encoder/decoder (pure) ---- */
function berLen(n) { if (n < 0x80) return Buffer.from([n]); const bytes = []; while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; } return Buffer.from([0x80 | bytes.length, ...bytes]); }
function tlv(tag, value) { const v = Buffer.isBuffer(value) ? value : Buffer.from(value); return Buffer.concat([Buffer.from([tag]), berLen(v.length), v]); }
const berInt = (n) => tlv(0x02, Buffer.from([n & 0xff]));
export function snmpGetSysDescr(community = SNMP_COMMUNITY) {
  const oid = Buffer.from([0x2b, 6, 1, 2, 1, 1, 1, 0]);                 // 1.3.6.1.2.1.1.1.0 (sysDescr.0)
  const varbind = tlv(0x30, Buffer.concat([tlv(0x06, oid), tlv(0x05, Buffer.alloc(0))]));   // { OID, NULL }
  const varbinds = tlv(0x30, varbind);
  const pdu = tlv(0xa0, Buffer.concat([berInt(0x1d), berInt(0), berInt(0), varbinds]));      // GetRequest: req-id, err-status, err-index, varbinds
  return tlv(0x30, Buffer.concat([berInt(0), tlv(0x04, Buffer.from(String(community).slice(0, 32), "ascii")), pdu]));  // version v1(0), community, PDU
}
// read TLVs defensively; return the first OCTET STRING found inside the response's variable bindings
function readTlvs(b, start, end) {
  const out = []; let p = start;
  while (p + 2 <= end) {
    const tag = b[p]; let len = b[p + 1], hdr = 2;
    if (len & 0x80) { const nb = len & 0x7f; len = 0; for (let i = 0; i < nb && p + 2 + i < end; i++) len = (len << 8) | b[p + 2 + i]; hdr = 2 + nb; }
    const vstart = p + hdr, vend = Math.min(vstart + len, end); if (vstart > end) break;
    out.push({ tag, start: vstart, end: vend }); p = vend;
  }
  return out;
}
export function parseSnmpSysDescr(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || []);
  if (b.length < 2 || b[0] !== 0x30) return { sysdescr: "", text: "" };
  // the first OCTET STRING (tag 0x04) that is not the community: scan the whole message for 0x04 TLVs and take the longest text
  const strings = [];
  const scan = (start, end, depth) => {
    for (const t of readTlvs(b, start, end)) {
      if ((t.tag === 0x30 || t.tag === 0xa0 || t.tag === 0xa2) && depth < 6) scan(t.start, t.end, depth + 1);
      else if (t.tag === 0x04) strings.push(clip(b.subarray(t.start, t.end).toString("latin1"), 300));
    }
  };
  scan(2 > b.length ? 0 : (b[1] & 0x80 ? 2 + (b[1] & 0x7f) : 2), b.length, 0);
  const desc = strings.filter((s) => s && s !== SNMP_COMMUNITY).sort((a, c) => c.length - a.length)[0] || "";
  return { sysdescr: desc, text: desc };
}
