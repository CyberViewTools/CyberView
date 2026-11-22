// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Industrial and clinical identification (scan-ics-identify), ONLY with --ics (off by default). This module owns its own
// TCP connections (scripts/security-check.mjs section 7 allows net.connect here and in probe.mjs only); its one UDP datagram
// (BACnet) goes through scanner/lib/udp.mjs, the only file that opens a UDP socket. It sends nothing but the frozen request
// bytes in ICS_PROTOCOLS below:
//   - one identification exchange per protocol per host, on the protocol's standard port, and only when that port is in
//     the scan's port list and (TCP) the normal probe found it open;
//   - private, loopback and link-local addresses only: a public address is never sent an industrial read, even with
//     --i-am-authorized-for-public-ranges;
//   - read-only requests only: no write, control, start/stop, restart, time-sync, upload/download, session, login or
//     DIMSE command; nothing is broadcast (BACnet Who-Is goes unicast to the one attested address);
//   - every connection takes a Limiter slot like a probe (host and total budgets, rate, --max-minutes, Ctrl-C).
// Results are inventory only: no identity read here is handed to the KEV/NVD matcher (product names from these devices do
// not map cleanly to NVD vendor/product names), and a version is kept only where the protocol's own field states one.
import net from "node:net";
import { isIP } from "node:net";
import { TIMEOUTS } from "./limits.mjs";
import { isPrivateKind, classify } from "./scope.mjs";
import { udpProbe } from "./udp.mjs";

/*
 * The frozen request table. Each step is one message, a hex literal; a protocol's steps run on ONE connection, in order,
 * and a step is sent only when the previous reply allows it (proceed). Nothing else is ever written to a target.
 * The only bytes not taken verbatim from the table: OPC UA's GetEndpoints carries the SecureChannelId and TokenId the
 * server assigned in its OpenSecureChannel reply (bytes 8-15 of that message, zero in the table), as the protocol requires.
 */
export const ICS_PROTOCOLS = Object.freeze({
  // Modbus/TCP, TCP 502. MODBUS Messaging on TCP/IP Implementation Guide V1.0b, 3.1.3 (MBAP header: transaction 0x0001,
  // protocol 0x0000, length 0x0005, unit identifier 0xFF; per 4.4.1.2 a server addressed by IP takes unit 0xFF, and 0xFF
  // is used rather than 0, which a serial gateway can treat as broadcast). MODBUS Application Protocol Specification
  // V1.1b3, 6.21: function 0x2B, MEI type 0x0E Read Device Identification, Read Device ID code 0x01 (basic: VendorName,
  // ProductCode, MajorMinorRevision), object id 0x00. One request; a "more follows" answer is recorded, never followed up.
  modbus: Object.freeze({ port: 502, transport: "tcp", name: "Modbus/TCP", catalog: Object.freeze(["modbus-identify"]),
    steps: Object.freeze(["000100000005ff2b0e0100"]) }),
  // EtherNet/IP encapsulation, TCP 44818. The CIP Networks Library Vol. 2 (EtherNet/IP Adaptation of CIP), 2-3
  // encapsulation header (24 bytes: command 0x0063 ListIdentity, length 0, session handle 0, status 0, sender context 0,
  // options 0) and 2-4.2 ListIdentity (no data, no RegisterSession). Reply: CIP Identity item 0x0C. Covers Rockwell.
  enip: Object.freeze({ port: 44818, transport: "tcp", name: "EtherNet/IP", catalog: Object.freeze(["ethernet-ip-list-identity", "rockwell-factorytalk-or-controllogix"]),
    steps: Object.freeze(["630000000000000000000000000000000000000000000000"]) }),
  // S7comm over ISO-on-TCP, TCP 102: ONE identification exchange of three messages on one connection.
  //   1. RFC 1006 section 6 TPKT (03 00 len) + ISO 8073/X.224 COTP Connection Request (0xE0, TPDU size 1024, calling
  //      TSAP 0x0100, called TSAP 0x0102 = rack 0 slot 2)
  //   2. TPKT + COTP DT + S7 job (protocol id 0x32, ROSCTR 0x01) function 0xF0 Setup Communication (1/1 jobs, PDU 480),
  //      layout as in the Wireshark s7comm dissector documentation
  //   3. TPKT + COTP DT + S7 userdata (ROSCTR 0x07): method 0x11 request, type/group 0x44 (request, CPU functions),
  //      subfunction 0x01 Read SZL, SZL-ID 0x0011 (module identification), index 0x0000 — Siemens "System Software for
  //      S7-300/400 System and Standard Functions", System Status Lists, SSL-ID W#16#xy11
  s7: Object.freeze({ port: 102, transport: "tcp", name: "S7comm", catalog: Object.freeze(["s7comm-identify"]),
    steps: Object.freeze([
      "0300001611e00000000100c0010ac1020100c2020102",
      "0300001902f08032010000000100080000f0000001000101e0",
      "0300002102f080320700000002000800080001120411440100ff09000400110000"]) }),
  // BACnet/IP, UDP 47808: ONE unicast datagram. ANSI/ASHRAE 135 Annex J.2.11 BVLC Original-Unicast-NPDU (0x81 0x0A,
  // length 8; never 0x0B Original-Broadcast-NPDU), clause 6.2 NPCI version 0x01 control 0x00 (no DNET: never routed or
  // re-broadcast to other networks), clause 20.1.2 BACnet-Unconfirmed-Request-PDU 0x10 service 0x08 Who-Is with no range.
  // Read: the I-Am (device instance, max APDU, segmentation, vendor id). No ReadProperty.
  bacnet: Object.freeze({ port: 47808, transport: "udp", name: "BACnet/IP", catalog: Object.freeze(["bacnet-who-is-i-am"]),
    steps: Object.freeze(["810a000801001008"]) }),
  // OPC UA binary, TCP 4840: Hello, OpenSecureChannel (SecurityPolicy None, mode None), GetEndpoints, then the TCP
  // connection is closed. No CreateSession, ActivateSession, Read, Browse, Write or Call.
  //   1. OPC 10000-6 7.1.2.3 Hello ("HELF", version 0, buffers 16384, max message 16384, 1 chunk, empty endpoint URL)
  //   2. OPC 10000-6 6.7.2 OPN asymmetric security header (policy http://opcfoundation.org/UA/SecurityPolicy#None, null
  //      certificate and thumbprint), sequence header 1/1, OPC 10000-4 5.5.2 OpenSecureChannelRequest (NodeId 446):
  //      RequestHeader (null token, handle 1, timeout 10000), client protocol 0, Issue, SecurityMode None, null nonce, 600000 ms
  //   3. OPC 10000-6 6.7.2 MSG symmetric header (SecureChannelId and TokenId from the server's OPN reply, zero here),
  //      sequence 2/2, OPC 10000-4 5.4.4 GetEndpointsRequest (NodeId 428): empty endpoint URL, no locales, no profile filter
  opcua: Object.freeze({ port: 4840, transport: "tcp", name: "OPC UA", catalog: Object.freeze(["opc-ua-getendpoints"]),
    steps: Object.freeze([
      "48454c4620000000000000000040000000400000004000000100000000000000",
      "4f504e4684000000000000002f000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412f5365637572697479506f6c696379234e6f6e65ffffffffffffffff01000000010000000100be01000000000000000000000100000000000000ffffffff10270000000000000000000000000001000000ffffffffc0270900",
      "4d53474645000000000000000000000002000000020000000100ac01000000000000000000000200000000000000ffffffff10270000000000000000000000000000000000"]) }),
  // DICOM upper layer, TCP 104: an association request for the Verification SOP Class only, then release. No DIMSE
  // command is ever sent (no P-DATA-TF, not even C-ECHO).
  //   1. PS3.8 9.3.2 A-ASSOCIATE-RQ: protocol version 1, called AE "ANY-SCP", calling AE "CYBERVIEW-SCAN", application
  //      context 1.2.840.10008.3.1.1.1 (PS3.7 A.2.1), presentation context 1: abstract syntax Verification
  //      1.2.840.10008.1.1 (PS3.4 A.4), transfer syntax Implicit VR Little Endian 1.2.840.10008.1.2 (PS3.5 10.1); user
  //      information (PS3.7 D.3.3): max PDU 16384, implementation class UID 2.25.176636423538074261390560019095003957045
  //      (a UUID-derived UID, PS3.5 B.2), implementation version name "CYBERVIEW_SCAN"
  //   2. PS3.8 9.3.6 A-RELEASE-RQ, sent only after an A-ASSOCIATE-AC (a rejection leaves nothing to release)
  dicom: Object.freeze({ port: 104, transport: "tcp", name: "DICOM", catalog: Object.freeze(["dicom-association-identify"]),
    steps: Object.freeze([
      "0100000000dd00010000414e592d5343502020202020202020204359424552564945572d5343414e2020000000000000000000000000000000000000000000000000000000000000000010000015312e322e3834302e31303030382e332e312e312e312000002e0100000030000011312e322e3834302e31303030382e312e3140000011312e322e3834302e31303030382e312e325000004a51000004000040005200002c322e32352e3137363633363432333533383037343236313339303536303031393039353030333935373034355500000e4359424552564945575f5343414e",
      "05000000000400000000"]) }),
});
export const ICS_KEYS = Object.freeze(Object.keys(ICS_PROTOCOLS));

/** What --ics sends, for the run header and report.json (run.network.sends). */
export function icsSends(enabled = false) {
  const head = { ics: `only with --ics (off by default): one read-only identification exchange per industrial/clinical protocol per host, on its standard port when that port is in the port list (and open, for TCP), private ranges only, never broadcast; frozen request bytes in scanner/lib/ics.mjs${enabled ? "" : " (not enabled for this run)"}` };
  if (!enabled) return head;
  return { ...head,
    "ics-modbus": "only with --ics: TCP 502, one Modbus Read Device Identification (function 0x2B / MEI 0x0E, basic objects); never a coil/register read or any write",
    "ics-enip": "only with --ics: TCP 44818, one EtherNet/IP ListIdentity (command 0x63); no session registration",
    "ics-s7": "only with --ics: TCP 102, COTP connect + S7 Setup Communication + one SZL read (ID 0x0011 module identification); no other S7 function",
    "ics-bacnet": "only with --ics: UDP 47808, one unicast BACnet Who-Is to the host's own address (never broadcast); the I-Am is read",
    "ics-opcua": "only with --ics: TCP 4840, OPC UA Hello + OpenSecureChannel (SecurityPolicy None) + GetEndpoints; no session, no login",
    "ics-dicom": "only with --ics: TCP 104, one DICOM A-ASSOCIATE-RQ (Verification only) then A-RELEASE-RQ; no DIMSE command (not even C-ECHO)" };
}

/** A host an industrial read may go to: private, loopback or link-local and not public; for UDP never a .0 or .255 IPv4 address. */
export function icsTargetOk(h, transport = "tcp") {
  const addr = String((h && h.address) || "");
  if (!h || h.public !== false || !isPrivateKind(h.kind) || !isPrivateKind(classify(addr))) return { ok: false, why: "not-sent: public address (industrial reads go to private ranges only)" };
  if (transport === "udp" && isIP(addr) === 4 && /\.(0|255)$/.test(addr)) return { ok: false, why: "not-sent: address may be a subnet broadcast address" };
  return { ok: true, why: "" };
}

/**
 * Which protocols one host gets: each protocol at most once, on its standard port, only when that port is in the scan's
 * port list; TCP only when the probe found the port open, UDP only when the host answered. -> { plan: [{ key, port }], skipped: [{ key, port, why }] }
 */
export function icsPlan(h, ports, ics) {
  const plan = [], skipped = [];
  if (!ics || ics.enabled !== true || !h) return { plan, skipped };
  const list = Array.isArray(ports) ? ports : [];
  for (const key of ICS_KEYS) {
    const P = ICS_PROTOCOLS[key];
    if (!list.includes(P.port)) continue;
    const gate = icsTargetOk(h, P.transport);
    if (!gate.ok) { skipped.push({ key, port: P.port, why: gate.why }); continue; }
    if (P.transport === "tcp" && !(h.ports || []).some((p) => p.port === P.port && p.state === "open")) { skipped.push({ key, port: P.port, why: "not-sent: port not open" }); continue; }
    if (P.transport === "udp" && !h.up) { skipped.push({ key, port: P.port, why: "not-sent: host did not answer" }); continue; }
    plan.push({ key, port: P.port });
  }
  return { plan, skipped };
}

/* ---- framing: when is one reply complete ---- */
const FRAME = {
  modbus: (b) => (b.length >= 6 ? 6 + b.readUInt16BE(4) : 0),
  enip: (b) => (b.length >= 4 ? 24 + b.readUInt16LE(2) : 0),
  s7: (b) => (b.length >= 4 ? b.readUInt16BE(2) : 0),
  opcua: (b) => (b.length >= 8 ? b.readUInt32LE(4) : 0),
  dicom: (b) => (b.length >= 6 ? 6 + b.readUInt32BE(2) : 0),
};

/* ---- may the next step be sent? (each later step only after the expected reply to the one before) ---- */
const s7Start = (b) => (b && b.length > 5 ? 5 + b[4] : -1);
const PROCEED = {
  s7: (replies, i) => {
    const r = replies[i - 1]; if (!r) return false;
    if (i === 1) return r.length >= 6 && r[5] === 0xd0;   // COTP Connection Confirm
    const o = s7Start(r);   // Setup Communication answered with ack-data and no error
    return o > 0 && r.length >= o + 12 && r[o] === 0x32 && r[o + 1] === 0x03 && r[o + 10] === 0 && r[o + 11] === 0;
  },
  opcua: (replies, i) => {
    const r = replies[i - 1]; if (!r) return false;
    if (i === 1) return r.length >= 8 && r.toString("latin1", 0, 3) === "ACK";
    return !!opnTokens(r);
  },
  dicom: (replies, i) => !!replies[i - 1] && replies[i - 1][0] === 0x02,   // release only an accepted association
};

/** The bytes of one step: the frozen literal; for OPC UA's GetEndpoints, the server-assigned channel and token ids. */
export function requestBytes(key, i, replies = []) {
  const P = ICS_PROTOCOLS[key];
  if (!P || i < 0 || i >= P.steps.length) return null;
  const buf = Buffer.from(P.steps[i], "hex");
  if (key === "opcua" && i === 2) {
    const t = opnTokens(replies[1]);
    if (!t) return null;
    buf.writeUInt32LE(t.channelId, 8); buf.writeUInt32LE(t.tokenId, 12);
  }
  return buf;
}

/* ---- the network exchange (the only sends in this module) ---- */

/**
 * One protocol's identification exchange with one host. Never throws.
 * opts.port overrides the standard port for loopback tests only; scan.mjs never passes it.
 * -> { protocol, port, transport, state: open | closed | filtered, sent, replies: [Buffer], error }
 */
export async function icsExchange(ip, key, { signal = null, timeouts = TIMEOUTS, port = 0 } = {}) {
  const P = ICS_PROTOCOLS[key];
  const out = { protocol: key, port: port || (P ? P.port : 0), transport: P ? P.transport : "", state: "filtered", sent: 0, replies: [], error: "" };
  if (!P) { out.error = "refused: unknown protocol"; return out; }
  if (signal && signal.aborted) { out.error = "interrupted"; return out; }
  return P.transport === "udp" ? udpExchange(ip, key, out, { signal, timeouts }) : tcpExchange(ip, key, out, { signal, timeouts });
}

function tcpExchange(ip, key, out, { signal, timeouts }) {
  const P = ICS_PROTOCOLS[key], frame = FRAME[key], proceed = PROCEED[key] || (() => false);
  return new Promise((resolve) => {
    let buf = Buffer.alloc(0), step = 0, total = 0, settled = false, readTimer = null, connectTimer = null, hard = null;
    const sock = net.connect({ host: ip, port: out.port });
    const finish = () => {
      if (settled) return; settled = true;
      clearTimeout(readTimer); clearTimeout(connectTimer); clearTimeout(hard);
      if (signal) signal.removeEventListener("abort", onAbort);
      try { sock.destroy(); } catch { /* closed */ }
      resolve(out);
    };
    const onAbort = () => { out.error = out.error || "interrupted"; finish(); };
    if (signal) signal.addEventListener("abort", onAbort, { once: true });
    connectTimer = setTimeout(() => { if (out.state === "filtered") { out.error = "connect timed out"; finish(); } }, timeouts.connectMs);
    hard = setTimeout(finish, timeouts.connectMs + timeouts.readMs * P.steps.length + 1000);
    // send the next step if there is one and the previous reply allows it; otherwise close
    const next = () => {
      if (step >= P.steps.length || (step > 0 && !proceed(out.replies, step))) return finish();
      const bytes = requestBytes(key, step, out.replies);
      if (!bytes) return finish();
      step++; out.sent++;
      clearTimeout(readTimer); readTimer = setTimeout(() => { out.error = out.error || "no reply"; finish(); }, timeouts.readMs);
      sock.write(bytes);
    };
    sock.once("connect", () => { out.state = "open"; clearTimeout(connectTimer); next(); });
    sock.on("data", (d) => {
      total += d.length;
      if (total > timeouts.maxBytes) { out.error = "reply over the size cap"; return finish(); }
      buf = Buffer.concat([buf, d]);
      const n = frame(buf);
      if (!n || buf.length < n) return;
      out.replies.push(buf.subarray(0, n)); buf = buf.subarray(n);
      clearTimeout(readTimer); next();
    });
    sock.on("error", (e) => { out.error = out.error || String((e && (e.code || e.message)) || e).slice(0, 80); if (e && e.code === "ECONNREFUSED") out.state = "closed"; finish(); });
    sock.on("close", finish);
  });
}

// BACnet's one unicast datagram, sent by udp.mjs (one send, no retransmit) with this module's frozen Who-Is bytes
const ICS_UDP = Object.freeze({ bacnet: Object.freeze({ port: 47808, proto: "bacnet", build: () => requestBytes("bacnet", 0), parse: (m) => Buffer.from(m) }) });
async function udpExchange(ip, key, out, { signal, timeouts }) {
  const r = await udpProbe(ip, key, { signal, timeouts, port: out.port, services: ICS_UDP });
  out.sent = 1; out.state = r.state === "open" ? "open" : "filtered";
  out.error = r.error || (r.state === "open" ? "" : "no reply");
  if (r.parsed) out.replies.push(r.parsed);
  return out;
}

/* ---- parsing the replies (pure) ---- */
const txt = (b, n = 120) => String(b == null ? "" : Buffer.isBuffer(b) ? b.toString("latin1") : b).replace(/[^ -~]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);

/** Modbus Read Device Identification reply -> { vendor, product_code, revision } | { exception } | null */
export function parseModbus(b) {
  if (!b || b.length < 9) return null;
  const pdu = b.subarray(7, Math.min(b.length, 6 + b.readUInt16BE(4)));
  if (pdu[0] === 0xab) return { exception: pdu[1] == null ? -1 : pdu[1] };   // 6.21: error code 0xAB, exception code
  if (pdu[0] !== 0x2b || pdu[1] !== 0x0e || pdu.length < 7) return null;
  const out = { conformity: pdu[3], more_follows: pdu[4] === 0xff }, names = { 0: "vendor", 1: "product_code", 2: "revision" };
  let o = 7;
  for (let k = 0; k < Math.min(pdu[6], 16) && o + 2 <= pdu.length; k++) {
    const id = pdu[o], len = pdu[o + 1];
    if (o + 2 + len > pdu.length) break;
    if (names[id]) out[names[id]] = txt(pdu.subarray(o + 2, o + 2 + len), 80);
    o += 2 + len;
  }
  return out;
}

/** EtherNet/IP ListIdentity reply -> identity item fields | null */
export function parseEnip(b) {
  if (!b || b.length < 63 || b.readUInt16LE(0) !== 0x63 || b.readUInt32LE(8) !== 0) return null;
  if (b.readUInt16LE(24) < 1 || b.readUInt16LE(26) !== 0x0c) return null;
  const vendorId = b.readUInt16LE(48), nameLen = b[62];
  return { vendor_id: vendorId, vendor: vendorId === 1 ? "Rockwell Automation/Allen-Bradley" : "", device_type: b.readUInt16LE(50), product_code: b.readUInt16LE(52),
    revision: `${b[54]}.${b[55]}`, serial: b.readUInt32LE(58).toString(16).padStart(8, "0"), product_name: txt(b.subarray(63, Math.min(b.length, 63 + nameLen)), 80) };
}

/** S7 Read SZL 0x0011 reply -> { order_number, hardware, firmware } | null */
export function parseS7(b) {
  const o = s7Start(b);
  if (o < 0 || b.length < o + 12 || b[o] !== 0x32 || b[o + 1] !== 0x07) return null;
  const d = o + 10 + b.readUInt16BE(o + 6);
  if (b.length < d + 12 || b[d] !== 0xff || b.readUInt16BE(d + 4) !== 0x0011) return null;
  const recLen = b.readUInt16BE(d + 8), count = b.readUInt16BE(d + 10), out = {};
  if (recLen < 28) return null;
  for (let k = 0, r = d + 12; k < Math.min(count, 10) && r + 28 <= b.length; k++, r += recLen) {
    const idx = b.readUInt16BE(r) & 0xff;
    if (idx === 0x01) out.order_number = txt(b.subarray(r + 2, r + 22), 40);
    if (idx === 0x06) out.hardware = txt(b.subarray(r + 2, r + 22), 40);
    if (idx === 0x07 && b[r + 24] === 0x56) out.firmware = `${b[r + 25]}.${b[r + 26]}.${b[r + 27]}`;   // Ausbg 'V' + major, Ausbe minor, patch
  }
  return out;
}

/** BACnet I-Am -> { device_instance, max_apdu, segmentation, vendor_id } | null */
export function parseBacnet(b) {
  if (!b || b.length < 8 || b[0] !== 0x81 || b[4] !== 0x01) return null;
  const ctrl = b[5];
  if (ctrl & 0x80) return null;   // a network-layer message, not an APDU
  let o = 6;
  if (ctrl & 0x20) { o += 2; o += 1 + b[o]; }   // DNET, DLEN, DADR
  if (ctrl & 0x08) { o += 2; o += 1 + b[o]; }   // SNET, SLEN, SADR
  if (ctrl & 0x20) o += 1;                      // hop count
  if (b[o] !== 0x10 || b[o + 1] !== 0x00) return null;   // Unconfirmed-Request I-Am
  o += 2;
  const vals = [];
  for (let k = 0; k < 4 && o < b.length; k++) {
    const t = b[o], lvt = t & 7; let len = lvt, h = 1;
    if (t & 0x08) return null;   // context tags do not appear in I-Am
    if (lvt === 5) { len = b[o + 1]; h = 2; }
    if (o + h + len > b.length || len > 4) return null;
    let v = 0; for (let j = 0; j < len; j++) v = v * 256 + b[o + h + j];
    vals.push({ tag: t >> 4, v }); o += h + len;
  }
  if (vals.length < 4 || vals[0].tag !== 12 || (vals[0].v >>> 22) !== 8) return null;
  return { device_instance: vals[0].v & 0x3fffff, max_apdu: vals[1].v, segmentation: vals[2].v, vendor_id: vals[3].v };
}

/* OPC UA binary decoding with bounds checks (OPC 10000-6 5.2) */
class Rd {
  constructor(b, o = 0) { this.b = b; this.o = o; }
  need(n) { if (n < 0 || this.o + n > this.b.length) throw new Error("short"); }
  u8() { this.need(1); return this.b[this.o++]; }
  u32() { this.need(4); const v = this.b.readUInt32LE(this.o); this.o += 4; return v; }
  i32() { this.need(4); const v = this.b.readInt32LE(this.o); this.o += 4; return v; }
  skip(n) { this.need(n); this.o += n; }
  str() { const n = this.i32(); if (n <= 0) return ""; this.need(n); const s = this.b.toString("utf8", this.o, this.o + n); this.o += n; return s; }
  bytes() { const n = this.i32(); if (n > 0) this.skip(n); }
  strArr(max = 64) { const n = this.i32(), a = []; for (let k = 0; k < n; k++) { if (k >= max) throw new Error("too many"); a.push(this.str()); } return a; }
  nodeId() {
    const e = this.u8(), t = e & 0x3f; let id = null;
    if (t === 0) id = this.u8(); else if (t === 1) { this.skip(1); this.need(2); id = this.b.readUInt16LE(this.o); this.o += 2; }
    else if (t === 2) { this.skip(2); id = this.u32(); } else if (t === 3) { this.skip(2); this.str(); } else if (t === 4) this.skip(18); else if (t === 5) { this.skip(2); this.bytes(); } else throw new Error("nodeid");
    if (e & 0x80) this.str();
    if (e & 0x40) this.skip(4);
    return id;
  }
  diag(depth = 0) {
    if (depth > 4) throw new Error("deep");
    const m = this.u8();
    if (m & 1) this.skip(4); if (m & 2) this.skip(4); if (m & 4) this.skip(4); if (m & 8) this.skip(4);
    if (m & 16) this.str(); if (m & 32) this.skip(4); if (m & 64) this.diag(depth + 1);
  }
  ext() { this.nodeId(); const enc = this.u8(); if (enc === 1 || enc === 2) this.bytes(); }
  responseHeader() { this.skip(12); const result = this.u32(); this.diag(); this.strArr(); this.ext(); return result; }
}

/** OPC UA OPN reply -> { channelId, tokenId } | null */
export function opnTokens(b) {
  try {
    if (!b || b.length < 24 || b.toString("latin1", 0, 3) !== "OPN") return null;
    const r = new Rd(b, 12);
    r.str(); r.bytes(); r.bytes(); r.skip(8);
    if (r.nodeId() !== 449) return null;
    if (r.responseHeader() !== 0) return null;
    r.u32();
    return { channelId: r.u32(), tokenId: r.u32() };
  } catch { return null; }
}

const MODES = { 1: "None", 2: "Sign", 3: "SignAndEncrypt" };
/** OPC UA GetEndpoints reply -> { application_name, application_uri, product_uri, endpoints: [{ mode, policy }] } | { error } | null */
export function parseOpcua(b) {
  try {
    if (!b || b.length < 16) return null;
    const type = b.toString("latin1", 0, 3);
    if (type === "ERR") return { error: `0x${b.readUInt32LE(8).toString(16).padStart(8, "0")}` };
    if (type !== "MSG") return null;
    const r = new Rd(b, 24);
    const node = r.nodeId();
    if (node === 397) return { error: `0x${r.responseHeader().toString(16).padStart(8, "0")}` };   // ServiceFault
    if (node !== 431) return null;
    const result = r.responseHeader();
    if (result !== 0) return { error: `0x${result.toString(16).padStart(8, "0")}` };
    const n = r.i32(), out = { application_name: "", application_uri: "", product_uri: "", endpoints: [] }, seen = new Set();
    for (let k = 0; k < Math.min(n, 16); k++) {
      r.str();   // endpoint URL
      const appUri = r.str(), prodUri = r.str(), m = r.u8();
      if (m & 1) r.str();
      const appName = m & 2 ? r.str() : "";
      r.i32(); r.str(); r.str(); r.strArr();
      r.bytes();   // the server certificate: skipped, never kept
      const mode = r.i32(), policy = r.str();
      const nt = r.i32(); for (let j = 0; j < nt; j++) { if (j >= 32) throw new Error("too many"); r.str(); r.i32(); r.str(); r.str(); r.str(); }
      r.str(); r.u8();
      if (!out.application_name) { out.application_name = txt(appName, 120); out.application_uri = txt(appUri, 160); out.product_uri = txt(prodUri, 160); }
      const e = { mode: MODES[mode] || String(mode), policy: txt(policy.split("#").pop(), 60) }, key = e.mode + "|" + e.policy;
      if (!seen.has(key) && out.endpoints.length < 10) { seen.add(key); out.endpoints.push(e); }
    }
    return out;
  } catch { return null; }
}

/** DICOM A-ASSOCIATE-AC/RJ -> { accepted, verification_accepted, implementation_class_uid, implementation_version_name } | { accepted: false, result, source, reason } | null */
export function parseDicom(b) {
  if (!b || b.length < 10) return null;
  if (b[0] === 0x03) return { accepted: false, result: b[7], source: b[8], reason: b[9] };
  if (b[0] === 0x07) return { accepted: false, aborted: true };
  if (b[0] !== 0x02 || b.length < 74) return null;
  const out = { accepted: true, verification_accepted: false, implementation_class_uid: "", implementation_version_name: "" };
  const end = Math.min(b.length, 6 + b.readUInt32BE(2));
  for (let o = 74; o + 4 <= end;) {
    const t = b[o], len = b.readUInt16BE(o + 2), v = o + 4;
    if (v + len > end) break;
    if (t === 0x21 && len >= 4) out.verification_accepted = b[v + 2] === 0;
    if (t === 0x50) for (let s = v; s + 4 <= v + len;) {
      const st = b[s], sl = b.readUInt16BE(s + 2);
      if (s + 4 + sl > v + len) break;
      if (st === 0x52) out.implementation_class_uid = txt(b.subarray(s + 4, s + 4 + sl), 64).replace(/[^0-9.]/g, "");
      if (st === 0x55) out.implementation_version_name = txt(b.subarray(s + 4, s + 4 + sl), 16);
      s += 4 + sl;
    }
    o = v + len;
  }
  return out;
}

const PARSE = { modbus: (rs) => parseModbus(rs[0]), enip: (rs) => parseEnip(rs[0]), s7: (rs) => parseS7(rs[2]), bacnet: (rs) => parseBacnet(rs[0]), opcua: (rs) => parseOpcua(rs[2]), dicom: (rs) => parseDicom(rs[0]) };

/** One exchange's result -> the report record (inventory only; a version only where the protocol states one). */
export function icsRecord(key, r) {
  const P = ICS_PROTOCOLS[key];
  const rec = { protocol: key, name: P ? P.name : key, catalog: P ? [...P.catalog] : [], port: r.port, transport: r.transport, messages_sent: r.sent, state: r.state, outcome: "", identity: null, version: "", version_stated: false, inventory_only: true, error: r.error || "" };
  let id = null;
  try { id = PARSE[key] ? PARSE[key](r.replies || []) : null; } catch { id = null; }
  if (id && !id.error && id.exception === undefined && id.accepted !== false) {
    rec.outcome = "identified"; rec.identity = id;
    const v = key === "modbus" ? id.revision : key === "enip" ? id.revision : key === "s7" ? id.firmware : "";
    if (v) { rec.version = String(v).slice(0, 40); rec.version_stated = true; }
  } else if (id) { rec.outcome = "answered without identity"; rec.identity = id; }
  else rec.outcome = r.state === "open" ? ((r.replies || []).length ? "unrecognised reply" : "no reply") : r.state === "closed" ? "closed" : "no answer";
  if (key === "dicom" && (r.replies || [])[1] && r.replies[1][0] === 0x06) rec.released = true;
  return rec;
}

/**
 * Run the industrial reads for one host. OFF unless ics.enabled === true (--ics). Each exchange takes one Limiter slot
 * (acquire), so budgets, rate, the time limit and Ctrl-C apply as to any probe. Results go to h.ics.
 * exchange: icsExchange (tests may pass a stand-in).
 */
export async function runIcs(h, { ports, ics, acquire, exchange = icsExchange, signal = null, log = () => {} }) {
  if (!ics || ics.enabled !== true) return;
  const { plan, skipped } = icsPlan(h, ports, ics);
  if (!plan.length && !skipped.length) return;
  h.ics = [];
  for (const it of plan) {
    const release = await acquire(h.address);
    if (!release) { h.ics.push({ protocol: it.key, port: it.port, outcome: "not-sent: budget or time", messages_sent: 0, inventory_only: true }); continue; }
    try { h.ics.push(icsRecord(it.key, await exchange(h.address, it.key, { signal }))); } finally { release(); }
  }
  for (const s of skipped) h.ics.push({ protocol: s.key, port: s.port, outcome: s.why, messages_sent: 0, inventory_only: true });
  const ok = h.ics.filter((x) => x.outcome === "identified");
  log(`${h.address}: industrial identification (--ics) ${plan.length} exchange(s), ${ok.length} identified${ok.length ? ": " + ok.map((x) => x.name).join(", ") : ""}`);
}
