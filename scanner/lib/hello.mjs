// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Identify hellos (scan-identify-hellos), OFF by default: only with --identify (and IPMI only with --identify-bmc as well).
// Each service gets exactly ONE standard, unauthenticated client message, the reply's first lines/fields are read, and the
// connection is closed (SMTP and POP3 add the protocol's own polite QUIT on the same connection). Every message is a frozen
// literal in the HELLO table below; the only substitutions are the target's own address ({target}, checked with isIP) and
// the scanner's fixed User-Agent ({ua}). Nothing authenticates, sends mail, enumerates users, starts a stream or a call,
// or is broadcast or multicast: mDNS is a UNICAST query to the attested host's own UDP 5353.
// Lead decision (2026-11-22) adds three binary identify reads on the same rules: RDP (one X.224 Connection Request with an
// RDP Negotiation Request; nothing after the Connection Confirm), SMB (one SMB2 NEGOTIATE; never SESSION_SETUP or SMB1) and
// LDAP (one anonymous base-scope root DSE search for four named attributes, then unbind; never a bind).
//
// This file owns its sockets (one TCP connect or one UDP datagram per service per host); scripts/security-check.mjs
// section 7 (scripts/lib/scanner-hello-check.mjs) enforces: the table is frozen literals, every request starts with an
// allowed verb (EHLO, CAPA, OPTIONS, QUIT) or is one of the reviewed binary messages, no forbidden verb anywhere
// (AUTH, USER, PASS, APOP, VRFY, EXPN, MAIL, RCPT, STARTTLS, STLS, REGISTER, INVITE, DESCRIBE, SETUP, PLAY, AXFR ...), a single
// socket write and a single datagram send in the transport, no loop there, no broadcast or multicast, and identifyHost refuses to run
// unless enabled. The caller (scan.mjs) takes a Limiter slot for every exchange, so the host and total budgets, the time
// limit and Ctrl-C apply exactly as they do to the probes.
import net from "node:net";
import dgram from "node:dgram";
import { TIMEOUTS } from "./limits.mjs";
import { USER_AGENT } from "./probe.mjs";
import { mailProtocol } from "./mail-starttls.mjs";

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").replace(/[^ -~]/g, "?").slice(0, n).trim();
const tok = (s, n = 24) => (/^[A-Za-z0-9][A-Za-z0-9._=-]*$/.test(s) ? s.slice(0, n) : "");
const fz = (o) => Object.freeze(o);

/** The frozen request table: a text request (and the polite QUIT), or the hex of a reviewed binary message (and closeHex). */
export const HELLO = fz({
  smtp: fz({ proto: "tcp", flag: "--identify", greeting: true,
    request: "EHLO cyberview-scanner.invalid\r\n", quit: "QUIT\r\n",
    sends: "only with --identify (off by default): on an open SMTP port (greeting 220, not implicit TLS), a second connection that reads the greeting, sends \"EHLO cyberview-scanner.invalid\", reads the 250 lines (STARTTLS, SIZE, AUTH mechanism names only) and sends \"QUIT\"; never AUTH, MAIL, RCPT, VRFY, EXPN or STARTTLS" }),
  pop3: fz({ proto: "tcp", flag: "--identify", greeting: true,
    request: "CAPA\r\n", quit: "QUIT\r\n",
    sends: "only with --identify (off by default): on an open POP3 port (greeting +OK, not implicit TLS), a second connection that reads the greeting, sends \"CAPA\", reads the capability names and sends \"QUIT\"; never USER, PASS, APOP or STLS" }),
  rtsp: fz({ proto: "tcp", flag: "--identify", ports: fz([554, 8554]),
    request: "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: {ua}\r\n\r\n",
    sends: "only with --identify (off by default): on TCP 554 or 8554 when listed and open, one \"OPTIONS * RTSP/1.0\" request; the Server and Public headers are read; never DESCRIBE, SETUP or PLAY (no stream is started)" }),
  "sip-tcp": fz({ proto: "tcp", flag: "--identify", ports: fz([5060]),
    request: "OPTIONS sip:{target} SIP/2.0\r\nVia: SIP/2.0/TCP cyberview-scanner.invalid;branch=z9hG4bK-cyberview-identify\r\nMax-Forwards: 0\r\nFrom: <sip:cyberview-scanner@cyberview-scanner.invalid>;tag=cyberview\r\nTo: <sip:{target}>\r\nCall-ID: cyberview-identify@cyberview-scanner.invalid\r\nCSeq: 1 OPTIONS\r\nUser-Agent: {ua}\r\nContent-Length: 0\r\n\r\n",
    sends: "only with --identify (off by default): on TCP 5060 when listed and open, one SIP OPTIONS (Max-Forwards 0, so it is never forwarded); User-Agent, Server and Allow are read; never REGISTER or INVITE" }),
  "sip-udp": fz({ proto: "udp", flag: "--identify", port: 5060,
    request: "OPTIONS sip:{target} SIP/2.0\r\nVia: SIP/2.0/UDP cyberview-scanner.invalid;rport;branch=z9hG4bK-cyberview-identify\r\nMax-Forwards: 0\r\nFrom: <sip:cyberview-scanner@cyberview-scanner.invalid>;tag=cyberview\r\nTo: <sip:{target}>\r\nCall-ID: cyberview-identify@cyberview-scanner.invalid\r\nCSeq: 1 OPTIONS\r\nUser-Agent: {ua}\r\nContent-Length: 0\r\n\r\n",
    sends: "only with --identify (off by default): when 5060 is in the port list, one SIP OPTIONS datagram to UDP 5060 (Max-Forwards 0); User-Agent, Server and Allow are read; never REGISTER or INVITE" }),
  // DNS-SD service-type query (RFC 6763 section 9): PTR _services._dns-sd._udp.local, class IN, sent from an ephemeral
  // port to the host's own UDP 5353 (a unicast "legacy" query, RFC 6762 section 6.7: the answer comes back to us only)
  mdns: fz({ proto: "udp", flag: "--identify", port: 5353,
    hex: "000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001",
    sends: "only with --identify (off by default): one unicast mDNS/DNS-SD query (PTR _services._dns-sd._udp.local) to the host's own UDP 5353, never multicast; the advertised service types and a TXT Name= label are read" }),
  // ASF presence ping (RMCP class 6, IANA 4542, message type 0x80): the standard RMCP identify; no IPMI session
  ipmi: fz({ proto: "udp", flag: "--identify-bmc", port: 623,
    hex: "0600ff06000011be80000000",
    sends: "only with --identify and --identify-bmc (both off by default): one RMCP/ASF presence ping to UDP 623; the pong says whether a BMC with IPMI answers; no session, no Get Channel Auth, no cipher or hash request" }),
  // RDP, [MS-RDPBCGR] 2.2.1.1 Client X.224 Connection Request PDU: TPKT (T.123: 03 00, length 19), X.224 CR TPDU (X.224
  // 13.3: LI 0x0e, CR 0xe0, DST-REF 0, SRC-REF 0, class 0; no cookie or routing token), RDP_NEG_REQ (2.2.1.1.1: type 0x01,
  // flags 0, length 8, requestedProtocols PROTOCOL_SSL|PROTOCOL_HYBRID = 0x00000003 little-endian). The server's Connection
  // Confirm (2.2.1.2) carries RDP_NEG_RSP.selectedProtocol or RDP_NEG_FAILURE.failureCode; nothing more is sent.
  rdp: fz({ proto: "tcp", flag: "--identify", ports: fz([3389]),
    hex: "030000130ee000000000000100080003000000",
    sends: "only with --identify (off by default): on TCP 3389 when listed and open, one X.224 Connection Request with an RDP Negotiation Request (TLS or CredSSP offered); the Connection Confirm's selected protocol is read (NLA/CredSSP, TLS or standard RDP security); never TLS, CredSSP, MCS or a login" }),
  // SMB, [MS-SMB2] 2.2.3 NEGOTIATE over direct TCP ([MS-SMB2] 2.1: 4-byte header 00 + 24-bit length 0x6c): SMB2 header
  // (2.2.1.2, ProtocolId FE 'SMB', StructureSize 64, Command 0 NEGOTIATE, CreditRequest 1, MessageId 0, all else 0), body
  // StructureSize 36, DialectCount 4, SecurityMode SIGNING_ENABLED, Capabilities 0, ClientGuid "CyberView-Scannr", 8 zero
  // bytes (ClientStartTime), Dialects 0x0202, 0x0210, 0x0300, 0x0302. 0x0311 is not offered: it needs negotiate contexts.
  // The response (2.2.4) gives SecurityMode and DialectRevision. No SMB1, no SESSION_SETUP, no TREE_CONNECT.
  smb: fz({ proto: "tcp", flag: "--identify", ports: fz([445]),
    hex: "0000006cfe534d424000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002400040001000000000000004379626572566965772d5363616e6e7200000000000000000202100200030203",
    sends: "only with --identify (off by default): on TCP 445 when listed and open, one SMB2 NEGOTIATE (dialects 2.0.2, 2.1, 3.0, 3.0.2); the chosen dialect and the signing mode (enabled/required) are read; never SMB1, SESSION_SETUP, TREE_CONNECT or a login" }),
  // LDAP, RFC 4511 4.5.1 SearchRequest as BER (X.690): LDAPMessage { messageID 1, [APPLICATION 3] { baseObject "" (root DSE,
  // RFC 4512 5.1), scope baseObject(0), derefAliases neverDerefAliases(0), sizeLimit 1, timeLimit 10, typesOnly FALSE,
  // filter present objectClass ([7]), attributes supportedLDAPVersion, vendorName, vendorVersion, objectClass } };
  // then the close message, LDAPMessage { messageID 2, [APPLICATION 2] UnbindRequest NULL } (RFC 4511 4.3). No bind of any kind.
  ldap: fz({ proto: "tcp", flag: "--identify", ports: fz([389]),
    hex: "3063020101635e04000a01000a010002010102010a010100870b6f626a656374436c617373303e0414737570706f727465644c44415056657273696f6e040a76656e646f724e616d65040d76656e646f7256657273696f6e040b6f626a656374436c617373",
    closeHex: "30050201024200",
    sends: "only with --identify (off by default): on TCP 389 when listed and open, one anonymous base-scope search of the root DSE for supportedLDAPVersion, vendorName, vendorVersion and objectClass only, then an unbind; never a bind, a subtree search or any other attribute" }),
});

/** Lines for the run header and report.json: what each hello sends (all off by default). */
export const HELLO_SENDS = fz(Object.fromEntries(Object.entries(HELLO).map(([k, v]) => [`identify-${k}`, v.sends])));

/** The exact bytes for one hello on one host: the frozen literal, with only {target} (an IP address) and {ua} filled in. */
export function wire(key, ip = "") {
  const e = HELLO[key];
  if (!e) return null;
  if (e.hex) return Buffer.from(e.hex, "hex");
  const v = net.isIP(ip);
  if (/\{target\}/.test(e.request) && !v) return null;
  const target = v === 6 ? `[${ip}]` : ip;
  return Buffer.from(e.request.replace(/\{target\}/g, target).replace(/\{ua\}/g, USER_AGENT), "latin1");
}
const quitBytes = (key) => (!HELLO[key] ? null : HELLO[key].quit ? Buffer.from(HELLO[key].quit, "latin1") : HELLO[key].closeHex ? Buffer.from(HELLO[key].closeHex, "hex") : null);

/* ---- reply parsers (pure): only what the rows name is kept; names and tokens, never bodies ---- */
const lines = (s) => String(s || "").split(/\r?\n/);
/** A complete SMTP reply: the last line is "ddd " (or "ddd" alone). */
export const smtpDone = (s) => lines(s).some((l) => /^\d{3}(?: |$)/.test(l));
export const pop3Done = (s) => /^-ERR/.test(s) || /\r?\n\.\r?\n/.test(s) || /^\+OK[^\r\n]*\r?\n\.\r?\n/.test(s);
export const greetDone = (s) => /\r?\n/.test(s);
export const headDone = (s) => /\r?\n\r?\n/.test(s);
const bin = (s) => (Buffer.isBuffer(s) ? s : Buffer.from(String(s || ""), "latin1"));
/** A whole TPKT (RDP) or direct-TCP SMB2 message has arrived. */
export const tpktDone = (s) => { const b = bin(s); return b.length >= 4 && b[0] === 3 && b.length >= b.readUInt16BE(2); };
export const nbssDone = (s) => { const b = bin(s); return b.length >= 4 && b.length >= 4 + (b.readUInt32BE(0) & 0xffffff); };
/** One BER TLV at o -> { tag, start (of the value), end } or null when incomplete. */
function tlv(b, o) {
  if (o + 2 > b.length) return null;
  let len = b[o + 1], start = o + 2;
  if (len & 0x80) { const n = len & 0x7f; if (n < 1 || n > 3 || start + n > b.length) return null; len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[start + i]; start += n; }
  return start + len > b.length ? null : { tag: b[o], start, end: start + len };
}
/** LDAP: a SearchResultDone ([APPLICATION 5]) or any non-entry response has arrived. */
export const ldapDone = (s) => {
  const b = bin(s);
  for (let o = 0, n = 0; o < b.length && n < 20; n++) { const m = tlv(b, o); if (!m || m.tag !== 0x30) return false; const id = tlv(b, m.start); const op = id && tlv(b, id.end); if (!op) return false; if (op.tag !== 0x64) return true; o = m.end; }
  return false;
};

const RDP_PROTO = { 0: "standard RDP security", 1: "TLS", 2: "CredSSP (NLA)", 4: "RDSTLS", 8: "CredSSP with Early User Authorization (NLA)" };
const RDP_FAIL = { 1: "SSL_REQUIRED_BY_SERVER", 2: "SSL_NOT_ALLOWED_BY_SERVER", 3: "SSL_CERT_NOT_ON_SERVER", 4: "INCONSISTENT_FLAGS", 5: "HYBRID_REQUIRED_BY_SERVER", 6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER" };
/** RDP Connection Confirm ([MS-RDPBCGR] 2.2.1.2) -> { confirm, selected, protocol, failure, nla } */
export function parseRdp(s) {
  const b = bin(s), out = { confirm: false, selected: null, protocol: "", failure: "", nla: null };
  if (!tpktDone(b) || b.length < 11 || (b[5] & 0xf0) !== 0xd0) return out;
  out.confirm = true;
  if (b.length < 19) { out.selected = 0; out.protocol = RDP_PROTO[0]; out.nla = false; return out; }   // no negotiation response: legacy security
  const v = b.readUInt32LE(15);
  if (b[11] === 0x02) { out.selected = v; out.protocol = RDP_PROTO[v] || `unknown (${v})`; out.nla = v === 2 || v === 8; }
  else if (b[11] === 0x03) { out.failure = RDP_FAIL[v] || `failure ${v}`; out.nla = v === 5 ? true : null; }
  return out;
}
const SMB_DIALECT = { 0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1", 0x02ff: "2.???" };
/** SMB2 NEGOTIATE response ([MS-SMB2] 2.2.4) -> { smb2, status, dialect, signing_enabled, signing_required } */
export function parseSmb(s) {
  const b = bin(s), out = { smb2: false, status: null, dialect: "", signing_enabled: null, signing_required: null };
  if (b.length < 4 + 64 + 8 || b.readUInt32BE(4) !== 0xfe534d42) return out;
  out.smb2 = true; out.status = b.readUInt32LE(12);
  if (b.readUInt16LE(16) !== 0 || out.status !== 0 || b.readUInt16LE(68) !== 65) return out;
  const mode = b.readUInt16LE(70), d = b.readUInt16LE(72);
  out.dialect = SMB_DIALECT[d] || `0x${d.toString(16)}`; out.signing_enabled = (mode & 1) !== 0; out.signing_required = (mode & 2) !== 0;
  return out;
}
/** LDAP root DSE SearchResultEntry -> { ok, versions[], vendor_name, vendor_version, object_classes[] } (the four requested attributes only) */
export function parseLdap(s) {
  const b = bin(s), out = { ok: false, versions: [], vendor_name: "", vendor_version: "", object_classes: [] };
  const m = tlv(b, 0); if (!m || m.tag !== 0x30) return out;
  const id = tlv(b, m.start), op = id && tlv(b, id.end);
  if (!op || op.tag !== 0x64) return out;
  const dn = tlv(b, op.start), attrs = dn && tlv(b, dn.end);
  if (!attrs || attrs.tag !== 0x30) return out;
  out.ok = true;
  for (let o = attrs.start, n = 0; o < attrs.end && n < 20; n++) {
    const pa = tlv(b, o); if (!pa) break; o = pa.end;
    const ty = tlv(b, pa.start), vals = ty && tlv(b, ty.end); if (!vals) continue;
    const type = b.subarray(ty.start, ty.end).toString("latin1").toLowerCase(), list = [];
    for (let q = vals.start, k = 0; q < vals.end && k < 10; k++) { const v = tlv(b, q); if (!v) break; list.push(clip(b.subarray(v.start, v.end).toString("utf8"), 80)); q = v.end; }
    if (type === "supportedldapversion") out.versions = list.filter((x) => /^\d{1,2}$/.test(x));
    else if (type === "vendorname") out.vendor_name = list[0] || "";
    else if (type === "vendorversion") out.vendor_version = list[0] || "";
    else if (type === "objectclass") out.object_classes = list.filter((x) => /^[A-Za-z][A-Za-z0-9-]{0,60}$/.test(x));
  }
  return out;
}

/** EHLO reply -> { code, starttls, size, auth[], keywords[] } (the first 250 line carries the server's name: not kept). */
export function parseEhlo(text) {
  const ls = lines(text).filter((l) => /^\d{3}[ -]?/.test(l));
  const code = ls.length ? Number(ls[0].slice(0, 3)) : 0;
  const out = { code, starttls: false, size: null, auth: [], keywords: [] };
  if (code !== 250) return out;
  for (const l of ls.slice(1, 60)) {
    const parts = l.slice(4).trim().split(/[\s=]+/), kw = (parts[0] || "").toUpperCase();
    if (!/^[A-Z0-9][A-Z0-9-]{0,29}$/.test(kw)) continue;
    if (!out.keywords.includes(kw) && out.keywords.length < 30) out.keywords.push(kw);
    if (/^STARTTLS$/.test(kw)) out.starttls = true;
    if (kw === "SIZE" && /^\d{1,12}$/.test(parts[1] || "")) out.size = Number(parts[1]);
    if (/^AUTH$/.test(kw)) for (const m of parts.slice(1)) { const t = m.toUpperCase(); if (/^[A-Z0-9_-]{1,20}$/.test(t) && !out.auth.includes(t) && out.auth.length < 12) out.auth.push(t); }
  }
  return out;
}

/** CAPA reply -> { ok, starttls, sasl[], capabilities[], implementation } */
export function parseCapa(text) {
  const ls = lines(text), out = { ok: /^\+OK/.test(ls[0] || ""), starttls: false, sasl: [], capabilities: [], implementation: "" };
  if (!out.ok) return out;
  for (const l of ls.slice(1, 60)) {
    if (l === ".") break;
    const parts = l.trim().split(/\s+/), cap = (parts[0] || "").toUpperCase();
    if (!/^[A-Z0-9][A-Z0-9-]{0,29}$/.test(cap)) continue;
    if (!out.capabilities.includes(cap) && out.capabilities.length < 30) out.capabilities.push(cap);
    if (/^STLS$/.test(cap)) out.starttls = true;
    if (cap === "SASL") for (const m of parts.slice(1)) { const t = m.toUpperCase(); if (/^[A-Z0-9_-]{1,20}$/.test(t) && !out.sasl.includes(t) && out.sasl.length < 12) out.sasl.push(t); }
    if (cap === "IMPLEMENTATION") out.implementation = clip(parts.slice(1).join(" "), 80);   // the server's own statement
  }
  return out;
}

/** RTSP or SIP response head -> { protocol, code, server, user_agent, methods[] } (methods from Public or Allow). */
export function parseHead(text, protocol) {
  const ls = lines(text), m = new RegExp(`^${protocol === "sip" ? "SIP/2\\.0" : "RTSP/1\\.\\d"} (\\d{3})`).exec(ls[0] || "");
  const out = { protocol, code: m ? Number(m[1]) : 0, server: "", user_agent: "", methods: [] };
  if (!m) return out;
  for (const l of ls.slice(1, 60)) {
    if (!l) break;
    const h = /^([A-Za-z-]{1,40})\s*:\s*(.*)$/.exec(l);
    if (!h) continue;
    const name = h[1].toLowerCase();
    if (name === "server") out.server = clip(h[2], 120);
    else if (name === "user-agent") out.user_agent = clip(h[2], 120);
    else if (name === "public" || name === "allow") for (const x of h[2].split(",")) { const t = x.trim().toUpperCase(); if (/^[A-Z_-]{2,20}$/.test(t) && !out.methods.includes(t) && out.methods.length < 20) out.methods.push(t); }
  }
  return out;
}

/** A DNS name at offset o (with compression pointers, bounded) -> [name, next offset] */
function dnsName(buf, o) {
  const labels = []; let jumps = 0, end = -1, p = o;
  while (p < buf.length && labels.length < 40) {
    const len = buf[p];
    if (len === 0) { p++; break; }
    if ((len & 0xc0) === 0xc0) { if (p + 1 >= buf.length || ++jumps > 10) return ["", buf.length]; if (end < 0) end = p + 2; p = ((len & 0x3f) << 8) | buf[p + 1]; continue; }
    if (p + 1 + len > buf.length) return ["", buf.length];
    labels.push(buf.subarray(p + 1, p + 1 + len).toString("latin1")); p += 1 + len;
  }
  return [labels.join("."), end >= 0 ? end : p];
}

/** mDNS reply -> { services[] (service types such as _ndi._tcp.local), name (a TXT Name= label) } */
export function parseMdns(buf) {
  const out = { services: [], name: "" };
  if (!Buffer.isBuffer(buf) || buf.length < 12) return out;
  const qd = buf.readUInt16BE(4), rr = buf.readUInt16BE(6) + buf.readUInt16BE(8) + buf.readUInt16BE(10);
  let o = 12;
  for (let i = 0; i < qd && o < buf.length; i++) o = dnsName(buf, o)[1] + 4;
  for (let i = 0; i < Math.min(rr, 64) && o + 10 <= buf.length; i++) {
    const [, n] = dnsName(buf, o); o = n;
    if (o + 10 > buf.length) break;
    const type = buf.readUInt16BE(o), rdlen = buf.readUInt16BE(o + 8), rd = o + 10;
    if (rd + rdlen > buf.length) break;
    if (type === 12) { const [t] = dnsName(buf, rd); const s = clip(t, 80); if (/^_[A-Za-z0-9-]{1,30}\._(?:tcp|udp)\.local$/i.test(s) && !out.services.includes(s.toLowerCase()) && out.services.length < 20) out.services.push(s.toLowerCase()); }
    if (type === 16 && !out.name) for (let q = rd; q < rd + rdlen;) { const l = buf[q], s = buf.subarray(q + 1, q + 1 + l).toString("utf8"); q += 1 + l; const m = /^Name=(.*)$/i.exec(s); if (m) { out.name = clip(m[1], 60); break; } }
    o = rd + rdlen;
  }
  return out;
}

/** RMCP/ASF presence pong -> { pong, ipmi } (supported-entities bit 7 = IPMI supported); anything else -> { pong: false } */
export function parseAsfPong(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 28 || buf[0] !== 0x06 || buf[3] !== 0x06 || buf.readUInt32BE(4) !== 4542 || buf[8] !== 0x40) return { pong: false, ipmi: false };
  return { pong: true, ipmi: (buf[20] & 0x80) !== 0 };
}

/* ---- transport (no loop): one connection or one datagram per call; checked by scanner-hello-check.mjs ---- */
function say(sock, bytes) { sock.write(bytes); }
function readUntil(sock, done, ms, maxBytes) {
  return new Promise((resolve) => {
    const parts = []; let n = 0;
    const fin = () => { clearTimeout(t); sock.removeListener("data", on); resolve(Buffer.concat(parts).subarray(0, maxBytes).toString("latin1")); };
    const on = (d) => { parts.push(d); n += d.length; if (n >= maxBytes || done(Buffer.concat(parts).toString("latin1"))) fin(); };
    const t = setTimeout(fin, ms);
    sock.on("data", on); sock.once("end", fin); sock.once("close", fin); sock.once("error", fin);
  });
}
const DONE = { smtp: smtpDone, pop3: pop3Done, rdp: tpktDone, smb: nbssDone, ldap: ldapDone };
/** One TCP hello: connect, [read the greeting], send the frozen request, read the reply, [send QUIT], close. Never throws. */
export async function tcpHello(ip, port, key, { signal = null, timeouts = TIMEOUTS } = {}) {
  const e = HELLO[key], out = { service: key, port, proto: "tcp", state: "no-answer", sent: [], greeting: "", reply: "", error: "" };
  const bytes = e && e.proto === "tcp" ? wire(key, ip) : null;
  if (!bytes) return { ...out, state: "not-sent", error: "not a TCP hello" };
  if (signal && signal.aborted) return { ...out, state: "not-sent", error: "stopped" };
  let sock = null;
  const kill = () => { try { sock && sock.destroy(); } catch { /* closed */ } };
  if (signal) signal.addEventListener("abort", kill, { once: true });
  const hard = setTimeout(kill, timeouts.connectMs + timeouts.readMs * 3 + 1000);
  try {
    sock = await new Promise((resolve, reject) => {
      const s = net.connect({ host: ip, port, timeout: timeouts.connectMs });
      const t = setTimeout(() => { s.destroy(); reject(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })); }, timeouts.connectMs);
      s.once("connect", () => { clearTimeout(t); s.setTimeout(0); resolve(s); });
      s.once("error", (err) => { clearTimeout(t); s.destroy(); reject(err); });
    });
    if (e.greeting) {
      out.greeting = await readUntil(sock, key === "smtp" ? smtpDone : greetDone, timeouts.readMs, timeouts.maxBytes);
      // the service must greet as the protocol says before anything is sent; otherwise nothing is sent at all
      if (!(key === "smtp" ? /^220[ -]/.test(out.greeting) && smtpDone(out.greeting) : /^\+OK/.test(out.greeting))) { out.state = "not-sent"; out.error = "no matching greeting"; return out; }
    }
    say(sock, bytes); out.sent.push(e.hex ? `${key} request (${e.hex.length / 2} bytes)` : clip(e.request.split(/[\s]/)[0], 12));
    out.reply = await readUntil(sock, DONE[key] || headDone, timeouts.readMs, timeouts.maxBytes);
    if (out.reply) out.state = "answered";
    if ((e.quit || e.closeHex) && out.reply && !sock.destroyed && !sock.writableEnded) { say(sock, quitBytes(key)); out.sent.push(e.quit ? "QUIT" : `${key} close`); }
    sock.end();
  } catch (err) {
    out.state = err && err.code === "ECONNREFUSED" ? "refused" : out.state;
    out.error = String((err && (err.code || err.message)) || err).slice(0, 80);
  } finally { clearTimeout(hard); if (signal) signal.removeEventListener("abort", kill); kill(); }
  return out;
}
/** One UDP hello: ONE datagram to the host's own address, at most one reply (from that address) read, close. Never throws. */
export async function udpHello(ip, key, { signal = null, timeouts = TIMEOUTS, port = 0 } = {}) {
  const e = HELLO[key], dest = port || (e && e.port), out = { service: key, port: dest, proto: "udp", state: "no-answer", sent: [], reply: null, error: "" };
  const bytes = e && e.proto === "udp" && net.isIP(ip) ? wire(key, ip) : null;
  if (!bytes) return { ...out, state: "not-sent", error: "not a UDP hello" };
  if (signal && signal.aborted) return { ...out, state: "not-sent", error: "stopped" };
  const sock = dgram.createSocket(net.isIP(ip) === 6 ? "udp6" : "udp4");
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => { if (settled) return; settled = true; clearTimeout(timer); if (signal) signal.removeEventListener("abort", finish); try { sock.close(); } catch { /* closed */ } resolve(out); };
    const timer = setTimeout(finish, timeouts.connectMs + timeouts.readMs);
    if (signal) signal.addEventListener("abort", finish, { once: true });
    sock.once("error", (err) => { out.error = String((err && (err.code || err.message)) || err).slice(0, 80); finish(); });
    sock.on("message", (msg, rinfo) => { if (rinfo.address !== ip) return; out.state = "answered"; out.reply = msg.subarray(0, timeouts.maxBytes); finish(); });
    sock.send(bytes, dest, ip, (err) => { if (err) { out.error = String(err.code || err.message).slice(0, 80); finish(); } });
    out.sent.push(e.hex ? `${e.hex.length / 2}-byte ${key} query` : clip(e.request.split(/[\s]/)[0], 12));
  });
}
/* ---- end transport ---- */

/**
 * Which hellos one host gets, from what the probes already found. -> [{ key, port }] with at most one entry per service.
 * TCP: SMTP/POP3 on open ports whose greeting says so (not implicit TLS); RTSP on 554/8554 and SIP on 5060 when open.
 * UDP: SIP when 5060 is in the port list; mDNS always (with --identify); IPMI only with --identify-bmc.
 */
export function helloPlan(h, { ports = [], bmc = false } = {}) {
  const plan = [], tlsPorts = new Set((h.tls || []).map((t) => t.port)), have = new Set();
  const add = (key, port) => { if (!have.has(key)) { have.add(key); plan.push({ key, port }); } };
  for (const p of (h.ports || []).slice().sort((a, b) => a.port - b.port)) {
    if (p.state !== "open" || tlsPorts.has(p.port)) continue;
    const svc = (h.services || []).find((s) => s.port === p.port) || {}, mp = mailProtocol(p.banner, p.port, svc.proto || "");
    if (mp === "smtp" || mp === "pop3") add(mp, p.port);
    else if (HELLO.rtsp.ports.includes(p.port)) add("rtsp", p.port);
    else if (HELLO["sip-tcp"].ports.includes(p.port)) add("sip-tcp", p.port);
    else for (const k of ["rdp", "smb", "ldap"]) if (HELLO[k].ports.includes(p.port)) add(k, p.port);
  }
  if (ports.includes(5060)) add("sip-udp", 5060);
  add("mdns", 5353);
  if (bmc) add("ipmi", 623);
  return plan;
}

/** One hello's raw result -> the report record { service, port, proto, state, sent[], read } */
export function helloRecord(r) {
  const rec = { service: r.service, port: r.port, proto: r.proto, state: r.state, sent: r.sent || [], read: null, ...(r.error ? { error: r.error } : {}) };
  if (r.state !== "answered") return rec;
  if (r.service === "smtp") rec.read = parseEhlo(r.reply);
  else if (r.service === "pop3") { const c = parseCapa(r.reply); rec.read = c; }
  else if (r.service === "rtsp") rec.read = parseHead(r.reply, "rtsp");
  else if (r.service === "sip-tcp" || r.service === "sip-udp") rec.read = parseHead(Buffer.isBuffer(r.reply) ? r.reply.toString("latin1") : r.reply, "sip");
  else if (r.service === "mdns") rec.read = parseMdns(r.reply);
  else if (r.service === "ipmi") rec.read = parseAsfPong(r.reply);
  else if (r.service === "rdp") rec.read = parseRdp(r.reply);
  else if (r.service === "smb") rec.read = parseSmb(r.reply);
  else if (r.service === "ldap") rec.read = parseLdap(r.reply);
  return rec;
}

/** Services (all guessed: no version is read) and observations from the hello records. */
export function helloFindings(records) {
  const services = [], obs = [];
  const svc = (port, proto, vendor, product, label, evidence) => ({ port, proto, vendor, product, label, version: "", shown_version: "", distro: "", source: "identify hello (--identify)", evidence: clip(evidence, 200), guessed: true });
  for (const r of records) {
    const d = r.read;
    if (!d) continue;
    if (r.service === "smtp" && d.code === 250) {
      if (!d.starttls) obs.push({ port: r.port, kind: "smtp-no-starttls", severity: "medium", text: `SMTP on port ${r.port} does not advertise STARTTLS in its EHLO reply: mail${r.port === 587 ? " and submission logins" : ""} to and from it can cross the network unencrypted` });
      const plain = d.auth.filter((m) => m === "PLAIN" || m === "LOGIN");
      if (plain.length) obs.push({ port: r.port, kind: "smtp-auth-cleartext", severity: "medium", text: `SMTP on port ${r.port} offers AUTH ${plain.join(", ")} before any TLS: a password sent this way crosses the network in clear text unless clients always use STARTTLS first` });
    }
    if (r.service === "pop3" && d.ok) {
      if (!d.starttls) obs.push({ port: r.port, kind: "pop3-no-stls", severity: "medium", text: `POP3 on port ${r.port} does not advertise STLS in its CAPA reply: mail logins on it cross the network in clear text` });
      if (d.implementation) services.push(svc(r.port, "pop3", "", "", `POP3 server (CAPA IMPLEMENTATION: ${d.implementation})`, `CAPA IMPLEMENTATION ${d.implementation}`));
    }
    if ((r.service === "rtsp" || r.service === "sip-tcp" || r.service === "sip-udp") && d.code) {
      const who = r.service === "rtsp" ? d.server : d.user_agent || d.server, kind = r.service === "rtsp" ? "RTSP" : "SIP";
      services.push(svc(r.port, r.service === "rtsp" ? "rtsp" : "sip", "", "", `${kind} ${r.service === "rtsp" ? "server" : "user agent"}${who ? `: ${who}` : ""}`, `${kind} OPTIONS answered ${d.code}${who ? `; ${r.service === "rtsp" || !d.user_agent ? "Server" : "User-Agent"}: ${who}` : ""}${d.methods.length ? `; methods ${d.methods.join(" ")}` : ""}`));
      obs.push({ port: r.port, proto: r.proto, kind: r.service === "rtsp" ? "rtsp-answers" : "sip-answers", severity: r.service === "rtsp" ? "info" : "low",
        text: r.service === "rtsp" ? `RTSP answers an unauthenticated OPTIONS on port ${r.port} (status ${d.code}): a camera or media server is reachable; make sure streams require authentication`
          : `SIP answers an unauthenticated OPTIONS on ${r.proto.toUpperCase()} ${r.port} (status ${d.code}): a phone system is reachable from here; exposed SIP is a common target for toll fraud` });
    }
    if (r.service === "mdns" && (d.services.length || d.name)) {
      services.push(svc(r.port, "mdns", "", "", `mDNS responder (${d.services.slice(0, 6).join(", ") || "no service types"})`, `unicast DNS-SD answer: ${d.services.join(" ")}${d.name ? `; Name=${d.name}` : ""}`));
      // the reviewed catalog row (ptzoptics-pt30x-sdi-ndi-cameras): _ndi and _ssh advertised together; product only, guessed
      if (d.services.some((s) => s.startsWith("_ndi._")) && d.services.some((s) => s.startsWith("_ssh._")))
        services.push(svc(r.port, "mdns", "PTZOptics", "PT30X-SDI/NDI Cameras", "PTZOptics PT30X-SDI/NDI camera (guessed from mDNS _ndi and _ssh; no version read)", `mDNS advertises _ndi and _ssh${d.name ? `; Name=${d.name}` : ""}`));
      obs.push({ port: r.port, proto: "udp", kind: "mdns-unicast", severity: "low", text: `mDNS answers a unicast query on UDP 5353 from off the local link, listing ${d.services.length} service type(s): it tells anyone who can reach it what runs there` });
    }
    if (r.service === "rdp" && d.confirm) {
      services.push(svc(r.port, "rdp", "", "", `RDP (${d.protocol || d.failure || "negotiation not read"})`, `X.224 Connection Confirm: ${d.protocol ? `selected ${d.protocol}` : d.failure ? `negotiation failure ${d.failure}` : "no negotiation response"}`));
      if (d.selected === 1 || d.selected === 0) obs.push({ port: r.port, kind: "rdp-no-nla", severity: d.selected === 0 ? "high" : "medium", text: d.selected === 0
        ? `RDP on port ${r.port} chose standard RDP security (no TLS, no Network Level Authentication) when TLS and CredSSP were offered: the session is weakly protected and the login screen is open to anyone who connects`
        : `RDP on port ${r.port} chose TLS without CredSSP when both were offered: Network Level Authentication is not required, so the login screen (and any pre-authentication flaw) is reachable before a user authenticates` });
    }
    if (r.service === "smb" && d.smb2 && d.dialect) {
      services.push(svc(r.port, "smb", "", "", `SMB2 server (dialect ${d.dialect})`, `SMB2 NEGOTIATE: dialect ${d.dialect}, signing ${d.signing_required ? "required" : d.signing_enabled ? "enabled, not required" : "not enabled"}`));
      if (!d.signing_required) obs.push({ port: r.port, kind: "smb-signing-not-required", severity: "medium", text: `SMB on port ${r.port} does not require message signing (dialect ${d.dialect}): NTLM relay to this host is possible; require signing unless a documented exception applies` });
    }
    if (r.service === "ldap" && d.ok) {
      const openldap = d.object_classes.some((c) => c.toLowerCase() === "openldaprootdse");
      const who = d.vendor_name ? `${d.vendor_name}${d.vendor_version ? ` ${d.vendor_version}` : ""}` : openldap ? "OpenLDAP" : "";
      services.push(svc(r.port, "ldap", openldap ? "OpenLDAP" : "", openldap ? "OpenLDAP" : "", `LDAP directory${who ? `: ${who}` : ""}${d.versions.length ? ` (LDAPv${d.versions.join("/")})` : ""}`,
        `root DSE: ${[d.vendor_name && `vendorName ${d.vendor_name}`, d.vendor_version && `vendorVersion ${d.vendor_version}`, openldap && "objectClass OpenLDAProotDSE", d.versions.length && `supportedLDAPVersion ${d.versions.join(" ")}`].filter(Boolean).join("; ") || "answered"}`));
      obs.push({ port: r.port, kind: "ldap-anonymous-rootdse", severity: "info", text: `LDAP on port ${r.port} answers an anonymous root DSE read without TLS${who ? ` and names itself ${who}` : ""}; directory binds on this port cross the network in clear text unless StartTLS is required` });
    }
    if (r.service === "ipmi" && d.pong) {
      services.push(svc(r.port, "ipmi", "", "", `BMC (RMCP/ASF presence pong${d.ipmi ? ", IPMI supported" : ""})`, `ASF presence pong on UDP 623${d.ipmi ? "; supported entities: IPMI" : ""}`));
      obs.push({ port: r.port, proto: "udp", kind: "ipmi-exposed", severity: "medium", text: `A BMC answers RMCP on UDP 623${d.ipmi ? " and states IPMI support" : ""}: out-of-band management is reachable from here; keep BMCs on an isolated management network` });
    }
  }
  return { services, observations: obs };
}

/**
 * Run the planned hellos for one host, one at a time, each through the caller's Limiter (acquire(host) -> release | null).
 * Refuses to do anything unless opts.enabled === true. -> [record]
 */
export async function identifyHost(h, opts = {}) {
  if (!opts || opts.enabled !== true) return [];
  const { acquire, signal = null, ports = [], bmc = false, tcp = tcpHello, udp = udpHello } = opts;
  const out = [];
  for (const item of helloPlan(h, { ports, bmc: bmc === true })) {
    const release = await acquire(h.address);
    if (!release) { out.push({ service: item.key, port: item.port, proto: HELLO[item.key].proto, state: "not-sent: budget or time", sent: [], read: null }); continue; }
    try {
      const r = HELLO[item.key].proto === "tcp" ? await tcp(h.address, item.port, item.key, { signal }) : await udp(h.address, item.key, { signal });
      out.push(helloRecord(r));
    } finally { release(); }
  }
  return out;
}

/** The run header line. */
export function identifyHeaderText(o) {
  if (!o || !o.enabled) return "off (--identify not given): no protocol hello is sent";
  return `on (--identify): one standard unauthenticated message per service (SMTP EHLO, POP3 CAPA, RTSP and SIP OPTIONS, unicast mDNS, RDP X.224 negotiation, SMB2 NEGOTIATE, LDAP root DSE read), then close; BMC (IPMI RMCP ping) ${o.bmc ? "on (--identify-bmc)" : "off"}`;
}
