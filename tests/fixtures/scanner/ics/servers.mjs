// Loopback stand-ins for the industrial identification reads (scan-ics-identify): each server listens on 127.0.0.1 only,
// records every byte it receives, and answers each complete request with a reply built here from the public protocol
// layouts. Invented identities only (no real device data). Used by tests/unit/scanner-ics.test.mjs.
import net from "node:net";
import dgram from "node:dgram";

const u16le = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u16be = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const i32le = (n) => { const b = Buffer.alloc(4); b.writeInt32LE(n); return b; };
const ustr = (s) => (s === null ? i32le(-1) : Buffer.concat([u32le(Buffer.byteLength(s)), Buffer.from(s)]));
const cat = (...a) => Buffer.concat(a.map((x) => (Buffer.isBuffer(x) ? x : Buffer.from(x))));

/** How a server knows one request is complete (the same framing rules the client uses). */
export const FRAMES = {
  modbus: (b) => (b.length >= 6 ? 6 + b.readUInt16BE(4) : 0),
  enip: (b) => (b.length >= 4 ? 24 + b.readUInt16LE(2) : 0),
  s7: (b) => (b.length >= 4 ? b.readUInt16BE(2) : 0),
  opcua: (b) => (b.length >= 8 ? b.readUInt32LE(4) : 0),
  dicom: (b) => (b.length >= 6 ? 6 + b.readUInt32BE(2) : 0),
};

/* ---- replies ---- */
export function modbusReply(objs = [["ExampleVendor"], ["EX-100"], ["V2.3"]], { more = 0 } = {}) {
  const items = objs.map(([v], i) => cat([i, Buffer.byteLength(v)], v));
  const pdu = cat([0x2b, 0x0e, 0x01, 0x01, more, 0x00, objs.length], ...items);
  return cat(u16be(1), u16be(0), u16be(pdu.length + 1), [0xff], pdu);
}
export const modbusException = () => cat(u16be(1), u16be(0), u16be(3), [0xff, 0xab, 0x01]);

export function enipReply({ vendor = 1, name = "1756-L71/B LOGIX5571", major = 20, minor = 11 } = {}) {
  const item = cat(u16le(1), [0x00, 0x02, 0xaf, 0x12, 127, 0, 0, 1], Buffer.alloc(8), u16le(vendor), u16le(0x0e), u16le(0x36), [major, minor], u16le(0x3060), u32le(0x00c0ffee), [Buffer.byteLength(name)], name, [0x03]);
  const data = cat(u16le(1), u16le(0x0c), u16le(item.length), item);
  return cat(u16le(0x63), u16le(data.length), u32le(0), u32le(0), Buffer.alloc(8), u32le(0), data);
}

const tpkt = (body) => cat([0x03, 0x00], u16be(body.length + 4), body);
export const s7Cc = () => tpkt(Buffer.from("11d00001000100c0010ac1020100c2020102", "hex"));
export const s7SetupAck = () => tpkt(Buffer.from("02f080320300000001000800000000f0000001000100f0", "hex"));
export function s7Szl({ order = "6ES7 214-1AG40-0XB0", fw = [4, 2, 1] } = {}) {
  const rec = (idx, mlfb, ausbg, ausbe) => cat(u16be(idx), Buffer.from(mlfb.padEnd(20, " ")), u16be(0), ausbg, ausbe);
  const recs = cat(rec(1, order, [0, 1], [0, 1]), rec(6, order, [0, 1], [0, 1]), rec(7, "", [0x56, fw[0]], [fw[1], fw[2]]));
  const data = cat([0xff, 0x09], u16be(8 + recs.length), u16be(0x0011), u16be(0), u16be(28), u16be(3), recs);
  const params = Buffer.from("000112081284010100000000", "hex");
  return tpkt(cat([0x02, 0xf0, 0x80], [0x32, 0x07, 0, 0, 0, 2], u16be(params.length), u16be(data.length), params, data));
}

export function bacnetIAm({ instance = 123, vendor = 7 } = {}) {
  const apdu = cat([0x10, 0x00, 0xc4], Buffer.from([(8 << 22 | instance) >>> 24 & 255, (8 << 22 | instance) >>> 16 & 255, (8 << 22 | instance) >>> 8 & 255, instance & 255]), [0x22, 0x05, 0xc4], [0x91, 0x03], [0x21, vendor]);
  const npdu = cat([0x01, 0x00], apdu);
  return cat([0x81, 0x0a], u16be(npdu.length + 4), npdu);
}

const respHeader = (result = 0) => cat(Buffer.alloc(8), u32le(1), u32le(result), [0x00], i32le(-1), [0x00, 0x00, 0x00]);
const uaMsg = (type, body) => cat(type, u32le(body.length + 8), body);
export const OPC_IDS = { channel: 0x11223344, token: 0x55667788 };
export const uaAck = () => uaMsg("ACKF", cat(u32le(0), u32le(16384), u32le(16384), u32le(16384), u32le(1)));
export function uaOpn({ result = 0 } = {}) {
  return uaMsg("OPNF", cat(u32le(OPC_IDS.channel), ustr("http://opcfoundation.org/UA/SecurityPolicy#None"), i32le(-1), i32le(-1), u32le(1), u32le(1),
    [0x01, 0x00, 449 & 255, 449 >> 8], respHeader(result), u32le(0), u32le(OPC_IDS.channel), u32le(OPC_IDS.token), Buffer.alloc(8), u32le(600000), i32le(-1)));
}
export function uaEndpoints({ name = "Example OPC UA Server", eps = [[1, "None"], [3, "Basic256Sha256"]] } = {}) {
  const ep = ([mode, pol]) => cat(ustr("opc.tcp://plc.example:4840"), ustr("urn:example:opcua:server"), ustr("urn:example:product"), [0x02], ustr(name), i32le(0), i32le(-1), i32le(-1), i32le(-1),
    ustr("CERTIFICATE-BYTES-NOT-KEPT"), i32le(mode), ustr("http://opcfoundation.org/UA/SecurityPolicy#" + pol), i32le(1), ustr("anon"), i32le(0), i32le(-1), i32le(-1), i32le(-1),
    ustr("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"), [mode === 1 ? 0 : 100]);
  return uaMsg("MSGF", cat(u32le(OPC_IDS.channel), u32le(OPC_IDS.token), u32le(2), u32le(2), [0x01, 0x00, 431 & 255, 431 >> 8], respHeader(0), i32le(eps.length), ...eps.map(ep)));
}

export function dicomAc({ uid = "1.2.826.0.1.3680043.2.1143.107.104.103.115", ver = "EXAMPLE_DCM_1" } = {}) {
  const item = (t, v) => cat([t, 0], u16be(v.length), v);
  const ml = Buffer.alloc(4); ml.writeUInt32BE(16384);
  const vars = cat(item(0x10, Buffer.from("1.2.840.10008.3.1.1.1")), item(0x21, cat([1, 0, 0, 0], item(0x40, Buffer.from("1.2.840.10008.1.2")))),
    item(0x50, cat(item(0x51, ml), item(0x52, Buffer.from(uid)), item(0x55, Buffer.from(ver)))));
  const body = cat([0, 1, 0, 0], Buffer.from("ANY-SCP".padEnd(16, " ")), Buffer.from("CYBERVIEW-SCAN".padEnd(16, " ")), Buffer.alloc(32), vars);
  const h = Buffer.alloc(6); h[0] = 0x02; h.writeUInt32BE(body.length, 2);
  return cat(h, body);
}
export const dicomRj = () => Buffer.from("03000000000400010107", "hex");
export const dicomReleaseRp = () => Buffer.from("06000000000400000000", "hex");

/**
 * A TCP stand-in on 127.0.0.1: answers the n-th complete request on a connection with replies[n] (none when missing),
 * and records every request it received. -> { port, got: [hex per request], bytes: total, connections, close() }
 */
export async function tcpFixture(frame, replies) {
  const st = { got: [], bytes: 0, connections: 0 };
  const srv = net.createServer((s) => {
    st.connections++;
    let buf = Buffer.alloc(0), n = 0;
    s.on("data", (d) => {
      st.bytes += d.length; buf = Buffer.concat([buf, d]);
      for (;;) {
        const len = frame(buf);
        if (!len || buf.length < len) break;
        st.got.push(buf.subarray(0, len).toString("hex")); buf = buf.subarray(len);
        const r = replies[n++];
        if (r) s.write(typeof r === "function" ? r() : r);
      }
    });
    s.on("error", () => {});
  });
  const port = await new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
  return { port, ...st, get got() { return st.got; }, get bytes() { return st.bytes; }, get connections() { return st.connections; },
    close: () => new Promise((r) => srv.close(() => r())) };
}

/** A UDP stand-in on 127.0.0.1: records every datagram and answers each with reply (if given). */
export async function udpFixture(reply) {
  const st = { got: [] };
  const sock = dgram.createSocket("udp4");
  sock.on("message", (m, rinfo) => { st.got.push(m.toString("hex")); if (reply) sock.send(reply, rinfo.port, rinfo.address); });
  const port = await new Promise((r) => sock.bind(0, "127.0.0.1", () => r(sock.address().port)));
  return { port, get got() { return st.got; }, close: () => new Promise((r) => sock.close(() => r())) };
}
