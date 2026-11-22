// Section 7 of scripts/security-check.mjs, the scanner's industrial identification reads (scanner/lib/ics.mjs, only with
// --ics): the rules that keep them one frozen, read-only identification exchange per protocol per host, never a write,
// control, session, login or DIMSE command, never broadcast, never to a public address, and off unless --ics is given.
// Pure: the caller hands in the source texts and the loaded module; returns problem strings.

const F = "scanner/lib/ics.mjs";
/** The protocols the reviewed Design allows, with the most messages each may send on its one connection. */
export const ALLOWED = Object.freeze({ modbus: 1, enip: 1, s7: 3, bacnet: 1, opcua: 3, dicom: 2 });
/** Socket options and literals that would broadcast or multicast. */
export const BROADCAST = /setBroadcast|addMembership|addSourceSpecificMembership|setMulticast|255\.255\.255\.255|broadcast\s*:\s*true/;

const hex = (s) => (typeof s === "string" && /^(?:[0-9a-f]{2})+$/.test(s) ? Buffer.from(s, "hex") : null);

/** Decode one protocol's frozen steps and say what is wrong with them (empty when every message is the allowed read). */
export function stepProblems(key, steps) {
  const P = [], b = (Array.isArray(steps) ? steps : []).map(hex);
  if (!b.length || b.some((x) => !x)) return [`${F}: ${key}: every step must be a lowercase hex literal`];
  if (b.length > (ALLOWED[key] || 0)) P.push(`${F}: ${key}: ${b.length} messages, more than the ${ALLOWED[key] || 0} its one identification exchange allows`);
  const bad = (i, what) => P.push(`${F}: ${key} step ${i + 1}: ${what}`);
  if (key === "modbus") b.forEach((m, i) => {
    if (m.length < 10 || m.readUInt16BE(2) !== 0 || m.readUInt16BE(4) !== m.length - 6) return bad(i, "not a well-formed MBAP frame");
    if (m[6] === 0) bad(i, "unit identifier 0 can be a broadcast through a serial gateway; use 0xFF");
    if (m[7] !== 0x2b || m[8] !== 0x0e) bad(i, `function 0x${m[7].toString(16)} is not Read Device Identification (0x2B/0x0E); write, diagnostic, coil and register functions are refused`);
    else if (m[9] !== 0x01) bad(i, "only the basic device identification category (code 0x01) is allowed");
  });
  if (key === "enip") b.forEach((m, i) => {
    if (m.length !== 24) return bad(i, "a ListIdentity request is a bare 24-byte encapsulation header");
    if (m.readUInt16LE(0) !== 0x63) bad(i, `command 0x${m.readUInt16LE(0).toString(16)} is not ListIdentity (0x63); RegisterSession, SendRRData and other commands are refused`);
    if (m.readUInt16LE(2) !== 0 || m.readUInt32LE(4) !== 0) bad(i, "ListIdentity carries no data and no session handle");
  });
  if (key === "s7") b.forEach((m, i) => {
    if (m.length < 7 || m[0] !== 0x03 || m.readUInt16BE(2) !== m.length) return bad(i, "not a well-formed TPKT frame");
    const cotp = m[5];
    if (i === 0) { if (cotp !== 0xe0) bad(i, "the first message must be the COTP connection request"); return; }
    if (cotp !== 0xf0) return bad(i, "S7 messages must ride a COTP data frame");
    const o = 5 + m[4];
    if (m[o] !== 0x32) return bad(i, "not an S7 PDU");
    if (i === 1) { if (m[o + 1] !== 0x01 || m[o + 10] !== 0xf0) bad(i, "the second message must be Setup Communication (job, function 0xF0); read/write variable, PLC control/stop and block up/download are refused"); return; }
    const p = o + 10, d = p + m.readUInt16BE(o + 6);
    if (m[o + 1] !== 0x07 || m[p + 4] !== 0x11 || m[p + 5] !== 0x44 || m[p + 6] !== 0x01) return bad(i, "the third message must be a userdata Read SZL request (method 0x11, CPU functions 0x44, subfunction 0x01)");
    if (m.readUInt16BE(d + 4) !== 0x0011) bad(i, `SZL-ID 0x${m.readUInt16BE(d + 4).toString(16)} is not 0x0011 module identification`);
  });
  if (key === "bacnet") b.forEach((m, i) => {
    if (m.length < 8 || m[0] !== 0x81) return bad(i, "not a BVLC frame");
    if (m[1] !== 0x0a) bad(i, `BVLC function 0x${m[1].toString(16)} is not Original-Unicast-NPDU (0x0A); broadcast and distribution functions are refused`);
    if (m[4] !== 0x01 || (m[5] & 0x20) || (m[5] & 0x80)) bad(i, "the NPDU must name no destination network (no DNET: never routed or re-broadcast) and carry an APDU");
    const a = 6 + ((m[5] & 0x08) ? 3 + m[8] : 0);
    if (m[a] !== 0x10 || m[a + 1] !== 0x08) bad(i, "the APDU must be the unconfirmed Who-Is (0x10 0x08); ReadProperty, WriteProperty and every confirmed service are refused");
  });
  if (key === "opcua") b.forEach((m, i) => {
    const t = m.toString("latin1", 0, 4), want = ["HELF", "OPNF", "MSGF"][i];
    if (t !== want) return bad(i, `message ${t} is not ${want}; the exchange is Hello, OpenSecureChannel, GetEndpoints and nothing else`);
    if (m.readUInt32LE(4) !== m.length) bad(i, "message size field does not match");
    if (i === 1) {
      const n = m.readInt32LE(12), pol = m.toString("latin1", 16, 16 + n);
      if (pol !== "http://opcfoundation.org/UA/SecurityPolicy#None") bad(i, "OpenSecureChannel must use SecurityPolicy None (no certificate is sent)");
      const nodeAt = 16 + n + 8 + 8;
      if (m[nodeAt] !== 0x01 || m.readUInt16LE(nodeAt + 2) !== 446) bad(i, "the OPN body must be OpenSecureChannelRequest (446)");
    }
    if (i === 2 && (m[24] !== 0x01 || m.readUInt16LE(26) !== 428)) bad(i, `service ${m[24] === 0x01 ? m.readUInt16LE(26) : "?"} is not GetEndpointsRequest (428); CreateSession, ActivateSession, Read, Browse, Write and Call are refused`);
  });
  if (key === "dicom") b.forEach((m, i) => {
    if (m.length < 10 || m.readUInt32BE(2) !== m.length - 6) return bad(i, "not a well-formed upper-layer PDU");
    if (m[0] === 0x04) return bad(i, "P-DATA-TF carries DIMSE commands (C-ECHO, C-FIND, C-STORE ...); none may be sent");
    if (i === 0) {
      if (m[0] !== 0x01) return bad(i, "the first message must be an A-ASSOCIATE-RQ");
      // every presentation context (item 0x20) may name only the Verification abstract syntax (sub-item 0x30)
      const as = [];
      for (let o = 74; o + 4 <= m.length;) {
        const t = m[o], l = m.readUInt16BE(o + 2);
        if (t === 0x20) for (let q = o + 8; q + 4 <= o + 4 + l;) { const st = m[q], sl = m.readUInt16BE(q + 2); if (st === 0x30) as.push(m.toString("latin1", q + 4, q + 4 + sl)); q += 4 + sl; }
        o += 4 + l;
      }
      if (!as.length || as.some((x) => x !== "1.2.840.10008.1.1")) bad(i, `abstract syntax ${as.join(", ") || "none"} is not only Verification (1.2.840.10008.1.1)`);
    } else if (m[0] !== 0x05 && m[0] !== 0x07) bad(i, `PDU type 0x${m[0].toString(16)}: after the association only A-RELEASE-RQ or A-ABORT may be sent`);
  });
  if (!ALLOWED[key]) P.push(`${F}: protocol "${key}" is not in the reviewed Design (DNP3 and FHIR are not built here)`);
  return P;
}

/**
 * { icsSrc, scanSrc, cliSrc, otherSrcs: [{ file, src }], mod } -> [problem strings]
 * mod: the imported scanner/lib/ics.mjs or null when it could not be loaded.
 */
export function icsProblems({ icsSrc = "", scanSrc = "", cliSrc = "", otherSrcs = [], mod = null } = {}) {
  const P = [];
  // (a) one send path each: exactly one TCP write, of bytes from requestBytes() (which reads the frozen table); the one UDP
  //     datagram goes through udp.mjs (one send) with the frozen BACnet entry, and no other file hands udpProbe a table
  const writes = (icsSrc.match(/\.write\s*\(/g) || []).length, sends = (icsSrc.match(/\.send\s*\(/g) || []).length;
  if (writes !== 1 || !/sock\.write\(bytes\);/.test(icsSrc)) P.push(`${F}: must write to a target in exactly one place, sock.write(bytes) (found ${writes} .write( call(s))`);
  if ((icsSrc.match(/const bytes = requestBytes\(key, step, out\.replies\);/g) || []).length !== 1) P.push(`${F}: every write must use bytes from requestBytes() (the frozen table)`);
  if (sends !== 0 || /dgram/.test(icsSrc)) P.push(`${F}: sends a datagram itself (found ${sends} .send( call(s)); its one datagram goes through scanner/lib/udp.mjs`);
  const udpCalls = icsSrc.match(/\budpProbe\(/g) || [];
  if (udpCalls.length !== 1 || !/await udpProbe\(ip, key, \{ signal, timeouts, port: out\.port, services: ICS_UDP \}\);/.test(icsSrc)) P.push(`${F}: must send its one datagram with a single udpProbe(ip, key, { ..., services: ICS_UDP }) call`);
  if (!/const ICS_UDP = Object\.freeze\(\{ bacnet: Object\.freeze\(\{ port: 47808, proto: "bacnet", build: \(\) => requestBytes\("bacnet", 0\),/.test(icsSrc)) P.push(`${F}: ICS_UDP must be one frozen BACnet entry whose bytes are requestBytes("bacnet", 0)`);
  for (const { file, src } of [...otherSrcs, { file: "scanner/lib/scan.mjs", src: scanSrc }]) if (/\budpProbe\([^)]*\bservices\s*:/.test(src)) P.push(`${file}: only scanner/lib/ics.mjs may hand udpProbe a service table`);
  if (!/const buf = Buffer\.from\(P\.steps\[i\], "hex"\);/.test(icsSrc)) P.push(`${F}: requestBytes() must start from the frozen hex literal of the step`);
  if (/\bsetInterval\b/.test(icsSrc)) P.push(`${F}: no repeating timer (one exchange per protocol per host)`);
  // (b) never broadcast
  if (BROADCAST.test(icsSrc)) P.push(`${F}: sets a broadcast/multicast option or address; industrial reads are unicast to one attested address`);
  // (c) frozen literal steps, and every step decodes to the allowed read-only message
  const lits = [...icsSrc.matchAll(/steps:\s*Object\.freeze\(\[([^\]]*)\]\)/g)].map((m) => m[1].split(",").map((x) => x.trim()).filter(Boolean));
  if ((icsSrc.match(/\bsteps\s*:/g) || []).length !== lits.length || !lits.length) P.push(`${F}: every "steps:" must be a frozen literal array of hex strings`);
  for (const arr of lits) for (const el of arr) if (!/^"(?:[0-9a-f]{2})+"$/.test(el)) P.push(`${F}: step ${el.slice(0, 40)} is not a plain hex string literal`);
  // (d) off unless --ics, and never to a public address
  if (!/export async function runIcs\(h, \{[^\n]*\}\) \{\s*if \(!ics \|\| ics\.enabled !== true\) return;/.test(icsSrc)) P.push(`${F}: runIcs must first return unless ics.enabled === true (--ics)`);
  if (!/if \(!ics \|\| ics\.enabled !== true \|\| !h\) return \{ plan, skipped \};/.test(icsSrc)) P.push(`${F}: icsPlan must plan nothing unless ics.enabled === true`);
  if (!/const gate = icsTargetOk\(h, P\.transport\);\s*if \(!gate\.ok\)/.test(icsSrc)) P.push(`${F}: icsPlan must gate every host with icsTargetOk (private ranges only)`);
  if (!/const icsOn = !!\(ics && ics\.enabled === true\);/.test(scanSrc) || !/if \(icsOn\) await runIcs\(/.test(scanSrc)) P.push("scanner/lib/scan.mjs: runIcs may run only when ics.enabled === true (--ics)");
  if (!/const ics = a\.ics \? \{ enabled: true \} : \{ enabled: false \};/.test(cliSrc) || !/"ics"/.test(cliSrc)) P.push("scanner/cyberview-scan.mjs: ics must be enabled only by the --ics flag");
  for (const { file, src } of otherSrcs) if (/\bicsExchange\b|\brunIcs\b/.test(src)) P.push(`${file}: only scanner/lib/scan.mjs may start industrial reads`);
  if (mod) {
    const T = mod.ICS_PROTOCOLS || {};
    if (!Object.isFrozen(T) || Object.values(T).some((p) => !Object.isFrozen(p) || !Object.isFrozen(p.steps))) P.push(`${F}: ICS_PROTOCOLS, its entries and their steps must be frozen`);
    const litSet = new Set(lits.flat().map((x) => x.replace(/"/g, "")));
    for (const [k, p] of Object.entries(T)) {
      for (const s of p.steps || []) if (!litSet.has(s)) P.push(`${F}: ${k}: a step is not a literal in the source`);
      P.push(...stepProblems(k, p.steps));
    }
    const priv = { address: "192.168.1.10", kind: "private", public: false };
    const openAll = { ...priv, up: true, ports: Object.values(T).map((p) => ({ port: p.port, state: "open" })) }, all = Object.values(T).map((p) => p.port);
    try {
      if (mod.icsPlan(openAll, all, { enabled: false }).plan.length || mod.icsPlan(openAll, all, undefined).plan.length || mod.icsPlan(openAll, all, { enabled: "yes" }).plan.length) P.push(`${F}: icsPlan plans reads without --ics`);
      const pub = { ...openAll, address: "8.8.8.8", kind: "public", public: true };
      if (mod.icsPlan(pub, all, { enabled: true }).plan.length || mod.icsTargetOk(pub, "tcp").ok || mod.icsTargetOk({ ...priv, public: true }, "tcp").ok || mod.icsTargetOk({ ...priv, address: "8.8.8.8" }, "tcp").ok) P.push(`${F}: a public address would be sent an industrial read`);
      if (mod.icsTargetOk({ ...priv, address: "192.168.1.255" }, "udp").ok) P.push(`${F}: a possible subnet broadcast address would be sent a datagram`);
      const plan = mod.icsPlan(openAll, [...all, ...all], { enabled: true }).plan;
      if (new Set(plan.map((x) => x.key)).size !== plan.length) P.push(`${F}: icsPlan must plan each protocol at most once per host`);
      if (mod.icsPlan({ ...priv, up: true, ports: [] }, all, { enabled: true }).plan.some((x) => x.key !== "bacnet")) P.push(`${F}: a TCP read must wait for the probe to find its port open`);
      if (mod.icsPlan(openAll, [], { enabled: true }).plan.length) P.push(`${F}: a read must only go to a port in the scan's port list`);
    } catch (e) { P.push(`${F}: the gate functions failed (${String(e && e.message).slice(0, 80)})`); }
  }
  return P;
}
