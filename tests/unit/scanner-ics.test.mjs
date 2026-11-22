// Industrial identification reads (scan-ics-identify), only with --ics: a frozen table of read-only requests, one exchange
// per protocol per host on its standard port, private ranges only, never broadcast, every connection through the Limiter.
// Loopback only: the stand-in servers (tests/fixtures/scanner/ics/servers.mjs) record every byte they receive.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as ICS from "../../scanner/lib/ics.mjs";
import { probeAll } from "../../scanner/lib/scan.mjs";
import { settings } from "../../scanner/lib/limits.mjs";
import { STATEMENT } from "../../scanner/lib/scope.mjs";
import { main } from "../../scanner/cyberview-scan.mjs";
import { icsProblems, stepProblems } from "../../scripts/lib/scanner-ics-check.mjs";
import * as FX from "../fixtures/scanner/ics/servers.mjs";

const { ICS_PROTOCOLS, ICS_KEYS, icsExchange, icsRecord, icsPlan, icsTargetOk, icsSends, requestBytes, runIcs } = ICS;
const ROOT = new URL("../../", import.meta.url).pathname;
const SNAP = new URL("../fixtures/scanner/snapshot", import.meta.url).pathname;
const FAST = { connectMs: 800, readMs: 800, maxBytes: 16384 };
const step = (k, i) => ICS_PROTOCOLS[k].steps[i];
const LOCAL = { address: "127.0.0.1", names: [], kind: "loopback", public: false };
const STD = Object.fromEntries(ICS_KEYS.map((k) => [k, ICS_PROTOCOLS[k].port]));

/** Start one stand-in per protocol and a wrapper that sends each standard-port exchange to its loopback port. */
async function fixtures(over = {}) {
  const fx = {
    modbus: await FX.tcpFixture(FX.FRAMES.modbus, over.modbus || [FX.modbusReply()]),
    enip: await FX.tcpFixture(FX.FRAMES.enip, over.enip || [FX.enipReply()]),
    s7: await FX.tcpFixture(FX.FRAMES.s7, over.s7 || [FX.s7Cc(), FX.s7SetupAck(), FX.s7Szl()]),
    opcua: await FX.tcpFixture(FX.FRAMES.opcua, over.opcua || [FX.uaAck(), FX.uaOpn(), FX.uaEndpoints()]),
    dicom: await FX.tcpFixture(FX.FRAMES.dicom, over.dicom || [FX.dicomAc(), FX.dicomReleaseRp()]),
    bacnet: await FX.udpFixture(over.bacnet === undefined ? FX.bacnetIAm() : over.bacnet),
  };
  const calls = [];
  const exchange = (ip, key, o = {}) => { calls.push([ip, key]); return icsExchange(ip, key, { ...o, timeouts: FAST, port: fx[key].port }); };
  return { fx, calls, exchange, received: () => ICS_KEYS.reduce((n, k) => n + fx[k].got.length, 0), close: () => Promise.all(Object.values(fx).map((f) => f.close())) };
}
/** A probe stand-in: every port in `open` answers (no bytes sent), everything else is closed. */
const probeOpen = (open) => async (ip, port) => ({ port, state: open.includes(port) ? "open" : "closed", banner: "", raw: null, http: null, tls: null, error: "" });
const ALL = ICS_KEYS.map((k) => STD[k]);

/* ---- the frozen table ---- */
test("the table: six reviewed protocols, frozen hex literals, every message the allowed read-only one; no DNP3, no FHIR", () => {
  assert.deepEqual([...ICS_KEYS].sort(), ["bacnet", "dicom", "enip", "modbus", "opcua", "s7"]);
  assert.deepEqual(STD, { modbus: 502, enip: 44818, s7: 102, bacnet: 47808, opcua: 4840, dicom: 104 });
  assert.ok(Object.isFrozen(ICS_PROTOCOLS) && ICS_KEYS.every((k) => Object.isFrozen(ICS_PROTOCOLS[k]) && Object.isFrozen(ICS_PROTOCOLS[k].steps)));
  assert.throws(() => { ICS_PROTOCOLS.modbus.steps.push("00"); });
  for (const k of ICS_KEYS) assert.deepEqual(stepProblems(k, ICS_PROTOCOLS[k].steps), [], k);
  assert.equal(step("modbus", 0), "000100000005ff2b0e0100");   // MBAP + 0x2B/0x0E basic, unit 0xFF
  assert.equal(step("enip", 0), "63".padEnd(48, "0"));        // ListIdentity, no data, no session
  assert.equal(step("bacnet", 0), "810a000801001008");          // Original-Unicast-NPDU, no DNET, Who-Is
  assert.equal(ICS_PROTOCOLS.dicom.steps[1], "05000000000400000000");
  assert.equal(Buffer.from(step("dicom", 0), "hex").includes(Buffer.from("1.2.840.10008.1.1\x40")), true);   // Verification only
  assert.equal(ICS_PROTOCOLS.dnp3, undefined); assert.equal(ICS_PROTOCOLS.fhir, undefined);
  assert.equal(requestBytes("modbus", 1), null); assert.equal(requestBytes("nope", 0), null);
  assert.equal(requestBytes("opcua", 2, []), null);   // GetEndpoints is never sent without a valid OpenSecureChannel reply
});

test("SENDS wording: off by default and worded 'only with --ics'; per-protocol lines when enabled", () => {
  const off = icsSends(false), on = icsSends(true);
  assert.deepEqual(Object.keys(off), ["ics"]); assert.match(off.ics, /^only with --ics \(off by default\)/); assert.match(off.ics, /not enabled for this run/);
  assert.deepEqual(Object.keys(on).sort(), ["ics", "ics-bacnet", "ics-dicom", "ics-enip", "ics-modbus", "ics-opcua", "ics-s7"]);
  for (const [k, v] of Object.entries(on)) if (k !== "ics") assert.match(v, /^only with --ics: /);
  assert.match(on["ics-bacnet"], /never broadcast/); assert.match(on["ics-dicom"], /not even C-ECHO/);
});

/* ---- exact bytes on the wire, per protocol ---- */
test("Modbus: exactly one Read Device Identification request; VendorName, ProductCode and the stated revision read", async () => {
  const f = await FX.tcpFixture(FX.FRAMES.modbus, [FX.modbusReply()]);
  try {
    const r = await icsExchange("127.0.0.1", "modbus", { port: f.port, timeouts: FAST });
    assert.deepEqual(f.got, [step("modbus", 0)]); assert.equal(f.connections, 1); assert.equal(r.sent, 1);
    const rec = icsRecord("modbus", r);
    assert.equal(rec.outcome, "identified"); assert.equal(rec.inventory_only, true);
    assert.deepEqual([rec.identity.vendor, rec.identity.product_code, rec.identity.revision], ["ExampleVendor", "EX-100", "V2.3"]);
    assert.equal(rec.version, "V2.3"); assert.equal(rec.version_stated, true);
  } finally { await f.close(); }
  // an exception reply and a "more follows" reply: recorded, never followed by a second request
  const g = await FX.tcpFixture(FX.FRAMES.modbus, [FX.modbusException()]);
  try { const r = await icsExchange("127.0.0.1", "modbus", { port: g.port, timeouts: FAST }); assert.equal(g.got.length, 1); assert.equal(icsRecord("modbus", r).outcome, "answered without identity"); } finally { await g.close(); }
  const m = await FX.tcpFixture(FX.FRAMES.modbus, [FX.modbusReply(undefined, { more: 0xff })]);
  try { const r = await icsExchange("127.0.0.1", "modbus", { port: m.port, timeouts: FAST }); assert.equal(m.got.length, 1); assert.equal(icsRecord("modbus", r).identity.more_follows, true); } finally { await m.close(); }
});

test("EtherNet/IP: one ListIdentity, no session; vendor 1 named Rockwell, product name and revision read", async () => {
  const f = await FX.tcpFixture(FX.FRAMES.enip, [FX.enipReply()]);
  try {
    const rec = icsRecord("enip", await icsExchange("127.0.0.1", "enip", { port: f.port, timeouts: FAST }));
    assert.deepEqual(f.got, [step("enip", 0)]);
    assert.equal(rec.identity.vendor_id, 1); assert.match(rec.identity.vendor, /Rockwell/); assert.equal(rec.identity.product_name, "1756-L71/B LOGIX5571");
    assert.equal(rec.identity.revision, "20.11"); assert.equal(rec.version, "20.11"); assert.equal(rec.identity.serial, "00c0ffee");
    assert.deepEqual(rec.catalog, ["ethernet-ip-list-identity", "rockwell-factorytalk-or-controllogix"]);
  } finally { await f.close(); }
  const g = await FX.tcpFixture(FX.FRAMES.enip, [FX.enipReply({ vendor: 999, name: "Example Adapter" })]);
  try { const rec = icsRecord("enip", await icsExchange("127.0.0.1", "enip", { port: g.port, timeouts: FAST })); assert.equal(rec.identity.vendor, ""); assert.equal(rec.identity.vendor_id, 999); } finally { await g.close(); }
});

test("S7: the three-message identification exchange in order, then nothing; order number and firmware from SZL 0x0011", async () => {
  const f = await FX.tcpFixture(FX.FRAMES.s7, [FX.s7Cc(), FX.s7SetupAck(), FX.s7Szl()]);
  try {
    const r = await icsExchange("127.0.0.1", "s7", { port: f.port, timeouts: FAST }), rec = icsRecord("s7", r);
    assert.deepEqual(f.got, ICS_PROTOCOLS.s7.steps); assert.equal(f.connections, 1); assert.equal(r.sent, 3);
    assert.equal(rec.identity.order_number, "6ES7 214-1AG40-0XB0"); assert.equal(rec.identity.firmware, "4.2.1"); assert.equal(rec.version, "4.2.1");
  } finally { await f.close(); }
  // no Connection Confirm: the S7 messages are never sent
  const g = await FX.tcpFixture(FX.FRAMES.s7, [Buffer.from("0300000b06800000000100", "hex")]);
  try { const r = await icsExchange("127.0.0.1", "s7", { port: g.port, timeouts: FAST }); assert.deepEqual(g.got, [step("s7", 0)]); assert.equal(r.sent, 1); } finally { await g.close(); }
  // Setup Communication refused (error class set): the SZL read is never sent
  const bad = Buffer.from(FX.s7SetupAck()); bad[17] = 0x85;
  const h = await FX.tcpFixture(FX.FRAMES.s7, [FX.s7Cc(), bad]);
  try { await icsExchange("127.0.0.1", "s7", { port: h.port, timeouts: FAST }); assert.deepEqual(h.got, ICS_PROTOCOLS.s7.steps.slice(0, 2)); } finally { await h.close(); }
});

test("BACnet: one unicast Who-Is datagram to the host's own address; device instance and vendor id read from the I-Am", async () => {
  const f = await FX.udpFixture(FX.bacnetIAm({ instance: 123, vendor: 7 }));
  try {
    const r = await icsExchange("127.0.0.1", "bacnet", { port: f.port, timeouts: FAST }), rec = icsRecord("bacnet", r);
    assert.deepEqual(f.got, [step("bacnet", 0)]); assert.equal(r.sent, 1);
    assert.deepEqual(rec.identity, { device_instance: 123, max_apdu: 1476, segmentation: 3, vendor_id: 7 }); assert.equal(rec.version_stated, false);
  } finally { await f.close(); }
  // a silent port: still exactly one datagram, no retransmit
  const g = await FX.udpFixture(null);
  try { const r = await icsExchange("127.0.0.1", "bacnet", { port: g.port, timeouts: FAST }); assert.equal(g.got.length, 1); assert.equal(r.error, "no reply"); } finally { await g.close(); }
});

test("OPC UA: Hello, OpenSecureChannel (None), GetEndpoints carrying the server's channel and token ids; no session", async () => {
  const f = await FX.tcpFixture(FX.FRAMES.opcua, [FX.uaAck(), FX.uaOpn(), FX.uaEndpoints()]);
  try {
    const r = await icsExchange("127.0.0.1", "opcua", { port: f.port, timeouts: FAST }), rec = icsRecord("opcua", r);
    const third = Buffer.from(step("opcua", 2), "hex"); third.writeUInt32LE(FX.OPC_IDS.channel, 8); third.writeUInt32LE(FX.OPC_IDS.token, 12);
    assert.deepEqual(f.got, [step("opcua", 0), step("opcua", 1), third.toString("hex")]);
    assert.equal(rec.identity.application_name, "Example OPC UA Server"); assert.equal(rec.identity.product_uri, "urn:example:product");
    assert.deepEqual(rec.identity.endpoints, [{ mode: "None", policy: "None" }, { mode: "SignAndEncrypt", policy: "Basic256Sha256" }]);
    assert.equal(JSON.stringify(rec).includes("CERTIFICATE-BYTES"), false);   // the server certificate is skipped, never kept
  } finally { await f.close(); }
  // OpenSecureChannel refused: GetEndpoints is never sent
  const g = await FX.tcpFixture(FX.FRAMES.opcua, [FX.uaAck(), FX.uaOpn({ result: 0x80010000 })]);
  try { const r = await icsExchange("127.0.0.1", "opcua", { port: g.port, timeouts: FAST }); assert.equal(g.got.length, 2); assert.equal(r.sent, 2); } finally { await g.close(); }
});

test("DICOM: one A-ASSOCIATE-RQ (Verification only), then A-RELEASE-RQ; no DIMSE; a rejection is not followed by anything", async () => {
  const f = await FX.tcpFixture(FX.FRAMES.dicom, [FX.dicomAc(), FX.dicomReleaseRp()]);
  try {
    const r = await icsExchange("127.0.0.1", "dicom", { port: f.port, timeouts: FAST }), rec = icsRecord("dicom", r);
    assert.deepEqual(f.got, ICS_PROTOCOLS.dicom.steps); assert.ok(f.got.every((h) => !h.startsWith("04")));   // never P-DATA-TF
    assert.equal(rec.identity.implementation_class_uid, "1.2.826.0.1.3680043.2.1143.107.104.103.115"); assert.equal(rec.identity.implementation_version_name, "EXAMPLE_DCM_1");
    assert.equal(rec.identity.verification_accepted, true); assert.equal(rec.released, true); assert.equal(rec.version_stated, false);
  } finally { await f.close(); }
  const g = await FX.tcpFixture(FX.FRAMES.dicom, [FX.dicomRj()]);
  try {
    const rec = icsRecord("dicom", await icsExchange("127.0.0.1", "dicom", { port: g.port, timeouts: FAST }));
    assert.deepEqual(g.got, [step("dicom", 0)]); assert.equal(rec.outcome, "answered without identity"); assert.equal(rec.identity.reason, 7);
  } finally { await g.close(); }
});

test("a reply over the size cap ends the exchange; a closed port is recorded, not retried", async () => {
  const big = Buffer.alloc(20000, 0x41); big.writeUInt16BE(1, 0); big.writeUInt16BE(0, 2); big.writeUInt16BE(65000, 4);
  const f = await FX.tcpFixture(FX.FRAMES.modbus, [big]);
  try { const r = await icsExchange("127.0.0.1", "modbus", { port: f.port, timeouts: FAST }); assert.equal(r.error, "reply over the size cap"); assert.equal(r.sent, 1); } finally { await f.close(); }
  const tmp = await FX.tcpFixture(FX.FRAMES.modbus, []), port = tmp.port; await tmp.close();
  const r = await icsExchange("127.0.0.1", "modbus", { port, timeouts: FAST });
  assert.equal(r.state, "closed"); assert.equal(icsRecord("modbus", r).outcome, "closed");
});

/* ---- gates: opt-in, private only, standard port in the list and open, once per protocol ---- */
test("icsPlan: nothing without --ics; never a public address; only listed standard ports, TCP only when open; once each", () => {
  const h = { ...LOCAL, up: true, ports: ALL.map((port) => ({ port, state: "open" })) };
  for (const off of [undefined, null, {}, { enabled: false }, { enabled: "true" }, { enabled: 1 }]) assert.deepEqual(icsPlan(h, ALL, off), { plan: [], skipped: [] });
  assert.deepEqual(icsPlan(h, [...ALL, ...ALL], { enabled: true }).plan.map((x) => x.key).sort(), [...ICS_KEYS].sort());
  assert.deepEqual(icsPlan(h, [502, 80], { enabled: true }).plan, [{ key: "modbus", port: 502 }]);
  assert.deepEqual(icsPlan(h, [5020], { enabled: true }), { plan: [], skipped: [] });   // a non-standard port is never used
  const closed = icsPlan({ ...h, ports: [] }, [502, 47808], { enabled: true });
  assert.deepEqual(closed.plan, [{ key: "bacnet", port: 47808 }]); assert.deepEqual(closed.skipped, [{ key: "modbus", port: 502, why: "not-sent: port not open" }]);
  assert.deepEqual(icsPlan({ ...h, ports: [], up: false }, [47808], { enabled: true }).skipped[0].why, "not-sent: host did not answer");
  const pub = icsPlan({ ...h, address: "8.8.8.8", kind: "public", public: true }, ALL, { enabled: true });
  assert.equal(pub.plan.length, 0); assert.ok(pub.skipped.every((s) => /public address/.test(s.why)));
  for (const bad of [{ ...LOCAL, public: true }, { ...LOCAL, address: "203.0.113.5" }, { ...LOCAL, kind: "public" }, null]) assert.equal(icsTargetOk(bad, "tcp").ok, false);
  for (const ok of ["10.0.0.5", "172.16.4.4", "192.168.1.20", "127.0.0.1", "169.254.1.1"]) assert.equal(icsTargetOk({ address: ok, kind: ok.startsWith("127") ? "loopback" : ok.startsWith("169") ? "link-local" : "private", public: false }, "udp").ok, true, ok);
  for (const b of ["192.168.1.255", "10.0.0.0"]) { assert.equal(icsTargetOk({ address: b, kind: "private", public: false }, "udp").ok, false); assert.equal(icsTargetOk({ address: b, kind: "private", public: false }, "tcp").ok, true); }
});

test("without --ics nothing is sent: the stand-ins receive zero bytes and the exchange is never called", async () => {
  const s = await fixtures();
  try {
    const st = settings({}).settings;
    for (const ics of [undefined, { enabled: false }]) {
      const p = await probeAll([LOCAL], { ports: ALL, settings: st, assumeUp: true, probe: probeOpen(ALL), ics, icsProbe: s.exchange });
      assert.equal(p.hosts[0].ics, undefined); assert.deepEqual(p.ics, { enabled: false });
    }
    assert.deepEqual(s.calls, []); assert.equal(s.received(), 0);
    for (const k of ICS_KEYS) if (k !== "bacnet") assert.equal(s.fx[k].connections, 0, k);
  } finally { await s.close(); }
});

test("with --ics: one exchange per protocol on loopback through the Limiter, the exact frozen bytes, inventory-only records", async () => {
  const s = await fixtures();
  try {
    const p = await probeAll([LOCAL], { ports: ALL, settings: settings({}).settings, assumeUp: true, probe: probeOpen(ALL.filter((x) => x !== 47808)), ics: { enabled: true }, icsProbe: s.exchange });
    const h = p.hosts[0];
    assert.deepEqual(s.calls.map((c) => c[1]).sort(), [...ICS_KEYS].sort()); assert.ok(s.calls.every((c) => c[0] === "127.0.0.1"));
    assert.deepEqual(h.ics.map((x) => x.outcome), ICS_KEYS.map(() => "identified"));
    assert.ok(h.ics.every((x) => x.inventory_only === true));
    assert.equal(h.services.length, 0);   // nothing is handed to the matcher
    for (const k of ["modbus", "enip", "s7", "dicom"]) assert.deepEqual(s.fx[k].got, [...ICS_PROTOCOLS[k].steps], k);
    assert.deepEqual(s.fx.bacnet.got, [step("bacnet", 0)]); assert.equal(s.fx.opcua.got.length, 3);
    assert.equal(p.stats.connections, ALL.length - 0 + ICS_KEYS.length);   // 6 probe connections + 6 industrial exchanges, all counted
    assert.deepEqual(p.ics, { enabled: true });
  } finally { await s.close(); }
});

test("with --ics: a public host, an unlisted port and a spent budget send nothing", async () => {
  const s = await fixtures();
  try {
    const pub = { address: "203.0.113.9", names: [], kind: "public", public: true };
    const a = await probeAll([pub], { ports: ALL, settings: settings({}).settings, assumeUp: true, probe: probeOpen(ALL), ics: { enabled: true }, icsProbe: s.exchange });
    assert.deepEqual(s.calls, []); assert.ok(a.hosts[0].ics.every((x) => /public address/.test(x.outcome) && x.messages_sent === 0));
    const b = await probeAll([LOCAL], { ports: [80, 443], settings: settings({}).settings, assumeUp: true, probe: probeOpen([80, 443]), ics: { enabled: true }, icsProbe: s.exchange });
    assert.deepEqual(s.calls, []); assert.equal(b.hosts[0].ics, undefined);
    // the host budget is spent by the probes: the industrial exchanges are recorded as not sent
    const c = await probeAll([LOCAL], { ports: [502, 102], settings: settings({ hostBudget: 2 }).settings, assumeUp: true, probe: probeOpen([502, 102]), ics: { enabled: true }, icsProbe: s.exchange });
    assert.deepEqual(s.calls, []); assert.deepEqual(c.hosts[0].ics.map((x) => x.outcome), ["not-sent: budget or time", "not-sent: budget or time"]);
    assert.equal(s.received(), 0);
  } finally { await s.close(); }
});

test("an aborted run (Ctrl-C) starts no industrial exchange", async () => {
  const s = await fixtures(), ac = new AbortController(); ac.abort("interrupted");
  try {
    const p = await probeAll([LOCAL], { ports: ALL, settings: settings({}).settings, assumeUp: true, probe: probeOpen(ALL), signal: ac.signal, ics: { enabled: true }, icsProbe: s.exchange });
    assert.deepEqual(s.calls, []); assert.equal(p.interrupted, true);
  } finally { await s.close(); }
  const calls = [];
  await runIcs({ ...LOCAL, up: true, ports: [{ port: 502, state: "open" }] }, { ports: [502], ics: { enabled: false }, acquire: async () => () => {}, exchange: async (...a) => { calls.push(a); return {}; } });
  assert.deepEqual(calls, []);
});

/* ---- CLI, header and report ---- */
test("CLI: --ics is off by default; the header declares it; report.json carries run.ics, the sends and each host's records", async () => {
  const d = mkdtempSync(join(tmpdir(), "cvics-")), p = join(d, "scope.json");
  writeFileSync(p, JSON.stringify({ cyberview_scope: 1, owner: "Example lab", contact: "lab@example.org", attestation: { statement: STATEMENT, agreed: true, name: "Test Operator", date: "2026-11-20", expires: "", authorization_ref: "test" }, targets: ["127.0.0.1"], exclude: [] }));
  const s = await fixtures();
  const io = (lines) => ({ out: (x) => lines.push(x), err: (x) => lines.push(x), sleep: async () => {}, publicWaitMs: 0, resolve: async () => { throw new Error("no DNS"); }, probe: probeOpen([502, 102]), icsProbe: s.exchange });
  try {
    let lines = [];
    assert.equal(await main(["check", "--scope", p], io(lines)), 0);
    assert.match(lines.join("\n"), /ics +only with --ics \(off by default\)/); assert.doesNotMatch(lines.join("\n"), /ics-modbus/);
    lines = [];
    await main(["scan", "--scope", p, "--data", SNAP, "--ports", "502,102", "--assume-up", "--out", join(d, "off")], io(lines));
    assert.deepEqual(s.calls, []); assert.equal(s.received(), 0);
    let rep = JSON.parse(readFileSync(join(d, "off", "report.json"), "utf8"));
    assert.deepEqual(rep.run.ics, { enabled: false }); assert.equal(rep.hosts[0].ics, undefined); assert.match(rep.run.network.sends.ics, /not enabled for this run/);
    lines = [];
    await main(["scan", "--scope", p, "--data", SNAP, "--ports", "502,102", "--assume-up", "--ics", "--out", join(d, "on")], io(lines));
    const text = lines.join("\n");
    assert.match(text, /ics-modbus +only with --ics: TCP 502/); assert.match(text, /Industrial reads \(--ics\): standard port\(s\) 102, 502 in the port list/);
    assert.deepEqual(s.calls.map((c) => c[1]).sort(), ["modbus", "s7"]);
    rep = JSON.parse(readFileSync(join(d, "on", "report.json"), "utf8"));
    assert.deepEqual(rep.run.ics, { enabled: true }); assert.ok(rep.run.network.sends["ics-s7"]);
    assert.deepEqual(rep.hosts[0].ics.map((x) => [x.protocol, x.outcome, x.version]), [["modbus", "identified", "V2.3"], ["s7", "identified", "4.2.1"]]);
    assert.equal(rep.findings.length, 0);
    // --ics with no standard port in the list says nothing industrial will be sent
    lines = [];
    await main(["check", "--scope", p, "--ics", "--ports", "80"], io(lines));
    assert.match(lines.join("\n"), /nothing industrial will be sent/);
  } finally { await s.close(); }
});

/* ---- section 7 of the security check ---- */
test("security check: passes on the tree and fires on writes, broadcast, public targets, missing opt-in and extra sends", async () => {
  const src = (f) => readFileSync(join(ROOT, f), "utf8");
  const base = { icsSrc: src("scanner/lib/ics.mjs"), scanSrc: src("scanner/lib/scan.mjs"), cliSrc: src("scanner/cyberview-scan.mjs"), mod: ICS };
  assert.deepEqual(icsProblems(base), []);
  const bad = (patch, re) => { const p = icsProblems({ ...base, ...patch }); assert.ok(p.some((x) => re.test(x)), p.join("\n") || "no problem reported"); };
  const withStep = (key, steps) => ({ ...ICS, ICS_PROTOCOLS: Object.freeze({ ...ICS_PROTOCOLS, [key]: Object.freeze({ ...ICS_PROTOCOLS[key], steps: Object.freeze(steps) }) }) });
  // write / control function codes, per protocol
  bad({ mod: withStep("modbus", ["000100000006ff0600010001"]) }, /function 0x6 is not Read Device Identification/);   // Write Single Register
  bad({ mod: withStep("modbus", ["00010000000bff10000000010200ff"]) }, /not a well-formed MBAP|is not Read Device Identification/);
  bad({ mod: withStep("modbus", ["0001000000050008000000"]) }, /unit identifier 0/);
  bad({ mod: withStep("enip", ["650004000000000000000000000000000000000000000000"]) }, /not ListIdentity|no data/);   // RegisterSession
  bad({ mod: withStep("s7", [step("s7", 0), step("s7", 1).replace(/f0000001000101e0$/, "29000000000000fd"), step("s7", 2)]) }, /Setup Communication/);   // PLC stop
  bad({ mod: withStep("s7", [step("s7", 0), step("s7", 1), step("s7", 2).replace(/00110000$/, "001c0000")]) }, /SZL-ID 0x1c is not 0x0011/);
  bad({ mod: withStep("s7", [...ICS_PROTOCOLS.s7.steps, step("s7", 2)]) }, /more than the 3/);
  bad({ mod: withStep("opcua", [step("opcua", 0), step("opcua", 1), step("opcua", 2).replace("0100ac01", "0100cd01")]) }, /not GetEndpointsRequest \(428\)/);   // CreateSession 461
  bad({ mod: withStep("dicom", [step("dicom", 0), "04000000000a00000006010300000000"]) }, /P-DATA-TF carries DIMSE/);
  bad({ mod: withStep("dicom", [step("dicom", 0).replace("312e322e3834302e31303030382e312e3140", "312e322e3834302e31303030382e312e3240")]) }, /not only Verification/);
  bad({ mod: withStep("bacnet", ["810a000c0104020c0c02"]) }, /Who-Is/);   // confirmed ReadProperty
  bad({ mod: withStep("dnp3", ["056405c901000000"]) }, /not in the reviewed Design/);
  // broadcast
  bad({ mod: withStep("bacnet", ["810b000801001008"]) }, /not Original-Unicast-NPDU/);
  bad({ mod: withStep("bacnet", ["810a000c0120ffff00ff1008"]) }, /no DNET/);
  bad({ icsSrc: base.icsSrc.replace("const sock = net.connect(", "const s2 = { setBroadcast() {} }; s2.setBroadcast(true); const sock = net.connect(") }, /broadcast\/multicast/);
  bad({ mod: { ...ICS, icsTargetOk: (h, t) => ({ ok: t !== "x", why: "" }) } }, /subnet broadcast/);
  // public targets
  bad({ mod: { ...ICS, icsPlan: (h, ports, ics) => ICS.icsPlan({ ...h, public: false, kind: "private", address: "10.0.0.1" }, ports, ics), icsTargetOk: () => ({ ok: true }) } }, /public address would be sent/);
  bad({ icsSrc: base.icsSrc.replace("const gate = icsTargetOk(h, P.transport);\n    if (!gate.ok)", "const gate = { ok: true };\n    if (!gate.ok)") }, /gate every host with icsTargetOk/);
  // missing opt-in
  bad({ icsSrc: base.icsSrc.replace("  if (!ics || ics.enabled !== true) return;\n  const { plan, skipped }", "  const { plan, skipped }") }, /runIcs must first return/);
  bad({ icsSrc: base.icsSrc.replace("if (!ics || ics.enabled !== true || !h) return { plan, skipped };", "if (!h) return { plan, skipped };") }, /icsPlan must plan nothing/);
  bad({ mod: { ...ICS, icsPlan: (h, ports) => ICS.icsPlan(h, ports, { enabled: true }) } }, /plans reads without --ics/);
  bad({ scanSrc: base.scanSrc.replace("const icsOn = !!(ics && ics.enabled === true);", "const icsOn = true;") }, /scan\.mjs: runIcs may run only/);
  bad({ cliSrc: base.cliSrc.replace("const ics = a.ics ? { enabled: true } : { enabled: false };", "const ics = { enabled: true };") }, /only by the --ics flag/);
  bad({ otherSrcs: [{ file: "scanner/lib/other.mjs", src: "icsExchange(ip, 'modbus')" }] }, /only scanner\/lib\/scan\.mjs may start/);
  // extra or computed sends
  bad({ icsSrc: base.icsSrc.replace("sock.write(bytes);", "sock.write(bytes); sock.write(Buffer.from([0x05]));") }, /exactly one place/);
  bad({ icsSrc: base.icsSrc + "\nx.send(y);" }, /sends a datagram itself/);
  bad({ icsSrc: base.icsSrc.replace('import net from "node:net";', 'import net from "node:net";\nimport dgram from "node:dgram";') }, /sends a datagram itself/);
  bad({ icsSrc: base.icsSrc.replace('build: () => requestBytes("bacnet", 0)', 'build: () => Buffer.from([0x81, 0x0b])') }, /ICS_UDP must be one frozen BACnet entry/);
  bad({ otherSrcs: [{ file: "scanner/lib/other.mjs", src: "udpProbe(ip, 'x', { services: mine })" }] }, /only scanner\/lib\/ics\.mjs may hand udpProbe/);
  bad({ icsSrc: base.icsSrc.replace('steps: Object.freeze(["000100000005ff2b0e0100"])', "steps: Object.freeze([makeFrame(unit)])") }, /not a plain hex string literal/);
  bad({ icsSrc: base.icsSrc.replace("const buf = Buffer.from(P.steps[i], \"hex\");", "const buf = Buffer.from(build(key, i));") }, /frozen hex literal/);
  bad({ mod: { ...ICS, ICS_PROTOCOLS: { ...ICS_PROTOCOLS } } }, /must be frozen/);
  bad({ mod: withStep("modbus", ["000100000005ff2b0e0200"]) }, /basic device identification|a step is not a literal/);
});
