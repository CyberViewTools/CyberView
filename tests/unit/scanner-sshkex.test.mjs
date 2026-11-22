// scan-ssh-kex: the server's SSH_MSG_KEXINIT read on the same connection after the scanner's identification line.
// Loopback stand-in SSH servers only (127.0.0.1, ephemeral ports); each records every byte the scanner sends it.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { kexinitFrom, parsePacket, parsePayload, sshKexInfo, sshKexObservations, weakOf, WEAK, PQC_KEX, MAX_PACKET } from "../../scanner/lib/ssh-kex.mjs";
import { probePort, SSH_IDENT } from "../../scanner/lib/probe.mjs";
import { probeAll } from "../../scanner/lib/scan.mjs";
import { settings } from "../../scanner/lib/limits.mjs";

const BANNER = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5";
const FAST = { connectMs: 1000, readMs: 400, maxBytes: 16384 };

/** A canned KEXINIT binary packet (unencrypted, no MAC) with these name-lists. */
function kexinit({ kex = [], hostkey = [], cipher = [], mac = [], comp = ["none"] } = {}) {
  const lists = [kex, hostkey, cipher, cipher, mac, mac, comp, comp, [], []];
  const parts = [Buffer.from([20]), Buffer.alloc(16, 7)];
  for (const l of lists) { const s = Buffer.from(l.join(","), "latin1"), n = Buffer.alloc(4); n.writeUInt32BE(s.length); parts.push(n, s); }
  parts.push(Buffer.from([0, 0, 0, 0, 0]));
  const payload = Buffer.concat(parts);
  let pad = 8 - ((payload.length + 5) % 8); if (pad < 4) pad += 8;
  const head = Buffer.alloc(5); head.writeUInt32BE(1 + payload.length + pad); head[4] = pad;
  return Buffer.concat([head, payload, Buffer.alloc(pad)]);
}
const WEAK_SET = { kex: ["curve25519-sha256", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "ext-info-s"], hostkey: ["ssh-rsa", "ssh-dss", "ssh-ed25519"],
  cipher: ["aes128-ctr", "aes128-cbc", "3des-cbc", "arcfour256"], mac: ["hmac-sha2-256", "hmac-md5", "hmac-sha1-96"] };
const PQ_SET = { kex: ["mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "kex-strict-s-v00@openssh.com"], hostkey: ["ssh-ed25519", "rsa-sha2-512"],
  cipher: ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"], mac: ["hmac-sha2-256-etm@openssh.com"] };

/** mode: "after-ident" (KEXINIT once the client's line arrives, like OpenSSH), "with-banner" (sent at once), "banner-only" (never). */
async function sshServer(packet, mode = "after-ident") {
  const got = [], socks = new Set(); let conns = 0;
  const srv = net.createServer((s) => {
    conns++; socks.add(s); s.on("error", () => {});
    s.write(BANNER + "\r\n");
    if (mode === "with-banner") s.write(packet);
    let sent = false;
    s.on("data", (d) => { got.push(Buffer.from(d)); if (mode === "after-ident" && !sent && Buffer.concat(got).includes("\r\n")) { sent = true; s.write(packet); } });
    // the server never closes on its own: the scanner must stop by itself
  });
  const port = await new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
  return { port, conns: () => conns, got: () => Buffer.concat(got).toString("latin1"), close: () => new Promise((r) => { for (const s of socks) s.destroy(); srv.close(() => r()); }) };
}
const waitFor = async (f) => { for (let i = 0; i < 100 && !f(); i++) await new Promise((r) => setTimeout(r, 10)); };

test("ssh-kex parser: canned KEXINIT -> the ten name-lists; partial and malformed input fail cleanly", () => {
  const pkt = kexinit(WEAK_SET), buf = Buffer.concat([Buffer.from(BANNER + "\r\n"), pkt]);
  const k = kexinitFrom(buf).kex;
  assert.deepEqual(k.kex, WEAK_SET.kex); assert.deepEqual(k.hostkey, WEAK_SET.hostkey); assert.deepEqual(k.cipher_s2c, WEAK_SET.cipher); assert.deepEqual(k.mac_c2s, WEAK_SET.mac);
  assert.deepEqual(k.compression_c2s, ["none"]); assert.deepEqual(k.lang_s2c, []); assert.equal(k.first_kex_follows, false);
  // LF-only identification line also works
  assert.deepEqual(kexinitFrom(Buffer.concat([Buffer.from(BANNER + "\n"), pkt])).kex.kex, WEAK_SET.kex);
  // more bytes needed: nothing after the line, a line without its end, a packet cut short
  assert.equal(kexinitFrom(Buffer.from(BANNER + "\r\n")).need, true);
  assert.equal(kexinitFrom(Buffer.from(BANNER)).need, true);
  assert.equal(kexinitFrom(buf.subarray(0, buf.length - 10)).need, true);
  // not SSH, not a KEXINIT, an oversize length, a bad padding, non-ASCII names, an overlong list: errors, never throws
  assert.ok(kexinitFrom(Buffer.from("220 ftp ready\r\n")).error);
  assert.ok(kexinitFrom(Buffer.from("SSH-" + "x".repeat(300))).error);
  const other = Buffer.from(pkt); other[5] = 21; assert.match(parsePacket(other).error, /not KEXINIT/);
  const big = Buffer.from(pkt); big.writeUInt32BE(MAX_PACKET + 1); assert.match(parsePacket(big).error, /packet length/);
  const badPad = Buffer.from(pkt); badPad[4] = 2; assert.match(parsePacket(badPad).error, /padding/);
  const bin = kexinit({ kex: ["curve25519-sha256"] }); bin[5 + 17 + 4] = 0x01; assert.match(parsePacket(bin).error, /printable/);
  const payload = Buffer.concat([Buffer.from([20]), Buffer.alloc(16), Buffer.from([0, 0, 0x20, 0])]); assert.match(parsePayload(payload).error, /too long|cut short/);
  assert.ok(parsePayload(Buffer.from([20, 1, 2])).error); assert.ok(parsePayload(null).error);
  for (const junk of [Buffer.alloc(0), Buffer.from("SSH-2.0-x\r\n\x00\x00"), Buffer.from("SSH-2.0-x\r\n\xff\xff\xff\xff\x05\x14")]) assert.doesNotThrow(() => kexinitFrom(junk));
});

test("ssh-kex observations: the frozen weak set is flagged per category, PQC names are information only", () => {
  const k = kexinitFrom(Buffer.concat([Buffer.from(BANNER + "\r\n"), kexinit(WEAK_SET)])).kex;
  const obs = sshKexObservations(22, k), by = Object.fromEntries(obs.map((o) => [o.kind, o]));
  assert.deepEqual(Object.keys(by).sort(), ["ssh-weak-cipher", "ssh-weak-hostkey", "ssh-weak-kex", "ssh-weak-mac"]);
  assert.equal(by["ssh-weak-kex"].severity, "high"); assert.match(by["ssh-weak-kex"].text, /diffie-hellman-group1-sha1.*|diffie-hellman-group14-sha1/);
  assert.match(by["ssh-weak-kex"].text, /diffie-hellman-group14-sha1/); assert.doesNotMatch(by["ssh-weak-kex"].text, /curve25519/);
  assert.equal(by["ssh-weak-hostkey"].severity, "high"); assert.match(by["ssh-weak-hostkey"].text, /ssh-rsa.*ssh-dss/);
  assert.equal(by["ssh-weak-cipher"].severity, "high"); assert.match(by["ssh-weak-cipher"].text, /aes128-cbc.*3des-cbc.*arcfour256/); assert.doesNotMatch(by["ssh-weak-cipher"].text, /aes128-ctr/);
  assert.equal(by["ssh-weak-mac"].severity, "medium"); assert.match(by["ssh-weak-mac"].text, /hmac-md5.*hmac-sha1-96/);
  assert.ok(obs.every((o) => o.port === 22 && o.text.length <= 600));
  // c2s and s2c carry the same names here: each weak name is listed once
  assert.equal(weakOf(k).filter((w) => w.name === "aes128-cbc").length, 1);
  const info = sshKexInfo(k);
  assert.deepEqual(info.kex, ["curve25519-sha256", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"]);   // ext-info-s is a marker, not a kex
  assert.deepEqual(info.pqc, []); assert.equal(info.strict_kex, false); assert.ok(info.weak.includes("ssh-dss"));

  const p = kexinitFrom(Buffer.concat([Buffer.from(BANNER + "\r\n"), kexinit(PQ_SET)])).kex, po = sshKexObservations(22, p);
  assert.deepEqual(po.map((o) => [o.kind, o.severity]), [["ssh-pqc-kex", "info"]]);
  assert.match(po[0].text, /mlkem768x25519-sha256, sntrup761x25519-sha512@openssh\.com/);
  const pi = sshKexInfo(p); assert.deepEqual(pi.pqc, ["mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com"]); assert.equal(pi.strict_kex, true); assert.deepEqual(pi.weak, []);
  // the lists are frozen
  assert.ok(Object.isFrozen(WEAK) && Object.isFrozen(WEAK.kex) && Object.isFrozen(PQC_KEX));
  assert.throws(() => { "use strict"; WEAK.kex["curve25519-sha256"] = ["high", "x"]; });
  assert.deepEqual(sshKexObservations(22, null), []); assert.equal(sshKexInfo(null), null);
});

test("ssh-kex probe: KEXINIT read on the same connection; the scanner sends exactly its identification line", async () => {
  for (const [set, mode] of [[WEAK_SET, "after-ident"], [PQ_SET, "after-ident"], [WEAK_SET, "with-banner"]]) {
    const s = await sshServer(kexinit(set), mode);
    try {
      const t0 = Date.now();
      // the default timeouts: the read must stop as soon as the KEXINIT is whole, not wait for the read limit
      const r = await probePort("127.0.0.1", s.port);
      assert.ok(Date.now() - t0 < 3000, `stopped after the KEXINIT (${Date.now() - t0} ms, ${mode})`);
      assert.equal(r.state, "open"); assert.equal(r.error, ""); assert.match(r.banner, /^SSH-2\.0-OpenSSH_9\.6p1/);
      assert.deepEqual(r.ssh_kex.kex, set.kex);
      await waitFor(() => s.got().length);
      assert.equal(s.got(), SSH_IDENT + "\r\n", "the only bytes sent are the identification line");
      assert.equal(s.conns(), 1, "one connection: the KEXINIT is read on the same connection");
    } finally { await s.close(); }
  }
});

test("ssh-kex probe: a banner-only server times out the second read cleanly (no error, no observation)", async () => {
  const s = await sshServer(null, "banner-only");
  try {
    const t0 = Date.now();
    const r = await probePort("127.0.0.1", s.port, { timeouts: FAST });
    assert.ok(Date.now() - t0 < FAST.connectMs + FAST.readMs * 2 + 1000);
    assert.equal(r.state, "open"); assert.equal(r.error, ""); assert.equal(r.ssh_kex, undefined);
    await waitFor(() => s.got().length);
    assert.equal(s.got(), SSH_IDENT + "\r\n");
  } finally { await s.close(); }
  // a server that answers the identification with junk instead of a KEXINIT: no ssh_kex, no error
  const junk = await sshServer(Buffer.from("not a packet at all, just text\r\n"), "after-ident");
  try { const r = await probePort("127.0.0.1", junk.port, { timeouts: FAST }); assert.equal(r.error, ""); assert.equal(r.ssh_kex, undefined); await waitFor(() => junk.got().length); assert.equal(junk.got(), SSH_IDENT + "\r\n"); }
  finally { await junk.close(); }
});

test("ssh-kex scan: observations and the per-port algorithm record reach the host, one connection per port", async () => {
  const weak = await sshServer(kexinit(WEAK_SET)), pq = await sshServer(kexinit(PQ_SET));
  let calls = 0;
  const probe = (ip, port, o) => { calls++; return probePort(ip, port, o); };
  try {
    const { hosts } = await probeAll([{ address: "127.0.0.1", names: [], kind: "loopback", public: false }],
      { ports: [weak.port, pq.port], settings: settings({}, { hasPublic: false }).settings, probe, assumeUp: true });
    const h = hosts[0];
    assert.equal(calls, 2);
    assert.deepEqual(h.ssh.map((x) => x.port).sort(), [weak.port, pq.port].sort());
    const kinds = h.observations.map((o) => `${o.port === weak.port ? "w" : "p"}:${o.kind}`).sort();
    assert.deepEqual(kinds, ["p:ssh-pqc-kex", "w:ssh-weak-cipher", "w:ssh-weak-hostkey", "w:ssh-weak-kex", "w:ssh-weak-mac"]);
    assert.deepEqual(h.ssh.find((x) => x.port === pq.port).pqc, ["mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com"]);
    assert.equal(h.services.filter((x) => x.product === "OpenSSH").length, 2);   // the banner still fingerprints as before
    assert.equal(weak.got(), SSH_IDENT + "\r\n"); assert.equal(pq.got(), SSH_IDENT + "\r\n");
  } finally { await weak.close(); await pq.close(); }
});
