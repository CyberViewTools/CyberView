// scan-edge-versions (PR A): edge and appliance fingerprints from the root page, headers, greeting and certificate the
// scan already collected. No real host is contacted: canned responses, plus loopback servers that record every byte sent.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import net from "node:net";
import { fromEdge, RULES, CERT_ROWS } from "../../scanner/lib/fp-edge.mjs";
import { fromCert } from "../../scanner/lib/fingerprint.mjs";
import { servicesOf, probeAll } from "../../scanner/lib/scan.mjs";
import { probePort } from "../../scanner/lib/probe.mjs";
import { cleanFlaws, findings } from "../../scanner/lib/match.mjs";
import { summarize } from "../../scanner/lib/report.mjs";
import { settings } from "../../scanner/lib/limits.mjs";

const FIX = JSON.parse(readFileSync(new URL("../fixtures/scanner/edge/pages.json", import.meta.url), "utf8"));
const page = (k, port = 443) => ({ port, http: FIX[k], tls: { cert: null } });
const all = (k) => fromEdge(page(k));
const one = (k) => { const s = all(k); assert.equal(s.length, 1, `${k}: ${JSON.stringify(s)}`); return s[0]; };
const TODAY = "2026-11-22";

test("a version only where the collected data states it (Server header, page text, asset path, greeting)", () => {
  const cases = [
    ["acs", "Cisco", "Secure Access Control System", "5.8.0.32", "5.8.0.32", "HTTP Server header"],
    ["dcnm", "Cisco", "Prime Data Center Network Manager", "7.0.2", "7.0.2", "root page text"],
    ["dir645", "D-Link", "DIR-645 Firmware", "1.04", "1.04", "HTTP Server header"],
    ["dir820lw", "D-Link", "DIR-820LW Firmware", "2.00W", "2.00w", "HTTP Server header"],
    ["aleos", "Sierra Wireless", "ALEOS", "4.9.3", "4.9.3", "root page text"],
    ["sma1000", "SonicWall", "SMA1000 Firmware", "12.4", "12.4", "HTTP Server header"],
    ["cyberoam", "Sophos", "CyberoamOS", "10.6.6", "10.6.6", "root page text"],
  ];
  for (const [k, vendor, product, shown, version, source] of cases) {
    const s = one(k);
    assert.deepEqual([s.vendor, s.product, s.shown_version, s.version, s.guessed, s.source], [vendor, product, shown, version, false, source], k);
    assert.match(s.evidence, /states/, k);
  }
  // a greeting banner (no HTTP): Brocade's telnet greeting states the release
  const b = fromEdge({ port: 23, banner: "\r\nFabric OS (tm)  Release v7.4.2a\r\n\r\nswitch login: " })[0];
  assert.deepEqual([b.vendor, b.product, b.shown_version, b.version, b.guessed, b.proto], ["Broadcom", "Fabric OS", "7.4.2a", "7.4.2a", false, "telnet"]);
});

test("without a stated version: a guessed, version-less hint", () => {
  const cases = [
    ["arcserve", "Arcserve", "Unified Data Protection"], ["array", "Array Networks", "ArrayOS AG"], ["aviatrix", "Aviatrix", "Controller"],
    ["vmanage", "Cisco", "Catalyst SD-WAN Manager"], ["dcs2530", "D-Link", "DCS-2530L Firmware"], ["dir300", "D-Link", "DIR-300 Firmware"],
    ["dir859_title", "D-Link", "DIR-859 Firmware"], ["dnr322l", "D-Link", "DNR-322L Firmware"], ["ddwrt", "DD-WRT", "DD-WRT"],
    ["ivanti_csa", "Ivanti", "Cloud Services Appliance (CSA)"], ["tmg_http", "Microsoft", "Forefront Threat Management Gateway"],
    ["netgear_wap", "NETGEAR", "WAP371 Firmware"], ["expedition", "Palo Alto Networks", "Expedition"], ["kemp", "Progress", "LoadMaster"],
    ["aleos_title_only", "Sierra Wireless", "ALEOS"], ["sophos_utm", "Sophos", "SG UTM"], ["sophos_swa", "Sophos", "Web Appliance"],
    ["tplink_wr841n", "TP-Link", "TL-WR841N Firmware"], ["tplink_wa855re", "TP-Link", "TL-WA855RE Firmware"], ["tplink_family", "TP-Link", "WR940N Firmware"],
    ["gs1900", "Zyxel", "GS1900 Firmware"], ["zyxel_fw", "Zyxel", "USG FLEX 100 Firmware"], ["p660", "Zyxel", "P660HN-T1A Firmware"],
  ];
  for (const [k, vendor, product] of cases) {
    const s = one(k);
    assert.deepEqual([s.vendor, s.product, s.version, s.shown_version, s.guessed], [vendor, product, "", "", true], k);
    assert.match(s.evidence, /no version stated/, k);
  }
  // SSH and FTP greetings
  const sc = fromEdge({ port: 22, banner: "SSH-2.0-NetScreen\r\n" })[0];
  assert.deepEqual([sc.vendor, sc.product, sc.proto, sc.guessed], ["Juniper", "ScreenOS", "ssh", true]);
  const tmg = fromEdge({ port: 21, banner: "220-Authenticate for FTP Access.\r\n220 Ready\r\n" })[0];
  assert.deepEqual([tmg.product, tmg.proto, tmg.guessed], ["Forefront Threat Management Gateway", "ftp", true]);
});

test("only what the catalog row states: no model or product named without its own marker", () => {
  for (const k of ["dcs_other", "dir300_generic", "netgear_generic_wap", "sma_unsplit", "user_portal_only", "rompager_other", "plain_intranet"])
    assert.deepEqual(all(k), [], k);
  // a page title is never read as a version
  const t = one("title_with_number"); assert.deepEqual([t.product, t.version, t.shown_version, t.guessed], ["Controller", "", "", true]);
  // a TP-Link model rule wins over the family rule (one record, not two)
  assert.equal(all("tplink_wr841n").length, 1);
  assert.deepEqual(fromEdge({ port: 22, banner: "SSH-2.0-OpenSSH_9.6\r\n" }), []);
  assert.deepEqual(fromEdge({ port: 443 }), []); assert.deepEqual(fromEdge(null), []);
});

test("certificate-only catalog rows are the hints fingerprint.mjs already has (guessed, no version)", () => {
  const cn = { "qnap-qts": "QNAP NAS", "synology-diskstation-manager": "Synology Inc", "citrix-netscaler-adc": "NetScaler", "fortinet-fortios": "FortiGate",
    "ivanti-connect-secure": "Ivanti", "mikrotik-routeros": "MikroTik", "palo-alto-pan-os": "Palo Alto Networks", "sonicwall-sonicos": "SonicWall",
    "sophos-firewall": "Sophos", "zyxel-firmware": "Zyxel" };
  assert.deepEqual(Object.keys(cn).sort(), [...CERT_ROWS].sort());
  for (const id of CERT_ROWS) {
    const s = fromCert({ subject: { CN: cn[id], O: cn[id] }, issuer: { CN: cn[id] } })[0];
    assert.ok(s, id); assert.equal(s.version, ""); assert.equal(s.guessed, true);
  }
});

test("servicesOf: the edge hint joins the existing parsers without duplicates", () => {
  const sv = servicesOf({ port: 80, http: FIX.dir645, tls: null });
  assert.deepEqual(sv.map((s) => s.product), ["DIR-645 Firmware"]);
  // an SSH greeting that names ScreenOS replaces the anonymous "SSH server" record
  assert.deepEqual(servicesOf({ port: 22, banner: "SSH-2.0-NetScreen" }).map((s) => s.product), ["ScreenOS"]);
  // ordinary banners are untouched
  assert.equal(servicesOf({ port: 22, banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13" })[0].product, "OpenSSH");
  // a product already stated is not repeated
  assert.deepEqual(fromEdge(page("acs"), [{ product: "Secure Access Control System", guessed: false }]), []);
  // every rule names catalog ids and NVD-style names: 47 catalog rows are built here and 10 are the certificate hints;
  // cisco-ios-ios-xe is not built (its row names the Server header but states no pattern to match)
  const ids = new Set(RULES.flatMap((r) => r.ids));
  assert.ok(RULES.every((r) => r.ids.length && r.vendor && r.product));
  assert.equal(ids.size, 47); assert.equal(ids.has("cisco-ios-ios-xe"), false);
});

test("matching: a login-page title alone is never 'affected' and stays out of the headline; a stated version is", () => {
  const flaws = cleanFlaws({ kev: [
    { cve: "CVE-2026-90801", vendor: "Sierra Wireless", product: "ALEOS", name: "Fixture ALEOS flaw", added: "2026-10-01", due: "2026-10-22", cvss: 9.8, epss: 0.9, av: "N",
      affected: [{ vendor: "sierrawireless", product: "aleos", from: "4.9.0", from_incl: true, to: "4.9.5", to_incl: false }] },
    { cve: "CVE-2026-90802", vendor: "Progress", product: "LoadMaster", name: "Fixture LoadMaster flaw", added: "2026-10-01", due: "2026-10-22", cvss: 10, epss: 0.9, av: "N",
      affected: [{ vendor: "progress", product: "loadmaster", to: "7.2.60", to_incl: false }] },
    { cve: "CVE-2026-90803", vendor: "D-Link", product: "DIR-645", name: "Fixture DIR-645 flaw", added: "2026-10-01", due: "2026-10-22", cvss: 9.1, epss: 0.2, av: "N",
      affected: [{ vendor: "dlink", product: "dir-645 firmware", to: "1.05", to_incl: false }] },
  ] });
  const host = (svcs) => [{ address: "10.0.0.9", names: [], public: false, up: true, ports: [], services: svcs }];
  for (const k of ["aleos_title_only", "kemp"]) {
    const hs = host(all(k)), fs = findings(hs, flaws, new Map(), { today: TODAY });
    assert.equal(fs.length, 1, k); assert.equal(fs[0].state, "check", k); assert.equal(fs[0].confidence, "low", k);
    const sm = summarize(hs, fs); assert.deepEqual([sm.known_exploited, sm.critical, sm.act, sm.version_confirmed, sm.low_confidence], [0, 0, 0, 0, 1], k);
  }
  const hs = host([...all("aleos"), ...fromEdge(page("dir645", 80))]), fs = findings(hs, flaws, new Map(), { today: TODAY });
  assert.deepEqual(fs.map((f) => [f.cve, f.state, f.confidence]).sort(), [["CVE-2026-90801", "affected", "high"], ["CVE-2026-90803", "affected", "high"]]);
  assert.equal(summarize(hs, fs).known_exploited, 2);
});

test("evidence carries short tokens only, never page content", () => {
  for (const k of Object.keys(FIX).filter((x) => !x.startsWith("_"))) for (const s of all(k)) {
    assert.ok(s.evidence.length <= 200, k);
    assert.ok(!/<|EXTRAWEB_REFERER<|Sign in|Copyright 2018/.test(s.evidence), `${k}: evidence must not copy page content: ${s.evidence}`);
  }
});

// a loopback stand-in that records every byte the scanner sends, answering with a canned response
async function recorder(reply, { greet = "" } = {}) {
  const got = [], conns = { n: 0 };
  const srv = net.createServer((sock) => {
    let buf = ""; if (greet) sock.write(greet);
    conns.n++;
    sock.on("data", (d) => { buf += d.toString("latin1"); if (buf.includes("\r\n\r\n") && !got.includes(buf)) { got.push(buf); sock.end(reply); } });
    sock.on("error", () => {});
  });
  await new Promise((res) => srv.listen(0, "127.0.0.1", res));
  return { port: srv.address().port, got, conns, close: () => new Promise((res) => srv.close(res)) };
}

test("no new bytes: one GET / per web port, and the edge parser adds no request or connection", async () => {
  const srv = await recorder("HTTP/1.1 200 OK\r\nServer: Linux, WEBACCESS/1.0, DIR-645 Ver 1.04\r\nContent-Type: text/html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
  try {
    let calls = 0;
    const probe = async (ip, p, o) => { calls++; return probePort(ip, p, o); };
    const out = await probeAll([{ address: "127.0.0.1", names: [], kind: "loopback", public: false }], { ports: [srv.port], settings: settings({}).settings, probe, assumeUp: true, httpPorts: [srv.port] });
    await new Promise((res) => setTimeout(res, 50));
    assert.equal(calls, 1); assert.equal(srv.conns.n, 1, "one connection"); assert.equal(srv.got.length, 1);
    assert.match(srv.got[0].split("\r\n")[0], /^GET \/ HTTP\/1\.1$/);
    assert.equal((srv.got[0].match(/ HTTP\/1\.1\r\n/g) || []).length, 1, "one request");
    const s = out.hosts[0].services.find((x) => x.product === "DIR-645 Firmware");
    assert.ok(s, JSON.stringify(out.hosts[0].services)); assert.equal(s.version, "1.04");
  } finally { await srv.close(); }
});
