// Passive pack 3 (scanner/lib/fp-pack3.mjs): products named from data the scan already collected — the greeting, the one
// GET / response (title, headers, cookie names, recorded Location, body markers) and the TLS certificate — plus a login-page
// inventory from the same root page. No real host is contacted: pure fixtures, and loopback stand-ins that record every byte
// the scanner sends them.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import http from "node:http";
import { readFileSync } from "node:fs";
import { RULES, CATALOG_IDS, ACCOUNTED_IDS, ALREADY_COVERED, LOGIN_LABEL, pack3 } from "../../scanner/lib/fp-pack3.mjs";
import { servicesOf, probeAll } from "../../scanner/lib/scan.mjs";
import { probePort } from "../../scanner/lib/probe.mjs";
import { cleanFlaws, findings } from "../../scanner/lib/match.mjs";
import { summarize } from "../../scanner/lib/report.mjs";
import { settings } from "../../scanner/lib/limits.mjs";
import { fromGreeting } from "../../scanner/lib/fingerprint.mjs";
import { certInventory, internalName, internalIp } from "../../scanner/lib/cert-inventory.mjs";
import { mailInventory } from "../../scanner/lib/mail-starttls.mjs";
import { W } from "../../scanner/lib/shared.mjs";

const TODAY = "2026-11-22";
const page = (body, headers = {}, status = 200) => ({ port: 80, state: "open", banner: "", raw: null, tls: null, http: { status, headers: { "content-type": "text/html", ...headers }, body } });
const titled = (t, extra = "", headers = {}) => page(`<!doctype html><html><head><title>${t}</title></head><body>${extra}</body></html>`, headers);
const greet = (banner, port = 21) => ({ port, state: "open", banner, raw: null, http: null, tls: null });
const products = (r, opts) => pack3(r, [], opts).filter((s) => s.label !== LOGIN_LABEL);
const one = (r, opts) => { const s = products(r, opts); assert.equal(s.length, 1, JSON.stringify(s)); return s[0]; };
const none = (r, opts) => assert.deepEqual(products(r, opts).map((s) => s.label), []);

/* ---- the table: the 28 manifest rows, each built here or listed as already built elsewhere ---- */
const MANIFEST = ["citrix-storefront-server", "synacor-zimbra-collaborate-suite-zcs", "synacor-zimbra-collaboration-suite-zcs", "teclib-glpi", "zammad-gmbh-zammad",
  "solarwinds-virtualization-manager", "zabbix-frontend", "ivanti-endpoint-manager-cloud-service-appliance-epm-csa", "proftpd-proftpd", "soliton-systems-k-k-filezen",
  "teamviewer-desktop", "quest-kace-system-management-appliance", "quest-kace-systems-management-appliance-sma", "nextgen-healthcare-mirth-connect",
  "nice-linear-emerge-e3-series", "openplc-scadabr", "unitronics-vision-plc-and-hmi", "zkteco-biotime", "internal-names-in-certificate-san", "ocsp-must-staple-advertised",
  "wildcard-certificate-breadth", "amcrest-cameras-and-network-video-recorder-nvr", "nuuo-nvrmini-devices", "nuuo-nvrmini2-devices", "mta-open-submission-on-port-25-only",
  "intel-active-management-technology-amt-small-business-technology-sbt-and-standar", "cisco-cisco-ip-phones", "login-page-inventory"];

test("pack 3 table: every manifest row is built once or listed as already covered; duplicate rows share one rule; rules well formed", () => {
  assert.equal(MANIFEST.length, 28);
  assert.deepEqual([...ACCOUNTED_IDS].sort(), [...MANIFEST].sort());
  for (const id of Object.keys(ALREADY_COVERED)) assert.ok(!CATALOG_IDS.includes(id), `${id} is built elsewhere, not here`);
  const ids = new Set(), seen = new Set();
  for (const r of RULES) {
    assert.ok(!ids.has(r.id), `duplicate rule ${r.id}`); ids.add(r.id);
    assert.ok(r.catalog.length && r.signals.length && r.vendor && r.product, r.id);
    for (const c of r.catalog) { assert.ok(!seen.has(c), `${c} in two rules`); seen.add(c); }
    for (const s of r.signals) assert.ok(typeof s.why === "string" && s.why.length > 5 && s.why.length < 120, `${r.id}: fixed evidence wording`);
  }
  // the duplicate pairs are one rule with both IDs
  for (const pair of [["nuuo-nvrmini-devices", "nuuo-nvrmini2-devices"], ["quest-kace-system-management-appliance", "quest-kace-systems-management-appliance-sma"],
    ["synacor-zimbra-collaborate-suite-zcs", "synacor-zimbra-collaboration-suite-zcs"]]) assert.equal(RULES.filter((r) => pair.every((c) => r.catalog.includes(c))).length, 1, pair[0]);
});

test("pack 3 module is pure: no network module, no path, no request", () => {
  const src = readFileSync(new URL("../../scanner/lib/fp-pack3.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(src, /node:(net|tls|http|https|dgram|child_process)|\bfetch\s*\(|\.request\s*\(|\.connect\s*\(/);
  assert.doesNotMatch(src, /from\s+["']\.\/(probe|udp|paths)\.mjs["']/);
});

test("product names match the KEV rows' vendor/product with the site's own nameHit (both spellings of the duplicate rows)", () => {
  const KEV = { "citrix-storefront": [["Citrix", "StoreFront Server"]], zimbra: [["Synacor", "Zimbra Collaboration Suite (ZCS)"], ["Synacor", "Zimbra Collaborate Suite (ZCS)"]],
    glpi: [["Teclib", "GLPI"]], zammad: [["Zammad GmbH", "Zammad"]], "solarwinds-vman": [["SolarWinds", "Virtualization Manager"]], zabbix: [["Zabbix", "Frontend"]],
    "ivanti-csa": [["Ivanti", "Endpoint Manager Cloud Service Appliance (EPM CSA)"]], filezen: [["Soliton Systems K.K.", "FileZen"]], teamviewer: [["TeamViewer", "Desktop"]],
    "kace-sma": [["Quest", "KACE System Management Appliance"], ["Quest", "KACE Systems Management Appliance (SMA)"]], "mirth-connect": [["NextGen Healthcare", "Mirth Connect"]],
    "linear-emerge": [["Nice", "Linear eMerge E3-Series"]], scadabr: [["OpenPLC", "ScadaBR"]], unitronics: [["Unitronics", "Vision PLC and HMI"]], biotime: [["ZKTeco", "BioTime"]],
    amcrest: [["Amcrest", "Cameras and Network Video Recorder (NVR)"]], "nuuo-nvr": [["NUUO", "NVRmini Devices"], ["NUUO", "NVRmini2 Devices"]],
    "intel-amt": [["Intel", "Active Management Technology (AMT), Small Business Technology (SBT), and Standard Manageability"]], "cisco-ip-phone": [["Cisco", "Cisco IP Phones"]] };
  assert.deepEqual(Object.keys(KEV).sort(), RULES.map((r) => r.id).sort());
  for (const r of RULES) for (const [v, p] of KEV[r.id]) assert.ok(W.nameHit(`${r.vendor} ${r.product}`, v, p), `${r.id} vs ${v} ${p}`);
});

/* ---- web root page signals ---- */
test("Citrix StoreFront from the CTXS script markers only; a NetScaler / ADC title alone is not StoreFront", () => {
  assert.equal(one(page('<script>CTXS.WebApiClient.init()</script>')).product, "StoreFront Server");
  assert.equal(one(page('<script src="/Citrix/StoreWeb/scripts/ctxs.core.min.js?v=1"></script>')).product, "StoreFront Server");
  none(titled("Citrix Login")); none(titled("Netscaler Gateway"));
  // the certificate hint still names NetScaler ADC separately (fingerprint.mjs); StoreFront is a different product
  const s = one(page("<script>CTXS.AccessGateway.x</script>"));
  assert.equal(s.guessed, true); assert.equal(s.version, "");
});

test("Zimbra (both catalog spellings, one rule): login titles, the ZM_TEST cookie name, the certificate OU; never versioned here", () => {
  for (const t of ["Zimbra Web Client Sign In", "Zimbra Collaboration Suite Log In", "Zimbra Web Client Log In"]) { const s = one(titled(t)); assert.equal(s.label, "Zimbra Collaboration Suite (ZCS)"); assert.equal(s.guessed, true); }
  const c = one(page("<html></html>", { "set-cookie": ["ZM_TEST=true; Path=/"] })); assert.match(c.evidence, /ZM_TEST/); assert.doesNotMatch(c.evidence, /true/);
  const crt = { port: 443, state: "open", banner: "", http: null, tls: { cert: { subject: { CN: "mail.lab.test", OU: "Zimbra Collaboration Server" }, issuer: { CN: "x" } } } };
  assert.equal(one(crt).proto, "https");
  none(titled("Zimbra Administration")); none(titled("Webmail"));
});

test("GLPI needs both markers; version from the footer or the common.min.js ?v= asset", () => {
  none(page("<p>GLPI</p>")); none(page('<a href="https://glpi-project.org">x</a>'));
  const a = one(page('<p>GLPI</p><a href="https://glpi-project.org">site</a>'));
  assert.equal(a.guessed, true); assert.equal(a.version, "");
  const b = one(page('<p>GLPI version 10.0.6 Copyright (C) 2015-2023 Teclib\' and contributors</p><a href="http://glpi-project.org/">x</a>'));
  assert.equal(b.version, "10.0.6"); assert.equal(b.guessed, false); assert.match(b.evidence, /version 10\.0\.6 from the root page/);
  const c = one(page('<script src="/js/common.min.js?v=9.5.13"></script>GLPI glpi-project.org'));
  assert.equal(c.version, "9.5.13");
});

test("Zabbix: zbxCallPostScripts, meta Author ZABBIX SIA or the title; version from jsLoader.php?ver= or the footer", () => {
  assert.equal(one(page("<script>zbxCallPostScripts('x')</script>")).product, "Frontend");
  assert.equal(one(page('<meta name="Author" content="ZABBIX SIA">')).guessed, true);
  assert.equal(one(titled("zabbix-server: Zabbix")).label, "Zabbix frontend");
  assert.equal(one(titled("Zabbix", '<script src="jsLoader.php?ver=5.0.21&amp;lang=en_US"></script>')).version, "5.0.21");
  assert.equal(one(titled("Zabbix", "<footer>Zabbix 6.0.4. &copy; 2001&ndash;2022, Zabbix SIA</footer>")).version, "6.0.4");
  none(titled("Zabbix dashboard notes"));
});

test("titles and body markers named by the rows: Zammad, SolarWinds VMan, Ivanti CSA, FileZen, TeamViewer, ScadaBR, BioTime; no version", () => {
  const cases = [[titled("Zammad Helpdesk"), "Zammad"], [page('<script id="zammad_form_script" src="/assets/form/form.js"></script>'), "Zammad"],
    [titled("SolarWinds Virtualization Manager"), "Virtualization Manager"], [titled("Ivanti(R) Cloud Services Appliance"), "Endpoint Manager Cloud Service Appliance (EPM CSA)"],
    [page("<p>LANDESK(R) Cloud Services Appliance</p>"), "Endpoint Manager Cloud Service Appliance (EPM CSA)"], [titled("FileZen"), "FileZen"],
    [page("<p>FileZen, Copyrights(C) 2010 Soliton</p>"), "FileZen"],
    [page("<html><body>This site is running <a href='http://www.TeamViewer.com'>TeamViewer</a>.</body></html>"), "Desktop"],
    [titled("ScadaBR"), "ScadaBR"], [page("<p>ScadaBR Software</p>"), "ScadaBR"], [titled("BioTime 8.0"), "BioTime"]];
  for (const [r, p] of cases) { const s = one(r); assert.equal(s.product, p); assert.equal(s.version, ""); assert.equal(s.guessed, true); }
  none(titled("SolarWinds Orion")); none(page("<p>LANDESK(R)</p>")); none(titled("oVirt Open Virtualization Manager")); none(page("<p>TeamViewer</p>"));
  assert.doesNotMatch(one(titled("BioTime 8.0")).evidence, /8\.0/, "the title suffix is not read as a version (group not reviewed)");
});

test("Quest KACE (both catalog spellings, one rule): version from X-DellKACE-Version / X-KBOX-Version; a deployment appliance header is never the SMA", () => {
  const a = one(page("<html></html>", { "x-dellkace-version": "13.2.183", "x-dellkace-appliance": "K1000" }));
  assert.equal(a.version, "13.2.183"); assert.equal(a.guessed, false); assert.equal(a.label, "Quest KACE Systems Management Appliance (SMA, formerly K1000) (K1000)");
  assert.match(a.evidence, /from the x-dellkace-version header/);
  assert.equal(one(page("<html></html>", { "x-kbox-version": "5.3.47927" })).version, "5.3.47927");
  const t = one(titled("KACE Systems Management Appliance Administrator Login")); assert.equal(t.guessed, true);
  assert.equal(one(titled("K1000 Service Center")).version, "");
  none(page("<html></html>", { "x-dellkace-version": "9.1.1", "x-dellkace-appliance": "K2000" }));
  none(titled("KACE Systems Deployment Appliance"));
});

test("Mirth Connect is the clinical row: off unless { clinical: true }, and the scan path does not turn it on", () => {
  const r = titled("Mirth Connect Administrator");
  none(r); assert.equal(one(r, { clinical: true }).product, "Mirth Connect");
  assert.ok(!servicesOf(r).some((s) => s.product === "Mirth Connect"));
});

test("families: eMerge, Unitronics, Amcrest and NUUO are named as families, never versioned, always guessed", () => {
  const cases = [[titled("Linear eMerge Essential v1.00-06"), "Linear eMerge E3-Series"], [titled("Unitronics"), "Vision PLC and HMI"],
    [page('<img src="/img/Logo-Unitronics.svg">'), "Vision PLC and HMI"], [page('<a href="https://www.unitronics.com">x</a>'), "Vision PLC and HMI"],
    [page('<p>Amcrest Technologies</p><input name="LDAPUser">'), "Cameras and Network Video Recorder (NVR)"],
    [titled("NUUO Network Video Recorder Login", "<p>Version 3.0.0</p>"), "NVRmini/NVRmini2 Devices"]];
  for (const [r, p] of cases) { const s = one(r); assert.equal(s.product, p); assert.equal(s.version, ""); assert.equal(s.guessed, true); assert.match(s.evidence, /no version stated/); }
  none(page("<p>Amcrest Technologies</p>"));   // the decision names both body strings
  assert.match(one(titled("NUUO Network Video Recorder Login")).label, /NVRmini \/ NVRmini2 not told apart/);
});

test("Intel AMT / Standard Manageability: version from the Server header only; no digest realm is ever answered", () => {
  const a = one({ ...page("", { server: "Intel(R) Active Management Technology 11.8.50.3399", "www-authenticate": 'Digest realm="Digest:A1B2", nonce="x"' }, 401), port: 16992 });
  assert.equal(a.version, "11.8.50.3399"); assert.equal(a.guessed, false); assert.equal(a.port, 16992); assert.match(a.evidence, /from the Server header/);
  assert.equal(one(page("", { server: "Intel(R) Standard Manageability 9.0.30" })).version, "9.0.30");
  assert.equal(one(page("", { server: "Intel(R) Active Management Technology" })).guessed, true);
  none(page("", { server: "AMT" }));
});

test("Cisco IP Phone: title Cisco Systems, Inc. with Cisco IP Phone, or CP-<model>; the model is a token, never a version", () => {
  const a = one(titled("Cisco Systems, Inc.", "<b>Cisco IP Phone CP-7941G ( SEP001122334455 )</b>"));
  assert.equal(a.product, "Cisco IP Phones"); assert.equal(a.label, "Cisco IP Phone (CP-7941G)"); assert.equal(a.version, ""); assert.equal(a.guessed, true);
  assert.doesNotMatch(JSON.stringify(a), /SEP0011/);
  assert.equal(one(titled("Cisco IP Phone CP-8841")).label, "Cisco IP Phone (CP-8841)");
  none(titled("Cisco Systems, Inc.")); none(titled("Cisco IP Phone settings"));
});

/* ---- login-page inventory: the root page and the recorded redirect only ---- */
test("login-page inventory: a password field on the root page or a recorded redirect into a login path; nothing requested; one per port", () => {
  const form = page('<form method="post" action="/auth"><input name="u"><input type="password" name="p"></form>');
  const l = pack3(form).filter((s) => s.label === LOGIN_LABEL);
  assert.equal(l.length, 1); assert.equal(l[0].product, ""); assert.equal(l[0].guessed, true); assert.match(l[0].evidence, /password field/);
  const red = pack3(page("", { location: "/ui/login?next=%2F" }, 302)).filter((s) => s.label === LOGIN_LABEL);
  assert.equal(red.length, 1); assert.match(red[0].evidence, /redirects to a login path \(recorded, not followed\)/); assert.doesNotMatch(red[0].evidence, /next=/);
  assert.deepEqual(pack3(page("<p>welcome</p>")), []); assert.deepEqual(pack3(page("", { location: "/home" }, 302)), []);
  assert.deepEqual(pack3(page("", { location: "https://idp.example.org/?login_hint=x" }, 302)), [], "a query string is not a login path");
  assert.equal(pack3(form, [{ label: LOGIN_LABEL }]).length, 0);
  // a product page with a login form gets both: the product and the inventory line
  const z = pack3(titled("Zimbra Web Client Sign In", '<input type="password" name="password">'));
  assert.deepEqual(z.map((s) => s.label), ["Zimbra Collaboration Suite (ZCS)", LOGIN_LABEL]);
  // through the scan path: the login line survives servicesOf's final filter and never reaches the inventory CSV (no product)
  assert.ok(servicesOf(form).some((s) => s.label === LOGIN_LABEL));
});

/* ---- dedupe and evidence ---- */
test("nothing from nothing; a product already named on the port is not added twice", () => {
  assert.deepEqual(pack3(null), []); assert.deepEqual(pack3({ port: 80 }), []);
  none(titled("Fixture intranet"));
  assert.deepEqual(products(titled("ScadaBR"), undefined), products(titled("ScadaBR")));
  assert.deepEqual(pack3(titled("ScadaBR"), [{ product: "ScadaBR" }]), []);
  assert.deepEqual(pack3(titled("FileZen"), [{ product: "filezen" }]), [], "names compared normalised");
  // through servicesOf: the product appears once
  assert.equal(servicesOf(titled("Zabbix", '<script>zbxCallPostScripts()</script>')).filter((s) => s.product === "Frontend").length, 1);
});

test("evidence is fixed rule wording plus the version or model read: never the body or a cookie value", () => {
  const secret = "s3cr3t-token-in-the-page";
  const ss = pack3(titled("Zimbra Web Client Sign In", `<p>${secret}</p><input type="password">`, { "set-cookie": [`ZM_TEST=${secret}`, `JSESSIONID=${secret}`] }));
  assert.equal(ss.length, 2);
  for (const s of ss) { assert.doesNotMatch(JSON.stringify(s), new RegExp(secret)); assert.ok(s.evidence.length <= 200); assert.match(s.evidence, /passive: data already collected/); }
  const k = one(page("", { "x-dellkace-version": "13.0.1", "x-dellkace-appliance": "K1000<script>alert(1)</script>" }));
  assert.doesNotMatch(k.label + k.evidence, /[<>]|script|alert/); assert.match(k.evidence, /model K1000;/);
});

/* ---- rows already built elsewhere: verified, not rebuilt ---- */
test("already covered: ProFTPD from the FTP greeting (fingerprint.mjs), with the version when the greeting states it", () => {
  const [a] = fromGreeting("220 ProFTPD 1.3.5e Server (Debian) [::ffff:10.0.0.5]\r\n", 21);
  assert.equal(a.product, "ProFTPD"); assert.equal(a.shown_version, "1.3.5e"); assert.equal(a.guessed, false);
  const [b] = fromGreeting("220 ProFTPD Server (ProFTPD Default Installation) [10.0.0.5]\r\n", 21);
  assert.equal(b.product, "ProFTPD"); assert.equal(b.guessed, true);
  const via = servicesOf(greet("220 ProFTPD 1.3.8b Server ready.\r\n"));
  assert.deepEqual(via.map((s) => [s.product, s.shown_version]), [["ProFTPD", "1.3.8b"]]);
});

test("already covered: certificate internal names, must-staple and wildcard breadth (cert-inventory.mjs); port-25-only SMTP (mail-starttls.mjs)", () => {
  assert.equal(internalName("nas.local"), ".local name"); assert.match(internalIp("192.168.1.10"), /private/);
  const report = { hosts: [{ address: "10.0.0.5", names: ["app.lab.example.org"], tls: [{ port: 443, cert: { subject: "CN=app", issuer: "CN=ca", san_dns: ["*.lab.example.org", "db01"], san_ip: ["10.0.0.5"], must_staple: true } }] }] };
  const r = certInventory(report).rows[0];
  assert.deepEqual(r.internal_names.map((x) => x.name), ["db01", "10.0.0.5"]); assert.equal(r.must_staple, true);
  assert.deepEqual(r.wildcards, [{ name: "*.lab.example.org", covers_attested: ["app.lab.example.org"] }]);
  const mail = mailInventory({ run: { ports: [25, 465, 587] }, hosts: [{ address: "10.0.0.6", ports: [{ port: 25, banner: "220 mx ESMTP Postfix" }], services: [], tls: [] }] });
  assert.match(mail[0].submission, /port 25 only/);
});

/* ---- findings: a stated version can be a headline; a version-less or family identification stays low confidence ---- */
test("findings: KACE header version inside a range is high confidence; a NUUO family identification stays out of the headline counts", () => {
  const wb = { kev: [
    { cve: "CVE-2026-90961", vendor: "Quest", product: "KACE Systems Management Appliance (SMA)", name: "fixture KACE flaw", added: "2026-11-01", due: "2026-11-21", cvss: 9.8, av: "N",
      affected: [{ vendor: "quest", product: "kace systems management appliance", to: "14.0" }] },
    { cve: "CVE-2026-90962", vendor: "NUUO", product: "NVRmini2 Devices", name: "fixture NUUO flaw", added: "2026-11-01", due: "2026-11-21", cvss: 9.8, av: "N", affected: [] },
  ] };
  const flaws = cleanFlaws(wb);
  const host = { address: "127.0.0.1", names: [], up: true, ports: [],
    services: [...pack3(page("", { "x-dellkace-version": "13.2.183" })), ...pack3(titled("NUUO Network Video Recorder Login"))] };
  const f = findings([host], flaws, new Map(), { today: TODAY });
  const k = f.find((x) => x.cve === "CVE-2026-90961"), n = f.find((x) => x.cve === "CVE-2026-90962");
  assert.equal(k.state, "affected"); assert.equal(k.confidence, "high");
  assert.equal(n.state, "check"); assert.equal(n.confidence, "low");
  const sum = summarize([host], f);
  assert.equal(sum.low_confidence, 1); assert.equal(sum.known_exploited, 1);
});

/* ---- the scan path, and the bytes on the wire ---- */
test("probeAll: identification comes from the one probe result per port (probe called exactly once per port)", async () => {
  const calls = [];
  const probe = async (ip, port) => { calls.push(port); return port === 80 ? { ...titled("ScadaBR"), port } : port === 21 ? { ...greet("220 ProFTPD 1.3.6 Server\r\n"), port } : { port, state: "closed", banner: "", http: null, tls: null }; };
  const st = settings({}).settings;
  const out = await probeAll([{ address: "127.0.0.1", names: [], kind: "loopback", public: false }], { ports: [21, 80, 443], settings: st, probe, assumeUp: true });
  assert.deepEqual(calls.sort((a, b) => a - b), [21, 80, 443]);
  const prods = out.hosts[0].services.map((s) => s.product);
  assert.ok(prods.includes("ScadaBR") && prods.includes("ProFTPD"), prods.join(","));
});

test("loopback: an FTP greeting service receives zero bytes and is identified from what it sent", async () => {
  const got = { connections: 0, bytes: [] };
  const srv = net.createServer((s) => { got.connections++; s.on("data", (d) => got.bytes.push(d)); s.on("error", () => {}); s.write("220 ProFTPD 1.3.5 Server (fixture)\r\n"); setTimeout(() => s.end(), 1500); });
  const port = await new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
  try {
    const r = await probePort("127.0.0.1", port);
    const p = servicesOf(r).find((x) => x.product === "ProFTPD");
    assert.ok(p); assert.equal(p.version, "1.3.5");
    assert.equal(got.connections, 1); assert.equal(Buffer.concat(got.bytes).length, 0, "nothing was sent to a greeting service");
  } finally { await new Promise((q) => srv.close(() => q())); }
});

test("loopback: a web service sees exactly one connection and one GET / (no /login, no version path, no redirect followed)", async () => {
  const reqs = []; let conns = 0;
  const srv = http.createServer((req, res) => {
    reqs.push(`${req.method} ${req.url}`);
    res.writeHead(302, { Location: "/zimbra/login?client=preferred", "Set-Cookie": "ZM_TEST=true; Path=/", "X-DellKACE-Version": "13.2.183", "Content-Type": "text/html" });
    res.end('<html><head><title>Zimbra Web Client Sign In</title></head><body><input type="password" name="password"></body></html>');
  });
  srv.on("connection", () => { conns++; });
  const port = await new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
  try {
    const r = await probePort("127.0.0.1", port, { httpPorts: [port] });
    const svcs = servicesOf(r);
    const z = svcs.find((x) => x.label === "Zimbra Collaboration Suite (ZCS)"), k = svcs.find((x) => x.product.startsWith("KACE")), l = svcs.find((x) => x.label === LOGIN_LABEL);
    assert.ok(z && k && l, JSON.stringify(svcs.map((s) => s.label)));
    assert.equal(z.guessed, true); assert.equal(k.version, "13.2.183");
    assert.deepEqual(reqs, ["GET /"]); assert.equal(conns, 1);
  } finally { await new Promise((q) => { if (srv.closeAllConnections) srv.closeAllConnections(); srv.close(() => q()); }); }
});
