// scan-app-versions, passive pack 1 (scanner/lib/fp-apps.mjs): application products named only from what the scan already
// collected (the one GET / response, the certificate, a greeting). No real host is contacted: inputs are canned probe results,
// and the one loopback test serves 127.0.0.1 only. CVE ids below are invented fixtures (CVE-2026-90xxx).
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { RULES, SKIPPED, appServices, collected } from "../../scanner/lib/fp-apps.mjs";
import { servicesOf, probeAll } from "../../scanner/lib/scan.mjs";
import { probePort } from "../../scanner/lib/probe.mjs";
import { settings } from "../../scanner/lib/limits.mjs";
import { cleanFlaws, findings } from "../../scanner/lib/match.mjs";
import { summarize } from "../../scanner/lib/report.mjs";
import { D } from "../../scanner/lib/shared.mjs";

const TODAY = "2026-11-22";
const web = (o = {}, port = 80) => ({ port, state: "open", banner: "", http: { status: o.status || 200, headers: o.headers || {}, body: o.body || "" }, tls: o.tls || null });
const one = (r, id) => appServices(r).filter((s) => s.catalog.includes(id));
const page = (title, extra = "") => `<html><head><title>${title}</title></head><body>${extra}</body></html>`;

// the 42 catalog rows of this pack: every id is either built or skipped with a reason
const PACK = ["qdrant", "ray-project-ray", "apache-tomcat", "advantive-veracore", "apache-axis", "apache-hugegraph-server", "apache-kylin", "apache-spark",
  "asp-net-or-system-web", "django-application", "express-or-node-js-http", "laravel-application", "oracle-fusion-middleware", "oracle-intelligence-enterprise-edition",
  "progress-telerik-report-server", "ruby-on-rails-application", "telerik-user-interface-ui-for-asp-net-ajax", "yiiframework-yii", "accellion-fta", "crushftp-crushftp",
  "d-link-multiple-nas-devices", "fortra-goanywhere-mft", "nakivo-backup-and-replication", "progress-moveit-transfer", "progress-ws-ftp-server", "projectsend-projectsend",
  "qnap-network-attached-storage-nas", "rejetto-http-file-server", "terramaster-terramaster-os", "veritas-backup-exec-agent", "jenkins", "kestra-kestra-oss", "saltstack-salt",
  "citrix-content-collaboration", "citrix-sharefile", "microsoft-internet-key-exchange-ike-service-extensions", "microsoft-sharepoint", "onlyoffice-docs",
  "servicenow-utah-vancouver-and-washington-dc-now-platform", "sysaid-sysaid-on-prem", "sysaid-sysaid-server", "istio-or-envoy-admin"];

test("the rules table covers the pack: every catalog id is built once or skipped with a reason, and every rule is well formed", () => {
  assert.equal(PACK.length, 42);
  const built = RULES.flatMap((r) => r.ids);
  assert.equal(new Set(built).size, built.length, "no catalog id in two rules");
  for (const id of PACK) assert.ok(built.includes(id) !== Object.prototype.hasOwnProperty.call(SKIPPED, id), `${id}: built xor skipped`);
  for (const id of [...built, ...Object.keys(SKIPPED)]) assert.ok(PACK.includes(id), `${id} is not in this pack`);
  assert.equal(built.length, 38);
  for (const r of RULES) {
    assert.ok(Array.isArray(r.when) && r.when.length && r.when.every((g) => g.length && g.every((s) => s[1] instanceof RegExp && typeof s[2] === "string")), r.ids[0]);
    assert.equal(typeof r.cpe, "string");
    for (const v of r.version || []) assert.ok(["header", "page", "shown"].includes(v[2]), `${r.ids[0]} version trust`);
  }
});

/* ---- one positive fixture per built rule, from already-collected data only ---- */
const CASES = [
  ["ray-project-ray", web({ body: page("Ray Dashboard") }, 8265)],
  ["advantive-veracore", web({ body: '<img src="/veracore/img/LoginLogo.png">' })],
  ["advantive-veracore", web({ status: 302, headers: { location: "/veracore/Home/" } })],
  ["apache-axis", web({ body: '<link href="axis2-web/css/axis-style.css">' })],
  ["apache-hugegraph-server", web({ body: '{"service":"hugegraph","version":"x"}' })],
  ["apache-kylin", web({ body: '<meta http-equiv="refresh" content="1;url=kylin">' })],
  ["apache-kylin", web({ body: '<a href="/kylin/">go</a>' })],
  ["apache-spark", web({ body: page("Spark Jobs", "Spark Jobs application UI") }, 4040)],
  ["apache-spark", web({ status: 302, headers: { location: "/jobs/" } }, 4040)],
  ["asp-net-or-system-web", web({ headers: { "x-powered-by": "ASP.NET" } })],
  ["asp-net-or-system-web", web({ headers: { "set-cookie": ["ASP.NET_SessionId=abc; path=/"] } })],
  ["django-application", web({ headers: { "set-cookie": ["csrftoken=SECRETVALUE; Path=/"] } })],
  ["express-or-node-js-http", web({ headers: { "x-powered-by": "Express" } })],
  ["laravel-application", web({ headers: { "set-cookie": ["laravel_session=SECRETVALUE; path=/; httponly"] } })],
  ["oracle-fusion-middleware", web({ body: page("Welcome to Oracle Fusion Middleware") })],
  ["oracle-intelligence-enterprise-edition", web({ body: page("Oracle Business Intelligence Sign In") })],
  ["progress-telerik-report-server", web({ body: page("Login", "Telerik Report Server") })],
  ["ruby-on-rails-application", web({ headers: { "x-runtime": "0.012345" } })],
  ["telerik-user-interface-ui-for-asp-net-ajax", web({ body: '<script src="/Telerik.Web.UI.WebResource.axd?d=1"></script>' })],
  ["yiiframework-yii", web({ headers: { "set-cookie": ["YII_CSRF_TOKEN=SECRETVALUE"] } })],
  ["yiiframework-yii", web({ body: '<script src="/assets/1a2b3c4d/yii.js"></script>' })],
  ["accellion-fta", web({ body: "secured by Accellion" })],
  ["accellion-fta", web({ status: 302, headers: { location: "/courier/1000@/mail_user_login.html" } })],
  ["crushftp-crushftp", web({ headers: { "set-cookie": ["CrushAuth=SECRETVALUE"] } })],
  ["d-link-multiple-nas-devices", web({ body: page("ShareCenter", "Please Select Your Account") })],
  ["fortra-goanywhere-mft", web({ headers: { server: "GoAnywhere" } })],
  ["fortra-goanywhere-mft", web({ body: "GoAnywhereWebClientContainer" })],
  ["progress-moveit-transfer", web({ body: '<link href="stylesheet_MOVEit.css">' })],
  ["progress-ws-ftp-server", web({ body: page("WS_FTP Server Web Transfer") })],
  ["projectsend-projectsend", web({ body: 'Provided by <a href="https://www.projectsend.org/" target="_blank">ProjectSend</a>' })],
  ["qnap-network-attached-storage-nas", web({ body: page("QNAP Turbo NAS") })],
  ["rejetto-http-file-server", web({ headers: { "set-cookie": ["HFS_SID=SECRETVALUE"] } })],
  ["terramaster-terramaster-os", web({ body: page("TOS Loading") })],
  ["terramaster-terramaster-os", web({ headers: { "x-powered-by": "TerraMaster" } })],
  ["kestra-kestra-oss", web({ body: page("Kestra", '<script>window.KESTRA_UI_PATH = "/ui/";</script>') })],
  ["saltstack-salt", web({ body: page("SaltGUI") })],
  ["citrix-sharefile", web({ body: page("ShareFile Storage Server") })],
  ["microsoft-sharepoint", web({ headers: { sprequestguid: "0000" } })],
  ["onlyoffice-docs", web({ body: '<img src="/images/onlyoffice_logo/logo.png" alt="ONLYOFFICE">' })],
  ["servicenow-utah-vancouver-and-washington-dc-now-platform", web({ body: "ServiceNow <script>window.NOW.x=1; NOW.user.userID='';</script>" })],
  ["sysaid-sysaid-on-prem", web({ body: "SysAid Help Desk Software" })],
  ["istio-or-envoy-admin", web({ headers: { server: "envoy" } })],
];

test("each built rule names its product from the already-collected root page, version-less and guessed when no version is stated", () => {
  const covered = new Set();
  for (const [id, r] of CASES) {
    const s = one(r, id);
    assert.equal(s.length, 1, `${id} matched once`);
    assert.equal(s[0].version, "", `${id}: no version compared`);
    assert.equal(s[0].guessed, true, `${id}: guessed`);
    assert.ok(s[0].evidence && s[0].evidence.length <= 200);
    assert.doesNotMatch(s[0].evidence, /SECRETVALUE/, "cookie values are never kept");
    s[0].catalog.forEach((c) => covered.add(c));
  }
  // the remaining built ids are covered by the version, banner and certificate tests below
  const rest = RULES.flatMap((r) => r.ids).filter((x) => !covered.has(x)).sort();
  assert.deepEqual(rest, ["jenkins", "nakivo-backup-and-replication"]);
});

test("the two-signal rules need both signals; look-alikes do not match", () => {
  assert.equal(one(web({ body: page("Kestra") }), "kestra-kestra-oss").length, 0, "title alone is not Kestra");
  assert.equal(one(web({ body: "ShareCenter" }), "d-link-multiple-nas-devices").length, 0);
  assert.equal(one(web({ body: "ServiceNow window.NOW." }), "servicenow-utah-vancouver-and-washington-dc-now-platform").length, 0);
  assert.equal(one(web({ body: "Spark Jobs" }), "apache-spark").length, 0);
  // a redirect to /jobs/ names Spark only on the Spark UI port
  assert.equal(one(web({ status: 302, headers: { location: "/jobs/" } }, 8080), "apache-spark").length, 0);
  // Ray behind token auth: a 401 with no title is not a product match
  assert.equal(one(web({ status: 401, body: "" }, 8265), "ray-project-ray").length, 0);
  // HugeGraph Studio is not HugeGraph-Server
  assert.equal(one(web({ body: page("HugeGraph Studio") }), "apache-hugegraph-server").length, 0);
  // ASP.NET's generic WebResource.axd (or Sitefinity's) is not Telerik UI
  assert.equal(one(web({ body: '<script src="/WebResource.axd?d=1"></script>' }), "telerik-user-interface-ui-for-asp-net-ajax").length, 0);
  // a redirect Location is read only on a redirect status
  assert.equal(one(web({ status: 200, headers: { location: "/veracore/Home/" } }), "advantive-veracore").length, 0);
  // a plain page names nothing
  assert.deepEqual(appServices(web({ headers: { server: "nginx/1.24.0" }, body: page("Welcome") })), []);
  assert.deepEqual(appServices({ port: 80, state: "closed" }), []);
  assert.deepEqual(appServices(null), []);
});

/* ---- versions: only where the collected data states one, trusted by where it came from ---- */
test("a version stated in a header or greeting is compared and not guessed", () => {
  const j = one(web({ headers: { "x-jenkins": "2.426.1" } }, 8080), "jenkins")[0];
  assert.equal(j.version, "2.426.1"); assert.equal(j.shown_version, "2.426.1"); assert.equal(j.guessed, false); assert.equal(j.proto, "http");
  assert.equal(one(web({ headers: { "x-jenkins": "" } }), "jenkins").length, 0);
  const m = one(web({ headers: { "x-moveitisapi-version": "15.0.1.31" } }, 443), "progress-moveit-transfer")[0];
  assert.equal(m.version, "15.0.1.31"); assert.equal(m.guessed, false);
  const c = one(web({ headers: { server: "CrushFTP HTTP Server Version 10.5.1" } }), "crushftp-crushftp")[0];
  assert.equal(c.version, "10.5.1"); assert.equal(c.guessed, false);
  const c2 = one(web({ headers: { server: "CrushFTP" } }), "crushftp-crushftp")[0];
  assert.equal(c2.version, ""); assert.equal(c2.guessed, true);
  const h = one(web({ headers: { server: "HFS 2.3m" } }), "rejetto-http-file-server")[0];
  assert.equal(h.shown_version, "2.3m"); assert.equal(h.version, "2.3"); assert.equal(h.guessed, false);
  const o = one(web({ headers: { server: "Oracle-Fusion-Middleware/12.2.1.4.0 (Oracle-HTTP-Server)" } }), "oracle-fusion-middleware")[0];
  assert.equal(o.version, "12.2.1.4.0"); assert.equal(o.guessed, false);
  // greeting banners on a non-web port (the FTP greeting the probe already read)
  const w = appServices({ port: 21, state: "open", banner: "220 host X WS_FTP Server 8.7.3(12345)\r\n" })[0];
  assert.deepEqual([w.catalog[0], w.proto, w.version, w.guessed], ["progress-ws-ftp-server", "ftp", "8.7.3", false]);
  const cf = appServices({ port: 21, state: "open", banner: "220 CrushFTP Server Ready!\r\n" })[0];
  assert.deepEqual([cf.catalog[0], cf.version, cf.guessed], ["crushftp-crushftp", "", true]);
});

test("a version printed in the page is compared but stays guessed; a login-page title or a runtime version is shown, never compared", () => {
  const p = one(web({ body: 'Provided by <a href="https://www.projectsend.org/">ProjectSend</a> version 1.2.3 - Free software' }), "projectsend-projectsend")[0];
  assert.equal(p.version, "1.2.3"); assert.equal(p.guessed, true);
  const hf = one(web({ body: '<a href="http://www.rejetto.com/hfs/">HttpFileServer 2.3k</a>' }), "rejetto-http-file-server")[0];
  assert.equal(hf.shown_version, "2.3k"); assert.equal(hf.guessed, true);
  const sy = one(web({ body: 'SysAid Help Desk Software <script src="ajaxTools.js?v=23.3.36"></script>' }), "sysaid-sysaid-server")[0];
  assert.equal(sy.version, "23.3.36"); assert.equal(sy.guessed, true); assert.deepEqual(sy.catalog, ["sysaid-sysaid-on-prem", "sysaid-sysaid-server"]);
  // a bare build number in the cache-buster is not a dotted version: not read
  assert.equal(one(web({ body: 'SysAid Help Desk Software <script src="ajaxTools.js?v=23336"></script>' }), "sysaid-sysaid-server")[0].version, "");
  const ofm = one(web({ body: '<link href="css/fmw_bottom_area.css"><div id="welcome_text">TO ORACLE<strong> FUSION MIDDLEWARE 12.2.1.3</strong>' }), "oracle-fusion-middleware")[0];
  assert.equal(ofm.version, "12.2.1.3"); assert.equal(ofm.guessed, true);
  // NAKIVO: the version is in the login page's title -> shown only
  const n = one(web({ body: page("NAKIVO Backup &amp; Replication v10.11.1") }), "nakivo-backup-and-replication")[0];
  assert.equal(n.shown_version, "10.11.1"); assert.equal(n.version, ""); assert.equal(n.guessed, true);
  assert.match(n.evidence, /login-page title alone never confirms a version/);
  // X-AspNet-Version is the .NET runtime version, not an ASP.NET release
  const a = one(web({ headers: { "x-aspnet-version": "4.0.30319" } }), "asp-net-or-system-web")[0];
  assert.equal(a.shown_version, "4.0.30319"); assert.equal(a.version, ""); assert.equal(a.guessed, true);
  // ServiceNow's g_builddate is a build stamp: evidence only, never a version
  const sn = one(web({ body: "ServiceNow window.NOW.a NOW.user.userID g_builddate = \"08-01-2024_1200\"" }), "servicenow-utah-vancouver-and-washington-dc-now-platform")[0];
  assert.equal(sn.version, ""); assert.equal(sn.shown_version, ""); assert.match(sn.evidence, /g_builddate "08-01-2024_1200" \(not mapped to a release\)/);
});

/* ---- certificate, dedupe, related records ---- */
test("QNAP from the certificate's stated subject; a product already named on the port is not repeated", () => {
  const cert = { subject: { CN: "QNAP NAS", OU: "QTS", O: "QNAP Systems, Inc." }, issuer: { CN: "QNAP NAS" } };
  const alone = appServices({ port: 443, state: "open", banner: "", http: null, tls: { cert } });
  assert.deepEqual(alone.map((s) => [s.catalog[0], s.proto, s.version]), [["qnap-network-attached-storage-nas", "tls", ""]]);
  assert.match(alone[0].evidence, /certificate CN=QNAP NAS/);
  // through the hook, fingerprint.mjs's certificate hint already names QNAP QTS: one record, not two
  const all = servicesOf({ port: 443, state: "open", banner: "", http: { status: 200, headers: {}, body: page("QNAP Turbo NAS") }, tls: { cert } });
  assert.equal(all.filter((s) => s.product === "QTS").length, 1);
  // an unrelated certificate that merely mentions qnap elsewhere does not satisfy this rule
  assert.equal(appServices({ port: 443, state: "open", tls: { cert: { subject: { CN: "nas.example.org", O: "Example" }, issuer: { CN: "QNAP CA" } } } }).length, 0);
});

test("Salt: a SaltGUI / SaltStack Config title is a related web UI, never matched as the Salt master", () => {
  const s = one(web({ body: page("SaltStack Config") }), "saltstack-salt")[0];
  assert.equal(s.product, ""); assert.match(s.label, /not the Salt master/);
});

/* ---- matching and headline counts ---- */
const WB = { built_at: "2026-11-21T12:00:00Z", guides: {}, kev: [
  { cve: "CVE-2026-90901", vendor: "Jenkins", product: "Jenkins", name: "Fixture flaw in Jenkins", added: "2026-11-01", due: "2026-11-10", cvss: 9.8, epss: 0.9, av: "N",
    affected: [{ vendor: "jenkins", product: "jenkins", to: "2.430", to_incl: false }] },
  { cve: "CVE-2026-90902", vendor: "NAKIVO", product: "Backup and Replication", name: "Fixture flaw in NAKIVO", added: "2026-11-01", due: "2026-11-10", cvss: 9.8, epss: 0.9, av: "N",
    affected: [{ vendor: "nakivo", product: "backup_\\&_replication", to: "10.12", to_incl: false }] },
  { cve: "CVE-2026-90903", vendor: "Fortra", product: "GoAnywhere MFT", name: "Fixture flaw in GoAnywhere", added: "2026-11-01", due: "2026-11-10", cvss: 9.8, epss: 0.9, av: "N",
    affected: [{ vendor: "fortra", product: "goanywhere_managed_file_transfer", to: "7.4.1", to_incl: false }] },
] };

test("a stated header version becomes a high-confidence finding; title-only and version-less records stay low and out of the headline counts", () => {
  if (!D.vendorIndex) D.vendorIndex = {};
  const flaws = cleanFlaws(WB);
  const services = [
    ...servicesOf(web({ headers: { "x-jenkins": "2.426.1" } }, 8080)),
    ...servicesOf(web({ body: page("NAKIVO Backup &amp; Replication v10.11.1") }, 4443)),
    ...servicesOf(web({ headers: { server: "GoAnywhere" } }, 8000)),
  ];
  const hosts = [{ address: "127.0.0.1", names: [], public: false, up: true, ports: [], services }];
  const f = findings(hosts, flaws, new Map(), { today: TODAY });
  const by = Object.fromEntries(f.map((x) => [x.cve, x]));
  assert.equal(by["CVE-2026-90901"].state, "affected"); assert.equal(by["CVE-2026-90901"].confidence, "high");
  // the login-page title states 10.11.1 (inside the range) but never yields "affected"
  assert.equal(by["CVE-2026-90902"].state, "check"); assert.equal(by["CVE-2026-90902"].confidence, "low");
  assert.equal(by["CVE-2026-90903"].state, "check"); assert.equal(by["CVE-2026-90903"].confidence, "low");
  const s = summarize(hosts, f);
  assert.equal(s.low_confidence, 2); assert.equal(s.known_exploited, 1);
});

test("collected() keeps cookie NAMES only and reads the Location only from a redirect", () => {
  const ev = collected(web({ status: 301, headers: { "set-cookie": ["a=1; path=/", "laravel_session=SECRETVALUE"], location: "/x" } }));
  assert.deepEqual(ev.cookies, ["a", "laravel_session"]); assert.equal(ev.location, "/x");
  assert.doesNotMatch(JSON.stringify({ ...ev, one: null }), /SECRETVALUE/);
});

/* ---- no extra bytes: the pack reads what the probe already collected ---- */
test("no extra request: a loopback server sees exactly the one GET / while the pack names Jenkins from its header", async () => {
  const seen = [];
  const srv = http.createServer((req, res) => { seen.push(`${req.method} ${req.url}`); res.writeHead(200, { "X-Jenkins": "2.426.1", "Content-Type": "text/html", "Set-Cookie": "JSESSIONID=SECRETVALUE" }); res.end(page("Dashboard [Jenkins]")); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  try {
    const r = await probePort("127.0.0.1", port, { httpPorts: [port] });
    const svcs = servicesOf(r);
    assert.deepEqual(seen, ["GET /"], "the only request is the probe's own GET /");
    const j = svcs.find((s) => s.catalog && s.catalog.includes("jenkins"));
    assert.equal(j.version, "2.426.1");
    assert.doesNotMatch(JSON.stringify(svcs), /SECRETVALUE/);
  } finally { await new Promise((r) => srv.close(r)); }
});

test("no extra probe: probeAll calls the probe once per port, the pack adds services without another call", async () => {
  let calls = 0;
  const probe = async (ip, port) => { calls++; return web({ headers: { server: "envoy" } }, port); };
  const out = await probeAll([{ address: "127.0.0.1", names: [], kind: "loopback", public: false }], { ports: [8080, 9000], settings: settings({}, { hasPublic: false }).settings, probe, assumeUp: true });
  assert.equal(calls, 2);
  assert.equal(out.hosts[0].services.filter((s) => s.catalog && s.catalog[0] === "istio-or-envoy-admin").length, 2);
});
