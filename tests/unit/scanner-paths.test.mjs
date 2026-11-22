// The bounded HTTP path rail (scan-http-paths): a frozen table of reviewed literal paths, hint-gated on evidence the scan
// already collected, GET only, capped per host, every request through the Limiter, redirects recorded not followed, and
// every outcome in coverage. Loopback only: the stand-in web server records every request it receives.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { RAIL, RAIL_PATHS, PATHS_PER_HOST, railEvidence, railPlan, railResult, railCoverage, outcomeOf, pathsPerHost, mmh3, faviconHash, railHeaderText } from "../../scanner/lib/paths.mjs";
import { getPath, USER_AGENT, SENDS } from "../../scanner/lib/probe.mjs";
import { probeAll } from "../../scanner/lib/scan.mjs";
import { settings } from "../../scanner/lib/limits.mjs";
import { STATEMENT } from "../../scanner/lib/scope.mjs";
import { main } from "../../scanner/cyberview-scan.mjs";
import { railProblems, FORBIDDEN_PATH } from "../../scripts/lib/scanner-rail-check.mjs";

const ROOT = new URL("../../", import.meta.url).pathname;
const SNAP = new URL("../fixtures/scanner/snapshot", import.meta.url).pathname;
const LOCAL = [{ address: "127.0.0.1", names: [], kind: "loopback", public: false }];
const page = (title, extra = "") => `<!doctype html><title>${title}</title>${extra}<p>ok</p>`;

/** A loopback web server: "/" answers with root, other paths from routes (default 404); records every request. */
async function web(root, routes = {}) {
  const got = [];
  const srv = http.createServer((req, res) => {
    got.push({ method: req.method, url: req.url, ua: req.headers["user-agent"] });
    const r = req.url === "/" ? root : routes[req.url] || { status: 404, headers: { "Content-Type": "text/plain" }, body: "not found" };
    res.writeHead(r.status || 200, { "Content-Type": "text/html", ...(r.headers || {}) });
    res.end(r.body || "");
  });
  const port = await new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
  return { port, got, seen: () => got.map((x) => `${x.method} ${x.url}`), close: () => new Promise((r) => { srv.closeAllConnections(); srv.close(() => r()); }) };
}
const scan = (s, paths, st = settings({}).settings) => probeAll(LOCAL, { ports: [s.port], httpPorts: [s.port], settings: st, assumeUp: true, paths });
const ON = { enabled: true };

/* ---- the frozen table ---- */
test("the table is frozen data: 50 reviewed rows, 39 literal paths, none login/management/exploit-class, cap 8", () => {
  assert.equal(RAIL.length, 50); assert.equal(RAIL_PATHS.length, 39); assert.equal(PATHS_PER_HOST, 8);
  assert.ok(Object.isFrozen(RAIL) && Object.isFrozen(RAIL_PATHS) && RAIL.every((e) => Object.isFrozen(e) && Object.isFrozen(e.paths)));
  assert.equal(new Set(RAIL.map((e) => e.id)).size, 50);
  for (const p of RAIL_PATHS) { assert.match(p, /^\/[A-Za-z0-9_.\-\/]*$/); assert.equal(FORBIDDEN_PATH.test(p), false, p); }
  assert.throws(() => { RAIL_PATHS.push("/x"); });
  // the BMC rows are a separate opt-in group
  assert.deepEqual(RAIL.filter((e) => e.group === "bmc").map((e) => e.id).sort(), ["ami-megarac-spx", "redfish-service-root"]);
});

test("getPath refuses any path that is not a frozen literal, before connecting", async () => {
  const s = await web({ body: page("x") });
  try {
    for (const p of ["/login", "/", "/version?x=1", "/../etc/passwd", "/VERSION", "", null, "/api/v1/version/../x"]) {
      const r = await getPath("127.0.0.1", s.port, p);
      assert.equal(r.status, 0); assert.match(r.error, /refused/);
    }
    assert.deepEqual(s.got, []);
  } finally { await s.close(); }
});

/* ---- gating ---- */
test("flag off: even a hinted host gets GET / and nothing else", async () => {
  const s = await web({ body: page("MLflow") }, { "/version": { body: "2.9.2" } });
  try {
    const r = await scan(s, null);
    assert.deepEqual(s.seen(), ["GET /"]);
    assert.equal(r.hosts[0].rail, undefined); assert.deepEqual(r.paths, { enabled: false });
    assert.equal(r.hosts[0]._railEv, undefined);
  } finally { await s.close(); }
});

test("flag on, unhinted host: the server sees only GET /", async () => {
  const s = await web({ body: page("Fixture intranet"), headers: { Server: "nginx/1.22.1" } });
  try {
    const r = await scan(s, ON);
    assert.deepEqual(s.seen(), ["GET /"]);
    assert.equal(r.hosts[0].rail, undefined);
    assert.equal(r.stats.connections, 1);
  } finally { await s.close(); }
});

test("flag on, hinted host: only that entry's frozen paths, all GET with the scanner's User-Agent; the version token is parsed", async () => {
  const s = await web({ body: page("MLflow") }, { "/health": { body: "OK", headers: { "Content-Type": "text/plain" } }, "/version": { body: "2.9.2", headers: { "Content-Type": "text/plain" } } });
  try {
    const r = await scan(s, ON), h = r.hosts[0];
    assert.deepEqual(s.seen(), ["GET /", "GET /health", "GET /version"]);
    assert.ok(s.got.every((x) => x.method === "GET" && x.ua === USER_AGENT));
    assert.equal(r.stats.connections, 3);   // each rail request took a Limiter slot and counts in the budgets
    assert.deepEqual(h.rail.map((x) => [x.path, x.status, x.outcome]), [["/health", 200, "ok"], ["/version", 200, "ok"]]);
    const ml = h.services.filter((x) => x.product === "MLflow");
    assert.equal(ml.length, 1); assert.equal(ml[0].shown_version, "2.9.2"); assert.equal(ml[0].guessed, false);
    assert.match(ml[0].source, /path rail, mlflow-mlflow/);
    // the body is never kept: only status, outcome and the parsed token
    assert.equal(JSON.stringify(h.rail).includes("<title>"), false);
    for (const rec of h.rail) assert.deepEqual(Object.keys(rec).sort(), ["for", "found", "outcome", "path", "port", "status"]);
  } finally { await s.close(); }
});

test("the per-host cap holds across many hints, and every hinted path over it is recorded as not sent", async () => {
  const body = page("NETGEAR Router DGN2200 Prometheus Time Series Collection and Processing Server", '<meta name="generator" content="WordPress 6.4"><link href="/wp-content/x.css"><a href="/_sitecore/y">micollab</a> Portainer');
  const s = await web({ body });
  try {
    const r = await scan(s, ON), h = r.hosts[0];
    const extra = s.seen().filter((x) => x !== "GET /");
    assert.equal(extra.length, PATHS_PER_HOST);
    assert.ok(extra.every((x) => x.startsWith("GET ") && RAIL_PATHS.includes(x.slice(4))));
    const notSent = h.rail.filter((x) => x.outcome === "not-sent: per-host cap");
    assert.ok(notSent.length > 0);
    assert.equal(h.rail.length, PATHS_PER_HOST + notSent.length);
    // a lower --paths-per-host is honoured
    s.got.length = 0;
    await scan(s, { enabled: true, perHost: 3 });
    assert.equal(s.seen().filter((x) => x !== "GET /").length, 3);
    // and a higher one is never: the hard cap wins
    s.got.length = 0;
    await scan(s, { enabled: true, perHost: 50 });
    assert.equal(s.seen().filter((x) => x !== "GET /").length, PATHS_PER_HOST);
  } finally { await s.close(); }
});

test("rail requests count against the host budget (the Limiter), and what the budget stops is recorded", async () => {
  const s = await web({ body: page("MLflow") }, { "/health": { body: "OK" }, "/version": { body: "2.9.2" } });
  try {
    const r = await scan(s, ON, settings({ hostBudget: 2 }).settings);
    assert.deepEqual(s.seen(), ["GET /", "GET /health"]);
    assert.deepEqual(r.hosts[0].rail.map((x) => x.outcome), ["ok", "not-sent: budget or time"]);
  } finally { await s.close(); }
});

test("a redirect on a rail path is recorded, never followed; 401 and 404 are recorded in coverage", async () => {
  const s = await web({ body: page("MLflow") }, { "/health": { status: 302, headers: { Location: "/elsewhere" } }, "/version": { status: 401, headers: { "WWW-Authenticate": "Basic" } } });
  try {
    const r = await scan(s, ON), h = r.hosts[0];
    assert.deepEqual(s.seen(), ["GET /", "GET /health", "GET /version"]);   // /elsewhere never requested
    assert.deepEqual(h.rail.map((x) => [x.path, x.status, x.outcome, x.location || ""]), [["/health", 302, "redirect", "/elsewhere"], ["/version", 401, "unauthorized", ""]]);
    assert.equal(h.services.some((x) => x.product === "MLflow"), false);   // nothing parsed from a non-200
    const cov = railCoverage(r.hosts, { enabled: true, perHost: 8 });
    assert.equal(cov.requests, 2); assert.deepEqual(cov.by_outcome, { redirect: 1, unauthorized: 1 });
    assert.deepEqual(cov.not_ok.map((x) => x.outcome), ["redirect", "unauthorized"]);
  } finally { await s.close(); }
  const t = await web({ body: page("MLflow") });   // every rail path 404
  try {
    const r = await scan(t, ON);
    assert.deepEqual(railCoverage(r.hosts, { enabled: true }).by_outcome, { "not-found": 2 });
  } finally { await t.close(); }
});

test("outcomes: ok, redirect, unauthorized, forbidden, not-found, other, timeout, error", () => {
  assert.deepEqual([{ status: 200 }, { status: 301 }, { status: 401 }, { status: 403 }, { status: 404 }, { status: 500 }, { status: 0, error: "timeout" }, null, { status: 0, error: "ECONNREFUSED" }].map(outcomeOf),
    ["ok", "redirect", "unauthorized", "forbidden", "not-found", "http-500", "timeout", "timeout", "error"]);
});

/* ---- hints (pure) ---- */
const ev = (port, { title = "", headers = {}, body = "", cert = null, status = 200 } = {}) => railEvidence(port, { http: { status, headers, body: (title ? `<title>${title}</title>` : "") + body }, tls: cert ? { cert } : null });
const ids = (evs, o) => railPlan(evs, o).plan.flatMap((x) => x.ids);
test("hints read only the evidence already collected: title, headers, cookie names, redirect, certificate, port", () => {
  assert.deepEqual(ids([ev(80, { title: "Intranet" })]), []);
  assert.deepEqual(ids([ev(80, { title: "Apache Flink Web Dashboard" })]), ["apache-flink"]);
  assert.deepEqual(ids([ev(2375)]), ["docker-engine-api"]);
  assert.deepEqual(ids([ev(80, { headers: { server: "MinIO" } })]), ["minio"]);
  assert.deepEqual(ids([ev(80, { status: 302, headers: { location: "https://vpn.example/dana-na/auth/url_default/welcome.cgi" } })]), ["pulse-secure-pulse-connect-secure"]);
  assert.deepEqual(ids([ev(80, { headers: { "set-cookie": ["SC_ANALYTICS_GLOBAL_COOKIE=abc; path=/"] } })]), ["sitecore-xp"]);
  assert.deepEqual(ids([ev(80, { headers: { "x-generator": "Drupal 7 (https://www.drupal.org)" } })]), ["drupal-core"]);
  assert.deepEqual(ids([ev(443, { cert: { subject: { CN: "Puppet CA: pe.example" }, issuer: { CN: "Puppet CA: pe.example" } } })]), ["perforce-puppet-enterprise"]);
  // shared paths are requested once per port and parsed for every hinted row
  const p = railPlan([ev(80, { title: "NETGEAR Router DGN2200" })]).plan;
  assert.deepEqual(p.map((x) => x.path), ["/currentsetting.htm", "/settingsJGS516.gif"]);
  assert.deepEqual(p[0].ids, ["netgear-dgn2200-devices", "netgear-multiple-routers", "netgear-wireless-router-dgn2200"]);
  // cookie values are never kept in the evidence, names only
  assert.deepEqual(ev(80, { headers: { "set-cookie": ["mage-cache-storage=SECRETVALUE"] } }).cookies, ["mage-cache-storage"]);
  assert.equal(JSON.stringify(ev(80, { headers: { "set-cookie": ["a=SECRETVALUE"] } })).includes("SECRETVALUE"), false);
});

test("BMC identify stays opt-in: the AMI certificate hints only with bmc on", () => {
  const ami = ev(443, { cert: { subject: { CN: "AMI", OU: "Service Processors", O: "American Megatrends Inc" }, issuer: { CN: "AMI" } } });
  assert.deepEqual(ids([ami]), []);
  assert.deepEqual(ids([ami], { bmc: true }), ["ami-megarac-spx", "redfish-service-root"]);
  assert.deepEqual(railPlan([ami], { bmc: true }).plan.map((x) => x.path), ["/redfish/v1/"]);
});

/* ---- parsers (canned responses) ---- */
const res = (body, headers = {}, status = 200) => ({ status, headers, body: Buffer.isBuffer(body) ? body.toString("latin1") : body, raw: Buffer.isBuffer(body) ? body : Buffer.from(body) });
const parse = (id, path, r) => railResult({ port: 80, tls: false, path, ids: [id] }, r);
const one = (id, path, r) => { const s = parse(id, path, r).services; return s.length ? `${s[0].vendor}|${s[0].product}|${s[0].shown_version}|${s[0].version}|${s[0].guessed}` : null; };
test("parsers keep at most a product and version token", () => {
  assert.equal(one("kubernetes-api-version", "/version", res('{"major":"1","minor":"28","gitVersion":"v1.28.2","platform":"linux/amd64"}')), "Kubernetes|Kubernetes|1.28.2|1.28.2|false");
  assert.equal(one("etcd-version", "/version", res('{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}')), "etcd|etcd|3.5.9|3.5.9|false");
  assert.equal(one("docker-engine-api", "/version", res('{"Version":"24.0.7","ApiVersion":"1.43"}')), "Docker|Docker Engine|24.0.7|24.0.7|false");
  assert.equal(one("docker-engine-api", "/version", res('{"etcdserver":"3.5.9"}')), null);   // another product's document
  assert.equal(one("drupal-core", "/CHANGELOG.txt", res("\nDrupal 7.98, 2023-06-07\n-----\n")), "Drupal|Drupal|7.98|7.98|false");
  assert.equal(one("netgear-dgn2200-devices", "/currentsetting.htm", res("Firmware=V1.0.0.50_7.0.50\r\nRegionTag=DGN2200_WW\r\nModel=DGN2200v4\r\n")), "NETGEAR|DGN2200v4 Firmware|1.0.0.50_7.0.50|1.0.0.50|false");
  assert.equal(one("netgear-dgn2200-devices", "/currentsetting.htm", res("Firmware=V1.0.0.1\r\nModel=R7000\r\n")), null);   // not this model
  assert.equal(one("sitecore-xp", "/sitecore/shell/sitecore.version.xml", res("<information><version><major>9</major><minor>3</minor><build>0</build><revision>003498</revision></version><company>Sitecore Corporation</company></information>")), "Sitecore|Experience Platform|9.3.0|9.3.0|false");
  assert.equal(one("wordpress-file-manager-plugin", "/wp-content/plugins/wp-file-manager/readme.txt", res("=== File Manager ===\nStable tag: 6.8\n")), "webdesi9|File Manager (WordPress plugin)|6.8|6.8|false");
  assert.equal(one("mitel-micollab", "/ucs/micollab/version.json", res('{"version":"9.8.1.5"}')), "Mitel|MiCollab|9.8.1.5|9.8.1.5|false");
  assert.equal(one("hashicorp-vault", "/v1/sys/health", res('{"initialized":true,"sealed":false,"version":"1.15.2"}')), "HashiCorp|Vault|1.15.2|1.15.2|false");
  assert.equal(one("kibana-login-or-status-path", "/api/status", res('{"version":{"number":"8.11.1"}}')), "Elastic|Kibana|8.11.1|8.11.1|false");
  assert.equal(one("plex-media-server", "/identity", res('<?xml version="1.0"?><MediaContainer size="0" claimed="1" machineIdentifier="x" version="1.32.5.7349-8f4248874"></MediaContainer>')), "Plex|Plex Media Server|1.32.5.7349|1.32.5.7349|false");
  // build numbers that are not the release naming NVD's ranges use: shown, never compared
  assert.equal(one("pulse-secure-pulse-connect-secure", "/dana-na/nc/nc_gina_ver.txt", res('<PARAM NAME="ProductVersion" VALUE="9.1.11.10541">')), "Ivanti|Connect Secure|9.1.11.10541||true");
  assert.equal(one("adobe-magento-commerce", "/magento_version", res("Magento/2.4 (Community)")), "Adobe|Magento|2.4||true");
  // presence only: no version, so it stays guessed (out of the headline counts)
  assert.equal(one("berriai-litellm", "/health/liveliness", res('"I\'m alive!"')), "BerriAI|LiteLLM|||true");
  assert.equal(one("minio", "/minio/health/live", res("", { server: "MinIO" })), "MinIO|MinIO|||true");
  // nothing is parsed from a non-200, and the record keeps no body
  const r = parse("drupal-core", "/CHANGELOG.txt", res("Drupal 7.98, 2023", {}, 404));
  assert.deepEqual(r.services, []); assert.equal(JSON.stringify(r.record).includes("Drupal 7.98"), false);
});

test("static-asset rows need the reviewed status/content pair, so a generic 404 or error page never matches", () => {
  const ico = Buffer.from([0, 0, 1, 0, 1, 0, 16, 16]);
  assert.equal(one("samsung-magicinfo-9-server", "/MagicInfo/logo.ico", res(ico, { "content-type": "image/x-icon" })), "Samsung|MagicINFO 9 Server|||true");
  assert.equal(one("samsung-magicinfo-9-server", "/MagicInfo/logo.ico", res("<html>MagicInfo logo not here</html>", { "content-type": "text/html" })), null);
  assert.equal(one("samsung-magicinfo-9-server", "/MagicInfo/logo.ico", res(ico, { "content-type": "image/x-icon" }, 404)), null);
  assert.equal(one("netgear-jgs516pe-devices", "/settingsJGS516.gif", res(Buffer.from("GIF89a\x01\x00", "latin1"), { "content-type": "image/gif" })), "NETGEAR|JGS516PE Firmware|||true");
  assert.equal(one("netgear-jgs516pe-devices", "/settingsJGS516.gif", res("<html></html>", { "content-type": "text/html" })), null);
});

test("favicon hash: murmur3 matches the published vectors; only a matching icon names SonicWall Email Security", () => {
  assert.equal(mmh3(Buffer.from("foo")), -156908512);
  assert.equal(mmh3(Buffer.from("hello")), 613153351);
  assert.equal(mmh3(Buffer.alloc(0)), 0);
  const icon = Buffer.from("not the sonicwall icon");
  assert.notEqual(faviconHash(icon), 2063459123);
  assert.equal(one("sonicwall-sonicwall-email-security", "/favicon.ico", res(icon, { "content-type": "image/x-icon" })), null);
});

/* ---- settings, CLI, header and report ---- */
test("--paths-per-host can only lower the cap; the rail options need --paths", async () => {
  assert.deepEqual(pathsPerHost(undefined), { ok: true, value: 8 });
  assert.deepEqual(pathsPerHost("3"), { ok: true, value: 3 });
  assert.equal(pathsPerHost("9").ok, false); assert.match(pathsPerHost(16).problem, /only be lowered/);
  assert.equal(pathsPerHost("0").ok, false); assert.equal(pathsPerHost("2.5").ok, false);
  const d = mkdtempSync(join(tmpdir(), "cvpaths-")), p = join(d, "scope.json");
  writeFileSync(p, JSON.stringify({ cyberview_scope: 1, owner: "Example lab", contact: "lab@example.org", attestation: { statement: STATEMENT, agreed: true, name: "Test Operator", date: "2026-11-20", expires: "", authorization_ref: "test" }, targets: ["127.0.0.1"], exclude: [] }));
  const io = () => { const out = [], err = []; return { out: (s) => out.push(s), err: (s) => err.push(s), sleep: async () => {}, publicWaitMs: 0, lines: { out, err } }; };
  let x = io(); assert.equal(await main(["check", "--scope", p, "--paths", "--paths-per-host", "9"], x), 2); assert.match(x.lines.err.join("\n"), /ceiling of 8/);
  x = io(); assert.equal(await main(["check", "--scope", p, "--paths-bmc"], x), 2); assert.match(x.lines.err.join("\n"), /need --paths/);
  x = io(); assert.equal(await main(["check", "--scope", p], x), 0); assert.match(x.lines.out.join("\n"), /Path rail: +off \(--paths not given\): web ports get one GET \/ and nothing else/);
  x = io(); assert.equal(await main(["check", "--scope", p, "--paths", "--paths-per-host", "4"], x), 0);
  const head = x.lines.out.join("\n");
  assert.match(head, /Path rail: +on \(--paths\): at most 4 extra GET request\(s\) per host \(hard cap 8\)/); assert.match(head, /BMC identify off/);
  assert.match(head, /paths +only with --paths \(off by default\): at most 8 extra HTTP GET requests per host/);
  assert.match(SENDS.paths, /redirects recorded, not followed/);
  assert.match(railHeaderText({ enabled: true, perHost: 8, bmc: true }), /BMC identify on/);
});

test("end to end: --paths writes every rail request's status in coverage and the host, the parsed token in services, and no body", async () => {
  const s = await web({ body: page("MLflow") }, { "/health": { status: 404, body: "no" }, "/version": { body: "2.9.2", headers: { "Content-Type": "text/plain" } } });
  const d = mkdtempSync(join(tmpdir(), "cvpaths-")), p = join(d, "scope.json"), out = join(d, "out");
  writeFileSync(p, JSON.stringify({ cyberview_scope: 1, owner: "Example lab", contact: "lab@example.org", attestation: { statement: STATEMENT, agreed: true, name: "Test Operator", date: "2026-11-20", expires: "", authorization_ref: "test" }, targets: ["127.0.0.1"], exclude: [] }));
  const lines = [];
  const io = { out: (x) => lines.push(x), err: (x) => lines.push(x), sleep: async () => {}, publicWaitMs: 0, resolve: async () => { throw new Error("no DNS"); } };
  try {
    const code = await main(["scan", "--scope", p, "--data", SNAP, "--ports", String(s.port), "--http-ports", String(s.port), "--assume-up", "--paths", "--out", out], io);
    assert.ok([0, 2].includes(code), lines.join("\n"));
    assert.deepEqual(s.seen(), ["GET /", "GET /health", "GET /version"]);
    const rep = JSON.parse(readFileSync(join(out, "report.json"), "utf8"));
    assert.deepEqual(rep.run.paths, { enabled: true, per_host: 8, bmc: false });
    assert.equal(rep.coverage.paths.requests, 2); assert.deepEqual(rep.coverage.paths.by_outcome, { "not-found": 1, ok: 1 });
    assert.deepEqual(rep.coverage.paths.not_ok.map((x) => [x.path, x.status]), [["/health", 404]]);
    assert.deepEqual(rep.hosts[0].paths.map((x) => [x.path, x.outcome, x.found]), [["/health", "not-found", []], ["/version", "ok", ["MLflow 2.9.2"]]]);
    assert.ok(rep.hosts[0].services.some((x) => x.product === "MLflow" && x.shown_version === "2.9.2"));
    assert.ok(rep.run.network.sends.paths);
    assert.match(readFileSync(join(out, "summary.txt"), "utf8"), /Path rail \(--paths, at most 8 per host\): 2 extra GET request\(s\) — 1 not-found, 1 ok/);
    assert.equal(readFileSync(join(out, "report.json"), "utf8").includes("<title>MLflow"), false);
  } finally { await s.close(); }
  // the same scan without --paths: one GET / only, and the report says the rail was off
  const t = await web({ body: page("MLflow") }, { "/version": { body: "2.9.2" } });
  const out2 = join(d, "out2");
  try {
    await main(["scan", "--scope", p, "--data", SNAP, "--ports", String(t.port), "--http-ports", String(t.port), "--assume-up", "--out", out2], io);
    assert.deepEqual(t.seen(), ["GET /"]);
    const rep = JSON.parse(readFileSync(join(out2, "report.json"), "utf8"));
    assert.deepEqual(rep.run.paths, { enabled: false }); assert.equal(rep.coverage.paths.enabled, false); assert.equal(rep.hosts[0].paths, undefined);
  } finally { await t.close(); }
});

/* ---- section 7 of the security check ---- */
test("security check: passes on the tree, and fails on a computed path, a non-GET method, a cap over 16 or a forbidden path", async () => {
  const r = spawnSync(process.execPath, [join(ROOT, "scripts/security-check.mjs")], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /path rail: 39 frozen literal path\(s\), GET only, at most 8 per host/);
  const src = (f) => readFileSync(join(ROOT, f), "utf8");
  const base = { pathsSrc: src("scanner/lib/paths.mjs"), probeSrc: src("scanner/lib/probe.mjs"), scanSrc: src("scanner/lib/scan.mjs"), mod: await import("../../scanner/lib/paths.mjs") };
  assert.deepEqual(railProblems(base), []);
  const bad = (patch, re) => { const p = railProblems({ ...base, ...patch }); assert.ok(p.some((x) => re.test(x)), p.join("\n") || "no problem reported"); };
  // (a) built from data instead of a literal
  bad({ pathsSrc: base.pathsSrc.replace('paths: ["/api/v1/version"], hint: any(T(/\\bAirflow', "paths: [ev.location], hint: any(T(/\\bAirflow") }, /not a plain string literal/);
  bad({ pathsSrc: base.pathsSrc.replace('paths: ["/config"]', "paths: dynamicList") }, /must be a literal array/);
  bad({ probeSrc: base.probeSrc.replace('if (typeof path !== "string" || !RAIL_PATHS.includes(path)) return', "if (typeof path !== \"string\") return") }, /must first refuse/);
  bad({ probeSrc: base.probeSrc.replace('path: railPath && RAIL_PATHS.includes(railPath) ? railPath : "/"', "path: railPath || \"/\"") }, /request path must be/);
  bad({ scanSrc: base.scanSrc.replace("getPath(h.address, item.port, item.path,", "getPath(h.address, item.port, ev.location,") }, /planned rail item/);
  bad({ otherSrcs: [{ file: "scanner/lib/other.mjs", src: "getPath(ip, 80, x)" }] }, /only scanner\/lib\/scan\.mjs may call/);
  // (b) a method other than GET
  bad({ probeSrc: base.probeSrc.replace('method: "GET"', 'method: "HEAD"') }, /must be method "GET"/);
  bad({ pathsSrc: base.pathsSrc + '\nconst x = { method: "POST" };' }, /GET only/);
  // (c) the cap
  bad({ pathsSrc: base.pathsSrc.replace("export const PATHS_PER_HOST = 8;", "export const PATHS_PER_HOST = 17;") }, /PATHS_PER_HOST must be a literal from 1 to 16/);
  bad({ mod: { ...base.mod, PATHS_PER_HOST: 32 } }, /above 16/);
  // (d) forbidden paths
  for (const p of ["/user/login", "/signin", "/cgi-bin/x.cgi", "/actuator/env", "/heapdump", "/phpinfo.php", "/console", "/server-status", "/_cat/indices", "/_search", "/_all_dbs", "/graphql", "/xmlrpc.php", "/soap", "/.env"])
    bad({ pathsSrc: base.pathsSrc.replace('paths: ["/config"]', `paths: ["${p}"]`) }, /exploit-class|not a plain literal/);
  bad({ pathsSrc: base.pathsSrc.replace('paths: ["/config"]', 'paths: ["/config?x=1"]') }, /not a plain literal path/);
  // a runtime table that holds a path not written as a literal
  bad({ mod: { ...base.mod, RAIL_PATHS: Object.freeze([...base.mod.RAIL_PATHS, "/injected"]) } }, /not a literal in the source/);
});
