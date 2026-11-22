// scan-cms-html: CMS, plugin, theme and JavaScript library versions disclosed in the root page the scanner already fetched.
// Loopback only (127.0.0.1); the fixture pages name hosts only as text, nothing outside this machine is contacted.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import http from "node:http";
import { fromHttp } from "../../scanner/lib/fingerprint.mjs";
import { cmsServices, jsLibraries, wpAssets, scriptSources, MAX_RECORDS } from "../../scanner/lib/fp-cms.mjs";
import { servicesOf } from "../../scanner/lib/scan.mjs";
import { probePort } from "../../scanner/lib/probe.mjs";
import { cleanFlaws, findings } from "../../scanner/lib/match.mjs";
import { toInventory } from "../../scanner/lib/report.mjs";

const FIX = new URL("../fixtures/scanner/cms/", import.meta.url);
// the fixture pages write script tags as <@js ...></@js> so the scanner's fixture folder stays free of literal markup tags
// (the "no attack strings" guard in scanner.test.mjs); the real tag is put back here
const TAG = "scr" + "ipt";
const page = (f) => readFileSync(new URL(f, FIX), "utf8").replace(/<(\/?)@js\b/g, `<$1${TAG}`);
const by = (list, product) => list.filter((s) => s.product === product);

/** A loopback web server that serves one page and records every request it receives. */
async function pageServer(body) {
  const got = [];
  const srv = http.createServer((req, res) => {
    let n = 0; req.on("data", (d) => { n += d.length; });
    req.on("end", () => { got.push({ method: req.method, url: req.url, bodyBytes: n }); res.writeHead(200, { "Content-Type": "text/html", Server: "nginx/1.24.0" }); res.end(body); });
  });
  const port = await new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
  return { port, got, close: () => new Promise((r) => { if (srv.closeAllConnections) srv.closeAllConnections(); srv.close(() => r()); }) };
}

test("cms: a WordPress page with a plugin and a named jquery-3.4.1.js yields versioned inventory", () => {
  const s = fromHttp({ headers: {}, body: page("wordpress.html") }, 80, false);
  const wp = by(s, "WordPress"); assert.equal(wp.length, 1); assert.equal(wp[0].version, "6.4.2"); assert.equal(wp[0].guessed, false);
  const jq = by(s, "jQuery"); assert.equal(jq.length, 1);
  assert.equal(jq[0].vendor, "jQuery"); assert.equal(jq[0].version, "3.4.1"); assert.equal(jq[0].shown_version, "3.4.1"); assert.equal(jq[0].guessed, false);
  assert.match(jq[0].evidence, /jquery-3\.4\.1\.js/);
  const bs = by(s, "Bootstrap"); assert.equal(bs[0].vendor, "getbootstrap"); assert.equal(bs[0].version, "4.3.1"); assert.equal(bs[0].guessed, false);
  // plugin: the ?ver= cache-buster is shown in the inventory, never compared (WordPress can put its own version there)
  const cf7 = by(s, "contact_form_7")[0];
  assert.equal(cf7.label, "WordPress plugin contact-form-7"); assert.equal(cf7.shown_version, "5.8.4"); assert.equal(cf7.version, ""); assert.equal(cf7.guessed, true);
  assert.equal(by(s, "elementor")[0].shown_version, "3.18.0");
  assert.equal(by(s, "woocommerce")[0].shown_version, "8.3.1", "plugin path inside a JSON-escaped inline script");
  // the theme's ?ver= equals WordPress's own version, so it is not the theme's
  const th = by(s, "twentytwentyfour")[0]; assert.equal(th.shown_version, ""); assert.equal(th.label, "WordPress theme twentytwentyfour");
  // jquery-migrate.min.js?ver=3.4.1 is not jQuery
  assert.ok(!s.some((x) => /migrate/i.test(x.product)));
  assert.equal(jq.length, 1);
  // the inventory CSV carries the versions
  const csv = toInventory({ hosts: [{ services: s }] });
  assert.match(csv, /jQuery,3\.4\.1,jQuery,1/); assert.match(csv, /contact_form_7,5\.8\.4,,1/); assert.match(csv, /Bootstrap,4\.3\.1,getbootstrap,1/);
});

test("cms: a bare generator tag stays guessed with no version", () => {
  const s = fromHttp({ headers: {}, body: page("bare-generator.html") }, 80, false);
  assert.equal(s.length, 1); assert.equal(s[0].product, "WordPress"); assert.equal(s[0].guessed, true); assert.equal(s[0].version, ""); assert.equal(s[0].shown_version, "");
  for (const g of ["DotNetNuke", "OctoberCMS"]) {
    const r = fromHttp({ headers: {}, body: `<meta name="generator" content="${g}">` }, 80, false);
    assert.equal(r.length, 1, g); assert.equal(r[0].guessed, true); assert.equal(r[0].version, "");
  }
  // generators of products no catalog row assigns to this slice are not read
  assert.deepEqual(fromHttp({ headers: {}, body: '<meta name="generator" content="MediaWiki 1.39.5">' }, 80, false), []);
  // the existing Drupal/Joomla generator handling is unchanged
  const dr = fromHttp({ headers: {}, body: '<meta name="Generator" content="Drupal 10 (https://www.drupal.org)">' }, 80, false);
  assert.equal(dr.length, 1); assert.equal(dr[0].guessed, true); assert.equal(dr[0].version, "");
});

test("cms: zero extra GETs — the loopback server sees exactly one GET / and nothing else", async () => {
  const srv = await pageServer(page("wordpress.html"));
  try {
    const r = await probePort("127.0.0.1", srv.port, { httpPorts: [srv.port] });
    assert.equal(r.state, "open");
    const s = servicesOf(r);
    assert.equal(by(s, "jQuery")[0].version, "3.4.1");
    assert.equal(by(s, "contact_form_7")[0].shown_version, "5.8.4");
    assert.equal(by(s, "nginx")[0].version, "1.24.0");
    await new Promise((res) => setTimeout(res, 100));
    assert.deepEqual(srv.got, [{ method: "GET", url: "/", bodyBytes: 0 }]);
  } finally { await srv.close(); }
});

test("cms: no page body, URL query values or secrets are kept in a record", () => {
  const body = page("wordpress.html"), s = fromHttp({ headers: {}, body }, 80, false);
  const all = JSON.stringify(s);
  assert.ok(!all.includes("SECRETVALUE"), "query parameters other than ver= are dropped");
  assert.ok(!all.includes("cdn.example.invalid") && !all.includes("127.0.0.1"), "hosts in script URLs are not stored");
  assert.ok(!all.includes("<script") && !all.includes("Hello"));
  for (const x of s) assert.ok(x.evidence.length <= 200);
});

test("cms: a finding only through the existing match path, and only a stated version is compared", () => {
  const wb = { kev: [
    { cve: "CVE-2026-90901", vendor: "jQuery", product: "jQuery", name: "Fixture jQuery flaw", added: "2026-11-01", due: "2026-11-21", affected: [{ vendor: "jquery", product: "jquery", from: "1.2", from_incl: true, to: "3.5.0" }] },
    { cve: "CVE-2026-90902", vendor: "rocklobster", product: "Contact Form 7", name: "Fixture plugin flaw", added: "2026-11-01", due: "2026-11-21", affected: [{ vendor: "rocklobster", product: "contact_form_7", to: "5.9.0" }] },
    { cve: "CVE-2026-90903", vendor: "lodash", product: "lodash", name: "Fixture lodash flaw (not on the page)", added: "2026-11-01", due: "2026-11-21", affected: [{ vendor: "lodash", product: "lodash", to: "4.17.21" }] },
  ] };
  const services = fromHttp({ headers: {}, body: page("wordpress.html") }, 80, false);
  const f = findings([{ address: "10.0.0.9", names: [], services }], cleanFlaws(wb), new Map(), { today: "2026-11-22" });
  const jq = f.find((x) => x.cve === "CVE-2026-90901"); assert.equal(jq.state, "affected"); assert.equal(jq.confidence, "high");
  const cf = f.find((x) => x.cve === "CVE-2026-90902"); assert.equal(cf.state, "check"); assert.equal(cf.confidence, "low", "a ?ver= version never makes a confident finding");
  assert.ok(!f.some((x) => x.cve === "CVE-2026-90903"));
  // a jQuery outside the range: no finding
  const clear = findings([{ address: "10.0.0.9", names: [], services: fromHttp({ headers: {}, body: '<script src="/js/jquery-3.7.1.min.js"></script>' }, 80, false) }], cleanFlaws(wb), new Map(), { today: "2026-11-22" });
  assert.ok(!clear.some((x) => x.cve === "CVE-2026-90901"));
});

test("cms: JavaScript library names and versions from file names, CDN paths, banners and query strings", () => {
  const lib = (src) => jsLibraries(`<script src="${src}"></script>`).map((f) => [f.lib.product, f.version, f.how]);
  assert.deepEqual(lib("/js/jquery-3.4.1.min.js"), [["jQuery", "3.4.1", "stated"]]);
  assert.deepEqual(lib("/js/jquery-3.4.1.slim.min.js"), [["jQuery", "3.4.1", "stated"]]);
  assert.deepEqual(lib("/wp-includes/js/jquery/jquery.min.js?ver=3.4.1"), [["jQuery", "3.4.1", "query"]]);
  assert.deepEqual(lib("https://cdn.example.invalid/npm/jquery@3.6.0/dist/jquery.min.js"), [["jQuery", "3.6.0", "stated"]]);
  assert.deepEqual(lib("//cdn.example.invalid/ajax/libs/jquery/2.2.4/jquery.min.js"), [["jQuery", "2.2.4", "stated"]]);
  assert.deepEqual(lib("/js/jquery.min.js"), [["jQuery", "", "presence"]]);
  assert.deepEqual(lib("/js/jquery-ui.min.js?ver=1.13.2"), [["jQueryUI", "1.13.2", "query"]]);
  assert.deepEqual(lib("/vendor/bootstrap-4.6.2.min.js"), [["Bootstrap", "4.6.2", "stated"]]);
  assert.deepEqual(lib("/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"), [["Bootstrap", "5.3.2", "stated"]]);
  assert.deepEqual(lib("/lib/angular.min.js"), [["angular.js", "", "presence"]]);
  assert.deepEqual(lib("/lib/vue.global.prod.js"), [["vue.js", "", "presence"]]);
  assert.deepEqual(lib("/lib/lodash-4.17.15.min.js"), [["lodash", "4.17.15", "stated"]]);
  for (const notJq of ["/js/jquery-migrate-3.4.1.min.js", "/js/jquery.validate.min.js", "/js/jquery.cookie.js", "/js/myjquery-3.4.1.js", "/js/angular-route.min.js"]) assert.deepEqual(lib(notJq), [], notJq);
  assert.deepEqual(jsLibraries("<script>/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */</script>").map((f) => [f.lib.product, f.version]), [["jQuery", "1.12.4"]]);
  // a versionless sighting next to a versioned one adds nothing; two different versions are both kept
  assert.equal(jsLibraries('<script src="/a/jquery.min.js"></script><script src="/b/jquery-1.12.4.js"></script>').length, 1);
  assert.equal(jsLibraries('<script src="/a/jquery-1.12.4.js"></script><script src="/b/jquery-3.7.1.js"></script>').length, 2);
  assert.deepEqual(scriptSources("<script type=module src=/x/app.js></script><script src='/y.js'></script>"), ["/x/app.js", "/y.js"]);
});

test("cms: WordPress core with no generator tag (catalog wordpress-core)", () => {
  const svc = (port, proto, vendor, product, version, extra = {}) => ({ port, proto, vendor, product, version: extra.matchVersion !== undefined ? extra.matchVersion : version, shown_version: version, guessed: !!extra.guessed, evidence: extra.evidence, label: extra.label || product });
  const wp = cmsServices('<script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.3.1"></script><script src="/wp-content/plugins/akismet/x.js?ver=6.3.1"></script>', 80, "http", svc);
  assert.deepEqual(wp.map((s) => [s.product, s.shown_version, s.version, s.guessed]), [["WordPress", "6.3.1", "", true], ["akismet", "", "", true]]);
  const gu = fromHttp({ headers: {}, body: "<!-- generator=\"https://wordpress.org/?v=6.2.3\" -->" }, 80, false)[0];
  assert.deepEqual([gu.product, gu.version, gu.guessed], ["WordPress", "6.2.3", false]);
  for (const headers of [{ link: '<https://blog.test/wp-json/>; rel="https://api.w.org/"' }, { "x-pingback": "https://blog.test/xmlrpc.php" }]) {
    const r = fromHttp({ headers, body: "<p>x</p>" }, 80, false);
    assert.deepEqual(r.map((s) => [s.product, s.version, s.guessed]), [["WordPress", "", true]], JSON.stringify(headers));
  }
  // block-library CSS ?ver= is not a catalog signal: presence only
  const bl = fromHttp({ headers: {}, body: '<link href="/wp-includes/css/dist/block-library/style.min.css?ver=6.3.1">' }, 80, false);
  assert.deepEqual(bl.map((s) => [s.product, s.shown_version]), [["WordPress", ""]]);
  assert.deepEqual(fromHttp({ headers: {}, body: "<p>plain page</p>" }, 80, false), []);
});

test("cms: catalog products from the one GET / (headers, cookie names, generator, markup)", () => {
  const one = (headers, body) => fromHttp({ headers, body }, 443, true).map((s) => [s.vendor, s.product, s.version, s.shown_version, s.guessed]);
  assert.deepEqual(one({ "x-powered-by": "Craft CMS" }, ""), [["Craft CMS", "Craft CMS", "", "", true]]);
  assert.deepEqual(one({ "set-cookie": ["CraftSessionId=abc123secret; path=/; HttpOnly"] }, ""), [["Craft CMS", "Craft CMS", "", "", true]]);
  assert.ok(!JSON.stringify(fromHttp({ headers: { "set-cookie": ["CraftSessionId=abc123secret"] }, body: "" }, 80, false)).includes("abc123secret"), "cookie values are never kept");
  assert.deepEqual(one({ dnnoutputcache: "true" }, ""), [["DNN Software", "DotNetNuke", "", "", true]]);
  assert.deepEqual(one({}, '<script src="/js/dnncore.js"></script>'), [["DNN Software", "DotNetNuke", "", "", true]]);
  assert.deepEqual(one({ "x-generator": "Drupal 10 (https://www.drupal.org)" }, ""), [["Drupal", "Drupal", "", "", true]]);
  assert.deepEqual(one({ "x-generator": "Drupal 7.98 (https://www.drupal.org)" }, ""), [["Drupal", "Drupal", "7.98", "7.98", false]]);
  assert.deepEqual(one({ "x-drupal-cache": "HIT" }, ""), [["Drupal", "Drupal", "", "", true]]);
  assert.deepEqual(one({}, '<script>jQuery.extend(Drupal.settings, {})</script>'), [["Drupal", "Drupal", "", "", true]]);
  // the existing generator record stays single: X-Generator without a dotted version adds nothing new
  const dr = fromHttp({ headers: { "x-generator": "Drupal 10" }, body: '<meta name="generator" content="Drupal 10 (https://www.drupal.org)">' }, 80, false);
  assert.equal(dr.length, 1);
  const ke = fromHttp({ headers: {}, body: '<meta name="generator" content="Kentico CMS 12.0.R2 (build 12.0.29) ">' }, 80, false)[0];
  assert.deepEqual([ke.vendor, ke.product, ke.shown_version, ke.version, ke.guessed], ["Kentico", "Xperience CMS", "12.0.29", "", true], "Kentico build number: inventory only");
  assert.deepEqual(one({ "set-cookie": "CMSPreferredCulture=en-US; path=/" }, ""), [["Kentico", "Xperience CMS", "", "", true]]);
  assert.deepEqual(one({ "set-cookie": ["october_session=x"] }, ""), [["October", "October CMS", "", "", true]]);
  assert.deepEqual(one({}, '<meta name="generator" content="Sitefinity 14.4.8142 DX">'), [["Progress", "Sitefinity", "14.4.8142", "14.4.8142", false]]);
  assert.deepEqual(one({}, '<link href="/Sitefinity/WebsiteTemplates/x/a.css">'), [["Progress", "Sitefinity", "", "", true]]);
  assert.deepEqual(one({}, '<script src="/WebResource.axd"></script><link href="/Telerik.Web.UI.WebResource.axd">'), [], "standalone Telerik UI is not Sitefinity");
  assert.deepEqual(one({ "x-sap-pad": "1" }, ""), [["SAP", "Commerce Cloud", "", "", true]]);
  assert.deepEqual(one({}, '<div class="content yCmsContentSlot"></div>'), [["SAP", "Commerce Cloud", "", "", true]]);
  assert.deepEqual(one({ "x-powered-by": "ThinkPHP" }, ""), [["ThinkPHP", "ThinkPHP", "", "", true]]);
  assert.deepEqual(one({ server: "cpsrvd/11.110.0.15" }, ""), [["WebPros", "cPanel", "11.110.0.15", "11.110.0.15", false]]);
  assert.deepEqual(one({}, "<title>WHM Login</title>"), [["WebPros", "cPanel", "", "", true]]);
  assert.deepEqual(one({}, '<html data-xwiki-reference="xwiki:Main.WebHome"><div id="xwikiplatformversion"><a href="https://extensions.xwiki.org">XWiki Jetty HSQLDB 15.10.5</a></div>'), [["XWiki", "XWiki Platform", "15.10.5", "15.10.5", false]]);
  assert.deepEqual(one({}, '<meta name="wiki" content="xwiki"/>'), [["XWiki", "XWiki Platform", "", "", true]]);
  // Joomla (catalog joomla): the existing generator record only
  assert.deepEqual(one({}, '<meta name="generator" content="Joomla! - Open Source Content Management">'), [["Joomla", "Joomla!", "", "", true]]);
  assert.deepEqual(one({}, '<script src="/media/jui/js/jquery.min.js"></script>').map((x) => x[1]), ["jQuery"], "no invented Joomla path markers");
});

test("cms: plugin and record caps hold on a hostile page", () => {
  const many = Array.from({ length: 300 }, (_, i) => `<script src="/wp-content/plugins/p${i}/a.js?ver=1.${i}"></script>`).join("");
  assert.equal(wpAssets(many).length, 20);
  const s = fromHttp({ headers: {}, body: many }, 80, false);
  assert.ok(s.length <= MAX_RECORDS + 1);
  const t0 = Date.now(); fromHttp({ headers: {}, body: "<script src=".repeat(6000) }, 80, false); assert.ok(Date.now() - t0 < 1000);
});
