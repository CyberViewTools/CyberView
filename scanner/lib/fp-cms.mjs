// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// CMS, plugin, theme and JavaScript library versions DISCLOSED in the root page the scanner already fetched (its one request for the root page).
// Pure functions, no network: this module never fetches a script, a plugin file or a /wp-content tree, keeps no page body,
// and uses no plugin or path wordlist — it only reads names and versions the page itself names in its own markup and headers.
//
// Records have the shape fromHttp() returns (fingerprint.mjs svc()), with NVD CPE vendor/product names so the workbench's
// ranges match. Reliability, and so what can become a confident finding:
//   stated   a version in a script's file name (jquery-3.4.1.min.js), a CDN path segment (/jquery/3.4.1/, jquery@3.4.1),
//            a library's own banner comment (/*! jQuery v3.4.1), a versioned generator tag or a Server header: compared
//            with the ranges
//   query    a ?ver= / ?v= cache-buster (WordPress adds its OWN version to assets enqueued without one, so it may not be the
//            plugin's or library's version) or a build number whose range semantics are not confirmed: shown in the
//            inventory only; the record is guessed and its compared version is empty, so any match is "check the version"
//            (low confidence, outside the headline counts)
//   presence a product marker with no version: guessed, no version

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n);
const VER = "(\\d+\\.\\d+(?:\\.\\d+){0,2})";
const isVer = (v) => /^\d+\.\d+(?:\.\d+){0,2}$/.test(v || "");
export const MAX_RECORDS = 30;
const MAX_PLUGINS = 20, MAX_THEMES = 5;

/* JavaScript libraries, by file name. names: the file's stem; suffix: optional build words; dirs: CDN folder names that carry
   the version (/ajax/libs/<dir>/<ver>/, /npm/<dir>@<ver>/). Products are NVD's CPE vendor:product. jQuery UI is named
   "jQueryUI" so the word "jquery" alone never matches jQuery core's ranges with a jQuery UI version. jquery-migrate and
   jquery.<plugin>.js files are not jQuery: the stem must be exactly one of the names. */
const LIBS = [
  { vendor: "jQuery", product: "jQuery", label: "jQuery", names: ["jquery"], suffix: ["slim", "min"], dirs: ["jquery"], banner: /\/\*!?\s*jQuery\s+v(\d+\.\d+\.\d+)\s*\|/ },
  { vendor: "jQuery", product: "jQueryUI", label: "jQuery UI", names: ["jquery-ui", "jqueryui"], suffix: ["custom", "min"], dirs: ["jqueryui", "jquery-ui"], banner: /\/\*!\s*jQuery UI\s*-\s*v(\d+\.\d+\.\d+)/ },
  { vendor: "getbootstrap", product: "Bootstrap", label: "Bootstrap", names: ["bootstrap"], suffix: ["bundle", "min"], dirs: ["bootstrap", "twitter-bootstrap"], banner: /\/\*!\s*Bootstrap\s+v(\d+\.\d+\.\d+)/ },
  { vendor: "AngularJS", product: "angular.js", label: "AngularJS", names: ["angular"], suffix: ["min"], dirs: ["angular.js", "angular"], banner: /\/\*\*?\s*@license AngularJS v(\d+\.\d+\.\d+)/ },
  { vendor: "lodash", product: "lodash", label: "Lodash", names: ["lodash"], suffix: ["core", "min"], dirs: ["lodash.js", "lodash"] },
  { vendor: "momentjs", product: "moment", label: "Moment.js", names: ["moment"], suffix: ["with-locales", "min"], dirs: ["moment.js", "moment"] },
  { vendor: "vuejs", product: "vue.js", label: "Vue.js", names: ["vue"], suffix: ["global", "runtime", "prod", "min"], dirs: ["vue"] },
  { vendor: "handlebarsjs", product: "handlebars", label: "Handlebars", names: ["handlebars"], suffix: ["runtime", "min"], dirs: ["handlebars.js", "handlebars"] },
  { vendor: "underscorejs", product: "underscore", label: "Underscore.js", names: ["underscore"], suffix: ["min"], dirs: ["underscore.js", "underscore"] },
];
function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
for (const L of LIBS) L.file = new RegExp(`^(?:${L.names.map(esc).join("|")})(?:[-.]v?${VER})?(?:[.-](?:${L.suffix.map(esc).join("|")}))*\\.js$`, "i");

/* Products identified from the one root-page response (headers, cookie NAMES, body): one entry per detection-catalog row assigned to this
   slice, each signal exactly as the row states it. A signal with v names the capture group holding a version; how: "stated"
   (compared with the ranges) or "query" (inventory only). Every other signal is presence only (guessed, no version). Cookie
   values are never read. Products are NVD CPE names. */
const PRODUCTS = [
  { row: "craft-cms-craft-cms", vendor: "Craft CMS", product: "Craft CMS", signals: [
    { header: "x-powered-by", re: /\bCraft CMS\b/ }, { cookie: "CRAFT_CSRF_TOKEN" }, { cookie: "CraftSessionId" }, { body: /CRAFT_CSRF_TOKEN/ }] },
  { row: "dotnetnuke-dnn-dotnetnuke-dnn", vendor: "DNN Software", product: "DotNetNuke", label: "DotNetNuke (DNN)", signals: [
    { gen: /^DotNetNuke/i }, { header: "dnnoutputcache" }, { header: "x-compressed-by", re: /DotNetNuke/ }, { cookie: "DotNetNukeAnonymous" }, { cookie: "dnn_IsMobile" },
    { body: /<!-- by DotNetNuke Corporation/ }, { body: /<!-- DNN Platform/ }, { script: /\/js\/dnncore\.js$/i }, { script: /\/js\/dnn\.js$/i }] },
  { row: "drupal-core", vendor: "Drupal", product: "Drupal", signals: [
    { header: "x-generator", re: /^Drupal(?:\s([\d.]+))?/, v: 1, how: "stated", dotted: true }, { gen: /^Drupal(?:\s([\d.]+))?/, v: 1, how: "stated", dotted: true },
    { header: "x-drupal-cache" }, { script: /(?:^|\/)drupal\.js$/i }, { body: /jQuery\.extend\(Drupal\.settings|\bDrupal\.settings\b/ }, { body: /\/sites\/(?:default|all)\// }] },
  { row: "kentico-kentico-xperience, kentico-xperience-cms", vendor: "Kentico", product: "Xperience CMS", label: "Kentico Xperience (Kentico CMS)", signals: [
    { gen: /^Kentico CMS ([\d.R]+) \(?build ([\d.]+)\)?/, v: 2, how: "query" }, { gen: /^Kentico CMS ([\d.R]+)/, v: 1, how: "query" },
    { body: /\/CMSPages\/GetResource\.ashx/i }, { body: /\/kentico\.resource/i }, { cookie: "CMSCookieLevel" }, { cookie: "CMSPreferredCulture" }, { body: /\bCMS\.Application\b/ }] },
  { row: "october-cms-october-cms", vendor: "October", product: "October CMS", signals: [
    { gen: /^OctoberCMS/i }, { cookie: "october_session" }, { body: /OctoberCMS/ }] },
  { row: "progress-asp-net-ajax-and-sitefinity", vendor: "Progress", product: "Sitefinity", label: "Progress Sitefinity", signals: [
    { gen: /^Sitefinity\s(\S{3,9})/i, v: 1, how: "stated" }, { body: /Powered by Sitefinity ASP\.NET CMS/i }, { body: /\/Sitefinity\/WebsiteTemplates\//i }, { body: /Telerik\.Sitefinity/ }] },
  { row: "sap-commerce-cloud", vendor: "SAP", product: "Commerce Cloud", label: "SAP Commerce Cloud (hybris)", signals: [
    { header: "x-sap-pad" }, { cookie: "_hybris" }, { script: /(?:^|\/)hybris\.js$/i }, { body: /class=["'][^"']{0,200}yCmsContentSlot/ }, { body: /\/_ui\/responsive\// }, { body: /\/sys_master\// }] },
  { row: "thinkphp-thinkphp", vendor: "ThinkPHP", product: "ThinkPHP", signals: [
    { header: "x-powered-by", re: /ThinkPHP/i }, { cookie: "thinkphp_show_page_trace" }, { body: /href="http:\/\/www\.thinkphp\.cn">thinkphp<\/a>/i }] },
  { row: "webpros-cpanel-and-whm-and-wp2-wordpress-squared", vendor: "WebPros", product: "cPanel", label: "cPanel & WHM", signals: [
    { header: "server", re: /^cpsrvd\/(\S+)/, v: 1, how: "stated" }, { header: "server", re: /^cpsrvd\b/ },
    { body: /<title>\s*(?:cPanel Login|WHM Login|cPanel&reg;)\s*<\/title>/i }, { body: /sys_cpanel\/images\/powered_by\.gif/ }] },
  { row: "xwiki-platform", vendor: "XWiki", product: "XWiki Platform", signals: [
    { body: /id=["']xwikiplatformversion["'][^>]{0,200}>(?:\s*<a\b[^>]{0,300}>)?[^<]{0,80}?(\d+\.\d+(?:\.\d+)?)/, v: 1, how: "stated" },
    { body: /\bdata-xwiki-/ }, { body: /<meta name=["']wiki["'] content=["']xwiki["']/i }, { body: /<div id=["']xwikilicence["']/ }] },
];
/** The detection-catalog rows this module implements (the handoff lists them). */
export const CATALOG_ROWS = ["wordpress-core", "drupal", "joomla", "javascript-libraries-in-the-root-page", ...PRODUCTS.flatMap((p) => p.row.split(", "))];

const unent = (s) => s.replace(/&amp;|&#0?38;/gi, "&").replace(/\\\//g, "/");
function queryVer(q) { const m = /(?:^|[?&])(?:ver|v|version)=v?([^&#]{1,40})/i.exec(q || ""); return m && isVer(m[1]) ? m[1] : ""; }
/** "<scheme://host>/a/b/c.js?x" -> { segs: ["a","b"], base: "c.js", path: "/a/b/c.js", query: "x" } (host dropped, never stored) */
function splitUrl(u) {
  const s = unent(clip(u, 500)).trim(), q = s.indexOf("?"), h = s.indexOf("#");
  const path = s.slice(0, q >= 0 ? q : h >= 0 ? h : s.length).replace(/^[a-z][\w+.-]*:\/\/[^/]*/i, "").replace(/^\/\/[^/]*/, "");
  const parts = path.split("/").filter(Boolean);
  return { segs: parts.slice(0, -1).map((p) => { try { return decodeURIComponent(p); } catch { return p; } }), base: parts[parts.length - 1] || "", path: "/" + parts.join("/"), query: q >= 0 ? s.slice(q + 1, h > q ? h : undefined) : "" };
}

/** Script sources in the page, in order (at most 200). */
export function scriptSources(body) {
  const out = [];
  for (const m of String(body || "").matchAll(/<(?:script)\b[^>]{0,400}?\bsrc\s*=\s*(?:"([^"]{1,500})"|'([^']{1,500})'|([^\s"'>]{1,500}))/gi)) { out.push(m[1] || m[2] || m[3]); if (out.length >= 200) break; }
  return out;
}

/** The generator meta tags of a page (at most 5). */
export function generators(body) {
  const out = [];
  for (const m of String(body || "").matchAll(/<meta\s+(?:name=["']generator["']\s+content=["']([^"']{1,120})["']|content=["']([^"']{1,120})["']\s+name=["']generator["'])/gi)) { out.push((m[1] || m[2]).trim()); if (out.length >= 5) break; }
  return out;
}
/** Cookie NAMES from Set-Cookie (the values are never read). */
const cookieNames = (h) => [].concat(h["set-cookie"] || []).slice(0, 50).map((c) => String(c).split("=")[0].trim());

/** One catalog product against the response: { version, how, evidence } from the first signal that gives a version, else
 *  from the first that matches (presence), else null. */
function identify(p, { headers, cookies, gens, scripts, body }) {
  let first = null;
  for (const s of p.signals) {
    let m = null, ev = "";
    if (s.header) { const raw = clip([].concat(headers[s.header] || [])[0], 200); if (raw) { m = s.re ? s.re.exec(raw) : [raw]; ev = s.re ? `${s.header}: ${raw}` : `${s.header} header present`; } }
    else if (s.cookie) { if (cookies.includes(s.cookie)) { m = [s.cookie]; ev = `cookie named ${s.cookie} (value not read)`; } }
    else if (s.gen) { for (const g of gens) if ((m = s.gen.exec(g))) { ev = `generator: ${clip(g, 100)}`; break; } }
    else if (s.script) { const src = scripts.map(splitUrl).find((u) => s.script.test(u.path)); if (src) { m = [src.base]; ev = `script file ${clip(src.base, 60)}`; } }
    else if (s.body) { if ((m = s.body.exec(body))) ev = `page markup: ${clip(m[0].replace(/\s+/g, " "), 60)}`; }
    if (!m) continue;
    let v = s.v ? m[s.v] || "" : "";
    if (v && s.dotted && !/\d\.\d/.test(v)) { ev += " (major version only)"; v = ""; }
    if (v) return { version: v, how: s.how || "query", evidence: ev };
    if (!first) first = { version: "", how: "presence", evidence: ev };
  }
  return first;
}

/** JavaScript libraries named by the page's script tags (file name or CDN path) or by a banner comment in an inline script. */
export function jsLibraries(body) {
  const found = [];
  const push = (L, version, how, evidence) => { if (!found.some((f) => f.lib === L && f.version === version)) found.push({ lib: L, version, how, evidence: clip(evidence, 160) }); };
  for (const src of scriptSources(body)) {
    const { segs, base, query } = splitUrl(src);
    const L = LIBS.find((x) => x.file.test(base)); if (!L) continue;
    const fileVer = (L.file.exec(base) || [])[1] || "";
    if (fileVer) { push(L, fileVer, "stated", `script file ${base}`); continue; }
    let pathVer = "", dir = "";
    for (let i = 0; i < segs.length && !pathVer; i++) {
      const at = /^(.+)@v?(\d+\.\d+(?:\.\d+){0,2})$/.exec(segs[i]);
      if (at && L.dirs.includes(at[1].toLowerCase())) { pathVer = at[2]; dir = at[1]; }
      else if (L.dirs.includes(segs[i].toLowerCase()) && isVer((segs[i + 1] || "").replace(/^v/, ""))) { pathVer = segs[i + 1].replace(/^v/, ""); dir = segs[i]; }
    }
    if (pathVer) { push(L, pathVer, "stated", `script path ${clip(dir, 40)}/${pathVer}/.../${base}`); continue; }
    const qv = queryVer(query);
    push(L, qv, qv ? "query" : "presence", qv ? `script file ${base}?ver=${qv}` : `script file ${base}`);
  }
  for (const L of LIBS) if (L.banner) { const m = L.banner.exec(String(body || "")); if (m) push(L, m[1], "stated", `inline banner comment ${L.label} v${m[1]}`); }
  // a versionless sighting of a library that also appears with a version adds nothing
  return found.filter((f) => f.version || !found.some((g) => g.lib === f.lib && g.version));
}

/** WordPress plugins and themes named in the page's own asset URLs (/wp-content/plugins/<slug>/, /wp-content/themes/<slug>/). */
export function wpAssets(body) {
  const text = unent(String(body || "")), items = new Map();
  for (const m of text.matchAll(/\/wp-content\/(plugins|themes)\/([a-z0-9][a-z0-9_.-]{0,63})\/[^"'\s<>?#]{0,200}(\?[^"'\s<>#]{0,200})?/gi)) {
    const kind = m[1].toLowerCase() === "plugins" ? "plugin" : "theme", slug = m[2].toLowerCase(), k = `${kind}:${slug}`;
    if (!items.has(k)) {
      if ([...items.values()].filter((x) => x.kind === kind).length >= (kind === "plugin" ? MAX_PLUGINS : MAX_THEMES)) continue;
      items.set(k, { kind, slug, vers: new Set() });
    }
    const v = queryVer((m[3] || "").slice(1)); if (v) items.get(k).vers.add(v);
  }
  return [...items.values()];
}

/**
 * Everything the response discloses, as service records. svc is fingerprint.mjs's record builder (passed in so the shape is
 * the same); have: the records fromHttp() already made from headers and the generator tag; headers: the response headers
 * (only named fields and cookie NAMES are read).
 */
export function cmsServices(body, port, proto, svc, have = [], headers = {}) {
  const b = String(body || ""), out = [], h = headers && typeof headers === "object" ? headers : {};
  const add = (vendor, product, version, how, evidence, label) => {
    if (out.length >= MAX_RECORDS) return;
    const stated = how === "stated" && version;
    out.push(svc(port, proto, vendor, product, version, { source: "root page body and headers", evidence, guessed: !stated, ...(stated ? {} : { matchVersion: "" }), ...(label ? { label } : {}) }));
  };
  const gens = generators(b), ctx = { headers: h, cookies: cookieNames(h), gens, scripts: scriptSources(b), body: b };
  // catalog products: Craft CMS, DNN, Drupal, Kentico, October CMS, Sitefinity, SAP Commerce Cloud, ThinkPHP, cPanel, XWiki
  for (const p of PRODUCTS) {
    if (have.some((x) => x.product === p.product && x.shown_version)) continue;
    const r = identify(p, ctx); if (!r) continue;
    if (!r.version && have.some((x) => x.product === p.product)) continue;
    add(p.vendor, p.product, r.version, r.how, r.evidence, p.label);
  }
  // WordPress core (catalog wordpress-core): the wordpress.org generator URL's ?v=, wp-emoji-release.min.js's ver=, a
  // versionless generator, /wp-content/ or /wp-includes/ paths, a Link header to api.w.org, an X-Pingback header to /xmlrpc.php
  const text = unent(b), wpHave = have.find((x) => x.product === "WordPress");
  let core = wpHave ? wpHave.shown_version : "";
  if (!wpHave) {
    const gv = /wordpress\.org\/\?v=(\d+\.\d+(?:\.\d+)?)\b/i.exec(text), ev = /wp-emoji-release\.min\.js\?(?:[^"'\s<>]*?&)?ver=(\d+\.\d+(?:\.\d+)?)\b/i.exec(text);
    const link = clip([].concat(h.link || []).join(" "), 600), ping = clip([].concat(h["x-pingback"] || [])[0], 200).trim();
    const bare = gens.find((g) => /^WordPress\b/i.test(g));
    if (gv) { core = gv[1]; add("WordPress", "WordPress", core, "stated", `generator URL wordpress.org/?v=${core}`); }
    else if (ev) { core = ev[1]; add("WordPress", "WordPress", core, "query", `wp-emoji-release.min.js?ver=${core} (WordPress's own cache-buster)`); }
    else if (bare) add("WordPress", "WordPress", "", "presence", `generator: ${clip(bare, 100)} (no version)`);
    else if (/\/wp-(?:content|includes)\//i.test(text)) add("WordPress", "WordPress", "", "presence", "/wp-content/ or /wp-includes/ asset paths in the page");
    else if (/https:\/\/api\.w\.org\//.test(link)) add("WordPress", "WordPress", "", "presence", "Link header rel https://api.w.org/");
    else if (/\/xmlrpc\.php$/.test(ping)) add("WordPress", "WordPress", "", "presence", "X-Pingback header ends in /xmlrpc.php");
  }
  // WordPress plugins and themes the page itself names in its asset URLs (no wordlist; their ?ver= is inventory only)
  for (const it of wpAssets(b)) {
    const vers = [...it.vers].filter((v) => v !== core), v = vers.length === 1 ? vers[0] : "";
    const why = v ? ` ?ver=${v} (cache-buster: usually the ${it.kind}'s version, not confirmed)` : it.vers.size ? (vers.length > 1 ? " (its assets state different ?ver= values)" : ` (?ver= equals WordPress's own version, so it says nothing about the ${it.kind})`) : "";
    add("", it.slug.replace(/-/g, "_"), v, "query", `wp-content/${it.kind}s/${it.slug}${why}`, `WordPress ${it.kind} ${it.slug}`);
  }
  // JavaScript libraries
  for (const f of jsLibraries(b)) if (!have.some((x) => x.product === f.lib.product && x.shown_version === f.version)) add(f.lib.vendor, f.lib.product, f.version, f.how, f.evidence, f.lib.label);
  return out;
}

/** The hook fromHttp() calls: adds the response's records, and lets a versioned record replace a versionless one for the same product. */
export function mergeCms(out, body, port, proto, svc, headers = {}) {
  for (const s of cmsServices(body, port, proto, svc, out, headers)) {
    const i = out.findIndex((x) => x.product === s.product && !x.shown_version);
    if (i >= 0 && s.shown_version) out[i] = s; else if (i < 0) out.push(s);
  }
  return out;
}
