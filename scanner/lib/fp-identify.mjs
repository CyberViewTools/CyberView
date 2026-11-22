// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Passive product identification (scan-identify-passive): a fixed RULES table and one evaluator. Every signal reads data the
// scan ALREADY collected on the one connection per port — the greeting read on connect, the one root-page response (status,
// title, headers, cookie NAMES, recorded Location, body markers) and the TLS certificate. This file sends nothing, opens
// nothing and asks for no path: rows that would need a new request, port, hello or datagram are not in the table.
//
// Rules (binding):
//   - a signal is the marker a reviewed catalog row names; nothing is guessed beyond it (the catalog IDs are on each rule)
//   - a version is read only where the collected data states it (a header, a JSON field, a page token); otherwise the
//     record is `guessed` and stays out of the headline counts (report.mjs summarize: low confidence)
//   - evidence is the rule's own fixed wording plus the version read: never a body, a cookie value or page text
//   - industrial, building and camera rows are identification only, from the same root-page response; never a write or control
//     command, never an ICS protocol query
import { cleanVersion, certInfo, httpInfo } from "./fingerprint.mjs";

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").slice(0, n);
const core = (v) => (/^\d+(?:\.\d+)*/.exec(v) || [""])[0];
const V = "(\\d+(?:\\.\\d+){1,3})";   // a dotted version token, captured

/**
 * One rule: { id, catalog: [catalog IDs], vendor, product, label?, family? (always guessed: the marker names a product family,
 * not the catalog's exact model), signals: [signal], version: [{ from, re | path }] }.
 * A rule matches when ANY of its signals matches; a signal matches when ALL of its fields match and none of its `not` does.
 * Signal fields (each a RegExp, or an array of RegExps that must all match):
 *   title     the root page's <title> (as httpInfo() reads it)      body      the root page body (as collected, never stored)
 *   server    the Server header                                     header    { name: RegExp } any other response header
 *   cookie    a Set-Cookie NAME (values are never read)              location  the recorded Location header (never followed)
 *   cert      the certificate subject, "CN=..., O=..., OU=..."       banner    the greeting read on connect
 *   json      [[dotted path, RegExp | "string" | "object" | "absent"]] on the root body when it is a JSON object
 *   why       the fixed evidence text for this signal
 * version sources: { from: "server" | "body" | "banner", re (first capture) } or { from: "json", path }.
 */
export const RULES = Object.freeze([
  { id: "gitlab", catalog: ["gitlab-community-and-enterprise-editions", "gitlab-community-edition-and-enterprise-edition"], vendor: "GitLab", product: "GitLab",
    label: "GitLab (Community or Enterprise Edition)",
    // a redirect to /users/sign_in alone is not enough: it is the default sign-in path of many Rails (Devise) applications
    signals: [{ cookie: /^_gitlab_session$/, why: "cookie _gitlab_session set by the root page" },
      { body: [/GitLab/, /https:\/\/about\.gitlab\.com/], why: "root page names GitLab and links https://about.gitlab.com" }],
    version: [] },
  { id: "activemq", catalog: ["apache-activemq"], vendor: "Apache", product: "ActiveMQ",
    signals: [{ banner: /^[\s\S]{4}\u0001ActiveMQ/, why: "OpenWire WireFormatInfo frame read on connect" },
      { title: /^Apache ActiveMQ\b/, why: "root page title Apache ActiveMQ" }, { body: /Welcome to the Apache ActiveMQ!/, why: "root page shows the ActiveMQ console welcome" }],
    version: [{ from: "banner", re: new RegExp(`ProviderVersion\\t[\\s\\S]{2}${V}`) }] },
  { id: "rocketmq-console", catalog: ["apache-rocketmq"], vendor: "Apache", product: "RocketMQ", label: "Apache RocketMQ (console UI; broker version not read)",
    signals: [{ title: /^RocketMq-console-ng$/, why: "root page title RocketMq-console-ng" }], version: [] },
  { id: "pi-hole", catalog: ["pi-hole-adminlte"], vendor: "Pi-hole", product: "Pi-hole AdminLTE",
    signals: [{ title: /^Pi-hole\b/, why: "root page title Pi-hole" },
      { body: /Pi-hole: (?:Your|A) black hole for Internet advertisements/, why: "root page carries the Pi-hole tagline" }], version: [] },
  { id: "adminer", catalog: ["adminer-adminer"], vendor: "Adminer", product: "Adminer",
    signals: [{ title: /^Login - Adminer$/, why: "root page title Login - Adminer" }],
    version: [{ from: "body", re: new RegExp(`<span class="version">${V}</span>`) }] },
  { id: "couchdb", catalog: ["apache-couchdb"], vendor: "Apache", product: "CouchDB",
    signals: [{ server: /^CouchDB\/\d/, why: "Server header CouchDB/<version>" },
      { json: [["couchdb", "string"], ["vendor", "object"]], why: "root welcome document (\"couchdb\", \"vendor\")" }],
    version: [{ from: "server", re: new RegExp(`^CouchDB/${V}`) }, { from: "json", path: "version", when: [["couchdb", "string"]] }] },
  { id: "opensearch", catalog: ["opensearch-root-document"], vendor: "Amazon", product: "OpenSearch",
    signals: [{ json: [["cluster_name", "string"], ["version.number", "string"], ["version.distribution", /^opensearch$/]], why: "root JSON document (cluster_name, version.distribution opensearch)" }],
    version: [{ from: "json", path: "version.number" }], cluster: true },
  { id: "elasticsearch", catalog: ["elasticsearch-root-document"], vendor: "Elastic", product: "Elasticsearch",
    signals: [{ json: [["cluster_name", "string"], ["version.number", "string"], ["version.distribution", "absent"]], why: "root JSON document (cluster_name, version.number)" }],
    version: [{ from: "json", path: "version.number" }], cluster: true },
  { id: "mongo-express", catalog: ["mongodb-mongo-express"], vendor: "mongo-express", product: "mongo-express",
    signals: [{ title: /^Home - Mongo Express$/, why: "root page title Home - Mongo Express" }], version: [] },
  { id: "phpmyadmin", catalog: ["phpmyadmin-phpmyadmin"], vendor: "phpMyAdmin", product: "phpMyAdmin",
    signals: [{ title: /^phpMyAdmin\b/, why: "root page title phpMyAdmin" }, { body: /alt="phpMyAdmin/, why: "root page carries the phpMyAdmin logo" },
      { body: /name="pma_username/, why: "root page carries the phpMyAdmin login form" }, { body: /\/pmahomme\//, why: "root page loads the pmahomme theme" }],
    version: [] },
  { id: "aria-operations", catalog: ["broadcom-vmware-aria-operations", "vmware-vrealize-operations-manager-api"], vendor: "VMware", product: "Aria Operations (vRealize Operations Manager)",
    signals: [{ title: /VMware Aria Operations|vRealize Operations Manager/, why: "root page title VMware Aria Operations / vRealize Operations Manager" }],
    version: [{ from: "body", re: new RegExp(`SessionProvider\\.js\\?version=${V}`) }] },
  { id: "esxi", catalog: ["broadcom-vmware-esx"], vendor: "VMware", product: "ESXi",
    // the bare meta-refresh to /ui is not used on its own: many web apps redirect there
    signals: [{ body: /ng-app="esxUiApp"/, why: "root page is the ESXi Host Client (esxUiApp)" }, { body: /\bID_E?ESX_Welcome\b/, why: "root page is the ESXi welcome page" }],
    version: [] },
  { id: "vcenter", catalog: ["broadcom-vmware-vcenter"], vendor: "VMware", product: "vCenter Server",
    signals: [{ location: /^(?:https?:\/\/[^/]+)?\/(?:ui|websso)(?:\/|$)/, body: /VMware vSphere|vCenter/, not: { body: /esxUiApp|ID_E?ESX_Welcome/ }, why: "redirect to /ui or /websso/ with a VMware vSphere/vCenter page" },
      { body: [/href="\/(?:ui|websso)\b/, /VMware vSphere|vCenter/], not: { body: /esxUiApp|ID_E?ESX_Welcome/ }, why: "root page links /ui or /websso/ and names VMware vSphere/vCenter" }],
    version: [] },
  { id: "recoverpoint", catalog: ["dell-recoverpoint-for-virtual-machines-rp4vms"], vendor: "Dell", product: "RecoverPoint for Virtual Machines", family: true,
    signals: [{ body: /RecoverPoint Wizard/, why: "root page shows the RecoverPoint Wizard (RecoverPoint family; RP4VMs not told apart)" }], version: [] },
  { id: "hikvision", catalog: ["hikvision-security-cameras-web-server"], vendor: "Hikvision", product: "Hikvision camera/NVR web server", family: true,
    signals: [{ server: /^(?:Hikvision|DNVRS|DVRDVS)-Webs$/, why: "Server header Hikvision-Webs / DNVRS-Webs / DVRDVS-Webs" },
      { header: { "www-authenticate": /\brealm="?hikvision"?(?:[\s,]|$)/i }, why: "WWW-Authenticate realm hikvision" },
      { cert: /(?:^|, )O=HIKVISION(?:,|$)/, why: "TLS certificate subject O=HIKVISION" }], version: [] },
  { id: "papercut", catalog: ["papercut-mf-ng"], vendor: "PaperCut", product: "PaperCut MF/NG",
    signals: [{ title: /^PaperCut Login\b/, why: "page title PaperCut Login" }, { body: /<meta[^>]{0,200}content="PaperCut/i, why: "page meta content PaperCut" }], version: [] },
  { id: "reolink", catalog: ["reolink-multiple-ip-cameras", "reolink-rlc-410w-ip-camera"], vendor: "Reolink", product: "Reolink IP camera", label: "Reolink IP camera (model not read)", family: true,
    signals: [{ title: /Reolink$/, why: "root page title ends Reolink (camera family; model not read)" }], version: [] },
  { id: "solarview", catalog: ["solarview-compact"], vendor: "Contec", product: "SolarView Compact",
    signals: [{ body: /SolarView Compact/, why: "root page names SolarView Compact" }], version: [] },
  { id: "workspace-one-access", catalog: ["vmware-workspace-one-access-and-identity-manager"], vendor: "VMware", product: "Workspace ONE Access (Identity Manager)",
    signals: [{ location: /^(?:https?:\/\/[^/]+)?\/SAAS\//, why: "redirect into /SAAS/ (recorded, not followed)" }, { body: /\/SAAS\/auth/, why: "root page references /SAAS/auth" }], version: [] },
  { id: "opensmtpd", catalog: ["opensmtpd"], vendor: "OpenBSD", product: "OpenSMTPD",
    signals: [{ banner: /^220[ -][^\r\n]*\bOpenSMTPD\b/, why: "SMTP greeting names OpenSMTPD (no version in the greeting)" }], version: [] },
  { id: "qmail", catalog: ["qmail"], vendor: "qmail", product: "qmail",
    signals: [{ banner: /^220[ -][^\r\n]*\bqmail\b/i, why: "SMTP greeting names qmail (no version in the greeting)" }], version: [] },
  { id: "cwp", catalog: ["cwp-control-web-panel"], vendor: "CWP", product: "Control Web Panel", label: "CWP Control Web Panel (CentOS Web Panel)",
    signals: [{ server: /^cwpsrv$/i, why: "Server header cwpsrv" }, { cookie: /^cwpsrv-[0-9a-f]{32}$/, why: "cookie cwpsrv-<id>" },
      { title: /^(?:Login \| CentOS WebPanel|CWP \| User)$/, why: "root page title Login | CentOS WebPanel / CWP | User" }], version: [] },
  { id: "cyberpanel", catalog: ["cyberpersons-cyberpanel"], vendor: "CyberPersons", product: "CyberPanel",
    signals: [{ title: /CyberPanel/, why: "root page title contains CyberPanel" }], version: [] },
  { id: "hpe-oneview", catalog: ["hewlett-packard-enterprise-hpe-oneview"], vendor: "HPE", product: "OneView",
    signals: [{ title: /^OneView\b/, why: "root page title OneView" }],
    version: [{ from: "body", re: new RegExp(`var artifactVersion\\s*=\\s*"${V}"`) }] },
  { id: "omnipcx", catalog: ["alcatel-omnipcx-enterprise"], vendor: "Alcatel-Lucent", product: "OmniPCX Enterprise",
    signals: [{ banner: /^220[ -]Alize Session Manager FTP Server/, why: "FTP greeting Alize Session Manager FTP Server" }], version: [] },
  { id: "grandstream-ucm6200", catalog: ["grandstream-ucm6200"], vendor: "Grandstream", product: "UCM6200 series",
    // the Device Configuration title is shared by several Grandstream products: a UCM marker is required with it
    signals: [{ title: /^Grandstream Device Configuration$/, body: /tl\.account\.ucm\.js|\bUCM62\d\d\b/, why: "root page title Grandstream Device Configuration with a UCM6200 marker" },
      { banner: /Grandstream UCM62\d\d\S{0,20} Command Shell/, why: "telnet greeting Grandstream UCM62xx Command Shell (read on connect; no login)" }], version: [] },
  { id: "openfire", catalog: ["ignite-realtime-openfire"], vendor: "Ignite Realtime", product: "Openfire",
    signals: [{ title: /^Openfire Admin Console/, why: "root page title Openfire Admin Console" }, { body: /Openfire, Version: /, why: "root page states Openfire, Version:" }],
    version: [{ from: "body", re: new RegExp(`Openfire, Version:\\s*${V}`) }] },
  { id: "mitel", catalog: ["mitel-sip-phones"], vendor: "Mitel", product: "", label: "Mitel device web interface (product and model not determined)", family: true,
    // generic Mitel marker: identified for the inventory only, never matched to a product's flaws (could be MiCollab or a phone)
    signals: [{ body: /Mitel Networks Corporation/, why: "root page names Mitel Networks Corporation (generic Mitel; not phone-specific)" }], version: [] },
  { id: "unrealircd", catalog: ["unrealircd"], vendor: "UnrealIRCd", product: "UnrealIRCd",
    signals: [{ banner: /\bUnrealIRCd\b/, why: "IRC greeting names UnrealIRCd (no version read)" }], version: [] },
]);

/** The catalog IDs this module covers (for docs and tests). */
export const CATALOG_IDS = Object.freeze([...new Set(RULES.flatMap((r) => r.catalog))]);

const all = (v) => (Array.isArray(v) ? v : [v]);
function at(obj, path) {
  let x = obj;
  for (const k of path.split(".")) { if (!x || typeof x !== "object" || Array.isArray(x) || !Object.prototype.hasOwnProperty.call(x, k)) return undefined; x = x[k]; }
  return x;
}
function jsonTest(j, [path, t]) {
  const v = at(j, path);
  if (t === "absent") return v === undefined;
  if (t === "string") return typeof v === "string" && v.length > 0;
  if (t === "object") return !!v && typeof v === "object";
  return typeof v === "string" && t.test(v);
}

/** What one probed port already returned, in the shape the rules read. Pure. */
export function facts(r) {
  const res = r && r.http && typeof r.http === "object" ? r.http : null, H = res && res.headers && typeof res.headers === "object" ? res.headers : {};
  const one = (k) => clip(Array.isArray(H[k]) ? H[k][0] : H[k], 300).trim();
  const body = res ? clip(res.body, 65536) : "";
  let json = null;
  if (/^\s*\{/.test(body) && body.length < 65536) { try { const j = JSON.parse(body); if (j && typeof j === "object" && !Array.isArray(j)) json = j; } catch { /* not JSON */ } }
  const cookies = (Array.isArray(H["set-cookie"]) ? H["set-cookie"] : H["set-cookie"] ? [H["set-cookie"]] : []).slice(0, 30)
    .map((c) => (/^\s*([^=;\s]{1,80})=/.exec(String(c)) || [, ""])[1]).filter(Boolean);
  const ci = r && r.tls && r.tls.cert ? certInfo(r.tls.cert) : null;
  return { http: !!res, title: res ? httpInfo(res).title : "", body, json, headers: H, one, server: one("server"), location: one("location"), cookies,
    cert: ci ? ci.subject : "", banner: r && r.banner ? String(r.banner).slice(0, 2048) : "" };
}

function fieldHit(f, key, want) {
  switch (key) {
    case "title": return !!f.title && all(want).every((re) => re.test(f.title));
    case "body": return !!f.body && all(want).every((re) => re.test(f.body));
    case "server": return !!f.server && all(want).every((re) => re.test(f.server));
    case "location": return !!f.location && all(want).every((re) => re.test(f.location));
    case "cert": return !!f.cert && all(want).every((re) => re.test(f.cert));
    case "banner": return !!f.banner && all(want).every((re) => re.test(f.banner));
    case "cookie": return all(want).every((re) => f.cookies.some((n) => re.test(n)));
    case "header": return Object.entries(want).every(([k, re]) => { const v = f.one(k); return !!v && re.test(v); });
    case "json": return !!f.json && want.every((t) => jsonTest(f.json, t));
    default: return false;
  }
}
const FIELDS = ["title", "body", "server", "location", "cert", "banner", "cookie", "header", "json"];
function signalHit(f, s) {
  const keys = FIELDS.filter((k) => s[k] !== undefined);
  if (!keys.length || !keys.every((k) => fieldHit(f, k, s[k]))) return false;
  return !(s.not && FIELDS.some((k) => s.not[k] !== undefined && fieldHit(f, k, s.not[k])));
}
function versionOf(f, rule) {
  for (const v of rule.version || []) {
    if (v.when && !(f.json && v.when.every((t) => jsonTest(f.json, t)))) continue;
    let raw = "";
    if (v.from === "json") { const x = f.json ? at(f.json, v.path) : undefined; raw = typeof x === "string" ? x : ""; }
    else { const src = v.from === "server" ? f.server : v.from === "banner" ? f.banner : f.body, m = src ? v.re.exec(src) : null; raw = m ? m[1] : ""; }
    const shown = cleanVersion(raw);
    if (shown) return { shown, from: v.from === "json" ? `JSON field ${v.path}` : v.from === "server" ? "Server header" : v.from === "banner" ? "greeting" : "root page" };
  }
  return null;
}
const protoOf = (r, rule, sig) => (sig.banner ? ({ omnipcx: "ftp", opensmtpd: "smtp", qmail: "smtp", unrealircd: "irc", activemq: "openwire", "grandstream-ucm6200": "telnet" })[rule.id] || "tcp" : r.tls ? "https" : "http");
const sourceOf = (sig) => (sig.banner ? "greeting read on connect" : sig.cert ? "TLS certificate" : sig.json ? "root JSON document" : sig.server || sig.header ? "HTTP response header" : sig.cookie ? "cookie name" : sig.location ? "recorded redirect" : "root page");

/**
 * Passive identification for one probed port (probe.mjs's result). existing: the services the other parsers already found
 * on this port (a product already named is not added twice). Pure: no network, no path, nothing stored but fixed evidence.
 * -> service records in fingerprint.mjs's shape.
 */
export function identify(r, existing = []) {
  if (!r || typeof r !== "object" || (!r.http && !r.banner && !(r.tls && r.tls.cert))) return [];
  const f = facts(r), out = [];
  for (const rule of RULES) {
    const sig = rule.signals.find((s) => signalHit(f, s));
    if (!sig) continue;
    const label = rule.label || (rule.vendor && rule.product && !rule.product.toLowerCase().startsWith(rule.vendor.toLowerCase().split(" ")[0]) ? `${rule.vendor} ${rule.product}` : rule.product || rule.vendor);
    if ([...existing, ...out].some((s) => (rule.product ? s.product === rule.product : s.label === label))) continue;
    const v = rule.family ? null : versionOf(f, rule);
    const cluster = rule.cluster && f.json && typeof f.json.cluster_name === "string" ? clip(f.json.cluster_name, 60).replace(/[^\w.\-]/g, "?") : "";
    const evidence = `${sig.why}${v ? `; version ${v.shown} from the ${v.from}` : "; no version stated"}${cluster ? `; cluster ${cluster}` : ""} (passive: data already collected)`;
    out.push({ port: r.port, proto: protoOf(r, rule, sig), vendor: rule.vendor, product: rule.product, label, version: v ? core(v.shown) : "", shown_version: v ? v.shown : "", distro: "",
      source: `passive identify (${sourceOf(sig)})`, evidence: clip(evidence, 200), guessed: !v });
  }
  return out;
}
