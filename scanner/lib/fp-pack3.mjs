// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Passive pack 3 (scan-passive-3): a fixed RULES table and one evaluator, like fp-identify.mjs. Every signal reads data the
// scan ALREADY collected on the one connection per port — the greeting read on connect, the one root-page response (title,
// headers, cookie NAMES, recorded Location, body markers) and the TLS certificate. This file sends nothing, opens nothing and
// asks for no path: rows whose version or model would need another request (ZmSettings.js, /status.php, /common/about.php,
// /emerge.ico, a favicon) keep only their root-page signal and stay version-less.
//
// Rules (binding):
//   - a signal is the marker the reviewed catalog row and the lead's decision name; nothing beyond it (catalog IDs on each rule)
//   - a version is read only where the collected data states it (a header, a footer, an asset token); otherwise the record is
//     `guessed` and stays out of the headline counts (report.mjs summarize: low confidence)
//   - `family` rules name a product family the marker cannot split (NUUO NVRmini vs NVRmini2, eMerge model, Unitronics model):
//     never a version, always guessed
//   - evidence is the rule's own fixed wording plus the version or a short model token read: never a body, a cookie value or
//     page text
//   - industrial, building, camera and clinical rows are identification only from the same root-page response; never a write,
//     control command or protocol query. The clinical row (Mirth Connect) needs { clinical: true }, which scan.mjs passes (lead decision: root page only)
//   - the login-page inventory reads the root page and the recorded Location only; it never requests /login or any path
import { cleanVersion } from "./fingerprint.mjs";
import { facts } from "./fp-identify.mjs";

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").slice(0, n);
const core = (v) => (/^\d+(?:\.\d+)*/.exec(v) || [""])[0];
const V = "(\\d+(?:\\.\\d+){1,3})";   // a dotted version token, captured
const token = (s) => clip(s, 40).replace(/[^A-Za-z0-9.\-]/g, "").slice(0, 24);   // a short model token, never free text
const norm = (s) => String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();

/**
 * One rule: { id, catalog: [catalog IDs], vendor, product (the name the KEV/NVD rows use, so the site's nameHit matches),
 * label (what the report shows), family?, optIn? ("clinical"), signals: [signal], version: [{ from, re }], model?: { from, re } }.
 * A rule matches when ANY signal matches; a signal matches when ALL its fields match and none of its `not` does.
 * Signal fields (RegExp, or an array that must all match): title, body, server, header { name: RegExp }, cookie (NAME only),
 * location (recorded, never followed), cert (subject "CN=..., O=..., OU=..."), banner; why = fixed evidence text.
 * version/model sources: from "server" | "body" | "title" | "header:<name>" (first capture).
 */
export const RULES = Object.freeze([
  { id: "citrix-storefront", catalog: ["citrix-storefront-server"], vendor: "Citrix", product: "StoreFront Server", label: "Citrix StoreFront",
    // a NetScaler / ADC login title alone is not StoreFront (the row says so); only the StoreFront client script markers count
    signals: [{ body: /\bCTXS\.(?:WebApiClient|AccessGateway)\b/, why: "root page uses the StoreFront CTXS.WebApiClient / CTXS.AccessGateway script" },
      { body: /ctxs\.core\.min\.js/, why: "root page loads the StoreFront script ctxs.core.min.js" }], version: [] },
  { id: "zimbra", catalog: ["synacor-zimbra-collaboration-suite-zcs", "synacor-zimbra-collaborate-suite-zcs"], vendor: "Synacor",
    product: "Zimbra Collaboration/Collaborate Suite (ZCS)", label: "Zimbra Collaboration Suite (ZCS)",
    // the version (ZmSettings.js CLIENT_VERSION) needs a path the rail does not have: version-less here
    signals: [{ title: /^(?:Zimbra Web Client Sign In|Zimbra Web Client Log In|Zimbra Collaboration Suite Log In)$/, why: "root page title is the Zimbra web client sign-in" },
      { cookie: /^ZM_TEST$/, why: "cookie ZM_TEST set by the root page (value not read)" },
      { cert: /(?:^|, )OU=Zimbra Collaboration Server(?:,|$)/, why: "TLS certificate subject OU=Zimbra Collaboration Server" }], version: [] },
  { id: "glpi", catalog: ["teclib-glpi"], vendor: "Teclib", product: "GLPI",
    // two markers: the word GLPI (upper case, so not the domain itself) together with glpi-project.org
    signals: [{ body: [/\bGLPI\b/, /glpi-project\.org/i], why: "root page names GLPI and links glpi-project.org" }],
    version: [{ from: "body", re: new RegExp(`GLPI version\\s*${V}`) }, { from: "body", re: new RegExp(`common\\.min\\.js\\?v=${V}`) }] },
  { id: "zammad", catalog: ["zammad-gmbh-zammad"], vendor: "Zammad GmbH", product: "Zammad", label: "Zammad helpdesk",
    signals: [{ title: /^Zammad Helpdesk$/i, why: "root page title Zammad Helpdesk" },
      { body: /\bid=["'][^"']{0,80}zammad_form_script/i, why: "root page carries an element id zammad_form_script" }], version: [] },
  { id: "solarwinds-vman", catalog: ["solarwinds-virtualization-manager"], vendor: "SolarWinds", product: "Virtualization Manager",
    signals: [{ title: /^SolarWinds Virtualization Manager$/, why: "root page title SolarWinds Virtualization Manager" }], version: [] },
  { id: "zabbix", catalog: ["zabbix-frontend"], vendor: "Zabbix", product: "Frontend", label: "Zabbix frontend",
    signals: [{ body: /\bzbxCallPostScripts\b/, why: "root page carries the Zabbix zbxCallPostScripts script" },
      { body: /<meta\b[^>]{0,120}name=["']Author["'][^>]{0,120}content=["']ZABBIX SIA["']|<meta\b[^>]{0,120}content=["']ZABBIX SIA["'][^>]{0,120}name=["']Author["']/i, why: "root page meta Author ZABBIX SIA" },
      { title: /^(?:Zabbix|.*: Zabbix)$/, why: "root page title Zabbix / <server>: Zabbix" }],
    version: [{ from: "body", re: new RegExp(`jsLoader\\.php\\?ver=${V}`) }, { from: "body", re: new RegExp(`Zabbix ${V}\\.?\\s*(?:&copy;|©|Copyright)`) }] },
  { id: "ivanti-csa", catalog: ["ivanti-endpoint-manager-cloud-service-appliance-epm-csa"], vendor: "Ivanti", product: "Endpoint Manager Cloud Service Appliance (EPM CSA)",
    label: "Ivanti Cloud Services Appliance (EPM CSA)",
    signals: [{ title: /^Ivanti\(R\) Cloud Services Appliance$/, why: "root page title Ivanti(R) Cloud Services Appliance" },
      { body: [/LANDESK\(R\)/, /Cloud Services Appliance/], why: "root page names LANDESK(R) Cloud Services Appliance" }], version: [] },
  { id: "filezen", catalog: ["soliton-systems-k-k-filezen"], vendor: "Soliton Systems K.K.", product: "FileZen", label: "Soliton FileZen",
    // Last-Modified is not a version (the row says so): version-less
    signals: [{ title: /^FileZen$/, why: "root page title FileZen" }, { body: /FileZen, Copyrights\(C\)/, why: "root page carries the FileZen copyright line" }], version: [] },
  { id: "teamviewer", catalog: ["teamviewer-desktop"], vendor: "TeamViewer", product: "Desktop", label: "TeamViewer (web placeholder page)",
    signals: [{ body: /This site is running <a href=["']http:\/\/www\.TeamViewer\.com["']>TeamViewer<\/a>\./, why: "root page is the TeamViewer placeholder (This site is running TeamViewer)" }], version: [] },
  { id: "kace-sma", catalog: ["quest-kace-system-management-appliance", "quest-kace-systems-management-appliance-sma"], vendor: "Quest",
    product: "KACE System/Systems Management Appliance (SMA)", label: "Quest KACE Systems Management Appliance (SMA, formerly K1000)",
    // the deployment appliance (K2000 / SDA) shares the X-DellKACE headers: a header naming it is never taken for the SMA
    signals: [{ header: { "x-dellkace-version": /\d/ }, not: { header: { "x-dellkace-appliance": /K2000|SDA|Deployment/i } }, why: "response header X-DellKACE-Version" },
      { header: { "x-kbox-version": /\d/ }, not: { header: { "x-dellkace-appliance": /K2000|SDA|Deployment/i } }, why: "response header X-KBOX-Version" },
      { header: { "x-dellkace-appliance": /K1000|SMA\b|Systems Management/i }, why: "response header X-DellKACE-Appliance names the SMA" },
      { title: /^(?:KACE Systems Management Appliance\b|K1000 Service Center$)/, why: "root page title KACE Systems Management Appliance / K1000 Service Center" }],
    version: [{ from: "header:x-dellkace-version", re: new RegExp(`^\\s*${V}`) }, { from: "header:x-kbox-version", re: new RegExp(`^\\s*${V}`) }],
    model: { from: "header:x-dellkace-appliance", re: /^\s*([A-Za-z0-9][A-Za-z0-9 .\-]{0,30})/ } },
  { id: "mirth-connect", catalog: ["nextgen-healthcare-mirth-connect"], vendor: "NextGen Healthcare", product: "Mirth Connect", optIn: "clinical",
    signals: [{ title: /^Mirth Connect Administrator$/, why: "root page title Mirth Connect Administrator" }], version: [] },
  { id: "linear-emerge", catalog: ["nice-linear-emerge-e3-series"], vendor: "Nice", product: "Linear eMerge E3-Series", label: "Nice Linear eMerge (E3-Series not confirmed)", family: true,
    signals: [{ title: /Linear eMerge/, why: "root page title names Linear eMerge (model not read)" }], version: [] },
  { id: "scadabr", catalog: ["openplc-scadabr"], vendor: "OpenPLC", product: "ScadaBR",
    signals: [{ title: /^ScadaBR$/, why: "root page title ScadaBR" }, { body: /ScadaBR Software/, why: "root page names ScadaBR Software" }], version: [] },
  { id: "unitronics", catalog: ["unitronics-vision-plc-and-hmi"], vendor: "Unitronics", product: "Vision PLC and HMI", label: "Unitronics PLC/HMI web interface (model not read)", family: true,
    signals: [{ title: /^Unitronics$/, why: "root page title Unitronics" }, { body: /Logo-Unitronics\.svg/, why: "root page loads Logo-Unitronics.svg" },
      { body: /unitronics\.com/i, why: "root page links unitronics.com" }], version: [] },
  { id: "biotime", catalog: ["zkteco-biotime"], vendor: "ZKTeco", product: "BioTime",
    // a version may follow in the title, but the group was not reviewed: never read
    signals: [{ title: /^BioTime/, why: "root page title BioTime" }], version: [] },
  { id: "amcrest", catalog: ["amcrest-cameras-and-network-video-recorder-nvr"], vendor: "Amcrest", product: "Cameras and Network Video Recorder (NVR)",
    label: "Amcrest camera/NVR web interface (model not read)", family: true,
    signals: [{ body: [/Amcrest Technologies/, /LDAPUser/], why: "root page names Amcrest Technologies with the LDAPUser field" }], version: [] },
  { id: "nuuo-nvr", catalog: ["nuuo-nvrmini-devices", "nuuo-nvrmini2-devices"], vendor: "NUUO", product: "NVRmini/NVRmini2 Devices",
    label: "NUUO Network Video Recorder (family; NVRmini / NVRmini2 not told apart)", family: true,
    signals: [{ title: /^NUUO Network Video Recorder Login$/, why: "root page title NUUO Network Video Recorder Login (family only)" }], version: [] },
  { id: "intel-amt", catalog: ["intel-active-management-technology-amt-small-business-technology-sbt-and-standar"], vendor: "Intel",
    product: "Active Management Technology (AMT), Small Business Technology (SBT), and Standard Manageability", label: "Intel AMT / Standard Manageability",
    // the header only; digest realms are never answered (no authentication of any kind)
    signals: [{ server: /^Intel\(R\) Active Management Technology\b/, why: "Server header Intel(R) Active Management Technology" },
      { server: /^Intel\(R\) Standard Manageability\b/, why: "Server header Intel(R) Standard Manageability" }],
    version: [{ from: "server", re: new RegExp(`^Intel\\(R\\) (?:Active Management Technology|Standard Manageability) ${V}`) }] },
  { id: "cisco-ip-phone", catalog: ["cisco-cisco-ip-phones"], vendor: "Cisco", product: "Cisco IP Phones", label: "Cisco IP Phone",
    // HTTP only: the SIP part of the row waits for a reviewed SIP OPTIONS identify
    signals: [{ title: /^Cisco Systems, Inc\.$/, body: /Cisco IP Phone/, why: "root page title Cisco Systems, Inc. with Cisco IP Phone" },
      { title: /Cisco IP Phone CP-\d+/, why: "root page title Cisco IP Phone CP-<model>" }, { body: /Cisco IP Phone CP-\d+/, why: "root page names Cisco IP Phone CP-<model>" }],
    version: [], model: { from: "titlebody", re: /Cisco IP Phone (CP-\d{3,5}[A-Z]?)\b/ } },
]);

/**
 * Catalog rows this pack checked and found ALREADY built elsewhere (listed so nobody rebuilds them):
 * the certificate rows in cert-inventory.mjs (#114), the port-25-only SMTP inventory in mail-starttls.mjs (#114) and the
 * ProFTPD greeting in fingerprint.mjs (GREET table; version from the greeting when stated).
 */
export const ALREADY_COVERED = Object.freeze({
  "internal-names-in-certificate-san": "scanner/lib/cert-inventory.mjs (internal_names: RFC 1918 / private addresses, .local and other internal suffixes, single-label names)",
  "ocsp-must-staple-advertised": "scanner/lib/cert-inventory.mjs (must_staple: TLS Feature extension status_request)",
  "wildcard-certificate-breadth": "scanner/lib/cert-inventory.mjs (wildcards[].covers_attested against the attested names; inventory, no out-of-scope checks)",
  "mta-open-submission-on-port-25-only": "scanner/lib/mail-starttls.mjs (smtp25.submission: SMTP on port 25 only, no submission port answered)",
  "proftpd-proftpd": "scanner/lib/fingerprint.mjs GREET (ProFTPD <version> from the FTP greeting; version-less when the greeting has none)",
});

/** The catalog IDs this module builds, and every catalog ID it accounts for (built here, or already covered). */
export const CATALOG_IDS = Object.freeze([...new Set([...RULES.flatMap((r) => r.catalog), "login-page-inventory"])]);
export const ACCOUNTED_IDS = Object.freeze([...CATALOG_IDS, ...Object.keys(ALREADY_COVERED)]);

const all = (v) => (Array.isArray(v) ? v : [v]);
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
    default: return false;
  }
}
const FIELDS = ["title", "body", "server", "location", "cert", "banner", "cookie", "header"];
function signalHit(f, s) {
  const keys = FIELDS.filter((k) => s[k] !== undefined);
  if (!keys.length || !keys.every((k) => fieldHit(f, k, s[k]))) return false;
  return !(s.not && FIELDS.some((k) => s.not[k] !== undefined && fieldHit(f, k, s.not[k])));
}
const srcText = (f, from) => (from === "server" ? f.server : from === "body" ? f.body : from === "title" ? f.title : from === "titlebody" ? `${f.title}\n${f.body}`
  : from.startsWith("header:") ? f.one(from.slice(7)) : "");
const fromName = (from) => (from === "server" ? "Server header" : from.startsWith("header:") ? `${from.slice(7)} header` : "root page");
function versionOf(f, rule) {
  for (const v of rule.version || []) {
    const src = srcText(f, v.from), m = src ? v.re.exec(src) : null, shown = cleanVersion(m ? m[1] : "");
    if (shown) return { shown, from: fromName(v.from) };
  }
  return null;
}
const sourceOf = (sig) => (sig.banner ? "greeting read on connect" : sig.cert ? "TLS certificate" : sig.server || sig.header ? "HTTP response header" : sig.cookie ? "cookie name" : sig.location ? "recorded redirect" : "root page");

// login-page inventory: a password field on the root page, or a recorded redirect into a login path (never followed)
const PASSWORD_FIELD = /<input\b[^>]{0,400}\btype\s*=\s*["']?password\b/i;
const LOGIN_REDIRECT = /^(?:https?:\/\/[^/?#]+)?\/[^?#]{0,200}login/i;
export const LOGIN_LABEL = "Login page (inventory)";
function loginPage(r, f, existing) {
  if (!f.http || [...existing].some((s) => s.label === LOGIN_LABEL)) return [];
  const why = f.body && PASSWORD_FIELD.test(f.body) ? "root page has a password field (a login form)"
    : f.location && LOGIN_REDIRECT.test(f.location) ? "root page redirects to a login path (recorded, not followed)" : "";
  if (!why) return [];
  return [{ port: r.port, proto: r.tls ? "https" : "http", vendor: "", product: "", label: LOGIN_LABEL, version: "", shown_version: "", distro: "",
    source: "passive login-page inventory (root page)", evidence: `${why} (passive: data already collected; inventory, not a finding)`, guessed: true }];
}

/**
 * Passive pack 3 for one probed port (probe.mjs's result). existing: the services the other parsers already found on this
 * port (a product already named there is not added twice). opts.clinical turns on the clinical row (Mirth Connect).
 * Pure: no network, no path, nothing stored but fixed evidence. -> service records in fingerprint.mjs's shape.
 */
export function pack3(r, existing = [], { clinical = false } = {}) {
  if (!r || typeof r !== "object" || (!r.http && !r.banner && !(r.tls && r.tls.cert))) return [];
  const f = facts(r), out = [];
  const named = (rule, label) => [...existing, ...out].some((s) => (s.product && norm(s.product) === norm(rule.product)) || (s.label && norm(s.label) === norm(label)));
  for (const rule of RULES) {
    if (rule.optIn === "clinical" && !clinical) continue;
    const sig = rule.signals.find((s) => signalHit(f, s));
    if (!sig) continue;
    const label = rule.label || `${rule.vendor} ${rule.product}`;
    if (named(rule, label)) continue;
    const v = rule.family ? null : versionOf(f, rule);
    const mm = rule.model ? rule.model.re.exec(srcText(f, rule.model.from) || "") : null, model = mm ? token(mm[1]) : "";
    const evidence = `${sig.why}${model ? `; model ${model}` : ""}${v ? `; version ${v.shown} from the ${v.from}` : "; no version stated"} (passive: data already collected)`;
    out.push({ port: r.port, proto: r.tls ? "https" : "http", vendor: rule.vendor, product: rule.product, label: model ? `${label} (${model})` : label,
      version: v ? core(v.shown) : "", shown_version: v ? v.shown : "", distro: "", source: `passive pack 3 (${sourceOf(sig)})`, evidence: clip(evidence, 200), guessed: !v });
  }
  out.push(...loginPage(r, f, [...existing, ...out]));
  return out;
}
