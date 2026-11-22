// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Application fingerprints, passive pack 1 (scan-app-versions): products named from data the scan ALREADY collected for a
// port — the one GET / response (status, title, headers, body markers, cookie NAMES, the recorded redirect Location), the
// TLS certificate from the one handshake, and a greeting banner. Pure; no network, no request of any kind.
//
// A data-driven rules table plus one small evaluator. Each rule names the catalog id(s) it serves, the product as NVD's CPE
// names it (so CyberView's version ranges match), the signals that identify it, and, only where the catalog row states
// one, where a version is read. How far a version is trusted depends on where it came from:
//   header / banner  the service states it in a header or greeting      -> compared with the ranges (high confidence possible)
//   page             a version printed in the page body (footer, asset)  -> compared, but the record stays `guessed` (medium at most)
//   shown            a login-page title, a CLR runtime version           -> kept as shown_version for the operator, NEVER compared:
//                                                                           the record stays version-less, low confidence, out of headlines
// A rule with no version extractor (most of them) yields a guessed, version-less inventory record: a finding from it is
// "check" with low confidence and never counts in the headline numbers (report.mjs summarize()).
// Evidence names the signal that matched (a header name and short value, a cookie NAME, a marker's description); the page
// text itself is never copied.
import { cleanVersion, httpInfo } from "./fingerprint.mjs";

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n);
const core = (v) => (/^\d+(?:\.\d+)*/.exec(v) || [""])[0];

// a signal: [where, test, what]. where: "server" | "powered" (X-Powered-By) | "h:<header>" (that header's value) |
// "hname" (any header NAME) | "cookie" (any cookie NAME) | "title" | "body" | "location" (recorded redirect) | "cert"
// (subject "CN=.., O=.., OU=..") | "banner" (greeting first line). Optional 4th element: { port } limits it to one port.
// A rule matches when EVERY signal of ANY one group in `when` matches.
export const RULES = Object.freeze([
  { ids: ["ray-project-ray"], cpe: "ray_project:ray", vendor: "Ray Project", product: "Ray", label: "Ray (dashboard)",
    when: [[["title", /Ray Dashboard/, 'page title "Ray Dashboard"']]] },
  { ids: ["advantive-veracore"], cpe: "advantive:veracore", vendor: "Advantive", product: "VeraCore",
    when: [[["body", /\/veracore\/img\/LoginLogo\.png/i, "VeraCore login logo path in the root page"]], [["body", /VeraCore/, 'root page marker "VeraCore"']],
      [["location", /veracore/i, "redirect Location to a VeraCore path (recorded, not followed)"]]] },
  { ids: ["apache-axis"], cpe: "apache:axis2", vendor: "Apache", product: "Axis2",
    when: [[["body", /axis2-web\/css\/axis-style\.css/, "Axis2 stylesheet path in the root page"]], [["body", /http:\/\/ws\.apache\.org\/axis2/, "Axis2 project link in the root page"]],
      [["body", /axis2-web/, 'root page marker "axis2-web"']]] },
  { ids: ["apache-hugegraph-server"], cpe: "apache:hugegraph", vendor: "Apache", product: "HugeGraph-Server",
    when: [[["body", /"service"\s*:\s*"hugegraph"/, 'root document field "service":"hugegraph"']]] },
  { ids: ["apache-kylin"], cpe: "apache:kylin", vendor: "Apache", product: "Kylin",
    when: [[["body", /<meta\s+http-equiv=["']refresh["'][^>]{0,80}url=kylin\b/i, "root page meta refresh to kylin"]], [["body", /href=["']\/kylin\/["']/, 'root page link href="/kylin/"']]] },
  { ids: ["apache-spark"], cpe: "apache:spark", vendor: "Apache", product: "Spark",
    when: [[["body", /Spark Jobs/, 'root page marker "Spark Jobs"'], ["body", /application UI/, 'root page marker "application UI"']],
      [["location", /^(?:https?:\/\/[^/]+)?\/jobs\/?$/i, "redirect Location to /jobs/ on the Spark UI port (recorded, not followed)", { port: 4040 }]]] },
  { ids: ["asp-net-or-system-web"], cpe: "microsoft:asp.net", vendor: "Microsoft", product: "ASP.NET",
    when: [[["h:x-aspnet-version", /\S/, "X-AspNet-Version header"]], [["powered", /^ASP\.NET$/i, "X-Powered-By: ASP.NET"]], [["cookie", /^ASP\.NET_SessionId$/i, "cookie name ASP.NET_SessionId"]]],
    // X-AspNet-Version is the .NET runtime (CLR) version, not an ASP.NET release: shown for the operator, never compared
    version: [["h:x-aspnet-version", /^(\d[\w.]*)$/, "shown"]] },
  { ids: ["django-application"], cpe: "djangoproject:django", vendor: "Django Software Foundation", product: "Django", label: "Django",
    when: [[["cookie", /^csrftoken$/, "cookie name csrftoken"]], [["body", /you(?:'|&#39;|&#x27;)re seeing this error because you have <code>DEBUG = True<\/code>/i, "Django debug page"]]] },
  { ids: ["express-or-node-js-http"], cpe: "expressjs:express", vendor: "Expressjs", product: "Express", label: "Express (Node.js)",
    when: [[["powered", /^Express$/i, "X-Powered-By: Express"]]] },
  { ids: ["laravel-application"], cpe: "laravel:framework", vendor: "Laravel", product: "Laravel Framework",
    when: [[["cookie", /^laravel_session$/, "cookie name laravel_session"]]] },
  { ids: ["oracle-fusion-middleware"], cpe: "oracle:fusion_middleware", vendor: "Oracle", product: "Fusion Middleware",
    when: [[["server", /^Oracle-Fusion-Middleware/, "Server: Oracle-Fusion-Middleware"]], [["title", /^Welcome to Oracle Fusion Middleware$/, 'page title "Welcome to Oracle Fusion Middleware"']],
      [["body", /css\/fmw_bottom_area\.css/, "Fusion Middleware welcome stylesheet path"]]],
    version: [["server", /^Oracle-Fusion-Middleware\/([^\s]+ \([^)]+\))/, "header"], ["body", /<div id="welcome_text">TO ORACLE<strong> FUSION MIDDLEWARE ([^\s<]+)<\/strong>/, "page"]] },
  { ids: ["oracle-intelligence-enterprise-edition"], cpe: "oracle:business_intelligence", vendor: "Oracle", product: "Business Intelligence", label: "Oracle Business Intelligence Enterprise Edition",
    when: [[["title", /^Oracle Business Intelligence(?: Sign In)?$/, 'page title "Oracle Business Intelligence"']], [["body", /Oracle BI Presentation Services/, 'root page marker "Oracle BI Presentation Services"']]] },
  { ids: ["progress-telerik-report-server"], cpe: "progress:telerik_report_server", vendor: "Progress", product: "Telerik Report Server",
    when: [[["body", /Telerik Report Server/, 'root page marker "Telerik Report Server"']]] },
  { ids: ["ruby-on-rails-application"], cpe: "rubyonrails:rails", vendor: "Ruby on Rails", product: "Rails", label: "Ruby on Rails",
    when: [[["h:x-runtime", /^\d+(?:\.\d+)?$/, "X-Runtime header"]], [["body", /Action Controller: Exception caught/i, "Rails exception page"]]] },
  { ids: ["telerik-user-interface-ui-for-asp-net-ajax"], cpe: "telerik:ui_for_asp.net_ajax", vendor: "Telerik", product: "UI for ASP.NET AJAX",
    when: [[["body", /class=["']Telerik_stylesheet["']/, 'root page class "Telerik_stylesheet"']], [["body", /\$create\(Telerik\.Web\.UI\.Rad/, "Telerik.Web.UI control script"]],
      [["body", /Telerik\.Web\.UI\.WebResource\.axd\?/i, "Telerik.Web.UI.WebResource.axd reference"]]] },
  { ids: ["yiiframework-yii"], cpe: "yiiframework:yii", vendor: "Yiiframework", product: "Yii", label: "Yii Framework",
    when: [[["cookie", /^YII_CSRF_TOKEN$/, "cookie name YII_CSRF_TOKEN"]], [["body", /name=["']YII_CSRF_TOKEN["']/, "hidden field YII_CSRF_TOKEN"]],
      [["body", /<!\[CDATA\[YII-BLOCK-(?:HEAD|BODY-BEGIN|BODY-END)\]\]>/, "YII-BLOCK page comment"]], [["body", /\/assets\/\w{8}\/yii(?:\.validation|\.activeForm)?\.js/i, "Yii asset script path"]],
      [["body", /Powered by\s*(?:<a[^>]{0,200}>)?\s*Yii Framework/i, 'footer "Powered by Yii Framework"']]] },
  { ids: ["accellion-fta"], cpe: "accellion:fta", vendor: "Accellion", product: "FTA", label: "Accellion FTA",
    when: [[["body", /secured by accellion/i, 'root page marker "secured by accellion"']], [["body", /\/cfadmin\/img\/accellion-logo\.png/i, "Accellion logo path in the root page"]],
      [["location", /\/courier\/\d+@\/mail_user_login\.html/, "redirect Location to the FTA courier login (recorded, not followed)"]]] },
  { ids: ["crushftp-crushftp"], cpe: "crushftp:crushftp", vendor: "CrushFTP", product: "CrushFTP",
    when: [[["server", /^CrushFTP\b/, "Server: CrushFTP"]], [["cookie", /^CrushAuth$/, "cookie name CrushAuth"]], [["h:www-authenticate", /CrushFTP Server Version/, "WWW-Authenticate realm CrushFTP"]],
      [["body", /crushftp_functions\.js/, "crushftp_functions.js script"]], [["banner", /^220[ -](?:CrushFTP Server Ready|Welcome to CrushFTP)/, "FTP greeting CrushFTP"]]],
    version: [["server", /^CrushFTP (?:HTTP\d? Server )?Version ([\d.]+)$/, "header"], ["h:www-authenticate", /CrushFTP Server Version ([\d.]+)/, "header"]] },
  { ids: ["d-link-multiple-nas-devices"], cpe: "dlink:<model>_firmware (one CPE per NAS model)", vendor: "D-Link", product: "ShareCenter NAS",
    when: [[["body", /ShareCenter/, 'root page marker "ShareCenter"'], ["body", /Please Select Your Account/, 'root page marker "Please Select Your Account"']]] },
  { ids: ["fortra-goanywhere-mft"], cpe: "fortra:goanywhere_managed_file_transfer", vendor: "Fortra", product: "GoAnywhere Managed File Transfer", label: "Fortra GoAnywhere MFT",
    when: [[["server", /^goanywhere$/i, "Server: goanywhere"]], [["body", /GoAnywhereWebClientContainer/, "GoAnywhereWebClientContainer in the root page"]]] },
  { ids: ["nakivo-backup-and-replication"], cpe: "nakivo:backup_\\&_replication", vendor: "NAKIVO", product: "Backup & Replication", label: "NAKIVO Backup & Replication",
    when: [[["title", /^NAKIVO Backup (?:&|&amp;) Replication v/, 'page title "NAKIVO Backup & Replication v..."']]],
    version: [["title", /^NAKIVO Backup (?:&|&amp;) Replication v(\d[\w.]*)/, "shown"]] },
  { ids: ["progress-moveit-transfer"], cpe: "progress:moveit_transfer", vendor: "Progress", product: "MOVEit Transfer",
    when: [[["h:x-moveitisapi-version", /\S/, "X-MOVEitISAPI-Version header"]], [["body", /stylesheet_MOVEit/, 'root page marker "stylesheet_MOVEit"']],
      [["body", /moveit\.transfer/i, 'root page marker "moveit.transfer"']], [["body", /MOVEitPopUp/, 'root page marker "MOVEitPopUp"']]],
    version: [["h:x-moveitisapi-version", /^(\d[\w.]*)$/, "header"]] },
  { ids: ["progress-ws-ftp-server"], cpe: "progress:ws_ftp_server", vendor: "Progress", product: "WS_FTP Server",
    when: [[["banner", /^220[ -].*WS_FTP Server\b/, "FTP greeting WS_FTP Server"]], [["title", /WS_FTP Server Web Transfer/, 'page title "WS_FTP Server Web Transfer"']],
      [["body", /Web Transfer Client/, 'root page marker "Web Transfer Client"']], [["body", /\/ThinClient\/(?:WTM|WebResource)/, "ThinClient script path"]]],
    version: [["banner", /WS_FTP Server (\d[\w.]*)/, "header"]] },
  { ids: ["projectsend-projectsend"], cpe: "projectsend:projectsend", vendor: "ProjectSend", product: "ProjectSend",
    when: [[["body", /Provided by <a href="https?:\/\/www\.projectsend\.org\/?"[^>]{0,200}>ProjectSend<\/a>/i, 'footer "Provided by ProjectSend"']]],
    version: [["body", /version ([^<\n]{1,40}?) - Free software/i, "page"]] },
  { ids: ["qnap-network-attached-storage-nas"], cpe: "qnap:qts", vendor: "QNAP", product: "QTS",
    when: [[["cert", /CN=QNAP NAS(?:,|$)/, "certificate CN=QNAP NAS"], ["cert", /OU=QTS(?:,|$)/, "certificate OU=QTS"], ["cert", /O=QNAP Systems, Inc\./, "certificate O=QNAP Systems, Inc."]],
      [["title", /QNAP Turbo NAS/, 'page title "QNAP Turbo NAS"']]] },
  { ids: ["rejetto-http-file-server"], cpe: "rejetto:http_file_server", vendor: "Rejetto", product: "HTTP File Server",
    when: [[["server", /^HFS\b/, "Server: HFS"]], [["cookie", /^HFS_SID$/, "cookie name HFS_SID"]], [["body", /<a href="http:\/\/www\.rejetto\.com\/hfs\/">HttpFileServer\b/, 'footer "HttpFileServer"']]],
    version: [["server", /^HFS (\d\.\d.+)$/, "header"], ["body", /<a href="http:\/\/www\.rejetto\.com\/hfs\/">HttpFileServer (\d[^<\s]*)<\/a>/, "page"]] },
  { ids: ["terramaster-terramaster-os"], cpe: "terra-master:terramaster_operating_system", vendor: "TerraMaster", product: "TerraMaster Operating System", label: "TerraMaster TOS",
    when: [[["title", /^TOS Loading$/, 'page title "TOS Loading"']], [["server", /^TOS\b/, "Server: TOS"]], [["powered", /^TerraMaster\b/i, "X-Powered-By: TerraMaster"]]] },
  { ids: ["jenkins"], cpe: "jenkins:jenkins", vendor: "Jenkins", product: "Jenkins",
    when: [[["h:x-jenkins", /\S/, "X-Jenkins header"]]],
    version: [["h:x-jenkins", /^(\d[\w.]*)$/, "header"]] },
  { ids: ["kestra-kestra-oss"], cpe: "kestra:kestra", vendor: "Kestra", product: "Kestra",
    when: [[["title", /^Kestra$/, 'page title "Kestra"'], ["body", /window\.KESTRA_UI_PATH\s*=/, "window.KESTRA_UI_PATH in the root page"]]] },
  // a web UI that sits beside Salt, not the Salt master itself: listed as related, named no CPE product, never matched
  { ids: ["saltstack-salt"], cpe: "", vendor: "SaltStack", product: "", label: "SaltGUI or SaltStack Config web UI (related to SaltStack Salt; not the Salt master)",
    when: [[["title", /^SaltGUI$/, 'page title "SaltGUI"']], [["title", /SaltStack Config/, 'page title "SaltStack Config"']]] },
  { ids: ["citrix-sharefile", "citrix-content-collaboration"], cpe: "citrix:sharefile_storage_zones_controller", vendor: "Citrix", product: "ShareFile Storage Zones Controller",
    when: [[["title", /ShareFile Storage Server/, 'page title "ShareFile Storage Server"']], [["body", /ShareFile Storage Server/, 'root page marker "ShareFile Storage Server"']]] },
  { ids: ["microsoft-sharepoint"], cpe: "microsoft:sharepoint_server", vendor: "Microsoft", product: "SharePoint Server",
    when: [[["hname", /^microsoftsharepointteamservices$/, "MicrosoftSharePointTeamServices header"]], [["hname", /^sprequest/, "SPRequest header"]]] },
  { ids: ["onlyoffice-docs"], cpe: "onlyoffice:document_server", vendor: "ONLYOFFICE", product: "Document Server", label: "ONLYOFFICE Docs",
    when: [[["body", /title=["']ONLYOFFICE/, 'title="ONLYOFFICE attribute']], [["body", /content=["']ONLYOFFICE/, 'meta content="ONLYOFFICE']], [["body", /\/images\/onlyoffice_logo\//, "ONLYOFFICE logo path"]],
      [["body", /alt=["']ONLYOFFICE/, 'alt="ONLYOFFICE']], [["body", /ONLYOFFICE/, 'root page marker "ONLYOFFICE"']]] },
  // g_builddate is a build stamp; mapping it to Utah / Vancouver / Washington DC is not known, so it is evidence only
  { ids: ["servicenow-utah-vancouver-and-washington-dc-now-platform"], cpe: "servicenow:servicenow", vendor: "ServiceNow", product: "ServiceNow", label: "ServiceNow Now Platform",
    when: [[["body", /ServiceNow/i, 'root page marker "ServiceNow"'], ["body", /window\.NOW\./i, "window.NOW. in the root page"], ["body", /NOW\.user\.userID/i, "NOW.user.userID in the root page"]]],
    stamp: ["body", /g_builddate\s*=\s*["']([\w .:\-/]{1,40})["']/, "build stamp g_builddate"] },
  { ids: ["sysaid-sysaid-on-prem", "sysaid-sysaid-server"], cpe: "sysaid:sysaid", vendor: "SysAid", product: "SysAid", label: "SysAid On-Prem (SysAid Server)",
    when: [[["body", /SysAid Help Desk Software/i, 'root page marker "SysAid Help Desk Software"']], [["body", /info@sysaid\.com/i, "SysAid contact address in the root page"]]],
    version: [["body", /(?:ajaxTools\.js|master\.css)\?v=(\d+(?:\.\d+)+)/i, "page"]] },
  { ids: ["istio-or-envoy-admin"], cpe: "envoyproxy:envoy", vendor: "Envoyproxy", product: "Envoy", label: "Envoy (Istio)",
    when: [[["server", /^(?:istio-)?envoy$/i, "Server: envoy"]]] },
]);

/** Catalog rows of this pack deliberately NOT built, with the reason (reported in the handoff). */
export const SKIPPED = Object.freeze({
  "qdrant": "the reviewed signal is 'the root document of a Qdrant server' with no stated token; no marker to match without inventing one",
  "apache-tomcat": "already identified by fingerprint.mjs (Server: Apache-Coyote, no version); the row states no further passive version signal",
  "veritas-backup-exec-agent": "NDMP is binary and the row states no byte signature or version field; the probe reads no NDMP handshake today",
  "microsoft-internet-key-exchange-ike-service-extensions": "needs an IKE hello on UDP/500, which no probe sends; Vendor ID mapping not stated (needs research)",
});

/** What one probed port already collected, as plain strings (header values clipped, cookie NAMES only). */
export function collected(r) {
  const h = r && r.http && r.http.headers && typeof r.http.headers === "object" ? r.http.headers : {};
  const one = (k) => clip(Array.isArray(h[k]) ? h[k][0] : h[k], 300).trim();
  const raw = Array.isArray(h["set-cookie"]) ? h["set-cookie"] : h["set-cookie"] ? [h["set-cookie"]] : [];
  const cookies = raw.slice(0, 30).map((c) => (/^\s*([^=;\s]{1,60})=/.exec(String(c)) || [, ""])[1]).filter(Boolean);
  const c = r && r.tls && r.tls.cert && typeof r.tls.cert.subject === "object" ? r.tls.cert.subject : null;
  const f = (k) => (c && c[k] ? clip(Array.isArray(c[k]) ? c[k][0] : c[k], 100) : "");
  return {
    http: !!(r && r.http), one, names: Object.keys(h).slice(0, 100).map((k) => k.toLowerCase()), cookies,
    title: r && r.http ? httpInfo(r.http).title : "", body: r && r.http ? clip(r.http.body, 65536) : "",
    location: r && r.http && Number(r.http.status) >= 300 && Number(r.http.status) < 400 ? one("location") : "",
    cert: c ? ["CN", "O", "OU"].map((k) => (f(k) ? `${k}=${f(k)}` : "")).filter(Boolean).join(", ") : "",
    banner: r && r.banner ? clip(String(r.banner).split(/\r?\n/)[0], 255).trim() : "",
  };
}

// the text a signal is tested against (a list for header and cookie names)
function field(ev, where) {
  if (where === "server") return ev.one("server");
  if (where === "powered") return ev.one("x-powered-by");
  if (where.startsWith("h:")) return ev.one(where.slice(2));
  if (where === "hname") return ev.names;
  if (where === "cookie") return ev.cookies;
  return ev[where] || "";
}
const hits = (ev, port, [where, re, , opt]) => {
  if (opt && opt.port && opt.port !== port) return false;
  const v = field(ev, where);
  return Array.isArray(v) ? v.some((x) => re.test(x)) : !!v && re.test(v);
};
const SOURCE = { server: "HTTP Server header", powered: "HTTP X-Powered-By header", hname: "HTTP response header", cookie: "HTTP cookie name", title: "page title",
  body: "root page", location: "recorded redirect", cert: "TLS certificate", banner: "greeting" };
const srcOf = (where) => (where.startsWith("h:") ? `HTTP ${where.slice(2)} header` : SOURCE[where] || "HTTP response");

/**
 * One probed port (probe.mjs's result) -> service records for every rule that matches, in the shape fingerprint.mjs uses,
 * plus `catalog` (the catalog ids) and `cpe`. `existing`: records already found for the port; a product already named
 * there is not repeated. Pure.
 */
export function appServices(r, existing = []) {
  if (!r || typeof r !== "object" || r.state === "closed") return [];
  const ev = collected(r), port = r.port, out = [];
  if (!ev.http && !ev.cert && !ev.banner) return out;
  const have = (v, p) => p && (existing || []).concat(out).some((s) => s && s.product && s.product.toLowerCase() === p.toLowerCase() && String(s.vendor || "").toLowerCase() === v.toLowerCase());
  for (const rule of RULES) {
    const group = rule.when.find((g) => g.every((s) => hits(ev, port, s)));
    if (!group || have(rule.vendor, rule.product)) continue;
    // every signal that fired (any group), for the evidence; descriptions only, never page text
    const fired = rule.when.flat().filter((s) => hits(ev, port, s)).map((s) => s[2]).filter((x, i, a) => a.indexOf(x) === i).slice(0, 3);
    let shown = "", version = "", trust = "", from = "";
    for (const [where, re, how] of rule.version || []) {
      const v = field(ev, where), m = typeof v === "string" && v ? re.exec(v) : null;
      const s = m ? cleanVersion(String(m[1]).trim().split(/\s+/)[0]) : "";
      if (s) { shown = s; trust = how; from = where; version = how === "shown" ? "" : core(s); break; }
    }
    let stamp = "";
    if (rule.stamp) { const v = field(ev, rule.stamp[0]), m = typeof v === "string" ? rule.stamp[1].exec(v) : null; if (m) stamp = `${rule.stamp[2]} "${clip(m[1], 40)}" (not mapped to a release)`; }
    const banner = group.some((s) => s[0] === "banner"), proto = banner ? (/^220/.test(ev.banner) ? "ftp" : "banner") : group.some((s) => s[0] === "cert") && !ev.http ? "tls" : r.tls ? "https" : "http";
    const label = rule.label || (rule.vendor && rule.product && !rule.product.toLowerCase().startsWith(rule.vendor.toLowerCase().split(" ")[0]) ? `${rule.vendor} ${rule.product}` : rule.product || rule.vendor);
    const vtext = !shown ? "no version stated" : trust === "shown" ? `version ${shown} shown in the ${srcOf(from)} (not compared: ${from === "title" ? "a login-page title alone never confirms a version" : "it is not the product's release number"})`
      : `version ${shown} from the ${srcOf(from)}`;
    out.push({ port, proto, vendor: rule.vendor, product: rule.product, label, version, shown_version: shown, distro: "",
      source: srcOf(group[0][0]), evidence: clip(`${vtext}${stamp ? `; ${stamp}` : ""}; seen: ${fired.join("; ")}`, 200),
      // stated by a header or greeting with a version: as reliable as fingerprint.mjs's header parsers; anything else is inferred
      guessed: !(version && (trust === "header")), catalog: rule.ids.slice(), cpe: rule.cpe });
  }
  return out;
}
