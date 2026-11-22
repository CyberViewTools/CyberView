// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// scan-app-versions, passive pack 2: application fingerprints read ONLY from what the scan already collected on a port —
// the root page's status, title, headers, body markers and cookie NAMES, the recorded (never followed) redirect Location,
// and a greeting the service sent on its own. This file sends nothing and opens nothing: it is a rules table plus one small
// evaluator. Pure functions.
//
// Each rule: the catalog id(s) it builds, the product as the scanner names it (vendor + product, matched against CyberView's
// flaws with the site's own name matching), the NVD CPE vendor:product it corresponds to (reference only), and the evidence
// it accepts (any one matcher is enough). A version is read only where the matcher says the collected data states one
// (`version: 1` = the first capture group); `compare: false` records the stated number for the reader but never compares it
// with affected ranges (it names a component, not the product's release). A product named without a version is `guessed`:
// matching can then only say "check" (low confidence), which stays out of the headline counts (report.mjs summarize).
// Evidence names the rule's own marker or the header line; never body text, never a cookie value.
import { cleanVersion } from "./fingerprint.mjs";

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").slice(0, n);
const core = (v) => (/^\d+(?:\.\d+)*/.exec(v) || [""])[0];

// fields a matcher may read: title, body, location, server, via, www-authenticate, header:<name>, headers (any header
// value except Set-Cookie), cookie-name, cookie:<name> (the named cookie's value, for a stated version only), banner
const T = (re, label) => ({ field: "title", re, label });
const B = (re, label, extra = {}) => ({ field: "body", re, label, ...extra });
const H = (field, re, label, extra = {}) => ({ field, re, label, ...extra });
const G = (proto, re, label, extra = {}) => ({ field: "banner", proto, re, label, ...extra });

export const RULES = Object.freeze([
  { ids: ["micro-focus-micro-focus-access-manager"], vendor: "Micro Focus", product: "Access Manager", cpe: "microfocus:access_manager",
    note: "points to an Access Manager Identity Server path (/nidp/); the Identity Server may be this host or the one it links to",
    any: [H("location", /\/nidp\//i, "redirect Location to an Identity Server path /nidp/"), B(/\/nidp\//i, "root page references an Identity Server path /nidp/")] },
  { ids: ["omnissa-workspace-one-uem"], vendor: "VMware", product: "Workspace ONE UEM", label: "Omnissa Workspace ONE UEM (formerly VMware AirWatch)", cpe: "vmware:workspace_one_uem_console",
    any: [T(/About VMware AirWatch/i, "page title names About VMware AirWatch"), B(/About VMware AirWatch/i, "root page names About VMware AirWatch"),
      B(/Self-Service Portal/i, "root page names Self-Service Portal and AirWatch", { all: [/AirWatch/i] })] },
  { ids: ["cisco-secure-email-gateway"], vendor: "Cisco", product: "Secure Email Gateway", label: "Cisco Secure Email Gateway (IronPort / AsyncOS)", cpe: "cisco:secure_email_gateway",
    any: [G("ftp", /^220[ -].*\b(?:Cisco )?IronPort FTP server \(V([^)\s]+)\)/i, "FTP greeting names IronPort FTP server", { version: 1 }),
      G("smtp", /^220[ -](?!.*\bFTP\b).*\b(?:IronPort|AsyncOS)\b/i, "SMTP greeting names IronPort / AsyncOS")] },
  { ids: ["mdaemon-email-server"], vendor: "MDaemon", product: "MDaemon Email Server", cpe: "mdaemon:mdaemon",
    any: [G("imap", /^\* OK\b.*\bIMAP4rev1 MDaemon (\d+(?:\.\d+)+\w*) ready/i, "IMAP greeting names MDaemon", { version: 1 }),
      G("pop3", /^\+OK\b.*\bPOP3? MDaemon (\d+(?:\.\d+)+\w*) ready/i, "POP greeting names MDaemon", { version: 1 }),
      // WDaemon is MDaemon's webmail server: its number is recorded, not compared with MDaemon's ranges
      H("server", /^WDaemon\/(\S+)/i, "Server header names WDaemon (MDaemon WorldClient)", { version: 1, compare: false }),
      B(/\/WorldClient\.dll\?View=Main/i, "root page posts to WorldClient.dll?View=Main"), B(/<strong>mdaemon\/worldclient/i, "root page names MDaemon/WorldClient")] },
  { ids: ["playsms-playsms"], vendor: "playSMS", product: "playSMS", cpe: "playsms:playsms",
    any: [B(/index\.php\?app=page&(?:amp;)?inc=(?:register|forgot)/i, "root page links playSMS register / forgot pages"), B(/\/plugin\/themes\/km2\//i, "root page loads the playSMS km2 theme")] },
  { ids: ["roundcube-webmail~kev-auto"], vendor: "Roundcube", product: "Roundcube Webmail", cpe: "roundcube:webmail",
    any: [T(/^RoundCube/i, "page title starts with Roundcube"), B(/id=["']rcmloginuser["']/i, "root page has the Roundcube login field rcmloginuser"),
      B(/new rcube_webmail\(\)/, "root page starts rcube_webmail"), B(/rcmail\.init\(\)/, "root page calls rcmail.init()"),
      B(/"rcversion":\s*(\d{1,7})\b/, "root page states a Roundcube rcversion build number", { version: 1, compare: false }),
      B(/name=["']_user["']/i, "root page has a _user login field and names Roundcube", { all: [/roundcube/i] })] },
  { ids: ["smartertools-smartermail"], vendor: "SmarterTools", product: "SmarterMail", cpe: "smartertools:smartermail",
    any: [G("imap", /^\* OK\b.*\bIMAP4rev1 SmarterMail\b/i, "IMAP greeting names SmarterMail")] },
  { ids: ["apache-superset"], vendor: "Apache", product: "Superset", cpe: "apache:superset",
    // the page's own bootstrap data states the release (HTML-escaped JSON); read only on a page identified as Superset
    version: /version_string(?:&#34;|&quot;|")\s*:\s*(?:&#34;|&quot;|")(\d+(?:\.\d+)+[\w.\-]*)/,
    any: [T(/^Superset$/, "page title is Superset"), B(/alt=["']Superset["']/, "root page has the Superset logo alt=\"Superset\"")] },
  { ids: ["hewlett-packard-hp-openview-network-node-manager"], vendor: "HP", product: "OpenView Network Node Manager", cpe: "hp:openview_network_node_manager",
    note: "a Server header of an OpenView BBC/coda component; its number is the component's, not NNM's release",
    any: [H("server", /^(?:com\.hp\.openview\.)?[cC]oda (\S+)/, "Server header names OpenView coda", { version: 1, compare: false }),
      H("server", /^BBC\b.*\bovbbcrcp (\S+)/, "Server header names OpenView BBC ovbbcrcp", { version: 1, compare: false }),
      H("server", /^com\.hp\.openview\.bbc\.LLBServer (\S+)/, "Server header names OpenView BBC LLBServer", { version: 1, compare: false }),
      H("server", /^BBC\b.*\bovbbccb (\S+)/, "Server header names OpenView BBC ovbbccb", { version: 1, compare: false })] },
  { ids: ["progress-whatsup-gold"], vendor: "Progress", product: "WhatsUp Gold", cpe: "progress:whatsup_gold",
    any: [H("server", /^WhatsUp_Gold\/(\S+)/i, "Server header names WhatsUp_Gold", { version: 1 }), T(/^WhatsUp Gold$/i, "page title is WhatsUp Gold"),
      H("www-authenticate", /realm=["']?WhatsUp ?Gold/i, "WWW-Authenticate realm names WhatsUp Gold")] },
  { ids: ["sciencelogic-sl1"], vendor: "ScienceLogic", product: "SL1", cpe: "sciencelogic:sl1",
    any: [T(/ScienceLogic EM7/i, "page title names ScienceLogic EM7"), B(/login\.em7/, "root page loads login.em7 and css.em7", { all: [/css\.em7/] })] },
  { ids: ["solarwinds-orion"], vendor: "SolarWinds", product: "Orion Platform", cpe: "solarwinds:orion_platform",
    any: [T(/^SolarWinds Orion$/i, "page title is SolarWinds Orion"), B(/SolarWinds Orion/, "root page names SolarWinds Orion"), B(/\/SolarWinds\.css/i, "root page loads /SolarWinds.css")] },
  { ids: ["splunk-enterprise~kev-auto"], vendor: "Splunk", product: "Splunk Enterprise", cpe: "splunk:splunk",
    any: [H("server", /^Splunkd\b/i, "Server header is Splunkd"), T(/^Login - Splunk$/, "page title is Login - Splunk")] },
  { ids: ["tibco-jasperreports"], vendor: "TIBCO", product: "JasperReports Server", cpe: "tibco:jasperreports_server",
    any: [T(/^TIBCO Jaspersoft: Login$/i, "page title is TIBCO Jaspersoft: Login"), T(/Jaspersoft/i, "page title names Jaspersoft")] },
  { ids: ["ivanti-endpoint-manager-epm"], vendor: "Ivanti", product: "Endpoint Manager", cpe: "ivanti:endpoint_manager",
    // the LANDesk Management AGENT is related software, not the EPM core console: excluded
    any: [B(/Ivanti Endpoint Manager/i, "root page names Ivanti Endpoint Manager"), B(/LANDesk(?:\(R\)|®)? Management(?! Agent)/i, "root page names LANDesk Management"),
      H("headers", /Ivanti Endpoint Manager/i, "a response header names Ivanti Endpoint Manager"), H("headers", /LANDesk(?:\(R\)|®)? Management(?! Agent)/i, "a response header names LANDesk Management")] },
  { ids: ["microsoft-remote-desktop-services"], vendor: "Microsoft", product: "Remote Desktop Services", label: "Microsoft Remote Desktop Services (RD Web Access)", cpe: "microsoft:windows (ranges are Windows builds)",
    any: [H("cookie-name", /^TSWAFeatureCheckCookie$/, "cookie name TSWAFeatureCheckCookie (RD Web Access)"),
      B(/Microsoft Remote Desktop/, "root page names Microsoft Remote Desktop with <rdp-client-top-view>", { all: [/<rdp-client-top-view>/i] })] },
  { ids: ["n-able-n-central"], vendor: "N-able", product: "N-central", cpe: "n-able:n-central",
    any: [H("cookie:ncentral_version", /^(\d+\.\d+\.\d+\.\d+)$/, "cookie name ncentral_version states the release", { version: 1 }),
      T(/^N-central Login(?: Redirect)?$/i, "page title is N-central Login")] },
  { ids: ["solarwinds-serv-u"], vendor: "SolarWinds", product: "Serv-U", cpe: "solarwinds:serv-u",
    any: [G("ftp", /^220[ -].*\bServ-U\b/i, "FTP greeting names Serv-U")] },
  { ids: ["wing-ftp-server"], vendor: "Wing FTP", product: "Wing FTP Server", cpe: "wftpserver:wing_ftp_server",
    any: [G("ftp", /^220[ -].*\bWing FTP Server\b/i, "FTP greeting names Wing FTP Server")] },
  { ids: ["kaseya-virtual-system-server-administrator-vsa"], vendor: "Kaseya", product: "VSA", label: "Kaseya VSA", cpe: "kaseya:vsa",
    any: [B(/\/vsapres\/web20\/core\/login\.aspx/i, "root page references /vsapres/web20/core/login.aspx")] },
  { ids: ["trend-micro-apex-one", "trend-micro-officescan"], vendor: "Trend Micro", product: "Apex One (OfficeScan)", cpe: "trendmicro:apex_one, trendmicro:officescan",
    any: [T(/officescan/i, "page title names OfficeScan"), B(/Trend Micro/, "root page names Trend Micro with TMlogonEncrypted", { all: [/TMlogonEncrypted/] })] },
  // the ManageEngine family: each console by its own title (Desktop/Endpoint Central are left to the zoho-desktop-central row)
  ...[["ManageEngine ServiceDesk Plus - MSP", "ManageEngine ServiceDesk Plus MSP", "manageengine_servicedesk_plus_msp"],
    ["ManageEngine ServiceDesk Plus", "ManageEngine ServiceDesk Plus", "manageengine_servicedesk_plus"],
    ["ManageEngine SupportCenter Plus", "ManageEngine SupportCenter Plus", "manageengine_supportcenter_plus"],
    ["ManageEngine OpManager", "ManageEngine OpManager", "manageengine_opmanager"],
    ["ManageEngine AssetExplorer", "ManageEngine AssetExplorer", "manageengine_assetexplorer"],
    ["ADAudit Plus", "ManageEngine ADAudit Plus", "manageengine_adaudit_plus"],
    ["ManageEngine - ADManager Plus", "ManageEngine ADManager Plus", "manageengine_admanager_plus"],
    ["ManageEngine PasswordManager Pro", "ManageEngine Password Manager Pro", "manageengine_password_manager_pro"],
    ["ManageEngine PAM360", "ManageEngine PAM360", "manageengine_pam360"],
    ["ManageEngine Access Manager Plus", "ManageEngine Access Manager Plus", "manageengine_access_manager_plus"]]
    .map(([title, product, cpe]) => ({ ids: ["zoho-manageengine"], vendor: "Zoho", product, cpe: `zohocorp:${cpe}`,
      any: [T(new RegExp(`^${title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:$|\\s)`, "i"), `page title is ${title}`)] })),
  { ids: ["apache-apisix"], vendor: "Apache", product: "APISIX", cpe: "apache:apisix",
    any: [H("server", /^APISIX(?:\/(\S+))?(?:\s|$)/i, "Server header names APISIX", { version: 1 }), T(/^Apache APISIX Dashboard$/i, "page title is Apache APISIX Dashboard")] },
  { ids: ["apache-traffic-server"], vendor: "Apache", product: "Traffic Server", cpe: "apache:traffic_server",
    any: [H("server", /Apache ?Traffic ?Server/i, "Server header names Apache Traffic Server"), H("via", /Apache ?Traffic ?Server/i, "Via header names Apache Traffic Server")] },
  { ids: ["embedthis-goahead"], vendor: "Embedthis", product: "GoAhead", cpe: "embedthis:goahead",
    any: [H("server", /^GoAhead(?:-Webs|-http)?(?:\/(\S+))?(?:\s|$)/i, "Server header names GoAhead", { version: 1 })] },
  { ids: ["envoy-proxy"], vendor: "Envoy Proxy", product: "Envoy", cpe: "envoyproxy:envoy",
    any: [H("server", /^envoy(?:\s|$)/i, "Server header is envoy")] },
  { ids: ["haproxy"], vendor: "HAProxy", product: "HAProxy", cpe: "haproxy:haproxy",
    any: [H("server", /^haproxy\b/i, "Server header names HAProxy"), H("via", /\bhaproxy\b/i, "Via header names HAProxy")] },
  { ids: ["microsoft-http-protocol-stack", "microsoft-http-sys"], vendor: "Microsoft", product: "HTTP.sys (HTTP Protocol Stack)", cpe: "microsoft:windows (ranges are Windows builds)",
    note: "the header states the HTTP API version (usually 2.0), not a Windows build",
    any: [H("server", /^Microsoft-HTTPAPI\/(\S+)/i, "Server header names Microsoft-HTTPAPI", { version: 1, compare: false })] },
  { ids: ["nostromo-nhttpd"], vendor: "Nostromo", product: "nhttpd", cpe: "nazgul:nostromo_nhttpd",
    any: [H("server", /^nostromo\s*([0-9.]+)?/i, "Server header names nostromo", { version: 1 })] },
  { ids: ["squid-caching-proxy"], vendor: "Squid", product: "Squid", label: "Squid caching proxy", cpe: "squid-cache:squid",
    any: [H("server", /^squid\b/i, "Server header names Squid"), H("via", /\bsquid\b/i, "Via header names Squid")] },
  { ids: ["traefik"], vendor: "Traefik Labs", product: "Traefik", cpe: "traefik:traefik",
    any: [H("server", /^traefik\b/i, "Server header names Traefik")] },
  { ids: ["varnish-cache"], vendor: "Varnish", product: "Varnish Cache", cpe: "varnish-cache:varnish",
    any: [H("header:x-varnish", /./, "X-Varnish header is sent"), H("via", /\bvarnish\b/i, "Via header names Varnish")] },
]);

/** The collected evidence on one probed port, as the rules read it. Pure; reads only probe.mjs's result for that port. */
export function evidenceOf(r) {
  const res = r && r.http && typeof r.http === "object" ? r.http : null, H0 = res && res.headers && typeof res.headers === "object" ? res.headers : {};
  const one = (k) => clip(Array.isArray(H0[k]) ? H0[k][0] : H0[k], 300).trim();
  const body = res ? clip(res.body, 65536) : "", t = /<title[^>]*>([^<]{0,200})<\/title>/i.exec(body);
  const cookies = (Array.isArray(H0["set-cookie"]) ? H0["set-cookie"] : H0["set-cookie"] ? [H0["set-cookie"]] : []).slice(0, 30).map((c) => clip(c, 4096));
  const jar = cookies.map((c) => /^\s*([^=;\s]{1,60})=([^;]{0,200})/.exec(c)).filter(Boolean).map((m) => [m[1], m[2].trim()]);
  return { http: !!res, tls: !!(r && r.tls), port: Number(r && r.port) || 0, status: res ? Number(res.status) || 0 : 0,
    title: t ? t[1].replace(/\s+/g, " ").trim().slice(0, 120) : "", body, location: one("location"), server: one("server"), via: one("via"),
    "www-authenticate": one("www-authenticate"), one, headerValues: Object.keys(H0).filter((k) => k !== "set-cookie").slice(0, 60).map(one),
    cookieNames: jar.map(([n]) => n), cookie: (n) => (jar.find(([k]) => k === n) || [, ""])[1],
    banner: r && r.banner ? clip(String(r.banner).split(/\r?\n/)[0], 300).trim() : "" };
}

/** Does one matcher fire on this evidence? -> the regex match (or a stand-in array), or null */
function fire(m, ev) {
  const test = (s) => (typeof s === "string" && s ? m.re.exec(s) : null);
  let hit = null, ctx = "";
  if (m.field === "banner") { hit = test(ev.banner); ctx = ev.banner; }
  else if (!ev.http) return null;
  else if (m.field === "cookie-name") hit = ev.cookieNames.map(test).find(Boolean) || null;
  else if (m.field.startsWith("cookie:")) hit = test(ev.cookie(m.field.slice(7)));
  else if (m.field === "headers") hit = ev.headerValues.map(test).find(Boolean) || null;
  else if (m.field.startsWith("header:")) hit = test(ev.one(m.field.slice(7)));
  else { ctx = ev[m.field]; hit = test(ctx); }
  if (hit && m.all && !m.all.every((re) => re.test(m.field === "title" ? ev.title : ev.body))) return null;
  return hit ? { hit, ctx } : null;
}

const SOURCE = { title: "HTTP page title", body: "HTTP root page", location: "HTTP redirect Location (recorded, not followed)", server: "HTTP Server header", via: "HTTP Via header",
  "www-authenticate": "HTTP WWW-Authenticate header", headers: "HTTP response header", "cookie-name": "HTTP Set-Cookie name" };
const sourceOf = (m) => m.field === "banner" ? `${m.proto.toUpperCase()} greeting` : SOURCE[m.field]
  || (m.field.startsWith("cookie:") ? `HTTP Set-Cookie ${m.field.slice(7)}` : `HTTP ${m.field.slice(7)} header`);

/** The pack-2 services one probed port reveals, from data already collected. -> service records (fingerprint.mjs shape) */
export function appsPack2(r) {
  const ev = evidenceOf(r), out = [];
  if (!ev.http && !ev.banner) return out;
  for (const rule of RULES) {
    if (out.some((s) => s.product === rule.product)) continue;
    let best = null;
    for (const m of rule.any) {
      const f = fire(m, ev); if (!f) continue;
      let shown = m.version ? cleanVersion(f.hit[m.version] || "") : "";
      let compare = m.compare !== false;
      if (!shown && rule.version && ev.http) { const v = rule.version.exec(ev.body); if (v) { shown = cleanVersion(v[1]); compare = true; } }
      const c = { m, f, shown, compare, rank: shown ? (compare ? 2 : 1) : 0 };
      if (!best || c.rank > best.rank) best = c;   // a compared version, then a recorded number, then the first marker
      if (shown && compare) break;
    }
    if (!best) continue;
    const { m, shown, compare } = best, proto = m.field === "banner" ? m.proto : ev.tls ? "https" : "http";
    const version = shown && compare ? core(shown) : "";
    let evidence = m.field === "server" || m.field === "via" || m.field === "www-authenticate" ? `${m.field === "www-authenticate" ? "WWW-Authenticate" : m.field === "via" ? "Via" : "Server"}: ${ev[m.field]}`
      : m.field === "banner" ? `${m.proto.toUpperCase()} greeting: ${ev.banner}`
      : m.field === "title" ? `page title: ${ev.title}` : m.label;
    if (shown && !compare) evidence += ` (stated number ${shown} recorded, not compared with affected ranges)`;
    else if (shown && m.field !== "server" && m.field !== "banner") evidence += ` (version ${shown})`;
    if (rule.note) evidence += `; ${rule.note}`;
    out.push({ port: ev.port, proto, vendor: rule.vendor, product: rule.product,
      label: rule.label || (rule.product.toLowerCase().startsWith(rule.vendor.toLowerCase().split(" ")[0]) ? rule.product : `${rule.vendor} ${rule.product}`),
      version, shown_version: shown, distro: "", source: sourceOf(m),
      evidence: clip(evidence, 200), guessed: !version, catalog: rule.ids.slice() });
  }
  return out;
}

/**
 * The hook servicesOf (scan.mjs) calls: the services already found on the port, plus pack 2's. A pack-2 product already named
 * on the port is not added twice, and a product-less greeting record ("SMTP server") on the same port gives way to the
 * product pack 2 identified from that same greeting.
 */
export function withPack2(existing, r) {
  const have = Array.isArray(existing) ? existing : [], add = appsPack2(r).filter((s) => !have.some((o) => o.port === s.port && o.product && o.product.toLowerCase() === s.product.toLowerCase()));
  const named = new Set(add.filter((s) => !/^https?$/.test(s.proto)).map((s) => s.port));
  return [...have.filter((o) => !(o.product === "" && named.has(o.port) && !/^https?$/.test(o.proto))), ...add];
}
