// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Edge and appliance fingerprints (scan-edge-versions, PR A): VPN gateways, firewalls, load balancers, routers, cameras,
// NAS and switches that CISA lists as known exploited, identified from data the scan ALREADY collected on one port:
// the root page response (page title, a few fixed body markers, the Server header, a WWW-Authenticate realm) and the
// greeting banner. No request, path, connection or login is added here; version files are a later, reviewed change
// (scan-edge-paths, after the path rail). Certificate-only hints stay in fingerprint.mjs (CERT_HINTS).
//
// Rules are data: each row of RULES is one detection-catalog entry (its catalog ids in `ids`), using only the signal the
// catalog row states. A version is reported only where the row says the collected data states one (a Server header's
// version, a version line in the page text outside the title, a versioned asset path, a greeting). Everything else is a
// guessed, version-less hint: matching can then only say "product seen, version to check" (low confidence), which
// stays out of the headline counts. A page title is never read as a version.
import { cleanVersion } from "./fingerprint.mjs";

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n);
const core = (v) => (/^\d+(?:\.\d+)*/.exec(v) || [""])[0];

/*
 * One rule:
 *   ids        the detection-catalog ids this rule builds
 *   vendor     NVD/KEV vendor name; product: the product name, or a template with {model} (the captured model token)
 *   label      how the report names it ({model} allowed)
 *   any        [[field, regex, name?]]: at least one must match (name: a fixed short name used for body markers)
 *   all        [[field, regex, name?]]: every one must ALSO match (a second marker the catalog row requires)
 *   model      [field, regex]: group 1 is a model token; when given, the rule fires only if the model is found
 *   version    [field, regex, name]: group 1 is a version the collected data states; norm(v) rewrites it for comparison
 *   matchFull  compare the full stated version (e.g. "7.4.2a", "2.00W"), not only its leading numbers
 * Fields: title (the page title), body (the page, up to 64 KB), text (the page without its title), server, realm (the
 * WWW-Authenticate realm), ssh (the SSH software token), greeting (a non-HTTP greeting's first lines), header:<name>.
 */
const T = (re) => ["title", re], B = (re, name) => ["body", re, name], S = (re) => ["server", re], R = (re) => ["realm", re];
// D-Link model rows: the literal model token in the Server header, the page title or the realm; a "Ver x.xx" suffix on
// the Server header is the version only for the rows whose catalog entry says so
const dlink = (ids, re, fields, ver = false) => ({ ids, vendor: "D-Link", product: "{model} Firmware", label: "D-Link {model}",
  any: fields.map((f) => [f, re]), model: null, models: fields.map((f) => [f, re]),
  version: ver ? ["server", new RegExp(`${re.source}\\s+Ver\\s+([\\w.]+)`, "i"), "Server header"] : null, matchFull: true });

export const RULES = [
  { ids: ["arcserve-unified-data-protection-udp"], vendor: "Arcserve", product: "Unified Data Protection", label: "Arcserve UDP",
    any: [T(/Arcserve UDP/i), B(/Arcserve UDP/i, "Arcserve UDP branding"), B(/["'(]\/arcserve\.js\b/i, "arcserve.js script path")] },
  { ids: ["array-networks-ag-vxag-arrayos", "array-networks-arrayos-ag"], vendor: "Array Networks", product: "ArrayOS AG", label: "Array Networks AG (ArrayOS)",
    any: [T(/Array Networks Pilot Login/i), B(/Array Networks Pilot Login/i, "Array Networks Pilot Login"), B(/Array Networks/i, "Array Networks branding"), B(/\bArrayOS\b/, "ArrayOS branding")] },
  { ids: ["aviatrix-aviatrix-controller", "aviatrix-controllers"], vendor: "Aviatrix", product: "Controller", label: "Aviatrix Controller",
    any: [T(/^Aviatrix.*Controller$/i)] },
  { ids: ["cisco-catalyst-sd-wan-controller-and-manager", "cisco-catalyst-sd-wan-manager", "cisco-catalyst-sd-wan-manger"], vendor: "Cisco", product: "Catalyst SD-WAN Manager", label: "Cisco Catalyst SD-WAN Manager (vManage)",
    any: [T(/^Cisco vManage$/)] },
  { ids: ["cisco-prime-data-center-network-manager-dcnm"], vendor: "Cisco", product: "Prime Data Center Network Manager", label: "Cisco Prime DCNM",
    any: [B(/Cisco Prime Data Center Network Manager/, "Cisco Prime Data Center Network Manager branding")],
    // "Version: 7.0(2)" -> compared as 7.0.2 (NVD writes Cisco's parenthesised releases with dots)
    version: ["text", /\bVersion:\s*(\d+\.\d+\(\d+[a-z]?\)|\d+\.\d+(?:\.\d+)*)/, "Version line on the login page"], norm: (v) => v.replace(/\((\d+[a-z]?)\)$/i, ".$1") },
  { ids: ["cisco-secure-access-control-system-acs"], vendor: "Cisco", product: "Secure Access Control System", label: "Cisco Secure ACS",
    any: [S(/^(?:Cisco )?ACS [\w._-]+/)], version: ["server", /^(?:Cisco )?ACS ([\w._-]+)/, "Server header"], matchFull: true },
  { ids: ["d-link-dcs-2530l-and-dcs-2670l-devices", "d-link-dcs-930l-devices"], vendor: "D-Link", product: "{model} Firmware", label: "D-Link {model} camera",
    any: [R(/^DCS-[^"]+$/)], model: ["realm", /^(DCS-2530L|DCS-2670L|DCS-930L)$/] },
  { ids: ["d-link-dir-300-router"], vendor: "D-Link", product: "DIR-300 Firmware", label: "D-Link DIR-300",
    any: [T(/^Web Application Manager$/)], all: [["server+body", /D-Link/i, "D-Link branding"]] },
  dlink(["d-link-dir-600-router"], /\b(DIR-600)(?![\w-])/, ["server", "title", "realm"], true),
  dlink(["d-link-dir-605-router"], /\b(DIR-605L?)(?![\w-])/, ["server", "title", "realm"], true),
  dlink(["d-link-dir-610-devices"], /\b(DIR-610)(?![\w-])/, ["server", "title", "realm"]),
  dlink(["d-link-dir-645-router"], /\b(DIR-645)(?![\w-])/, ["server"], true),
  dlink(["d-link-dir-820l"], /\b(DIR-820LW?)(?![\w-])/, ["server"], true),
  dlink(["d-link-dir-820-router"], /\b(DIR-820)(?![\w-])/, ["server"], true),
  dlink(["d-link-dir-823x"], /\b(DIR-823X?)(?![\w-])/, ["server", "title", "realm"]),
  dlink(["d-link-dir-825-r1-devices"], /\b(DIR-825)(?![\w-])/, ["server", "title", "realm"]),
  dlink(["d-link-dir-859-router"], /\b(DIR-859)(?![\w-])/, ["server", "title", "realm"]),
  { ids: ["d-link-dnr-322l"], vendor: "D-Link", product: "DNR-322L Firmware", label: "D-Link DNR-322L video recorder", any: [R(/^DNR-322L$/)] },
  dlink(["d-link-dns-320-device", "d-link-dns-320-storage-device"], /\b(DNS-320)(?![\w-])/, ["title", "server", "realm"]),
  dlink(["d-link-dsl-2750b-devices"], /\b(DSL-2750B?)(?![\w-])/, ["server", "title", "realm"]),
  dlink(["d-link-dsl-2760u"], /\b(DSL-2760U?)(?![\w-])/, ["server", "title", "realm"]),
  { ids: ["dd-wrt-dd-wrt"], vendor: "DD-WRT", product: "DD-WRT", any: [T(/DD-WRT/), B(/DD-WRT/, "DD-WRT branding")] },
  { ids: ["ivanti-cloud-services-appliance-csa"], vendor: "Ivanti", product: "Cloud Services Appliance (CSA)", label: "Ivanti Cloud Services Appliance",
    any: [T(/^Ivanti\(R\) Cloud Services Appliance$/)] },
  { ids: ["juniper-screenos"], vendor: "Juniper", product: "ScreenOS", label: "Juniper ScreenOS (NetScreen)", any: [["ssh", /^NetScreen$/]] },
  { ids: ["microsoft-forefront-threat-management-gateway-tmg"], vendor: "Microsoft", product: "Forefront Threat Management Gateway", label: "Microsoft Forefront TMG / ISA Server",
    any: [B(/The ISA Server denied the specified Uniform Resource Locator \(URL\)/, "ISA Server denied-URL page"),
      B(/No data record is available\. For more information about this event, see ISA Server Help/, "ISA Server error page"),
      ["greeting", /^220-Authenticate for FTP Access\./, "Forefront TMG FTP greeting"]] },
  { ids: ["netgear-wireless-access-point-wap-devices"], vendor: "NETGEAR", product: "{model} Firmware", label: "NETGEAR {model} access point",
    any: [T(/NETGEAR/i), R(/NETGEAR/i)], model: ["title+realm", /NETGEAR\b.*?\b(WAP\w+)\b/i] },
  { ids: ["palo-alto-networks-expedition"], vendor: "Palo Alto Networks", product: "Expedition", label: "Palo Alto Networks Expedition (migration tool)",
    any: [T(/^Expedition Project$/)] },
  { ids: ["progress-loadmaster"], vendor: "Progress", product: "LoadMaster", label: "Progress Kemp LoadMaster", any: [T(/^Kemp Login Screen$/)] },
  { ids: ["sierra-wireless-airlink-aleos"], vendor: "Sierra Wireless", product: "ALEOS", label: "Sierra Wireless AirLink (ALEOS)",
    any: [T(/^::: ACEmanager :::$/)], version: ["text", /\bALEOS Version ([\d.]+)\s*\|\s*Copyright/, "ALEOS Version line on the page"] },
  { ids: ["sonicwall-sma1000-appliances"], vendor: "SonicWall", product: "SMA1000 Firmware", label: "SonicWall SMA 1000",
    any: [S(/^SMA\/[\w.]+/), B(/EXTRAWEB_REFERER/, "EXTRAWEB_REFERER marker"), B(/\/__extraweb__\/[\s\S]{0,4000}SonicWall|SonicWall[\s\S]{0,4000}\/__extraweb__\//i, "SonicWall /__extraweb__/ marker")],
    // the panel signals are shared with SMA 100: named SMA 1000 only when the page, title or Server token says so
    all: [["server+body", /\bSMA ?1000\b/i, "SMA 1000 named"]], version: ["server", /^SMA\/([\d.]+)/, "Server header"] },
  { ids: ["sophos-cyberoamos"], vendor: "Sophos", product: "CyberoamOS", label: "Sophos Cyberoam",
    any: [T(/^Cyberoam(?: SSL VPN Portal)?$/), B(/JavaScript must be enabled in order for you to use cyberoam admin console/i, "Cyberoam admin console marker")],
    version: ["text", /["'(]\/javascript\/validation\/sslvpnlogin\.js\?version=([\w.]+)/i, "asset path sslvpnlogin.js?version="] },
  { ids: ["sophos-sg-utm"], vendor: "Sophos", product: "SG UTM", label: "Sophos SG UTM", any: [T(/^User Portal$/)], all: [B(/\/themes\/lite1\//, "/themes/lite1/ theme path")] },
  { ids: ["sophos-web-appliance"], vendor: "Sophos", product: "Web Appliance", label: "Sophos Web Appliance", any: [T(/^Sophos Web Appliance$/)] },
  { ids: ["tp-link-archer-ax21"], vendor: "TP-Link", product: "Archer AX21 Firmware", label: "TP-Link Archer AX21",
    any: [R(/^TP-LINK .*Router.*AX21\b/i), T(/\b(?:Archer )?AX21\b/)], all: [["title+realm", /TP-LINK|Archer/i, "TP-Link branding"]] },
  { ids: ["tp-link-tl-wa855re"], vendor: "TP-Link", product: "TL-WA855RE Firmware", label: "TP-Link TL-WA855RE", any: [R(/^TP-LINK.*(?:Access Point|Extender|AP) (?:TL-)?WA855RE$/)] },
  { ids: ["tp-link-tl-wr841n"], vendor: "TP-Link", product: "TL-WR841N Firmware", label: "TP-Link TL-WR841N",
    any: [R(/^TP-LINK Wireless N Router WR841N$/), S(/\bTL-WR841N\//)] },
  { ids: ["tp-link-multiple-routers"], vendor: "TP-Link", product: "{model} Firmware", label: "TP-Link {model}", fallback: true,
    any: [R(/^TP-LINK /i), T(/^TP-LINK /i)], model: ["title+realm", /^TP-LINK (?:.*Router.*|.*(?:Access Point|Extender|AP)) ([A-Z0-9+-]+)$/i] },
  { ids: ["zyxel-gs1900-series-switches"], vendor: "Zyxel", product: "{model} Firmware", label: "Zyxel {model} switch", modelDefault: "GS1600 or GS1900",
    // the row's signal is the title (the web server name it also mentions is not used: the repository's attack-string
    // guard refuses that word in scanner files); shared with GS1600, so named GS1900 only when the page or realm says so
    any: [T(/^Intelligent Switch>?$/)], model: ["body+realm", /\b(GS1900)\b/] },
  { ids: ["zyxel-multiple-firewalls"], vendor: "Zyxel", product: "{model} Firmware", label: "Zyxel firewall {model}", modelDefault: "ZyWALL USG",
    any: [B(/\/lib\/mode_ana/, "/lib/mode_ana path"), B(/ZyWALL USG/, "ZyWALL USG branding")], all: [B(/\b(?:VPN|USG|ATP)/, "VPN/USG/ATP")],
    model: ["title", /^((?:USG|ATP|VPN)[A-Za-z0-9 -]{0,30})$/] },
  { ids: ["zyxel-p660hn-t1a-routers"], vendor: "Zyxel", product: "P660HN-T1A Firmware", label: "Zyxel P-660HN-T1A",
    any: [S(/^ZyXEL-RomPager\b/), R(/Prestige|P-?660/), T(/Prestige|P-?660/)], all: [["title+realm+body", /\b(?:P660HN-T1A|P-660HN-T1A|P-660HN)\b/, "P-660HN model token"]] },
  // greeting banners (no HTTP): the catalog's Brocade telnet greeting states the release
  { ids: ["broadcom-brocade-fabric-os"], vendor: "Broadcom", product: "Fabric OS", label: "Brocade Fabric OS",
    any: [["greeting", /Fabric OS \(tm\)\s+Release v[\w.]+/, "Fabric OS telnet greeting"]], version: ["greeting", /Fabric OS \(tm\)\s+Release v([\w.]+)/, "telnet greeting"], matchFull: true },
];

// catalog rows that are certificate-only hints already in fingerprint.mjs CERT_HINTS (listed so coverage is explicit)
export const CERT_ROWS = ["qnap-qts", "synology-diskstation-manager", "citrix-netscaler-adc", "fortinet-fortios", "ivanti-connect-secure", "mikrotik-routeros",
  "palo-alto-pan-os", "sonicwall-sonicos", "sophos-firewall", "zyxel-firmware"];

const headerOf = (h, k) => { const v = h[k]; return clip(Array.isArray(v) ? v.join(", ") : v, 300).trim(); };

/** The fields a rule can look at, from what probe.mjs returned for one port. Nothing here is stored. */
export function edgeFields(r) {
  const res = r && r.http && typeof r.http === "object" ? r.http : null;
  const H = res && res.headers && typeof res.headers === "object" ? res.headers : {};
  const body = res ? clip(res.body, 65536) : "";
  const tm = /<title[^>]*>([^<]{0,200})<\/title>/i.exec(body), title = tm ? tm[1].replace(/\s+/g, " ").trim().slice(0, 120) : "";
  const rm = /realm="([^"]{1,120})"/i.exec(headerOf(H, "www-authenticate"));
  const banner = !res && r && r.banner ? clip(r.banner, 1024) : "";
  const ssh = /^SSH-\d\.\d+-(\S+)/.exec(banner);
  const f = { title, body, text: body.replace(/<title[^>]*>[^<]{0,200}<\/title>/gi, " "), server: headerOf(H, "server"), realm: rm ? rm[1] : "",
    ssh: ssh ? ssh[1] : "", greeting: banner && !ssh ? banner : "", H };
  return f;
}
const get = (f, field) => field.includes("+") ? field.split("+").map((k) => get(f, k)).join("\n") : field.startsWith("header:") ? headerOf(f.H, field.slice(7)) : f[field] || "";
const NAMES = { title: "page title", server: "Server header", realm: "WWW-Authenticate realm", ssh: "SSH banner", greeting: "greeting" };
const SRC = { title: "page title", body: "root page marker", text: "root page marker", server: "HTTP Server header", realm: "HTTP WWW-Authenticate realm", ssh: "SSH banner", greeting: "greeting banner" };
// evidence: a fixed name for body markers; for short fields the value the service sent (clipped), never page content
const why = (f, [field, re, name]) => (field === "body" || field === "text" || field.includes("+") ? `the root page shows the ${name}` : `${NAMES[field] || field} "${clip(get(f, field), 80)}"`);
const VSRC = { text: "root page text", server: "HTTP Server header", greeting: "greeting banner" };

/**
 * The edge/appliance services one probed port shows, from data already collected.
 * r: probe.mjs's result ({ port, banner, http: { status, headers, body }, tls }); have: services already found on this port
 * (a product already named there is not repeated as a hint; a stated version replaces a hint).
 * -> service records ({ port, proto, vendor, product, label, version, shown_version, distro, source, evidence, guessed, catalog })
 */
export function fromEdge(r, have = []) {
  if (!r || typeof r !== "object" || (!r.http && !r.banner)) return [];
  const f = edgeFields(r), port = r.port;
  const proto = r.http ? (r.tls ? "https" : "http") : f.ssh ? "ssh" : /^220[ -]/.test(f.greeting) ? "ftp" : "telnet";
  const list = (Array.isArray(have) ? have : []).filter((s) => s && s.product), out = [];
  const seen = new Set(list.map((s) => s.product)), sure = new Set(list.filter((s) => !s.guessed).map((s) => s.product));
  for (const rule of RULES) {
    const hit = (rule.any || []).find(([field, re]) => re.test(get(f, field)));
    if (!hit || !(rule.all || []).every(([field, re]) => re.test(get(f, field)))) continue;
    // a family rule (no model of its own) steps aside when a model-specific rule of the same vendor already fired
    if (rule.fallback && out.some((s) => s.vendor === rule.vendor)) continue;
    let model = "";
    const tries = rule.models || (rule.model ? rule.model[0].split("+").map((k) => [k, rule.model[1]]) : []);
    for (const [field, re] of tries) { const m = re.exec(get(f, field)); if (m) { model = m[1]; break; } }
    if (!model) model = rule.modelDefault || "";
    if (tries.length && !model) continue;
    const fill = (s) => String(s || "").replace("{model}", clip(model, 40).trim());
    const product = fill(rule.product), label = fill(rule.label || `${rule.vendor} ${rule.product}`);
    let shown = "", vwhy = "", vsrc = "";
    if (rule.version) {
      const [field, re, name] = rule.version, m = re.exec(get(f, field));
      const v = m ? m[m.length - 1] : "";   // the version is the last group (a model rule's pattern has its model group first)
      if (v) { shown = cleanVersion(rule.norm ? rule.norm(v) : v); vwhy = `${name} states ${clip(v, 40)}`; vsrc = VSRC[field] || "root page text"; }
    }
    const reason = why(f, hit);
    const s = { port, proto, vendor: rule.vendor, product, label, version: shown ? (rule.matchFull ? shown.toLowerCase() : core(shown)) : "", shown_version: shown, distro: "",
      source: shown ? vsrc : SRC[hit[0]] || "root page", guessed: !shown, catalog: rule.ids.slice(0, 3),
      evidence: clip(shown ? `${vwhy}; identified by ${reason}` : `${reason} (product inferred; no version stated in the collected data)`, 200) };
    if (sure.has(product) || (s.guessed && seen.has(product))) continue;
    out.push(s); seen.add(product);
    if (out.length >= 4) break;
  }
  return out;
}
