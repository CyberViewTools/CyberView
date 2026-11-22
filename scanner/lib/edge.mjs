// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// [scan-edge-versions] product hints from a page, header, or greeting the scan already collected.
// Each rule is a literal the detection catalog cites. A login title is a guess with no version, so it
// cannot become a version-confirmed finding. Needs-research rows are not here. No new request is made.
// Cisco ASA / AnyConnect and CGI login checks are not here.

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").slice(0, n);

function titleOf(body) {
  const t = /<title[^>]*>([^<]{0,200})<\/title>/i.exec(String(body || ""));
  return t ? t[1].replace(/\s+/g, " ").trim() : "";
}
function header(headers, name) {
  if (!headers) return "";
  const v = headers[name] ?? headers[name.toLowerCase()];
  return clip(Array.isArray(v) ? v[0] : v, 300);
}

function hit(id, vendor, product, version, evidence, guessed) {
  return { id, vendor, product, version: version || "", evidence: clip(evidence, 180), guessed: guessed || !version };
}

/**
 * Already-collected root response -> product rows.
 * Sources are the catalog citations (Nuclei templates, Recog, Nmap service probes).
 */
export function edgeFromHttp(res) {
  const headers = (res && res.headers) || {};
  const body = clip(res && res.body, 65536);
  const title = titleOf(body);
  const server = header(headers, "server");
  const realm = header(headers, "www-authenticate");
  const text = `${title}\n${server}\n${realm}\n${body.slice(0, 8000)}`;
  const out = [];
  const add = (row) => { if (row && row.product && !out.some((x) => x.product === row.product)) out.push(row); };

  // https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposed-panels/arcserve-panel.yaml
  if (/Arcserve UDP/i.test(text)) add(hit("arcserve-unified-data-protection-udp", "Arcserve", "Unified Data Protection", "", "page contains Arcserve UDP (nuclei arcserve-panel)", true));

  // https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposed-panels/array-networks-ssl-vpn-panel.yaml
  if (/Array Networks|ArrayOS/i.test(text)) add(hit("array-networks-arrayos-ag", "Array Networks", "ArrayOS", "", "page contains Array Networks or ArrayOS (nuclei array-networks-ssl-vpn-panel)", true));

  // https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposed-panels/aviatrix-panel.yaml
  if (/^Aviatrix\b/i.test(title) && /Controller/i.test(title)) add(hit("aviatrix-controllers", "Aviatrix", "Controller", "", `title ${title} (nuclei aviatrix-panel)`, true));

  // https://github.com/rapid7/recog/blob/main/xml/http_servers.xml — name the model only when its token is present
  const model = /\b(DNS-320|DSL-2750B|DSL-2760U|DWL-2600AP)\b/.exec(text);
  if (model) add(hit("d-link-" + model[1].toLowerCase(), "D-Link", model[1], "", `model token ${model[1]} in the collected page or header (Recog http_servers)`, true));

  // https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposed-panels/paloalto-expedition-panel.yaml
  if (/Expedition Project/i.test(title)) add(hit("palo-alto-networks-expedition", "Palo Alto Networks", "Expedition", "", "title Expedition Project (nuclei paloalto-expedition-panel)", true));

  // https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposed-panels/kemp-loadmaster-panel.yaml
  if (/Kemp Login Screen/i.test(title)) add(hit("progress-loadmaster", "Progress", "LoadMaster", "", "title Kemp Login Screen (nuclei kemp-loadmaster-panel)", true));

  // https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposed-panels/acemanager-login.yaml
  if (/ACEmanager/i.test(title)) {
    const v = /ALEOS Version\s+(\d+\.\d+(?:\.\d+)?)/i.exec(body);
    add(hit("sierra-wireless-airlink-aleos", "Sierra Wireless", "ALEOS", v ? v[1] : "", v ? `ALEOS Version ${v[1]} on the ACEmanager page` : "title ACEmanager (nuclei acemanager-login)", !v));
  }

  // https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposed-panels/sophos-web-appliance.yaml
  if (/Sophos Web Appliance/i.test(title)) add(hit("sophos-web-appliance", "Sophos", "Web Appliance", "", "title Sophos Web Appliance (nuclei sophos-web-appliance)", true));

  // Cyberoam titles. Version token only when the page's own script query states it.
  if (/^Cyberoam\b/i.test(title)) {
    const v = /sslvpnlogin\.js\?version=(\d[\w.]*)/i.exec(body);
    add(hit("sophos-cyberoamos", "Sophos", "Cyberoam", v ? v[1] : "", v ? `Cyberoam script version ${v[1]}` : `title ${title} (Cyberoam login, no version)`, !v));
  }

  // https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposed-panels/sophos-utm-userportal.yaml
  // The title alone is not Sophos. Both the title and the theme path must be present.
  if (/^User Portal$/i.test(title) && /\/themes\/lite1\//.test(body)) add(hit("sophos-sg-utm", "Sophos", "UTM", "", "title User Portal with /themes/lite1/ (nuclei sophos UTM user portal)", true));

  // SMA Server token carries a version. https://github.com/projectdiscovery/nuclei-templates (sonicwall SMA panel)
  const sma = /\bSMA\/(\d+\.\d+(?:\.\d+)?)/i.exec(server);
  if (sma) add(hit( /1000/.test(text) ? "sonicwall-sma1000-appliances" : "sonicwall-sma100-appliances", "SonicWall", /1000/.test(text) ? "SMA 1000" : "SMA", sma[1], `Server ${server}`, false));
  else if (/EXTRAWEB_REFERER/i.test(text) || (/__extraweb__/i.test(body) && /SonicWall/i.test(body))) add(hit("sonicwall-sma100-appliances", "SonicWall", "SMA", "", "SonicWall SMA marker on the collected page", true));

  // Nmap nmap-service-probes: Server: (?:Cisco )?ACS (version)
  const acs = /^(?:Cisco )?ACS (\d[\w._-]*)/i.exec(server);
  if (acs) add(hit("cisco-secure-access-control-system-acs", "Cisco", "Secure Access Control System", acs[1], `Server ${server} (nmap-service-probes)`, false));

  // FortiSandbox title, or the version header Recog documents as ^(\d+\.\d+\.\d+)$
  const fsa = header(headers, "x-fortisandbox-version");
  const fsaVer = /^(\d+\.\d+\.\d+)$/.exec(fsa);
  if (/FortiSandbox/i.test(title) || fsaVer) add(hit("fortinet-fortisandbox", "Fortinet", "FortiSandbox", fsaVer ? fsaVer[1] : "", fsaVer ? `X-FortiSandbox-Version ${fsaVer[1]}` : "title FortiSandbox", !fsaVer));

  return out.slice(0, 8);
}

/** Greeting already read (Telnet / SSH). Nmap matches Fabric OS on this banner text. */
export function edgeFromBanner(banner) {
  const text = clip(banner, 1024);
  const m = /Fabric OS \(tm\)\s+Release v(\d[\w.]*)/i.exec(text);
  if (!m) return [];
  return [hit("broadcom-brocade-fabric-os", "Broadcom", "Fabric OS", m[1], `greeting Fabric OS Release v${m[1]} (nmap-service-probes)`, false)];
}
