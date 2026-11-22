// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Research pack (scan-research-pack): product identification from fingerprints that research agents found in PUBLIC
// references (Recog, Nmap's service probes, Wappalyzer/webappanalyzer, nuclei templates and the products' own source). Each
// rule cites its first source in `src`. Every signal reads data the scan ALREADY collected: the greeting a service sends on
// its own, the one root-page response (title, headers, cookie NAMES, body markers, the recorded Location), the TLS
// certificate's subject/issuer, and the existing DNS version.bind answer (udp.mjs). This file sends nothing, opens nothing
// and asks for no path. Fingerprints that need a reply to a message the scanner does not send (Redis PING, MQTT CONNECT,
// Kafka ApiVersions, Oracle TNS, PJL INFO, SQL Server pre-login, MongoDB hello, RDP, SMB, LDAP, ACME ALPN) are not here.
//
// Rules (binding):
//   - a version is read only where the collected data states it (a capture group the source names); otherwise the record
//     is `guessed` and stays out of the headline counts (report.mjs summarize: low confidence)
//   - `compare: false` shows a stated number but never compares it with affected ranges (it is not the product's release)
//   - evidence is the rule's fixed wording plus the version read: never a body, a cookie value, a serial number, a
//     certificate CN or any other device identifier (HP's Server header carries a serial number: it is never kept)
import { cleanVersion } from "./fingerprint.mjs";
import { facts } from "./fp-identify.mjs";

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").slice(0, n);
const core = (v) => (/^\d+(?:\.\d+)*/.exec(v) || [""])[0];
const V = "(\\d+(?:\\.\\d+){1,3})";

const RECOG_TITLE = "https://raw.githubusercontent.com/rapid7/recog/main/xml/html_title.xml";
const RECOG_SERVER = "https://raw.githubusercontent.com/rapid7/recog/main/xml/http_servers.xml";
const RECOG_COOKIE = "https://raw.githubusercontent.com/rapid7/recog/main/xml/http_cookies.xml";
const RECOG_X509 = "https://raw.githubusercontent.com/rapid7/recog/main/xml/x509_subjects.xml";
const RECOG_DNS = "https://raw.githubusercontent.com/rapid7/recog/main/xml/dns_versionbind.xml";
const NMAP = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes";
const WAPPA = (l) => `https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/${l}.json`;
const NUCLEI = (p) => `https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/${p}.yaml`;

/**
 * One rule: { id (the research row), src (first source URL), vendor, product, label?, family? (never a version),
 *   signals: [signal], version: [{ from, re (first capture), compare?, minParts? }], replaces?: [product] }.
 * A rule matches when ANY signal matches; a signal matches when ALL its fields match.
 * Signal fields: title, body, server (RegExp or array of RegExps, all must match), header { name: RegExp }, cookie (a
 *   Set-Cookie NAME), location (the recorded Location, never followed), banner (the greeting read on connect),
 *   subject / issuer { CN|O|OU|L|ST|C: RegExp } (each named certificate field must match), why (fixed evidence text).
 * Version sources: "server", "body", "banner", "header:<name>". minParts: fewer dotted parts than this are shown only.
 * replaces: a guessed, certificate-inferred record of that product on the same port gives way (the cert names a sibling).
 */
export const RULES = Object.freeze([
  /* ---- AI / data platforms (root page title) ---- */
  { id: "jupyter-notebook-or-lab", src: RECOG_TITLE, vendor: "Jupyter", product: "Notebook", label: "Jupyter Notebook", signals: [{ title: /^Jupyter Notebook$/, why: "root page title Jupyter Notebook" }] },
  { id: "jupyter-notebook-or-lab", src: RECOG_TITLE, vendor: "Jupyter", product: "JupyterLab", signals: [{ title: /^JupyterLab$/, why: "root page title JupyterLab" }] },
  { id: "jupyter-notebook-or-lab", src: RECOG_TITLE, vendor: "Jupyter", product: "Jupyter Server", signals: [{ title: /^Jupyter Server$/, why: "root page title Jupyter Server" }] },
  { id: "jupyter-notebook-or-lab", src: RECOG_TITLE, vendor: "Jupyter", product: "JupyterHub", signals: [{ title: /^JupyterHub$/, why: "root page title JupyterHub" }] },
  { id: "langflow", src: "https://raw.githubusercontent.com/langflow-ai/langflow/main/src/frontend/index.html", vendor: "Langflow", product: "Langflow",
    signals: [{ title: /^Langflow$/, why: "root page title Langflow" }] },
  { id: "mlflow", src: "https://raw.githubusercontent.com/mlflow/mlflow/master/mlflow/server/js/public/index.html", vendor: "MLflow", product: "MLflow",
    signals: [{ title: /^MLflow$/, why: "root page title MLflow" }] },
  { id: "ray-dashboard", src: "https://raw.githubusercontent.com/ray-project/ray/master/python/ray/dashboard/client/public/index.html", vendor: "Ray Project", product: "Ray", label: "Ray (dashboard)",
    signals: [{ title: /^Ray Dashboard$/, why: "root page title Ray Dashboard" }] },
  { id: "osgeo-geoserver", src: "https://raw.githubusercontent.com/geoserver/geoserver/main/src/web/core/src/main/java/org/geoserver/web/GeoServerBasePage.html", vendor: "OSGeo", product: "GeoServer",
    signals: [{ title: /^GeoServer\b/, why: "root page title begins GeoServer" }] },
  { id: "apache-ofbiz", src: "https://raw.githubusercontent.com/apache/ofbiz-framework/trunk/framework/webapp/src/main/java/org/apache/ofbiz/webapp/stats/VisitHandler.java", vendor: "Apache", product: "OFBiz",
    signals: [{ cookie: /^OFBiz\.Visitor$/, why: "cookie name OFBiz.Visitor" }] },
  { id: "n8n", src: WAPPA("n"), vendor: "n8n", product: "n8n",
    signals: [{ body: /<meta\s+name="n8n:config:rest-endpoint"/, why: "root page meta n8n:config:rest-endpoint" }, { cookie: /^n8n-auth$/, why: "cookie name n8n-auth" }] },

  /* ---- enterprise applications ---- */
  { id: "sap-netweaver", src: RECOG_SERVER, vendor: "SAP", product: "NetWeaver",
    signals: [{ server: /^SAP NetWeaver Application Server(?: [\d.]+ \/ (?:ICM|AS Java) [\d.]+| \/ ABAP [\d.]+| \(ICM\))?$/, why: "Server header SAP NetWeaver Application Server" },
      { server: /^SAP J2EE Engine(?:\/\d+\.\d+)?$/, why: "Server header SAP J2EE Engine" }],
    // the header's number is the kernel/ICM or engine release, not the component release NVD's ranges use: shown, not compared
    version: [{ from: "server", re: /^SAP NetWeaver Application Server (\d+(?:\.\d+)+) \//, compare: false }, { from: "server", re: /^SAP NetWeaver Application Server \/ ABAP (\d+(?:\.\d+)+)$/, compare: false },
      { from: "server", re: /^SAP J2EE Engine\/(\d+\.\d+)$/, compare: false }] },
  { id: "atlassian-bitbucket-server", src: RECOG_COOKIE, vendor: "Atlassian", product: "Bitbucket",
    signals: [{ cookie: /^BITBUCKETSESSIONID$/, why: "cookie name BITBUCKETSESSIONID" }, { title: /^Log in - Bitbucket$/, why: "root page title Log in - Bitbucket" }],
    version: [{ from: "body", re: new RegExp(`Atlassian Bitbucket\\s*<span[^>]{0,200}\\bid="product-version"[^>]{0,200}>\\s*v${V}`) }] },
  { id: "atlassian-confluence", src: WAPPA("a"), vendor: "Atlassian", product: "Confluence",
    signals: [{ header: { "x-confluence-request-time": /^\d/ }, why: "response header X-Confluence-Request-Time" }, { title: /^(?:Dashboard|Log In) - Confluence$/, why: "root page title Dashboard / Log In - Confluence" }],
    version: [{ from: "body", re: new RegExp(`class="print-only"[^>]{0,120}>[^<]{0,80}Atlassian Confluence ${V}`) }] },
  { id: "atlassian-jira", src: WAPPA("a"), vendor: "Atlassian", product: "Jira",
    signals: [{ body: /<meta\s+name="application-name"\s+content="JIRA"/, why: "root page meta application-name JIRA" }],
    version: [{ from: "body", re: new RegExp(`<meta\\s+name="application-name"\\s+content="JIRA"[^>]{0,300}\\bdata-version="${V}"`) }] },
  { id: "gogs", src: RECOG_COOKIE, vendor: "Gogs", product: "Gogs",
    signals: [{ cookie: /^i_like_gogits$/, why: "cookie name i_like_gogits" }],
    version: [{ from: "body", re: new RegExp(`©\\s*\\d{4}\\s*Gogs\\s+Version:\\s*${V}\\s+Page:`) }] },
  { id: "hashicorp-terraform-enterprise-or-boundary", src: "https://raw.githubusercontent.com/hashicorp/boundary-ui/main/ui/admin/app/index.html", vendor: "HashiCorp", product: "Boundary",
    signals: [{ body: /<meta\s+name="description"\s+content="Simple and secure remote access with HashiCorp Boundary\.">/, why: "root page meta description of the HashiCorp Boundary admin UI" }] },
  { id: "hashicorp-terraform-enterprise-or-boundary", src: "https://raw.githubusercontent.com/hashicorp/boundary-ui/main/ui/admin/app/index.html", vendor: "HashiCorp", product: "Consul",
    signals: [{ title: /^Consul by HashiCorp$/, why: "root page title Consul by HashiCorp" }] },
  { id: "rocket-chat", src: NMAP, vendor: "Rocket.Chat", product: "Rocket.Chat",
    signals: [{ header: { "x-rocket-chat-version": /^\d/ }, why: "response header X-Rocket-Chat-Version" }, { body: /<meta\s+name="application-name"\s+content="Rocket\.Chat"/, why: "root page meta application-name Rocket.Chat" },
      { title: /^Rocket\.Chat\b/, why: "root page title Rocket.Chat" }],
    version: [{ from: "header:x-rocket-chat-version", re: new RegExp(`^${V}$`) }] },

  /* ---- registries, storage, backup ---- */
  { id: "docker-registry-v2", src: "https://raw.githubusercontent.com/distribution/distribution/main/docs/content/spec/api.md", vendor: "Docker", product: "Distribution registry",
    label: "Docker Registry (Distribution; API registry/2.0, software version not stated)",
    signals: [{ header: { "docker-distribution-api-version": /^registry\/2\.0$/ }, why: "response header Docker-Distribution-Api-Version: registry/2.0" }] },
  { id: "harbor-registry", src: WAPPA("h"), vendor: "Linux Foundation", product: "Harbor",
    signals: [{ body: /<harbor-app>/, why: "root page carries the <harbor-app> element" }, { title: /^Harbor$/, why: "root page title Harbor" }] },
  { id: "netapp-ontap-or-oncommand", src: RECOG_SERVER, vendor: "NetApp", product: "Data ONTAP",
    signals: [{ server: /^NetApp\/+\S/, why: "Server header NetApp/<release>" }, { banner: /^SSH-[\d.]+-Data ONTAP SSH [\d.]+\r?$/m, why: "SSH greeting Data ONTAP SSH" }],
    version: [{ from: "server", re: /^NetApp\/+(\d+(?:\.\d+)+\w*)$/ }] },
  { id: "synology-dsm-version-path", src: WAPPA("s"), vendor: "Synology", product: "DiskStation Manager",
    signals: [{ body: /<meta\s+name="application-name"\s+content="Synology DiskStation">/, why: "root page meta application-name Synology DiskStation" },
      { title: / - Synology DiskStation$/, why: "root page title ends - Synology DiskStation" }, { server: /^Synology\/DSM\//, why: "Server header Synology/DSM/" }] },
  { id: "truenas-or-freenas", src: RECOG_TITLE, vendor: "iXsystems", product: "FreeNAS", signals: [{ title: /^FreeNAS$/, why: "root page title FreeNAS (legacy FreeNAS; TrueNAS has no static marker)" }] },
  { id: "commvault", src: NMAP, vendor: "Commvault", product: "Commvault", label: "Commvault (CommVault Galaxy data backup)",
    signals: [{ banner: /^\u0000\u0000\u0000\t\u0000\u0000\u0000\|\u0000\u0000\u0000/, why: "binary greeting of CommVault Galaxy read on connect (Nmap NULL-probe match)" }] },
  { id: "veritas-netbackup-or-backup-exec", src: NMAP, vendor: "Veritas", product: "Backup Exec", label: "Veritas (Symantec) Backup Exec NDMP service",
    signals: [{ banner: /^\u0080\u0000\u0000\u0024\u0000\u0000\u0000\u0001[\s\S]{4}\u0000{6}\u0005\u0002/, why: "NDMPv3 greeting of Backup Exec read on connect (Nmap NULL-probe match)" }] },
  { id: "mongodb-handshake", src: "https://raw.githubusercontent.com/mongodb/docs/master/source/reference/command/hello.txt", vendor: "MongoDB", product: "MongoDB",
    signals: [{ body: /It looks like you are trying to access MongoDB over HTTP on the native driver port\./, why: "MongoDB native port answered the root GET with its HTTP notice" }] },

  /* ---- printers, cameras ---- */
  { id: "axis-communications-camera", src: RECOG_TITLE, vendor: "Axis", product: "network camera", label: "Axis network camera (model and firmware not read)", family: true,
    signals: [{ title: /^AXIS$/, why: "root page title AXIS" }, { server: /^Linux\/\S+-axis[^,]+, UPnP\/[\d.]+, Portable SDK for UPnP devices\/\S+$/, why: "Server header names an -axis Linux kernel with the UPnP SDK" }] },
  { id: "hp-or-vendor-printer-web-ui", src: RECOG_SERVER, vendor: "HP", product: "printer", label: "HP printer (embedded web server)", family: true,
    // the HP HTTP Server header carries the device's serial number: the rule matches on it but keeps only the model family
    signals: [{ server: /^HP HTTP Server; (?:Hewlett-Packard )?HP \S+ \S+[^;]*; Serial Number: [^;]+;/, why: "Server header HP HTTP Server (serial number in the header not kept)", model: /^HP HTTP Server; (?:Hewlett-Packard )?HP (\S+ \S+)/ },
      { server: /^HP-Chai(?:Server|SOE)\/\d+\.\d+$/, why: "Server header HP-ChaiServer/HP-ChaiSOE (embedded web server)" },
      { title: /^HP (?:Color )?LaserJet/, why: "root page title HP LaserJet" }] },
  { id: "ipp-or-cups-printer-identification", src: "https://raw.githubusercontent.com/OpenPrinting/cups/master/man/cupsd.conf.5", vendor: "OpenPrinting", product: "CUPS",
    signals: [{ server: /^CUPS(?:\/[-\w.]+)?(?:\s|$)/, why: "Server header CUPS" }, { title: /^Home - CUPS\b/, why: "root page title Home - CUPS" }],
    // ServerTokens may show only major.minor ("CUPS/2.4"): shown, never compared with patch-level ranges
    version: [{ from: "server", re: /^CUPS\/(\d+(?:\.\d+)+)/, minParts: 3 }] },

  /* ---- identity and access ---- */
  { id: "authelia", src: NUCLEI("exposed-panels/authelia-panel"), vendor: "Authelia", product: "Authelia", signals: [{ title: /^Login - Authelia$/, why: "root page title Login - Authelia" }] },
  { id: "duo-authentication-proxy-or-web-sdk", src: RECOG_TITLE, vendor: "Duo", product: "Access Gateway", label: "Duo Access Gateway", signals: [{ title: /^Duo Access Gateway$/, why: "root page title Duo Access Gateway" }] },
  { id: "duo-authentication-proxy-or-web-sdk", src: RECOG_TITLE, vendor: "Duo", product: "Network Gateway", label: "Duo Network Gateway", signals: [{ title: /^Login - Duo Network Gateway$/, why: "root page title Login - Duo Network Gateway" }] },
  { id: "freeipa", src: "https://raw.githubusercontent.com/freeipa/freeipa/master/install/share/ipa-rewrite.conf.template", vendor: "FreeIPA", product: "FreeIPA",
    // the /ipa/ui redirect is FreeIPA's default; it is a generic-looking path, so the IPASESSION cookie, when set, is named too
    signals: [{ location: /^(?:https?:\/\/[^/\s]+)?\/ipa\/ui\/?$/, cookie: /^IPASESSION$/, why: "redirect to /ipa/ui with the FreeIPA session cookie name IPASESSION" },
      { location: /^(?:https?:\/\/[^/\s]+)?\/ipa\/ui\/?$/, why: "root redirect to /ipa/ui (FreeIPA's default rewrite; recorded, not followed)" }] },
  { id: "shibboleth-idp", src: NUCLEI("technologies/shibboleth-detect"), vendor: "Shibboleth", product: "Identity Provider", label: "Shibboleth IdP",
    signals: [{ title: /^Shibboleth IdP$/, why: "root page title Shibboleth IdP (weak: title only)" }] },

  /* ---- mail ---- */
  { id: "barracuda-email-security-gateway", src: "https://raw.githubusercontent.com/rapid7/recog/main/xml/smtp_banners.xml", vendor: "Barracuda", product: "Email Security Gateway",
    // the 32-hex token in the greeting is per-device: matched, never kept
    signals: [{ banner: /^220 [\w.-]{1,512} ESMTP \([a-fA-F0-9]{32}\)\r?$/m, why: "SMTP greeting in the Barracuda form 220 <host> ESMTP (<32 hex>) (token not kept)" }] },
  { id: "fortinet-fortimail", src: RECOG_X509, vendor: "Fortinet", product: "FortiMail", replaces: ["FortiOS"],
    signals: [{ subject: { CN: /^FortiMail$/, OU: /^FortiMail$/, O: /^Fortinet$/, L: /^Sunnyvale$/, ST: /^California$/, C: /^US$/ }, why: "TLS certificate is FortiMail's default (CN=FortiMail, OU=FortiMail, O=Fortinet)" }] },
  { id: "mailcow", src: "https://raw.githubusercontent.com/mailcow/mailcow-dockerized/master/data/web/templates/base.twig", vendor: "mailcow", product: "mailcow",
    signals: [{ body: /alt="mailcow-logo"/, why: "root page carries the mailcow logo (alt=\"mailcow-logo\")" }] },
  { id: "proofpoint-on-prem-appliance", src: NUCLEI("exposed-panels/proofpoint-protection-server-panel"), vendor: "Proofpoint", product: "Protection Server",
    signals: [{ title: /^Proofpoint Protection Server/, why: "root page title Proofpoint Protection Server" }, { cookie: /^PPSAUTH$/, why: "cookie name PPSAUTH" }] },

  /* ---- monitoring ---- */
  { id: "cacti", src: RECOG_TITLE, vendor: "Cacti", product: "Cacti",
    signals: [{ title: /^Login to Cacti$/, why: "root page title Login to Cacti" }],
    version: [{ from: "body", re: new RegExp(`class=['"]versionInfo['"]>Version ${V}`) }] },
  { id: "jaeger-ui", src: "https://raw.githubusercontent.com/jaegertracing/jaeger-ui/main/packages/jaeger-ui/index.html", vendor: "Jaeger", product: "Jaeger",
    signals: [{ title: /^Jaeger UI$/, why: "root page title Jaeger UI" }, { body: /id="jaeger-ui-root"/, why: "root page carries jaeger-ui-root" }] },
  { id: "librenms", src: RECOG_TITLE, vendor: "LibreNMS", product: "LibreNMS", signals: [{ title: /^LibreNMS$/, why: "root page title LibreNMS" }] },
  { id: "prtg-network-monitor", src: NMAP, vendor: "Paessler", product: "PRTG Network Monitor",
    signals: [{ server: /^PRTG(?:\/[\w.-]+)?$/, why: "Server header PRTG" }, { title: /PRTG Network Monitor/, why: "root page title names PRTG Network Monitor" }],
    version: [{ from: "server", re: /^PRTG\/(\d+(?:\.\d+)+)$/ }] },
  { id: "sentry", src: "https://raw.githubusercontent.com/getsentry/sentry/master/src/sentry/templates/sentry/layout.html", vendor: "Sentry", product: "Sentry",
    signals: [{ body: /images\/logos\/logo-sentry\.svg/, why: "root page links images/logos/logo-sentry.svg (weak: usually the login page)" }] },
  { id: "wazuh-or-ossec-dashboard", src: "https://raw.githubusercontent.com/wazuh/wazuh-packages/master/unattended_installer/cert_tool/certFunctions.sh", vendor: "Wazuh", product: "Wazuh", label: "Wazuh dashboard (default certificate)",
    signals: [{ subject: { O: /^Wazuh$/, OU: /^Wazuh$/, L: /^California$/, C: /^US$/ }, issuer: { O: /^Wazuh$/, OU: /^Wazuh$/ }, why: "TLS certificate from Wazuh's default certificate tool (O=Wazuh, OU=Wazuh, issuer Wazuh root CA)" }] },
  { id: "netdata", src: RECOG_SERVER, vendor: "Netdata", product: "Netdata",
    signals: [{ server: /^NetData Embedded HTTP Server v[a-zA-Z0-9\-.]+$/, why: "Server header NetData Embedded HTTP Server" }],
    version: [{ from: "server", re: /^NetData Embedded HTTP Server v([a-zA-Z0-9\-.]+)$/ }] },

  /* ---- remote access ---- */
  { id: "apache-guacamole", src: "https://raw.githubusercontent.com/apache/guacamole-client/main/guacamole/src/main/frontend/src/index.html", vendor: "Apache", product: "Guacamole",
    signals: [{ body: /<guac-modal>/, why: "root page carries the <guac-modal> element" }] },
  { id: "connectwise-screenconnect", src: RECOG_SERVER, vendor: "ConnectWise", product: "ScreenConnect",
    // the number after the hyphen is not the release: matched, never kept
    signals: [{ server: /^ScreenConnect\/[\d.]+-\d+(?: Microsoft-HTTPAPI\/2\.0)?$/, why: "Server header ScreenConnect/<version>" }],
    version: [{ from: "server", re: /^ScreenConnect\/(\d+(?:\.\d+)+)-\d+/ }] },
  { id: "simplehelp", src: NUCLEI("exposed-panels/simplehelp-login-panel"), vendor: "SimpleHelp", product: "SimpleHelp",
    signals: [{ title: /^Welcome to SimpleHelp$/, why: "page title Welcome to SimpleHelp (weak: the source sees it on /welcome)" }] },
  { id: "jitsi-meet", src: "https://raw.githubusercontent.com/jitsi/jitsi-meet/master/index.html", vendor: "Jitsi", product: "Jitsi Meet",
    signals: [{ body: /libs\/lib-jitsi-meet\.min\.js\?v=/, why: "root page loads libs/lib-jitsi-meet.min.js (build counter, not a release)" }] },
  { id: "github-enterprise-server", src: RECOG_TITLE, vendor: "GitHub", product: "Enterprise Server", label: "GitHub Enterprise Server",
    signals: [{ title: /^(?:GitHub Enterprise|Setup GitHub Enterprise|GitHub Enterprise preflight check)$/, why: "root page title GitHub Enterprise" }] },

  /* ---- server management (BMC) ---- */
  { id: "dell-idrac", src: RECOG_X509, vendor: "Dell", product: "iDRAC", label: "Dell iDRAC (default certificate; generation and firmware not read)", family: true,
    // the CN carries a MAC-like id or the service tag: matched, never kept
    signals: [{ subject: { CN: /^iDRACdefault[0-9A-Fa-f]{12}$/, OU: /^iDRAC Group$/, O: /^Dell Inc\.$/, L: /^Round Rock$/, C: /^US$/ }, why: "TLS certificate is iDRAC's default (OU=iDRAC Group, O=Dell Inc.)" },
      { subject: { CN: /^idrac-[A-Z0-9]{7}$/, OU: /^Remote Access Group$/, O: /^Dell Inc\.$/, L: /^Round Rock$/, ST: /^Texas$/, C: /^US$/ }, why: "TLS certificate is iDRAC's default (OU=Remote Access Group, O=Dell Inc.)" },
      { subject: { CN: /^iDRAC default certificate$/, OU: /^Server Firmware Group$/, O: /^Dell Inc\.$/ }, why: "TLS certificate is iDRAC's default (OU=Server Firmware Group, O=Dell Inc.)" }] },
  { id: "fujitsu-irmc", src: RECOG_TITLE, vendor: "Fujitsu", product: "iRMC", label: "Fujitsu iRMC (generation from the title; firmware not read)", family: true,
    signals: [{ title: /ServerView.* iRMC S\d+ Web Server/, why: "root page title ServerView Remote Management iRMC Web Server" }] },
  { id: "hpe-ilo", src: RECOG_SERVER, vendor: "HPE", product: "Integrated Lights-Out", label: "HPE iLO (Integrated Lights-Out)",
    signals: [{ server: /^HP-iLO-Server\/\S+$/, why: "Server header HP-iLO-Server/<firmware>" }, { title: /^(?:HP Integrated Lights-Out(?: 2)?|iLO [34])$/, why: "root page title HP Integrated Lights-Out / iLO" }],
    version: [{ from: "server", re: /^HP-iLO-Server\/(\d+(?:\.\d+)+)$/ }] },
  { id: "intel-amt-or-vpro-web-ui", src: RECOG_SERVER, vendor: "Intel", product: "Active Management Technology Firmware", label: "Intel AMT (Active Management Technology)",
    signals: [{ server: /^Intel\(R\) Active Management Technology\s\d+(?:\.\d+){1,3}/, why: "Server header Intel(R) Active Management Technology <version>" },
      { server: /^(?:AMT|Intel\(R\) Active Management Technology)$/, why: "Server header AMT" }, { server: /^Intel\(R\) Standard Manageability\b/, why: "Server header Intel(R) Standard Manageability" }],
    version: [{ from: "server", re: new RegExp(`^Intel\\(R\\) (?:Active Management Technology|Standard Manageability)\\s${V}`) }] },
  { id: "supermicro-bmc", src: NUCLEI("exposed-panels/supermicro-bmc-panel"), vendor: "Supermicro", product: "BMC", label: "Supermicro BMC",
    signals: [{ title: /^Supermicro BMC Login$/, why: "root page title Supermicro BMC Login" }] },
].map((r) => Object.freeze({ ...r, signals: Object.freeze(r.signals), version: Object.freeze(r.version || []) })));

/** DNS version.bind answers (CHAOS TXT, the existing udp.mjs query): the server's own words. */
export const DNS_RULES = Object.freeze([
  { id: "dnsmasq", src: RECOG_DNS, vendor: "Thekelleys", product: "dnsmasq", re: /^dnsmasq-(?:pi-hole-)?(\d+\.[\w.]+?)(?:-(?:ubnt|OpenDNS)[\w.-]*)?$/i },
  { id: "knot-dns", src: RECOG_DNS, vendor: "CZ.NIC", product: "Knot DNS", re: /^Knot DNS (\d+(?:\.\d+)+(?:-dev)?)$/ },
  { id: "nsd", src: RECOG_DNS, vendor: "NLnet Labs", product: "Name Server Daemon", label: "NSD (NLnet Labs Name Server Daemon)", re: /^NSD ([\d.]*(?:b\d+)?)$/ },
  { id: "unbound", src: RECOG_DNS, vendor: "NLnet Labs", product: "Unbound", re: /^unbound(?: (\d+(?:\.\d+)+))?$/i },
  { id: "coredns", src: "https://raw.githubusercontent.com/coredns/coredns/master/plugin/chaos/README.md", vendor: "CoreDNS", product: "CoreDNS", re: /^CoreDNS-(\d+(?:\.\d+)+)$/ },
].map((r) => Object.freeze(r)));

/** Every research row this module builds (for docs and tests). */
export const RESEARCH_IDS = Object.freeze([...new Set([...RULES, ...DNS_RULES].map((r) => r.id))]);

const arr = (v) => (Array.isArray(v) ? v : [v]);
// a certificate name object (Node's subject/issuer) -> { CN, O, ... } with the first value of each field
function dnFields(o) {
  const out = {};
  if (o && typeof o === "object") for (const [k, v] of Object.entries(o).slice(0, 16)) out[k] = clip(Array.isArray(v) ? v[0] : v, 120);
  return out;
}
const dnHit = (dn, want) => Object.entries(want).every(([k, re]) => typeof dn[k] === "string" && re.test(dn[k]));

function field(f, key, want) {
  switch (key) {
    case "title": return !!f.title && arr(want).every((re) => re.test(f.title));
    case "body": return !!f.body && arr(want).every((re) => re.test(f.body));
    case "server": return !!f.server && arr(want).every((re) => re.test(f.server));
    case "location": return !!f.location && arr(want).every((re) => re.test(f.location));
    case "banner": return !!f.banner && arr(want).every((re) => re.test(f.banner));
    case "cookie": return arr(want).every((re) => f.cookies.some((n) => re.test(n)));
    case "header": return Object.entries(want).every(([k, re]) => { const v = f.one(k); return !!v && re.test(v); });
    case "subject": return !!f.subject && dnHit(f.subject, want);
    case "issuer": return !!f.issuer && dnHit(f.issuer, want);
    default: return false;
  }
}
const KEYS = ["title", "body", "server", "location", "banner", "cookie", "header", "subject", "issuer"];
const hit = (f, s) => { const k = KEYS.filter((x) => s[x] !== undefined); return k.length > 0 && k.every((x) => field(f, x, s[x])); };

function versionOf(f, rule) {
  for (const v of rule.version) {
    const src = v.from === "server" ? f.server : v.from === "banner" ? f.banner : v.from === "body" ? f.body : v.from.startsWith("header:") ? f.one(v.from.slice(7)) : "";
    const m = src ? v.re.exec(src) : null, shown = m ? cleanVersion(m[1]) : "";
    if (!shown) continue;
    const parts = core(shown).split(".").length, compare = v.compare !== false && !(v.minParts && parts < v.minParts);
    return { shown, compare, from: v.from === "server" ? "Server header" : v.from === "banner" ? "greeting" : v.from === "body" ? "root page" : `${v.from.slice(7)} header` };
  }
  return null;
}
const sourceOf = (s) => (s.banner ? "greeting read on connect" : s.subject || s.issuer ? "TLS certificate" : s.server || s.header ? "HTTP response header" : s.cookie ? "cookie name" : s.location ? "recorded redirect" : "root page");
const protoOf = (r, rule, s) => (s.banner ? ({ "barracuda-email-security-gateway": "smtp", "netapp-ontap-or-oncommand": "ssh", "veritas-netbackup-or-backup-exec": "ndmp" })[rule.id] || "tcp"
  : (s.subject || s.issuer) && !r.http ? "tls" : r.tls ? "https" : "http");
const labelOf = (rule) => rule.label || (rule.vendor && !rule.product.toLowerCase().startsWith(rule.vendor.toLowerCase().split(" ")[0]) ? `${rule.vendor} ${rule.product}` : rule.product);

/** Research-pack identification for one probed port (probe.mjs's result). Pure. -> new service records only. */
export function research(r, existing = []) {
  if (!r || typeof r !== "object" || (!r.http && !r.banner && !(r.tls && r.tls.cert))) return [];
  const cert = r.tls && r.tls.cert ? r.tls.cert : null;
  const f = { ...facts(r), subject: cert ? dnFields(cert.subject) : null, issuer: cert ? dnFields(cert.issuer) : null }, out = [];
  const have = (rule) => [...existing, ...out].some((s) => s && s.port === r.port && s.product && s.product.toLowerCase() === rule.product.toLowerCase() && String(s.vendor || "").toLowerCase() === rule.vendor.toLowerCase());
  for (const rule of RULES) {
    const sig = rule.signals.find((s) => hit(f, s));
    if (!sig || have(rule)) continue;
    const v = rule.family ? null : versionOf(f, rule);
    let label = labelOf(rule);
    if (sig.model) { const m = sig.model.exec(f.server), model = m ? clip(m[1], 40) : ""; if (/^[A-Za-z][\w.\- ]{0,39}$/.test(model)) label = `${label.replace(/ \(.*\)$/, "")} (${model})`; }
    const vtext = !v ? "no version stated" : v.compare ? `version ${v.shown} from the ${v.from}` : `version ${v.shown} shown in the ${v.from} (not compared: ${rule.version.some((x) => x.minParts) ? "only the major.minor line is stated" : "not the product's release number"})`;
    out.push({ port: r.port, proto: protoOf(r, rule, sig), vendor: rule.vendor, product: rule.product, label: clip(label, 120), version: v && v.compare ? core(v.shown) : "", shown_version: v ? v.shown : "", distro: "",
      source: `research pack (${sourceOf(sig)})`, evidence: clip(`${sig.why}; ${vtext} (passive: data already collected)`, 200), guessed: !(v && v.compare), catalog: [rule.id], src: rule.src });
  }
  return out;
}

/**
 * The hook servicesOf (scan.mjs) calls: the services already found on the port plus the research pack's. A product already
 * named on the port is not added twice; a product-less greeting record ("SMTP server") gives way to the product identified
 * from that same greeting; a guessed certificate-inferred record a rule `replaces` (FortiOS for a FortiMail certificate)
 * gives way to the more specific product.
 */
export function withResearch(existing, r) {
  const have = Array.isArray(existing) ? existing : [], add = research(r, have);
  const banner = new Set(add.filter((s) => /\(greeting read on connect\)$/.test(s.source)).map((s) => s.port));
  const gone = add.flatMap((s) => { const rule = RULES.find((x) => x.id === s.catalog[0] && x.product === s.product); return (rule && rule.replaces) || []; });
  return [...have.filter((o) => !(o.product === "" && banner.has(o.port) && !/^https?$/.test(o.proto)) && !(o.guessed && o.source === "TLS certificate" && gone.includes(o.product))), ...add];
}

/** DNS: the existing version.bind answer (udp.mjs result) -> the generic "DNS server" record gives way to a named product. */
export function withResearchUdp(r, svcs) {
  const list = Array.isArray(svcs) ? svcs : [];
  if (!r || r.state !== "open" || r.proto !== "dns" || !r.parsed || !r.parsed.version) return list;
  const text = clip(r.parsed.version, 120).trim();
  for (const rule of DNS_RULES) {
    const m = rule.re.exec(text); if (!m) continue;
    if (list.some((s) => s.product === rule.product)) return list;
    const shown = cleanVersion(m[1] || "");
    const rec = { port: r.port, proto: "dns", vendor: rule.vendor, product: rule.product, label: rule.label || rule.product, version: core(shown), shown_version: shown, distro: "",
      source: "research pack (DNS version.bind)", evidence: clip(`DNS version.bind names ${rule.product}${shown ? `; version ${shown} stated` : "; no version stated"}`, 200), guessed: !shown, catalog: [rule.id], src: rule.src };
    return [...list.filter((s) => s.product !== ""), rec];
  }
  return list;
}
