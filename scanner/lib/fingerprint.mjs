// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Fingerprint parsers: what a service says about itself (a greeting banner, HTTP response headers, a TLS certificate) ->
// product, vendor and version. Pure functions, no network; every input is text the service sent on its own or in answer to
// the scanner's one benign request. Product names follow NVD's CPE names so the version ranges in CyberView's data match.
//
// A service record: { port, proto, product, vendor, version, shown_version, distro, source, evidence, guessed }
//   version        what is compared with the affected ranges (OpenSSH's portable suffix "p1" removed)
//   shown_version  the version exactly as the service stated it
//   distro         a Linux distribution's package build ("Ubuntu", "Debian" ...): fixes may be backported, so a version
//                  inside an affected range is reported with medium confidence, never high
//   guessed        the product is inferred (from a certificate's issuer, a greeting with no version), not stated with a version

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").slice(0, n);
const VER = /^\d+(?:[.\-_+~]\w+)*$/;
export const cleanVersion = (v) => { const s = clip(v, 40).trim().replace(/^v(?=\d)/i, ""); return VER.test(s) ? s : ""; };
function distroOf(s) {
  const t = String(s || "");
  if (/ubuntu/i.test(t)) return "Ubuntu";
  if (/debian|deb\d+u?\d*/i.test(t)) return "Debian";
  if (/red ?hat|rhel|\.el\d/i.test(t)) return "Red Hat";
  if (/centos/i.test(t)) return "CentOS";
  if (/rocky/i.test(t)) return "Rocky Linux";
  if (/alma/i.test(t)) return "AlmaLinux";
  if (/suse/i.test(t)) return "SUSE";
  if (/alpine/i.test(t)) return "Alpine";
  if (/amazon|amzn/i.test(t)) return "Amazon Linux";
  if (/freebsd/i.test(t)) return "FreeBSD";
  return "";
}
// the part of a stated version that is compared with the ranges: "8.1.2-1ubuntu2.19" -> "8.1.2" (the rest is a package build)
const core = (v) => (/^\d+(?:\.\d+)*/.exec(v) || [""])[0];
function svc(port, proto, vendor, product, version, extra = {}) {
  const shown = cleanVersion(version);
  return { port, proto, vendor, product, label: extra.label || (vendor && !product.toLowerCase().startsWith(vendor.toLowerCase().split(" ")[0]) ? `${vendor} ${product}` : product), version: extra.matchVersion !== undefined ? extra.matchVersion : core(shown), shown_version: shown, distro: extra.distro || "",
    source: extra.source || proto, evidence: clip(extra.evidence || "", 200), guessed: !!extra.guessed };
}

/* ---- SSH: the server speaks first, "SSH-2.0-<software> <comment>" (RFC 4253 section 4.2) ---- */
export function fromSsh(banner, port = 22) {
  const line = clip(String(banner || "").split(/\r?\n/)[0], 255).trim();
  const m = /^SSH-(\d\.\d+)-(\S+)(?:\s+(.*))?$/.exec(line);
  if (!m) return [];
  const soft = m[2], comment = m[3] || "", ev = `SSH banner: ${line}`;
  let x;
  if ((x = /^OpenSSH_(\d+\.\d+(?:\.\d+)?)(p\d+)?(?:[-_+](.*))?$/i.exec(soft))) {
    // OpenSSH portable's "p1" is the portability release of the same version: NVD ranges use the base version
    return [svc(port, "ssh", "OpenBSD", "OpenSSH", x[1] + (x[2] || ""), { matchVersion: x[1], distro: distroOf(`${x[3] || ""} ${comment}`), source: "SSH banner", evidence: ev })];
  }
  if ((x = /^dropbear_(\d{4}\.\d+)$/i.exec(soft))) return [svc(port, "ssh", "Dropbear SSH Project", "Dropbear SSH", x[1], { source: "SSH banner", evidence: ev })];
  if ((x = /^libssh[_-](\d+\.\d+(?:\.\d+)?)$/i.exec(soft))) return [svc(port, "ssh", "libssh", "libssh", x[1], { source: "SSH banner", evidence: ev })];
  // OpenSSH whose version could not be read (e.g. "SSH-2.0-OpenSSH" or "OpenSSH_for_Windows" with the number stripped):
  // name the product so the finding is "OpenSSH, version not read" (low confidence), not an anonymous "SSH server".
  if (/^OpenSSH(?:[_-]|$)/i.test(soft)) return [svc(port, "ssh", "OpenBSD", "OpenSSH", "", { source: "SSH banner", evidence: ev, guessed: true })];
  return [svc(port, "ssh", "", "", "", { label: `SSH server (${clip(soft, 40)})`, source: "SSH banner", evidence: ev, guessed: true })];
}

/* ---- FTP, SMTP, POP3, IMAP greetings (the server speaks first) ---- */
const GREET = [
  [/\(vsFTPd (\d[\w.]*)\)/i, "vsftpd Project", "vsftpd", "ftp"],
  [/ProFTPD (\d[\w.]*)/i, "ProFTPD Project", "ProFTPD", "ftp"],
  [/ProFTPD/i, "ProFTPD Project", "ProFTPD", "ftp"],
  [/Pure-FTPd/i, "PureFTPd", "Pure-FTPd", "ftp"],
  [/FileZilla Server(?: version)? (\d[\w.]*)/i, "FileZilla", "FileZilla Server", "ftp"],
  [/Microsoft FTP Service/i, "Microsoft", "Internet Information Services", "ftp"],
  [/ESMTP Exim (\d[\w.]*)/i, "Exim", "Exim", "smtp"],
  [/\bExim\b/i, "Exim", "Exim", "smtp"],
  [/ESMTP Postfix/i, "Postfix", "Postfix", "smtp"],
  [/Sendmail (\d+\.\d+\.\d+)/i, "Sendmail", "Sendmail", "smtp"],
  [/Microsoft ESMTP MAIL Service/i, "Microsoft", "Exchange Server", "smtp"],
  [/Microsoft Exchange (?:IMAP4|POP3)/i, "Microsoft", "Exchange Server", "mail"],
  [/Dovecot/i, "Dovecot", "Dovecot", "mail"],
  [/Cyrus IMAP v?(\d[\w.]*)/i, "Cyrus", "Cyrus IMAP", "mail"],
  [/Courier-IMAP/i, "Courier MTA", "Courier-IMAP", "mail"],
];
export function fromGreeting(banner, port) {
  const text = clip(banner, 1024), first = text.split(/\r?\n/)[0].trim();
  if (!first) return [];
  if (/^SSH-/.test(first)) return fromSsh(first, port);
  if (/^RFB \d{3}\.\d{3}/.test(first)) return [svc(port, "vnc", "", "", "", { label: "VNC server", source: "VNC greeting", evidence: `VNC greeting: ${first} (protocol version only)`, guessed: true })];
  for (const [re, vendor, product, proto] of GREET) {
    const m = re.exec(text);
    if (m) return [svc(port, proto, vendor, product, m[1] || "", { distro: distroOf(first), source: `${proto.toUpperCase()} greeting`, evidence: `${proto.toUpperCase()} greeting: ${first}`, guessed: !m[1] })];
  }
  // a bare "220" greeting is FTP or SMTP: decide by what the banner says, falling back to the port only when it is silent
  // (an FTP service on a non-21 port must not be mislabelled SMTP, and vice versa).
  let proto = "";
  if (/^220[ -]/.test(first)) proto = /\bftp\b/i.test(first) ? "ftp" : /\b(?:e?smtp|mail)\b/i.test(first) ? "smtp" : port === 21 ? "ftp" : [25, 465, 587].includes(port) ? "smtp" : "";
  else if (/^\+OK/.test(first)) proto = "pop3";
  else if (/^\* OK/.test(first)) proto = "imap";
  return proto ? [svc(port, proto, "", "", "", { label: `${proto.toUpperCase()} server`, source: "greeting", evidence: `greeting: ${first}`, guessed: true })] : [];
}

/* ---- MySQL and MariaDB: the server's first packet is a handshake carrying its version (protocol 10) ---- */
export function fromMysql(buf, port = 3306) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || []);
  if (b.length < 6) return [];
  const len = b[0] | (b[1] << 8) | (b[2] << 16), body = b.subarray(4, 4 + Math.min(len, b.length - 4));
  if (body[0] === 0xff) return [svc(port, "mysql", "", "", "", { label: "MySQL-compatible server", source: "MySQL greeting", evidence: "MySQL greeting: the server refused this client before the handshake (no version shown)", guessed: true })];
  if (body[0] !== 0x0a) return [];
  const end = body.indexOf(0, 1), v = clip(body.subarray(1, end > 0 ? Math.min(end, 61) : 61).toString("latin1"), 60);
  const ev = `MySQL handshake: server version ${v}`;
  let m;
  if ((m = /^(?:5\.5\.5-)?(\d+\.\d+\.\d+)-MariaDB/i.exec(v))) return [svc(port, "mysql", "MariaDB", "MariaDB", m[1], { distro: distroOf(v), source: "MySQL handshake", evidence: ev })];
  if ((m = /^(\d+\.\d+\.\d+)/.exec(v))) return [svc(port, "mysql", "Oracle", "MySQL", m[1], { distro: distroOf(v), source: "MySQL handshake", evidence: ev })];
  return [];
}

/* ---- HTTP: the Server and X-Powered-By headers, Exchange's X-OWA-Version, a page's generator meta tag ---- */
const SERVER = [
  [/^apache$/i, "Apache", "HTTP Server"], [/^nginx$/i, "F5", "nginx"], [/^microsoft-iis$/i, "Microsoft", "Internet Information Services"],
  [/^lighttpd$/i, "lighttpd", "lighttpd"], [/^openresty$/i, "OpenResty", "OpenResty"], [/^caddy$/i, "Caddy", "Caddy"],
  [/^litespeed$/i, "LiteSpeed Technologies", "LiteSpeed Web Server"], [/^apache-coyote$/i, "Apache", "Tomcat", "no-version"],
[/^werkzeug$/i, "Pallets", "Werkzeug"], [/^gunicorn$/i, "Gunicorn", "Gunicorn"],
  [/^php$/i, "PHP", "PHP"], [/^python$/i, "Python", "Python"], [/^openssl$/i, "OpenSSL", "OpenSSL"], [/^mod_ssl$/i, "", ""],
];
/** "Apache/2.4.58 (Ubuntu) OpenSSL/3.0.2" -> [{ name, version, comment }] */
export function serverTokens(h) {
  const out = [], s = clip(h, 300).trim();
  const jetty = /^Jetty\(([^)]+)\)/i.exec(s);
  if (jetty) return [{ name: "jetty", version: jetty[1].replace(/\.v\d{8}$/, ""), comment: "" }];
  for (const m of s.matchAll(/([A-Za-z][\w.\-]*)(?:\/([^\s()]+))?(?:\s*\(([^)]*)\))?/g)) out.push({ name: m[1], version: m[2] || "", comment: m[3] || "" });
  return out.slice(0, 12);
}
export function fromHttp(res, port = 80, tls = false) {
  const out = [], h = res && res.headers && typeof res.headers === "object" ? res.headers : {}, proto = tls ? "https" : "http";
  const header = (k) => clip(Array.isArray(h[k]) ? h[k][0] : h[k], 300);
  const add = (vendor, product, version, field, raw, extra = {}) => {
    if (!product || out.some((x) => x.product === product)) return;
    out.push(svc(port, proto, vendor, product, version, { source: `HTTP ${field} header`, evidence: `${field}: ${raw}`, ...extra }));
  };
  for (const field of ["server", "x-powered-by"]) {
    const raw = header(field); if (!raw) continue;
    const toks = serverTokens(raw), distro = distroOf(raw);
    for (const t of toks) {
      if (/^jetty$/i.test(t.name)) { add("Eclipse", "Jetty", t.version, field === "server" ? "Server" : "X-Powered-By", raw); continue; }
      const row = SERVER.find(([re]) => re.test(t.name)); if (!row || !row[2]) continue;
      add(row[1], row[2], row[3] === "no-version" ? "" : t.version, field === "server" ? "Server" : "X-Powered-By", raw, { distro, guessed: row[3] === "no-version" || !cleanVersion(t.version) });
    }
  }
  const owa = header("x-owa-version");
  if (owa) add("Microsoft", "Exchange Server", owa, "X-OWA-Version", owa);
  const body = clip(res && res.body, 65536), gen = /<meta\s+name=["']generator["']\s+content=["']([^"']{1,120})["']/i.exec(body) || /<meta\s+content=["']([^"']{1,120})["']\s+name=["']generator["']/i.exec(body);
  if (gen) {
    const g = gen[1]; let m;
    if ((m = /^WordPress\s+(\d[\w.]*)/i.exec(g))) out.push(svc(port, proto, "WordPress", "WordPress", m[1], { source: "page generator tag", evidence: `generator: ${g}` }));
    else if ((m = /^Drupal\s+(\d+)/i.exec(g))) out.push(svc(port, proto, "Drupal", "Drupal", "", { source: "page generator tag", evidence: `generator: ${g} (major version only)`, guessed: true }));
    else if (/^Joomla/i.test(g)) out.push(svc(port, proto, "Joomla", "Joomla!", "", { source: "page generator tag", evidence: `generator: ${g}`, guessed: true }));
  }
  return out;
}
/** The page title and status, kept as context for the report (never parsed further). */
export function httpInfo(res) {
  const body = clip(res && res.body, 65536), t = /<title[^>]*>([^<]{0,200})<\/title>/i.exec(body);
  const loc = res && res.headers ? clip(res.headers.location, 200) : "";
  return { status: Number(res && res.status) || 0, title: t ? t[1].replace(/\s+/g, " ").trim().slice(0, 120) : "", redirect: loc };
}

/* ---- TLS certificate: who issued it, when it expires; a few appliance makers issue their own default certificates ---- */
const CERT_HINTS = [
  [/fortinet|fortigate/i, "Fortinet", "FortiOS"], [/palo ?alto/i, "Palo Alto Networks", "PAN-OS"], [/pulse secure|ivanti/i, "Ivanti", "Connect Secure"],
  [/citrix|netscaler/i, "Citrix", "NetScaler ADC"], [/sonicwall/i, "SonicWall", "SonicOS"], [/sophos/i, "Sophos", "Sophos Firewall"],
  [/synology/i, "Synology", "DiskStation Manager"], [/qnap/i, "QNAP", "QTS"], [/mikrotik/i, "MikroTik", "RouterOS"], [/zyxel/i, "Zyxel", "Zyxel firmware"],
];
const name = (o) => (o && typeof o === "object" ? ["CN", "O", "OU"].map((k) => (o[k] ? `${k}=${Array.isArray(o[k]) ? o[k][0] : o[k]}` : "")).filter(Boolean).join(", ") : "");
export function certInfo(cert, now = Date.now()) {
  if (!cert || typeof cert !== "object" || !cert.subject) return null;
  const to = Date.parse(cert.valid_to || ""), from = Date.parse(cert.valid_from || "");
  const subject = clip(name(cert.subject), 200), issuer = clip(name(cert.issuer), 200);
  return { subject, issuer, valid_from: isFinite(from) ? new Date(from).toISOString().slice(0, 10) : "", valid_to: isFinite(to) ? new Date(to).toISOString().slice(0, 10) : "",
    expired: isFinite(to) && to < now, self_signed: !!subject && subject === issuer, san: clip(cert.subjectaltname, 300) };
}
export function fromCert(cert, port = 443) {
  const info = certInfo(cert); if (!info) return [];
  const text = `${info.subject} ${info.issuer}`;
  for (const [re, vendor, product] of CERT_HINTS) if (re.test(text)) return [svc(port, "tls", vendor, product, "", { source: "TLS certificate", evidence: `certificate issuer ${info.issuer || "?"}, subject ${info.subject || "?"} (product inferred from the certificate; no version)`, guessed: true })];
  return [];
}

/* ---- UDP service checks (udp.mjs): version.bind TXT (DNS), mode-6 read (NTP), sysDescr GET (SNMP) ---- */
export function fromUdp(result) {
  if (!result || result.state !== "open" || !result.parsed) return [];
  const p = result.parsed, port = result.port, proto = result.proto;
  if (proto === "dns" && p.version) {
    const ev = `DNS version.bind: ${clip(p.version, 120)}`;
    let m;
    if ((m = /BIND\s+(\d+\.\d+(?:\.\d+)?(?:-?[A-Za-z0-9.]+)?)/i.exec(p.version)) || (m = /^(\d+\.\d+\.\d+)/.exec(p.version))) return [svc(port, "dns", "ISC", "BIND", m[1], { distro: distroOf(p.version), source: "DNS version.bind", evidence: ev })];
    return [svc(port, "dns", "", "", "", { label: "DNS server", source: "DNS version.bind", evidence: ev, guessed: true })];
  }
  if (proto === "ntp" && (p.version || p.system)) {
    const ev = `NTP read: version ${clip(p.version || "?", 80)}${p.system ? `, system ${clip(p.system, 60)}` : ""}`, m = /(\d+\.\d+\.\d+(?:p\d+)?)/.exec(p.version || "");
    if (m) return [svc(port, "ntp", "NTP Project", "NTP", m[1], { matchVersion: (/^\d+(?:\.\d+)*/.exec(m[1]) || [""])[0], source: "NTP mode-6 read", evidence: ev })];
    return [svc(port, "ntp", "", "", "", { label: "NTP server", source: "NTP mode-6 read", evidence: ev, guessed: true })];
  }
  return [];   // SNMP sysDescr is a free-text description: kept as an observation, not matched to a CPE
}

/** Observations from the UDP checks a defender wants to know (an exposed SNMP agent answering the default community, the sysDescr it returned). */
export function udpObservations(result) {
  if (!result || result.state !== "open") return [];
  const out = [], p = result.parsed || {};
  if (result.proto === "snmp") {
    out.push({ port: result.port, proto: "snmp", kind: "snmp-public", text: `SNMP answers the default "public" community over UDP${p.sysdescr ? `; sysDescr: ${clip(p.sysdescr, 200)}` : ""}` });
  }
  return out;
}

/** Observations that are not CVEs but a defender wants to know (expired or self-signed certificate, a cleartext login service). */
export function observations(port, { banner = "", cert = null, now = Date.now() } = {}) {
  const out = [], info = cert ? certInfo(cert, now) : null;
  if (info && info.expired) out.push({ port, kind: "tls-expired", text: `The TLS certificate expired on ${info.valid_to}` });
  if (info && info.self_signed) out.push({ port, kind: "tls-self-signed", text: "The TLS certificate is self-signed" });
  if (port === 23) out.push({ port, kind: "cleartext-login", text: "Telnet is open: logins cross the network in clear text" });
  if (port === 21 && /^220/.test(banner)) out.push({ port, kind: "cleartext-login", text: "FTP is open: unless it requires TLS, logins cross the network in clear text" });
  return out;
}
