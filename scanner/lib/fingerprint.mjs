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
/* ---- the certificate's own DER: signature and public-key algorithm (Node 22 does not expose them), parsed, never trusted ---- */
// a bounded ASN.1 DER reader: one TLV at a time, lengths checked against the buffer, no recursion beyond what is asked for
function tlv(b, i) {
  if (!b || i + 2 > b.length) return null;
  const tag = b[i]; let len = b[i + 1], o = i + 2;
  if (len & 0x80) { const n = len & 0x7f; if (n < 1 || n > 4 || o + n > b.length) return null; len = 0; for (let k = 0; k < n; k++) len = len * 256 + b[o + k]; o += n; }
  return o + len > b.length ? null : { tag, start: o, end: o + len, next: o + len };
}
const kids = (b, t, max = 12) => { const out = []; for (let i = t.start; i < t.end && out.length < max;) { const c = tlv(b, i); if (!c) break; out.push(c); i = c.next; } return out; };
function oid(b, t) {
  if (!t || t.tag !== 0x06 || t.end - t.start > 32) return "";
  const v = b.subarray(t.start, t.end), out = [Math.floor(v[0] / 40), v[0] % 40]; let n = 0;
  for (let k = 1; k < v.length; k++) { n = n * 128 + (v[k] & 0x7f); if (!(v[k] & 0x80)) { out.push(n); n = 0; } }
  return out.join(".");
}
// signature algorithms by OID -> [name, hash]; the hash is what a "weak signature" is judged on
const SIG_OIDS = {
  "1.2.840.113549.1.1.2": ["md2WithRSAEncryption", "MD2"], "1.2.840.113549.1.1.4": ["md5WithRSAEncryption", "MD5"],
  "1.2.840.113549.1.1.5": ["sha1WithRSAEncryption", "SHA-1"], "1.2.840.113549.1.1.14": ["sha224WithRSAEncryption", "SHA-224"],
  "1.2.840.113549.1.1.11": ["sha256WithRSAEncryption", "SHA-256"], "1.2.840.113549.1.1.12": ["sha384WithRSAEncryption", "SHA-384"],
  "1.2.840.113549.1.1.13": ["sha512WithRSAEncryption", "SHA-512"], "1.2.840.113549.1.1.10": ["RSASSA-PSS", ""],
  "1.2.840.10040.4.3": ["dsaWithSHA1", "SHA-1"], "1.2.840.10045.4.1": ["ecdsa-with-SHA1", "SHA-1"],
  "1.2.840.10045.4.3.2": ["ecdsa-with-SHA256", "SHA-256"], "1.2.840.10045.4.3.3": ["ecdsa-with-SHA384", "SHA-384"], "1.2.840.10045.4.3.4": ["ecdsa-with-SHA512", "SHA-512"],
  "1.3.101.112": ["Ed25519", ""], "1.3.101.113": ["Ed448", ""],
  "2.16.840.1.101.3.4.3.17": ["ML-DSA-44", ""], "2.16.840.1.101.3.4.3.18": ["ML-DSA-65", ""], "2.16.840.1.101.3.4.3.19": ["ML-DSA-87", ""],
};
const KEY_OIDS = { "1.2.840.113549.1.1.1": "RSA", "1.2.840.113549.1.1.10": "RSA-PSS", "1.2.840.10040.4.1": "DSA", "1.2.840.10045.2.1": "EC",
  "1.3.101.110": "X25519", "1.3.101.111": "X448", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
  "2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65", "2.16.840.1.101.3.4.3.19": "ML-DSA-87" };
/** DER certificate -> { sig_alg, sig_hash, key_type } ("" where it cannot be read). Pure; reads only the algorithm fields. */
export function certAlgorithms(raw) {
  const out = { sig_alg: "", sig_hash: "", key_type: "" };
  try {
    const b = Buffer.isBuffer(raw) ? raw : null; if (!b || b.length > 65536) return out;
    const top = tlv(b, 0); if (!top || top.tag !== 0x30) return out;
    const [tbs, sigAlg] = kids(b, top, 3); if (!tbs || !sigAlg) return out;
    const so = oid(b, kids(b, sigAlg, 1)[0]), sig = SIG_OIDS[so];
    out.sig_alg = sig ? sig[0] : so; out.sig_hash = sig ? sig[1] : "";
    // TBSCertificate: [0] version (optional), serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    const f = kids(b, tbs, 8), base = f[0] && f[0].tag === 0xa0 ? 1 : 0, spki = f[base + 5];
    if (spki && spki.tag === 0x30) { const alg = kids(b, spki, 1)[0]; const ko = alg ? oid(b, kids(b, alg, 1)[0]) : ""; out.key_type = KEY_OIDS[ko] || ko; }
  } catch { /* unreadable: leave blank */ }
  return out;
}

export function certInfo(cert, now = Date.now()) {
  if (!cert || typeof cert !== "object" || !cert.subject) return null;
  const to = Date.parse(cert.valid_to || ""), from = Date.parse(cert.valid_from || "");
  const subject = clip(name(cert.subject), 200), issuer = clip(name(cert.issuer), 200), alg = certAlgorithms(cert.raw);
  return { subject, issuer, valid_from: isFinite(from) ? new Date(from).toISOString().slice(0, 10) : "", valid_to: isFinite(to) ? new Date(to).toISOString().slice(0, 10) : "",
    expired: isFinite(to) && to < now, not_yet_valid: isFinite(from) && from > now, days_left: isFinite(to) ? Math.floor((to - now) / 86400000) : null,
    self_signed: !!subject && subject === issuer, san: clip(cert.subjectaltname, 300),
    key_type: clip(alg.key_type, 40), key_bits: Number(cert.bits) || 0, curve: clip(cert.curve, 40), sig_alg: clip(alg.sig_alg, 60), sig_hash: clip(alg.sig_hash, 20),
    fingerprint256: /^[0-9A-F:]{95}$/i.test(String(cert.fingerprint256 || "")) ? String(cert.fingerprint256).toUpperCase() : "" };
}

/* ---- the negotiated TLS parameters, as recorded from the one handshake ---- */
/** -> { protocol, cipher, cipher_std, kex_type, kex_group, kex_bits, kex_note, pqc } */
export function tlsInfo(t) {
  if (!t || typeof t !== "object") return null;
  const k = t.kex && typeof t.kex === "object" ? t.kex : {}, protocol = clip(t.protocol, 20), group = clip(k.name, 40);
  // Node names the classical groups it negotiated (X25519, prime256v1, a DH size) but reports nothing for a hybrid
  // post-quantum group; never read a blank as "no PQC" or as "PQC": say it was not reported.
  const unreported = protocol === "TLSv1.3" && !k.type;
  return { protocol, cipher: clip(t.cipher, 80), cipher_std: clip(t.cipher_std, 80), kex_type: clip(k.type, 10), kex_group: group, kex_bits: Number(k.size) || 0,
    kex_note: unreported ? "key-exchange group not reported by this runtime (Node does not name hybrid post-quantum groups such as X25519MLKEM768)" : "",
    pqc: /MLKEM|KYBER/i.test(group) };
}

/** Does a certificate name a host? RFC 6125: SAN DNS names first (CN only when there is no SAN), one left-most "*" label. */
export function certNames(cert) {
  const san = String((cert && (cert.san !== undefined ? cert.san : cert.subjectaltname)) || ""), dns = [...san.matchAll(/DNS:([^,\s]+)/g)].map((m) => m[1].toLowerCase());
  if (dns.length) return dns.slice(0, 100);
  const cn = /CN=([^,]+)/.exec(typeof (cert && cert.subject) === "string" ? cert.subject : name(cert && cert.subject));
  return cn ? [cn[1].trim().toLowerCase()] : [];
}
export function nameMatches(names, host) {
  const h = String(host || "").toLowerCase().replace(/\.$/, "");
  return (names || []).some((n) => n === h || (n.startsWith("*.") && h.endsWith(n.slice(1)) && h.split(".").length === n.split(".").length));
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
    out.push({ port: result.port, proto: "snmp", kind: "snmp-public", severity: "medium", text: `SNMP answers the default "public" community over UDP${p.sysdescr ? `; sysDescr: ${clip(p.sysdescr, 200)}` : ""}` });
  }
  return out;
}

// thresholds for the TLS observations (fixed, documented in docs/scanner.md)
export const TLS_RULES = Object.freeze({ expiringDays: 30, minRsaBits: 2048, minEcBits: 224, minDhBits: 2048,
  oldProtocols: ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"], weakHashes: ["MD2", "MD5", "SHA-1"],
  weakCipher: /(^|[_-])(NULL|EXPORT|EXP|RC4|RC2|DES|3DES|DES-CBC3|IDEA|ANON|ADH|AECDH|MD5)([_-]|$)/i });
const cap1 = (s) => s.charAt(0).toUpperCase() + s.slice(1);

/**
 * Observations that are not CVEs but a defender wants to know: certificate problems, weak negotiated TLS, a cleartext
 * login service. Pure; works only on what one connection already returned (no extra probe).
 * opts: { banner, cert (as probe.mjs returns it), tls (probe.mjs tls object), names (the attested names used for this host), now }
 * -> [{ port, kind, severity: high | medium | low | info, text }]
 */
export function observations(port, { banner = "", cert = null, tls = null, names = [], now = Date.now() } = {}) {
  const out = [], info = cert ? certInfo(cert, now) : null, t = tls ? tlsInfo(tls) : null;
  const add = (kind, severity, text) => out.push({ port, kind, severity, text });
  if (info) {
    if (info.expired) add("tls-expired", "high", `The TLS certificate expired on ${info.valid_to}`);
    else if (info.not_yet_valid) add("tls-not-yet-valid", "medium", `The TLS certificate is not valid until ${info.valid_from}`);
    else if (info.days_left != null && info.days_left <= TLS_RULES.expiringDays) add("tls-expiring", "medium", `The TLS certificate expires in ${info.days_left} day(s), on ${info.valid_to}`);
    if (info.self_signed) add("tls-self-signed", "low", "The TLS certificate is self-signed");
    const rsa = /^(RSA|RSA-PSS|DSA)$/.test(info.key_type) || (!info.key_type && !info.curve);
    if (info.key_bits && rsa && info.key_bits < TLS_RULES.minRsaBits) add("tls-weak-key", "high", `The TLS certificate's ${info.key_type || "RSA"} key is ${info.key_bits} bits (under ${TLS_RULES.minRsaBits})`);
    if (info.key_bits && info.key_type === "EC" && info.key_bits < TLS_RULES.minEcBits) add("tls-weak-key", "high", `The TLS certificate's EC key is ${info.key_bits} bits (under ${TLS_RULES.minEcBits})`);
    // a weak hash on a self-signed leaf is not what browsers judge, but it is still a weak signature worth replacing
    if (TLS_RULES.weakHashes.includes(info.sig_hash)) add("tls-weak-signature", info.self_signed ? "medium" : "high", `The TLS certificate is signed with ${info.sig_hash} (${info.sig_alg})`);
    const want = (names || []).filter((n) => n && !/^[\d.:]+$/.test(n));
    if (want.length) { const cn = certNames(info); if (cn.length && !want.some((n) => nameMatches(cn, n))) add("tls-name-mismatch", "medium", `The TLS certificate does not name ${want.slice(0, 3).join(", ")} (it names ${cn.slice(0, 4).join(", ")}${cn.length > 4 ? " ..." : ""})`); }
  }
  if (t) {
    if (TLS_RULES.oldProtocols.includes(t.protocol)) add("tls-old-protocol", "high", `${t.protocol} was negotiated: the server accepts a protocol version that is retired (RFC 8996)`);
    if (TLS_RULES.weakCipher.test(t.cipher) || TLS_RULES.weakCipher.test(t.cipher_std)) add("tls-weak-cipher", "high", `A weak cipher suite was negotiated: ${t.cipher_std || t.cipher}`);
    if (t.kex_type === "DH" && t.kex_bits && t.kex_bits < TLS_RULES.minDhBits) add("tls-weak-dh", "high", `The ephemeral Diffie-Hellman group is ${t.kex_bits} bits (under ${TLS_RULES.minDhBits})`);
    if (/^TLS_RSA_WITH_/i.test(t.cipher_std)) add("tls-no-forward-secrecy", "low", `${t.cipher_std} has no forward secrecy (RSA key exchange)`);
  }
  if (port === 23) add("cleartext-login", "high", "Telnet is open: logins cross the network in clear text");
  if (port === 21 && /^220/.test(banner)) add("cleartext-login", "medium", "FTP is open: unless it requires TLS, logins cross the network in clear text");
  return out.map((o) => ({ ...o, text: cap1(o.text) }));
}

/* ---- HTTP and mail hygiene (tk-hygiene PR 2): from the one GET / response and the greeting already read ---- */
// fixed lists; each entry is a page title or a marker that vendors ship verbatim. Only the entry's NAME goes into the report,
// never the matched text or any part of the body.
const DEFAULT_TITLES = [
  [/^Apache2 (?:Ubuntu|Debian) Default Page/i, "Apache2 Ubuntu/Debian default page"], [/^Test Page for the (?:Apache|Nginx) HTTP Server/i, "Red Hat/CentOS test page"],
  [/^Welcome to nginx!?$/i, "nginx welcome page"], [/^IIS Windows Server$|^IIS\d*$|^Internet Information Services$/i, "IIS default page"],
  [/^Apache Tomcat\/\d/i, "Tomcat default page"], [/^Welcome to CentOS$/i, "CentOS welcome page"], [/^Welcome to JBoss/i, "JBoss/WildFly welcome page"],
  [/^Welcome to Jetty/i, "Jetty welcome page"], [/^Caddy works!?$/i, "Caddy default page"], [/^Default Web Site Page$/i, "Plesk default page"],
];
const SETUP_TITLES = [[/WordPress\s*(?:›|&rsaquo;|>)?\s*(?:Setup Configuration File|Installation)/i, "WordPress installer"], [/Joomla! Web Installer/i, "Joomla installer"],
  [/^phpMyAdmin setup/i, "phpMyAdmin setup"], [/Drupal.*(?:Choose language|Installation)/i, "Drupal installer"], [/^Installation\s*[-–|]\s*Matomo/i, "Matomo installer"]];
const DEBUG_MARKERS = [
  [/you(?:'|&#39;|&#x27;)re seeing this error because you have <code>DEBUG = True<\/code>/i, "Django debug page"],
  [/<title>[^<]*Werkzeug Debugger<\/title>/i, "Werkzeug debugger page"], [/Whoops! There was an error\./i, "Whoops (PHP) error page"],
  [/Server Error in '\/[^']*' Application\./i, "ASP.NET error page with details"], [/Action Controller: Exception caught/i, "Rails exception page"],
  [/<b>(?:Fatal|Parse) error<\/b>:.{0,200} on line <b>\d+<\/b>/is, "PHP error with file path"],
  [/\bat (?:java|javax|org\.springframework|org\.apache)\.[\w$.]+\((?:\w+\.java:\d+|Native Method)\)/, "Java stack trace"],
  [/Traceback \(most recent call last\):/, "Python traceback"],
];
const CDN = [["cf-ray", "Cloudflare"], ["x-amz-cf-id", "Amazon CloudFront"], ["x-akamai-request-id", "Akamai"], ["akamai-grn", "Akamai"], ["x-sucuri-id", "Sucuri"],
  ["x-iinfo", "Imperva"], ["x-azure-ref", "Azure Front Door"], ["x-fastly-request-id", "Fastly"], ["x-vercel-id", "Vercel"]];
export const HTTP_RULES = Object.freeze({ minHstsSeconds: 15552000, maxSkewSeconds: 300 });

/**
 * Hygiene observations from the root page response already collected. Pure.
 * opts: { tls (the page came over TLS), inScope (host -> bool, for redirect targets), names (the host's attested names), now }
 */
export function httpObservations(port, res, { tls = false, inScope = () => false, now = Date.now() } = {}) {
  const out = [], add = (kind, severity, text) => out.push({ port, kind, severity, text });
  if (!res || typeof res !== "object") return out;
  const H = res.headers && typeof res.headers === "object" ? res.headers : {};
  const one = (k) => clip(Array.isArray(H[k]) ? H[k][0] : H[k], 2000).trim(), status = Number(res.status) || 0;
  const body = clip(res.body, 65536), title = httpInfo(res).title, html = /html/i.test(one("content-type")) || /<html|<title/i.test(body);
  // redirects: recorded, never followed
  const loc = one("location");
  if (status >= 300 && status < 400 && loc) {
    let u = null; try { u = new URL(loc, `${tls ? "https" : "http"}://placeholder.invalid/`); } catch { /* not a URL */ }
    if (u && u.hostname !== "placeholder.invalid") {
      if (tls && u.protocol === "http:") add("http-downgrade-redirect", "medium", `HTTPS redirects to plain HTTP (${clip(u.origin, 120)})`);
      if (!inScope(u.hostname.replace(/^\[|\]$/g, ""))) add("http-redirect-out-of-scope", "info", `The root page redirects to ${clip(u.hostname, 100)}, outside the scope (recorded, not followed)`);
    } else if (u && tls && u.protocol === "http:") add("http-downgrade-redirect", "medium", "HTTPS redirects to plain HTTP on the same host");
  }
  if (!tls && status >= 200 && status < 300 && html) add("http-no-https", "low", "The site is served over plain HTTP with no redirect to HTTPS");
  // security headers (only on a page: a 2xx HTML response)
  if (status >= 200 && status < 300 && html) {
    const missing = [];
    if (tls) {
      const hsts = one("strict-transport-security"), m = /max-age\s*=\s*"?(\d+)/i.exec(hsts);
      if (!hsts) missing.push("Strict-Transport-Security");
      else if (!m || +m[1] < HTTP_RULES.minHstsSeconds) add("http-weak-hsts", "low", `Strict-Transport-Security max-age is ${m ? m[1] : "missing"} (under ${HTTP_RULES.minHstsSeconds} seconds, 180 days)`);
    }
    const csp = one("content-security-policy");
    if (!csp) missing.push("Content-Security-Policy");
    else { const bad = ["'unsafe-inline'", "'unsafe-eval'"].filter((x) => new RegExp(`script-src[^;]*${x}|default-src[^;]*${x}`, "i").test(csp)); if (bad.length) add("http-weak-csp", "low", `Content-Security-Policy allows ${bad.join(" and ")} for scripts`); }
    if (!/nosniff/i.test(one("x-content-type-options"))) missing.push("X-Content-Type-Options");
    if (!one("x-frame-options") && !/frame-ancestors/i.test(csp)) missing.push("X-Frame-Options (or CSP frame-ancestors)");
    const rp = one("referrer-policy");
    if (!rp) missing.push("Referrer-Policy"); else if (/unsafe-url/i.test(rp)) add("http-weak-referrer-policy", "low", "Referrer-Policy is unsafe-url: full URLs are sent to other sites");
    if (!one("permissions-policy")) missing.push("Permissions-Policy");
    if (missing.length) add("http-missing-headers", missing.includes("Strict-Transport-Security") ? "medium" : "low", `Security headers missing: ${missing.join(", ")}`);
  }
  // cookies: names only, never values
  const cookies = (Array.isArray(H["set-cookie"]) ? H["set-cookie"] : H["set-cookie"] ? [H["set-cookie"]] : []).slice(0, 30).map((c) => clip(c, 4096));
  const cname = (c) => clip((/^\s*([^=;\s]{1,60})=/.exec(c) || [, "?"])[1], 60);
  const noSecure = tls ? cookies.filter((c) => !/;\s*secure\b/i.test(c)).map(cname) : [], noHttpOnly = cookies.filter((c) => !/;\s*httponly\b/i.test(c)).map(cname);
  if (noSecure.length) add("http-cookie-not-secure", "medium", `Cookie(s) set without Secure over HTTPS: ${noSecure.slice(0, 6).join(", ")}`);
  if (noHttpOnly.length) add("http-cookie-not-httponly", "low", `Cookie(s) set without HttpOnly (readable by page scripts): ${noHttpOnly.slice(0, 6).join(", ")}`);
  if (one("access-control-allow-origin") === "*") add("http-cors-wildcard", "low", "Access-Control-Allow-Origin is * on the root page");
  // default, setup and debug pages: the entry's name only
  if (title) {
    const d = DEFAULT_TITLES.find(([re]) => re.test(title)); if (d) add("http-default-page", "low", `A default page is served: ${d[1]}`);
    const s = SETUP_TITLES.find(([re]) => re.test(title)); if (s) add("http-setup-page", "high", `An unfinished setup page is served: ${s[1]} (anyone who reaches it may complete the installation)`);
    if (/^(?:Index of \/|Directory listing for \/)/i.test(title)) add("http-directory-listing", "medium", "The root page is a directory listing");
  } else if (/<h1>It works!<\/h1>/i.test(body)) add("http-default-page", "low", "A default page is served: Apache \"It works!\" page");
  const dbg = DEBUG_MARKERS.filter(([re]) => re.test(body)).map(([, n]) => n);
  if (dbg.length) add("http-debug-page", "high", `The root page shows debug output: ${dbg.slice(0, 3).join(", ")} (the page text is not copied)`);
  const dh = ["x-debug-token", "x-debug-token-link"].filter((k) => H[k]);
  if (dh.length) add("http-debug-header", "medium", `A debug/profiler header is sent: ${dh.join(", ")}`);
  if (/[#@]\s*sourceMappingURL=/.test(body) || H["sourcemap"] || H["x-sourcemap"]) add("http-source-map", "info", "The root page references a JavaScript source map (original source may be readable)");
  // methods and protocols the server advertises in headers it sent anyway (no OPTIONS request is made)
  const allow = one("allow").toUpperCase();
  if (/\b(TRACE|TRACK)\b/.test(allow)) add("http-trace-allowed", "medium", `The Allow header lists ${allow.match(/\b(TRACE|TRACK)\b/g).join(" and ")}`);
  if (one("dav") || /\b(PROPFIND|MKCOL)\b/.test(allow)) add("http-webdav", "info", "WebDAV is advertised (DAV or Allow header)");
  const alt = one("alt-svc"); if (/\bh3\b|\bh2\b/i.test(alt)) add("http-alt-svc", "info", `Alt-Svc advertises ${[...new Set(alt.match(/\bh[23]\b/gi).map((x) => x.toLowerCase()))].join(" and ")}`);
  const cdn = CDN.find(([k]) => H[k]); if (cdn) add("http-cdn-front", "info", `The response came through ${cdn[1]}: these results describe the front, not the origin server`);
  const date = Date.parse(one("date"));
  if (isFinite(date) && Math.abs(date - now) / 1000 > HTTP_RULES.maxSkewSeconds) add("http-clock-skew", "low", `The server clock is off by about ${Math.round(Math.abs(date - now) / 60000)} minute(s) (HTTP Date header)`);
  const server = one("server");
  if (/\d+\.\d+/.test(server) && distroOf(server)) add("http-server-patch-level", "info", `The Server header states a version and package build: ${clip(server, 80)}`);
  else if (/\/\d+\.\d+/.test(server)) add("http-server-version", "info", `The Server header states a version: ${clip(server, 80)}`);
  return out.map((o) => ({ ...o, text: cap1(o.text) }));
}

/** Cleartext mail: a POP3/IMAP/SMTP-submission greeting read without TLS (STARTTLS may still be offered; it is not checked). */
export function mailObservations(port, banner, { tls = false } = {}) {
  const first = String(banner || "").split(/\r?\n/)[0];
  if (tls || !first) return [];
  if ((port === 110 && /^\+OK/.test(first)) || (port === 143 && /^\* OK/.test(first))) return [{ port, kind: "cleartext-mail", severity: "medium", text: `${port === 110 ? "POP3" : "IMAP"} answers without TLS on port ${port}: unless STARTTLS is required, mail logins cross the network in clear text` }];
  if (port === 587 && /^220/.test(first)) return [{ port, kind: "cleartext-submission", severity: "low", text: "SMTP submission answers without TLS on port 587: logins are safe only if STARTTLS is required before AUTH (not checked)" }];
  return [];
}

/** The fixed fingerprint tables, read-only, for the KEV coverage-gap report (scanner/lib/kev-coverage.mjs). */
export const FINGERPRINT_TABLES = Object.freeze({ GREET, SERVER, CERT_HINTS });
