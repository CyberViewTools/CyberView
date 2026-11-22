// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// [scan-kev-coverage] KEV products the installed fingerprints do not name. No network.
// The list is the products the parsers actually emit. A product missing from it is a gap, which is
// the point of the report. It is not a claim that the product is absent from a network.

import { W } from "./shared.mjs";

export const FINGERPRINT_PRODUCTS = [
  "OpenSSH", "Dropbear SSH", "libssh", "vsftpd", "ProFTPD", "Pure-FTPd", "FileZilla Server",
  "Internet Information Services", "Exim", "Postfix", "Sendmail", "Exchange Server", "Dovecot",
  "Cyrus IMAP", "Courier-IMAP", "MariaDB", "MySQL", "HTTP Server", "nginx", "lighttpd", "OpenResty",
  "Caddy", "LiteSpeed Web Server", "Tomcat", "Werkzeug", "Gunicorn", "PHP", "Python", "OpenSSL", "Jetty",
  "WordPress", "Drupal", "Joomla!", "Kentico CMS", "October CMS", "DotNetNuke", "Craft CMS", "BIND", "NTP",
  "FortiOS", "PAN-OS", "Connect Secure", "NetScaler ADC", "SonicOS", "Sophos Firewall", "DiskStation Manager",
  "QTS", "RouterOS", "Zyxel firmware", "Unified Data Protection", "ArrayOS", "Controller", "Expedition",
  "LoadMaster", "ALEOS", "Web Appliance", "Cyberoam", "UTM", "SMA", "SMA 1000", "Secure Access Control System",
  "FortiSandbox", "Fabric OS", "DNS-320", "DSL-2750B", "DSL-2760U", "DWL-2600AP",
];

export function kevGaps(flaws) {
  const out = [];
  for (const f of flaws || []) {
    if (!f || !f.kev || !f.product) continue;
    const covered = FINGERPRINT_PRODUCTS.some((n) => W.nameHit(n, f.vendor, f.product) || W.nameHit(`${f.vendor || ""} ${n}`, f.vendor, f.product));
    if (!covered) out.push({ cve: f.cve, vendor: f.vendor || "", product: f.product });
  }
  return out.slice(0, 500);
}

export function gapsText(gaps) {
  const lines = ["KEV products with no installed fingerprint. This does not say a host runs them."];
  if (!gaps.length) lines.push("None. Every KEV product in this snapshot is named by an installed fingerprint, or the snapshot listed none.");
  for (const g of gaps) lines.push(`${g.cve} ${g.vendor} ${g.product}`.trim());
  return lines.join("\n") + "\n";
}
