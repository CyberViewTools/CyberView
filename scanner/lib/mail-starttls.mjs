// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Mail inventory (scan-mail-starttls), from the greetings ALREADY read: no EHLO, CAPABILITY, CAPA or STARTTLS command is
// sent. PURE: it reads report.json only. What a greeting can say on its own:
//   IMAP  a server may put its capability list in the greeting ("* OK [CAPABILITY ... STARTTLS ...]", RFC 9051 / 3501
//         section 7.1): STARTTLS is then read from it
//   SMTP, POP3  the greeting never lists capabilities (they need EHLO / CAPA, which this scanner does not send): STARTTLS
//         is reported as "not checked", never as absent
//   implicit TLS ports (465, 993, 995): the handshake already happened
// It also records an SMTP service on port 25 with no submission port (465/587) answering, as inventory.
// With --identify (scanner/lib/hello.mjs), the scan's own EHLO / CAPA reply is used instead: STARTTLS (SMTP) or STLS (POP3)
// listed or not listed, in place of "not checked".
// No open-relay test of any kind: nothing is sent to the mail server beyond what probe.mjs already does (a connect and a read).

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n);
export const STARTTLS = Object.freeze({
  implicit: "implicit TLS (the handshake was made on connect)",
  advertised: "advertised in the greeting's capability list",
  notListed: "not in the greeting's capability list",
  cut: "unknown: the greeting was cut before its capability list ended",
  notChecked: "not checked: the greeting carries no capability list (that needs EHLO, CAPABILITY or CAPA, which is not sent)",
  helloListed: "advertised in the EHLO/CAPA reply (--identify)",
  helloNotListed: "not advertised in the EHLO/CAPA reply (--identify)",
});

/** One greeting line -> "smtp" | "imap" | "pop3" | "" (the service record's protocol breaks a bare 220 tie). */
export function mailProtocol(banner, port, proto = "") {
  const first = String(banner || "").split(/\r?\n/)[0];
  if (/^\* (?:OK|PREAUTH)\b/i.test(first)) return "imap";
  if (/^\+OK\b/.test(first)) return "pop3";
  if (/^220[ -]/.test(first)) return proto === "smtp" || (proto !== "ftp" && [25, 465, 587].includes(port)) ? "smtp" : "";
  return "";
}

/** STARTTLS as far as the greeting shows it. */
export function starttlsFromGreeting(protocol, banner, { tls = false } = {}) {
  if (tls) return STARTTLS.implicit;
  if (protocol !== "imap") return STARTTLS.notChecked;
  const m = /\[CAPABILITY\s+([^\]]*)(\])?/i.exec(String(banner || ""));
  if (!m) return STARTTLS.notChecked;
  if (!m[2]) return /(^|\s)STARTTLS(\s|$)/i.test(m[1]) ? STARTTLS.advertised : STARTTLS.cut;
  return m[1].split(/\s+/).some((c) => c.toUpperCase() === "STARTTLS") ? STARTTLS.advertised : STARTTLS.notListed;
}

/** The --identify EHLO/CAPA answer for this port, if one was read -> a STARTTLS text, or "" */
function helloStarttls(h, port, protocol) {
  const x = (h.identify || []).find((r) => r.port === port && r.service === protocol && r.read && typeof r.read.starttls === "boolean" && (r.read.code === 250 || r.read.ok === true));
  return x ? (x.read.starttls ? STARTTLS.helloListed : STARTTLS.helloNotListed) : "";
}

/** report -> [{ host, names, port, protocol, product, tls, starttls, submission }] */
export function mailInventory(report) {
  const out = [], scanned = new Set(((report && report.run && report.run.ports) || []).map(Number));
  for (const h of (report && report.hosts) || []) {
    const tlsPorts = new Set((h.tls || []).map((t) => t.port)), open = new Set((h.ports || []).map((p) => p.port));
    const rows = [];
    for (const p of h.ports || []) {
      const svc = (h.services || []).find((s) => s.port === p.port) || {};
      const protocol = mailProtocol(p.banner, p.port, svc.proto || "");
      if (!protocol) continue;
      rows.push({ host: h.address, names: (h.names || []).slice(0, 5), port: p.port, protocol, product: clip(svc.label || svc.product || "", 80), tls: tlsPorts.has(p.port),
        starttls: helloStarttls(h, p.port, protocol) || starttlsFromGreeting(protocol, p.banner, { tls: tlsPorts.has(p.port) }), submission: "" });
    }
    const smtp25 = rows.find((r) => r.protocol === "smtp" && r.port === 25);
    if (smtp25) {
      const sub = [465, 587].filter((x) => open.has(x));
      smtp25.submission = sub.length ? `submission answers on ${sub.join(" and ")}` : [465, 587].every((x) => scanned.has(x)) ? "SMTP on port 25 only: no submission port (465/587) answered"
        : "submission ports 465/587 were not both scanned";
    }
    out.push(...rows);
  }
  return out;
}

const cell = (v) => { let s = v == null ? "" : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
export const MAIL_HEAD = ["host", "names", "port", "protocol", "product", "implicit_tls", "starttls", "submission"];
export function toMailCsv(rows) {
  return [MAIL_HEAD, ...rows.map((r) => [r.host, r.names.join(" "), r.port, r.protocol, r.product, r.tls ? "yes" : "no", r.starttls, r.submission])].map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}
