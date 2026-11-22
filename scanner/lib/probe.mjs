// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// The network layer: the ONLY file in the scanner that opens connections to scan targets or writes to them
// (scripts/security-check.mjs enforces this). What it does, per open port, in ONE connection:
//   - an ordinary TCP connect (no raw packets, no half-open or stealth scanning, no spoofed source)
//   - read the greeting a service sends on its own (SSH, FTP, SMTP, POP3, IMAP, MySQL, VNC), at most 16 KB
//   - on an SSH port, answer with the scanner's own identification line so the target's logs say who connected
//   - on a web port, one HTTP request for the root page with the scanner's User-Agent, no redirects followed
//   - on a TLS port, a normal TLS handshake to read the certificate (the certificate is read, not trusted)
// It sends no other bytes: no credentials, no crafted input, no exploit, nothing that changes the target.
import net from "node:net";
import tls from "node:tls";
import http from "node:http";
import https from "node:https";
import { TIMEOUTS } from "./limits.mjs";
import { isRailPath, railEntry } from "./paths.mjs";

export const VERSION = "1.0.0";
export const INFO_URL = "https://xanderhutch.github.io/CyberView/vulnerabilities.html#scanner";
export const USER_AGENT = `CyberView-Scanner/${VERSION} (authorized vulnerability scan, detection only; +${INFO_URL})`;
export const SSH_IDENT = `SSH-2.0-CyberViewScanner_${VERSION} authorized-vulnerability-scan`;

/** The ports checked when the scope file and the command line name none: common services that state a version. */
export const DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 5900, 8000, 8008, 8080, 8443, 8888, 9443];
export const HTTP_PORTS = new Set([80, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090]);
export const HTTPS_PORTS = new Set([443, 4443, 8443, 9443, 10443]);
export const TLS_PORTS = new Set([465, 636, 990, 993, 995, ...HTTPS_PORTS]);
/** What each kind of port is sent: shown in the run header and the report. */
export const SENDS = {
  connect: "a TCP connect; the connection is closed after the read",
  greeting: "nothing: the scanner only reads what the service sends first",
  ssh: `its identification line "${SSH_IDENT}"`,
  http: `one HTTP request for the root page (method GET, path "/") with User-Agent "${USER_AGENT}"`,
  tls: "a standard TLS handshake (the certificate is read, never trusted or used)",
};

/**
 * One port: connect, then read or ask as above. Never throws.
 * -> { port, state: open | closed | filtered, banner, raw (Buffer, MySQL only), http: { status, headers, body },
 *      tls: { protocol, cipher, cipher_std, kex: { type, name, size }, cert: { ..., bits, curve, fingerprint256, raw (DER) } }, error }
 */
export async function probePort(ip, port, { servername = "", hostHeader = "", signal = null, timeouts = TIMEOUTS, httpPorts = [], httpsPorts = [] } = {}) {
  const out = { port, state: "filtered", banner: "", raw: null, http: null, tls: null, error: "" };
  let sock = null;
  const kill = () => { try { sock && sock.destroy(); } catch { /* closed */ } };
  if (signal) { if (signal.aborted) return out; signal.addEventListener("abort", kill, { once: true }); }
  const hard = setTimeout(kill, timeouts.connectMs + timeouts.readMs * 2 + 1000);
  try {
    // the operator can name extra web ports (--http-ports, --https-ports) for services on non-standard ports;
    // --http-ports forces plain text even on a port that is TLS by convention (e.g. a plain HTTP service on 9443)
    let useTls = (TLS_PORTS.has(port) || httpsPorts.includes(port)) && !httpPorts.includes(port);
    const web = HTTP_PORTS.has(port) || HTTPS_PORTS.has(port) || httpPorts.includes(port) || httpsPorts.includes(port);
    try { sock = await connect(ip, port, useTls, servername, timeouts.connectMs); }
    catch (e) {
      // a TLS handshake that fails on a port we assumed was TLS: the service may be plain HTTP/text. The TCP connected
      // but TLS did not, so try once without TLS. A refused or timed-out port is a real closed/filtered, not retried.
      if (useTls && e && !["ECONNREFUSED", "ETIMEDOUT", "ENOTFOUND", "EHOSTUNREACH", "ENETUNREACH", "ERR_SOCKET_CONNECTION_TIMEOUT"].includes(e.code)) {
        useTls = false; out.tls_failed = true;
        sock = await connect(ip, port, false, servername, timeouts.connectMs);
      } else throw e;
    }
    out.state = "open";
    if (useTls) {
      // everything below is read from the handshake that already happened: no extra bytes are sent for it
      const c = sock.getPeerCertificate(false), ci = sock.getCipher() || {};
      let eph = {}; try { eph = sock.getEphemeralKeyInfo() || {}; } catch { /* not available */ }
      out.tls = { protocol: sock.getProtocol() || "", cipher: ci.name || "", cipher_std: ci.standardName || "", kex: { type: eph.type || "", name: eph.name || "", size: Number(eph.size) || 0 },
        cert: c && c.subject ? { subject: c.subject, issuer: c.issuer, valid_from: c.valid_from, valid_to: c.valid_to, subjectaltname: c.subjectaltname || "",
          bits: Number(c.bits) || 0, curve: c.nistCurve || c.asn1Curve || "", fingerprint256: c.fingerprint256 || "", raw: Buffer.isBuffer(c.raw) ? c.raw : null } : null };
    }
    if (web) out.http = await httpGet(sock, useTls, hostHeader || ip, port, timeouts);
    else {
      const buf = await readFor(sock, timeouts.readMs, timeouts.maxBytes);
      if (port === 3306 || (buf.length > 5 && buf[3] === 0 && buf[4] === 0x0a)) out.raw = buf;
      out.banner = buf.toString("latin1").slice(0, 2048);
      // SSH: say who we are, then read the server's KEXINIT on this same connection (RFC 4253). Nothing else is sent.
      if (/^SSH-\d/.test(out.banner) && !sock.destroyed) {
        await new Promise((r) => sock.write(SSH_IDENT + "\r\n", r));
        const more = await readFor(sock, Math.min(800, timeouts.readMs), 8192);
        if (more.length) out.kexRaw = more;
      }
    }
  } catch (e) {
    out.state = e && e.code === "ECONNREFUSED" ? "closed" : out.state === "open" ? "open" : "filtered";
    out.error = String((e && (e.code || e.message)) || e).slice(0, 80);
  } finally {
    clearTimeout(hard); if (signal) signal.removeEventListener("abort", kill); kill();
  }
  return out;
}

function connect(ip, port, useTls, servername, ms) {
  return new Promise((resolve, reject) => {
    const opts = { host: ip, port, timeout: ms };
    // a TLS port gets a normal handshake; rejectUnauthorized is off only so that a self-signed certificate can still be read
    const s = useTls ? tls.connect({ ...opts, servername: servername && !net.isIP(servername) ? servername : undefined, rejectUnauthorized: false }) : net.connect(opts);
    const t = setTimeout(() => { s.destroy(); reject(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })); }, ms);
    s.once(useTls ? "secureConnect" : "connect", () => { clearTimeout(t); s.setTimeout(0); resolve(s); });
    s.once("error", (e) => { clearTimeout(t); s.destroy(); reject(e); });
  });
}

/** Collect what the service sends for up to ms (or maxBytes), then stop. */
function readFor(sock, ms, maxBytes) {
  return new Promise((resolve) => {
    const parts = []; let n = 0, quiet = null;
    const done = () => { clearTimeout(t); clearTimeout(quiet); sock.removeListener("data", on); resolve(Buffer.concat(parts).subarray(0, maxBytes)); };
    const on = (d) => { parts.push(d); n += d.length; if (n >= maxBytes) return done(); clearTimeout(quiet); quiet = setTimeout(done, 600); };
    const t = setTimeout(done, ms);
    sock.on("data", on); sock.once("end", done); sock.once("close", done); sock.once("error", done);
  });
}

/** One request over the open socket; the body is cut at maxBytes; redirects are recorded, not followed. path is a frozen rail path or "/". */
function httpGet(sock, useTls, host, port, timeouts, path = "/") {
  return new Promise((resolve) => {
    const lib = useTls ? https : http, hostH = /:/.test(host) && net.isIP(host) === 6 ? `[${host}]` : host;
    const req = lib.request({ method: "GET", path, createConnection: () => sock, timeout: timeouts.readMs,
      headers: { "User-Agent": USER_AGENT, Accept: "text/html,*/*;q=0.5", Connection: "close", Host: [80, 443].includes(port) ? hostH : `${hostH}:${port}` } });
    const finish = (v) => { clearTimeout(t); resolve(v); };
    const t = setTimeout(() => { req.destroy(); finish(null); }, timeouts.readMs + 500);
    req.on("response", (res) => {
      const parts = []; let n = 0;
      const end = () => finish({ status: res.statusCode || 0, headers: res.headers, body: Buffer.concat(parts).toString("utf8").slice(0, timeouts.maxBytes) });
      res.on("data", (d) => { if (n < timeouts.maxBytes) { parts.push(d); n += d.length; } if (n >= timeouts.maxBytes) { res.destroy(); end(); } });
      res.on("end", end); res.on("error", end); res.on("close", end);
    });
    req.on("timeout", () => req.destroy());
    req.on("error", () => finish(null));
    req.end();
  });
}

/**
 * One extra request for a frozen rail path. A path that is not on the rail is not connected.
 * Status-style entries return no body. Never throws.
 */
export async function probeHttpPath(ip, port, path, { servername = "", hostHeader = "", signal = null, timeouts = TIMEOUTS, httpPorts = [], httpsPorts = [] } = {}) {
  const entry = railEntry(path);
  if (!entry || !isRailPath(path)) return { port, path, state: "skipped", error: "not on the frozen path rail", http: null };
  const out = { port, path, state: "filtered", error: "", http: null };
  let sock = null;
  const kill = () => { try { sock && sock.destroy(); } catch { /* closed */ } };
  if (signal) { if (signal.aborted) return out; signal.addEventListener("abort", kill, { once: true }); }
  const hard = setTimeout(kill, timeouts.connectMs + timeouts.readMs + 1000);
  try {
    const useTls = (TLS_PORTS.has(port) || httpsPorts.includes(port)) && !httpPorts.includes(port);
    sock = await connect(ip, port, useTls, servername, timeouts.connectMs);
    out.state = "open";
    const http = await httpGet(sock, useTls, hostHeader || ip, port, timeouts, path);
    out.http = trimRailBody(entry, http);
  } catch (e) {
    out.state = e && e.code === "ECONNREFUSED" ? "closed" : out.state === "open" ? "open" : "filtered";
    out.error = String((e && (e.code || e.message)) || e).slice(0, 80);
  } finally {
    clearTimeout(hard); if (signal) signal.removeEventListener("abort", kill); kill();
  }
  return out;
}

function trimRailBody(entry, http) {
  if (!http) return null;
  if (entry.keep === "text") return { status: http.status, headers: {}, body: String(http.body || "").slice(0, 500) };
  if (entry.keep === "git") {
    const line = String(http.body || "").split(/\r?\n/)[0].slice(0, 80);
    return { status: http.status, headers: {}, body: /^ref:\s+\S+$/.test(line) ? line : "" };
  }
  return { status: http.status, headers: {}, body: "" };
}
