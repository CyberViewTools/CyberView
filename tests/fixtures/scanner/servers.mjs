// Stand-in services on loopback (127.0.0.1, ephemeral ports) for the scanner's tests and demonstration: they send the
// greetings and headers real services send, and record every byte the scanner sends them, so a test can prove the scanner
// sends nothing but its identification and one request for the root page. Never reachable from outside this machine.
import net from "node:net";
import http from "node:http";
import tls from "node:tls";
import { readFileSync } from "node:fs";

export async function startServers({ ssh = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", ftp = "220 (vsFTPd 3.0.3)", server = "nginx/1.22.1", poweredBy = "PHP/8.1.12" } = {}) {
  const got = { ssh: [], ftp: [], http: [] }, servers = [];
  const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => { servers.push(srv); r(srv.address().port); }));
  const banner = (text, key) => net.createServer((s) => { s.on("data", (d) => got[key].push(d.toString("latin1"))); s.on("error", () => {}); s.write(text + "\r\n"); setTimeout(() => s.end(), 3000); });
  const web = http.createServer((req, res) => {
    got.http.push({ method: req.method, url: req.url, headers: req.headers });
    res.writeHead(200, { Server: server, "X-Powered-By": poweredBy, "Content-Type": "text/html" });
    res.end("<!doctype html><title>Fixture intranet</title><p>ok</p>");
  });
  const ports = { ssh: await listen(banner(ssh, "ssh")), ftp: await listen(banner(ftp, "ftp")), http: await listen(web) };
  // a port that was just closed: connecting to it is refused
  const tmp = net.createServer(); const closed = await new Promise((r) => tmp.listen(0, "127.0.0.1", () => { const p = tmp.address().port; tmp.close(() => r(p)); }));
  return { ports, closed, got, close: () => Promise.all(servers.map((s) => new Promise((r) => { if (s.closeAllConnections) s.closeAllConnections(); s.close(() => r()); }))) };
}

/** A stand-in TLS service on loopback with one of the fixture certificates (tests/fixtures/scanner/tls/, test-only keys).
 *  Counts connections so a test can prove the hygiene checks add none. opts go to tls.createServer (maxVersion, ciphers ...). */
export async function startTlsServer(which = "weak", opts = {}) {
  const dir = new URL("./tls/", import.meta.url);
  let connections = 0;
  const srv = tls.createServer({ key: readFileSync(new URL(`${which}-key.pem`, dir)), cert: readFileSync(new URL(`${which}-cert.pem`, dir)), ciphers: "DEFAULT:@SECLEVEL=0", ...opts }, (s) => { s.on("error", () => {}); s.end(); });
  const socks = new Set();
  srv.on("connection", (c) => { connections++; socks.add(c); c.on("close", () => socks.delete(c)); });
  srv.on("tlsClientError", () => {});
  const port = await new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
  // close() also destroys any connection still open, so a half-closed TLS socket cannot hold the test open
  return { port, connections: () => connections, close: () => new Promise((r) => { for (const c of socks) c.destroy(); srv.close(() => r()); }) };
}

// run directly for a demonstration: node tests/fixtures/scanner/servers.mjs (prints the ports, stops on Ctrl-C)
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop())) {
  const s = await startServers();
  console.log(JSON.stringify({ ...s.ports, closed: s.closed }));
  process.on("SIGTERM", () => { console.error(JSON.stringify(s.got)); process.exit(0); });
  process.on("SIGINT", () => { console.error(JSON.stringify(s.got)); process.exit(0); });
}
