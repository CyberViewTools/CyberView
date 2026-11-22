// Writes the two sample report.json files the Scanner page's report viewer is tested with (tests/test_all.py,
// tests/unit/scanner-view.test.mjs): a real scan run by scanner/cyberview-scan.mjs with a stand-in probe (no host is
// contacted) against the fixture snapshot (invented CVE ids). The second scan has OpenSSH upgraded, the web port closed
// and a certificate from another issuer.
//   node tests/fixtures/scanner/viewer/make-reports.mjs   (rewrites report-a.json and report-b.json next to this file)
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { makeDer, probeCert } from "../reportpack/der.mjs";

const HERE = dirname(fileURLToPath(import.meta.url)), FIX = dirname(HERE), SNAP = join(FIX, "snapshot");
const ROOT = dirname(dirname(dirname(FIX)));   // tests/fixtures/scanner -> the repository root
const { STATEMENT } = await import(pathToFileURL(join(ROOT, "scanner", "lib", "scope.mjs")).href);
const { main } = await import(pathToFileURL(join(ROOT, "scanner", "cyberview-scan.mjs")).href);
const BANNERS = JSON.parse(readFileSync(join(FIX, "banners.json"), "utf8"));
const fp = (der) => createHash("sha256").update(der).digest("hex").toUpperCase().match(/../g).join(":");
const CERT = makeDer({ serial: "01ab", cn: "files.lab.example", issuer: "Lab CA", dns: ["files.lab.example"] });
const CERT2 = makeDer({ serial: "02cd", cn: "files.lab.example", issuer: "Other CA", dns: ["files.lab.example"] });

const probe = (v2) => async (ip, port) => {
  if (ip === "10.0.0.5") {
    if (port === 22) return { port, state: "open", banner: v2 ? BANNERS.ssh_openssh_plain : "SSH-2.0-OpenSSH_9.6p1\r\n" };
    if (port === 80 && !v2) return { port, state: "open", http: { status: 200, headers: { server: "nginx/1.22.1" }, body: "" } };
    if (port === 443) {
      const der = v2 ? CERT2 : CERT;
      return { port, state: "open", tls: { protocol: "TLSv1.3", cipher: "TLS_AES_128_GCM_SHA256", cipher_std: "TLS_AES_128_GCM_SHA256", kex: {},
        cert: probeCert(der, { fingerprint: fp(der), cn: "files.lab.example", issuer: v2 ? "Other CA" : "Lab CA", san: "DNS:files.lab.example" }) }, http: { status: 404, headers: {}, body: "" } };
    }
  }
  if (ip === "10.0.0.6") {
    if (port === 21) return { port, state: "open", banner: BANNERS.ftp_vsftpd };
    if (port === 22) return { port, state: "open", banner: BANNERS.ssh_dropbear };
  }
  return { port, state: ip === "10.0.0.7" ? "filtered" : "closed" };
};
const io = (v2) => ({ out: () => {}, err: (s) => process.stderr.write(s + "\n"), sleep: async () => {}, publicWaitMs: 0, probe: probe(v2),
  fetchImpl: () => { throw new Error("no network"); }, resolve: async () => { throw Object.assign(new Error("no DNS"), { code: "ENOTFOUND" }); } });

const d = mkdtempSync(join(tmpdir(), "cvview-")), scope = join(d, "scope.json");
writeFileSync(scope, JSON.stringify({ cyberview_scope: 1, owner: "Example lab", contact: "lab@example.org",
  attestation: { statement: STATEMENT, agreed: true, name: "Test Operator", date: "2026-11-20", expires: "", authorization_ref: "fixture" },
  targets: ["10.0.0.5", "10.0.0.6", "10.0.0.7"], exclude: [] }));
for (const [v2, name] of [[false, "report-a.json"], [true, "report-b.json"]]) {
  const code = await main(["scan", "--scope", scope, "--data", SNAP, "--ports", "21,22,80,443", "--out", join(d, name)], io(v2));
  if (code !== 0 && code !== 2) throw new Error(`scan exited ${code}`);
  const rep = JSON.parse(readFileSync(join(d, name, "report.json"), "utf8"));
  rep.scope.file = "scope.json"; rep.run.data.source = "cyberview-data";   // not the temporary folders it was made in
  writeFileSync(join(HERE, name), JSON.stringify(rep, null, 2) + "\n");
}
console.log("wrote report-a.json and report-b.json");
