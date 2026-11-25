// Distribution fix records (scanner/lib/distro.mjs): Debian version order, OSV reduction, and the verdicts a signed-in
// check gets for Ubuntu/Debian package builds. Package names and versions are real; the CVE ids 2026-90xxx are invented.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, cpSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join } from "node:path"; import { spawnSync } from "node:child_process";
import { debCompare, ecosystemKey, releaseKey, addOsv, releaseFiles, verdict } from "../../scanner/lib/distro.mjs";
import { parsePackages } from "../../scanner/lib/imports.mjs";

test("Debian version order: epochs, revisions, tilde before everything, letters before symbols, numbers by value", () => {
  const lt = [["1:8.9p1-3ubuntu0.9", "1:8.9p1-3ubuntu0.10"], ["1.0~rc1-1", "1.0-1"], ["1.0-1", "1.0-1ubuntu1"], ["1:9.9", "2:1.0"], ["1.2.3-1", "1.2.3-1+deb12u1"],
    ["0.9.8", "0.9.10"], ["1.0", "1.0+dfsg"], ["1.0", "1.0a"], ["1.0-1~bpo1", "1.0-1"], ["2.36-9+deb12u3", "2.36-9+deb12u10"], ["1.0~~", "1.0~"]];
  for (const [a, b] of lt) { assert.equal(debCompare(a, b), -1, `${a} < ${b}`); assert.equal(debCompare(b, a), 1, `${b} > ${a}`); }
  for (const [a, b] of [["1.0", "0:1.0"], ["1.0-0", "1.0-0"], ["1.00", "1.0"]]) assert.equal(debCompare(a, b), 0, `${a} == ${b}`);
});

test("release names: os-release and OSV ecosystems map to the same keys; Ubuntu Pro is kept apart", () => {
  assert.equal(releaseKey("ubuntu", "22.04"), "ubuntu-22.04"); assert.equal(releaseKey("debian", "12"), "debian-12"); assert.equal(releaseKey("debian", "12.5"), "debian-12");
  assert.equal(releaseKey("fedora", "40"), ""); assert.equal(ecosystemKey("Ubuntu:22.04:LTS"), "ubuntu-22.04"); assert.equal(ecosystemKey("Debian:12"), "debian-12");
  assert.equal(ecosystemKey("Ubuntu:Pro:18.04:LTS"), "ubuntu-pro-18.04"); assert.equal(ecosystemKey("Alpine:v3.19"), "");
});

const OSV = [
  { id: "UBUNTU-CVE-2026-90901", upstream: ["CVE-2026-90901"], affected: [{ package: { ecosystem: "Ubuntu:22.04:LTS", name: "openssh" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1:8.9p1-3ubuntu0.10" }] }] }] },
  { id: "UBUNTU-CVE-2026-90902", upstream: ["CVE-2026-90902"], affected: [{ package: { ecosystem: "Ubuntu:22.04:LTS", name: "openssh" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1:8.9p1-3ubuntu0.4" }] }] }] },
  { id: "UBUNTU-CVE-2026-90903", upstream: ["CVE-2026-90903"], affected: [{ package: { ecosystem: "Ubuntu:22.04:LTS", name: "openssh" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }] }], versions: ["1:8.9p1-3ubuntu0.6"] }] },
  { id: "DEBIAN-CVE-2026-90904", aliases: ["CVE-2026-90904"], affected: [{ package: { ecosystem: "Debian:12", name: "openssh" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1:9.2p1-2+deb12u3" }] }] }] },
  { id: "UBUNTU-CVE-2026-90101", upstream: ["CVE-2026-90101"], affected: [{ package: { ecosystem: "Ubuntu:22.04:LTS", name: "openssh" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1:8.9p1-3ubuntu0.5" }] }] }] },
  { id: "UBUNTU-CVE-2026-90905", upstream: ["CVE-2026-90905"], withdrawn: "2026-01-01", affected: [{ package: { ecosystem: "Ubuntu:22.04:LTS", name: "openssh" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }] }] }] },
];
const reduced = () => { const acc = {}; OSV.forEach((r) => addOsv(acc, r)); return releaseFiles(acc, "2026-11-25T00:00:00Z"); };

test("OSV records reduce to one file per release; withdrawn records are dropped; no fix is an empty string", () => {
  const { index, files } = reduced();
  assert.deepEqual(Object.keys(index.releases).sort(), ["debian-12", "ubuntu-22.04"]);
  assert.deepEqual(files["ubuntu-22.04.json"].src.openssh, [["CVE-2026-90101", "1:8.9p1-3ubuntu0.5"], ["CVE-2026-90901", "1:8.9p1-3ubuntu0.10"], ["CVE-2026-90902", "1:8.9p1-3ubuntu0.4"], ["CVE-2026-90903", ""]]);
  const rel = files["ubuntu-22.04.json"], it = { src: "openssh", name: "openssh-server", raw_version: "1:8.9p1-3ubuntu0.6" };
  assert.deepEqual([verdict(rel, it, "CVE-2026-90901").state, verdict(rel, it, "CVE-2026-90902").state, verdict(rel, it, "CVE-2026-90903").state, verdict(rel, it, "CVE-2026-90999")], ["affected", "fixed", "no-fix", null]);
});

test("package list from the signed-in check: the #os line gives the release, the fifth column the source package", () => {
  const r = parsePackages("#os ubuntu 22.04 jammy\nii  openssh-server 1:8.9p1-3ubuntu0.6 amd64 openssh\nii  libc6:amd64 2.35-0ubuntu3.8 amd64 glibc\n");
  assert.deepEqual(r.items.map((x) => [x.name, x.version, x.release, x.src, x.raw_version]), [["openssh-server", "8.9p1", "ubuntu-22.04", "openssh", "1:8.9p1-3ubuntu0.6"], ["libc6", "2.35", "ubuntu-22.04", "glibc", "2.35-0ubuntu3.8"]]);
  const plain = parsePackages("ii  openssh-server 1:8.9p1-3ubuntu0.6 amd64 secure shell server\n");
  assert.equal(plain.items[0].release, undefined, "an ordinary dpkg -l list (no #os line) is read as before");
});

test("end to end: match a signed-in package list; a fixed build is moved to vendor_fixed, an old one is confirmed, a distribution-only CVE is added", () => {
  const dir = mkdtempSync(join(tmpdir(), "cv-distro-")), data = join(dir, "data");
  cpSync(new URL("../fixtures/scanner/snapshot", import.meta.url).pathname, data, { recursive: true });
  const { index, files } = reduced(); mkdirSync(join(data, "data", "distro"), { recursive: true });
  writeFileSync(join(data, "data", "distro", "index.json"), JSON.stringify(index));
  for (const [f, j] of Object.entries(files)) writeFileSync(join(data, "data", "distro", f), JSON.stringify(j));
  const list = join(dir, "server01.packages.txt");
  writeFileSync(list, "#os ubuntu 22.04 jammy\nii  openssh-server 1:8.9p1-3ubuntu0.6 amd64 openssh\n");
  const out = join(dir, "out");
  const r = spawnSync(process.execPath, [new URL("../../scanner/cyberview-scan.mjs", import.meta.url).pathname, "match", "--data", data, "--packages", list, "--out", out], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const rep = JSON.parse(readFileSync(join(out, "report.json"), "utf8")), ids = rep.findings.map((f) => f.cve);
  assert.ok(ids.includes("CVE-2026-90901"), "older build than the distribution's fix: reported");
  assert.ok(ids.includes("CVE-2026-90903"), "affected with no fix released: reported");
  assert.ok(!ids.includes("CVE-2026-90902"), "the installed build has the fix: not a finding");
  assert.ok(!ids.includes("CVE-2026-90904"), "another release's record does not apply");
  const f1 = rep.findings.find((f) => f.cve === "CVE-2026-90901");
  assert.equal(f1.confidence, "high"); assert.match(f1.confidence_why, /Ubuntu 22\.04 fixed this in openssh 1:8\.9p1-3ubuntu0\.10/); assert.deepEqual(f1.fix.distro_fixed, ["1:8.9p1-3ubuntu0.10"]);
  assert.equal(rep.run.data.distro.used[0], "ubuntu-22.04");
  assert.ok(rep.notes.some((n) => /own fix records/.test(n)));
  // the fixture's upstream OpenSSH flaw (CVE-2026-90101, OpenSSH < 9.8 matches 8.9p1): Ubuntu fixed it in 1:8.9p1-3ubuntu0.5, the build here is newer
  assert.ok(!ids.includes("CVE-2026-90101"), "upstream range matched, but Ubuntu's build has the fix: not a finding");
  const vf = (rep.vendor_fixed || []).find((x) => x.cve === "CVE-2026-90101");
  assert.ok(vf, "listed under vendor_fixed so the answer can be checked"); assert.match(vf.on[0].why, /fixed this in openssh 1:8\.9p1-3ubuntu0\.5; this computer has 1:8\.9p1-3ubuntu0\.6/);
});

test("site data build: OSV folders -> index and release files; kernel flavours and Ubuntu Pro left out", async () => {
  const { build } = await import("../../scripts/distro.mjs");
  const dir = mkdtempSync(join(tmpdir(), "cv-osv-")), osv = join(dir, "osv"), out = join(dir, "out");
  mkdirSync(join(osv, "Ubuntu"), { recursive: true }); mkdirSync(join(osv, "Debian"), { recursive: true });
  OSV.forEach((r, i) => writeFileSync(join(osv, r.id.startsWith("DEBIAN") ? "Debian" : "Ubuntu", `${i}.json`), JSON.stringify(r)));
  writeFileSync(join(osv, "Ubuntu", "k.json"), JSON.stringify({ id: "UBUNTU-CVE-2026-90950", upstream: ["CVE-2026-90950"], affected: [{ package: { ecosystem: "Ubuntu:22.04:LTS", name: "linux-aws" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "5.15.0-1001.1" }] }] }, { package: { ecosystem: "Ubuntu:Pro:18.04:LTS", name: "openssh" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1:7.6p1-4ubuntu0.7+esm1" }] }] }] }));
  writeFileSync(join(osv, "Ubuntu", "broken.json"), "{not json");
  const idx = build(osv, out, { now: "2026-11-25T00:00:00Z", log: () => {} });
  assert.deepEqual(Object.keys(idx.releases).sort(), ["debian-12", "ubuntu-22.04"]);
  const u = JSON.parse(readFileSync(join(out, "ubuntu-22.04.json"), "utf8"));
  assert.ok(!u.src["linux-aws"], "kernel flavour left out"); assert.ok(u.src.openssh);
});
