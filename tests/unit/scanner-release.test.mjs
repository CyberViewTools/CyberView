// The single-file scanner release (scripts/scanner-release.mjs): the bundle is built into a temporary folder, checked line
// by line against the source (nothing in it that the source does not contain, apart from the rewritten import/export
// lines, the module wrappers and the two embedded site files), and run with node next to the source CLI: the same help,
// the same refusal without a scope file, the same "what is sent" table, and a loopback scan that sends the stand-in
// services on 127.0.0.1 exactly the same bytes and reports the same findings. No real host is contacted.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { bundle, scannerVersion, ENTRY, SHARED } from "../../scripts/scanner-release.mjs";
import { STATEMENT } from "../../scanner/lib/scope.mjs";
import { VERSION } from "../../scanner/lib/probe.mjs";
import { startServers } from "../fixtures/scanner/servers.mjs";

const ROOT = new URL("../../", import.meta.url).pathname;
const SNAP = join(ROOT, "tests/fixtures/scanner/snapshot");
const SOURCE_CLI = join(ROOT, ENTRY);
const tmp = () => mkdtempSync(join(tmpdir(), "cvrel-"));
const run = (args, cwd) => new Promise((res) => execFile(process.execPath, args, { cwd, encoding: "utf8", timeout: 60000 },
  (e, stdout, stderr) => res({ code: e ? (typeof e.code === "number" ? e.code : -1) : 0, stdout, stderr })));

// one build for the whole file, written where no repository is around it (as an operator would run it)
const B = bundle({ commit: "0123456789abcdef0123456789abcdef01234567" });
const DIR = tmp(), BUNDLE = join(DIR, `cyberview-scan-${B.version}.mjs`);
writeFileSync(BUNDLE, B.code, { mode: 0o755 });

test("the bundle is named and stamped with the source's version, the commit and the licence, and builds the same bytes twice", () => {
  assert.equal(B.version, VERSION); assert.equal(scannerVersion(), VERSION);
  assert.ok(B.code.startsWith("#!/usr/bin/env node\n"));
  assert.match(B.code, new RegExp(`^// CyberView Scanner ${VERSION.replace(/\./g, "\\.")}: single-file release build`, "m"));
  assert.match(B.code, /^\/\/ Source commit: 0123456789abcdef0123456789abcdef01234567$/m);
  assert.ok(B.code.includes(readFileSync(join(ROOT, "scanner/LICENSE"), "utf8").trimEnd()), "scanner/LICENSE text is in the header");
  assert.equal(bundle({ commit: "0123456789abcdef0123456789abcdef01234567" }).code, B.code, "deterministic: same commit, same checksum");
  assert.equal(B.modules[B.modules.length - 1], ENTRY); assert.ok(B.modules.includes(SHARED));
  assert.deepEqual(Object.keys(B.site).sort(), ["cvedb-lib.js", "workbench-lib.js"]);
  for (const [f, text] of Object.entries(B.site)) assert.equal(text, readFileSync(join(ROOT, "site", f), "utf8"), `${f} embedded unchanged`);
});

// An independent reading of the bundle: walk it module by module against the source files and accept only the lines the
// bundler is allowed to write. Anything else (a line of code not in the source) fails the test.
test("the bundle contains no code the source does not: every line is a source line or an allowed wrapper/import line", () => {
  const lines = B.code.split("\n");
  let i = 0;
  const next = () => lines[i++];
  // header: comments, the licence block, then one namespace import per node: built-in the sources import
  assert.equal(next(), "#!/usr/bin/env node");
  while (lines[i].startsWith("// ")) i++;
  assert.equal(next(), "/*");
  while (lines[i] !== "*/") i++;
  i++;
  const builtinsInBundle = new Set();
  while (lines[i].startsWith("import ")) {
    const m = /^import \* as __node_\w+ from "(node:[\w/]+)";$/.exec(next());
    assert.ok(m, `header import line not allowed: ${lines[i - 1]}`); builtinsInBundle.add(m[1]);
  }
  const builtinsInSource = new Set();
  for (const rel of B.modules) for (const m of readFileSync(join(ROOT, rel), "utf8").matchAll(/^import .+ from "(node:[\w/]+)";$/gm)) builtinsInSource.add(m[1]);
  assert.deepEqual([...builtinsInBundle].sort(), [...builtinsInSource].sort(), "the bundle imports exactly the node: modules the source imports");
  assert.ok(!builtinsInBundle.has("node:child_process"));
  const seen = [];
  while (i < lines.length) {
    const l = next();
    if (l === "") continue;
    if (l.startsWith("export const {")) { assert.match(l, /^export const \{ (parseArgs, main|main, parseArgs) \} = __mod_scanner_cyberview_scan;$/); continue; }
    const head = /^\/\/ ---- (scanner\/[\w/.-]+\.mjs) ----$/.exec(l);
    assert.ok(head, `line outside any module: ${l.slice(0, 120)}`);
    const rel = head[1]; seen.push(rel);
    assert.match(next(), /^const __mod_[\w$]+ = \(\(\) => \{$/);
    let src = readFileSync(join(ROOT, rel), "utf8").split("\n");
    if (src[0].startsWith("#!")) src.shift();
    while (src.length && src[src.length - 1] === "") src.pop();
    for (const s of src) {
      if (/^import .+ from "[^"]+";$/.test(s)) { assert.match(next(), /^(const (\{ [\w$:, ]+ \}|[\w$]+) = __(mod|node)_[\w$]+(\.default)?; ?)+$/, `${rel}: rewritten import`); continue; }
      if (/^export \{[^}]*\};$/.test(s)) continue;                       // re-export list: folded into the returned object
      const want = s.replace(/^export\s+/, "");
      const got = next();
      if (rel === SHARED && got !== want) {
        // the one allowed change: the disk read of site/*.js becomes the embedded copy
        const okRoot = s.startsWith("const ROOT = ") && got === "const SITE = Object.freeze({ " + Object.keys(B.site).map((f) => `${JSON.stringify(f)}: ${JSON.stringify(B.site[f])}`).join(", ") + " });";
        const okRead = got === want.replace(`readFileSync(join(ROOT, "site", file), "utf8")`, "SITE[file]");
        assert.ok(okRoot || okRead, `${rel}: unexpected change: ${got.slice(0, 120)}`);
        continue;
      }
      assert.equal(got, want, `${rel}: bundle line differs from the source`);
    }
    assert.match(next(), /^return Object\.freeze\(\{ [\w$:, ]* \}\);$/);
    assert.equal(next(), "})();");
  }
  assert.deepEqual(seen, B.modules);
  // the security check's "detection only" refusals hold for the bundle as a whole too
  for (const re of [/node:child_process|require\(["']child_process|\bexecSync\b|\bspawn\(/, /\beval\s*\(|new\s+Function\s*\(/, /method:\s*["'](POST|PUT|PATCH|DELETE)["']/i])
    assert.ok(!re.test(B.code), `bundle matches ${re}`);
});

test("node bundle --help prints the same usage as the source CLI; no command and an unknown command fail the same way", async () => {
  const d = tmp();
  for (const args of [["--help"], ["help"], [], ["frobnicate"]]) {
    const a = await run([SOURCE_CLI, ...args], d), b = await run([BUNDLE, ...args], d);
    assert.equal(b.code, a.code, `exit code for ${args.join(" ") || "(none)"}`);
    assert.equal(b.stdout, a.stdout); assert.equal(b.stderr, a.stderr);
  }
  const h = await run([BUNDLE, "help"], d);
  assert.equal(h.code, 0); assert.match(h.stdout, new RegExp(`^CyberView Scanner ${VERSION.replace(/\./g, "\\.")} \\(detection only`));
});

const scope = (d, o = {}) => { writeFileSync(join(d, "scope.json"), JSON.stringify({ cyberview_scope: 1, owner: "Example lab", contact: "lab@example.org",
  attestation: { statement: STATEMENT, agreed: true, name: "Test Operator", date: "2026-11-20", expires: "", authorization_ref: "test" }, targets: ["127.0.0.1"], exclude: [], ...o })); return "scope.json"; };

test("the bundle refuses exactly as the source does: no scope file, an unattested scope, a public address without the flag", async () => {
  const d = tmp();
  writeFileSync(join(d, "unsigned.json"), JSON.stringify({ cyberview_scope: 1, owner: "x", contact: "x@example.org", attestation: { statement: STATEMENT, agreed: false, name: "" }, targets: ["127.0.0.1"] }));
  const pub = tmp(); scope(pub, { targets: ["8.8.8.8"] });
  for (const [args, cwd] of [[["scan", "--data", SNAP], d], [["check"], d], [["scan", "--scope", "unsigned.json", "--data", SNAP], d], [["check", "--scope", "scope.json"], pub]]) {
    const a = await run([SOURCE_CLI, ...args], cwd), b = await run([BUNDLE, ...args], cwd);
    assert.equal(a.code, 2, `source refuses ${args.join(" ")}`); assert.equal(b.code, 2, `bundle refuses ${args.join(" ")}`);
    assert.equal(b.stderr, a.stderr); assert.equal(b.stdout, a.stdout); assert.match(b.stderr, /^REFUSED: /);
  }
});

test("check prints the same WHAT IS SENT table from the bundle as from the source", async () => {
  const d = tmp(); scope(d);
  const a = await run([SOURCE_CLI, "check", "--scope", "scope.json", "--udp"], d), b = await run([BUNDLE, "check", "--scope", "scope.json", "--udp"], d);
  assert.equal(a.code, 0); assert.equal(b.code, 0);
  assert.equal(b.stdout, a.stdout); assert.equal(b.stderr, a.stderr);
  assert.match(b.stdout, /WHAT IS SENT/); assert.match(b.stdout, new RegExp(`CyberViewScanner_${VERSION.replace(/\./g, "\\.")} authorized-vulnerability-scan`));
});

test("a loopback scan from the bundle sends the same bytes and reports the same findings as the source CLI", async () => {
  const srv = await startServers();
  try {
    const ports = ["--ports", `${srv.ports.ssh},${srv.ports.http},${srv.closed}`, "--http-ports", String(srv.ports.http), "--assume-up"];
    const once = async (cli) => {
      const d = tmp(); scope(d);
      srv.got.ssh.length = 0; srv.got.http.length = 0; srv.got.ftp.length = 0;
      const r = await run([cli, "scan", "--scope", "scope.json", "--data", SNAP, ...ports, "--out", "out"], d);
      const rep = JSON.parse(readFileSync(join(d, "out", "report.json"), "utf8"));
      return { r, d, rep, got: JSON.parse(JSON.stringify(srv.got)), mode: statSync(join(d, "out", "report.json")).mode & 0o777 };
    };
    const a = await once(SOURCE_CLI), b = await once(BUNDLE);
    assert.equal(a.r.code, 0, a.r.stderr); assert.equal(b.r.code, 0, b.r.stderr);
    // the services saw exactly the same: one SSH identification line, one GET / with the scanner's User-Agent
    assert.deepEqual(b.got, a.got);
    assert.equal(b.got.ssh.length, 1); assert.equal(b.got.http.length, 1); assert.equal(b.got.http[0].method, "GET"); assert.equal(b.got.http[0].url, "/");
    // the same terminal output (the output folder's absolute path aside) and the same report
    assert.equal(b.r.stdout.split(b.d).join("<dir>"), a.r.stdout.split(a.d).join("<dir>"));
    assert.deepEqual(b.rep.findings, a.rep.findings); assert.ok(b.rep.findings.length > 0);
    assert.deepEqual(b.rep.summary, a.rep.summary);
    assert.deepEqual(b.rep.hosts.map((h) => h.services), a.rep.hosts.map((h) => h.services));
    assert.equal(b.mode & 0o077, 0, "report written privately, as by the source");
  } finally { await srv.close(); }
});

test("the release script writes cyberview-scan-<version>.mjs into --out with the commit given, and refuses a bad --commit", async () => {
  const d = tmp();
  const r = await run([join(ROOT, "scripts/scanner-release.mjs"), "--out", d, "--commit", "0123456789abcdef0123456789abcdef01234567"], ROOT);
  assert.equal(r.code, 0, r.stderr);
  const f = join(d, `cyberview-scan-${VERSION}.mjs`), code = readFileSync(f, "utf8");
  assert.equal(code, B.code);
  assert.match(r.stdout, new RegExp(`sha256 ${createHash("sha256").update(code).digest("hex")}`));
  const bad = await run([join(ROOT, "scripts/scanner-release.mjs"), "--out", d, "--commit", "$(whoami)"], ROOT);
  assert.equal(bad.code, 1); assert.match(bad.stderr, /--commit must be a git commit id/);
});
