#!/usr/bin/env node
// Packs the CyberView Scanner into ONE self-contained ES module for a GitHub Release, so an operator downloads a single
// file and runs it with `node` 22+ instead of cloning the repository. No AI model, no dependencies, no network.
//
// How: the entry (scanner/cyberview-scan.mjs) and every module it imports (scanner/lib/*.mjs) are copied verbatim, each
// inside its own function scope, in the order Node would evaluate them. Only three kinds of line are rewritten:
//   import { a, b as c } from "./x.mjs"   ->  const { a, b: c } = __mod_scanner_lib_x;
//   import { a } from "node:fs"           ->  const { a } = __node_fs;   (one hoisted `import * as __node_fs from "node:fs"`)
//   export function f / export const x    ->  function f / const x        (collected into the module's returned object)
// scanner/lib/shared.mjs reads site/workbench-lib.js and site/cvedb-lib.js from disk and runs them with node:vm; in the
// bundle the same function runs the same two files from embedded strings instead of the disk (the only other change).
// Anything the bundler does not understand (dynamic import, default export, multi-line import, a cycle, a missing
// export) stops the build rather than guessing. The output is deterministic: same commit, same bytes, same checksum.
//
// Run:  node scripts/scanner-release.mjs [--out DIR] [--commit SHA]
//       writes DIR/cyberview-scan-<version>.mjs (default DIR: dist/scanner, git-ignored; never commit the bundle)
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
export const ENTRY = "scanner/cyberview-scan.mjs";
export const SHARED = "scanner/lib/shared.mjs";

const posix = (p) => p.split(sep).join("/");
const ident = (s) => s.replace(/\.m?js$/, "").replace(/[^A-Za-z0-9_$]/g, "_");
const modVar = (rel) => "__mod_" + ident(rel);
const nodeVar = (spec) => "__node_" + ident(spec.replace(/^node:/, ""));

/** The scanner's version as the source defines it (scanner/lib/probe.mjs VERSION). */
export function scannerVersion(root = ROOT) {
  const m = /^export const VERSION = "(\d+\.\d+\.\d+)";$/m.exec(readFileSync(join(root, "scanner/lib/probe.mjs"), "utf8"));
  if (!m) throw new Error("scanner/lib/probe.mjs: VERSION not found (expected: export const VERSION = \"x.y.z\";)");
  return m[1];
}

// `a, b as c` -> [["a","a"],["b","c"]]  (imported name, local name)
function namedList(s, where) {
  return s.split(",").map((x) => x.trim()).filter(Boolean).map((x) => {
    const m = /^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/.exec(x);
    if (!m) throw new Error(`${where}: cannot read import/export name "${x}"`);
    return [m[1], m[2] || m[1]];
  });
}
const destructure = (pairs) => "{ " + pairs.map(([a, b]) => (a === b ? a : `${a}: ${b}`)).join(", ") + " }";

const IMPORT = /^import\s+(.+?)\s+from\s+["']([^"']+)["'];?\s*$/;
const EXPORT_DECL = /^export\s+((?:async\s+)?function\s*\*?|const|let|var|class)\s*([A-Za-z_$][\w$]*)/;
const EXPORT_LIST = /^export\s*\{([^}]*)\}\s*;?\s*$/;

/** Reads one module: its local and node: imports, its exported names, and its body with those lines rewritten. */
function parseModule(rel, src) {
  const where = rel, deps = [], builtins = [], exports = [], out = [];
  const lines = src.split("\n");
  if (lines[0].startsWith("#!")) lines.shift();
  if (/\bimport\s*\(/.test(src)) throw new Error(`${where}: dynamic import() is not supported by the bundler`);
  for (const line of lines) {
    if (/^\s*import[\s{*"']/.test(line) && !/^\s*import\.meta/.test(line)) {
      const m = IMPORT.exec(line);
      if (!m || /^\s/.test(line)) throw new Error(`${where}: unsupported import statement: ${line.slice(0, 120)}`);
      const [, clause, spec] = m;
      let def = "", ns = "", named = [];
      const c = clause.trim();
      const star = /^\*\s+as\s+([A-Za-z_$][\w$]*)$/.exec(c);
      const parts = /^(?:([A-Za-z_$][\w$]*)\s*,?\s*)?(?:\{([^}]*)\})?$/.exec(c);
      if (star) ns = star[1];
      else if (parts && (parts[1] || parts[2] !== undefined)) { def = parts[1] || ""; named = parts[2] !== undefined ? namedList(parts[2], where) : []; }
      else throw new Error(`${where}: unsupported import clause: ${c}`);
      let src;
      if (spec.startsWith("node:")) { src = nodeVar(spec); if (!builtins.includes(spec)) builtins.push(spec); }
      else if (spec.startsWith("./") || spec.startsWith("../")) {
        const target = posix(relative(ROOT, resolve(ROOT, dirname(rel), spec)));
        if (!/^scanner\/.+\.mjs$/.test(target)) throw new Error(`${where}: imports ${spec}, outside scanner/ (only scanner modules are bundled)`);
        if (def || ns) throw new Error(`${where}: default or namespace import of a local module (${spec}) is not supported`);
        deps.push({ target, names: named.map(([a]) => a) });
        src = modVar(target);
      } else throw new Error(`${where}: bare import "${spec}"; the scanner has no dependencies and the bundler adds none`);
      const stmts = [];
      if (ns) stmts.push(`const ${ns} = ${src};`);
      if (def) stmts.push(`const ${def} = ${src}.default;`);
      if (named.length) stmts.push(`const ${destructure(named)} = ${src};`);
      out.push(stmts.join(" "));
      continue;
    }
    if (/^\s*export\b/.test(line)) {
      if (/^\s/.test(line)) throw new Error(`${where}: indented export is not supported: ${line.slice(0, 120)}`);
      const list = EXPORT_LIST.exec(line);
      if (list) { for (const [local, name] of namedList(list[1], where)) exports.push([name, local]); continue; }
      const d = EXPORT_DECL.exec(line);
      if (!d || /^export\s+(const|let|var)\s*[{[]/.test(line)) throw new Error(`${where}: unsupported export: ${line.slice(0, 120)}`);
      exports.push([d[2], d[2]]);
      out.push(line.replace(/^export\s+/, ""));
      continue;
    }
    out.push(line);
  }
  while (out.length && out[out.length - 1] === "") out.pop();
  return { rel, deps, builtins, exports, body: out };
}

/** shared.mjs, with the two site files embedded: the disk read becomes a lookup in SITE; the vm call is unchanged. */
function sharedForBundle(src, root) {
  const files = [...src.matchAll(/\bload\("([\w.-]+\.js)",/g)].map((m) => m[1]);
  if (!files.length) throw new Error(`${SHARED}: no load("<site file>", ...) calls found`);
  const site = {};
  for (const f of files) site[f] = readFileSync(join(root, "site", f), "utf8");
  const swap = (s, from, to) => {
    const n = s.split(from).length - 1;
    if (n !== 1) throw new Error(`${SHARED} changed: expected exactly one "${from.slice(0, 60)}", found ${n}; update scripts/scanner-release.mjs`);
    return s.replace(from, () => to);
  };
  let out = swap(src, "const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));",
    "const SITE = Object.freeze({ " + files.map((f) => `${JSON.stringify(f)}: ${JSON.stringify(site[f])}`).join(", ") + " });");
  out = swap(out, `readFileSync(join(ROOT, "site", file), "utf8")`, "SITE[file]");
  return { src: out, site };
}

/** Builds the bundle text. Returns { code, version, commit, modules: [rel...], site: {file: text} }. */
export function bundle({ root = ROOT, commit = "unknown" } = {}) {
  const version = scannerVersion(root), mods = new Map(), order = [], state = new Map();
  let site = {};
  const load = (rel, chain) => {
    if (state.get(rel) === "done") return;
    if (state.get(rel) === "busy") throw new Error(`import cycle: ${[...chain, rel].join(" -> ")} (the bundler needs an acyclic graph)`);
    state.set(rel, "busy");
    const file = join(root, rel);
    if (!existsSync(file)) throw new Error(`${chain[chain.length - 1] || "entry"}: imports missing file ${rel}`);
    let src = readFileSync(file, "utf8");
    if (rel === SHARED) { const s = sharedForBundle(src, root); src = s.src; site = s.site; }
    const m = parseModule(rel, src);
    mods.set(rel, m);
    for (const d of m.deps) load(d.target, [...chain, rel]);   // dependencies first, in import order: Node's evaluation order
    state.set(rel, "done");
    order.push(rel);
  };
  load(ENTRY, []);
  // every imported name must be exported by its module (a typo would otherwise be a silent undefined)
  for (const m of mods.values()) for (const d of m.deps) {
    const have = new Set(mods.get(d.target).exports.map(([n]) => n));
    for (const n of d.names) if (!have.has(n)) throw new Error(`${m.rel}: imports "${n}" from ${d.target}, which does not export it`);
  }
  const builtins = [];
  for (const rel of order) for (const b of mods.get(rel).builtins) if (!builtins.includes(b)) builtins.push(b);
  const licence = readFileSync(join(root, "scanner/LICENSE"), "utf8").trimEnd();
  if (licence.includes("*/")) throw new Error("scanner/LICENSE contains */ and cannot sit in a block comment");
  const L = [
    "#!/usr/bin/env node",
    `// CyberView Scanner ${version}: single-file release build of scanner/cyberview-scan.mjs.`,
    `// Source commit: ${commit}`,
    "// Built by scripts/scanner-release.mjs (no dependencies). Requires Node.js 22 or later: node cyberview-scan-" + version + ".mjs --help",
    "// Contents: scanner/cyberview-scan.mjs and the scanner/lib modules it imports, each copied verbatim into its own function",
    "// scope, plus site/workbench-lib.js and site/cvedb-lib.js embedded as text and run with node:vm exactly as",
    "// scanner/lib/shared.mjs runs them in the repository. Those two site libraries are covered by CyberView's root LICENSE.",
    "// Verify this file against SHA256SUMS on the GitHub Release it came from before running it.",
    "/*",
    licence,
    "*/",
    ...builtins.map((b) => `import * as ${nodeVar(b)} from ${JSON.stringify(b)};`),
  ];
  for (const rel of order) {
    const m = mods.get(rel);
    L.push("", `// ---- ${rel} ----`, `const ${modVar(rel)} = (() => {`, ...m.body,
      `return Object.freeze({ ${m.exports.map(([n, l]) => (n === l ? n : `${n}: ${l}`)).join(", ")} });`, "})();");
  }
  const entry = mods.get(ENTRY);
  L.push("", `export const ${destructure(entry.exports.map(([n]) => [n, n]))} = ${modVar(ENTRY)};`, "");
  return { code: L.join("\n"), version, commit, modules: order, site };
}

function gitCommit() {
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA;
  try { return execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim(); } catch { return "unknown"; }
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const args = process.argv.slice(2), opt = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : undefined; };
  try {
    const commit = opt("--commit") || gitCommit();
    if (!/^([0-9a-f]{7,40}|unknown)$/.test(commit)) throw new Error(`--commit must be a git commit id, not "${commit}"`);
    const b = bundle({ commit });
    const out = resolve(opt("--out") || join(ROOT, "dist", "scanner"));
    mkdirSync(out, { recursive: true });
    const file = join(out, `cyberview-scan-${b.version}.mjs`);
    writeFileSync(file, b.code, { mode: 0o755 });
    const sha = createHash("sha256").update(b.code).digest("hex");
    console.log(`${file}\n  version ${b.version}, commit ${commit}, ${b.modules.length} module(s), ${Object.keys(b.site).length} embedded site file(s), ${Buffer.byteLength(b.code)} bytes\n  sha256 ${sha}`);
  } catch (e) { console.error(`scanner-release: ${e.message}`); process.exit(1); }
}
