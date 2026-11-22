// scripts/scanner-stats.mjs: the Scanner page's live numbers, read from scanner/ read-only, never throwing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scannerStats, tableRows, baseTableRows, productsIn, kevCoverage, cleanRecent, fingerprintFiles } from "../../scripts/scanner-stats.mjs";

test("counts the real scanner: version, products, rules and opt-ins", async () => {
  const s = await scannerStats({ kev: [] });
  assert.match(s.version, /^\d+\.\d+\.\d+/);
  assert.ok(s.modules.includes("fingerprint.mjs"));
  assert.ok(s.products > 20, `products ${s.products}`);
  assert.ok(s.rules > 20, `rules ${s.rules}`);
  assert.ok(s.areas.services > 0 && s.areas.edge > 0 && s.areas.cms > 0);
  assert.ok(s.opt_ins.some((o) => o.flag === "--html"));
  assert.deepEqual(s.errors, []);
  assert.equal(s.kev_products, null, "no KEV data: coverage unknown, not zero");
  assert.ok(s.recent.length >= 5 && s.recent.every((r) => r.title && /^\d{4}-\d{2}-\d{2}$/.test(r.date)));
});

test("publishes counts only: no rule text, patterns or catalog ids", async () => {
  const s = await scannerStats({ kev: [] });
  const keys = Object.keys(s).sort();
  assert.deepEqual(keys, ["areas", "built_at", "catalog_rows", "cert_inventory", "errors", "kev_covered", "kev_gap", "kev_products", "modules", "opt_ins", "paths_per_host",
    "products", "rail_entries", "rail_paths", "recent", "rules", "version"]);
  for (const k of ["products", "rules", "catalog_rows"]) assert.equal(typeof s[k], "number");
});

test("an empty or missing scanner never throws; everything is null", async () => {
  const root = mkdtempSync(join(tmpdir(), "scs-"));
  try {
    const s = await scannerStats({ root, kev: [{ vendor: "X", product: "Y" }] });
    assert.equal(s.version, null); assert.equal(s.products, null); assert.equal(s.rules, null);
    assert.deepEqual(s.modules, []); assert.deepEqual(s.opt_ins, []); assert.deepEqual(s.recent, []);
    mkdirSync(join(root, "scanner", "lib"), { recursive: true });
    writeFileSync(join(root, "scanner", "lib", "fp-broken.mjs"), "export const RULES = [ this is not javascript");
    writeFileSync(join(root, "scanner", "lib", "fp-apps.mjs"), 'export const RULES = [{ ids: ["a"], vendor: "Acme", product: "Console" }, { ids: ["b"], vendor: "Acme", product: "Gate" }];');
    writeFileSync(join(root, "scanner", "lib", "paths.mjs"), 'export const RAIL = [{ id: "r1", paths: ["/v"] }]; export const RAIL_PATHS = ["/v"]; export const PATHS_PER_HOST = 8;\n// parse: tok("Acme", "Console", "1")');
    const t = await scannerStats({ root, kev: [{ vendor: "Acme", product: "Console" }, { vendor: "Other", product: "Thing" }] });
    assert.deepEqual(t.modules, ["fp-apps.mjs", "fp-broken.mjs", "paths.mjs"]);
    assert.equal(t.areas.apps, 2); assert.equal(t.rail_entries, 1); assert.equal(t.rail_paths, 1); assert.equal(t.paths_per_host, 8);
    assert.equal(t.products, 2);
    assert.deepEqual([t.kev_products, t.kev_covered, t.kev_gap], [2, 1, 1]);
    assert.ok(t.errors.some((e) => e.startsWith("fp-broken.mjs")));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("FINGERPRINT_TABLES and *_ROWS exports are counted", () => {
  const r = tableRows({ FINGERPRINT_TABLES: { a: [{ id: "x" }, { id: "y" }], b: { rules: [{ ids: ["z"] }] } }, CERT_ROWS: ["c1", "c2"], helper: () => 1, LIST: [1, 2, 3] });
  assert.equal(r.rules, 3); assert.equal(r.ids.size, 5);
});

test("source text: base tables and product pairs", () => {
  const src = 'const GREET = [\n  [/a/i, "V", "P", "ftp"],\n  [/b/, "V2", "P2"],\n];\nconst SERVER = [\n  [/^x$/i, "X", "Xs"], [/^y$/i, "", ""],\n];\n';
  assert.equal(baseTableRows(src), 4);
  assert.deepEqual([...productsIn(src)].sort(), ["v2|p2", "v|p", "x|xs"]);
  assert.equal(productsIn('{ vendor: "D-Link", product: "{model} Firmware" }').size, 0, "templates are not products");
});

test("KEV coverage by name, through NVD's affected names too", () => {
  const prods = new Set(["apache|http server", "proftpd project|proftpd"]);
  const c = kevCoverage([{ vendor: "Apache", product: "HTTP Server" }, { vendor: "ProFTPD", product: "ProFTPD" }, { vendor: "Apache", product: "HTTP Server" },
    { vendor: "Acme", product: "Router", affected: [{ vendor: "acme", product: "router_firmware" }] }], prods);
  assert.deepEqual(c, { total: 3, covered: 2, gap: 1 });
  assert.deepEqual(kevCoverage([], prods), { total: null, covered: null, gap: null });
});

test("the recent list is validated and length-limited", () => {
  const r = cleanRecent({ recent: [{ title: "A", line: "x".repeat(900), date: "2026-11-22", pr: 108 }, { title: "", date: "2026-11-22" }, { title: "B", date: "later" }, { title: "C", date: "2026-11-21", pr: "1; drop" }, null] });
  assert.equal(r.length, 2); assert.equal(r[0].line.length, 300); assert.equal(r[1].pr, null);
  assert.deepEqual(cleanRecent(null), []);
});

test("fingerprint module detection by file name", () => {
  assert.deepEqual(fingerprintFiles("/nonexistent/dir"), []);
});
