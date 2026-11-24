import { test } from "node:test";
import assert from "node:assert/strict";
import { problems, described, statedFigures, codeFiles } from "../../scripts/docs-check.mjs";

const base = { files: [], layout: "", jobs: "", routines: [], figures: [], live: { feeds: 5900, grid: 60 } };

test("docs-check: a file is described by full path, by name alone, or by a glob line", () => {
  assert.ok(described("scripts/lib/net.mjs   fetch", "scripts/lib/net.mjs"));
  assert.ok(described("config/feeds.json, queries.json   extra", "config/queries.json"));
  assert.ok(described("pages.yml (deploy), build.yml", ".github/workflows/build.yml"));
  assert.ok(described("config/feeds.d/*.json   shards", "config/feeds.d/finance.json"));
});

test("docs-check: a longer name does not describe a shorter one", () => {
  assert.equal(described("scripts/x-feeds.mjs  other", "scripts/feeds.mjs"), false);
  assert.equal(described("scripts/cve-db.mjs  old", "scripts/db.mjs"), false);
  assert.equal(described("scripts/feeds.mjsx", "scripts/feeds.mjs"), false);
});

test("docs-check: an undescribed file fails, naming it", () => {
  const p = problems({ ...base, files: ["scripts/new.mjs"], layout: "scripts/old.mjs  x" });
  assert.equal(p.length, 1);
  assert.match(p[0], /docs\/layout\.md does not describe scripts\/new\.mjs/);
});

test("docs-check: an active routine missing from jobs.md fails; key or name counts; inactive is skipped", () => {
  const routines = [{ key: "a", name: "Alpha" }, { key: "b", name: "Beta" }, { key: "c", name: "Gamma" }, { key: "d", active: false }];
  const p = problems({ ...base, routines, jobs: "| a | x |\n| Beta desk |" });
  assert.deepEqual(p.map((x) => x.match(/"(\w)"/)[1]), ["c"]);
});

test("docs-check: stated figures are found and compared with live counts", () => {
  const f = statedFigures("README.md", "reads about 2,500 feeds and 40 grid sources; about 5,900 RSS and Atom feeds; 60 public operator and agency feeds");
  assert.deepEqual(f.map((x) => [x.kind, x.said]), [["feeds", 2500], ["feeds", 5900], ["grid", 40], ["grid", 60]]);
  const p = problems({ ...base, figures: f });
  assert.equal(p.length, 2);
  assert.ok(p.some((x) => /says 2,500 feeds; there are 5,900/.test(x)));
  assert.ok(p.some((x) => /says 40 grid sources; there are 60/.test(x)));
});

test("docs-check: small numbers in prose are not taken as stated totals", () => {
  assert.deepEqual(statedFigures("x", "at most 4 feeds per host; twelve vendors' feeds; about 30 feeds"), []);
});

test("docs-check: a live count of zero (not measurable) never fails", () => {
  assert.deepEqual(problems({ ...base, figures: [{ file: "x", said: 10, kind: "feeds" }], live: { feeds: 0, grid: 0 } }), []);
});

test("docs-check: the scanned set includes scripts and workflows", () => {
  const files = codeFiles();
  assert.ok(files.includes("scripts/docs-check.mjs") && files.some((f) => f.startsWith(".github/workflows/")));
});

test("docs-check: 'Reads N feeds' and 'hundreds of feeds' are stated figures too", () => {
  const f = statedFigures("routines.json", "Reads 131 agency, vendor and news feeds; check hundreds of government, vendor and news feeds");
  assert.deepEqual(f.map((x) => x.said), [131, 500]);
  assert.equal(problems({ ...base, figures: f }).length, 2);
  assert.deepEqual(problems({ ...base, figures: f, live: { feeds: 520, grid: 60 } }).filter((x) => /says 500/.test(x)), []);
});
