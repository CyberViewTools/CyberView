// The deploy and CI workflows build main's code against the data branch, and one data commit starts one deploy.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const WF = join(import.meta.dirname, "..", "..", ".github", "workflows");
const read = (f) => readFileSync(join(WF, f), "utf8");
const triggers = (y) => /\non:\n([\s\S]*?)\n(?=\S)/.exec(y)[1];
const SPARSE = /sparse-checkout: \|\n\s+\/\*\n\s+!\/data\/\n\s+sparse-checkout-cone-mode: false/;

test("pages.yml: code pushes and dispatches only (data commits dispatch; nothing deploys twice)", () => {
  const y = read("pages.yml"), on = triggers(y);
  assert.match(on, /push:\n\s+branches: \[main\]\n\s+paths-ignore: \["data\/\*\*"\]/);
  assert.match(on, /workflow_dispatch:/);
  assert.doesNotMatch(on, /workflow_run|schedule|pull_request/);
  assert.match(y, /ref: main\n\s+sparse-checkout/);
  assert.match(y, SPARSE);
  assert.match(y, /uses: \.\/\.github\/actions\/data/);
  assert.match(y, /group: pages\n\s+cancel-in-progress: true/);
  assert.match(y, /verify-build\.mjs --against-live/);
  assert.match(y, /verify-build\.mjs --live/);
});

test("build.yml: pull requests and pushes to main, against the data branch", () => {
  const y = read("build.yml"), on = triggers(y);
  assert.match(on, /pull_request:\n\s+branches: \[main\]/);
  assert.match(on, /push:\n\s+branches: \[main\]/);
  assert.match(y, SPARSE);
  assert.ok((y.match(/uses: \.\/\.github\/actions\/data/g) || []).length >= 2, "validate and browser jobs mount the data");
});
