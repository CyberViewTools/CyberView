// GDELT requests are spaced machine-wide (scripts/lib/gdelt.mjs): one every 6 seconds across osint.mjs and grid-news.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { waitFor, GAP_MS } from "../../scripts/lib/gdelt.mjs";

test("waitFor: no wait the first time, the rest of the gap after a recent request, none after it", () => {
  assert.equal(waitFor(NaN, 1000), 0);
  assert.equal(waitFor(10000, 12000), GAP_MS - 2000);
  assert.equal(waitFor(10000, 10000 + GAP_MS + 1), 0);
  assert.ok(GAP_MS >= 5000);
});

test("every GDELT DOC-API caller takes a slot before every request", () => {
  // osint.mjs retired its DOC-API collector 2026-11-23 (scripts/gdelt-gkg.mjs replaced it); grid-news.mjs still queries it.
  for (const f of ["grid-news.mjs"]) {
    const s = readFileSync(new URL("../../scripts/" + f, import.meta.url), "utf8");
    assert.match(s, /import \{ gdeltSlot \} from "\.\/lib\/gdelt\.mjs"/);
    assert.ok((s.match(/await gdeltSlot\(/g) || []).length >= (s.match(/api\.gdeltproject\.org/g) || []).length, f);
  }
});
