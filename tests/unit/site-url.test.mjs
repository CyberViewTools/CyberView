// The site's address in one place (scripts/lib/site-url.mjs).
import { test } from "node:test";
import assert from "node:assert/strict";
import { siteUrl } from "../../scripts/lib/site-url.mjs";
test("site address: env, then config, then the Pages default; https only, no trailing slash", () => {
  assert.equal(siteUrl("https://cyberview.example/", "https://other.example"), "https://cyberview.example");
  assert.equal(siteUrl("", "https://cyberview.example"), "https://cyberview.example");
  assert.equal(siteUrl("", ""), "https://cyberview.tools");
  assert.equal(siteUrl("http://plain.example", "javascript:alert(1)"), "https://cyberview.tools");
});
