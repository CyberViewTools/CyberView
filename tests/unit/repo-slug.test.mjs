// API calls (the deploy request, issues, pull requests) use the canonical repository, never the origin remote's name,
// which still says xanderhutch/CyberView in checkouts made before the repository moved (26 Nov 2026).
import { test } from "node:test";
import assert from "node:assert/strict";
import { REPO, repoSlug } from "../../scripts/lib/repo.mjs";

test("repoSlug: canonical repository unless Actions or an override says otherwise", () => {
  assert.equal(REPO, "CyberViewTools/CyberView");
  assert.equal(repoSlug(undefined, {}), REPO);
  assert.equal(repoSlug(undefined, { GITHUB_REPOSITORY: "a/b" }), "a/b");
  assert.equal(repoSlug(undefined, { CYBERVIEW_REPO: "c/d" }), "c/d");
});
