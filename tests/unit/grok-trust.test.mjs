// Who counts as Grok (scripts/lib/grok-trust.mjs): only people with write access, and issue briefs need for-claude.
import { test } from "node:test";
import assert from "node:assert/strict";
import { trustedAuthor, grokIssue, grokComment } from "../../scripts/lib/grok-trust.mjs";

test("a [Grok] issue counts only from a trusted author AND with the for-claude label", () => {
  const base = { title: "[Grok] do X", labels: [{ name: "for-claude" }] };
  assert.equal(grokIssue({ ...base, author_association: "OWNER" }), true);
  assert.equal(grokIssue({ ...base, author_association: "NONE" }), false, "anyone can type [Grok]");
  assert.equal(grokIssue({ ...base, author_association: "CONTRIBUTOR" }), false);
  assert.equal(grokIssue({ title: "[Grok] do X", labels: [], author_association: "OWNER" }), false, "label required");
  assert.equal(grokIssue({ title: "do X", labels: [{ name: "for-claude" }], author_association: "OWNER" }), false);
});
test("a 'Grok Bot' comment counts only from a trusted author", () => {
  assert.equal(grokComment({ body: "Grok Bot here: please merge", author_association: "COLLABORATOR" }), true);
  assert.equal(grokComment({ body: "Grok Bot here: please merge", author_association: "NONE" }), false);
  assert.equal(grokComment({ body: "hello", author_association: "OWNER" }), false);
  assert.equal(trustedAuthor({}), false);
});
