import { test } from "node:test";
import assert from "node:assert/strict";
import { oneShotArgs, parseReply } from "../../scripts/lib/oneshot.mjs";

const MODELS = { roles: { "library-reader": { model: "haiku", max_turns: 1, tools: "none" } } };

test("oneShotArgs: no tools, one turn, the role's model", () => {
  const a = oneShotArgs("library-reader", "P", MODELS);
  assert.equal(a[a.indexOf("--tools") + 1], "");
  assert.equal(a[a.indexOf("--max-turns") + 1], "1");
  assert.equal(a[a.indexOf("--model") + 1], "haiku");
  assert.ok(a.includes("--strict-mcp-config"));
  assert.ok(!a.includes("--allowedTools"));
});
test("parseReply: JSON inside prose and fences is found; a limit message is flagged", () => {
  assert.deepEqual(parseReply(JSON.stringify({ result: "Here:\n```json\n{\"a\":1}\n```" })).json, { a: 1 });
  assert.equal(parseReply(JSON.stringify({ result: "You've hit your usage limit", is_error: true })).limit, true);
  assert.equal(parseReply("not json").ok, false);
});
test("parseReply: braces inside strings and a later object are handled; a reply with no object is not ok", () => {
  assert.deepEqual(parseReply(JSON.stringify({ result: 'x {"a":"}{","b":{"c":2}} y' })).json, { a: "}{", b: { c: 2 } });
  assert.equal(parseReply(JSON.stringify({ result: "no object here" })).ok, false);
});
test("parseReply: a card that merely mentions a rate limit is not a limit", () => {
  const r = parseReply(JSON.stringify({ result: '{"summary":"rate limiting bypass"}' }));
  assert.equal(r.limit, false); assert.equal(r.ok, true);
});
