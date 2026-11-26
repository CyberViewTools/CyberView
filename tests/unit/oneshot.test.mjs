import { test } from "node:test";
import assert from "node:assert/strict";
import { oneShotArgs, parseReply, oneShot } from "../../scripts/lib/oneshot.mjs";
import { noteOutcome, limitState } from "../../scripts/run-job.mjs";

const MODELS = { roles: { "library-reader": { model: "haiku", max_turns: 1, tools: "none" } } };

test("oneShotArgs: no tools, one turn, the role's model", () => {
  const a = oneShotArgs("library-reader", MODELS);
  assert.ok(!a.some((x) => x === "P" || x.length > 60), "the prompt is sent on stdin, not in argv");
  assert.equal(a[0], "-p"); assert.equal(a[1], "--model");
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
test("an unknown role throws instead of falling back to sonnet", async () => {
  assert.throws(() => oneShotArgs("library-nope", MODELS), /unknown role/);
  await assert.rejects(() => oneShot("library-nope", "P"), /unknown role/);
});
test("noteOutcome: a subscription limit sets the limit state; a limit on the fallback key sets the fallback-limited state", () => {
  const at = new Date().toISOString();
  noteOutcome({ ok: true, at }, "subscription");
  const before = limitState();
  noteOutcome({ ok: false, limit: true, at, error: "usage limit" }, "subscription");
  assert.equal(limitState().limitHit.limit, true);
  assert.equal(limitState().fallbackKeyLimited, before.fallbackKeyLimited);
  noteOutcome({ ok: false, limit: true, at, error: "usage limit" }, "api-fallback");
  assert.equal(limitState().fallbackKeyLimited, true);
});
