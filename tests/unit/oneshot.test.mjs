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
test("parseReply: a failed call is error, a bad reply and a limit are not", () => {
  assert.equal(parseReply("not json").error, true);
  assert.equal(parseReply(JSON.stringify({ result: "boom", is_error: true })).error, true);
  assert.equal(parseReply(JSON.stringify({ result: "x", terminal_reason: "api_error" })).error, true);
  assert.equal(parseReply(JSON.stringify({ result: "You've hit your usage limit", is_error: true })).error, false);
  assert.equal(parseReply(JSON.stringify({ result: "no object here" })).error, false);
  assert.equal(parseReply(JSON.stringify({ result: '{"a":1}' })).error, false);
});

// B-I5: the committed usage ledger never holds the model's reply text (report text could be echoed in it)
import { ledgerFor } from "../../scripts/lib/oneshot.mjs";
test("ledgerFor: no reply text reaches the recorded line; errors are short codes", () => {
  const SECRET = "The report says SECRET-REPORT-TEXT about the victim";
  const env = (o) => JSON.stringify({ num_turns: 1, usage: { input_tokens: 10, output_tokens: 5 }, ...o });
  const cases = [
    [env({ result: `{"summary":"${SECRET}"}` }), null, {}, null],
    [env({ result: SECRET, is_error: true }), null, {}, "api-error"],
    [env({ result: "x", subtype: "error_max_turns" }), null, {}, "turn-cap"],
    ["", "timeout", { timedOut: true }, "timeout"],
    ["", `boom ${SECRET}`, { code: 3 }, "exit-3"],
    ["not json " + SECRET, null, { code: 0 }, "no-json"],
    [env({ result: "You've hit your usage limit · resets 3pm (UTC)", is_error: true }), null, {}, "limit"],
  ];
  for (const [out, err, meta, code] of cases) {
    const l = ledgerFor("library", "library-reader", "abc", "haiku", 5, out, err, "subscription", meta);
    const s = JSON.stringify(l);
    assert.ok(!s.includes("SECRET") && !s.includes("victim"), s);
    assert.equal(l.last, ""); assert.equal(l.error, code, s);
  }
  assert.equal(ledgerFor("library", "library-reader", "abc", "haiku", 5, env({ result: "You've hit your usage limit · resets 3pm (UTC)", is_error: true }), null, "subscription", {}).limit, true);
});
