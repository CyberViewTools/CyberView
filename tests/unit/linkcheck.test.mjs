// Unit tests for scripts/linkcheck.mjs: the HEAD-then-GET check and the rotation. fetch is stubbed; no network.
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { check, classify, rotate } from "../../scripts/linkcheck.mjs";

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });
/** Stub fetch: answers[method] is a status, or an Error to throw; records the methods used. */
function stub(answers) {
  const calls = [];
  globalThis.fetch = async (_u, o) => { calls.push(o.method); const a = answers[o.method]; if (a instanceof Error) throw a; return { status: a }; };
  return calls;
}

test("HEAD 404 then GET 200: the page is live", async () => {
  const calls = stub({ HEAD: 404, GET: 200 });
  const r = await check("https://example.com/a");
  assert.deepEqual(calls, ["HEAD", "GET"]);
  assert.equal(classify(r.status, r.code), "ok");
});
test("HEAD 404 then GET 404: broken", async () => {
  const calls = stub({ HEAD: 404, GET: 404 });
  const r = await check("https://example.com/a");
  assert.deepEqual(calls, ["HEAD", "GET"]);
  assert.equal(classify(r.status, r.code), "broken");
});
test("HEAD 410 then GET 410: broken; HEAD 410 then GET 200: ok", async () => {
  stub({ HEAD: 410, GET: 410 });
  assert.equal(classify(...Object.values(await check("https://example.com/a"))), "broken");
  stub({ HEAD: 410, GET: 200 });
  assert.equal(classify(...Object.values(await check("https://example.com/a"))), "ok");
});
test("HEAD 200: ok with no second request", async () => {
  const calls = stub({ HEAD: 200, GET: 500 });
  const r = await check("https://example.com/a");
  assert.deepEqual(calls, ["HEAD"]);
  assert.equal(classify(r.status, r.code), "ok");
});
test("HEAD 405 still falls back to GET", async () => {
  const calls = stub({ HEAD: 405, GET: 200 });
  assert.equal((await check("https://example.com/a")).status, 200);
  assert.deepEqual(calls, ["HEAD", "GET"]);
});
test("HEAD 500 is final and not broken", async () => {
  const calls = stub({ HEAD: 500, GET: 200 });
  const r = await check("https://example.com/a");
  assert.deepEqual(calls, ["HEAD"]);
  assert.equal(classify(r.status, r.code), "blocked");
});

test("rotate walks the whole list across runs and wraps", () => {
  const list = ["a", "b", "c", "d", "e"];
  let off, seen = [];
  for (let i = 0; i < 3; i++) { const r = rotate(list, off, 2); seen.push(...r.slice); off = r.next; }
  assert.deepEqual(seen, ["a", "b", "c", "d", "e", "a"]);
  assert.equal(off, 1);
});
test("rotate tolerates an absent, bad or out-of-range offset and a short list", () => {
  assert.deepEqual(rotate(["a", "b", "c"], undefined, 2), { slice: ["a", "b"], next: 2 });
  assert.deepEqual(rotate(["a", "b", "c"], "x", 2).slice, ["a", "b"]);
  assert.deepEqual(rotate(["a", "b", "c"], 7, 2), { slice: ["b", "c"], next: 0 });
  assert.deepEqual(rotate(["a", "b"], 1, 400), { slice: ["b", "a"], next: 1 }, "a list shorter than the cap is checked whole, each URL once");
  assert.deepEqual(rotate([], 3, 5), { slice: [], next: 0 });
});
