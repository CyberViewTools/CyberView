// Unit tests for scripts/lib/net.mjs against a local HTTP server.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { get, circuitOpen } from "../../scripts/lib/net.mjs";

let srv, base, hits = {};
before(async () => {
  srv = createServer((req, res) => {
    hits[req.url] = (hits[req.url] || 0) + 1;
    if (req.url === "/ok") return res.end('{"a":1}');
    if (req.url === "/bom") return res.end('﻿{"b":2}');
    if (req.url === "/flaky") return hits[req.url] < 2 ? (res.statusCode = 503, res.end()) : res.end('{"c":3}');
    if (req.url === "/404") return (res.statusCode = 404, res.end());
    if (req.url === "/html") return res.end("<html>");
    if (req.url === "/busy1") return hits[req.url] < 2 ? (res.statusCode = 429, res.setHeader("retry-after", "1"), res.end()) : res.end('{"d":4}');
    if (req.url === "/busylong") return (res.statusCode = 429, res.setHeader("retry-after", "3600"), res.end());
    res.statusCode = 500; res.end();
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${srv.address().port}`;
});
after(() => srv.close());

test("parses JSON, including a byte-order mark", async () => {
  assert.deepEqual(await get(base + "/ok", { key: "t1" }), { a: 1 });
  assert.deepEqual(await get(base + "/bom", { key: "t1" }), { b: 2 });
});

test("retries a 5xx, then succeeds", async () => {
  assert.deepEqual(await get(base + "/flaky", { key: "t2", delayMs: 10 }), { c: 3 });
  assert.equal(hits["/flaky"], 2);
});

test("does not retry a 404, and names the status", async () => {
  await assert.rejects(get(base + "/404", { key: "t3", delayMs: 10 }), (e) => e.code === "http_404");
  assert.equal(hits["/404"], 1);
});

test("bad JSON is reported as bad_json", async () => {
  await assert.rejects(get(base + "/html", { key: "t4" }), (e) => e.code === "bad_json");
});

test("circuit opens after three failed calls and then skips the source", async () => {
  for (let i = 0; i < 3; i++) await assert.rejects(get(base + "/down", { key: "t5", retries: 0 }));
  assert.ok(circuitOpen("t5"));
  const before = hits["/down"];
  await assert.rejects(get(base + "/down", { key: "t5", retries: 0 }), (e) => e.code === "circuit_open");
  assert.equal(hits["/down"], before);
});

test("429 with Retry-After: waits what the source asked, then succeeds", async () => {
  const t0 = Date.now();
  assert.deepEqual(await get(base + "/busy1", { key: "t6", delayMs: 10 }), { d: 4 });
  assert.ok(Date.now() - t0 >= 950, "waited the second the source asked for, not the 10 ms backoff");
});

test("429 asking for an hour: not retried in this run, and the source stays skipped until then", async () => {
  await assert.rejects(get(base + "/busylong", { key: "t7", delayMs: 10 }), (e) => e.code === "http_429" && e.retryAfterMs === 3600000);
  assert.equal(hits["/busylong"], 1);
  assert.ok(circuitOpen("t7"));
  await assert.rejects(get(base + "/busylong", { key: "t7" }), (e) => e.code === "circuit_open");
});
