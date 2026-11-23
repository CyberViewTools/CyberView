// fetchFeed (scripts/collect.mjs): 415 handling, with fetch stubbed (no network).
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { fetchFeed } from "../../scripts/collect.mjs";

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });
const RSS = '<rss><channel><item><title>t</title><link>https://example.org/a</link></item></channel></rss>';
const stub = (fn) => { const calls = []; globalThis.fetch = async (u, o) => { calls.push(o.headers); return fn(o.headers); }; return calls; };
const res = (status, body = "") => ({ status, ok: status >= 200 && status < 300, text: async () => body });

test("415 on our accept list: asked again at once without it, same user-agent", async () => {
  const calls = stub((h) => h.accept ? res(415) : res(200, RSS));
  const r = await fetchFeed({ url: "https://example.org/feed" });
  assert.equal(r.items.length, 1);
  assert.equal(calls.length, 2);
  assert.ok(calls[0].accept);
  assert.equal(calls[1].accept, undefined);
  assert.equal(calls[1]["user-agent"], calls[0]["user-agent"]);
  assert.match(calls[1]["user-agent"], /^cyberview-collector\/1\.0/);
});

test("415 that persists without accept still fails as a 415", async () => {
  stub(() => res(415));
  const r = await fetchFeed({ url: "https://example.org/feed" });
  assert.equal(r.error, "HTTP 415");
});

test("403 still stops at once, with no second request", async () => {
  const calls = stub(() => res(403));
  const r = await fetchFeed({ url: "https://example.org/feed" });
  assert.match(r.error, /^HTTP 403/);
  assert.equal(calls.length, 1);
});
