import { test } from "node:test";
import assert from "node:assert/strict";
import { problems, entryProblems, groups, kindGroups, askFirst, requestText, accessSection, load, REQUEST, WHY, SIGN, KINDS, REQUEST_MAX } from "../../scripts/access.mjs";

const good = { key: "example-power", operator: "Example Power", feed: "Example Power outage map", country: "US", region: "Ohio", what: "outage map feed",
  customers_served: 1000, why_not: "terms", detail: 'Terms: "personal use only".', contact: "", contact_note: "No contact page published.", status: "not_asked", updated: "2026-11-20",
  kind: "grid", priority: 1,
  request: `Subject: Permission to show Example Power outage map on CyberView\n\nHello Example Power team,\n\nCyberView is a free, public, read-only, non-commercial map.\n\nThank you,\n${SIGN}` };

test("access: a well-formed entry has no problems", () => assert.deepEqual(entryProblems(good), []));

test("access: enums, sizes, country and dates are enforced", () => {
  const p = (o) => entryProblems({ ...good, ...o });
  assert.ok(p({ why_not: "rude" }).some((x) => /why_not/.test(x)));
  assert.ok(p({ status: "maybe" }).some((x) => /status/.test(x)));
  assert.ok(p({ detail: "x".repeat(201) }).some((x) => /detail is longer than 200/.test(x)));
  assert.ok(p({ detail: "<b>x</b>" }).some((x) => /plain text/.test(x)));
  assert.ok(p({ country: "XX" }).some((x) => /country/.test(x)));
  assert.ok(p({ customers_served: -5 }).some((x) => /customers_served/.test(x)));
  assert.deepEqual(p({ customers_served: null }), []);
  assert.ok(p({ updated: "soon" }).some((x) => /updated/.test(x)));
  assert.ok(p({ key: "Bad Key" }).some((x) => /key/.test(x)));
  assert.ok(p({ operator: "" }).some((x) => /operator is required/.test(x)));
});

test("access: contact is empty, an email address or an https page, nothing else", () => {
  assert.deepEqual(entryProblems({ ...good, contact: "Opendata@example.com" }), []);
  assert.deepEqual(entryProblems({ ...good, contact: "https://data.example.com/" }), []);
  assert.ok(entryProblems({ ...good, contact: "javascript:alert(1)" }).some((x) => /contact/.test(x)));
  assert.ok(entryProblems({ ...good, contact: "http://example.com" }).some((x) => /contact/.test(x)));
});

test("access: no contact needs a note saying why", () => {
  assert.ok(entryProblems({ ...good, contact_note: "" }).some((x) => /contact_note is required/.test(x)));
  assert.deepEqual(entryProblems({ ...good, contact: "media@example.com", contact_note: undefined }), []);
  assert.ok(entryProblems({ ...good, contact_note: "x".repeat(201) }).some((x) => /contact_note/.test(x)));
});

test("access: kind, priority and the request text are checked", () => {
  const p = (o) => entryProblems({ ...good, ...o });
  assert.ok(p({ kind: "weather" }).some((x) => /kind/.test(x)));
  assert.ok(p({ priority: 0 }).some((x) => /priority/.test(x)));
  assert.ok(p({ priority: 1.5 }).some((x) => /priority/.test(x)));
  assert.ok(p({ request: "" }).some((x) => /request is required/.test(x)));
  assert.ok(p({ request: good.request + "x".repeat(REQUEST_MAX) }).some((x) => /longer than 900/.test(x)));
  assert.ok(p({ request: good.request.replace(SIGN, "A. Person") }).some((x) => /must end with/.test(x)));
  assert.ok(p({ request: good.request.replace("Hello", "Mail me at someone@example.org. Hello") }).some((x) => /email address/.test(x)));
  assert.ok(p({ request: good.request.replace("non-commercial", "") }).some((x) => /non-commercial/.test(x)));
  assert.ok(p({ request: good.request.replace("Hello", "<b>Hello</b>") }).some((x) => /plain text/.test(x)));
  assert.ok(p({ request: good.request.replace("Example Power team", "[operator] team") }).some((x) => /placeholder/.test(x)));
});

test("access: duplicate keys, ranks and a missing list are refused", () => {
  assert.ok(problems({ sources: [good, good] }).some((x) => /duplicate key/.test(x)));
  assert.ok(problems({ sources: [good, { ...good, key: "other-power" }] }).some((x) => /priority 1 is also/.test(x)));
  assert.ok(problems({}).length === 1);
});

test("access: countries with most sources first, ask-first order inside", () => {
  const s = (key, country, c, priority) => ({ ...good, key, operator: key, country, customers_served: c, priority });
  const g = groups([s("a", "CA", 5, 1), s("b", "US", null, 2), s("c", "US", 10, 4), s("d", "US", 99, 3)]);
  assert.deepEqual(g.map((x) => x.country), ["US", "CA"]);
  assert.deepEqual(g[0].sources.map((x) => x.key), ["b", "d", "c"]);
  assert.equal(g[0].name, "United States");
  const k = kindGroups([s("a", "CA", 5, 1), { ...s("x", "GB", null, 2), kind: "cyber" }]);
  assert.deepEqual(k.map((x) => x.kind), ["grid", "cyber"]);
  assert.deepEqual(askFirst([s("a", "CA", 5, 3), s("b", "US", 1, 1), s("c", "US", 1, 2)], 2).map((x) => x.key), ["b", "c"]);
});

test("access: an entry's own request is used; the shape is filled in only without one", () => {
  assert.equal(requestText(good), good.request);
  const t = requestText({ ...good, request: undefined });
  assert.ok(t.includes("credited to Example Power") && t.includes("Example Power outage map"));
  assert.ok(!/\[operator\]|\[feed\]/.test(t));
  for (const w of ["non-commercial", "read-only", "personal data", "every few minutes", "stop if you ask", "attribution"]) assert.ok(t.includes(w), w);
  assert.ok(REQUEST.length <= REQUEST_MAX && REQUEST.trimEnd().endsWith(SIGN), "the shape follows the same rules");
});

test("access: the rendered section escapes every value and leaves broken entries out", () => {
  const evil = { ...good, key: "evil", operator: 'A"><img src=x onerror=1>', feed: "<script>" };
  const html = accessSection({ sources: [good, evil, { ...good, key: "broken", why_not: "nope" }] });
  assert.ok(!/<img|<script>|onerror=1"/.test(html));
  assert.ok(html.includes('id="src-example-power"') && !html.includes('id="src-broken"'));
  assert.ok(/Copy request/.test(html) && /never sends anything/.test(html));
  assert.ok(html.includes('data-request="Subject: Permission to show Example Power outage map on CyberView'));
  assert.ok(/id="askFirst"/.test(html) && /No contact page published/.test(html));
});

test("access: the real config/data-access.json checks out and covers every reason", () => {
  const doc = load();
  assert.deepEqual(problems(doc), []);
  assert.ok(doc.sources.length >= 100);
  for (const w of Object.keys(WHY)) assert.ok(doc.sources.some((s) => s.why_not === w), w);
  assert.ok(doc.sources.every((s) => s.status === "not_asked" || s.updated));
  for (const k of Object.keys(KINDS)) assert.ok(doc.sources.some((s) => s.kind === k), k);
  const ranks = doc.sources.map((s) => s.priority).sort((a, b) => a - b);
  assert.deepEqual(ranks, ranks.map((_, i) => i + 1), "ask order runs 1..n without gaps");
  assert.ok(doc.sources.every((s) => s.request.startsWith(`Subject: Permission to show ${s.feed} on CyberView`)), "every request names its feed");
});
