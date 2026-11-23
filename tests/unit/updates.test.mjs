import { test } from "node:test";
import assert from "node:assert/strict";
import { candidates, isRedirect, redirectOnly } from "../../scripts/updates.mjs";

const now = Date.parse("2026-11-19T18:00:00Z");
const ev = { id: "acme-ransomware-attack-2026-11", title: "Acme Corp hit by ransomware attack", org: "Acme Corp", category: "incident", severity: 3, status: "developing", first_seen: "2026-11-18T10:00:00Z", updated_at: "2026-11-18T12:00:00Z",
  cves: ["CVE-2026-5555"], sources: [{ url: "https://news.example/acme-1" }] };
const lead = (o) => ({ title: "Acme Corp ransomware attack: company confirms data theft", url: "https://news.example/acme-2", source: "Example News", tier: "news", published: "2026-11-19T09:00:00Z", ...o });

test("a newer page about a published event, from a page it does not cite, is a candidate", () => {
  const c = candidates([lead()], [ev], new Set(), now);
  assert.equal(c.length, 1); assert.equal(c[0].id, ev.id); assert.equal(c[0].leads[0].url, "https://news.example/acme-2");
});
test("cited pages, handled pages, older pages, claims and database rows are not", () => {
  assert.equal(candidates([lead({ url: "https://news.example/acme-1" })], [ev], new Set(), now).length, 0);
  assert.equal(candidates([lead()], [ev], new Set(["https://news.example/acme-2"]), now).length, 0);
  assert.equal(candidates([lead({ published: "2026-11-18T11:00:00Z" })], [ev], new Set(), now).length, 0);
  assert.equal(candidates([lead({ kind: "claim" }), lead({ kind: "cve", url: "https://db.example/x" })], [ev], new Set(), now).length, 0);
  assert.equal(candidates([lead({ title: "Unrelated bank outage in Spain", url: "https://news.example/z" })], [ev], new Set(), now).length, 0);
});
test("a CVE named in the headline links the page to its event; agencies rank first; an aggregator's redirect never gets an updater", () => {
  const leads = [lead({ title: "Patch now: CVE-2026-5555 exploited", url: "https://news.google.com/rss/articles/x" }), lead({ title: "Advisory on CVE-2026-5555", url: "https://agency.example/a", tier: "gov", source: "Agency" })];
  const c = candidates(leads, [ev], new Set(), now);
  assert.equal(c.length, 1); assert.deepEqual(c[0].leads.map((l) => l.url), ["https://agency.example/a"], "the redirect is left out: no worker can read or cite it");
  // the follow-up desk keeps redirects (a sign the story moved), ranked last
  const all = candidates(leads, [ev], new Set(), now, 48, { redirects: true });
  assert.equal(all[0].leads[0].url, "https://agency.example/a"); assert.equal(all[0].leads.at(-1).url, "https://news.google.com/rss/articles/x");
  // an event only a redirect names: no updater, and it is counted, not dropped silently
  const only = [leads[0]];
  assert.equal(candidates(only, [ev], new Set(), now).length, 0);
  assert.deepEqual(redirectOnly(candidates(only, [ev], new Set(), now, 48, { redirects: true }), candidates(only, [ev], new Set(), now)), { events: 1, leads: 1 });
  for (const u of ["https://news.google.com/rss/articles/x", "https://www.bing.com/news/apiclick.aspx?x", "https://www.msn.com/en-us/news/x"]) assert.equal(isRedirect(u), true, u);
  for (const u of ["https://agency.example/a", "https://example.com/news.google.com/x", "https://blogs.bing.com/x"]) assert.equal(isRedirect(u), false, u);
});

import { handledFrom } from "../../scripts/updates.mjs";
test("a page that would not load is retried once an hour later, then dropped; any other outcome is final", () => {
  const t = Date.parse("2026-11-19T18:00:00Z"), u = "https://x.example/a";
  assert.equal(handledFrom([{ at: "2026-11-19T17:30:00Z", outcome: "unreachable", urls: [u] }], t).has(u), true, "wait an hour");
  assert.equal(handledFrom([{ at: "2026-11-19T16:30:00Z", outcome: "unreachable", urls: [u] }], t).has(u), false, "then try again");
  assert.equal(handledFrom([{ at: "2026-11-19T14:00:00Z", outcome: "unreachable", urls: [u] }, { at: "2026-11-19T15:30:00Z", outcome: "unreachable", urls: [u] }], t).has(u), true, "two failures: dropped");
  assert.equal(handledFrom([{ at: "2026-11-18T10:00:00Z", outcome: "unchanged", urls: [u] }], t).has(u), true);
});
