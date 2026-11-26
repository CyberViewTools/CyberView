// Library checks (scripts/lib/library-check.mjs). Run: node --test tests/unit/
import test from "node:test";
import assert from "node:assert/strict";
import { BY, KINDS, SECTIONS, QUOTE_MAX, normText, quoteInText, cleanCard, cardProblems, cleanStory, storyProblems } from "../../scripts/lib/library-check.mjs";

const A = "a".repeat(40), B = "b".repeat(40);
const Q1 = "The group relies on the Manuscrypt backdoor", Q2 = "attributed to North Korea by analysts", Q3 = "Lazarus exploited CVE-2023-42793 in TeamCity";
const card = (facts = {}, over = {}) => ({
  sha1: A, status: "read", partial: false, read_at: "2026-11-25T00:00:00Z", model: "haiku", summary: "A report about a campaign.", kind: "actor-campaign",
  facts: { actors: [], sectors: [], countries: [], dates: [], tools: [], techniques: [], cves: [], figures: [], ...facts }, subject: null, hedges: [], ...over,
});
const story = (sections, over = {}) => ({
  key: "actor:1", kind: "subject", name: "Test", headline: "Headline", in_short: "Short.", sections, status: "draft", based_on: "x", tries: 0, by: BY,
  written_at: "2026-11-25T00:00:00Z", writer_model: "sonnet", ...over,
});

test("quoteInText: PDF noise still matches, invention never does", () => {
  const text = "The group de-\nployed  “Manuscrypt” against cryptocurrency ex­changes in 2023.";
  assert.equal(quoteInText('deployed "Manuscrypt" against cryptocurrency exchanges', text), true);
  assert.equal(quoteInText("deployed Manuscrypt against banks", text), false);
  assert.equal(quoteInText("in 2023", text), false);
});
test("normText joins line-break hyphens and straightens quotes", () => {
  assert.equal(normText("Ex-\n ample ’s  X"), "example 's x");
});
test("cardProblems: a fabricated CVE and a value missing from its quote are refused", () => {
  const text = "Lazarus exploited CVE-2023-42793 in JetBrains TeamCity servers during October 2023.";
  const ok = card({ cves: [{ v: "CVE-2023-42793", q: "Lazarus exploited CVE-2023-42793 in JetBrains TeamCity" }] });
  assert.deepEqual(cardProblems(ok, text), []);
  const bad = card({ cves: [{ v: "CVE-2024-11111", q: "Lazarus exploited CVE-2023-42793 in JetBrains TeamCity" }] });
  assert.ok(cardProblems(bad, text).some((p) => p.startsWith("value-not-in-quote")));
  const made = card({ tools: [{ v: "Manuscrypt", q: "the group used the Manuscrypt backdoor widely" }] });
  assert.ok(cardProblems(made, text).some((p) => p.startsWith("quote-not-in-text")));
});
test("cardProblems: malformed CVE, long quote, date year, summary and kind", () => {
  const long = "x".repeat(QUOTE_MAX + 1), text = `CVE-23-1 here ${long} and in March 2022 it ended`;
  const p = cardProblems(card({ cves: [{ v: "CVE-23-1", q: "CVE-23-1 here xxxxxxxx" }], techniques: [{ v: "x", q: long }], dates: [{ v: "2021-03", what: "end", q: "in March 2022 it ended" }] }, { summary: " ", kind: "nope" }), text);
  for (const code of ["cve-malformed", "quote-too-long", "value-not-in-quote", "empty-summary", "bad-kind"]) assert.ok(p.some((x) => x.startsWith(code)), code);
  assert.deepEqual(cardProblems(card({ dates: [{ v: "2022-03", what: "end", q: "in March 2022 it ended" }] }), text), []);
});
test("cardProblems: code is refused", () => {
  assert.ok(cardProblems(card({}, { summary: "Run `powershell -enc AAAA` to reproduce." }), "x".repeat(50)).includes("code"));
});
test("storyProblems: uncited, unbacked and bare attribution", () => {
  const cards = new Map([[A, card({ tools: [{ v: "Manuscrypt", q: Q1 }], countries: [{ v: "North Korea", q: Q2 }] }, { sha1: A })],
                         [B, card({ cves: [{ v: "CVE-2023-42793", q: Q3 }] }, { sha1: B })]]);
  const s = story([{ h: "methods", sentences: [
    { t: "The group relies on Manuscrypt.", cites: [A] },
    { t: "It exploited CVE-2023-42793.", cites: [A] },
    { t: "It has stolen from exchanges.", cites: [] },
    { t: "It works for the North Korea government.", cites: [A] } ] }]);
  const p = storyProblems(s, cards, null);
  assert.equal(p.filter((x) => x.startsWith("unbacked")).length, 1);
  assert.equal(p.filter((x) => x.startsWith("uncited")).length, 1);
  assert.equal(p.filter((x) => x.startsWith("bare-attribution")).length, 1);
});
test("storyProblems: years, figures, bad cites, bylines, sections, code", () => {
  const cards = new Map([[A, card({ dates: [{ v: "2023-10", what: "x", q: "during October 2023 it" }], figures: [{ v: "1,200", q: "1,200 hosts were hit" }] }, { sha1: A })]]);
  const mk = (t, cites = [A], over = {}, h = "who") => storyProblems(story([{ h, sentences: [{ t, cites }] }], over), cards, null);
  assert.deepEqual(mk("It began in 2023 and hit 1,200 hosts."), []);
  assert.ok(mk("It began in 2019.").some((x) => x.startsWith("unbacked")));
  assert.ok(mk("It hit 9,000 hosts.").some((x) => x.startsWith("unbacked")));
  assert.ok(mk("Fine.", ["c".repeat(40)]).some((x) => x.startsWith("bad-cite")));
  assert.ok(mk("Fine.", [A], { by: "someone" }).includes("no-byline"));
  assert.ok(mk("Run `ls` now.").includes("code"));
  assert.ok(storyProblems(story([]), cards, null).some((x) => x.startsWith("missing-section")));
  const two = new Map([...cards, [B, card({}, { sha1: B })]]);
  const sp = storyProblems(story([{ h: "who", sentences: [{ t: "A.", cites: [A] }, { t: "B.", cites: [B] }] }], { kind: "actor" }), two, null);
  assert.deepEqual(sp.filter((x) => x.startsWith("missing-section")).sort(), ["missing-section: methods", "missing-section: targets"]);
});
test("storyProblems: takeaway may be uncited; catalogue cite needs an actor", () => {
  const s = story([{ h: "takeaway", sentences: [{ t: "General advice: review remote access.", cites: [] }] },
                   { h: "who", sentences: [{ t: "Also tracked as Jade Sleet.", cites: ["catalogue"] }] }]);
  assert.deepEqual(storyProblems(s, new Map(), { name: "TraderTraitor", aliases: ["Jade Sleet"], tools: [] }), []);
  assert.ok(storyProblems(s, new Map(), null).some((x) => x.startsWith("bad-cite")));
});
test("cleanCard and cleanStory: shape, caps and unknown keys", () => {
  assert.equal(cleanCard(null, A), null);
  assert.equal(cleanCard(card(), "short"), null);
  const c = cleanCard({ ...card({ tools: Array.from({ length: 30 }, (_, i) => ({ v: `t${i}`, q: "q", extra: 1 })) }), junk: 1, summary: "s".repeat(900) }, A.toUpperCase());
  assert.equal(c.sha1, A); assert.equal(c.facts.tools.length, 20); assert.ok(c.summary.length <= 600); assert.equal(c.junk, undefined); assert.equal(c.facts.tools[0].extra, undefined);
  assert.equal(cleanStory([]), null);
  const s = cleanStory({ ...story([{ h: "who", sentences: [{ t: "x", cites: [A, "bogus", "catalogue"], z: 1 }] }, { h: "nope", sentences: [] }]), junk: 1 });
  assert.deepEqual(s.sections.map((x) => x.h), ["who"]); assert.deepEqual(s.sections[0].sentences[0].cites, [A, "catalogue"]); assert.equal(s.junk, undefined);
  assert.ok(KINDS.length === 6 && SECTIONS.length === 5);
});
