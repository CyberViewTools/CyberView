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

// Fix round 1
const okCards = (extra = {}, actorFacts = {}) => new Map([[A, card({ countries: [{ v: "Russia", q: "attributed to Russia by analysts" }, { v: "UK", q: "the UK agency said so" }], tools: [{ v: "Manuscrypt", q: Q1 }], figures: [{ v: "2000 hosts", q: "2000 hosts were hit" }], ...extra }, { sha1: A })]]);
const one = (t, cites = [A], h = "who") => story([{ h, sentences: [{ t, cites }] }]);
test("storyProblems: headline and in_short are backed and checked for attribution", () => {
  const cards = okCards();
  const p = storyProblems({ ...one("It used Manuscrypt."), headline: "Lazarus stole $9 billion via CVE-2099-0001", in_short: "Russian military intelligence ran it." }, cards, null);
  assert.ok(p.some((x) => x.startsWith("unbacked: headline")), p.join("|"));
  assert.ok(p.some((x) => x.startsWith("bare-attribution: in_short")), p.join("|"));
  assert.deepEqual(storyProblems({ ...one("It used Manuscrypt."), headline: "Manuscrypt campaign", in_short: "A campaign using Manuscrypt." }, cards, null), []);
  const cat = { name: "Lazarus", aliases: [], tools: [] };
  assert.deepEqual(storyProblems({ ...story([{ h: "who", sentences: [{ t: "Known as Lazarus.", cites: ["catalogue"] }] }]), headline: "Lazarus profile" }, new Map(), cat), []);
});
test("storyProblems: bare attribution catches demonyms and 2-letter codes", () => {
  const cards = okCards();
  assert.ok(storyProblems(one("Russian military intelligence ran it."), cards, null).some((x) => x.startsWith("bare-attribution")));
  assert.ok(storyProblems(one("The UK government ran it."), cards, null).some((x) => x.startsWith("bare-attribution")));
  assert.equal(storyProblems(one("Rus government."), cards, null).some((x) => x.startsWith("bare-attribution")), false);
  assert.deepEqual(storyProblems(one("According to Mandiant, Russian military intelligence ran it."), cards, null), []);
});
test("storyProblems: a 4-digit number inside a held figure is not an unbacked year", () => {
  assert.deepEqual(storyProblems(one("It hit 2000 hosts."), okCards(), null), []);
  assert.ok(storyProblems(one("It began in 2000."), okCards(), null).some((x) => x.startsWith("unbacked")));
});
test("quoteInText: a real compound split at a line break matches either way; typographic hyphens fold", () => {
  assert.equal(quoteInText("state-sponsored actors operate", "state-\nsponsored actors operate"), true);
  assert.equal(quoteInText("statesponsored actors operate", "state-\nsponsored actors operate"), true);
  assert.equal(quoteInText("state‑sponsored actors operate", "a state-sponsored actors operate"), true);
  assert.equal(quoteInText("state-sponsored actors invent", "state-\nsponsored actors operate"), false);
});
test("storyProblems: CVE ids with typographic hyphens are still checked", () => {
  assert.ok(storyProblems(one("It used CVE\u20112099\u20110001."), okCards({ dates: [{ v: "2099", what: "x", q: "in 2099 it began" }] }), null).some((x) => x.startsWith("unbacked")));
});
test("storyProblems: empty sections do not count", () => {
  assert.ok(storyProblems(story([{ h: "who", sentences: [] }]), new Map(), null).some((x) => x.startsWith("missing-section")));
  const two = new Map([[A, card({}, { sha1: A })], [B, card({}, { sha1: B })]]);
  const sp = storyProblems(story([{ h: "who", sentences: [{ t: "A.", cites: [A] }, { t: "B.", cites: [B] }] }, { h: "targets", sentences: [] }, { h: "methods", sentences: [] }], { kind: "actor" }), two, null);
  assert.deepEqual(sp.filter((x) => x.startsWith("missing-section")).sort(), ["missing-section: methods", "missing-section: targets"]);
});
test("checks do not throw on null facts, sentences, sections or cards", () => {
  assert.doesNotThrow(() => cardProblems({ summary: "s", kind: "incident", facts: { tools: [null, { v: "x", q: "x" }], cves: [null] }, hedges: null }, "text"));
  const cards = new Map([[A, null], [B, { facts: { tools: [null, { v: "Rat", q: "q" }], countries: [null] } }]]);
  assert.doesNotThrow(() => storyProblems({ by: BY, kind: "actor", sections: [null, { h: "who", sentences: [null, { t: "x", cites: [A, B, null] }] }] }, cards, null));
});
test("storyProblems: hedged attribution passes, catalogue alias needs its cite, no match inside a longer word", () => {
  const cards = new Map([[A, card({ countries: [{ v: "North Korea", q: Q2 }], tools: [{ v: "Rat", q: "the Rat tool was used widely" }] }, { sha1: A })]]);
  assert.deepEqual(storyProblems(one("According to Mandiant, it works for the North Korean government."), cards, null), []);
  const cat = { name: "TraderTraitor", aliases: ["Jade Sleet"], tools: [] };
  assert.ok(storyProblems(one("Also tracked as Jade Sleet."), cards, cat).some((x) => x.startsWith("unbacked")));
  assert.deepEqual(storyProblems(one("It ran a pirate operation."), cards, null), []);
});
