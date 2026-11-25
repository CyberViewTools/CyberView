// Which country a feed covers and how many feeds each country has (scripts/lib/feed-country.mjs), and the checker's
// refusal of a country code CyberView does not count. No network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { COUNTRIES, countryFromName, countryOf, coverage } from "../../scripts/lib/feed-country.mjs";
import { shapeProblem } from "../../scripts/feed-check.mjs";

test("countryFromName reads the bracketed label at the end of a feed name", () => {
  assert.equal(countryFromName("CBC News (Canada)"), "CA");
  assert.equal(countryFromName("Brandon Sun (CA)"), "CA");
  assert.equal(countryFromName("CJME (Regina, SK)"), "CA");
  assert.equal(countryFromName("Arizona Daily Star (Tucson, US)"), "US");
  assert.equal(countryFromName("Folha (Brasil)"), "BR");
  assert.equal(countryFromName("The Register (UK)"), "GB");
  assert.equal(countryFromName("Hespress (Maroc)"), "MA");
  assert.equal(countryFromName("Plain name"), "");
  assert.equal(countryFromName("Odd (Atlantis)"), "");
});

test("countryOf prefers the country field, then the name, then a country-code domain", () => {
  assert.equal(countryOf({ name: "X", url: "https://example.com/feed", country: "KE" }), "KE");
  assert.equal(countryOf({ name: "X (Ghana)", url: "https://example.ca/feed" }), "GH");
  assert.equal(countryOf({ name: "X", url: "https://www.cbc.ca/rss" }), "CA");
  assert.equal(countryOf({ name: "X", url: "https://news.bbc.co.uk/rss" }), "GB");
  assert.equal(countryOf({ name: "X", url: "https://www.cisa.gov/feed" }), "US");
  assert.equal(countryOf({ name: "X", url: "https://startup.io/feed" }), "");
  assert.equal(countryOf({ name: "X", url: "https://example.com/feed" }), "");
  assert.equal(countryOf({ name: "X", url: "not a url" }), "");
  assert.equal(countryOf({ name: "X", url: "https://example.com/", country: "ZZ" }), "");
});

test("coverage counts feeds per country and lists the thin ones, fewest first", () => {
  const feeds = [
    { name: "A", url: "https://a.ca/f" }, { name: "B", url: "https://b.ca/f" }, { name: "C", url: "https://c.ca/f" },
    { name: "D (Kenya)", url: "https://d.com/f" }, { name: "E", url: "https://e.com/f" },
  ];
  const c = coverage(feeds, { under: 2 });
  assert.equal(c.counts.CA, 3);
  assert.equal(c.counts.KE, 1);
  assert.equal(c.international, 1);
  assert.equal(c.thin.length, COUNTRIES.length - 1);
  assert.equal(c.thin.at(-1).cc, "KE");
  assert.ok(!c.thin.some((t) => t.cc === "CA"));
  assert.equal(c.thin[0].n, 0);
});

test("the checker refuses a country code CyberView does not count", () => {
  const base = { name: "X (Kenya)", tier: "news", url: "https://x.ke/feed", lang: "en", region: "africa" };
  assert.equal(shapeProblem({ ...base, country: "KE" }), "");
  assert.match(shapeProblem({ ...base, country: "ZZ" }), /country ZZ/);
});

test("a country named as a whole word in a .com feed's name places it; ambiguous names do not", async () => {
  const { countryInText } = await import("../../scripts/lib/feed-country.mjs");
  assert.equal(countryOf({ name: "Burundi Iwacu", url: "https://www.iwacu-burundi.org/feed/" }), "BI");
  assert.equal(countryOf({ name: "Times of Malta", url: "https://timesofmalta.com/rss" }), "MT");
  assert.equal(countryInText("Papua New Guinea Post-Courier"), "PG");
  assert.equal(countryInText("Nigerian Tribune"), "");
  assert.equal(countryInText("Georgia Public Broadcasting"), "");
  assert.equal(countryInText("Jordan's blog"), "");
  assert.equal(countryOf({ name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/" }), "");
});
