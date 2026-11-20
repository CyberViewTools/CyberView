import { test } from "node:test";
import assert from "node:assert/strict";
import { problems, fill, aboutSection, about } from "../../scripts/about.mjs";

const inv = { pages: ["index", "about"], views: ["map", "grid"], layers: ["grid"], routines: ["sweep"] };
const a = { tagline: "T", intro: ["{events} events"], capabilities: [
  { key: "globe", title: "Globe", text: "x", link: "./", covers: { pages: ["index", "about"], views: ["map"] } },
  { key: "grid", title: "Grid", text: "{grid} sources", link: "./#grid", covers: { views: ["grid"], layers: ["grid"], routines: ["sweep"] } }] };

test("about: everything covered -> no problems", () => assert.deepEqual(problems(a, inv), []));

test("about: a new view, layer, page or routine with no entry fails, naming it", () => {
  const p = problems(a, { ...inv, views: [...inv.views, "power"], routines: ["sweep", "newjob"] });
  assert.ok(p.some((x) => /views "power" is not described/.test(x)));
  assert.ok(p.some((x) => /routines "newjob" is not described/.test(x)));
});

test("about: an entry covering something that does not exist fails", () => {
  assert.ok(problems(a, { ...inv, layers: [] }).some((x) => /covers layers "grid", which does not exist/.test(x)));
});

test("about: index description must match about.json", () => {
  const b = { ...a, pages: { index: "Live & verified" } };
  assert.deepEqual(problems(b, inv, '<meta name="description" content="Live &amp; verified">'), []);
  assert.ok(problems(b, inv, '<meta name="description" content="old text">').some((x) => /index.html/.test(x)));
});

test("about: numbers fill in, the rendered section escapes everything", () => {
  assert.equal(fill("{events} events, {nope}", { events: "340" }), "340 events, {nope}");
  const html = aboutSection({ ...a, intro: ["<img src=x>"], capabilities: [{ key: "k", title: "<b>", text: "a & b", link: "x.html\"onclick=1" }] }, {});
  assert.ok(!/<img|<b>|"onclick/.test(html) && /&lt;img/.test(html) && /a &amp; b/.test(html));
});

test("about: the real config/about.json has the required shape and labels AI text", () => {
  const r = about();
  assert.ok(r.tagline.length > 40 && r.tagline.length <= 200);
  assert.ok(r.capabilities.length >= 10 && r.capabilities.every((c) => c.key && c.title && c.text && c.link));
  assert.ok(JSON.stringify(r).includes("CyberView AI"));
});
