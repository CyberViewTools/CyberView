// Page technology (scanner/lib/fp-cms.mjs, page-technology slice): web platforms from generator/headers/cookie names/markup and
// script libraries from file names, CDN paths and banners. Only a stated version is compared with CVE ranges; the rest is inventory.
import { test } from "node:test";
import assert from "node:assert/strict";
import { cmsServices } from "../../scanner/lib/fp-cms.mjs";
import { svc } from "../../scanner/lib/fingerprint.mjs";
const run = (b, h = {}) => cmsServices(b, 443, "https", svc, [], h).map((s) => [s.product, s.version || "", !s.guessed]);
const has = (r, product, version, stated) => r.some(([p, v, st]) => p === product && v === version && st === stated);

test("platforms with a stated version: Ghost, MediaWiki, Discourse, vBulletin, Liferay, Umbraco, Next.js", () => {
  assert.ok(has(run('<meta name="generator" content="Ghost 5.82">'), "Ghost", "5.82", true));
  assert.ok(has(run('<meta name="generator" content="MediaWiki 1.39.3">'), "MediaWiki", "1.39.3", true));
  assert.ok(has(run('<meta name="generator" content="Discourse 3.1.0 - https://github.com/discourse/discourse version 1a2b">'), "Discourse", "3.1.0", true));
  assert.ok(has(run('<meta name="generator" content="vBulletin 5.6.4">'), "vBulletin", "5.6.4", true));
  assert.ok(has(run("<html>", { "liferay-portal": "Liferay Community Edition Portal 7.4.3.4 CE GA4 (Cavanaugh / Build 7403)" }), "Liferay Portal", "7.4.3.4", true));
  assert.ok(has(run("<html>", { "x-umbraco-version": "10.4.0" }), "Umbraco CMS", "10.4.0", true));
  assert.ok(has(run("<html>", { "x-powered-by": "Next.js 13.4.1" }), "Next.js", "13.4.1", true));
});

test("platforms by presence only are never version-matched: TYPO3 major.minor, Moodle cookie, Magento, PrestaShop, Nuxt, Next.js markup", () => {
  for (const [b, h, p] of [['<meta name="generator" content="TYPO3 CMS 12.4">', {}, "TYPO3"], ["<html>", { "set-cookie": ["MoodleSession=abc; path=/"] }, "Moodle"],
    ['<link href="/static/version1700000000/frontend/Magento/luma/en_US/css/styles-m.css">', {}, "Magento"], ["<script>var prestashop = {};</script>", {}, "PrestaShop"],
    ["<script>window.__NUXT__={}</script>", {}, "Nuxt"], ['<script id="__NEXT_DATA__" type="application/json">{}</script>', {}, "Next.js"]]) {
    const r = run(b, h); assert.ok(r.some(([x, , st]) => x === p && !st), `${p} named, not version-matched`);
  }
});

test("libraries: file name, CDN path, banner; look-alike file names are not libraries", () => {
  const r = run('<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script><script src="/js/prototype-1.7.3.js"></script>' +
    '<script src="/vendor/ckeditor/4.16.0/ckeditor.js"></script><script>/*! @license DOMPurify 2.3.1 | (c) Cure53 */</script><script src="/js/knockout-3.5.1.js"></script>');
  for (const [p, v] of [["chart.js", "4.4.0"], ["prototype", "1.7.3"], ["ckeditor", "4.16.0"], ["DOMPurify", "2.3.1"], ["knockout", "3.5.1"]]) assert.ok(has(r, p, v, true), `${p} ${v}`);
  assert.deepEqual(run('<script src="/js/jquery.select2.js"></script><script src="/js/mychart.js"></script><p>chart, video, ember</p>'), []);
});
