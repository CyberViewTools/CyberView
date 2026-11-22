# Handoff: scan-cms-html — CMS and JS versions from the already-fetched root page

Run scanner-build-2026-11-22, plan_id w1-6f3a. Module `scanner/lib/fp-cms.mjs`, hook: one import and one line in
`fromHttp()` (`scanner/lib/fingerprint.mjs`). Tests `tests/unit/scanner-cms.test.mjs`, fixtures `tests/fixtures/scanner/cms/`.

## Discovery → Design
- **Need:** the scanner already holds the root page's headers and body (up to 64 KB, in memory) but read only Server,
  X-Powered-By, X-OWA-Version and one generator tag. Sites that state a CMS, plugin or JavaScript library version in their own
  markup were reported without it.
- **Constraints:** no new request of any kind (no script fetch, no plugin readme, no /wp-content tree); no wordlist; no body,
  cookie value or full URL stored; a version without a reliable source stays out of the headline counts.
- **Detection catalog rows built (BUILD-NOW):** `wordpress-core`, `drupal`, `drupal-core`, `joomla`, `craft-cms-craft-cms`,
  `dotnetnuke-dnn-dotnetnuke-dnn`, `kentico-kentico-xperience`, `kentico-xperience-cms`, `october-cms-october-cms`,
  `progress-asp-net-ajax-and-sitefinity`, `sap-commerce-cloud`, `thinkphp-thinkphp`,
  `webpros-cpanel-and-whm-and-wp2-wordpress-squared`, `xwiki-platform`, `javascript-libraries-in-the-root-page` (15). Each
  signal in `PRODUCTS` is the one its row states; `CATALOG_ROWS` exports the list.
  - `joomla`: the existing generator record already covers the row's signal; nothing added (no invented Joomla paths).
  - `drupal`: the existing major-only generator record is kept; `drupal-core` adds X-Generator (a dotted version is
    compared, a major-only one is not), X-Drupal-Cache, a `drupal.js` script, `Drupal.settings`, `/sites/default|all/`.
  - `kentico-*`: both rows share one record ("Kentico Xperience (Kentico CMS)", product words match both CPE names). The
    generator's build number is shown in the inventory but not compared (its relation to NVD's ranges is not confirmed).
  - `progress-asp-net-ajax-and-sitefinity`: Sitefinity only; Telerik UI for ASP.NET AJAX is not inferred from it, and
    Telerik's own `WebResource.axd` is not treated as Sitefinity (as the row requires).
  - `dotnetnuke`: `dnn.apiversion` was not used for a version (its on-page form is not documented in the row).
- **Task scope beyond the catalog rows (from the slice brief):** WordPress plugins and themes the page names in its own
  `/wp-content/plugins|themes/<slug>/` asset URLs (also JSON-escaped), with `?ver=`; JavaScript libraries from script file
  names, CDN path segments and banner comments. Catalog row `wordpress-plugin-or-theme-versions` (readme files) is the later
  rail half and is NOT built here.

## Design → Implementation
- **Data model:** the fromHttp() record shape (`svc()`), source "root page body and headers", evidence a short token
  (file base name, `cookie named X (value not read)`, `wp-content/plugins/<slug> ?ver=…`, a clipped header or markup token).
  Hosts and query strings of script URLs are dropped (only `ver=` is read). Caps: 30 records, 20 plugins, 5 themes,
  200 script tags, 5 generator tags.
- **Reliability:** `stated` (file name, CDN path, banner comment, versioned generator, `cpsrvd/x.y`, X-Generator dotted,
  XWiki footer version, `wordpress.org/?v=`) is compared with ranges. `query` (`?ver=`, wp-emoji `ver=`, Kentico build)
  is shown in the inventory (`shown_version`) with an empty compared version and `guessed: true`, so any match is
  "check" / low confidence and outside the headline counts. Presence-only markers are guessed with no version.
- **Name safety:** plugins carry no vendor and never compare a version, so a slug that contains another product's word
  (e.g. `wordpress-seo`, `redis-cache`) can at worst produce a low-confidence "check". jQuery UI is product `jQueryUI` so it
  never matches jQuery core ranges; `jquery-migrate` and `jquery.<plugin>.js` are not read as jQuery.
- **Safety-model check:** zero extra bytes (the test drives `probePort` against a loopback server and asserts it saw exactly
  `[{ GET, "/" }]`); no wordlist; no body stored; cookie values never read; security-check green; `CAPS` untouched.
- **Fixtures:** script tags in the fixture pages are written `<@js …></@js>` and restored in the test, so the scanner
  fixture folder stays clean for the "no attack strings" guard in `tests/unit/scanner.test.mjs`.

## Implementation → Review
- One commit on this worktree's branch, not pushed. `npm run unit` 738/738, security-check passed.
- **Follow-ons (LATER rows, not built):** path rail (`scan-cms-paths`): `adobe-experience-manager`,
  `adobe-magento-commerce`, `craft-cms`, `dotcms-dotcms`, `drupal-changelog-or-generator-upgrade`, `fuel-cms-fuel-cms`,
  `ghost`, `liferay-portal`, `mediawiki`, `phpbb`, `prestashop`, `sitecore-experience-platform`, `sitecore-xp`, `strapi`,
  `typo3-cms`, `umbraco`, `vbulletin`, `wordpress-file-manager-plugin`, `wordpress-plugin-or-theme-versions`,
  `wordpress-snap-creek-duplicator-plugin`, `wordpress-social-warfare-plugin`, `xwiki`; needs research:
  `artifex-ghostscript`, `microsoft-power-pages`, `thinkphp-nonecms`.
- **Open questions:** whether WordPress's bundled `wp-includes/js/jquery/jquery.min.js?ver=` (registered with jQuery's real
  version) may be promoted from inventory-only to compared; whether cpsrvd's `11.x.y.z` maps to NVD's cPanel ranges as-is.

## Doc text to add

**docs/scanner.md** (fingerprints section):

> **CMS and JavaScript libraries from the root page.** From the one root-page response it already has (no extra request),
> the scanner reads CMS and product markers the page states about itself: WordPress (generator, wordpress.org `?v=`,
> wp-emoji `ver=`, asset paths, api.w.org Link, X-Pingback), Drupal (generator, X-Generator, X-Drupal-Cache, settings
> markup), Joomla (generator), Craft CMS, DotNetNuke, Kentico, October CMS, Sitefinity, SAP Commerce Cloud, ThinkPHP,
> cPanel & WHM and XWiki; WordPress plugins and themes named in the page's own asset URLs; and jQuery, jQuery UI,
> Bootstrap, AngularJS, Lodash, Moment.js, Vue.js, Handlebars and Underscore from script file names, CDN paths and banner
> comments. A version in a file name, CDN path, banner, generator or Server header is compared with the affected ranges.
> A `?ver=` cache-buster (WordPress may put its own version there) is listed in the inventory only and can at most give a
> low-confidence "check the version". Cookie values, page bodies and script URLs are never stored; scripts and plugin
> files are never fetched.

**scanner/README.md** ("deliberately does not do" list, add):

> - fetch a page's scripts, stylesheets, plugin readmes or `/wp-content` files, or try plugin or theme names from a list:
>   CMS and library versions come only from what the root page itself names.
