# Handoff: scan-cms-html — CMS and JS from the root page

## Discovery → Design
- **Need:** version inventory from the page the scan already fetched.
- **Constraints:** no extra request, no plugin wordlist. A bare generator stays a guess.
- **Recommendation:** build.

## Design → Implementation
- WordPress plugins and themes disclosed with the `ver` query the CMS itself appends (WordPress developer docs for `wp_enqueue_script`).
- jQuery and a few other libraries from the release filename (`jquery-3.4.1.js`, jquery.com).
- Craft CMS, October CMS, DotNetNuke and Kentico from the generator or `X-Powered-By` the catalog's sourced rows name. Needs-research rows are not matched.

## Implementation → Review
- This branch. Frozen version files are `scan-cms-paths`, not this item.
