# Grid source files

Each `*.mjs` here adds grid sources to `scripts/grid.mjs` without editing it (one file per region group, so builders can
work in parallel). `lib-*.mjs` files hold shared parsers (for example one vendor map platform used by many utilities)
and are not loaded as sources. Shape (see the comment above PLUGIN_ERRORS in scripts/grid.mjs):

```js
export default {
  sources: { "toronto-hydro": { name: "Toronto Hydro", country: "CA", url: "https://...", page: "https://...",
             hosts: ["www.torontohydro.com"], terms_url: "https://...", terms_ok: "silent", customers_served: 790000 } },
  regions: { "toronto-hydro|Toronto": { name: "Toronto", lat: 43.7, lng: -79.4 } },
  adapters: { "toronto-hydro": async (h) => parseTorontoHydro(await h.get(h.SOURCES["toronto-hydro"].url)) },
};
```
Every adapter has a pure parser with a unit test on a real saved response (tests/fixtures/grid/<key>.*). Only sources a
scout recorded as `connect` (swarm/grid-sources-*/out) are added: allowed or silent terms, robots.txt not disallowing,
not blocking automated readers. Never work around a block.
