// scripts/lib/store.mjs — the data layout helpers (pure parts; no filesystem).
import { test } from "node:test";
import assert from "node:assert/strict";
import { straysFor } from "../../scripts/lib/store.mjs";

test("straysFor: same-id files under other months are strays; the kept path and other events are not", () => {
  const id = "furukawa-electric-power-systems-shipment-system-2026-11";
  const keep = `data/events/2026-10/${id}.json`;
  const paths = [
    `data/events/2026-10/${id}.json`,          // the kept (current-month) file
    `data/events/2026-11/${id}.json`,          // stale copy after a date correction -> stray
    `data/events/2026-11/some-other-event-2026-11.json`,   // a different event -> kept
    `data/events/2026-09/${id}.json`,          // an even older stray -> removed too
  ];
  assert.deepEqual(straysFor(id, keep, paths), [
    `data/events/2026-11/${id}.json`,
    `data/events/2026-09/${id}.json`,
  ]);
});

test("straysFor: no strays when the id lives only at the kept path", () => {
  const id = "solo-event-2026-11";
  const keep = `data/events/2026-11/${id}.json`;
  assert.deepEqual(straysFor(id, keep, [keep, `data/events/2026-11/another-2026-11.json`]), []);
});

test("straysFor: tolerates an empty or missing path list", () => {
  assert.deepEqual(straysFor("x-2026-11", "data/events/2026-11/x-2026-11.json", []), []);
  assert.deepEqual(straysFor("x-2026-11", "data/events/2026-11/x-2026-11.json", undefined), []);
});
