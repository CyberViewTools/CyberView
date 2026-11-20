// Pure merges for files several jobs write at once (used by git-sync.mjs and lib/conflicts.mjs). No AI model.
/** Pure: three-way merge of two JSON objects by key. base = common ancestor, up = what is on main, mine = this commit. */
export function mergeJson(base, up, mine, opts = {}) {
  const out = { ...up };
  for (const k of new Set([...Object.keys(base || {}), ...Object.keys(mine || {})])) {
    const b = JSON.stringify((base || {})[k]), m = JSON.stringify((mine || {})[k]);
    if (b === m) continue;                                                         // this commit did not touch the key: main's value stands
    if (!(k in (mine || {}))) { if (!opts.keepKeys) delete out[k]; continue; }   // keepKeys: a key this commit lost is kept (status.json never deletes keys)
    const u = (up || {})[k];
    out[k] = u && mine[k] && typeof u === "object" && typeof mine[k] === "object" && !Array.isArray(u) && !Array.isArray(mine[k]) ? mergeJson((base || {})[k], u, mine[k], opts) : mine[k];
  }
  return out;
}
/** Pure: merge two JSON-lines files with a de-duplicating rule (dedupe: array of objects -> array of objects), for line
 *  files where two writers can each write a different line for the same thing (grid series slots, closed incidents).
 *  Lines that do not parse are kept as a plain union. */
export function mergeKeyed(up, mine, dedupe) {
  const objs = [], raw = [];
  for (const l of `${up || ""}\n${mine || ""}`.split("\n")) { if (!l.trim()) continue; try { objs.push(JSON.parse(l)); } catch { raw.push(l); } }
  const out = dedupe(objs).map((x) => JSON.stringify(x));
  return mergeLines(out.join("\n"), raw.join("\n"));
}
/** Pure: union of two line files, main's order first, then lines only this commit has. */
export function mergeLines(up, mine) {
  const seen = new Set(), out = [];
  for (const l of `${up || ""}\n${mine || ""}`.split("\n")) if (l.trim() && !seen.has(l)) { seen.add(l); out.push(l); }
  return out.join("\n") + "\n";
}

