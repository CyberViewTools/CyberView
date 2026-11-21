// GDELT allows one request every 5 seconds per address. osint.mjs and grid-news.mjs both query it, often in the same
// research cycle, and every one of their first requests got HTTP 429 (2026-11-21). This gate spaces every GDELT request
// on this machine, across processes, by GAP_MS, using a small time file in the temp folder. No AI model.
import { readFileSync, writeFileSync, openSync, closeSync, unlinkSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const GAP_MS = 6000;
const FILE = join(tmpdir(), "cyberview-gdelt-last"), LOCK = FILE + ".lock";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Pure: how long to wait before the next request, given the last request time and now. */
export function waitFor(last, now, gap = GAP_MS) { return Number.isFinite(last) ? Math.max(0, last + gap - now) : 0; }

async function lock() {
  for (let i = 0; i < 200; i++) {
    try { closeSync(openSync(LOCK, "wx")); return true; } catch {}
    try { if (Date.now() - statSync(LOCK).mtimeMs > 30000) unlinkSync(LOCK); } catch {}   // a lock left by a dead process
    await sleep(100);
  }
  return false;
}

/** Wait for this machine's next GDELT slot and claim it. */
export async function gdeltSlot(gap = GAP_MS) {
  const held = await lock();
  try {
    let last = NaN; try { last = Number(readFileSync(FILE, "utf8")); } catch {}
    const w = waitFor(last, Date.now(), gap); if (w) await sleep(w);
    writeFileSync(FILE, String(Date.now()));
  } finally { if (held) try { unlinkSync(LOCK); } catch {} }
}
