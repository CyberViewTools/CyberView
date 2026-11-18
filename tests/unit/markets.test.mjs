// Unit tests for scripts/lib/markets.mjs: CSV parsing, merging, split guard, event-window maths.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseDailyCsv, mergeDays, splitDays, impact, change, chartSeries } from "../../scripts/lib/markets.mjs";

const days = (pairs) => pairs.map(([d, c]) => [d, c, 0]);
const seq = (start, n, f) => Array.from({ length: n }, (_, i) => {
  const d = new Date(Date.parse(start) + i * 864e5).toISOString().slice(0, 10); return [d, f(i)];
});

test("parse: Alpha Vantage CSV, newest-first in, oldest-first out, junk dropped", () => {
  const csv = "timestamp,open,high,low,close,volume\r\n2026-11-17,1,1,1,10.5,100\r\n2026-11-16,1,1,1,10,90\r\nbad,row\r\n2026-11-15,1,1,1,0,1\r\n";
  assert.deepEqual(parseDailyCsv(csv), [["2026-11-16", 10, 90], ["2026-11-17", 10.5, 100]]);
  assert.throws(() => parseDailyCsv('{"Note":"limit"}'), (e) => e.code === "bad_shape");
});

test("merge: new rows win, sorted, capped", () => {
  const m = mergeDays(days([["2026-01-02", 1], ["2026-01-01", 1]]), days([["2026-01-02", 2], ["2026-01-03", 3]]));
  assert.deepEqual(m.map((r) => r[1]), [1, 2, 3]);
});

test("split guard: a 4-for-1 split is detected, ordinary moves are not", () => {
  assert.deepEqual(splitDays(days([["a", 772], ["b", 194], ["c", 200], ["d", 170]])), ["b"]);
  assert.deepEqual(splitDays(days([["a", 100], ["b", 80], ["c", 120]])), []);
});

test("impact: day 0 is the first trading day on or after the date; abnormal = stock minus market", () => {
  const stock = days(seq("2026-01-01", 30, (i) => (i < 15 ? 100 : 90)));      // drops 10% on day index 15
  const bench = days(seq("2026-01-01", 30, (i) => (i < 15 ? 500 : 495)));     // market drops 1%
  const im = impact(stock, bench, stock[15][0]);
  assert.equal(im.day0, stock[15][0]);
  assert.equal(im.ret0, -0.1);
  assert.equal(im.mkt0, -0.01);
  assert.equal(im.abn0, -0.09);
  assert.equal(im.ret5, -0.1);
  assert.equal(im.series.find((r) => r[1] === 0)[2], 90);   // indexed to 100 at the base
  assert.equal(im.series.find((r) => r[1] === -1)[2], 100);
});

test("impact: weekend date rolls to the next trading day; split inside the window refuses to compute", () => {
  const stock = days([["2026-11-13", 100], ["2026-11-16", 102], ["2026-11-17", 101]]);
  const bench = days([["2026-11-13", 10], ["2026-11-16", 10], ["2026-11-17", 10]]);
  assert.equal(impact(stock, bench, "2026-11-15").day0, "2026-11-16");
  const split = days([["2026-06-30", 760], ["2026-07-01", 772], ["2026-07-02", 194], ["2026-07-03", 195]]);
  assert.deepEqual(impact(split, bench, "2026-07-03"), { split: true });
  assert.equal(impact(stock, bench, "2026-11-13"), null);   // no trading day before day 0
});

test("change and chart series ignore or bridge splits", () => {
  const d = days([["a", 772], ["b", 194], ["c", 200]]);
  assert.equal(change(d, 2), null);
  assert.equal(change(d, 1), 0.0309);
  const s = chartSeries(d, 3);
  assert.equal(s[0][1], 194, "pre-split close rescaled into post-split terms");
  assert.equal(s[2][1], 200);
});
