import test from "node:test";
import assert from "node:assert/strict";
import { renderOverview } from "./overview.mjs";
import { projectHostSample, appendHostSample, seriesSegments, chartGeometry, visibleSeriesSegments, createOverviewFrameLoop, HISTORY_LIMIT, PRESENTATION_DELAY_MS } from "../styles/overview.js";

const now = Date.parse("2026-10-15T12:00:00Z");
const actual = (overrides = {}) => ({ scope: "host", source: "prometheus-node-exporter", capturedAt: new Date(now).toISOString(), cpu: { available: true, usedPercent: 12.4 }, memory: { available: true, usedPercent: 17.1 }, swap: { available: true, usedBytes: 0, totalBytes: 0 }, network: { available: true, totals: { rxBytesPerSecond: 1024, txBytesPerSecond: null } }, diskIo: { available: true, totals: { readBytesPerSecond: 0, writeBytesPerSecond: 4096 } }, ...overrides });

test("projects only available actual metrics, preserving observed zero and missing totals", () => {
  const sample = projectHostSample(actual(), now);
  assert.equal(sample.cpu, 12.4);
  assert.equal(sample.memory, 17.1);
  assert.equal(sample.swap, 0);
  assert.equal(sample.networkRx, 1024);
  assert.equal(sample.networkTx, null);
  assert.equal(sample.diskRead, 0);
  assert.equal(sample.diskWrite, 4096);
  assert.equal(projectHostSample(actual({ cpu: { available: false, usedPercent: 42 } }), now).cpu, null);
  assert.equal(projectHostSample(actual({ memory: { available: true, usedPercent: NaN } }), now).memory, null);
});

test("stale, unknown-source and failed responses create gaps instead of fabricated readings", () => {
  for (const value of [{}, actual({ source: "container" }), actual({ capturedAt: new Date(now - 60_001).toISOString() }), actual({ capturedAt: new Date(now + 5_001).toISOString() })]) {
    const sample = projectHostSample(value, now);
    for (const key of ["cpu", "memory", "swap", "networkRx", "networkTx", "diskRead", "diskWrite"]) assert.equal(sample[key], null);
  }
});

test("history is bounded with enough measured buffer for both presentation boundaries", () => {
  let history = [];
  assert.equal(appendHostSample(history, { observedAt: now, cpu: 5 }).length, 1);
  for (let i = 0; i < 100; i++) history = appendHostSample(history, { observedAt: now + i * 2000, cpu: i });
  assert.equal(history.length, HISTORY_LIMIT);
  assert.equal(history[0].cpu, 36);
  assert.equal(appendHostSample(history, history.at(-1)), history);
  history = appendHostSample(history, { observedAt: now + 500_000, cpu: 0 });
  assert.equal(history.length, 1);
  assert.equal(history[0].cpu, 0);
});

test("SVG paths break on unavailable data and unobserved time while real zeros remain connected", () => {
  const history = [{ observedAt: now, cpu: 0 }, { observedAt: now + 2000, cpu: 4 }, { observedAt: now + 4000, cpu: null }, { observedAt: now + 6000, cpu: 5 }, { observedAt: now + 20_000, cpu: 6 }];
  assert.deepEqual(seriesSegments(history, "cpu").map((segment) => segment.map((point) => point.value)), [[0, 4], [5], [6]]);
  const geometry = chartGeometry(history, ["cpu"], { ceiling: 100 });
  assert.equal(geometry.series[0].line.match(/M/g).length, 3);
  assert.equal(geometry.series[0].area.match(/Z/g).length, 1);
  assert.equal(geometry.series[0].point.x, 600);
  const zero = chartGeometry([{ observedAt: now, swap: 0 }], ["swap"]);
  assert.equal(zero.maximum, 0);
  assert.equal(zero.hasData, true);
  assert.ok(Number.isFinite(zero.series[0].point.y));
  assert.equal(chartGeometry([{ observedAt: now, swap: null }], ["swap"]).hasData, false);
});

test("overview retains graphs, capacity and PSI while removing requested detail blocks and controls", () => {
  const html = renderOverview();
  for (const key of ["cpu", "memory", "disk", "network"]) assert.ok(html.includes(`data-host-metric="${key}"`));
  assert.ok(!html.includes("data-host-detail="));
  assert.ok(!html.includes("Memoria e filesystem"));
  assert.ok(!html.includes("<h3>Sistema</h3>"));
  for (const key of ["cpuWaitingPercent", "memoryWaitingPercent", "memoryStalledPercent", "ioWaitingPercent", "ioStalledPercent"]) assert.ok(html.includes(`data-host-pressure="${key}"`));
  for (const key of ["network", "diskIo"]) assert.ok(html.includes(`data-overview-chart="${key}"`));
  for (const removed of ["data-host-table", "data-host-metrics-refresh", "data-host-metrics-status", "data-overview-state", "Il server, in tempo reale", "node_exporter"]) assert.ok(!html.includes(removed));
  assert.ok(html.includes("data-overview-page"));
  assert.ok(!html.includes("data-global-backup-control"));
});

test("both boundaries interpolate real neighbors without changing recorded measurements", () => {
  const cursor = now + 121_000;
  const history = [{ observedAt: now, cpu: 10 }, { observedAt: now + 2000, cpu: 30 }, { observedAt: now + 120_000, cpu: 40 }, { observedAt: now + 122_000, cpu: 80 }];
  const original = structuredClone(history);
  const segments = visibleSeriesSegments(history, "cpu", cursor);
  assert.equal(segments[0][0].at, cursor - 120_000);
  assert.equal(segments[0][0].value, 20);
  assert.equal(segments.at(-1).at(-1).at, cursor);
  assert.equal(segments.at(-1).at(-1).value, 60);
  const geometry = chartGeometry(history, ["cpu"], { ceiling: 100, renderTime: cursor });
  assert.ok(geometry.series[0].line.startsWith("M0.00,116.00"));
  assert.equal(geometry.series[0].point.x, 600);
  assert.equal(geometry.series[0].point.y, 68);
  assert.deepEqual(history, original);
});

test("poll arrivals and retention eviction cannot move either endpoint at the same display cursor", () => {
  let history = [];
  for (let i = 0; i < 64; i++) history = appendHostSample(history, { observedAt: now + i * 2000, cpu: i, networkRx: i * 100 });
  const cursor = now + 128_000 - PRESENTATION_DELAY_MS;
  const before = chartGeometry(history, ["cpu", "networkRx"], { renderTime: cursor });
  const next = appendHostSample(history, { observedAt: now + 128_000, cpu: 90, networkRx: 999999 });
  assert.equal(next.length, HISTORY_LIMIT);
  assert.equal(next[0].observedAt, now + 2000);
  const after = chartGeometry(next, ["cpu", "networkRx"], { renderTime: cursor });
  assert.deepEqual(after, before, "future sample and out-of-view oldest eviction must not alter visible geometry or autoscale");
  const moving = chartGeometry(next, ["cpu"], { ceiling: 100, renderTime: cursor + 100 });
  const previous = chartGeometry(next, ["cpu"], { ceiling: 100, renderTime: cursor });
  assert.equal(moving.series[0].point.x, 600);
  assert.ok(Math.abs(moving.series[0].point.y - previous.series[0].point.y) < 1);
  assert.ok(moving.series[0].line.startsWith("M0.00,"));
});

test("clipping does not interpolate across missing values or unobserved intervals", () => {
  const missing = [{observedAt:now,cpu:10},{observedAt:now+2000,cpu:null},{observedAt:now+4000,cpu:90}];
  const segments = visibleSeriesSegments(missing, "cpu", now+3000);
  assert.deepEqual(segments, [[{at:now,value:10}]]);
  assert.equal(chartGeometry(missing,["cpu"],{renderTime:now+3000}).series[0].point.x,585);
  const unobserved = [{observedAt:now,cpu:10},{observedAt:now+20_000,cpu:90}];
  assert.deepEqual(visibleSeriesSegments(unobserved,"cpu",now+10_000),[[{at:now,value:10}]]);
});

test("all charts share one frame loop which cancels while hidden or disconnected", () => {
  let pending = new Map(), serial = 0, visible = true, connected = true, draws = [];
  const loop = createOverviewFrameLoop({ requestFrame: (callback) => { pending.set(++serial, callback); return serial; }, cancelFrame: (id) => pending.delete(id), isVisible: () => visible, now: () => now });
  const panel = () => ({ connected: () => connected, visible: () => true, draw: (time) => draws.push(time) });
  loop.add(panel()); loop.add(panel());
  assert.equal(pending.size, 1);
  const callback = [...pending.values()][0]; pending.clear(); callback();
  assert.deepEqual(draws, [now, now]);
  assert.equal(pending.size, 1);
  visible = false; loop.refresh();
  assert.equal(pending.size, 0);
  visible = true; loop.refresh();
  assert.equal(pending.size, 1);
  connected = false; loop.refresh();
  assert.equal(pending.size, 0);
});
