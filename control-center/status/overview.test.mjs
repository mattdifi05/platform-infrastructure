import test from "node:test";
import assert from "node:assert/strict";
import { renderOverview } from "./overview.mjs";
import { projectHostSample, appendHostSample, seriesSegments, chartGeometry, displayHistory, createOverviewFrameLoop, HISTORY_LIMIT, SAMPLE_TRANSITION_MS } from "../styles/overview.js";

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

test("history is bounded to 60 observations and two minutes without prefilled past", () => {
  let history = [];
  assert.equal(appendHostSample(history, { observedAt: now, cpu: 5 }).length, 1);
  for (let i = 0; i < 100; i++) history = appendHostSample(history, { observedAt: now + i * 2000, cpu: i });
  assert.equal(history.length, HISTORY_LIMIT);
  assert.equal(history[0].cpu, 40);
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

test("visual easing reaches the real target, preserves recorded history and never bridges missing values", () => {
  const history = [{ observedAt: now, cpu: 10, memory: null }, { observedAt: now + 2000, cpu: 30, memory: 17, networkRx: null }];
  const original = structuredClone(history);
  const transition = { startedAt: now + 2000, from: { cpu: 10, memory: null, networkRx: 1024 } };
  assert.equal(displayHistory(history, transition, transition.startedAt).at(-1).cpu, 10);
  const middle = displayHistory(history, transition, transition.startedAt + SAMPLE_TRANSITION_MS / 2);
  assert.equal(middle.at(-1).cpu, 20);
  assert.equal(middle.at(-1).memory, 17);
  assert.equal(middle.at(-1).networkRx, null);
  assert.equal(displayHistory(history, transition, transition.startedAt + SAMPLE_TRANSITION_MS), history);
  assert.deepEqual(history, original);
  const before = chartGeometry(history, ["cpu"], { ceiling: 100, renderTime: now + 2000 });
  const after = chartGeometry(history, ["cpu"], { ceiling: 100, renderTime: now + 3000 });
  assert.equal(before.series[0].point.x - after.series[0].point.x, 5);
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
