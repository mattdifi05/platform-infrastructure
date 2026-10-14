const SERIES = ["cpu", "memory", "swap", "networkRx", "networkTx", "diskRead", "diskWrite"];
export const HISTORY_LIMIT = 60;
export const HISTORY_WINDOW_MS = 120_000;
export const MAX_SAMPLE_GAP_MS = 6_000;

const number = (value) => typeof value === "number" && Number.isFinite(value) && value >= 0;
const reading = (metric, key) => metric?.available === true && number(metric[key]) ? metric[key] : null;

// This is a projection of the existing host response, never a second collector.
export function projectHostSample(metrics = {}, observedAt = Date.now()) {
  const capturedAt = Date.parse(metrics.capturedAt || "");
  const age = observedAt - capturedAt;
  const fresh = metrics.scope === "host" && metrics.source === "prometheus-node-exporter"
    && Number.isFinite(capturedAt) && age >= -5_000 && age <= 60_000;
  const value = fresh ? metrics : {};
  return {
    observedAt,
    capturedAt: fresh ? capturedAt : null,
    cpu: reading(value.cpu, "usedPercent"),
    memory: reading(value.memory, "usedPercent"),
    swap: reading(value.swap, "usedBytes"),
    networkRx: value.network?.available === true && number(value.network.totals?.rxBytesPerSecond) ? value.network.totals.rxBytesPerSecond : null,
    networkTx: value.network?.available === true && number(value.network.totals?.txBytesPerSecond) ? value.network.totals.txBytesPerSecond : null,
    diskRead: value.diskIo?.available === true && number(value.diskIo.totals?.readBytesPerSecond) ? value.diskIo.totals.readBytesPerSecond : null,
    diskWrite: value.diskIo?.available === true && number(value.diskIo.totals?.writeBytesPerSecond) ? value.diskIo.totals.writeBytesPerSecond : null,
  };
}

export function appendHostSample(history, sample) {
  if (!number(sample?.observedAt)) return history;
  const last = history.at(-1);
  if (last && sample.observedAt <= last.observedAt) return history;
  return [...history.filter((item) => sample.observedAt - item.observedAt <= HISTORY_WINDOW_MS), sample].slice(-HISTORY_LIMIT);
}

// Split on missing readings and on unobserved intervals (hidden tabs, slow requests).
// A zero is a real observation; a missing value never becomes a zero.
export function seriesSegments(history, key, maxGapMs = MAX_SAMPLE_GAP_MS) {
  const segments = [];
  let segment = null;
  let previousAt = null;
  for (const sample of history) {
    if (!number(sample[key])) { segment = null; previousAt = sample.observedAt; continue; }
    if (!segment || previousAt === null || sample.observedAt - previousAt > maxGapMs) {
      segment = [];
      segments.push(segment);
    }
    segment.push({ at: sample.observedAt, value: sample[key] });
    previousAt = sample.observedAt;
  }
  return segments;
}

export function chartGeometry(history, keys, { ceiling = null, width = 600, height = 160 } = {}) {
  const now = history.at(-1)?.observedAt ?? 0;
  const values = history.flatMap((sample) => keys.map((key) => sample[key]).filter(number));
  const maximum = number(ceiling) ? ceiling : Math.max(0, ...values);
  const point = ({ at, value }) => ({
    x: Math.max(0, Math.min(width, width * (1 - (now - at) / HISTORY_WINDOW_MS))),
    y: height - 20 - (maximum > 0 ? Math.min(1, value / maximum) * (height - 40) : 0),
  });
  const coord = (value) => value.toFixed(2);
  return {
    maximum,
    hasData: values.length > 0,
    series: keys.map((key) => {
      const segments = seriesSegments(history, key).map((segment) => segment.map(point));
      const line = segments.map((segment) => segment.map((p, i) => `${i ? "L" : "M"}${coord(p.x)},${coord(p.y)}`).join(" ")).join(" ");
      const area = segments.filter((segment) => segment.length > 1).map((segment) => `M${coord(segment[0].x)},${height - 20} ${segment.map((p) => `L${coord(p.x)},${coord(p.y)}`).join(" ")} L${coord(segment.at(-1).x)},${height - 20} Z`).join(" ");
      const latest = history.at(-1);
      return { key, line, area, point: latest && number(latest[key]) ? point({ at: latest.observedAt, value: latest[key] }) : null };
    }),
  };
}

const amount = (value) => number(value) ? new Intl.NumberFormat("it-IT", { maximumFractionDigits: 1 }).format(value) : "—";
function bytes(value) {
  if (!number(value)) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${amount(value)} ${units[unit]}`;
}
const speed = (value) => number(value) ? `${bytes(value)}/s` : "—";

const panels = new WeakMap();

export function mountOverview(root) {
  if (panels.has(root)) return panels.get(root);
  const charts = [...root.querySelectorAll("[data-overview-chart]")];
  const set = (selector, text) => { const node = root.querySelector(selector); if (node) node.textContent = text; };
  const panel = { history: [], lastObservedAt: null, update };
  panels.set(root, panel);

  function update(eventSample) {
    if (!eventSample || !number(eventSample.observedAt) || eventSample.observedAt === panel.lastObservedAt) return;
    const metrics = eventSample.metrics || {};
    const sample = projectHostSample(metrics, eventSample.observedAt);
    const next = appendHostSample(panel.history, sample);
    if (next === panel.history) return;
    panel.lastObservedAt = eventSample.observedAt;
    panel.history = next;
    const available = SERIES.some((key) => number(sample[key]));
    const state = root.querySelector("[data-overview-state]");
    if (state) { state.textContent = available ? "Metriche live" : "Dati non disponibili"; state.dataset.state = available ? "available" : "unavailable"; }
    const fresh = sample.capturedAt !== null;
    const inode = fresh ? metrics.inodes : null;
    const swap = fresh ? metrics.swap : null;
    set('[data-overview-value="inodes"]', number(reading(inode, "usedPercent")) ? `${amount(inode.usedPercent)}%` : "—");
    set('[data-overview-detail="inodes"]', number(reading(inode, "used")) && number(reading(inode, "total")) ? `${amount(inode.used)} / ${amount(inode.total)}` : "Inode non disponibili");
    const inodeMeter = root.querySelector('[data-overview-meter="inodes"]');
    if (inodeMeter) { inodeMeter.hidden = !number(reading(inode, "usedPercent")); inodeMeter.value = Math.min(100, reading(inode, "usedPercent") ?? 0); }
    set('[data-overview-value="swap"]', bytes(sample.swap));
    set('[data-overview-detail="swap"]', swap?.available === true && swap.totalBytes === 0 && swap.usedBytes === 0 ? "Nessuna swap configurata" : number(reading(swap, "totalBytes")) ? `su ${bytes(swap.totalBytes)}` : "Memoria su disco");
    set('[data-overview-value="diskRead"]', speed(sample.diskRead));
    set('[data-overview-value="diskWrite"]', speed(sample.diskWrite));

    for (const chart of charts) {
      const id = chart.dataset.overviewChart;
      const keys = [...chart.querySelectorAll("[data-overview-line]")].map((node) => node.dataset.overviewLine);
      const percent = chart.dataset.overviewUnit === "%";
      const geometry = chartGeometry(panel.history, keys, { ceiling: percent ? 100 : null });
      const scale = chart.querySelector("[data-overview-ceiling]");
      if (scale) scale.textContent = geometry.hasData ? percent ? "100%" : chart.dataset.overviewUnit === "bytes/s" ? speed(geometry.maximum) : bytes(geometry.maximum) : "—";
      const empty = chart.querySelector("[data-overview-chart-empty]");
      if (empty) { empty.hidden = geometry.hasData; empty.textContent = "Dati non disponibili"; }
      const start = chart.querySelector("[data-overview-chart-start]");
      const elapsed = Math.max(0, sample.observedAt - panel.history[0].observedAt);
      if (start) start.textContent = `Ultimi ${Math.floor(elapsed / 1000)} s raccolti`;
      const svg = chart.querySelector("svg");
      if (svg) svg.setAttribute("aria-label", `${id === "diskIo" ? "Attività disco" : id === "network" ? "Connessione" : id === "memory" ? "RAM" : id.toUpperCase()}: ${geometry.hasData ? "campioni raccolti da apertura pagina, interruzioni per dati mancanti" : "dati non disponibili"}`);
      for (const series of geometry.series) {
        chart.querySelector(`[data-overview-line="${series.key}"]`)?.setAttribute("d", series.line);
        chart.querySelector(`[data-overview-area="${series.key}"]`)?.setAttribute("d", series.area);
        const marker = chart.querySelector(`[data-overview-point="${series.key}"]`);
        if (marker) {
          marker.toggleAttribute("hidden", !series.point);
          if (series.point) { marker.setAttribute("cx", series.point.x); marker.setAttribute("cy", series.point.y); }
        }
      }
    }
  }
  if (root.ccHostMetricsSample) update(root.ccHostMetricsSample);
  return panel;
}

if (typeof document !== "undefined") {
  const scan = () => document.querySelectorAll("[data-overview-page] [data-host-metrics]").forEach(mountOverview);
  document.addEventListener("cc-host-metrics-sample", (event) => {
    const root = event.target;
    if (root?.matches?.("[data-host-metrics]") && root.closest("[data-overview-page]")) mountOverview(root).update(event.detail);
  });
  const start = () => {
    scan();
    new MutationObserver((records) => { if (records.some((record) => record.addedNodes.length)) scan(); }).observe(document.body, { childList: true, subtree: true });
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
}
