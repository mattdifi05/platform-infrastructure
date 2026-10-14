// Project/container filesystem fallbacks are intentionally excluded from this
// host-only projection of the existing Prometheus node-exporter sampler.
const number = value => typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
export function hostMetricsPayload(snapshot) {
  const sampled = snapshot?.available === true && Number.isFinite(Date.parse(snapshot.capturedAt || ""));
  const cpu = snapshot?.cpu || {}, memory = snapshot?.memory || {}, disk = snapshot?.disk || {};
  const cpuPercent = sampled && cpu.available ? number(cpu.usedPercent) : null;
  const cpuCores = sampled && cpu.available ? number(cpu.cores) : null;
  const memoryAvailable = sampled && memory.available === true && number(memory.totalBytes) > 0 && number(memory.usedBytes) !== null;
  const diskAvailable = sampled && disk.available === true && number(disk.totalBytes) > 0 && number(disk.usedBytes) !== null;
  return {
    scope: "host", source: "prometheus-node-exporter", capturedAt: sampled ? snapshot.capturedAt : null,
    cpu: { available: cpuPercent !== null, usedPercent: cpuPercent, cores: cpuCores, window: "2m" },
    memory: { available: memoryAvailable, usedBytes: memoryAvailable ? memory.usedBytes : null, totalBytes: memoryAvailable ? memory.totalBytes : null, usedPercent: memoryAvailable ? number(memory.usedPercent) : null },
    disk: { available: diskAvailable, usedBytes: diskAvailable ? disk.usedBytes : null, totalBytes: diskAvailable ? disk.totalBytes : null, usedPercent: diskAvailable ? number(disk.usedPercent) : null },
  };
}

const physicalInterfaces = /^(?:eth[0-9]+|en[a-zA-Z0-9]+|bond[0-9]+)$/;
const physicalDisks = /^(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)$/;
const networkFields = { rxBytes: "receive_bytes", txBytes: "transmit_bytes", rxErrors: "receive_errs", txErrors: "transmit_errs", rxDrops: "receive_drop", txDrops: "transmit_drop" };
const diskFields = { readBytesPerSecond: "read_bytes", writeBytesPerSecond: "written_bytes", readsPerSecond: "reads_completed", writesPerSecond: "writes_completed", busyPercent: "io_time_seconds" };
const pressureFields = { cpuWaitingPercent: "cpu_waiting", memoryWaitingPercent: "memory_waiting", memoryStalledPercent: "memory_stalled", ioWaitingPercent: "io_waiting", ioStalledPercent: "io_stalled" };
const gauges = ["node_load1", "node_load5", "node_load15", "node_memory_SwapTotal_bytes", "node_memory_SwapFree_bytes", "node_boot_time_seconds", "node_time_seconds", "node_procs_running", "node_procs_blocked", "node_filefd_allocated", "node_filefd_maximum", "node_filesystem_files", "node_filesystem_files_free"];
const queryRate = (metric, extra = "") => `rate(${metric}{job="node-exporter"${extra}}[2m])`;
export const HOST_METRIC_QUERIES = Object.freeze({
  up: 'up{job="node-exporter"}',
  sampleTime: 'max(timestamp({job="node-exporter",__name__=~"node_cpu_seconds_total|node_memory_MemTotal_bytes"}))',
  gauges: `{job="node-exporter",__name__=~"${gauges.join("|")}"}`,
  network: '{job="node-exporter",__name__=~"node_network_(receive_bytes|transmit_bytes|receive_errs|transmit_errs|receive_drop|transmit_drop)_total",device=~"eth[0-9]+|en[a-zA-Z0-9]+|bond[0-9]+"}',
  rxBytesPerSecond: queryRate("node_network_receive_bytes_total", ',device=~"eth[0-9]+|en[a-zA-Z0-9]+|bond[0-9]+"'),
  txBytesPerSecond: queryRate("node_network_transmit_bytes_total", ',device=~"eth[0-9]+|en[a-zA-Z0-9]+|bond[0-9]+"'),
  ...Object.fromEntries(Object.entries(diskFields).map(([key, metric]) => [key, queryRate(`node_disk_${metric}_total`, ',device=~"sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+"')])),
  ...Object.fromEntries(Object.entries(pressureFields).map(([key, metric]) => [key, queryRate(`node_pressure_${metric}_seconds_total`)])),
});

function rowValue(row) {
  const raw = row?.value?.[1];
  if (typeof raw !== "string" && typeof raw !== "number" || raw === "") return null;
  const value = Number(raw);
  return number(value);
}
function onlyValue(rows) { return rows?.length === 1 ? rowValue(rows[0]) : null; }
function sumMeasured(rows, key) {
  // Missing one interface/device must not become a misleading partial total.
  return rows.length && rows.every(row => number(row[key]) !== null) ? rows.reduce((sum, row) => sum + row[key], 0) : null;
}
function ratio(used, total) { return number(used) !== null && number(total) !== null && total > 0 ? used / total * 100 : null; }
function groupDevices(results, fields, predicate) {
  const devices = new Map();
  for (const field of fields) for (const row of results[field] || []) {
    const name = row?.metric?.device;
    if (typeof name !== "string" || !predicate.test(name)) continue;
    if (!devices.has(name)) devices.set(name, { name, ...Object.fromEntries(fields.map(key => [key, null])) });
    devices.get(name)[field] = rowValue(row);
  }
  return [...devices.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function extendedPayload(snapshot, results, now) {
  const up = onlyValue(results.up);
  const sampleTime = onlyValue(results.sampleTime);
  const ageSeconds = sampleTime === null ? null : (now - sampleTime * 1000) / 1000;
  // One explicitly identified exporter and its actual scrape timestamp are
  // required. Query evaluation time alone is not evidence of a fresh sample.
  const fresh = up === 1 && ageSeconds !== null && ageSeconds >= -5 && ageSeconds <= 60;
  const freshness = { available: fresh, exporterUp: up === null ? null : up === 1, sampledAt: sampleTime === null ? null : new Date(sampleTime * 1000).toISOString(), ageSeconds, stale: !fresh };
  const base = hostMetricsPayload(fresh ? snapshot : null);
  base.capturedAt = fresh ? freshness.sampledAt : null;
  const rows = fresh ? results.gauges || [] : [];
  const gauge = name => onlyValue(rows.filter(row => row?.metric?.__name__ === name));
  const validResults = fresh ? results : {};
  const networkResults = { rxBytesPerSecond: validResults.rxBytesPerSecond, txBytesPerSecond: validResults.txBytesPerSecond };
  for (const [field, metric] of Object.entries(networkFields)) networkResults[field] = (validResults.network || []).filter(row => row?.metric?.__name__ === `node_network_${metric}_total`);
  const netKeys = ["rxBytesPerSecond", "txBytesPerSecond", ...Object.keys(networkFields)];
  const interfaces = groupDevices(networkResults, netKeys, physicalInterfaces);
  const network = { available: interfaces.some(row => netKeys.some(key => row[key] !== null)), window: "2m", interfaces, totals: Object.fromEntries(netKeys.map(key => [key, sumMeasured(interfaces, key)])) };
  const diskKeys = Object.keys(diskFields);
  const devices = groupDevices(validResults, diskKeys, physicalDisks);
  for (const device of devices) if (device.busyPercent !== null) device.busyPercent *= 100;
  const diskIo = { available: devices.some(row => diskKeys.some(key => row[key] !== null)), window: "2m", devices, totals: Object.fromEntries(diskKeys.filter(key => key !== "busyPercent").map(key => [key, sumMeasured(devices, key)])) };
  const loadValues = { one: gauge("node_load1"), five: gauge("node_load5"), fifteen: gauge("node_load15") };
  const load = { available: Object.values(loadValues).some(value => value !== null), ...loadValues };
  const totalSwap = gauge("node_memory_SwapTotal_bytes"), freeSwap = gauge("node_memory_SwapFree_bytes");
  const validSwap = totalSwap !== null && freeSwap !== null && freeSwap <= totalSwap;
  const swapUsed = validSwap ? totalSwap - freeSwap : null;
  const swap = { available: validSwap, totalBytes: validSwap ? totalSwap : null, usedBytes: swapUsed, freeBytes: validSwap ? freeSwap : null, usedPercent: ratio(swapUsed, totalSwap) };
  // Deduplicate backing devices so bind mounts cannot inflate the host total.
  const inodeMounts = rows.filter(row => row?.metric?.__name__ === "node_filesystem_files" && ["/", "/srv/platform-nvme"].includes(row.metric.mountpoint) && !/^(?:tmpfs|fuse.*|overlay|squashfs)$/.test(row.metric.fstype || ""));
  const inodeDevices = new Map();
  for (const row of inodeMounts) {
    const key = row.metric.device;
    const total = rowValue(row);
    const free = onlyValue(rows.filter(other => other?.metric?.__name__ === "node_filesystem_files_free" && other.metric?.device === key && other.metric?.mountpoint === row.metric.mountpoint));
    if (typeof key === "string") inodeDevices.set(key, { total, free });
  }
  const inodeRows = [...inodeDevices.values()];
  const inodeTotal = sumMeasured(inodeRows, "total"), inodeFree = sumMeasured(inodeRows, "free");
  const validInodes = inodeTotal !== null && inodeFree !== null && inodeFree <= inodeTotal;
  const inodeUsed = validInodes ? inodeTotal - inodeFree : null;
  const inodes = { available: validInodes, total: validInodes ? inodeTotal : null, used: inodeUsed, free: validInodes ? inodeFree : null, usedPercent: ratio(inodeUsed, inodeTotal) };
  const boot = gauge("node_boot_time_seconds"), hostTime = gauge("node_time_seconds");
  const uptimeSeconds = boot !== null && hostTime !== null && hostTime >= boot ? hostTime - boot : null;
  const running = gauge("node_procs_running"), blocked = gauge("node_procs_blocked");
  const processes = { available: running !== null || blocked !== null, running, blocked };
  const pressureValues = Object.fromEntries(Object.keys(pressureFields).map(key => { const value = onlyValue(validResults[key]); return [key, value === null ? null : value * 100]; }));
  const pressure = { available: Object.values(pressureValues).some(value => value !== null), window: "2m", ...pressureValues };
  const allocated = gauge("node_filefd_allocated"), maximum = gauge("node_filefd_maximum");
  const fileDescriptors = { available: allocated !== null && maximum !== null, allocated, maximum, usedPercent: ratio(allocated, maximum) };
  return { ...base, freshness, network, load, swap, diskIo, inodes, uptimeSeconds, processes, pressure, fileDescriptors };
}

export function createHostMetricsReader({ readSnapshot, query, ttlMs = 2000, now = Date.now }) {
  if (typeof readSnapshot !== "function" || typeof query !== "function") throw Error("Host metrics require the existing snapshot reader and Prometheus query dependency.");
  const ttl = Number.isFinite(ttlMs) ? Math.max(1000, Math.min(60000, ttlMs)) : 2000;
  let cached = null, expiresAt = 0, pending = null;
  return async function readHostMetrics() {
    if (cached && expiresAt > now()) return cached;
    if (pending) return pending;
    pending = (async () => {
      const [snapshot, entries] = await Promise.all([
        Promise.resolve().then(readSnapshot).catch(() => null),
        Promise.all(Object.entries(HOST_METRIC_QUERIES).map(async ([key, expression]) => {
          try { const rows = await query(expression); return [key, Array.isArray(rows) ? rows : []]; } catch { return [key, []]; }
        })),
      ]);
      cached = extendedPayload(snapshot, Object.fromEntries(entries), now());
      expiresAt = now() + ttl;
      return cached;
    })().finally(() => { pending = null; });
    return pending;
  };
}
