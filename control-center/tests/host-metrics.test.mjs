import assert from "node:assert/strict";
import test from "node:test";
import { hostMetricsPayload, createHostMetricsReader, HOST_METRIC_QUERIES } from "../resources/host-metrics.mjs";

test("host settings reject the container filesystem fallback when Prometheus is unavailable", () => {
  const result = hostMetricsPayload({ available: false, cpu: { available: false, usedPercent: null }, memory: { available: false, totalBytes: 0, usedBytes: 0 }, disk: { available: true, totalBytes: 9999, usedBytes: 1234, usedPercent: 12.34 } });
  assert.equal(result.scope, "host");
  assert.equal(result.capturedAt, null);
  assert.deepEqual(result.disk, { available: false, usedBytes: null, totalBytes: null, usedPercent: null });
  assert.equal(result.memory.usedBytes, null);
  assert.equal(result.cpu.usedPercent, null);
});

test("host projection preserves genuine measured zero and uses only the node-exporter sampler fields", () => {
  const capturedAt = new Date().toISOString();
  const result = hostMetricsPayload({ available: true, capturedAt, cpu: { available: true, usedPercent: 0, cores: 4 }, memory: { available: true, totalBytes: 16000, usedBytes: 4000, usedPercent: 25 }, disk: { available: true, totalBytes: 80000, usedBytes: 30000, usedPercent: 37.5 }, containers: [{ cpuPercent: 88 }] });
  assert.equal(result.capturedAt, capturedAt);
  assert.equal(result.cpu.available, true);
  assert.equal(result.cpu.usedPercent, 0);
  assert.equal(result.memory.usedPercent, 25);
  assert.equal(result.disk.usedPercent, 37.5);
  assert.equal("containers" in result, false);
});

const clock = Date.parse("2026-10-14T18:00:00Z");
const row = (value, metric = {}) => ({ metric, value: [clock / 1000, String(value)] });
const gauge = (name, value, labels = {}) => row(value, { __name__: name, ...labels });
function fixture(overrides = {}) {
  const metrics = { up: [row(1)], sampleTime: [row(clock / 1000 - 8)], gauges: [], ...overrides };
  let reads = 0, queries = 0;
  const query = async expression => { queries++; const key = Object.keys(HOST_METRIC_QUERIES).find(key => HOST_METRIC_QUERIES[key] === expression); return metrics[key] || []; };
  const readSnapshot = async () => { reads++; return { available: true, capturedAt: new Date(clock).toISOString(), cpu: { available: true, usedPercent: 20, cores: 4 }, memory: { available: true, totalBytes: 16000, usedBytes: 4000, usedPercent: 25 }, disk: { available: true, totalBytes: 80000, usedBytes: 30000, usedPercent: 37.5 } }; };
  return { metrics, query, readSnapshot, counts: () => ({ reads, queries }) };
}

test("host reader keeps rates in bytes/second, filters virtual interfaces, and preserves measured zero errors", async () => {
  const f = fixture({
    network: [gauge("node_network_receive_bytes_total", 8192, { device: "eth0" }), gauge("node_network_transmit_bytes_total", 4096, { device: "eth0" }), gauge("node_network_receive_errs_total", 0, { device: "eth0" }), gauge("node_network_receive_bytes_total", 999999, { device: "veth123" }), gauge("node_network_receive_bytes_total", 999999, { device: "lo" })],
    rxBytesPerSecond: [row(1024, { device: "eth0" }), row(99999, { device: "docker0" })], txBytesPerSecond: [row(512, { device: "eth0" })],
    readBytesPerSecond: [row(2048, { device: "sda" }), row(999, { device: "sda1" })], writeBytesPerSecond: [row(1024, { device: "sda" })], readsPerSecond: [row(4, { device: "sda" })], writesPerSecond: [row(2, { device: "sda" })], busyPercent: [row(0.25, { device: "sda" })],
    cpuWaitingPercent: [row(0.015)],
  });
  const result = await createHostMetricsReader({ ...f, now: () => clock })();
  assert.deepEqual(result.network.interfaces.map(i => i.name), ["eth0"]);
  assert.equal(result.network.totals.rxBytesPerSecond, 1024);
  assert.equal(result.network.totals.txBytesPerSecond, 512);
  assert.equal(result.network.totals.rxBytes, 8192);
  assert.equal(result.network.totals.rxErrors, 0);
  assert.equal(result.network.totals.txErrors, null);
  assert.deepEqual(result.diskIo.devices.map(d => d.name), ["sda"]);
  assert.equal(result.diskIo.totals.readBytesPerSecond, 2048);
  assert.equal(result.diskIo.devices[0].busyPercent, 25);
  assert.equal(result.pressure.cpuWaitingPercent, 1.5);
  assert.match(HOST_METRIC_QUERIES.rxBytesPerSecond, /^rate\(node_network_receive_bytes_total.*\[2m\]\)$/);
});

test("missing exporters and stale actual scrape samples hide all host values even when query time looks fresh", async () => {
  for (const overrides of [{ up: [row(0)] }, { sampleTime: [row(clock / 1000 - 61)] }, { sampleTime: [row(clock / 1000 + 6)] }, { sampleTime: [] }, { up: [row(1), row(1)] }]) {
    const f = fixture({ gauges: [gauge("node_load1", 7)], rxBytesPerSecond: [row(123, { device: "eth0" })], ...overrides });
    const result = await createHostMetricsReader({ ...f, now: () => clock })();
    assert.equal(result.freshness.available, false);
    assert.equal(result.capturedAt, null);
    assert.equal(result.cpu.usedPercent, null);
    assert.equal(result.memory.usedBytes, null);
    assert.equal(result.disk.usedBytes, null);
    assert.equal(result.network.available, false);
    assert.equal(result.load.one, null);
  }
});

test("optional collector absence stays null while actual swap absence remains measured zero", async () => {
  const f = fixture({ gauges: [gauge("node_memory_SwapTotal_bytes", 0), gauge("node_memory_SwapFree_bytes", 0)] });
  const result = await createHostMetricsReader({ ...f, now: () => clock })();
  assert.deepEqual(result.swap, { available: true, totalBytes: 0, usedBytes: 0, freeBytes: 0, usedPercent: null });
  assert.equal(result.network.available, false);
  assert.equal(result.diskIo.totals.readsPerSecond, null);
  assert.equal(result.pressure.cpuWaitingPercent, null);
  assert.equal(result.uptimeSeconds, null);
  assert.equal(result.processes.running, null);
  assert.equal(result.fileDescriptors.allocated, null);
  assert.equal(result.freshness.ageSeconds, 8);
  assert.equal(result.capturedAt, new Date(clock - 8000).toISOString());
});

test("host gauges compute swap, inode, uptime and descriptor ratios without counting bind mounts twice", async () => {
  const filesystem = { device: "/dev/sda1", fstype: "ext4" };
  const f = fixture({ gauges: [
    gauge("node_load1", 1.2), gauge("node_load5", 0.8), gauge("node_load15", 0.5),
    gauge("node_memory_SwapTotal_bytes", 4096), gauge("node_memory_SwapFree_bytes", 1024),
    gauge("node_filesystem_files", 1000, { ...filesystem, mountpoint: "/" }), gauge("node_filesystem_files_free", 250, { ...filesystem, mountpoint: "/" }),
    gauge("node_filesystem_files", 1000, { ...filesystem, mountpoint: "/srv/platform-nvme" }), gauge("node_filesystem_files_free", 250, { ...filesystem, mountpoint: "/srv/platform-nvme" }),
    gauge("node_time_seconds", clock / 1000), gauge("node_boot_time_seconds", clock / 1000 - 86400),
    gauge("node_procs_running", 2), gauge("node_procs_blocked", 0), gauge("node_filefd_allocated", 200), gauge("node_filefd_maximum", 1000),
  ] });
  const result = await createHostMetricsReader({ ...f, now: () => clock })();
  assert.deepEqual(result.load, { available: true, one: 1.2, five: 0.8, fifteen: 0.5 });
  assert.equal(result.swap.usedBytes, 3072);
  assert.equal(result.swap.usedPercent, 75);
  assert.deepEqual(result.inodes, { available: true, total: 1000, used: 750, free: 250, usedPercent: 75 });
  assert.equal(result.uptimeSeconds, 86400);
  assert.equal(result.processes.blocked, 0);
  assert.equal(result.fileDescriptors.usedPercent, 20);
});

test("partial and invalid observations do not fabricate complete network totals or numeric readings", async () => {
  const f = fixture({ rxBytesPerSecond: [row(100, { device: "eth0" }), row(200, { device: "ens3" })], txBytesPerSecond: [row(50, { device: "eth0" })], gauges: [gauge("node_load1", "NaN"), gauge("node_procs_running", -1)] });
  const result = await createHostMetricsReader({ ...f, now: () => clock })();
  assert.equal(result.network.totals.rxBytesPerSecond, 300);
  assert.equal(result.network.totals.txBytesPerSecond, null);
  assert.equal(result.load.available, false);
  assert.equal(result.processes.running, null);
});

test("reader coalesces concurrent requests and refreshes after its two second cache expires", async () => {
  let time = clock, release;
  const f = fixture();
  const barrier = new Promise(resolve => { release = resolve; });
  const reader = createHostMetricsReader({ ...f, now: () => time, readSnapshot: async () => { await barrier; return f.readSnapshot(); } });
  const first = reader(), second = reader();
  release();
  const [one, two] = await Promise.all([first, second]);
  assert.strictEqual(one, two);
  assert.equal(f.counts().reads, 1);
  assert.equal(f.counts().queries, Object.keys(HOST_METRIC_QUERIES).length);
  time += 1999; assert.strictEqual(await reader(), one);
  time += 1; await reader();
  assert.equal(f.counts().reads, 2);
  assert.equal(f.counts().queries, Object.keys(HOST_METRIC_QUERIES).length * 2);
});

test("query and snapshot errors return unavailable blocks without breaking the response", async () => {
  const result = await createHostMetricsReader({ readSnapshot: async () => { throw Error("unavailable"); }, query: async () => { throw Error("timeout"); }, now: () => clock })();
  assert.equal(result.freshness.exporterUp, null);
  assert.equal(result.freshness.stale, true);
  assert.equal(result.cpu.available, false);
  assert.equal(result.network.totals.rxBytesPerSecond, null);
});

test("host metrics overlay limits collectors to finite read-only proc files and udev device metadata", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../../deployment/host/empty-vps/compose.host-metrics.yaml", import.meta.url), "utf8");
  const expected = ["/proc/stat", "/proc/meminfo", "/proc/1/mountinfo", "/proc/loadavg", "/proc/uptime", "/proc/diskstats", "/proc/1/net/dev", "/proc/pressure/cpu", "/proc/pressure/io", "/proc/pressure/memory", "/proc/sys/fs/file-nr", "/proc/sys/fs/file-max", "/run/udev/data", "/var/lib/platform-host-metrics/rootfs"];
  assert.deepEqual([...source.matchAll(/^        source: (.+)$/gm)].map(match => match[1]).sort(), expected.sort());
  for (const block of source.split("      - type: bind\n").slice(1)) { assert.match(block, /read_only: true/); assert.match(block, /create_host_path: false/); }
  const udev = source.split("      - type: bind\n").find(block => /^        source: \/run\/udev\/data$/m.test(block));
  assert.match(udev, /target: \/run\/udev\/data\n/);
  assert.doesNotMatch(udev, /propagation:/, "udev bind keeps Docker's default private propagation");
  for (const collector of ["stat", "time", "loadavg", "diskstats", "netdev", "pressure", "filefd"]) assert.ok(source.includes(`      - --collector.${collector}\n`));
  assert.match(source, /--no-collector.netdev.netlink/);
  assert.match(source, /pid: !reset null/); assert.match(source, /cap_drop: \[ALL\]/); assert.match(source, /ports: !reset \[\]/);
  assert.doesNotMatch(source, /network_mode: host|pid: host|source: \/(?:proc|sys)?\s*$/m);
});
