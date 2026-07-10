const REQUIRED_READ_ONLY = new Set([
  "control-center",
  "project-router",
  "platform-alert-dispatcher",
  "backup-scheduler",
  "docker-socket-proxy",
]);

const FORBIDDEN_WORKLOAD_TARGETS = [
  "/infra",
  "/backups",
  "/mnt/host",
  "/var/run/docker.sock",
  "/var/www/infra-docs",
  "/var/www/project-state",
];

export function evaluateRuntimeIsolation(config, options = {}) {
  const services = object(config?.services);
  const networks = object(config?.networks);
  const maxMemoryBytes = integer(options.maxMemoryBytes ?? 13_500 * 1024 * 1024);
  const maxWorkloadMemoryBytes = integer(options.maxWorkloadMemoryBytes ?? 8_000 * 1024 * 1024);
  const checks = [];
  const failures = [];
  const record = (id, passed, detail) => {
    checks.push({ id, status: passed ? "passed" : "failed", detail });
    if (!passed) failures.push(`${id}: ${detail}`);
  };

  let totalMemoryBytes = 0;
  for (const [name, service] of Object.entries(services)) {
    const memory = bytes(service.mem_limit);
    totalMemoryBytes += memory;
    record(`resource-cpu-${name}`, number(service.cpus) > 0, `${name} cpus=${service.cpus ?? "unset"}`);
    record(`resource-memory-${name}`, memory > 0, `${name} memory=${memory || "unset"}`);
    record(`resource-reservation-${name}`, bytes(service.mem_reservation) > 0 && bytes(service.mem_reservation) <= memory, `${name} reservation=${bytes(service.mem_reservation)} limit=${memory}`);
    record(`resource-pids-${name}`, integer(service.pids_limit) > 0, `${name} pids=${service.pids_limit ?? "unset"}`);
    record(`resource-fd-${name}`, nofileHard(service) >= 1024, `${name} nofile=${nofileHard(service) || "unset"}`);
    record(`resource-io-${name}`, integer(service.blkio_config?.weight) >= 10, `${name} ioWeight=${service.blkio_config?.weight ?? "unset"}`);
    record(`resource-cpu-shares-${name}`, integer(service.cpu_shares) >= 2, `${name} cpuShares=${service.cpu_shares ?? "unset"}`);
  }
  record("resource-memory-admission", totalMemoryBytes <= maxMemoryBytes, `total=${totalMemoryBytes} max=${maxMemoryBytes}`);

  const workloadServices = Object.entries(services)
    .filter(([, service]) => String(service?.labels?.["com.platform.workload-id"] || ""))
    .map(([name]) => name)
    .sort();
  const readOnlyServices = new Set([...REQUIRED_READ_ONLY, ...workloadServices]);
  for (const name of readOnlyServices) {
    record(`rootfs-read-only-${name}`, services[name]?.read_only === true, `${name} readOnly=${services[name]?.read_only === true}`);
  }

  for (const name of workloadServices) {
    const service = services[name] || {};
    const workloadId = String(service.labels?.["com.platform.workload-id"] || "");
    const role = String(service.labels?.["com.platform.workload-role"] || "");
    record(`workload-name-prefix-${name}`, name.startsWith(`${workloadId}-`), `${name} workload=${workloadId}`);
    record(`workload-role-${name}`, ["api", "web", "worker", "scheduled-worker"].includes(role), `${name} role=${role}`);
    record(`workload-non-root-${name}`, Boolean(service.user) && !/^(?:0|root)(?::|$)/.test(String(service.user)), `${name} user=${service.user || "unset"}`);
    record(`workload-no-new-privileges-${name}`, service.security_opt?.includes("no-new-privileges:true"), `${name} securityOpt=${service.security_opt || "unset"}`);
    record(`workload-drop-all-capabilities-${name}`, service.cap_drop?.includes("ALL") && !(service.cap_add?.length > 0), `${name} capDrop=${service.cap_drop || "unset"}`);
    const mounts = volumes(service);
    for (const target of FORBIDDEN_WORKLOAD_TARGETS) {
      const exposed = mounts.some((mount) => mount.target === target || mount.target.startsWith(`${target}/`));
      record(`workload-deny-mount-${stableId(target)}-${name}`, !exposed, `${name} target=${target} exposed=${exposed}`);
    }
    const binds = mounts.filter((mount) => mount.type === "bind");
    record(`workload-no-bind-mounts-${name}`, binds.length === 0, `${name} binds=${binds.map((mount) => mount.target).join(",") || "none"}`);
  }

  for (const name of ["control-center", "project-router"]) {
    const mounts = volumes(services[name]);
    const broadHost = mounts.some((mount) => mount.target === "/mnt/host" || mount.target.startsWith("/mnt/host/"));
    record(`control-plane-no-host-parent-${name}`, !broadHost, `${name} broadHost=${broadHost}`);
  }
  const routerMounts = volumes(services["project-router"]);
  record("router-projects-read-only", routerMounts.some((mount) => mount.target === "/var/www/projects" && mount.readOnly), "router project catalog is read-only");
  record("router-state-read-only", routerMounts.some((mount) => mount.target === "/var/www/project-state" && mount.readOnly), "router state catalog is read-only");

  const rawSocketOwners = Object.entries(services)
    .filter(([, service]) => volumes(service).some((mount) => mount.source === "/var/run/docker.sock" || mount.target === "/var/run/docker.sock"))
    .map(([name]) => name)
    .sort();
  record("raw-socket-single-owner", rawSocketOwners.length === 1 && rawSocketOwners[0] === "docker-socket-proxy", `owners=${rawSocketOwners.join(",") || "none"}`);

  const proxy = services["docker-socket-proxy"] || {};
  record("socket-proxy-image-pinned", /@sha256:[a-f0-9]{64}$/.test(String(proxy.image || "")), `image=${proxy.image || "unset"}`);
  const proxyEnvironment = object(proxy.environment);
  const disabledProxySections = ["AUTH", "BUILD", "COMMIT", "CONFIGS", "SECRETS", "SERVICES", "SESSION", "SWARM", "SYSTEM", "TASKS"];
  const enabledDangerous = disabledProxySections.filter((key) => String(proxyEnvironment[key]) !== "0");
  record("socket-proxy-dangerous-sections-disabled", enabledDangerous.length === 0, `enabled=${enabledDangerous.join(",") || "none"}`);
  const proxyPorts = Array.isArray(proxy.ports) ? proxy.ports : [];
  const loopbackPorts = proxyPorts.filter((port) => String(port?.host_ip || "") === "127.0.0.1" && integer(port?.target) === 2375);
  const nonLoopbackPorts = proxyPorts.filter((port) => String(port?.host_ip || "") !== "127.0.0.1");
  record("socket-proxy-loopback-only", loopbackPorts.length === 1 && nonLoopbackPorts.length === 0, `loopback=${loopbackPorts.length} nonLoopback=${nonLoopbackPorts.length}`);

  const scheduler = services["backup-scheduler"] || {};
  record("scheduler-uses-proxy", object(scheduler.environment).DOCKER_HOST === "tcp://docker-socket-proxy:2375", `DOCKER_HOST=${object(scheduler.environment).DOCKER_HOST || "unset"}`);
  record("scheduler-api-version-bounded", object(scheduler.environment).DOCKER_API_VERSION === "1.51", `DOCKER_API_VERSION=${object(scheduler.environment).DOCKER_API_VERSION || "unset"}`);

  record("socket-network-internal", networks.platform_docker_control?.internal === true, `internal=${networks.platform_docker_control?.internal === true}`);
  const socketMembers = Object.entries(services)
    .filter(([, service]) => networkNames(service).includes("platform_docker_control"))
    .map(([name]) => name)
    .sort();
  record("socket-network-members", same(socketMembers, ["backup-scheduler", "docker-socket-proxy"]), `members=${socketMembers.join(",") || "none"}`);

  const workloadMemory = workloadServices.reduce((total, name) => total + bytes(services[name]?.mem_limit), 0);
  record("workload-memory-bounded", workloadServices.length === 0 || (workloadMemory > 0 && workloadMemory <= maxWorkloadMemoryBytes), `workloadMemory=${workloadMemory} max=${maxWorkloadMemoryBytes}`);

  return {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    status: failures.length ? "failed" : "passed",
    summary: {
      checks: checks.length,
      passed: checks.filter((item) => item.status === "passed").length,
      failed: failures.length,
      services: Object.keys(services).length,
      hostedWorkloads: new Set(workloadServices.map((name) => String(services[name].labels["com.platform.workload-id"]))).size,
      hostedServices: workloadServices.length,
      totalMemoryLimitBytes: totalMemoryBytes,
      maxMemoryBudgetBytes: maxMemoryBytes,
      rawSocketOwners,
    },
    checks,
    failures,
  };
}

function object(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function integer(value) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

function number(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function bytes(value) {
  if (typeof value === "number" && Number.isFinite(value)) return Math.max(0, Math.trunc(value));
  const clean = String(value ?? "").trim().toLowerCase();
  if (/^\d+$/.test(clean)) return Number.parseInt(clean, 10);
  const match = clean.match(/^(\d+(?:\.\d+)?)\s*([kmgt])(?:i?b)?$/);
  if (!match) return 0;
  const power = { k: 1, m: 2, g: 3, t: 4 }[match[2]];
  return Math.trunc(Number(match[1]) * (1024 ** power));
}

function nofileHard(service) {
  const value = service?.ulimits?.nofile;
  if (typeof value === "number" || typeof value === "string") return integer(value);
  return integer(value?.hard);
}

function volumes(service) {
  return (service?.volumes || []).map((mount) => {
    if (typeof mount === "string") {
      const parts = mount.split(":");
      return { type: parts[0]?.startsWith("/") || parts[0]?.startsWith(".") ? "bind" : "volume", source: parts[0] || "", target: parts[1] || "", readOnly: parts.slice(2).includes("ro") };
    }
    return {
      type: String(mount?.type || ""),
      source: String(mount?.source || ""),
      target: String(mount?.target || ""),
      readOnly: mount?.read_only === true,
    };
  });
}

function networkNames(service) {
  if (Array.isArray(service?.networks)) return service.networks.map(String);
  return Object.keys(object(service?.networks));
}

function stableId(value) {
  return String(value).replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").toLowerCase();
}

function same(left, right) {
  return JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}
