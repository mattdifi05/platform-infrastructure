const HOSTED_APPS = [
  { service: "php-anniversary", sourceTarget: "/opt/platform-source/anniversary" },
  { service: "php-fiplatform", sourceTarget: "/opt/platform-source/fiplatform" },
  { service: "php-matthewdifilippo", sourceTarget: "/opt/platform-source/matthewdifilippo" },
  { service: "php-stream", sourceTarget: "/opt/platform-source/stream" },
  { service: "php-workcalendar", sourceTarget: "/opt/platform-source/workcalendar" },
  { service: "node-account", sourceTarget: "/workspace" },
  { service: "node-ui", sourceTarget: "/workspace" },
];

const READ_ONLY_ROOTFS_SERVICES = [
  ...HOSTED_APPS.map((item) => item.service),
  "backend",
  "web",
  "worker-jobs",
  "worker-notifications",
  "control-center",
  "project-router",
  "backup-scheduler",
  "docker-socket-proxy",
];

const FORBIDDEN_HOSTED_TARGETS = [
  "/infra",
  "/backups",
  "/mnt/host",
  "/var/run/docker.sock",
  "/var/www/infra-docs",
  "/var/www/project-state",
];

const FORBIDDEN_PHP_ENV = [
  "MAILER_FROM",
  "MAILER_REPLY_TO",
  "PROJECTS_GATEWAY_EMAIL",
  "PROJECTS_GATEWAY_SIGNING_KEYS_FILE",
  "SMTP_HOST",
  "SMTP_PASSWORD_FILE",
  "SMTP_PORT",
  "SMTP_SECURE",
  "SMTP_USER",
];

export function evaluateRuntimeIsolation(config, options = {}) {
  const services = object(config?.services);
  const networks = object(config?.networks);
  const maxMemoryBytes = integer(options.maxMemoryBytes ?? 13_500 * 1024 * 1024);
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
    record(`resource-reservation-${name}`, bytes(service.mem_reservation) > 0 && bytes(service.mem_reservation) < memory, `${name} reservation=${bytes(service.mem_reservation)} limit=${memory}`);
    record(`resource-pids-${name}`, integer(service.pids_limit) > 0, `${name} pids=${service.pids_limit ?? "unset"}`);
    record(`resource-fd-${name}`, nofileHard(service) >= 1024, `${name} nofile=${nofileHard(service) || "unset"}`);
    record(`resource-io-${name}`, integer(service.blkio_config?.weight) >= 10, `${name} ioWeight=${service.blkio_config?.weight ?? "unset"}`);
    record(`resource-cpu-shares-${name}`, integer(service.cpu_shares) >= 2, `${name} cpuShares=${service.cpu_shares ?? "unset"}`);
  }
  record("resource-memory-admission", totalMemoryBytes <= maxMemoryBytes, `total=${totalMemoryBytes} max=${maxMemoryBytes}`);

  for (const name of READ_ONLY_ROOTFS_SERVICES) {
    record(`rootfs-read-only-${name}`, services[name]?.read_only === true, `${name} readOnly=${services[name]?.read_only === true}`);
  }

  for (const app of HOSTED_APPS) {
    const service = services[app.service] || {};
    const mounts = volumes(service);
    const sourceMounts = mounts.filter((mount) => mount.target === app.sourceTarget);
    record(`app-source-exact-${app.service}`, sourceMounts.length === 1 && sourceMounts[0].readOnly, `${app.service} ${app.sourceTarget} mounts=${sourceMounts.length} readOnly=${sourceMounts[0]?.readOnly === true}`);
    for (const target of FORBIDDEN_HOSTED_TARGETS) {
      const exposed = mounts.some((mount) => mount.target === target || mount.target.startsWith(`${target}/`));
      record(`app-deny-mount-${stableId(target)}-${app.service}`, !exposed, `${app.service} target=${target} exposed=${exposed}`);
    }
    const rawSocket = mounts.some((mount) => mount.source === "/var/run/docker.sock" || mount.target === "/var/run/docker.sock");
    record(`app-no-docker-socket-${app.service}`, !rawSocket, `${app.service} rawSocket=${rawSocket}`);
  }

  for (const name of HOSTED_APPS.filter((item) => item.service.startsWith("php-")).map((item) => item.service)) {
    const service = services[name] || {};
    const secretNames = (service.secrets || []).map((item) => typeof item === "string" ? item : item.source).filter(Boolean);
    record(`php-no-admin-secrets-${name}`, secretNames.length === 0, `${name} secrets=${secretNames.join(",") || "none"}`);
    const environment = object(service.environment);
    const forbidden = FORBIDDEN_PHP_ENV.filter((key) => Object.hasOwn(environment, key));
    record(`php-no-shared-mail-or-gateway-${name}`, forbidden.length === 0, `${name} forbiddenEnv=${forbidden.join(",") || "none"}`);
    const tmpfs = Array.isArray(service.tmpfs) ? service.tmpfs.map(String) : [];
    record(`php-ephemeral-runtime-${name}`, tmpfs.some((item) => item === "/var/www/projects" || item.startsWith("/var/www/projects:")), `${name} uses an isolated tmpfs runtime copy`);
  }

  for (const name of ["node-account", "node-ui"]) {
    const environment = object(services[name]?.environment);
    record(`node-no-runtime-install-${name}`, String(environment.NODE_PROJECT_INSTALL_COMMAND || "") === "" && String(environment.NODE_PROJECT_BUILD_COMMAND || "") === "", `${name} install/build disabled in the runtime container`);
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

  const dockerNetwork = networks.platform_docker_control || {};
  record("socket-network-internal", dockerNetwork.internal === true, `internal=${dockerNetwork.internal === true}`);
  const dockerNetworkMembers = Object.entries(services)
    .filter(([, service]) => networkNames(service).includes("platform_docker_control"))
    .map(([name]) => name)
    .sort();
  record("socket-network-members", JSON.stringify(dockerNetworkMembers) === JSON.stringify(["backup-scheduler", "docker-socket-proxy"]), `members=${dockerNetworkMembers.join(",") || "none"}`);

  const hostedServices = new Set(HOSTED_APPS.map((item) => item.service));
  const hostedMemory = [...hostedServices].reduce((total, name) => total + bytes(services[name]?.mem_limit), 0);
  const hostedCpuShares = [...hostedServices].map((name) => integer(services[name]?.cpu_shares));
  record("hosted-memory-bounded", hostedMemory > 0 && hostedMemory <= 2_100 * 1024 * 1024, `hostedMemory=${hostedMemory}`);
  record("hosted-cpu-priority-below-control", hostedCpuShares.every((value) => value > 0 && value < integer(services["control-center"]?.cpu_shares)), `hostedShares=${[...new Set(hostedCpuShares)].join(",")} control=${services["control-center"]?.cpu_shares ?? "unset"}`);

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    status: failures.length ? "failed" : "passed",
    summary: {
      checks: checks.length,
      passed: checks.filter((item) => item.status === "passed").length,
      failed: failures.length,
      services: Object.keys(services).length,
      hostedApplications: HOSTED_APPS.length,
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
      return { source: parts[0] || "", target: parts[1] || "", readOnly: parts.slice(2).includes("ro") };
    }
    return {
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
