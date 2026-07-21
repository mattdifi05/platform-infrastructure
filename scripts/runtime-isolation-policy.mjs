const REQUIRED_READ_ONLY = new Set([
  "control-center",
  "project-router",
  "platform-alert-dispatcher",
  "backup-scheduler",
  "docker-operation-gateway",
  "broker-auth-bootstrap",
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
  const projectName = String(options.projectName ?? config?.name ?? "");
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
  const workloadIds = new Set(workloadServices.map((name) => String(services[name]?.labels?.["com.platform.workload-id"] || "")));
  const unsafeWorkloadConfigs = Object.entries(object(config?.configs))
    .filter(([name]) => [...workloadIds].some((id) => name.startsWith(`${id}_`) || name.startsWith(`${id.replaceAll("-", "_")}_`)))
    .filter(([, definition]) => Object.hasOwn(object(definition), "content") || Object.hasOwn(object(definition), "environment"))
    .map(([name]) => name);
  record("workload-no-inline-config-definitions", unsafeWorkloadConfigs.length === 0, `configs=${unsafeWorkloadConfigs.join(",") || "none"}`);
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
    record(`workload-numeric-user-${name}`, /^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$/.test(String(service.user || "")), `${name} user=${service.user || "unset"}`);
    record(`workload-private-pid-${name}`, !Object.hasOwn(service, "pid"), `${name} pid=${service.pid ?? "private"}`);
    record(`workload-no-swap-${name}`, bytes(service.memswap_limit) === bytes(service.mem_limit), `${name} memswap=${bytes(service.memswap_limit)} memory=${bytes(service.mem_limit)}`);
    const oomControls = ["oom_kill_disable", "oom_score_adj", "mem_swappiness"].filter((field) => Object.hasOwn(service, field));
    record(`workload-no-oom-overrides-${name}`, oomControls.length === 0, `${name} oomControls=${oomControls.join(",") || "none"}`);
    record(
      `workload-bounded-local-logging-${name}`,
      JSON.stringify(service.logging) === JSON.stringify({ driver: "local", options: { "max-size": "10m", "max-file": "3" } }),
      `${name} logging=${JSON.stringify(service.logging ?? null)}`,
    );
    record(`workload-no-new-privileges-${name}`, service.security_opt?.includes("no-new-privileges:true"), `${name} securityOpt=${service.security_opt || "unset"}`);
    record(`workload-drop-all-capabilities-${name}`, service.cap_drop?.includes("ALL") && !(service.cap_add?.length > 0), `${name} capDrop=${service.cap_drop || "unset"}`);
    record(`workload-no-volumes-from-${name}`, !Object.hasOwn(service, "volumes_from"), `${name} volumesFrom=${service.volumes_from || "none"}`);
    const externalContainerInheritance = (Array.isArray(service.volumes_from) ? service.volumes_from : [])
      .map(String)
      .filter((entry) => entry.startsWith("container:"));
    record(
      `workload-no-external-container-volume-inheritance-${name}`,
      externalContainerInheritance.length === 0,
      `${name} externalContainers=${externalContainerInheritance.join(",") || "none"}`,
    );
    const lifecycleHooks = ["post_start", "pre_start", "pre_stop"].filter((field) => Object.hasOwn(service, field));
    record(`workload-no-lifecycle-hooks-${name}`, lifecycleHooks.length === 0, `${name} hooks=${lifecycleHooks.join(",") || "none"}`);
    const hasScaling = Object.hasOwn(service, "scale")
      || Object.hasOwn(object(service.deploy), "replicas")
      || Object.hasOwn(object(service.deploy), "mode");
    record(`workload-no-scaling-${name}`, !hasScaling, `${name} scale=${service.scale ?? "unset"} replicas=${service.deploy?.replicas ?? "unset"} mode=${service.deploy?.mode ?? "unset"}`);
    record(`workload-no-configs-${name}`, !Object.hasOwn(service, "configs"), `${name} configs=${service.configs || "none"}`);
    record(`workload-no-api-socket-${name}`, !Object.hasOwn(service, "use_api_socket"), `${name} useApiSocket=${service.use_api_socket ?? "unset"}`);
    record(`workload-no-provider-${name}`, !Object.hasOwn(service, "provider"), `${name} provider=${service.provider?.type ?? "none"}`);
    record(`workload-no-runtime-override-${name}`, !Object.hasOwn(service, "runtime"), `${name} runtime=${service.runtime ?? "default"}`);
    record(`workload-no-stop-grace-override-${name}`, !Object.hasOwn(service, "stop_grace_period"), `${name} stopGrace=${service.stop_grace_period ?? "default"}`);
    const deviceControls = ["devices", "device_cgroup_rules"].filter((field) => Object.hasOwn(service, field));
    record(`workload-no-device-access-${name}`, deviceControls.length === 0, `${name} deviceControls=${deviceControls.join(",") || "none"}`);
    record(`workload-no-supplemental-groups-${name}`, !Object.hasOwn(service, "group_add"), `${name} groupAdd=${service.group_add || "none"}`);
    const acceleratorControls = ["gpus", "device_requests"].filter((field) => Object.hasOwn(service, field));
    if (Object.hasOwn(object(service.deploy?.resources?.reservations), "devices")) {
      acceleratorControls.push("deploy.resources.reservations.devices");
    }
    record(`workload-no-accelerators-${name}`, acceleratorControls.length === 0, `${name} acceleratorControls=${acceleratorControls.join(",") || "none"}`);
    const foreignSecrets = (Array.isArray(service.secrets) ? service.secrets : [])
      .map((entry) => typeof entry === "string" ? entry : String(entry?.source || ""))
      .filter((source) => {
        const definition = object(config?.secrets?.[source]);
        return !source.startsWith(`${workloadId}-`)
          || definition.external !== true
          || typeof definition.name !== "string"
          || !definition.name.endsWith(`_${source}`);
      });
    record(`workload-owned-secrets-${name}`, foreignSecrets.length === 0, `${name} foreignSecrets=${foreignSecrets.join(",") || "none"}`);
    const mounts = volumes(service);
    for (const target of FORBIDDEN_WORKLOAD_TARGETS) {
      const exposed = mounts.some((mount) => mount.target === target || mount.target.startsWith(`${target}/`));
      record(`workload-deny-mount-${stableId(target)}-${name}`, !exposed, `${name} target=${target} exposed=${exposed}`);
    }
    const binds = mounts.filter((mount) => mount.type === "bind");
    record(`workload-no-bind-mounts-${name}`, binds.length === 0, `${name} binds=${binds.map((mount) => mount.target).join(",") || "none"}`);
    const optionedVolumes = mounts
      .filter((mount) => mount.type === "volume" && Object.hasOwn(object(config?.volumes?.[mount.source]), "driver_opts"))
      .map((mount) => mount.source);
    record(`workload-no-local-volume-options-${name}`, optionedVolumes.length === 0, `${name} optionedVolumes=${optionedVolumes.join(",") || "none"}`);
    const foreignVolumes = mounts
      .filter((mount) => mount.type === "volume")
      .filter((mount) => {
        const definition = object(config?.volumes?.[mount.source]);
        return !mount.source.startsWith(`${workloadId}_`)
          || definition.external === true
          || definition.name !== `${projectName}_${mount.source}`;
      })
      .map((mount) => mount.source);
    record(`workload-owned-volumes-${name}`, foreignVolumes.length === 0, `${name} foreignVolumes=${foreignVolumes.join(",") || "none"}`);
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
  record("raw-socket-single-owner", rawSocketOwners.length === 1 && rawSocketOwners[0] === "docker-operation-gateway", `owners=${rawSocketOwners.join(",") || "none"}`);

  const brokerBootstrap = services["broker-auth-bootstrap"] || {};
  const brokerBootstrapMounts = volumes(brokerBootstrap);
  record("broker-bootstrap-no-network", brokerBootstrap.network_mode === "none" && networkNames(brokerBootstrap).length === 0, `networkMode=${brokerBootstrap.network_mode || "unset"}`);
  record("broker-bootstrap-lock-read-only", brokerBootstrapMounts.some((mount) => mount.target === "/run/platform/hosted-workloads.lock.json" && mount.readOnly), "broker bootstrap consumes the deployment lock read-only");
  const brokerOutputs = brokerBootstrapMounts
    .filter((mount) => mount.target.startsWith("/out/"))
    .map((mount) => `${mount.type}:${mount.target}:${mount.readOnly ? "ro" : "rw"}`)
    .sort();
  record("broker-bootstrap-config-volumes", same(brokerOutputs, ["volume:/out/nats:rw", "volume:/out/redis:rw"]), `outputs=${brokerOutputs.join(",") || "none"}`);
  record("broker-bootstrap-minimum-capability", brokerBootstrap.cap_drop?.includes("ALL") && same([...(brokerBootstrap.cap_add ?? [])].sort(), ["CHOWN"]), `capAdd=${brokerBootstrap.cap_add || "none"}`);
  const redisMounts = volumes(services.redis);
  record("redis-generated-acl-read-only", redisMounts.some((mount) => mount.target === "/run/platform-broker" && mount.readOnly), "Redis consumes only its generated ACL volume");
  const nats = services.nats || {};
  const natsMounts = volumes(nats);
  const natsCommand = [...(Array.isArray(nats.entrypoint) ? nats.entrypoint : []), ...(Array.isArray(nats.command) ? nats.command : [])].map(String);
  const natsCommandLine = natsCommand.join(" ");
  const natsEnvironment = object(nats.environment);
  record("nats-generated-config-read-only", natsMounts.some((mount) => mount.target === "/run/platform-broker" && mount.readOnly), "NATS consumes only its generated account config volume");
  record("nats-no-global-credential-flags", !/(?:^|\s)--(?:user|pass)(?:=|\s|$)/.test(natsCommandLine)
    && !natsEnvironment.NATS_PASSWORD && !natsEnvironment.NATS_PASSWORD_FILE && !natsEnvironment.NATS_USER,
  `command=${natsCommandLine}`);
  record("nats-non-root-identity", Boolean(nats.user) && !/^(?:0|root)(?::|$)/.test(String(nats.user)), `user=${nats.user || "unset"}`);

  const gateway = services["docker-operation-gateway"] || {};
  const gatewayEnvironment = object(gateway.environment);
  const gatewayEntrypoint = Array.isArray(gateway.entrypoint) ? gateway.entrypoint.map(String) : [String(gateway.entrypoint || "")];
  const gatewayCredential = "backup_scheduler_docker_gateway_token";
  const gatewayCredentialOwners = Object.entries(services)
    .filter(([, service]) => secretNames(service).includes(gatewayCredential))
    .map(([name]) => name)
    .sort();
  record("docker-gateway-typed-entrypoint", gatewayEntrypoint.includes("/infra/scripts/docker-operation-gateway.mjs"), `entrypoint=${gatewayEntrypoint.join(" ")}`);
  record("docker-gateway-no-host-ports", !Array.isArray(gateway.ports) || gateway.ports.length === 0, `ports=${JSON.stringify(gateway.ports || [])}`);
  record("docker-gateway-principal-auth", secretNames(gateway).includes(gatewayCredential) && gatewayEnvironment.BACKUP_SCHEDULER_DOCKER_GATEWAY_TOKEN_FILE === `/run/secrets/${gatewayCredential}`, `secrets=${secretNames(gateway).join(",") || "none"}`);
  record("docker-gateway-principal-secret-exclusive", same(gatewayCredentialOwners, ["backup-scheduler", "docker-operation-gateway"]), `owners=${gatewayCredentialOwners.join(",") || "none"}`);
  record("docker-gateway-no-remote-docker-host", !gatewayEnvironment.DOCKER_HOST, `DOCKER_HOST=${gatewayEnvironment.DOCKER_HOST || "unset"}`);

  const scheduler = services["backup-scheduler"] || {};
  const schedulerEnvironment = object(scheduler.environment);
  record("scheduler-uses-typed-gateway", schedulerEnvironment.PLATFORM_DOCKER_GATEWAY_URL === "http://docker-operation-gateway:8787", `gateway=${schedulerEnvironment.PLATFORM_DOCKER_GATEWAY_URL || "unset"}`);
  record("scheduler-has-no-docker-api", !schedulerEnvironment.DOCKER_HOST && !schedulerEnvironment.DOCKER_API_VERSION, `DOCKER_HOST=${schedulerEnvironment.DOCKER_HOST || "unset"}`);
  record("scheduler-principal-secret", secretNames(scheduler).includes(gatewayCredential) && schedulerEnvironment.BACKUP_SCHEDULER_DOCKER_GATEWAY_TOKEN_FILE === `/run/secrets/${gatewayCredential}`, `secrets=${secretNames(scheduler).join(",") || "none"}`);

  record("socket-network-internal", networks.platform_docker_control?.internal === true, `internal=${networks.platform_docker_control?.internal === true}`);
  const socketMembers = Object.entries(services)
    .filter(([, service]) => networkNames(service).includes("platform_docker_control"))
    .map(([name]) => name)
    .sort();
  record("socket-network-members", same(socketMembers, ["backup-scheduler", "docker-operation-gateway"]), `members=${socketMembers.join(",") || "none"}`);

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

function secretNames(service) {
  return (service?.secrets || []).map((secret) => typeof secret === "string" ? secret : String(secret?.source || ""));
}

function stableId(value) {
  return String(value).replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").toLowerCase();
}

function same(left, right) {
  return JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}
