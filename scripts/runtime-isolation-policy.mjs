const REQUIRED_READ_ONLY = new Set([
  "control-center",
  "project-router",
  "platform-alert-dispatcher",
  "backup-scheduler",
  "docker-action-activation-sidecar",
  "docker-action-broker",
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
  const namedVolumes = object(config?.volumes);
  const topLevelSecrets = object(config?.secrets);
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
    record(`workload-no-supplemental-groups-${name}`, !(service.group_add?.length > 0), `${name} groupAdd=${service.group_add || "none"}`);
    const mounts = volumes(service);
    for (const target of FORBIDDEN_WORKLOAD_TARGETS) {
      const exposed = mounts.some((mount) => mount.target === target || mount.target.startsWith(`${target}/`));
      record(`workload-deny-mount-${stableId(target)}-${name}`, !exposed, `${name} target=${target} exposed=${exposed}`);
    }
    const binds = mounts.filter((mount) => mount.type === "bind");
    record(`workload-no-bind-mounts-${name}`, binds.length === 0, `${name} binds=${binds.map((mount) => mount.target).join(",") || "none"}`);
    for (const mount of mounts.filter((item) => item.type === "volume")) {
      const declaration = object(namedVolumes[mount.source]);
      const aliased = declaration.external === true || declaration.name || declaration.driver_opts || (declaration.driver && declaration.driver !== "local");
      record(`workload-volume-no-host-alias-${stableId(mount.source)}-${name}`, !aliased, `${name} volume=${mount.source} declaration=${JSON.stringify(declaration)}`);
    }
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
  record("raw-socket-single-owner", rawSocketOwners.length === 1 && rawSocketOwners[0] === "docker-action-broker", `owners=${rawSocketOwners.join(",") || "none"}`);

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

  const dockerBroker = services["docker-action-broker"] || {};
  const dockerBrokerEnvironment = object(dockerBroker.environment);
  const dockerBrokerMounts = volumes(dockerBroker);
  const brokerImage = String(dockerBroker.image || "");
  record("docker-broker-immutable-image", /^[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[a-f0-9]{64}$/.test(brokerImage) && !dockerBroker.build, `image=${brokerImage || "unset"} build=${Boolean(dockerBroker.build)}`);
  record("docker-broker-host-private", dockerBroker.network_mode === "none" && networkNames(dockerBroker).length === 0
    && !(dockerBroker.ports?.length > 0) && !(dockerBroker.expose?.length > 0), `networkMode=${dockerBroker.network_mode || "unset"}`);
  record("docker-broker-no-candidate-code", !dockerBrokerMounts.some((mount) => ["/infra", "/opt/platform-docker-broker", "/opt/platform-docker-worker"].includes(mount.target)), `mounts=${dockerBrokerMounts.map((mount) => mount.target).join(",")}`);
  record("docker-broker-no-remote-host", !dockerBrokerEnvironment.DOCKER_HOST && !dockerBrokerEnvironment.DOCKER_API_VERSION, `DOCKER_HOST=${dockerBrokerEnvironment.DOCKER_HOST || "unset"}`);
  record("docker-broker-minimum-process-authority", dockerBroker.read_only === true && dockerBroker.cap_drop?.includes("ALL")
    && !(dockerBroker.cap_add?.length > 0) && dockerBroker.security_opt?.includes("no-new-privileges:true"), `capDrop=${dockerBroker.cap_drop || "unset"}`);
  record("docker-broker-no-supplemental-groups", !(dockerBroker.group_add?.length > 0), `groupAdd=${dockerBroker.group_add || "none"}`);
  const exactBrokerTargets = [
    "/var/run/docker.sock",
    "/run/platform/docker-action-broker",
    "/var/lib/platform/docker-action-broker",
    "/run/platform/docker-action-activation/by-bundle-sha256",
    "/run/platform/docker-action-trust/runtime-intent.json",
    "/run/platform/docker-action-trust/active-receipt.json",
  ];
  record("docker-broker-exact-mount-targets", same(dockerBrokerMounts.map((mount) => mount.target), exactBrokerTargets), `targets=${dockerBrokerMounts.map((mount) => mount.target).join(",")}`);
  const rawSocketMount = dockerBrokerMounts.find((mount) => mount.target === "/var/run/docker.sock");
  record("docker-broker-exact-raw-socket", rawSocketMount?.type === "bind"
    && rawSocketMount.source === "/var/run/docker.sock" && rawSocketMount.readOnly === true, `mount=${JSON.stringify(rawSocketMount || {})}`);
  const socketVolume = object(namedVolumes.docker_action_broker_socket);
  const stateVolume = object(namedVolumes.docker_action_broker_state);
  const activationCasVolume = object(namedVolumes.docker_action_activation_cas);
  record("docker-broker-socket-volume-not-aliased", Object.keys(socketVolume).length === 0, `declaration=${JSON.stringify(socketVolume)}`);
  record("docker-broker-state-volume-not-aliased", Object.keys(stateVolume).length === 0, `declaration=${JSON.stringify(stateVolume)}`);
  record("docker-broker-activation-cas-volume-not-aliased", Object.keys(activationCasVolume).length === 0, `declaration=${JSON.stringify(activationCasVolume)}`);
  const activationCasMount = dockerBrokerMounts.find((mount) => mount.target === "/run/platform/docker-action-activation/by-bundle-sha256");
  record("docker-broker-activation-cas-read-only", activationCasMount?.type === "volume"
    && activationCasMount.source === "docker_action_activation_cas" && activationCasMount.readOnly, `mount=${JSON.stringify(activationCasMount || {})}`);
  const trustMounts = dockerBrokerMounts.filter((mount) => mount.target.startsWith("/run/platform/docker-action-trust/"));
  record("docker-broker-trust-inputs-read-only", trustMounts.length === 2 && trustMounts.every((mount) => mount.type === "bind" && mount.readOnly
    && mount.source.startsWith("/srv/platform/trust/")), `trust=${trustMounts.map((mount) => `${mount.source}:${mount.readOnly}`).join(",")}`);

  const capabilitySecrets = ["docker_action_backup_prune_plan", "docker_action_evidence_runtime_snapshot"];
  const trustSecret = "docker_action_runtime_intent_trust_key";
  for (const secret of [...capabilitySecrets, trustSecret]) {
    const declaration = object(topLevelSecrets[secret]);
    const owners = Object.entries(services).filter(([, service]) => secretNames(service).includes(secret)).map(([name]) => name).sort();
    const expectedOwners = secret === trustSecret ? ["docker-action-broker"] : ["backup-scheduler", "docker-action-broker"];
    record(`docker-broker-secret-source-${secret}`, declaration.file === `./secrets/${secret}.txt`
      && !declaration.external && !declaration.name && !declaration.driver_opts, `declaration=${JSON.stringify(declaration)}`);
    record(`docker-broker-secret-owners-${secret}`, same(owners, expectedOwners), `owners=${owners.join(",") || "none"}`);
    for (const owner of owners) {
      const mount = secretMount(services[owner], secret);
      record(`docker-broker-secret-mode-${secret}-${owner}`, mount?.uid === "0" && mount?.gid === "0" && Number(mount?.mode) === 0o400, `mount=${JSON.stringify(mount || {})}`);
    }
  }

  const scheduler = services["backup-scheduler"] || {};
  const schedulerEnvironment = object(scheduler.environment);
  const schedulerMounts = volumes(scheduler);
  record("scheduler-uses-local-action-socket", schedulerEnvironment.DOCKER_ACTION_BROKER_SOCKET === "/run/platform/docker-action-broker/broker.sock"
    && schedulerMounts.some((mount) => mount.source === "docker_action_broker_socket" && mount.target === "/run/platform/docker-action-broker" && mount.readOnly), `socket=${schedulerEnvironment.DOCKER_ACTION_BROKER_SOCKET || "unset"}`);
  record("scheduler-binds-final-render", /^[a-f0-9]{64}$/.test(String(schedulerEnvironment.DOCKER_ACTION_COMBINED_RENDER_SHA256 || "")),
    `combinedRenderSha256=${schedulerEnvironment.DOCKER_ACTION_COMBINED_RENDER_SHA256 || "unset"}`);
  record("scheduler-has-no-docker-api", !schedulerEnvironment.DOCKER_HOST && !schedulerEnvironment.DOCKER_API_VERSION, `DOCKER_HOST=${schedulerEnvironment.DOCKER_HOST || "unset"}`);
  record("scheduler-no-trust-documents", !schedulerMounts.some((mount) => mount.target.startsWith("/run/platform/docker-action-trust/")), `targets=${schedulerMounts.map((mount) => mount.target).join(",")}`);
  record("scheduler-no-supplemental-groups", !(scheduler.group_add?.length > 0), `groupAdd=${scheduler.group_add || "none"}`);

  const activationSidecar = services["docker-action-activation-sidecar"] || {};
  const activationSidecarMounts = volumes(activationSidecar);
  const activationSidecarImage = String(activationSidecar.image || "");
  record("activation-sidecar-immutable-provider-image", /^[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[a-f0-9]{64}$/.test(activationSidecarImage)
    && !activationSidecar.build, `image=${activationSidecarImage || "unset"} build=${Boolean(activationSidecar.build)}`);
  record("activation-sidecar-host-private", activationSidecar.network_mode === "none"
    && networkNames(activationSidecar).length === 0 && !(activationSidecar.ports?.length > 0)
    && !(activationSidecar.expose?.length > 0), `networkMode=${activationSidecar.network_mode || "unset"}`);
  record("activation-sidecar-minimum-authority", activationSidecar.read_only === true
    && activationSidecar.cap_drop?.includes("ALL") && !(activationSidecar.cap_add?.length > 0)
    && !(activationSidecar.group_add?.length > 0)
    && activationSidecar.security_opt?.includes("no-new-privileges:true"), `capDrop=${activationSidecar.cap_drop || "unset"}`);
  record("activation-sidecar-fixed-entrypoint", same(activationSidecar.entrypoint || [], ["/opt/provider-activation/materialize-dsse-cas"]),
    `entrypoint=${activationSidecar.entrypoint || "unset"}`);
  record("activation-sidecar-exact-mounts", activationSidecarMounts.length === 2
    && activationSidecarMounts.some((mount) => mount.type === "bind"
      && mount.source.startsWith("/srv/platform/provider-activation/")
      && mount.target === "/run/platform/provider-activation/inbox" && mount.readOnly)
    && activationSidecarMounts.some((mount) => mount.type === "volume"
      && mount.source === "docker_action_activation_cas"
      && mount.target === "/run/platform/docker-action-activation/by-bundle-sha256" && !mount.readOnly),
  `mounts=${activationSidecarMounts.map((mount) => `${mount.source}:${mount.target}:${mount.readOnly}`).join(",")}`);
  record("activation-sidecar-no-docker-control", !activationSidecarMounts.some((mount) => mount.source === "/var/run/docker.sock"
    || mount.target === "/var/run/docker.sock" || mount.target === "/infra"), `targets=${activationSidecarMounts.map((mount) => mount.target).join(",")}`);

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

function secretMount(service, name) {
  const value = (service?.secrets || []).find((secret) => typeof secret === "object" && String(secret?.source || "") === name);
  if (!value) return null;
  return {
    source: String(value.source || ""),
    target: String(value.target || value.source || ""),
    uid: String(value.uid ?? ""),
    gid: String(value.gid ?? ""),
    mode: Number(value.mode),
  };
}

function stableId(value) {
  return String(value).replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").toLowerCase();
}

function same(left, right) {
  return JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}
