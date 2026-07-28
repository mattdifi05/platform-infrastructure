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

const RUNTIME_IDENTITY_LABELS = [
  "com.platform.runtime.candidate-id",
  "com.platform.runtime.commit",
  "com.platform.runtime.tree",
  "com.platform.runtime.deployment-id",
  "com.platform.runtime.source-render-sha256",
  "com.platform.runtime.workload-lock-sha256",
];
const WORKLOAD_SERVICE_KEYS = new Set([
  "image", "command", "entrypoint", "working_dir", "environment", "volumes", "secrets", "networks",
  "healthcheck", "read_only", "init", "restart", "security_opt", "cap_drop", "cap_add", "user",
  "logging", "pids_limit", "cpu_shares", "blkio_config", "ulimits", "cpus", "mem_limit",
  "memswap_limit", "mem_reservation", "labels", "depends_on",
]);
const PLATFORM_DEPENDENCIES = new Set(["postgres", "redis", "nats", "minio", "keycloak", "alertmanager"]);
const ACCELERATOR_ENVIRONMENT_NAMES = new Set([
  "CUDA_VISIBLE_DEVICES", "HIP_VISIBLE_DEVICES", "ONEAPI_DEVICE_SELECTOR",
  "ROCR_VISIBLE_DEVICES", "SYCL_DEVICE_FILTER", "ZE_AFFINITY_MASK",
]);

export function evaluateRuntimeIsolation(config, options = {}) {
  const services = object(config?.services);
  const networks = object(config?.networks);
  const protectedNetworkNames = new Set(Array.isArray(options.protectedNetworkNames)
    ? options.protectedNetworkNames.map(String)
    : Object.entries(networks)
      .filter(([, definition]) => typeof definition?.labels?.["com.platform.trust-zone"] === "string")
      .map(([name]) => name));
  const projectName = String(options.projectName ?? "");
  const maxMemoryBytes = integer(options.maxMemoryBytes ?? 13_500 * 1024 * 1024);
  const maxWorkloadMemoryBytes = integer(options.maxWorkloadMemoryBytes ?? 8_000 * 1024 * 1024);
  const runtimeIdentityRequired = options.runtimeIdentity != null;
  const runtimeIdentity = object(options.runtimeIdentity);
  const runtimeIdentityValid = !runtimeIdentityRequired || (
    JSON.stringify(Object.keys(runtimeIdentity).sort()) === JSON.stringify([...RUNTIME_IDENTITY_LABELS].sort())
    && /^[a-f0-9]{64}$/.test(String(runtimeIdentity[RUNTIME_IDENTITY_LABELS[0]] || ""))
    && /^([a-f0-9]{40}|[a-f0-9]{64})$/.test(String(runtimeIdentity[RUNTIME_IDENTITY_LABELS[1]] || ""))
    && /^([a-f0-9]{40}|[a-f0-9]{64})$/.test(String(runtimeIdentity[RUNTIME_IDENTITY_LABELS[2]] || ""))
    && /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(String(runtimeIdentity[RUNTIME_IDENTITY_LABELS[3]] || ""))
    && /^[a-f0-9]{64}$/.test(String(runtimeIdentity[RUNTIME_IDENTITY_LABELS[4]] || ""))
    && /^[a-f0-9]{64}$/.test(String(runtimeIdentity[RUNTIME_IDENTITY_LABELS[5]] || ""))
  );
  const checks = [];
  const failures = [];
  const record = (id, passed, detail) => {
    checks.push({ id, status: passed ? "passed" : "failed", detail });
    if (!passed) failures.push(`${id}: ${detail}`);
  };
  record("workload-runtime-identity-input", runtimeIdentityValid, `required=${runtimeIdentityRequired} valid=${runtimeIdentityValid}`);

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
  const workloadIdentity = canonicalWorkloadIdentity(config, workloadIds);
  record(
    "workload-id-prefix-disjoint",
    workloadIdentity.prefixDisjoint,
    `ids=${[...workloadIds].sort().join(",") || "none"}`,
  );
  record(
    "workload-canonical-resource-owners",
    workloadIdentity.conflicts.length === 0,
    `conflicts=${workloadIdentity.conflicts.join(",") || "none"}`,
  );
  record(
    "workload-project-name-bound",
    workloadServices.length === 0 || (/^[a-z0-9][a-z0-9_-]*$/.test(projectName) && config?.name === projectName),
    `expected=${projectName || "unset"} rendered=${config?.name || "unset"}`,
  );
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
    const runtimeLabelKeys = Object.keys(object(service.labels)).filter((label) => label.startsWith("com.platform.runtime.")).sort();
    const runtimeIdentityMatches = !runtimeIdentityRequired || (runtimeIdentityValid
      && JSON.stringify(runtimeLabelKeys) === JSON.stringify([...RUNTIME_IDENTITY_LABELS].sort())
      && RUNTIME_IDENTITY_LABELS.every((label) => service.labels?.[label] === runtimeIdentity[label]));
    record(`workload-runtime-identity-${name}`, runtimeIdentityMatches, `${name} labels=${runtimeLabelKeys.join(",") || "none"}`);
    record(
      `workload-name-prefix-${name}`,
      workloadIdentity.services.get(name) === workloadId,
      `${name} workload=${workloadId} canonicalOwner=${workloadIdentity.services.get(name) || "none"}`,
    );
    record(`workload-role-${name}`, ["api", "web", "worker", "scheduled-worker"].includes(role), `${name} role=${role}`);
    record(`workload-numeric-user-${name}`, /^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$/.test(String(service.user || "")), `${name} user=${service.user || "unset"}`);
    record(`workload-private-pid-${name}`, !Object.hasOwn(service, "pid"), `${name} pid=${service.pid ?? "private"}`);
    record(`workload-gated-restart-${name}`, service.restart === "no", `${name} restart=${service.restart ?? "unset"}`);
    record(`workload-no-swap-${name}`, bytes(service.memswap_limit) === bytes(service.mem_limit), `${name} memswap=${bytes(service.memswap_limit)} memory=${bytes(service.mem_limit)}`);
    const oomControls = ["oom_kill_disable", "oom_score_adj", "mem_swappiness"].filter((field) => Object.hasOwn(service, field));
    record(`workload-no-oom-overrides-${name}`, oomControls.length === 0, `${name} oomControls=${oomControls.join(",") || "none"}`);
    const joinedProtectedNetworks = networkNames(service).filter((network) => protectedNetworkNames.has(network));
    record(`workload-no-protected-network-${name}`, joinedProtectedNetworks.length === 0, `${name} protectedNetworks=${joinedProtectedNetworks.join(",") || "none"}`);
    const foreignNetworkIdentities = networkNames(service).filter((network) => {
      const attachment = Array.isArray(service.networks) ? null : service.networks?.[network];
      const definition = object(networks[network]);
      const attachmentIsPlain = attachment == null
        || (typeof attachment === "object" && !Array.isArray(attachment) && Object.keys(attachment).length === 0);
      return protectedNetworkNames.has(network)
        || workloadIdentity.networks.get(network) !== workloadId
        || !attachmentIsPlain
        || definition.external === true
        || definition.name !== `${projectName}_${network}`;
    });
    record(`workload-network-identity-${name}`, foreignNetworkIdentities.length === 0, `${name} foreignNetworks=${foreignNetworkIdentities.join(",") || "none"}`);
    const invalidNetworkTopologies = networkNames(service).filter((network) => {
      const definition = networks[network];
      const zone = workloadNetworkZone(network, workloadId);
      return !definition || typeof definition !== "object" || Array.isArray(definition)
        || JSON.stringify(Object.keys(definition).sort()) !== JSON.stringify(["internal", "name"])
        || definition.internal !== (zone !== "egress");
    });
    record(`workload-network-topology-${name}`, invalidNetworkTopologies.length === 0, `${name} invalidTopologies=${invalidNetworkTopologies.join(",") || "none"}`);
    record(
      `workload-bounded-local-logging-${name}`,
      JSON.stringify(service.logging) === JSON.stringify({ driver: "local", options: { "max-size": "10m", "max-file": "3" } }),
      `${name} logging=${JSON.stringify(service.logging ?? null)}`,
    );
    record(
      `workload-bounded-global-blkio-${name}`,
      JSON.stringify(Object.keys(object(service.blkio_config)).sort()) === JSON.stringify(["weight"]),
      `${name} blkioKeys=${Object.keys(object(service.blkio_config)).sort().join(",") || "none"}`,
    );
    record(
      `workload-exact-security-opt-${name}`,
      JSON.stringify(service.security_opt) === JSON.stringify(["no-new-privileges:true"]),
      `${name} securityOpt=${service.security_opt || "unset"}`,
    );
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
    record(`workload-no-label-file-${name}`, !Object.hasOwn(service, "label_file"), `${name} labelFile=${service.label_file ?? "none"}`);
    const explicitEnvironment = !Object.hasOwn(service, "environment")
      || (service.environment && typeof service.environment === "object" && !Array.isArray(service.environment)
        && Object.values(service.environment).every((value) => value != null));
    record(`workload-explicit-environment-${name}`, explicitEnvironment, `${name} environmentType=${Array.isArray(service.environment) ? "array" : typeof service.environment}`);
    const acceleratorEnvironment = Object.keys(object(service.environment))
      .filter((key) => key.startsWith("NVIDIA_") || ACCELERATOR_ENVIRONMENT_NAMES.has(key));
    record(`workload-no-accelerator-environment-${name}`, acceleratorEnvironment.length === 0, `${name} acceleratorEnvironment=${acceleratorEnvironment.join(",") || "none"}`);
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
    if (Object.hasOwn(object(service.deploy?.resources?.reservations), "generic_resources")) {
      acceleratorControls.push("deploy.resources.reservations.generic_resources");
    }
    record(`workload-no-accelerators-${name}`, acceleratorControls.length === 0, `${name} acceleratorControls=${acceleratorControls.join(",") || "none"}`);
    record(`workload-no-deploy-controls-${name}`, !Object.hasOwn(service, "deploy"), `${name} deploy=${JSON.stringify(service.deploy ?? null)}`);
    const healthcheck = object(service.healthcheck);
    const healthTest = Array.isArray(healthcheck.test) ? healthcheck.test : [];
    const exactHealthcheck = JSON.stringify(Object.keys(healthcheck).sort()) === JSON.stringify(["test"])
      && healthTest.length >= 2 && healthTest.length <= 16 && healthTest[0] === "CMD"
      && healthTest.slice(1).every((value) => typeof value === "string" && value.length > 0 && value.length <= 256 && !/[\0\r\n]/.test(value));
    record(`workload-exact-healthcheck-${name}`, exactHealthcheck, `${name} healthcheck=${JSON.stringify(service.healthcheck ?? null)}`);
    const ulimits = object(service.ulimits);
    const nofile = object(ulimits.nofile);
    const exactUlimits = JSON.stringify(Object.keys(ulimits).sort()) === JSON.stringify(["nofile"])
      && JSON.stringify(Object.keys(nofile).sort()) === JSON.stringify(["hard", "soft"])
      && integer(nofile.soft) >= 1024 && integer(nofile.hard) <= 65536 && integer(nofile.soft) <= integer(nofile.hard);
    record(`workload-exact-ulimits-${name}`, exactUlimits, `${name} ulimits=${JSON.stringify(service.ulimits ?? null)}`);
    const unsupportedServiceFields = Object.keys(service).filter((field) => !WORKLOAD_SERVICE_KEYS.has(field)).sort();
    record(`workload-closed-service-schema-${name}`, unsupportedServiceFields.length === 0, `${name} unsupported=${unsupportedServiceFields.join(",") || "none"}`);
    const dependencyEntries = Object.entries(object(service.depends_on));
    const invalidDependencies = dependencyEntries.filter(([dependency, condition]) => {
      const sameWorkload = workloadIdentity.services.get(dependency) === workloadId;
      const exactCondition = condition && typeof condition === "object" && !Array.isArray(condition)
        && Object.keys(condition).every((field) => ["condition", "required", "restart"].includes(field))
        && ["service_started", "service_healthy"].includes(condition.condition)
        && (!Object.hasOwn(condition, "required") || condition.required === true)
        && (!Object.hasOwn(condition, "restart") || condition.restart === false);
      return (!sameWorkload && !PLATFORM_DEPENDENCIES.has(dependency)) || !exactCondition;
    }).map(([dependency]) => dependency);
    const exactDependsOn = !Object.hasOwn(service, "depends_on")
      || (service.depends_on && typeof service.depends_on === "object" && !Array.isArray(service.depends_on)
        && invalidDependencies.length === 0);
    record(`workload-bounded-dependencies-${name}`, exactDependsOn, `${name} invalidDependencies=${invalidDependencies.join(",") || "none"}`);
    const secretGrants = (Array.isArray(service.secrets) ? service.secrets : [])
      .map((entry) => {
        const source = typeof entry === "string" ? entry : String(entry?.source || "");
        return {
          source,
          target: typeof entry === "string" ? entry : String(entry?.target || source),
        };
      });
    const foreignSecrets = secretGrants
      .map((grant) => grant.source)
      .filter((source) => {
        const definition = object(config?.secrets?.[source]);
        return workloadIdentity.secrets.get(source) !== workloadId
          || definition.external !== true
          || definition.name !== `${projectName}_${source}`;
      });
    record(`workload-owned-secrets-${name}`, foreignSecrets.length === 0, `${name} foreignSecrets=${foreignSecrets.join(",") || "none"}`);
    const secretTargets = new Map();
    const duplicateSecretTargets = new Set();
    for (const grant of secretGrants) {
      if (!grant.target || secretTargets.has(grant.target)) duplicateSecretTargets.add(grant.target || "<empty>");
      else secretTargets.set(grant.target, grant.source);
    }
    const invalidFileSecretBindings = Object.entries(object(service.environment))
      .filter(([key]) => key.endsWith("_FILE"))
      .filter(([, value]) => {
        const match = String(value).match(/^\/run\/secrets\/([a-z0-9][a-z0-9_-]*)$/);
        if (!match || duplicateSecretTargets.size > 0) return true;
        const source = secretTargets.get(match[1]);
        return !source || workloadIdentity.secrets.get(source) !== workloadId;
      })
      .map(([key]) => key);
    record(
      `workload-file-secret-bindings-${name}`,
      invalidFileSecretBindings.length === 0 && duplicateSecretTargets.size === 0,
      `${name} invalidBindings=${invalidFileSecretBindings.join(",") || "none"} duplicateTargets=${[...duplicateSecretTargets].join(",") || "none"}`,
    );
    const mounts = volumes(service);
    const exactVolumeMounts = mounts.length <= 1 && mounts.every((mount) => (
      mount.type === "volume"
      && workloadIdentity.volumes.get(mount.source) === workloadId
      && mount.target === "/data"
      && JSON.stringify(mount.rawKeys) === JSON.stringify(["source", "target", "type"])
    ));
    record(
      `workload-exact-volume-mounts-${name}`,
      exactVolumeMounts,
      `${name} mounts=${mounts.map((mount) => `${mount.type}:${mount.source}:${mount.target}:${mount.rawKeys.join(",")}`).join("|") || "none"}`,
    );
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
        return workloadIdentity.volumes.get(mount.source) !== workloadId
          || JSON.stringify(Object.keys(definition).sort()) !== JSON.stringify(["name"])
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
      return {
        type: parts[0]?.startsWith("/") || parts[0]?.startsWith(".") ? "bind" : "volume",
        source: parts[0] || "",
        target: parts[1] || "",
        readOnly: parts.slice(2).includes("ro"),
        rawKeys: ["string"],
      };
    }
    return {
      type: String(mount?.type || ""),
      source: String(mount?.source || ""),
      target: String(mount?.target || ""),
      readOnly: mount?.read_only === true,
      rawKeys: Object.keys(object(mount)).sort(),
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

const WORKLOAD_NETWORK_ZONES = new Set(["ingress", "postgres", "cache", "bus", "identity", "storage", "observability", "egress"]);

function canonicalWorkloadIdentity(config, workloadIds) {
  const services = object(config?.services);
  const ids = [...workloadIds].sort();
  let prefixDisjoint = new Set(ids).size === ids.length;
  for (let leftIndex = 0; leftIndex < ids.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < ids.length; rightIndex += 1) {
      const left = ids[leftIndex];
      const right = ids[rightIndex];
      if (left.startsWith(`${right}-`) || right.startsWith(`${left}-`)) prefixDisjoint = false;
    }
  }
  const conflicts = [];
  const addCanonicalOwner = (owners, kind, name, separator, required = false) => {
    if (!name) return;
    const candidates = ids.filter((id) => name.startsWith(`${separator(id)}`));
    if (candidates.length === 1) {
      owners.set(name, candidates[0]);
      return candidates[0];
    }
    if (required || candidates.length > 1) {
      conflicts.push(`${kind}:${name}:owners=${candidates.join("|") || "none"}`);
    }
    return null;
  };
  const identity = {
    prefixDisjoint,
    conflicts,
    services: new Map(),
    secrets: new Map(),
    volumes: new Map(),
    networks: new Map(),
  };
  for (const [serviceName, service] of Object.entries(services)) {
    const labelledOwner = String(service?.labels?.["com.platform.workload-id"] ?? "");
    const canonicalOwner = addCanonicalOwner(
      identity.services,
      "service",
      serviceName,
      (id) => `${id}-`,
      labelledOwner.length > 0,
    );
    if ((canonicalOwner || labelledOwner) && canonicalOwner !== labelledOwner) {
      conflicts.push(`service-label:${serviceName}:canonical=${canonicalOwner || "none"}:label=${labelledOwner || "none"}`);
    }
  }
  for (const secretName of Object.keys(object(config?.secrets))) {
    addCanonicalOwner(identity.secrets, "secret", secretName, (id) => `${id}-`);
  }
  for (const volumeName of Object.keys(object(config?.volumes))) {
    addCanonicalOwner(identity.volumes, "volume", volumeName, (id) => `${id.replaceAll("-", "_")}_`);
  }
  for (const networkName of Object.keys(object(config?.networks))) {
    addCanonicalOwner(identity.networks, "network", networkName, (id) => `${id.replaceAll("-", "_")}_`);
  }
  return identity;
}

function workloadNetworkZone(network, workloadId) {
  return network.slice(`${workloadId.replaceAll("-", "_")}_`.length);
}

function stableId(value) {
  return String(value).replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").toLowerCase();
}

function same(left, right) {
  return JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}
