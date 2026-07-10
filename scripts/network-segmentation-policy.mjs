const CORE_INTERNAL_NETWORKS = [
  "platform_edge",
  "platform_routing",
  "platform_db_admin",
  "platform_postgres",
  "platform_cache",
  "platform_bus",
  "platform_storage",
  "platform_observability",
  "platform_docker_control",
];

const ZONE_CORE_SERVICE = new Map([
  ["ingress", "project-router"],
  ["postgres", "postgres"],
  ["cache", "redis"],
  ["bus", "nats"],
  ["identity", "keycloak"],
  ["storage", "minio"],
  ["observability", "prometheus"],
]);

export function evaluateNetworkSegmentation(config) {
  const failures = [];
  const checks = [];
  const services = object(config?.services);
  const networks = object(config?.networks);
  const serviceNetworks = new Map(Object.entries(services).map(([name, service]) => [name, networkNames(service)]));
  const networkMembers = new Map(Object.keys(networks).map((name) => [name, []]));
  for (const [service, names] of serviceNetworks) {
    for (const network of names) {
      if (!networkMembers.has(network)) networkMembers.set(network, []);
      networkMembers.get(network).push(service);
    }
  }

  const record = (id, passed, detail) => {
    checks.push({ id, status: passed ? "passed" : "failed", detail });
    if (!passed) failures.push(`${id}: ${detail}`);
  };
  const shared = (left, right) => {
    const rightNetworks = new Set(serviceNetworks.get(right) || []);
    return (serviceNetworks.get(left) || []).filter((network) => rightNetworks.has(network));
  };
  const requireShared = (id, left, right, expected) => {
    const actual = shared(left, right);
    record(id, actual.includes(expected), `${left}<->${right} shared=${actual.join(",") || "none"}; required=${expected}`);
  };
  const requireDenied = (id, left, right) => {
    const actual = shared(left, right);
    record(id, actual.length === 0, `${left}<->${right} shared=${actual.join(",") || "none"}`);
  };

  for (const network of CORE_INTERNAL_NETWORKS) {
    record(`internal-${network}`, networks[network]?.internal === true, `${network} internal=${networks[network]?.internal === true}`);
  }
  record("egress-platform", networks.platform_egress?.internal !== true && networks.platform_egress?.enable_ipv6 !== true, "platform_egress allows IPv4 outbound routing with IPv6 disabled");

  const flatMembers = [...serviceNetworks].filter(([, names]) => names.includes("enterprise_net")).map(([name]) => name);
  record("legacy-flat-network-unused", flatMembers.length === 0, `enterprise_net members=${flatMembers.join(",") || "none"}`);
  requireShared("edge-waf-traefik", "waf", "traefik", "platform_edge");
  requireShared("routing-traefik-router", "traefik", "project-router", "platform_routing");
  requireShared("routing-traefik-control", "traefik", "control-center", "platform_routing");
  requireShared("db-admin-control-postgres", "control-center", "postgres", "platform_db_admin");
  requireShared("db-admin-control-mariadb", "control-center", "mariadb", "platform_db_admin");
  requireShared("observability-prometheus-loki", "prometheus", "loki", "platform_observability");
  requireShared("observability-prometheus-alertmanager", "prometheus", "alertmanager", "platform_observability");
  requireShared("observability-alertmanager-dispatcher", "alertmanager", "platform-alert-dispatcher", "platform_observability");
  requireShared("docker-control-scheduler-proxy", "backup-scheduler", "docker-socket-proxy", "platform_docker_control");
  const socketMembers = [...(networkMembers.get("platform_docker_control") || [])].sort();
  record("members-platform-docker-control", same(socketMembers, ["backup-scheduler", "docker-socket-proxy"]), `members=${socketMembers.join(",") || "none"}`);

  const workloads = new Map();
  for (const [name, service] of Object.entries(services)) {
    const workloadId = String(service?.labels?.["com.platform.workload-id"] || "");
    if (!workloadId) continue;
    if (!workloads.has(workloadId)) workloads.set(workloadId, []);
    workloads.get(workloadId).push(name);
    const prefix = `${workloadId.replaceAll("-", "_")}_`;
    const foreign = (serviceNetworks.get(name) || []).filter((network) => !network.startsWith(prefix));
    record(`workload-dedicated-networks-${name}`, foreign.length === 0, `${name} foreign=${foreign.join(",") || "none"}`);
    requireDenied(`deny-${name}-docker-socket-proxy`, name, "docker-socket-proxy");
  }

  for (const [network, members] of networkMembers) {
    const workloadMembers = members.filter((name) => services[name]?.labels?.["com.platform.workload-id"]);
    if (workloadMembers.length === 0) continue;
    const ids = [...new Set(workloadMembers.map((name) => String(services[name].labels["com.platform.workload-id"])))];
    record(`single-owner-${network}`, ids.length === 1, `${network} workloadIds=${ids.join(",")}`);
    if (ids.length !== 1) continue;
    const prefix = `${ids[0].replaceAll("-", "_")}_`;
    const zone = network.startsWith(prefix) ? network.slice(prefix.length) : "foreign";
    const coreMembers = members.filter((name) => !workloadMembers.includes(name)).sort();
    if (zone === "egress") {
      record(`workload-egress-${network}`, networks[network]?.internal !== true && networks[network]?.enable_ipv6 !== true && coreMembers.length === 0, `${network} core=${coreMembers.join(",") || "none"}`);
    } else {
      const expectedCore = ZONE_CORE_SERVICE.get(zone);
      record(`workload-internal-${network}`, networks[network]?.internal === true, `${network} internal=${networks[network]?.internal === true}`);
      record(`workload-zone-core-${network}`, Boolean(expectedCore) && same(coreMembers, [expectedCore]), `${network} zone=${zone} core=${coreMembers.join(",") || "none"}`);
    }
  }

  const workloadEntries = [...workloads.entries()];
  for (let left = 0; left < workloadEntries.length; left += 1) {
    for (let right = left + 1; right < workloadEntries.length; right += 1) {
      for (const first of workloadEntries[left][1]) {
        for (const second of workloadEntries[right][1]) requireDenied(`deny-cross-workload-${first}-${second}`, first, second);
      }
    }
  }
  for (const target of ["postgres", "mariadb", "redis", "nats", "minio", "prometheus", "loki", "alertmanager"]) {
    requireDenied(`deny-router-${target}`, "project-router", target);
  }

  const pgAdmin = services.phppgadmin || {};
  record("phppgadmin-image-pinned", /@sha256:[a-f0-9]{64}$/.test(String(pgAdmin.image || "")), "phpPgAdmin image must use an immutable digest");
  record("phppgadmin-admin-networks", same([...(serviceNetworks.get("phppgadmin") || [])].sort(), ["platform_db_admin", "platform_routing"]), `networks=${(serviceNetworks.get("phppgadmin") || []).sort().join(",")}`);
  record("router-lock-contract", String(services["project-router"]?.environment?.PROJECT_ROUTER_WORKLOAD_LOCK_FILE || "").startsWith("/var/www/project-state/"), "project-router uses the verified workload lock");

  return {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    status: failures.length ? "failed" : "passed",
    summary: {
      checks: checks.length,
      passed: checks.filter((item) => item.status === "passed").length,
      failed: failures.length,
      services: Object.keys(services).length,
      networks: Object.keys(networks).length,
      hostedWorkloads: workloads.size,
    },
    checks,
    failures,
    topology: Object.fromEntries([...networkMembers.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([network, members]) => [network, [...members].sort()])),
  };
}

function object(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function networkNames(service) {
  if (Array.isArray(service?.networks)) return service.networks.map(String);
  return Object.keys(object(service?.networks));
}

function same(left, right) {
  return JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}
