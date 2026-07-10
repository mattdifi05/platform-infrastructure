const APP_NETWORKS = [
  { service: "php-anniversary", ingress: "app_php_anniversary_ingress", data: "app_php_anniversary_data", egress: "app_php_anniversary_egress", database: "mariadb" },
  { service: "php-fiplatform", ingress: "app_php_fiplatform_ingress", data: "app_php_fiplatform_data", egress: "app_php_fiplatform_egress", database: "mariadb" },
  { service: "php-matthewdifilippo", ingress: "app_php_matthewdifilippo_ingress", data: "app_php_matthewdifilippo_data", egress: "app_php_matthewdifilippo_egress", database: "mariadb" },
  { service: "php-stream", ingress: "app_php_stream_ingress", data: "app_php_stream_data", egress: "app_php_stream_egress", database: "mariadb" },
  { service: "php-workcalendar", ingress: "app_php_workcalendar_ingress", data: "app_php_workcalendar_data", egress: "app_php_workcalendar_egress", database: "mariadb" },
  { service: "node-account", ingress: "app_node_account_ingress", data: "app_node_account_data", egress: "app_node_account_egress", database: "postgres" },
  { service: "node-ui", ingress: "app_node_ui_ingress", data: "", egress: "app_node_ui_egress", database: "" },
];

const INTERNAL_NETWORKS = [
  "platform_edge",
  "platform_routing",
  "platform_db_admin",
  "platform_postgres",
  "platform_cache",
  "platform_bus",
  "platform_storage",
  "platform_observability",
  "platform_docker_control",
  ...APP_NETWORKS.flatMap((item) => [item.ingress, item.data].filter(Boolean)),
];

export function evaluateNetworkSegmentation(config) {
  const failures = [];
  const checks = [];
  const services = config?.services && typeof config.services === "object" ? config.services : {};
  const networks = config?.networks && typeof config.networks === "object" ? config.networks : {};
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
  const membersEqual = (network, expected) => {
    const actual = [...(networkMembers.get(network) || [])].sort();
    const wanted = [...expected].sort();
    return actual.length === wanted.length && actual.every((item, index) => item === wanted[index]);
  };
  const sharedNetworks = (left, right) => {
    const rightNetworks = new Set(serviceNetworks.get(right) || []);
    return (serviceNetworks.get(left) || []).filter((network) => rightNetworks.has(network));
  };
  const requireShared = (id, left, right, expected) => {
    const shared = sharedNetworks(left, right);
    record(id, shared.includes(expected), `${left}<->${right} shared=${shared.join(",") || "none"}; required=${expected}`);
  };
  const requireDenied = (id, left, right) => {
    const shared = sharedNetworks(left, right);
    record(id, shared.length === 0, `${left}<->${right} shared=${shared.join(",") || "none"}`);
  };

  for (const network of INTERNAL_NETWORKS) {
    record(`internal-${network}`, networks[network]?.internal === true, `${network} internal=${networks[network]?.internal === true}`);
  }
  for (const network of ["platform_egress", ...APP_NETWORKS.map((item) => item.egress)]) {
    record(`egress-${network}`, networks[network]?.internal !== true && networks[network]?.enable_ipv6 !== true, `${network} allows IPv4 outbound routing, has IPv6 disabled and does not share application peers`);
  }
  for (const service of ["traefik", "control-center"]) {
    record(`provider-egress-${service}`, (serviceNetworks.get(service) || []).includes("platform_egress"), `${service} can reach required ACME/provider endpoints through platform_egress`);
  }

  const flatServices = [...serviceNetworks.entries()].filter(([, names]) => names.includes("enterprise_net")).map(([name]) => name);
  record("legacy-flat-network-unused", flatServices.length === 0, `enterprise_net members=${flatServices.join(",") || "none"}`);

  requireShared("edge-waf-traefik", "waf", "traefik", "platform_edge");
  requireShared("routing-traefik-router", "traefik", "project-router", "platform_routing");
  requireShared("routing-traefik-control", "traefik", "control-center", "platform_routing");
  requireShared("routing-traefik-backend", "traefik", "backend", "platform_routing");
  requireShared("db-admin-control-postgres", "control-center", "postgres", "platform_db_admin");
  requireShared("db-admin-control-mariadb", "control-center", "mariadb", "platform_db_admin");
  requireShared("observability-prometheus-loki", "prometheus", "loki", "platform_observability");
  requireShared("observability-prometheus-alertmanager", "prometheus", "alertmanager", "platform_observability");
  requireShared("observability-alertmanager-receiver", "alertmanager", "worker-notifications", "platform_observability");
  record("members-platform-docker-control", membersEqual("platform_docker_control", ["backup-scheduler", "docker-socket-proxy"]), `platform_docker_control members=${(networkMembers.get("platform_docker_control") || []).sort().join(",")}`);
  requireShared("docker-control-scheduler-proxy", "backup-scheduler", "docker-socket-proxy", "platform_docker_control");

  for (const app of APP_NETWORKS) {
    record(`members-${app.ingress}`, membersEqual(app.ingress, ["project-router", app.service]), `${app.ingress} members=${(networkMembers.get(app.ingress) || []).sort().join(",")}`);
    requireShared(`router-${app.service}`, "project-router", app.service, app.ingress);
    record(`members-${app.egress}`, membersEqual(app.egress, [app.service]), `${app.egress} members=${(networkMembers.get(app.egress) || []).sort().join(",")}`);
    if (app.data) {
      record(`members-${app.data}`, membersEqual(app.data, [app.service, app.database]), `${app.data} members=${(networkMembers.get(app.data) || []).sort().join(",")}`);
      requireShared(`database-${app.service}`, app.service, app.database, app.data);
    }
    for (const admin of ["prometheus", "loki", "alertmanager", "control-center", "phpmyadmin", "phppgadmin"]) {
      requireDenied(`deny-${app.service}-${admin}`, app.service, admin);
    }
    requireDenied(`deny-${app.service}-docker-socket-proxy`, app.service, "docker-socket-proxy");
  }

  for (let index = 0; index < APP_NETWORKS.length; index += 1) {
    for (let other = index + 1; other < APP_NETWORKS.length; other += 1) {
      requireDenied(`deny-cross-app-${APP_NETWORKS[index].service}-${APP_NETWORKS[other].service}`, APP_NETWORKS[index].service, APP_NETWORKS[other].service);
    }
  }
  for (const target of ["postgres", "mariadb", "prometheus", "loki", "alertmanager"] ) {
    requireDenied(`deny-router-${target}`, "project-router", target);
  }

  const pgAdmin = services.phppgadmin || {};
  record("phppgadmin-image-pinned", /@sha256:[a-f0-9]{64}$/.test(String(pgAdmin.image || "")), "phpPgAdmin image must use an immutable digest");
  const pgAdminNetworks = [...(serviceNetworks.get("phppgadmin") || [])].sort();
  record("phppgadmin-admin-networks", JSON.stringify(pgAdminNetworks) === JSON.stringify(["platform_db_admin", "platform_routing"]), `phppgadmin networks=${pgAdminNetworks.join(",")}`);

  const routerAllowlist = String(services["project-router"]?.environment?.PROJECT_ROUTER_ALLOWED_UPSTREAMS || "");
  const expectedRouterServices = APP_NETWORKS.map((item) => item.service);
  record(
    "router-service-allowlist",
    expectedRouterServices.every((service) => new RegExp(`(?:^|,)\\s*${escapeRegExp(service)}:[0-9]+(?:\\s*,|$)`).test(routerAllowlist))
      && !/:\/\//.test(routerAllowlist),
    "router allowlist contains exact service-id:port entries and no URLs",
  );

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    status: failures.length ? "failed" : "passed",
    summary: {
      checks: checks.length,
      passed: checks.filter((item) => item.status === "passed").length,
      failed: failures.length,
      services: Object.keys(services).length,
      networks: Object.keys(networks).length,
      hostedApplications: APP_NETWORKS.length,
    },
    checks,
    failures,
    topology: Object.fromEntries([...networkMembers.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([network, members]) => [network, [...members].sort()])),
  };
}

function networkNames(service) {
  if (Array.isArray(service?.networks)) return service.networks.map(String);
  if (service?.networks && typeof service.networks === "object") return Object.keys(service.networks);
  return [];
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
