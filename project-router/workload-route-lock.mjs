const SHA256 = /^[a-f0-9]{64}$/;
const WORKLOAD_ID = /^[a-z][a-z0-9-]{1,60}$/;
const SERVICE_NAME = /^[a-z][a-z0-9-]{1,62}$/;
const ROUTE_SLUG = /^[a-z][a-z0-9-]{1,62}$/;

export const HOSTED_ROUTE_LOCK_VERSION = 4;
export const HOSTED_ROUTE_VALIDATOR_VERSION = "hosted-contract-v4";
export const HOSTED_ROUTE_RAW_POLICY_VERSION = "hosted-raw-v3";
export const HOSTED_ROUTE_RAW_POLICY_CONTROLS = Object.freeze([
  "bind-bounded-dependencies", "bind-bounded-local-logging", "bind-closed-service-schema",
  "bind-exact-healthcheck", "bind-exact-security-opt", "bind-exact-ulimits", "bind-exact-volume-mounts", "bind-firewall-gated-restart",
  "bind-network-identity", "bind-network-topology",
  "bind-no-swap-oom-policy", "bind-owned-secret-aliases", "bind-owned-volume-driver",
  "bind-owned-volumes", "bind-platform-extension-records", "bind-private-pid-numeric-user",
  "deny-accelerator-environment",
  "deny-api-socket", "deny-compose-interpolation", "deny-deploy-controls", "deny-device-access",
  "deny-env-file", "deny-extends", "deny-file-configs", "deny-generic-resources",
  "deny-gpu-access", "deny-include", "deny-inline-configs", "deny-label-file",
  "deny-lifecycle-hooks", "deny-local-volume-options", "deny-providers",
  "deny-runtime-identity-labels", "deny-runtime-overrides", "deny-scaling",
  "deny-stop-grace-overrides", "deny-supplemental-groups", "deny-volumes-from",
]);

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function assertPrefixDisjointWorkloadIds(workloadIds) {
  const ordered = [...workloadIds].sort();
  if (new Set(ordered).size !== ordered.length) {
    throw new Error("Hosted workload declarations are invalid.");
  }
  for (let leftIndex = 0; leftIndex < ordered.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < ordered.length; rightIndex += 1) {
      const left = ordered[leftIndex];
      const right = ordered[rightIndex];
      if (left.startsWith(`${right}-`) || right.startsWith(`${left}-`)) {
        throw new Error(`Hosted workload ids are not prefix-disjoint: ${left}, ${right}.`);
      }
    }
  }
}

function deriveCanonicalRoutes(workloads) {
  const serviceNames = new Set();
  const routeSlugs = new Set();
  const routes = [];
  for (const workload of workloads) {
    if (!workload || typeof workload !== "object" || Array.isArray(workload)
        || !Array.isArray(workload.services) || workload.services.length === 0) {
      throw new Error("Hosted workload canonical route lineage has invalid workload declarations.");
    }
    for (const service of workload.services) {
      if (!service || typeof service !== "object" || Array.isArray(service)
          || !same(Object.keys(service).sort(), ["name", "role", "routes"])
          || typeof service.name !== "string" || !SERVICE_NAME.test(service.name)
          || !service.name.startsWith(`${workload.id}-`)
          || !new Set(["api", "web", "worker", "scheduled-worker"]).has(service.role)
          || !Array.isArray(service.routes)
          || serviceNames.has(service.name)) {
        throw new Error("Hosted workload canonical route lineage has invalid service declarations.");
      }
      serviceNames.add(service.name);
      if (service.routes.length > 0 && !new Set(["api", "web"]).has(service.role)) {
        throw new Error("Hosted workload canonical route lineage exposes a non-routable role.");
      }
      for (const route of service.routes) {
        if (!route || typeof route !== "object" || Array.isArray(route)
            || !same(Object.keys(route).sort(), ["port", "slug"])
            || typeof route.slug !== "string" || !ROUTE_SLUG.test(route.slug)
            || typeof route.port !== "number" || !Number.isInteger(route.port)
            || route.port < 1 || route.port > 65535
            || routeSlugs.has(route.slug)) {
          throw new Error("Hosted workload canonical route lineage has invalid route declarations.");
        }
        routeSlugs.add(route.slug);
        routes.push({
          workloadId: workload.id,
          slug: route.slug,
          service: service.name,
          port: route.port,
          upstream: `http://${service.name}:${route.port}`,
        });
      }
    }
  }
  return routes.sort((left, right) => (left.slug < right.slug ? -1 : (left.slug > right.slug ? 1 : 0)));
}

function hasExactProtectedResourceNames(receipt) {
  const resources = receipt?.protectedResourceNames;
  const expectedKeys = ["configs", "networks", "secrets", "services", "volumes"];
  if (!resources || typeof resources !== "object" || Array.isArray(resources)
      || !same(Object.keys(resources).sort(), expectedKeys)) return false;
  for (const names of Object.values(resources)) {
    if (!Array.isArray(names)
        || !same(names, [...new Set(names)].sort())
        || names.some((name) => typeof name !== "string" || name.length === 0)) return false;
  }
  return Array.isArray(receipt.protectedNetworkNames)
    && same(receipt.protectedNetworkNames, resources.networks);
}

export function parseHostedRouteLock(lock) {
  if (!lock || typeof lock !== "object" || Array.isArray(lock)
      || lock.version !== HOSTED_ROUTE_LOCK_VERSION
      || lock.validatorVersion !== HOSTED_ROUTE_VALIDATOR_VERSION
      || lock.state !== "verified"
      || !Array.isArray(lock.routes)
      || !Array.isArray(lock.workloads)) {
    throw new Error("Hosted workload lock is not an exact verified v4 lock.");
  }
  if (lock.workloads.length > 0) {
    if (lock.rawPolicyVersion !== HOSTED_ROUTE_RAW_POLICY_VERSION
        || !same(lock.rawPolicyControls, HOSTED_ROUTE_RAW_POLICY_CONTROLS)
        || lock.rawPolicyReceipt?.policyVersion !== HOSTED_ROUTE_RAW_POLICY_VERSION
        || !same(lock.rawPolicyReceipt?.controls, HOSTED_ROUTE_RAW_POLICY_CONTROLS)
        || !hasExactProtectedResourceNames(lock.rawPolicyReceipt)
        || !SHA256.test(String(lock.rawPolicySha256 ?? ""))
        || !SHA256.test(String(lock.workloadContentSha256 ?? ""))
        || !SHA256.test(String(lock.coreRenderSha256 ?? ""))
        || !SHA256.test(String(lock.combinedRenderSha256 ?? ""))) {
      throw new Error("Hosted workload lock policy/render receipt is incomplete.");
    }
  } else if (lock.routes.length !== 0 || !SHA256.test(String(lock.brokerPolicySha256 ?? ""))) {
    throw new Error("Zero-workload route lock is not canonical.");
  }

  const workloadIds = lock.workloads.map((workload) => String(workload?.id ?? ""));
  if (workloadIds.some((workloadId) => !WORKLOAD_ID.test(workloadId))) {
    throw new Error("Hosted workload declarations are invalid.");
  }
  assertPrefixDisjointWorkloadIds(workloadIds);
  const canonicalRoutes = deriveCanonicalRoutes(lock.workloads);
  if (!same(lock.routes, canonicalRoutes)) {
    throw new Error("Hosted workload canonical route lineage differs from the verified lock contract.");
  }

  const routes = new Map();
  const allowed = new Set();
  for (const route of canonicalRoutes) {
    routes.set(route.slug, route.upstream);
    allowed.add(`${route.service}:${route.port}`);
  }
  return { routes, allowed };
}
