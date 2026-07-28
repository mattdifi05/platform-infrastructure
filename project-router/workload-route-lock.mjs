const SHA256 = /^[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9-]{1,62}$/;

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
  if (workloadIds.some((workloadId) => !ID.test(workloadId))) {
    throw new Error("Hosted workload declarations are invalid.");
  }
  assertPrefixDisjointWorkloadIds(workloadIds);
  const declaredServices = new Map();
  for (const workload of lock.workloads) {
    const workloadId = String(workload?.id ?? "");
    if (!Array.isArray(workload.services)) {
      throw new Error("Hosted workload declarations are invalid.");
    }
    for (const service of workload.services) {
      const serviceName = String(service?.name ?? "");
      if (!ID.test(serviceName) || !serviceName.startsWith(`${workloadId}-`) || declaredServices.has(serviceName)) {
        throw new Error("Hosted workload declarations do not have exact canonical service owners.");
      }
      declaredServices.set(serviceName, workloadId);
    }
  }

  const routes = new Map();
  const allowed = new Set();
  for (const route of lock.routes) {
    const workloadId = String(route?.workloadId ?? "").toLowerCase();
    const slug = String(route?.slug ?? "").toLowerCase();
    const service = String(route?.service ?? "").toLowerCase();
    const port = Number(route?.port);
    if (!ID.test(workloadId)
        || !ID.test(slug)
        || !ID.test(service)
        || !Number.isInteger(port) || port < 1 || port > 65535
        || route.upstream !== `http://${service}:${port}`
        || routes.has(slug)
        || declaredServices.get(service) !== workloadId) {
      throw new Error("Hosted workload route violates the verified lock contract.");
    }
    routes.set(slug, route.upstream);
    allowed.add(`${service}:${port}`);
  }
  return { routes, allowed };
}
