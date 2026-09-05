#!/usr/bin/env node

import { createHash } from "node:crypto";
import fs, { constants as fsConstants } from "node:fs";
import { isIP } from "node:net";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const POLICY_SCHEMA = "platform.local-private-app-egress-policy/v1";
export const INVENTORY_SCHEMA = "platform.local-private-app-egress-runtime-inventory/v3";
export const MANIFEST_SCHEMA = "platform.local-private-app-egress-manifest/v1";
export const CANONICAL_DOCKER_HOST = "unix:///var/run/docker.sock";
export const CONSUMER_INVENTORY_SOURCE = "all-container-desired-attachments+active-network-endpoints/v2";

export const NON_PUBLIC_IPV4 = Object.freeze([
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.88.99.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/3"
]);

const POLICY_KEYS = Object.freeze([
  "applications",
  "networkNamePrefix",
  "nftables",
  "ownershipSourceLock",
  "projectName",
  "schema"
]);
const APPLICATION_KEYS = Object.freeze([
  "allowedConsumers",
  "network",
  "owner",
  "requiredInternalNetworks",
  "state"
]);
const NETWORK_POLICY_KEYS = Object.freeze([
  "bridgeName",
  "gateway",
  "logicalName",
  "physicalName",
  "subnet"
]);
const INVENTORY_KEYS = Object.freeze([
  "capturedAt",
  "consumerInventorySource",
  "containerIds",
  "containerInventoryComplete",
  "daemonIdAfter",
  "daemonIdBefore",
  "dockerHost",
  "networkInventoryComplete",
  "networkNames",
  "networks",
  "renderSha256",
  "renderer",
  "routeInventoryComplete",
  "routes",
  "schema",
  "sourceLockSha256"
]);

function fail(message) {
  throw new Error(message);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertObject(value, label) {
  if (!isObject(value)) fail(`${label} must be an object.`);
  return value;
}

function assertExactKeys(value, expected, label) {
  assertObject(value, label);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`${label} has foreign or missing fields: got ${actual.join(",") || "none"}.`);
  }
}

function identifier(value, label, expression = /^[a-z][a-z0-9_-]{0,127}$/) {
  const clean = String(value ?? "");
  if (!expression.test(clean)) fail(`${label} is invalid.`);
  return clean;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function requiredSha256(value, label) {
  const clean = String(value ?? "").toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(clean)) fail(`${label} must be one SHA-256 digest.`);
  return clean;
}

function exactSortedStrings(value, label) {
  if (!Array.isArray(value) || value.length === 0 || value.some((entry) => typeof entry !== "string")) {
    fail(`${label} must be a non-empty string array.`);
  }
  const sorted = [...value].sort();
  if (new Set(value).size !== value.length || JSON.stringify(value) !== JSON.stringify(sorted)) {
    fail(`${label} must be unique and canonically sorted.`);
  }
  return value;
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (isObject(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function parseJson(text, label) {
  try {
    return JSON.parse(String(text));
  } catch {
    fail(`${label} is not valid JSON.`);
  }
}

function parseIpv4(address, label) {
  const parts = String(address).split(".");
  if (parts.length !== 4) fail(`${label} is not a canonical IPv4 address.`);
  let result = 0n;
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) fail(`${label} is not a canonical IPv4 address.`);
    const octet = Number(part);
    if (octet > 255) fail(`${label} is not a canonical IPv4 address.`);
    result = (result << 8n) | BigInt(octet);
  }
  return result;
}

function ipv4Text(value) {
  return [24n, 16n, 8n, 0n].map((shift) => String((value >> shift) & 255n)).join(".");
}

export function parseIpv4Cidr(value, label = "IPv4 CIDR", { requireNetwork = true } = {}) {
  const match = String(value).match(/^([^/]+)\/(0|[1-9]|[12][0-9]|3[0-2])$/);
  if (!match) fail(`${label} is not a canonical IPv4 CIDR.`);
  const address = parseIpv4(match[1], label);
  const prefix = Number(match[2]);
  const hostBits = 32n - BigInt(prefix);
  const size = 1n << hostBits;
  const network = address & (0xffffffffn ^ (size - 1n));
  if (requireNetwork && address !== network) fail(`${label} must use its network address.`);
  return {
    text: `${ipv4Text(network)}/${prefix}`,
    prefix,
    network,
    end: network + size - 1n,
    size
  };
}

function cidrsOverlap(left, right) {
  return left.network <= right.end && right.network <= left.end;
}

function isRfc1918(cidr) {
  return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    .map((entry) => parseIpv4Cidr(entry))
    .some((privateCidr) => cidr.network >= privateCidr.network && cidr.end <= privateCidr.end);
}

export function bridgeNameForOwner(ownerValue) {
  const owner = identifier(ownerValue, "application owner", /^[a-z][a-z0-9-]{0,60}$/);
  const slug = owner.replaceAll("-", "");
  if (slug.length <= 11) return `lpe-${slug}`;
  return `lpe-${slug.slice(0, 6)}-${sha256(owner).slice(0, 4)}`;
}

function logicalNameForOwner(owner) {
  return `${owner.replaceAll("-", "_")}_egress`;
}

function validateRenderer(renderer, label = "renderer") {
  assertExactKeys(renderer, ["name", "sha256", "version"], label);
  const name = identifier(renderer.name, `${label} name`, /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/);
  const version = String(renderer.version ?? "");
  if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(version)) fail(`${label} version is invalid.`);
  return { name, version, sha256: requiredSha256(renderer.sha256, `${label} SHA-256`) };
}

function ownershipMap(sourceLock) {
  if (!Array.isArray(sourceLock?.repositories) || sourceLock.repositories.length === 0) {
    fail("Ownership source lock has no repository inventory.");
  }
  const serviceOwners = new Map();
  const knownOwners = new Set();
  const add = (ownerValue, services, label) => {
    const owner = identifier(ownerValue, `${label} owner`, /^[a-z][a-z0-9-]{0,60}$/);
    knownOwners.add(owner);
    if (!Array.isArray(services) || services.length === 0) fail(`${label} has no runtime services.`);
    for (const serviceValue of services) {
      const service = identifier(serviceValue, `${label} runtime service`);
      if (serviceOwners.has(service)) fail(`Runtime service ${service} has multiple source-lock owners.`);
      serviceOwners.set(service, owner);
    }
  };
  for (const repository of sourceLock.repositories) {
    assertObject(repository, "source-lock repository");
    const repositoryId = identifier(repository.id, "source-lock repository id", /^[a-z][a-z0-9-]{0,60}$/);
    if (Array.isArray(repository.runtimeServices)) add(repositoryId, repository.runtimeServices, repositoryId);
    if (Array.isArray(repository.applications) && repository.applications.some(isObject)) {
      for (const application of repository.applications) {
        if (!isObject(application)) fail(`${repositoryId} mixes application ownership shapes.`);
        add(application.id, application.runtimeServices, `${repositoryId} application`);
      }
    }
  }
  return { knownOwners, serviceOwners };
}

function validateRequiredInternalNetworks(value, allowedConsumers, owner) {
  assertObject(value, `${owner} required internal networks`);
  const consumerKeys = Object.keys(value);
  if (JSON.stringify(consumerKeys) !== JSON.stringify(allowedConsumers)) {
    fail(`${owner} required internal network consumers must exactly match its allowed consumers.`);
  }
  return Object.fromEntries(allowedConsumers.map((consumer) => {
    const networks = value[consumer];
    if (!Array.isArray(networks) || networks.some((network) => typeof network !== "string")) {
      fail(`${consumer} required internal networks must be a string array.`);
    }
    const sorted = [...networks].sort();
    if (new Set(networks).size !== networks.length || JSON.stringify(networks) !== JSON.stringify(sorted)) {
      fail(`${consumer} required internal networks must be unique and canonically sorted.`);
    }
    return [consumer, networks.map((network) => identifier(network, `${consumer} required internal network`))];
  }));
}

function validatePolicyDocument(policy, sourceLock, { policyText, sourceLockText } = {}) {
  assertExactKeys(policy, POLICY_KEYS, "egress policy");
  if (policy.schema !== POLICY_SCHEMA) fail("Unsupported local-private egress policy schema.");
  const projectName = identifier(policy.projectName, "policy project name");
  const networkNamePrefix = identifier(policy.networkNamePrefix, "policy network name prefix");

  assertExactKeys(policy.ownershipSourceLock, ["path", "sha256"], "ownership source-lock binding");
  const lockPath = String(policy.ownershipSourceLock.path ?? "");
  if (lockPath !== "config/v1-local-private-source-lock.json") {
    fail("Policy must use the canonical LOCAL_PRIVATE ownership source lock.");
  }
  const expectedLockSha = requiredSha256(policy.ownershipSourceLock.sha256, "ownership source-lock SHA-256");
  if (typeof sourceLockText === "string" && sha256(sourceLockText) !== expectedLockSha) {
    fail("Ownership source-lock bytes differ from the policy binding.");
  }
  assertObject(sourceLock, "ownership source lock");
  if (sourceLock?.runtime?.composeProject !== projectName || sourceLock?.compose?.projectName !== projectName) {
    fail("Policy project differs from the ownership source lock.");
  }
  const renderer = validateRenderer(sourceLock?.compose?.renderer, "source-lock renderer");
  const owners = ownershipMap(sourceLock);

  assertExactKeys(policy.nftables, ["family", "hookPriority", "table"], "nftables policy");
  if (policy.nftables.family !== "inet" || policy.nftables.table !== "platform_local_private_egress") {
    fail("The dedicated nftables namespace is not canonical.");
  }
  if (policy.nftables.hookPriority !== -5) fail("The nftables hook priority must be exactly -5.");

  if (!Array.isArray(policy.applications) || policy.applications.length === 0) {
    fail("Egress policy must contain at least one explicit application proposal.");
  }
  const applications = [];
  for (const application of policy.applications) {
    assertExactKeys(application, APPLICATION_KEYS, "egress application proposal");
    if (application.state !== "proposed") fail("Tracked application egress entries must remain proposed until runtime admission.");
    const owner = identifier(application.owner, "egress application owner", /^[a-z][a-z0-9-]{0,60}$/);
    if (!owners.knownOwners.has(owner)) fail(`Unknown application owner ${owner}.`);
    const allowedConsumers = exactSortedStrings(application.allowedConsumers, `${owner} allowed consumers`)
      .map((consumer) => identifier(consumer, `${owner} allowed consumer`));
    for (const consumer of allowedConsumers) {
      const mappedOwner = owners.serviceOwners.get(consumer);
      if (!mappedOwner) fail(`${consumer} is a core or unknown service, not an application-owned consumer.`);
      if (mappedOwner !== owner) fail(`${consumer} belongs to ${mappedOwner}, not ${owner}.`);
    }
    const requiredInternalNetworks = validateRequiredInternalNetworks(
      application.requiredInternalNetworks,
      allowedConsumers,
      owner
    );

    assertExactKeys(application.network, NETWORK_POLICY_KEYS, `${owner} network policy`);
    const expectedLogical = logicalNameForOwner(owner);
    const expectedPhysical = `${networkNamePrefix}_${expectedLogical}`;
    const expectedBridge = bridgeNameForOwner(owner);
    if (application.network.logicalName !== expectedLogical
        || application.network.physicalName !== expectedPhysical
        || application.network.bridgeName !== expectedBridge) {
      fail(`${owner} has a foreign logical, physical, or bridge network name.`);
    }
    if (!/^[a-z][a-z0-9-]{0,14}$/.test(expectedBridge)) fail(`${owner} bridge name exceeds the Linux interface boundary.`);
    const subnet = parseIpv4Cidr(application.network.subnet, `${owner} subnet`);
    if (subnet.prefix !== 28 || !isRfc1918(subnet)) fail(`${owner} must use one static RFC1918 /28 subnet.`);
    const gateway = parseIpv4(application.network.gateway, `${owner} gateway`);
    if (gateway !== subnet.network + 1n) fail(`${owner} gateway must be the first usable address in its /28.`);
    applications.push({
      state: "proposed",
      owner,
      allowedConsumers,
      requiredInternalNetworks,
      network: {
        logicalName: expectedLogical,
        physicalName: expectedPhysical,
        bridgeName: expectedBridge,
        subnet: subnet.text,
        gateway: ipv4Text(gateway)
      },
      parsedSubnet: subnet
    });
  }
  const sortedOwners = applications.map(({ owner }) => owner).sort();
  if (new Set(sortedOwners).size !== applications.length
      || JSON.stringify(applications.map(({ owner }) => owner)) !== JSON.stringify(sortedOwners)) {
    fail("Application egress proposals must have unique, canonical owner ordering.");
  }
  for (let left = 0; left < applications.length; left += 1) {
    for (let right = left + 1; right < applications.length; right += 1) {
      if (cidrsOverlap(applications[left].parsedSubnet, applications[right].parsedSubnet)) {
        fail(`${applications[left].owner} and ${applications[right].owner} egress subnets overlap.`);
      }
    }
  }
  return {
    schema: POLICY_SCHEMA,
    projectName,
    networkNamePrefix,
    policySha256: typeof policyText === "string" ? sha256(policyText) : sha256(canonicalJson(policy)),
    ownershipSourceLock: { path: lockPath, sha256: expectedLockSha },
    renderer,
    nftables: { family: "inet", table: policy.nftables.table, hookPriority: -5 },
    applications
  };
}

export function validatePolicy({ policy, sourceLock, policyText, sourceLockText }) {
  const policyDocument = typeof policy === "string" ? parseJson(policy, "egress policy") : policy;
  const sourceLockDocument = typeof sourceLock === "string" ? parseJson(sourceLock, "ownership source lock") : sourceLock;
  return validatePolicyDocument(policyDocument, sourceLockDocument, {
    policyText: policyText ?? (typeof policy === "string" ? policy : undefined),
    sourceLockText: sourceLockText ?? (typeof sourceLock === "string" ? sourceLock : undefined)
  });
}

function renderNetworkConsumers(render, logicalName) {
  return Object.entries(render.services)
    .filter(([, service]) => isObject(service?.networks) && Object.hasOwn(service.networks, logicalName))
    .map(([name]) => name)
    .sort();
}

function exactNetworkDefinition(definition, application) {
  const { owner, network } = application;
  assertObject(definition, `${owner} rendered network`);
  if (definition.name !== network.physicalName || definition.driver !== "bridge") {
    fail(`${owner} rendered network has a foreign physical name or driver.`);
  }
  if ((definition.internal ?? false) !== false || definition.enable_ipv6 !== false
      || definition.enable_ipv4 === false
      || (definition.attachable !== undefined && definition.attachable !== false)
      || (definition.external !== undefined && definition.external !== false)) {
    fail(`${owner} rendered egress network must be non-internal, non-attachable, non-external and IPv6-disabled.`);
  }
  assertExactKeys(definition.labels, ["com.platform.egress-owner", "com.platform.trust-zone"], `${owner} network labels`);
  if (definition.labels["com.platform.egress-owner"] !== owner
      || definition.labels["com.platform.trust-zone"] !== "isolated-application-egress") {
    fail(`${owner} rendered egress network has foreign trust-zone or owner labels.`);
  }
  assertExactKeys(definition.driver_opts, ["com.docker.network.bridge.name"], `${owner} network driver options`);
  if (definition.driver_opts["com.docker.network.bridge.name"] !== network.bridgeName) {
    fail(`${owner} rendered bridge name differs from policy.`);
  }
  assertObject(definition.ipam, `${owner} rendered IPAM`);
  const ipamKeys = Object.keys(definition.ipam).sort();
  if (ipamKeys.some((key) => !["config", "driver"].includes(key)) || !ipamKeys.includes("config")) {
    fail(`${owner} rendered IPAM has foreign fields.`);
  }
  if (definition.ipam.driver !== undefined && definition.ipam.driver !== "default") {
    fail(`${owner} rendered IPAM driver is not default.`);
  }
  if (!Array.isArray(definition.ipam.config) || definition.ipam.config.length !== 1) {
    fail(`${owner} rendered IPAM must contain one static subnet.`);
  }
  assertExactKeys(definition.ipam.config[0], ["gateway", "subnet"], `${owner} rendered IPAM subnet`);
  if (definition.ipam.config[0].subnet !== network.subnet || definition.ipam.config[0].gateway !== network.gateway) {
    fail(`${owner} rendered IPAM differs from policy.`);
  }
}

export function validateRender(renderText, validatedPolicy) {
  const render = parseJson(renderText, "canonical Compose render");
  if (!isObject(render?.services) || !isObject(render?.networks)) {
    fail("Canonical Compose render must contain service and network objects.");
  }
  if (render.name !== validatedPolicy.projectName) {
    fail("Canonical Compose render project name differs from policy and source lock.");
  }
  for (const application of validatedPolicy.applications) {
    const { owner, allowedConsumers, requiredInternalNetworks, network } = application;
    if (!Object.hasOwn(render.networks, network.logicalName)) fail(`${owner} rendered egress network is missing.`);
    exactNetworkDefinition(render.networks[network.logicalName], application);
    const actualConsumers = renderNetworkConsumers(render, network.logicalName);
    if (JSON.stringify(actualConsumers) !== JSON.stringify(allowedConsumers)) {
      fail(`${owner} rendered egress consumers differ from the explicit allowlist.`);
    }
    for (const consumer of allowedConsumers) {
      const service = assertObject(render.services[consumer], `${consumer} rendered service`);
      const serviceNetworks = assertObject(service.networks, `${consumer} rendered networks`);
      const expectedNetworks = [...requiredInternalNetworks[consumer], network.logicalName].sort();
      const actualNetworks = Object.keys(serviceNetworks).sort();
      if (JSON.stringify(actualNetworks) !== JSON.stringify(expectedNetworks)) {
        fail(`${consumer} rendered network attachments differ from its exact required internal and egress networks.`);
      }
      if (!Array.isArray(service.cap_drop)
          || (service.cap_add !== undefined && !Array.isArray(service.cap_add))
          || (service.privileged !== undefined && service.privileged !== false)) {
        fail(`${consumer} has an invalid capability or privilege shape.`);
      }
      const capDrop = Array.isArray(service.cap_drop) ? service.cap_drop : [];
      const capAdd = Array.isArray(service.cap_add) ? service.cap_add : [];
      if (!capDrop.includes("ALL") && !capDrop.includes("NET_RAW")) {
        fail(`${consumer} must drop NET_RAW before app egress is admissible.`);
      }
      if (capAdd.length !== 0 || service.privileged === true
          || ["host", "none"].includes(service.network_mode)
          || String(service.network_mode ?? "").startsWith("service:")
          || String(service.network_mode ?? "").startsWith("container:")) {
        fail(`${consumer} has unsafe capabilities or network namespace authority.`);
      }
      for (const attachedName of requiredInternalNetworks[consumer]) {
        const attached = render.networks[attachedName];
        if (!isObject(attached)) fail(`${consumer} references unknown network ${attachedName}.`);
        if (attached.internal !== true) {
          fail(`${consumer} required internal network ${attachedName} must declare internal: true.`);
        }
      }
    }
  }
  return { render, sha256: sha256(renderText) };
}

function validateIpv6Cidr(value, label) {
  const clean = String(value);
  const match = clean.match(/^([^/]+)\/(?:[0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$/);
  if (!match || isIP(match[1]) !== 6) {
    fail(`${label} is not an IPv6 CIDR.`);
  }
  return clean.toLowerCase();
}

function validateInventoryNetwork(entry, index) {
  const label = `runtime network ${index}`;
  assertExactKeys(entry, [
    "attachable",
    "bridgeName",
    "composeNetwork",
    "composeProject",
    "composeVersion",
    "consumers",
    "driver",
    "enableIPv6",
    "id",
    "ingress",
    "internal",
    "name",
    "policyOwner",
    "scope",
    "subnets",
    "trustZone"
  ], label);
  const name = identifier(entry.name, `${label} name`, /^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$/);
  const id = String(entry.id);
  if (!/^[a-f0-9]{64}$/.test(id)) fail(`${label} ID is invalid.`);
  for (const booleanKey of ["attachable", "enableIPv6", "ingress", "internal"]) {
    if (typeof entry[booleanKey] !== "boolean") fail(`${label} ${booleanKey} must be boolean.`);
  }
  const driver = identifier(entry.driver, `${label} driver`, /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/);
  const scope = identifier(entry.scope, `${label} scope`, /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/);
  const bridgeName = String(entry.bridgeName ?? "");
  if (bridgeName && !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/.test(bridgeName)) fail(`${label} bridge name is invalid.`);
  for (const field of ["composeNetwork", "composeProject", "composeVersion", "policyOwner", "trustZone"]) {
    if (typeof entry[field] !== "string" || entry[field].length > 255) fail(`${label} ${field} is invalid.`);
  }
  if (!Array.isArray(entry.consumers)) fail(`${label} consumers must be an array.`);
  const consumers = entry.consumers.map((consumer, consumerIndex) => {
    const consumerLabel = `${label} consumer ${consumerIndex}`;
    assertExactKeys(consumer, [
      "attachmentState",
      "containerId",
      "containerState",
      "desiredNetworkId",
      "endpointId",
      "projectName",
      "serviceName"
    ], consumerLabel);
    if (!/^[a-f0-9]{64}$/.test(String(consumer.containerId))) fail(`${label} consumer container ID is invalid.`);
    const attachmentState = String(consumer.attachmentState);
    const containerState = String(consumer.containerState);
    let desiredNetworkId = null;
    let endpointId = null;
    if (attachmentState === "configured-unmaterialized") {
      if (containerState !== "created" || consumer.desiredNetworkId !== null || consumer.endpointId !== null) {
        fail(`${consumerLabel} configured-unmaterialized attachment is inconsistent with its created container or absent Engine IDs.`);
      }
    } else if (attachmentState === "active-endpoint") {
      if (consumer.desiredNetworkId !== id) fail(`${consumerLabel} desired network ID differs from its inspected network.`);
      if (!new Set(["paused", "restarting", "running"]).has(containerState)
          || !/^[a-f0-9]{64}$/.test(String(consumer.endpointId))) {
        fail(`${consumerLabel} active endpoint is inconsistent with container state or endpoint ID.`);
      }
      desiredNetworkId = String(consumer.desiredNetworkId);
      endpointId = String(consumer.endpointId);
    } else if (attachmentState === "configured-stopped") {
      if (consumer.desiredNetworkId !== id) fail(`${consumerLabel} desired network ID differs from its inspected network.`);
      if (!new Set(["created", "exited"]).has(containerState) || consumer.endpointId !== null) {
        fail(`${consumerLabel} configured-stopped attachment is inconsistent with container state or endpoint ID.`);
      }
      desiredNetworkId = String(consumer.desiredNetworkId);
    } else {
      fail(`${consumerLabel} attachment state is invalid.`);
    }
    return {
      attachmentState,
      containerId: String(consumer.containerId),
      containerState,
      desiredNetworkId,
      endpointId,
      projectName: consumer.projectName === null
        ? null
        : identifier(consumer.projectName, `${label} consumer project`),
      serviceName: consumer.serviceName === null
        ? null
        : identifier(consumer.serviceName, `${label} consumer service`)
    };
  });
  const consumerIds = consumers.map(({ containerId }) => containerId);
  const consumerKeys = consumers.map((consumer) => `${consumer.containerId}|${consumer.attachmentState}|${consumer.containerState}|${consumer.desiredNetworkId ?? ""}|${consumer.endpointId ?? ""}|${consumer.projectName ?? ""}|${consumer.serviceName ?? ""}`);
  if (new Set(consumerIds).size !== consumerIds.length
      || new Set(consumerKeys).size !== consumerKeys.length
      || JSON.stringify(consumerKeys) !== JSON.stringify([...consumerKeys].sort())) {
    fail(`${label} consumers must have unique container IDs and canonical ordering.`);
  }
  if (!Array.isArray(entry.subnets)) fail(`${label} subnets must be an array.`);
  const subnets = entry.subnets.map((subnet, subnetIndex) => {
    assertExactKeys(subnet, ["gateway", "subnet"], `${label} subnet ${subnetIndex}`);
    const subnetText = String(subnet.subnet);
    const family = subnetText.includes(":") ? "ipv6" : "ipv4";
    const parsed = family === "ipv4"
      ? parseIpv4Cidr(subnetText, `${label} subnet ${subnetIndex}`)
      : validateIpv6Cidr(subnetText, `${label} subnet ${subnetIndex}`);
    if (family === "ipv4") {
      const gateway = parseIpv4(subnet.gateway, `${label} gateway ${subnetIndex}`);
      if (gateway <= parsed.network || gateway >= parsed.end) fail(`${label} IPv4 gateway is outside its usable subnet.`);
    } else if (typeof subnet.gateway !== "string" || (subnet.gateway !== "" && isIP(subnet.gateway) !== 6)) {
      fail(`${label} IPv6 gateway is invalid.`);
    }
    return { gateway: String(subnet.gateway).toLowerCase(), subnet: family === "ipv4" ? parsed.text : parsed, family, parsed };
  });
  const subnetKeys = subnets.map((subnet) => `${subnet.family}|${subnet.subnet}|${subnet.gateway}`);
  if (new Set(subnetKeys).size !== subnetKeys.length
      || JSON.stringify(subnetKeys) !== JSON.stringify([...subnetKeys].sort())) {
    fail(`${label} subnets must be unique and canonically sorted.`);
  }
  return { ...entry, name, driver, scope, bridgeName, consumers, subnets };
}

function validateRoute(entry, index) {
  const label = `runtime route ${index}`;
  assertExactKeys(entry, ["destination", "device", "family", "type"], label);
  if (!new Set(["ipv4", "ipv6"]).has(entry.family)) fail(`${label} family is invalid.`);
  const destination = String(entry.destination);
  let parsed = null;
  if (destination !== "default") {
    parsed = entry.family === "ipv4"
      ? parseIpv4Cidr(destination, `${label} destination`)
      : validateIpv6Cidr(destination, `${label} destination`);
  }
  const device = String(entry.device ?? "");
  if (device && !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/.test(device)) fail(`${label} device is invalid.`);
  const type = identifier(entry.type, `${label} type`, /^[a-z][a-z0-9_-]{0,31}$/);
  return { family: entry.family, destination, device, type, parsed };
}

export function validatePreviousManifest(manifestText, validatedPolicy) {
  const manifest = parseJson(manifestText, "previous admitted egress manifest");
  assertExactKeys(manifest, ["applications", "binding", "integrity", "nftables", "policy", "schema", "status"], "previous egress manifest");
  if (manifest.schema !== MANIFEST_SCHEMA || manifest.status !== "admitted") {
    fail("Previous egress manifest is not admitted under the supported schema.");
  }
  assertExactKeys(manifest.integrity, ["canonicalSha256"], "previous manifest integrity");
  const claimedIntegrity = requiredSha256(manifest.integrity.canonicalSha256, "previous manifest integrity SHA-256");
  const core = structuredClone(manifest);
  delete core.integrity;
  if (sha256(canonicalJson(core)) !== claimedIntegrity) fail("Previous egress manifest integrity check failed.");

  assertExactKeys(manifest.policy, ["ownershipSourceLockPath", "ownershipSourceLockSha256", "sha256"], "previous manifest policy binding");
  requiredSha256(manifest.policy.sha256, "previous policy SHA-256");
  if (manifest.policy.ownershipSourceLockPath !== validatedPolicy.ownershipSourceLock.path
      || manifest.policy.ownershipSourceLockSha256 !== validatedPolicy.ownershipSourceLock.sha256) {
    fail("Previous manifest ownership source-lock binding differs from current policy.");
  }
  assertExactKeys(manifest.binding, [
    "capturedAt", "daemonId", "dockerHost", "projectName", "renderSha256", "renderer", "runtimeInventorySha256"
  ], "previous manifest runtime binding");
  if (manifest.binding.projectName !== validatedPolicy.projectName
      || manifest.binding.dockerHost !== CANONICAL_DOCKER_HOST
      || canonicalJson(validateRenderer(manifest.binding.renderer, "previous manifest renderer")) !== canonicalJson(validatedPolicy.renderer)) {
    fail("Previous manifest project, Docker transport, or renderer binding differs from current policy.");
  }
  identifier(manifest.binding.daemonId, "previous manifest Docker daemon ID", /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/);
  requiredSha256(manifest.binding.renderSha256, "previous manifest render SHA-256");
  requiredSha256(manifest.binding.runtimeInventorySha256, "previous manifest inventory SHA-256");

  assertExactKeys(manifest.nftables, [
    "expectedPreimageNormalizedSha256", "family", "normalizedSha256", "program", "programSha256", "table"
  ], "previous manifest nftables binding");
  if (manifest.nftables.family !== "inet" || manifest.nftables.table !== validatedPolicy.nftables.table) {
    fail("Previous manifest uses a foreign nftables namespace.");
  }
  if (manifest.nftables.expectedPreimageNormalizedSha256 !== null) {
    requiredSha256(manifest.nftables.expectedPreimageNormalizedSha256, "previous nftables preimage SHA-256");
  }
  if (requiredSha256(manifest.nftables.programSha256, "previous nftables program SHA-256") !== sha256(String(manifest.nftables.program))) {
    fail("Previous nftables program digest is invalid.");
  }
  if (requiredSha256(manifest.nftables.normalizedSha256, "previous normalized nftables SHA-256")
      !== sha256(normalizeNftText(manifest.nftables.program))) {
    fail("Previous normalized nftables digest is invalid.");
  }
  if (!Array.isArray(manifest.applications) || manifest.applications.length === 0) {
    fail("Previous manifest has no admitted applications.");
  }
  const applications = manifest.applications.map((application, index) => {
    assertExactKeys(application, [
      "admittedFromState", "allowedConsumers", "network", "owner", "requiredInternalNetworks", "runtimeNetworkId"
    ], `previous manifest application ${index}`);
    if (application.admittedFromState !== "proposed") fail("Previous manifest application did not originate from a proposal.");
    const owner = identifier(application.owner, "previous manifest application owner", /^[a-z][a-z0-9-]{0,60}$/);
    const allowedConsumers = exactSortedStrings(application.allowedConsumers, `${owner} previous consumers`)
      .map((consumer) => identifier(consumer, `${owner} previous consumer`));
    const requiredInternalNetworks = validateRequiredInternalNetworks(
      application.requiredInternalNetworks,
      allowedConsumers,
      `${owner} previous manifest`
    );
    assertExactKeys(application.network, NETWORK_POLICY_KEYS, `${owner} previous network`);
    const runtimeNetworkId = application.runtimeNetworkId;
    if (runtimeNetworkId !== null && !/^[a-f0-9]{64}$/.test(String(runtimeNetworkId))) {
      fail(`${owner} previous runtime network ID is invalid.`);
    }
    return { owner, allowedConsumers, requiredInternalNetworks, network: application.network, runtimeNetworkId };
  });
  const owners = applications.map(({ owner }) => owner);
  if (new Set(owners).size !== owners.length || JSON.stringify(owners) !== JSON.stringify([...owners].sort())) {
    fail("Previous manifest applications are not uniquely and canonically ordered.");
  }
  const previousPolicyShape = {
    nftables: validatedPolicy.nftables,
    applications: applications.map((application) => ({ ...application, parsedSubnet: parseIpv4Cidr(application.network.subnet) }))
  };
  if (renderNftProgram(previousPolicyShape) !== manifest.nftables.program) {
    fail("Previous manifest nftables program differs from its admitted applications.");
  }
  return { manifest, applications, byOwner: new Map(applications.map((application) => [application.owner, application])) };
}

function exactExistingRuntimeNetwork(existing, application, previousApplication, projectName, rendererVersion) {
  const { owner, allowedConsumers, requiredInternalNetworks, network } = application;
  if (!previousApplication
      || canonicalJson(previousApplication.allowedConsumers) !== canonicalJson(allowedConsumers)
      || canonicalJson(previousApplication.requiredInternalNetworks) !== canonicalJson(requiredInternalNetworks)
      || canonicalJson(previousApplication.network) !== canonicalJson(network)) {
    fail(`${owner} existing network lacks exact previous-manifest authority.`);
  }
  if (previousApplication.runtimeNetworkId !== null && previousApplication.runtimeNetworkId !== existing.id) {
    fail(`${owner} runtime network ID differs from its previous admitted identity.`);
  }
  if (existing.driver !== "bridge" || existing.scope !== "local" || existing.internal !== false
      || existing.attachable !== false || existing.ingress !== false || existing.enableIPv6 !== false
      || existing.bridgeName !== network.bridgeName
      || existing.composeProject !== projectName
      || existing.composeNetwork !== network.logicalName
      || existing.composeVersion !== rendererVersion
      || existing.policyOwner !== owner
      || existing.trustZone !== "isolated-application-egress"
      || existing.consumers.some((consumer) => consumer.projectName !== projectName)
      || canonicalJson([...new Set(existing.consumers.map(({ serviceName }) => serviceName))].sort()) !== canonicalJson(allowedConsumers)) {
    fail(`${owner} existing runtime network identity or consumers differ from its admitted boundary.`);
  }
  if (existing.subnets.length !== 1 || existing.subnets[0].family !== "ipv4"
      || existing.subnets[0].subnet !== network.subnet || existing.subnets[0].gateway !== network.gateway) {
    fail(`${owner} existing runtime network IPAM differs from its admitted boundary.`);
  }
}

export function validateRuntimeInventory(inventoryText, validatedPolicy, validatedRender, previous = null) {
  const inventory = parseJson(inventoryText, "runtime network and route inventory");
  assertExactKeys(inventory, INVENTORY_KEYS, "runtime inventory");
  if (inventory.schema !== INVENTORY_SCHEMA) fail("Unsupported runtime inventory schema.");
  if (inventory.networkInventoryComplete !== true || inventory.containerInventoryComplete !== true
      || inventory.routeInventoryComplete !== true) {
    fail("Runtime inventory must attest complete network, container and route enumeration.");
  }
  if (inventory.consumerInventorySource !== CONSUMER_INVENTORY_SOURCE) {
    fail("Runtime consumer inventory must bind all desired attachments and active network endpoints.");
  }
  if (inventory.dockerHost !== CANONICAL_DOCKER_HOST) fail("Runtime inventory is not bound to the canonical local Docker socket.");
  const daemonIdBefore = identifier(inventory.daemonIdBefore, "initial Docker daemon ID", /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/);
  const daemonIdAfter = identifier(inventory.daemonIdAfter, "final Docker daemon ID", /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/);
  if (daemonIdBefore !== daemonIdAfter) fail("Docker daemon identity changed while runtime inventory was captured.");
  if (previous && previous.manifest.binding.daemonId !== daemonIdBefore) {
    fail("Docker daemon identity differs from the previous admitted manifest.");
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(String(inventory.capturedAt))) {
    fail("Runtime inventory capturedAt must be UTC RFC3339.");
  }
  if (requiredSha256(inventory.sourceLockSha256, "runtime source-lock SHA-256") !== validatedPolicy.ownershipSourceLock.sha256) {
    fail("Runtime inventory source-lock binding differs from policy.");
  }
  if (requiredSha256(inventory.renderSha256, "runtime render SHA-256") !== validatedRender.sha256) {
    fail("Runtime inventory render binding differs from the supplied exact render.");
  }
  const renderer = validateRenderer(inventory.renderer, "runtime renderer");
  if (canonicalJson(renderer) !== canonicalJson(validatedPolicy.renderer)) {
    fail("Runtime renderer differs from the source-lock pinned renderer.");
  }

  if (!Array.isArray(inventory.containerIds)
      || inventory.containerIds.some((containerId) => !/^[a-f0-9]{64}$/.test(String(containerId)))) {
    fail("Runtime container IDs must be an array of full Engine IDs.");
  }
  if (new Set(inventory.containerIds).size !== inventory.containerIds.length
      || JSON.stringify(inventory.containerIds) !== JSON.stringify([...inventory.containerIds].sort())) {
    fail("Runtime container IDs must be unique and canonically sorted.");
  }

  exactSortedStrings(inventory.networkNames, "runtime network names");
  if (!Array.isArray(inventory.networks)) fail("Runtime networks must be an array.");
  const networks = inventory.networks.map(validateInventoryNetwork);
  const names = networks.map((network) => network.name);
  if (new Set(names).size !== names.length || JSON.stringify(names) !== JSON.stringify([...names].sort())
      || JSON.stringify(names) !== JSON.stringify(inventory.networkNames)) {
    fail("Runtime network names do not exactly cover the sorted inspection inventory.");
  }
  const containerIdSet = new Set(inventory.containerIds);
  if (networks.some((network) => network.consumers.some(({ containerId }) => !containerIdSet.has(containerId)))) {
    fail("Runtime desired attachment references a container outside the complete container inventory.");
  }
  if (!Array.isArray(inventory.routes) || inventory.routes.length === 0) fail("Runtime route inventory is empty.");
  const routes = inventory.routes.map(validateRoute);
  const routeKeys = routes.map((route) => `${route.family}|${route.destination}|${route.device}|${route.type}`);
  if (new Set(routeKeys).size !== routeKeys.length
      || JSON.stringify(routeKeys) !== JSON.stringify([...routeKeys].sort())) {
    fail("Runtime routes must be unique and canonically sorted.");
  }
  if (!routes.some((route) => route.family === "ipv4" && (route.destination === "default" || route.destination === "0.0.0.0/0"))) {
    fail("Complete runtime routes must include the host IPv4 default route.");
  }

  const runtimeNetworkIds = new Map();
  for (const application of validatedPolicy.applications) {
    const { owner, network, parsedSubnet } = application;
    const existingTarget = networks.find((existing) => existing.name === network.physicalName) ?? null;
    const previousApplication = previous?.byOwner.get(owner) ?? null;
    if (existingTarget) {
      exactExistingRuntimeNetwork(
        existingTarget,
        application,
        previousApplication,
        validatedPolicy.projectName,
        validatedPolicy.renderer.version
      );
      runtimeNetworkIds.set(owner, existingTarget.id);
    } else {
      if (networks.some((existing) => existing.bridgeName === network.bridgeName)) {
        fail(`${owner} target bridge name is already owned by another network.`);
      }
      runtimeNetworkIds.set(owner, null);
    }
    for (const existing of networks) {
      for (const subnet of existing.subnets.filter((candidate) => candidate.family === "ipv4")) {
        if (existingTarget && existing.id === existingTarget.id) continue;
        if (cidrsOverlap(parsedSubnet, subnet.parsed)) {
          fail(`${owner} subnet overlaps Docker network ${existing.name} (${subnet.subnet}).`);
        }
      }
    }
    for (const route of routes) {
      if (route.family === "ipv4" && route.destination !== "default" && route.parsed?.prefix !== 0
          && cidrsOverlap(parsedSubnet, route.parsed)) {
        const isOwnedTargetRoute = existingTarget
          && route.device === network.bridgeName
          && route.parsed.network >= parsedSubnet.network
          && route.parsed.end <= parsedSubnet.end;
        if (isOwnedTargetRoute) continue;
        fail(`${owner} subnet overlaps host route ${route.destination} on ${route.device || "unknown device"}.`);
      }
    }
  }

  for (const previousApplication of previous?.applications ?? []) {
    if (validatedPolicy.applications.some(({ owner }) => owner === previousApplication.owner)) continue;
    const oldNetworkPresent = networks.some((network) => network.name === previousApplication.network.physicalName
      || network.bridgeName === previousApplication.network.bridgeName);
    if (oldNetworkPresent) fail(`${previousApplication.owner} cannot be removed while its admitted runtime network still exists.`);
  }
  return {
    inventory,
    sha256: sha256(inventoryText),
    daemonId: daemonIdBefore,
    renderer,
    networks,
    routes,
    runtimeNetworkIds
  };
}

export function normalizeNftText(value) {
  return String(value)
    .replace(/[\t\r\n ]+/g, " ")
    .replace(/\s*([{};,=])\s*/g, "$1")
    .trim();
}

export function renderNftProgram(validatedPolicy) {
  const lines = [
    `table inet ${validatedPolicy.nftables.table} {`,
    "  set non_public_ipv4 {",
    "    type ipv4_addr",
    "    flags interval",
    `    elements = { ${NON_PUBLIC_IPV4.join(", ")} }`,
    "  }",
    "",
    "  chain input {",
    `    type filter hook input priority ${validatedPolicy.nftables.hookPriority}; policy accept;`
  ];
  for (const application of validatedPolicy.applications) {
    lines.push(`    iifname "${application.network.bridgeName}" drop comment "lp-egress/input/${application.owner}"`);
  }
  lines.push("  }", "", "  chain forward {",
    `    type filter hook forward priority ${validatedPolicy.nftables.hookPriority}; policy accept;`);
  for (const application of validatedPolicy.applications) {
    const { owner, network } = application;
    lines.push(
      `    iifname "${network.bridgeName}" meta nfproto 10 drop comment "lp-egress/forward/${owner}/ipv6"`,
      `    iifname "${network.bridgeName}" ip saddr != ${network.subnet} drop comment "lp-egress/forward/${owner}/spoof"`,
      `    iifname "${network.bridgeName}" ip saddr ${network.subnet} ip daddr @non_public_ipv4 drop comment "lp-egress/forward/${owner}/non-public"`
    );
  }
  lines.push("  }", "}", "");
  return lines.join("\n");
}

export function compileManifest({ policyText, sourceLockText, renderText, inventoryText, previousManifestText = null }) {
  const policy = validatePolicy({ policy: policyText, sourceLock: sourceLockText });
  const render = validateRender(renderText, policy);
  const previous = previousManifestText ? validatePreviousManifest(previousManifestText, policy) : null;
  const runtime = validateRuntimeInventory(inventoryText, policy, render, previous);
  const program = renderNftProgram(policy);
  const core = {
    schema: MANIFEST_SCHEMA,
    status: "admitted",
    policy: {
      sha256: policy.policySha256,
      ownershipSourceLockPath: policy.ownershipSourceLock.path,
      ownershipSourceLockSha256: policy.ownershipSourceLock.sha256
    },
    binding: {
      capturedAt: runtime.inventory.capturedAt,
      daemonId: runtime.daemonId,
      dockerHost: CANONICAL_DOCKER_HOST,
      projectName: policy.projectName,
      renderSha256: render.sha256,
      renderer: policy.renderer,
      runtimeInventorySha256: runtime.sha256
    },
    applications: policy.applications.map(({ state: _state, parsedSubnet: _parsedSubnet, ...application }) => ({
      ...application,
      admittedFromState: "proposed",
      runtimeNetworkId: runtime.runtimeNetworkIds.get(application.owner)
    })),
    nftables: {
      expectedPreimageNormalizedSha256: previous?.manifest.nftables.normalizedSha256 ?? null,
      family: "inet",
      table: policy.nftables.table,
      program,
      programSha256: sha256(program),
      normalizedSha256: sha256(normalizeNftText(program))
    }
  };
  return { ...core, integrity: { canonicalSha256: sha256(canonicalJson(core)) } };
}

function usage() {
  return [
    "Usage:",
    "  local-private-egress-policy.mjs validate --policy ABSOLUTE_FILE --source-lock ABSOLUTE_FILE",
    "  local-private-egress-policy.mjs compile --policy ABSOLUTE_FILE --source-lock ABSOLUTE_FILE --render ABSOLUTE_FILE --runtime-inventory ABSOLUTE_FILE [--previous-manifest ABSOLUTE_FILE]",
    "",
    "compile writes one canonical admitted manifest to stdout; it never changes Docker, nftables or files."
  ].join("\n");
}

function parseArguments(argv) {
  const command = argv.shift();
  if (!new Set(["validate", "compile"]).has(command)) fail(usage());
  const options = {};
  while (argv.length) {
    const option = argv.shift();
    if (!option?.startsWith("--") || argv.length === 0) fail(usage());
    const key = option.slice(2);
    if (!new Set(["policy", "source-lock", "render", "runtime-inventory", "previous-manifest"]).has(key) || Object.hasOwn(options, key)) fail(usage());
    options[key] = argv.shift();
  }
  const required = command === "compile"
    ? ["policy", "source-lock", "render", "runtime-inventory"]
    : ["policy", "source-lock"];
  if (required.some((key) => !options[key])) fail(usage());
  for (const [key, value] of Object.entries(options)) {
    if (!path.isAbsolute(value)) fail(`--${key} must be an absolute path.`);
  }
  return { command, options };
}

function readRegularFile(filePath, label) {
  const metadata = fs.lstatSync(filePath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) fail(`${label} must be one regular non-symlink file.`);
  return fs.readFileSync(filePath, "utf8");
}

export function readProtectedManifest(filePath, { requiredUid = 0, boundary = "/" } = {}) {
  const resolvedPath = fs.realpathSync.native(filePath);
  const resolvedBoundary = fs.realpathSync.native(boundary);
  if (resolvedPath !== filePath
      || (resolvedPath !== resolvedBoundary && !resolvedPath.startsWith(`${resolvedBoundary}${path.sep}`))) {
    fail("Previous admitted manifest path or trust boundary is not canonical.");
  }
  let current = path.dirname(resolvedPath);
  while (true) {
    const directory = fs.lstatSync(current);
    if (!directory.isDirectory() || directory.isSymbolicLink()
        || directory.uid !== requiredUid || (directory.mode & 0o022) !== 0) {
      fail("Previous admitted manifest has an untrusted owner or writable ancestor.");
    }
    if (current === resolvedBoundary) break;
    const parent = path.dirname(current);
    if (parent === current) fail("Previous admitted manifest is outside its trust boundary.");
    current = parent;
  }
  const descriptor = fs.openSync(resolvedPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const metadata = fs.fstatSync(descriptor);
    if (!metadata.isFile() || metadata.nlink !== 1
        || metadata.uid !== requiredUid || (metadata.mode & 0o022) !== 0) {
      fail("Previous admitted manifest must be one protected, single-link regular file.");
    }
    return fs.readFileSync(descriptor, "utf8");
  } finally {
    fs.closeSync(descriptor);
  }
}

function readRootOwnedManifest(filePath) {
  return readProtectedManifest(filePath);
}

function main(argv) {
  const { command, options } = parseArguments([...argv]);
  const policyText = readRegularFile(options.policy, "policy");
  const sourceLockText = readRegularFile(options["source-lock"], "ownership source lock");
  if (command === "validate") {
    const result = validatePolicy({ policy: policyText, sourceLock: sourceLockText });
    process.stdout.write(`${canonicalJson({
      schema: POLICY_SCHEMA,
      projectName: result.projectName,
      policySha256: result.policySha256,
      proposedOwners: result.applications.map(({ owner }) => owner),
      sourceLockSha256: result.ownershipSourceLock.sha256,
      renderer: result.renderer
    })}\n`);
    return;
  }
  const manifest = compileManifest({
    policyText,
    sourceLockText,
    renderText: readRegularFile(options.render, "canonical Compose render"),
    inventoryText: readRegularFile(options["runtime-inventory"], "runtime inventory"),
    previousManifestText: options["previous-manifest"]
      ? readRootOwnedManifest(options["previous-manifest"])
      : null
  });
  process.stdout.write(`${canonicalJson(manifest)}\n`);
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
