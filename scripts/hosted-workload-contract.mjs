#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  assertBrokerPolicyDigest,
  brokerPolicySha256,
  normalizeWorkloadBrokers,
  validateGlobalBrokerOwnership,
} from "./workload-broker-policy.mjs";

const ID = /^[a-z][a-z0-9-]{1,62}$/;
const SERVICE = /^[a-z][a-z0-9-]{1,62}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const IMAGE = /^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]+)?@sha256:[a-f0-9]{64}$/;
const SAFE_PATH = /^[A-Za-z0-9_./-]+$/;
export const HOSTED_WORKLOAD_LOCK_VERSION = 2;
export const HOSTED_WORKLOAD_VALIDATOR_VERSION = "hosted-contract-v2";
const PLATFORM_DEPENDENCIES = new Set([
  "postgres",
  "redis",
  "nats",
  "minio",
  "keycloak",
  "alertmanager",
]);
const PLATFORM_NETWORK_EXTENSION_ZONES = new Map([
  ["project-router", new Set(["ingress"])],
  ["postgres", new Set(["postgres"])],
  ["redis", new Set(["cache"])],
  ["nats", new Set(["bus"])],
  ["keycloak", new Set(["identity"])],
  ["minio", new Set(["storage"])],
  ["prometheus", new Set(["observability"])],
]);
const WORKLOAD_NETWORK_ZONES = new Set(["ingress", "postgres", "cache", "bus", "identity", "storage", "observability", "egress"]);

function invalid(message) {
  throw new Error(message);
}

function readJson(filePath, label = filePath) {
  try {
    const { bytes } = readStableRegularFile(filePath, label);
    return JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    invalid(`${label} is not valid JSON: ${error.message}`);
  }
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function sha256Bytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
}

function same(left, right) {
  return JSON.stringify(stable(left)) === JSON.stringify(stable(right));
}

function workloadNetworkPrefix(id) {
  return `${id.replaceAll("-", "_")}_`;
}

function workloadNetworkOwner(network, workloadIds) {
  return workloadIds.find((id) => network.startsWith(workloadNetworkPrefix(id)));
}

function workloadNetworkZone(network, workloadId) {
  return network.slice(workloadNetworkPrefix(workloadId).length);
}

function requiredText(value, label) {
  const text = String(value ?? "").trim();
  if (!text || /[\0\r\n]/.test(text)) invalid(`${label} is missing or invalid.`);
  return text;
}

function resolveWithin(root, value, label) {
  const text = requiredText(value, label);
  if (!SAFE_PATH.test(text) || text.includes("//") || text.split("/").includes("..")) {
    invalid(`${label} contains unsupported path syntax.`);
  }
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, text);
  if (resolved !== resolvedRoot && !resolved.startsWith(`${resolvedRoot}${path.sep}`)) {
    invalid(`${label} escapes its allowed root.`);
  }
  return resolved;
}

function physicalRoot(root, label) {
  const lexicalRoot = path.resolve(root);
  assertNoSymlinkPathComponents(lexicalRoot, label);
  const rootStat = fs.lstatSync(lexicalRoot, { throwIfNoEntry: false });
  if (!rootStat?.isDirectory() || rootStat.isSymbolicLink()) {
    invalid(`${label} must be a real non-symlink directory.`);
  }
  return fs.realpathSync.native(lexicalRoot);
}

function assertNoSymlinkPathComponents(absolutePath, label) {
  const resolved = path.resolve(absolutePath);
  const parsed = path.parse(resolved);
  let cursor = parsed.root;
  for (const component of resolved.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, component);
    const stat = fs.lstatSync(cursor, { throwIfNoEntry: false });
    if (!stat) invalid(`${label} path component does not exist: ${cursor}`);
    if (stat.isSymbolicLink()) invalid(`${label} contains a symlink component: ${cursor}`);
  }
}

function resolvePhysicalWithin(root, value, label, expectedType) {
  const lexicalRoot = path.resolve(root);
  const canonicalRoot = physicalRoot(lexicalRoot, `${label} root`);
  const lexical = resolveWithin(lexicalRoot, value, label);
  let cursor = lexicalRoot;
  const relative = path.relative(lexicalRoot, lexical);
  for (const component of relative.split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, component);
    const entry = fs.lstatSync(cursor, { throwIfNoEntry: false });
    if (!entry) invalid(`${label} does not exist: ${cursor}`);
    if (entry.isSymbolicLink()) invalid(`${label} contains a symlink component: ${cursor}`);
  }
  const canonical = fs.realpathSync.native(lexical);
  if (canonical !== canonicalRoot && !canonical.startsWith(`${canonicalRoot}${path.sep}`)) {
    invalid(`${label} escapes its physical root.`);
  }
  const stat = fs.lstatSync(canonical, { throwIfNoEntry: false });
  if (expectedType === "file" && !stat?.isFile()) invalid(`${label} must be a regular file.`);
  if (expectedType === "directory" && !stat?.isDirectory()) invalid(`${label} must be a directory.`);
  return canonical;
}

function fileRecord(filePath, kind) {
  const stat = fs.lstatSync(filePath, { throwIfNoEntry: false });
  if (!stat?.isFile() || stat.isSymbolicLink()) invalid(`${kind} file does not exist or is symlinked: ${filePath}`);
  return { kind, path: filePath, sha256: sha256File(filePath), sizeBytes: stat.size };
}

function readStableRegularFile(filePath, label) {
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
    const before = fs.fstatSync(descriptor);
    if (!before.isFile()) invalid(`${label} must be a regular file.`);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
      invalid(`${label} changed while it was being read.`);
    }
    return { bytes, stat: after };
  } catch (error) {
    invalid(`${label} could not be read safely: ${error.message}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function createSnapshotGeneration(snapshotRoot) {
  fs.mkdirSync(snapshotRoot, { recursive: true, mode: 0o700 });
  const canonicalRoot = physicalRoot(snapshotRoot, "snapshot root");
  const stat = fs.lstatSync(canonicalRoot, { throwIfNoEntry: false });
  if (!stat?.isDirectory() || stat.isSymbolicLink()) invalid("Snapshot root must be a real directory.");
  fs.chmodSync(snapshotRoot, 0o700);
  const generation = fs.mkdtempSync(path.join(canonicalRoot, ".staging-"));
  fs.chmodSync(generation, 0o700);
  return { root: canonicalRoot, generation: fs.realpathSync.native(generation), nextIndex: 0 };
}

function fileIdentity(filePath) {
  const stat = fs.lstatSync(filePath, { bigint: true, throwIfNoEntry: false });
  if (!stat) invalid(`Snapshot identity is missing: ${filePath}`);
  return { device: String(stat.dev), inode: String(stat.ino), uid: String(stat.uid), mode: Number(stat.mode & 0o777n) };
}

function sameIdentity(actual, expected) {
  return actual.device === String(expected?.device)
    && actual.inode === String(expected?.inode)
    && actual.uid === String(expected?.uid)
    && actual.mode === Number(expected?.mode);
}

function finalizeSnapshot(snapshot, records, contentDigest) {
  const staging = snapshot.generation;
  const finalGeneration = path.join(snapshot.root, `content-${contentDigest}`);
  if (fs.existsSync(finalGeneration)) {
    const existing = fs.lstatSync(finalGeneration);
    if (!existing.isDirectory() || existing.isSymbolicLink()) invalid("Existing content-addressed snapshot is not a real directory.");
    for (const record of records.filter((item) => item.snapshot === true)) {
      const existingPath = path.join(finalGeneration, path.basename(record.path));
      const stat = fs.lstatSync(existingPath, { throwIfNoEntry: false });
      if (!stat?.isFile() || stat.isSymbolicLink() || sha256Bytes(readStableRegularFile(existingPath, record.kind).bytes) !== record.sha256) {
        invalid(`Existing content-addressed snapshot does not match ${record.kind}.`);
      }
    }
    fs.rmSync(staging, { recursive: true, force: true });
  } else {
    fs.renameSync(staging, finalGeneration);
  }
  fs.chmodSync(finalGeneration, 0o500);
  snapshot.generation = finalGeneration;
  for (const record of records.filter((item) => item.snapshot === true)) {
    record.path = path.join(finalGeneration, path.basename(record.path));
    const identity = fileIdentity(record.path);
    record.snapshotDevice = identity.device;
    record.snapshotInode = identity.inode;
    record.snapshotUid = identity.uid;
  }
  return {
    rootIdentity: fileIdentity(snapshot.root),
    generationIdentity: fileIdentity(finalGeneration),
  };
}

function snapshotFile(sourcePath, kind, snapshot, metadata = {}) {
  const { bytes } = readStableRegularFile(sourcePath, kind);
  const suffix = path.extname(sourcePath).replace(/[^A-Za-z0-9.]/g, "") || ".data";
  const name = `${String(snapshot.nextIndex++).padStart(4, "0")}-${kind.replace(/[^a-z0-9-]/gi, "-")}${suffix}`;
  const snapshotPath = path.join(snapshot.generation, name);
  const descriptor = fs.openSync(snapshotPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o400);
  try {
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.chmodSync(snapshotPath, 0o400);
  return {
    kind,
    sourcePath,
    path: snapshotPath,
    sha256: sha256Bytes(bytes),
    sizeBytes: bytes.length,
    snapshot: true,
    ...metadata,
  };
}

function workloadContentSha256(records) {
  const content = records
    .filter((record) => record.snapshot === true)
    .map(({ kind, sourcePath, sha256, sizeBytes, workloadId = null }) => ({ kind, sourcePath, sha256, sizeBytes, workloadId }))
    .sort((left, right) => `${left.workloadId}:${left.kind}:${left.sourcePath}`.localeCompare(`${right.workloadId}:${right.kind}:${right.sourcePath}`));
  return sha256Bytes(Buffer.from(JSON.stringify(stable(content))));
}

export function validateWorkloadEnvironmentText(text, workloadId, label = "workload environment") {
  const prefix = `${workloadId.toUpperCase().replaceAll("-", "_")}_`;
  const names = new Set();
  for (const [index, rawLine] of String(text).split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    if (separator < 1) invalid(`${label}:${index + 1} is not KEY=value.`);
    const name = line.slice(0, separator).trim();
    const value = line.slice(separator + 1);
    if (!/^[A-Z][A-Z0-9_]*$/.test(name) || !name.startsWith(prefix)) {
      invalid(`${label}:${index + 1} must use the ${prefix} prefix.`);
    }
    if (names.has(name)) invalid(`${label} contains duplicate variable ${name}.`);
    names.add(name);
    if (/(?:PASSWORD|TOKEN|SECRET|DATABASE_URL|NATS_URL)(?:_|$)/.test(name)) {
      invalid(`${label} cannot contain sensitive variable ${name}; use an external Docker secret.`);
    }
    if (/\$\{[^}]+\}/.test(value) || /[\0\r\n]/.test(value)) invalid(`${label}:${index + 1} has unsupported interpolation or control characters.`);
    if (/\b(?:postgres|mysql|mariadb|nats):\/\/[^/@:\s]+:[^/@\s]+@/i.test(value)) {
      invalid(`${label}:${index + 1} embeds credentials.`);
    }
  }
  if (names.size === 0) invalid(`${label} must contain at least one workload-prefixed variable.`);
  return [...names].sort();
}

function workloadEnvironmentRecord(filePath, workloadId, snapshot) {
  const record = snapshotFile(filePath, "workload-environment", snapshot, { workloadId });
  validateWorkloadEnvironmentText(fs.readFileSync(record.path, "utf8"), workloadId, filePath);
  return record;
}

function sqlRecords(root, relativeRoots, snapshot, workloadId) {
  const records = [];
  for (const relativeRoot of relativeRoots ?? []) {
    const directory = resolvePhysicalWithin(root, relativeRoot, "migration root", "directory");
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
      if (!entry.name.endsWith(".sql")) continue;
      if (entry.isSymbolicLink() || !entry.isFile()) invalid(`Migration must be a regular non-symlink file: ${path.join(directory, entry.name)}`);
      const migrationPath = resolvePhysicalWithin(directory, entry.name, "migration", "file");
      records.push(snapshotFile(migrationPath, "migration", snapshot, { workloadId }));
    }
  }
  return records;
}

function normalizeDnsHost(value, label) {
  const host = requiredText(value, label).toLowerCase().replace(/\.$/, "");
  if (host.length > 253 || host.includes(":") || host.includes("*") || host.split(".").some((part) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part))) {
    invalid(`${label} must be an exact normalized DNS hostname.`);
  }
  return host;
}

function normalizeRoute(route, serviceName, workloadId) {
  const slug = requiredText(route?.slug, `route slug for ${serviceName}`).toLowerCase();
  const port = Number(route?.port);
  if (!ID.test(slug)) invalid(`Route slug '${slug}' is invalid.`);
  if (!Number.isInteger(port) || port < 1 || port > 65535) invalid(`Route port for ${slug} is invalid.`);
  const canonicalHost = normalizeDnsHost(route?.host, `route host for ${slug}`);
  const labels = canonicalHost.split(".");
  if (labels[0] !== slug) invalid(`Route host for ${slug} must begin with the exact route slug.`);
  if (route?.aliases !== undefined && !Array.isArray(route.aliases)) invalid(`Route aliases for ${slug} must be an array.`);
  const aliases = [...new Set((route?.aliases ?? []).map((value) => requiredText(value, `route alias for ${slug}`).toLowerCase()))].sort();
  for (const alias of aliases) {
    if (!ID.test(alias) || alias === slug) invalid(`Route alias '${alias}' for ${slug} is invalid.`);
  }
  const suffix = labels.slice(1).join(".");
  const hosts = [canonicalHost, ...aliases.map((alias) => suffix ? `${alias}.${suffix}` : alias)];
  return { owner: workloadId, slug, aliases, canonicalHost, hosts, port };
}

export function validateGlobalRouteOwnership(workloads, { reservedHosts = [] } = {}) {
  const nameClaims = new Map();
  const hostClaims = new Map([...reservedHosts].map((host) => [normalizeDnsHost(host, "reserved route host"), "platform"]));
  const upstreamClaims = new Map();
  const claims = [];
  for (const workload of workloads) {
    for (const service of workload.services ?? []) {
      for (const route of service.routes ?? []) {
        claims.push({ workloadId: workload.id, service: service.name, route, identity: `${workload.id}/${service.name}/${route.slug}` });
      }
    }
  }
  claims.sort((left, right) => left.identity.localeCompare(right.identity));
  for (const claim of claims) {
    const { workloadId, service, route, identity } = claim;
    if (route.owner !== workloadId) invalid(`Route ${identity} is not bound to its workload owner.`);
    for (const name of [route.slug, ...route.aliases]) claimUnique(nameClaims, name, identity, "slug or alias");
    for (const host of route.hosts) claimUnique(hostClaims, host, identity, "host");
    claimUnique(upstreamClaims, `${service}:${route.port}`, identity, "upstream");
  }
  return true;
}

function claimUnique(registry, value, identity, kind) {
  const previous = registry.get(value);
  if (previous && previous !== identity) {
    const owners = [previous, identity].sort();
    invalid(`Global route ${kind} '${value}' is claimed by both ${owners[0]} and ${owners[1]}.`);
  }
  registry.set(value, identity);
}

function reservedHostsFromEnvironment(filePath) {
  const values = new Map();
  for (const line of readStableRegularFile(path.resolve(filePath), "core environment").bytes.toString("utf8").split(/\r?\n/)) {
    const separator = line.indexOf("=");
    if (separator < 1) continue;
    values.set(line.slice(0, separator).trim(), line.slice(separator + 1).trim().replace(/^['"]|['"]$/g, ""));
  }
  const domain = values.get("DOMAIN") || values.get("LOCAL_DOMAIN") || "";
  const hosts = [
    "ADMIN_HOST",
    "CONTROL_CENTER_HOST",
    "DOCS_HOST",
    "AUTH_HOST",
    "STORAGE_HOST",
    "MINIO_CONSOLE_HOST",
    "GRAFANA_HOST",
    "PHPMYADMIN_HOST",
    "PROMETHEUS_HOST",
    "ALERTMANAGER_HOST",
    "TRAEFIK_DASHBOARD_HOST",
    "PROJECTS_HOST",
  ]
    .map((key) => values.get(key))
    .filter(Boolean);
  if (domain) hosts.push(domain, ...["portal", "docs", "app", "api", "auth", "storage", "grafana"].map((name) => `${name}.${domain}`));
  return [...new Set(hosts)];
}

export function validateWorkloadManifest(document, manifestPath = "manifest") {
  if (document?.version !== 1) invalid(`${manifestPath} must use version 1.`);
  const id = requiredText(document.id, "workload id").toLowerCase();
  if (!ID.test(id)) invalid(`Workload id '${id}' is invalid.`);
  const composeFile = requiredText(document.composeFile, "composeFile");
  if (!SAFE_PATH.test(composeFile) || path.isAbsolute(composeFile) || composeFile.split("/").includes("..")) {
    invalid("composeFile must be a contained relative path.");
  }
  const projectMetadataFile = document.projectMetadataFile == null
    ? null
    : requiredText(document.projectMetadataFile, "projectMetadataFile");
  if (projectMetadataFile && (!SAFE_PATH.test(projectMetadataFile) || path.isAbsolute(projectMetadataFile) || projectMetadataFile.split("/").includes(".."))) {
    invalid("projectMetadataFile must be a contained relative path.");
  }
  if (!Array.isArray(document.services) || document.services.length === 0) invalid(`${id} must declare services.`);
  const serviceNames = new Set();
  const routeSlugs = new Set();
  const services = document.services.map((service) => {
    const name = requiredText(service?.name, `service name for ${id}`).toLowerCase();
    const role = requiredText(service?.role, `service role for ${name}`).toLowerCase();
    if (!SERVICE.test(name) || !name.startsWith(`${id}-`)) invalid(`Service ${name} must be prefixed with ${id}-.`);
    if (!new Set(["api", "web", "worker", "scheduled-worker"]).has(role)) invalid(`Service ${name} has unsupported role ${role}.`);
    if (serviceNames.has(name)) invalid(`Duplicate service ${name}.`);
    serviceNames.add(name);
    const routes = (service.routes ?? []).map((route) => normalizeRoute(route, name, id));
    if (routes.length > 0 && !new Set(["api", "web"]).has(role)) invalid(`Only api/web services may expose routes: ${name}.`);
    for (const route of routes) {
      if (routeSlugs.has(route.slug)) invalid(`Duplicate route slug ${route.slug}.`);
      routeSlugs.add(route.slug);
    }
    return { name, role, routes };
  });
  const secrets = [...new Set((document.secrets ?? []).map((value) => requiredText(value, "secret name")))].sort();
  for (const secret of secrets) {
    if (!SERVICE.test(secret) || !secret.startsWith(`${id}-`)) invalid(`Secret ${secret} must be workload-prefixed.`);
  }
  const brokers = normalizeWorkloadBrokers(document.brokers, { id, services, secrets });
  return {
    version: 1,
    id,
    composeFile,
    projectMetadataFile,
    services,
    secrets,
    brokers,
    migrationRoots: [...new Set(document.migrationRoots ?? [])],
  };
}

export function resolveCatalog({ catalogPath, workloadRoot, coreEnvFile, coreFiles, projectName, snapshotRoot }) {
  const snapshot = createSnapshotGeneration(path.resolve(requiredText(snapshotRoot, "snapshot root")));
  const catalogRecord = snapshotFile(path.resolve(catalogPath), "catalog", snapshot);
  const catalog = readJson(catalogRecord.path, "hosted workload catalog");
  if (catalog?.version !== 1 || !Array.isArray(catalog.workloads)) {
    invalid("Hosted workload catalog must use version 1 and workloads[].");
  }
  const root = physicalRoot(workloadRoot, "workload root");
  const records = [catalogRecord, fileRecord(path.resolve(coreEnvFile), "core-environment")];
  for (const coreFile of coreFiles) records.push(fileRecord(path.resolve(coreFile), "core-compose"));
  const ids = new Set();
  const services = new Set();
  const workloads = catalog.workloads.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) invalid("Each workload catalog entry must be an object.");
    const manifestPath = resolvePhysicalWithin(root, entry.manifest, "workload manifest", "file");
    const manifestRecord = snapshotFile(manifestPath, "workload-manifest", snapshot);
    const manifest = validateWorkloadManifest(readJson(manifestRecord.path), manifestPath);
    const environmentPath = resolvePhysicalWithin(root, entry.environmentFile, `environment file for ${manifest.id}`, "file");
    if (ids.has(manifest.id)) invalid(`Duplicate workload id ${manifest.id}.`);
    ids.add(manifest.id);
    for (const service of manifest.services) {
      if (services.has(service.name)) invalid(`Duplicate workload service ${service.name}.`);
      services.add(service.name);
    }
    const composePath = resolvePhysicalWithin(path.dirname(manifestPath), manifest.composeFile, "workload compose file", "file");
    manifestRecord.workloadId = manifest.id;
    const composeRecord = snapshotFile(composePath, "workload-compose", snapshot, { workloadId: manifest.id });
    const environmentRecord = workloadEnvironmentRecord(environmentPath, manifest.id, snapshot);
    const workloadRecords = [manifestRecord, composeRecord, environmentRecord];
    let projectMetadataRecord = null;
    if (manifest.projectMetadataFile) {
      const projectMetadataSourcePath = resolvePhysicalWithin(path.dirname(manifestPath), manifest.projectMetadataFile, "project metadata file", "file");
      projectMetadataRecord = snapshotFile(projectMetadataSourcePath, "project-metadata", snapshot, { workloadId: manifest.id });
      workloadRecords.push(projectMetadataRecord);
    }
    workloadRecords.push(...sqlRecords(path.dirname(manifestPath), manifest.migrationRoots, snapshot, manifest.id));
    records.push(...workloadRecords);
    return {
      ...manifest,
      manifestPath: manifestRecord.path,
      manifestSourcePath: manifestPath,
      composePath: composeRecord.path,
      composeSourcePath: composePath,
      environmentPath: environmentRecord.path,
      environmentSourcePath: environmentPath,
      projectMetadataPath: projectMetadataRecord?.path ?? null,
      projectMetadataSourcePath: projectMetadataRecord?.sourcePath ?? null,
      files: workloadRecords,
    };
  });
  validateGlobalRouteOwnership(workloads, { reservedHosts: reservedHostsFromEnvironment(coreEnvFile) });
  validateGlobalBrokerOwnership(workloads);
  const contentDigest = workloadContentSha256(records);
  const snapshotReceipt = finalizeSnapshot(snapshot, records, contentDigest);
  for (const workload of workloads) {
    workload.manifestPath = workload.files.find((record) => record.kind === "workload-manifest").path;
    workload.composePath = workload.files.find((record) => record.kind === "workload-compose").path;
    workload.environmentPath = workload.files.find((record) => record.kind === "workload-environment").path;
    workload.projectMetadataPath = workload.files.find((record) => record.kind === "project-metadata")?.path ?? null;
  }
  return {
    version: HOSTED_WORKLOAD_LOCK_VERSION,
    validatorVersion: HOSTED_WORKLOAD_VALIDATOR_VERSION,
    state: "resolved",
    generatedAt: new Date().toISOString(),
    snapshotRoot: snapshot.root,
    snapshotGeneration: snapshot.generation,
    snapshotRootIdentity: snapshotReceipt.rootIdentity,
    snapshotGenerationIdentity: snapshotReceipt.generationIdentity,
    workloadRoot: root,
    catalogPath: path.resolve(catalogPath),
    coreEnvFile: path.resolve(coreEnvFile),
    projectName: requiredText(projectName, "Compose project name"),
    coreFiles: coreFiles.map((file) => path.resolve(file)),
    workloads,
    brokerPolicySha256: brokerPolicySha256(workloads),
    files: records,
    workloadContentSha256: contentDigest,
  };
}

function objectWithoutNetworks(service, name) {
  const copy = structuredClone(service);
  delete copy.networks;
  if (name === "redis" || name === "nats") delete copy.secrets;
  return copy;
}

function serviceNetworks(service) {
  return new Set(Object.keys(service?.networks ?? {}));
}

function assertPlatformServicesUnchanged(core, combined, workloadIds) {
  for (const [name, coreService] of Object.entries(core.services ?? {})) {
    const combinedService = combined.services?.[name];
    if (!combinedService) invalid(`Workload overlays removed platform service ${name}.`);
    if (!same(objectWithoutNetworks(coreService, name), objectWithoutNetworks(combinedService, name))) {
      invalid(`Workload overlays changed protected platform service ${name}.`);
    }
    const coreNetworks = serviceNetworks(coreService);
    const combinedNetworks = serviceNetworks(combinedService);
    const additions = [...combinedNetworks].filter((network) => !coreNetworks.has(network));
    for (const network of additions) {
      const owner = workloadNetworkOwner(network, workloadIds);
      if (!owner) invalid(`Platform service ${name} received non-workload network ${network}.`);
      const zone = workloadNetworkZone(network, owner);
      if (!PLATFORM_NETWORK_EXTENSION_ZONES.get(name)?.has(zone)) {
        invalid(`Platform service ${name} cannot join workload ${owner} zone ${zone}.`);
      }
    }
  }
}

function assertResourceLimits(name, service) {
  const cpus = Number(service.cpus);
  const memLimit = Number(service.mem_limit);
  const memReservation = Number(service.mem_reservation);
  const pids = Number(service.pids_limit);
  const cpuShares = Number(service.cpu_shares);
  const ioWeight = Number(service.blkio_config?.weight);
  const nofile = Number(typeof service.ulimits?.nofile === "object" ? service.ulimits.nofile.hard : service.ulimits?.nofile);
  if (!(cpus >= 0.1 && cpus <= 2)) invalid(`${name} requires cpus between 0.1 and 2.`);
  if (!(memLimit >= 64 * 1024 * 1024 && memLimit <= 2 * 1024 * 1024 * 1024)) invalid(`${name} requires a bounded mem_limit.`);
  if (!(memReservation >= 16 * 1024 * 1024 && memReservation <= memLimit)) invalid(`${name} requires a valid mem_reservation.`);
  if (!(pids >= 16 && pids <= 512)) invalid(`${name} requires pids_limit between 16 and 512.`);
  if (!(cpuShares >= 2 && cpuShares <= 1024)) invalid(`${name} requires bounded cpu_shares.`);
  if (!(ioWeight >= 10 && ioWeight <= 1000)) invalid(`${name} requires bounded block I/O weight.`);
  if (!(nofile >= 1024 && nofile <= 65536)) invalid(`${name} requires a bounded nofile limit.`);
}

function assertEnvironmentSecrets(name, service) {
  for (const [key, rawValue] of Object.entries(service.environment ?? {})) {
    const value = String(rawValue ?? "");
    if (key.endsWith("_FILE")) {
      if (!value.startsWith("/run/secrets/") || !SERVICE.test(value.slice("/run/secrets/".length))) {
        invalid(`${name} has an invalid secret file path for ${key}.`);
      }
      continue;
    }
    if (/(?:PASSWORD|TOKEN|SECRET|DATABASE_URL|NATS_URL)$/i.test(key) && value) {
      invalid(`${name} exposes sensitive environment variable ${key}; use a Docker secret file.`);
    }
    if (/\b(?:postgres|mysql|mariadb):\/\/[^/@:\s]+:[^/@\s]+@/i.test(value)) {
      invalid(`${name} embeds credentials in environment variable ${key}.`);
    }
  }
}

function assertSecrets(name, service, manifest, combined) {
  const allowed = new Set(manifest.secrets);
  for (const entry of service.secrets ?? []) {
    const source = typeof entry === "string" ? entry : entry.source;
    if (!allowed.has(source)) invalid(`${name} uses undeclared secret ${source}.`);
    if (combined.secrets?.[source]?.external !== true) invalid(`${name} secret ${source} must be external.`);
  }
}

function assertVolumes(name, service, workloadId) {
  for (const volume of service.volumes ?? []) {
    if (volume.type !== "volume" || !String(volume.source ?? "").startsWith(`${workloadId}_`)) {
      invalid(`${name} may use only workload-prefixed named volumes; bind mounts are forbidden.`);
    }
  }
}

function assertWorkloadService({ serviceDefinition, manifestService, manifest, combined }) {
  const name = manifestService.name;
  if (!IMAGE.test(String(serviceDefinition.image ?? ""))) invalid(`${name} image must be digest-pinned.`);
  if (serviceDefinition.build) invalid(`${name} cannot build inside the platform deployment.`);
  if (serviceDefinition.container_name) invalid(`${name} cannot reserve a global container_name.`);
  if (serviceDefinition.privileged || serviceDefinition.network_mode === "host" || serviceDefinition.pid === "host" || serviceDefinition.ipc === "host") {
    invalid(`${name} requests a host-level privilege.`);
  }
  if (Array.isArray(serviceDefinition.ports) && serviceDefinition.ports.length > 0) invalid(`${name} cannot publish host ports.`);
  if (serviceDefinition.read_only !== true) invalid(`${name} must use a read-only root filesystem.`);
  if (serviceDefinition.init !== true || serviceDefinition.restart !== "unless-stopped") invalid(`${name} requires init and restart=unless-stopped.`);
  if (!serviceDefinition.security_opt?.includes("no-new-privileges:true")) invalid(`${name} must enable no-new-privileges.`);
  if (!serviceDefinition.cap_drop?.includes("ALL") || (serviceDefinition.cap_add?.length ?? 0) > 0) invalid(`${name} must drop all capabilities.`);
  if (!serviceDefinition.user || /^(?:0|root)(?::|$)/.test(String(serviceDefinition.user))) invalid(`${name} must declare a non-root user.`);
  if (!Array.isArray(serviceDefinition.healthcheck?.test) || serviceDefinition.healthcheck.test.length < 2 || serviceDefinition.healthcheck.disable === true) {
    invalid(`${name} requires a functional healthcheck.`);
  }
  assertResourceLimits(name, serviceDefinition);
  assertEnvironmentSecrets(name, serviceDefinition);
  assertSecrets(name, serviceDefinition, manifest, combined);
  assertVolumes(name, serviceDefinition, manifest.id);
  const networks = serviceNetworks(serviceDefinition);
  if (networks.size === 0) invalid(`${name} must declare networks.`);
  for (const network of networks) {
    if (!network.startsWith(workloadNetworkPrefix(manifest.id))) invalid(`${name} uses unauthorized network ${network}.`);
  }
  for (const dependency of Object.keys(serviceDefinition.depends_on ?? {})) {
    if (!manifest.services.some((service) => service.name === dependency) && !PLATFORM_DEPENDENCIES.has(dependency)) {
      invalid(`${name} depends on unauthorized service ${dependency}.`);
    }
  }
  if (serviceDefinition.labels?.["com.platform.workload-id"] !== manifest.id || serviceDefinition.labels?.["com.platform.workload-role"] !== manifestService.role) {
    invalid(`${name} workload labels do not match its manifest.`);
  }
}

function secretEntries(service) {
  return (service?.secrets ?? []).map((entry) => {
    if (typeof entry === "string") return { source: entry, target: entry };
    return { source: String(entry?.source ?? ""), target: String(entry?.target ?? entry?.source ?? "") };
  });
}

function assertBrokerEnvironment(name, service, manifest, manifestService) {
  const networks = serviceNetworks(service);
  const secrets = new Set(secretEntries(service).map((entry) => entry.source));
  const environment = service.environment ?? {};
  const prefix = workloadNetworkPrefix(manifest.id);
  const usesRedis = networks.has(`${prefix}cache`);
  const usesNats = networks.has(`${prefix}bus`);
  if (usesRedis) {
    const policy = manifest.brokers?.redis;
    if (!policy) invalid(`${name} joins the cache zone without a locked Redis ACL identity.`);
    const expected = {
      REDIS_HOST: "redis",
      REDIS_PORT: "6379",
      REDIS_USERNAME: policy.username,
      REDIS_PASSWORD_FILE: `/run/secrets/${policy.credentialSecret}`,
      REDIS_KEY_PREFIX: policy.keyPrefix,
      REDIS_CHANNEL_PREFIX: policy.channelPrefix,
    };
    if (!secrets.has(policy.credentialSecret) || Object.entries(expected).some(([key, value]) => String(environment[key] ?? "") !== value)) {
      invalid(`${name} Redis connection fields do not match its locked ACL identity.`);
    }
  }
  const natsUser = manifest.brokers?.nats?.users.find((user) => user.service === manifestService.name) ?? null;
  if (usesNats) {
    if (!natsUser) invalid(`${name} joins the bus zone without a locked NATS service identity.`);
    const expected = {
      NATS_HOST: "nats",
      NATS_PORT: "4222",
      NATS_ACCOUNT: manifest.brokers.nats.account,
      NATS_USERNAME: natsUser.username,
      NATS_PASSWORD_FILE: `/run/secrets/${natsUser.credentialSecret}`,
      NATS_SUBJECT_PREFIX: natsUser.publish[0].slice(0, -1),
      NATS_QUEUE_GROUP: natsUser.queueGroups[0],
    };
    if (!secrets.has(natsUser.credentialSecret) || Object.entries(expected).some(([key, value]) => String(environment[key] ?? "") !== value)) {
      invalid(`${name} NATS connection fields do not match its locked account identity.`);
    }
  } else if (natsUser) {
    invalid(`${name} declares a NATS identity but does not join its workload bus zone.`);
  }
  return { usesRedis, usesNats };
}

function validateBrokerCoreSecretExtensions({ core, combined, workloads }) {
  const expectedByService = new Map([
    ["redis", workloads.flatMap((workload) => workload.brokers?.redis ? [workload.brokers.redis.credentialSecret] : [])],
    ["nats", workloads.flatMap((workload) => workload.brokers?.nats?.users.map((user) => user.credentialSecret) ?? [])],
  ]);
  for (const [serviceName, tenantSecrets] of expectedByService) {
    if (!core.services?.[serviceName]) {
      if (tenantSecrets.length) invalid(`Core broker ${serviceName} is missing for declared workload identities.`);
      continue;
    }
    const baseline = secretEntries(core.services[serviceName]);
    const expected = [
      ...baseline,
      ...tenantSecrets.map((source) => ({ source, target: source })),
    ].map((entry) => `${entry.source}\0${entry.target}`).sort();
    const actual = secretEntries(combined.services?.[serviceName]).map((entry) => `${entry.source}\0${entry.target}`).sort();
    if (!same(actual, expected)) invalid(`${serviceName} must mount exactly its core and locked workload credential secrets.`);
    for (const secret of tenantSecrets) {
      if (combined.secrets?.[secret]?.external !== true) invalid(`${serviceName} workload credential ${secret} must be external.`);
    }
  }
}

export function validateRenderedWorkloads({ core, combined, lock }) {
  validateGlobalRouteOwnership(lock.workloads);
  assertBrokerPolicyDigest(lock);
  const workloadIds = lock.workloads.map((workload) => workload.id);
  assertPlatformServicesUnchanged(core, combined, workloadIds);
  const declared = new Map();
  for (const workload of lock.workloads) {
    for (const service of workload.services) declared.set(service.name, { workload, service });
  }
  const coreNames = new Set(Object.keys(core.services ?? {}));
  const extras = Object.keys(combined.services ?? {}).filter((name) => !coreNames.has(name));
  if (!same(extras.sort(), [...declared.keys()].sort())) invalid("Rendered workload services do not exactly match the signed catalog.");
  const routes = [];
  const redisUsers = new Set();
  const natsUsers = new Set();
  for (const [name, item] of declared) {
    const rendered = combined.services?.[name];
    if (!rendered) invalid(`Rendered service ${name} is missing.`);
    assertWorkloadService({ serviceDefinition: rendered, manifestService: item.service, manifest: item.workload, combined });
    const brokerUse = assertBrokerEnvironment(name, rendered, item.workload, item.service);
    if (brokerUse.usesRedis) redisUsers.add(item.workload.id);
    if (brokerUse.usesNats) natsUsers.add(`${item.workload.id}/${item.service.name}`);
    for (const route of item.service.routes) {
      const workloadNetworks = [...serviceNetworks(rendered)].filter((network) => network.startsWith(workloadNetworkPrefix(item.workload.id)));
      const routerNetworks = serviceNetworks(combined.services?.["project-router"]);
      if (!workloadNetworks.some((network) => routerNetworks.has(network))) invalid(`Route ${route.slug} has no dedicated network shared with project-router.`);
      routes.push({
        owner: item.workload.id,
        workloadId: item.workload.id,
        slug: route.slug,
        aliases: route.aliases,
        canonicalHost: route.canonicalHost,
        hosts: route.hosts,
        service: name,
        port: route.port,
        upstream: `http://${name}:${route.port}`,
      });
    }
  }
  for (const workload of lock.workloads) {
    if (workload.brokers?.redis && !redisUsers.has(workload.id)) invalid(`${workload.id} declares Redis authorization without a cache-zone consumer.`);
    for (const user of workload.brokers?.nats?.users ?? []) {
      if (!natsUsers.has(`${workload.id}/${user.service}`)) invalid(`${workload.id} NATS user ${user.service} has no bus-zone consumer.`);
    }
  }
  validateBrokerCoreSecretExtensions({ core, combined, workloads: lock.workloads });
  for (const [name, network] of Object.entries(combined.networks ?? {})) {
    if (core.networks?.[name]) continue;
    const owner = lock.workloads.find((workload) => name.startsWith(workloadNetworkPrefix(workload.id)));
    if (!owner) invalid(`Undeclared workload network ${name}.`);
    const zone = workloadNetworkZone(name, owner.id);
    if (!WORKLOAD_NETWORK_ZONES.has(zone)) invalid(`Workload network ${name} has unsupported zone ${zone}.`);
    if (zone === "egress") {
      if (network?.internal === true || network?.enable_ipv6 === true) invalid(`Workload egress network ${name} must allow IPv4 egress with IPv6 disabled.`);
    } else if (network?.internal !== true) {
      invalid(`Workload network ${name} must be internal.`);
    }
  }
  return { routes: routes.sort((a, b) => a.canonicalHost.localeCompare(b.canonicalHost)) };
}

export function verifyLockFiles(lock) {
  if (lock?.version !== HOSTED_WORKLOAD_LOCK_VERSION || lock?.validatorVersion !== HOSTED_WORKLOAD_VALIDATOR_VERSION) {
    invalid(`Hosted workload lock must use schema ${HOSTED_WORKLOAD_LOCK_VERSION} and validator ${HOSTED_WORKLOAD_VALIDATOR_VERSION}.`);
  }
  if (!Array.isArray(lock?.files) || lock.files.length === 0) invalid("Workload lock has no file records.");
  assertBrokerPolicyDigest(lock);
  const snapshotGeneration = physicalRoot(requiredText(lock.snapshotGeneration, "snapshot generation"), "snapshot generation");
  if (path.dirname(snapshotGeneration) !== physicalRoot(requiredText(lock.snapshotRoot, "snapshot root"), "snapshot root")) {
    invalid("Snapshot generation is outside the locked snapshot root.");
  }
  if (!sameIdentity(fileIdentity(lock.snapshotRoot), lock.snapshotRootIdentity)
      || !sameIdentity(fileIdentity(snapshotGeneration), lock.snapshotGenerationIdentity)) {
    invalid("Snapshot root or generation identity changed after resolution.");
  }
  const effectiveUid = typeof process.getuid === "function" ? String(process.getuid()) : lock.snapshotRootIdentity.uid;
  if (String(lock.snapshotRootIdentity.uid) !== effectiveUid || String(lock.snapshotGenerationIdentity.uid) !== effectiveUid) {
    invalid("Snapshot root and generation must be owned by the deployment identity.");
  }
  if (lock.snapshotRootIdentity.mode !== 0o700 || lock.snapshotGenerationIdentity.mode !== 0o500) {
    invalid("Snapshot root or generation permissions are not deployment-owned.");
  }
  for (const record of lock.files) {
    if (!SHA256.test(String(record.sha256 ?? ""))) invalid(`Invalid lock digest for ${record.path}.`);
    if (record.snapshot === true) {
      if (path.dirname(record.path) !== snapshotGeneration) invalid(`Snapshot file is outside the locked generation: ${record.path}.`);
      const stat = fs.lstatSync(record.path, { throwIfNoEntry: false });
      if (!stat?.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o400) invalid(`Snapshot file is not immutable: ${record.path}.`);
      const identity = fileIdentity(record.path);
      if (identity.device !== String(record.snapshotDevice) || identity.inode !== String(record.snapshotInode)
          || identity.uid !== String(record.snapshotUid) || identity.uid !== String(lock.snapshotGenerationIdentity.uid)) {
        invalid(`Snapshot file identity or owner changed: ${record.path}.`);
      }
    }
    const { bytes } = readStableRegularFile(record.path, `locked ${record.kind}`);
    if (sha256Bytes(bytes) !== record.sha256) invalid(`Locked file changed: ${record.path}.`);
  }
  const expectedContent = workloadContentSha256(lock.files);
  if (!SHA256.test(String(lock.workloadContentSha256 ?? "")) || lock.workloadContentSha256 !== expectedContent) {
    invalid("Hosted workload content digest does not match its verified snapshot records.");
  }
  return true;
}

function parseArgs(values) {
  const out = { _: [] };
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (!value.startsWith("--")) out._.push(value);
    else out[value.slice(2)] = values[index + 1] && !values[index + 1].startsWith("--") ? values[++index] : true;
  }
  return out;
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function main() {
  const command = process.argv[2];
  const args = parseArgs(process.argv.slice(3));
  if (command === "resolve") {
    const lock = resolveCatalog({
      catalogPath: path.resolve(requiredText(args.catalog, "--catalog")),
      workloadRoot: path.resolve(requiredText(args.workloadRoot, "--workloadRoot")),
      coreEnvFile: path.resolve(requiredText(args.envFile, "--envFile")),
      coreFiles: requiredText(args.coreFiles, "--coreFiles").split(",").map((file) => path.resolve(file)),
      projectName: requiredText(args.projectName, "--projectName"),
      snapshotRoot: path.resolve(requiredText(args.snapshotRoot, "--snapshotRoot")),
    });
    writeJson(path.resolve(requiredText(args.output, "--output")), lock);
    return;
  }
  if (command === "verify-render") {
    const lockPath = path.resolve(requiredText(args.lock, "--lock"));
    const lock = readJson(lockPath, "workload lock");
    verifyLockFiles(lock);
    const corePath = path.resolve(requiredText(args.coreRender, "--coreRender"));
    const combinedPath = path.resolve(requiredText(args.combinedRender, "--combinedRender"));
    const validation = validateRenderedWorkloads({ core: readJson(corePath), combined: readJson(combinedPath), lock });
    writeJson(path.resolve(requiredText(args.output, "--output")), {
      ...lock,
      state: "verified",
      verifiedAt: new Date().toISOString(),
      coreRenderSha256: sha256File(corePath),
      combinedRenderSha256: sha256File(combinedPath),
      routes: validation.routes,
    });
    return;
  }
  if (command === "verify-lock") {
    const lock = readJson(path.resolve(requiredText(args.lock, "--lock")), "workload lock");
    if (lock.state !== "verified") invalid("Workload lock is not verified.");
    verifyLockFiles(lock);
    return;
  }
  if (command === "compose-files") {
    const lock = readJson(path.resolve(requiredText(args.lock, "--lock")), "workload lock");
    if (lock.state !== "verified" && args.allowResolved !== "true") invalid("Workload lock is not verified.");
    verifyLockFiles(lock);
    process.stdout.write(`${lock.workloads.map((workload) => workload.composePath).join("\n")}\n`);
    return;
  }
  if (command === "env-files") {
    const lock = readJson(path.resolve(requiredText(args.lock, "--lock")), "workload lock");
    if (lock.state !== "verified" && args.allowResolved !== "true") invalid("Workload lock is not verified.");
    verifyLockFiles(lock);
    process.stdout.write(`${lock.workloads.map((workload) => workload.environmentPath).join("\n")}\n`);
    return;
  }
  invalid("Usage: hosted-workload-contract.mjs resolve|verify-render|verify-lock|compose-files|env-files");
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
