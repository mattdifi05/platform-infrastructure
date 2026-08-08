#!/usr/bin/env node
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {
  assertBrokerPolicyDigest,
  brokerPolicySha256,
  normalizeWorkloadBrokers,
  validateGlobalBrokerOwnership,
} from "./workload-broker-policy.mjs";

const WORKLOAD_ID = /^[a-z][a-z0-9-]{1,60}$/;
const SERVICE_NAME = /^[a-z][a-z0-9-]{1,62}$/;
const RESOURCE_NAME = /^[a-z][a-z0-9-]{1,62}$/;
const ROUTE_SLUG = /^[a-z][a-z0-9-]{1,62}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const IMAGE = /^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]+)?@sha256:[a-f0-9]{64}$/;
const SAFE_PATH = /^[A-Za-z0-9_./-]+$/;
const PRODUCTION_INFRASTRUCTURE_ROOT = "/srv/platform-infrastructure";
const TARGET_LOCAL_AUTHORITY = Symbol("target-local-core-environment-authority");
export const HOSTED_WORKLOAD_LOCK_VERSION = 4;
export const HOSTED_WORKLOAD_VALIDATOR_VERSION = "hosted-contract-v4";
const RAW_POLICY_CONTROLS = Object.freeze(["bind-bounded-dependencies", "bind-bounded-local-logging", "bind-closed-service-schema", "bind-exact-healthcheck", "bind-exact-security-opt", "bind-exact-ulimits", "bind-exact-volume-mounts", "bind-firewall-gated-restart", "bind-network-identity", "bind-network-topology", "bind-no-swap-oom-policy", "bind-owned-secret-aliases", "bind-owned-volume-driver", "bind-owned-volumes", "bind-platform-extension-records", "bind-private-pid-numeric-user", "deny-accelerator-environment", "deny-api-socket", "deny-compose-interpolation", "deny-deploy-controls", "deny-device-access", "deny-env-file", "deny-extends", "deny-file-configs", "deny-generic-resources", "deny-gpu-access", "deny-include", "deny-inline-configs", "deny-label-file", "deny-lifecycle-hooks", "deny-local-volume-options", "deny-providers", "deny-runtime-identity-labels", "deny-runtime-overrides", "deny-scaling", "deny-stop-grace-overrides", "deny-supplemental-groups", "deny-volumes-from"]);
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
const WORKLOAD_SERVICE_KEYS = new Set([
  "image", "command", "entrypoint", "working_dir", "environment", "volumes", "secrets", "networks",
  "healthcheck", "read_only", "init", "restart", "security_opt", "cap_drop", "cap_add", "user",
  "logging", "pids_limit", "cpu_shares", "blkio_config", "ulimits", "cpus", "mem_limit",
  "memswap_limit", "mem_reservation", "labels", "depends_on",
]);
const ACCELERATOR_ENVIRONMENT_NAMES = new Set([
  "CUDA_VISIBLE_DEVICES", "HIP_VISIBLE_DEVICES", "ONEAPI_DEVICE_SELECTOR",
  "ROCR_VISIBLE_DEVICES", "SYCL_DEVICE_FILTER", "ZE_AFFINITY_MASK",
]);

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

function parseJsonBytes(bytes, label) {
  try {
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

function targetLocalAuthority({ infrastructureRoot, expectedOwner, testOnly = false }) {
  return Object.freeze({
    [TARGET_LOCAL_AUTHORITY]: testOnly,
    infrastructureRoot,
    expectedOwner,
    serviceRoot: path.dirname(infrastructureRoot),
    releaseStore: path.join(infrastructureRoot, "releases"),
    releaseStateStore: path.join(infrastructureRoot, "release-states"),
  });
}

const PRODUCTION_TARGET_LOCAL_AUTHORITY = process.platform === "linux"
  ? targetLocalAuthority({
    infrastructureRoot: PRODUCTION_INFRASTRUCTURE_ROOT,
    expectedOwner: 0,
  })
  : null;

export function createTargetLocalCoreEnvironmentTestAuthority(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)
      || JSON.stringify(Object.keys(options).sort()) !== JSON.stringify(["expectedOwner", "infrastructureRoot"])) {
    invalid("Target-local core environment test authority requires exact infrastructureRoot and expectedOwner options.");
  }
  const infrastructureRoot = path.resolve(exactText(options.infrastructureRoot, "test infrastructure root"));
  if (!Number.isSafeInteger(options.expectedOwner) || options.expectedOwner < 0) {
    invalid("Target-local core environment test authority owner is invalid.");
  }
  return targetLocalAuthority({
    infrastructureRoot,
    expectedOwner: options.expectedOwner,
    testOnly: true,
  });
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
  const owners = new Map();
  for (const id of assertNonPrefixCollidingWorkloadIds(workloadIds)) {
    for (const zone of WORKLOAD_NETWORK_ZONES) {
      const logicalName = `${workloadNetworkPrefix(id)}${zone}`;
      const prior = owners.get(logicalName);
      if (prior && prior !== id) invalid(`Workload network ${logicalName} has ambiguous canonical owners.`);
      owners.set(logicalName, id);
    }
  }
  return owners.get(network) ?? null;
}

function canonicalHyphenOwner(logicalName, workloadIds, resourceType) {
  const name = requiredText(logicalName, `${resourceType} logical name`);
  const owners = assertNonPrefixCollidingWorkloadIds(workloadIds)
    .filter((id) => name.startsWith(`${id}-`));
  if (owners.length !== 1) {
    invalid(`${resourceType} ${name} must have exactly one canonical owner.`);
  }
  return owners[0];
}

function canonicalVolumeOwner(logicalName, workloadIds) {
  const name = requiredText(logicalName, "Workload volume logical name");
  const owners = assertNonPrefixCollidingWorkloadIds(workloadIds)
    .filter((id) => name.startsWith(`${id}_`));
  if (owners.length !== 1) {
    invalid(`Workload volume ${name} must have exactly one canonical owner.`);
  }
  return owners[0];
}

function workloadNetworkZone(network, workloadId) {
  return network.slice(workloadNetworkPrefix(workloadId).length);
}

function assertNonPrefixCollidingWorkloadIds(workloadIds) {
  const ordered = [...workloadIds].map((id) => {
    if (typeof id !== "string" || !WORKLOAD_ID.test(id)) invalid("Hosted workload lock contains a noncanonical workload id.");
    return id;
  }).sort();
  if (new Set(ordered).size !== ordered.length) invalid("Hosted workload ids must be unique.");
  for (let leftIndex = 0; leftIndex < ordered.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < ordered.length; rightIndex += 1) {
      const left = ordered[leftIndex];
      const right = ordered[rightIndex];
      if (left.startsWith(`${right}-`) || right.startsWith(`${left}-`)) {
        invalid(`Prefix-colliding workload ids ${left} and ${right} are forbidden.`);
      }
    }
  }
  return ordered;
}

function addCanonicalOwner(owners, resourceType, logicalName, workloadId) {
  const name = requiredText(logicalName, `${resourceType} logical name`);
  const owner = requiredText(workloadId, `${resourceType} workload owner`);
  const prior = owners.get(name);
  if (prior && prior !== owner) {
    invalid(`${resourceType} ${name} is ambiguously owned by ${prior} and ${owner}.`);
  }
  owners.set(name, owner);
}

function requiredText(value, label) {
  const text = String(value ?? "").trim();
  if (!text || /[\0\r\n]/.test(text)) invalid(`${label} is missing or invalid.`);
  return text;
}

function exactText(value, label) {
  if (typeof value !== "string" || value.length === 0 || value !== value.trim() || /[\0\r\n]/.test(value)) {
    invalid(`${label} is missing or invalid.`);
  }
  return value;
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

function resolvePhysicalEntryWithin(root, value, label, expectedType) {
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
  const stat = fs.lstatSync(canonical, { bigint: true, throwIfNoEntry: false });
  if (expectedType === "file" && !stat?.isFile()) invalid(`${label} must be a regular file.`);
  if (expectedType === "directory" && !stat?.isDirectory()) invalid(`${label} must be a directory.`);
  return {
    path: canonical,
    root: canonicalRoot,
    rootIdentity: fileIdentity(canonicalRoot),
    identity: stableEntryIdentity(stat),
    expectedType,
  };
}

function resolvePhysicalWithin(root, value, label, expectedType) {
  return resolvePhysicalEntryWithin(root, value, label, expectedType).path;
}

function fileRecord(filePath, kind) {
  const source = captureRegularFile(filePath, kind);
  const { bytes } = readStableRegularFile(source, kind);
  return { kind, path: source.path, sha256: sha256Bytes(bytes), sizeBytes: bytes.length, ...fileIdentity(source.path) };
}

function stableEntryIdentity(stat) {
  return {
    device: String(stat.dev),
    inode: String(stat.ino),
    links: String(stat.nlink),
    uid: String(stat.uid),
    mode: String(stat.mode),
    size: String(stat.size),
    mtimeNs: String(stat.mtimeNs ?? stat.mtimeMs),
    ctimeNs: String(stat.ctimeNs ?? stat.ctimeMs),
  };
}

function sameStableEntryIdentity(left, right) {
  return Object.keys(left).every((key) => left[key] === right?.[key]);
}

function captureRegularFile(filePath, label) {
  const resolved = path.resolve(filePath);
  const stat = fs.lstatSync(resolved, { bigint: true, throwIfNoEntry: false });
  if (!stat?.isFile() || stat.isSymbolicLink()) invalid(`${label} file does not exist or is symlinked: ${resolved}`);
  return { path: resolved, root: null, rootIdentity: null, identity: stableEntryIdentity(stat), expectedType: "file" };
}

function revalidatePhysicalEntry(source, descriptorStat, label) {
  if (source.root) {
    const canonicalRoot = physicalRoot(source.root, `${label} root`);
    if (canonicalRoot !== source.root || !sameIdentity(fileIdentity(canonicalRoot), source.rootIdentity)) {
      invalid(`${label} physical root identity changed before snapshot capture.`);
    }
    assertNoSymlinkPathComponents(source.path, label);
    const canonical = fs.realpathSync.native(source.path);
    if (canonical !== source.path || (canonical !== canonicalRoot && !canonical.startsWith(`${canonicalRoot}${path.sep}`))) {
      invalid(`${label} escaped its physical root before snapshot capture.`);
    }
  }
  const current = fs.lstatSync(source.path, { bigint: true, throwIfNoEntry: false });
  const correctType = source.expectedType === "directory" ? current?.isDirectory() : current?.isFile();
  if (!correctType || current.isSymbolicLink()) invalid(`${label} changed type before snapshot capture.`);
  const currentIdentity = stableEntryIdentity(current);
  if (!sameStableEntryIdentity(source.identity, currentIdentity)
      || (descriptorStat && !sameStableEntryIdentity(source.identity, stableEntryIdentity(descriptorStat)))) {
    invalid(`${label} identity changed before snapshot capture.`);
  }
}

function readStableRegularFile(filePathOrSource, label, beforeOpen) {
  const source = typeof filePathOrSource === "string" ? captureRegularFile(filePathOrSource, label) : filePathOrSource;
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  let descriptor;
  try {
    beforeOpen?.(source, label);
    descriptor = fs.openSync(source.path, fs.constants.O_RDONLY | noFollow);
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile()) invalid(`${label} must be a regular file.`);
    revalidatePhysicalEntry(source, before, label);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (!sameStableEntryIdentity(stableEntryIdentity(before), stableEntryIdentity(after))) {
      invalid(`${label} changed while it was being read.`);
    }
    revalidatePhysicalEntry(source, after, label);
    return { bytes, stat: after };
  } catch (error) {
    invalid(`${label} could not be read safely: ${error.message}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function runSnapshotHelper(command, args, input = undefined) {
  const python = process.env.HOSTED_WORKLOAD_PYTHON || "python3";
  const helper = path.join(import.meta.dirname, "hosted-workload-fs.py");
  const result = spawnSync(python, [helper, command, ...args], {
    input,
    encoding: input == null ? "utf8" : undefined,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const detail = String(result.stderr ?? result.error?.message ?? "unknown helper error").trim();
    invalid(`Descriptor-relative snapshot ${command} failed: ${detail}`);
  }
  try {
    return JSON.parse(Buffer.isBuffer(result.stdout) ? result.stdout.toString("utf8") : result.stdout);
  } catch (error) {
    invalid(`Descriptor-relative snapshot ${command} returned invalid JSON: ${error.message}`);
  }
}

function identityArgument(identity) {
  return JSON.stringify(identity ?? null);
}

function createSnapshotGeneration(snapshotRoot, snapshotAccessHook) {
  const lexicalRoot = path.resolve(snapshotRoot);
  const lexicalParent = path.dirname(lexicalRoot);
  const canonicalParent = physicalRoot(lexicalParent, "snapshot root parent");
  if (path.join(canonicalParent, path.basename(lexicalRoot)) !== lexicalRoot) invalid("Snapshot root parent is not canonical.");
  const effectiveUid = typeof process.getuid === "function" ? String(process.getuid()) : fileIdentity(canonicalParent).uid;
  const parentIdentity = fileIdentity(canonicalParent);
  if (parentIdentity.uid !== effectiveUid || parentIdentity.mode !== 0o700) {
    invalid("Snapshot root parent must be deployment-owned with mode 0700.");
  }
  const existing = fs.lstatSync(lexicalRoot, { throwIfNoEntry: false });
  if (existing && (!existing.isDirectory() || existing.isSymbolicLink())) {
    invalid("Snapshot root must be a real non-symlink directory.");
  }
  const existingRootIdentity = existing ? fileIdentity(lexicalRoot) : null;
  if (existingRootIdentity && (existingRootIdentity.uid !== effectiveUid || existingRootIdentity.mode !== 0o700)) {
    invalid("Snapshot root must be deployment-owned with mode 0700.");
  }
  snapshotAccessHook?.({ parent: canonicalParent, root: lexicalRoot }, "before descriptor-relative snapshot create");
  const created = runSnapshotHelper("create", [
    "--parent", canonicalParent,
    "--root-name", path.basename(lexicalRoot),
    "--expected-parent", identityArgument(parentIdentity),
    "--expected-root", identityArgument(existingRootIdentity),
  ]);
  const canonicalRoot = physicalRoot(lexicalRoot, "snapshot root");
  if (!sameIdentity(fileIdentity(canonicalParent), created.parentIdentity)
      || !sameIdentity(fileIdentity(canonicalRoot), created.rootIdentity)) {
    invalid("Snapshot parent or root changed after descriptor-relative creation.");
  }
  const generation = path.join(canonicalRoot, created.stagingName);
  return {
    parent: canonicalParent,
    parentIdentity: created.parentIdentity,
    root: canonicalRoot,
    rootIdentity: created.rootIdentity,
    rootName: path.basename(canonicalRoot),
    generation,
    stagingName: created.stagingName,
    stagingIdentity: created.stagingIdentity,
    nextIndex: 0,
  };
}

function fsyncDirectory(directory) {
  const directoryFlag = fs.constants.O_DIRECTORY ?? 0;
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | directoryFlag);
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function fileIdentity(filePath) {
  const stat = fs.lstatSync(filePath, { bigint: true, throwIfNoEntry: false });
  if (!stat) invalid(`Snapshot identity is missing: ${filePath}`);
  return { device: String(stat.dev), inode: String(stat.ino), uid: String(stat.uid), mode: Number(stat.mode & 0o777n) };
}

function assertAuthorityDirectory(candidate, label, expectedOwner) {
  const details = fs.lstatSync(candidate, { throwIfNoEntry: false });
  if (!details?.isDirectory() || details.isSymbolicLink()
      || fs.realpathSync.native(candidate) !== candidate
      || details.uid !== expectedOwner || (details.mode & 0o022) !== 0) {
    invalid(`${label} must be a canonical authority-owned non-group/world-writable directory.`);
  }
}

function coreReleaseRoot(coreFiles, label = "core Compose files") {
  if (!Array.isArray(coreFiles) || coreFiles.length === 0) invalid(`${label} are missing.`);
  const releaseRoot = path.dirname(path.resolve(exactText(coreFiles[0], `${label} path`)));
  if (coreFiles.some((file) => path.dirname(path.resolve(exactText(file, `${label} path`))) !== releaseRoot)) {
    invalid(`${label} must share one exact release root.`);
  }
  return releaseRoot;
}

function assertTargetLocalCoreEnvironmentAuthority(record, authority = PRODUCTION_TARGET_LOCAL_AUTHORITY, releaseRoot) {
  if (!authority || (authority !== PRODUCTION_TARGET_LOCAL_AUTHORITY && authority[TARGET_LOCAL_AUTHORITY] !== true)) {
    invalid("Target-local core environment authority is unavailable outside its fixed production boundary.");
  }
  const canonicalReleaseRoot = path.resolve(exactText(releaseRoot, "core release root"));
  const releaseId = path.basename(canonicalReleaseRoot);
  const environmentPath = path.resolve(exactText(record?.path, "core environment path"));
  const digest = exactText(record?.sha256, "core environment digest");
  const stateRoot = path.dirname(environmentPath);
  const stateId = path.basename(stateRoot);
  const expectedPath = path.join(authority.releaseStateStore, stateId, "environment.env");
  const releaseIdPattern = /^(?:[a-f0-9]{40}|[a-f0-9]{64})-[a-f0-9]{64}$/;
  if (!SHA256.test(digest)
      || !releaseIdPattern.test(releaseId)
      || canonicalReleaseRoot !== releaseRoot
      || canonicalReleaseRoot !== path.join(authority.releaseStore, releaseId)
      || environmentPath !== record.path
      || environmentPath !== expectedPath
      || !SAFE_PATH.test(environmentPath)
      || environmentPath.includes("//")
      || stateId !== `${releaseId}-${digest}`
      || String(record.uid) !== String(authority.expectedOwner)
      || Number(record.mode) !== 0o640) {
    invalid("Core environment is not the exact target-local release-state authority.");
  }
  assertNoSymlinkPathComponents(environmentPath, "target-local core environment");
  const details = fs.lstatSync(environmentPath, { throwIfNoEntry: false });
  if (!details?.isFile() || details.isSymbolicLink() || details.nlink !== 1
      || details.uid !== authority.expectedOwner || (details.mode & 0o777) !== 0o640
      || fs.realpathSync.native(environmentPath) !== environmentPath) {
    invalid("Target-local core environment must be one authority-owned mode-0640 single regular file.");
  }
  assertAuthorityDirectory(authority.serviceRoot, "Platform service root", authority.expectedOwner);
  assertAuthorityDirectory(authority.infrastructureRoot, "Platform infrastructure root", authority.expectedOwner);
  assertAuthorityDirectory(authority.releaseStore, "Immutable release store", authority.expectedOwner);
  assertAuthorityDirectory(canonicalReleaseRoot, "Immutable release root", authority.expectedOwner);
  assertAuthorityDirectory(authority.releaseStateStore, "Release-state store", authority.expectedOwner);
  assertAuthorityDirectory(stateRoot, "Release-state root", authority.expectedOwner);
  return true;
}

function assertCoreEnvironmentAuthority(record, authority = PRODUCTION_TARGET_LOCAL_AUTHORITY, releaseRoot) {
  const effectiveUid = typeof process.getuid === "function" ? String(process.getuid()) : String(record.uid);
  if (record.path === path.join(releaseRoot, ".env")
      && String(record.uid) === effectiveUid && [0o400, 0o600].includes(Number(record.mode))) return true;
  return assertTargetLocalCoreEnvironmentAuthority(record, authority, releaseRoot);
}

export function verifyPrepareEnvironmentAuthority({ envFile, sha256, releaseRoot, authority } = {}) {
  const expectedSha256 = exactText(sha256, "expected core environment digest");
  if (!SHA256.test(expectedSha256)) invalid("Expected core environment digest is invalid.");
  const record = fileRecord(path.resolve(exactText(envFile, "core environment path")), "core-environment");
  if (record.sha256 !== expectedSha256) invalid("Core environment digest differs from the prepare authority request.");
  assertTargetLocalCoreEnvironmentAuthority(record, authority, path.resolve(exactText(releaseRoot, "core release root")));
  return true;
}

function sameIdentity(actual, expected) {
  return actual.device === String(expected?.device)
    && actual.inode === String(expected?.inode)
    && actual.uid === String(expected?.uid)
    && actual.mode === Number(expected?.mode);
}

function finalizeSnapshot(snapshot, records, contentDigest) {
  const finalName = `content-${contentDigest}`;
  const snapshotRecords = records.filter((item) => item.snapshot === true);
  const finalized = runSnapshotHelper("finalize", [
    "--parent", snapshot.parent,
    "--root-name", snapshot.rootName,
    "--staging-name", snapshot.stagingName,
    "--expected-parent", identityArgument(snapshot.parentIdentity),
    "--expected-root", identityArgument(snapshot.rootIdentity),
    "--expected-staging", identityArgument(snapshot.stagingIdentity),
    "--final-name", finalName,
  ], Buffer.from(JSON.stringify(snapshotRecords.map((record) => ({ name: path.basename(record.path), sha256: record.sha256 })))));
  if (finalized.finalName !== finalName) invalid("Descriptor-relative snapshot helper returned an unexpected generation name.");
  const finalGeneration = path.join(snapshot.root, finalName);
  snapshot.generation = finalGeneration;
  for (const record of snapshotRecords) {
    record.path = path.join(finalGeneration, path.basename(record.path));
    const identity = finalized.fileIdentities[path.basename(record.path)];
    if (!identity) invalid(`Descriptor-relative snapshot helper omitted ${record.kind} identity.`);
    record.snapshotDevice = identity.device;
    record.snapshotInode = identity.inode;
    record.snapshotUid = identity.uid;
  }
  return {
    parentIdentity: finalized.parentIdentity,
    rootIdentity: finalized.rootIdentity,
    generationIdentity: finalized.generationIdentity,
    durability: {
      version: 1,
      filesFsynced: true,
      generationDirectoryFsynced: true,
      rootDirectoryFsynced: true,
    },
  };
}

function snapshotFile(sourcePathOrEntry, kind, snapshot, metadata = {}, beforeOpen) {
  const source = typeof sourcePathOrEntry === "string" ? captureRegularFile(sourcePathOrEntry, kind) : sourcePathOrEntry;
  const { bytes } = readStableRegularFile(source, kind, beforeOpen);
  const suffix = path.extname(source.path).replace(/[^A-Za-z0-9.]/g, "") || ".data";
  const name = `${String(snapshot.nextIndex++).padStart(4, "0")}-${kind.replace(/[^a-z0-9-]/gi, "-")}${suffix}`;
  const snapshotPath = path.join(snapshot.generation, name);
  runSnapshotHelper("write", [
    "--parent", snapshot.parent,
    "--root-name", snapshot.rootName,
    "--staging-name", snapshot.stagingName,
    "--expected-parent", identityArgument(snapshot.parentIdentity),
    "--expected-root", identityArgument(snapshot.rootIdentity),
    "--expected-staging", identityArgument(snapshot.stagingIdentity),
    "--file-name", name,
  ], bytes);
  const record = {
    kind,
    sourcePath: source.path,
    path: snapshotPath,
    sha256: sha256Bytes(bytes),
    sizeBytes: bytes.length,
    snapshot: true,
    ...metadata,
  };
  Object.defineProperty(record, "snapshotBytes", { value: bytes, enumerable: false });
  return record;
}

function workloadContentSha256(records) {
  const content = records
    .filter((record) => record.snapshot === true)
    .map(({ kind, sourcePath, sha256, sizeBytes, workloadId = null }) => ({ kind, sourcePath, sha256, sizeBytes, workloadId }))
    .sort((left, right) => `${left.workloadId}:${left.kind}:${left.sourcePath}`.localeCompare(`${right.workloadId}:${right.kind}:${right.sourcePath}`));
  return sha256Bytes(Buffer.from(JSON.stringify(stable(content))));
}

function recordKey(record) {
  return `${record.workloadId ?? ""}:${record.kind ?? ""}:${record.sourcePath ?? ""}:${record.path ?? ""}`;
}

function exactRecord(records, kind, workloadId = null, required = true) {
  const matches = records.filter((record) => record.kind === kind && (record.workloadId ?? null) === workloadId);
  if (matches.length !== (required ? 1 : 0)) {
    invalid(`Hosted workload lock requires ${required ? "exactly one" : "no"} ${kind} record${workloadId ? ` for ${workloadId}` : ""}.`);
  }
  return matches[0] ?? null;
}

function workloadManifestSemantics(workload) {
  return {
    version: workload.version,
    id: workload.id,
    composeFile: workload.composeFile,
    projectMetadataFile: workload.projectMetadataFile ?? null,
    services: workload.services,
    secrets: workload.secrets,
    migrationRoots: workload.migrationRoots,
  };
}

function verifyWorkloadRecordBindings(lock, coreEnvironmentAuthority) {
  if (!Array.isArray(lock.workloads)) invalid("Hosted workload lock has no workloads array.");
  assertNonPrefixCollidingWorkloadIds(lock.workloads.map((workload) => workload?.id));
  const records = lock.files;
  const recordPaths = records.map((record) => record.path);
  if (new Set(recordPaths).size !== recordPaths.length) invalid("Hosted workload lock contains duplicate file paths.");

  const catalogRecord = exactRecord(records, "catalog");
  const coreEnvironmentRecord = exactRecord(records, "core-environment");
  if (catalogRecord.snapshot !== true || coreEnvironmentRecord.snapshot === true || coreEnvironmentRecord.path !== lock.coreEnvFile) {
    invalid("Hosted workload catalog or core environment role is not bound to its file record.");
  }
  assertCoreEnvironmentAuthority(coreEnvironmentRecord, coreEnvironmentAuthority, coreReleaseRoot(lock.coreFiles));
  const coreRecords = records.filter((record) => record.kind === "core-compose" && record.snapshot !== true);
  const coreRecordPaths = coreRecords.map((record) => record.path).sort();
  if (!Array.isArray(lock.coreFiles) || new Set(lock.coreFiles).size !== lock.coreFiles.length
      || !same(coreRecordPaths, [...lock.coreFiles].sort())) {
    invalid("Hosted workload core Compose paths are not exactly bound to core-compose records.");
  }

  const workloadIds = new Set();
  const boundRecords = new Set([catalogRecord, coreEnvironmentRecord, ...coreRecords]);
  for (const workload of lock.workloads) {
    const workloadId = requiredText(workload?.id, "locked workload id");
    if (workloadIds.has(workloadId)) invalid(`Duplicate locked workload ${workloadId}.`);
    workloadIds.add(workloadId);
    const related = records.filter((record) => record.workloadId === workloadId);
    const manifestRecord = exactRecord(related, "workload-manifest", workloadId);
    const composeRecord = exactRecord(related, "workload-compose", workloadId);
    const environmentRecord = exactRecord(related, "workload-environment", workloadId);
    const metadataRecords = related.filter((record) => record.kind === "project-metadata");
    if (metadataRecords.length > 1) invalid(`${workloadId} has duplicate project-metadata records.`);
    const metadataRecord = metadataRecords[0] ?? null;

    if (workload.manifestPath !== manifestRecord.path || workload.manifestSourcePath !== manifestRecord.sourcePath
        || workload.composePath !== composeRecord.path || workload.composeSourcePath !== composeRecord.sourcePath
        || workload.environmentPath !== environmentRecord.path || workload.environmentSourcePath !== environmentRecord.sourcePath
        || (workload.projectMetadataPath ?? null) !== (metadataRecord?.path ?? null)
        || (workload.projectMetadataSourcePath ?? null) !== (metadataRecord?.sourcePath ?? null)) {
      invalid(`${workloadId} activation pointers are not exactly bound to snapshot records.`);
    }

    const allowedKinds = new Set(["workload-manifest", "workload-compose", "workload-environment", "project-metadata", "migration"]);
    if (related.some((record) => record.snapshot !== true || !allowedKinds.has(record.kind))) {
      invalid(`${workloadId} contains an unsupported or non-snapshot workload record.`);
    }
    const embedded = Array.isArray(workload.files) ? [...workload.files].sort((left, right) => recordKey(left).localeCompare(recordKey(right))) : null;
    const expected = [...related].sort((left, right) => recordKey(left).localeCompare(recordKey(right)));
    if (!embedded || !same(embedded, expected)) invalid(`${workloadId} embedded file records differ from the global lock records.`);

    const manifest = validateWorkloadManifest(readJson(manifestRecord.path, `${workloadId} locked manifest`), manifestRecord.sourcePath);
    if (!same(workloadManifestSemantics(workload), workloadManifestSemantics(manifest))) {
      invalid(`${workloadId} semantic manifest fields differ from the locked manifest snapshot.`);
    }
    const manifestDirectory = path.dirname(manifestRecord.sourcePath);
    if (composeRecord.sourcePath !== resolveWithin(manifestDirectory, manifest.composeFile, `${workloadId} compose source`)) {
      invalid(`${workloadId} Compose source role differs from its manifest.`);
    }
    if (Boolean(manifest.projectMetadataFile) !== Boolean(metadataRecord)
        || (metadataRecord && metadataRecord.sourcePath !== resolveWithin(manifestDirectory, manifest.projectMetadataFile, `${workloadId} metadata source`))) {
      invalid(`${workloadId} project metadata role differs from its manifest.`);
    }
    const migrationRoots = manifest.migrationRoots.map((relativeRoot) => resolveWithin(manifestDirectory, relativeRoot, `${workloadId} migration root`));
    for (const record of related.filter((item) => item.kind === "migration")) {
      if (!record.sourcePath.endsWith(".sql") || !migrationRoots.includes(path.dirname(record.sourcePath))) {
        invalid(`${workloadId} migration record is outside its declared migration roots.`);
      }
    }
    for (const record of related) boundRecords.add(record);
  }
  if (boundRecords.size !== records.length) invalid("Hosted workload lock contains unbound file records.");

  const catalog = readJson(catalogRecord.path, "locked hosted workload catalog");
  if (catalog?.version !== 1 || !Array.isArray(catalog.workloads) || catalog.workloads.length !== lock.workloads.length) {
    invalid("Locked catalog does not exactly match the workload set.");
  }
  const catalogBindings = catalog.workloads.map((entry) => ({
    manifestSourcePath: resolveWithin(lock.workloadRoot, entry?.manifest, "catalog manifest"),
    environmentSourcePath: resolveWithin(lock.workloadRoot, entry?.environmentFile, "catalog environment"),
  })).sort((left, right) => left.manifestSourcePath.localeCompare(right.manifestSourcePath));
  const workloadBindings = lock.workloads.map((workload) => ({
    manifestSourcePath: workload.manifestSourcePath,
    environmentSourcePath: workload.environmentSourcePath,
  })).sort((left, right) => left.manifestSourcePath.localeCompare(right.manifestSourcePath));
  if (!same(catalogBindings, workloadBindings)) invalid("Locked catalog source roles differ from workload source pointers.");
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

function workloadEnvironmentRecord(fileEntry, workloadId, snapshot, sourceAccessHook) {
  const record = snapshotFile(fileEntry, "workload-environment", snapshot, { workloadId }, sourceAccessHook);
  validateWorkloadEnvironmentText(record.snapshotBytes.toString("utf8"), workloadId, fileEntry.path);
  return record;
}

function sqlRecords(root, relativeRoots, snapshot, workloadId, sourceAccessHook) {
  const records = [];
  for (const relativeRoot of relativeRoots ?? []) {
    const directory = resolvePhysicalEntryWithin(root, relativeRoot, "migration root", "directory");
    sourceAccessHook?.(directory, "migration root");
    revalidatePhysicalEntry(directory, null, "migration root");
    const entries = fs.readdirSync(directory.path, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
    revalidatePhysicalEntry(directory, null, "migration root");
    for (const entry of entries) {
      if (!entry.name.endsWith(".sql")) continue;
      if (entry.isSymbolicLink() || !entry.isFile()) invalid(`Migration must be a regular non-symlink file: ${path.join(directory.path, entry.name)}`);
      const migration = resolvePhysicalEntryWithin(directory.path, entry.name, "migration", "file");
      records.push(snapshotFile(migration, "migration", snapshot, { workloadId }, sourceAccessHook));
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
  const slug = exactText(route?.slug, `route slug for ${serviceName}`);
  const port = route?.port;
  if (!ROUTE_SLUG.test(slug)) invalid(`Route slug '${slug}' is invalid.`);
  if (!Number.isInteger(port) || port < 1 || port > 65535) invalid(`Route port for ${slug} is invalid.`);
  const canonicalHost = normalizeDnsHost(route?.host, `route host for ${slug}`);
  const labels = canonicalHost.split(".");
  if (labels[0] !== slug) invalid(`Route host for ${slug} must begin with the exact route slug.`);
  if (route?.aliases !== undefined && !Array.isArray(route.aliases)) invalid(`Route aliases for ${slug} must be an array.`);
  const aliases = [...new Set((route?.aliases ?? []).map((value) => requiredText(value, `route alias for ${slug}`).toLowerCase()))].sort();
  for (const alias of aliases) {
    if (!ROUTE_SLUG.test(alias) || alias === slug) invalid(`Route alias '${alias}' for ${slug} is invalid.`);
  }
  const suffix = labels.slice(1).join(".");
  const hosts = [canonicalHost, ...aliases.map((alias) => suffix ? `${alias}.${suffix}` : alias)];
  if (hosts.some((host) => host.length > 253)) {
    invalid(`Derived route host for ${slug} must be an exact normalized DNS hostname.`);
  }
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
  const id = document?.id;
  if (typeof id !== "string" || !WORKLOAD_ID.test(id)) invalid(`Workload id '${String(id ?? "")}' is invalid.`);
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
    const name = exactText(service?.name, `service name for ${id}`);
    const role = exactText(service?.role, `service role for ${name}`);
    if (!SERVICE_NAME.test(name) || !name.startsWith(`${id}-`)) invalid(`Service ${name} must be prefixed with ${id}-.`);
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
  if (document.secrets != null && !Array.isArray(document.secrets)) invalid(`${id} secrets must be an array.`);
  const secrets = [...new Set((document.secrets ?? []).map((value) => exactText(value, "secret name")))].sort();
  for (const secret of secrets) {
    if (!RESOURCE_NAME.test(secret) || !secret.startsWith(`${id}-`)) invalid(`Secret ${secret} must be workload-prefixed.`);
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
    migrationRoots: [...new Set((document.migrationRoots ?? []).map((value) => {
      const relativeRoot = requiredText(value, "migration root");
      if (!SAFE_PATH.test(relativeRoot) || path.isAbsolute(relativeRoot) || relativeRoot.split("/").includes("..")) {
        invalid("migration root must be a contained relative path.");
      }
      return relativeRoot;
    }))],
  };
}

export function deriveCanonicalRoutes(workloads) {
  if (!Array.isArray(workloads)) invalid("Hosted workload route lineage has no workloads array.");
  const workloadIds = assertNonPrefixCollidingWorkloadIds(workloads.map((workload) => workload?.id));
  const serviceNames = new Set();
  const routeNames = new Set();
  const routeHosts = new Set();
  const routeUpstreams = new Set();
  const routes = [];
  for (const workload of workloads) {
    if (!workload || typeof workload !== "object" || Array.isArray(workload)
        || !Array.isArray(workload.services) || workload.services.length === 0) {
      invalid("Hosted workload route lineage has invalid workload declarations.");
    }
    for (const service of workload.services) {
      if (!service || typeof service !== "object" || Array.isArray(service)
          || !same(Object.keys(service).sort(), ["name", "role", "routes"])
          || typeof service.name !== "string" || !SERVICE_NAME.test(service.name)
          || canonicalHyphenOwner(service.name, workloadIds, "Workload service") !== workload.id
          || !new Set(["api", "web", "worker", "scheduled-worker"]).has(service.role)
          || !Array.isArray(service.routes)
          || serviceNames.has(service.name)) {
        invalid("Hosted workload route lineage has invalid service declarations.");
      }
      serviceNames.add(service.name);
      if (service.routes.length > 0 && !new Set(["api", "web"]).has(service.role)) {
        invalid(`Hosted workload route lineage cannot expose ${service.role} service ${service.name}.`);
      }
      for (const route of service.routes) {
        const expectedRouteKeys = ["aliases", "canonicalHost", "hosts", "owner", "port", "slug"];
        const aliases = Array.isArray(route?.aliases) ? route.aliases : [];
        const canonicalHost = typeof route?.canonicalHost === "string"
          ? normalizeDnsHost(route.canonicalHost, "canonical route host")
          : "";
        const suffix = canonicalHost.split(".").slice(1).join(".");
        const expectedHosts = canonicalHost
          ? [canonicalHost, ...aliases.map((alias) => suffix ? `${alias}.${suffix}` : alias)]
          : [];
        const upstreamIdentity = `${service.name}:${route?.port}`;
        if (!route || typeof route !== "object" || Array.isArray(route)
            || !same(Object.keys(route).sort(), expectedRouteKeys)
            || route.owner !== workload.id
            || typeof route.slug !== "string" || !ROUTE_SLUG.test(route.slug)
            || !same(aliases, [...new Set(aliases)].sort())
            || aliases.some((alias) => typeof alias !== "string" || !ROUTE_SLUG.test(alias) || alias === route.slug)
            || canonicalHost !== route.canonicalHost
            || canonicalHost.split(".")[0] !== route.slug
            || !same(route.hosts, expectedHosts)
            || expectedHosts.some((host) => host.length > 253)
            || typeof route.port !== "number" || !Number.isInteger(route.port)
            || route.port < 1 || route.port > 65535
            || [route.slug, ...aliases].some((name) => routeNames.has(name))
            || expectedHosts.some((host) => routeHosts.has(host))
            || routeUpstreams.has(upstreamIdentity)) {
          invalid("Hosted workload route lineage has invalid route declarations.");
        }
        for (const name of [route.slug, ...aliases]) routeNames.add(name);
        for (const host of expectedHosts) routeHosts.add(host);
        routeUpstreams.add(upstreamIdentity);
        routes.push({
          owner: workload.id,
          workloadId: workload.id,
          slug: route.slug,
          aliases,
          canonicalHost,
          hosts: expectedHosts,
          service: service.name,
          port: route.port,
          upstream: `http://${service.name}:${route.port}`,
        });
      }
    }
  }
  return routes.sort((left, right) => left.canonicalHost.localeCompare(right.canonicalHost));
}

function verifyCanonicalRouteLineage(lock) {
  if (lock?.state === "resolved") {
    if (Object.hasOwn(lock, "routes")) invalid("Resolved workload lock must not contain canonical routes.");
    return true;
  }
  if (lock?.state !== "verified"
      || !Array.isArray(lock.routes)
      || !same(lock.routes, deriveCanonicalRoutes(lock.workloads))) {
    invalid("Verified workload lock canonical route lineage is invalid.");
  }
  return true;
}

export function resolveCatalog({ catalogPath, workloadRoot, coreEnvFile, coreFiles, projectName, snapshotRoot, activationLockPath, sourceAccessHook, snapshotAccessHook, coreEnvironmentAuthority }) {
  const snapshot = createSnapshotGeneration(path.resolve(requiredText(snapshotRoot, "snapshot root")), snapshotAccessHook);
  const activationPath = path.resolve(activationLockPath ?? path.join(path.dirname(snapshot.root), "hosted-workloads.lock.json"));
  if (path.dirname(activationPath) !== path.dirname(snapshot.root)) {
    invalid("Activation lock and snapshot root must share one deployment-private parent.");
  }
  const catalogRecord = snapshotFile(path.resolve(catalogPath), "catalog", snapshot, {}, sourceAccessHook);
  const catalog = parseJsonBytes(catalogRecord.snapshotBytes, "hosted workload catalog");
  if (catalog?.version !== 1 || !Array.isArray(catalog.workloads)) {
    invalid("Hosted workload catalog must use version 1 and workloads[].");
  }
  const root = physicalRoot(workloadRoot, "workload root");
  const coreEnvironmentRecord = fileRecord(path.resolve(coreEnvFile), "core-environment");
  assertCoreEnvironmentAuthority(coreEnvironmentRecord, coreEnvironmentAuthority, coreReleaseRoot(coreFiles));
  const records = [catalogRecord, coreEnvironmentRecord];
  for (const coreFile of coreFiles) records.push(fileRecord(path.resolve(coreFile), "core-compose"));
  const ids = new Set();
  const services = new Set();
  const secretOwners = new Map();
  const workloads = catalog.workloads.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) invalid("Each workload catalog entry must be an object.");
    const manifestEntry = resolvePhysicalEntryWithin(root, entry.manifest, "workload manifest", "file");
    const manifestPath = manifestEntry.path;
    const manifestRecord = snapshotFile(manifestEntry, "workload-manifest", snapshot, {}, sourceAccessHook);
    const manifest = validateWorkloadManifest(parseJsonBytes(manifestRecord.snapshotBytes, manifestPath), manifestPath);
    const environmentEntry = resolvePhysicalEntryWithin(root, entry.environmentFile, `environment file for ${manifest.id}`, "file");
    const environmentPath = environmentEntry.path;
    if (ids.has(manifest.id)) invalid(`Duplicate workload id ${manifest.id}.`);
    ids.add(manifest.id);
    for (const service of manifest.services) {
      if (services.has(service.name)) invalid(`Duplicate workload service ${service.name}.`);
      services.add(service.name);
    }
    for (const secret of manifest.secrets) {
      const existingOwner = secretOwners.get(secret);
      if (existingOwner) invalid(`Secret ${secret} is ambiguously declared by ${existingOwner} and ${manifest.id}.`);
      secretOwners.set(secret, manifest.id);
    }
    const composeEntry = resolvePhysicalEntryWithin(path.dirname(manifestPath), manifest.composeFile, "workload compose file", "file");
    const composePath = composeEntry.path;
    manifestRecord.workloadId = manifest.id;
    const composeRecord = snapshotFile(composeEntry, "workload-compose", snapshot, { workloadId: manifest.id }, sourceAccessHook);
    const environmentRecord = workloadEnvironmentRecord(environmentEntry, manifest.id, snapshot, sourceAccessHook);
    const workloadRecords = [manifestRecord, composeRecord, environmentRecord];
    let projectMetadataRecord = null;
    if (manifest.projectMetadataFile) {
      const projectMetadataEntry = resolvePhysicalEntryWithin(path.dirname(manifestPath), manifest.projectMetadataFile, "project metadata file", "file");
      projectMetadataRecord = snapshotFile(projectMetadataEntry, "project-metadata", snapshot, { workloadId: manifest.id }, sourceAccessHook);
      workloadRecords.push(projectMetadataRecord);
    }
    workloadRecords.push(...sqlRecords(path.dirname(manifestPath), manifest.migrationRoots, snapshot, manifest.id, sourceAccessHook));
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
  assertNonPrefixCollidingWorkloadIds(ids);
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
    activationLockPath: activationPath,
    snapshotParentIdentity: snapshotReceipt.parentIdentity,
    snapshotRootIdentity: snapshotReceipt.rootIdentity,
    snapshotGenerationIdentity: snapshotReceipt.generationIdentity,
    snapshotDurability: snapshotReceipt.durability,
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
  if (name === "broker-auth-bootstrap") delete copy.secrets;
  return copy;
}

function serviceNetworks(service) {
  return new Set(Object.keys(service?.networks ?? {}));
}

function pathsOverlap(left, right) {
  const a = path.resolve(left);
  const b = path.resolve(right);
  return a === b || a.startsWith(`${b}${path.sep}`) || b.startsWith(`${a}${path.sep}`);
}

function assertActivationStorageIsolation(core, combined, lock) {
  if (!lock.activationLockPath || !lock.snapshotRoot) return;
  const activationLockPath = path.resolve(lock.activationLockPath);
  const snapshotRoot = path.resolve(lock.snapshotRoot);
  let routerLockMounts = 0;
  for (const [serviceName, service] of Object.entries(combined.services ?? {})) {
    for (const volume of service.volumes ?? []) {
      if (volume?.type !== "bind" || !volume.source) continue;
      const source = path.resolve(volume.source);
      const exactRouterLockMount = serviceName === "project-router"
        && source === activationLockPath
        && volume.target === "/run/platform/hosted-workloads.lock.json"
        && volume.read_only === true;
      if (exactRouterLockMount) {
        routerLockMounts += 1;
        continue;
      }
      if ((pathsOverlap(source, activationLockPath) || pathsOverlap(source, snapshotRoot)) && volume.read_only !== true) {
        invalid(`${serviceName} has writable access to deployment-private hosted workload activation state.`);
      }
    }
  }
  if (routerLockMounts !== 1) invalid("project-router requires exactly one read-only activation-lock mount.");
  const coreRouterMounts = (core.services?.["project-router"]?.volumes ?? []).filter((volume) => volume?.type === "bind"
    && path.resolve(volume.source) === activationLockPath
    && volume.target === "/run/platform/hosted-workloads.lock.json"
    && volume.read_only === true);
  if (coreRouterMounts.length !== 1) invalid("Core render does not preserve the read-only router activation-lock mount.");
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
    for (const network of coreNetworks) {
      const coreAttachment = Array.isArray(coreService.networks) ? null : coreService.networks?.[network];
      const combinedAttachment = Array.isArray(combinedService.networks) ? null : combinedService.networks?.[network];
      if (!combinedNetworks.has(network) || !same(coreAttachment, combinedAttachment)) {
        invalid(`Workload overlays removed or changed protected network attachment ${name}:${network}.`);
      }
    }
    const additions = [...combinedNetworks].filter((network) => !coreNetworks.has(network));
    for (const network of additions) {
      const owner = workloadNetworkOwner(network, workloadIds);
      if (!owner) invalid(`Platform service ${name} received non-workload network ${network}.`);
      const zone = workloadNetworkZone(network, owner);
      if (!PLATFORM_NETWORK_EXTENSION_ZONES.get(name)?.has(zone)) {
        invalid(`Platform service ${name} cannot join workload ${owner} zone ${zone}.`);
      }
      const attachment = Array.isArray(combinedService.networks) ? null : combinedService.networks?.[network];
      if (attachment != null && (!attachment || typeof attachment !== "object" || Array.isArray(attachment) || Object.keys(attachment).length > 0)) {
        invalid(`Platform service ${name} cannot set aliases or address overrides on workload network ${network}.`);
      }
    }
  }
}

function assertPlatformExtensionReceipt(core, combined, lock) {
  const expected = [];
  for (const workloadReceipt of lock.rawPolicyReceipt?.workloads ?? []) {
    for (const extension of workloadReceipt.platformExtensions ?? []) {
      for (const networkName of extension.networkNames ?? []) {
        expected.push(`${extension.serviceName}:${networkName}`);
      }
    }
  }
  const actual = [];
  for (const [serviceName, coreService] of Object.entries(core.services ?? {})) {
    const coreNetworks = serviceNetworks(coreService);
    for (const networkName of serviceNetworks(combined.services?.[serviceName])) {
      if (!coreNetworks.has(networkName)) actual.push(`${serviceName}:${networkName}`);
    }
  }
  if (!same([...new Set(actual)].sort(), [...new Set(expected)].sort())) {
    invalid("Platform workload-network extensions do not exactly match the raw policy receipt.");
  }
}

function assertProtectedTopLevelResourcesUnchanged(core, combined) {
  for (const resourceType of ["configs", "secrets", "volumes", "networks"]) {
    for (const [name, definition] of Object.entries(core[resourceType] ?? {})) {
      if (!Object.hasOwn(combined[resourceType] ?? {}, name)) {
        invalid(`Workload overlays removed protected ${resourceType} resource ${name}.`);
      }
      if (!same(definition, combined[resourceType][name])) {
        invalid(`Workload overlays changed protected ${resourceType} resource ${name}.`);
      }
    }
  }
}

function assertClosedTopLevelResources(core, combined, lock) {
  const physicalName = (document, resourceType, logicalName) =>
    document[resourceType]?.[logicalName]?.name ?? `${lock.projectName}_${logicalName}`;
  const assertNoPhysicalCollisions = (resourceType, logicalNames, protectedPhysicalNames) => {
    const owners = new Map();
    for (const logicalName of logicalNames) {
      const physical = physicalName(combined, resourceType, logicalName);
      if (protectedPhysicalNames.has(physical)) {
        invalid(`Workload ${resourceType} ${logicalName} aliases protected physical resource ${physical}.`);
      }
      const prior = owners.get(physical);
      if (prior) invalid(`Workload ${resourceType} ${logicalName} aliases physical resource already owned by ${prior}.`);
      owners.set(physical, logicalName);
    }
  };

  const coreConfigNames = Object.keys(core.configs ?? {}).sort();
  const combinedConfigNames = Object.keys(combined.configs ?? {}).sort();
  if (!same(combinedConfigNames, coreConfigNames)) {
    invalid("Workload overlays cannot add, alias, replace, or remove top-level configs.");
  }

  const coreSecretNames = Object.keys(core.secrets ?? {}).sort();
  const coreSecretSet = new Set(coreSecretNames);
  const secretOwners = new Map();
  const referencedSecretNames = new Set();
  const workloadIds = lock.workloads.map((workload) => workload.id);
  for (const workload of lock.workloads) {
    for (const secretName of workload.secrets) {
      if (coreSecretSet.has(secretName)) {
        invalid(`Workload ${workload.id} secret ${secretName} collides with a protected core secret.`);
      }
      const canonicalOwner = canonicalHyphenOwner(secretName, workloadIds, "Workload secret");
      if (canonicalOwner !== workload.id) {
        invalid(`Workload secret ${secretName} belongs to workload ${canonicalOwner}, not ${workload.id}.`);
      }
      const prior = secretOwners.get(secretName);
      if (prior) invalid(`Workload secret ${secretName} is ambiguously owned by ${prior} and ${workload.id}.`);
      secretOwners.set(secretName, workload.id);
    }
    for (const service of workload.services) {
      for (const entry of combined.services?.[service.name]?.secrets ?? []) {
        referencedSecretNames.add(typeof entry === "string" ? entry : entry.source);
      }
    }
  }
  const declaredSecretNames = [...secretOwners.keys()].sort();
  if (!same([...referencedSecretNames].sort(), declaredSecretNames)) {
    invalid("Signed workload secrets must be exactly owned and referenced by workload services.");
  }
  const expectedSecretNames = [...coreSecretNames, ...declaredSecretNames].sort();
  const combinedSecretNames = Object.keys(combined.secrets ?? {}).sort();
  if (!same(combinedSecretNames, [...new Set(expectedSecretNames)].sort())) {
    invalid("Rendered top-level secrets do not exactly match protected core plus signed workload secrets.");
  }
  assertNoPhysicalCollisions(
    "secrets",
    declaredSecretNames,
    new Set(coreSecretNames.map((name) => physicalName(core, "secrets", name))),
  );

  const coreServiceNames = new Set(Object.keys(core.services ?? {}));
  const coreVolumeNames = Object.keys(core.volumes ?? {}).sort();
  const coreVolumeSet = new Set(coreVolumeNames);
  const volumeOwners = new Map();
  for (const workload of lock.workloads) {
    for (const manifestService of workload.services) {
      const service = combined.services?.[manifestService.name];
      for (const mount of service?.volumes ?? []) {
        if (mount?.type !== "volume" || typeof mount.source !== "string") continue;
        if (coreVolumeSet.has(mount.source)) {
          invalid(`Workload ${workload.id} volume ${mount.source} collides with a protected core volume.`);
        }
        const canonicalOwner = canonicalVolumeOwner(mount.source, workloadIds);
        if (canonicalOwner !== workload.id) {
          invalid(`Workload volume ${mount.source} belongs to workload ${canonicalOwner}, not ${workload.id}.`);
        }
        const prior = volumeOwners.get(mount.source);
        if (prior && prior !== workload.id) {
          invalid(`Workload volume ${mount.source} is ambiguously owned by ${prior} and ${workload.id}.`);
        }
        volumeOwners.set(mount.source, workload.id);
      }
    }
  }
  const workloadVolumeNames = [...volumeOwners.keys()].sort();
  const expectedVolumeNames = [
    ...coreVolumeNames,
    ...workloadVolumeNames,
  ].sort();
  const combinedVolumeNames = Object.keys(combined.volumes ?? {}).sort();
  if (!same(combinedVolumeNames, [...new Set(expectedVolumeNames)].sort())) {
    invalid("Rendered top-level volumes do not exactly match protected core plus mounted workload volumes.");
  }
  assertNoPhysicalCollisions(
    "volumes",
    workloadVolumeNames,
    new Set(coreVolumeNames.map((name) => physicalName(core, "volumes", name))),
  );

  const coreNetworkNames = Object.keys(core.networks ?? {}).sort();
  const coreNetworkSet = new Set(coreNetworkNames);
  const referencedWorkloadNetworks = new Set();
  const workloadNetworkConsumers = new Map();
  for (const workload of lock.workloads) {
    for (const manifestService of workload.services) {
      for (const networkName of serviceNetworks(combined.services?.[manifestService.name])) {
        if (!coreNetworkSet.has(networkName)) {
          referencedWorkloadNetworks.add(networkName);
          const consumers = workloadNetworkConsumers.get(networkName) ?? [];
          consumers.push(manifestService.name);
          workloadNetworkConsumers.set(networkName, consumers);
        }
      }
    }
  }
  for (const [serviceName, service] of Object.entries(combined.services ?? {})) {
    if (!coreServiceNames.has(serviceName)) continue;
    const coreNetworks = serviceNetworks(core.services?.[serviceName]);
    for (const networkName of serviceNetworks(service)) {
      if (!coreNetworks.has(networkName)) referencedWorkloadNetworks.add(networkName);
    }
  }
  const renderedWorkloadNetworks = Object.keys(combined.networks ?? {})
    .filter((name) => !coreNetworkSet.has(name))
    .sort();
  if (!same([...referencedWorkloadNetworks].sort(), renderedWorkloadNetworks)) {
    invalid("Rendered workload networks must be exactly referenced by signed workload services or platform extensions.");
  }
  for (const networkName of renderedWorkloadNetworks) {
    if ((workloadNetworkConsumers.get(networkName) ?? []).length === 0) {
      invalid(`Workload network ${networkName} has no signed workload service consumer.`);
    }
  }
  const routerNetworks = serviceNetworks(combined.services?.["project-router"]);
  for (const networkName of routerNetworks) {
    if (coreNetworkSet.has(networkName)) continue;
    const owner = lock.workloads.find((workload) => networkName === `${workloadNetworkPrefix(workload.id)}ingress`);
    if (!owner) continue;
    const routedConsumers = owner.services.filter((service) =>
      service.routes.length > 0
      && serviceNetworks(combined.services?.[service.name]).has(networkName));
    if (routedConsumers.length === 0) {
      invalid(`Router ingress network ${networkName} has no signed routed workload consumer.`);
    }
  }
  assertNoPhysicalCollisions(
    "networks",
    renderedWorkloadNetworks,
    new Set(coreNetworkNames.map((name) => physicalName(core, "networks", name))),
  );
}

function assertResourceLimits(name, service) {
  if (!service.blkio_config || typeof service.blkio_config !== "object" || Array.isArray(service.blkio_config)
      || !same(Object.keys(service.blkio_config).sort(), ["weight"])) {
    invalid(`${name} blkio_config must contain only the bounded global weight.`);
  }
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
  if (Number(service.memswap_limit) !== memLimit) invalid(`${name} requires memswap_limit equal to mem_limit.`);
  if (["oom_kill_disable", "oom_score_adj", "mem_swappiness"].some((field) => Object.hasOwn(service, field))) {
    invalid(`${name} cannot override OOM or swappiness controls.`);
  }
  if (!(pids >= 16 && pids <= 512)) invalid(`${name} requires pids_limit between 16 and 512.`);
  if (!(cpuShares >= 2 && cpuShares <= 1024)) invalid(`${name} requires bounded cpu_shares.`);
  if (!(ioWeight >= 10 && ioWeight <= 1000)) invalid(`${name} requires bounded block I/O weight.`);
  if (!(nofile >= 1024 && nofile <= 65536)) invalid(`${name} requires a bounded nofile limit.`);
}

function assertEnvironmentSecrets(name, service, secretGrants) {
  if (Object.hasOwn(service, "environment")
      && (!service.environment || typeof service.environment !== "object" || Array.isArray(service.environment)
        || Object.values(service.environment).some((value) => value == null))) {
    invalid(`${name} environment must be an explicit mapping with no ambient null values.`);
  }
  for (const [key, rawValue] of Object.entries(service.environment ?? {})) {
    if (key.startsWith("NVIDIA_") || ACCELERATOR_ENVIRONMENT_NAMES.has(key)) {
      invalid(`${name} cannot request accelerator access through environment variable ${key}.`);
    }
    const value = String(rawValue ?? "");
    if (key.endsWith("_FILE")) {
      const match = value.match(/^\/run\/secrets\/([a-z][a-z0-9-]{1,62})$/);
      if (!match) {
        invalid(`${name} has an invalid secret file path for ${key}.`);
      }
      if (!secretGrants.has(match[1])) {
        invalid(`${name} secret file ${key} references ungranted secret target ${match[1]}.`);
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

function assertSecrets(name, service, manifest, combined, projectName, protectedSecretNames, workloadIds) {
  const allowed = new Set(manifest.secrets);
  const targets = new Map();
  if (!Array.isArray(service.secrets ?? [])) {
    invalid(`${name} secrets must be an exact sequence.`);
  }
  for (const entry of service.secrets ?? []) {
    const longSyntax = entry && typeof entry === "object" && !Array.isArray(entry);
    if (typeof entry !== "string"
        && (!longSyntax
          || !same(Object.keys(entry).sort(), Object.hasOwn(entry, "target") ? ["source", "target"] : ["source"]))) {
      invalid(`${name} secret grants must use exact short syntax or exact source/target long syntax.`);
    }
    const source = typeof entry === "string" ? entry : entry.source;
    const target = typeof entry === "string" ? entry : (Object.hasOwn(entry, "target") ? entry.target : entry.source);
    if (!RESOURCE_NAME.test(String(source ?? "")) || !RESOURCE_NAME.test(String(target ?? ""))) {
      invalid(`${name} secret grants require canonical source and target names.`);
    }
    if (targets.has(target)) {
      invalid(`${name} has duplicate secret grant target ${target}.`);
    }
    targets.set(target, source);
    if (!allowed.has(source)) invalid(`${name} uses undeclared secret ${source}.`);
    const canonicalOwner = canonicalHyphenOwner(source, workloadIds, "Workload secret");
    if (canonicalOwner !== manifest.id) {
      invalid(`${name} secret ${source} belongs to workload ${canonicalOwner}, not ${manifest.id}.`);
    }
    if (protectedSecretNames.has(source)) {
      invalid(`${name} secret ${source} collides with a protected core secret.`);
    }
    const definition = combined.secrets?.[source];
    const expectedPhysicalName = `${projectName}_${source}`;
    if (!definition || !same(Object.keys(definition).sort(), ["external", "name"])
        || definition.external !== true || definition.name !== expectedPhysicalName) {
      invalid(`${name} secret ${source} must bind workload-owned external secret ${expectedPhysicalName}.`);
    }
  }
  return targets;
}

function assertVolumes(name, service, workloadId, protectedVolumeNames) {
  const targets = new Set();
  for (const volume of service.volumes ?? []) {
    if (!volume || typeof volume !== "object" || Array.isArray(volume)
        || !same(Object.keys(volume).sort(), ["source", "target", "type"])
        || volume.type !== "volume"
        || !String(volume.source ?? "").startsWith(`${workloadId}_`)) {
      invalid(`${name} may use only workload-prefixed named volumes; bind mounts are forbidden.`);
    }
    if (volume.target !== "/data" || targets.has(volume.target)) {
      invalid(`${name} workload volume targets must be the single closed /data mount; protected and overlapping targets are forbidden.`);
    }
    if (protectedVolumeNames.has(volume.source)) {
      invalid(`${name} volume ${volume.source} collides with a protected core volume.`);
    }
    targets.add(volume.target);
  }
}

function assertWorkloadService({
  serviceDefinition,
  manifestService,
  manifest,
  combined,
  projectName,
  protectedNetworkNames,
  protectedSecretNames,
  protectedVolumeNames,
  workloadIds,
}) {
  const name = manifestService.name;
  const canonicalServiceOwner = canonicalHyphenOwner(name, workloadIds, "Workload service");
  if (canonicalServiceOwner !== manifest.id) {
    invalid(`Workload service ${name} belongs to workload ${canonicalServiceOwner}, not ${manifest.id}.`);
  }
  const predeclaredRuntimeLabels = Object.keys(serviceDefinition.labels ?? {}).filter((label) => label.startsWith("com.platform.runtime."));
  if (predeclaredRuntimeLabels.length > 0) invalid(`${name} cannot predeclare trusted runtime identity labels.`);
  if (!IMAGE.test(String(serviceDefinition.image ?? ""))) invalid(`${name} image must be digest-pinned.`);
  if (serviceDefinition.build) invalid(`${name} cannot build inside the platform deployment.`);
  if (serviceDefinition.label_file != null) invalid(`${name} cannot load labels from a host file.`);
  if (["post_start", "pre_start", "pre_stop"].some((field) => serviceDefinition[field] != null)) {
    invalid(`${name} cannot define service lifecycle hooks.`);
  }
  if (serviceDefinition.scale != null || serviceDefinition.deploy?.replicas != null || serviceDefinition.deploy?.mode != null) {
    invalid(`${name} cannot request service scaling.`);
  }
  if ((serviceDefinition.configs?.length ?? 0) > 0) invalid(`${name} cannot mount platform or host-backed configs.`);
  if (serviceDefinition.use_api_socket != null) invalid(`${name} cannot use the Compose API socket.`);
  if (serviceDefinition.provider != null) invalid(`${name} cannot delegate execution to a provider.`);
  if (serviceDefinition.runtime != null) invalid(`${name} cannot override the OCI runtime.`);
  if (serviceDefinition.stop_grace_period != null) invalid(`${name} cannot override the stop grace period.`);
  if (serviceDefinition.devices != null || serviceDefinition.device_cgroup_rules != null) invalid(`${name} cannot request host device access.`);
  if (serviceDefinition.group_add != null) invalid(`${name} cannot add supplemental groups.`);
  const acceleratorRequest = serviceDefinition.gpus != null
    || serviceDefinition.device_requests != null
    || Object.hasOwn(serviceDefinition.deploy?.resources?.reservations ?? {}, "devices")
    || Object.hasOwn(serviceDefinition.deploy?.resources?.reservations ?? {}, "generic_resources");
  if (acceleratorRequest) invalid(`${name} cannot request GPU or accelerator access.`);
  if (serviceDefinition.deploy != null) invalid(`${name} cannot define deploy controls; use the bounded top-level workload resource contract.`);
  if (serviceDefinition.volumes_from != null) invalid(`${name} cannot inherit volumes from another service.`);
  if (serviceDefinition.container_name) invalid(`${name} cannot reserve a global container_name.`);
  if (serviceDefinition.privileged || serviceDefinition.network_mode === "host" || serviceDefinition.ipc === "host") {
    invalid(`${name} requests a host-level privilege.`);
  }
  if (serviceDefinition.pid != null) invalid(`${name} cannot share another PID namespace.`);
  if (Array.isArray(serviceDefinition.ports) && serviceDefinition.ports.length > 0) invalid(`${name} cannot publish host ports.`);
  if (serviceDefinition.read_only !== true) invalid(`${name} must use a read-only root filesystem.`);
  if (serviceDefinition.init !== true || serviceDefinition.restart !== "no") invalid(`${name} requires init and restart=no for firewall-gated activation.`);
  if (!same(serviceDefinition.security_opt, ["no-new-privileges:true"])) {
    invalid(`${name} security_opt must be exactly [no-new-privileges:true].`);
  }
  if (!serviceDefinition.cap_drop?.includes("ALL") || (serviceDefinition.cap_add?.length ?? 0) > 0) invalid(`${name} must drop all capabilities.`);
  if (!/^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$/.test(String(serviceDefinition.user ?? ""))) {
    invalid(`${name} must declare a canonical numeric non-root uid:gid.`);
  }
  if (!same(serviceDefinition.logging, { driver: "local", options: { "max-size": "10m", "max-file": "3" } })) {
    invalid(`${name} must use local logging with max-size=10m and max-file=3.`);
  }
  const healthcheck = serviceDefinition.healthcheck;
  if (!healthcheck || typeof healthcheck !== "object" || Array.isArray(healthcheck)
      || !same(Object.keys(healthcheck).sort(), ["test"])
      || !Array.isArray(healthcheck.test) || healthcheck.test.length < 2 || healthcheck.test.length > 16
      || healthcheck.test[0] !== "CMD"
      || healthcheck.test.slice(1).some((value) => typeof value !== "string" || value.length === 0 || value.length > 256 || /[\0\r\n]/.test(value))) {
    invalid(`${name} requires a functional healthcheck.`);
  }
  const nofile = serviceDefinition.ulimits?.nofile;
  if (!serviceDefinition.ulimits || typeof serviceDefinition.ulimits !== "object" || Array.isArray(serviceDefinition.ulimits)
      || !same(Object.keys(serviceDefinition.ulimits).sort(), ["nofile"])
      || !nofile || typeof nofile !== "object" || Array.isArray(nofile)
      || !same(Object.keys(nofile).sort(), ["hard", "soft"])
      || !Number.isInteger(Number(nofile.soft)) || !Number.isInteger(Number(nofile.hard))
      || Number(nofile.soft) < 1024 || Number(nofile.hard) > 65536 || Number(nofile.soft) > Number(nofile.hard)) {
    invalid(`${name} ulimits must contain only bounded nofile soft/hard values.`);
  }
  const unsupportedFields = Object.keys(serviceDefinition).filter((field) => !WORKLOAD_SERVICE_KEYS.has(field)).sort();
  if (unsupportedFields.length > 0) invalid(`${name} uses unsupported Compose service fields: ${unsupportedFields.join(", ")}.`);
  assertResourceLimits(name, serviceDefinition);
  const secretGrants = assertSecrets(
    name,
    serviceDefinition,
    manifest,
    combined,
    projectName,
    protectedSecretNames,
    workloadIds,
  );
  assertEnvironmentSecrets(name, serviceDefinition, secretGrants);
  assertVolumes(name, serviceDefinition, manifest.id, protectedVolumeNames);
  const networks = serviceNetworks(serviceDefinition);
  if (networks.size === 0) invalid(`${name} must declare networks.`);
  for (const network of networks) {
    if (protectedNetworkNames.has(network)) invalid(`${name} cannot join protected core network ${network}.`);
    if (workloadNetworkOwner(network, combinedWorkloadIds(combined)) !== manifest.id) invalid(`${name} uses unauthorized network ${network}.`);
    const attachment = Array.isArray(serviceDefinition.networks) ? null : serviceDefinition.networks?.[network];
    if (attachment != null && (!attachment || typeof attachment !== "object" || Array.isArray(attachment) || Object.keys(attachment).length > 0)) {
      invalid(`${name} cannot set aliases or address overrides on network ${network}.`);
    }
  }
  const dependencies = serviceDefinition.depends_on ?? {};
  if (!dependencies || typeof dependencies !== "object" || Array.isArray(dependencies)) {
    invalid(`${name} depends_on must be an exact normalized mapping.`);
  }
  for (const [dependency, condition] of Object.entries(dependencies)) {
    if (!manifest.services.some((service) => service.name === dependency) && !PLATFORM_DEPENDENCIES.has(dependency)) {
      invalid(`${name} depends on unauthorized service ${dependency}.`);
    }
    if (!condition || typeof condition !== "object" || Array.isArray(condition)
        || Object.keys(condition).some((field) => !["condition", "required", "restart"].includes(field))
        || !["service_started", "service_healthy"].includes(condition.condition)
        || (Object.hasOwn(condition, "required") && condition.required !== true)
        || (Object.hasOwn(condition, "restart") && condition.restart !== false)) {
      invalid(`${name} dependency ${dependency} must use a bounded required start/health condition.`);
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
    ["broker-auth-bootstrap", workloads.flatMap((workload) => [
      ...(workload.brokers?.redis ? [workload.brokers.redis.credentialSecret] : []),
      ...(workload.brokers?.nats?.users.map((user) => user.credentialSecret) ?? []),
    ])],
  ]);
  for (const [serviceName, tenantSecrets] of expectedByService) {
    if (!core.services?.[serviceName]) {
      if (tenantSecrets.length) invalid(`Core broker authorization bootstrap is missing for declared workload identities.`);
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

function combinedWorkloadIds(combined) {
  return [...new Set(Object.values(combined.services ?? {})
    .map((service) => service?.labels?.["com.platform.workload-id"])
    .filter((id) => typeof id === "string" && id.length > 0))];
}

export function validateRenderedWorkloads({ core, combined, lock }) {
  const workloadIds = lock.workloads.map((workload) => workload.id);
  assertNonPrefixCollidingWorkloadIds(workloadIds);
  validateGlobalRouteOwnership(lock.workloads);
  assertBrokerPolicyDigest(lock);
  const protectedNetworkNames = new Set(Object.keys(core.networks ?? {}));
  const protectedSecretNames = new Set(Object.keys(core.secrets ?? {}));
  const protectedVolumeNames = new Set(Object.keys(core.volumes ?? {}));
  const protectedResourceNames = {
    configs: Object.keys(core.configs ?? {}).sort(),
    networks: [...protectedNetworkNames].sort(),
    secrets: [...protectedSecretNames].sort(),
    services: Object.keys(core.services ?? {}).sort(),
    volumes: [...protectedVolumeNames].sort(),
  };
  if (lock.rawPolicyReceipt
      && (!same(lock.rawPolicyReceipt.protectedNetworkNames, protectedResourceNames.networks)
        || !same(lock.rawPolicyReceipt.protectedResourceNames, protectedResourceNames))) {
    invalid("Raw source policy protected-resource receipt does not match the exact core render.");
  }
  assertActivationStorageIsolation(core, combined, lock);
  assertProtectedTopLevelResourcesUnchanged(core, combined);
  assertClosedTopLevelResources(core, combined, lock);
  assertPlatformServicesUnchanged(core, combined, workloadIds);
  assertPlatformExtensionReceipt(core, combined, lock);
  for (const [name, definition] of Object.entries(combined.configs ?? {})) {
    if (!Object.hasOwn(core.configs ?? {}, name) && definition?.file != null) {
      invalid(`Workload config ${name} cannot use a host file source.`);
    }
    if (!Object.hasOwn(core.configs ?? {}, name) && (definition?.content != null || definition?.environment != null)) {
      invalid(`Workload config ${name} cannot use inline or host-environment content.`);
    }
  }
  const renderedVolumeOwners = new Map();
  for (const workload of lock.workloads) {
    for (const manifestService of workload.services) {
      for (const mount of combined.services?.[manifestService.name]?.volumes ?? []) {
        if (mount?.type === "volume" && typeof mount.source === "string") {
          addCanonicalOwner(renderedVolumeOwners, "Workload volume", mount.source, workload.id);
        }
      }
    }
  }
  for (const [name, definition] of Object.entries(combined.volumes ?? {})) {
    if (!Object.hasOwn(core.volumes ?? {}, name) && Object.hasOwn(definition ?? {}, "driver_opts")) {
      invalid(`Workload volume ${name} cannot use local driver options.`);
    }
    if (Object.hasOwn(core.volumes ?? {}, name)) continue;
    const ownerId = renderedVolumeOwners.get(name);
    if (!ownerId) invalid(`Undeclared workload volume ${name}.`);
    const expectedPhysicalName = `${lock.projectName}_${name}`;
    if (!definition || typeof definition !== "object" || Array.isArray(definition)
        || !same(Object.keys(definition).sort(), ["name"]) || definition.name !== expectedPhysicalName) {
      invalid(`Workload volume ${name} must bind physical volume ${expectedPhysicalName}.`);
    }
  }
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
    assertWorkloadService({
      serviceDefinition: rendered,
      manifestService: item.service,
      manifest: item.workload,
      combined,
      projectName: lock.projectName,
      protectedNetworkNames,
      protectedSecretNames,
      protectedVolumeNames,
      workloadIds,
    });
    const brokerUse = assertBrokerEnvironment(name, rendered, item.workload, item.service);
    if (brokerUse.usesRedis) redisUsers.add(item.workload.id);
    if (brokerUse.usesNats) natsUsers.add(`${item.workload.id}/${item.service.name}`);
    for (const route of item.service.routes) {
      const requiredIngressNetwork = `${workloadNetworkPrefix(item.workload.id)}ingress`;
      const routerNetworks = serviceNetworks(combined.services?.["project-router"]);
      if (!serviceNetworks(rendered).has(requiredIngressNetwork) || !routerNetworks.has(requiredIngressNetwork)) {
        invalid(`Route ${route.slug} has no exact dedicated ingress network shared with project-router.`);
      }
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
    const ownerId = workloadNetworkOwner(name, workloadIds);
    const owner = lock.workloads.find((workload) => workload.id === ownerId);
    if (!owner) invalid(`Undeclared or ambiguously owned workload network ${name}.`);
    const zone = workloadNetworkZone(name, owner.id);
    if (!WORKLOAD_NETWORK_ZONES.has(zone)) invalid(`Workload network ${name} has unsupported zone ${zone}.`);
    const expectedPhysicalName = `${lock.projectName}_${name}`;
    if (network?.external === true || network?.name !== expectedPhysicalName) {
      invalid(`Workload network ${name} cannot alias foreign physical network ${network?.name ?? name}.`);
    }
    const expectedInternal = zone !== "egress";
    const expectedKeys = zone === "egress" ? ["enable_ipv6", "internal", "name"] : ["internal", "name"];
    if (!network || typeof network !== "object" || Array.isArray(network)
        || !same(Object.keys(network).sort(), expectedKeys)
        || network.internal !== expectedInternal
        || (zone === "egress" && network.enable_ipv6 !== false)) {
      invalid(`Workload network ${name} must use the exact ${zone} topology with internal=${expectedInternal}.`);
    }
  }
  return { routes: routes.sort((a, b) => a.canonicalHost.localeCompare(b.canonicalHost)) };
}

export function verifyLockFiles(lock, { coreEnvironmentAuthority } = {}) {
  if (lock?.version !== HOSTED_WORKLOAD_LOCK_VERSION || lock?.validatorVersion !== HOSTED_WORKLOAD_VALIDATOR_VERSION) {
    invalid(`Hosted workload lock must use schema ${HOSTED_WORKLOAD_LOCK_VERSION} and validator ${HOSTED_WORKLOAD_VALIDATOR_VERSION}.`);
  }
  if (!Array.isArray(lock?.files) || lock.files.length === 0) invalid("Workload lock has no file records.");
  assertBrokerPolicyDigest(lock);
  const snapshotGeneration = physicalRoot(requiredText(lock.snapshotGeneration, "snapshot generation"), "snapshot generation");
  const snapshotRoot = physicalRoot(requiredText(lock.snapshotRoot, "snapshot root"), "snapshot root");
  const snapshotParent = physicalRoot(path.dirname(snapshotRoot), "snapshot root parent");
  if (path.dirname(snapshotGeneration) !== snapshotRoot) {
    invalid("Snapshot generation is outside the locked snapshot root.");
  }
  if (path.dirname(path.resolve(requiredText(lock.activationLockPath, "activation lock path"))) !== snapshotParent) {
    invalid("Activation lock is outside the deployment-private snapshot parent.");
  }
  if (!sameIdentity(fileIdentity(snapshotParent), lock.snapshotParentIdentity)
      || !sameIdentity(fileIdentity(snapshotRoot), lock.snapshotRootIdentity)
      || !sameIdentity(fileIdentity(snapshotGeneration), lock.snapshotGenerationIdentity)) {
    invalid("Snapshot parent, root, or generation identity changed after resolution.");
  }
  const effectiveUid = typeof process.getuid === "function" ? String(process.getuid()) : lock.snapshotRootIdentity.uid;
  if (String(lock.snapshotParentIdentity.uid) !== effectiveUid || String(lock.snapshotRootIdentity.uid) !== effectiveUid
      || String(lock.snapshotGenerationIdentity.uid) !== effectiveUid) {
    invalid("Snapshot parent, root, and generation must be owned by the deployment identity.");
  }
  if (lock.snapshotParentIdentity.mode !== 0o700 || lock.snapshotRootIdentity.mode !== 0o700 || lock.snapshotGenerationIdentity.mode !== 0o500) {
    invalid("Snapshot parent, root, or generation permissions are not deployment-owned.");
  }
  if (!same(lock.snapshotDurability, {
    version: 1,
    filesFsynced: true,
    generationDirectoryFsynced: true,
    rootDirectoryFsynced: true,
  })) {
    invalid("Snapshot lock has no complete crash-durability receipt.");
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
    } else if (!sameIdentity(fileIdentity(record.path), record)) {
      invalid(`Locked non-snapshot file identity changed: ${record.path}.`);
    }
    const { bytes } = readStableRegularFile(record.path, `locked ${record.kind}`);
    if (sha256Bytes(bytes) !== record.sha256) invalid(`Locked file changed: ${record.path}.`);
  }
  verifyWorkloadRecordBindings(lock, coreEnvironmentAuthority);
  const expectedContent = workloadContentSha256(lock.files);
  if (!SHA256.test(String(lock.workloadContentSha256 ?? "")) || lock.workloadContentSha256 !== expectedContent) {
    invalid("Hosted workload content digest does not match its verified snapshot records.");
  }
  verifyCanonicalRouteLineage(lock);
  return true;
}

export function verifyRawPolicyReceipt(lock) {
  const receipt = lock?.rawPolicyReceipt;
  if (Array.isArray(lock?.workloads)) {
    assertNonPrefixCollidingWorkloadIds(lock.workloads.map((workload) => workload?.id));
  }
  if (lock?.rawPolicyVersion !== "hosted-raw-v3"
      || lock?.rawPolicyWorkloadContentSha256 !== lock?.workloadContentSha256
      || !same(lock?.rawPolicyControls, RAW_POLICY_CONTROLS)
      || !receipt || typeof receipt !== "object" || Array.isArray(receipt)
      || !same(Object.keys(receipt).sort(), ["controls", "policyVersion", "protectedNetworkNames", "protectedResourceNames", "workloadContentSha256", "workloads"])
      || receipt.policyVersion !== lock.rawPolicyVersion
      || receipt.workloadContentSha256 !== lock.workloadContentSha256
      || !same(receipt.controls, RAW_POLICY_CONTROLS)
      || !Array.isArray(receipt.protectedNetworkNames)
      || !same(receipt.protectedNetworkNames, [...new Set(receipt.protectedNetworkNames)].sort())
      || receipt.protectedNetworkNames.some((name) => typeof name !== "string" || name.length === 0)
      || !receipt.protectedResourceNames || typeof receipt.protectedResourceNames !== "object"
      || Array.isArray(receipt.protectedResourceNames)
      || !same(Object.keys(receipt.protectedResourceNames).sort(), ["configs", "networks", "secrets", "services", "volumes"])
      || Object.values(receipt.protectedResourceNames).some((names) =>
        !Array.isArray(names)
        || !same(names, [...new Set(names)].sort())
        || names.some((name) => typeof name !== "string" || name.length === 0))
      || !same(receipt.protectedResourceNames.networks, receipt.protectedNetworkNames)
      || !Array.isArray(receipt.workloads)
      || !SHA256.test(String(lock?.rawPolicySha256 ?? ""))
      || sha256Bytes(Buffer.from(JSON.stringify(stable(receipt)))) !== lock.rawPolicySha256) {
    invalid("Hosted workload lock has no valid raw source policy receipt.");
  }
  const expectedIds = lock.workloads.map((workload) => workload.id).sort();
  const receiptIds = receipt.workloads.map((item) => item?.workloadId).sort();
  if (!same(receiptIds, expectedIds)) invalid("Raw source policy receipt does not cover the exact workload set.");
  const canonicalOwners = {
    networks: new Map(),
    secrets: new Map(),
    services: new Map(),
    volumes: new Map(),
  };
  for (const item of receipt.workloads) {
    if (!same(Object.keys(item ?? {}).sort(), [
      "composeSha256", "configNames", "networkNames", "platformExtensions",
      "secretNames", "serviceNames", "topLevelKeys", "volumeNames", "workloadId",
    ])) {
      invalid("Raw source policy workload receipt has an unexpected shape.");
    }
    const workload = lock.workloads.find((candidate) => candidate.id === item.workloadId);
    const composeRecords = lock.files.filter((record) => record.kind === "workload-compose" && record.workloadId === item.workloadId);
    const serviceNames = Array.isArray(item.serviceNames) ? item.serviceNames : [];
    const configNames = Array.isArray(item.configNames) ? item.configNames : [];
    const secretNames = Array.isArray(item.secretNames) ? item.secretNames : [];
    const volumeNames = Array.isArray(item.volumeNames) ? item.volumeNames : [];
    const networkNames = Array.isArray(item.networkNames) ? item.networkNames : [];
    const topLevelKeys = Array.isArray(item.topLevelKeys) ? item.topLevelKeys : [];
    const platformExtensions = Array.isArray(item.platformExtensions) ? item.platformExtensions : [];
    const platformExtensionNames = platformExtensions.map((entry) => entry?.serviceName);
    if (!workload || composeRecords.length !== 1 || item.composeSha256 !== composeRecords[0].sha256
        || !same(serviceNames, [...new Set(serviceNames)].sort())
        || !same(networkNames, [...new Set(networkNames)].sort())
        || networkNames.some((name) => workloadNetworkOwner(name, expectedIds) !== item.workloadId || receipt.protectedNetworkNames.includes(name))
        || !same(configNames, [])
        || !same(secretNames, workload.secrets)
        || secretNames.some((name) =>
          canonicalHyphenOwner(name, expectedIds, "Workload secret") !== item.workloadId
          || receipt.protectedResourceNames.secrets.includes(name))
        || !same(volumeNames, [...new Set(volumeNames)].sort())
        || volumeNames.some((name) =>
          canonicalVolumeOwner(name, expectedIds) !== item.workloadId
          || receipt.protectedResourceNames.volumes.includes(name))
        || serviceNames.some((name) =>
          canonicalHyphenOwner(name, expectedIds, "Workload service") !== item.workloadId
          || receipt.protectedResourceNames.services.includes(name))
        || !same(topLevelKeys, [...new Set(topLevelKeys)].sort()) || !topLevelKeys.includes("services")
        || !same(serviceNames, workload.services.map((service) => service.name).sort())
        || !same(platformExtensionNames, [...new Set(platformExtensionNames)].sort())
        || platformExtensions.some((extension) => {
          const allowedZones = PLATFORM_NETWORK_EXTENSION_ZONES.get(extension?.serviceName);
          const extensionNetworks = Array.isArray(extension?.networkNames) ? extension.networkNames : [];
          return !same(Object.keys(extension ?? {}).sort(), ["networkNames", "serviceName"])
            || !allowedZones
            || !same(extensionNetworks, [...new Set(extensionNetworks)].sort())
            || extensionNetworks.length === 0
            || extensionNetworks.some((name) => workloadNetworkOwner(name, expectedIds) !== item.workloadId
              || !allowedZones.has(workloadNetworkZone(name, item.workloadId)));
        })) {
      invalid(`Raw source policy receipt is not bound to ${item.workloadId ?? "a workload"}.`);
    }
    for (const serviceName of serviceNames) addCanonicalOwner(canonicalOwners.services, "Workload service", serviceName, item.workloadId);
    for (const secretName of secretNames) addCanonicalOwner(canonicalOwners.secrets, "Workload secret", secretName, item.workloadId);
    for (const volumeName of volumeNames) addCanonicalOwner(canonicalOwners.volumes, "Workload volume", volumeName, item.workloadId);
    for (const networkName of networkNames) addCanonicalOwner(canonicalOwners.networks, "Workload network", networkName, item.workloadId);
  }
  verifyCanonicalRouteLineage(lock);
}

export function verifyActivationRender({ lockPath, coreRenderPath, combinedRenderPath }) {
  const canonicalLockPath = path.resolve(requiredText(lockPath, "activation lock"));
  const lock = readJson(canonicalLockPath, "activation workload lock");
  if (lock.state !== "verified") invalid("Activation workload lock is not verified.");
  if (canonicalLockPath !== path.resolve(requiredText(lock.activationLockPath, "activation lock path"))) {
    invalid("Verified lock is not read from its activation path.");
  }
  verifyLockFiles(lock);
  verifyRawPolicyReceipt(lock);
  const readPinnedRender = (renderPath, expectedSha256, label) => {
    const canonicalPath = path.resolve(requiredText(renderPath, label));
    const { bytes } = readStableRegularFile(canonicalPath, label);
    if (!SHA256.test(String(expectedSha256 ?? "")) || sha256Bytes(bytes) !== expectedSha256) {
      invalid(`${label} does not match the SHA-256 pinned by the verified lock.`);
    }
    return parseJsonBytes(bytes, label);
  };
  const core = readPinnedRender(coreRenderPath, lock.coreRenderSha256, "activation core render");
  const combined = readPinnedRender(combinedRenderPath, lock.combinedRenderSha256, "activation combined render");
  const validation = validateRenderedWorkloads({ core, combined, lock });
  if (!same(lock.routes, validation.routes)) {
    invalid("Activation render does not match the verified canonical route lineage.");
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
  const outputPath = path.resolve(filePath);
  const parent = physicalRoot(path.dirname(outputPath), "lock output parent");
  const effectiveUid = typeof process.getuid === "function" ? String(process.getuid()) : fileIdentity(parent).uid;
  const parentIdentity = fileIdentity(parent);
  if (parentIdentity.uid !== effectiveUid || parentIdentity.mode !== 0o700) {
    invalid("Lock output parent must be deployment-owned with mode 0700.");
  }
  const existing = fs.lstatSync(outputPath, { throwIfNoEntry: false });
  if (existing && (!existing.isFile() || existing.isSymbolicLink())) invalid("Lock output path must not be symlinked or non-regular.");
  const temporary = path.join(parent, `.${path.basename(outputPath)}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`);
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | noFollow, 0o600);
    fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, outputPath);
    fsyncDirectory(parent);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
  }
}

function main() {
  const command = process.argv[2];
  const args = parseArgs(process.argv.slice(3));
  if (command === "prepare-environment-authority") {
    let authority;
    if (args.testInfrastructureRoot !== undefined) {
      if (process.platform === "linux") invalid("Target-local test authority is forbidden on Linux.");
      authority = createTargetLocalCoreEnvironmentTestAuthority({
        infrastructureRoot: path.resolve(requiredText(args.testInfrastructureRoot, "--testInfrastructureRoot")),
        expectedOwner: process.getuid(),
      });
    }
    verifyPrepareEnvironmentAuthority({
      envFile: path.resolve(requiredText(args.envFile, "--envFile")),
      sha256: requiredText(args.sha256, "--sha256"),
      releaseRoot: path.resolve(requiredText(args.releaseRoot, "--releaseRoot")),
      authority,
    });
    return;
  }
  if (command === "resolve") {
    const lock = resolveCatalog({
      catalogPath: path.resolve(requiredText(args.catalog, "--catalog")),
      workloadRoot: path.resolve(requiredText(args.workloadRoot, "--workloadRoot")),
      coreEnvFile: path.resolve(requiredText(args.envFile, "--envFile")),
      coreFiles: requiredText(args.coreFiles, "--coreFiles").split(",").map((file) => path.resolve(file)),
      projectName: requiredText(args.projectName, "--projectName"),
      snapshotRoot: path.resolve(requiredText(args.snapshotRoot, "--snapshotRoot")),
      activationLockPath: path.resolve(requiredText(args.activationLock, "--activationLock")),
    });
    writeJson(path.resolve(requiredText(args.output, "--output")), lock);
    return;
  }
  if (command === "verify-render") {
    const lockPath = path.resolve(requiredText(args.lock, "--lock"));
    const lock = readJson(lockPath, "workload lock");
    verifyLockFiles(lock);
    verifyRawPolicyReceipt(lock);
    const corePath = path.resolve(requiredText(args.coreRender, "--coreRender"));
    const combinedPath = path.resolve(requiredText(args.combinedRender, "--combinedRender"));
    const validation = validateRenderedWorkloads({ core: readJson(corePath), combined: readJson(combinedPath), lock });
    const outputPath = path.resolve(requiredText(args.output, "--output"));
    if (outputPath !== lock.activationLockPath) invalid("Verified lock output differs from the deployment activation path.");
    writeJson(outputPath, {
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
    const lockPath = path.resolve(requiredText(args.lock, "--lock"));
    const lock = readJson(lockPath, "workload lock");
    if (lock.state !== "verified" && !(args.allowResolved === "true" && lock.state === "resolved")) invalid("Workload lock is not verified.");
    if (lock.state === "verified" && lockPath !== lock.activationLockPath) invalid("Verified lock is not read from its activation path.");
    verifyLockFiles(lock);
    verifyRawPolicyReceipt(lock);
    return;
  }
  if (command === "verify-activation-render") {
    verifyActivationRender({
      lockPath: path.resolve(requiredText(args.lock, "--lock")),
      coreRenderPath: path.resolve(requiredText(args.coreRender, "--coreRender")),
      combinedRenderPath: path.resolve(requiredText(args.combinedRender, "--combinedRender")),
    });
    return;
  }
  if (command === "compose-files") {
    const lockPath = path.resolve(requiredText(args.lock, "--lock"));
    const lock = readJson(lockPath, "workload lock");
    if (lock.state !== "verified" && args.allowResolved !== "true") invalid("Workload lock is not verified.");
    if (lock.state === "verified" && lockPath !== lock.activationLockPath) invalid("Verified lock is not read from its activation path.");
    verifyLockFiles(lock);
    verifyRawPolicyReceipt(lock);
    process.stdout.write(`${lock.workloads.map((workload) => workload.composePath).join("\n")}\n`);
    return;
  }
  if (command === "env-files") {
    const lockPath = path.resolve(requiredText(args.lock, "--lock"));
    const lock = readJson(lockPath, "workload lock");
    if (lock.state !== "verified" && args.allowResolved !== "true") invalid("Workload lock is not verified.");
    if (lock.state === "verified" && lockPath !== lock.activationLockPath) invalid("Verified lock is not read from its activation path.");
    verifyLockFiles(lock);
    verifyRawPolicyReceipt(lock);
    process.stdout.write(`${lock.workloads.map((workload) => workload.environmentPath).join("\n")}\n`);
    return;
  }
  invalid("Usage: hosted-workload-contract.mjs prepare-environment-authority|resolve|verify-render|verify-lock|verify-activation-render|compose-files|env-files");
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
