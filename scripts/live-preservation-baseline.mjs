import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const livePreservationBaselineSchema = "platform.live-preservation-baseline/v1";

const TOP_LEVEL_KEYS = [
  "schema",
  "baselineId",
  "scope",
  "evidenceClass",
  "synthetic",
  "complete",
  "status",
  "gateAdmissible",
  "mutationAuthority",
  "effect",
  "identityObservationMode",
  "capturedAt",
  "host",
  "source",
  "policy",
  "redaction",
  "summary",
  "checkouts",
  "composeProjects",
  "containers",
  "volumes",
  "bindMounts",
  "sourceRoots",
  "networks",
  "hostListeners",
  "databases",
  "secretMetadata",
  "logicalRecoveryAnchors",
  "digests",
  "deficiencies",
];

const DIGEST_FIELDS = {
  checkoutsSha256: "checkouts",
  composeProjectsSha256: "composeProjects",
  containersSha256: "containers",
  volumesSha256: "volumes",
  bindMountsSha256: "bindMounts",
  sourceRootsSha256: "sourceRoots",
  networksSha256: "networks",
  hostListenersSha256: "hostListeners",
  databasesSha256: "databases",
  secretMetadataSha256: "secretMetadata",
  logicalRecoveryAnchorsSha256: "logicalRecoveryAnchors",
};

const SHA256 = /^[a-f0-9]{64}$/;
const GIT_OBJECT = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const DOCKER_IMAGE_ID = /^sha256:[a-f0-9]{64}$/;
const ABSOLUTE_PATH = /^\/(?!.*(?:^|\/)\.\.(?:\/|$))[^\0\r\n]*$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const ENVIRONMENT_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;
const RESOURCE_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$/;
const SECRET_METADATA_ID = /^secret-metadata:[A-Za-z0-9._/-]+$/;

function fail(message) {
  throw new Error(`Live preservation baseline: ${message}`);
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function sha256Canonical(value) {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function clone(value) {
  return structuredClone(value);
}

function record(value, label, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object.`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  const unknown = actual.filter((key) => !expected.includes(key));
  if (unknown.length) fail(`${label} contains unknown field(s): ${unknown.join(", ")}.`);
  const missing = expected.filter((key) => !actual.includes(key));
  if (missing.length) fail(`${label} is missing field(s): ${missing.join(", ")}.`);
  return value;
}

function array(value, label) {
  if (!Array.isArray(value)) fail(`${label} must be an array.`);
  return value;
}

function string(value, label, pattern = null, { allowEmpty = false } = {}) {
  if (typeof value !== "string" || (!allowEmpty && !value) || /[\0\r\n]/.test(value)) fail(`${label} must be a safe string.`);
  if (pattern && !pattern.test(value)) fail(`${label} has an invalid value.`);
  return value;
}

function nullableString(value, label, pattern = null) {
  if (value === null) return null;
  return string(value, label, pattern);
}

function boolean(value, label) {
  if (typeof value !== "boolean") fail(`${label} must be a boolean.`);
  return value;
}

function integer(value, label, { minimum = 0, nullable = false } = {}) {
  if (nullable && value === null) return null;
  if (!Number.isSafeInteger(value) || value < minimum) fail(`${label} must be a safe integer >= ${minimum}.`);
  return value;
}

function oneOf(value, label, values) {
  if (!values.includes(value)) fail(`${label} must be one of ${values.join(", ")}.`);
  return value;
}

function hash(value, label, { nullable = false } = {}) {
  if (nullable && value === null) return null;
  return string(value, label, SHA256);
}

function timestamp(value, label, { nullable = false } = {}) {
  if (nullable && value === null) return null;
  string(value, label, TIMESTAMP);
  const epoch = Date.parse(value);
  if (!Number.isFinite(epoch)) fail(`${label} is not a real UTC timestamp.`);
  const iso = new Date(epoch).toISOString();
  const roundTrip = value.includes(".") ? iso : iso.replace(/\.000Z$/, "Z");
  if (roundTrip !== value) fail(`${label} is not a real UTC timestamp.`);
  return value;
}

function absolutePath(value, label) {
  return string(value, label, ABSOLUTE_PATH);
}

function exactSorted(values, label, key = (entry) => entry) {
  const projected = values.map(key);
  const sorted = [...projected].sort((left, right) => left.localeCompare(right));
  if (projected.some((entry, index) => entry !== sorted[index])) fail(`${label} must be canonically sorted.`);
  const duplicate = projected.find((entry, index) => index > 0 && entry === projected[index - 1]);
  if (duplicate !== undefined) fail(`${label} contains duplicate identity ${duplicate}.`);
}

function stringArray(value, label, { pattern = null, sorted = true } = {}) {
  const values = array(value, label);
  values.forEach((entry, index) => string(entry, `${label}[${index}]`, pattern));
  if (sorted) exactSorted(values, label);
  else if (new Set(values).size !== values.length) fail(`${label} contains duplicate values.`);
  return values;
}

function filesystemIdentity(value, label, { nullable = false } = {}) {
  if (nullable && value === null) return null;
  record(value, label, ["type", "device", "inode", "uid", "gid", "mode", "nlink"]);
  oneOf(value.type, `${label}.type`, ["directory", "regular-file", "socket", "symbolic-link", "other"]);
  string(value.device, `${label}.device`, /^[0-9]+$/);
  string(value.inode, `${label}.inode`, /^[0-9]+$/);
  integer(value.uid, `${label}.uid`);
  integer(value.gid, `${label}.gid`);
  string(value.mode, `${label}.mode`, /^[0-7]{4}$/);
  integer(value.nlink, `${label}.nlink`, { minimum: 1, nullable: true });
  return value;
}

function validateHost(value) {
  record(value, "host", [
    "hostname", "machineIdSha256", "bootId", "sshHostKeySha256", "dockerDaemonId", "dockerRootDir",
    "dockerRootIdentity", "os", "principal",
  ]);
  string(value.hostname, "host.hostname", /^[A-Za-z0-9._-]+$/);
  hash(value.machineIdSha256, "host.machineIdSha256");
  string(value.bootId, "host.bootId", /^[a-f0-9-]{36}$/);
  hash(value.sshHostKeySha256, "host.sshHostKeySha256", { nullable: true });
  nullableString(value.dockerDaemonId, "host.dockerDaemonId", /^[A-Za-z0-9:._-]+$/);
  absolutePath(value.dockerRootDir, "host.dockerRootDir");
  filesystemIdentity(value.dockerRootIdentity, "host.dockerRootIdentity", { nullable: true });
  record(value.os, "host.os", ["id", "versionId", "kernel", "architecture"]);
  string(value.os.id, "host.os.id", /^[A-Za-z0-9._-]+$/);
  string(value.os.versionId, "host.os.versionId", /^[A-Za-z0-9._-]+$/);
  string(value.os.kernel, "host.os.kernel");
  string(value.os.architecture, "host.os.architecture", /^[A-Za-z0-9._-]+$/);
  record(value.principal, "host.principal", ["uid", "gid"]);
  integer(value.principal.uid, "host.principal.uid");
  integer(value.principal.gid, "host.principal.gid");
}

function validateSource(value) {
  record(value, "source", [
    "kind", "referenceSha256", "captureOutputs", "capturedProjectionDigests", "rawEvidenceCommitted", "secretValuesCaptured", "collectionMutatedLive",
  ]);
  oneOf(value.kind, "source.kind", ["LOCAL-CAPTURE-TRANSCRIPT", "SYNTHETIC"]);
  hash(value.referenceSha256, "source.referenceSha256");
  array(value.captureOutputs, "source.captureOutputs");
  if (!value.captureOutputs.length) fail("source.captureOutputs must not be empty.");
  value.captureOutputs.forEach((entry, index) => {
    const label = `source.captureOutputs[${index}]`;
    record(entry, label, ["kind", "callIdSha256", "outputSha256"]);
    string(entry.kind, `${label}.kind`, /^[a-z0-9][a-z0-9._-]*$/);
    hash(entry.callIdSha256, `${label}.callIdSha256`);
    hash(entry.outputSha256, `${label}.outputSha256`);
  });
  exactSorted(value.captureOutputs, "source.captureOutputs", (entry) => entry.kind);
  array(value.capturedProjectionDigests, "source.capturedProjectionDigests").forEach((entry, index) => {
    const label = `source.capturedProjectionDigests[${index}]`;
    record(entry, label, ["kind", "sha256"]);
    string(entry.kind, `${label}.kind`, /^[a-z0-9][a-z0-9._-]*$/);
    hash(entry.sha256, `${label}.sha256`);
  });
  if (!value.capturedProjectionDigests.length) fail("source.capturedProjectionDigests must not be empty.");
  exactSorted(value.capturedProjectionDigests, "source.capturedProjectionDigests", (entry) => entry.kind);
  if (value.rawEvidenceCommitted !== false || value.secretValuesCaptured !== false || value.collectionMutatedLive !== false) {
    fail("source must attest only local, uncommitted, non-secret, read-only evidence.");
  }
}

function validatePolicy(value) {
  record(value, "policy", [
    "unknownResourceDisposition", "missingResourceDisposition", "changedResourceDisposition", "globalTeardownAllowed",
    "removeOrphansAllowed", "pruneAllowed", "foreignResourceMutationAllowed",
  ]);
  if (value.unknownResourceDisposition !== "PRESERVE"
      || value.missingResourceDisposition !== "STOP"
      || value.changedResourceDisposition !== "STOP"
      || value.globalTeardownAllowed !== false
      || value.removeOrphansAllowed !== false
      || value.pruneAllowed !== false
      || value.foreignResourceMutationAllowed !== false) {
    fail("policy must be preserve-by-default and prohibit teardown, orphan removal, prune, and foreign mutation.");
  }
}

function validateRedaction(value) {
  record(value, "redaction", [
    "secretValuesCaptured", "environmentValuesCaptured", "databaseRowsCaptured", "privateKeysCaptured", "environmentKeyNamesCaptured",
  ]);
  if (value.secretValuesCaptured !== false
      || value.environmentValuesCaptured !== false
      || value.databaseRowsCaptured !== false
      || value.privateKeysCaptured !== false
      || value.environmentKeyNamesCaptured !== true) {
    fail("redaction contract must exclude all secret values, environment values, database rows, and private keys.");
  }
}

function validateSummary(value) {
  const keys = [
    "containers", "volumes", "attachedVolumes", "danglingVolumes", "namedVolumes", "anonymousVolumes", "bindMounts", "sourceRoots",
    "networks", "hostListeners", "databases", "applications", "secretMetadataRecords",
  ];
  record(value, "summary", keys);
  keys.forEach((key) => integer(value[key], `summary.${key}`));
}

function validateCheckout(value, index) {
  const label = `checkouts[${index}]`;
  record(value, label, ["id", "role", "path", "commit", "tree", "branch", "dirty", "dirtyPathCount", "statusSha256", "fsIdentity"]);
  string(value.id, `${label}.id`, /^[a-z0-9][a-z0-9._-]{2,127}$/);
  oneOf(value.role, `${label}.role`, ["ACTIVE-LIVE", "REMEDIATION", "CANDIDATE", "RELATED"]);
  absolutePath(value.path, `${label}.path`);
  string(value.commit, `${label}.commit`, GIT_OBJECT);
  string(value.tree, `${label}.tree`, GIT_OBJECT);
  string(value.branch, `${label}.branch`);
  boolean(value.dirty, `${label}.dirty`);
  integer(value.dirtyPathCount, `${label}.dirtyPathCount`);
  if (value.dirty !== (value.dirtyPathCount > 0)) fail(`${label} dirty state and dirtyPathCount disagree.`);
  hash(value.statusSha256, `${label}.statusSha256`, { nullable: true });
  filesystemIdentity(value.fsIdentity, `${label}.fsIdentity`, { nullable: true });
}

function validateConfigFile(value, label) {
  record(value, label, ["path", "sensitivity", "contentCaptured", "sha256", "fsIdentity"]);
  absolutePath(value.path, `${label}.path`);
  oneOf(value.sensitivity, `${label}.sensitivity`, ["NON-SECRET-CONFIG", "SECRET-METADATA-ONLY"]);
  boolean(value.contentCaptured, `${label}.contentCaptured`);
  hash(value.sha256, `${label}.sha256`, { nullable: true });
  filesystemIdentity(value.fsIdentity, `${label}.fsIdentity`, { nullable: true });
  if (value.sensitivity === "SECRET-METADATA-ONLY" && (value.contentCaptured || value.sha256 !== null)) {
    fail(`${label} must not capture or hash secret content.`);
  }
  if (value.contentCaptured !== (value.sha256 !== null)) fail(`${label} contentCaptured and sha256 disagree.`);
}

function validateComposeProject(value, index) {
  const label = `composeProjects[${index}]`;
  record(value, label, ["name", "workingDirectories", "configFiles", "containerNames"]);
  string(value.name, `${label}.name`, RESOURCE_NAME);
  stringArray(value.workingDirectories, `${label}.workingDirectories`, { pattern: ABSOLUTE_PATH });
  array(value.configFiles, `${label}.configFiles`);
  if (!value.configFiles.length) fail(`${label}.configFiles must not be empty.`);
  value.configFiles.forEach((entry, fileIndex) => validateConfigFile(entry, `${label}.configFiles[${fileIndex}]`));
  if (new Set(value.configFiles.map((entry) => entry.path)).size !== value.configFiles.length) fail(`${label}.configFiles contains duplicate paths.`);
  stringArray(value.containerNames, `${label}.containerNames`, { pattern: RESOURCE_NAME });
}

function validateContainerMount(value, label) {
  record(value, label, ["kind", "sourceRef", "destination", "readOnly", "propagation"]);
  oneOf(value.kind, `${label}.kind`, ["volume", "bind"]);
  string(value.sourceRef, `${label}.sourceRef`);
  if (value.kind === "bind") absolutePath(value.sourceRef, `${label}.sourceRef`);
  absolutePath(value.destination, `${label}.destination`);
  boolean(value.readOnly, `${label}.readOnly`);
  string(value.propagation, `${label}.propagation`, /^[A-Za-z0-9_-]*$/, { allowEmpty: true });
}

function validateEndpoint(value, label, { includeContainerName }) {
  const keys = includeContainerName
    ? ["containerName", "endpointId", "ipv4", "ipv6", "macAddress", "aliases"]
    : ["networkRef", "endpointId", "ipv4", "ipv6", "macAddress", "aliases"];
  record(value, label, keys);
  if (includeContainerName) string(value.containerName, `${label}.containerName`, RESOURCE_NAME);
  else string(value.networkRef, `${label}.networkRef`, RESOURCE_NAME);
  nullableString(value.endpointId, `${label}.endpointId`, SHA256);
  string(value.ipv4, `${label}.ipv4`, /^[0-9./]*$/, { allowEmpty: true });
  string(value.ipv6, `${label}.ipv6`, /^[a-fA-F0-9:./]*$/, { allowEmpty: true });
  nullableString(value.macAddress, `${label}.macAddress`, /^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/);
  if (value.aliases !== null) {
    array(value.aliases, `${label}.aliases`).forEach((entry, index) => string(entry, `${label}.aliases[${index}]`));
    const sortedAliases = [...value.aliases].sort((left, right) => left.localeCompare(right));
    if (value.aliases.some((entry, index) => entry !== sortedAliases[index])) fail(`${label}.aliases must be canonically sorted.`);
  }
}

function validatePort(value, label) {
  record(value, label, ["protocol", "containerPort", "hostIp", "hostPort"]);
  oneOf(value.protocol, `${label}.protocol`, ["tcp", "udp", "sctp"]);
  integer(value.containerPort, `${label}.containerPort`, { minimum: 1 });
  if (value.containerPort > 65535) fail(`${label}.containerPort exceeds 65535.`);
  if (value.hostIp !== null) string(value.hostIp, `${label}.hostIp`, /^[a-fA-F0-9:.*]+$/);
  integer(value.hostPort, `${label}.hostPort`, { minimum: 1, nullable: true });
  if (value.hostPort !== null && value.hostPort > 65535) fail(`${label}.hostPort exceeds 65535.`);
  if ((value.hostIp === null) !== (value.hostPort === null)) fail(`${label} must set hostIp and hostPort together.`);
}

function validateContainer(value, index) {
  const label = `containers[${index}]`;
  record(value, label, [
    "id", "name", "project", "service", "imageRef", "imageId", "createdAt", "state", "health", "exitCode", "configHash",
    "configuredUser", "effectiveUid", "effectiveGid", "readOnlyRootfs", "privileged", "mounts", "networks", "ports", "environmentKeys",
  ]);
  string(value.id, `${label}.id`, SHA256);
  string(value.name, `${label}.name`, RESOURCE_NAME);
  nullableString(value.project, `${label}.project`, RESOURCE_NAME);
  nullableString(value.service, `${label}.service`, RESOURCE_NAME);
  string(value.imageRef, `${label}.imageRef`);
  nullableString(value.imageId, `${label}.imageId`, DOCKER_IMAGE_ID);
  timestamp(value.createdAt, `${label}.createdAt`, { nullable: true });
  oneOf(value.state, `${label}.state`, ["created", "running", "paused", "restarting", "removing", "exited", "dead"]);
  oneOf(value.health, `${label}.health`, ["none", "starting", "healthy", "unhealthy"]);
  integer(value.exitCode, `${label}.exitCode`, { minimum: -2147483648, nullable: true });
  hash(value.configHash, `${label}.configHash`, { nullable: true });
  string(value.configuredUser, `${label}.configuredUser`, null, { allowEmpty: true });
  integer(value.effectiveUid, `${label}.effectiveUid`, { nullable: true });
  integer(value.effectiveGid, `${label}.effectiveGid`, { nullable: true });
  if (typeof value.readOnlyRootfs !== "boolean" && value.readOnlyRootfs !== null) fail(`${label}.readOnlyRootfs must be boolean or null.`);
  if (typeof value.privileged !== "boolean" && value.privileged !== null) fail(`${label}.privileged must be boolean or null.`);
  array(value.mounts, `${label}.mounts`).forEach((entry, mountIndex) => validateContainerMount(entry, `${label}.mounts[${mountIndex}]`));
  exactSorted(value.mounts, `${label}.mounts`, (entry) => `${entry.destination}\0${entry.kind}\0${entry.sourceRef}`);
  array(value.networks, `${label}.networks`).forEach((entry, networkIndex) => validateEndpoint(entry, `${label}.networks[${networkIndex}]`, { includeContainerName: false }));
  exactSorted(value.networks, `${label}.networks`, (entry) => entry.networkRef);
  array(value.ports, `${label}.ports`).forEach((entry, portIndex) => validatePort(entry, `${label}.ports[${portIndex}]`));
  exactSorted(value.ports, `${label}.ports`, (entry) => `${entry.protocol}:${String(entry.containerPort).padStart(5, "0")}:${entry.hostIp ?? ""}:${String(entry.hostPort ?? 0).padStart(5, "0")}`);
  stringArray(value.environmentKeys, `${label} environment keys`, { pattern: ENVIRONMENT_KEY });
}

function validateVolume(value, index) {
  const label = `volumes[${index}]`;
  record(value, label, [
    "name", "nameClass", "driver", "scope", "mountpoint", "createdAt", "optionsSha256", "labelsSha256", "composeProject",
    "composeVolume", "fsIdentity", "observedBytes", "attachments", "dangling",
  ]);
  string(value.name, `${label}.name`, /^(?:[a-f0-9]{64}|[A-Za-z0-9][A-Za-z0-9_.-]{0,255})$/);
  oneOf(value.nameClass, `${label}.nameClass`, ["ANONYMOUS", "NAMED"]);
  if ((value.nameClass === "ANONYMOUS") !== SHA256.test(value.name)) fail(`${label}.nameClass disagrees with the exact 64-hex name shape.`);
  nullableString(value.driver, `${label}.driver`, /^[A-Za-z0-9_.-]+$/);
  nullableString(value.scope, `${label}.scope`, /^[A-Za-z0-9_.-]+$/);
  if (value.mountpoint !== null) absolutePath(value.mountpoint, `${label}.mountpoint`);
  timestamp(value.createdAt, `${label}.createdAt`, { nullable: true });
  hash(value.optionsSha256, `${label}.optionsSha256`, { nullable: true });
  hash(value.labelsSha256, `${label}.labelsSha256`, { nullable: true });
  if (value.composeProject !== null) string(value.composeProject, `${label}.composeProject`, /^[A-Za-z0-9_.-]*$/, { allowEmpty: true });
  if (value.composeVolume !== null) string(value.composeVolume, `${label}.composeVolume`, /^[A-Za-z0-9_.-]*$/, { allowEmpty: true });
  filesystemIdentity(value.fsIdentity, `${label}.fsIdentity`, { nullable: true });
  integer(value.observedBytes, `${label}.observedBytes`, { nullable: true });
  array(value.attachments, `${label}.attachments`).forEach((entry, attachmentIndex) => {
    const attachmentLabel = `${label}.attachments[${attachmentIndex}]`;
    record(entry, attachmentLabel, ["containerName", "destination", "readOnly"]);
    string(entry.containerName, `${attachmentLabel}.containerName`, RESOURCE_NAME);
    absolutePath(entry.destination, `${attachmentLabel}.destination`);
    boolean(entry.readOnly, `${attachmentLabel}.readOnly`);
  });
  exactSorted(value.attachments, `${label}.attachments`, (entry) => `${entry.containerName}\0${entry.destination}`);
  boolean(value.dangling, `${label}.dangling`);
  if (value.dangling !== (value.attachments.length === 0)) fail(`${label}.dangling disagrees with attachments.`);
}

function validateBindMount(value, index) {
  const label = `bindMounts[${index}]`;
  record(value, label, ["source", "canonicalPath", "classification", "lstatIdentity", "targetIdentity", "contentSha256", "consumers"]);
  absolutePath(value.source, `${label}.source`);
  absolutePath(value.canonicalPath, `${label}.canonicalPath`);
  oneOf(value.classification, `${label}.classification`, [
    "APPLICATION-DATA", "CONFIG", "SECRET-METADATA", "SOCKET", "HOST-API", "SHARED-STORAGE", "UNKNOWN-PRESERVE",
  ]);
  filesystemIdentity(value.lstatIdentity, `${label}.lstatIdentity`, { nullable: true });
  filesystemIdentity(value.targetIdentity, `${label}.targetIdentity`, { nullable: true });
  hash(value.contentSha256, `${label}.contentSha256`, { nullable: true });
  array(value.consumers, `${label}.consumers`).forEach((entry, consumerIndex) => {
    const consumerLabel = `${label}.consumers[${consumerIndex}]`;
    record(entry, consumerLabel, ["containerName", "destination", "readOnly"]);
    string(entry.containerName, `${consumerLabel}.containerName`, RESOURCE_NAME);
    absolutePath(entry.destination, `${consumerLabel}.destination`);
    boolean(entry.readOnly, `${consumerLabel}.readOnly`);
  });
  exactSorted(value.consumers, `${label}.consumers`, (entry) => `${entry.containerName}\0${entry.destination}`);
}

function validateNetwork(value, index) {
  const label = `networks[${index}]`;
  record(value, label, ["id", "name", "driver", "scope", "internal", "attachable", "ingress", "ipam", "optionsSha256", "labelsSha256", "endpoints"]);
  string(value.id, `${label}.id`, SHA256);
  string(value.name, `${label}.name`, RESOURCE_NAME);
  string(value.driver, `${label}.driver`, /^[A-Za-z0-9_.-]+$/);
  string(value.scope, `${label}.scope`, /^[A-Za-z0-9_.-]+$/);
  boolean(value.internal, `${label}.internal`);
  boolean(value.attachable, `${label}.attachable`);
  boolean(value.ingress, `${label}.ingress`);
  array(value.ipam, `${label}.ipam`).forEach((entry, ipamIndex) => {
    const ipamLabel = `${label}.ipam[${ipamIndex}]`;
    record(entry, ipamLabel, ["subnet", "gateway"]);
    string(entry.subnet, `${ipamLabel}.subnet`, /^[a-fA-F0-9:./]+$/);
    string(entry.gateway, `${ipamLabel}.gateway`, /^[a-fA-F0-9:.]+$/);
  });
  exactSorted(value.ipam, `${label}.ipam`, (entry) => `${entry.subnet}\0${entry.gateway}`);
  hash(value.optionsSha256, `${label}.optionsSha256`, { nullable: true });
  hash(value.labelsSha256, `${label}.labelsSha256`, { nullable: true });
  array(value.endpoints, `${label}.endpoints`).forEach((entry, endpointIndex) => validateEndpoint(entry, `${label}.endpoints[${endpointIndex}]`, { includeContainerName: true }));
  exactSorted(value.endpoints, `${label}.endpoints`, (entry) => entry.containerName);
}

function validateSourceRoot(value, index) {
  const label = `sourceRoots[${index}]`;
  record(value, label, ["path", "fsIdentity", "observedBytes", "fileCount", "mounted"]);
  absolutePath(value.path, `${label}.path`);
  filesystemIdentity(value.fsIdentity, `${label}.fsIdentity`, { nullable: true });
  integer(value.observedBytes, `${label}.observedBytes`, { nullable: true });
  integer(value.fileCount, `${label}.fileCount`, { nullable: true });
  boolean(value.mounted, `${label}.mounted`);
}

function validateHostListener(value, index) {
  const label = `hostListeners[${index}]`;
  record(value, label, ["protocol", "address", "port", "ownerClass", "uid"]);
  oneOf(value.protocol, `${label}.protocol`, ["tcp", "udp"]);
  string(value.address, `${label}.address`, /^[A-Za-z0-9:.*%_-]+$/);
  integer(value.port, `${label}.port`, { minimum: 1 });
  if (value.port > 65535) fail(`${label}.port exceeds 65535.`);
  string(value.ownerClass, `${label}.ownerClass`, /^[A-Za-z0-9_.-]+$/);
  integer(value.uid, `${label}.uid`, { nullable: true });
}

function validateDatabase(value, index) {
  const label = `databases[${index}]`;
  record(value, label, ["id", "engine", "engineVersion", "serverContainer", "name", "kind", "owner", "tableCount", "catalogSha256", "storageRefs"]);
  string(value.id, `${label}.id`, /^[A-Za-z0-9][A-Za-z0-9:._-]+$/);
  oneOf(value.engine, `${label}.engine`, ["POSTGRESQL", "MARIADB", "REDIS"]);
  string(value.engineVersion, `${label}.engineVersion`);
  string(value.serverContainer, `${label}.serverContainer`, RESOURCE_NAME);
  string(value.name, `${label}.name`);
  oneOf(value.kind, `${label}.kind`, ["APPLICATION", "PLATFORM", "SYSTEM", "RESTORE", "UNMAPPED"]);
  nullableString(value.owner, `${label}.owner`);
  integer(value.tableCount, `${label}.tableCount`, { nullable: true });
  hash(value.catalogSha256, `${label}.catalogSha256`, { nullable: true });
  stringArray(value.storageRefs, `${label}.storageRefs`);
  if (!value.storageRefs.length) fail(`${label}.storageRefs must not be empty.`);
}

function validateSecretMetadata(value, index) {
  const label = `secretMetadata[${index}]`;
  record(value, label, ["id", "kind", "path", "fsIdentity", "environmentKeys", "contentCaptured", "valuesCaptured"]);
  string(value.id, `${label}.id`, SECRET_METADATA_ID);
  oneOf(value.kind, `${label}.kind`, ["ENV-FILE", "SECRET-FILE", "CONFIG-SECRET-OVERLAY"]);
  absolutePath(value.path, `${label}.path`);
  filesystemIdentity(value.fsIdentity, `${label}.fsIdentity`, { nullable: true });
  stringArray(value.environmentKeys, `${label} environment keys`, { pattern: ENVIRONMENT_KEY });
  if (value.contentCaptured !== false || value.valuesCaptured !== false) fail(`${label} must contain metadata only, never secret content or values.`);
}

function validateLogicalRecoveryAnchor(value, index) {
  const label = `logicalRecoveryAnchors[${index}]`;
  record(value, label, [
    "id", "displayName", "mappingState", "sourceRootRefs", "sourceBindRefs", "containerRefs", "databaseRefs", "storageRefs", "configRefs", "secretMetadataRefs",
  ]);
  string(value.id, `${label}.id`, /^[a-z0-9][a-z0-9._-]{1,127}$/);
  string(value.displayName, `${label}.displayName`);
  oneOf(value.mappingState, `${label}.mappingState`, ["MAPPED", "PARTIAL", "UNMAPPED", "NONE-OBSERVED", "SOURCE-ONLY"]);
  stringArray(value.sourceRootRefs, `${label}.sourceRootRefs`, { pattern: ABSOLUTE_PATH });
  stringArray(value.sourceBindRefs, `${label}.sourceBindRefs`, { pattern: ABSOLUTE_PATH });
  stringArray(value.containerRefs, `${label}.containerRefs`, { pattern: RESOURCE_NAME });
  stringArray(value.databaseRefs, `${label}.databaseRefs`, { pattern: /^[A-Za-z0-9][A-Za-z0-9:._-]+$/ });
  stringArray(value.storageRefs, `${label}.storageRefs`);
  stringArray(value.configRefs, `${label}.configRefs`, { pattern: ABSOLUTE_PATH });
  stringArray(value.secretMetadataRefs, `${label}.secretMetadataRefs`, { pattern: SECRET_METADATA_ID });
}

function validateDeficiency(value, index) {
  const label = `deficiencies[${index}]`;
  record(value, label, ["code", "resourceClass", "resourceId", "field", "reason"]);
  string(value.code, `${label}.code`, /^[A-Z0-9][A-Z0-9_-]{2,127}$/);
  string(value.resourceClass, `${label}.resourceClass`, /^[a-z][a-z0-9-]{1,63}$/);
  string(value.resourceId, `${label}.resourceId`);
  string(value.field, `${label}.field`, /^[A-Za-z][A-Za-z0-9.\[\]_-]{0,255}$/);
  string(value.reason, `${label}.reason`);
}

function canonicalDigests(document) {
  return Object.fromEntries(Object.entries(DIGEST_FIELDS).map(([digestField, resourceField]) => [
    digestField,
    sha256Canonical(document[resourceField]),
  ]));
}

function baselinePayload(document) {
  const payload = clone(document);
  delete payload.baselineId;
  return payload;
}

export function sealLivePreservationBaseline(input) {
  const sealed = clone(input);
  sealed.digests = canonicalDigests(sealed);
  sealed.baselineId = sha256Canonical(baselinePayload(sealed));
  return sealed;
}

function validateCrossReferences(document) {
  const containers = new Map(document.containers.map((entry) => [entry.name, entry]));
  const volumes = new Map(document.volumes.map((entry) => [entry.name, entry]));
  const binds = new Map(document.bindMounts.map((entry) => [entry.source, entry]));
  const sourceRoots = new Map(document.sourceRoots.map((entry) => [entry.path, entry]));
  const networks = new Map(document.networks.map((entry) => [entry.name, entry]));
  const databases = new Map(document.databases.map((entry) => [entry.id, entry]));
  const secretMetadata = new Map(document.secretMetadata.map((entry) => [entry.id, entry]));
  const configPaths = new Set(document.composeProjects.flatMap((project) => project.configFiles.map((entry) => entry.path)));
  const storageRefs = new Set([...volumes.keys(), ...binds.keys(), ...sourceRoots.keys()]);
  const composeMembership = new Map();

  for (const project of document.composeProjects) {
    for (const name of project.containerNames) {
      const container = containers.get(name);
      if (!container) fail(`compose project ${project.name} references unknown container ${name}.`);
      if (composeMembership.has(name)) fail(`container ${name} belongs to multiple compose projects.`);
      composeMembership.set(name, project.name);
      if (container.project !== null && container.project !== project.name) {
        fail(`container ${name} compose project label conflicts with project membership.`);
      }
    }
  }
  for (const container of document.containers) {
    if (container.project !== null && composeMembership.get(container.name) !== container.project) {
      fail(`container ${container.name} compose project label lacks reciprocal project membership.`);
    }
  }

  for (const container of document.containers) {
    for (const mount of container.mounts) {
      if (mount.kind === "volume") {
        const volume = volumes.get(mount.sourceRef);
        if (!volume) fail(`container ${container.name} references unknown volume ${mount.sourceRef}.`);
        const reciprocal = volume.attachments.some((entry) => entry.containerName === container.name
          && entry.destination === mount.destination && entry.readOnly === mount.readOnly);
        if (!reciprocal) fail(`container ${container.name} volume mount ${mount.destination} lacks a reciprocal attachment.`);
      } else {
        const bind = binds.get(mount.sourceRef);
        if (!bind) fail(`container ${container.name} references unknown bind ${mount.sourceRef}.`);
        const reciprocal = bind.consumers.some((entry) => entry.containerName === container.name
          && entry.destination === mount.destination && entry.readOnly === mount.readOnly);
        if (!reciprocal) fail(`container ${container.name} bind mount ${mount.destination} lacks a reciprocal consumer.`);
      }
    }
    for (const endpoint of container.networks) {
      const network = networks.get(endpoint.networkRef);
      if (!network) fail(`container ${container.name} references unknown network ${endpoint.networkRef}.`);
      const reciprocal = network.endpoints.some((entry) => entry.containerName === container.name
        && canonicalJson({ ...entry, containerName: undefined }) === canonicalJson({ ...endpoint, networkRef: undefined }));
      if (!reciprocal) {
        const match = network.endpoints.find((entry) => entry.containerName === container.name);
        if (!match
            || match.endpointId !== endpoint.endpointId
            || match.ipv4 !== endpoint.ipv4
            || match.ipv6 !== endpoint.ipv6
            || match.macAddress !== endpoint.macAddress
            || canonicalJson(match.aliases) !== canonicalJson(endpoint.aliases)) {
          fail(`container ${container.name} network ${endpoint.networkRef} lacks a reciprocal endpoint.`);
        }
      }
    }
  }

  for (const volume of document.volumes) {
    for (const attachment of volume.attachments) {
      const container = containers.get(attachment.containerName);
      if (!container) fail(`volume ${volume.name} references unknown container ${attachment.containerName}.`);
      if (!container.mounts.some((entry) => entry.kind === "volume" && entry.sourceRef === volume.name
          && entry.destination === attachment.destination && entry.readOnly === attachment.readOnly)) {
        fail(`volume ${volume.name} attachment lacks a reciprocal container mount.`);
      }
    }
  }
  for (const bind of document.bindMounts) {
    for (const consumer of bind.consumers) {
      const container = containers.get(consumer.containerName);
      if (!container) fail(`bind ${bind.source} references unknown container ${consumer.containerName}.`);
      if (!container.mounts.some((entry) => entry.kind === "bind" && entry.sourceRef === bind.source
          && entry.destination === consumer.destination && entry.readOnly === consumer.readOnly)) {
        fail(`bind ${bind.source} consumer lacks a reciprocal container mount.`);
      }
    }
  }
  for (const network of document.networks) {
    for (const endpoint of network.endpoints) {
      const container = containers.get(endpoint.containerName);
      if (!container) fail(`network ${network.name} references unknown container ${endpoint.containerName}.`);
      if (!container.networks.some((entry) => entry.networkRef === network.name
          && entry.endpointId === endpoint.endpointId
          && entry.ipv4 === endpoint.ipv4
          && entry.ipv6 === endpoint.ipv6
          && entry.macAddress === endpoint.macAddress
          && canonicalJson(entry.aliases) === canonicalJson(endpoint.aliases))) {
        fail(`network ${network.name} endpoint lacks a reciprocal container endpoint.`);
      }
    }
  }
  for (const database of document.databases) {
    if (!containers.has(database.serverContainer)) fail(`database ${database.id} references unknown server container ${database.serverContainer}.`);
    for (const ref of database.storageRefs) if (!storageRefs.has(ref)) fail(`database ${database.id} references unknown storage ${ref}.`);
  }
  for (const anchor of document.logicalRecoveryAnchors) {
    for (const ref of anchor.sourceRootRefs) if (!sourceRoots.has(ref)) fail(`logical recovery anchor ${anchor.id} references unknown source root ${ref}.`);
    for (const ref of anchor.sourceBindRefs) if (!binds.has(ref)) fail(`logical recovery anchor ${anchor.id} references unknown source bind ${ref}.`);
    for (const ref of anchor.containerRefs) if (!containers.has(ref)) fail(`logical recovery anchor ${anchor.id} references unknown container ${ref}.`);
    for (const ref of anchor.databaseRefs) if (!databases.has(ref)) fail(`logical recovery anchor ${anchor.id} references unknown database ${ref}.`);
    for (const ref of anchor.storageRefs) if (!storageRefs.has(ref)) fail(`logical recovery anchor ${anchor.id} references unknown storage ${ref}.`);
    for (const ref of anchor.configRefs) if (!configPaths.has(ref)) fail(`logical recovery anchor ${anchor.id} references unknown config metadata ${ref}.`);
    for (const ref of anchor.secretMetadataRefs) if (!secretMetadata.has(ref)) fail(`logical recovery anchor ${anchor.id} references unknown secret metadata ${ref}.`);
  }
}

function validateCompleteness(document) {
  const missing = [];
  const requireValue = (value, field) => { if (value === null) missing.push(field); };
  const requireIdentity = (identity, field) => {
    requireValue(identity, field);
    if (identity !== null) requireValue(identity.nlink, `${field}.nlink`);
  };
  requireValue(document.capturedAt.completedAt, "capturedAt.completedAt");
  requireValue(document.host.sshHostKeySha256, "host.sshHostKeySha256");
  requireValue(document.host.dockerDaemonId, "host.dockerDaemonId");
  requireIdentity(document.host.dockerRootIdentity, "host.dockerRootIdentity");
  document.checkouts.forEach((entry, index) => {
    requireValue(entry.statusSha256, `checkouts[${index}].statusSha256`);
    requireIdentity(entry.fsIdentity, `checkouts[${index}].fsIdentity`);
  });
  document.composeProjects.forEach((project, projectIndex) => project.configFiles.forEach((entry, fileIndex) => {
    requireIdentity(entry.fsIdentity, `composeProjects[${projectIndex}].configFiles[${fileIndex}].fsIdentity`);
    if (entry.sensitivity === "NON-SECRET-CONFIG") requireValue(entry.sha256, `composeProjects[${projectIndex}].configFiles[${fileIndex}].sha256`);
  }));
  const composeMembership = new Set(document.composeProjects.flatMap((project) => project.containerNames));
  document.containers.forEach((entry, index) => {
    ["imageId", "createdAt", "configHash", "effectiveUid", "effectiveGid", "readOnlyRootfs", "privileged"].forEach((field) => {
      requireValue(entry[field], `containers[${index}].${field}`);
    });
    if (composeMembership.has(entry.name)) {
      requireValue(entry.project, `containers[${index}].project`);
      requireValue(entry.service, `containers[${index}].service`);
    }
    entry.networks.forEach((endpoint, endpointIndex) => {
      requireValue(endpoint.endpointId, `containers[${index}].networks[${endpointIndex}].endpointId`);
      requireValue(endpoint.macAddress, `containers[${index}].networks[${endpointIndex}].macAddress`);
      requireValue(endpoint.aliases, `containers[${index}].networks[${endpointIndex}].aliases`);
    });
  });
  document.volumes.forEach((entry, index) => {
    ["driver", "scope", "mountpoint", "createdAt", "optionsSha256", "labelsSha256"].forEach((field) => requireValue(entry[field], `volumes[${index}].${field}`));
    requireIdentity(entry.fsIdentity, `volumes[${index}].fsIdentity`);
  });
  document.bindMounts.forEach((entry, index) => {
    requireIdentity(entry.lstatIdentity, `bindMounts[${index}].lstatIdentity`);
    requireIdentity(entry.targetIdentity, `bindMounts[${index}].targetIdentity`);
  });
  document.sourceRoots.forEach((entry, index) => requireIdentity(entry.fsIdentity, `sourceRoots[${index}].fsIdentity`));
  document.networks.forEach((entry, index) => {
    requireValue(entry.optionsSha256, `networks[${index}].optionsSha256`);
    requireValue(entry.labelsSha256, `networks[${index}].labelsSha256`);
    entry.endpoints.forEach((endpoint, endpointIndex) => {
      requireValue(endpoint.endpointId, `networks[${index}].endpoints[${endpointIndex}].endpointId`);
      requireValue(endpoint.macAddress, `networks[${index}].endpoints[${endpointIndex}].macAddress`);
      requireValue(endpoint.aliases, `networks[${index}].endpoints[${endpointIndex}].aliases`);
    });
  });
  document.hostListeners.forEach((entry, index) => requireValue(entry.uid, `hostListeners[${index}].uid`));
  document.databases.forEach((entry, index) => requireValue(entry.catalogSha256, `databases[${index}].catalogSha256`));
  document.secretMetadata.forEach((entry, index) => requireIdentity(entry.fsIdentity, `secretMetadata[${index}].fsIdentity`));

  const coveredContainers = new Set(document.logicalRecoveryAnchors.flatMap((anchor) => anchor.containerRefs));
  const coveredDatabases = new Set(document.logicalRecoveryAnchors.flatMap((anchor) => anchor.databaseRefs));
  const coveredStorage = new Set(document.logicalRecoveryAnchors.flatMap((anchor) => anchor.storageRefs));
  const coveredSourceRoots = new Set(document.logicalRecoveryAnchors.flatMap((anchor) => anchor.sourceRootRefs));
  const coveredSourceBinds = new Set(document.logicalRecoveryAnchors.flatMap((anchor) => anchor.sourceBindRefs));
  const coveredConfigs = new Set(document.logicalRecoveryAnchors.flatMap((anchor) => anchor.configRefs));
  const coveredSecrets = new Set(document.logicalRecoveryAnchors.flatMap((anchor) => anchor.secretMetadataRefs));
  const requireCoverage = (values, covered, field) => {
    for (const value of values) if (!covered.has(value)) missing.push(`${field}[${value}]`);
  };

  document.logicalRecoveryAnchors.forEach((anchor, index) => {
    if (anchor.mappingState !== "MAPPED") missing.push(`logicalRecoveryAnchors[${index}].mappingState`);
  });
  document.databases.forEach((database, index) => {
    if (database.kind === "UNMAPPED") missing.push(`databases[${index}].kind`);
  });
  document.bindMounts.forEach((bind, index) => {
    if (bind.classification === "UNKNOWN-PRESERVE") missing.push(`bindMounts[${index}].classification`);
  });
  requireCoverage(document.containers.map((entry) => entry.name), coveredContainers, "logicalCoverage.container");
  requireCoverage(document.databases.map((entry) => entry.id), coveredDatabases, "logicalCoverage.database");
  requireCoverage(document.volumes.map((entry) => entry.name), coveredStorage, "logicalCoverage.volume");
  requireCoverage(document.bindMounts.map((entry) => entry.source), new Set([...coveredSourceBinds, ...coveredStorage]), "logicalCoverage.bindMount");
  requireCoverage(document.sourceRoots.map((entry) => entry.path), new Set([...coveredSourceRoots, ...coveredStorage]), "logicalCoverage.sourceRoot");
  requireCoverage(document.composeProjects.flatMap((project) => project.configFiles.map((entry) => entry.path)), coveredConfigs, "logicalCoverage.config");
  requireCoverage(document.secretMetadata.map((entry) => entry.id), coveredSecrets, "logicalCoverage.secretMetadata");
  if (missing.length) fail(`complete=true is missing complete preservation evidence: ${missing.slice(0, 10).join(", ")}${missing.length > 10 ? ", ..." : ""}.`);
}

export function validateLivePreservationBaseline(input, { requireComplete = false } = {}) {
  const document = clone(input);
  record(document, "document", TOP_LEVEL_KEYS);
  if (document.schema !== livePreservationBaselineSchema) fail(`schema must be ${livePreservationBaselineSchema}.`);
  hash(document.baselineId, "baselineId");
  if (document.scope !== "platform-infrastructure") fail("scope must be platform-infrastructure.");
  oneOf(document.evidenceClass, "evidenceClass", ["LIVE-READ-ONLY", "SYNTHETIC-TEST"]);
  boolean(document.synthetic, "synthetic");
  if (document.synthetic !== (document.evidenceClass === "SYNTHETIC-TEST")) fail("synthetic must match evidenceClass.");
  boolean(document.complete, "complete");
  const expectedStatus = document.complete ? "COMPLETE-PRESERVATION-BASELINE" : "INCOMPLETE-NO-GO";
  if (document.status !== expectedStatus) fail(`status must be ${expectedStatus}.`);
  if (document.gateAdmissible !== false || document.mutationAuthority !== false || document.effect !== "DENY-ONLY") {
    fail("document must be deny-only, non-gate-admissible, and carry no mutation authority.");
  }
  if (document.identityObservationMode !== "POINT-IN-TIME") fail("identityObservationMode must be POINT-IN-TIME.");
  record(document.capturedAt, "capturedAt", ["startedAt", "completedAt"]);
  timestamp(document.capturedAt.startedAt, "capturedAt.startedAt");
  timestamp(document.capturedAt.completedAt, "capturedAt.completedAt", { nullable: true });
  if (document.capturedAt.completedAt !== null
      && Date.parse(document.capturedAt.completedAt) < Date.parse(document.capturedAt.startedAt)) fail("capture window ends before it starts.");
  validateHost(document.host);
  validateSource(document.source);
  if (document.synthetic !== (document.source.kind === "SYNTHETIC")) fail("source.kind must match synthetic evidence class.");
  validatePolicy(document.policy);
  validateRedaction(document.redaction);
  validateSummary(document.summary);

  array(document.checkouts, "checkouts").forEach(validateCheckout);
  exactSorted(document.checkouts, "checkouts", (entry) => entry.id);
  array(document.composeProjects, "composeProjects").forEach(validateComposeProject);
  exactSorted(document.composeProjects, "composeProjects", (entry) => entry.name);
  array(document.containers, "containers").forEach(validateContainer);
  exactSorted(document.containers, "containers", (entry) => entry.name);
  if (new Set(document.containers.map((entry) => entry.id)).size !== document.containers.length) fail("containers contains duplicate full IDs.");
  array(document.volumes, "volumes").forEach(validateVolume);
  exactSorted(document.volumes, "volumes", (entry) => entry.name);
  array(document.bindMounts, "bindMounts").forEach(validateBindMount);
  exactSorted(document.bindMounts, "bindMounts", (entry) => entry.source);
  array(document.sourceRoots, "sourceRoots").forEach(validateSourceRoot);
  exactSorted(document.sourceRoots, "sourceRoots", (entry) => entry.path);
  array(document.networks, "networks").forEach(validateNetwork);
  exactSorted(document.networks, "networks", (entry) => entry.name);
  if (new Set(document.networks.map((entry) => entry.id)).size !== document.networks.length) fail("networks contains duplicate full IDs.");
  array(document.hostListeners, "hostListeners").forEach(validateHostListener);
  exactSorted(document.hostListeners, "hostListeners", (entry) => `${entry.protocol}:${entry.address}:${String(entry.port).padStart(5, "0")}:${entry.ownerClass}`);
  array(document.databases, "databases").forEach(validateDatabase);
  exactSorted(document.databases, "databases", (entry) => entry.id);
  array(document.secretMetadata, "secretMetadata").forEach(validateSecretMetadata);
  exactSorted(document.secretMetadata, "secretMetadata", (entry) => entry.id);
  array(document.logicalRecoveryAnchors, "logicalRecoveryAnchors").forEach(validateLogicalRecoveryAnchor);
  exactSorted(document.logicalRecoveryAnchors, "logicalRecoveryAnchors", (entry) => entry.id);
  array(document.deficiencies, "deficiencies").forEach(validateDeficiency);
  exactSorted(document.deficiencies, "deficiencies", (entry) => `${entry.code}\0${entry.resourceClass}\0${entry.resourceId}\0${entry.field}`);
  if (document.complete !== (document.deficiencies.length === 0)) fail("complete and deficiencies must be exact opposites.");

  const attachedVolumes = document.volumes.filter((entry) => !entry.dangling).length;
  const expectedSummary = {
    containers: document.containers.length,
    volumes: document.volumes.length,
    attachedVolumes,
    danglingVolumes: document.volumes.length - attachedVolumes,
    namedVolumes: document.volumes.filter((entry) => entry.nameClass === "NAMED").length,
    anonymousVolumes: document.volumes.filter((entry) => entry.nameClass === "ANONYMOUS").length,
    bindMounts: document.bindMounts.length,
    sourceRoots: document.sourceRoots.length,
    networks: document.networks.length,
    hostListeners: document.hostListeners.length,
    databases: document.databases.length,
    applications: document.logicalRecoveryAnchors.length,
    secretMetadataRecords: document.secretMetadata.length,
  };
  if (canonicalJson(document.summary) !== canonicalJson(expectedSummary)) fail("summary does not match the exact resource inventory.");

  validateCrossReferences(document);
  record(document.digests, "digests", Object.keys(DIGEST_FIELDS));
  const expectedDigests = canonicalDigests(document);
  if (canonicalJson(document.digests) !== canonicalJson(expectedDigests)) fail("one or more resource class digests are stale or mismatched.");
  const expectedBaselineId = sha256Canonical(baselinePayload(document));
  if (document.baselineId !== expectedBaselineId) fail("baselineId digest is stale or mismatched.");
  if (document.complete) validateCompleteness(document);
  if (requireComplete && !document.complete) fail("comparison requires complete preservation evidence; this baseline is INCOMPLETE-NO-GO.");

  return {
    schema: "platform.live-preservation-baseline-validation/v1",
    valid: true,
    complete: document.complete,
    status: document.status,
    gateAdmissible: false,
    mutationAuthority: false,
    comparisonEligible: document.complete,
    baselineId: document.baselineId,
    summary: document.summary,
    deficiencies: document.deficiencies,
  };
}

function preservationProjection(kind, value) {
  if (kind === "volumes") {
    const copy = clone(value);
    delete copy.observedBytes;
    return copy;
  }
  return value;
}

function compareClass(kind, baseline, observation, key, issues) {
  const expected = new Map(baseline.map((entry) => [key(entry), entry]));
  const actual = new Map(observation.map((entry) => [key(entry), entry]));
  for (const identity of expected.keys()) {
    if (!actual.has(identity)) issues.push(`${kind}:missing-resource:${identity}`);
    else if (canonicalJson(preservationProjection(kind, expected.get(identity)))
      !== canonicalJson(preservationProjection(kind, actual.get(identity)))) {
      issues.push(`${kind}:changed-resource:${identity}`);
    }
  }
  for (const identity of actual.keys()) if (!expected.has(identity)) issues.push(`${kind}:unknown-resource:${identity}:preserve-by-default`);
}

export function compareLivePreservationBaseline(baselineInput, observationInput) {
  const issues = [];
  try {
    validateLivePreservationBaseline(baselineInput, { requireComplete: true });
  } catch (error) {
    issues.push(`baseline-invalid:${String(error?.message ?? error)}`);
  }
  try {
    validateLivePreservationBaseline(observationInput, { requireComplete: true });
  } catch (error) {
    issues.push(`observation-invalid:${String(error?.message ?? error)}`);
  }
  if (!issues.length) {
    const baseline = clone(baselineInput);
    const observation = clone(observationInput);
    const stableHostFields = ["hostname", "machineIdSha256", "sshHostKeySha256", "dockerDaemonId", "dockerRootDir", "dockerRootIdentity"];
    const baselineHost = Object.fromEntries(stableHostFields.map((key) => [key, baseline.host[key]]));
    const observationHost = Object.fromEntries(stableHostFields.map((key) => [key, observation.host[key]]));
    if (canonicalJson(baselineHost) !== canonicalJson(observationHost)) issues.push("host:changed-identity:external-admission-required");
    compareClass("checkouts", baseline.checkouts, observation.checkouts, (entry) => entry.id, issues);
    compareClass("compose-projects", baseline.composeProjects, observation.composeProjects, (entry) => entry.name, issues);
    compareClass("containers", baseline.containers, observation.containers, (entry) => entry.name, issues);
    compareClass("volumes", baseline.volumes, observation.volumes, (entry) => entry.name, issues);
    compareClass("bind-mounts", baseline.bindMounts, observation.bindMounts, (entry) => entry.source, issues);
    compareClass("source-roots", baseline.sourceRoots, observation.sourceRoots, (entry) => entry.path, issues);
    compareClass("networks", baseline.networks, observation.networks, (entry) => entry.name, issues);
    compareClass("host-listeners", baseline.hostListeners, observation.hostListeners,
      (entry) => `${entry.protocol}:${entry.address}:${entry.port}:${entry.ownerClass}`, issues);
    compareClass("databases", baseline.databases, observation.databases, (entry) => entry.id, issues);
    compareClass("secret-metadata", baseline.secretMetadata, observation.secretMetadata, (entry) => entry.id, issues);
    compareClass("logical-recovery-anchors", baseline.logicalRecoveryAnchors, observation.logicalRecoveryAnchors, (entry) => entry.id, issues);
  }
  issues.sort();
  return {
    schema: "platform.live-preservation-comparison/v1",
    preserved: issues.length === 0,
    status: issues.length === 0 ? "PASS-PRESERVATION-ONLY" : "STOP",
    mutationAuthorized: false,
    issues,
  };
}

function loadJsonFile(file, label) {
  const resolved = path.resolve(file);
  const stat = lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink()) fail(`${label} must be a regular non-symlink file.`);
  if (realpathSync(resolved) !== resolved) fail(`${label} path must be canonical.`);
  return JSON.parse(readFileSync(resolved, "utf8").replace(/^\uFEFF/, ""));
}

function argumentValue(args, name) {
  const index = args.indexOf(name);
  if (index < 0 || index + 1 >= args.length || args[index + 1].startsWith("--")) fail(`${name} is required.`);
  return args[index + 1];
}

function cli(argv) {
  const [command, ...args] = argv;
  if (command === "validate") {
    const baseline = loadJsonFile(argumentValue(args, "--baseline"), "baseline");
    return validateLivePreservationBaseline(baseline, { requireComplete: args.includes("--require-complete") });
  }
  if (command === "compare") {
    const baseline = loadJsonFile(argumentValue(args, "--baseline"), "baseline");
    const observation = loadJsonFile(argumentValue(args, "--observation"), "observation");
    return compareLivePreservationBaseline(baseline, observation);
  }
  fail("usage: live-preservation-baseline.mjs validate --baseline FILE [--require-complete] | compare --baseline FILE --observation FILE");
}

const invoked = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invoked) {
  try {
    const result = cli(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (result.status === "STOP") process.exitCode = 2;
  } catch (error) {
    process.stdout.write(`${JSON.stringify({
      schema: "platform.live-preservation-baseline-error/v1",
      valid: false,
      status: "STOP",
      gateAdmissible: false,
      mutationAuthority: false,
      error: String(error?.message ?? error),
    }, null, 2)}\n`);
    process.exitCode = 2;
  }
}
