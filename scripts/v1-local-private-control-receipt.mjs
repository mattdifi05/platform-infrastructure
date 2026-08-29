#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

export const V1_LOCAL_PRIVATE_CONTAINER_NAMES = Object.freeze([
  "enterprise-alertmanager", "enterprise-backend", "enterprise-backup-scheduler",
  "enterprise-cadvisor", "enterprise-control-center", "enterprise-grafana",
  "enterprise-keycloak", "enterprise-local-dns", "enterprise-local-registry",
  "enterprise-loki", "enterprise-minio", "enterprise-nats", "enterprise-node-exporter",
  "enterprise-postgres", "enterprise-project-router", "enterprise-prometheus",
  "enterprise-promtail", "enterprise-redis", "enterprise-traefik", "enterprise-waf",
  "enterprise-web", "enterprise-worker-jobs", "enterprise-worker-notifications",
  "mariadb", "node-account", "node-opstudents", "node-ui", "php-anniversary",
  "php-apache", "php-fiplatform", "php-matthewdifilippo", "php-stream",
  "php-workcalendar", "phpmyadmin", "phppgadmin",
]);
export const V1_LOCAL_PRIVATE_CANONICAL_CONTAINER_NAMES = Object.freeze([
  ...V1_LOCAL_PRIVATE_CONTAINER_NAMES.filter((name) => name !== "enterprise-backup-scheduler"),
  "enterprise-broker-auth-bootstrap", "enterprise-platform-alert-dispatcher",
].sort());
export const V1_LOCAL_PRIVATE_ACTIVE_MANAGED_CONTAINER_NAMES = Object.freeze([
  "enterprise-alertmanager", "enterprise-broker-auth-bootstrap", "enterprise-control-center",
  "enterprise-grafana", "enterprise-keycloak", "enterprise-loki", "enterprise-minio",
  "enterprise-nats", "enterprise-platform-alert-dispatcher", "enterprise-postgres",
  "enterprise-project-router", "enterprise-prometheus", "enterprise-promtail", "enterprise-redis",
  "enterprise-traefik", "enterprise-waf", "mariadb",
].sort());
export const V1_LOCAL_PRIVATE_PRESERVED_LEGACY_CONTAINER_NAMES = Object.freeze(
  V1_LOCAL_PRIVATE_CANONICAL_CONTAINER_NAMES.filter((name) => !V1_LOCAL_PRIVATE_ACTIVE_MANAGED_CONTAINER_NAMES.includes(name)),
);
export const V1_LOCAL_PRIVATE_READY_BUT_DISABLED = Object.freeze([
  "PROVIDER_ADMISSION", "DNS_PUBLICATION", "DAST", "SIGSTORE_PROMOTION",
  "PROVIDER_DOCKER_ACTION_ACTIVATION_SIDECAR", "PROVIDER_DOCKER_ACTION_BROKER",
  "PROVIDER_SOCKETLESS_BACKUP_SCHEDULER",
]);

const HISTORIC_WITH_LEGACY_DISPATCHER = Object.freeze([...V1_LOCAL_PRIVATE_CONTAINER_NAMES, "enterprise-alert-dispatcher"].sort());
const SCHEMA = "platform.v1-local-private-control-receipt/v1";
const AUTHORITY_SCHEMA = "platform.v1-local-private-exact-release-authority/v1";
const ABORT_RECORD_SCHEMA = "platform.v1-local-private-reconciliation-abort-record/v1";
const MAX_BYTES = 128 * 1024;
const SHA256 = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const IMAGE_ID = /^sha256:[a-f0-9]{64}$/;
const BACKUP_TOOL_IMAGE_KEYS = Object.freeze([
  "mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone",
]);
const EVIDENCE_LOGICAL_KEYS = Object.freeze([
  "anniversary", "fiplatform", "matthewdifilippo", "opstudents", "public", "stexor", "stream",
  "workcalendar", "pg-stexor", "pg-keycloak", "mariadb", "minio", "keycloak-config", "confidential",
]);
const LEGACY_UNMANAGED_REASON_BY_CONTAINER = Object.freeze({
  "enterprise-backend": "NO_HOSTED_WORKLOAD_AUTHORITY",
  "enterprise-cadvisor": "COMPOSE_PROFILE_RAW_HOST_METRICS_DISABLED",
  "enterprise-local-dns": "COMPOSE_PROFILE_DNS_DISABLED",
  "enterprise-local-registry": "COMPOSE_PROFILE_LOCAL_RUNTIME_DISABLED",
  "enterprise-node-exporter": "COMPOSE_PROFILE_RAW_HOST_METRICS_DISABLED",
  "enterprise-web": "NO_HOSTED_WORKLOAD_AUTHORITY",
  "enterprise-worker-jobs": "NO_HOSTED_WORKLOAD_AUTHORITY",
  "enterprise-worker-notifications": "NO_HOSTED_WORKLOAD_AUTHORITY",
  "node-account": "NO_HOSTED_WORKLOAD_AUTHORITY",
  "node-opstudents": "NO_HOSTED_WORKLOAD_AUTHORITY",
  "node-ui": "NO_HOSTED_WORKLOAD_AUTHORITY",
  "php-anniversary": "NO_HOSTED_WORKLOAD_AUTHORITY",
  "php-apache": "COMPOSE_PROFILE_LEGACY_SHARED_RUNTIME_DISABLED",
  "php-fiplatform": "NO_HOSTED_WORKLOAD_AUTHORITY",
  "php-matthewdifilippo": "NO_HOSTED_WORKLOAD_AUTHORITY",
  "php-stream": "NO_HOSTED_WORKLOAD_AUTHORITY",
  "php-workcalendar": "NO_HOSTED_WORKLOAD_AUTHORITY",
  phpmyadmin: "COMPOSE_PROFILE_ADMIN_DISABLED",
  phppgadmin: "COMPOSE_PROFILE_ADMIN_DISABLED",
});
const LEGACY_UNMANAGED_CONTAINERS = Object.freeze(V1_LOCAL_PRIVATE_PRESERVED_LEGACY_CONTAINER_NAMES.map((containerName) => Object.freeze({
  containerName,
  reason: LEGACY_UNMANAGED_REASON_BY_CONTAINER[containerName],
  status: "LEGACY_UNMANAGED",
})));
const RUNTIME_IDENTITY_FIELDS = Object.freeze([
  "candidateId", "commit", "deploymentId", "sourceRenderSha256", "tree", "workloadLockSha256",
]);
const RUNTIME_IDENTITY_LABEL_FIELDS = Object.freeze([
  "com.platform.runtime.candidate-id", "com.platform.runtime.commit",
  "com.platform.runtime.deployment-id", "com.platform.runtime.source-render-sha256",
  "com.platform.runtime.tree", "com.platform.runtime.workload-lock-sha256",
]);
const TRANSITION_COMPARABLE_IDENTITY_FIELDS = Object.freeze([
  "configHash", "containerId", "imageId", "imageReference", "runtimeConfigSha256",
]);
const TRANSITION_IDENTITY_FIELDS = Object.freeze([
  ...TRANSITION_COMPARABLE_IDENTITY_FIELDS, "name",
]);
const CONTROLLER_IDENTITY_PROJECTION_LEGACY_19 = "LEGACY_19";
const CONTROLLER_IDENTITY_PROJECTION_FULL_34 = "FULL_34";
const CURRENT_CONTROLLER_IDENTITY_PROJECTION = CONTROLLER_IDENTITY_PROJECTION_FULL_34;
const CONTROLLER_IDENTITY_PROJECTION_BY_SHA256 = new Map([
  ["f60c20fabeaf3f68b2478ebe31018d52d2d9a967a3598c2ac8256bc01dd33f7d", CONTROLLER_IDENTITY_PROJECTION_LEGACY_19],
]);
const PREDECESSOR_RUNTIME_PROVENANCE_FIELDS = Object.freeze([
  "candidateCommit", "candidateTree", "controllerIdentityProjection", "controllerSha256",
  "profile", "releaseRoot", "sourceArchiveSha256",
]);
const ABORTED_RUNTIME_PROFILE_HISTORICAL = "HISTORICAL_V1";
const ABORTED_RUNTIME_PROFILE_CANONICAL = "CANONICAL_RECONCILED_V1";
const TOP_FIELDS = Object.freeze([
  "activatedAtUnixSeconds", "authorityMode", "candidateCommit", "candidateTree", "checkpointSha256",
  "containerRecreate", "controller", "dataMutation", "dockerControlPlane", "dockerMutation",
  "documentId", "externalDependencies", "hostControlMutation", "installReceiptSha256",
  "localArtifactTrust", "mutationModel", "mutationPerformed", "networkIsolation", "providerComponents",
  "readyButDisabled", "releaseRoot", "runtime", "schema", "sourceArchiveSha256", "status", "supervisor",
]);

function invalid(message) { throw new Error(message); }
function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
function hashBytes(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function exactObject(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be one object.`);
  if (stableJson(Object.keys(value).sort()) !== stableJson([...fields].sort())) invalid(`${label} has missing or unexpected fields.`);
  return value;
}
function exactArray(value, expected, label) { if (stableJson(value) !== stableJson(expected)) invalid(`${label} is not the exact closed sequence.`); }
function sha(value, label) { if (typeof value !== "string" || !SHA256.test(value)) invalid(`${label} is not one lowercase SHA-256.`); return value; }
function commit(value, label) { if (typeof value !== "string" || !COMMIT.test(value)) invalid(`${label} is not one full Git object ID.`); return value; }
function runtimeIdentityLabels(identity) {
  return {
    "com.platform.runtime.candidate-id": identity.candidateId,
    "com.platform.runtime.commit": identity.commit,
    "com.platform.runtime.deployment-id": identity.deploymentId,
    "com.platform.runtime.source-render-sha256": identity.sourceRenderSha256,
    "com.platform.runtime.tree": identity.tree,
    "com.platform.runtime.workload-lock-sha256": identity.workloadLockSha256,
  };
}
function serviceForManagedContainer(containerName) {
  if (containerName === "enterprise-broker-auth-bootstrap") return "broker-auth-bootstrap";
  if (containerName === "enterprise-platform-alert-dispatcher") return "platform-alert-dispatcher";
  return containerName.replace(/^enterprise-/, "");
}
function readCanonicalFile(filename, label, maximum = MAX_BYTES) {
  const path = String(filename ?? "").trim();
  if (!path) invalid(`${label} path is required.`);
  let metadata;
  try { metadata = fs.lstatSync(path); } catch { invalid(`${label} is missing.`); }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || metadata.size < 2 || metadata.size > maximum) invalid(`${label} identity/size is invalid.`);
  const raw = fs.readFileSync(path);
  let value;
  try { value = JSON.parse(raw.toString("utf8")); } catch { invalid(`${label} is not strict JSON.`); }
  if (`${stableJson(value)}\n` !== raw.toString("utf8")) invalid(`${label} is not canonical JSON.`);
  return { raw, value };
}

function loadAuthority(filename) {
  const { raw, value } = readCanonicalFile(filename, "V1 exact release authority");
  exactObject(value, [
    "activeManagedContainerNames", "artifacts", "authorityMode", "authorizedDataMutations", "backupToolImages", "candidateCommit",
    "candidateTree", "checkoutProof", "controllerVerificationScope", "disabledComposeServices", "documentId", "evidenceProducer",
    "expectedContainerNames", "legacyNetworkAttachments", "legacyRouteChecks", "legacyUnmanagedContainers", "preservedLegacyContainerNames",
    "recoveryEscrowCertificate", "releaseRoot", "renderEnvironment", "renderSha256", "runtimeIdentity", "schema", "serviceTargets",
    "sourceArchiveSha256", "status",
  ], "V1 exact release authority");
  const withoutId = { ...value }; delete withoutId.documentId;
  if (value.documentId !== hashBytes(stableJson(withoutId)) || value.schema !== AUTHORITY_SCHEMA || value.status !== "AUTHORIZED" || value.authorityMode !== "LOCAL_PRIVATE") invalid("V1 exact release authority identity/status is invalid.");
  commit(value.candidateCommit, "Authority candidate commit"); commit(value.candidateTree, "Authority candidate tree");
  sha(value.sourceArchiveSha256, "Authority source archive"); sha(value.renderSha256, "Authority render");
  if (value.releaseRoot !== `/srv/platform-infrastructure/releases/${value.candidateCommit}-${value.sourceArchiveSha256}`) invalid("Authority release root is not exact.");
  const escrowCertificate = exactObject(value.recoveryEscrowCertificate, ["path", "sha256", "sha256Fingerprint"], "Authority recovery escrow certificate");
  if (escrowCertificate.path !== `${value.releaseRoot}/config/local-private-recovery-escrow-cert.pem`) invalid("Authority recovery escrow certificate path is invalid.");
  sha(escrowCertificate.sha256, "Authority recovery escrow certificate bytes");
  sha(escrowCertificate.sha256Fingerprint, "Authority recovery escrow certificate fingerprint");
  const backupToolImages = exactObject(value.backupToolImages, BACKUP_TOOL_IMAGE_KEYS, "Authority backup tool images");
  for (const name of BACKUP_TOOL_IMAGE_KEYS) {
    const image = exactObject(backupToolImages[name], ["imageId", "imageReference"], `Authority backup tool image ${name}`);
    if (!IMAGE_ID.test(image.imageId) || typeof image.imageReference !== "string" || !/^[^@\s]+@sha256:[a-f0-9]{64}$/.test(image.imageReference)) invalid(`Authority backup tool image ${name} is not immutable.`);
  }
  const producer = exactObject(value.evidenceProducer, [
    "executor", "executorFlags", "forbiddenResticOperations", "hostingerAllowed", "logicalKeys",
    "offsiteRepository", "operations", "path", "recoveryEscrowPrefix", "sha256",
  ], "Authority evidence producer");
  if (producer.executor !== "/usr/bin/python3"
    || stableJson(producer.executorFlags) !== stableJson(["-I"])
    || stableJson(producer.forbiddenResticOperations) !== stableJson(["forget", "prune"])
    || producer.hostingerAllowed !== false
    || stableJson(producer.logicalKeys) !== stableJson(EVIDENCE_LOGICAL_KEYS)
    || producer.offsiteRepository !== "rclone:platform-onedrive:platform-infrastructure/restic"
    || stableJson(producer.operations) !== stableJson(["pre", "post"])
    || producer.path !== value.releaseRoot + "/scripts/v1-local-private-evidence-producer.py"
    || producer.recoveryEscrowPrefix !== "platform-onedrive:platform-infrastructure/key-escrow") invalid("Authority evidence producer contract is invalid.");
  sha(producer.sha256, "Authority evidence producer source");
  const proof = exactObject(value.checkoutProof, ["clean", "githubMainCommit", "githubMainRef", "headCommit", "headTree", "producer", "status", "verifiedAtUnixSeconds"], "Authority checkout proof");
  if (proof.clean !== true || proof.status !== "PASS" || proof.producer !== "CLEAN_CHECKOUT_GITHUB_MAIN_V1" || proof.githubMainRef !== "refs/remotes/github/main" || proof.headCommit !== value.candidateCommit || proof.githubMainCommit !== value.candidateCommit || proof.headTree !== value.candidateTree || !Number.isInteger(proof.verifiedAtUnixSeconds)) invalid("Authority does not prove one clean checkout equal to github/main.");
  if (value.controllerVerificationScope !== "AUTHORITY_ARCHIVE_RELEASE_RENDER_ONLY_NOT_GITHUB") invalid("Authority controller verification scope is invalid.");
  exactArray(value.expectedContainerNames, V1_LOCAL_PRIVATE_CANONICAL_CONTAINER_NAMES, "Authority expected containers");
  exactArray(value.activeManagedContainerNames, V1_LOCAL_PRIVATE_ACTIVE_MANAGED_CONTAINER_NAMES, "Authority active managed containers");
  exactArray(value.preservedLegacyContainerNames, V1_LOCAL_PRIVATE_PRESERVED_LEGACY_CONTAINER_NAMES, "Authority preserved legacy containers");
  exactArray(value.legacyUnmanagedContainers, LEGACY_UNMANAGED_CONTAINERS, "Authority legacy unmanaged containers");
  exactArray(value.disabledComposeServices, ["backup-scheduler", "docker-action-activation-sidecar", "docker-action-broker"], "Authority disabled services");
  const runtimeIdentity = exactObject(value.runtimeIdentity, RUNTIME_IDENTITY_FIELDS, "Authority runtime identity");
  commit(runtimeIdentity.commit, "Authority runtime identity commit");
  commit(runtimeIdentity.tree, "Authority runtime identity tree");
  sha(runtimeIdentity.candidateId, "Authority runtime candidate ID");
  sha(runtimeIdentity.sourceRenderSha256, "Authority runtime source render");
  sha(runtimeIdentity.workloadLockSha256, "Authority runtime workload lock");
  const runtimeSeed = {
    candidateCommit: value.candidateCommit,
    candidateTree: value.candidateTree,
    sourceRenderSha256: runtimeIdentity.sourceRenderSha256,
    workloadLockSha256: runtimeIdentity.workloadLockSha256,
  };
  if (runtimeIdentity.commit !== value.candidateCommit || runtimeIdentity.tree !== value.candidateTree
    || runtimeIdentity.candidateId !== hashBytes(stableJson(runtimeSeed))
    || runtimeIdentity.deploymentId !== `v1-local-private:${runtimeIdentity.candidateId}`) {
    invalid("Authority runtime identity is not derived from candidate/tree/source-render/workload-lock.");
  }
  const artifacts = exactObject(value.artifacts, ["composeWrapper", "controller", "installer", "reconciler", "sudoers", "unit"], "Authority artifacts");
  const artifactPaths = {
    composeWrapper: `${value.releaseRoot}/scripts/compose-vps.sh`,
    controller: "/usr/local/libexec/platform-v1-local-private-control",
    installer: "/usr/local/libexec/platform-v1-brownfield-install-consumer",
    reconciler: "/usr/local/libexec/platform-v1-local-private-reconcile",
    sudoers: "/etc/sudoers.d/platform-v1-local-private-control",
    unit: "/etc/systemd/system/platform-v1-local-private-control.service",
  };
  for (const [name, artifact] of Object.entries(artifacts)) {
    exactObject(artifact, ["path", "sha256"], `Authority ${name} artifact`); sha(artifact.sha256, `Authority ${name} artifact`);
    if (artifact.path !== artifactPaths[name]) invalid(`Authority ${name} artifact path is invalid.`);
  }
  const renderEnvironment = exactObject(value.renderEnvironment, ["path", "sha256"], "Authority render environment");
  if (renderEnvironment.path !== "/var/lib/platform-infrastructure/v1/local-private/exact-compose.env") invalid("Authority render environment path is invalid.");
  sha(renderEnvironment.sha256, "Authority render environment");
  if (!Array.isArray(value.legacyNetworkAttachments) || !value.legacyNetworkAttachments.length || !Array.isArray(value.legacyRouteChecks) || !value.legacyRouteChecks.length || !Array.isArray(value.authorizedDataMutations) || !Array.isArray(value.serviceTargets)) invalid("Authority reconciliation allowances/targets are invalid.");
  exactArray(value.serviceTargets.map((item) => item?.containerName), V1_LOCAL_PRIVATE_ACTIVE_MANAGED_CONTAINER_NAMES, "Authority service target names");
  const expectedRuntimeLabels = runtimeIdentityLabels(runtimeIdentity);
  for (const [index, target] of value.serviceTargets.entries()) {
    exactObject(target, ["configHash", "containerName", "project", "semantic", "service"], `Authority service target ${index}`);
    sha(target.configHash, `Authority service target ${index} config hash`);
    if (target.project !== "platform_infra_vps" || target.service !== serviceForManagedContainer(target.containerName)
      || !target.semantic || typeof target.semantic !== "object" || Array.isArray(target.semantic)) {
      invalid("Authority service target is invalid.");
    }
    const labels = exactObject(target.semantic.runtimeIdentityLabels, RUNTIME_IDENTITY_LABEL_FIELDS, `Authority service target ${index} runtime identity labels`);
    if (stableJson(labels) !== stableJson(expectedRuntimeLabels)) invalid("Authority service target runtime identity labels differ from authority.");
  }
  const attachmentSet = new Set();
  for (const attachment of value.legacyNetworkAttachments) {
    exactObject(attachment, ["aliases", "containerName", "networkName"], "Authority legacy network attachment");
    const key = `${attachment.containerName}\0${attachment.networkName}`;
    if (!V1_LOCAL_PRIVATE_PRESERVED_LEGACY_CONTAINER_NAMES.includes(attachment.containerName) || typeof attachment.networkName !== "string" || !attachment.networkName || !Array.isArray(attachment.aliases) || attachmentSet.has(key)) invalid("Authority legacy network attachment is invalid.");
    attachmentSet.add(key);
  }
  const routeNames = new Set();
  for (const route of value.legacyRouteChecks) {
    exactObject(route, ["containerName", "expectedStatus", "name", "url"], "Authority legacy route check");
    if (!V1_LOCAL_PRIVATE_PRESERVED_LEGACY_CONTAINER_NAMES.includes(route.containerName) || typeof route.name !== "string" || !route.name || routeNames.has(route.name) || !Number.isInteger(route.expectedStatus) || route.expectedStatus < 200 || route.expectedStatus > 399 || typeof route.url !== "string" || !/^https?:\/\//.test(route.url)) invalid("Authority legacy route check is invalid.");
    routeNames.add(route.name);
  }
  const mutationSet = new Set();
  for (const mutation of value.authorizedDataMutations) {
    exactObject(mutation, ["id", "service", "target", "type"], "Authority data mutation");
    if (typeof mutation.id !== "string" || !mutation.id || mutationSet.has(mutation.id) || typeof mutation.target !== "string" || !mutation.target.startsWith("/")) invalid("Authority data mutation is invalid.");
    mutationSet.add(mutation.id);
  }
  return { sha256: hashBytes(raw), value };
}

function verifyPorts(networkIsolation) {
  exactObject(networkIsolation, ["policy", "publishedPorts", "status"], "Network isolation");
  if (networkIsolation.policy !== "EDGE_PUBLISHED_PORT_ALLOWLIST" || networkIsolation.status !== "PASS" || !Array.isArray(networkIsolation.publishedPorts)) invalid("Network isolation is invalid.");
  const signature = new Set();
  for (const port of networkIsolation.publishedPorts) {
    exactObject(port, ["containerName", "containerPort", "hostIp", "hostPort", "protocol"], "Published port");
    signature.add(`${port.containerName}|${port.hostIp}|${port.hostPort}|${port.containerPort}|${port.protocol}`);
  }
  for (const entry of ["enterprise-waf|0.0.0.0|80|8080|tcp", "enterprise-waf|0.0.0.0|443|8443|tcp", "enterprise-local-registry|127.0.0.1|5000|5000|tcp"]) if (!signature.has(entry)) invalid("Published edge port bindings are incomplete.");
  if (networkIsolation.publishedPorts.some((port) => !new Set(["enterprise-waf", "enterprise-local-dns", "enterprise-local-registry"]).has(port.containerName))) invalid("A non-edge workload publishes a host port.");
}

function verifyRuntime(runtime, reconciled) {
  exactObject(runtime, ["containerCount", "containers", "daemon", "exitedCount", "rawDockerAuthority", "runningCount"], "Runtime");
  if (!Array.isArray(runtime.containers)) invalid("Runtime containers are invalid.");
  const names = runtime.containers.map((item) => item?.name);
  const historic = [V1_LOCAL_PRIVATE_CONTAINER_NAMES, HISTORIC_WITH_LEGACY_DISPATCHER].some((profile) => stableJson(profile) === stableJson(names));
  if ((reconciled && stableJson(names) !== stableJson(V1_LOCAL_PRIVATE_CANONICAL_CONTAINER_NAMES)) || (!reconciled && !historic)) invalid("Runtime names are not one closed V1 form.");
  const expectedExited = reconciled ? 2 : 1;
  if (runtime.containerCount !== names.length || runtime.runningCount !== names.length - expectedExited || runtime.exitedCount !== expectedExited) invalid("Runtime cardinality is false.");
  exactObject(runtime.daemon, ["dockerRootDir", "id", "name", "serverVersion"], "Docker daemon");
  const noHealth = new Set(["enterprise-local-dns", "enterprise-local-registry", "phpmyadmin"]);
  const ids = new Set();
  for (const item of runtime.containers) {
    exactObject(item, reconciled
      ? ["configHash", "containerId", "exitCode", "health", "imageAvailability", "imageId", "imageReference", "name", "networkMembership", "project", "runtimeConfigSha256", "semanticSha256", "service", "state"]
      : ["configHash", "containerId", "exitCode", "health", "imageAvailability", "imageId", "name", "project", "service", "state"], `Runtime container ${item?.name}`);
    sha(item.configHash, `${item.name} config hash`); sha(item.containerId, `${item.name} container ID`);
    if (!IMAGE_ID.test(item.imageId) || ids.has(item.containerId)) invalid(`${item.name} immutable identity is invalid.`);
    ids.add(item.containerId);
    if (reconciled) {
      sha(item.runtimeConfigSha256, `${item.name} runtime config`); sha(item.semanticSha256, `${item.name} semantic config`);
      if (typeof item.imageReference !== "string" || !item.imageReference || !Array.isArray(item.networkMembership) || item.imageAvailability !== "LOCAL_IMAGE_STORE") invalid(`${item.name} reconciled semantic evidence is invalid.`);
    }
    if (item.name === "phppgadmin") {
      if (item.state !== "exited") invalid("phppgadmin is not the historical exited admin container.");
    } else if (item.name === "enterprise-broker-auth-bootstrap") {
      if (item.state !== "exited" || item.exitCode !== 0 || item.health !== "none") invalid("Broker auth bootstrap is not completed exit-0.");
    } else if (item.state !== "running" || (noHealth.has(item.name) ? item.health !== "none" : item.health !== "healthy")) invalid(`${item.name} state/health is invalid.`);
  }
  if (reconciled) {
    const raw = exactObject(runtime.rawDockerAuthority, ["mode", "owners", "status"], "Raw Docker authority");
    if (raw.mode !== "NONE" || raw.status !== "PASS" || !Array.isArray(raw.owners) || raw.owners.length !== 0) invalid("Reconciled runtime retains raw Docker authority.");
  } else {
    const raw = exactObject(runtime.rawDockerAuthority, ["containerId", "name", "readOnly", "source", "status", "target"], "Raw Docker authority");
    if (raw.name !== "enterprise-backup-scheduler" || raw.readOnly !== false || raw.status !== "PASS") invalid("Historical raw Docker authority is not the legacy scheduler.");
  }
}

function transitionIdentity(value, label) {
  exactObject(value, TRANSITION_IDENTITY_FIELDS, label);
  sha(value.configHash, `${label} config`); sha(value.containerId, `${label} container`); sha(value.runtimeConfigSha256, `${label} runtime config`);
  if (!IMAGE_ID.test(value.imageId) || typeof value.imageReference !== "string" || !value.imageReference || typeof value.name !== "string" || !value.name) invalid(`${label} is invalid.`);
  return value;
}

function transitionIdentityMatchesAcrossDomains(value, runtimeRecord) {
  const transition = transitionIdentity(value, "Cross-domain transition identity");
  const runtimeIdentity = transitionIdentity({
    configHash: runtimeRecord.configHash,
    containerId: runtimeRecord.containerId,
    imageId: runtimeRecord.imageId,
    imageReference: runtimeRecord.imageReference,
    name: runtimeRecord.name,
    runtimeConfigSha256: runtimeRecord.runtimeConfigSha256,
  }, "Runtime transition identity");
  return transition.name === runtimeIdentity.name
    && TRANSITION_COMPARABLE_IDENTITY_FIELDS.every((field) => transition[field] === runtimeIdentity[field]);
}

function transitionStatus(previous, current) {
  if (current === null) {
    if (previous === null) invalid("Service transition has neither a previous nor current identity.");
    return "REMOVED";
  }
  if (previous === null) return "CREATED";
  if (previous.name !== current.name) return "REPLACED";
  return TRANSITION_COMPARABLE_IDENTITY_FIELDS.every((field) => previous[field] === current[field])
    ? "RETAINED"
    : "RECREATED";
}

function verifyExternal(external, runtime, authority, projectionTransition = null) {
  exactObject(external, [
    "authority", "beganAtUnixSeconds", "containerRecreate", "controllerDockerMutation", "dataMutation",
    "dataMutations", "dataMutationsSha256", "externalDockerMutation", "legacyNetworkAttachments",
    "legacyNetworkAttachmentsSha256", "legacyUnmanagedContainers", "previousReceiptDocumentId", "releaseAuthorityDocumentId",
    "releaseAuthoritySha256", "runtimeEvidenceSha256", "runtimeIdentity", "serviceTransitions", "serviceTransitionsSha256", "status",
  ], "External reconciliation");
  if (external.authority !== "ROOT_OPERATOR_EXPLICIT_V1_RECONCILIATION" || external.status !== "SEALED" || external.controllerDockerMutation !== false || !Number.isInteger(external.beganAtUnixSeconds)) invalid("External reconciliation authority is invalid.");
  if (external.releaseAuthorityDocumentId !== authority.value.documentId || external.releaseAuthoritySha256 !== authority.sha256) invalid("External reconciliation is not bound to the supplied exact release authority.");
  if (stableJson(external.legacyUnmanagedContainers) !== stableJson(authority.value.legacyUnmanagedContainers)
    || stableJson(external.runtimeIdentity) !== stableJson(authority.value.runtimeIdentity)) {
    invalid("External reconciliation scope/runtime identity differs from exact release authority.");
  }
  for (const key of ["dataMutationsSha256", "legacyNetworkAttachmentsSha256", "previousReceiptDocumentId", "releaseAuthorityDocumentId", "releaseAuthoritySha256", "runtimeEvidenceSha256", "serviceTransitionsSha256"]) sha(external[key], `External ${key}`);
  if (!Array.isArray(external.dataMutations) || external.dataMutationsSha256 !== hashBytes(stableJson(external.dataMutations))) invalid("External data mutation evidence digest differs.");
  const allowedMutations = new Set(authority.value.authorizedDataMutations.map((item) => item.id));
  for (const item of external.dataMutations) {
    exactObject(item, ["authorityId", "evidencePath", "evidenceSha256"], "Data mutation evidence"); sha(item.evidenceSha256, "Data mutation evidence");
    const expectedPath = `/var/lib/platform-infrastructure/v1/local-private/data-mutation-evidence/${external.releaseAuthorityDocumentId}-${item.authorityId}-${item.evidenceSha256}.json`;
    if (!allowedMutations.has(item.authorityId) || item.evidencePath !== expectedPath) invalid("Data mutation exceeds exact release authority or its immutable evidence path.");
  }
  if (external.dataMutation !== (external.dataMutations.length > 0)) invalid("Data mutation boolean is false.");
  if (!Array.isArray(external.legacyNetworkAttachments) || external.legacyNetworkAttachmentsSha256 !== hashBytes(stableJson(external.legacyNetworkAttachments))) invalid("Legacy network attachment evidence digest differs.");
  const allowedAttachments = new Set(authority.value.legacyNetworkAttachments.map(stableJson));
  for (const item of external.legacyNetworkAttachments) if (!allowedAttachments.has(stableJson(item))) invalid("Legacy network attachment exceeds exact release authority.");
  if (!Array.isArray(external.serviceTransitions) || ![V1_LOCAL_PRIVATE_CANONICAL_CONTAINER_NAMES.length, V1_LOCAL_PRIVATE_CANONICAL_CONTAINER_NAMES.length + 1].includes(external.serviceTransitions.length)) invalid("Service transition cardinality is invalid.");
  const currentRuntime = new Map(runtime.containers.map((item) => [item.name, item]));
  const managedTargets = new Map(authority.value.serviceTargets.map((item) => [item.containerName, item]));
  const currentNames = [];
  const removedNames = [];
  let containerRecreate = false;
  if (projectionTransition !== null && stableJson(projectionTransition) !== stableJson({ from: CONTROLLER_IDENTITY_PROJECTION_LEGACY_19, to: CONTROLLER_IDENTITY_PROJECTION_FULL_34 })) {
    invalid("External reconciliation runtime identity projection transition is unsupported.");
  }
  for (const raw of external.serviceTransitions) {
    const transition = exactObject(raw, ["current", "previous", "service", "status"], "Service transition");
    const current = transition.current === null ? null : transitionIdentity(transition.current, "Current transition identity");
    const previous = transition.previous === null ? null : transitionIdentity(transition.previous, "Previous transition identity");
    if (current) {
      const runtimeItem = currentRuntime.get(current.name);
      const exactRuntimeIdentity = runtimeItem && transitionIdentityMatchesAcrossDomains(current, runtimeItem);
      const projectedCommonIdentity = projectionTransition !== null && runtimeItem
        && current.name === runtimeItem.name
        && TRANSITION_COMPARABLE_IDENTITY_FIELDS
          .filter((field) => field !== "runtimeConfigSha256")
          .every((field) => current[field] === runtimeItem[field]);
      if ((!exactRuntimeIdentity && !projectedCommonIdentity) || transition.service !== runtimeItem?.service) invalid("Transition current identity differs from runtime.");
      const managedTarget = managedTargets.get(current.name);
      if (managedTarget && (runtimeItem.configHash !== managedTarget.configHash || runtimeItem.project !== managedTarget.project
        || runtimeItem.service !== managedTarget.service)) {
        invalid("Managed runtime service differs from its exact authority target.");
      }
      currentNames.push(current.name);
    }
    if (previous) {
      const allowedPreviousNames = new Set(current ? [current.name] : ["enterprise-backup-scheduler"]);
      if (current?.name === "enterprise-platform-alert-dispatcher") allowedPreviousNames.add("enterprise-alert-dispatcher");
      if (!allowedPreviousNames.has(previous.name)) invalid("Transition previous identity is not a declared predecessor.");
    }
    const expectedStatus = transitionStatus(previous, current);
    if (transition.status !== expectedStatus) invalid("Service transition status is false.");
    if (["CREATED", "REMOVED", "REPLACED", "RECREATED"].includes(expectedStatus)) containerRecreate = true;
    if (expectedStatus === "REMOVED") removedNames.push(previous.name);
    if (current && V1_LOCAL_PRIVATE_PRESERVED_LEGACY_CONTAINER_NAMES.includes(current.name) && expectedStatus !== "RETAINED") invalid("A preserved legacy workload was recreated or changed.");
  }
  exactArray([...currentNames].sort(), V1_LOCAL_PRIVATE_CANONICAL_CONTAINER_NAMES, "Transition current names");
  if (![[], ["enterprise-backup-scheduler"]].some((value) => stableJson(value) === stableJson(removedNames))) invalid("Transition removed names are invalid.");
  if (external.serviceTransitionsSha256 !== hashBytes(stableJson(external.serviceTransitions))) invalid("Transition digest differs.");
  const dockerMutation = containerRecreate || external.legacyNetworkAttachments.length > 0;
  if (external.containerRecreate !== containerRecreate || external.externalDockerMutation !== dockerMutation) invalid("External Docker mutation truth is false.");
}

function physicalStatePath(logicalPath, stateRoot) {
  if (stateRoot === undefined) return logicalPath;
  if (typeof stateRoot !== "string" || !stateRoot.startsWith("/") || stateRoot.endsWith("/") || logicalPath.includes("\0")) {
    invalid("Offline state root is invalid.");
  }
  return `${stateRoot}${logicalPath}`;
}

function verifyAborted(binding, authority, stateRoot, abortRecordFile) {
  exactObject(binding, [
    "authorityDocumentId", "authoritySha256", "completedAtUnixSeconds", "journalSha256", "recordPath",
    "recordSha256", "residualDataMutations", "residualDataMutationsSha256", "schema", "status", "transactionId",
  ], "Aborted authorized reconciliation");
  for (const key of ["authorityDocumentId", "authoritySha256", "journalSha256", "recordSha256", "residualDataMutationsSha256", "transactionId"]) sha(binding[key], `Aborted reconciliation ${key}`);
  if (binding.schema !== ABORT_RECORD_SCHEMA
    || !Number.isInteger(binding.completedAtUnixSeconds)
    || binding.completedAtUnixSeconds < 1_700_000_000
    || binding.authorityDocumentId !== authority.value.documentId
    || binding.authoritySha256 !== authority.sha256
    || !Array.isArray(binding.residualDataMutations)
    || binding.residualDataMutationsSha256 !== hashBytes(stableJson(binding.residualDataMutations))
    || binding.status !== (binding.residualDataMutations.length ? "ABORTED_WITH_RESIDUAL_DATA_MUTATIONS" : "ABORTED_NO_DATA_MUTATION")) {
    invalid("Aborted reconciliation authority/status/mutation binding is invalid.");
  }
  const allowed = new Set(authority.value.authorizedDataMutations.map((item) => item.id));
  const seen = new Set();
  for (const item of binding.residualDataMutations) {
    exactObject(item, ["authorityId", "evidencePath", "evidenceSha256"], "Aborted residual data mutation");
    sha(item.evidenceSha256, "Aborted residual data mutation evidence");
    const expectedPath = `/var/lib/platform-infrastructure/v1/local-private/data-mutation-evidence/${binding.authorityDocumentId}-${item.authorityId}-${item.evidenceSha256}.json`;
    if (!allowed.has(item.authorityId) || seen.has(item.authorityId) || item.evidencePath !== expectedPath) invalid("Aborted residual data mutation exceeds its exact authority or fixed evidence path.");
    const evidence = readCanonicalFile(physicalStatePath(item.evidencePath, stateRoot), `Aborted residual data mutation ${item.authorityId} evidence`);
    if (hashBytes(evidence.raw) !== item.evidenceSha256) invalid("Aborted residual data mutation evidence digest differs.");
    seen.add(item.authorityId);
  }
  if (stableJson(binding.residualDataMutations) !== stableJson([...binding.residualDataMutations].sort((a, b) => a.authorityId.localeCompare(b.authorityId)))) invalid("Aborted residual data mutations are not sorted.");
  const record = { ...binding };
  delete record.recordPath;
  delete record.recordSha256;
  const recordBytes = Buffer.from(`${stableJson(record)}\n`);
  if (hashBytes(recordBytes) !== binding.recordSha256
    || binding.recordPath !== `/var/lib/platform-infrastructure/v1/local-private/aborted-reconciliations/${binding.transactionId}-${binding.recordSha256}.json`) {
    invalid("Aborted reconciliation immutable record binding is invalid.");
  }
  if (stateRoot !== undefined && abortRecordFile !== undefined) invalid("Use either --abortRecordFile or an offline state root, not both.");
  const selectedRecordFile = abortRecordFile ?? physicalStatePath(binding.recordPath, stateRoot);
  const archived = readCanonicalFile(selectedRecordFile, "Immutable reconciliation abort record");
  if (!archived.raw.equals(recordBytes)) invalid("Immutable reconciliation abort record bytes differ from the receipt.");
  return binding;
}

function controllerProjectionRegistry(currentControllerSha256) {
  sha(currentControllerSha256, "Current authority controller");
  const configured = CONTROLLER_IDENTITY_PROJECTION_BY_SHA256.get(currentControllerSha256);
  if (configured && configured !== CURRENT_CONTROLLER_IDENTITY_PROJECTION) {
    invalid("Current controller semantic identity projection conflicts with registered history.");
  }
  return new Map([
    ...CONTROLLER_IDENTITY_PROJECTION_BY_SHA256,
    [currentControllerSha256, CURRENT_CONTROLLER_IDENTITY_PROJECTION],
  ]);
}

function verifyPredecessorRuntimeProvenance(receipt, currentAuthority, runtimeAuthority) {
  const provenance = exactObject(
    receipt.predecessorRuntimeProvenance,
    PREDECESSOR_RUNTIME_PROVENANCE_FIELDS,
    "Predecessor runtime provenance",
  );
  commit(provenance.candidateCommit, "Predecessor runtime candidate commit");
  commit(provenance.candidateTree, "Predecessor runtime candidate tree");
  sha(provenance.sourceArchiveSha256, "Predecessor runtime source archive");
  sha(provenance.controllerSha256, "Predecessor runtime controller");
  if (provenance.releaseRoot !== `/srv/platform-infrastructure/releases/${provenance.candidateCommit}-${provenance.sourceArchiveSha256}`) {
    invalid("Predecessor runtime release binding is invalid.");
  }
  const registry = controllerProjectionRegistry(currentAuthority.value.artifacts.controller.sha256);
  const sourceProjection = registry.get(provenance.controllerSha256);
  if (!sourceProjection || sourceProjection !== provenance.controllerIdentityProjection) {
    invalid("Predecessor runtime controller projection is unregistered.");
  }
  const projectionTransition = sourceProjection === CURRENT_CONTROLLER_IDENTITY_PROJECTION
    ? null
    : { from: sourceProjection, to: CURRENT_CONTROLLER_IDENTITY_PROJECTION };
  if (projectionTransition !== null && stableJson(projectionTransition) !== stableJson({ from: CONTROLLER_IDENTITY_PROJECTION_LEGACY_19, to: CONTROLLER_IDENTITY_PROJECTION_FULL_34 })) {
    invalid("Predecessor-to-current runtime identity projection transition is unsupported.");
  }
  const names = receipt.runtime.containers.map((item) => item.name);
  if (receipt.externalAuthorizedReconciliation) {
    if (provenance.profile !== ABORTED_RUNTIME_PROFILE_CANONICAL
      || stableJson(names) !== stableJson(V1_LOCAL_PRIVATE_CANONICAL_CONTAINER_NAMES)
      || !runtimeAuthority) {
      invalid("Canonical predecessor runtime provenance profile is invalid.");
    }
    const external = receipt.externalAuthorizedReconciliation;
    const authority = runtimeAuthority.value;
    if (runtimeAuthority.sha256 !== external.releaseAuthoritySha256
      || authority.documentId !== external.releaseAuthorityDocumentId
      || authority.candidateCommit !== provenance.candidateCommit
      || authority.candidateTree !== provenance.candidateTree
      || authority.sourceArchiveSha256 !== provenance.sourceArchiveSha256
      || authority.releaseRoot !== provenance.releaseRoot
      || authority.artifacts.controller.sha256 !== provenance.controllerSha256
      || stableJson(authority.runtimeIdentity) !== stableJson(external.runtimeIdentity)
      || external.runtimeIdentity.commit !== provenance.candidateCommit
      || external.runtimeIdentity.tree !== provenance.candidateTree) {
      invalid("Canonical predecessor runtime provenance differs from its exact release authority.");
    }
  } else if (provenance.profile !== ABORTED_RUNTIME_PROFILE_HISTORICAL
    || ![V1_LOCAL_PRIVATE_CONTAINER_NAMES, HISTORIC_WITH_LEGACY_DISPATCHER]
      .some((profile) => stableJson(profile) === stableJson(names))) {
    invalid("Historical predecessor runtime provenance profile is invalid.");
  }
  return { projectionTransition, recoveryCandidateCommit: provenance.candidateCommit };
}

function verifyRecovery(receipt, reconciled, recoveryCandidateCommit = receipt.candidateCommit) {
  const trust = exactObject(receipt.localArtifactTrust, ["mode", "schedulerRecovery", "status", "subjects"], "Local artifact trust");
  if (trust.mode !== "LOCAL_DOCKER_IMMUTABLE_IMAGE_ID" || trust.status !== "PASS") invalid("Local artifact trust status is invalid.");
  const subjects = receipt.runtime.containers.map(({ configHash, containerId, imageAvailability, imageId, name }) => ({ configHash, containerId, imageAvailability, imageId, name }));
  exactArray(trust.subjects, subjects, "Local artifact subjects");
  const recovery = exactObject(trust.schedulerRecovery, ["archiveFormat", "configDigest", "configHash", "containerId", "containerName", "exportLabels", "exportPath", "exportSha256", "exportSizeBytes", "imageIndexDigest", "imageIndexPath", "imageManifestDigest", "manifestConfig", "recoveryImageId", "recoveryTag", "runningImageId", "status"], "Scheduler recovery");
  if (recovery.containerName !== "enterprise-backup-scheduler" || recovery.status !== "RECOVERY_IMAGE_EXPORT_BOUND" || !IMAGE_ID.test(recovery.runningImageId) || !IMAGE_ID.test(recovery.recoveryImageId) || recovery.runningImageId === recovery.recoveryImageId) invalid("Scheduler recovery identity is invalid.");
  sha(recovery.configHash, "Scheduler recovery config"); sha(recovery.containerId, "Scheduler recovery container"); sha(recovery.exportSha256, "Scheduler recovery export");
  const labels = exactObject(recovery.exportLabels, ["com.platform.v1.local-private.candidate-commit", "com.platform.v1.local-private.scheduler-config-hash", "com.platform.v1.local-private.scheduler-container-id", "com.platform.v1.local-private.scheduler-running-image-id"], "Scheduler recovery labels");
  commit(recoveryCandidateCommit, "Scheduler recovery provenance candidate");
  if (labels["com.platform.v1.local-private.candidate-commit"] !== recoveryCandidateCommit || labels["com.platform.v1.local-private.scheduler-config-hash"] !== recovery.configHash || labels["com.platform.v1.local-private.scheduler-container-id"] !== recovery.containerId || labels["com.platform.v1.local-private.scheduler-running-image-id"] !== recovery.runningImageId) invalid("Scheduler recovery labels are not runtime-provenance-bound.");
  if (recovery.recoveryTag !== `platform/v1-scheduler-recovery:${recoveryCandidateCommit}`) invalid("Scheduler recovery tag differs from runtime provenance.");
  if (!reconciled) {
    const live = receipt.runtime.containers.find((item) => item.name === "enterprise-backup-scheduler");
    if (!live || live.containerId !== recovery.containerId || live.configHash !== recovery.configHash || live.imageId !== recovery.runningImageId) invalid("Historical scheduler recovery is not runtime-bound.");
  } else {
    const removed = receipt.externalAuthorizedReconciliation.serviceTransitions.find((item) => item.status === "REMOVED" && item.previous?.name === "enterprise-backup-scheduler");
    if (removed && (removed.previous.containerId !== recovery.containerId || removed.previous.configHash !== recovery.configHash || removed.previous.imageId !== recovery.runningImageId)) invalid("Removed scheduler recovery differs from transition evidence.");
  }
}

export function verifyV1LocalPrivateControlReceipt(options) {
  const { value: receipt } = readCanonicalFile(options.file, "V1 LOCAL_PRIVATE receipt");
  const reconciled = receipt?.schema === SCHEMA && Object.hasOwn(receipt, "externalAuthorizedReconciliation");
  const aborted = receipt?.schema === SCHEMA && Object.hasOwn(receipt, "abortedAuthorizedReconciliation");
  const hasPredecessorProvenance = receipt?.schema === SCHEMA && Object.hasOwn(receipt, "predecessorRuntimeProvenance");
  if (receipt?.schema !== SCHEMA) invalid("V1 LOCAL_PRIVATE receipt schema is invalid.");
  exactObject(receipt, [
    ...TOP_FIELDS,
    ...(reconciled ? ["externalAuthorizedReconciliation"] : []),
    ...(aborted ? ["abortedAuthorizedReconciliation"] : []),
    ...(hasPredecessorProvenance ? ["predecessorRuntimeProvenance"] : []),
  ], "V1 LOCAL_PRIVATE receipt");
  if (hasPredecessorProvenance && !aborted) invalid("Predecessor runtime provenance is valid only for an aborted reconciliation.");
  if (options.stateRoot !== undefined && !aborted) invalid("An offline state root is valid only for an aborted receipt.");
  if (options.abortRecordFile !== undefined && !aborted) invalid("An abort record file is valid only for an aborted receipt.");
  const authority = options.authorityFile ? loadAuthority(options.authorityFile) : null;
  if ((reconciled || aborted) && !authority) invalid("A reconciled or aborted V1 receipt requires --authorityFile.");
  const expected = authority?.value ?? { candidateCommit: options.candidateCommit, candidateTree: options.candidateTree, sourceArchiveSha256: options.sourceArchiveSha256, releaseRoot: `/srv/platform-infrastructure/releases/${options.candidateCommit}-${options.sourceArchiveSha256}` };
  commit(expected.candidateCommit, "Expected candidate commit"); commit(expected.candidateTree, "Expected candidate tree"); sha(expected.sourceArchiveSha256, "Expected source archive");
  if (receipt.candidateCommit !== expected.candidateCommit || receipt.candidateTree !== expected.candidateTree || receipt.sourceArchiveSha256 !== expected.sourceArchiveSha256 || receipt.releaseRoot !== expected.releaseRoot) invalid("Receipt release binding differs from authority.");
  if (receipt.status !== "ACTIVE" || receipt.authorityMode !== "LOCAL_PRIVATE" || receipt.hostControlMutation !== true || receipt.mutationPerformed !== true) invalid("Receipt status/mutation boundary is invalid.");
  if (!Number.isInteger(receipt.activatedAtUnixSeconds)) invalid("Receipt activation time is invalid.");
  sha(receipt.checkpointSha256, "Receipt checkpoint"); sha(receipt.installReceiptSha256, "Receipt install evidence");
  const controlPlane = exactObject(receipt.dockerControlPlane, ["mode", "providerBrokerStatus", "service", "status"], "Docker control plane");
  if (controlPlane.mode !== "LOCAL_ROOT_SYSTEMD_SUPERVISOR" || controlPlane.providerBrokerStatus !== "READY_BUT_DISABLED" || controlPlane.service !== "platform-v1-local-private-control.service" || controlPlane.status !== "ACTIVE") invalid("Docker control plane is invalid.");
  const authorityBoundController = Boolean(authority);
  exactObject(receipt.controller, authorityBoundController
    ? ["installedPath", "sha256", "sudoersPath", "sudoersSha256", "unitPath", "unitSha256"]
    : ["installedPath", "sha256", "unitPath", "unitSha256"], "Controller identity");
  if (receipt.controller.installedPath !== "/usr/local/libexec/platform-v1-local-private-control" || receipt.controller.unitPath !== "/etc/systemd/system/platform-v1-local-private-control.service") invalid("Controller installed paths are invalid.");
  const controllerSha = authority?.value.artifacts.controller.sha256 ?? options.controllerSha256;
  const unitSha = authority?.value.artifacts.unit.sha256 ?? options.unitSha256;
  if (receipt.controller.sha256 !== sha(controllerSha, "Expected controller") || receipt.controller.unitSha256 !== sha(unitSha, "Expected unit")) invalid("Receipt controller/unit bytes differ from authority.");
  if (authorityBoundController
    && (receipt.controller.sudoersPath !== "/etc/sudoers.d/platform-v1-local-private-control"
      || receipt.controller.sudoersSha256 !== sha(authority.value.artifacts.sudoers.sha256, "Expected sudoers"))) {
    invalid("Receipt sudoers bytes differ from authority.");
  }
  exactArray(receipt.readyButDisabled, V1_LOCAL_PRIVATE_READY_BUT_DISABLED, "READY_BUT_DISABLED");
  exactArray(receipt.providerComponents, [
    { name: "PROVIDER_DOCKER_ACTION_ACTIVATION_SIDECAR", status: "READY_BUT_DISABLED" },
    { name: "PROVIDER_DOCKER_ACTION_BROKER", status: "READY_BUT_DISABLED" },
    { name: "PROVIDER_SOCKETLESS_BACKUP_SCHEDULER", status: "READY_BUT_DISABLED" },
  ], "Provider components");
  exactArray(receipt.externalDependencies, [
    { name: "HOSTINGER", status: "NOT_REQUIRED" }, { name: "CLOUDFLARE", status: "NOT_REQUIRED" },
    { name: "PUBLIC_DNS", status: "READY_BUT_DISABLED" }, { name: "EXTERNAL_DAST", status: "READY_BUT_DISABLED" },
    { name: "SIGSTORE_PROMOTION", status: "READY_BUT_DISABLED" }, { name: "PUBLIC_PROVIDER", status: "READY_BUT_DISABLED" },
  ], "External dependencies");
  verifyRuntime(receipt.runtime, reconciled);
  let runtimeAuthority = authority;
  const externalUsesCurrentAuthority = reconciled
    && receipt.externalAuthorizedReconciliation.releaseAuthorityDocumentId === authority?.value.documentId
    && receipt.externalAuthorizedReconciliation.releaseAuthoritySha256 === authority?.sha256;
  if (reconciled && !externalUsesCurrentAuthority) {
    if (!aborted || !hasPredecessorProvenance || !options.predecessorAuthorityFile) {
      invalid("A mixed-generation aborted receipt requires --predecessorAuthorityFile.");
    }
    runtimeAuthority = loadAuthority(options.predecessorAuthorityFile);
  } else if (options.predecessorAuthorityFile) {
    if (!aborted || !hasPredecessorProvenance || !reconciled) {
      invalid("A predecessor authority file is valid only for an aborted reconciled receipt.");
    }
    const suppliedRuntimeAuthority = loadAuthority(options.predecessorAuthorityFile);
    if (suppliedRuntimeAuthority.sha256 !== authority.sha256
      || suppliedRuntimeAuthority.value.documentId !== authority.value.documentId) {
      invalid("Same-generation predecessor authority bytes differ from current authority.");
    }
    runtimeAuthority = suppliedRuntimeAuthority;
  }
  let projectionTransition = null;
  let recoveryCandidateCommit = receipt.candidateCommit;
  if (hasPredecessorProvenance) {
    const verifiedProvenance = verifyPredecessorRuntimeProvenance(receipt, authority, runtimeAuthority);
    projectionTransition = verifiedProvenance.projectionTransition;
    recoveryCandidateCommit = verifiedProvenance.recoveryCandidateCommit;
  }
  if (reconciled) {
    verifyExternal(receipt.externalAuthorizedReconciliation, receipt.runtime, runtimeAuthority, projectionTransition);
    if (receipt.dockerMutation !== receipt.externalAuthorizedReconciliation.externalDockerMutation || receipt.containerRecreate !== receipt.externalAuthorizedReconciliation.containerRecreate) invalid("Reconciled receipt Docker mutation truth differs from transaction evidence.");
  } else if (receipt.dockerMutation !== false || receipt.containerRecreate !== false) invalid("Historical receipt Docker mutation truth is invalid.");
  let residualDataMutation = false;
  if (aborted) {
    residualDataMutation = verifyAborted(
      receipt.abortedAuthorizedReconciliation, authority, options.stateRoot, options.abortRecordFile,
    ).residualDataMutations.length > 0;
    if (receipt.mutationModel !== "ABORTED_EXTERNAL_AUTHORIZED_RECONCILIATION") invalid("Aborted receipt mutation model is invalid.");
  } else if (receipt.mutationModel !== (reconciled ? "EXTERNAL_AUTHORIZED_RECONCILIATION" : "ADDITIVE_ADOPTION")) invalid("Receipt mutation model is invalid.");
  const expectedDataMutation = (reconciled && receipt.externalAuthorizedReconciliation.dataMutation) || residualDataMutation;
  if (receipt.dataMutation !== expectedDataMutation) invalid("Receipt data mutation truth differs from sealed or residual evidence.");
  verifyPorts(receipt.networkIsolation); verifyRecovery(receipt, reconciled, recoveryCandidateCommit);
  exactObject(receipt.supervisor, ["active", "enabled", "service", "status", "type"], "Supervisor");
  if (receipt.supervisor.active !== true || receipt.supervisor.enabled !== true || receipt.supervisor.status !== "ACTIVE" || receipt.supervisor.service !== "platform-v1-local-private-control.service" || receipt.supervisor.type !== "ROOT_SYSTEMD_NOTIFY") invalid("Supervisor is not ACTIVE.");
  const copy = { ...receipt }; delete copy.documentId;
  if (receipt.documentId !== hashBytes(stableJson(copy))) invalid("Receipt documentId is invalid.");
  return Object.freeze(receipt);
}

function options(args) {
  if (args[0] !== "verify") invalid("Usage: v1-local-private-control-receipt.mjs verify --file FILE [--authorityFile FILE [--predecessorAuthorityFile FILE] [--abortRecordFile FILE] | historical bindings]");
  const allowed = new Set(["file", "authorityFile", "predecessorAuthorityFile", "abortRecordFile", "candidateCommit", "candidateTree", "sourceArchiveSha256", "controllerSha256", "unitSha256"]);
  const result = {};
  for (let index = 1; index < args.length; index += 2) {
    const flag = args[index]; const value = args[index + 1];
    if (!flag?.startsWith("--") || value === undefined || value.startsWith("--")) invalid("V1 receipt options must be value-bearing.");
    const key = flag.slice(2);
    if (!allowed.has(key) || Object.hasOwn(result, key)) invalid(`Unknown or duplicate option ${flag}.`);
    result[key] = value;
  }
  if (!result.file) invalid("V1 receipt is missing --file.");
  if (!result.authorityFile && ["candidateCommit", "candidateTree", "sourceArchiveSha256", "controllerSha256", "unitSha256"].some((key) => !result[key])) invalid("Historical verification requires all explicit release/controller bindings.");
  return result;
}

function main() { verifyV1LocalPrivateControlReceipt(options(process.argv.slice(2))); process.stdout.write("V1 LOCAL_PRIVATE control receipt verified.\n"); }
if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  try { main(); } catch (error) { process.stderr.write(`${String(error?.message ?? error)}\n`); process.exitCode = 1; }
}
