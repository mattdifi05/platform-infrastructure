#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

export const V1_EXACT_RELEASE_AUTHORITY_PATH = "/var/lib/platform-infrastructure/v1/local-private/exact-release-authority.json";
export const V1_INSTALL_READY_BUT_DISABLED = Object.freeze([
  "PROVIDER_ADMISSION",
  "DNS_PUBLICATION",
  "DAST",
  "SIGSTORE_PROMOTION",
  "DOCKER_CONTROL_PLANE",
]);

const RECEIPT_SCHEMA = "platform.v1-brownfield-install-receipt/v1";
const CONTROL_ARTIFACT_RECEIPT_SCHEMA = "platform.v1-control-artifact-install-receipt/v1";
const BOOTSTRAP_BRIDGE_RECEIPT_SCHEMA = "platform.v1-brownfield-bootstrap-bridge-receipt/v1";
const NODE_RUNTIME_PREREQUISITE_RECEIPT_SCHEMA = "platform.v1-node-runtime-prerequisite-receipt/v1";
const AUTHORITY_SCHEMA = "platform.v1-local-private-exact-release-authority/v1";
const BACKUP_TOOL_IMAGE_KEYS = Object.freeze([
  "mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone",
]);
const EVIDENCE_LOGICAL_KEYS = Object.freeze([
  "anniversary", "fiplatform", "matthewdifilippo", "opstudents", "public", "stexor", "stream",
  "workcalendar", "pg-stexor", "pg-keycloak", "mariadb", "minio", "keycloak-config", "confidential",
]);
const MAX_RECEIPT_BYTES = 64 * 1024;
const MAX_AUTHORITY_BYTES = 128 * 1024;
const EXACT_RECEIPT_FIELDS = Object.freeze([
  "activationAuthorized", "authorizationSource", "backupEvidenceAuthoritative",
  "candidateCommit", "candidateTree", "dataMutation", "dockerMutation",
  "readyButDisabled", "releaseRoot", "schema", "sourceArchiveSha256", "status",
]);
const EXACT_CONTROL_ARTIFACT_RECEIPT_FIELDS = Object.freeze([
  "artifacts", "candidateCommit", "candidateTree", "dataMutation", "dockerMutation", "hostControlMutation",
  "schema", "sourceArchiveSha256", "status",
]);
const EXACT_BOOTSTRAP_BRIDGE_RECEIPT_FIELDS = Object.freeze([
  "bridgeSha256", "candidateCommit", "candidateConsumerSha256", "candidateTree",
  "checkpointAfterSha256", "checkpointBeforeSha256", "controlArtifactReceiptSha256",
  "dataMutation", "dockerMutation", "documentId", "gitBundleSha256", "hostControlMutation",
  "installReceiptSha256", "legacyBroadSudoersAfterSha256", "legacyBroadSudoersBeforeSha256",
  "legacyConsumerSha256", "legacyV1SudoersSha256", "nodeRuntimeReceiptSha256",
  "releaseRoot", "schema", "sourceArchiveAfterSha256", "sourceArchiveBeforeSha256",
  "stagingEnvironmentSha256", "stagingMutation", "status", "transportSanction",
]);
const EXACT_PREPARE_RECEIPT_FIELDS = Object.freeze([
  "authorityDocumentId", "authorityPath", "authoritySha256", "renderSha256",
  "sourceArchiveSha256", "status",
]);
const EXACT_PREPARE_VALIDATION_RECEIPT_FIELDS = Object.freeze([
  "authorityDocumentId", "authorityPath", "authoritySha256", "renderSha256",
  "sourceArchiveSha256", "status", "validationCheckpointPath", "validationCheckpointSha256",
]);
const V1_VALIDATION_CHECKPOINT_PATH = "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint-validation.json";
const EXACT_NODE_RUNTIME_PREREQUISITE_FIELDS = Object.freeze([
  "activationAuthorized", "binaryPath", "binarySha256", "candidateCommit", "candidateTree",
  "dataMutation", "dockerMutation", "documentId", "helperSha256", "hostControlMutation",
  "packageArchitecture", "packageName", "packageSource", "packageVersion", "receiptPath",
  "releaseRoot", "runtimeVersion", "schema", "sourceArchiveSha256", "status", "workloadMutation",
]);
const EXACT_AUTHORITY_FIELDS = Object.freeze([
  "activeManagedContainerNames", "artifacts", "authorityMode", "authorizedDataMutations", "backupToolImages",
  "candidateCommit", "candidateTree", "checkoutProof", "controllerVerificationScope",
  "disabledComposeServices", "documentId", "evidenceProducer", "expectedContainerNames",
  "legacyNetworkAttachments", "legacyRouteChecks", "legacyUnmanagedContainers", "preservedLegacyContainerNames",
  "recoveryEscrowCertificate", "releaseRoot", "renderEnvironment", "renderSha256", "runtimeIdentity", "schema", "serviceTargets",
  "sourceArchiveSha256", "status",
]);
const FIXED_ARTIFACT_PATHS = Object.freeze({
  controller: "/usr/local/libexec/platform-v1-local-private-control",
  installer: "/usr/local/libexec/platform-v1-brownfield-install-consumer",
  reconciler: "/usr/local/libexec/platform-v1-local-private-reconcile",
  sudoers: "/etc/sudoers.d/platform-v1-local-private-control",
  unit: "/etc/systemd/system/platform-v1-local-private-control.service",
});
const CONTROL_ARTIFACT_SPECS = Object.freeze([
  Object.freeze({ mode: "0555", name: "installer", path: FIXED_ARTIFACT_PATHS.installer, source: "scripts/v1-brownfield-install-consumer.py" }),
  Object.freeze({ mode: "0555", name: "controller", path: FIXED_ARTIFACT_PATHS.controller, source: "scripts/v1-local-private-control.py" }),
  Object.freeze({ mode: "0555", name: "reconciler", path: FIXED_ARTIFACT_PATHS.reconciler, source: "scripts/v1-local-private-reconcile.py" }),
  Object.freeze({ mode: "0444", name: "unit", path: FIXED_ARTIFACT_PATHS.unit, source: "systemd/platform-v1-local-private-control.service" }),
  Object.freeze({ mode: "0440", name: "sudoers", path: FIXED_ARTIFACT_PATHS.sudoers, source: "sudoers/platform-v1-local-private-control" }),
]);
const DISABLED_COMPOSE_SERVICES = Object.freeze([
  "backup-scheduler",
  "docker-action-activation-sidecar",
  "docker-action-broker",
]);

function invalid(message) {
  throw new Error(message);
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function lowercaseSha256(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value) || value === "0".repeat(64)) {
    invalid(`${label} must be one non-placeholder lowercase SHA-256 digest.`);
  }
  return value;
}

function gitObject(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{40}$/.test(value)) {
    invalid(`${label} must be one lowercase 40-hex Git object ID.`);
  }
  return value;
}

function exactObject(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be one JSON object.`);
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    invalid(`${label} has missing or unexpected fields.`);
  }
  return value;
}

function readCanonicalObject(filename, label, maximum) {
  const pathname = String(filename ?? "").trim();
  if (!pathname) invalid(`${label} path is required.`);
  let stat;
  try {
    stat = fs.lstatSync(pathname);
  } catch {
    invalid(`${label} is missing.`);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) invalid(`${label} must be a regular non-symlink file.`);
  if (stat.size < 2 || stat.size > maximum) invalid(`${label} size is invalid.`);
  const bytes = fs.readFileSync(pathname);
  const raw = bytes.toString("utf8");
  if (!Buffer.from(raw, "utf8").equals(bytes)) invalid(`${label} is not strict UTF-8.`);
  if (raw.includes("\0") || raw.includes("\r") || raw.startsWith("\ufeff")) invalid(`${label} encoding is invalid.`);
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    invalid(`${label} is not valid JSON.`);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be one JSON object.`);
  if (`${stableJson(value)}\n` !== raw) invalid(`${label} is not canonical JSON.`);
  return { raw, value };
}

function exactSortedStrings(value, label, { nonempty = true } = {}) {
  if (!Array.isArray(value) || (nonempty && value.length === 0)) invalid(`${label} must be one${nonempty ? " non-empty" : ""} sequence.`);
  if (value.some((item) => typeof item !== "string" || !item || !/^[A-Za-z0-9_.-]+$/.test(item))) {
    invalid(`${label} contains an invalid name.`);
  }
  if (JSON.stringify(value) !== JSON.stringify([...new Set(value)].sort())) invalid(`${label} is duplicated or not canonically ordered.`);
  return value;
}

function releaseBinding(value, label) {
  const candidateCommit = gitObject(value.candidateCommit, `${label} candidate commit`);
  const candidateTree = gitObject(value.candidateTree, `${label} candidate tree`);
  const sourceArchiveSha256 = lowercaseSha256(value.sourceArchiveSha256, `${label} source archive`);
  const releaseRoot = `/srv/platform-infrastructure/releases/${candidateCommit}-${sourceArchiveSha256}`;
  if (value.releaseRoot !== releaseRoot) invalid(`${label} release root is not content-bound to its candidate/archive.`);
  return { candidateCommit, candidateTree, releaseRoot, sourceArchiveSha256 };
}

function validateAuthorityCollections(authority) {
  const active = exactSortedStrings(authority.activeManagedContainerNames, "V1 authority active managed containers");
  const preserved = exactSortedStrings(authority.preservedLegacyContainerNames, "V1 authority preserved legacy containers");
  const expected = exactSortedStrings(authority.expectedContainerNames, "V1 authority expected containers");
  if (JSON.stringify([...new Set([...active, ...preserved])].sort()) !== JSON.stringify(expected)) {
    invalid("V1 authority expected containers are not the exact active/preserved union.");
  }
  const legacyReasons = new Set([
    "NO_HOSTED_WORKLOAD_AUTHORITY", "COMPOSE_PROFILE_ADMIN_DISABLED", "COMPOSE_PROFILE_DNS_DISABLED",
    "COMPOSE_PROFILE_RAW_HOST_METRICS_DISABLED", "COMPOSE_PROFILE_LOCAL_RUNTIME_DISABLED",
    "COMPOSE_PROFILE_LEGACY_SHARED_RUNTIME_DISABLED",
  ]);
  if (!Array.isArray(authority.legacyUnmanagedContainers) || authority.legacyUnmanagedContainers.length !== 19) {
    invalid("V1 authority legacy unmanaged set is not the exact nineteen-container set.");
  }
  const legacyNames = authority.legacyUnmanagedContainers.map((raw, index) => {
    const item = exactObject(raw, ["containerName", "reason", "status"], `V1 authority legacy unmanaged container ${index}`);
    if (!preserved.includes(item.containerName) || item.status !== "LEGACY_UNMANAGED" || !legacyReasons.has(item.reason)) {
      invalid("V1 authority contains an invalid legacy unmanaged container classification.");
    }
    return item.containerName;
  });
  if (stableJson(legacyNames) !== stableJson(preserved)) {
    invalid("V1 authority legacy unmanaged containers are not canonically aligned with the preserved set.");
  }
  if (JSON.stringify(authority.disabledComposeServices) !== JSON.stringify(DISABLED_COMPOSE_SERVICES)) {
    invalid("V1 authority disabled Compose services are not the closed LOCAL_PRIVATE provider set.");
  }

  if (!Array.isArray(authority.authorizedDataMutations)) invalid("V1 authority data-mutation scope is not a sequence.");
  const mutationIds = [];
  for (const [index, raw] of authority.authorizedDataMutations.entries()) {
    const item = exactObject(raw, ["id", "service", "target", "type"], `V1 authority data mutation ${index}`);
    if (typeof item.id !== "string" || !/^[A-Za-z0-9_.-]+$/.test(item.id) || typeof item.service !== "string"
      || typeof item.target !== "string" || !item.target.startsWith("/")
      || !new Set(["BOOTSTRAP_WRITE", "SCHEMA_MIGRATION", "CONFIGURATION_WRITE"]).has(item.type)) {
      invalid("V1 authority contains an invalid data-mutation grant.");
    }
    mutationIds.push(item.id);
  }
  if (JSON.stringify(mutationIds) !== JSON.stringify([...new Set(mutationIds)].sort())) invalid("V1 authority data-mutation grants are duplicated or unordered.");

  if (!Array.isArray(authority.legacyNetworkAttachments) || authority.legacyNetworkAttachments.length === 0) {
    invalid("V1 authority legacy network attachments are missing.");
  }
  const attachmentOrder = [];
  for (const [index, raw] of authority.legacyNetworkAttachments.entries()) {
    const item = exactObject(raw, ["aliases", "containerName", "networkName"], `V1 authority legacy network attachment ${index}`);
    if (!preserved.includes(item.containerName) || typeof item.networkName !== "string" || !item.networkName || item.networkName === "enterprise_net") {
      invalid("V1 authority contains an invalid legacy network attachment.");
    }
    exactSortedStrings(item.aliases, `V1 authority legacy network attachment ${index} aliases`, { nonempty: false });
    attachmentOrder.push(`${item.containerName}\0${item.networkName}`);
  }
  if (JSON.stringify(attachmentOrder) !== JSON.stringify([...new Set(attachmentOrder)].sort())) invalid("V1 authority legacy network attachments are duplicated or unordered.");

  if (!Array.isArray(authority.legacyRouteChecks) || authority.legacyRouteChecks.length === 0) invalid("V1 authority legacy route checks are missing.");
  const routeNames = [];
  for (const [index, raw] of authority.legacyRouteChecks.entries()) {
    const item = exactObject(raw, ["containerName", "expectedStatus", "name", "url"], `V1 authority legacy route check ${index}`);
    let parsed;
    try { parsed = new URL(item.url); } catch { invalid("V1 authority contains an invalid legacy route URL."); }
    if (!preserved.includes(item.containerName) || typeof item.name !== "string" || !/^[A-Za-z0-9_.-]+$/.test(item.name)
      || !Number.isInteger(item.expectedStatus) || item.expectedStatus < 200 || item.expectedStatus > 399
      || !new Set(["http:", "https:"]).has(parsed.protocol) || parsed.username || parsed.password || parsed.hash) {
      invalid("V1 authority contains an invalid legacy route check.");
    }
    routeNames.push(item.name);
  }
  if (JSON.stringify(routeNames) !== JSON.stringify([...new Set(routeNames)].sort())) invalid("V1 authority legacy route checks are duplicated or unordered.");

  if (!Array.isArray(authority.serviceTargets) || authority.serviceTargets.length !== active.length) invalid("V1 authority service targets do not cover the active managed set.");
  const targetContainers = [];
  const targetServices = new Set();
  for (const [index, raw] of authority.serviceTargets.entries()) {
    const item = exactObject(raw, ["configHash", "containerName", "project", "semantic", "service"], `V1 authority service target ${index}`);
    if (!active.includes(item.containerName) || typeof item.project !== "string" || !item.project
      || typeof item.service !== "string" || !/^[A-Za-z0-9_.-]+$/.test(item.service)
      || !item.semantic || typeof item.semantic !== "object" || Array.isArray(item.semantic) || targetServices.has(item.service)) {
      invalid("V1 authority contains an invalid or duplicated service target.");
    }
    lowercaseSha256(item.configHash, `V1 authority service target ${index} Compose config hash`);
    const semantic = exactObject(item.semantic, [
      "blkioWeight", "capAdd", "capDrop", "command", "cpuShares", "entrypoint", "environment",
      "extraHosts", "groupAdd", "healthcheck", "imageId", "imageReference", "init", "memoryBytes",
      "memoryReservationBytes", "logging", "mounts", "nanoCpus", "networkEndpoints", "networkMode",
      "networks", "pidMode", "pidsLimit", "ports", "privileged", "readOnlyRootfs", "restartPolicy",
      "routingLabels", "runtimeIdentityLabels", "securityOpt", "tmpfs", "ulimits", "user", "workingDirectory",
    ], `V1 authority service target ${index} semantic`);
    if (typeof semantic.imageReference !== "string" || !/^[^@\s]+@sha256:[a-f0-9]{64}$/.test(semantic.imageReference)
      || typeof semantic.imageId !== "string" || !/^sha256:[a-f0-9]{64}$/.test(semantic.imageId)) {
      invalid("V1 authority service target image is not bound to immutable registry/image digests.");
    }
    if (!Array.isArray(semantic.environment)) invalid("V1 authority service target environment binding is not a sequence.");
    const environmentNames = [];
    for (const [environmentIndex, environmentRaw] of semantic.environment.entries()) {
      const environment = exactObject(environmentRaw, ["name", "valueSha256"], `V1 authority target environment ${index}.${environmentIndex}`);
      if (typeof environment.name !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(environment.name)) {
        invalid("V1 authority target environment name is invalid.");
      }
      lowercaseSha256(environment.valueSha256, "V1 authority target environment value");
      environmentNames.push(environment.name);
    }
    if (JSON.stringify(environmentNames) !== JSON.stringify([...new Set(environmentNames)].sort())) {
      invalid("V1 authority target environment bindings are duplicated or unordered.");
    }
    if (!Array.isArray(semantic.mounts) || semantic.mounts.some((mount) =>
      mount && typeof mount === "object"
        && [mount.source, mount.target].some((value) => ["/run/docker.sock", "/var/run/docker.sock"].includes(value)))) {
      invalid("V1 authority service target mounts are invalid or expose raw Docker authority.");
    }
    targetContainers.push(item.containerName);
    targetServices.add(item.service);
  }
  if (JSON.stringify(targetContainers) !== JSON.stringify(active)) invalid("V1 authority service targets are not canonically aligned with active containers.");
}

export function verifyV1ExactReleaseAuthority({ file, repositoryRoot }) {
  const { raw, value: authority } = readCanonicalObject(file, "V1 exact release authority", MAX_AUTHORITY_BYTES);
  exactObject(authority, EXACT_AUTHORITY_FIELDS, "V1 exact release authority");
  const binding = releaseBinding(authority, "V1 exact release authority");
  const base = { ...authority };
  delete base.documentId;
  lowercaseSha256(authority.documentId, "V1 exact release authority document ID");
  if (authority.documentId !== sha256(stableJson(base))) invalid("V1 exact release authority document ID is invalid.");
  if (authority.schema !== AUTHORITY_SCHEMA || authority.status !== "AUTHORIZED" || authority.authorityMode !== "LOCAL_PRIVATE"
    || authority.controllerVerificationScope !== "AUTHORITY_ARCHIVE_RELEASE_RENDER_ONLY_NOT_GITHUB") {
    invalid("V1 exact release authority schema/status/scope is invalid.");
  }
  const proof = exactObject(authority.checkoutProof, [
    "clean", "githubMainCommit", "githubMainRef", "headCommit", "headTree", "producer", "status", "verifiedAtUnixSeconds",
  ], "V1 exact release authority checkout proof");
  if (proof.clean !== true || proof.status !== "PASS" || proof.producer !== "CLEAN_CHECKOUT_GITHUB_MAIN_V1"
    || proof.githubMainRef !== "refs/remotes/github/main" || proof.githubMainCommit !== binding.candidateCommit
    || proof.headCommit !== binding.candidateCommit || proof.headTree !== binding.candidateTree
    || !Number.isInteger(proof.verifiedAtUnixSeconds) || proof.verifiedAtUnixSeconds < 1_700_000_000) {
    invalid("V1 exact release authority checkout proof is invalid.");
  }
  lowercaseSha256(authority.renderSha256, "V1 exact release authority render");
  const runtimeIdentity = exactObject(authority.runtimeIdentity, [
    "candidateId", "commit", "deploymentId", "sourceRenderSha256", "tree", "workloadLockSha256",
  ], "V1 exact release runtime identity");
  gitObject(runtimeIdentity.commit, "V1 runtime identity commit");
  gitObject(runtimeIdentity.tree, "V1 runtime identity tree");
  lowercaseSha256(runtimeIdentity.candidateId, "V1 runtime candidate ID");
  lowercaseSha256(runtimeIdentity.sourceRenderSha256, "V1 runtime source render");
  lowercaseSha256(runtimeIdentity.workloadLockSha256, "V1 runtime workload lock");
  const runtimeSeed = {
    candidateCommit: binding.candidateCommit,
    candidateTree: binding.candidateTree,
    sourceRenderSha256: runtimeIdentity.sourceRenderSha256,
    workloadLockSha256: runtimeIdentity.workloadLockSha256,
  };
  if (runtimeIdentity.commit !== binding.candidateCommit || runtimeIdentity.tree !== binding.candidateTree
    || runtimeIdentity.candidateId !== sha256(stableJson(runtimeSeed))
    || runtimeIdentity.deploymentId !== `v1-local-private:${runtimeIdentity.candidateId}`) {
    invalid("V1 exact release runtime identity is not derived from candidate/tree/source-render/workload-lock.");
  }
  const environment = exactObject(authority.renderEnvironment, ["path", "sha256"], "V1 exact release render environment");
  if (environment.path !== "/var/lib/platform-infrastructure/v1/local-private/exact-compose.env") {
    invalid("V1 exact release render environment path is invalid.");
  }
  lowercaseSha256(environment.sha256, "V1 exact release render environment");
  const escrowCertificate = exactObject(authority.recoveryEscrowCertificate, ["path", "sha256", "sha256Fingerprint"], "V1 recovery escrow certificate");
  if (escrowCertificate.path !== `${binding.releaseRoot}/config/local-private-recovery-escrow-cert.pem`) invalid("V1 recovery escrow certificate path is invalid.");
  lowercaseSha256(escrowCertificate.sha256, "V1 recovery escrow certificate bytes");
  lowercaseSha256(escrowCertificate.sha256Fingerprint, "V1 recovery escrow certificate fingerprint");
  const backupToolImages = exactObject(authority.backupToolImages, BACKUP_TOOL_IMAGE_KEYS, "V1 backup tool images");
  for (const name of BACKUP_TOOL_IMAGE_KEYS) {
    const image = exactObject(backupToolImages[name], ["imageId", "imageReference"], `V1 backup tool image ${name}`);
    if (typeof image.imageId !== "string" || !/^sha256:[a-f0-9]{64}$/.test(image.imageId)
      || typeof image.imageReference !== "string" || !/^[^@\s]+@sha256:[a-f0-9]{64}$/.test(image.imageReference)) {
      invalid(`V1 backup tool image ${name} is not bound to an immutable reference and resolved image ID.`);
    }
  }

  const producer = exactObject(authority.evidenceProducer, [
    "executor", "executorFlags", "forbiddenResticOperations", "hostingerAllowed", "logicalKeys",
    "offsiteRepository", "operations", "path", "recoveryEscrowPrefix", "sha256",
  ], "V1 evidence producer");
  if (producer.executor !== "/usr/bin/python3"
    || stableJson(producer.executorFlags) !== stableJson(["-I"])
    || stableJson(producer.forbiddenResticOperations) !== stableJson(["forget", "prune"])
    || producer.hostingerAllowed !== false
    || stableJson(producer.logicalKeys) !== stableJson(EVIDENCE_LOGICAL_KEYS)
    || producer.offsiteRepository !== "rclone:platform-onedrive:platform-infrastructure/restic"
    || stableJson(producer.operations) !== stableJson(["pre", "post"])
    || producer.path !== binding.releaseRoot + "/scripts/v1-local-private-evidence-producer.py"
    || producer.recoveryEscrowPrefix !== "platform-onedrive:platform-infrastructure/key-escrow") {
    invalid("V1 evidence producer closed execution/storage contract is invalid.");
  }
  lowercaseSha256(producer.sha256, "V1 evidence producer source");

  const artifacts = exactObject(authority.artifacts, ["composeWrapper", "controller", "installer", "reconciler", "sudoers", "unit"], "V1 exact release artifacts");
  for (const [name, expectedPath] of Object.entries({ composeWrapper: `${binding.releaseRoot}/scripts/compose-vps.sh`, ...FIXED_ARTIFACT_PATHS })) {
    const artifact = exactObject(artifacts[name], ["path", "sha256"], `V1 exact ${name} artifact`);
    if (artifact.path !== expectedPath) invalid(`V1 exact ${name} artifact path is invalid.`);
    lowercaseSha256(artifact.sha256, `V1 exact ${name} artifact`);
  }
  validateAuthorityCollections(authority);
  if (repositoryRoot !== undefined) {
    const expectedHashes = Object.fromEntries(repositoryArtifactExpectations(repositoryRoot).map((artifact) => [artifact.name, artifact.sha256]));
    expectedHashes.composeWrapper = repositoryArtifactHash(repositoryRoot, "scripts/compose-vps.sh", "composeWrapper");
    for (const [name, expectedHash] of Object.entries(expectedHashes)) {
      if (artifacts[name].sha256 !== expectedHash) invalid(`V1 exact ${name} artifact differs from the selected exact-main source bytes.`);
    }
    const certificatePath = `${repositoryRoot}/config/local-private-recovery-escrow-cert.pem`;
    const certificateMetadata = fs.lstatSync(certificatePath);
    if (!certificateMetadata.isFile() || certificateMetadata.isSymbolicLink() || certificateMetadata.nlink !== 1 || certificateMetadata.size < 2 || certificateMetadata.size > 65536) invalid("Exact-main recovery escrow certificate identity is invalid.");
    const certificateBytes = fs.readFileSync(certificatePath);
    let certificate;
    try { certificate = new crypto.X509Certificate(certificateBytes); } catch { invalid("Exact-main recovery escrow certificate is not X.509 PEM."); }
    const fingerprint = certificate.fingerprint256.replaceAll(":", "").toLowerCase();
    if (sha256(certificateBytes) !== escrowCertificate.sha256 || fingerprint !== escrowCertificate.sha256Fingerprint) invalid("Exact-main recovery escrow certificate bytes/fingerprint differ from authority.");
    const producerPath = repositoryRoot + "/scripts/v1-local-private-evidence-producer.py";
    const producerMetadata = fs.lstatSync(producerPath);
    if (!producerMetadata.isFile() || producerMetadata.isSymbolicLink() || producerMetadata.nlink !== 1 || producerMetadata.size < 2 || producerMetadata.size > 2 * 1024 * 1024) invalid("Exact-main evidence producer identity is invalid.");
    if (sha256(fs.readFileSync(producerPath)) !== producer.sha256) invalid("Exact-main evidence producer bytes differ from authority.");
    if (repositoryArtifactHash(repositoryRoot, "config/no-hosted-workloads.local-private.lock.json", "LOCAL_PRIVATE workload lock") !== runtimeIdentity.workloadLockSha256) {
      invalid("Exact-main LOCAL_PRIVATE workload-lock bytes differ from runtime identity.");
    }
  }
  return Object.freeze({ ...authority, authoritySha256: sha256(raw), binding: Object.freeze(binding) });
}

function expectedBinding(options_) {
  const authoritySelected = options_.authorityFile !== undefined;
  const explicitNames = ["candidateCommit", "candidateTree", "sourceArchiveSha256"];
  const explicitCount = explicitNames.filter((name) => options_[name] !== undefined).length;
  if (authoritySelected && explicitCount !== 0) invalid("Authority and explicit expected candidate modes are mutually exclusive.");
  if (authoritySelected) return verifyV1ExactReleaseAuthority({ file: options_.authorityFile }).binding;
  if (explicitCount !== explicitNames.length) invalid("Receipt verification requires either --authorityFile or the complete explicit expected candidate triple.");
  const candidateCommit = gitObject(options_.candidateCommit, "Expected candidate commit");
  const candidateTree = gitObject(options_.candidateTree, "Expected candidate tree");
  const sourceArchiveSha256 = lowercaseSha256(options_.sourceArchiveSha256, "Expected source archive");
  return Object.freeze({
    candidateCommit,
    candidateTree,
    sourceArchiveSha256,
    releaseRoot: `/srv/platform-infrastructure/releases/${candidateCommit}-${sourceArchiveSha256}`,
  });
}

export function verifyV1InstallReceipt(options_) {
  const expected = expectedBinding(options_);
  const { value: receipt } = readCanonicalObject(options_.file, "V1 install receipt", MAX_RECEIPT_BYTES);
  exactObject(receipt, EXACT_RECEIPT_FIELDS, "V1 install receipt");
  if (receipt.schema !== RECEIPT_SCHEMA) invalid("V1 install receipt schema is invalid.");
  if (!new Set(["INSTALL_ONLY_COMPLETE", "ALREADY_INSTALLED"]).has(receipt.status)) invalid("V1 install receipt status is invalid.");
  const actual = releaseBinding(receipt, "V1 install receipt");
  for (const name of ["candidateCommit", "candidateTree", "sourceArchiveSha256", "releaseRoot"]) {
    if (actual[name] !== expected[name]) invalid(`V1 install receipt ${name} differs from the selected release authority.`);
  }
  for (const field of ["activationAuthorized", "dockerMutation", "dataMutation"]) {
    if (receipt[field] !== false) invalid(`V1 install receipt ${field} must be false.`);
  }
  if (receipt.authorizationSource !== "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY") invalid("V1 install receipt authorization source is invalid.");
  if (receipt.backupEvidenceAuthoritative !== false) invalid("V1 install receipt backup evidence must remain non-authoritative.");
  if (JSON.stringify(receipt.readyButDisabled) !== JSON.stringify(V1_INSTALL_READY_BUT_DISABLED)) {
    invalid("V1 install receipt READY_BUT_DISABLED set is not exact.");
  }
  return Object.freeze({ ...receipt, readyButDisabled: Object.freeze([...receipt.readyButDisabled]) });
}

function canonicalRepositoryRoot(repositoryRoot) {
  const root = String(repositoryRoot ?? "");
  let metadata;
  try { metadata = fs.lstatSync(root); } catch { invalid("Exact-main repository root is missing."); }
  if (!root || !fs.realpathSync.native(root).startsWith("/") || fs.realpathSync.native(root) !== root
    || !metadata.isDirectory() || metadata.isSymbolicLink()) {
    invalid("Exact-main repository root must be one canonical physical directory.");
  }
  return root;
}

function repositoryArtifactHash(repositoryRoot, source, name) {
  const root = canonicalRepositoryRoot(repositoryRoot);
  const filename = `${root}/${source}`;
  let sourceMetadata;
  try { sourceMetadata = fs.lstatSync(filename); } catch { invalid(`Exact-main ${name} artifact source is missing.`); }
  if (!sourceMetadata.isFile() || sourceMetadata.isSymbolicLink() || sourceMetadata.nlink !== 1
    || sourceMetadata.size < 1 || sourceMetadata.size > 2 * 1024 * 1024
    || (sourceMetadata.mode & 0o022) !== 0) {
    invalid(`Exact-main ${name} artifact source identity is unsafe.`);
  }
  return sha256(fs.readFileSync(filename));
}

function repositoryArtifactExpectations(repositoryRoot) {
  const root = canonicalRepositoryRoot(repositoryRoot);
  return CONTROL_ARTIFACT_SPECS.map((spec) => {
    return Object.freeze({
      mode: spec.mode,
      name: spec.name,
      path: spec.path,
      sha256: repositoryArtifactHash(root, spec.source, spec.name),
    });
  });
}

function controlArtifactExpectations(options_) {
  if (options_.authorityFile !== undefined) {
    if (options_.repositoryRoot !== undefined) invalid("Authority and repository-root control artifact modes are mutually exclusive.");
    const authority = verifyV1ExactReleaseAuthority({ file: options_.authorityFile });
    return Object.freeze({
      artifacts: Object.freeze(CONTROL_ARTIFACT_SPECS.map((spec) => Object.freeze({
        mode: spec.mode,
        name: spec.name,
        path: spec.path,
        sha256: authority.artifacts[spec.name].sha256,
      }))),
      binding: authority.binding,
    });
  }
  const binding = expectedBinding(options_);
  if (options_.repositoryRoot === undefined) invalid("Explicit control artifact verification requires --repositoryRoot.");
  return Object.freeze({ artifacts: Object.freeze(repositoryArtifactExpectations(options_.repositoryRoot)), binding });
}

export function verifyV1ControlArtifactReceipt(options_) {
  const expected = controlArtifactExpectations(options_);
  const { value: receipt } = readCanonicalObject(options_.file, "V1 control artifact receipt", MAX_RECEIPT_BYTES);
  exactObject(receipt, EXACT_CONTROL_ARTIFACT_RECEIPT_FIELDS, "V1 control artifact receipt");
  if (receipt.schema !== CONTROL_ARTIFACT_RECEIPT_SCHEMA
    || !new Set(["CONTROL_ARTIFACTS_INSTALLED", "ALREADY_INSTALLED"]).has(receipt.status)) {
    invalid("V1 control artifact receipt schema/status is invalid.");
  }
  for (const name of ["candidateCommit", "candidateTree", "sourceArchiveSha256"]) {
    if (receipt[name] !== expected.binding[name]) invalid(`V1 control artifact receipt ${name} differs from the selected release.`);
  }
  if (receipt.dockerMutation !== false || receipt.dataMutation !== false) {
    invalid("V1 control artifact receipt falsely declares Docker or data mutation.");
  }
  if (receipt.hostControlMutation !== (receipt.status === "CONTROL_ARTIFACTS_INSTALLED")) {
    invalid("V1 control artifact receipt host-control mutation truth differs from its idempotent status.");
  }
  if (!Array.isArray(receipt.artifacts) || receipt.artifacts.length !== CONTROL_ARTIFACT_SPECS.length) {
    invalid("V1 control artifact receipt artifact set is not exact.");
  }
  const normalized = receipt.artifacts.map((raw, index) => {
    const artifact = exactObject(raw, ["mode", "name", "path", "sha256"], `V1 control artifact ${index}`);
    lowercaseSha256(artifact.sha256, `V1 control artifact ${index}`);
    return artifact;
  });
  if (stableJson(normalized) !== stableJson(expected.artifacts)) {
    invalid("V1 control artifact receipt does not bind the exact closed installer/controller/reconciler/unit/sudoers set.");
  }
  return Object.freeze({ ...receipt, artifacts: Object.freeze(normalized.map((item) => Object.freeze({ ...item }))) });
}

export function verifyV1BootstrapBridgeReceipt(options_) {
  const expected = expectedBinding(options_);
  const { value: receipt } = readCanonicalObject(options_.file, "V1 bootstrap bridge receipt", MAX_RECEIPT_BYTES);
  exactObject(receipt, EXACT_BOOTSTRAP_BRIDGE_RECEIPT_FIELDS, "V1 bootstrap bridge receipt");
  const withoutId = { ...receipt };
  delete withoutId.documentId;
  lowercaseSha256(receipt.documentId, "V1 bootstrap bridge receipt document ID");
  if (receipt.documentId !== sha256(stableJson(withoutId))) invalid("V1 bootstrap bridge receipt document ID is invalid.");
  if (receipt.schema !== BOOTSTRAP_BRIDGE_RECEIPT_SCHEMA || receipt.status !== "BOOTSTRAP_CONTROL_INSTALLED") {
    invalid("V1 bootstrap bridge receipt schema/status is invalid.");
  }
  if (receipt.candidateCommit !== expected.candidateCommit || receipt.candidateTree !== expected.candidateTree
    || receipt.sourceArchiveAfterSha256 !== expected.sourceArchiveSha256 || receipt.releaseRoot !== expected.releaseRoot) {
    invalid("V1 bootstrap bridge receipt differs from the expected candidate/archive.");
  }
  for (const field of [
    "bridgeSha256", "candidateConsumerSha256", "checkpointAfterSha256", "checkpointBeforeSha256",
    "controlArtifactReceiptSha256", "gitBundleSha256", "installReceiptSha256", "nodeRuntimeReceiptSha256",
    "legacyBroadSudoersAfterSha256", "legacyBroadSudoersBeforeSha256", "legacyConsumerSha256",
    "legacyV1SudoersSha256", "sourceArchiveBeforeSha256", "stagingEnvironmentSha256",
  ]) lowercaseSha256(receipt[field], "V1 bootstrap bridge " + field);
  const sanction = receipt.transportSanction;
  if (!sanction || typeof sanction !== "object" || Array.isArray(sanction)) {
    invalid("V1 bootstrap bridge transportSanction is not an object.");
  } else {
    const sanctionKeys = Object.keys(sanction).sort();
    if (sanction.present === true) {
      if (JSON.stringify(sanctionKeys) !== JSON.stringify(["present", "reasonCode", "sanctionDigest", "signerCertSha256"])
        || sanction.reasonCode !== "TRANSPORT_CHECKPOINT_REGENERATED_NO_PRIOR_BYTES"
        || !/^[0-9a-f]{64}$/.test(sanction.sanctionDigest)
        || !/^[0-9a-f]{64}$/.test(sanction.signerCertSha256)) {
        invalid("V1 bootstrap bridge transportSanction payload is invalid.");
      }
    } else if (sanction.present !== false || JSON.stringify(sanctionKeys) !== JSON.stringify(["present"])) {
      invalid("V1 bootstrap bridge transportSanction sentinel is invalid.");
    }
  }
  if (receipt.legacyConsumerSha256 !== "9902e8c83f12cee7d16ee97b660cde12444da479acbe85f9efa4c613d82f76a9"
    || receipt.legacyV1SudoersSha256 !== sha256([
      "Defaults:platform_infrastructure env_reset",
      "Defaults:platform_infrastructure secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "platform_infrastructure ALL=(root) NOPASSWD: /usr/local/libexec/platform-v1-local-private-control activate",
      "",
    ].join("\n"))
    || receipt.legacyBroadSudoersBeforeSha256 !== sha256("platform_infrastructure ALL=(ALL) NOPASSWD:ALL\n")
    || receipt.legacyBroadSudoersAfterSha256 !== receipt.legacyBroadSudoersBeforeSha256) {
    invalid("V1 bootstrap bridge historical consumer/sudo precondition is invalid.");
  }
  if (receipt.dataMutation !== false || receipt.dockerMutation !== false
    || typeof receipt.hostControlMutation !== "boolean" || typeof receipt.stagingMutation !== "boolean") {
    invalid("V1 bootstrap bridge mutation truth is invalid.");
  }
  if (options_.repositoryRoot !== undefined) {
    if (receipt.bridgeSha256 !== repositoryArtifactHash(options_.repositoryRoot, "scripts/v1-brownfield-bootstrap-bridge.py", "bootstrap bridge")
      || receipt.candidateConsumerSha256 !== repositoryArtifactHash(options_.repositoryRoot, "scripts/v1-brownfield-install-consumer.py", "bootstrap consumer")) {
      invalid("V1 bootstrap bridge receipt differs from selected exact-main source bytes.");
    }
  }
  return Object.freeze(receipt);
}

export function verifyV1PrepareReceipt({ file, authorityFile }) {
  const authority = verifyV1ExactReleaseAuthority({ file: authorityFile });
  const { value: receipt } = readCanonicalObject(file, "V1 LOCAL_PRIVATE prepare receipt", MAX_RECEIPT_BYTES);
  const bindings = {
    authorityDocumentId: authority.documentId,
    authorityPath: V1_EXACT_RELEASE_AUTHORITY_PATH,
    authoritySha256: authority.authoritySha256,
    renderSha256: authority.renderSha256,
    sourceArchiveSha256: authority.sourceArchiveSha256,
  };
  if (receipt && typeof receipt === "object" && !Array.isArray(receipt) && receipt.status === "PREPARED_VALIDATION") {
    exactObject(receipt, EXACT_PREPARE_VALIDATION_RECEIPT_FIELDS, "V1 LOCAL_PRIVATE prepare receipt");
    const expected = {
      ...bindings,
      status: "PREPARED_VALIDATION",
      validationCheckpointPath: V1_VALIDATION_CHECKPOINT_PATH,
    };
    lowercaseSha256(receipt.validationCheckpointSha256, "V1 LOCAL_PRIVATE validation checkpoint digest");
    expected.validationCheckpointSha256 = receipt.validationCheckpointSha256;
    if (stableJson(receipt) !== stableJson(expected)) invalid("V1 LOCAL_PRIVATE validation prepare receipt differs from its immutable exact release authority.");
    return Object.freeze({ ...receipt });
  }
  exactObject(receipt, EXACT_PREPARE_RECEIPT_FIELDS, "V1 LOCAL_PRIVATE prepare receipt");
  const expected = { ...bindings, status: "PREPARED" };
  if (stableJson(receipt) !== stableJson(expected)) invalid("V1 LOCAL_PRIVATE prepare receipt differs from its immutable exact release authority.");
  return Object.freeze({ ...receipt });
}

export function verifyV1NodeRuntimePrerequisiteReceipt({
  file, candidateCommit, candidateTree, sourceArchiveSha256, repositoryRoot,
}) {
  gitObject(candidateCommit, "V1 Node runtime candidate commit");
  gitObject(candidateTree, "V1 Node runtime candidate tree");
  lowercaseSha256(sourceArchiveSha256, "V1 Node runtime source archive");
  const { value: receipt } = readCanonicalObject(file, "V1 Node runtime prerequisite receipt", MAX_RECEIPT_BYTES);
  exactObject(receipt, EXACT_NODE_RUNTIME_PREREQUISITE_FIELDS, "V1 Node runtime prerequisite receipt");
  const base = { ...receipt };
  delete base.documentId;
  lowercaseSha256(receipt.documentId, "V1 Node runtime prerequisite document ID");
  if (receipt.documentId !== sha256(stableJson(base))) invalid("V1 Node runtime prerequisite document ID is invalid.");
  if (receipt.schema !== NODE_RUNTIME_PREREQUISITE_RECEIPT_SCHEMA || receipt.status !== "NODE_RUNTIME_READY"
    || receipt.candidateCommit !== candidateCommit || receipt.candidateTree !== candidateTree
    || receipt.sourceArchiveSha256 !== sourceArchiveSha256
    || receipt.releaseRoot !== `/srv/platform-infrastructure/releases/${candidateCommit}-${sourceArchiveSha256}`
    || receipt.receiptPath !== "/var/lib/platform-infrastructure/v1/local-private/node-runtime-prerequisite-receipt.json") {
    invalid("V1 Node runtime prerequisite candidate/release/receipt binding is invalid.");
  }
  if (receipt.packageName !== "nodejs"
    || receipt.packageVersion !== "22.22.1+dfsg+~cs22.19.15-1ubuntu1"
    || receipt.packageArchitecture !== "amd64"
    || receipt.packageSource !== "UBUNTU_APT_EXACT_VERSION"
    || receipt.runtimeVersion !== "v22.22.1"
    || receipt.binaryPath !== "/usr/bin/node") {
    invalid("V1 Node runtime prerequisite package/runtime pin is invalid.");
  }
  lowercaseSha256(receipt.binarySha256, "V1 Node runtime binary");
  lowercaseSha256(receipt.helperSha256, "V1 Node runtime helper");
  if (receipt.activationAuthorized !== false || receipt.dataMutation !== false
    || receipt.dockerMutation !== false || receipt.workloadMutation !== false
    || typeof receipt.hostControlMutation !== "boolean") {
    invalid("V1 Node runtime prerequisite mutation authority is invalid.");
  }
  if (repositoryRoot !== undefined
    && receipt.helperSha256 !== repositoryArtifactHash(
      repositoryRoot, "scripts/v1-node-runtime-prerequisite.py", "Node runtime prerequisite helper",
    )) {
    invalid("V1 Node runtime prerequisite helper differs from selected exact-main source bytes.");
  }
  return Object.freeze({ ...receipt });
}

function options(arguments_, command, extraAllowed = []) {
  if (arguments_[0] !== command) invalid("V1 receipt command is invalid.");
  const allowed = new Set(["file", "authorityFile", "candidateCommit", "candidateTree", "sourceArchiveSha256", ...extraAllowed]);
  const parsed = {};
  for (let index = 1; index < arguments_.length; index += 2) {
    const flag = arguments_[index];
    const value = arguments_[index + 1];
    if (!flag?.startsWith("--") || value === undefined || value.startsWith("--")) invalid("V1 install receipt options must be value-bearing.");
    const name = flag.slice(2);
    if (!allowed.has(name) || Object.hasOwn(parsed, name)) invalid(`Unknown or duplicate V1 install receipt option: ${flag}.`);
    parsed[name] = value;
  }
  if (!Object.hasOwn(parsed, "file")) invalid("V1 install receipt is missing --file.");
  return parsed;
}

function main() {
  const arguments_ = process.argv.slice(2);
  if (arguments_[0] === "verify") {
    const parsed = options(arguments_, "verify");
    expectedBinding(parsed);
    verifyV1InstallReceipt(parsed);
    process.stdout.write("V1 install-only receipt verified.\n");
    return;
  }
  if (arguments_[0] === "verify-control-artifacts") {
    verifyV1ControlArtifactReceipt(options(arguments_, "verify-control-artifacts", ["repositoryRoot"]));
    process.stdout.write("V1 control artifact receipt verified.\n");
    return;
  }
  if (arguments_[0] === "verify-bootstrap") {
    verifyV1BootstrapBridgeReceipt(options(arguments_, "verify-bootstrap", ["repositoryRoot"]));
    process.stdout.write("V1 bootstrap bridge receipt verified.\n");
    return;
  }
  if (arguments_[0] === "verify-authority") {
    const parsed = options(arguments_, "verify-authority", ["repositoryRoot"]);
    if (!new Set(["file", "file,repositoryRoot"]).has(Object.keys(parsed).sort().join(","))) {
      invalid("V1 authority verification accepts --file and optional --repositoryRoot only.");
    }
    verifyV1ExactReleaseAuthority({ file: parsed.file, repositoryRoot: parsed.repositoryRoot });
    process.stdout.write("V1 exact release authority verified.\n");
    return;
  }
  if (arguments_[0] === "verify-prepare") {
    const parsed = options(arguments_, "verify-prepare");
    if (Object.keys(parsed).sort().join(",") !== "authorityFile,file") invalid("V1 prepare verification requires only --file and --authorityFile.");
    verifyV1PrepareReceipt({ file: parsed.file, authorityFile: parsed.authorityFile });
    process.stdout.write("V1 LOCAL_PRIVATE prepare receipt verified.\n");
    return;
  }
  if (arguments_[0] === "verify-node-runtime") {
    const parsed = options(arguments_, "verify-node-runtime", ["repositoryRoot"]);
    if (Object.keys(parsed).sort().join(",") !== "candidateCommit,candidateTree,file,repositoryRoot,sourceArchiveSha256") {
      invalid("V1 Node runtime verification requires exact candidate/tree/archive/repository inputs.");
    }
    verifyV1NodeRuntimePrerequisiteReceipt(parsed);
    process.stdout.write("V1 Node runtime prerequisite receipt verified.\n");
    return;
  }
  invalid("Usage: v1-brownfield-install-receipt.mjs {verify|verify-bootstrap|verify-control-artifacts|verify-node-runtime|verify-authority|verify-prepare} ...");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
