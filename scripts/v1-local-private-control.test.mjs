import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  V1_LOCAL_PRIVATE_ACTIVE_MANAGED_CONTAINER_NAMES as activeManaged,
  V1_LOCAL_PRIVATE_CANONICAL_CONTAINER_NAMES as canonicalNames,
  V1_LOCAL_PRIVATE_CONTAINER_NAMES as historicNames,
  V1_LOCAL_PRIVATE_PRESERVED_LEGACY_CONTAINER_NAMES as preservedLegacy,
  V1_LOCAL_PRIVATE_READY_BUT_DISABLED as readyButDisabled,
  verifyV1LocalPrivateControlReceipt,
} from "./v1-local-private-control-receipt.mjs";

const stableJson = (value) => Array.isArray(value)
  ? `[${value.map(stableJson).join(",")}]`
  : value && typeof value === "object"
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`
    : JSON.stringify(value);
const sha = (value) => crypto.createHash("sha256").update(String(value)).digest("hex");
const image = (value) => `sha256:${sha(`image:${value}`)}`;
const commit = sha("candidate").slice(0, 40);
const tree = sha("tree").slice(0, 40);
const archive = sha("archive");
const releaseRoot = `/srv/platform-infrastructure/releases/${commit}-${archive}`;
const controllerSha = sha("controller");
const sudoersSha = sha("sudoers");
const unitSha = sha("unit");
const sourceRenderSha = sha("runtime-source-render");
const workloadLockSha = sha("no-hosted-workload-lock");
const runtimeCandidateId = sha(stableJson({
  candidateCommit: commit,
  candidateTree: tree,
  sourceRenderSha256: sourceRenderSha,
  workloadLockSha256: workloadLockSha,
}));
const runtimeIdentity = Object.freeze({
  candidateId: runtimeCandidateId,
  commit,
  deploymentId: `v1-local-private:${runtimeCandidateId}`,
  sourceRenderSha256: sourceRenderSha,
  tree,
  workloadLockSha256: workloadLockSha,
});
const runtimeIdentityLabels = Object.freeze({
  "com.platform.runtime.candidate-id": runtimeIdentity.candidateId,
  "com.platform.runtime.commit": runtimeIdentity.commit,
  "com.platform.runtime.deployment-id": runtimeIdentity.deploymentId,
  "com.platform.runtime.source-render-sha256": runtimeIdentity.sourceRenderSha256,
  "com.platform.runtime.tree": runtimeIdentity.tree,
  "com.platform.runtime.workload-lock-sha256": runtimeIdentity.workloadLockSha256,
});
const legacyUnmanagedReasons = Object.freeze({
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
const legacyUnmanagedContainers = Object.freeze(preservedLegacy.map((containerName) => Object.freeze({
  containerName,
  reason: legacyUnmanagedReasons[containerName],
  status: "LEGACY_UNMANAGED",
})));

function canonicalDocument(value) {
  const result = { ...value };
  result.documentId = sha(stableJson(value));
  return result;
}

function writeCanonical(root, name, value) {
  const filename = path.join(root, name);
  fs.writeFileSync(filename, `${stableJson(value)}\n`, { mode: 0o600 });
  return filename;
}

function mutable(value) {
  return JSON.parse(JSON.stringify(value));
}

function recanonicalize(value) {
  delete value.documentId;
  return canonicalDocument(value);
}

function authorityFixture() {
  const value = {
    activeManagedContainerNames: activeManaged,
    artifacts: {
      composeWrapper: { path: `${releaseRoot}/scripts/compose-vps.sh`, sha256: sha("compose-wrapper") },
      controller: { path: "/usr/local/libexec/platform-v1-local-private-control", sha256: controllerSha },
      installer: { path: "/usr/local/libexec/platform-v1-brownfield-install-consumer", sha256: sha("installer") },
      reconciler: { path: "/usr/local/libexec/platform-v1-local-private-reconcile", sha256: sha("reconciler") },
      sudoers: { path: "/etc/sudoers.d/platform-v1-local-private-control", sha256: sudoersSha },
      unit: { path: "/etc/systemd/system/platform-v1-local-private-control.service", sha256: unitSha },
    },
    authorityMode: "LOCAL_PRIVATE",
    authorizedDataMutations: [{ id: "broker-auth-bootstrap-config", service: "broker-auth-bootstrap", target: "/run/platform/broker", type: "BOOTSTRAP_WRITE" }],
    backupToolImages: {
      mariadbRestore: { imageId: image("mariadb-restore"), imageReference: `registry.local/mariadb-restore@sha256:${sha("mariadb-restore-manifest")}` },
      minioRestore: { imageId: image("minio-restore"), imageReference: `registry.local/minio-restore@sha256:${sha("minio-restore-manifest")}` },
      nodeUtility: { imageId: image("node-utility"), imageReference: `registry.local/node-utility@sha256:${sha("node-utility-manifest")}` },
      postgresRestore: { imageId: image("postgres-restore"), imageReference: `registry.local/postgres-restore@sha256:${sha("postgres-restore-manifest")}` },
      resticRclone: { imageId: image("restic-rclone"), imageReference: `registry.local/restic-rclone@sha256:${sha("restic-rclone-manifest")}` },
    },
    candidateCommit: commit,
    candidateTree: tree,
    checkoutProof: { clean: true, githubMainCommit: commit, githubMainRef: "refs/remotes/github/main", headCommit: commit, headTree: tree, producer: "CLEAN_CHECKOUT_GITHUB_MAIN_V1", status: "PASS", verifiedAtUnixSeconds: 1_800_000_000 },
    controllerVerificationScope: "AUTHORITY_ARCHIVE_RELEASE_RENDER_ONLY_NOT_GITHUB",
    disabledComposeServices: ["backup-scheduler", "docker-action-activation-sidecar", "docker-action-broker"],
    evidenceProducer: {
      executor: "/usr/bin/python3", executorFlags: ["-I"],
      forbiddenResticOperations: ["forget", "prune"], hostingerAllowed: false,
      logicalKeys: ["anniversary", "fiplatform", "matthewdifilippo", "opstudents", "public", "stexor", "stream", "workcalendar", "pg-stexor", "pg-keycloak", "mariadb", "minio", "keycloak-config", "confidential"],
      offsiteRepository: "rclone:platform-onedrive:platform-infrastructure/restic",
      operations: ["pre", "post"], path: releaseRoot + "/scripts/v1-local-private-evidence-producer.py",
      recoveryEscrowPrefix: "platform-onedrive:platform-infrastructure/key-escrow",
      sha256: sha("evidence-producer"),
    },
    expectedContainerNames: canonicalNames,
    legacyNetworkAttachments: [{ aliases: ["backend"], containerName: "enterprise-backend", networkName: "platform_infra_vps_routing" }],
    legacyRouteChecks: [{ containerName: "enterprise-backend", expectedStatus: 200, name: "backend-health", url: "https://backend.local/health" }],
    legacyUnmanagedContainers,
    preservedLegacyContainerNames: preservedLegacy,
    recoveryEscrowCertificate: {
      path: `${releaseRoot}/config/local-private-recovery-escrow-cert.pem`,
      sha256: sha("recovery-certificate-pem"),
      sha256Fingerprint: sha("recovery-certificate-der"),
    },
    releaseRoot,
    renderEnvironment: { path: "/var/lib/platform-infrastructure/v1/local-private/exact-compose.env", sha256: sha("PLATFORM_COMPOSE_VARIANT=LOCAL_PRIVATE\n") },
    renderSha256: sha("render"),
    runtimeIdentity,
    schema: "platform.v1-local-private-exact-release-authority/v1",
    serviceTargets: activeManaged.map((containerName) => ({
      configHash: sha(`config:${containerName}`),
      containerName,
      project: "platform_infra_vps",
      semantic: { runtimeIdentityLabels },
      service: service(containerName),
    })),
    sourceArchiveSha256: archive,
    status: "AUTHORIZED",
  };
  return canonicalDocument(value);
}

function predecessorAuthorityFixture() {
  const value = mutable(authorityFixture());
  delete value.documentId;
  const predecessorCommit = sha("predecessor-candidate").slice(0, 40);
  const predecessorTree = sha("predecessor-tree").slice(0, 40);
  const predecessorArchive = sha("predecessor-archive");
  const predecessorRoot = `/srv/platform-infrastructure/releases/${predecessorCommit}-${predecessorArchive}`;
  const predecessorSourceRender = sha("predecessor-runtime-source-render");
  const predecessorWorkloadLock = sha("predecessor-workload-lock");
  const predecessorCandidateId = sha(stableJson({
    candidateCommit: predecessorCommit,
    candidateTree: predecessorTree,
    sourceRenderSha256: predecessorSourceRender,
    workloadLockSha256: predecessorWorkloadLock,
  }));
  const predecessorRuntimeIdentity = {
    candidateId: predecessorCandidateId,
    commit: predecessorCommit,
    deploymentId: `v1-local-private:${predecessorCandidateId}`,
    sourceRenderSha256: predecessorSourceRender,
    tree: predecessorTree,
    workloadLockSha256: predecessorWorkloadLock,
  };
  const predecessorLabels = runtimeIdentityLabels instanceof Function
    ? runtimeIdentityLabels(predecessorRuntimeIdentity)
    : {
        "com.platform.runtime.candidate-id": predecessorRuntimeIdentity.candidateId,
        "com.platform.runtime.commit": predecessorRuntimeIdentity.commit,
        "com.platform.runtime.deployment-id": predecessorRuntimeIdentity.deploymentId,
        "com.platform.runtime.source-render-sha256": predecessorRuntimeIdentity.sourceRenderSha256,
        "com.platform.runtime.tree": predecessorRuntimeIdentity.tree,
        "com.platform.runtime.workload-lock-sha256": predecessorRuntimeIdentity.workloadLockSha256,
      };
  value.candidateCommit = predecessorCommit;
  value.candidateTree = predecessorTree;
  value.sourceArchiveSha256 = predecessorArchive;
  value.releaseRoot = predecessorRoot;
  value.runtimeIdentity = predecessorRuntimeIdentity;
  value.checkoutProof = { ...value.checkoutProof, githubMainCommit: predecessorCommit, headCommit: predecessorCommit, headTree: predecessorTree };
  value.artifacts.composeWrapper.path = `${predecessorRoot}/scripts/compose-vps.sh`;
  value.artifacts.controller.sha256 = "f60c20fabeaf3f68b2478ebe31018d52d2d9a967a3598c2ac8256bc01dd33f7d";
  value.evidenceProducer.path = `${predecessorRoot}/scripts/v1-local-private-evidence-producer.py`;
  value.recoveryEscrowCertificate.path = `${predecessorRoot}/config/local-private-recovery-escrow-cert.pem`;
  for (const target of value.serviceTargets) target.semantic.runtimeIdentityLabels = predecessorLabels;
  return canonicalDocument(value);
}

function ports() {
  return [
    { containerName: "enterprise-local-dns", containerPort: 53, hostIp: "192.168.1.10", hostPort: 53, protocol: "tcp" },
    { containerName: "enterprise-local-dns", containerPort: 53, hostIp: "192.168.1.10", hostPort: 53, protocol: "udp" },
    { containerName: "enterprise-local-registry", containerPort: 5000, hostIp: "127.0.0.1", hostPort: 5000, protocol: "tcp" },
    { containerName: "enterprise-waf", containerPort: 8080, hostIp: "0.0.0.0", hostPort: 80, protocol: "tcp" },
    { containerName: "enterprise-waf", containerPort: 8443, hostIp: "0.0.0.0", hostPort: 443, protocol: "tcp" },
  ];
}

function service(name) {
  if (name === "enterprise-broker-auth-bootstrap") return "broker-auth-bootstrap";
  if (name === "enterprise-platform-alert-dispatcher") return "platform-alert-dispatcher";
  return name.replace(/^enterprise-/, "");
}

function runtimeRecord(name, reconciled) {
  const completed = name === "phppgadmin" || name === "enterprise-broker-auth-bootstrap";
  const noHealth = new Set(["enterprise-local-dns", "enterprise-local-registry", "phpmyadmin"]);
  const record = {
    configHash: sha(`config:${name}`),
    containerId: sha(`container:${name}`),
    exitCode: 0,
    health: completed || noHealth.has(name) ? "none" : "healthy",
    imageAvailability: name === "enterprise-backup-scheduler" ? "RECOVERY_IMAGE_EXPORT_BOUND" : "LOCAL_IMAGE_STORE",
    imageId: image(name),
    name,
    project: name === "node-opstudents" ? "opstudents" : "platform_infra_vps",
    service: service(name),
    state: completed ? "exited" : "running",
  };
  if (reconciled) Object.assign(record, {
    imageReference: `registry.local/${name}@sha256:${sha(`manifest:${name}`)}`,
    networkMembership: [{ aliases: [service(name)], networkName: "enterprise_net" }],
    runtimeConfigSha256: sha(`runtime-config:${name}`),
    semanticSha256: sha(`semantic:${name}`),
  });
  return record;
}

const transitionIdentity = (record) => ({
  configHash: record.configHash,
  containerId: record.containerId,
  imageId: record.imageId,
  imageReference: record.imageReference,
  name: record.name,
  runtimeConfigSha256: record.runtimeConfigSha256,
});

function recovery(scheduler, candidateCommit = commit) {
  const recoveryImage = image("scheduler-recovery");
  return {
    archiveFormat: "OCI_DOCKER_SAVE_V1",
    configDigest: image("scheduler-recovery-config"),
    configHash: scheduler.configHash,
    containerId: scheduler.containerId,
    containerName: "enterprise-backup-scheduler",
    exportLabels: {
      "com.platform.v1.local-private.candidate-commit": candidateCommit,
      "com.platform.v1.local-private.scheduler-config-hash": scheduler.configHash,
      "com.platform.v1.local-private.scheduler-container-id": scheduler.containerId,
      "com.platform.v1.local-private.scheduler-running-image-id": scheduler.imageId,
    },
    exportPath: "/var/lib/platform-infrastructure/v1/predeploy/current/scheduler-recovery-image.tar",
    exportSha256: sha("recovery-export"),
    exportSizeBytes: 4096,
    imageIndexDigest: recoveryImage,
    imageIndexPath: `blobs/sha256/${recoveryImage.slice(7)}`,
    imageManifestDigest: image("scheduler-recovery-manifest"),
    manifestConfig: `blobs/sha256/${sha("scheduler-recovery-config")}`,
    recoveryImageId: recoveryImage,
    recoveryTag: `platform/v1-scheduler-recovery:${candidateCommit}`,
    runningImageId: scheduler.imageId,
    status: "RECOVERY_IMAGE_EXPORT_BOUND",
  };
}

function commonReceipt(containers, schedulerRecovery) {
  return {
    activatedAtUnixSeconds: 1_800_000_100,
    authorityMode: "LOCAL_PRIVATE",
    candidateCommit: commit,
    candidateTree: tree,
    checkpointSha256: sha("checkpoint"),
    containerRecreate: false,
    controller: { installedPath: "/usr/local/libexec/platform-v1-local-private-control", sha256: controllerSha, unitPath: "/etc/systemd/system/platform-v1-local-private-control.service", unitSha256: unitSha },
    dataMutation: false,
    dockerControlPlane: { mode: "LOCAL_ROOT_SYSTEMD_SUPERVISOR", providerBrokerStatus: "READY_BUT_DISABLED", service: "platform-v1-local-private-control.service", status: "ACTIVE" },
    dockerMutation: false,
    externalDependencies: [
      { name: "HOSTINGER", status: "NOT_REQUIRED" }, { name: "CLOUDFLARE", status: "NOT_REQUIRED" },
      { name: "PUBLIC_DNS", status: "READY_BUT_DISABLED" }, { name: "EXTERNAL_DAST", status: "READY_BUT_DISABLED" },
      { name: "SIGSTORE_PROMOTION", status: "READY_BUT_DISABLED" }, { name: "PUBLIC_PROVIDER", status: "READY_BUT_DISABLED" },
    ],
    hostControlMutation: true,
    installReceiptSha256: sha("install"),
    localArtifactTrust: {
      mode: "LOCAL_DOCKER_IMMUTABLE_IMAGE_ID",
      schedulerRecovery,
      status: "PASS",
      subjects: containers.map(({ configHash, containerId, imageAvailability, imageId, name }) => ({ configHash, containerId, imageAvailability, imageId, name })),
    },
    mutationModel: "ADDITIVE_ADOPTION",
    mutationPerformed: true,
    networkIsolation: { policy: "EDGE_PUBLISHED_PORT_ALLOWLIST", publishedPorts: ports(), status: "PASS" },
    providerComponents: [
      { name: "PROVIDER_DOCKER_ACTION_ACTIVATION_SIDECAR", status: "READY_BUT_DISABLED" },
      { name: "PROVIDER_DOCKER_ACTION_BROKER", status: "READY_BUT_DISABLED" },
      { name: "PROVIDER_SOCKETLESS_BACKUP_SCHEDULER", status: "READY_BUT_DISABLED" },
    ],
    readyButDisabled,
    releaseRoot,
    runtime: {
      containerCount: containers.length,
      containers,
      daemon: { dockerRootDir: "/var/lib/docker", id: "daemon", name: "server", serverVersion: "29.0.0" },
      exitedCount: containers.filter((item) => item.state === "exited").length,
      rawDockerAuthority: { containerId: schedulerRecovery.containerId, name: "enterprise-backup-scheduler", readOnly: false, source: "/var/run/docker.sock", status: "PASS", target: "/var/run/docker.sock" },
      runningCount: containers.filter((item) => item.state === "running").length,
    },
    schema: "platform.v1-local-private-control-receipt/v1",
    sourceArchiveSha256: archive,
    status: "ACTIVE",
    supervisor: { active: true, enabled: true, service: "platform-v1-local-private-control.service", status: "ACTIVE", type: "ROOT_SYSTEMD_NOTIFY" },
  };
}

function historicFixture() {
  const containers = historicNames.map((name) => runtimeRecord(name, false));
  const scheduler = containers.find((item) => item.name === "enterprise-backup-scheduler");
  return canonicalDocument(commonReceipt(containers, recovery(scheduler)));
}

function reconciledFixture(authoritySha, { noOp = false } = {}) {
  const containers = canonicalNames.map((name) => runtimeRecord(name, true));
  const scheduler = runtimeRecord("enterprise-backup-scheduler", true);
  const previous = new Map(containers.map((item) => [item.name, transitionIdentity(item)]));
  if (!noOp) {
    previous.delete("enterprise-broker-auth-bootstrap");
    previous.delete("enterprise-platform-alert-dispatcher");
  }
  const transitions = containers.map((item) => {
    const current = transitionIdentity(item);
    const before = previous.get(item.name) ?? null;
    return { current, previous: before, service: item.service, status: before === null ? "CREATED" : "RETAINED" };
  });
  if (!noOp) transitions.push({ current: null, previous: transitionIdentity(scheduler), service: "backup-scheduler", status: "REMOVED" });
  transitions.sort((left, right) => (left.current ?? left.previous).name.localeCompare((right.current ?? right.previous).name));
  const dataEvidenceSha = sha("data-mutation");
  const dataMutations = noOp ? [] : [{ authorityId: "broker-auth-bootstrap-config", evidencePath: `/var/lib/platform-infrastructure/v1/local-private/data-mutation-evidence/${authorityFixture().documentId}-broker-auth-bootstrap-config-${dataEvidenceSha}.json`, evidenceSha256: dataEvidenceSha }];
  const external = {
    authority: "ROOT_OPERATOR_EXPLICIT_V1_RECONCILIATION",
    beganAtUnixSeconds: 1_800_000_000,
    containerRecreate: !noOp,
    controllerDockerMutation: false,
    dataMutation: dataMutations.length > 0,
    dataMutations,
    dataMutationsSha256: sha(stableJson(dataMutations)),
    externalDockerMutation: !noOp,
    legacyNetworkAttachments: [],
    legacyNetworkAttachmentsSha256: sha(stableJson([])),
    legacyUnmanagedContainers,
    previousReceiptDocumentId: sha("previous-receipt"),
    releaseAuthorityDocumentId: authorityFixture().documentId,
    releaseAuthoritySha256: authoritySha,
    runtimeEvidenceSha256: sha("runtime-evidence"),
    runtimeIdentity,
    serviceTransitions: transitions,
    serviceTransitionsSha256: sha(stableJson(transitions)),
    status: "SEALED",
  };
  const receipt = commonReceipt(containers, recovery(scheduler));
  receipt.controller = {
    ...receipt.controller,
    sudoersPath: "/etc/sudoers.d/platform-v1-local-private-control",
    sudoersSha256: sudoersSha,
  };
  receipt.externalAuthorizedReconciliation = external;
  receipt.containerRecreate = external.containerRecreate;
  receipt.dataMutation = external.dataMutation;
  receipt.dockerMutation = external.externalDockerMutation;
  receipt.mutationModel = "EXTERNAL_AUTHORIZED_RECONCILIATION";
  receipt.runtime.rawDockerAuthority = { mode: "NONE", owners: [], status: "PASS" };
  return canonicalDocument(receipt);
}

function abortBindingFixture(root, authority) {
  const authoritySha = sha(`${stableJson(authority)}\n`);
  const record = {
    authorityDocumentId: authority.documentId,
    authoritySha256: authoritySha,
    completedAtUnixSeconds: 1_800_000_200,
    journalSha256: sha("aborted-journal"),
    residualDataMutations: [],
    residualDataMutationsSha256: sha(stableJson([])),
    schema: "platform.v1-local-private-reconciliation-abort-record/v1",
    status: "ABORTED_NO_DATA_MUTATION",
    transactionId: sha("aborted-transaction"),
  };
  const recordBytes = `${stableJson(record)}\n`;
  const recordSha256 = sha(recordBytes);
  const recordPath = `/var/lib/platform-infrastructure/v1/local-private/aborted-reconciliations/${record.transactionId}-${recordSha256}.json`;
  const physical = `${root}${recordPath}`;
  fs.mkdirSync(path.dirname(physical), { recursive: true });
  fs.writeFileSync(physical, recordBytes, { mode: 0o444 });
  return { ...record, recordPath, recordSha256 };
}

function mixedGenerationAbortedFixture(root, currentAuthority, predecessorAuthority) {
  const predecessorAuthoritySha = sha(`${stableJson(predecessorAuthority)}\n`);
  const receipt = mutable(reconciledFixture(predecessorAuthoritySha, { noOp: true }));
  delete receipt.documentId;
  const external = receipt.externalAuthorizedReconciliation;
  external.releaseAuthorityDocumentId = predecessorAuthority.documentId;
  external.releaseAuthoritySha256 = predecessorAuthoritySha;
  external.runtimeIdentity = predecessorAuthority.runtimeIdentity;
  for (const transition of external.serviceTransitions) {
    if (transition.current) transition.current.runtimeConfigSha256 = sha(`legacy-19:${transition.current.name}`);
    if (transition.previous) transition.previous.runtimeConfigSha256 = sha(`legacy-19:${transition.previous.name}`);
  }
  external.serviceTransitionsSha256 = sha(stableJson(external.serviceTransitions));
  const predecessorCommit = predecessorAuthority.candidateCommit;
  const recoveryBinding = receipt.localArtifactTrust.schedulerRecovery;
  recoveryBinding.exportLabels["com.platform.v1.local-private.candidate-commit"] = predecessorCommit;
  recoveryBinding.recoveryTag = `platform/v1-scheduler-recovery:${predecessorCommit}`;
  receipt.abortedAuthorizedReconciliation = abortBindingFixture(root, currentAuthority);
  receipt.predecessorRuntimeProvenance = {
    candidateCommit: predecessorAuthority.candidateCommit,
    candidateTree: predecessorAuthority.candidateTree,
    controllerIdentityProjection: "LEGACY_19",
    controllerSha256: predecessorAuthority.artifacts.controller.sha256,
    profile: "CANONICAL_RECONCILED_V1",
    releaseRoot: predecessorAuthority.releaseRoot,
    sourceArchiveSha256: predecessorAuthority.sourceArchiveSha256,
  };
  receipt.mutationModel = "ABORTED_EXTERNAL_AUTHORIZED_RECONCILIATION";
  return canonicalDocument(receipt);
}

test("closed V1 inventory is 36 total, 17 active managed, and 19 preserved legacy", () => {
  assert.equal(canonicalNames.length, 36);
  assert.equal(activeManaged.length, 17);
  assert.equal(preservedLegacy.length, 19);
  assert.equal(canonicalNames.includes("enterprise-backup-scheduler"), false);
  assert.equal(canonicalNames.includes("enterprise-platform-alert-dispatcher"), true);
});

test("historical V1 receipt remains verifiable without a new protocol", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-control-"));
  try {
    const file = writeCanonical(root, "receipt.json", historicFixture());
    assert.equal(verifyV1LocalPrivateControlReceipt({ file, candidateCommit: commit, candidateTree: tree, sourceArchiveSha256: archive, controllerSha256: controllerSha, unitSha256: unitSha }).schema, "platform.v1-local-private-control-receipt/v1");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("reconciled V1 receipt binds authority, scheduler removal, raw NONE, and mutation truth", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-control-"));
  try {
    const authority = authorityFixture();
    const authorityFile = writeCanonical(root, "authority.json", authority);
    const authoritySha = sha(`${stableJson(authority)}\n`);
    const receipt = reconciledFixture(authoritySha);
    const file = writeCanonical(root, "receipt.json", receipt);
    const verified = verifyV1LocalPrivateControlReceipt({ file, authorityFile });
    assert.equal(verified.schema, "platform.v1-local-private-control-receipt/v1");
    assert.equal(verified.runtime.rawDockerAuthority.mode, "NONE");
    assert.equal(verified.externalAuthorizedReconciliation.serviceTransitions.some((item) => item.status === "REMOVED" && item.previous.name === "enterprise-backup-scheduler"), true);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("repeated no-op V1 reconciliation is accepted with all mutation booleans false", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-control-"));
  try {
    const authority = authorityFixture();
    const authorityFile = writeCanonical(root, "authority.json", authority);
    const receipt = reconciledFixture(sha(`${stableJson(authority)}\n`), { noOp: true });
    const file = writeCanonical(root, "receipt.json", receipt);
    const verified = verifyV1LocalPrivateControlReceipt({ file, authorityFile });
    assert.equal(verified.containerRecreate, false);
    assert.equal(verified.dockerMutation, false);
    assert.equal(verified.dataMutation, false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("mixed-generation aborted receipt binds current control authority and registered predecessor runtime provenance", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-control-mixed-abort-"));
  try {
    const currentAuthority = authorityFixture();
    const predecessorAuthority = predecessorAuthorityFixture();
    const authorityFile = writeCanonical(root, "current-authority.json", currentAuthority);
    const predecessorAuthorityFile = writeCanonical(root, "predecessor-authority.json", predecessorAuthority);
    const receipt = mixedGenerationAbortedFixture(root, currentAuthority, predecessorAuthority);
    const file = writeCanonical(root, "mixed-aborted-receipt.json", receipt);
    const abortRecordFile = `${root}${receipt.abortedAuthorizedReconciliation.recordPath}`;
    const verified = verifyV1LocalPrivateControlReceipt({
      file, authorityFile, predecessorAuthorityFile, abortRecordFile,
    });
    assert.equal(verified.candidateCommit, currentAuthority.candidateCommit);
    assert.equal(verified.externalAuthorizedReconciliation.runtimeIdentity.commit, predecessorAuthority.candidateCommit);
    assert.equal(
      verified.localArtifactTrust.schedulerRecovery.exportLabels["com.platform.v1.local-private.candidate-commit"],
      predecessorAuthority.candidateCommit,
    );
    assert.throws(
      () => verifyV1LocalPrivateControlReceipt({ file, authorityFile, abortRecordFile }),
      /requires --predecessorAuthorityFile/,
    );

    const falseRecovery = mutable(receipt);
    falseRecovery.localArtifactTrust.schedulerRecovery.exportLabels["com.platform.v1.local-private.candidate-commit"] = currentAuthority.candidateCommit;
    falseRecovery.localArtifactTrust.schedulerRecovery.recoveryTag = `platform/v1-scheduler-recovery:${currentAuthority.candidateCommit}`;
    const falseRecoveryFile = writeCanonical(root, "false-recovery-provenance.json", recanonicalize(falseRecovery));
    assert.throws(
      () => verifyV1LocalPrivateControlReceipt({ file: falseRecoveryFile, authorityFile, predecessorAuthorityFile, abortRecordFile }),
      /runtime-provenance-bound/,
    );

    const unknownProjection = mutable(receipt);
    unknownProjection.predecessorRuntimeProvenance.controllerSha256 = sha("unregistered-controller");
    const unknownProjectionFile = writeCanonical(root, "unknown-projection.json", recanonicalize(unknownProjection));
    assert.throws(
      () => verifyV1LocalPrivateControlReceipt({ file: unknownProjectionFile, authorityFile, predecessorAuthorityFile, abortRecordFile }),
      /projection is unregistered/,
    );

    const commonIdentityDrift = mutable(receipt);
    const runtime = commonIdentityDrift.runtime.containers.find((item) => item.name === "enterprise-control-center");
    runtime.containerId = sha("foreign-common-container-id");
    commonIdentityDrift.localArtifactTrust.subjects.find((item) => item.name === runtime.name).containerId = runtime.containerId;
    const commonIdentityDriftFile = writeCanonical(root, "common-identity-drift.json", recanonicalize(commonIdentityDrift));
    assert.throws(
      () => verifyV1LocalPrivateControlReceipt({ file: commonIdentityDriftFile, authorityFile, predecessorAuthorityFile, abortRecordFile }),
      /Transition current identity differs from runtime/,
    );

    const corruptedAbortRecordFile = writeCanonical(root, "corrupted-abort-record.json", {
      status: "ABORTED_NO_DATA_MUTATION",
    });
    assert.throws(
      () => verifyV1LocalPrivateControlReceipt({ file, authorityFile, predecessorAuthorityFile, abortRecordFile: corruptedAbortRecordFile }),
      /missing or unexpected fields|bytes differ/,
    );
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("legacy-dispatcher historical abort remains a closed ACTIVE receipt with predecessor-bound recovery", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-control-legacy-abort-"));
  try {
    const currentAuthority = authorityFixture();
    const predecessorAuthority = predecessorAuthorityFixture();
    const authorityFile = writeCanonical(root, "current-authority.json", currentAuthority);
    const receipt = mutable(historicFixture());
    delete receipt.documentId;
    receipt.runtime.containers.push(runtimeRecord("enterprise-alert-dispatcher", false));
    receipt.runtime.containers.sort((left, right) => left.name.localeCompare(right.name));
    receipt.runtime.containerCount = receipt.runtime.containers.length;
    receipt.runtime.runningCount = receipt.runtime.containers.filter((item) => item.state === "running").length;
    receipt.localArtifactTrust.subjects = receipt.runtime.containers.map(
      ({ configHash, containerId, imageAvailability, imageId, name }) => ({ configHash, containerId, imageAvailability, imageId, name }),
    );
    receipt.controller = {
      ...receipt.controller,
      sudoersPath: "/etc/sudoers.d/platform-v1-local-private-control",
      sudoersSha256: sudoersSha,
    };
    const predecessorCommit = predecessorAuthority.candidateCommit;
    receipt.localArtifactTrust.schedulerRecovery.exportLabels["com.platform.v1.local-private.candidate-commit"] = predecessorCommit;
    receipt.localArtifactTrust.schedulerRecovery.recoveryTag = `platform/v1-scheduler-recovery:${predecessorCommit}`;
    receipt.abortedAuthorizedReconciliation = abortBindingFixture(root, currentAuthority);
    receipt.predecessorRuntimeProvenance = {
      candidateCommit: predecessorAuthority.candidateCommit,
      candidateTree: predecessorAuthority.candidateTree,
      controllerIdentityProjection: "LEGACY_19",
      controllerSha256: predecessorAuthority.artifacts.controller.sha256,
      profile: "HISTORICAL_V1",
      releaseRoot: predecessorAuthority.releaseRoot,
      sourceArchiveSha256: predecessorAuthority.sourceArchiveSha256,
    };
    receipt.mutationModel = "ABORTED_EXTERNAL_AUTHORIZED_RECONCILIATION";
    const value = canonicalDocument(receipt);
    const file = writeCanonical(root, "legacy-aborted-receipt.json", value);
    const abortRecordFile = `${root}${value.abortedAuthorizedReconciliation.recordPath}`;
    const verified = verifyV1LocalPrivateControlReceipt({ file, authorityFile, abortRecordFile });
    assert.equal(verified.runtime.containers.some((item) => item.name === "enterprise-alert-dispatcher"), true);
    assert.equal(
      verified.localArtifactTrust.schedulerRecovery.exportLabels["com.platform.v1.local-private.candidate-commit"],
      predecessorCommit,
    );

    const unbound = mutable(value);
    delete unbound.predecessorRuntimeProvenance;
    const unboundFile = writeCanonical(root, "legacy-unbound-abort.json", recanonicalize(unbound));
    assert.throws(
      () => verifyV1LocalPrivateControlReceipt({ file: unboundFile, authorityFile, abortRecordFile }),
      /runtime-provenance-bound/,
    );
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("transition evidence rejects runtime digest drift across aligned controller and reconciler domains", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-control-"));
  try {
    const authority = authorityFixture();
    const authorityFile = writeCanonical(root, "authority.json", authority);
    const authoritySha = sha(`${stableJson(authority)}\n`);
    const receipt = mutable(reconciledFixture(authoritySha, { noOp: true }));
    const transition = receipt.externalAuthorizedReconciliation.serviceTransitions.find((item) => item.current?.name === "enterprise-control-center");
    transition.current.runtimeConfigSha256 = sha("foreign-current-runtime-config");
    receipt.externalAuthorizedReconciliation.serviceTransitionsSha256 = sha(stableJson(receipt.externalAuthorizedReconciliation.serviceTransitions));
    const file = writeCanonical(root, "current-digest-drift.json", recanonicalize(receipt));
    assert.throws(
      () => verifyV1LocalPrivateControlReceipt({ file, authorityFile }),
      /Transition current identity differs from runtime/,
    );

    const previousDrift = mutable(reconciledFixture(authoritySha, { noOp: true }));
    const previousTransition = previousDrift.externalAuthorizedReconciliation.serviceTransitions.find((item) => item.current?.name === "enterprise-control-center");
    previousTransition.previous.runtimeConfigSha256 = sha("foreign-previous-runtime-config");
    previousDrift.externalAuthorizedReconciliation.serviceTransitionsSha256 = sha(stableJson(previousDrift.externalAuthorizedReconciliation.serviceTransitions));
    const previousFile = writeCanonical(root, "previous-digest-drift.json", recanonicalize(previousDrift));
    assert.throws(() => verifyV1LocalPrivateControlReceipt({ file: previousFile, authorityFile }), /Service transition status is false/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("transition status remains fail-closed for every stable identity discriminator", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-control-"));
  try {
    const authority = authorityFixture();
    const authorityFile = writeCanonical(root, "authority.json", authority);
    const authoritySha = sha(`${stableJson(authority)}\n`);
    const drifts = {
      configHash: sha("foreign-transition-config"),
      containerId: sha("foreign-transition-container"),
      imageId: image("foreign-transition-image"),
      imageReference: `registry.local/foreign@sha256:${sha("foreign-transition-manifest")}`,
      runtimeConfigSha256: sha("foreign-transition-runtime-config"),
    };
    for (const [field, value] of Object.entries(drifts)) {
      const receipt = mutable(reconciledFixture(authoritySha, { noOp: true }));
      const transition = receipt.externalAuthorizedReconciliation.serviceTransitions.find((item) => item.current?.name === "enterprise-control-center");
      transition.previous[field] = value;
      receipt.externalAuthorizedReconciliation.serviceTransitionsSha256 = sha(stableJson(receipt.externalAuthorizedReconciliation.serviceTransitions));
      const file = writeCanonical(root, `stable-drift-${field}.json`, recanonicalize(receipt));
      assert.throws(
        () => verifyV1LocalPrivateControlReceipt({ file, authorityFile }),
        /Service transition status is false/,
        field,
      );
    }

    const renamed = mutable(reconciledFixture(authoritySha, { noOp: true }));
    const dispatcher = renamed.externalAuthorizedReconciliation.serviceTransitions.find((item) => item.current?.name === "enterprise-platform-alert-dispatcher");
    dispatcher.previous.name = "enterprise-alert-dispatcher";
    renamed.externalAuthorizedReconciliation.serviceTransitionsSha256 = sha(stableJson(renamed.externalAuthorizedReconciliation.serviceTransitions));
    const renamedFile = writeCanonical(root, "stable-drift-name.json", recanonicalize(renamed));
    assert.throws(
      () => verifyV1LocalPrivateControlReceipt({ file: renamedFile, authorityFile }),
      /Service transition status is false/,
      "name",
    );
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("transition replacement accepts only the declared legacy dispatcher predecessor", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-control-"));
  try {
    const authority = authorityFixture();
    const authorityFile = writeCanonical(root, "authority.json", authority);
    const authoritySha = sha(`${stableJson(authority)}\n`);
    const receipt = mutable(reconciledFixture(authoritySha, { noOp: true }));
    const dispatcher = receipt.externalAuthorizedReconciliation.serviceTransitions.find((item) => item.current?.name === "enterprise-platform-alert-dispatcher");
    dispatcher.previous.name = "enterprise-alert-dispatcher";
    dispatcher.status = "REPLACED";
    receipt.externalAuthorizedReconciliation.containerRecreate = true;
    receipt.externalAuthorizedReconciliation.externalDockerMutation = true;
    receipt.externalAuthorizedReconciliation.serviceTransitionsSha256 = sha(stableJson(receipt.externalAuthorizedReconciliation.serviceTransitions));
    receipt.containerRecreate = true;
    receipt.dockerMutation = true;
    const allowedFile = writeCanonical(root, "declared-dispatcher-replacement.json", recanonicalize(receipt));
    assert.equal(
      verifyV1LocalPrivateControlReceipt({ file: allowedFile, authorityFile }).externalAuthorizedReconciliation.containerRecreate,
      true,
    );

    const undeclared = mutable(receipt);
    undeclared.externalAuthorizedReconciliation.serviceTransitions.find((item) => item.current?.name === "enterprise-platform-alert-dispatcher").previous.name = "enterprise-undeclared-dispatcher";
    undeclared.externalAuthorizedReconciliation.serviceTransitionsSha256 = sha(stableJson(undeclared.externalAuthorizedReconciliation.serviceTransitions));
    const undeclaredFile = writeCanonical(root, "undeclared-dispatcher-replacement.json", recanonicalize(undeclared));
    assert.throws(
      () => verifyV1LocalPrivateControlReceipt({ file: undeclaredFile, authorityFile }),
      /Transition previous identity is not a declared predecessor/,
    );
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("transition current binding rejects stable identity drift across domains", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-control-"));
  try {
    const authority = authorityFixture();
    const authorityFile = writeCanonical(root, "authority.json", authority);
    const authoritySha = sha(`${stableJson(authority)}\n`);
    const drifts = {
      configHash: sha("foreign-current-config"),
      containerId: sha("foreign-current-container"),
      imageId: image("foreign-current-image"),
      imageReference: `registry.local/foreign-current@sha256:${sha("foreign-current-manifest")}`,
      name: "enterprise-control-center-foreign",
    };
    for (const [field, value] of Object.entries(drifts)) {
      const receipt = mutable(reconciledFixture(authoritySha, { noOp: true }));
      const transition = receipt.externalAuthorizedReconciliation.serviceTransitions.find((item) => item.current?.name === "enterprise-control-center");
      transition.current[field] = value;
      receipt.externalAuthorizedReconciliation.serviceTransitionsSha256 = sha(stableJson(receipt.externalAuthorizedReconciliation.serviceTransitions));
      const file = writeCanonical(root, `unbound-current-${field}.json`, recanonicalize(receipt));
      assert.throws(
        () => verifyV1LocalPrivateControlReceipt({ file, authorityFile }),
        /Transition current identity differs from runtime/,
        field,
      );
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("transition runtime digests remain shape-validated in both domains", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-control-"));
  try {
    const authority = authorityFixture();
    const authorityFile = writeCanonical(root, "authority.json", authority);
    const authoritySha = sha(`${stableJson(authority)}\n`);
    for (const [name, mutate] of [
      ["malformed-previous", (receipt, transition) => { transition.previous.runtimeConfigSha256 = "not-a-sha256"; }],
      ["malformed-current", (receipt, transition) => { transition.current.runtimeConfigSha256 = "not-a-sha256"; }],
      ["malformed-runtime", (receipt) => { receipt.runtime.containers.find((item) => item.name === "enterprise-control-center").runtimeConfigSha256 = "not-a-sha256"; }],
    ]) {
      const receipt = mutable(reconciledFixture(authoritySha, { noOp: true }));
      const transition = receipt.externalAuthorizedReconciliation.serviceTransitions.find((item) => item.current?.name === "enterprise-control-center");
      mutate(receipt, transition);
      receipt.externalAuthorizedReconciliation.serviceTransitionsSha256 = sha(stableJson(receipt.externalAuthorizedReconciliation.serviceTransitions));
      const file = writeCanonical(root, `${name}.json`, recanonicalize(receipt));
      assert.throws(
        () => verifyV1LocalPrivateControlReceipt({ file, authorityFile }),
        /runtime config is not one lowercase SHA-256/,
        name,
      );
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("reconciled verifier rejects malformed managed authority scope and runtime labels", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-control-"));
  try {
    const mutations = [
      (authority) => { delete authority.legacyUnmanagedContainers; },
      (authority) => { authority.legacyUnmanagedContainers[0].reason = "CALLER_ASSERTED"; },
      (authority) => { authority.runtimeIdentity.unexpected = true; },
      (authority) => { authority.runtimeIdentity.candidateId = sha("foreign-runtime-candidate"); },
      (authority) => { delete authority.serviceTargets[0].configHash; },
      (authority) => { authority.serviceTargets[0].configHash = "not-a-sha256"; },
      (authority) => { delete authority.serviceTargets[0].semantic.runtimeIdentityLabels["com.platform.runtime.candidate-id"]; },
      (authority) => { authority.serviceTargets[0].semantic.runtimeIdentityLabels["com.platform.runtime.candidate-id"] = sha("foreign-runtime-label"); },
      (authority) => { authority.serviceTargets[0].semantic.runtimeIdentityLabels.unexpected = "value"; },
    ];
    for (const [index, mutate] of mutations.entries()) {
      const authority = mutable(authorityFixture());
      mutate(authority);
      const authorityFile = writeCanonical(root, `bad-authority-${index}.json`, recanonicalize(authority));
      const receipt = reconciledFixture(sha(`${stableJson(authority)}\n`));
      const receiptFile = writeCanonical(root, `receipt-for-bad-authority-${index}.json`, receipt);
      assert.throws(() => verifyV1LocalPrivateControlReceipt({ file: receiptFile, authorityFile }));
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("reconciled verifier exact-binds external legacy/runtime scope and managed config hashes", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-control-"));
  try {
    const authority = authorityFixture();
    const authorityFile = writeCanonical(root, "authority.json", authority);
    const authoritySha = sha(`${stableJson(authority)}\n`);
    for (const [index, mutate] of [
      (external) => { external.legacyUnmanagedContainers[0].reason = "CALLER_ASSERTED"; },
      (external) => { external.runtimeIdentity.workloadLockSha256 = sha("foreign-runtime-lock"); },
      (external) => { delete external.runtimeIdentity; },
      (external) => { external.unexpected = true; },
    ].entries()) {
      const receipt = mutable(reconciledFixture(authoritySha));
      mutate(receipt.externalAuthorizedReconciliation);
      const file = writeCanonical(root, `bad-external-${index}.json`, recanonicalize(receipt));
      assert.throws(() => verifyV1LocalPrivateControlReceipt({ file, authorityFile }));
    }

    const receipt = mutable(reconciledFixture(authoritySha, { noOp: true }));
    const containerName = "enterprise-control-center";
    const foreignConfigHash = sha("foreign-managed-config");
    receipt.runtime.containers.find((item) => item.name === containerName).configHash = foreignConfigHash;
    receipt.localArtifactTrust.subjects.find((item) => item.name === containerName).configHash = foreignConfigHash;
    const transition = receipt.externalAuthorizedReconciliation.serviceTransitions.find((item) => item.current?.name === containerName);
    transition.current.configHash = foreignConfigHash;
    transition.previous.configHash = foreignConfigHash;
    receipt.externalAuthorizedReconciliation.serviceTransitionsSha256 = sha(stableJson(receipt.externalAuthorizedReconciliation.serviceTransitions));
    const file = writeCanonical(root, "bad-managed-config.json", recanonicalize(receipt));
    assert.throws(
      () => verifyV1LocalPrivateControlReceipt({ file, authorityFile }),
      /Managed runtime service differs from its exact authority target/,
    );
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("reconciled verifier rejects legacy dispatcher, scheduler, and preserved legacy recreate", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-control-"));
  try {
    const authority = authorityFixture();
    const authorityFile = writeCanonical(root, "authority.json", authority);
    const authoritySha = sha(`${stableJson(authority)}\n`);
    for (const mutate of [
      (receipt) => { receipt.runtime.containers.find((item) => item.name === "enterprise-platform-alert-dispatcher").name = "enterprise-alert-dispatcher"; },
      (receipt) => { receipt.runtime.containers.push(runtimeRecord("enterprise-backup-scheduler", true)); receipt.runtime.containerCount += 1; },
      (receipt) => { receipt.externalAuthorizedReconciliation.serviceTransitions.find((item) => item.current?.name === "enterprise-backend").status = "RECREATED"; },
    ]) {
      const receipt = reconciledFixture(authoritySha);
      mutate(receipt);
      delete receipt.documentId;
      receipt.documentId = sha(stableJson(receipt));
      const file = writeCanonical(root, `bad-${Math.random()}.json`, receipt);
      assert.throws(() => verifyV1LocalPrivateControlReceipt({ file, authorityFile }));
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("controller and tests contain no unapproved V2 or stale symbolic target authority", () => {
  const root = path.resolve(import.meta.dirname, "..");
  const forbidden = ["PINNED_" + "EXACT_MAIN_V1", "/v" + "2", "832bf2baec47055342af" + "7e7f73425444381b91e0"];
  for (const name of ["scripts/v1-local-private-control.py", "scripts/v1-local-private-control-receipt.mjs", "sudoers/platform-v1-local-private-control"]) {
    let source = fs.readFileSync(path.join(root, name), "utf8");
    if (name === "scripts/v1-local-private-control.py") {
      const validationCheckpointV2 = 'VALIDATION_CHECKPOINT_SCHEMA = "platform.v1-local-private-predeploy-checkpoint-validation/v2"';
      assert.equal(source.split(validationCheckpointV2).length, 2);
      source = source.replace(validationCheckpointV2, "");
    }
    for (const token of forbidden) assert.equal(source.includes(token), false);
  }
});
