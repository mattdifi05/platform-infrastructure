import crypto from "node:crypto";

export const REQUEST_SCHEMA = "platform.docker-action.request/v2";
export const RUNTIME_INTENT_SCHEMA = "platform.docker-runtime-intent/v1";
export const ACTIVE_RECEIPT_SCHEMA = "platform.docker-active-receipt/v2";
export const RESPONSE_SCHEMA = "platform.docker-action.response/v2";
export const RESULT_SCHEMA = "platform.docker-action.result/v2";
export const MAX_REQUEST_BYTES = 16 * 1024;
export const MAX_CLOCK_SKEW_MS = 30_000;
export const MAX_REQUEST_LIFETIME_MS = 60_000;
export const MAX_PHASE_OUTPUT_BYTES = 4096;

export const SCHEDULER_ACTIONS = deepFreeze({
  "backup.catalog": Object.freeze({
    capabilityId: "backup.catalog.v2",
    capabilityFile: "/run/secrets/docker_action_backup_catalog",
    profileId: "scheduler.backup.catalog.v2",
    modeled: true,
    workerCommand: "backup-catalog",
    parameters: Object.freeze([]),
  }),
  "backup.job.execute": Object.freeze({
    capabilityId: "backup.job.execute.v2",
    capabilityFile: "/run/secrets/docker_action_backup_job_execute",
    profileId: "scheduler.backup.job.execute.v2",
    modeled: true,
    workerCommand: "backup-job",
    parameters: Object.freeze(["jobFileName", "jobId", "jobOperation", "jobSha256"]),
  }),
  "backup.prune.plan": Object.freeze({
    capabilityId: "backup.prune.plan.v2",
    capabilityFile: "/run/secrets/docker_action_backup_prune_plan",
    profileId: "scheduler.backup.prune.plan.v2",
    modeled: true,
    workerCommand: "backup-prune-plan",
    parameters: Object.freeze([]),
  }),
  "backup.prune.apply": Object.freeze({
    capabilityId: "backup.prune.apply.v2",
    capabilityFile: "/run/secrets/docker_action_backup_prune_apply",
    profileId: "scheduler.backup.prune.apply.v2",
    modeled: true,
    workerCommand: "backup-prune-apply",
    parameters: Object.freeze([]),
  }),
  "restore.drill.full": Object.freeze({
    capabilityId: "restore.drill.full.v2",
    capabilityFile: "/run/secrets/docker_action_restore_drill_full",
    profileId: "scheduler.restore.drill.full.v2",
    modeled: true,
    workerCommand: "restore-drill-full",
    parameters: Object.freeze([]),
  }),
  "backup.offsite.sync": Object.freeze({
    capabilityId: "backup.offsite.sync.v2",
    capabilityFile: "/run/secrets/docker_action_backup_offsite_sync",
    profileId: "scheduler.backup.offsite.sync.v2",
    modeled: true,
    workerCommand: "backup-offsite-sync",
    parameters: Object.freeze([]),
  }),
});

export const EVIDENCE_ACTIONS = deepFreeze({
  "evidence.runtime.snapshot": Object.freeze({
    capabilityId: "evidence.runtime.snapshot.v2",
    capabilityFile: "/run/secrets/docker_action_evidence_runtime_snapshot",
    profileId: "evidence.runtime.snapshot.v2",
    engineAction: "runtimeSnapshot",
    modeled: true,
    parameters: Object.freeze([]),
  }),
});

export const ACTIONS = Object.freeze({ ...SCHEDULER_ACTIONS, ...EVIDENCE_ACTIONS });

export const CLI_ACTIONS = Object.freeze({
  "backup-platform-catalog": "backup.catalog",
  "execute-backup-job": "backup.job.execute",
  "prune-manifest-backups-plan": "backup.prune.plan",
  "prune-manifest-backups-apply": "backup.prune.apply",
  "full-restore-drill": "restore.drill.full",
  "offsite-backup-restic": "backup.offsite.sync",
  "runtime-docker-snapshot": "evidence.runtime.snapshot",
});

const SHA256 = /^[a-f0-9]{64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LOGICAL_ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const BACKUP_RESOURCE_ID = /^(?:source|database|storage|platform-state):[a-z0-9](?:[a-z0-9._:-]{0,158}[a-z0-9])?$/;
const CONTAINER_NAME = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;
const DIGEST_IMAGE = /^[a-zA-Z0-9][a-zA-Z0-9._/:+-]*@sha256:[a-f0-9]{64}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const DNS_HOST = /^[a-z0-9](?:[a-z0-9-]{0,62})(?:\.[a-z0-9](?:[a-z0-9-]{0,62}))*$/;
const ALLOWED_CONTAINER_PATHS = new Set([
  "/opt/platform-infrastructure",
  "/opt/platform-infrastructure/backups",
  "/opt/platform-infrastructure/reports",
  "/data/backups",
  "/data/reports",
  "/data/source",
  "/data/state",
  "/project",
  "/run/platform/claimed-job/job.json",
  "/run/platform/restore-scratch",
  "/run/platform/worker-secrets/manifest-signing",
  "/run/platform/worker-secrets/manifest-verification",
  "/run/platform/worker-secrets/offsite",
  "/var/www/project-state",
]);

const ACTION_PROFILE_KEYS = Object.freeze([
  "capabilityFileId",
  "claimedJobSourceId",
  "jobOperations",
  "operationPhaseIds",
  "phaseIds",
  "profileId",
  "profileSha256",
]);
const PHASE_PROFILE_KEYS = Object.freeze([
  "command",
  "endpointIds",
  "helperProfileIds",
  "mountIds",
  "mutationPolicy",
  "networkIds",
  "outputSchema",
  "phaseId",
  "phaseSha256",
  "scratchVolumeIds",
  "workerImageId",
  "workerImageRef",
  "workerSecretSetIds",
  "writableSubpathIds",
]);

const ACTION_PLANS = deepFreeze({
  "backup.catalog": {
    claimedJobSourceId: null,
    jobOperations: [],
    operationPhaseIds: {},
    phaseIds: ["catalog.capture"],
  },
  "backup.job.execute": {
    claimedJobSourceId: "jobs.running",
    jobOperations: ["backup", "restore-drill"],
    operationPhaseIds: {
      backup: ["job.backup.capture"],
      "restore-drill": ["job.restore.verify"],
    },
    phaseIds: [],
  },
  "backup.prune.plan": {
    claimedJobSourceId: null,
    jobOperations: [],
    operationPhaseIds: {},
    phaseIds: ["prune.plan"],
  },
  "backup.prune.apply": {
    claimedJobSourceId: null,
    jobOperations: [],
    operationPhaseIds: {},
    phaseIds: ["prune.apply"],
  },
  "restore.drill.full": {
    claimedJobSourceId: null,
    jobOperations: [],
    operationPhaseIds: {},
    phaseIds: ["restore.capture", "restore.verify"],
  },
  "backup.offsite.sync": {
    claimedJobSourceId: null,
    jobOperations: [],
    operationPhaseIds: {},
    phaseIds: ["offsite.sync"],
  },
});

const PHASE_PLANS = deepFreeze({
  "catalog.capture": phasePlan({
    command: "backup-catalog",
    endpointPurpose: "capture",
    mountIds: ["backup.root.rw", "report.root.rw", "source.root.ro", "state.catalog.ro"],
    mutationPolicy: "backup-write",
    networkIds: ["platform_db_admin", "platform_storage"],
    outputSchema: "platform.backup-catalog/v1",
    helperProfileIds: ["helper.capture.mariadb", "helper.capture.minio", "helper.capture.postgres"],
    workerSecretSetIds: ["manifest.signing"],
  }),
  "job.backup.capture": phasePlan({
    command: "backup-job",
    endpointPurpose: "capture",
    mountIds: ["backup.root.rw", "report.root.rw", "source.root.ro", "state.catalog.ro"],
    mutationPolicy: "backup-write",
    networkIds: ["platform_db_admin", "platform_storage"],
    outputSchema: "platform.backup-job-result/v1",
    helperProfileIds: ["helper.capture.mariadb", "helper.capture.minio", "helper.capture.postgres"],
    workerSecretSetIds: ["manifest.signing"],
  }),
  "job.restore.verify": phasePlan({
    command: "restore-job",
    endpointPurpose: "none",
    mountIds: ["backup.root.ro", "report.root.rw"],
    mutationPolicy: "restore-disposable",
    networkIds: [],
    outputSchema: "platform.backup-job-result/v1",
    scratchVolumeIds: ["restore.scratch"],
    helperProfileIds: ["helper.restore.mariadb.server", "helper.restore.mariadb.restore", "helper.restore.mariadb.verify", "helper.restore.minio.server", "helper.restore.minio.restore", "helper.restore.minio.verify", "helper.restore.postgres.server", "helper.restore.postgres.restore", "helper.restore.postgres.verify"],
    workerSecretSetIds: ["manifest.verification"],
  }),
  "prune.plan": phasePlan({
    command: "backup-prune-plan",
    endpointPurpose: "none",
    mountIds: ["backup.root.ro", "report.root.rw"],
    mutationPolicy: "report-only",
    networkIds: [],
    outputSchema: "platform.backup-prune-plan/v1",
    helperProfileIds: [],
    workerSecretSetIds: ["manifest.verification"],
  }),
  "prune.apply": phasePlan({
    command: "backup-prune-apply",
    endpointPurpose: "none",
    mountIds: ["backup.root.rw", "report.root.rw"],
    mutationPolicy: "retention-apply",
    networkIds: [],
    outputSchema: "platform.backup-prune-apply/v1",
    helperProfileIds: [],
    workerSecretSetIds: ["manifest.verification"],
    writableSubpathIds: ["backup.quarantine"],
  }),
  "restore.capture": phasePlan({
    command: "backup-catalog",
    endpointPurpose: "capture",
    mountIds: ["backup.root.rw", "report.root.rw", "source.root.ro", "state.catalog.ro"],
    mutationPolicy: "backup-write",
    networkIds: ["platform_db_admin", "platform_storage"],
    outputSchema: "platform.backup-catalog/v1",
    helperProfileIds: ["helper.capture.mariadb", "helper.capture.minio", "helper.capture.postgres"],
    workerSecretSetIds: ["manifest.signing"],
  }),
  "restore.verify": phasePlan({
    command: "restore-drill-full",
    endpointPurpose: "none",
    mountIds: ["backup.root.ro", "report.root.rw"],
    mutationPolicy: "restore-disposable",
    networkIds: [],
    outputSchema: "platform.restore-drill/v1",
    scratchVolumeIds: ["restore.scratch"],
    helperProfileIds: ["helper.restore.mariadb.server", "helper.restore.mariadb.restore", "helper.restore.mariadb.verify", "helper.restore.minio.server", "helper.restore.minio.restore", "helper.restore.minio.verify", "helper.restore.postgres.server", "helper.restore.postgres.restore", "helper.restore.postgres.verify"],
    workerSecretSetIds: ["manifest.verification"],
  }),
  "offsite.sync": phasePlan({
    command: "backup-offsite-sync",
    endpointPurpose: "offsite",
    mountIds: ["backup.root.ro", "report.root.rw"],
    mutationPolicy: "offsite-write",
    networkIds: ["platform_egress"],
    outputSchema: "platform.offsite-backup-receipt/v1",
    helperProfileIds: ["helper.offsite.restic"],
    workerSecretSetIds: ["manifest.verification"],
  }),
});

const SERVICE_ENDPOINT_PLANS = deepFreeze({
  "capture.database.mariadb": {
    backupResourceId: "database:mariadb",
    engine: "mariadb",
    endpointId: "capture.database.mariadb",
    host: "mariadb",
    networkId: "platform_db_admin",
    port: 3306,
    protocol: "mariadb",
    purpose: "capture",
    secretSetId: "mariadb.capture.credentials",
    targetContainerId: "mariadb",
    tlsMode: "require",
  },
  "capture.database.postgres": {
    backupResourceId: "database:postgres",
    engine: "postgres",
    endpointId: "capture.database.postgres",
    host: "postgres",
    networkId: "platform_db_admin",
    port: 5432,
    protocol: "postgresql",
    purpose: "capture",
    secretSetId: "postgres.capture.credentials",
    targetContainerId: "postgres",
    tlsMode: "require",
  },
  "capture.storage.minio": {
    backupResourceId: "storage:minio",
    engine: "minio",
    endpointId: "capture.storage.minio",
    host: "minio",
    networkId: "platform_storage",
    port: 9000,
    protocol: "s3-http",
    purpose: "capture",
    secretSetId: "minio.capture.credentials",
    targetContainerId: "minio",
    tlsMode: "none",
  },
  "offsite.repository": {
    backupResourceId: null,
    engine: "restic",
    endpointId: "offsite.repository",
    host: "backup.example.net",
    networkId: "platform_egress",
    port: 443,
    protocol: "restic-https",
    purpose: "offsite",
    secretSetId: "offsite.credentials",
    targetContainerId: null,
    tlsMode: "verify-full",
  },
});

const HELPER_PROFILE_PLANS = deepFreeze({
  "helper.capture.mariadb": helperProfilePlan({
    engine: "mariadb",
    entrypoint: ["/usr/bin/mariadb-dump"],
    imageRef: "mariadb:12.3.2@sha256:b1c7bf836e64ed9406a8984af29509f40089d55cea14b32f12c4726a1f17104b",
    networkId: "platform_db_admin",
    operation: "capture",
    outputMode: "artifact",
    resourceKind: "database",
    secretSetId: "mariadb.capture.credentials",
  }),
  "helper.capture.minio": helperProfilePlan({
    engine: "minio",
    entrypoint: ["/bin/sh"],
    imageRef: "quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727",
    networkId: "platform_storage",
    operation: "capture",
    outputMode: "artifact",
    resourceKind: "storage",
    secretSetId: "minio.capture.credentials",
  }),
  "helper.capture.postgres": helperProfilePlan({
    engine: "postgres",
    entrypoint: ["/usr/local/bin/pg_dump"],
    imageRef: "postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa",
    networkId: "platform_db_admin",
    operation: "capture",
    outputMode: "artifact",
    resourceKind: "database",
    secretSetId: "postgres.capture.credentials",
  }),
  "helper.offsite.restic": helperProfilePlan({
    engine: "restic",
    entrypoint: ["/usr/bin/restic"],
    imageRef: "restic/restic:0.18.0@sha256:4cf4a61ef9786f4de53e9de8c8f5c040f33830eb0a10bf3d614410ee2fcb6120",
    networkId: "platform_egress",
    operation: "offsite-sync",
    outputMode: "json",
    resourceKind: null,
    secretSetId: "offsite.credentials",
  }),
  "helper.restore.mariadb.restore": helperProfilePlan({
    engine: "mariadb",
    entrypoint: ["/usr/bin/mariadb"],
    imageRef: "mariadb:12.3.2@sha256:b1c7bf836e64ed9406a8984af29509f40089d55cea14b32f12c4726a1f17104b",
    operation: "restore",
    outputMode: "none",
    resourceKind: "database",
  }),
  "helper.restore.mariadb.server": helperProfilePlan({
    engine: "mariadb",
    entrypoint: ["/usr/local/bin/docker-entrypoint.sh"],
    imageRef: "mariadb:12.3.2@sha256:b1c7bf836e64ed9406a8984af29509f40089d55cea14b32f12c4726a1f17104b",
    operation: "restore-server",
    outputMode: "none",
    resourceKind: "database",
  }),
  "helper.restore.mariadb.verify": helperProfilePlan({
    engine: "mariadb",
    entrypoint: ["/usr/bin/mariadb"],
    imageRef: "mariadb:12.3.2@sha256:b1c7bf836e64ed9406a8984af29509f40089d55cea14b32f12c4726a1f17104b",
    operation: "verify",
    outputMode: "json",
    resourceKind: "database",
  }),
  "helper.restore.minio.restore": helperProfilePlan({
    engine: "minio",
    entrypoint: ["/usr/bin/mc"],
    imageRef: "quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727",
    operation: "restore",
    outputMode: "none",
    resourceKind: "storage",
  }),
  "helper.restore.minio.server": helperProfilePlan({
    engine: "minio",
    entrypoint: ["/usr/bin/minio"],
    imageRef: "quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e",
    operation: "restore-server",
    outputMode: "none",
    resourceKind: "storage",
  }),
  "helper.restore.minio.verify": helperProfilePlan({
    engine: "minio",
    entrypoint: ["/usr/bin/mc"],
    imageRef: "quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727",
    operation: "verify",
    outputMode: "json",
    resourceKind: "storage",
  }),
  "helper.restore.postgres.restore": helperProfilePlan({
    engine: "postgres",
    entrypoint: ["/usr/local/bin/pg_restore"],
    imageRef: "postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa",
    operation: "restore",
    outputMode: "none",
    resourceKind: "database",
  }),
  "helper.restore.postgres.server": helperProfilePlan({
    engine: "postgres",
    entrypoint: ["/usr/local/bin/docker-entrypoint.sh"],
    imageRef: "postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa",
    operation: "restore-server",
    outputMode: "none",
    resourceKind: "database",
  }),
  "helper.restore.postgres.verify": helperProfilePlan({
    engine: "postgres",
    entrypoint: ["/usr/local/bin/psql"],
    imageRef: "postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa",
    operation: "verify",
    outputMode: "json",
    resourceKind: "database",
  }),
});

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function hmac(value, key) {
  return crypto.createHmac("sha256", normalizeKey(key)).update(canonicalJson(value)).digest("hex");
}

function domainHmac(schema, value, key) {
  return crypto
    .createHmac("sha256", normalizeKey(key))
    .update(`${schema}\0`)
    .update(canonicalJson(value))
    .digest("hex");
}

export function signRuntimeIntent(intent, trustKey) {
  const unsigned = withoutKey(intent, "mac");
  return { ...unsigned, mac: hmac(unsigned, trustKey) };
}

export function signActionRequest(request, capabilityKey) {
  const unsigned = withoutKey(request, "mac");
  return { ...unsigned, mac: domainHmac(REQUEST_SCHEMA, unsigned, capabilityKey) };
}

export function signActionResponse(response, capabilityKey) {
  const unsigned = withoutKey(response, "mac");
  return { ...unsigned, mac: domainHmac(RESPONSE_SCHEMA, unsigned, capabilityKey) };
}

export function normalizeTrustedContext(intentValue, receiptValue, trustKey, { now = Date.now() } = {}) {
  const intent = assertPlainObject(intentValue, "runtime intent");
  assertExactKeys(intent, [
    "activeReceiptSha256",
    "activationBundleSha256",
    "allowedActions",
    "candidateId",
    "combinedRenderSha256",
    "dastChainSha256",
    "environment",
    "expiresAt",
    "generation",
    "intentId",
    "issuedAt",
    "mac",
    "releaseId",
    "schema",
    "targetId",
  ], "runtime intent");
  if (intent.schema !== RUNTIME_INTENT_SCHEMA) fail(403, "unsupported runtime intent schema");
  assertLogicalId(intent.intentId, "intentId");
  assertLogicalId(intent.releaseId, "releaseId");
  assertLogicalId(intent.candidateId, "candidateId");
  assertLogicalId(intent.environment, "environment");
  assertLogicalId(intent.targetId, "targetId");
  if (!Number.isSafeInteger(intent.generation) || intent.generation < 1) fail(403, "runtime intent generation is invalid");
  assertTimeWindow(intent.issuedAt, intent.expiresAt, now, 24 * 60 * 60_000, "runtime intent");
  if (!SHA256.test(String(intent.activeReceiptSha256 ?? ""))) fail(403, "runtime intent receipt digest is invalid");
  if (!SHA256.test(String(intent.activationBundleSha256 ?? ""))) fail(403, "runtime intent activation bundle digest is invalid");
  if (!SHA256.test(String(intent.combinedRenderSha256 ?? ""))) fail(403, "runtime intent combined render digest is invalid");
  if (!SHA256.test(String(intent.dastChainSha256 ?? ""))) fail(403, "runtime intent DAST chain digest is invalid");
  if (!Array.isArray(intent.allowedActions) || intent.allowedActions.length < 1) fail(403, "runtime intent has no allowed actions");
  const allowedActions = [...new Set(intent.allowedActions.map(String))];
  if (allowedActions.length !== intent.allowedActions.length || allowedActions.some((action) => !ACTIONS[action]?.modeled)) {
    fail(403, "runtime intent contains an unsupported or duplicate action");
  }
  verifyMac(intent, trustKey, "runtime intent");

  const receipt = normalizeActiveReceipt(receiptValue, { now });
  const receiptDigest = sha256(canonicalJson(receipt));
  if (!constantEqual(receiptDigest, intent.activeReceiptSha256)) fail(403, "active receipt digest does not match runtime intent");
  if (receipt.releaseId !== intent.releaseId) fail(403, "active receipt release does not match runtime intent");
  if (receipt.generation !== intent.generation) fail(403, "active receipt generation does not match runtime intent");
  for (const name of ["activationBundleSha256", "candidateId", "dastChainSha256", "environment", "targetId"]) {
    if (!constantEqual(receipt[name], intent[name])) fail(403, `active receipt ${name} does not match runtime intent`);
  }
  if (!constantEqual(receipt.combinedRenderSha256, intent.combinedRenderSha256)) {
    fail(403, "active receipt combined render digest does not match runtime intent");
  }
  return Object.freeze({
    intent: Object.freeze({ ...intent, allowedActions: Object.freeze(allowedActions) }),
    receipt,
    receiptDigest,
  });
}

export function normalizeActiveReceipt(value, { now = Date.now() } = {}) {
  const receipt = assertPlainObject(value, "active receipt");
  assertExactKeys(receipt, [
    "activationBundleSha256",
    "candidateId",
    "combinedRenderSha256",
    "dastChainSha256",
    "environment",
    "expiresAt",
    "generation",
    "issuedAt",
    "receiptId",
    "releaseId",
    "resources",
    "schema",
    "sourceRenderSha256",
    "targetId",
    "treeSha256",
  ], "active receipt");
  if (receipt.schema !== ACTIVE_RECEIPT_SCHEMA) fail(403, "unsupported active receipt schema");
  assertLogicalId(receipt.receiptId, "receiptId");
  assertLogicalId(receipt.releaseId, "releaseId");
  assertLogicalId(receipt.candidateId, "candidateId");
  assertLogicalId(receipt.environment, "environment");
  assertLogicalId(receipt.targetId, "targetId");
  if (!Number.isSafeInteger(receipt.generation) || receipt.generation < 1) fail(403, "active receipt generation is invalid");
  for (const [name, value] of [
    ["treeSha256", receipt.treeSha256],
    ["activationBundleSha256", receipt.activationBundleSha256],
    ["sourceRenderSha256", receipt.sourceRenderSha256],
    ["combinedRenderSha256", receipt.combinedRenderSha256],
    ["dastChainSha256", receipt.dastChainSha256],
  ]) {
    if (!SHA256.test(String(value ?? ""))) fail(403, `active receipt ${name} is invalid`);
  }
  assertTimeWindow(receipt.issuedAt, receipt.expiresAt, now, 30 * 24 * 60 * 60_000, "active receipt");
  const resources = normalizeResources(receipt.resources);
  for (const [logicalId, container] of Object.entries(resources.containers)) {
    if (!constantEqual(container.labels["com.platform.runtime.candidate-id"], receipt.candidateId)
      || !constantEqual(container.labels["com.platform.runtime.source-render-sha256"], receipt.sourceRenderSha256)) {
      fail(403, `container ${logicalId} candidate or source render label does not match the active receipt`);
    }
  }
  return Object.freeze({ ...receipt, resources });
}

export function normalizeActionRequest(value, trusted, capabilityKey, { now = Date.now() } = {}) {
  const request = assertPlainObject(value, "request");
  assertExactKeys(request, [
    "action",
    "activeReceiptSha256",
    "capabilityId",
    "combinedRenderSha256",
    "expiresAt",
    "issuedAt",
    "mac",
    "nonce",
    "parameters",
    "requestId",
    "runtimeIntentId",
    "schema",
  ], "request");
  if (request.schema !== REQUEST_SCHEMA) fail(400, "unsupported request schema");
  if (!UUID_V4.test(String(request.requestId ?? ""))) fail(400, "requestId must be a UUID v4");
  if (!NONCE.test(String(request.nonce ?? ""))) fail(400, "nonce must encode exactly 32 random bytes");
  assertTimeWindow(request.issuedAt, request.expiresAt, now, MAX_REQUEST_LIFETIME_MS, "request");
  const issuedAt = Date.parse(request.issuedAt);
  if (Math.abs(now - issuedAt) > MAX_CLOCK_SKEW_MS) fail(401, "request timestamp is outside the accepted window");

  const action = String(request.action ?? "");
  if (!/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+$/.test(action)) {
    fail(403, "action grammar is invalid");
  }
  const contract = ACTIONS[action];
  if (!contract) fail(403, "action is not authorized");
  if (!trusted.intent.allowedActions.includes(action)) fail(403, "action is not enabled by runtime intent");
  if (request.capabilityId !== contract.capabilityId) fail(403, "capability is not bound to this action");
  if (request.runtimeIntentId !== trusted.intent.intentId) fail(403, "request runtime intent does not match");
  if (!constantEqual(String(request.activeReceiptSha256 ?? ""), trusted.receiptDigest)) fail(403, "request active receipt does not match");
  if (!constantEqual(String(request.combinedRenderSha256 ?? ""), trusted.receipt.combinedRenderSha256)) {
    fail(403, "request combined render digest does not match");
  }
  const capabilityFile = trusted.receipt?.resources?.capabilityFiles?.[`capability.${action}`];
  if (!capabilityFile
    || !constantEqual(capabilityFile.brokerPath, contract.capabilityFile)
    || !constantEqual(capabilityFile.sha256, sha256(normalizeKey(capabilityKey)))) {
    fail(403, "capability file digest or action binding does not match loaded capability bytes");
  }
  const parameters = normalizeParameters(action, request.parameters, trusted.receipt.resources);
  verifyDomainMac(request, capabilityKey, REQUEST_SCHEMA, "request");
  return Object.freeze({
    action,
    capabilityId: contract.capabilityId,
    parameters,
    requestId: request.requestId,
    nonce: request.nonce,
    runtimeIntentId: request.runtimeIntentId,
    activeReceiptSha256: request.activeReceiptSha256,
    combinedRenderSha256: request.combinedRenderSha256,
  });
}

export function buildUnsignedRequest(action, parameters, trusted, { now = Date.now(), requestId = crypto.randomUUID(), nonce = crypto.randomBytes(32).toString("base64url") } = {}) {
  const contract = ACTIONS[action];
  if (!contract) fail(64, "unsupported action");
  const issuedAt = new Date(now);
  return {
    schema: REQUEST_SCHEMA,
    requestId,
    nonce,
    issuedAt: issuedAt.toISOString(),
    expiresAt: new Date(issuedAt.getTime() + 30_000).toISOString(),
    runtimeIntentId: trusted.intent.intentId,
    activeReceiptSha256: trusted.receiptDigest,
    combinedRenderSha256: trusted.receipt.combinedRenderSha256,
    capabilityId: contract.capabilityId,
    action,
    parameters,
  };
}

export function normalizeActionResponse(value, requestValue, capabilityKey) {
  const response = assertPlainObject(value, "response");
  const request = assertPlainObject(requestValue, "signed request");
  assertExactKeys(request, [
    "action",
    "activeReceiptSha256",
    "capabilityId",
    "combinedRenderSha256",
    "expiresAt",
    "issuedAt",
    "mac",
    "nonce",
    "parameters",
    "requestId",
    "runtimeIntentId",
    "schema",
  ], "signed request");
  if (request.schema !== REQUEST_SCHEMA || !SHA256.test(String(request.mac ?? ""))) {
    fail(400, "signed request schema or authentication envelope is invalid");
  }
  assertExactKeys(response, [
    "action",
    "errorCode",
    "mac",
    "requestId",
    "requestSha256",
    "result",
    "resultSha256",
    "schema",
    "status",
    "statusCode",
  ], "response");
  if (response.schema !== RESPONSE_SCHEMA) fail(400, "unsupported response schema");
  verifyDomainMac(response, capabilityKey, RESPONSE_SCHEMA, "response");

  const action = String(response.action ?? "");
  if (!/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+$/.test(action)) {
    fail(403, "response action grammar is invalid");
  }
  if (!Object.hasOwn(ACTIONS, action) || action !== request.action) {
    fail(403, "response action identity does not exactly match the request binding");
  }
  if (response.requestId !== request.requestId) fail(403, "response request identity does not match");
  const expectedRequestSha256 = sha256(canonicalJson(request));
  if (!SHA256.test(String(response.requestSha256 ?? ""))
    || !constantEqual(response.requestSha256, expectedRequestSha256)) {
    fail(403, "response signed-request digest binding does not match");
  }
  if (!SHA256.test(String(response.resultSha256 ?? ""))
    || !constantEqual(response.resultSha256, sha256(canonicalJson(response.result)))) {
    fail(403, "response result digest binding does not match");
  }

  if (response.status === "completed") {
    if (response.statusCode !== 200 || response.errorCode !== null || response.result === null) {
      fail(403, "completed response status contract is invalid");
    }
    normalizeActionResult(response.result, request);
  } else if (response.status === "rejected") {
    if (!Number.isSafeInteger(response.statusCode) || response.statusCode < 400 || response.statusCode > 599
      || !/^[A-Z][A-Z0-9_]{2,63}$/.test(String(response.errorCode ?? ""))
      || response.result !== null) {
      fail(403, "rejected response status contract is invalid");
    }
  } else {
    fail(403, "response status is invalid");
  }
  return deepFreeze(structuredClone(response));
}

function normalizeActionResult(value, request) {
  const result = assertPlainObject(value, "action result");
  assertExactKeys(result, ["action", "job", "phases", "schema", "status"], "action result");
  if (result.schema !== RESULT_SCHEMA || result.status !== "completed") {
    fail(403, "action result schema or status is invalid");
  }
  if (result.action !== request.action || !Object.hasOwn(ACTIONS, result.action)) {
    fail(403, "action result identity does not exactly match the request binding");
  }

  const isEvidence = result.action === "evidence.runtime.snapshot";
  const isJob = result.action === "backup.job.execute";
  if (isJob) {
    const job = assertPlainObject(result.job, "action result job");
    assertExactKeys(job, ["jobFileName", "jobId", "jobOperation", "jobSha256"], "action result job");
    if (canonicalJson(job) !== canonicalJson(request.parameters)) {
      fail(403, "action result job identity or operation does not exactly match the request binding");
    }
  } else if (result.job !== null) {
    fail(403, "fixed action result must not contain a job identity");
  }

  const expectedPhaseIds = isEvidence
    ? ["evidence.runtime.snapshot"]
    : isJob
      ? ACTION_PLANS[result.action].operationPhaseIds[request.parameters.jobOperation]
      : ACTION_PLANS[result.action].phaseIds;
  if (!Array.isArray(result.phases)
    || canonicalJson(result.phases.map((phase) => phase?.phaseId)) !== canonicalJson(expectedPhaseIds)) {
    fail(403, "action result phase plan does not exactly match the request binding");
  }
  for (const [index, phaseValue] of result.phases.entries()) {
    const phase = assertPlainObject(phaseValue, `action result phase ${index}`);
    assertExactKeys(phase, [
      "output",
      "outputSchema",
      "outputSha256",
      "phaseId",
      "status",
    ], `action result phase ${index}`);
    const expectedPhaseId = expectedPhaseIds[index];
    const expectedOutputSchema = isEvidence
      ? "platform.docker-runtime-snapshot/v2"
      : PHASE_PLANS[expectedPhaseId].outputSchema;
    if (phase.phaseId !== expectedPhaseId || phase.status !== "completed"
      || phase.outputSchema !== expectedOutputSchema) {
      fail(403, `action result phase ${index} identity, status or output schema is invalid`);
    }
    const output = assertPlainObject(phase.output, `action result phase ${phase.phaseId} output`);
    if (output.schema !== expectedOutputSchema) {
      fail(403, `action result phase ${phase.phaseId} output schema binding is invalid`);
    }
    const encodedOutput = canonicalJson(output);
    if (Buffer.byteLength(encodedOutput) > MAX_PHASE_OUTPUT_BYTES) {
      fail(403, `action result phase ${phase.phaseId} output exceeds the bounded contract`);
    }
    if (!SHA256.test(String(phase.outputSha256 ?? ""))
      || !constantEqual(phase.outputSha256, sha256(encodedOutput))) {
      fail(403, `action result phase ${phase.phaseId} output digest binding is invalid`);
    }
    if (isJob && (output.jobId !== request.parameters.jobId
      || output.jobOperation !== request.parameters.jobOperation)) {
      fail(403, `action result phase ${phase.phaseId} job identity or operation binding is invalid`);
    }
  }
  return result;
}

function normalizeParameters(action, value, resources) {
  const parameters = assertPlainObject(value, "parameters");
  assertExactKeys(parameters, ACTIONS[action].parameters, "parameters");
  if (action !== "backup.job.execute") return Object.freeze({});
  const jobId = String(parameters.jobId ?? "");
  const jobFileName = String(parameters.jobFileName ?? "");
  const jobOperation = String(parameters.jobOperation ?? "");
  const jobSha256 = String(parameters.jobSha256 ?? "");
  if (!/^[a-z0-9][a-z0-9-]{15,127}$/.test(jobId)) fail(400, "job identity is invalid");
  if (jobFileName !== `${jobId}.json`) fail(400, "job file name does not exactly match job identity");
  if (!["backup", "restore-drill"].includes(jobOperation)) fail(400, "job operation is invalid");
  if (!SHA256.test(jobSha256)) fail(400, "job digest is invalid");
  if (!Object.keys(resources.backupResources).length) fail(403, "active receipt contains no admitted backup resources");
  return Object.freeze({ jobFileName, jobId, jobOperation, jobSha256 });
}

function normalizeResources(value) {
  const resources = assertPlainObject(value, "active receipt resources");
  assertExactKeys(resources, [
    "actionProfiles",
    "backupResources",
    "capabilityFiles",
    "claimedJobSources",
    "containers",
    "helperProfiles",
    "mounts",
    "networks",
    "phaseProfiles",
    "serviceEndpoints",
    "volumes",
    "workerSecretSets",
    "writableSubpaths",
  ], "active receipt resources");

  const backupResources = normalizeMap(resources.backupResources, "backupResources", normalizeBackupResource, BACKUP_RESOURCE_ID);
  const containers = normalizeMap(resources.containers, "containers", (entry, logicalId) => {
    assertExactKeys(entry, ["authority", "containerId", "expectedHealth", "expectedState", "imageId", "imageRef", "labels", "name"], `container ${logicalId}`);
    if (!CONTAINER_NAME.test(String(entry.name ?? ""))) fail(403, `container ${logicalId} name is invalid`);
    if (!/^[a-f0-9]{64}$/.test(String(entry.containerId ?? ""))) fail(403, `container ${logicalId} ID is invalid`);
    if (!DIGEST_IMAGE.test(String(entry.imageRef ?? ""))) fail(403, `container ${logicalId} image must be digest pinned`);
    if (!/^sha256:[a-f0-9]{64}$/.test(String(entry.imageId ?? ""))) fail(403, `container ${logicalId} image ID is invalid`);
    if (!["running", "exited"].includes(entry.expectedState)) fail(403, `container ${logicalId} expected state is invalid`);
    if (!["healthy", "none"].includes(entry.expectedHealth)) fail(403, `container ${logicalId} expected health is invalid`);
    const labels = normalizeIdentityLabels(entry.labels, logicalId);
    const authority = normalizeContainerAuthority(entry.authority, logicalId);
    return Object.freeze({
      containerId: entry.containerId,
      name: entry.name,
      imageRef: entry.imageRef,
      imageId: entry.imageId,
      labels,
      authority,
      expectedState: entry.expectedState,
      expectedHealth: entry.expectedHealth,
    });
  });

  const capabilityFiles = normalizeExactMap(
    resources.capabilityFiles,
    Object.keys(ACTIONS).map((action) => `capability.${action}`),
    "capabilityFiles",
    (entry, fileId) => {
      assertExactKeys(entry, [
        "brokerPath",
        "device",
        "inode",
        "mode",
        "ownerGid",
        "ownerUid",
        "sha256",
        "symlinkFree",
      ], `capability file ${fileId}`);
      const action = fileId.slice("capability.".length);
      const binding = ACTIONS[action];
      if (!binding || entry.brokerPath !== binding.capabilityFile) {
        fail(403, `capability file ${fileId} action binding is invalid`);
      }
      assertProtectedFile(entry, `capability file ${fileId}`);
      return Object.freeze({ ...entry });
    },
  );

  const claimedJobSources = normalizeExactMap(
    resources.claimedJobSources,
    ["jobs.running"],
    "claimedJobSources",
    (entry, sourceId) => {
      assertExactKeys(entry, [
        "brokerRoot",
        "maximumBytes",
        "snapshotContainerPath",
        "snapshotVolumeId",
        "snapshotVolumeSubpath",
        "volumeId",
        "volumeSubpath",
      ], `claimed-job source ${sourceId}`);
      if (entry.brokerRoot !== "/run/platform/backup-jobs/running"
        || entry.volumeId !== "jobs.queue"
        || entry.volumeSubpath !== "running"
        || entry.snapshotVolumeId !== "broker.state"
        || entry.snapshotContainerPath !== "/run/platform/claimed-job/job.json"
        || entry.snapshotVolumeSubpath !== "claimed-jobs"
        || !Number.isSafeInteger(entry.maximumBytes)
        || entry.maximumBytes < 1
        || entry.maximumBytes > 1024 * 1024) {
        fail(403, `claimed-job source ${sourceId} canonical binding is invalid`);
      }
      for (const pathValue of [entry.brokerRoot, entry.snapshotContainerPath]) {
        if (pathValue.includes("/../") || pathValue.includes("/./") || pathValue.includes("\0")) {
          fail(403, `claimed-job source ${sourceId} path is invalid`);
        }
      }
      for (const subpath of [entry.volumeSubpath, entry.snapshotVolumeSubpath]) {
        if (!/^[a-z0-9][a-z0-9._-]{0,127}$/.test(subpath)) {
          fail(403, `claimed-job source ${sourceId} subpath is invalid`);
        }
      }
      return Object.freeze({ ...entry });
    },
  );

  const expectedMounts = {
    "backup.root.ro": ["ro", "/srv/platform/backups", "/data/backups"],
    "backup.root.rw": ["rw", "/srv/platform/backups", "/data/backups"],
    "report.root.rw": ["rw", "/srv/platform/reports", "/data/reports"],
    "source.root.ro": ["ro", "/srv/platform/project-sources", "/data/source"],
    "state.catalog.ro": ["ro", "/srv/platform/project-state", "/data/state"],
  };
  const mounts = normalizeExactMap(resources.mounts, Object.keys(expectedMounts), "mounts", (entry, logicalId) => {
    assertExactKeys(entry, [
      "access",
      "canonicalPath",
      "containerPath",
      "device",
      "inode",
      "kind",
      "mode",
      "ownerGid",
      "ownerUid",
      "symlinkFree",
    ], `mount ${logicalId}`);
    const hostPath = String(entry.canonicalPath ?? "");
    const containerPath = String(entry.containerPath ?? "");
    if (!hostPath.startsWith("/srv/platform/") || hostPath.includes("/../") || hostPath.includes("\0")) {
      fail(403, `mount ${logicalId} host path is outside the fixed platform root`);
    }
    if (!ALLOWED_CONTAINER_PATHS.has(containerPath)) fail(403, `mount ${logicalId} container path is not policy approved`);
    const expected = expectedMounts[logicalId];
    if (!expected || entry.access !== expected[0] || hostPath !== expected[1] || containerPath !== expected[2]) {
      fail(403, `mount ${logicalId} canonical identity is invalid`);
    }
    if (entry.kind !== "host-directory" || entry.symlinkFree !== true || entry.ownerUid !== 0 || entry.ownerGid !== 0
      || !Number.isSafeInteger(entry.device) || entry.device < 0 || !Number.isSafeInteger(entry.inode) || entry.inode < 1
      || !Number.isSafeInteger(entry.mode) || entry.mode !== 0o700) {
      fail(403, `mount ${logicalId} attestation is invalid`);
    }
    return Object.freeze({ ...entry });
  });

  const networkIdentity = {
    platform_db_admin: ["platform_db_admin", true, false],
    platform_storage: ["platform_storage", true, false],
    platform_egress: ["platform_egress", false, true],
  };
  const networks = normalizeExactMap(resources.networks, Object.keys(networkIdentity), "networks", (entry, logicalId) => {
    assertExactKeys(entry, [
      "driver",
      "engineId",
      "engineName",
      "externalEgress",
      "internal",
      "labelsSha256",
      "membershipSha256",
      "optionsSha256",
      "scope",
      "subnetSha256",
    ], `network ${logicalId}`);
    const [engineName, internal, externalEgress] = networkIdentity[logicalId];
    if (entry.engineName !== engineName || entry.driver !== "bridge" || entry.scope !== "local"
      || entry.internal !== internal || entry.externalEgress !== externalEgress
      || !SHA256.test(String(entry.engineId ?? ""))) {
      fail(403, `network ${logicalId} canonical identity is invalid`);
    }
    for (const key of ["labelsSha256", "membershipSha256", "optionsSha256", "subnetSha256"]) {
      if (!SHA256.test(String(entry[key] ?? ""))) fail(403, `network ${logicalId} ${key} is invalid`);
    }
    return Object.freeze({ ...entry });
  });

  const volumeIdentity = {
    "broker.state": ["platform_infra_vps_docker_action_broker_state", null],
    "jobs.queue": ["platform_infra_vps_backup_scheduler_jobs", null],
    "restore.scratch": ["platform_docker_action_restore_scratch", "/run/platform/restore-scratch"],
    "worker.input.mariadb-capture": ["platform_docker_action_mariadb_capture_credentials", null],
    "worker.input.manifest-signing": ["platform_docker_action_manifest_signing", null],
    "worker.input.manifest-verification": ["platform_docker_action_manifest_verification", null],
    "worker.input.minio-capture": ["platform_docker_action_minio_capture_credentials", null],
    "worker.input.offsite": ["platform_docker_action_offsite_credentials", null],
    "worker.input.postgres-capture": ["platform_docker_action_postgres_capture_credentials", null],
  };
  const volumes = normalizeExactMap(resources.volumes, Object.keys(volumeIdentity), "volumes", (entry, logicalId) => {
    assertExactKeys(entry, [
      "containerPath",
      "driver",
      "engineName",
      "labelsSha256",
      "optionsSha256",
      "scope",
    ], `volume ${logicalId}`);
    const [engineName, containerPath] = volumeIdentity[logicalId];
    if (entry.engineName !== engineName || entry.containerPath !== containerPath
      || entry.driver !== "local" || entry.scope !== "local"
      || !SHA256.test(String(entry.labelsSha256 ?? ""))
      || !SHA256.test(String(entry.optionsSha256 ?? ""))) {
      fail(403, `volume ${logicalId} canonical identity is invalid`);
    }
    return Object.freeze({ ...entry });
  });

  const secretSetIdentity = {
    "mariadb.capture.credentials": [
      "/run/platform/worker-secrets/mariadb-capture",
      "worker.input.mariadb-capture",
      { clientConfig: "client.cnf" },
    ],
    "manifest.signing": [
      "/run/platform/worker-secrets/manifest-signing",
      "worker.input.manifest-signing",
      { key: "signing.key" },
    ],
    "manifest.verification": [
      "/run/platform/worker-secrets/manifest-verification",
      "worker.input.manifest-verification",
      { key: "verification.pub" },
    ],
    "minio.capture.credentials": [
      "/run/platform/worker-secrets/minio-capture",
      "worker.input.minio-capture",
      { accessKey: "access-key", secretKey: "secret-key" },
    ],
    "offsite.credentials": [
      "/run/platform/worker-secrets/offsite",
      "worker.input.offsite",
      { password: "password", repository: "repository" },
    ],
    "postgres.capture.credentials": [
      "/run/platform/worker-secrets/postgres-capture",
      "worker.input.postgres-capture",
      { database: "database", pgpass: ".pgpass", username: "username" },
    ],
  };
  const workerSecretSets = normalizeExactMap(
    resources.workerSecretSets,
    Object.keys(secretSetIdentity),
    "workerSecretSets",
    (entry, logicalId) => {
      assertExactKeys(entry, ["containerRoot", "files", "volumeId"], `worker secret set ${logicalId}`);
      const [containerRoot, volumeId, expectedFiles] = secretSetIdentity[logicalId];
      if (entry.containerRoot !== containerRoot || entry.volumeId !== volumeId || !volumes[volumeId]) {
        fail(403, `worker secret set ${logicalId} canonical volume binding is invalid`);
      }
      const files = normalizeExactMap(entry.files, Object.keys(expectedFiles), `worker secret set ${logicalId} files`, (file, fileId) => {
        assertExactKeys(file, [
          "device",
          "inode",
          "mode",
          "ownerGid",
          "ownerUid",
          "relativePath",
          "sha256",
          "symlinkFree",
        ], `worker secret ${logicalId}.${fileId}`);
        assertProtectedFile(file, `worker secret ${logicalId}.${fileId}`);
        if (file.relativePath !== expectedFiles[fileId]) {
          fail(403, `worker secret ${logicalId}.${fileId} relative path is invalid`);
        }
        return Object.freeze({ ...file });
      });
      return Object.freeze({ ...entry, files });
    },
  );

  const serviceEndpoints = normalizeServiceEndpoints(resources.serviceEndpoints, {
    backupResources,
    containers,
    networks,
    workerSecretSets,
  });
  const helperProfiles = normalizeHelperProfiles(resources.helperProfiles, {
    networks,
    workerSecretSets,
  });

  const writableSubpaths = normalizeExactMap(
    resources.writableSubpaths,
    ["backup.quarantine"],
    "writableSubpaths",
    (entry, logicalId) => {
      assertExactKeys(entry, ["device", "mountId", "relativePath"], `writable subpath ${logicalId}`);
      const mount = mounts[entry.mountId];
      if (entry.mountId !== "backup.root.rw" || entry.relativePath !== ".quarantine"
        || !mount || mount.access !== "rw" || entry.device !== mount.device) {
        fail(403, `writable subpath ${logicalId} canonical mount binding is invalid`);
      }
      return Object.freeze({ ...entry });
    },
  );

  const actionProfiles = normalizeActionProfiles(resources.actionProfiles, {
    capabilityFiles,
    claimedJobSources,
  });
  const phaseProfiles = normalizePhaseProfiles(resources.phaseProfiles, {
    helperProfiles,
    mounts,
    networks,
    serviceEndpoints,
    volumes,
    workerSecretSets,
    writableSubpaths,
  });

  validateContainerMountAuthority(containers, mounts);
  return deepFreeze({
    actionProfiles,
    backupResources,
    capabilityFiles,
    claimedJobSources,
    containers,
    helperProfiles,
    mounts,
    networks,
    phaseProfiles,
    serviceEndpoints,
    volumes,
    workerSecretSets,
    writableSubpaths,
  });
}

function normalizeActionProfiles(value, { capabilityFiles, claimedJobSources }) {
  return normalizeExactMap(value, Object.keys(SCHEDULER_ACTIONS), "actionProfiles", (entry, action) => {
    assertExactKeys(entry, ACTION_PROFILE_KEYS, `action profile ${action}`);
    const plan = ACTION_PLANS[action];
    const expected = {
      capabilityFileId: `capability.${action}`,
      claimedJobSourceId: plan.claimedJobSourceId,
      jobOperations: plan.jobOperations,
      operationPhaseIds: plan.operationPhaseIds,
      phaseIds: plan.phaseIds,
      profileId: ACTIONS[action].profileId,
    };
    const unsigned = withoutKey(entry, "profileSha256");
    if (!SHA256.test(String(entry.profileSha256 ?? ""))
      || !constantEqual(entry.profileSha256, sha256(canonicalJson(unsigned)))) {
      fail(403, `action profile ${action} digest is invalid`);
    }
    if (canonicalJson(unsigned) !== canonicalJson(expected)) {
      fail(403, `action profile ${action} canonical identity or phase binding is invalid`);
    }
    if (!capabilityFiles[entry.capabilityFileId]) {
      fail(403, `action profile ${action} capability file binding is missing`);
    }
    if (entry.claimedJobSourceId !== null && !claimedJobSources[entry.claimedJobSourceId]) {
      fail(403, `action profile ${action} claimed-job source binding is missing`);
    }
    return deepFreeze(structuredClone(entry));
  });
}

function normalizeServiceEndpoints(value, {
  backupResources,
  containers,
  networks,
  workerSecretSets,
}) {
  return normalizeExactMap(
    value,
    Object.keys(SERVICE_ENDPOINT_PLANS),
    "serviceEndpoints",
    (entry, endpointId) => {
      const expected = SERVICE_ENDPOINT_PLANS[endpointId];
      assertExactKeys(entry, [
        "backupResourceId",
        "engine",
        "endpointId",
        "host",
        "networkId",
        "port",
        "protocol",
        "purpose",
        "secretSetId",
        "targetContainerId",
        "tlsMode",
      ], `service endpoint ${endpointId}`);
      if (canonicalJson(entry) !== canonicalJson(expected)) {
        fail(403, `service endpoint ${endpointId} canonical identity or authority binding is invalid`);
      }
      if (entry.endpointId !== endpointId || !DNS_HOST.test(entry.host) || entry.host.length > 253
        || !Number.isSafeInteger(entry.port) || entry.port < 1 || entry.port > 65535
        || !networks[entry.networkId] || !workerSecretSets[entry.secretSetId]) {
        fail(403, `service endpoint ${endpointId} identity, network or credential binding is invalid`);
      }
      if (entry.purpose === "capture") {
        const resource = backupResources[entry.backupResourceId];
        const container = containers[entry.targetContainerId];
        const expectedResourceEngine = resource?.kind === "database" ? resource.engine : resource?.kind === "storage" ? "minio" : null;
        if (!resource || !container || resource.externalId !== entry.targetContainerId
          || expectedResourceEngine !== entry.engine
          || !container.authority.networks.includes(networks[entry.networkId].engineName)) {
          fail(403, `service endpoint ${endpointId} resource or target container binding is invalid`);
        }
      } else if (entry.purpose !== "offsite"
        || entry.backupResourceId !== null
        || entry.targetContainerId !== null) {
        fail(403, `service endpoint ${endpointId} purpose binding is invalid`);
      }
      return deepFreeze(structuredClone(entry));
    },
  );
}

function normalizeHelperProfiles(value, { networks, workerSecretSets }) {
  return normalizeExactMap(
    value,
    Object.keys(HELPER_PROFILE_PLANS),
    "helperProfiles",
    (entry, helperProfileId) => {
      assertExactKeys(entry, [
        "engine",
        "entrypoint",
        "helperProfileId",
        "imageId",
        "imageRef",
        "networkId",
        "operation",
        "outputMode",
        "resourceKind",
        "secretSetId",
      ], `helper profile ${helperProfileId}`);
      const expected = HELPER_PROFILE_PLANS[helperProfileId];
      const semantic = withoutKey(entry, "imageId");
      if (entry.helperProfileId !== helperProfileId
        || canonicalJson(semantic) !== canonicalJson({ helperProfileId, ...expected })) {
        fail(403, `helper profile ${helperProfileId} canonical identity or authority binding is invalid`);
      }
      if (!DIGEST_IMAGE.test(String(entry.imageRef ?? ""))
        || !/^sha256:[a-f0-9]{64}$/.test(String(entry.imageId ?? ""))
        || !Array.isArray(entry.entrypoint)
        || entry.entrypoint.length !== 1
        || !entry.entrypoint.every((item) => typeof item === "string" && item.startsWith("/")
          && !item.includes("\0") && !item.includes("/../"))) {
        fail(403, `helper profile ${helperProfileId} image or entrypoint attestation is invalid`);
      }
      if (entry.networkId !== null && !networks[entry.networkId]) {
        fail(403, `helper profile ${helperProfileId} network binding is missing`);
      }
      if (entry.secretSetId !== null && !workerSecretSets[entry.secretSetId]) {
        fail(403, `helper profile ${helperProfileId} credential binding is missing`);
      }
      return deepFreeze(structuredClone(entry));
    },
  );
}

function normalizePhaseProfiles(value, {
  helperProfiles,
  mounts,
  networks,
  serviceEndpoints,
  volumes,
  workerSecretSets,
  writableSubpaths,
}) {
  return normalizeExactMap(value, Object.keys(PHASE_PLANS), "phaseProfiles", (entry, phaseId) => {
    assertExactKeys(entry, PHASE_PROFILE_KEYS, `phase profile ${phaseId}`);
    if (entry.phaseId !== phaseId) fail(403, `phase profile ${phaseId} identity is invalid`);
    const unsigned = withoutKey(entry, "phaseSha256");
    if (!SHA256.test(String(entry.phaseSha256 ?? ""))
      || !constantEqual(entry.phaseSha256, sha256(canonicalJson(unsigned)))) {
      fail(403, `phase profile ${phaseId} digest is invalid`);
    }
    const expected = PHASE_PLANS[phaseId];
    for (const field of [
      "command",
      "helperProfileIds",
      "mountIds",
      "mutationPolicy",
      "networkIds",
      "outputSchema",
      "scratchVolumeIds",
      "workerSecretSetIds",
      "writableSubpathIds",
    ]) {
      if (canonicalJson(entry[field]) !== canonicalJson(expected[field])) {
        fail(403, `phase profile ${phaseId} canonical ${field} binding is invalid`);
      }
    }
    if (!/^sha256:[a-f0-9]{64}$/.test(String(entry.workerImageId ?? ""))
      || !DIGEST_IMAGE.test(String(entry.workerImageRef ?? ""))) {
      fail(403, `phase profile ${phaseId} worker image binding is invalid`);
    }
    const expectedEndpointIds = Object.values(serviceEndpoints)
      .filter((endpoint) => endpoint.purpose === expected.endpointPurpose)
      .map((endpoint) => endpoint.endpointId)
      .sort();
    if (canonicalJson(entry.endpointIds) !== canonicalJson(expectedEndpointIds)) {
      fail(403, `phase profile ${phaseId} canonical endpoint binding is invalid`);
    }
    for (const mountId of entry.mountIds) {
      if (!mounts[mountId]) fail(403, `phase profile ${phaseId} has a dangling mount binding`);
    }
    for (const networkId of entry.networkIds) {
      if (!networks[networkId]) fail(403, `phase profile ${phaseId} has a dangling network binding`);
    }
    for (const endpointId of entry.endpointIds) {
      const endpoint = serviceEndpoints[endpointId];
      if (!endpoint || !entry.networkIds.includes(endpoint.networkId)
        || entry.workerSecretSetIds.includes(endpoint.secretSetId)
        || !entry.helperProfileIds.some((helperProfileId) => (
          helperProfiles[helperProfileId]?.secretSetId === endpoint.secretSetId
        ))) {
        fail(403, `phase profile ${phaseId} has a dangling endpoint authority binding`);
      }
    }
    for (const helperProfileId of entry.helperProfileIds) {
      const helperProfile = helperProfiles[helperProfileId];
      if (!helperProfile
        || (helperProfile.networkId !== null && !entry.networkIds.includes(helperProfile.networkId))
        || (helperProfile.secretSetId !== null && entry.workerSecretSetIds.includes(helperProfile.secretSetId))) {
        fail(403, `phase profile ${phaseId} has a dangling helper authority binding`);
      }
    }
    for (const volumeId of entry.scratchVolumeIds) {
      if (!volumes[volumeId]) fail(403, `phase profile ${phaseId} has a dangling scratch volume binding`);
    }
    for (const secretSetId of entry.workerSecretSetIds) {
      if (secretSetId.startsWith("capability.") || !workerSecretSets[secretSetId]) {
        fail(403, `phase profile ${phaseId} has a dangling worker secret-set binding`);
      }
    }
    for (const subpathId of entry.writableSubpathIds) {
      if (!writableSubpaths[subpathId]) fail(403, `phase profile ${phaseId} has a dangling writable-subpath binding`);
    }
    if (entry.mountIds.includes("backup.root.ro") && entry.mountIds.includes("backup.root.rw")) {
      fail(403, `phase profile ${phaseId} mixes read-only and writable backup roots`);
    }
    return deepFreeze(structuredClone(entry));
  });
}

function normalizeExactMap(value, expectedIds, label, normalize) {
  const map = assertPlainObject(value, label);
  if (canonicalJson(Object.keys(map).sort()) !== canonicalJson([...expectedIds].sort())) {
    fail(403, `${label} contains a missing or unsupported canonical identity`);
  }
  const out = {};
  for (const logicalId of Object.keys(map).sort()) {
    out[logicalId] = normalize(assertPlainObject(map[logicalId], `${label} ${logicalId}`), logicalId);
  }
  return Object.freeze(out);
}

function assertProtectedFile(entry, label) {
  if (entry.symlinkFree !== true || entry.ownerUid !== 0 || entry.ownerGid !== 0
    || entry.mode !== 0o400 || !Number.isSafeInteger(entry.device) || entry.device < 0
    || !Number.isSafeInteger(entry.inode) || entry.inode < 1
    || !SHA256.test(String(entry.sha256 ?? ""))) {
    fail(403, `${label} ownership, identity or digest attestation is invalid`);
  }
}

function normalizeMap(value, label, normalize, idPattern = LOGICAL_ID) {
  const map = assertPlainObject(value, label);
  const out = {};
  for (const logicalId of Object.keys(map).sort()) {
    if (!idPattern.test(logicalId)) fail(403, `${label} logical ID is invalid`);
    out[logicalId] = normalize(assertPlainObject(map[logicalId], `${label} ${logicalId}`), logicalId);
  }
  return Object.freeze(out);
}

function normalizeBackupResource(entry, logicalId) {
  const kind = logicalId.split(":", 1)[0];
  const common = ["externalId", "kind", "name", "projectId"];
  const expected = kind === "database" ? [...common, "engine"] : kind === "source" ? [...common, "sourceDirectory"] : common;
  assertExactKeys(entry, expected, `backup resource ${logicalId}`);
  if (entry.kind !== kind) fail(403, `backup resource ${logicalId} kind does not match its ID`);
  if (!LOGICAL_ID.test(String(entry.externalId ?? "")) || !LOGICAL_ID.test(String(entry.projectId ?? ""))) {
    fail(403, `backup resource ${logicalId} ownership is invalid`);
  }
  if (!CONTAINER_NAME.test(String(entry.name ?? ""))) fail(403, `backup resource ${logicalId} name is invalid`);
  const normalized = { externalId: entry.externalId, kind, name: entry.name, projectId: entry.projectId };
  if (kind === "database") {
    if (!["postgres", "mariadb"].includes(entry.engine)) fail(403, `backup resource ${logicalId} engine is invalid`);
    normalized.engine = entry.engine;
  }
  if (kind === "source") {
    if (!CONTAINER_NAME.test(String(entry.sourceDirectory ?? ""))) fail(403, `backup resource ${logicalId} source directory is invalid`);
    normalized.sourceDirectory = entry.sourceDirectory;
  }
  return Object.freeze(normalized);
}

function normalizeIdentityLabels(value, logicalId) {
  const labels = assertPlainObject(value, `container ${logicalId} labels`);
  const keys = [
    "com.platform.runtime.candidate-id",
    "com.platform.runtime.commit",
    "com.platform.runtime.deployment-id",
    "com.platform.runtime.source-render-sha256",
    "com.platform.runtime.tree",
    "com.platform.runtime.workload-lock-sha256",
  ];
  assertExactKeys(labels, keys, `container ${logicalId} labels`);
  const out = {};
  for (const key of keys) {
    const text = String(labels[key] ?? "");
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/.test(text)) fail(403, `container ${logicalId} label ${key} is invalid`);
    out[key] = text;
  }
  return Object.freeze(out);
}

function normalizeContainerAuthority(value, logicalId) {
  const authority = assertPlainObject(value, `container ${logicalId} authority`);
  const keys = [
    "binds",
    "capAdd",
    "capDrop",
    "cgroupnsMode",
    "configSha256",
    "deviceCgroupRules",
    "devices",
    "deviceRequests",
    "extraHosts",
    "groupAdd",
    "hostConfigSha256",
    "ipcMode",
    "links",
    "mounts",
    "networkMode",
    "networkSettingsSha256",
    "networks",
    "pidMode",
    "portBindings",
    "privileged",
    "publishAllPorts",
    "readonlyRootfs",
    "runtime",
    "securityOpt",
    "user",
    "usernsMode",
    "utsMode",
    "volumesFrom",
  ];
  assertExactKeys(authority, keys, `container ${logicalId} authority`);
  const stringArrays = {};
  for (const key of [
    "binds",
    "capAdd",
    "capDrop",
    "deviceCgroupRules",
    "devices",
    "deviceRequests",
    "extraHosts",
    "groupAdd",
    "links",
    "networks",
    "securityOpt",
    "volumesFrom",
  ]) {
    if (!Array.isArray(authority[key]) || authority[key].some((item) => typeof item !== "string" || item.length > 512)) {
      fail(403, `container ${logicalId} authority ${key} is invalid`);
    }
    stringArrays[key] = Object.freeze([...authority[key]]);
  }
  for (const key of ["configSha256", "hostConfigSha256", "networkSettingsSha256"]) {
    if (!SHA256.test(String(authority[key] ?? ""))) fail(403, `container ${logicalId} authority ${key} is invalid`);
  }
  const portBindings = assertPlainObject(authority.portBindings, `container ${logicalId} authority portBindings`);
  if (authority.privileged !== false || authority.publishAllPorts !== false || ["host", "container"].includes(authority.networkMode)
    || authority.pidMode === "host" || authority.ipcMode === "host" || authority.cgroupnsMode === "host"
    || authority.usernsMode === "host" || authority.utsMode === "host"
    || String(authority.networkMode).startsWith("container:")
    || stringArrays.devices.length || stringArrays.deviceRequests.length || stringArrays.deviceCgroupRules.length
    || stringArrays.capAdd.length || stringArrays.groupAdd.length || stringArrays.links.length
    || stringArrays.volumesFrom.length || stringArrays.extraHosts.length || Object.keys(portBindings).length
    || authority.runtime !== "runc") {
    fail(403, `container ${logicalId} authority contains a forbidden host privilege`);
  }
  for (const bind of stringArrays.binds) {
    const [source, destination, access, ...extra] = bind.split(":");
    if (!source || !destination || extra.length || !["ro", "rw"].includes(access)
      || !source.startsWith("/srv/platform/") || source.includes("/../") || source.includes("docker.sock")
      || !ALLOWED_CONTAINER_PATHS.has(destination)) {
      fail(403, `container ${logicalId} authority contains a forbidden bind`);
    }
  }
  if (!Array.isArray(authority.mounts)) fail(403, `container ${logicalId} authority mounts are invalid`);
  const mounts = authority.mounts.map((mount, index) => {
    const item = assertPlainObject(mount, `container ${logicalId} mount ${index}`);
    assertExactKeys(item, ["destination", "rw", "source", "type"], `container ${logicalId} mount ${index}`);
    const safeBind = item.type !== "bind" || (item.source.startsWith("/srv/platform/")
      && !item.source.includes("/../") && !item.source.includes("docker.sock"));
    const safeVolume = item.type !== "volume" || /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(item.source);
    if (!["bind", "volume", "tmpfs"].includes(item.type) || typeof item.source !== "string" || typeof item.destination !== "string"
      || typeof item.rw !== "boolean" || !safeBind || !safeVolume || !ALLOWED_CONTAINER_PATHS.has(item.destination)) {
      fail(403, `container ${logicalId} mount ${index} is forbidden`);
    }
    return Object.freeze({ destination: item.destination, rw: item.rw, source: item.source, type: item.type });
  });
  for (const key of ["networkMode", "pidMode", "ipcMode", "cgroupnsMode", "usernsMode", "utsMode", "runtime", "user"]) {
    if (typeof authority[key] !== "string" || authority[key].length > 256) fail(403, `container ${logicalId} authority ${key} is invalid`);
  }
  if (typeof authority.readonlyRootfs !== "boolean" || typeof authority.publishAllPorts !== "boolean") {
    fail(403, `container ${logicalId} rootfs or port publication authority is invalid`);
  }
  return Object.freeze({
    ...stringArrays,
    mounts: Object.freeze(mounts),
    configSha256: authority.configSha256,
    hostConfigSha256: authority.hostConfigSha256,
    networkSettingsSha256: authority.networkSettingsSha256,
    networkMode: authority.networkMode,
    pidMode: authority.pidMode,
    ipcMode: authority.ipcMode,
    cgroupnsMode: authority.cgroupnsMode,
    usernsMode: authority.usernsMode,
    utsMode: authority.utsMode,
    runtime: authority.runtime,
    portBindings: Object.freeze({}),
    privileged: false,
    publishAllPorts: false,
    readonlyRootfs: authority.readonlyRootfs,
    user: authority.user,
  });
}

function validateContainerMountAuthority(containers, mounts) {
  const attestations = new Set(Object.values(mounts).map((mount) => canonicalJson({
    source: mount.canonicalPath,
    destination: mount.containerPath,
    access: mount.access,
  })));
  for (const [logicalId, container] of Object.entries(containers)) {
    for (const bind of container.authority.binds) {
      const [source, destination, access] = bind.split(":");
      if (!attestations.has(canonicalJson({ source, destination, access }))) {
        fail(403, `container ${logicalId} bind is not backed by an exact host-path attestation`);
      }
    }
    for (const mount of container.authority.mounts.filter((item) => item.type === "bind")) {
      const access = mount.rw ? "rw" : "ro";
      if (!attestations.has(canonicalJson({ source: mount.source, destination: mount.destination, access }))) {
        fail(403, `container ${logicalId} bind mount is not backed by an exact host-path attestation`);
      }
    }
  }
}

function assertTimeWindow(issuedAtValue, expiresAtValue, now, maximumLifetimeMs, label) {
  const issuedAt = Date.parse(String(issuedAtValue ?? ""));
  const expiresAt = Date.parse(String(expiresAtValue ?? ""));
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt || expiresAt - issuedAt > maximumLifetimeMs) {
    fail(401, `${label} validity window is invalid`);
  }
  if (issuedAt > now + MAX_CLOCK_SKEW_MS) fail(401, `${label} is not yet valid`);
  if (expiresAt < now) fail(401, `${label} is expired`);
}

function verifyMac(document, key, label) {
  const actual = String(document.mac ?? "");
  if (!SHA256.test(actual)) fail(401, `${label} authentication failed`);
  const expected = hmac(withoutKey(document, "mac"), key);
  if (!constantEqual(actual, expected)) fail(401, `${label} authentication failed`);
}

function verifyDomainMac(document, key, schema, label) {
  const actual = String(document.mac ?? "");
  if (!SHA256.test(actual)) fail(401, `${label} authentication failed`);
  const expected = domainHmac(schema, withoutKey(document, "mac"), key);
  if (!constantEqual(actual, expected)) fail(401, `${label} authentication failed`);
}

function normalizeKey(key) {
  const value = Buffer.isBuffer(key) ? key : Buffer.from(String(key ?? ""));
  if (value.length < 32 || value.length > 4096) fail(500, "capability key length is invalid");
  return value;
}

function canonicalValue(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError("canonical JSON accepts only plain JSON values");
  }
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
}

function withoutKey(value, omitted) {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== omitted));
}

function assertPlainObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(400, `${label} must be an object`);
  }
  return value;
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) fail(400, `${label} contains unsupported or missing fields`);
}

function assertLogicalId(value, label) {
  if (!LOGICAL_ID.test(String(value ?? ""))) fail(403, `${label} is invalid`);
}

function constantEqual(left, right) {
  const actual = Buffer.from(String(left));
  const expected = Buffer.from(String(right));
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function phasePlan({
  command,
  endpointPurpose,
  helperProfileIds,
  mountIds,
  mutationPolicy,
  networkIds,
  outputSchema,
  scratchVolumeIds = [],
  workerSecretSetIds = [],
  writableSubpathIds = [],
}) {
  return {
    command,
    endpointPurpose,
    helperProfileIds,
    mountIds,
    mutationPolicy,
    networkIds,
    outputSchema,
    scratchVolumeIds,
    workerSecretSetIds,
    writableSubpathIds,
  };
}

function helperProfilePlan({
  engine,
  entrypoint,
  imageRef,
  networkId = null,
  operation,
  outputMode,
  resourceKind,
  secretSetId = null,
}) {
  return {
    engine,
    entrypoint,
    imageRef,
    networkId,
    operation,
    outputMode,
    resourceKind,
    secretSetId,
  };
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function fail(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  throw error;
}
