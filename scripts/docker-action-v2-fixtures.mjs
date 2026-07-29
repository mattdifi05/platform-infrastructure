import crypto from "node:crypto";

export const FIXTURE_NOW = Date.parse("2026-07-28T12:00:00.000Z");
export const ACTIVE_RECEIPT_SCHEMA_V2 = "platform.docker-active-receipt/v2";
export const REQUEST_SCHEMA_V2 = "platform.docker-action.request/v2";
export const RESPONSE_SCHEMA_V2 = "platform.docker-action.response/v2";
export const FIXTURE_TRUST_KEY = Buffer.from("runtime-intent-v2-trust-key-material".repeat(2));

export const SCHEDULER_ACTION_NAMES = Object.freeze([
  "backup.catalog",
  "backup.job.execute",
  "backup.prune.plan",
  "backup.prune.apply",
  "restore.drill.full",
  "backup.offsite.sync",
]);
export const EVIDENCE_ACTION_NAMES = Object.freeze(["evidence.runtime.snapshot"]);
export const ALL_ACTION_NAMES = Object.freeze([
  ...SCHEDULER_ACTION_NAMES,
  ...EVIDENCE_ACTION_NAMES,
]);

export const EXPECTED_ACTION_BINDINGS = deepFreeze({
  "backup.catalog": {
    capabilityFile: "/run/secrets/docker_action_backup_catalog",
    capabilityId: "backup.catalog.v2",
    profileId: "scheduler.backup.catalog.v2",
  },
  "backup.job.execute": {
    capabilityFile: "/run/secrets/docker_action_backup_job_execute",
    capabilityId: "backup.job.execute.v2",
    profileId: "scheduler.backup.job.execute.v2",
  },
  "backup.prune.plan": {
    capabilityFile: "/run/secrets/docker_action_backup_prune_plan",
    capabilityId: "backup.prune.plan.v2",
    profileId: "scheduler.backup.prune.plan.v2",
  },
  "backup.prune.apply": {
    capabilityFile: "/run/secrets/docker_action_backup_prune_apply",
    capabilityId: "backup.prune.apply.v2",
    profileId: "scheduler.backup.prune.apply.v2",
  },
  "restore.drill.full": {
    capabilityFile: "/run/secrets/docker_action_restore_drill_full",
    capabilityId: "restore.drill.full.v2",
    profileId: "scheduler.restore.drill.full.v2",
  },
  "backup.offsite.sync": {
    capabilityFile: "/run/secrets/docker_action_backup_offsite_sync",
    capabilityId: "backup.offsite.sync.v2",
    profileId: "scheduler.backup.offsite.sync.v2",
  },
  "evidence.runtime.snapshot": {
    capabilityFile: "/run/secrets/docker_action_evidence_runtime_snapshot",
    capabilityId: "evidence.runtime.snapshot.v2",
    profileId: "evidence.runtime.snapshot.v2",
  },
});

export const EXPECTED_ACTION_PHASES = deepFreeze({
  "backup.catalog": {
    jobOperations: [],
    operationPhaseIds: {},
    phaseIds: ["catalog.capture"],
  },
  "backup.job.execute": {
    jobOperations: ["backup", "restore-drill"],
    operationPhaseIds: {
      backup: ["job.backup.capture"],
      "restore-drill": ["job.restore.verify"],
    },
    phaseIds: [],
  },
  "backup.prune.plan": {
    jobOperations: [],
    operationPhaseIds: {},
    phaseIds: ["prune.plan"],
  },
  "backup.prune.apply": {
    jobOperations: [],
    operationPhaseIds: {},
    phaseIds: ["prune.apply"],
  },
  "restore.drill.full": {
    jobOperations: [],
    operationPhaseIds: {},
    phaseIds: ["restore.capture", "restore.verify"],
  },
  "backup.offsite.sync": {
    jobOperations: [],
    operationPhaseIds: {},
    phaseIds: ["offsite.sync"],
  },
});

export const EXPECTED_CLAIMED_JOB_SOURCE_IDS = deepFreeze({
  "backup.catalog": null,
  "backup.job.execute": "jobs.running",
  "backup.prune.plan": null,
  "backup.prune.apply": null,
  "restore.drill.full": null,
  "backup.offsite.sync": null,
});

export const EXPECTED_PHASE_PROFILES = deepFreeze({
  "catalog.capture": phase({
    command: "backup-catalog",
    mountIds: ["backup.root.rw", "report.root.rw", "source.root.ro", "state.catalog.ro"],
    mutationPolicy: "backup-write",
    networkIds: ["platform_db_admin", "platform_storage"],
    outputSchema: "platform.backup-catalog/v1",
    workerSecretSetIds: ["manifest.signing"],
  }),
  "job.backup.capture": phase({
    command: "backup-job",
    mountIds: ["backup.root.rw", "report.root.rw", "source.root.ro", "state.catalog.ro"],
    mutationPolicy: "backup-write",
    networkIds: ["platform_db_admin", "platform_storage"],
    outputSchema: "platform.backup-job-result/v1",
    workerSecretSetIds: ["manifest.signing"],
  }),
  "job.restore.verify": phase({
    command: "restore-job",
    mountIds: ["backup.root.ro", "report.root.rw"],
    mutationPolicy: "restore-disposable",
    networkIds: [],
    outputSchema: "platform.backup-job-result/v1",
    scratchVolumeIds: ["restore.scratch"],
    workerSecretSetIds: ["manifest.verification"],
  }),
  "prune.plan": phase({
    command: "backup-prune-plan",
    mountIds: ["backup.root.ro", "report.root.rw"],
    mutationPolicy: "report-only",
    networkIds: [],
    outputSchema: "platform.backup-prune-plan/v1",
    workerSecretSetIds: ["manifest.verification"],
  }),
  "prune.apply": phase({
    command: "backup-prune-apply",
    mountIds: ["backup.root.rw", "report.root.rw"],
    mutationPolicy: "retention-apply",
    networkIds: [],
    outputSchema: "platform.backup-prune-apply/v1",
    workerSecretSetIds: ["manifest.verification"],
    writableSubpathIds: ["backup.quarantine"],
  }),
  "restore.capture": phase({
    command: "backup-catalog",
    mountIds: ["backup.root.rw", "report.root.rw", "source.root.ro", "state.catalog.ro"],
    mutationPolicy: "backup-write",
    networkIds: ["platform_db_admin", "platform_storage"],
    outputSchema: "platform.backup-catalog/v1",
    workerSecretSetIds: ["manifest.signing"],
  }),
  "restore.verify": phase({
    command: "restore-drill-full",
    mountIds: ["backup.root.ro", "report.root.rw"],
    mutationPolicy: "restore-disposable",
    networkIds: [],
    outputSchema: "platform.restore-drill/v1",
    scratchVolumeIds: ["restore.scratch"],
    workerSecretSetIds: ["manifest.verification"],
  }),
  "offsite.sync": phase({
    command: "backup-offsite-sync",
    mountIds: ["backup.root.ro", "report.root.rw"],
    mutationPolicy: "offsite-write",
    networkIds: ["platform_egress"],
    outputSchema: "platform.offsite-backup-receipt/v1",
    workerSecretSetIds: ["manifest.verification", "offsite.credentials"],
  }),
});

export const ACTION_PROFILE_KEYS = Object.freeze([
  "capabilityFileId",
  "claimedJobSourceId",
  "jobOperations",
  "operationPhaseIds",
  "phaseIds",
  "profileId",
  "profileSha256",
]);
export const PHASE_PROFILE_KEYS = Object.freeze([
  "command",
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
export const ACTIVE_RECEIPT_KEYS = Object.freeze([
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
]);
export const ACTIVE_RECEIPT_RESOURCE_KEYS = Object.freeze([
  "actionProfiles",
  "backupResources",
  "capabilityFiles",
  "claimedJobSources",
  "containers",
  "mounts",
  "networks",
  "phaseProfiles",
  "volumes",
  "workerSecretSets",
  "writableSubpaths",
]);

export function canonicalFixtureJson(value) {
  return JSON.stringify(canonicalFixtureValue(value));
}

export function fixtureSha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function capabilityFileId(action) {
  requireAction(action);
  return `capability.${action}`;
}

export function fixtureCapabilityKey(action) {
  requireAction(action);
  return crypto
    .createHash("sha256")
    .update("test-only:platform.docker-action.capability/v2\0")
    .update(action)
    .digest();
}

export function expectedActionPhases(action) {
  return structuredClone(requiredBinding(EXPECTED_ACTION_PHASES, action, "action phase"));
}

export function expectedClaimedJobSourceId(action) {
  return requiredBinding(EXPECTED_CLAIMED_JOB_SOURCE_IDS, action, "claimed-job source");
}

export function expectedPhaseProfile(phaseId) {
  return structuredClone(requiredBinding(EXPECTED_PHASE_PROFILES, phaseId, "phase profile"));
}

export function buildFixtureNetworkInspect(receipt, logicalId) {
  const admitted = requiredBinding(receipt?.resources?.networks ?? {}, logicalId, "network");
  const material = fixtureNetworkMaterial(admitted.engineName, admitted.internal);
  return {
    Name: admitted.engineName,
    Id: admitted.engineId,
    Driver: admitted.driver,
    Internal: admitted.internal,
    Scope: admitted.scope,
    Labels: material.labels,
    Options: material.options,
    IPAM: material.ipam,
    Containers: material.membership,
  };
}

export function buildFixtureVolumeInspect(receipt, logicalId) {
  const admitted = requiredBinding(receipt?.resources?.volumes ?? {}, logicalId, "volume");
  const material = fixtureVolumeMaterial(admitted.engineName);
  return {
    Name: admitted.engineName,
    Driver: admitted.driver,
    Scope: admitted.scope,
    Labels: material.labels,
    Options: material.options,
  };
}

// Compatibility helpers intentionally return action unions only for older RED
// callers. Authoritative v2 admission uses phaseProfiles, never these unions.
export function expectedFixedMountIds(action) {
  return unionPhaseField(action, "mountIds");
}

export function expectedJobOperationMountIds(action) {
  const plan = expectedActionPhases(action);
  return Object.fromEntries(
    Object.entries(plan.operationPhaseIds).map(([operation, phaseIds]) => [
      operation,
      uniqueSorted(phaseIds.flatMap((phaseId) => EXPECTED_PHASE_PROFILES[phaseId].mountIds)),
    ]),
  );
}

export function expectedNetworkIds(action) {
  return unionPhaseField(action, "networkIds");
}

export function expectedWorkerSecretSetIds(action) {
  return unionPhaseField(action, "workerSecretSetIds");
}

export function profileDigest(profile) {
  return digestWithout(profile, "profileSha256");
}

export function phaseDigest(profile) {
  return digestWithout(profile, "phaseSha256");
}

export function resealActionProfiles(receipt) {
  for (const profile of Object.values(receipt.resources.actionProfiles ?? {})) {
    if (isPlainObject(profile)) profile.profileSha256 = profileDigest(profile);
  }
  for (const profile of Object.values(receipt.resources.phaseProfiles ?? {})) {
    if (isPlainObject(profile)) profile.phaseSha256 = phaseDigest(profile);
  }
  return receipt;
}

export const resealProfiles = resealActionProfiles;

export function buildRawActiveReceiptV2({ now = FIXTURE_NOW } = {}) {
  const capabilityFiles = {};
  for (const [index, action] of ALL_ACTION_NAMES.entries()) {
    capabilityFiles[capabilityFileId(action)] = protectedCapabilityFile({
      brokerPath: EXPECTED_ACTION_BINDINGS[action].capabilityFile,
      inode: 1000 + index,
      sha256: fixtureSha256(fixtureCapabilityKey(action)),
    });
  }

  const actionProfiles = {};
  for (const action of SCHEDULER_ACTION_NAMES) {
    const expected = EXPECTED_ACTION_PHASES[action];
    const unsigned = {
      capabilityFileId: capabilityFileId(action),
      claimedJobSourceId: expectedClaimedJobSourceId(action),
      jobOperations: [...expected.jobOperations],
      operationPhaseIds: structuredClone(expected.operationPhaseIds),
      phaseIds: [...expected.phaseIds],
      profileId: EXPECTED_ACTION_BINDINGS[action].profileId,
    };
    actionProfiles[action] = { ...unsigned, profileSha256: profileDigest(unsigned) };
  }

  const phaseProfiles = {};
  for (const [index, [phaseId, expected]] of Object.entries(EXPECTED_PHASE_PROFILES).entries()) {
    const digest = fixtureSha256(`fixture:worker-image:${phaseId}`);
    const unsigned = {
      ...structuredClone(expected),
      phaseId,
      workerImageId: `sha256:${digest}`,
      workerImageRef: `registry.example/platform/docker-action-${index + 1}@sha256:${digest}`,
    };
    phaseProfiles[phaseId] = { ...unsigned, phaseSha256: phaseDigest(unsigned) };
  }

  return {
    schema: ACTIVE_RECEIPT_SCHEMA_V2,
    activationBundleSha256: "a".repeat(64),
    candidateId: "candidate.v2",
    combinedRenderSha256: "b".repeat(64),
    dastChainSha256: "c".repeat(64),
    environment: "production",
    expiresAt: new Date(now + 60 * 60_000).toISOString(),
    generation: 2,
    issuedAt: new Date(now - 60_000).toISOString(),
    receiptId: "receipt.v2",
    releaseId: "release.v2",
    resources: {
      actionProfiles,
      backupResources: {
        "database:postgres": {
          engine: "postgres",
          externalId: "postgres",
          kind: "database",
          name: "postgres",
          projectId: "platform",
        },
        "platform-state:catalog": {
          externalId: "catalog",
          kind: "platform-state",
          name: "catalog",
          projectId: "platform",
        },
        "source:platform": {
          externalId: "platform",
          kind: "source",
          name: "platform",
          projectId: "platform",
          sourceDirectory: "platform",
        },
        "storage:minio": {
          externalId: "minio",
          kind: "storage",
          name: "minio",
          projectId: "platform",
        },
      },
      capabilityFiles,
      claimedJobSources: {
        "jobs.running": {
          brokerRoot: "/run/platform/backup-jobs/running",
          maximumBytes: 128 * 1024,
          volumeId: "jobs.queue",
          volumeSubpath: "running",
        },
      },
      containers: {},
      mounts: {
        "backup.root.ro": protectedMount({
          access: "ro",
          canonicalPath: "/srv/platform/backups",
          containerPath: "/data/backups",
          device: 42,
          inode: 4242,
        }),
        "backup.root.rw": protectedMount({
          access: "rw",
          canonicalPath: "/srv/platform/backups",
          containerPath: "/data/backups",
          device: 42,
          inode: 4242,
        }),
        "report.root.rw": protectedMount({
          access: "rw",
          canonicalPath: "/srv/platform/reports",
          containerPath: "/data/reports",
          device: 43,
          inode: 4300,
        }),
        "source.root.ro": protectedMount({
          access: "ro",
          canonicalPath: "/srv/platform/project-sources",
          containerPath: "/data/source",
          device: 44,
          inode: 4400,
        }),
        "state.catalog.ro": protectedMount({
          access: "ro",
          canonicalPath: "/srv/platform/project-state",
          containerPath: "/data/state",
          device: 45,
          inode: 4500,
        }),
      },
      networks: {
        platform_db_admin: admittedNetwork({
          engineId: "a".repeat(64),
          engineName: "platform_db_admin",
          externalEgress: false,
          internal: true,
        }),
        platform_storage: admittedNetwork({
          engineId: "b".repeat(64),
          engineName: "platform_storage",
          externalEgress: false,
          internal: true,
        }),
        platform_egress: admittedNetwork({
          engineId: "c".repeat(64),
          engineName: "platform_egress",
          externalEgress: true,
          internal: false,
        }),
      },
      phaseProfiles,
      volumes: {
        "jobs.queue": admittedVolume({
          engineName: "platform_infra_vps_backup_scheduler_jobs",
          seed: "jobs-queue",
        }),
        "restore.scratch": admittedVolume({
          containerPath: "/run/platform/restore-scratch",
          engineName: "platform_docker_action_restore_scratch",
          seed: "restore-scratch",
        }),
        "worker.input.manifest-signing": admittedVolume({
          engineName: "platform_docker_action_manifest_signing",
          seed: "manifest-signing",
        }),
        "worker.input.manifest-verification": admittedVolume({
          engineName: "platform_docker_action_manifest_verification",
          seed: "manifest-verification",
        }),
        "worker.input.offsite": admittedVolume({
          engineName: "platform_docker_action_offsite_credentials",
          seed: "offsite-credentials",
        }),
      },
      workerSecretSets: {
        "manifest.signing": workerSecretSet({
          containerRoot: "/run/platform/worker-secrets/manifest-signing",
          files: {
            key: protectedVolumeFile({
              inode: 2000,
              relativePath: "signing.key",
              sha256: "d".repeat(64),
            }),
          },
          volumeId: "worker.input.manifest-signing",
        }),
        "manifest.verification": workerSecretSet({
          containerRoot: "/run/platform/worker-secrets/manifest-verification",
          files: {
            key: protectedVolumeFile({
              inode: 2001,
              relativePath: "verification.pub",
              sha256: "e".repeat(64),
            }),
          },
          volumeId: "worker.input.manifest-verification",
        }),
        "offsite.credentials": workerSecretSet({
          containerRoot: "/run/platform/worker-secrets/offsite",
          files: {
            password: protectedVolumeFile({
              inode: 2002,
              relativePath: "password",
              sha256: "f".repeat(64),
            }),
            repository: protectedVolumeFile({
              inode: 2003,
              relativePath: "repository",
              sha256: "1".repeat(64),
            }),
          },
          volumeId: "worker.input.offsite",
        }),
      },
      writableSubpaths: {
        "backup.quarantine": {
          device: 42,
          mountId: "backup.root.rw",
          relativePath: ".quarantine",
        },
      },
    },
    sourceRenderSha256: "5".repeat(64),
    targetId: "platform.primary",
    treeSha256: "6".repeat(64),
  };
}

export function buildTrustedContextV2(contract, {
  allowedActions = SCHEDULER_ACTION_NAMES,
  now = FIXTURE_NOW,
  rawReceipt = buildRawActiveReceiptV2({ now }),
  trustKey = FIXTURE_TRUST_KEY,
} = {}) {
  requireContractFunctions(contract, [
    "canonicalJson",
    "normalizeActiveReceipt",
    "normalizeTrustedContext",
    "sha256",
    "signRuntimeIntent",
  ]);
  const receipt = contract.normalizeActiveReceipt(rawReceipt, { now });
  const receiptDigest = contract.sha256(contract.canonicalJson(receipt));
  const unsignedIntent = {
    schema: contract.RUNTIME_INTENT_SCHEMA,
    activeReceiptSha256: receiptDigest,
    activationBundleSha256: receipt.activationBundleSha256,
    allowedActions: [...allowedActions],
    candidateId: receipt.candidateId,
    combinedRenderSha256: receipt.combinedRenderSha256,
    dastChainSha256: receipt.dastChainSha256,
    environment: receipt.environment,
    expiresAt: new Date(now + 30 * 60_000).toISOString(),
    generation: receipt.generation,
    intentId: "intent.release-v2",
    issuedAt: new Date(now - 30_000).toISOString(),
    releaseId: receipt.releaseId,
    targetId: receipt.targetId,
  };
  const intent = contract.signRuntimeIntent(unsignedIntent, trustKey);
  const trusted = contract.normalizeTrustedContext(intent, rawReceipt, trustKey, { now });
  return Object.freeze({ intent, rawReceipt, receipt, receiptDigest, trusted });
}

export function buildFixtureUnsignedActionRequestV2(action, parameters, {
  index = 0,
  now = FIXTURE_NOW,
  trustedContext,
} = {}) {
  requireAction(action);
  if (!trustedContext?.intent || !trustedContext?.receipt || !trustedContext?.receiptDigest) {
    throw new TypeError("an independently constructed trusted context is required");
  }
  const suffix = String(index).padStart(12, "0");
  return {
    schema: REQUEST_SCHEMA_V2,
    requestId: `123e4567-e89b-42d3-a456-${suffix}`,
    nonce: Buffer.alloc(32, (index % 255) + 1).toString("base64url"),
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 30_000).toISOString(),
    runtimeIntentId: trustedContext.intent.intentId,
    activeReceiptSha256: trustedContext.receiptDigest,
    combinedRenderSha256: trustedContext.receipt.combinedRenderSha256,
    capabilityId: EXPECTED_ACTION_BINDINGS[action].capabilityId,
    action,
    parameters: structuredClone(parameters),
  };
}

export function signFixtureActionRequestV2(unsigned, capabilityKey) {
  if (!isPlainObject(unsigned) || unsigned.schema !== REQUEST_SCHEMA_V2 || Object.hasOwn(unsigned, "mac")) {
    throw new TypeError("unsigned request/v2 fixture is malformed");
  }
  const mac = crypto
    .createHmac("sha256", capabilityKey)
    .update(`${REQUEST_SCHEMA_V2}\0`)
    .update(canonicalFixtureJson(unsigned))
    .digest("hex");
  return { ...structuredClone(unsigned), mac };
}

export function buildFixtureSignedActionRequestV2(action, parameters, options = {}) {
  const unsigned = buildFixtureUnsignedActionRequestV2(action, parameters, options);
  return signFixtureActionRequestV2(
    unsigned,
    options.capabilityKey ?? fixtureCapabilityKey(action),
  );
}

export function buildSignedActionRequestV2(contract, action, parameters, {
  capabilityKey = fixtureCapabilityKey(action),
  index = 0,
  now = FIXTURE_NOW,
  trustedContext,
} = {}) {
  requireContractFunctions(contract, ["buildUnsignedRequest", "signActionRequest"]);
  const trusted = trustedContext
    ?? buildTrustedContextV2(contract, { allowedActions: [action], now }).trusted;
  const suffix = String(index).padStart(12, "0");
  const unsigned = contract.buildUnsignedRequest(action, parameters, trusted, {
    now,
    requestId: `123e4567-e89b-42d3-a456-${suffix}`,
    nonce: Buffer.alloc(32, index + 1).toString("base64url"),
  });
  return contract.signActionRequest(unsigned, capabilityKey);
}

function phase({
  command,
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
    mountIds,
    mutationPolicy,
    networkIds,
    outputSchema,
    scratchVolumeIds,
    workerSecretSetIds,
    writableSubpathIds,
  };
}

function protectedCapabilityFile({ brokerPath, inode, sha256 }) {
  return {
    brokerPath,
    device: 100,
    inode,
    mode: 0o400,
    ownerGid: 0,
    ownerUid: 0,
    sha256,
    symlinkFree: true,
  };
}

function protectedMount({
  access,
  canonicalPath,
  containerPath,
  device,
  inode,
}) {
  return {
    access,
    canonicalPath,
    containerPath,
    device,
    inode,
    kind: "host-directory",
    mode: 0o700,
    ownerGid: 0,
    ownerUid: 0,
    symlinkFree: true,
  };
}

function admittedNetwork({ engineId, engineName, externalEgress, internal }) {
  const material = fixtureNetworkMaterial(engineName, internal);
  return {
    driver: "bridge",
    engineId,
    engineName,
    externalEgress,
    internal,
    labelsSha256: fixtureSha256(canonicalFixtureJson(material.labels)),
    membershipSha256: fixtureSha256(canonicalFixtureJson(material.membership)),
    optionsSha256: fixtureSha256(canonicalFixtureJson(material.options)),
    scope: "local",
    subnetSha256: fixtureSha256(canonicalFixtureJson(material.ipam)),
  };
}

function admittedVolume({ containerPath = null, engineName, seed }) {
  const material = fixtureVolumeMaterial(engineName);
  return {
    containerPath,
    driver: "local",
    engineName,
    labelsSha256: fixtureSha256(canonicalFixtureJson(material.labels)),
    optionsSha256: fixtureSha256(canonicalFixtureJson(material.options)),
    scope: "local",
  };
}

function fixtureNetworkMaterial(engineName, internal) {
  const subnetByName = {
    platform_db_admin: "172.29.0.0/24",
    platform_storage: "172.30.0.0/24",
    platform_egress: "172.31.0.0/24",
  };
  return {
    labels: {
      "com.docker.compose.network": engineName,
      "com.platform.network-authority": "docker-action-broker-v2",
    },
    membership: {},
    options: {
      "com.docker.network.bridge.enable_icc": internal ? "false" : "true",
    },
    ipam: {
      Config: [{ Subnet: subnetByName[engineName] }],
      Driver: "default",
      Options: null,
    },
  };
}

function fixtureVolumeMaterial(engineName) {
  return {
    labels: {
      "com.docker.compose.volume": engineName,
      "com.platform.volume-authority": "docker-action-broker-v2",
    },
    options: {},
  };
}

function workerSecretSet({ containerRoot, files, volumeId }) {
  return { containerRoot, files, volumeId };
}

function protectedVolumeFile({ inode, relativePath, sha256 }) {
  return {
    device: 101,
    inode,
    mode: 0o400,
    ownerGid: 0,
    ownerUid: 0,
    relativePath,
    sha256,
    symlinkFree: true,
  };
}

function unionPhaseField(action, field) {
  const plan = expectedActionPhases(action);
  const phaseIds = [
    ...plan.phaseIds,
    ...Object.values(plan.operationPhaseIds).flat(),
  ];
  return uniqueSorted(phaseIds.flatMap((phaseId) => EXPECTED_PHASE_PROFILES[phaseId][field]));
}

function digestWithout(value, digestKey) {
  const unsigned = Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== digestKey),
  );
  return fixtureSha256(canonicalFixtureJson(unsigned));
}

function canonicalFixtureValue(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(canonicalFixtureValue);
  if (!isPlainObject(value)) {
    throw new TypeError("fixture canonical JSON accepts only plain JSON values");
  }
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonicalFixtureValue(value[key])]),
  );
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isPlainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function requiredBinding(registry, key, label) {
  if (!Object.hasOwn(registry, key)) {
    throw new TypeError(`unsupported ${label} fixture: ${key}`);
  }
  return registry[key];
}

function requireAction(action) {
  if (!ALL_ACTION_NAMES.includes(action)) {
    throw new TypeError(`unsupported action: ${action}`);
  }
}

function requireContractFunctions(contract, names) {
  if (!contract || typeof contract !== "object") {
    throw new TypeError("contract module is required");
  }
  for (const name of names) {
    if (typeof contract[name] !== "function") {
      throw new TypeError(`contract.${name} must be implemented`);
    }
  }
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}
