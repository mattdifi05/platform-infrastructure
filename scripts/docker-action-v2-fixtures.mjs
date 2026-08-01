import crypto from "node:crypto";

export const FIXTURE_NOW = Date.parse("2026-07-28T12:00:00.000Z");
export const ACTIVE_RECEIPT_SCHEMA_V2 = "platform.docker-active-receipt/v2";
export const RUNTIME_INTENT_SCHEMA_V1 = "platform.docker-runtime-intent/v1";
export const REQUEST_SCHEMA_V2 = "platform.docker-action.request/v2";
export const RESPONSE_SCHEMA_V2 = "platform.docker-action.response/v2";
export const RESULT_SCHEMA_V2 = "platform.docker-action.result/v2";
export const MAX_PHASE_OUTPUT_BYTES_V2 = 4096;
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

export const EXPECTED_EVIDENCE_RESULT_PHASE = deepFreeze({
  outputSchema: "platform.docker-runtime-snapshot/v2",
  phaseId: "evidence.runtime.snapshot",
});

export const EXPECTED_SERVICE_ENDPOINTS = deepFreeze({
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

const POSTGRES_IMAGE_ID = `sha256:${"8".repeat(64)}`;
const POSTGRES_IMAGE_REF = "postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa";
const MARIADB_IMAGE_ID = `sha256:${"9".repeat(64)}`;
const MARIADB_IMAGE_REF = "mariadb:12.3.2@sha256:b1c7bf836e64ed9406a8984af29509f40089d55cea14b32f12c4726a1f17104b";
const MINIO_MC_IMAGE_ID = `sha256:${"a".repeat(64)}`;
const MINIO_MC_IMAGE_REF = "quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727";
const MINIO_SERVER_IMAGE_ID = `sha256:${"b".repeat(64)}`;
const MINIO_SERVER_IMAGE_REF = "quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e";
const RESTIC_IMAGE_ID = `sha256:${"c".repeat(64)}`;
const RESTIC_IMAGE_REF = "restic/restic:0.18.0@sha256:4cf4a61ef9786f4de53e9de8c8f5c040f33830eb0a10bf3d614410ee2fcb6120";

export const EXPECTED_HELPER_PROFILES = deepFreeze({
  "helper.capture.mariadb": helperProfile({
    engine: "mariadb",
    entrypoint: ["/usr/bin/mariadb-dump"],
    imageId: MARIADB_IMAGE_ID,
    imageRef: MARIADB_IMAGE_REF,
    networkId: "platform_db_admin",
    operation: "capture",
    outputMode: "artifact",
    resourceKind: "database",
    secretSetId: "mariadb.capture.credentials",
    helperProfileId: "helper.capture.mariadb",
  }),
  "helper.capture.minio": helperProfile({
    engine: "minio",
    entrypoint: ["/bin/sh"],
    imageId: MINIO_MC_IMAGE_ID,
    imageRef: MINIO_MC_IMAGE_REF,
    networkId: "platform_storage",
    operation: "capture",
    outputMode: "artifact",
    resourceKind: "storage",
    secretSetId: "minio.capture.credentials",
    helperProfileId: "helper.capture.minio",
  }),
  "helper.capture.postgres": helperProfile({
    engine: "postgres",
    entrypoint: ["/usr/local/bin/pg_dump"],
    imageId: POSTGRES_IMAGE_ID,
    imageRef: POSTGRES_IMAGE_REF,
    networkId: "platform_db_admin",
    operation: "capture",
    outputMode: "artifact",
    resourceKind: "database",
    secretSetId: "postgres.capture.credentials",
    helperProfileId: "helper.capture.postgres",
  }),
  "helper.offsite.restic": helperProfile({
    engine: "restic",
    entrypoint: ["/usr/bin/restic"],
    imageId: RESTIC_IMAGE_ID,
    imageRef: RESTIC_IMAGE_REF,
    networkId: "platform_egress",
    operation: "offsite-sync",
    outputMode: "json",
    resourceKind: null,
    secretSetId: "offsite.credentials",
    helperProfileId: "helper.offsite.restic",
  }),
  "helper.restore.minio.restore": helperProfile({
    engine: "minio",
    entrypoint: ["/usr/bin/mc"],
    imageId: MINIO_MC_IMAGE_ID,
    imageRef: MINIO_MC_IMAGE_REF,
    operation: "restore",
    outputMode: "none",
    resourceKind: "storage",
    helperProfileId: "helper.restore.minio.restore",
  }),
  "helper.restore.minio.server": helperProfile({
    engine: "minio",
    entrypoint: ["/usr/bin/minio"],
    imageId: MINIO_SERVER_IMAGE_ID,
    imageRef: MINIO_SERVER_IMAGE_REF,
    operation: "restore-server",
    outputMode: "none",
    resourceKind: "storage",
    helperProfileId: "helper.restore.minio.server",
  }),
  "helper.restore.minio.verify": helperProfile({
    engine: "minio",
    entrypoint: ["/usr/bin/mc"],
    imageId: MINIO_MC_IMAGE_ID,
    imageRef: MINIO_MC_IMAGE_REF,
    operation: "verify",
    outputMode: "json",
    resourceKind: "storage",
    helperProfileId: "helper.restore.minio.verify",
  }),
  "helper.restore.mariadb.restore": helperProfile({
    engine: "mariadb",
    entrypoint: ["/usr/bin/mariadb"],
    imageId: MARIADB_IMAGE_ID,
    imageRef: MARIADB_IMAGE_REF,
    operation: "restore",
    outputMode: "none",
    resourceKind: "database",
    helperProfileId: "helper.restore.mariadb.restore",
  }),
  "helper.restore.mariadb.server": helperProfile({
    engine: "mariadb",
    entrypoint: ["/usr/local/bin/docker-entrypoint.sh"],
    imageId: MARIADB_IMAGE_ID,
    imageRef: MARIADB_IMAGE_REF,
    operation: "restore-server",
    outputMode: "none",
    resourceKind: "database",
    helperProfileId: "helper.restore.mariadb.server",
  }),
  "helper.restore.mariadb.verify": helperProfile({
    engine: "mariadb",
    entrypoint: ["/usr/bin/mariadb"],
    imageId: MARIADB_IMAGE_ID,
    imageRef: MARIADB_IMAGE_REF,
    operation: "verify",
    outputMode: "json",
    resourceKind: "database",
    helperProfileId: "helper.restore.mariadb.verify",
  }),
  "helper.restore.postgres.restore": helperProfile({
    engine: "postgres",
    entrypoint: ["/usr/local/bin/pg_restore"],
    imageId: POSTGRES_IMAGE_ID,
    imageRef: POSTGRES_IMAGE_REF,
    operation: "restore",
    outputMode: "none",
    resourceKind: "database",
    helperProfileId: "helper.restore.postgres.restore",
  }),
  "helper.restore.postgres.server": helperProfile({
    engine: "postgres",
    entrypoint: ["/usr/local/bin/docker-entrypoint.sh"],
    imageId: POSTGRES_IMAGE_ID,
    imageRef: POSTGRES_IMAGE_REF,
    operation: "restore-server",
    outputMode: "none",
    resourceKind: "database",
    helperProfileId: "helper.restore.postgres.server",
  }),
  "helper.restore.postgres.verify": helperProfile({
    engine: "postgres",
    entrypoint: ["/usr/local/bin/psql"],
    imageId: POSTGRES_IMAGE_ID,
    imageRef: POSTGRES_IMAGE_REF,
    operation: "verify",
    outputMode: "json",
    resourceKind: "database",
    helperProfileId: "helper.restore.postgres.verify",
  }),
});

export const EXPECTED_HELPER_PROFILE_IDS = Object.freeze(Object.keys(EXPECTED_HELPER_PROFILES));

export const EXPECTED_PHASE_PROFILES = deepFreeze({
  "catalog.capture": phase({
    command: "backup-catalog",
    endpointIds: ["capture.database.mariadb", "capture.database.postgres", "capture.storage.minio"],
    mountIds: ["backup.root.rw", "report.root.rw", "source.root.ro", "state.catalog.ro"],
    mutationPolicy: "backup-write",
    networkIds: ["platform_db_admin", "platform_storage"],
    outputSchema: "platform.backup-catalog/v1",
    helperProfileIds: ["helper.capture.mariadb", "helper.capture.minio", "helper.capture.postgres"],
    workerSecretSetIds: ["manifest.signing"],
  }),
  "job.backup.capture": phase({
    command: "backup-job",
    endpointIds: ["capture.database.mariadb", "capture.database.postgres", "capture.storage.minio"],
    mountIds: ["backup.root.rw", "report.root.rw", "source.root.ro", "state.catalog.ro"],
    mutationPolicy: "backup-write",
    networkIds: ["platform_db_admin", "platform_storage"],
    outputSchema: "platform.backup-job-result/v1",
    helperProfileIds: ["helper.capture.mariadb", "helper.capture.minio", "helper.capture.postgres"],
    workerSecretSetIds: ["manifest.signing"],
  }),
  "job.restore.verify": phase({
    command: "restore-job",
    endpointIds: [],
    mountIds: ["backup.root.ro", "report.root.rw"],
    mutationPolicy: "restore-disposable",
    networkIds: [],
    outputSchema: "platform.backup-job-result/v1",
    scratchVolumeIds: ["restore.scratch"],
    helperProfileIds: ["helper.restore.mariadb.server", "helper.restore.mariadb.restore", "helper.restore.mariadb.verify", "helper.restore.minio.server", "helper.restore.minio.restore", "helper.restore.minio.verify", "helper.restore.postgres.server", "helper.restore.postgres.restore", "helper.restore.postgres.verify"],
    workerSecretSetIds: ["manifest.verification"],
  }),
  "prune.plan": phase({
    command: "backup-prune-plan",
    endpointIds: [],
    mountIds: ["backup.root.ro", "report.root.rw"],
    mutationPolicy: "report-only",
    networkIds: [],
    outputSchema: "platform.backup-prune-plan/v1",
    helperProfileIds: [],
    workerSecretSetIds: ["manifest.verification"],
  }),
  "prune.apply": phase({
    command: "backup-prune-apply",
    endpointIds: [],
    mountIds: ["backup.root.rw", "report.root.rw"],
    mutationPolicy: "retention-apply",
    networkIds: [],
    outputSchema: "platform.backup-prune-apply/v1",
    helperProfileIds: [],
    workerSecretSetIds: ["manifest.verification"],
    writableSubpathIds: ["backup.quarantine"],
  }),
  "restore.capture": phase({
    command: "backup-catalog",
    endpointIds: ["capture.database.mariadb", "capture.database.postgres", "capture.storage.minio"],
    mountIds: ["backup.root.rw", "report.root.rw", "source.root.ro", "state.catalog.ro"],
    mutationPolicy: "backup-write",
    networkIds: ["platform_db_admin", "platform_storage"],
    outputSchema: "platform.backup-catalog/v1",
    helperProfileIds: ["helper.capture.mariadb", "helper.capture.minio", "helper.capture.postgres"],
    workerSecretSetIds: ["manifest.signing"],
  }),
  "restore.verify": phase({
    command: "restore-drill-full",
    endpointIds: [],
    mountIds: ["backup.root.ro", "report.root.rw"],
    mutationPolicy: "restore-disposable",
    networkIds: [],
    outputSchema: "platform.restore-drill/v1",
    scratchVolumeIds: ["restore.scratch"],
    helperProfileIds: ["helper.restore.mariadb.server", "helper.restore.mariadb.restore", "helper.restore.mariadb.verify", "helper.restore.minio.server", "helper.restore.minio.restore", "helper.restore.minio.verify", "helper.restore.postgres.server", "helper.restore.postgres.restore", "helper.restore.postgres.verify"],
    workerSecretSetIds: ["manifest.verification"],
  }),
  "offsite.sync": phase({
    command: "backup-offsite-sync",
    endpointIds: ["offsite.repository"],
    mountIds: ["backup.root.ro", "report.root.rw"],
    mutationPolicy: "offsite-write",
    networkIds: ["platform_egress"],
    outputSchema: "platform.offsite-backup-receipt/v1",
    helperProfileIds: ["helper.offsite.restic"],
    workerSecretSetIds: ["manifest.verification"],
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
  "endpointIds",
  "mountIds",
  "mutationPolicy",
  "networkIds",
  "outputSchema",
  "phaseId",
  "phaseSha256",
  "scratchVolumeIds",
  "helperProfileIds",
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
  "serviceEndpoints",
  "volumes",
  "helperProfiles",
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
    Mountpoint: `/var/lib/docker/volumes/${admitted.engineName}/_data`,
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

export function expectedEndpointIds(action) {
  return unionPhaseField(action, "endpointIds");
}

export function expectedHelperProfileIds(action) {
  return unionPhaseField(action, "helperProfileIds");
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
    const manifestDigest = fixtureSha256(`fixture:worker-image-manifest:${phaseId}`);
    const imageId = fixtureSha256(`fixture:worker-image-config:${phaseId}`);
    const unsigned = {
      ...structuredClone(expected),
      phaseId,
      workerImageId: `sha256:${imageId}`,
      workerImageRef: `registry.example/platform/docker-action-${index + 1}@sha256:${manifestDigest}`,
    };
    phaseProfiles[phaseId] = { ...unsigned, phaseSha256: phaseDigest(unsigned) };
  }
  const helperProfiles = structuredClone(EXPECTED_HELPER_PROFILES);

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
        "database:mariadb": {
          engine: "mariadb",
          externalId: "mariadb",
          kind: "database",
          name: "mariadb",
          projectId: "platform",
        },
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
          snapshotContainerPath: "/run/platform/claimed-job/job.json",
          snapshotVolumeId: "broker.state",
          snapshotVolumeSubpath: "claimed-jobs",
          volumeId: "jobs.queue",
          volumeSubpath: "running",
        },
      },
      containers: {
        mariadb: admittedContainer({
          logicalId: "mariadb",
          name: "mariadb",
          networkIds: ["platform_db_admin"],
        }),
        minio: admittedContainer({
          logicalId: "minio",
          name: "enterprise-minio",
          networkIds: ["platform_storage"],
        }),
        postgres: admittedContainer({
          logicalId: "postgres",
          name: "enterprise-postgres",
          networkIds: ["platform_db_admin"],
        }),
      },
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
      serviceEndpoints: structuredClone(EXPECTED_SERVICE_ENDPOINTS),
      volumes: {
        "broker.state": admittedVolume({
          engineName: "platform_infra_vps_docker_action_broker_state",
          seed: "broker-state",
        }),
        "jobs.queue": admittedVolume({
          engineName: "platform_infra_vps_backup_scheduler_jobs",
          seed: "jobs-queue",
        }),
        "restore.scratch": admittedVolume({
          containerPath: "/run/platform/restore-scratch",
          engineName: "platform_docker_action_restore_scratch",
          seed: "restore-scratch",
        }),
        "worker.input.mariadb-capture": admittedVolume({
          engineName: "platform_docker_action_mariadb_capture_credentials",
          seed: "mariadb-capture-credentials",
        }),
        "worker.input.manifest-signing": admittedVolume({
          engineName: "platform_docker_action_manifest_signing",
          seed: "manifest-signing",
        }),
        "worker.input.manifest-verification": admittedVolume({
          engineName: "platform_docker_action_manifest_verification",
          seed: "manifest-verification",
        }),
        "worker.input.minio-capture": admittedVolume({
          engineName: "platform_docker_action_minio_capture_credentials",
          seed: "minio-capture-credentials",
        }),
        "worker.input.offsite": admittedVolume({
          engineName: "platform_docker_action_offsite_credentials",
          seed: "offsite-credentials",
        }),
        "worker.input.postgres-capture": admittedVolume({
          engineName: "platform_docker_action_postgres_capture_credentials",
          seed: "postgres-capture-credentials",
        }),
      },
      workerSecretSets: {
        "mariadb.capture.credentials": workerSecretSet({
          containerRoot: "/run/platform/worker-secrets/mariadb-capture",
          files: {
            clientConfig: protectedVolumeFile({
              inode: 2004,
              relativePath: "client.cnf",
              sha256: "2".repeat(64),
            }),
          },
          volumeId: "worker.input.mariadb-capture",
        }),
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
        "minio.capture.credentials": workerSecretSet({
          containerRoot: "/run/platform/worker-secrets/minio-capture",
          files: {
            accessKey: protectedVolumeFile({
              inode: 2006,
              relativePath: "access-key",
              sha256: "4".repeat(64),
            }),
            secretKey: protectedVolumeFile({
              inode: 2007,
              relativePath: "secret-key",
              sha256: "8".repeat(64),
            }),
          },
          volumeId: "worker.input.minio-capture",
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
        "postgres.capture.credentials": workerSecretSet({
          containerRoot: "/run/platform/worker-secrets/postgres-capture",
          files: {
            database: protectedVolumeFile({
              inode: 2008,
              relativePath: "database",
              sha256: "9".repeat(64),
            }),
            pgpass: protectedVolumeFile({
              inode: 2009,
              relativePath: ".pgpass",
              sha256: "b".repeat(64),
            }),
            username: protectedVolumeFile({
              inode: 2010,
              relativePath: "username",
              sha256: "c".repeat(64),
            }),
          },
          volumeId: "worker.input.postgres-capture",
        }),
      },
      helperProfiles,
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

export function buildFixtureTrustedContextV2({
  allowedActions = SCHEDULER_ACTION_NAMES,
  now = FIXTURE_NOW,
  rawReceipt = buildRawActiveReceiptV2({ now }),
} = {}) {
  if (!Array.isArray(allowedActions)
    || allowedActions.length < 1
    || new Set(allowedActions).size !== allowedActions.length) {
    throw new TypeError("allowedActions must contain unique fixture actions");
  }
  for (const action of allowedActions) requireAction(action);
  const receipt = structuredClone(rawReceipt);
  const receiptDigest = fixtureSha256(canonicalFixtureJson(receipt));
  const unsignedIntent = {
    schema: RUNTIME_INTENT_SCHEMA_V1,
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
  const intent = {
    ...unsignedIntent,
    mac: crypto
      .createHmac("sha256", FIXTURE_TRUST_KEY)
      .update(`${unsignedIntent.schema}\0`)
      .update(canonicalFixtureJson(unsignedIntent))
      .digest("hex"),
  };
  const trusted = { intent, receipt, receiptDigest };
  deepFreeze(trusted);
  return Object.freeze({
    intent: trusted.intent,
    rawReceipt: structuredClone(rawReceipt),
    receipt: trusted.receipt,
    receiptDigest,
    trusted,
  });
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

export function buildFixtureActionResultV2(action, parameters = {}, {
  outputByPhaseId = {},
} = {}) {
  requireAction(action);
  const isEvidence = action === "evidence.runtime.snapshot";
  const plan = isEvidence
    ? null
    : requiredBinding(EXPECTED_ACTION_PHASES, action, "action phase");
  const isJob = action === "backup.job.execute";
  if (isJob) {
    const keys = Object.keys(parameters).sort();
    const expectedKeys = ["jobFileName", "jobId", "jobOperation", "jobSha256"];
    if (canonicalFixtureJson(keys) !== canonicalFixtureJson(expectedKeys)
      || !/^[a-z0-9][a-z0-9-]{15,127}$/.test(String(parameters.jobId ?? ""))
      || parameters.jobFileName !== `${parameters.jobId}.json`
      || !["backup", "restore-drill"].includes(parameters.jobOperation)
      || !/^[a-f0-9]{64}$/.test(String(parameters.jobSha256 ?? ""))) {
      throw new TypeError("typed job result fixture requires an exact canonical job identity");
    }
  } else if (!isPlainObject(parameters) || Object.keys(parameters).length !== 0) {
    throw new TypeError("fixed-action result fixture parameters must be empty");
  }
  const operation = isJob ? parameters.jobOperation : null;
  const phaseIds = isEvidence
    ? [EXPECTED_EVIDENCE_RESULT_PHASE.phaseId]
    : isJob
      ? requiredBinding(plan.operationPhaseIds, operation, "job operation")
      : plan.phaseIds;
  if (Object.keys(outputByPhaseId).some((phaseId) => !phaseIds.includes(phaseId))) {
    throw new TypeError("worker output fixture contains a phase outside the action plan");
  }
  const job = isJob
    ? {
        jobFileName: parameters.jobFileName,
        jobId: parameters.jobId,
        jobOperation: parameters.jobOperation,
        jobSha256: parameters.jobSha256,
      }
    : null;
  const phases = phaseIds.map((phaseId) => {
    const outputSchema = isEvidence
      ? EXPECTED_EVIDENCE_RESULT_PHASE.outputSchema
      : requiredBinding(EXPECTED_PHASE_PROFILES, phaseId, "phase profile").outputSchema;
    const output = structuredClone(
      outputByPhaseId[phaseId]
        ?? buildFixturePhaseOutputV2(action, phaseId, parameters),
    );
    if (!isPlainObject(output) || output.schema !== outputSchema) {
      throw new TypeError(`invalid worker output fixture for ${phaseId}`);
    }
    if (Buffer.byteLength(canonicalFixtureJson(output)) > MAX_PHASE_OUTPUT_BYTES_V2) {
      throw new TypeError(`oversized worker output fixture for ${phaseId}`);
    }
    return {
      output,
      outputSchema,
      outputSha256: fixtureSha256(canonicalFixtureJson(output)),
      phaseId,
      status: "completed",
    };
  });
  return {
    schema: RESULT_SCHEMA_V2,
    action,
    job,
    phases,
    status: "completed",
  };
}

export function buildFixturePhaseOutputV2(action, phaseId, parameters = {}) {
  requireAction(action);
  if (action === "evidence.runtime.snapshot") {
    if (phaseId !== EXPECTED_EVIDENCE_RESULT_PHASE.phaseId) {
      throw new TypeError(`unsupported evidence result phase fixture: ${phaseId}`);
    }
    return {
      schema: EXPECTED_EVIDENCE_RESULT_PHASE.outputSchema,
      resources: {},
    };
  }
  const plan = requiredBinding(EXPECTED_ACTION_PHASES, action, "action phase");
  const ownedPhaseIds = action === "backup.job.execute"
    ? requiredBinding(plan.operationPhaseIds, parameters.jobOperation, "job operation")
    : plan.phaseIds;
  if (!ownedPhaseIds.includes(phaseId)) {
    throw new TypeError(`${phaseId} is not owned by fixture action ${action}`);
  }
  const profile = requiredBinding(EXPECTED_PHASE_PROFILES, phaseId, "phase profile");
  const common = {
    schema: profile.outputSchema,
    status: "passed",
    evidenceSha256: fixtureSha256(`fixture:worker-evidence:${phaseId}`),
  };
  if (phaseId === "prune.plan") {
    return {
      schema: profile.outputSchema,
      mode: "plan",
      keepCompleteManifests: 42,
      completeManifestCount: 2,
      retainedManifestIds: ["manifest:one"],
      expiredManifestIds: ["manifest:two"],
      mutationPerformed: false,
    };
  }
  if (phaseId === "job.backup.capture" || phaseId === "job.restore.verify") {
    return {
      ...common,
      jobId: parameters.jobId,
      jobOperation: parameters.jobOperation,
      mutationPerformed: true,
    };
  }
  if (phaseId === "offsite.sync") {
    return {
      ...common,
      mutationPerformed: true,
      repositoryOffsite: true,
    };
  }
  return {
    ...common,
    mutationPerformed: true,
  };
}

function phase({
  command,
  endpointIds,
  mountIds,
  mutationPolicy,
  networkIds,
  outputSchema,
  scratchVolumeIds = [],
  helperProfileIds,
  workerSecretSetIds = [],
  writableSubpathIds = [],
}) {
  return {
    command,
    endpointIds,
    mountIds,
    mutationPolicy,
    networkIds,
    outputSchema,
    scratchVolumeIds,
    helperProfileIds,
    workerSecretSetIds,
    writableSubpathIds,
  };
}

function helperProfile({
  engine,
  entrypoint,
  imageId,
  imageRef,
  networkId = null,
  operation,
  outputMode,
  resourceKind,
  secretSetId = null,
  helperProfileId,
}) {
  return {
    engine,
    entrypoint,
    imageId,
    imageRef,
    networkId,
    operation,
    outputMode,
    resourceKind,
    secretSetId,
    helperProfileId,
  };
}

function admittedContainer({ logicalId, name, networkIds }) {
  const imageDigest = fixtureSha256(`fixture:container-image:${logicalId}`);
  return {
    authority: {
      binds: [],
      capAdd: [],
      capDrop: ["ALL"],
      cgroupnsMode: "private",
      configSha256: fixtureSha256(`fixture:container-config:${logicalId}`),
      deviceCgroupRules: [],
      devices: [],
      deviceRequests: [],
      extraHosts: [],
      groupAdd: [],
      hostConfigSha256: fixtureSha256(`fixture:container-host-config:${logicalId}`),
      ipcMode: "private",
      links: [],
      mounts: [],
      networkMode: networkIds[0],
      networkSettingsSha256: fixtureSha256(`fixture:container-network-settings:${logicalId}`),
      networks: [...networkIds],
      pidMode: "",
      portBindings: {},
      privileged: false,
      publishAllPorts: false,
      readonlyRootfs: false,
      runtime: "runc",
      securityOpt: ["no-new-privileges:true"],
      user: "999:999",
      usernsMode: "",
      utsMode: "",
      volumesFrom: [],
    },
    containerId: fixtureSha256(`fixture:container:${logicalId}`),
    expectedHealth: "healthy",
    expectedState: "running",
    imageId: `sha256:${imageDigest}`,
    imageRef: `registry.example/platform/${logicalId}@sha256:${imageDigest}`,
    labels: {
      "com.platform.runtime.candidate-id": "candidate.v2",
      "com.platform.runtime.commit": "a".repeat(40),
      "com.platform.runtime.deployment-id": "deployment.v2",
      "com.platform.runtime.source-render-sha256": "5".repeat(64),
      "com.platform.runtime.tree": "6".repeat(64),
      "com.platform.runtime.workload-lock-sha256": "7".repeat(64),
    },
    name,
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
