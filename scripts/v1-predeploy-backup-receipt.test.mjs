import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  derivePersistentSourceSet,
  REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE,
  verifyV1PredeployBackupReceipt,
} from "./v1-predeploy-backup-receipt.mjs";
import {
  sealLivePreservationBaseline,
  sha256Canonical,
  validateLivePreservationBaseline,
} from "./live-preservation-baseline.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const verifierPath = path.join(root, "scripts", "v1-predeploy-backup-receipt.mjs");
const FIXTURE_NOW = Date.now();
const GENERATED_AT = new Date(FIXTURE_NOW - 5 * 60 * 1000).toISOString();
const NOT_BEFORE = new Date(FIXTURE_NOW - 10 * 60 * 1000).toISOString();
const EXPIRES_AT = new Date(FIXTURE_NOW + 60 * 60 * 1000).toISOString();
const QUIESCE_STARTED_AT = new Date(FIXTURE_NOW - 6 * 60 * 1000).toISOString();
const CAPTURED_AT = new Date(FIXTURE_NOW - 5.5 * 60 * 1000).toISOString();
const TARGET_ROOT = "/srv/platform-infrastructure";
const BACKUP_ROOT = "/mnt/offline-backups/rebuild-001";
const CANDIDATE_COMMIT = "e".repeat(40);
const CANDIDATE_TREE = "f".repeat(40);
const BASELINE_HASH = "a".repeat(64);
const ANONYMOUS_ATTACHED = "1".padStart(64, "0");
const ANONYMOUS_DANGLING = "2".padStart(64, "0");

function clone(value) {
  return structuredClone(value);
}

function digest(source) {
  return crypto.createHash("sha256").update(source).digest("hex");
}

function identity({
  type = "regular-file",
  device = "99",
  inode = "100",
  uid = 0,
  gid = 0,
  mode = type === "directory" ? "0750" : "0440",
  nlink = 1,
} = {}) {
  return { type, device, inode, uid, gid, mode, nlink };
}

function artifact(artifactId, kind, filename, sourceRefs, sizeBytes, inode) {
  const artifactSha256 = digest(artifactId);
  const sourceRefsSha256 = sha256Canonical([...sourceRefs].sort());
  const ownershipManifestSha256 = digest(`${artifactId}:ownership`);
  const genericMaterialization = ["CODE", "OCI-IMAGE", "CONFIG"].includes(kind)
    ? {
      verified: true,
      verifiedAt: GENERATED_AT,
      method: kind === "OCI-IMAGE" ? "ISOLATED-OCI-ARCHIVE-INSPECTION" : "ISOLATED-ARCHIVE-MATERIALIZATION",
      artifactSha256,
      sourceRefsSha256,
      ownershipManifestSha256,
      resultSha256: digest(`${artifactId}:materialized`),
    }
    : null;
  return {
    artifactId,
    kind,
    backupPath: `${BACKUP_ROOT}/${filename}`,
    sourceRefs,
    sourceRefsSha256,
    ownershipManifestSha256,
    capturedAt: CAPTURED_AT,
    sizeBytes,
    sha256: artifactSha256,
    checksum: {
      algorithm: "SHA-256",
      verified: true,
      verifiedAt: GENERATED_AT,
      evidenceSha256: digest(`${artifactId}:checksum`),
    },
    identity: identity({ inode: String(inode) }),
    identityVerified: true,
    identityVerifiedAt: GENERATED_AT,
    materializationVerification: genericMaterialization,
  };
}

function baselineFixture() {
  const containerName = "app-a-container";
  const volumes = [{
    name: ANONYMOUS_ATTACHED,
    nameClass: "ANONYMOUS",
    driver: "local",
    scope: "local",
    mountpoint: `/var/lib/docker/volumes/${ANONYMOUS_ATTACHED}/_data`,
    createdAt: "2026-08-09T03:00:00.000Z",
    optionsSha256: BASELINE_HASH,
    labelsSha256: BASELINE_HASH,
    composeProject: "",
    composeVolume: "",
    fsIdentity: identity({ type: "directory", device: "1", inode: "201" }),
    observedBytes: 2048,
    attachments: [{ containerName, destination: "/cache", readOnly: false }],
    dangling: false,
  }, {
    name: ANONYMOUS_DANGLING,
    nameClass: "ANONYMOUS",
    driver: "local",
    scope: "local",
    mountpoint: `/var/lib/docker/volumes/${ANONYMOUS_DANGLING}/_data`,
    createdAt: "2026-08-09T03:00:00.000Z",
    optionsSha256: BASELINE_HASH,
    labelsSha256: BASELINE_HASH,
    composeProject: "",
    composeVolume: "",
    fsIdentity: identity({ type: "directory", device: "1", inode: "202" }),
    observedBytes: 0,
    attachments: [],
    dangling: true,
  }, {
    name: "app_a_data",
    nameClass: "NAMED",
    driver: "local",
    scope: "local",
    mountpoint: "/var/lib/docker/volumes/app_a_data/_data",
    createdAt: "2026-08-09T03:00:00.000Z",
    optionsSha256: BASELINE_HASH,
    labelsSha256: BASELINE_HASH,
    composeProject: "live",
    composeVolume: "app_a_data",
    fsIdentity: identity({ type: "directory", device: "1", inode: "203" }),
    observedBytes: 4096,
    attachments: [{ containerName, destination: "/var/lib/postgresql/data", readOnly: false }],
    dangling: false,
  }];
  const bindMounts = [{
    source: "/srv/apps/app-a",
    canonicalPath: "/srv/apps/app-a",
    classification: "APPLICATION-DATA",
    lstatIdentity: identity({ type: "directory", device: "1", inode: "301" }),
    targetIdentity: identity({ type: "directory", device: "1", inode: "301" }),
    contentSha256: BASELINE_HASH,
    consumers: [{ containerName, destination: "/srv/app", readOnly: false }],
  }, {
    source: "/srv/uploads/app-a",
    canonicalPath: "/srv/uploads/app-a",
    classification: "APPLICATION-DATA",
    lstatIdentity: identity({ type: "directory", device: "1", inode: "302" }),
    targetIdentity: identity({ type: "directory", device: "1", inode: "302" }),
    contentSha256: BASELINE_HASH,
    consumers: [{ containerName, destination: "/uploads", readOnly: false }],
  }];
  const document = {
    schema: "platform.live-preservation-baseline/v1",
    baselineId: "0".repeat(64),
    scope: "platform-infrastructure",
    evidenceClass: "SYNTHETIC-TEST",
    synthetic: true,
    complete: true,
    status: "COMPLETE-PRESERVATION-BASELINE",
    gateAdmissible: false,
    mutationAuthority: false,
    effect: "DENY-ONLY",
    identityObservationMode: "POINT-IN-TIME",
    capturedAt: {
      startedAt: "2026-08-09T04:14:07.000Z",
      completedAt: "2026-08-09T04:15:07.000Z",
    },
    host: {
      hostname: "synthetic-host",
      machineIdSha256: BASELINE_HASH,
      bootId: "00000000-0000-4000-8000-000000000001",
      sshHostKeySha256: BASELINE_HASH,
      dockerDaemonId: "SYNTHETIC-DAEMON-ID",
      dockerRootDir: "/var/lib/docker",
      dockerRootIdentity: identity({ type: "directory", device: "1", inode: "9" }),
      os: { id: "ubuntu", versionId: "26.04", kernel: "7.0.0-test", architecture: "x86_64" },
      principal: { uid: 0, gid: 0 },
    },
    source: {
      kind: "SYNTHETIC",
      referenceSha256: BASELINE_HASH,
      captureOutputs: [{ kind: "synthetic-fixture", callIdSha256: BASELINE_HASH, outputSha256: BASELINE_HASH }],
      capturedProjectionDigests: [{ kind: "docker-volume-full-inventory", sha256: BASELINE_HASH }],
      rawEvidenceCommitted: false,
      secretValuesCaptured: false,
      collectionMutatedLive: false,
    },
    policy: {
      unknownResourceDisposition: "PRESERVE",
      missingResourceDisposition: "STOP",
      changedResourceDisposition: "STOP",
      globalTeardownAllowed: false,
      removeOrphansAllowed: false,
      pruneAllowed: false,
      foreignResourceMutationAllowed: false,
    },
    redaction: {
      secretValuesCaptured: false,
      environmentValuesCaptured: false,
      databaseRowsCaptured: false,
      privateKeysCaptured: false,
      environmentKeyNamesCaptured: true,
    },
    summary: {
      containers: 1,
      volumes: volumes.length,
      attachedVolumes: 2,
      danglingVolumes: 1,
      namedVolumes: 1,
      anonymousVolumes: 2,
      bindMounts: bindMounts.length,
      sourceRoots: 2,
      networks: 0,
      hostListeners: 0,
      databases: 1,
      applications: 2,
      secretMetadataRecords: 1,
    },
    checkouts: [{
      id: "active-live",
      role: "ACTIVE-LIVE",
      path: TARGET_ROOT,
      commit: "c".repeat(40),
      tree: "d".repeat(40),
      branch: "main",
      dirty: false,
      dirtyPathCount: 0,
      statusSha256: BASELINE_HASH,
      fsIdentity: identity({ type: "directory", device: "1", inode: "10" }),
    }],
    composeProjects: [{
      name: "live",
      workingDirectories: [TARGET_ROOT],
      configFiles: [{
        path: `${TARGET_ROOT}/compose.yaml`,
        sensitivity: "NON-SECRET-CONFIG",
        contentCaptured: true,
        sha256: BASELINE_HASH,
        fsIdentity: identity({ type: "regular-file", device: "1", inode: "11", mode: "0644" }),
      }],
      containerNames: [containerName],
    }],
    containers: [{
      id: "3".repeat(64),
      name: containerName,
      project: "live",
      service: "app-a",
      imageRef: `registry.invalid/app-a@sha256:${"4".repeat(64)}`,
      imageId: `sha256:${"4".repeat(64)}`,
      createdAt: "2026-08-09T03:00:00.000Z",
      state: "running",
      health: "healthy",
      exitCode: 0,
      configHash: BASELINE_HASH,
      configuredUser: "1000:1000",
      effectiveUid: 1000,
      effectiveGid: 1000,
      readOnlyRootfs: false,
      privileged: false,
      mounts: [{
        kind: "volume", sourceRef: ANONYMOUS_ATTACHED, destination: "/cache", readOnly: false, propagation: "rprivate",
      }, {
        kind: "bind", sourceRef: "/srv/apps/app-a", destination: "/srv/app", readOnly: false, propagation: "rprivate",
      }, {
        kind: "bind", sourceRef: "/srv/uploads/app-a", destination: "/uploads", readOnly: false, propagation: "rprivate",
      }, {
        kind: "volume", sourceRef: "app_a_data", destination: "/var/lib/postgresql/data", readOnly: false, propagation: "rprivate",
      }],
      networks: [],
      ports: [],
      environmentKeys: ["APP_ENV"],
    }],
    volumes,
    bindMounts,
    sourceRoots: [{
      path: "/srv/apps/app-a",
      fsIdentity: identity({ type: "directory", device: "1", inode: "301" }),
      observedBytes: 8192,
      fileCount: 20,
      mounted: true,
    }, {
      path: "/srv/docs",
      fsIdentity: identity({ type: "directory", device: "1", inode: "303" }),
      observedBytes: 1024,
      fileCount: 4,
      mounted: true,
    }],
    networks: [],
    hostListeners: [],
    logicalRecoveryAnchors: [{
      id: "app-a",
      displayName: "Application A",
      mappingState: "MAPPED",
      sourceRootRefs: ["/srv/apps/app-a"],
      sourceBindRefs: ["/srv/apps/app-a"],
      containerRefs: [containerName],
      databaseRefs: ["postgres:app_a"],
      storageRefs: [ANONYMOUS_ATTACHED, ANONYMOUS_DANGLING, "/srv/apps/app-a", "/srv/uploads/app-a", "app_a_data"].sort(),
      configRefs: [`${TARGET_ROOT}/compose.yaml`],
      secretMetadataRefs: ["secret-metadata:app-a"],
    }, {
      id: "docs",
      displayName: "Documentation source",
      mappingState: "MAPPED",
      sourceRootRefs: ["/srv/docs"],
      sourceBindRefs: [],
      containerRefs: [],
      databaseRefs: [],
      storageRefs: [],
      configRefs: [],
      secretMetadataRefs: [],
    }],
    databases: [{
      id: "postgres:app_a",
      engine: "POSTGRESQL",
      engineVersion: "18.4",
      serverContainer: containerName,
      name: "app_a",
      kind: "APPLICATION",
      owner: "app_a",
      tableCount: 10,
      catalogSha256: BASELINE_HASH,
      storageRefs: ["app_a_data"],
    }],
    secretMetadata: [{
      id: "secret-metadata:app-a",
      kind: "SECRET-FILE",
      path: `${TARGET_ROOT}/secrets/app-a`,
      fsIdentity: identity({ type: "regular-file", device: "1", inode: "401", mode: "0600" }),
      environmentKeys: [],
      contentCaptured: false,
      valuesCaptured: false,
    }],
    digests: {
      checkoutsSha256: "0".repeat(64),
      composeProjectsSha256: "0".repeat(64),
      containersSha256: "0".repeat(64),
      volumesSha256: "0".repeat(64),
      bindMountsSha256: "0".repeat(64),
      sourceRootsSha256: "0".repeat(64),
      networksSha256: "0".repeat(64),
      hostListenersSha256: "0".repeat(64),
      databasesSha256: "0".repeat(64),
      secretMetadataSha256: "0".repeat(64),
      logicalRecoveryAnchorsSha256: "0".repeat(64),
    },
    deficiencies: [],
  };
  const sealed = sealLivePreservationBaseline(document);
  validateLivePreservationBaseline(sealed, { requireComplete: true });
  return sealed;
}

function storageReceipt(
  storageId,
  kind,
  artifactRef,
  {
    quiesceRequired = true,
    captureMode = "QUIESCED-ARCHIVE",
    recoveryRole = "PRIMARY",
    dependencyApplicationRefs = ["app-a"],
    dependencyDatabaseRefs = [],
  } = {},
) {
  return {
    storageId,
    kind,
    sourceRef: storageId,
    artifactRef,
    checksumVerified: true,
    captureMode,
    consistencyEvidenceSha256: digest(`${storageId}:consistency`),
    recoveryRole,
    dependencyApplicationRefs,
    dependencyDatabaseRefs,
    quiesceRequired,
    restoreVerification: {
      verified: true,
      verifiedAt: GENERATED_AT,
      method: "ISOLATED-MATERIALIZATION",
      artifactSha256: digest(artifactRef),
      ownershipManifestSha256: digest(`${artifactRef}:ownership`),
      resultSha256: digest(`${storageId}:restore`),
    },
  };
}

function sealReceipt(receipt) {
  const sealed = clone(receipt);
  delete sealed.receiptId;
  receipt.receiptId = sha256Canonical(sealed);
  return receipt;
}

function receiptFixture(baseline, baselineSha256) {
  const artifacts = [
    artifact("code-app-a", "CODE", "code-app-a.tar.zst", ["/srv/apps/app-a"], 1024, 101),
    artifact("code-docs", "CODE", "code-docs.tar.zst", ["/srv/docs"], 256, 102),
    artifact("config-app-a", "CONFIG", "config-app-a.tar.zst", [`${TARGET_ROOT}/compose.yaml`], 512, 103),
    artifact("dump-postgres-app-a", "DATABASE-DUMP", "postgres-app-a.dump", ["postgres:app_a"], 2048, 104),
    artifact("anonymous-attached", "ANONYMOUS-VOLUME", "anonymous-attached.tar.zst", [ANONYMOUS_ATTACHED], 2048, 105),
    artifact("anonymous-dangling", "ANONYMOUS-VOLUME", "anonymous-dangling.tar.zst", [ANONYMOUS_DANGLING], 128, 106),
    artifact("source-bind-app-a", "BIND", "source-bind-app-a.tar.zst", ["/srv/apps/app-a"], 8192, 107),
    artifact("uploads-app-a", "UPLOAD", "uploads-app-a.tar.zst", ["/srv/uploads/app-a"], 8192, 108),
    artifact("storage-app-a", "NAMED-VOLUME", "app-a-data.tar.zst", ["app_a_data"], 4096, 109),
    artifact("image-app-a", "OCI-IMAGE", "image-app-a.oci.tar", ["app-a-container"], 4096, 110),
  ];
  return sealReceipt({
    schema: "platform.v1-predeploy-backup-receipt/v1",
    receiptId: "0".repeat(64),
    scope: "platform-infrastructure",
    evidenceClass: "SYNTHETIC-TEST",
    synthetic: true,
    verifyOnly: true,
    selfAsserted: false,
    candidateRepositoryControlled: false,
    status: REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE,
    authoritative: false,
    liveAuthorization: false,
    mutationAuthority: false,
    candidate: {
      commit: CANDIDATE_COMMIT,
      tree: CANDIDATE_TREE,
    },
    generatedAt: GENERATED_AT,
    freshness: {
      notBefore: NOT_BEFORE,
      expiresAt: EXPIRES_AT,
      maxAgeSeconds: 7200,
    },
    baseline: {
      schema: "platform.live-preservation-baseline/v1",
      baselineId: baseline.baselineId,
      artifactSha256: baselineSha256,
      complete: true,
      effect: "DENY-ONLY",
    },
    target: {
      root: TARGET_ROOT,
      identity: identity({ type: "directory", device: "1", inode: "10" }),
    },
    backupRoot: {
      path: BACKUP_ROOT,
      identity: identity({ type: "directory", device: "99", inode: "20" }),
    },
    trust: {
      evidenceProducer: "TARGET-ROOT-INDEPENDENT-VERIFIER",
      providerSignerPolicy: "EXTERNAL-PENDING",
      targetSignerPolicy: "EXTERNAL-PENDING",
      signatureAccepted: false,
      canAuthorizeLive: false,
    },
    artifacts,
    recoveryRefs: [{
      recoveryRefId: "config-ref-app-a",
      applicationId: "app-a",
      kind: "CONFIG",
      sourceRef: `${TARGET_ROOT}/compose.yaml`,
      providerLocator: `provider-config://platform/app-a/compose@sha256:${digest("config-app-a:version")}`,
      providerIdentity: {
        providerType: "CONFIG-REGISTRY",
        providerRef: `provider-identity://platform/config-registry@sha256:${digest("config-registry:identity")}`,
        identitySha256: digest("config-registry:identity"),
      },
      versionSha256: digest("config-app-a:version"),
      retrievalVerification: {
        verified: true,
        verifiedAt: GENERATED_AT,
        method: "ISOLATED-CONFIG-READINESS",
        providerIdentitySha256: digest("config-registry:identity"),
        versionSha256: digest("config-app-a:version"),
        artifactSha256: digest("config-app-a"),
        valueRetrieved: false,
        evidenceSha256: digest("config-app-a:retrieval-readiness"),
      },
      externalAdmission: {
        requirementRef: `external-recovery-policy://platform/config-recovery/v1@sha256:${digest("config-recovery-policy")}`,
        requirementSha256: digest("config-recovery-policy"),
        status: "EXTERNAL-PENDING",
        evidenceRef: null,
        providerSignatureAccepted: false,
        targetSignatureAccepted: false,
        canAuthorizeLive: false,
      },
      artifactRef: "config-app-a",
      valuesIncluded: false,
    }, {
      recoveryRefId: "secret-ref-app-a",
      applicationId: "app-a",
      kind: "SECRET",
      sourceRef: "secret-metadata:app-a",
      providerLocator: `provider-secret://platform/app-a/runtime@sha256:${digest("secret-app-a:version")}`,
      providerIdentity: {
        providerType: "SECRET-VAULT",
        providerRef: `provider-identity://platform/secret-vault@sha256:${digest("secret-vault:identity")}`,
        identitySha256: digest("secret-vault:identity"),
      },
      versionSha256: digest("secret-app-a:version"),
      retrievalVerification: {
        verified: true,
        verifiedAt: GENERATED_AT,
        method: "METADATA-ONLY-SECRET-READINESS",
        providerIdentitySha256: digest("secret-vault:identity"),
        versionSha256: digest("secret-app-a:version"),
        artifactSha256: null,
        valueRetrieved: false,
        evidenceSha256: digest("secret-app-a:retrieval-readiness"),
      },
      externalAdmission: {
        requirementRef: `external-recovery-policy://platform/secret-recovery/v1@sha256:${digest("secret-recovery-policy")}`,
        requirementSha256: digest("secret-recovery-policy"),
        status: "EXTERNAL-PENDING",
        evidenceRef: null,
        providerSignatureAccepted: false,
        targetSignatureAccepted: false,
        canAuthorizeLive: false,
      },
      artifactRef: null,
      valuesIncluded: false,
    }],
    databases: [{
      databaseId: "postgres:app_a",
      engine: "POSTGRESQL",
      engineVersion: "18.4",
      databaseKind: "APPLICATION",
      disposition: "LOGICAL-DUMP",
      dumpArtifactRef: "dump-postgres-app-a",
      engineRecoveryRef: null,
      dumpFormat: "POSTGRESQL-CUSTOM",
      tool: "pg_dump",
      toolVersion: "18.4",
      toolSha256: digest("pg_dump:18.4"),
      serverCompatibility: {
        verified: true,
        verifiedAt: GENERATED_AT,
        serverEngineVersion: "18.4",
        evidenceSha256: digest("pg_dump:18.4:postgresql:18.4:compatibility"),
      },
      consistencyMethod: "PG-MVCC-SNAPSHOT",
      sourceCatalogSha256: BASELINE_HASH,
      consistentDump: true,
      checksumVerified: true,
      quiesceRequired: true,
      restoreVerification: {
        verified: true,
        verifiedAt: GENERATED_AT,
        method: "ISOLATED-LOGICAL-RESTORE",
        engine: "POSTGRESQL",
        engineVersion: "18.4",
        scope: "SINGLE-DATABASE",
        databaseName: "app_a",
        catalogSha256: BASELINE_HASH,
        artifactSha256: digest("dump-postgres-app-a"),
        ownershipManifestSha256: digest("dump-postgres-app-a:ownership"),
        resultSha256: digest("postgres:app_a:restore"),
      },
      regeneration: null,
    }],
    engineRecoveries: [],
    storage: [
      storageReceipt(ANONYMOUS_ATTACHED, "ANONYMOUS-VOLUME", "anonymous-attached"),
      storageReceipt(ANONYMOUS_DANGLING, "ANONYMOUS-VOLUME", "anonymous-dangling", { quiesceRequired: false }),
      storageReceipt("/srv/apps/app-a", "BIND", "source-bind-app-a"),
      storageReceipt("/srv/uploads/app-a", "UPLOAD", "uploads-app-a"),
      storageReceipt("app_a_data", "NAMED-VOLUME", "storage-app-a", {
        recoveryRole: "DATABASE-FALLBACK-ONLY",
        dependencyDatabaseRefs: ["postgres:app_a"],
      }),
    ],
    applications: [{
      applicationId: "app-a",
      mappingState: "MAPPED",
      codeArtifactRefs: ["code-app-a", "image-app-a"],
      containerImages: [{
        containerRef: "app-a-container",
        artifactRef: "image-app-a",
        imageRef: `registry.invalid/app-a@sha256:${"4".repeat(64)}`,
        imageId: `sha256:${"4".repeat(64)}`,
        archiveFormat: "OCI-IMAGE-LAYOUT-V1",
        manifestSha256: digest("app-a-container:oci-manifest"),
        materializationVerification: {
          verified: true,
          verifiedAt: GENERATED_AT,
          method: "ISOLATED-OCI-ARCHIVE-INSPECTION",
          artifactSha256: digest("image-app-a"),
          ownershipManifestSha256: digest("image-app-a:ownership"),
          imageRef: `registry.invalid/app-a@sha256:${"4".repeat(64)}`,
          imageId: `sha256:${"4".repeat(64)}`,
          manifestSha256: digest("app-a-container:oci-manifest"),
          resultSha256: digest("app-a-container:oci-materialization"),
        },
      }],
      configRecoveryRefs: ["config-ref-app-a"],
      databaseRefs: ["postgres:app_a"],
      storageRefs: [ANONYMOUS_ATTACHED, ANONYMOUS_DANGLING, "/srv/apps/app-a", "/srv/uploads/app-a", "app_a_data"].sort(),
      secretRecoveryRefs: ["secret-ref-app-a"],
      quiesce: {
        required: true,
        evidence: {
          method: "APPLICATION-WRITE-QUIESCE",
          startedAt: QUIESCE_STARTED_AT,
          completedAt: GENERATED_AT,
          verified: true,
          evidenceSha256: digest("app-a:quiesce"),
        },
      },
    }, {
      applicationId: "docs",
      mappingState: "MAPPED",
      codeArtifactRefs: ["code-docs"],
      containerImages: [],
      configRecoveryRefs: [],
      databaseRefs: [],
      storageRefs: [],
      secretRecoveryRefs: [],
      quiesce: { required: false, evidence: null },
    }],
    mappings: [{
      applicationId: "app-a",
      mappingState: "MAPPED",
      databaseRefs: ["postgres:app_a"],
      storageRefs: [ANONYMOUS_ATTACHED, ANONYMOUS_DANGLING, "/srv/apps/app-a", "/srv/uploads/app-a", "app_a_data"].sort(),
    }, {
      applicationId: "docs",
      mappingState: "MAPPED",
      databaseRefs: [],
      storageRefs: [],
    }],
    restorePlan: [
      restoreStep(1, "restore-app-a-code", "app-a", "CODE", ["code-app-a", "image-app-a"]),
      restoreStep(2, "restore-app-a-config", "app-a", "CONFIG", [], [], [], ["config-ref-app-a"]),
      restoreStep(
        3,
        "restore-app-a-storage",
        "app-a",
        "STORAGE",
        [],
        [],
        [ANONYMOUS_ATTACHED, ANONYMOUS_DANGLING, "/srv/apps/app-a", "/srv/uploads/app-a"].sort(),
        [],
        { fallbackStorageRefs: ["app_a_data"] },
      ),
      restoreStep(4, "restore-app-a-database", "app-a", "DATABASE", [], ["postgres:app_a"]),
      restoreStep(5, "restore-app-a-secrets", "app-a", "SECRETS", [], [], [], ["secret-ref-app-a"]),
      restoreStep(6, "verify-app-a", "app-a", "VERIFY"),
      restoreStep(7, "restore-docs-code", "docs", "CODE", ["code-docs"]),
      restoreStep(8, "verify-docs", "docs", "VERIFY"),
    ],
    rollback: {
      code: {
        planId: "rollback-code-v1",
        steps: [{
          order: 1,
          stepId: "rollback-app-a-code",
          applicationId: "app-a",
          artifactRefs: ["code-app-a", "image-app-a"],
          configRecoveryRefs: ["config-ref-app-a"],
        }, {
          order: 2,
          stepId: "rollback-docs-code",
          applicationId: "docs",
          artifactRefs: ["code-docs"],
          configRecoveryRefs: [],
        }],
      },
      data: {
        planId: "rollback-data-v1",
        automatic: false,
        requiresProviderTargetAdmission: true,
        postDeployPreservationRequired: true,
        externalAdmission: {
          requirementRef: `external-admission-policy://platform/rebuild-data-rollback/v1@sha256:${digest("data-rollback-admission-policy")}`,
          requirementSha256: digest("data-rollback-admission-policy"),
          status: "EXTERNAL-PENDING",
          evidenceRef: null,
          providerDurabilityAttestationRequired: true,
          targetMountAttestationRequired: true,
          providerSignatureAccepted: false,
          targetSignatureAccepted: false,
          canAuthorizeLive: false,
        },
        steps: [{
          order: 1,
          stepId: "rollback-app-a-data",
          applicationId: "app-a",
          databaseRefs: ["postgres:app_a"],
          delegatedDatabaseRefs: [],
          storageRefs: [ANONYMOUS_ATTACHED, ANONYMOUS_DANGLING, "/srv/apps/app-a", "/srv/uploads/app-a"].sort(),
          fallbackStorageRefs: ["app_a_data"],
          delegatedStorageRefs: [],
        }],
      },
    },
    migrationPolicy: {
      mode: "NON-DESTRUCTIVE-ONLY",
      destructiveAllowed: false,
      destructiveSteps: [],
    },
  });
}

function restoreStep(
  order,
  stepId,
  applicationId,
  phase,
  artifactRefs = [],
  databaseRefs = [],
  storageRefs = [],
  recoveryRefs = [],
  projection = {},
) {
  return {
    order,
    stepId,
    applicationId,
    phase,
    artifactRefs,
    databaseRefs,
    delegatedDatabaseRefs: projection.delegatedDatabaseRefs ?? [],
    storageRefs,
    fallbackStorageRefs: projection.fallbackStorageRefs ?? [],
    delegatedStorageRefs: projection.delegatedStorageRefs ?? [],
    recoveryRefs,
    destructiveMigration: false,
  };
}

function fixtureForBaseline(baseline) {
  const baselineSource = JSON.stringify(baseline);
  return {
    baseline,
    baselineSource,
    baselineSha256: digest(baselineSource),
    receipt: receiptFixture(baseline, digest(baselineSource)),
  };
}

function fixtures() {
  return fixtureForBaseline(baselineFixture());
}

test("derives one canonical complete persistent source set for the root consumer", () => {
  const baseline = baselineFixture();
  const derived = derivePersistentSourceSet(baseline);

  assert.equal(derived.schema, "platform.v1-persistent-source-set/v1");
  assert.equal(derived.sourceDeviceIdentitiesComplete, true);
  assert.deepEqual(derived.sourceClasses, [
    "DOCKER-ROOT-DIR",
    "ALL-CHECKOUTS",
    "ALL-COMPOSE-CONFIG-FILES",
    "ALL-VOLUME-AND-DATABASE-DIRECTORIES",
    "BIND-LSTAT-SOURCE-IDENTITIES",
    "BIND-CANONICAL-TARGET-IDENTITIES",
    "ALL-SOURCE-ROOTS",
    "ALL-SECRET-METADATA-PATHS",
  ]);
  assert.deepEqual(derived.sourceDeviceIdentities, ["1"]);
  assert.equal(derived.sourceDeviceCount, 1);
  assert.equal(derived.sourceDeviceSetSha256, sha256Canonical(["1"]));
  assert.equal(derived.sourceObservationCount, derived.sources.length);
  assert.equal(derived.sourceObservationSetSha256, sha256Canonical(derived.sources));
  assert.equal(derived.sourcePathCount, derived.sourcePaths.length);
  assert.equal(derived.sourcePathSetSha256, sha256Canonical(derived.sourcePaths));
  assert.equal(derived.sources.length, 13);
  assert.equal(derived.sourcePaths.length, 10);
  assert.ok(Object.isFrozen(derived));
  assert.ok(Object.isFrozen(derived.sources));
  assert.ok(Object.isFrozen(derived.sources[0]));
  assert.ok(Object.isFrozen(derived.sources[0].identity));
  assert.equal(Object.hasOwn(derived, "authoritative"), false);

  const classes = new Set(derived.sources.map((source) => source.sourceClass));
  assert.deepEqual([...classes].sort(), [...derived.sourceClasses].sort());
});

test("persistent source derivation snapshots one immutable baseline object graph", () => {
  const baseline = baselineFixture();
  let reads = 0;
  Object.defineProperty(baseline.host.dockerRootIdentity, "device", {
    enumerable: true,
    get() {
      reads += 1;
      return reads === 1 ? "1" : "99";
    },
  });
  const derived = derivePersistentSourceSet(baseline);
  assert.deepEqual(derived.sourceDeviceIdentities, ["1"]);
  assert.equal(reads, 1);
});

test("persistent source derivation rejects incomplete or cross-class ambiguous identities", () => {
  const incomplete = baselineFixture();
  incomplete.complete = false;
  incomplete.status = "INCOMPLETE-NO-GO";
  incomplete.deficiencies = [{
    code: "TEST_INCOMPLETE",
    resourceClass: "bind",
    resourceId: "/srv/apps/app-a",
    field: "fsIdentity",
    reason: "Synthetic incomplete source-set fixture.",
  }];
  assert.throws(
    () => derivePersistentSourceSet(sealLivePreservationBaseline(incomplete)),
    /complete preservation evidence|complete deny-only baseline/i,
  );

  const ambiguous = baselineFixture();
  ambiguous.sourceRoots[0].fsIdentity.inode = "999";
  assert.throws(
    () => derivePersistentSourceSet(sealLivePreservationBaseline(ambiguous)),
    /ambiguous filesystem identities/i,
  );
});

function systemRestoreFixture() {
  let baseline = baselineFixture();
  const systemDatabase = {
    id: "postgres:postgres",
    engine: "POSTGRESQL",
    engineVersion: "18.4",
    serverContainer: "app-a-container",
    name: "postgres",
    kind: "SYSTEM",
    owner: "postgres",
    tableCount: 0,
    catalogSha256: digest("postgres:postgres:catalog"),
    storageRefs: ["app_a_data"],
  };
  const restoreDatabase = {
    id: "postgres:restore_probe",
    engine: "POSTGRESQL",
    engineVersion: "18.4",
    serverContainer: "app-a-container",
    name: "restore_probe",
    kind: "RESTORE",
    owner: "postgres",
    tableCount: 1,
    catalogSha256: digest("postgres:restore_probe:catalog"),
    storageRefs: ["app_a_data"],
  };
  baseline.databases.push(systemDatabase, restoreDatabase);
  baseline.databases.sort((left, right) => left.id.localeCompare(right.id));
  baseline.summary.databases = baseline.databases.length;
  baseline.logicalRecoveryAnchors[0].databaseRefs.push(systemDatabase.id, restoreDatabase.id);
  baseline.logicalRecoveryAnchors[0].databaseRefs.sort();
  baseline = sealLivePreservationBaseline(baseline);
  validateLivePreservationBaseline(baseline, { requireComplete: true });
  const fixture = fixtureForBaseline(baseline);
  const globalArtifact = artifact(
    "global-postgres",
    "DATABASE-GLOBAL",
    "postgres-global.sql",
    [systemDatabase.id],
    512,
    111,
  );
  const restoreArtifact = artifact(
    "dump-postgres-restore-probe",
    "DATABASE-DUMP",
    "postgres-restore-probe.dump",
    [restoreDatabase.id],
    512,
    112,
  );
  fixture.receipt.artifacts.push(globalArtifact, restoreArtifact);
  fixture.receipt.databases.push({
    databaseId: systemDatabase.id,
    engine: systemDatabase.engine,
    engineVersion: systemDatabase.engineVersion,
    databaseKind: "SYSTEM",
    disposition: "ENGINE-GLOBAL-RECOVERY",
    dumpArtifactRef: null,
    engineRecoveryRef: "engine-global:postgresql:app-a-container",
    dumpFormat: null,
    tool: null,
    toolVersion: null,
    toolSha256: null,
    serverCompatibility: null,
    consistencyMethod: null,
    sourceCatalogSha256: null,
    consistentDump: null,
    checksumVerified: null,
    quiesceRequired: false,
    restoreVerification: null,
    regeneration: null,
  }, {
    databaseId: restoreDatabase.id,
    engine: restoreDatabase.engine,
    engineVersion: restoreDatabase.engineVersion,
    databaseKind: "RESTORE",
    disposition: "TRANSIENT-PRESERVED",
    dumpArtifactRef: restoreArtifact.artifactId,
    engineRecoveryRef: null,
    dumpFormat: "POSTGRESQL-CUSTOM",
    tool: "pg_dump",
    toolVersion: "18.4",
    toolSha256: digest("pg_dump:18.4"),
    serverCompatibility: {
      verified: true,
      verifiedAt: GENERATED_AT,
      serverEngineVersion: "18.4",
      evidenceSha256: digest("pg_dump:18.4:postgresql:18.4:compatibility"),
    },
    consistencyMethod: "PG-MVCC-SNAPSHOT",
    sourceCatalogSha256: restoreDatabase.catalogSha256,
    consistentDump: true,
    checksumVerified: true,
    quiesceRequired: false,
    restoreVerification: {
      verified: true,
      verifiedAt: GENERATED_AT,
      method: "ISOLATED-LOGICAL-RESTORE",
      engine: "POSTGRESQL",
      engineVersion: "18.4",
      scope: "SINGLE-DATABASE",
      databaseName: "restore_probe",
      catalogSha256: restoreDatabase.catalogSha256,
      artifactSha256: restoreArtifact.sha256,
      ownershipManifestSha256: restoreArtifact.ownershipManifestSha256,
      resultSha256: digest("postgres:restore_probe:restore"),
    },
    regeneration: null,
  });
  fixture.receipt.databases.sort((left, right) => left.databaseId.localeCompare(right.databaseId));
  const catalogManifestSha256 = sha256Canonical([{
    databaseId: systemDatabase.id,
    catalogSha256: systemDatabase.catalogSha256,
  }]);
  fixture.receipt.engineRecoveries.push({
    recoveryId: "engine-global:postgresql:app-a-container",
    engine: "POSTGRESQL",
    engineVersion: "18.4",
    serverContainer: "app-a-container",
    databaseRefs: [systemDatabase.id],
    artifactRef: globalArtifact.artifactId,
    format: "POSTGRESQL-GLOBAL-SQL",
    tool: "pg_dumpall",
    toolVersion: "18.4",
    toolSha256: digest("pg_dumpall:18.4"),
    serverCompatibility: {
      verified: true,
      verifiedAt: GENERATED_AT,
      serverEngineVersion: "18.4",
      evidenceSha256: digest("pg_dumpall:18.4:postgresql:18.4:compatibility"),
    },
    consistencyMethod: "PG-GLOBALS-CONSISTENT",
    catalogManifestSha256,
    checksumVerified: true,
    restoreVerification: {
      verified: true,
      verifiedAt: GENERATED_AT,
      method: "ISOLATED-ENGINE-GLOBAL-RESTORE",
      engine: "POSTGRESQL",
      engineVersion: "18.4",
      scope: "ENGINE-GLOBAL",
      databaseName: null,
      catalogSha256: catalogManifestSha256,
      artifactSha256: globalArtifact.sha256,
      ownershipManifestSha256: globalArtifact.ownershipManifestSha256,
      resultSha256: digest("global-postgres:restore"),
    },
  });
  const application = fixture.receipt.applications.find((entry) => entry.applicationId === "app-a");
  const mapping = fixture.receipt.mappings.find((entry) => entry.applicationId === "app-a");
  const restore = fixture.receipt.restorePlan.find((entry) => entry.applicationId === "app-a" && entry.phase === "DATABASE");
  const rollback = fixture.receipt.rollback.data.steps.find((entry) => entry.applicationId === "app-a");
  const databaseStorage = fixture.receipt.storage.find((entry) => entry.storageId === "app_a_data");
  for (const target of [application.databaseRefs, mapping.databaseRefs]) {
    target.push(systemDatabase.id, restoreDatabase.id);
    target.sort();
  }
  restore.databaseRefs.push(systemDatabase.id, restoreDatabase.id);
  restore.databaseRefs.sort();
  rollback.databaseRefs.push(systemDatabase.id, restoreDatabase.id);
  rollback.databaseRefs.sort();
  databaseStorage.dependencyDatabaseRefs.push(systemDatabase.id, restoreDatabase.id);
  databaseStorage.dependencyDatabaseRefs.sort();
  sealReceipt(fixture.receipt);
  return fixture;
}

function virtualSystemFixture() {
  let baseline = baselineFixture();
  const virtualDatabase = {
    id: "mariadb:information_schema",
    engine: "MARIADB",
    engineVersion: "12.1",
    serverContainer: "app-a-container",
    name: "information_schema",
    kind: "SYSTEM",
    owner: "mariadb.sys",
    tableCount: 0,
    catalogSha256: digest("mariadb:information_schema:catalog"),
    storageRefs: ["app_a_data"],
  };
  baseline.databases.push(virtualDatabase);
  baseline.databases.sort((left, right) => left.id.localeCompare(right.id));
  baseline.summary.databases = baseline.databases.length;
  baseline.logicalRecoveryAnchors[0].databaseRefs.push(virtualDatabase.id);
  baseline.logicalRecoveryAnchors[0].databaseRefs.sort();
  baseline = sealLivePreservationBaseline(baseline);
  validateLivePreservationBaseline(baseline, { requireComplete: true });
  const fixture = fixtureForBaseline(baseline);
  const baselineContainer = baseline.containers[0];
  fixture.receipt.databases.push({
    databaseId: virtualDatabase.id,
    engine: virtualDatabase.engine,
    engineVersion: virtualDatabase.engineVersion,
    databaseKind: "SYSTEM",
    disposition: "ENGINE-REGENERATED",
    dumpArtifactRef: null,
    engineRecoveryRef: null,
    dumpFormat: null,
    tool: null,
    toolVersion: null,
    toolSha256: null,
    serverCompatibility: null,
    consistencyMethod: null,
    sourceCatalogSha256: null,
    consistentDump: null,
    checksumVerified: null,
    quiesceRequired: false,
    restoreVerification: null,
    regeneration: {
      basis: "ENGINE-VIRTUAL-CATALOG-REGENERATION",
      method: "MARIADB-VIRTUAL-CATALOG-REGENERATION",
      engine: virtualDatabase.engine,
      engineVersion: virtualDatabase.engineVersion,
      serverContainer: virtualDatabase.serverContainer,
      imageRef: baselineContainer.imageRef,
      imageId: baselineContainer.imageId,
      catalogSha256: virtualDatabase.catalogSha256,
      verifiedAt: GENERATED_AT,
      evidenceSha256: digest("mariadb:information_schema:regeneration"),
    },
  });
  fixture.receipt.databases.sort((left, right) => left.databaseId.localeCompare(right.databaseId));
  const application = fixture.receipt.applications.find((entry) => entry.applicationId === "app-a");
  const mapping = fixture.receipt.mappings.find((entry) => entry.applicationId === "app-a");
  const restore = fixture.receipt.restorePlan.find((entry) => entry.applicationId === "app-a" && entry.phase === "DATABASE");
  const rollback = fixture.receipt.rollback.data.steps.find((entry) => entry.applicationId === "app-a");
  for (const target of [application.databaseRefs, mapping.databaseRefs, restore.databaseRefs, rollback.databaseRefs]) {
    target.push(virtualDatabase.id);
    target.sort();
  }
  const sharedStorage = fixture.receipt.storage.find((entry) => entry.storageId === "app_a_data");
  sharedStorage.dependencyDatabaseRefs.push(virtualDatabase.id);
  sharedStorage.dependencyDatabaseRefs.sort();
  sealReceipt(fixture.receipt);
  return fixture;
}

function sharedResourceFixture() {
  let baseline = baselineFixture();
  baseline.logicalRecoveryAnchors.push({
    id: "app-b",
    displayName: "Application B shared database consumer",
    mappingState: "MAPPED",
    sourceRootRefs: [],
    sourceBindRefs: [],
    containerRefs: [],
    databaseRefs: ["postgres:app_a"],
    storageRefs: ["app_a_data"],
    configRefs: [],
    secretMetadataRefs: [],
  });
  baseline.logicalRecoveryAnchors.sort((left, right) => left.id.localeCompare(right.id));
  baseline.summary.applications = baseline.logicalRecoveryAnchors.length;
  baseline = sealLivePreservationBaseline(baseline);
  validateLivePreservationBaseline(baseline, { requireComplete: true });
  const fixture = fixtureForBaseline(baseline);
  fixture.receipt.applications.push({
    applicationId: "app-b",
    mappingState: "MAPPED",
    codeArtifactRefs: [],
    containerImages: [],
    configRecoveryRefs: [],
    databaseRefs: ["postgres:app_a"],
    storageRefs: ["app_a_data"],
    secretRecoveryRefs: [],
    quiesce: {
      required: true,
      evidence: {
        method: "APPLICATION-WRITE-QUIESCE",
        startedAt: QUIESCE_STARTED_AT,
        completedAt: GENERATED_AT,
        verified: true,
        evidenceSha256: digest("app-b:quiesce"),
      },
    },
  });
  fixture.receipt.applications.sort((left, right) => left.applicationId.localeCompare(right.applicationId));
  fixture.receipt.mappings.push({
    applicationId: "app-b",
    mappingState: "MAPPED",
    databaseRefs: ["postgres:app_a"],
    storageRefs: ["app_a_data"],
  });
  fixture.receipt.mappings.sort((left, right) => left.applicationId.localeCompare(right.applicationId));
  fixture.receipt.restorePlan.push(
    restoreStep(9, "restore-app-b-storage-delegated", "app-b", "STORAGE", [], [], [], [], {
      delegatedStorageRefs: ["app_a_data"],
    }),
    restoreStep(10, "restore-app-b-database-delegated", "app-b", "DATABASE", [], [], [], [], {
      delegatedDatabaseRefs: ["postgres:app_a"],
    }),
    restoreStep(11, "verify-app-b", "app-b", "VERIFY"),
  );
  fixture.receipt.rollback.data.steps.push({
    order: 2,
    stepId: "rollback-app-b-data-delegated",
    applicationId: "app-b",
    databaseRefs: [],
    delegatedDatabaseRefs: ["postgres:app_a"],
    storageRefs: [],
    fallbackStorageRefs: [],
    delegatedStorageRefs: ["app_a_data"],
  });
  const sharedStorage = fixture.receipt.storage.find((entry) => entry.storageId === "app_a_data");
  sharedStorage.dependencyApplicationRefs.push("app-b");
  sharedStorage.dependencyApplicationRefs.sort();
  sealReceipt(fixture.receipt);
  return fixture;
}

function verify(receipt, fixture = fixtures()) {
  return verifyV1PredeployBackupReceipt({
    receipt,
    baseline: fixture.baseline,
    baselineSha256: fixture.baselineSha256,
    expectedTargetRoot: TARGET_ROOT,
    expectedCandidateCommit: CANDIDATE_COMMIT,
    expectedCandidateTree: CANDIDATE_TREE,
  });
}

test("accepts complete synthetic backup coverage but remains non-authoritative", () => {
  const fixture = fixtures();
  assert.deepEqual(verify(fixture.receipt, fixture), {
    status: REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE,
    authoritative: false,
    liveAuthorization: false,
    mutationAuthority: false,
  });
});

test("rejects a backup device shared with any persistent baseline source", () => {
  let baseline = baselineFixture();
  baseline.volumes[0].fsIdentity.device = "99";
  baseline = sealLivePreservationBaseline(baseline);
  validateLivePreservationBaseline(baseline, { requireComplete: true });
  const fixture = fixtureForBaseline(baseline);
  assert.throws(
    () => verify(fixture.receipt, fixture),
    /backup.*device.*persistent source/i,
  );
});

test("rejects a one-byte opaque database dump despite checksum-shaped claims", () => {
  const fixture = fixtures();
  const dump = fixture.receipt.artifacts.find((entry) => entry.kind === "DATABASE-DUMP");
  dump.sizeBytes = 1;
  sealReceipt(fixture.receipt);
  assert.throws(
    () => verify(fixture.receipt, fixture),
    /database.*opaque|minimum semantic size/i,
  );
});

test("binds container code recovery to the exact baseline image ref and image id", () => {
  let baseline = baselineFixture();
  baseline.containers[0].imageRef = `registry.invalid/replaced@sha256:${"8".repeat(64)}`;
  baseline.containers[0].imageId = `sha256:${"8".repeat(64)}`;
  baseline = sealLivePreservationBaseline(baseline);
  validateLivePreservationBaseline(baseline, { requireComplete: true });
  const fixture = fixtureForBaseline(baseline);
  assert.throws(
    () => verify(fixture.receipt, fixture),
    /container.*image|OCI/i,
  );
});

test("covers SYSTEM databases once through engine-global recovery and preserves RESTORE databases", () => {
  const fixture = systemRestoreFixture();
  assert.equal(verify(fixture.receipt, fixture).status, REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE);
});

test("rejects standalone SYSTEM dumps and any RESTORE omission", () => {
  const standalone = systemRestoreFixture();
  const system = standalone.receipt.databases.find((entry) => entry.databaseKind === "SYSTEM");
  system.dumpArtifactRef = "dump-postgres-app-a";
  sealReceipt(standalone.receipt);
  assert.throws(() => verify(standalone.receipt, standalone), /system database.*engine-global/i);

  const omitted = systemRestoreFixture();
  omitted.receipt.databases = omitted.receipt.databases.filter((entry) => entry.databaseKind !== "RESTORE");
  sealReceipt(omitted.receipt);
  assert.throws(() => verify(omitted.receipt, omitted), /database coverage/i);
});

test("rejects drifted engine-global and RESTORE catalog evidence", () => {
  const global = systemRestoreFixture();
  global.receipt.engineRecoveries[0].catalogManifestSha256 = "f".repeat(64);
  sealReceipt(global.receipt);
  assert.throws(() => verify(global.receipt, global), /engine-global recovery.*catalog/i);

  const transient = systemRestoreFixture();
  transient.receipt.databases.find((entry) => entry.databaseKind === "RESTORE").sourceCatalogSha256 = "f".repeat(64);
  sealReceipt(transient.receipt);
  assert.throws(() => verify(transient.receipt, transient), /engine-aware dump|catalog/i);
});

test("accepts PLATFORM databases only through the same closed engine-aware logical path", () => {
  let baseline = baselineFixture();
  baseline.databases[0].kind = "PLATFORM";
  baseline = sealLivePreservationBaseline(baseline);
  validateLivePreservationBaseline(baseline, { requireComplete: true });
  const fixture = fixtureForBaseline(baseline);
  fixture.receipt.databases[0].databaseKind = "PLATFORM";
  sealReceipt(fixture.receipt);
  assert.equal(verify(fixture.receipt, fixture).status, REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE);
});

test("regenerates only known engine-virtual SYSTEM catalogs and binds the exact server image", () => {
  const fixture = virtualSystemFixture();
  assert.equal(verify(fixture.receipt, fixture).status, REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE);

  fixture.receipt.databases.find((entry) => entry.disposition === "ENGINE-REGENERATED")
    .regeneration.imageId = `sha256:${"9".repeat(64)}`;
  sealReceipt(fixture.receipt);
  assert.throws(() => verify(fixture.receipt, fixture), /engine regeneration semantics/i);
});

test("restores shared database storage once as fallback and records full dependency closure", () => {
  const fixture = sharedResourceFixture();
  assert.equal(verify(fixture.receipt, fixture).status, REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE);
  assert.equal(
    fixture.receipt.restorePlan.flatMap((step) => step.fallbackStorageRefs).filter((id) => id === "app_a_data").length,
    1,
  );
  assert.equal(
    fixture.receipt.restorePlan.flatMap((step) => step.databaseRefs).filter((id) => id === "postgres:app_a").length,
    1,
  );
});

test("rejects a delegated consumer verified before the shared resource owner", () => {
  const fixture = sharedResourceFixture();
  const delegated = fixture.receipt.restorePlan.filter((step) => step.applicationId === "app-b");
  const others = fixture.receipt.restorePlan.filter((step) => step.applicationId !== "app-b");
  fixture.receipt.restorePlan = [...delegated, ...others];
  fixture.receipt.restorePlan.forEach((step, index) => { step.order = index + 1; });
  sealReceipt(fixture.receipt);
  assert.throws(() => verify(fixture.receipt, fixture), /restore owner.*before.*verification/i);
});

test("rejects compositional freshness that makes evidence almost twice maxAgeSeconds old", () => {
  const fixture = fixtures();
  const now = Date.now();
  const generatedAt = new Date(now - 7_100_000).toISOString();
  const notBefore = new Date(now - 14_200_000).toISOString();
  const capturedAt = new Date(now - 7_160_000).toISOString();
  const quiesceStartedAt = new Date(now - 7_220_000).toISOString();
  const quiesceCompletedAt = new Date(now - 7_130_000).toISOString();
  fixture.receipt.generatedAt = generatedAt;
  fixture.receipt.freshness = {
    notBefore,
    expiresAt: new Date(now + 50_000).toISOString(),
    maxAgeSeconds: 7200,
  };
  fixture.receipt.artifacts.forEach((entry) => {
    entry.capturedAt = capturedAt;
    entry.identityVerifiedAt = generatedAt;
    entry.checksum.verifiedAt = generatedAt;
    if (entry.materializationVerification) entry.materializationVerification.verifiedAt = generatedAt;
  });
  fixture.receipt.databases.forEach((entry) => {
    entry.serverCompatibility.verifiedAt = generatedAt;
    entry.restoreVerification.verifiedAt = generatedAt;
  });
  fixture.receipt.storage.forEach((entry) => { entry.restoreVerification.verifiedAt = generatedAt; });
  fixture.receipt.recoveryRefs.forEach((entry) => { entry.retrievalVerification.verifiedAt = generatedAt; });
  fixture.receipt.applications[0].containerImages
    .forEach((entry) => { entry.materializationVerification.verifiedAt = generatedAt; });
  fixture.receipt.applications[0].quiesce.evidence.startedAt = quiesceStartedAt;
  fixture.receipt.applications[0].quiesce.evidence.completedAt = quiesceCompletedAt;
  sealReceipt(fixture.receipt);
  assert.throws(() => verify(fixture.receipt, fixture), /freshness exceeds maxAgeSeconds/i);
});

test("binds quiesce to artifact capture and restore to the exact artifact", () => {
  const earlyCapture = fixtures();
  earlyCapture.receipt.artifacts.find((entry) => entry.kind === "DATABASE-DUMP").capturedAt = NOT_BEFORE;
  sealReceipt(earlyCapture.receipt);
  assert.throws(() => verify(earlyCapture.receipt, earlyCapture), /quiesce evidence is not causal/i);

  const wrongArtifact = fixtures();
  wrongArtifact.receipt.databases[0].restoreVerification.artifactSha256 = "f".repeat(64);
  sealReceipt(wrongArtifact.receipt);
  assert.throws(() => verify(wrongArtifact.receipt, wrongArtifact), /exact dump.*catalog.*ownership|restore result/i);
});

test("rejects opaque CONFIG, missing source materialization, and quiesce self-selection", () => {
  const opaqueConfig = fixtures();
  opaqueConfig.receipt.artifacts.find((entry) => entry.kind === "CONFIG").sizeBytes = 1;
  sealReceipt(opaqueConfig.receipt);
  assert.throws(() => verify(opaqueConfig.receipt, opaqueConfig), /minimum semantic size/i);

  const missingMaterialization = fixtures();
  missingMaterialization.receipt.artifacts.find((entry) => entry.kind === "CODE").materializationVerification = null;
  sealReceipt(missingMaterialization.receipt);
  assert.throws(() => verify(missingMaterialization.receipt, missingMaterialization), /isolated materialization/i);

  const bypassQuiesce = fixtures();
  bypassQuiesce.receipt.storage.find((entry) => entry.storageId === "/srv/uploads/app-a").quiesceRequired = false;
  sealReceipt(bypassQuiesce.receipt);
  assert.throws(() => verify(bypassQuiesce.receipt, bypassQuiesce), /quiesce must derive from baseline writability/i);
});

test("keeps rollback admission immutable, externally pending, and durability-attested", () => {
  const fixture = fixtures();
  fixture.receipt.rollback.data.externalAdmission.requirementSha256 = "f".repeat(64);
  sealReceipt(fixture.receipt);
  assert.throws(() => verify(fixture.receipt, fixture), /immutable external.*admission policy/i);
});

test("rejects placeholder secret provider locators without immutable retrieval readiness", () => {
  const fixture = fixtures();
  fixture.receipt.recoveryRefs.find((entry) => entry.kind === "SECRET").providerLocator =
    "provider-secret://nonexistent/placeholder";
  sealReceipt(fixture.receipt);
  assert.throws(() => verify(fixture.receipt, fixture), /schema validation|secret.*provider|retrieval readiness|placeholder/i);
});

test("rejects drifted secret versions, stale readiness, and config artifact substitution", () => {
  const versionDrift = fixtures();
  versionDrift.receipt.recoveryRefs.find((entry) => entry.kind === "SECRET").versionSha256 = "f".repeat(64);
  sealReceipt(versionDrift.receipt);
  assert.throws(() => verify(versionDrift.receipt, versionDrift), /immutable provider.*version|retrieval readiness/i);

  const stale = fixtures();
  stale.receipt.recoveryRefs.find((entry) => entry.kind === "SECRET").retrievalVerification.verifiedAt =
    "2020-01-01T00:00:00.000Z";
  sealReceipt(stale.receipt);
  assert.throws(() => verify(stale.receipt, stale), /retrieval verifiedAt.*evidence window/i);

  const configSubstitution = fixtures();
  configSubstitution.receipt.recoveryRefs.find((entry) => entry.kind === "CONFIG")
    .retrievalVerification.artifactSha256 = "f".repeat(64);
  sealReceipt(configSubstitution.receipt);
  assert.throws(() => verify(configSubstitution.receipt, configSubstitution), /exact materialized artifact version/i);
});

test("covers a canonical cohort of 127 anonymous volumes without omission", () => {
  let baseline = baselineFixture();
  const addedNames = [];
  for (let index = 3; index <= 127; index += 1) {
    const name = index.toString(16).padStart(64, "0");
    addedNames.push(name);
    baseline.volumes.push({
      name,
      nameClass: "ANONYMOUS",
      driver: "local",
      scope: "local",
      mountpoint: `/var/lib/docker/volumes/${name}/_data`,
      createdAt: "2026-08-09T03:00:00.000Z",
      optionsSha256: BASELINE_HASH,
      labelsSha256: BASELINE_HASH,
      composeProject: "",
      composeVolume: "",
      fsIdentity: identity({ type: "directory", device: "1", inode: String(1_000 + index) }),
      observedBytes: 0,
      attachments: [],
      dangling: true,
    });
  }
  baseline.volumes.sort((left, right) => left.name.localeCompare(right.name));
  baseline.logicalRecoveryAnchors[0].storageRefs.push(...addedNames);
  baseline.logicalRecoveryAnchors[0].storageRefs.sort();
  baseline.summary.volumes += addedNames.length;
  baseline.summary.anonymousVolumes += addedNames.length;
  baseline.summary.danglingVolumes += addedNames.length;
  baseline = sealLivePreservationBaseline(baseline);
  validateLivePreservationBaseline(baseline, { requireComplete: true });

  const baselineSource = JSON.stringify(baseline);
  const fixture = {
    baseline,
    baselineSource,
    baselineSha256: digest(baselineSource),
    receipt: receiptFixture(baseline, digest(baselineSource)),
  };
  for (let index = 0; index < addedNames.length; index += 1) {
    const name = addedNames[index];
    const suffix = String(index + 3).padStart(3, "0");
    const artifactId = `anonymous-volume-${suffix}`;
    fixture.receipt.artifacts.push(artifact(
      artifactId,
      "ANONYMOUS-VOLUME",
      `${artifactId}.tar.zst`,
      [name],
      128,
      1_000 + index,
    ));
    fixture.receipt.storage.push(storageReceipt(name, "ANONYMOUS-VOLUME", artifactId, { quiesceRequired: false }));
  }
  const app = fixture.receipt.applications.find((entry) => entry.applicationId === "app-a");
  const mapping = fixture.receipt.mappings.find((entry) => entry.applicationId === "app-a");
  const restore = fixture.receipt.restorePlan.find((entry) => entry.applicationId === "app-a" && entry.phase === "STORAGE");
  const rollback = fixture.receipt.rollback.data.steps.find((entry) => entry.applicationId === "app-a");
  for (const target of [app.storageRefs, mapping.storageRefs, restore.storageRefs, rollback.storageRefs]) {
    target.push(...addedNames);
    target.sort();
  }
  sealReceipt(fixture.receipt);
  assert.equal(verify(fixture.receipt, fixture).status, REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE);

  fixture.receipt.storage = fixture.receipt.storage.filter((entry) => entry.storageId !== addedNames.at(-1));
  sealReceipt(fixture.receipt);
  assert.throws(() => verify(fixture.receipt, fixture), /storage coverage/i);
});

test("covers a DB-less source root when the canonical baseline also classifies it as storage", () => {
  let baseline = baselineFixture();
  const docsAnchor = baseline.logicalRecoveryAnchors.find((entry) => entry.id === "docs");
  docsAnchor.storageRefs = ["/srv/docs"];
  baseline = sealLivePreservationBaseline(baseline);
  validateLivePreservationBaseline(baseline, { requireComplete: true });
  const baselineSource = JSON.stringify(baseline);
  const fixture = {
    baseline,
    baselineSource,
    baselineSha256: digest(baselineSource),
    receipt: receiptFixture(baseline, digest(baselineSource)),
  };
  fixture.receipt.artifacts.push(artifact(
    "source-root-docs-storage",
    "SOURCE-ROOT",
    "source-root-docs-storage.tar.zst",
    ["/srv/docs"],
    1024,
    700,
  ));
  fixture.receipt.storage.push(storageReceipt(
    "/srv/docs",
    "SOURCE-ROOT",
    "source-root-docs-storage",
    {
      quiesceRequired: false,
      captureMode: "FILESYSTEM-SNAPSHOT",
      dependencyApplicationRefs: ["docs"],
    },
  ));
  const docsApp = fixture.receipt.applications.find((entry) => entry.applicationId === "docs");
  const docsMapping = fixture.receipt.mappings.find((entry) => entry.applicationId === "docs");
  docsApp.storageRefs = ["/srv/docs"];
  docsMapping.storageRefs = ["/srv/docs"];
  const docsVerifyIndex = fixture.receipt.restorePlan.findIndex((entry) => entry.applicationId === "docs" && entry.phase === "VERIFY");
  fixture.receipt.restorePlan[docsVerifyIndex].order += 1;
  fixture.receipt.restorePlan.splice(
    docsVerifyIndex,
    0,
    restoreStep(8, "restore-docs-storage", "docs", "STORAGE", [], [], ["/srv/docs"]),
  );
  fixture.receipt.rollback.data.steps.push({
    order: 2,
    stepId: "rollback-docs-data",
    applicationId: "docs",
    databaseRefs: [],
    delegatedDatabaseRefs: [],
    storageRefs: ["/srv/docs"],
    fallbackStorageRefs: [],
    delegatedStorageRefs: [],
  });
  sealReceipt(fixture.receipt);
  assert.equal(verify(fixture.receipt, fixture).status, REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE);
});

const mutants = [
  { name: "missing application coverage", mutate: (r) => r.applications.pop(), expected: /application coverage/i },
  { name: "duplicate application coverage", mutate: (r) => r.applications.push(clone(r.applications[0])), expected: /duplicate applicationId/i },
  { name: "mapping-state drift", mutate: (r) => { r.applications[0].mappingState = "SOURCE-ONLY"; }, expected: /mappingState/i },
  { name: "missing source-root code coverage", mutate: (r) => { r.applications[1].codeArtifactRefs = []; }, expected: /code artifact coverage/i },
  { name: "missing container code identity", mutate: (r) => { r.applications[0].containerImages = []; }, expected: /container image coverage/i },
  { name: "missing config coverage", mutate: (r) => { r.applications[0].configRecoveryRefs = []; }, expected: /config recovery/i },
  { name: "config artifact carries an extra source", mutate: (r) => r.artifacts[2].sourceRefs.push(`${TARGET_ROOT}/secrets/app-a`), expected: /sourceRefsSha256|config artifact coverage/i },
  { name: "database engine drift", mutate: (r) => { r.databases[0].engine = "MARIADB"; }, expected: /engine.*baseline/i },
  { name: "duplicate database", mutate: (r) => r.databases.push(clone(r.databases[0])), expected: /duplicate databaseId/i },
  { name: "missing database", mutate: (r) => r.databases.pop(), expected: /database coverage/i },
  { name: "unverified database dump", mutate: (r) => { r.databases[0].restoreVerification.verified = false; }, expected: /schema validation|restore verification/i },
  { name: "inconsistent database dump", mutate: (r) => { r.databases[0].consistentDump = false; }, expected: /schema validation|engine-aware dump|consistent dump/i },
  { name: "stale database restore evidence", mutate: (r) => { r.databases[0].restoreVerification.verifiedAt = "2020-01-01T00:00:00.000Z"; }, expected: /evidence window/i },
  { name: "future database restore evidence", mutate: (r) => { r.databases[0].restoreVerification.verifiedAt = new Date(Date.parse(GENERATED_AT) + 60_000).toISOString(); }, expected: /evidence window/i },
  { name: "missing attached anonymous volume", mutate: (r) => { r.storage = r.storage.filter((entry) => entry.storageId !== ANONYMOUS_ATTACHED); }, expected: /storage coverage/i },
  { name: "missing dangling anonymous volume", mutate: (r) => { r.storage = r.storage.filter((entry) => entry.storageId !== ANONYMOUS_DANGLING); }, expected: /storage coverage/i },
  { name: "stale storage restore evidence", mutate: (r) => { r.storage[0].restoreVerification.verifiedAt = "2020-01-01T00:00:00.000Z"; }, expected: /evidence window/i },
  { name: "duplicate backup artifact", mutate: (r) => r.artifacts.push(clone(r.artifacts[0])), expected: /duplicate artifactId/i },
  { name: "zero-size backup artifact", mutate: (r) => { r.artifacts[0].sizeBytes = 0; }, expected: /schema validation|size/i },
  { name: "unverified artifact checksum", mutate: (r) => { r.artifacts[0].checksum.verified = false; }, expected: /schema validation|checksum/i },
  { name: "stale checksum evidence", mutate: (r) => { r.artifacts[0].checksum.verifiedAt = "2020-01-01T00:00:00.000Z"; }, expected: /evidence window/i },
  { name: "writable backup artifact", mutate: (r) => { r.artifacts[0].identity.mode = "0640"; }, expected: /immutable backup identity/i },
  { name: "duplicate immutable artifact identity", mutate: (r) => { r.artifacts[1].identity = clone(r.artifacts[0].identity); }, expected: /duplicate immutable identity/i },
  { name: "same backup and target device", mutate: (r) => { r.backupRoot.identity.device = r.target.identity.device; }, expected: /differ from every persistent source device/i },
  { name: "non-canonical same-device spelling", mutate: (r) => { r.backupRoot.identity.device = "01"; }, expected: /schema validation/i },
  { name: "target identity differs from baseline", mutate: (r) => { r.target.identity.inode = "11"; }, expected: /ACTIVE-LIVE/i },
  { name: "backup root under rebuild target", mutate: (r) => { r.backupRoot.path = `${TARGET_ROOT}/backups`; }, expected: /outside.*target/i },
  { name: "artifact path outside backup root", mutate: (r) => { r.artifacts[0].backupPath = "/tmp/code.tar"; }, expected: /inside backup root/i },
  { name: "secret value injection", mutate: (r) => { r.recoveryRefs[1].value = "plaintext-secret"; }, expected: /schema validation/i },
  { name: "duplicate recovery reference", mutate: (r) => r.recoveryRefs.push(clone(r.recoveryRefs[0])), expected: /duplicate recoveryRefId/i },
  { name: "missing secret recovery", mutate: (r) => { r.applications[0].secretRecoveryRefs = []; }, expected: /secret recovery/i },
  { name: "duplicate storage", mutate: (r) => r.storage.push(clone(r.storage[0])), expected: /duplicate storageId/i },
  { name: "missing storage artifact", mutate: (r) => { r.storage[0].artifactRef = "missing-storage-artifact"; }, expected: /Storage .* lacks/i },
  { name: "duplicate application mapping", mutate: (r) => r.mappings.push(clone(r.mappings[0])), expected: /duplicate applicationId/i },
  { name: "unmapped storage", mutate: (r) => { r.mappings[0].storageRefs = []; }, expected: /mapping storage coverage/i },
  { name: "missing quiesce evidence", mutate: (r) => { r.applications[0].quiesce.evidence = null; }, expected: /schema validation|quiesce evidence/i },
  { name: "stale quiesce evidence", mutate: (r) => { r.applications[0].quiesce.evidence.startedAt = "2020-01-01T00:00:00.000Z"; }, expected: /quiesce startedAt.*evidence window|quiesce evidence.*time window/i },
  {
    name: "backdated freshness window accepts old evidence",
    mutate: (r) => {
      r.freshness.notBefore = "2020-01-01T00:00:00.000Z";
      r.artifacts.forEach((entry) => { entry.checksum.verifiedAt = "2020-01-01T00:01:00.000Z"; });
      r.databases.forEach((entry) => { entry.restoreVerification.verifiedAt = "2020-01-01T00:01:00.000Z"; });
      r.storage.forEach((entry) => { entry.restoreVerification.verifiedAt = "2020-01-01T00:01:00.000Z"; });
      r.applications[0].quiesce.evidence.startedAt = "2020-01-01T00:00:30.000Z";
      r.applications[0].quiesce.evidence.completedAt = "2020-01-01T00:01:00.000Z";
    },
    expected: /freshness.*maxAge/i,
  },
  { name: "non-contiguous restore ordering", mutate: (r) => { r.restorePlan[1].order = 9; }, expected: /restore plan.*order/i },
  { name: "destructive restore step", mutate: (r) => { r.restorePlan[3].destructiveMigration = true; }, expected: /schema validation|destructive/i },
  { name: "destructive migration policy", mutate: (r) => { r.migrationPolicy.destructiveAllowed = true; }, expected: /schema validation|destructive/i },
  { name: "combined rollback identity", mutate: (r) => { r.rollback.data.planId = r.rollback.code.planId; }, expected: /rollback.*separate/i },
  { name: "automatic data rollback", mutate: (r) => { r.rollback.data.automatic = true; }, expected: /schema validation/i },
  { name: "data rollback bypasses external admission", mutate: (r) => { r.rollback.data.requiresProviderTargetAdmission = false; }, expected: /schema validation/i },
  { name: "data rollback drops post-deploy preservation", mutate: (r) => { r.rollback.data.postDeployPreservationRequired = false; }, expected: /schema validation/i },
  { name: "expired receipt", mutate: (r) => { r.freshness.expiresAt = new Date(FIXTURE_NOW - 60_000).toISOString(); }, expected: /fresh/i },
  { name: "evidence class laundering", mutate: (r) => { r.evidenceClass = "TARGET-ROOT-OBSERVED"; r.synthetic = false; }, expected: /evidence classes do not match/i },
  { name: "provider signer policy falsely ready", mutate: (r) => { r.trust.providerSignerPolicy = "READY"; }, expected: /schema validation/i },
  { name: "target signer policy falsely ready", mutate: (r) => { r.trust.targetSignerPolicy = "READY"; }, expected: /schema validation/i },
  { name: "signature acceptance claim", mutate: (r) => { r.trust.signatureAccepted = true; }, expected: /schema validation/i },
  { name: "teardown authorization claim", mutate: (r) => { r.teardownAuthorization = true; }, expected: /schema validation/i },
  { name: "wrong exact rebuild target", mutate: (r) => { r.target.root = "/srv/other-platform"; }, expected: /expected rebuild target root/i },
  { name: "candidate commit mismatch", mutate: (r) => { r.candidate.commit = "1".repeat(40); }, expected: /candidate commit/i },
  { name: "candidate tree mismatch", mutate: (r) => { r.candidate.tree = "2".repeat(40); }, expected: /candidate tree/i },
  { name: "self-asserted receipt", mutate: (r) => { r.selfAsserted = true; }, expected: /schema validation/i },
  { name: "live authorization claim", mutate: (r) => { r.liveAuthorization = true; }, expected: /schema validation/i },
  { name: "stale receiptId after content mutation", mutate: (r) => { r.artifacts[0].sizeBytes += 1; }, expected: /receiptId/i, reseal: false },
];

for (const { name, mutate, expected, reseal = true } of mutants) {
  test(`rejects mutant: ${name}`, () => {
    const fixture = fixtures();
    mutate(fixture.receipt);
    if (reseal) sealReceipt(fixture.receipt);
    assert.throws(() => verify(fixture.receipt, fixture), expected);
  });
}

test("requires the exact canonical complete deny-only baseline, not a shallow marker object", () => {
  const fixture = fixtures();
  assert.throws(
    () => verifyV1PredeployBackupReceipt({
      receipt: fixture.receipt,
      baseline: fixture.baseline,
      baselineSha256: "f".repeat(64),
      expectedTargetRoot: TARGET_ROOT,
      expectedCandidateCommit: CANDIDATE_COMMIT,
      expectedCandidateTree: CANDIDATE_TREE,
    }),
    /baseline digest/i,
  );

  const shallow = {
    schema: fixture.baseline.schema,
    baselineId: fixture.baseline.baselineId,
    scope: fixture.baseline.scope,
    evidenceClass: fixture.baseline.evidenceClass,
    synthetic: true,
    complete: true,
    status: "COMPLETE-PRESERVATION-BASELINE",
    gateAdmissible: false,
    mutationAuthority: false,
    effect: "DENY-ONLY",
    checkouts: fixture.baseline.checkouts,
    volumes: fixture.baseline.volumes,
    bindMounts: fixture.baseline.bindMounts,
    databases: fixture.baseline.databases,
    secretMetadata: fixture.baseline.secretMetadata,
    logicalRecoveryAnchors: fixture.baseline.logicalRecoveryAnchors,
    deficiencies: [],
  };
  const shallowFixture = fixtures();
  shallowFixture.baseline = shallow;
  shallowFixture.baselineSource = JSON.stringify(shallow);
  shallowFixture.baselineSha256 = digest(shallowFixture.baselineSource);
  shallowFixture.receipt.baseline.artifactSha256 = shallowFixture.baselineSha256;
  sealReceipt(shallowFixture.receipt);
  assert.throws(() => verify(shallowFixture.receipt, shallowFixture), /canonical deny-only baseline|missing field/i);

  const incomplete = fixtures();
  incomplete.baseline.complete = false;
  incomplete.baseline.status = "INCOMPLETE-NO-GO";
  incomplete.baseline.deficiencies = [{
    code: "TEST_INCOMPLETE",
    resourceClass: "volume",
    resourceId: ANONYMOUS_ATTACHED,
    field: "fsIdentity",
    reason: "Synthetic incomplete baseline mutant.",
  }];
  incomplete.baseline = sealLivePreservationBaseline(incomplete.baseline);
  incomplete.baselineSource = JSON.stringify(incomplete.baseline);
  incomplete.baselineSha256 = digest(incomplete.baselineSource);
  incomplete.receipt.baseline.baselineId = incomplete.baseline.baselineId;
  incomplete.receipt.baseline.artifactSha256 = incomplete.baselineSha256;
  sealReceipt(incomplete.receipt);
  assert.throws(() => verify(incomplete.receipt, incomplete), /complete preservation evidence|deny-only baseline/i);

  const authorityBearing = fixtures();
  authorityBearing.baseline.mutationAuthority = true;
  authorityBearing.baselineSource = JSON.stringify(authorityBearing.baseline);
  authorityBearing.baselineSha256 = digest(authorityBearing.baselineSource);
  authorityBearing.receipt.baseline.artifactSha256 = authorityBearing.baselineSha256;
  sealReceipt(authorityBearing.receipt);
  assert.throws(() => verify(authorityBearing.receipt, authorityBearing), /canonical deny-only baseline|mutation authority/i);
});

test("CLI verifies read-only inputs and emits only the non-authoritative sentinel", () => {
  const fixture = fixtures();
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "v1-backup-receipt-test-"));
  try {
    const baselinePath = path.join(temporaryRoot, "baseline.json");
    const receiptPath = path.join(temporaryRoot, "receipt.json");
    fs.writeFileSync(baselinePath, fixture.baselineSource, { mode: 0o600 });
    fs.writeFileSync(receiptPath, JSON.stringify(fixture.receipt), { mode: 0o600 });

    const result = spawnSync(process.execPath, [
      verifierPath,
      "--verify",
      "--receipt", receiptPath,
      "--baseline", baselinePath,
      "--target-root", TARGET_ROOT,
      "--candidate-commit", CANDIDATE_COMMIT,
      "--candidate-tree", CANDIDATE_TREE,
    ], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, `${REBUILD_BACKUP_VERIFIED_NON_AUTHORITATIVE}\n`);
    assert.equal(result.stderr, "");

    const expiredReceipt = clone(fixture.receipt);
    expiredReceipt.freshness.expiresAt = new Date(FIXTURE_NOW - 60 * 1000).toISOString();
    sealReceipt(expiredReceipt);
    fs.writeFileSync(receiptPath, JSON.stringify(expiredReceipt), { mode: 0o600 });
    const expired = spawnSync(process.execPath, [
      verifierPath,
      "--verify",
      "--receipt", receiptPath,
      "--baseline", baselinePath,
      "--target-root", TARGET_ROOT,
      "--candidate-commit", CANDIDATE_COMMIT,
      "--candidate-tree", CANDIDATE_TREE,
    ], { encoding: "utf8" });
    assert.notEqual(expired.status, 0);
    assert.equal(expired.stdout, "");
    assert.match(expired.stderr, /freshness window/i);

    for (const forbidden of ["--create", "--dump", "--restore", "--sign", "--authorize-live", "--teardown", "--now"]) {
      const rejected = spawnSync(process.execPath, [verifierPath, forbidden], { encoding: "utf8" });
      assert.notEqual(rejected.status, 0);
      assert.equal(rejected.stdout, "");
    }
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("implementation surface contains no backup producer, restore, signer, Docker, SSH, or network process", () => {
  const source = fs.readFileSync(verifierPath, "utf8");
  for (const forbidden of [
    "child_process",
    "spawn(",
    "exec(",
    "docker ",
    "ssh ",
    "createBackup",
    "dumpDatabase",
    "restoreBackup",
    "signReceipt",
    "authorizeLive",
  ]) {
    assert.equal(source.includes(forbidden), false, `forbidden producer surface: ${forbidden}`);
  }
});
