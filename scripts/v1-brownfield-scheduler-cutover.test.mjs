import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  sealLivePreservationBaseline,
  sha256Canonical,
} from "./live-preservation-baseline.mjs";
import {
  CUTOVER_SCHEMA,
  CUTOVER_STAGE_ORDER,
  EXTERNAL_EVIDENCE_HASH_FIELDS,
  LEGACY_CONTAINER_REQUIREMENTS,
  PROPOSED_MUTATION_TARGETS,
  verifyV1BrownfieldSchedulerCutover,
} from "./v1-brownfield-scheduler-cutover.mjs";

const SCRIPT = path.join(import.meta.dirname, "v1-brownfield-scheduler-cutover.mjs");
const REAL_BASELINE = path.resolve(
  import.meta.dirname,
  "..",
  "reports",
  "preservation-baselines",
  "live-server-20260809T041407Z.json",
);
const HASHES = Array.from({ length: 80 }, (_, index) => (
  (index + 1).toString(16).padStart(64, "0")
));
const CANDIDATE_COMMIT = "a".repeat(40);
const CANDIDATE_TREE = "b".repeat(40);
const QUEUE_PARENT = "/srv/legacy/platform-infrastructure/projects-portal/state";
const QUEUE_SOURCE = `${QUEUE_PARENT}/backup-jobs`;

function identity(index, {
  type = "directory",
  device = "1",
  uid = 0,
  gid = 0,
  mode = "0755",
} = {}) {
  return {
    type,
    device,
    inode: String(index + 1),
    uid,
    gid,
    mode,
    nlink: 1,
  };
}

function canonicalContainer(index) {
  const requirement = LEGACY_CONTAINER_REQUIREMENTS[index];
  const digest = (index + 101).toString(16).padStart(64, "0");
  const name = requirement?.name ?? `preserved-container-${String(index + 1).padStart(2, "0")}`;
  const service = requirement?.service ?? `preserved-service-${String(index + 1).padStart(2, "0")}`;
  return {
    id: digest,
    name,
    project: name === "enterprise-node-exporter" ? null : "platform_infra_vps",
    service,
    imageRef: `registry.example.test/platform/${service}@sha256:${digest}`,
    imageId: `sha256:${digest}`,
    createdAt: "2026-08-09T04:00:00.000Z",
    state: "running",
    health: "healthy",
    exitCode: 0,
    configHash: HASHES[index + 20],
    configuredUser: name === "enterprise-node-exporter" ? "nobody" : "0:0",
    effectiveUid: name === "enterprise-node-exporter" ? 65534 : 0,
    effectiveGid: name === "enterprise-node-exporter" ? 65534 : 0,
    readOnlyRootfs: false,
    privileged: false,
    mounts: [],
    networks: [],
    ports: [],
    environmentKeys: [],
  };
}

function canonicalVolume(index) {
  const anonymous = index >= 12;
  const name = anonymous
    ? (index + 1000).toString(16).padStart(64, "0")
    : `legacy_named_${String(index + 1).padStart(3, "0")}`;
  return {
    name,
    nameClass: anonymous ? "ANONYMOUS" : "NAMED",
    driver: "local",
    scope: "local",
    mountpoint: `/var/lib/docker/volumes/${name}/_data`,
    createdAt: "2026-08-09T03:00:00.000Z",
    optionsSha256: HASHES[40],
    labelsSha256: HASHES[41],
    composeProject: null,
    composeVolume: null,
    fsIdentity: identity(index + 100),
    observedBytes: 0,
    attachments: [],
    dangling: true,
  };
}

function addBind(raw, {
  source,
  classification,
  identityOptions = {},
  consumers,
}) {
  const lstatIdentity = identity(500 + raw.bindMounts.length, identityOptions);
  raw.bindMounts.push({
    source,
    canonicalPath: source,
    classification,
    lstatIdentity,
    targetIdentity: structuredClone(lstatIdentity),
    contentSha256: null,
    consumers: consumers.map(({ containerName, destination, readOnly }) => ({
      containerName,
      destination,
      readOnly,
    })),
  });
  for (const consumer of consumers) {
    const container = raw.containers.find((entry) => entry.name === consumer.containerName);
    assert.ok(container, `missing fixture container ${consumer.containerName}`);
    container.mounts.push({
      kind: "bind",
      sourceRef: source,
      destination: consumer.destination,
      readOnly: consumer.readOnly,
      propagation: consumer.propagation ?? "rprivate",
    });
  }
}

function completeCanonicalBaseline() {
  const containers = Array.from({ length: 34 }, (_, index) => canonicalContainer(index));
  const volumes = Array.from({ length: 139 }, (_, index) => canonicalVolume(index));
  const composeConfigPath = "/srv/legacy/platform-infrastructure/compose.yaml";
  const composeContainerNames = containers
    .filter(({ project }) => project === "platform_infra_vps")
    .map(({ name }) => name)
    .sort((left, right) => left.localeCompare(right));
  const raw = {
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
      machineIdSha256: HASHES[42],
      bootId: "00000000-0000-4000-8000-000000000001",
      sshHostKeySha256: HASHES[43],
      dockerDaemonId: "SYNTHETIC-DAEMON-ID",
      dockerRootDir: "/var/lib/docker",
      dockerRootIdentity: identity(1),
      os: {
        id: "ubuntu",
        versionId: "26.04",
        kernel: "7.0.0-test",
        architecture: "x86_64",
      },
      principal: { uid: 1000, gid: 1000 },
    },
    source: {
      kind: "SYNTHETIC",
      referenceSha256: HASHES[44],
      captureOutputs: [{
        kind: "synthetic-fixture",
        callIdSha256: HASHES[45],
        outputSha256: HASHES[46],
      }],
      capturedProjectionDigests: [{
        kind: "docker-volume-full-inventory",
        sha256: HASHES[47],
      }],
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
      containers: 34,
      volumes: 139,
      attachedVolumes: 0,
      danglingVolumes: 139,
      namedVolumes: 12,
      anonymousVolumes: 127,
      bindMounts: 0,
      sourceRoots: 0,
      networks: 0,
      hostListeners: 0,
      databases: 0,
      applications: 1,
      secretMetadataRecords: 0,
    },
    checkouts: [],
    composeProjects: [{
      name: "platform_infra_vps",
      workingDirectories: ["/srv/legacy/platform-infrastructure"],
      configFiles: [{
        path: composeConfigPath,
        sensitivity: "NON-SECRET-CONFIG",
        contentCaptured: true,
        sha256: HASHES[48],
        fsIdentity: identity(49),
      }],
      containerNames: composeContainerNames,
    }],
    containers,
    volumes,
    bindMounts: [],
    sourceRoots: [],
    networks: [],
    hostListeners: [],
    databases: [],
    secretMetadata: [],
    logicalRecoveryAnchors: [],
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

  addBind(raw, {
    source: QUEUE_PARENT,
    classification: "APPLICATION-DATA",
    identityOptions: { uid: 1000, gid: 1000, mode: "0755" },
    consumers: [
      {
        containerName: "enterprise-backup-scheduler",
        destination: "/var/www/project-state",
        readOnly: false,
      },
      {
        containerName: "enterprise-control-center",
        destination: "/var/www/project-state",
        readOnly: false,
      },
    ],
  });
  addBind(raw, {
    source: "/var/run/docker.sock",
    classification: "SOCKET",
    identityOptions: { type: "socket", mode: "0660" },
    consumers: [{
      containerName: "enterprise-backup-scheduler",
      destination: "/var/run/docker.sock",
      readOnly: false,
    }],
  });
  addBind(raw, {
    source: "/",
    classification: "HOST-API",
    consumers: [
      {
        containerName: "enterprise-cadvisor",
        destination: "/rootfs",
        readOnly: true,
        propagation: "rslave",
      },
      {
        containerName: "enterprise-node-exporter",
        destination: "/host",
        readOnly: true,
        propagation: "rslave",
      },
    ],
  });
  addBind(raw, {
    source: "/var/lib/docker",
    classification: "HOST-API",
    consumers: [{
      containerName: "enterprise-cadvisor",
      destination: "/var/lib/docker",
      readOnly: true,
      propagation: "rslave",
    }],
  });
  addBind(raw, {
    source: "/var/run",
    classification: "HOST-API",
    consumers: [{
      containerName: "enterprise-cadvisor",
      destination: "/var/run",
      readOnly: true,
    }],
  });

  for (const container of raw.containers) {
    container.mounts.sort((left, right) => (
      `${left.destination}\0${left.kind}\0${left.sourceRef}`
        .localeCompare(`${right.destination}\0${right.kind}\0${right.sourceRef}`)
    ));
  }
  raw.containers.sort((left, right) => left.name.localeCompare(right.name));
  raw.volumes.sort((left, right) => left.name.localeCompare(right.name));
  raw.bindMounts.sort((left, right) => left.source.localeCompare(right.source));
  raw.summary.bindMounts = raw.bindMounts.length;
  raw.logicalRecoveryAnchors = [{
    id: "synthetic-legacy-estate",
    displayName: "Synthetic legacy estate",
    mappingState: "MAPPED",
    sourceRootRefs: [],
    sourceBindRefs: raw.bindMounts.map(({ source }) => source),
    containerRefs: raw.containers.map(({ name }) => name),
    databaseRefs: [],
    storageRefs: raw.volumes.map(({ name }) => name),
    configRefs: [composeConfigPath],
    secretMetadataRefs: [],
  }];
  return sealLivePreservationBaseline(raw);
}

function hashBytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function baselineArtifactSha256(baseline) {
  return hashBytes(Buffer.from(`${JSON.stringify(baseline)}\n`, "utf8"));
}

function containerBinding(baseline, requirement, index) {
  const container = baseline.containers.find(({ name }) => name === requirement.name);
  assert.ok(container, `fixture is missing ${requirement.name}`);
  return {
    name: requirement.name,
    service: requirement.service,
    project: container.project,
    authorityKind: requirement.authorityKind,
    disposition: requirement.disposition,
    containerId: container.id,
    imageRef: container.imageRef,
    imageId: container.imageId,
    configHash: container.configHash,
    createdAt: container.createdAt,
    expectedState: "running",
    expectedHealth: "healthy",
    mountsSha256: sha256Canonical(container.mounts),
    recoveryArtifactSha256: HASHES[index + 50],
  };
}

function sealPlan(input) {
  const plan = structuredClone(input);
  plan.planId = "0".repeat(64);
  const payload = structuredClone(plan);
  delete payload.planId;
  plan.planId = sha256Canonical(payload);
  return plan;
}

function validFixture() {
  const baseline = completeCanonicalBaseline();
  const artifactSha256 = baselineArtifactSha256(baseline);
  const externalEvidence = Object.fromEntries(
    EXTERNAL_EVIDENCE_HASH_FIELDS.map((field, index) => [field, HASHES[index]]),
  );
  const queueContentSha256 = HASHES[60];
  const plan = sealPlan({
    schema: CUTOVER_SCHEMA,
    planId: "0".repeat(64),
    scope: "platform-infrastructure",
    evidenceClass: "SYNTHETIC-TEST",
    synthetic: true,
    verifyOnly: true,
    candidateRepositoryControlled: true,
    baseline: {
      schema: baseline.schema,
      baselineId: baseline.baselineId,
      artifactSha256,
      completedAt: baseline.capturedAt.completedAt,
      dockerDaemonId: baseline.host.dockerDaemonId,
    },
    candidate: {
      repository: "example/platform-infrastructure",
      commit: CANDIDATE_COMMIT,
      tree: CANDIDATE_TREE,
      sourceArchiveSha256: HASHES[61],
      combinedRenderSha256: HASHES[62],
    },
    target: {
      root: "/srv/platform-infrastructure",
      hostname: baseline.host.hostname,
      machineIdSha256: baseline.host.machineIdSha256,
      sshHostKeySha256: baseline.host.sshHostKeySha256,
      dockerDaemonId: baseline.host.dockerDaemonId,
    },
    authoritativeBackup: {
      schema: "platform.v1-authoritative-backup-binding/v1",
      authority: "EXTERNAL-TARGET-ROOT-AND-PROVIDER",
      receiptId: HASHES[63],
      receiptArtifactSha256: HASHES[64],
      attestationEnvelopeSha256:
        externalEvidence.authoritativeBackupAttestationEnvelopeSha256,
      evidenceArtifactSha256: HASHES[65],
      restoreVerificationArtifactSha256: HASHES[66],
      baselineId: baseline.baselineId,
      baselineArtifactSha256: artifactSha256,
      candidateRepository: "example/platform-infrastructure",
      candidateCommit: CANDIDATE_COMMIT,
      candidateTree: CANDIDATE_TREE,
      targetRoot: "/srv/platform-infrastructure",
      sourceDeviceSetSha256: HASHES[67],
      sourceDeviceCount: 7,
      backupDeviceIdentitySha256: HASHES[68],
      verifiedOutsideAllSourceDevices: true,
      completeApplicationCoverage: true,
      completeDatabaseCoverage: true,
      completeStorageCoverage: true,
      consistentDatabaseCaptures: true,
      readable: true,
      restorePlanVerified: true,
    },
    externalEvidence,
    legacyContainers: LEGACY_CONTAINER_REQUIREMENTS.map((requirement, index) => (
      containerBinding(baseline, requirement, index)
    )),
    queueMigration: {
      schema: "platform.v1-brownfield-scheduler-queue-migration/v1",
      observationArtifactSha256: HASHES[69],
      source: {
        path: QUEUE_SOURCE,
        parentBindSource: QUEUE_PARENT,
        contentTreeSha256: queueContentSha256,
        metadataManifestSha256: HASHES[70],
        aclSha256: HASHES[73],
        xattrSha256: HASHES[74],
        entryCount: 9,
        totalBytes: 4096,
        uid: 1000,
        gid: 1000,
        mode: "0755",
      },
      destination: {
        volumeName: "platform_infra_vps_backup_scheduler_jobs",
        initialState: "ABSENT-OR-EMPTY-CANDIDATE-OWNED",
        expectedContentTreeSha256: queueContentSha256,
        expectedMetadataManifestSha256: HASHES[70],
        expectedAclSha256: HASHES[73],
        expectedXattrSha256: HASHES[74],
        expectedEntryCount: 9,
        expectedTotalBytes: 4096,
        uid: 1000,
        gid: 1000,
        mode: "0755",
      },
      transfer: {
        sourceReadOnly: true,
        sourcePreserved: true,
        contentRewriteAllowed: false,
        symlinksAllowed: false,
        specialFilesAllowed: false,
        networkMode: "none",
        dockerSocketMounted: false,
        ownershipTransform: "NONE-PRESERVE-EXACT",
      },
    },
    stagedOrder: [...CUTOVER_STAGE_ORDER],
    safety: {
      unknownResources: "PRESERVE",
      foreignResourceMutationAllowed: false,
      globalTeardownAllowed: false,
      removeOrphansAllowed: false,
      pruneAllowed: false,
      databaseMutationAllowed: false,
      persistentStorageDeletionAllowed: false,
      sourceQueueMutationAllowed: false,
      rawAuthorityOverlapAllowed: false,
      proposedMutationTargets: [...PROPOSED_MUTATION_TARGETS],
    },
    rollback: {
      codeRollbackPlanArtifactSha256: HASHES[71],
      legacyRecoveryBundleSha256: HASHES[72],
      preservePostCutoverState: true,
      automaticDatabaseRestore: false,
      automaticQueueOverwrite: false,
      dataRollbackAuthorized: false,
      requireSeparateDataRollbackAdmission: true,
      brokerMustStopBeforeLegacyAuthorityRestore: true,
    },
  });
  return { baseline, baselineArtifactSha256: artifactSha256, plan };
}

function verifyFixture(fixture) {
  return verifyV1BrownfieldSchedulerCutover({
    plan: fixture.plan,
    baseline: fixture.baseline,
    baselineArtifactSha256: fixture.baselineArtifactSha256,
  });
}

function reseal(plan) {
  return sealPlan(plan);
}

function replaceFixtureBaseline(fixture, rawBaseline) {
  fixture.baseline = sealLivePreservationBaseline(rawBaseline);
  fixture.baselineArtifactSha256 = baselineArtifactSha256(fixture.baseline);
  fixture.plan.baseline.baselineId = fixture.baseline.baselineId;
  fixture.plan.baseline.artifactSha256 = fixture.baselineArtifactSha256;
  fixture.plan.baseline.completedAt = fixture.baseline.capturedAt.completedAt;
  fixture.plan.baseline.dockerDaemonId = fixture.baseline.host.dockerDaemonId;
  fixture.plan.authoritativeBackup.baselineId = fixture.baseline.baselineId;
  fixture.plan.authoritativeBackup.baselineArtifactSha256 = fixture.baselineArtifactSha256;
  fixture.plan = reseal(fixture.plan);
  return fixture;
}

test("SC01 complete synthetic inputs validate structurally but never authorize cutover", () => {
  const fixture = validFixture();
  const result = verifyFixture(fixture);

  assert.equal(result.schema, "platform.v1-brownfield-scheduler-cutover-validation/v1");
  assert.equal(result.status, "LOCAL-NOT-AUTHORIZED");
  assert.equal(result.externalStatus, "EXTERNAL-PENDING");
  assert.equal(result.referenceOnly, true);
  assert.equal(result.structuralBindingsValidated, true);
  assert.equal(result.authoritativeEvidenceVerified, false);
  assert.equal(result.executionAuthorized, false);
  assert.equal(result.mutationAuthority, false);
  assert.equal(result.localMutationAuthority, false);
  assert.equal(result.dataRollbackAuthorized, false);
  assert.equal(result.dockerExecutor, false);
  assert.equal(result.unknownResources, "PRESERVE");
  assert.deepEqual(result.proposedStagedOrder, CUTOVER_STAGE_ORDER);
  assert.deepEqual(result.proposedMutationTargets, PROPOSED_MUTATION_TARGETS);
  assert.equal(result.globalAuthorityProjection.scannedContainerCount, 34);
  assert.deepEqual(
    result.globalAuthorityProjection.authorityContainers.map(({ name }) => name),
    [
      "enterprise-backup-scheduler",
      "enterprise-cadvisor",
      "enterprise-node-exporter",
    ],
  );
  assert.equal(result.globalAuthorityProjection.unknownAuthorityCount, 0);
  assert.equal(result.globalAuthorityProjection.foreignAuthorityCount, 0);
  for (const projected of result.globalAuthorityProjection.authorityContainers) {
    const container = fixture.baseline.containers.find(({ name }) => name === projected.name);
    assert.equal(projected.containerCasSha256, sha256Canonical(container));
    const authorityBindings = fixture.baseline.bindMounts.filter((binding) => (
      ["HOST-API", "SOCKET"].includes(binding.classification)
        && binding.consumers.some(({ containerName }) => containerName === projected.name)
    ));
    assert.equal(projected.authorityBindingsSha256, sha256Canonical(authorityBindings));
  }
  assert.deepEqual(result.actions, []);
  assert.equal(result.planId, fixture.plan.planId);
  assert.equal(result.baselineId, fixture.baseline.baselineId);
  assert.ok(Object.isFrozen(result));
  assert.doesNotMatch(
    JSON.stringify(result),
    /FULL[-_ ]?PRODUCTION[-_ ]?GO|PREREQUISITES-SATISFIED|"status":"READY"|"executionAuthorized":true/,
  );
});

test("SC02 only a canonical COMPLETE baseline with exact raw artifact binding is accepted", () => {
  const fixture = validFixture();
  const incomplete = structuredClone(fixture.baseline);
  incomplete.complete = false;
  incomplete.status = "INCOMPLETE-NO-GO";
  incomplete.deficiencies = [{
    code: "SYNTHETIC-GAP",
    resourceClass: "container",
    resourceId: "enterprise-backup-scheduler",
    field: "configHash",
    reason: "negative fixture",
  }];
  fixture.baseline = sealLivePreservationBaseline(incomplete);
  assert.throws(() => verifyFixture(fixture), /complete preservation|INCOMPLETE-NO-GO|complete=true/i);

  const hashMismatch = validFixture();
  hashMismatch.baselineArtifactSha256 = HASHES[79];
  assert.throws(() => verifyFixture(hashMismatch), /baseline artifact SHA256/i);

  if (fs.existsSync(REAL_BASELINE)) {
    const real = JSON.parse(fs.readFileSync(REAL_BASELINE, "utf8"));
    const stopped = validFixture();
    stopped.baseline = real;
    stopped.baselineArtifactSha256 = hashBytes(fs.readFileSync(REAL_BASELINE));
    assert.throws(() => verifyFixture(stopped), /complete preservation|INCOMPLETE-NO-GO|complete=true/i);
  }
});

test("SC03 backup, candidate, target, and external artifact bindings are exact and closed", () => {
  const missingEvidence = validFixture();
  delete missingEvidence.plan.externalEvidence.activationGateEnvelopeSha256;
  missingEvidence.plan = reseal(missingEvidence.plan);
  assert.throws(() => verifyFixture(missingEvidence), /externalEvidence.*exact closed schema/i);

  const duplicateEvidence = validFixture();
  duplicateEvidence.plan.externalEvidence.activationGateEnvelopeSha256 =
    duplicateEvidence.plan.externalEvidence.deploymentGateEnvelopeSha256;
  duplicateEvidence.plan = reseal(duplicateEvidence.plan);
  assert.throws(() => verifyFixture(duplicateEvidence), /external evidence hashes must be pairwise distinct/i);

  const backupAttestationMismatch = validFixture();
  backupAttestationMismatch.plan.authoritativeBackup.attestationEnvelopeSha256 = HASHES[79];
  backupAttestationMismatch.plan = reseal(backupAttestationMismatch.plan);
  assert.throws(() => verifyFixture(backupAttestationMismatch), /backup attestation.*external evidence/i);

  for (const [field, value, pattern] of [
    ["candidateCommit", "c".repeat(40), /backup candidate.*cutover candidate/i],
    ["candidateTree", "d".repeat(40), /backup candidate.*cutover candidate/i],
    ["targetRoot", "/srv/another-root", /backup target root/i],
    ["baselineId", HASHES[79], /backup baseline/i],
  ]) {
    const mismatch = validFixture();
    mismatch.plan.authoritativeBackup[field] = value;
    mismatch.plan = reseal(mismatch.plan);
    assert.throws(() => verifyFixture(mismatch), pattern, field);
  }

  const forgedAuthority = validFixture();
  forgedAuthority.plan.executionAuthorized = true;
  forgedAuthority.plan = reseal(forgedAuthority.plan);
  assert.throws(() => verifyFixture(forgedAuthority), /cutover plan.*exact closed schema/i);
});

test("SC04 all four legacy containers are CAS-bound to the complete baseline", () => {
  for (const field of ["containerId", "imageId", "configHash", "createdAt", "mountsSha256"]) {
    const mismatch = validFixture();
    mismatch.plan.legacyContainers[1][field] = field === "createdAt"
      ? "2026-08-09T04:00:01.000Z"
      : field === "imageId"
        ? `sha256:${HASHES[79]}`
        : HASHES[79];
    mismatch.plan = reseal(mismatch.plan);
    assert.throws(() => verifyFixture(mismatch), /legacy container.*CAS|does not match.*baseline/i, field);
  }

  const missing = validFixture();
  missing.plan.legacyContainers.pop();
  missing.plan = reseal(missing.plan);
  assert.throws(() => verifyFixture(missing), /legacy container set and order/i);

  const reordered = validFixture();
  [reordered.plan.legacyContainers[0], reordered.plan.legacyContainers[1]] =
    [reordered.plan.legacyContainers[1], reordered.plan.legacyContainers[0]];
  reordered.plan = reseal(reordered.plan);
  assert.throws(() => verifyFixture(reordered), /legacy container set and order/i);

  const extra = validFixture();
  extra.plan.legacyContainers.push(structuredClone(extra.plan.legacyContainers[0]));
  extra.plan = reseal(extra.plan);
  assert.throws(() => verifyFixture(extra), /legacy container set and order/i);

  const baselineServiceMismatch = validFixture();
  const changedBaseline = structuredClone(baselineServiceMismatch.baseline);
  changedBaseline.containers.find(({ name }) => name === "enterprise-backup-scheduler").service =
    "unexpected-backup-scheduler";
  baselineServiceMismatch.baseline = sealLivePreservationBaseline(changedBaseline);
  baselineServiceMismatch.baselineArtifactSha256 = baselineArtifactSha256(
    baselineServiceMismatch.baseline,
  );
  baselineServiceMismatch.plan.baseline.baselineId = baselineServiceMismatch.baseline.baselineId;
  baselineServiceMismatch.plan.baseline.artifactSha256 =
    baselineServiceMismatch.baselineArtifactSha256;
  baselineServiceMismatch.plan.authoritativeBackup.baselineId =
    baselineServiceMismatch.baseline.baselineId;
  baselineServiceMismatch.plan.authoritativeBackup.baselineArtifactSha256 =
    baselineServiceMismatch.baselineArtifactSha256;
  baselineServiceMismatch.plan = reseal(baselineServiceMismatch.plan);
  assert.throws(() => verifyFixture(baselineServiceMismatch), /legacy container.*CAS/i);
});

test("SC05 queue migration binds the observed source and exact destination content and metadata", () => {
  const sourceEscape = validFixture();
  sourceEscape.plan.queueMigration.source.path = `${QUEUE_PARENT}/other/backup-jobs`;
  sourceEscape.plan = reseal(sourceEscape.plan);
  assert.throws(() => verifyFixture(sourceEscape), /exact backup-jobs child/i);

  const unobservedParent = validFixture();
  unobservedParent.plan.queueMigration.source.parentBindSource = "/srv/unobserved/state";
  unobservedParent.plan.queueMigration.source.path = "/srv/unobserved/state/backup-jobs";
  unobservedParent.plan = reseal(unobservedParent.plan);
  assert.throws(() => verifyFixture(unobservedParent), /observed application-data bind/i);

  for (const [mutate, pattern] of [
    [(plan) => { plan.queueMigration.destination.expectedContentTreeSha256 = HASHES[79]; }, /content tree digest/i],
    [(plan) => { plan.queueMigration.destination.expectedMetadataManifestSha256 = HASHES[79]; }, /metadata.*must match/i],
    [(plan) => { plan.queueMigration.destination.expectedAclSha256 = HASHES[79]; }, /ACL.*must match/i],
    [(plan) => { plan.queueMigration.destination.expectedXattrSha256 = HASHES[79]; }, /xattr.*must match/i],
    [(plan) => { plan.queueMigration.destination.expectedEntryCount += 1; }, /entry count/i],
    [(plan) => { plan.queueMigration.destination.expectedTotalBytes += 1; }, /total bytes/i],
    [(plan) => { plan.queueMigration.source.uid = -1; }, /source owner UID/i],
    [(plan) => { plan.queueMigration.source.mode = "755"; }, /source mode/i],
    [(plan) => { plan.queueMigration.destination.uid = 0; }, /ownership.*must match/i],
    [(plan) => { plan.queueMigration.destination.gid = 0; }, /ownership.*must match/i],
    [(plan) => { plan.queueMigration.destination.mode = "0700"; }, /mode.*must match/i],
    [(plan) => { plan.queueMigration.transfer.sourceReadOnly = false; }, /queue transfer boundary/i],
    [(plan) => { plan.queueMigration.transfer.sourcePreserved = false; }, /queue transfer boundary/i],
    [(plan) => { plan.queueMigration.transfer.symlinksAllowed = true; }, /queue transfer boundary/i],
    [(plan) => { plan.queueMigration.transfer.ownershipTransform = "EXPLICIT-ROOT-QUEUE-ONLY"; }, /queue transfer boundary/i],
    [(plan) => { plan.queueMigration.destination.volumeName = "unexpected_jobs"; }, /canonical queue volume/i],
  ]) {
    const mismatch = validFixture();
    mutate(mismatch.plan);
    mismatch.plan = reseal(mismatch.plan);
    assert.throws(() => verifyFixture(mismatch), pattern);
  }
});

test("SC06 staged order, mutation scope, preservation policy, and rollback remain immutable", () => {
  const reordered = validFixture();
  [reordered.plan.stagedOrder[2], reordered.plan.stagedOrder[3]] =
    [reordered.plan.stagedOrder[3], reordered.plan.stagedOrder[2]];
  reordered.plan = reseal(reordered.plan);
  assert.throws(() => verifyFixture(reordered), /exact deny-only staged order/i);

  const destructive = validFixture();
  destructive.plan.stagedOrder.push("docker-compose-down-remove-orphans");
  destructive.plan = reseal(destructive.plan);
  assert.throws(() => verifyFixture(destructive), /exact deny-only staged order/i);

  const widened = validFixture();
  widened.plan.safety.proposedMutationTargets.push("container:unrelated-application");
  widened.plan = reseal(widened.plan);
  assert.throws(() => verifyFixture(widened), /proposed mutation targets/i);

  const unknownMutation = validFixture();
  unknownMutation.plan.safety.unknownResources = "REMOVE";
  unknownMutation.plan = reseal(unknownMutation.plan);
  assert.throws(() => verifyFixture(unknownMutation), /preservation safety policy/i);

  for (const field of [
    "foreignResourceMutationAllowed",
    "globalTeardownAllowed",
    "removeOrphansAllowed",
    "pruneAllowed",
    "databaseMutationAllowed",
    "persistentStorageDeletionAllowed",
    "sourceQueueMutationAllowed",
    "rawAuthorityOverlapAllowed",
  ]) {
    const unsafe = validFixture();
    unsafe.plan.safety[field] = true;
    unsafe.plan = reseal(unsafe.plan);
    assert.throws(() => verifyFixture(unsafe), /preservation safety policy/i, field);
  }

  const dataRollback = validFixture();
  dataRollback.plan.rollback.dataRollbackAuthorized = true;
  dataRollback.plan = reseal(dataRollback.plan);
  assert.throws(() => verifyFixture(dataRollback), /rollback policy/i);

  for (const field of ["automaticDatabaseRestore", "automaticQueueOverwrite"]) {
    const automaticDataMutation = validFixture();
    automaticDataMutation.plan.rollback[field] = true;
    automaticDataMutation.plan = reseal(automaticDataMutation.plan);
    assert.throws(() => verifyFixture(automaticDataMutation), /rollback policy/i, field);
  }
});

test("SC07 implementation exposes no Docker, process, shell, network, signing, or mutation executor", () => {
  const source = fs.readFileSync(SCRIPT, "utf8");
  assert.doesNotMatch(source, /from\s+["']node:(?:child_process|net|http|https|tls|dgram|worker_threads)["']/);
  assert.doesNotMatch(source, /\b(?:exec|execFile|spawn|fork|system)Sync?\s*\(/);
  assert.doesNotMatch(source, /\bfetch\s*\(|docker\s+compose|--remove-orphans|\b(?:volume|system)\s+prune\b/i);
  assert.doesNotMatch(source, /BEGIN (?:OPENSSH |RSA |EC |PRIVATE )?PRIVATE KEY|createPrivateKey|generateKeyPair|\bsign\s*\(/);
  assert.doesNotMatch(source, /function\s+apply|command\s*===?\s*["']apply["']/i);
});

test("SC08 CLI is verify-only, emits descriptive output, and exits 78 even for valid input", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-scheduler-cutover-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const baselinePath = path.join(root, "baseline.json");
  const planPath = path.join(root, "plan.json");
  const fixture = validFixture();
  const baselineBytes = Buffer.from(`${JSON.stringify(fixture.baseline)}\n`, "utf8");
  fixture.baselineArtifactSha256 = hashBytes(baselineBytes);
  fixture.plan.baseline.artifactSha256 = fixture.baselineArtifactSha256;
  fixture.plan.authoritativeBackup.baselineArtifactSha256 = fixture.baselineArtifactSha256;
  fixture.plan = reseal(fixture.plan);
  fs.writeFileSync(baselinePath, baselineBytes);
  fs.writeFileSync(planPath, `${JSON.stringify(fixture.plan)}\n`);

  const valid = spawnSync(process.execPath, [
    SCRIPT,
    "verify",
    "--plan",
    planPath,
    "--baseline",
    baselinePath,
    "--expected-baseline-sha256",
    fixture.baselineArtifactSha256,
  ], { encoding: "utf8" });
  assert.equal(valid.status, 78, valid.stderr);
  const output = JSON.parse(valid.stdout);
  assert.equal(output.status, "LOCAL-NOT-AUTHORIZED");
  assert.equal(output.externalStatus, "EXTERNAL-PENDING");
  assert.equal(output.executionAuthorized, false);
  assert.equal(output.dockerExecutor, false);
  assert.deepEqual(output.actions, []);

  const apply = spawnSync(process.execPath, [SCRIPT, "apply"], { encoding: "utf8" });
  assert.equal(apply.status, 78);
  assert.match(apply.stdout, /LOCAL-NOT-AUTHORIZED/);
  assert.doesNotMatch(apply.stdout + apply.stderr, /docker compose|docker create|docker start/i);

  const mismatchedPin = spawnSync(process.execPath, [
    SCRIPT,
    "verify",
    "--plan",
    planPath,
    "--baseline",
    baselinePath,
    "--expected-baseline-sha256",
    HASHES[79],
  ], { encoding: "utf8" });
  assert.equal(mismatchedPin.status, 78);
  assert.match(mismatchedPin.stdout, /baseline artifact SHA256/i);
});

test("SC09 cutover target root is fixed to /srv/platform-infrastructure", () => {
  const redirected = validFixture();
  redirected.plan.target.root = "/srv/attacker-selected-root";
  redirected.plan.authoritativeBackup.targetRoot = redirected.plan.target.root;
  redirected.plan = reseal(redirected.plan);
  assert.throws(() => verifyFixture(redirected), /canonical target root/i);
});

test("SC10 every baseline container is scanned and unknown or foreign raw or host authority stops", () => {
  for (const [source, destination, classification, identityOptions] of [
    ["/run/docker.sock", "/run/docker.sock", "SOCKET", { type: "socket", mode: "0660" }],
    [
      "/run/user/1000/docker.sock",
      "/run/user/1000/docker.sock",
      "SOCKET",
      { type: "socket", mode: "0660" },
    ],
    [
      "/run/user/1001/docker.sock",
      "/run/user/1001/docker.sock",
      "APPLICATION-DATA",
      { type: "socket", mode: "0660" },
    ],
    [
      "/run/user/1001/control.sock",
      "/run/user/1001/control.sock",
      "APPLICATION-DATA",
      { type: "socket", mode: "0660" },
    ],
    ["/tmp/spoofed-api", "/var/run/docker.sock", "APPLICATION-DATA", {}],
    ["/var", "/host-var", "HOST-API", {}],
    ["/var/lib/docker/containers", "/spoofed-docker-root", "APPLICATION-DATA", {}],
    ["/proc", "/host-proc", "HOST-API", {}],
    ["/proc", "/spoofed-host-proc", "APPLICATION-DATA", {}],
    ["/proc/1/root", "/spoofed-proc-root", "APPLICATION-DATA", {}],
    ["/sys", "/host-sys", "HOST-API", {}],
    ["/dev", "/host-dev", "HOST-API", {}],
    ["/opaque-unclassified-bind", "/opaque", "UNKNOWN-PRESERVE", {}],
  ]) {
    const fixture = validFixture();
    const raw = structuredClone(fixture.baseline);
    const unknownContainer = raw.containers.find(({ name }) => name.startsWith("preserved-container-"));
    assert.ok(unknownContainer);
    addBind(raw, {
      source,
      classification,
      identityOptions,
      consumers: [{
        containerName: unknownContainer.name,
        destination,
        readOnly: true,
      }],
    });
    unknownContainer.mounts.sort((left, right) => (
      `${left.destination}\0${left.kind}\0${left.sourceRef}`
        .localeCompare(`${right.destination}\0${right.kind}\0${right.sourceRef}`)
    ));
    raw.bindMounts.sort((left, right) => left.source.localeCompare(right.source));
    raw.summary.bindMounts = raw.bindMounts.length;
    raw.logicalRecoveryAnchors[0].sourceBindRefs = raw.bindMounts.map(({ source: ref }) => ref);
    replaceFixtureBaseline(fixture, raw);
    assert.throws(
      () => verifyFixture(fixture),
      /unknown or foreign.*authority|global authority projection|complete preservation evidence/i,
      source,
    );
  }

  const unmapped = validFixture();
  const unmappedRaw = structuredClone(unmapped.baseline);
  const unmappedContainer = unmappedRaw.containers
    .find(({ name }) => name.startsWith("preserved-container-"));
  unmappedContainer.mounts.push({
    kind: "bind",
    sourceRef: "/unmapped-host-api",
    destination: "/unmapped-host-api",
    readOnly: true,
    propagation: "rprivate",
  });
  unmappedContainer.mounts.sort((left, right) => (
    `${left.destination}\0${left.kind}\0${left.sourceRef}`
      .localeCompare(`${right.destination}\0${right.kind}\0${right.sourceRef}`)
  ));
  replaceFixtureBaseline(unmapped, unmappedRaw);
  assert.throws(
    () => verifyFixture(unmapped),
    /unknown bind|cannot map bind/i,
  );

  const widenedKnownAuthority = validFixture();
  const raw = structuredClone(widenedKnownAuthority.baseline);
  addBind(raw, {
    source: "/var",
    classification: "HOST-API",
    consumers: [{
      containerName: "enterprise-backup-scheduler",
      destination: "/host-var",
      readOnly: true,
    }],
  });
  const scheduler = raw.containers.find(({ name }) => name === "enterprise-backup-scheduler");
  scheduler.mounts.sort((left, right) => (
    `${left.destination}\0${left.kind}\0${left.sourceRef}`
      .localeCompare(`${right.destination}\0${right.kind}\0${right.sourceRef}`)
  ));
  raw.bindMounts.sort((left, right) => left.source.localeCompare(right.source));
  raw.summary.bindMounts = raw.bindMounts.length;
  raw.logicalRecoveryAnchors[0].sourceBindRefs = raw.bindMounts.map(({ source }) => source);
  replaceFixtureBaseline(widenedKnownAuthority, raw);
  widenedKnownAuthority.plan.legacyContainers
    .find(({ name }) => name === scheduler.name).mountsSha256 = sha256Canonical(scheduler.mounts);
  widenedKnownAuthority.plan = reseal(widenedKnownAuthority.plan);
  assert.throws(
    () => verifyFixture(widenedKnownAuthority),
    /unknown or foreign.*authority/i,
  );
});

test("SC11 queue destination must preserve metadata, ownership, mode, ACL, and xattrs", () => {
  for (const mutate of [
    (plan) => { plan.queueMigration.destination.expectedMetadataManifestSha256 = HASHES[79]; },
    (plan) => { plan.queueMigration.destination.expectedAclSha256 = HASHES[79]; },
    (plan) => { plan.queueMigration.destination.expectedXattrSha256 = HASHES[79]; },
    (plan) => { plan.queueMigration.destination.uid += 1; },
    (plan) => { plan.queueMigration.destination.gid += 1; },
    (plan) => { plan.queueMigration.destination.mode = "0700"; },
  ]) {
    const mismatch = validFixture();
    mutate(mismatch.plan);
    mismatch.plan = reseal(mismatch.plan);
    assert.throws(
      () => verifyFixture(mismatch),
      /queue source and destination metadata.*must match/i,
    );
  }
});
