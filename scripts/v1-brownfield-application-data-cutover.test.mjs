import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import Ajv2020 from "../vendor/json-schema/node_modules/ajv/dist/2020.js";
import addFormatsModule from "../vendor/json-schema/node_modules/ajv-formats/dist/index.js";

import {
  APPLICATION_DATA_PARENT,
  APPLICATION_DATA_QUEUE,
  CUTOVER_PLAN,
  canonicalJson,
  deriveApplicationDataProjection,
  sealApplicationDataCutoverContract,
  sha256Canonical,
  verifyV1BrownfieldApplicationDataCutover,
} from "./v1-brownfield-application-data-cutover.mjs";
import {
  sealLivePreservationBaseline,
} from "./live-preservation-baseline.mjs";
import {
  CURRENT_CONTRACTS,
  PROTECTED_RESOURCE_MAP,
  QUEUE_OWNERSHIP,
  RUNTIME_SERVICES,
  RUNTIME_VOLUMES,
  sealRuntimeIdentityDocument,
} from "./v1-brownfield-runtime-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = path.join(root, "scripts", "v1-brownfield-application-data-cutover.mjs");
const TEMPLATE = path.join(root, "governance", "v1-brownfield-application-data-cutover.json");
const SCHEMA = path.join(root, "governance", "schemas", "v1-brownfield-application-data-cutover.schema.json");
const RUNTIME_TEMPLATE = path.join(root, "governance", "v1-brownfield-runtime-identity.json");
const H = (seed) => crypto.createHash("sha256").update(`application-data-cutover:${seed}`).digest("hex");

function identity(index, overrides = {}) {
  return {
    type: "directory",
    device: "1",
    inode: String(1000 + index),
    uid: 1000,
    gid: 1000,
    mode: "0750",
    nlink: 2,
    ...overrides,
  };
}

function container(name, service, sourcePath, destination, readOnly, index) {
  return {
    id: H(`container:${index}`),
    name,
    project: "platform_infra_vps",
    service,
    imageRef: `registry.invalid/platform/${service}@sha256:${H(`image-ref:${index}`)}`,
    imageId: `sha256:${H(`image-id:${index}`)}`,
    createdAt: "2026-08-11T00:00:00.000Z",
    state: "running",
    health: "healthy",
    exitCode: 0,
    configHash: H(`config:${index}`),
    configuredUser: "1000:1000",
    effectiveUid: 1000,
    effectiveGid: 1000,
    readOnlyRootfs: true,
    privileged: false,
    mounts: [{
      kind: "bind",
      sourceRef: sourcePath,
      destination,
      readOnly,
      propagation: "rprivate",
    }],
    networks: [],
    ports: [],
    environmentKeys: [],
  };
}

function baselineFixture() {
  const definitions = [
    ["enterprise-backup-scheduler", "backup-scheduler", APPLICATION_DATA_QUEUE, "/var/www/project-state/backup-jobs", false],
    ["enterprise-control-center", "control-center", APPLICATION_DATA_PARENT, "/var/www/project-state", false],
    ["enterprise-docker-action-broker", "docker-action-broker", APPLICATION_DATA_QUEUE, "/run/platform/backup-jobs", true],
    ["enterprise-project-router", "project-router", APPLICATION_DATA_PARENT, "/var/www/project-state", false],
    ["php-anniversary", "php-anniversary", APPLICATION_DATA_PARENT, "/var/www/project-state", false],
    ["php-apache", "php-apache", APPLICATION_DATA_PARENT, "/var/www/project-state", false],
    ["php-fiplatform", "php-fiplatform", APPLICATION_DATA_PARENT, "/var/www/project-state", false],
    ["php-matthewdifilippo", "php-matthewdifilippo", APPLICATION_DATA_PARENT, "/var/www/project-state", false],
    ["php-stream", "php-stream", APPLICATION_DATA_PARENT, "/var/www/project-state", false],
    ["php-workcalendar", "php-workcalendar", APPLICATION_DATA_PARENT, "/var/www/project-state", false],
  ];
  const containers = definitions.map((entry, index) => container(...entry, index))
    .sort((left, right) => left.name.localeCompare(right.name));
  for (const observed of containers) {
    if (["php-anniversary", "php-apache", "php-fiplatform"].includes(observed.name)) {
      observed.project = null;
    }
  }
  const parentConsumers = containers
    .filter((entry) => entry.mounts[0].sourceRef === APPLICATION_DATA_PARENT)
    .map((entry) => ({
      containerName: entry.name,
      destination: entry.mounts[0].destination,
      readOnly: entry.mounts[0].readOnly,
    }))
    .sort((left, right) => `${left.containerName}\0${left.destination}`.localeCompare(`${right.containerName}\0${right.destination}`));
  const queueConsumers = containers
    .filter((entry) => entry.mounts[0].sourceRef === APPLICATION_DATA_QUEUE)
    .map((entry) => ({
      containerName: entry.name,
      destination: entry.mounts[0].destination,
      readOnly: entry.mounts[0].readOnly,
    }))
    .sort((left, right) => `${left.containerName}\0${left.destination}`.localeCompare(`${right.containerName}\0${right.destination}`));
  const bindMounts = [{
    source: APPLICATION_DATA_PARENT,
    canonicalPath: APPLICATION_DATA_PARENT,
    classification: "APPLICATION-DATA",
    lstatIdentity: identity(40),
    targetIdentity: identity(40),
    contentSha256: H("full-parent-content"),
    consumers: parentConsumers,
  }, {
    source: APPLICATION_DATA_QUEUE,
    canonicalPath: APPLICATION_DATA_QUEUE,
    classification: "APPLICATION-DATA",
    lstatIdentity: identity(41),
    targetIdentity: identity(41),
    contentSha256: H("queue-content"),
    consumers: queueConsumers,
  }];
  const configPath = "/home/platform_infrastructure/platform-infrastructure/compose.yaml";
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
      startedAt: "2026-08-11T00:00:00.000Z",
      completedAt: "2026-08-11T00:01:00.000Z",
    },
    host: {
      hostname: "synthetic-host",
      machineIdSha256: H("machine"),
      bootId: "00000000-0000-4000-8000-000000000001",
      sshHostKeySha256: H("ssh-host-key"),
      dockerDaemonId: "SYNTHETIC-DAEMON-ID",
      dockerRootDir: "/var/lib/docker",
      dockerRootIdentity: identity(1, { uid: 0, gid: 0, mode: "0710" }),
      os: { id: "ubuntu", versionId: "26.04", kernel: "7.0.0-test", architecture: "x86_64" },
      principal: { uid: 0, gid: 0 },
    },
    source: {
      kind: "SYNTHETIC",
      referenceSha256: H("source"),
      captureOutputs: [{ kind: "synthetic-fixture", callIdSha256: H("call"), outputSha256: H("output") }],
      capturedProjectionDigests: [{ kind: "docker-container-inventory", sha256: H("projection") }],
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
      containers: containers.length,
      volumes: 0,
      attachedVolumes: 0,
      danglingVolumes: 0,
      namedVolumes: 0,
      anonymousVolumes: 0,
      bindMounts: bindMounts.length,
      sourceRoots: 0,
      networks: 0,
      hostListeners: 0,
      databases: 0,
      applications: 1,
      secretMetadataRecords: 0,
    },
    checkouts: [{
      id: "active-live",
      role: "ACTIVE-LIVE",
      path: "/home/platform_infrastructure/platform-infrastructure",
      commit: "1".repeat(40),
      tree: "2".repeat(40),
      branch: "main",
      dirty: false,
      dirtyPathCount: 0,
      statusSha256: H("status"),
      fsIdentity: identity(2),
    }],
    composeProjects: [{
      name: "platform_infra_vps",
      workingDirectories: ["/home/platform_infrastructure/platform-infrastructure"],
      configFiles: [{
        path: configPath,
        sensitivity: "NON-SECRET-CONFIG",
        contentCaptured: true,
        sha256: H("compose"),
        fsIdentity: identity(3, { type: "regular-file", mode: "0644", nlink: 1 }),
      }],
      containerNames: containers.filter(({ project }) => project !== null).map(({ name }) => name),
    }],
    containers,
    volumes: [],
    bindMounts,
    sourceRoots: [],
    networks: [],
    hostListeners: [],
    databases: [],
    secretMetadata: [],
    logicalRecoveryAnchors: [{
      id: "projects-portal",
      displayName: "Projects portal",
      mappingState: "MAPPED",
      sourceRootRefs: [],
      sourceBindRefs: [APPLICATION_DATA_PARENT, APPLICATION_DATA_QUEUE],
      containerRefs: containers.map(({ name }) => name),
      databaseRefs: [],
      storageRefs: [],
      configRefs: [configPath],
      secretMetadataRefs: [],
    }],
    digests: {},
    deficiencies: [],
  };
  return sealLivePreservationBaseline(document);
}

function runtimeLabels(logicalName) {
  return {
    "com.docker.compose.project": "platform_infra_vps",
    "com.docker.compose.version": "2.99.0-synthetic",
    "com.docker.compose.volume": logicalName,
  };
}

function runtimeIdentityFixture(projection, baselineArtifactSha256, baselineId) {
  const document = JSON.parse(fs.readFileSync(RUNTIME_TEMPLATE, "utf8"));
  document.synthetic = true;
  document.evidenceClass = "SYNTHETIC-TEST";
  document.status = "SYNTHETIC-COMPLETE-NOT-AUTHORIZED";
  document.stagingBoundary.sourceSetSha256 = H("runtime-staging-source-set");
  document.schedulerBoundary.contractArtifactSha256 = H("runtime-scheduler-contract");
  document.schedulerBoundary.identitySetSha256 = H("runtime-scheduler-identities");
  document.schedulerBoundary.queueMigrationSha256 = H("runtime-scheduler-queue");
  document.schedulerBoundary.applicationDataParentBindingSha256 = H("runtime-scheduler-parent-bind");

  const compose = document.productionBoundary.compose;
  compose.rawFullRenderBytesSha256 = H("runtime-raw-full-render-bytes");
  compose.fileOrderSha256 = sha256Canonical(compose.fileOrder);
  compose.profilesSha256 = sha256Canonical(compose.profiles);
  compose.environmentSha256 = H("runtime-environment-bytes");
  compose.projectNameSha256 = sha256Canonical(compose.projectName);
  compose.serviceSetSha256 = sha256Canonical(compose.serviceNames);
  compose.configSha256 = H("runtime-rendered-config");
  compose.networksSha256 = sha256Canonical(compose.networkNames);
  compose.attachmentsSha256 = H("runtime-all-network-attachments");
  compose.resourceMapSha256 = sha256Canonical(compose.resourceMap);
  compose.noHostedPolicyBytesSha256 = H("runtime-no-hosted-policy-bytes");

  document.productionBoundary.containers = document.productionBoundary.containers.map((entry, index) => {
    const completed = {
      ...entry,
      containerId: H(`runtime-container-id:${index}`),
      imageReference: `registry.invalid/platform/${entry.service}@sha256:${H(`runtime-manifest:${index}`)}`,
      imageId: `sha256:${H(`runtime-image-id:${index}`)}`,
      configHash: H(`runtime-container-config:${index}`),
      mountsSha256: H(`runtime-mounts:${index}`),
      networkAttachmentsSha256: H(`runtime-container-networks:${index}`),
      inspectionArtifactSha256: H(`runtime-container-inspection:${index}`),
    };
    completed.containerCasSha256 = sha256Canonical(completed);
    return completed;
  });
  document.productionBoundary.volumes = document.productionBoundary.volumes.map((entry, index) => {
    const completed = {
      ...entry,
      driver: "local",
      scope: "local",
      options: {},
      labels: runtimeLabels(entry.logicalName),
      createdAt: `2026-08-11T00:00:0${index}.000Z`,
      mountpoint: `/var/lib/docker/volumes/${entry.physicalName}/_data`,
      inspectionArtifactSha256: H(`runtime-volume-inspection:${index}`),
    };
    completed.volumeCasSha256 = sha256Canonical(completed);
    return completed;
  });
  const queue = document.productionBoundary.queueOwnership;
  queue.observationArtifactSha256 = H("runtime-queue-observation");
  queue.writerEnumerationSha256 = sha256Canonical({
    owners: queue.owners,
    extraParentOrChildReadWriteWriters: queue.extraParentOrChildReadWriteWriters,
  });
  queue.completeParentAndChildWriterEnumeration = true;

  const parent = document.productionBoundary.applicationDataParent;
  parent.sourcePath = APPLICATION_DATA_PARENT;
  parent.canonicalPath = APPLICATION_DATA_PARENT;
  parent.sourceIdentitySha256 = projection.parentTargetIdentitySha256;
  parent.baselineBindingSha256 = sha256Canonical({
    baselineArtifactSha256,
    baselineId,
    applicationDataBindSetSha256: projection.applicationDataBindSetSha256,
    parentTargetIdentitySha256: projection.parentTargetIdentitySha256,
  });
  for (const attachment of parent.finalAttachments) attachment.sourcePath = APPLICATION_DATA_PARENT;
  parent.consumerSetSha256 = sha256Canonical(parent.finalAttachments);
  parent.observationArtifactSha256 = H("runtime-application-data-observation");
  document.documentId = "0".repeat(64);
  return sealRuntimeIdentityDocument(document);
}

function snapshot(seed, rootIdentitySha256, capturedAt) {
  const result = {
    artifactSha256: "0".repeat(64),
    capturedAt,
    scopePath: APPLICATION_DATA_PARENT,
    entryCount: 37,
    rootIdentitySha256,
    metadataTreeSha256: H(`${seed}:metadata`),
    aclTreeSha256: H(`${seed}:acl`),
    xattrTreeSha256: H(`${seed}:xattr`),
    contentTreeSha256: H(`${seed}:content`),
    combinedTreeSha256: "0".repeat(64),
    unreadableEntryCount: 0,
    volatileEntryCount: 0,
  };
  result.combinedTreeSha256 = sha256Canonical({
    scopePath: result.scopePath,
    entryCount: result.entryCount,
    rootIdentitySha256: result.rootIdentitySha256,
    metadataTreeSha256: result.metadataTreeSha256,
    aclTreeSha256: result.aclTreeSha256,
    xattrTreeSha256: result.xattrTreeSha256,
    contentTreeSha256: result.contentTreeSha256,
    unreadableEntryCount: result.unreadableEntryCount,
    volatileEntryCount: result.volatileEntryCount,
  });
  const payload = structuredClone(result);
  payload.artifactSha256 = null;
  result.artifactSha256 = sha256Canonical(payload);
  return result;
}

function fixture(inputBaseline = baselineFixture()) {
  const baseline = structuredClone(inputBaseline);
  const baselineBytes = Buffer.from(`${canonicalJson(baseline)}\n`, "utf8");
  const rawArtifactSha256 = crypto.createHash("sha256").update(baselineBytes).digest("hex");
  const projection = deriveApplicationDataProjection(baseline);
  const runtimeIdentity = runtimeIdentityFixture(projection, rawArtifactSha256, baseline.baselineId);
  const runtimeIdentityBytes = Buffer.from(`${canonicalJson(runtimeIdentity)}\n`, "utf8");
  const runtimeIdentityArtifactSha256 = crypto.createHash("sha256").update(runtimeIdentityBytes).digest("hex");
  const contract = JSON.parse(fs.readFileSync(TEMPLATE, "utf8"));
  contract.evidenceClass = "SYNTHETIC-TEST";
  contract.synthetic = true;
  contract.status = "BASELINE-BOUND-NOT-AUTHORIZED";
  Object.assign(contract.baselineBinding, {
    rawArtifactSha256,
    baselineId: baseline.baselineId,
    complete: true,
    sourceDeviceSetSha256: projection.sourceSet.sourceDeviceSetSha256,
    sourceObservationSetSha256: projection.sourceSet.sourceObservationSetSha256,
    sourcePathSetSha256: projection.sourceSet.sourcePathSetSha256,
    sourceObservationCount: projection.sourceSet.sourceObservationCount,
    sourcePathCount: projection.sourceSet.sourcePathCount,
    applicationDataBindSetSha256: projection.applicationDataBindSetSha256,
    writerSetSha256: projection.writerSetSha256,
  });
  Object.assign(contract.applicationDataParent, {
    baselineTargetIdentitySha256: projection.parentTargetIdentitySha256,
    baselineParentContentSha256: projection.parentContentSha256,
    coveredBindSources: projection.coveredBindSources,
    coveredBindSetSha256: projection.applicationDataBindSetSha256,
  });
  Object.assign(contract.writerInventory, {
    complete: true,
    writers: projection.writers,
    writerSetSha256: projection.writerSetSha256,
  });
  Object.assign(contract.queue, {
    potentialWriterIds: projection.potentialQueueWriterIds,
    potentialWriterSetSha256: projection.potentialQueueWriterSetSha256,
  });
  const runtimeParent = runtimeIdentity.productionBoundary.applicationDataParent;
  const runtimeQueue = runtimeIdentity.productionBoundary.queueOwnership;
  contract.runtimeBinding = {
    schema: "platform.v1-brownfield-runtime-identity/v1",
    rawArtifactSha256: runtimeIdentityArtifactSha256,
    documentId: runtimeIdentity.documentId,
    baselineBindingSha256: runtimeParent.baselineBindingSha256,
    consumerSetSha256: runtimeParent.consumerSetSha256,
    applicationDataObservationArtifactSha256: runtimeParent.observationArtifactSha256,
    queueWriterEnumerationSha256: runtimeQueue.writerEnumerationSha256,
    compatibilityStatus: "MISMATCH-STOP",
    currentContractsConverged: false,
    applicationDataBaselineRecomputationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    queueWriterEnumerationRecomputationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    queueConflict: {
      status: "PRESERVE+STOP",
      reason: "NAMED-VOLUME-WOULD-HIDE-LEGACY-QUEUE-CHILD",
      legacyQueuePath: APPLICATION_DATA_QUEUE,
      runtimeLogicalVolume: "backup_scheduler_jobs",
      runtimeMountTarget: "/var/www/project-state/backup-jobs",
      resolutionStatus: "EXTERNAL-PROVIDER-EVIDENCE-REQUIRED",
    },
  };
  const runtimeAttachments = new Map(runtimeParent.finalAttachments.map((entry) => [entry.containerName, entry]));
  const finalDispositions = projection.writers.map((writer, index) => {
    const attachment = runtimeAttachments.get(writer.containerName);
    return {
      writerId: writer.writerId,
      containerName: writer.containerName,
      service: writer.service,
      preCutoverAccess: "RW",
      finalDisposition: "RESUME-UNCHANGED-LEGACY-WRITER",
      runtimeAttachmentAccess: attachment ? (attachment.readOnly ? "RO" : "RW") : "NONE",
      runtimeAttachmentTarget: attachment?.target ?? null,
      resumeOrder: index + 1,
      resumeRequired: true,
      targetReplacementProven: false,
    };
  });
  const lifecycleContainerNames = [...new Set(
    projection.writers.map(({ containerName }) => containerName),
  )].sort((left, right) => left.localeCompare(right));
  contract.writerLifecycle = {
    quiesceWriterIds: projection.writers.map(({ writerId }) => writerId),
    quiesceContainerNames: lifecycleContainerNames,
    finalDispositions,
    resumeWriterIds: projection.writers.map(({ writerId }) => writerId),
    resumeContainerNames: lifecycleContainerNames,
    writerDispositionSetSha256: sha256Canonical(finalDispositions),
    omittedWriterDisposition: "PRESERVE+STOP",
    duplicateWriterDisposition: "PRESERVE+STOP",
  };
  const preAttachSnapshot = snapshot("same-tree", projection.parentTargetIdentitySha256, "2026-08-11T00:02:00.000Z");
  const postAttachSnapshot = structuredClone(preAttachSnapshot);
  postAttachSnapshot.capturedAt = "2026-08-11T00:03:00.000Z";
  postAttachSnapshot.artifactSha256 = "0".repeat(64);
  const postAttachPayload = structuredClone(postAttachSnapshot);
  postAttachPayload.artifactSha256 = null;
  postAttachSnapshot.artifactSha256 = sha256Canonical(postAttachPayload);
  Object.assign(contract.preservationEvidence, {
    copyPerformed: false,
    relocationPerformed: false,
    destinationPath: null,
    sameFilesystemObjectRequired: true,
  });
  contract.preservationEvidence.preAttachSnapshot = preAttachSnapshot;
  contract.preservationEvidence.postAttachSnapshot = postAttachSnapshot;
  contract.preservationEvidence.comparison = {
    preAttachSnapshotSha256: preAttachSnapshot.artifactSha256,
    postAttachSnapshotSha256: postAttachSnapshot.artifactSha256,
    rootIdentityMatch: true,
    metadataMatch: true,
    aclMatch: true,
    xattrMatch: true,
    contentMatch: true,
    fullTreeMatch: true,
  };
  contract.documentId = "0".repeat(64);
  return {
    baseline,
    baselineBytes,
    baselineArtifactSha256: rawArtifactSha256,
    projection,
    runtimeIdentity,
    runtimeIdentityBytes,
    runtimeIdentityArtifactSha256,
    contract: sealApplicationDataCutoverContract(contract),
  };
}

function mutateContract(mutator) {
  const value = fixture();
  mutator(value.contract, value);
  value.contract.documentId = "0".repeat(64);
  value.contract = sealApplicationDataCutoverContract(value.contract);
  return value;
}

test("AD01 schema is strict and the governance template is immutable STOP-only", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA, "utf8"));
  const Ajv = Ajv2020.default ?? Ajv2020;
  const addFormats = addFormatsModule.default ?? addFormatsModule;
  const ajv = new Ajv({ allErrors: true, strict: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  const templateBytes = fs.readFileSync(TEMPLATE);
  const template = JSON.parse(templateBytes.toString("utf8"));
  assert.equal(
    templateBytes.equals(Buffer.from(`${canonicalJson(template)}\n`, "utf8")),
    true,
    "published governance template must be directly consumable by the canonical-wire CLI",
  );
  assert.equal(validate(template), true, JSON.stringify(validate.errors));
  const repeatedQuiescePlan = structuredClone(template);
  repeatedQuiescePlan.cutoverPlan.steps = Array.from(
    { length: 6 },
    () => structuredClone(template.cutoverPlan.steps[0]),
  );
  repeatedQuiescePlan.documentId = "0".repeat(64);
  const sealedRepeatedQuiescePlan = sealApplicationDataCutoverContract(repeatedQuiescePlan);
  assert.equal(
    validate(sealedRepeatedQuiescePlan),
    false,
    "strict schema must reject six positionally invalid QUIESCE steps",
  );
  const result = verifyV1BrownfieldApplicationDataCutover({ contract: template });
  assert.equal(result.status, "STOP");
  assert.equal(result.authorizationStatus, "LOCAL-NOT-AUTHORIZED");
  assert.equal(result.rollbackAuthorized, false);
  assert.deepEqual(result.actions, []);
});

test("AD02 exact complete raw baseline derives every RW parent/queue writer and still returns STOP", () => {
  const value = fixture();
  assert.deepEqual(value.projection.writers.map(({ service }) => service), [
    "backup-scheduler",
    "control-center",
    "project-router",
    "php-anniversary",
    "php-apache",
    "php-fiplatform",
    "php-matthewdifilippo",
    "php-stream",
    "php-workcalendar",
  ]);
  assert.equal(value.projection.writers.find(({ service }) => service === "php-apache").project, null);
  assert.equal(value.projection.writers.every(({ mapped, quiesceRequired }) => mapped && quiesceRequired), true);
  assert.deepEqual(value.projection.coveredBindSources, [APPLICATION_DATA_PARENT, APPLICATION_DATA_QUEUE]);
  assert.deepEqual(value.projection.potentialQueueWriterIds, value.projection.writers.map(({ writerId }) => writerId));
  const result = verifyV1BrownfieldApplicationDataCutover(value);
  assert.equal(result.status, "STOP");
  assert.equal(result.authorizationStatus, "LOCAL-NOT-AUTHORIZED");
  assert.equal(result.baselineComplete, true);
  assert.equal(result.fullParentPreservationVerified, false);
  assert.equal(result.fullParentPreservationEvidenceStatus, "CALLER-EVIDENCE-STRUCTURAL-ONLY");
  assert.equal(result.writerEnumerationVerified, false);
  assert.equal(result.runtimeIdentityVerified, false);
  assert.equal(result.applicationsResumeVerified, false);
  assert.equal(result.applicationsResumeVerificationStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert.equal(result.deploymentAuthority, false);
  assert.equal(result.mutationAuthority, false);
  assert.equal(result.stdoutAuthority, false);
  assert.equal(result.trustedNativeLauncherRequired, true);
  assert.equal(result.rollbackAuthorized, false);
  assert.deepEqual(result.actions, []);
  assert.ok(Object.isFrozen(result));
});

test("AD03 incomplete, non-canonical, stale-id, and raw-hash-substitution baselines fail closed", () => {
  const incomplete = baselineFixture();
  incomplete.complete = false;
  incomplete.status = "INCOMPLETE-NO-GO";
  incomplete.deficiencies = [{
    code: "TEST_INCOMPLETE",
    resourceClass: "bind",
    resourceId: APPLICATION_DATA_PARENT,
    field: "contentSha256",
    reason: "Synthetic incomplete baseline.",
  }];
  const sealedIncomplete = sealLivePreservationBaseline(incomplete);
  assert.throws(() => deriveApplicationDataProjection(sealedIncomplete), /complete preservation|complete deny-only/i);

  const value = fixture();
  assert.throws(
    () => verifyV1BrownfieldApplicationDataCutover({ ...value, baselineArtifactSha256: H("wrong-raw") }),
    /raw.*sha|digest/i,
  );
  const changedBytes = Buffer.concat([value.baselineBytes, Buffer.from(" ")]);
  assert.throws(
    () => verifyV1BrownfieldApplicationDataCutover({ ...value, baselineBytes: changedBytes }),
    /raw.*sha|digest|canonical/i,
  );
  const canonicalBaseline = canonicalJson(value.baseline);
  const duplicateBaselineBytes = Buffer.from(
    `{"schema":${JSON.stringify(value.baseline.schema)},${canonicalBaseline.slice(1)}\n`,
  );
  const duplicateBaselineSha256 = crypto.createHash("sha256").update(duplicateBaselineBytes).digest("hex");
  const duplicateBaseline = structuredClone(value);
  duplicateBaseline.baselineBytes = duplicateBaselineBytes;
  duplicateBaseline.baselineArtifactSha256 = duplicateBaselineSha256;
  duplicateBaseline.contract.baselineBinding.rawArtifactSha256 = duplicateBaselineSha256;
  duplicateBaseline.contract.documentId = "0".repeat(64);
  duplicateBaseline.contract = sealApplicationDataCutoverContract(duplicateBaseline.contract);
  assert.throws(
    () => verifyV1BrownfieldApplicationDataCutover(duplicateBaseline),
    /baseline.*canonical|duplicate.*key|canonical.*wire/i,
  );
  const stale = structuredClone(value.baseline);
  stale.baselineId = H("stale-baseline-id");
  const staleBytes = Buffer.from(`${canonicalJson(stale)}\n`);
  assert.throws(
    () => verifyV1BrownfieldApplicationDataCutover({
      contract: value.contract,
      baselineBytes: staleBytes,
      baselineArtifactSha256: crypto.createHash("sha256").update(staleBytes).digest("hex"),
    }),
    /baselineId|stale|mismatch|raw artifact/i,
  );
});

test("AD04 source-set acceptance is imported exactly and cannot be caller-redeclared", () => {
  const value = mutateContract((contract) => {
    contract.baselineBinding.sourceObservationSetSha256 = H("caller-source-set");
  });
  assert.throws(() => verifyV1BrownfieldApplicationDataCutover(value), /source.*set|observation/i);
  const count = mutateContract((contract) => {
    contract.baselineBinding.sourcePathCount += 1;
  });
  assert.throws(() => verifyV1BrownfieldApplicationDataCutover(count), /source.*set|source.*path|count/i);
});

test("AD05 the exact full parent, its baseline identity/content, and every descendant bind are mandatory", () => {
  for (const [mutator, pattern] of [
    [(contract) => { contract.applicationDataParent.sourcePath = APPLICATION_DATA_QUEUE; }, /source path|parent/i],
    [(contract) => { contract.applicationDataParent.baselineParentContentSha256 = H("child-only"); }, /content/i],
    [(contract) => { contract.applicationDataParent.coveredBindSources = [APPLICATION_DATA_QUEUE]; }, /covered bind|full parent|bind set/i],
    [(contract) => { contract.applicationDataParent.excludedPaths = [APPLICATION_DATA_QUEUE]; }, /schema|excluded|no exclusions/i],
  ]) {
    const value = mutateContract(mutator);
    assert.throws(() => verifyV1BrownfieldApplicationDataCutover(value), pattern);
  }
  const baseline = baselineFixture();
  baseline.bindMounts[0].contentSha256 = null;
  assert.throws(
    () => deriveApplicationDataProjection(sealLivePreservationBaseline(baseline)),
    /full parent.*content|content.*parent|parent\/descendant bind/i,
  );
});

test("AD06 missing, extra, foreign, or anchor-unmapped RW writers are rejected", () => {
  const missing = mutateContract((contract) => {
    contract.writerInventory.writers = contract.writerInventory.writers.slice(1);
    contract.writerInventory.writerSetSha256 = sha256Canonical(contract.writerInventory.writers);
    contract.baselineBinding.writerSetSha256 = contract.writerInventory.writerSetSha256;
  });
  assert.throws(() => verifyV1BrownfieldApplicationDataCutover(missing), /writer.*exact|enumeration|missing/i);

  const extra = mutateContract((contract) => {
    const forged = structuredClone(contract.writerInventory.writers[0]);
    forged.containerName = "foreign-writer";
    forged.service = "foreign-writer";
    forged.writerId = H("foreign-writer");
    forged.quiesceOrder = contract.writerInventory.writers.length + 1;
    contract.writerInventory.writers.push(forged);
    contract.writerInventory.writerSetSha256 = sha256Canonical(contract.writerInventory.writers);
    contract.baselineBinding.writerSetSha256 = contract.writerInventory.writerSetSha256;
  });
  assert.throws(() => verifyV1BrownfieldApplicationDataCutover(extra), /writer.*exact|enumeration|extra|foreign/i);

  const unmappedBaseline = baselineFixture();
  const anchor = unmappedBaseline.logicalRecoveryAnchors[0];
  anchor.containerRefs = anchor.containerRefs.filter((name) => name !== "php-apache");
  unmappedBaseline.summary.applications = 2;
  unmappedBaseline.logicalRecoveryAnchors.push({
    id: "foreign-application",
    displayName: "Foreign application",
    mappingState: "MAPPED",
    sourceRootRefs: [],
    sourceBindRefs: [],
    containerRefs: ["php-apache"],
    databaseRefs: [],
    storageRefs: [],
    configRefs: [],
    secretMetadataRefs: [],
  });
  unmappedBaseline.logicalRecoveryAnchors.sort((left, right) => left.id.localeCompare(right.id));
  assert.throws(
    () => deriveApplicationDataProjection(sealLivePreservationBaseline(unmappedBaseline)),
    /unmapped|foreign|same application/i,
  );

  const aliasedBaseline = baselineFixture();
  const aliasPath = "/srv/foreign-state-alias";
  const aliasWriter = container("alias-writer", "alias-writer", aliasPath, "/state", false, 98);
  aliasedBaseline.containers.push(aliasWriter);
  aliasedBaseline.containers.sort((left, right) => left.name.localeCompare(right.name));
  aliasedBaseline.composeProjects[0].containerNames.push(aliasWriter.name);
  aliasedBaseline.composeProjects[0].containerNames.sort((left, right) => left.localeCompare(right));
  aliasedBaseline.bindMounts.push({
    source: aliasPath,
    canonicalPath: aliasPath,
    classification: "APPLICATION-DATA",
    lstatIdentity: structuredClone(aliasedBaseline.bindMounts.find(({ source }) => source === APPLICATION_DATA_PARENT).targetIdentity),
    targetIdentity: structuredClone(aliasedBaseline.bindMounts.find(({ source }) => source === APPLICATION_DATA_PARENT).targetIdentity),
    contentSha256: H("aliased-parent-content"),
    consumers: [{ containerName: aliasWriter.name, destination: "/state", readOnly: false }],
  });
  aliasedBaseline.bindMounts.sort((left, right) => left.source.localeCompare(right.source));
  aliasedBaseline.logicalRecoveryAnchors[0].containerRefs.push(aliasWriter.name);
  aliasedBaseline.logicalRecoveryAnchors[0].containerRefs.sort((left, right) => left.localeCompare(right));
  aliasedBaseline.logicalRecoveryAnchors[0].sourceBindRefs.push(aliasPath);
  aliasedBaseline.logicalRecoveryAnchors[0].sourceBindRefs.sort((left, right) => left.localeCompare(right));
  aliasedBaseline.summary.containers += 1;
  aliasedBaseline.summary.bindMounts += 1;
  assert.throws(
    () => deriveApplicationDataProjection(sealLivePreservationBaseline(aliasedBaseline)),
    /alias|same filesystem|foreign.*identity/i,
  );

  const queueAliasBaseline = baselineFixture();
  const queueAliasPath = "/srv/foreign-queue-alias";
  const queueAliasWriter = container("queue-alias-writer", "queue-alias-writer", queueAliasPath, "/queue", false, 97);
  const queueIdentity = structuredClone(
    queueAliasBaseline.bindMounts.find(({ source }) => source === APPLICATION_DATA_QUEUE).targetIdentity,
  );
  queueAliasBaseline.containers.push(queueAliasWriter);
  queueAliasBaseline.containers.sort((left, right) => left.name.localeCompare(right.name));
  queueAliasBaseline.composeProjects[0].containerNames.push(queueAliasWriter.name);
  queueAliasBaseline.composeProjects[0].containerNames.sort((left, right) => left.localeCompare(right));
  queueAliasBaseline.bindMounts.push({
    source: queueAliasPath,
    canonicalPath: queueAliasPath,
    classification: "APPLICATION-DATA",
    lstatIdentity: structuredClone(queueIdentity),
    targetIdentity: structuredClone(queueIdentity),
    contentSha256: H("aliased-queue-content"),
    consumers: [{ containerName: queueAliasWriter.name, destination: "/queue", readOnly: false }],
  });
  queueAliasBaseline.bindMounts.sort((left, right) => left.source.localeCompare(right.source));
  queueAliasBaseline.logicalRecoveryAnchors[0].containerRefs.push(queueAliasWriter.name);
  queueAliasBaseline.logicalRecoveryAnchors[0].containerRefs.sort((left, right) => left.localeCompare(right));
  queueAliasBaseline.logicalRecoveryAnchors[0].sourceBindRefs.push(queueAliasPath);
  queueAliasBaseline.logicalRecoveryAnchors[0].sourceBindRefs.sort((left, right) => left.localeCompare(right));
  queueAliasBaseline.summary.containers += 1;
  queueAliasBaseline.summary.bindMounts += 1;
  assert.throws(
    () => deriveApplicationDataProjection(sealLivePreservationBaseline(queueAliasBaseline)),
    /queue.*alias|covered.*alias|foreign.*identity/i,
  );

  const volumeAliasBaseline = baselineFixture();
  const coveredQueueIdentity = structuredClone(
    volumeAliasBaseline.bindMounts.find(({ source }) => source === APPLICATION_DATA_QUEUE).targetIdentity,
  );
  const controlCenter = volumeAliasBaseline.containers.find(({ name }) => name === "enterprise-control-center");
  controlCenter.mounts.push({
    kind: "volume",
    sourceRef: "application_data_alias",
    destination: "/alias-state",
    readOnly: false,
    propagation: "rprivate",
  });
  controlCenter.mounts.sort((left, right) => `${left.destination}\0${left.kind}\0${left.sourceRef}`
    .localeCompare(`${right.destination}\0${right.kind}\0${right.sourceRef}`));
  volumeAliasBaseline.volumes.push({
    name: "application_data_alias",
    nameClass: "NAMED",
    driver: "local",
    scope: "local",
    mountpoint: "/var/lib/docker/volumes/application_data_alias/_data",
    createdAt: "2026-08-11T00:00:00.000Z",
    optionsSha256: H("volume-alias-options"),
    labelsSha256: H("volume-alias-labels"),
    composeProject: "platform_infra_vps",
    composeVolume: "application_data_alias",
    fsIdentity: coveredQueueIdentity,
    observedBytes: 4096,
    attachments: [{ containerName: controlCenter.name, destination: "/alias-state", readOnly: false }],
    dangling: false,
  });
  volumeAliasBaseline.logicalRecoveryAnchors[0].storageRefs.push("application_data_alias");
  volumeAliasBaseline.summary.volumes = 1;
  volumeAliasBaseline.summary.attachedVolumes = 1;
  volumeAliasBaseline.summary.namedVolumes = 1;
  assert.throws(
    () => deriveApplicationDataProjection(sealLivePreservationBaseline(volumeAliasBaseline)),
    /volume.*alias|same filesystem|foreign.*storage/i,
  );
});

test("AD07 every parent RW writer is conservatively a potential queue writer", () => {
  const value = mutateContract((contract) => {
    contract.queue.potentialWriterIds = contract.queue.potentialWriterIds.slice(1);
    contract.queue.potentialWriterSetSha256 = sha256Canonical(contract.queue.potentialWriterIds);
  });
  assert.throws(() => verifyV1BrownfieldApplicationDataCutover(value), /queue.*writer|potential writer/i);

  const ancestor = baselineFixture();
  const ancestorPath = "/home/platform_infrastructure/platform-infrastructure/projects-portal";
  const ancestorContainer = container(
    "ancestor-writer",
    "ancestor-writer",
    ancestorPath,
    "/workspace",
    false,
    99,
  );
  ancestor.containers.push(ancestorContainer);
  ancestor.containers.sort((left, right) => left.name.localeCompare(right.name));
  ancestor.composeProjects[0].containerNames.push(ancestorContainer.name);
  ancestor.composeProjects[0].containerNames.sort((left, right) => left.localeCompare(right));
  ancestor.bindMounts.push({
    source: ancestorPath,
    canonicalPath: ancestorPath,
    classification: "APPLICATION-DATA",
    lstatIdentity: identity(99),
    targetIdentity: identity(99),
    contentSha256: H("ancestor-content"),
    consumers: [{ containerName: ancestorContainer.name, destination: "/workspace", readOnly: false }],
  });
  ancestor.bindMounts.sort((left, right) => left.source.localeCompare(right.source));
  ancestor.logicalRecoveryAnchors[0].containerRefs.push(ancestorContainer.name);
  ancestor.logicalRecoveryAnchors[0].containerRefs.sort((left, right) => left.localeCompare(right));
  ancestor.logicalRecoveryAnchors[0].sourceBindRefs.push(ancestorPath);
  ancestor.logicalRecoveryAnchors[0].sourceBindRefs.sort((left, right) => left.localeCompare(right));
  ancestor.summary.containers += 1;
  ancestor.summary.bindMounts += 1;
  const ancestorProjection = deriveApplicationDataProjection(sealLivePreservationBaseline(ancestor));
  const mappedAncestor = ancestorProjection.writers.find(({ containerName }) => containerName === "ancestor-writer");
  assert.equal(mappedAncestor?.scope, "ANCESTOR");
  assert.equal(ancestorProjection.potentialQueueWriterIds.includes(mappedAncestor.writerId), true);

  const rootAncestor = baselineFixture();
  const rootWriter = container("root-writer", "root-writer", "/", "/host", false, 100);
  rootAncestor.containers.push(rootWriter);
  rootAncestor.containers.sort((left, right) => left.name.localeCompare(right.name));
  rootAncestor.composeProjects[0].containerNames.push(rootWriter.name);
  rootAncestor.composeProjects[0].containerNames.sort((left, right) => left.localeCompare(right));
  rootAncestor.bindMounts.push({
    source: "/",
    canonicalPath: "/",
    classification: "APPLICATION-DATA",
    lstatIdentity: identity(100),
    targetIdentity: identity(100),
    contentSha256: H("root-ancestor-content"),
    consumers: [{ containerName: rootWriter.name, destination: "/host", readOnly: false }],
  });
  rootAncestor.bindMounts.sort((left, right) => left.source.localeCompare(right.source));
  rootAncestor.logicalRecoveryAnchors[0].containerRefs.push(rootWriter.name);
  rootAncestor.logicalRecoveryAnchors[0].containerRefs.sort((left, right) => left.localeCompare(right));
  rootAncestor.logicalRecoveryAnchors[0].sourceBindRefs.push("/");
  rootAncestor.logicalRecoveryAnchors[0].sourceBindRefs.sort((left, right) => left.localeCompare(right));
  rootAncestor.summary.containers += 1;
  rootAncestor.summary.bindMounts += 1;
  const sealedRootAncestor = sealLivePreservationBaseline(rootAncestor);
  const rootProjection = deriveApplicationDataProjection(sealedRootAncestor);
  const mappedRoot = rootProjection.writers.find(({ containerName }) => containerName === "root-writer");
  assert.equal(mappedRoot?.scope, "ANCESTOR");
  assert.equal(rootProjection.potentialQueueWriterIds.includes(mappedRoot.writerId), true);
  const rootValue = fixture(sealedRootAncestor);
  const rootResult = verifyV1BrownfieldApplicationDataCutover(rootValue);
  assert.equal(rootResult.status, "STOP");
  assert.equal(rootValue.contract.writerLifecycle.resumeWriterIds.includes(mappedRoot.writerId), true);
});

test("AD08 no-relocation pre/post-attach metadata, ACL, xattr, content, combined-tree, and artifact digests bind exactly", () => {
  for (const field of ["metadataTreeSha256", "aclTreeSha256", "xattrTreeSha256", "contentTreeSha256"]) {
    const value = mutateContract((contract) => {
      contract.preservationEvidence.postAttachSnapshot[field] = H(`changed:${field}`);
    });
    assert.throws(() => verifyV1BrownfieldApplicationDataCutover(value), /snapshot|digest|tree|match/i, field);
  }
  const forgedCombined = mutateContract((contract) => {
    contract.preservationEvidence.postAttachSnapshot.combinedTreeSha256 = H("forged-combined");
  });
  assert.throws(() => verifyV1BrownfieldApplicationDataCutover(forgedCombined), /combined|snapshot|digest/i);
  const unreadable = mutateContract((contract) => {
    contract.preservationEvidence.postAttachSnapshot.unreadableEntryCount = 1;
  });
  assert.throws(() => verifyV1BrownfieldApplicationDataCutover(unreadable), /schema|unreadable|complete/i);
});

test("AD09 cutover order is exact no-relocation quiesce/snapshot/verify/attach/post-verify/resume, with no executor", () => {
  assert.deepEqual(CUTOVER_PLAN.map(({ phase }) => phase), [
    "QUIESCE",
    "SNAPSHOT",
    "VERIFY",
    "ATTACH",
    "POST-VERIFY",
    "RESUME",
  ]);
  const swapped = mutateContract((contract) => {
    [contract.cutoverPlan.steps[1], contract.cutoverPlan.steps[2]] = [
      contract.cutoverPlan.steps[2],
      contract.cutoverPlan.steps[1],
    ];
  });
  assert.throws(() => verifyV1BrownfieldApplicationDataCutover(swapped), /cutover|step|order|plan/i);
  const executable = mutateContract((contract) => {
    contract.cutoverPlan.executorAvailable = true;
  });
  assert.throws(() => verifyV1BrownfieldApplicationDataCutover(executable), /schema|executor|authorized/i);

  for (const [field, value] of [
    ["copyPerformed", true],
    ["relocationPerformed", true],
    ["destinationPath", "/srv/replacement-state"],
    ["sameFilesystemObjectRequired", false],
  ]) {
    const claim = mutateContract((contract) => { contract.preservationEvidence[field] = value; });
    assert.throws(() => verifyV1BrownfieldApplicationDataCutover(claim), /copy|relocat|destination|same filesystem|schema/i, field);
  }
});

test("AD10 runtime identity raw bytes and exact legacy-parent attachment bridge are mandatory", () => {
  const substituted = fixture();
  substituted.runtimeIdentityBytes = Buffer.concat([substituted.runtimeIdentityBytes, Buffer.from(" ")]);
  assert.throws(() => verifyV1BrownfieldApplicationDataCutover(substituted), /runtime.*raw|sha|digest/i);

  const duplicateRuntime = fixture();
  const canonicalRuntime = canonicalJson(duplicateRuntime.runtimeIdentity);
  duplicateRuntime.runtimeIdentityBytes = Buffer.from(
    `{"evidenceClass":"LIVE-READ-ONLY","synthetic":false,${canonicalRuntime.slice(1)}\n`,
  );
  duplicateRuntime.runtimeIdentityArtifactSha256 = crypto.createHash("sha256")
    .update(duplicateRuntime.runtimeIdentityBytes)
    .digest("hex");
  duplicateRuntime.contract.runtimeBinding.rawArtifactSha256 = duplicateRuntime.runtimeIdentityArtifactSha256;
  duplicateRuntime.contract.documentId = "0".repeat(64);
  duplicateRuntime.contract = sealApplicationDataCutoverContract(duplicateRuntime.contract);
  assert.throws(
    () => verifyV1BrownfieldApplicationDataCutover(duplicateRuntime),
    /runtime identity.*canonical|duplicate.*key|canonical.*wire/i,
  );

  const binding = mutateContract((contract) => {
    contract.runtimeBinding.consumerSetSha256 = H("substituted-consumer-set");
  });
  assert.throws(() => verifyV1BrownfieldApplicationDataCutover(binding), /runtime|consumer|attachment|binding/i);

  for (const [mutator, pattern] of [
    [(runtime) => { runtime.productionBoundary.applicationDataParent.finalAttachments[0].sourcePath = "/srv/relocated-state"; }, /runtime|attachment|canonical|legacy|source/i],
    [(runtime) => { runtime.productionBoundary.applicationDataParent.finalAttachments[1].readOnly = false; }, /runtime|attachment|project-router|owner identity/i],
  ]) {
    const value = fixture();
    mutator(value.runtimeIdentity);
    value.runtimeIdentity.documentId = "0".repeat(64);
    value.runtimeIdentity = sealRuntimeIdentityDocument(value.runtimeIdentity);
    value.runtimeIdentityBytes = Buffer.from(`${canonicalJson(value.runtimeIdentity)}\n`);
    value.runtimeIdentityArtifactSha256 = crypto.createHash("sha256").update(value.runtimeIdentityBytes).digest("hex");
    value.contract.runtimeBinding.rawArtifactSha256 = value.runtimeIdentityArtifactSha256;
    value.contract.runtimeBinding.documentId = value.runtimeIdentity.documentId;
    value.contract.documentId = "0".repeat(64);
    value.contract = sealApplicationDataCutoverContract(value.contract);
    assert.throws(() => verifyV1BrownfieldApplicationDataCutover(value), pattern);
  }
});

test("AD11 frozen runtime queue replacement conflict is explicit PRESERVE+STOP and cannot be hidden", () => {
  const value = fixture();
  const result = verifyV1BrownfieldApplicationDataCutover(value);
  assert.equal(result.runtimeCompatibilityStatus, "MISMATCH-STOP");
  assert.equal(result.queueConflictStatus, "PRESERVE+STOP");
  assert.equal(result.currentContractsConverged, false);

  const hidden = mutateContract((contract) => {
    contract.runtimeBinding.queueConflict.status = "RESOLVED";
  });
  assert.throws(() => verifyV1BrownfieldApplicationDataCutover(hidden), /queue|conflict|schema|preserve/i);
});

test("AD12 every quiesced writer has exactly one unchanged resume disposition", () => {
  for (const mutator of [
    (lifecycle) => { lifecycle.finalDispositions.pop(); },
    (lifecycle) => { lifecycle.finalDispositions.push(structuredClone(lifecycle.finalDispositions[0])); },
    (lifecycle) => { lifecycle.finalDispositions[0].finalDisposition = "DROP-WRITER"; },
    (lifecycle) => { lifecycle.resumeWriterIds.pop(); },
    (lifecycle) => { lifecycle.quiesceContainerNames.pop(); },
    (lifecycle) => { lifecycle.quiesceContainerNames.push(lifecycle.quiesceContainerNames[0]); },
    (lifecycle) => {
      [lifecycle.resumeContainerNames[0], lifecycle.resumeContainerNames[1]] = [
        lifecycle.resumeContainerNames[1],
        lifecycle.resumeContainerNames[0],
      ];
    },
  ]) {
    const value = mutateContract((contract) => mutator(contract.writerLifecycle));
    assert.throws(
      () => verifyV1BrownfieldApplicationDataCutover(value),
      /writer|disposition|resume|schema|duplicate|omitted/i,
    );
  }

  const multiBindBaseline = baselineFixture();
  const controlCenter = multiBindBaseline.containers.find(
    ({ name }) => name === "enterprise-control-center",
  );
  const queueBind = multiBindBaseline.bindMounts.find(
    ({ source }) => source === APPLICATION_DATA_QUEUE,
  );
  controlCenter.mounts.push({
    kind: "bind",
    sourceRef: APPLICATION_DATA_QUEUE,
    destination: "/var/www/project-state/backup-jobs",
    readOnly: false,
    propagation: "rprivate",
  });
  controlCenter.mounts.sort((left, right) => `${left.destination}\0${left.kind}\0${left.sourceRef}`
    .localeCompare(`${right.destination}\0${right.kind}\0${right.sourceRef}`));
  queueBind.consumers.push({
    containerName: controlCenter.name,
    destination: "/var/www/project-state/backup-jobs",
    readOnly: false,
  });
  queueBind.consumers.sort((left, right) => `${left.containerName}\0${left.destination}`
    .localeCompare(`${right.containerName}\0${right.destination}`));
  const multiBind = fixture(sealLivePreservationBaseline(multiBindBaseline));
  const controlCenterWriters = multiBind.projection.writers.filter(
    ({ containerName }) => containerName === controlCenter.name,
  );
  assert.equal(controlCenterWriters.length, 2);
  assert.equal(
    multiBind.contract.writerLifecycle.quiesceContainerNames.filter(
      (containerName) => containerName === controlCenter.name,
    ).length,
    1,
  );
  assert.deepEqual(
    multiBind.contract.writerLifecycle.quiesceContainerNames,
    multiBind.contract.writerLifecycle.resumeContainerNames,
  );
  assert.equal(verifyV1BrownfieldApplicationDataCutover(multiBind).status, "STOP");
});

test("AD13 no local mutation, deployment, rollback, Docker, network, signing, or actions can be authorized", () => {
  for (const field of [
    "deploymentAuthority",
    "executionAuthorized",
    "mutationAuthority",
    "localMutationAuthority",
    "executorAvailable",
    "dockerExecutor",
    "networkAuthority",
    "signingAuthority",
    "stdoutAuthority",
    "rollbackAuthorized",
  ]) {
    const value = mutateContract((contract) => { contract.safety[field] = true; });
    assert.throws(() => verifyV1BrownfieldApplicationDataCutover(value), /schema|authority|authorized|safety|executor/i, field);
  }
  const nativeLauncherBypass = mutateContract((contract) => {
    contract.safety.trustedNativeLauncherRequired = false;
  });
  assert.throws(
    () => verifyV1BrownfieldApplicationDataCutover(nativeLauncherBypass),
    /schema|authority|authorized|safety|launcher/i,
  );
  const action = mutateContract((contract) => { contract.safety.actions = ["docker compose up"]; });
  assert.throws(() => verifyV1BrownfieldApplicationDataCutover(action), /schema|actions|safety/i);
});

test("AD14 caller objects are snapshotted before validation", () => {
  const value = fixture();
  let reads = 0;
  Object.defineProperty(value.contract.writerInventory, "complete", {
    enumerable: true,
    get() {
      reads += 1;
      return reads === 1;
    },
  });
  const result = verifyV1BrownfieldApplicationDataCutover(value);
  assert.equal(result.status, "STOP");
  assert.equal(reads, 1);
});

test("AD15 CLI reads three bounded regular single-link artifacts and exits 78 after structural verification", () => {
  const value = fixture();
  const directory = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "v1-app-data-cutover-")),
  );
  try {
    const contractPath = path.join(directory, "contract.json");
    const baselinePath = path.join(directory, "baseline.json");
    const runtimePath = path.join(directory, "runtime-identity.json");
    const canonicalContract = canonicalJson(value.contract);
    fs.writeFileSync(contractPath, `${canonicalContract}\n`, { mode: 0o400 });
    fs.writeFileSync(baselinePath, value.baselineBytes, { mode: 0o400 });
    fs.writeFileSync(runtimePath, value.runtimeIdentityBytes, { mode: 0o400 });
    const invoke = (candidateContractPath = contractPath, candidateRuntimePath = runtimePath) => spawnSync(process.execPath, [
      SCRIPT,
      "verify",
      "--contract",
      candidateContractPath,
      "--baseline",
      baselinePath,
      "--baseline-sha256",
      value.baselineArtifactSha256,
      "--runtime-identity",
      candidateRuntimePath,
      "--runtime-identity-sha256",
      value.runtimeIdentityArtifactSha256,
    ], { encoding: "utf8" });
    const result = invoke();
    assert.equal(result.status, 78, result.stderr);
    assert.notEqual(result.stdout.trim(), "", result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.status, "STOP");
    assert.equal(output.authorizationStatus, "LOCAL-NOT-AUTHORIZED");
    assert.equal(output.stdoutAuthority, false);
    assert.equal(output.trustedNativeLauncherRequired, true);
    assert.deepEqual(output.actions, []);

    const duplicateKeyPath = path.join(directory, "contract-duplicate-identical.json");
    fs.writeFileSync(
      duplicateKeyPath,
      `{"schema":${JSON.stringify(value.contract.schema)},${canonicalContract.slice(1)}\n`,
      { mode: 0o400 },
    );
    const nonCanonicalOrderPath = path.join(directory, "contract-noncanonical-order.json");
    const nonCanonicalOrder = JSON.stringify(value.contract);
    assert.notEqual(nonCanonicalOrder, canonicalContract);
    fs.writeFileSync(nonCanonicalOrderPath, `${nonCanonicalOrder}\n`, { mode: 0o400 });
    const extraLfPath = path.join(directory, "contract-extra-lf.json");
    fs.writeFileSync(extraLfPath, `${canonicalContract}\n\n`, { mode: 0o400 });
    for (const rejectedContractPath of [duplicateKeyPath, nonCanonicalOrderPath, extraLfPath]) {
      const canonicalRejected = invoke(rejectedContractPath);
      assert.equal(canonicalRejected.status, 78);
      assert.equal(canonicalRejected.stdout, "");
      assert.match(canonicalRejected.stderr, /contract input.*canonical.*(?:json|wire)/i);
    }

    const symlink = path.join(directory, "contract-link.json");
    fs.symlinkSync(contractPath, symlink);
    const rejected = invoke(symlink);
    assert.equal(rejected.status, 78);
    assert.match(rejected.stderr, /regular|single-link|unavailable|symlink/i);

    const runtimeSymlink = path.join(directory, "runtime-link.json");
    fs.symlinkSync(runtimePath, runtimeSymlink);
    const runtimeRejected = invoke(contractPath, runtimeSymlink);
    assert.equal(runtimeRejected.status, 78);
    assert.match(runtimeRejected.stderr, /runtime identity.*(?:canonical|regular|single-link|unavailable|symlink)/i);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("AD16 exact canonical validators are imported and frozen dependency bytes are pinned", () => {
  const source = fs.readFileSync(SCRIPT, "utf8");
  assert.match(source, /validateLivePreservationBaseline[\s\S]*from "\.\/live-preservation-baseline\.mjs"/);
  assert.match(source, /derivePersistentSourceSet[\s\S]*from "\.\/v1-predeploy-backup-receipt\.mjs"/);
  assert.match(source, /verifyV1BrownfieldRuntimeIdentity[\s\S]*from "\.\/v1-brownfield-runtime-identity\.mjs"/);
  assert.equal(
    crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "scripts", "live-preservation-baseline.mjs"))).digest("hex"),
    "b9e6abc8f12922bdb88a74c380383fe63ed20e13ba4d7cc6225cfd26c2ccc980",
  );
  assert.equal(
    crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "scripts", "v1-predeploy-backup-receipt.mjs"))).digest("hex"),
    "1b9d15690f6cf39028861de7021df57b08608ff42dc9afb3b09bd318566f6df5",
  );
  assert.equal(
    crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "scripts", "v1-brownfield-runtime-identity.mjs"))).digest("hex"),
    "238e0e25d1acf47cc4accb5d7e0338e9149b78a1ebeb7fd067539726d7602c8e",
  );
  assert.deepEqual(RUNTIME_SERVICES.map(({ service }) => service), [
    "docker-action-activation-sidecar",
    "docker-action-broker",
    "backup-scheduler",
    "control-center",
  ]);
  assert.deepEqual(RUNTIME_VOLUMES.map(({ logicalName }) => logicalName), [
    "backup_scheduler_jobs",
    "backup_scheduler_logs",
    "docker_action_activation_cas",
    "docker_action_broker_socket",
    "docker_action_broker_state",
  ]);
  assert.equal(QUEUE_OWNERSHIP[0].target, "/var/www/project-state/backup-jobs");
  assert.equal(PROTECTED_RESOURCE_MAP.volumes.includes("backup_scheduler_jobs"), true);
  assert.equal(CURRENT_CONTRACTS.every(({ status }) => status === "MISMATCH-STOP"), true);
});
