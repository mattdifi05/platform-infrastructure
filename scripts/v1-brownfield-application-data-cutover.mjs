#!/usr/bin/env node
/**
 * Verify-only bridge from the complete brownfield preservation baseline to a
 * proposed first cutover of the whole projects-portal APPLICATION-DATA parent.
 *
 * This module parses and validates caller-supplied evidence. It never inspects
 * the live host, quiesces a process, copies or switches data, invokes Docker,
 * signs evidence, authorizes rollback, or returns executable actions.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

import {
  validateLivePreservationBaseline,
} from "./live-preservation-baseline.mjs";
import {
  derivePersistentSourceSet,
} from "./v1-predeploy-backup-receipt.mjs";
import {
  verifyV1BrownfieldRuntimeIdentity,
} from "./v1-brownfield-runtime-identity.mjs";

export const APPLICATION_DATA_CUTOVER_SCHEMA =
  "platform.v1-brownfield-application-data-cutover/v1";
export const APPLICATION_DATA_PARENT =
  "/home/platform_infrastructure/platform-infrastructure/projects-portal/state";
export const APPLICATION_DATA_QUEUE = `${APPLICATION_DATA_PARENT}/backup-jobs`;

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(path.join(root, "vendor", "json-schema", "package.json"));
const Ajv2020 = require("ajv/dist/2020");
const addFormats = require("ajv-formats");
const contractSchema = JSON.parse(fs.readFileSync(
  path.join(root, "governance", "schemas", "v1-brownfield-application-data-cutover.schema.json"),
  "utf8",
));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validateContractSchema = ajv.compile(contractSchema);

const SHA256 = /^[a-f0-9]{64}$/;
const MAX_CONTRACT_BYTES = 4 * 1024 * 1024;
const MAX_BASELINE_BYTES = 32 * 1024 * 1024;
const SNAPSHOT_FIELDS = Object.freeze([
  "metadataTreeSha256",
  "aclTreeSha256",
  "xattrTreeSha256",
  "contentTreeSha256",
]);

export const CUTOVER_PLAN = deepFreeze([
  {
    order: 1,
    phase: "QUIESCE",
    requires: [],
    scopePath: APPLICATION_DATA_PARENT,
    mode: "QUIESCE-EXACT-BASELINE-RW-WRITER-SET",
    executor: "EXTERNAL-ROOT-CONSUMER-REQUIRED",
    authorized: false,
    completed: false,
  },
  {
    order: 2,
    phase: "SNAPSHOT",
    requires: ["QUIESCE"],
    scopePath: APPLICATION_DATA_PARENT,
    mode: "SNAPSHOT-EXACT-LEGACY-PARENT-NO-COPY",
    executor: "EXTERNAL-ROOT-CONSUMER-REQUIRED",
    authorized: false,
    completed: false,
  },
  {
    order: 3,
    phase: "VERIFY",
    requires: ["QUIESCE", "SNAPSHOT"],
    scopePath: APPLICATION_DATA_PARENT,
    mode: "VERIFY-PRE-ATTACH-METADATA-ACL-XATTR-CONTENT-TREES",
    executor: "EXTERNAL-ROOT-CONSUMER-REQUIRED",
    authorized: false,
    completed: false,
  },
  {
    order: 4,
    phase: "ATTACH",
    requires: ["QUIESCE", "SNAPSHOT", "VERIFY"],
    scopePath: APPLICATION_DATA_PARENT,
    mode: "ATTACH-EXACT-LEGACY-PARENT-NO-RELOCATION",
    executor: "EXTERNAL-ROOT-CONSUMER-REQUIRED",
    authorized: false,
    completed: false,
  },
  {
    order: 5,
    phase: "POST-VERIFY",
    requires: ["ATTACH", "QUIESCE", "SNAPSHOT", "VERIFY"],
    scopePath: APPLICATION_DATA_PARENT,
    mode: "POST-VERIFY-SAME-IDENTITY-AND-TREES",
    executor: "EXTERNAL-ROOT-CONSUMER-REQUIRED",
    authorized: false,
    completed: false,
  },
  {
    order: 6,
    phase: "RESUME",
    requires: ["ATTACH", "POST-VERIFY", "QUIESCE", "SNAPSHOT", "VERIFY"],
    scopePath: APPLICATION_DATA_PARENT,
    mode: "RESUME-UNCHANGED-LEGACY-WRITERS",
    executor: "EXTERNAL-ROOT-CONSUMER-REQUIRED",
    authorized: false,
    completed: false,
  },
]);

const SAFETY_BOUNDARY = deepFreeze({
  unknownResources: "PRESERVE+STOP",
  preserveApplications: true,
  preserveDatabases: true,
  preservePersistentStorage: true,
  deploymentAuthority: false,
  executionAuthorized: false,
  mutationAuthority: false,
  localMutationAuthority: false,
  executorAvailable: false,
  dockerExecutor: false,
  networkAuthority: false,
  signingAuthority: false,
  stdoutAuthority: false,
  trustedNativeLauncherRequired: true,
  rollbackAuthorized: false,
  actions: [],
});

function invalid(message) {
  throw new Error(message);
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function snapshotJson(value, label) {
  try {
    return structuredClone(value);
  } catch (error) {
    invalid(`${label} cannot be snapshotted: ${String(error?.message ?? error)}`);
  }
}

export function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) invalid("Canonical JSON numbers must be safe integers.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    invalid("Canonical JSON accepts only plain JSON values.");
  }
  const keys = Object.keys(value).sort();
  if (keys.some((key) => value[key] === undefined)) {
    invalid("Canonical JSON cannot contain undefined values.");
  }
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

export function sha256Canonical(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function sameJson(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) invalid(`${label} must be one lowercase SHA-256.`);
  return value;
}

function isAtOrBelow(parentPath, candidatePath) {
  const relative = path.posix.relative(parentPath, candidatePath);
  return relative === ""
    || (relative !== ".." && !relative.startsWith("../") && !path.posix.isAbsolute(relative));
}

function pathOverlaps(left, right) {
  return isAtOrBelow(left, right) || isAtOrBelow(right, left);
}

function sameFilesystemObject(left, right) {
  return left?.type === right?.type
    && left?.device === right?.device
    && left?.inode === right?.inode;
}

function applicationIdsForWriter(baseline, binding, containerName) {
  return baseline.logicalRecoveryAnchors
    .filter((anchor) => anchor.sourceBindRefs.includes(binding.source)
      && anchor.containerRefs.includes(containerName))
    .map(({ id }) => id)
    .sort((left, right) => left.localeCompare(right));
}

function writerSortKey(writer) {
  return `${writer.containerName}\0${writer.sourcePath}\0${writer.destination}`;
}

export function deriveApplicationDataProjection(inputBaseline) {
  const baseline = snapshotJson(inputBaseline, "Application-data baseline");
  try {
    validateLivePreservationBaseline(baseline, { requireComplete: true });
  } catch (error) {
    invalid(`Canonical complete deny-only baseline rejected: ${String(error?.message ?? error)}`);
  }
  if (baseline.complete !== true
      || baseline.status !== "COMPLETE-PRESERVATION-BASELINE"
      || baseline.gateAdmissible !== false
      || baseline.mutationAuthority !== false
      || baseline.effect !== "DENY-ONLY"
      || baseline.deficiencies.length !== 0) {
    invalid("Application-data projection requires one complete deny-only baseline with no mutation authority.");
  }

  // This import is the canonical persistent-source accept-set. Do not mirror it here.
  const sourceSet = derivePersistentSourceSet(baseline);
  const coveredBinds = baseline.bindMounts.filter((binding) => (
    isAtOrBelow(APPLICATION_DATA_PARENT, binding.source)
    || isAtOrBelow(APPLICATION_DATA_PARENT, binding.canonicalPath)
  ));
  if (coveredBinds.length === 0) invalid("Baseline has no APPLICATION-DATA parent binding.");
  for (const binding of coveredBinds) {
    if (!isAtOrBelow(APPLICATION_DATA_PARENT, binding.source)
        || !isAtOrBelow(APPLICATION_DATA_PARENT, binding.canonicalPath)
        || binding.source !== binding.canonicalPath) {
      invalid("APPLICATION-DATA bind alias escapes or silently relocates the exact parent.");
    }
    if (binding.classification !== "APPLICATION-DATA") {
      invalid("Every bind at or below the exact parent must retain APPLICATION-DATA classification.");
    }
    if (!binding.lstatIdentity || !binding.targetIdentity || !SHA256.test(String(binding.contentSha256 ?? ""))) {
      invalid("Every APPLICATION-DATA parent/descendant bind requires identity and content evidence.");
    }
  }
  coveredBinds.sort((left, right) => left.source.localeCompare(right.source));
  const parentBindings = coveredBinds.filter(({ source, canonicalPath }) => (
    source === APPLICATION_DATA_PARENT && canonicalPath === APPLICATION_DATA_PARENT
  ));
  if (parentBindings.length !== 1) {
    invalid("Exactly one full parent APPLICATION-DATA binding is required; child-only preservation is forbidden.");
  }
  const queueBindings = coveredBinds.filter(({ source, canonicalPath }) => (
    source === APPLICATION_DATA_QUEUE && canonicalPath === APPLICATION_DATA_QUEUE
  ));
  if (queueBindings.length !== 1) {
    invalid("The backup-jobs queue must be explicitly observed inside the preserved full parent.");
  }

  const parent = parentBindings[0];
  const coveredFilesystemObjects = coveredBinds.flatMap((binding) => (
    [binding.lstatIdentity, binding.targetIdentity]
  ));
  const aliasesCoveredFilesystemObject = (identity) => (
    coveredFilesystemObjects.some((covered) => sameFilesystemObject(identity, covered))
  );
  const foreignVolumeAlias = baseline.volumes.find((volume) => (
    volume.attachments.some(({ readOnly }) => readOnly === false)
    && ((typeof volume.mountpoint === "string"
      && pathOverlaps(APPLICATION_DATA_PARENT, volume.mountpoint))
      || aliasesCoveredFilesystemObject(volume.fsIdentity))
  ));
  if (foreignVolumeAlias) {
    invalid(`RW volume ${foreignVolumeAlias.name} is a foreign storage alias of the exact APPLICATION-DATA parent; preserve and STOP.`);
  }
  const foreignIdentityAlias = baseline.bindMounts.find((binding) => (
    !pathOverlaps(APPLICATION_DATA_PARENT, binding.source)
    && !pathOverlaps(APPLICATION_DATA_PARENT, binding.canonicalPath)
    && binding.consumers.some(({ readOnly }) => readOnly === false)
    && [binding.lstatIdentity, binding.targetIdentity]
      .some((identity) => aliasesCoveredFilesystemObject(identity))
  ));
  if (foreignIdentityAlias) {
    invalid(`RW bind ${foreignIdentityAlias.source} is a foreign filesystem-identity alias of a covered APPLICATION-DATA parent/descendant object; preserve and STOP.`);
  }

  const writerBindings = baseline.bindMounts.filter((binding) => (
    pathOverlaps(APPLICATION_DATA_PARENT, binding.source)
    || pathOverlaps(APPLICATION_DATA_PARENT, binding.canonicalPath)
  ));
  for (const binding of writerBindings) {
    if (binding.source !== binding.canonicalPath
        || !pathOverlaps(APPLICATION_DATA_PARENT, binding.source)
        || !pathOverlaps(APPLICATION_DATA_PARENT, binding.canonicalPath)) {
      invalid("A bind writer alias overlaps the APPLICATION-DATA parent ambiguously; preserve and STOP.");
    }
  }
  const containers = new Map(baseline.containers.map((entry) => [entry.name, entry]));
  const rawWriters = [];
  for (const binding of writerBindings) {
    for (const consumer of binding.consumers.filter(({ readOnly }) => readOnly === false)) {
      const observed = containers.get(consumer.containerName);
      if (!observed
          || (observed.project !== null
            && (typeof observed.project !== "string" || observed.project.length === 0))
          || typeof observed.service !== "string" || observed.service.length === 0) {
        invalid(`RW writer ${String(consumer.containerName)} is foreign or lacks a baseline project/service mapping.`);
      }
      const applicationIds = applicationIdsForWriter(baseline, binding, observed.name);
      if (applicationIds.length === 0) {
        invalid(`RW writer ${observed.name} is foreign or unmapped from the same logical recovery application as its bind.`);
      }
      const writer = {
        containerName: observed.name,
        project: observed.project,
        service: observed.service,
        sourcePath: binding.source,
        canonicalPath: binding.canonicalPath,
        destination: consumer.destination,
        scope: binding.source === APPLICATION_DATA_PARENT
          ? "PARENT"
          : isAtOrBelow(APPLICATION_DATA_PARENT, binding.source) ? "DESCENDANT" : "ANCESTOR",
        access: "RW",
        applicationIds,
      };
      writer.writerId = sha256Canonical(writer);
      rawWriters.push(writer);
    }
  }
  rawWriters.sort((left, right) => writerSortKey(left).localeCompare(writerSortKey(right)));
  if (rawWriters.length === 0) invalid("The complete baseline enumerates no APPLICATION-DATA RW writer.");
  const seenWriters = new Set();
  const writers = rawWriters.map((writer, index) => {
    if (seenWriters.has(writer.writerId)) invalid("Baseline contains a duplicate APPLICATION-DATA writer mapping.");
    seenWriters.add(writer.writerId);
    return {
      writerId: writer.writerId,
      containerName: writer.containerName,
      project: writer.project,
      service: writer.service,
      sourcePath: writer.sourcePath,
      canonicalPath: writer.canonicalPath,
      destination: writer.destination,
      scope: writer.scope,
      access: writer.access,
      applicationIds: writer.applicationIds,
      quiesceOrder: index + 1,
      quiesceRequired: true,
      mapped: true,
    };
  });
  const writerSetSha256 = sha256Canonical(writers);
  const potentialQueueWriterIds = writers.map(({ writerId }) => writerId);
  const applicationDataBindSetSha256 = sha256Canonical(coveredBinds);
  return deepFreeze({
    schema: "platform.v1-brownfield-application-data-projection/v1",
    sourceSet,
    coveredBindSources: coveredBinds.map(({ source }) => source),
    applicationDataBindSetSha256,
    parentTargetIdentitySha256: sha256Canonical(parent.targetIdentity),
    parentContentSha256: parent.contentSha256,
    writers,
    writerSetSha256,
    potentialQueueWriterIds,
    potentialQueueWriterSetSha256: sha256Canonical(potentialQueueWriterIds),
  });
}

function contractPayload(contract) {
  const payload = snapshotJson(contract, "Application-data cutover contract");
  delete payload.documentId;
  return payload;
}

export function sealApplicationDataCutoverContract(inputContract) {
  const contract = snapshotJson(inputContract, "Application-data cutover contract");
  contract.documentId = sha256Canonical(contractPayload(contract));
  return contract;
}

function validateDocumentIdentity(contract) {
  if (!validateContractSchema(contract)) {
    invalid(`Application-data cutover schema rejected: ${ajv.errorsText(validateContractSchema.errors, { separator: "; " })}`);
  }
  exactSha256(contract.documentId, "Application-data cutover documentId");
  if (contract.documentId !== sha256Canonical(contractPayload(contract))) {
    invalid("Application-data cutover documentId does not match its exact closed payload.");
  }
  if (contract.schema !== APPLICATION_DATA_CUTOVER_SCHEMA
      || contract.scope !== "platform-infrastructure"
      || contract.verifyOnly !== true) {
    invalid("Application-data cutover document identity or verify-only boundary is invalid.");
  }
  if (contract.status === "EXTERNAL-PENDING") {
    if (contract.evidenceClass !== "EXTERNAL-PENDING-TEMPLATE" || contract.synthetic !== false) {
      invalid("Pending application-data input must remain the exact external-pending template.");
    }
    return true;
  }
  if (contract.status !== "BASELINE-BOUND-NOT-AUTHORIZED"
      || !["SYNTHETIC-TEST", "LIVE-READ-ONLY"].includes(contract.evidenceClass)
      || contract.synthetic !== (contract.evidenceClass === "SYNTHETIC-TEST")) {
    invalid("Baseline-bound application-data evidence class/status is invalid.");
  }
  return false;
}

function validateStaticBoundary(contract) {
  const parent = contract.applicationDataParent;
  if (parent.classification !== "APPLICATION-DATA"
      || parent.sourcePath !== APPLICATION_DATA_PARENT
      || parent.canonicalPath !== APPLICATION_DATA_PARENT
      || parent.preservationScope !== "FULL-PARENT-RECURSIVE-INCLUSIVE"
      || !Array.isArray(parent.excludedPaths)
      || parent.excludedPaths.length !== 0
      || parent.relocationAllowed !== false) {
    invalid("Application-data full parent preservation scope or source path is widened.");
  }
  const inventory = contract.writerInventory;
  if (inventory.derivation !== "ALL-RW-BIND-CONSUMERS-OVERLAPPING-EXACT-PARENT"
      || !Array.isArray(inventory.foreignWriters) || inventory.foreignWriters.length !== 0
      || !Array.isArray(inventory.unmappedWriters) || inventory.unmappedWriters.length !== 0
      || inventory.foreignWriterDisposition !== "PRESERVE+STOP"
      || inventory.unmappedWriterDisposition !== "PRESERVE+STOP") {
    invalid("Foreign or unmapped writer handling must preserve and STOP.");
  }
  if (contract.queue.sourcePath !== APPLICATION_DATA_QUEUE
      || contract.queue.preservationMode !== "INCLUDED-IN-FULL-PARENT"
      || contract.queue.coveredByParent !== true
      || contract.queue.standaloneReplacementAllowed !== false) {
    invalid("Queue must remain included in the exact full APPLICATION-DATA parent.");
  }
  if (contract.preservationEvidence.scopeMode !== "FULL-PARENT-NO-EXCLUSIONS"
      || contract.preservationEvidence.digestContract
        !== "SHA-256-CANONICAL-RELATIVE-PATH-RECORDS+FILE-TYPE+MODE+UID+GID+NLINK+ACL+XATTR+LINK-TARGET+CONTENT"
      || contract.preservationEvidence.copyPerformed !== false
      || contract.preservationEvidence.relocationPerformed !== false
      || contract.preservationEvidence.destinationPath !== null
      || contract.preservationEvidence.sameFilesystemObjectRequired !== true) {
    invalid("Full-parent metadata/ACL/xattr/content digest coverage is invalid.");
  }
  if (!sameJson(contract.cutoverPlan, {
    mode: "PROPOSAL-ONLY",
    steps: CUTOVER_PLAN,
    executorAvailable: false,
    executionAuthorized: false,
  })) {
    invalid("Cutover proposal must remain exact no-relocation quiesce/snapshot/verify/attach/post-verify/resume order with no executor.");
  }
  if (!sameJson(contract.safety, SAFETY_BOUNDARY)) {
    invalid("Application-data safety boundary cannot authorize mutation, deployment, rollback, or actions.");
  }
}

function validatePending(contract) {
  const binding = contract.baselineBinding;
  for (const field of [
    "rawArtifactSha256",
    "baselineId",
    "complete",
    "sourceDeviceSetSha256",
    "sourceObservationSetSha256",
    "sourcePathSetSha256",
    "sourceObservationCount",
    "sourcePathCount",
    "applicationDataBindSetSha256",
    "writerSetSha256",
  ]) {
    if (binding[field] !== null) invalid(`EXTERNAL-PENDING baselineBinding.${field} must remain null.`);
  }
  const parent = contract.applicationDataParent;
  for (const field of [
    "baselineTargetIdentitySha256",
    "baselineParentContentSha256",
    "coveredBindSetSha256",
  ]) {
    if (parent[field] !== null) invalid(`EXTERNAL-PENDING applicationDataParent.${field} must remain null.`);
  }
  if (!Array.isArray(parent.coveredBindSources) || parent.coveredBindSources.length !== 0) {
    invalid("EXTERNAL-PENDING covered bind sources must remain empty.");
  }
  if (contract.writerInventory.complete !== false
      || contract.writerInventory.writers.length !== 0
      || contract.writerInventory.writerSetSha256 !== null) {
    invalid("EXTERNAL-PENDING writer inventory must remain incomplete and empty.");
  }
  const runtime = contract.runtimeBinding;
  for (const field of [
    "rawArtifactSha256",
    "documentId",
    "baselineBindingSha256",
    "consumerSetSha256",
    "applicationDataObservationArtifactSha256",
    "queueWriterEnumerationSha256",
  ]) {
    if (runtime[field] !== null) invalid(`EXTERNAL-PENDING runtimeBinding.${field} must remain null.`);
  }
  if (runtime.queueConflict !== null) invalid("EXTERNAL-PENDING runtime queue conflict must remain null.");
  if (contract.writerLifecycle.quiesceWriterIds.length !== 0
      || contract.writerLifecycle.quiesceContainerNames.length !== 0
      || contract.writerLifecycle.finalDispositions.length !== 0
      || contract.writerLifecycle.resumeWriterIds.length !== 0
      || contract.writerLifecycle.resumeContainerNames.length !== 0
      || contract.writerLifecycle.writerDispositionSetSha256 !== null) {
    invalid("EXTERNAL-PENDING writer lifecycle must remain empty.");
  }
  if (contract.queue.potentialWriterIds.length !== 0
      || contract.queue.potentialWriterSetSha256 !== null) {
    invalid("EXTERNAL-PENDING queue writer inventory must remain empty.");
  }
  if (contract.preservationEvidence.preAttachSnapshot !== null
      || contract.preservationEvidence.postAttachSnapshot !== null
      || contract.preservationEvidence.comparison !== null) {
    invalid("EXTERNAL-PENDING preservation snapshots must remain null.");
  }
}

function parseJsonArtifactBytes(input, label, maximumBytes) {
  if (!Buffer.isBuffer(input) && !(input instanceof Uint8Array)) {
    invalid(`${label} raw artifact must be supplied as exact bytes.`);
  }
  const bytes = Buffer.from(input);
  if (bytes.length < 2 || bytes.length > maximumBytes) {
    invalid(`${label} raw artifact must be bounded non-empty JSON bytes.`);
  }
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes) || text.charCodeAt(0) === 0xFEFF) {
    invalid(`${label} raw artifact must be exact BOM-free UTF-8 bytes.`);
  }
  let document;
  try {
    document = JSON.parse(text);
  } catch {
    invalid(`${label} raw artifact is not valid JSON.`);
  }
  let canonicalWire;
  try {
    canonicalWire = `${canonicalJson(document)}\n`;
  } catch (error) {
    invalid(`${label} raw artifact cannot be represented as canonical JSON: ${String(error?.message ?? error)}`);
  }
  if (text !== canonicalWire) {
    invalid(`${label} raw artifact must use exact canonical JSON wire encoding with one trailing LF.`);
  }
  return { bytes, document };
}

function validateBaselineBinding(contract, projection, baseline, rawSha256) {
  const expected = {
    schema: "platform.live-preservation-baseline/v1",
    rawArtifactSha256: rawSha256,
    baselineId: baseline.baselineId,
    complete: true,
    effect: "DENY-ONLY",
    sourceSetSchema: projection.sourceSet.schema,
    sourceDeviceSetSha256: projection.sourceSet.sourceDeviceSetSha256,
    sourceObservationSetSha256: projection.sourceSet.sourceObservationSetSha256,
    sourcePathSetSha256: projection.sourceSet.sourcePathSetSha256,
    sourceObservationCount: projection.sourceSet.sourceObservationCount,
    sourcePathCount: projection.sourceSet.sourcePathCount,
    applicationDataBindSetSha256: projection.applicationDataBindSetSha256,
    writerSetSha256: projection.writerSetSha256,
  };
  if (!sameJson(contract.baselineBinding, expected)) {
    invalid("Baseline raw/source-set/application-data/writer binding differs from the exact canonical derivation.");
  }
}

function validateProjectionBindings(contract, projection) {
  const expectedParent = {
    classification: "APPLICATION-DATA",
    sourcePath: APPLICATION_DATA_PARENT,
    canonicalPath: APPLICATION_DATA_PARENT,
    preservationScope: "FULL-PARENT-RECURSIVE-INCLUSIVE",
    excludedPaths: [],
    baselineTargetIdentitySha256: projection.parentTargetIdentitySha256,
    baselineParentContentSha256: projection.parentContentSha256,
    coveredBindSources: projection.coveredBindSources,
    coveredBindSetSha256: projection.applicationDataBindSetSha256,
    relocationAllowed: false,
  };
  if (!sameJson(contract.applicationDataParent, expectedParent)) {
    invalid("Application-data full parent/content/identity/covered bind set differs from the baseline.");
  }
  const expectedInventory = {
    derivation: "ALL-RW-BIND-CONSUMERS-OVERLAPPING-EXACT-PARENT",
    complete: true,
    writers: projection.writers,
    writerSetSha256: projection.writerSetSha256,
    foreignWriters: [],
    unmappedWriters: [],
    foreignWriterDisposition: "PRESERVE+STOP",
    unmappedWriterDisposition: "PRESERVE+STOP",
  };
  if (!sameJson(contract.writerInventory, expectedInventory)) {
    invalid("RW writer inventory is not the exact complete baseline-derived enumeration.");
  }
  const expectedQueue = {
    sourcePath: APPLICATION_DATA_QUEUE,
    preservationMode: "INCLUDED-IN-FULL-PARENT",
    coveredByParent: true,
    standaloneReplacementAllowed: false,
    potentialWriterIds: projection.potentialQueueWriterIds,
    potentialWriterSetSha256: projection.potentialQueueWriterSetSha256,
  };
  if (!sameJson(contract.queue, expectedQueue)) {
    invalid("Queue potential writer set is not the conservative exact full-parent RW writer set.");
  }
}

function expectedRuntimeBaselineBinding(projection, baseline, baselineArtifactSha256) {
  return sha256Canonical({
    baselineArtifactSha256,
    baselineId: baseline.baselineId,
    applicationDataBindSetSha256: projection.applicationDataBindSetSha256,
    parentTargetIdentitySha256: projection.parentTargetIdentitySha256,
  });
}

function expectedQueueConflict() {
  return {
    status: "PRESERVE+STOP",
    reason: "NAMED-VOLUME-WOULD-HIDE-LEGACY-QUEUE-CHILD",
    legacyQueuePath: APPLICATION_DATA_QUEUE,
    runtimeLogicalVolume: "backup_scheduler_jobs",
    runtimeMountTarget: "/var/www/project-state/backup-jobs",
    resolutionStatus: "EXTERNAL-PROVIDER-EVIDENCE-REQUIRED",
  };
}

function deriveWriterLifecycle(projection, runtimeIdentity) {
  const attachments = new Map(
    runtimeIdentity.productionBoundary.applicationDataParent.finalAttachments
      .map((entry) => [entry.containerName, entry]),
  );
  const writerIds = projection.writers.map(({ writerId }) => writerId);
  const containerNames = [...new Set(
    projection.writers.map(({ containerName }) => containerName),
  )].sort((left, right) => left.localeCompare(right));
  const finalDispositions = projection.writers.map((writer, index) => {
    const attachment = attachments.get(writer.containerName);
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
  return {
    quiesceWriterIds: writerIds,
    quiesceContainerNames: containerNames,
    finalDispositions,
    resumeWriterIds: writerIds,
    resumeContainerNames: containerNames,
    writerDispositionSetSha256: sha256Canonical(finalDispositions),
    omittedWriterDisposition: "PRESERVE+STOP",
    duplicateWriterDisposition: "PRESERVE+STOP",
  };
}

function validateRuntimeBridge(
  contract,
  runtimeIdentity,
  runtimeArtifactSha256,
  projection,
  baseline,
  baselineArtifactSha256,
) {
  let runtimeResult;
  try {
    runtimeResult = verifyV1BrownfieldRuntimeIdentity(runtimeIdentity);
  } catch (error) {
    invalid(`Canonical runtime identity rejected: ${String(error?.message ?? error)}`);
  }
  if (runtimeResult.status !== "LOCAL-NOT-AUTHORIZED"
      || runtimeResult.currentContractsConverged !== false
      || runtimeResult.applicationDataBaselineRecomputationStatus !== "EXTERNAL_ROOT_CONSUMER_REQUIRED"
      || runtimeResult.queueWriterEnumerationRecomputationStatus !== "EXTERNAL_ROOT_CONSUMER_REQUIRED"
      || runtimeResult.deploymentAuthority !== false
      || runtimeResult.executionAuthorized !== false
      || runtimeResult.mutationAuthority !== false
      || runtimeResult.dataRollbackAuthorized !== false
      || runtimeResult.actions.length !== 0) {
    invalid("Runtime identity widened its frozen local STOP/no-authority boundary.");
  }
  if (runtimeIdentity.synthetic !== contract.synthetic
      || runtimeIdentity.evidenceClass !== contract.evidenceClass) {
    invalid("Runtime identity evidence class differs from the exact baseline-bound contract class.");
  }
  const parent = runtimeIdentity.productionBoundary.applicationDataParent;
  const expectedBaselineBindingSha256 = expectedRuntimeBaselineBinding(
    projection,
    baseline,
    baselineArtifactSha256,
  );
  if (parent.sourcePath !== APPLICATION_DATA_PARENT
      || parent.canonicalPath !== APPLICATION_DATA_PARENT
      || parent.sourceIdentitySha256 !== projection.parentTargetIdentitySha256
      || parent.baselineBindingSha256 !== expectedBaselineBindingSha256
      || parent.consumerSetSha256 !== sha256Canonical(parent.finalAttachments)
      || !parent.finalAttachments.every(({ sourcePath }) => sourcePath === APPLICATION_DATA_PARENT)) {
    invalid("Runtime application-data parent/identity/baseline/consumer attachment binding is not exact.");
  }
  const queue = runtimeIdentity.productionBoundary.queueOwnership;
  const queueWouldHideLegacyChild = queue.logicalVolumeName === "backup_scheduler_jobs"
    && queue.owners.some(({ access, target }) => (
      access === "RW" && target === "/var/www/project-state/backup-jobs"
    ));
  if (!queueWouldHideLegacyChild) {
    invalid("Frozen runtime queue replacement conflict disappeared or was substituted; preserve and STOP.");
  }
  const expectedBinding = {
    schema: "platform.v1-brownfield-runtime-identity/v1",
    rawArtifactSha256: runtimeArtifactSha256,
    documentId: runtimeIdentity.documentId,
    baselineBindingSha256: parent.baselineBindingSha256,
    consumerSetSha256: parent.consumerSetSha256,
    applicationDataObservationArtifactSha256: parent.observationArtifactSha256,
    queueWriterEnumerationSha256: queue.writerEnumerationSha256,
    compatibilityStatus: "MISMATCH-STOP",
    currentContractsConverged: false,
    applicationDataBaselineRecomputationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    queueWriterEnumerationRecomputationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    queueConflict: expectedQueueConflict(),
  };
  if (!sameJson(contract.runtimeBinding, expectedBinding)) {
    invalid("Runtime raw/document/parent/queue binding or explicit conflict differs from the frozen runtime identity.");
  }
  const expectedLifecycle = deriveWriterLifecycle(projection, runtimeIdentity);
  if (!sameJson(contract.writerLifecycle, expectedLifecycle)) {
    invalid("Every quiesced RW writer requires exactly one unchanged legacy resume disposition; omission or duplication STOPs.");
  }
  return runtimeResult;
}

function snapshotPayload(snapshot) {
  const payload = snapshotJson(snapshot, "Preservation snapshot");
  payload.artifactSha256 = null;
  return payload;
}

function combinedTreePayload(snapshot) {
  return {
    scopePath: snapshot.scopePath,
    entryCount: snapshot.entryCount,
    rootIdentitySha256: snapshot.rootIdentitySha256,
    metadataTreeSha256: snapshot.metadataTreeSha256,
    aclTreeSha256: snapshot.aclTreeSha256,
    xattrTreeSha256: snapshot.xattrTreeSha256,
    contentTreeSha256: snapshot.contentTreeSha256,
    unreadableEntryCount: snapshot.unreadableEntryCount,
    volatileEntryCount: snapshot.volatileEntryCount,
  };
}

function validateSnapshot(snapshot, label, projection) {
  exactSha256(snapshot.artifactSha256, `${label} artifact SHA-256`);
  exactSha256(snapshot.rootIdentitySha256, `${label} root identity SHA-256`);
  for (const field of SNAPSHOT_FIELDS) exactSha256(snapshot[field], `${label} ${field}`);
  exactSha256(snapshot.combinedTreeSha256, `${label} combined tree SHA-256`);
  if (snapshot.scopePath !== APPLICATION_DATA_PARENT
      || snapshot.entryCount < 1
      || snapshot.unreadableEntryCount !== 0
      || snapshot.volatileEntryCount !== 0
      || snapshot.rootIdentitySha256 !== projection.parentTargetIdentitySha256) {
    invalid(`${label} does not prove a complete stable snapshot of the exact APPLICATION-DATA parent.`);
  }
  if (snapshot.combinedTreeSha256 !== sha256Canonical(combinedTreePayload(snapshot))) {
    invalid(`${label} combined metadata/ACL/xattr/content tree digest is stale or forged.`);
  }
  if (snapshot.artifactSha256 !== sha256Canonical(snapshotPayload(snapshot))) {
    invalid(`${label} artifact SHA-256 is stale or forged.`);
  }
}

function validatePreservationEvidence(contract, projection, baseline) {
  const { preAttachSnapshot, postAttachSnapshot, comparison } = contract.preservationEvidence;
  if (!preAttachSnapshot || !postAttachSnapshot || !comparison) {
    invalid("Baseline-bound preservation requires pre/post-attach snapshots of the same parent and exact comparison evidence.");
  }
  validateSnapshot(preAttachSnapshot, "Pre-attach snapshot", projection);
  validateSnapshot(postAttachSnapshot, "Post-attach snapshot", projection);
  const baselineCompleted = Date.parse(baseline.capturedAt.completedAt);
  const preAttachCaptured = Date.parse(preAttachSnapshot.capturedAt);
  const postAttachCaptured = Date.parse(postAttachSnapshot.capturedAt);
  if (!Number.isFinite(preAttachCaptured) || !Number.isFinite(postAttachCaptured)
      || preAttachCaptured < baselineCompleted || postAttachCaptured < preAttachCaptured) {
    invalid("Preservation snapshot ordering must follow the complete baseline and pre-before-post attach order.");
  }
  for (const field of ["entryCount", "rootIdentitySha256", ...SNAPSHOT_FIELDS, "combinedTreeSha256"]) {
    if (preAttachSnapshot[field] !== postAttachSnapshot[field]) {
      invalid(`Post-attach legacy parent differs from pre-attach snapshot field ${field}; STOP.`);
    }
  }
  const expectedComparison = {
    preAttachSnapshotSha256: preAttachSnapshot.artifactSha256,
    postAttachSnapshotSha256: postAttachSnapshot.artifactSha256,
    rootIdentityMatch: true,
    metadataMatch: true,
    aclMatch: true,
    xattrMatch: true,
    contentMatch: true,
    fullTreeMatch: true,
  };
  if (!sameJson(comparison, expectedComparison)) {
    invalid("No-relocation comparison must bind the same root identity and exact matching metadata, ACL, xattr, content, and full-tree snapshots.");
  }
}

function stopResult(contract, { pending, baselineComplete = false, structural = false } = {}) {
  return deepFreeze({
    schema: "platform.v1-brownfield-application-data-cutover-validation/v1",
    status: "STOP",
    authorizationStatus: "LOCAL-NOT-AUTHORIZED",
    externalStatus: pending ? "EXTERNAL-PENDING" : "EXTERNAL-ROOT-CONSUMER-REQUIRED",
    verifyOnly: true,
    referenceOnly: true,
    baselineComplete,
    fullParentPreservationVerified: false,
    fullParentPreservationEvidenceStatus: structural
      ? "CALLER-EVIDENCE-STRUCTURAL-ONLY"
      : "EXTERNAL-PENDING",
    writerEnumerationVerified: false,
    writerEnumerationEvidenceStatus: structural
      ? "CALLER-EVIDENCE-STRUCTURAL-ONLY"
      : "EXTERNAL-PENDING",
    metadataAclXattrContentVerified: false,
    metadataAclXattrContentEvidenceStatus: structural
      ? "CALLER-EVIDENCE-STRUCTURAL-ONLY"
      : "EXTERNAL-PENDING",
    runtimeIdentityVerified: false,
    runtimeIdentityEvidenceStatus: structural
      ? "CALLER-EVIDENCE-STRUCTURAL-ONLY"
      : "EXTERNAL-PENDING",
    currentContractsConverged: false,
    runtimeCompatibilityStatus: pending ? "EXTERNAL-PENDING" : "MISMATCH-STOP",
    queueConflictStatus: pending ? "EXTERNAL-PENDING" : "PRESERVE+STOP",
    applicationsResumeVerified: false,
    applicationsResumeVerificationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    liveQuiesceStatus: "NOT-RUN",
    liveSnapshotStatus: "NOT-RUN",
    liveAttachStatus: "NOT-RUN",
    livePostVerifyStatus: "NOT-RUN",
    liveResumeStatus: "NOT-RUN",
    executorStatus: "UNAVAILABLE",
    deploymentAuthority: false,
    executionAuthorized: false,
    mutationAuthority: false,
    localMutationAuthority: false,
    dockerExecutor: false,
    networkAuthority: false,
    signingAuthority: false,
    stdoutAuthority: false,
    trustedNativeLauncherRequired: true,
    rollbackAuthorized: false,
    actions: [],
    documentId: contract.documentId,
  });
}

export function verifyV1BrownfieldApplicationDataCutover(input) {
  const request = snapshotJson(input, "Application-data verification request");
  const contract = snapshotJson(request.contract, "Application-data cutover contract");
  const pending = validateDocumentIdentity(contract);
  validateStaticBoundary(contract);
  if (pending) {
    validatePending(contract);
    return stopResult(contract, { pending: true });
  }

  const baselineArtifact = parseJsonArtifactBytes(
    request.baselineBytes,
    "Baseline",
    MAX_BASELINE_BYTES,
  );
  const baseline = baselineArtifact.document;
  exactSha256(request.baselineArtifactSha256, "Caller baseline raw SHA-256");
  const baselineRawSha256 = crypto.createHash("sha256").update(baselineArtifact.bytes).digest("hex");
  if (request.baselineArtifactSha256 !== baselineRawSha256
      || contract.baselineBinding.rawArtifactSha256 !== baselineRawSha256) {
    invalid("Baseline raw artifact SHA-256 does not match the exact captured bytes.");
  }
  try {
    validateLivePreservationBaseline(baseline, { requireComplete: true });
  } catch (error) {
    invalid(`Canonical complete baseline rejected: ${String(error?.message ?? error)}`);
  }
  if (baseline.synthetic !== contract.synthetic
      || contract.evidenceClass !== (baseline.synthetic ? "SYNTHETIC-TEST" : "LIVE-READ-ONLY")) {
    invalid("Contract evidence class does not match the exact baseline evidence class.");
  }
  const projection = deriveApplicationDataProjection(baseline);
  validateBaselineBinding(contract, projection, baseline, baselineRawSha256);
  validateProjectionBindings(contract, projection);
  const runtimeArtifact = parseJsonArtifactBytes(
    request.runtimeIdentityBytes,
    "Runtime identity",
    MAX_CONTRACT_BYTES,
  );
  exactSha256(request.runtimeIdentityArtifactSha256, "Caller runtime identity raw SHA-256");
  const runtimeRawSha256 = crypto.createHash("sha256").update(runtimeArtifact.bytes).digest("hex");
  if (request.runtimeIdentityArtifactSha256 !== runtimeRawSha256
      || contract.runtimeBinding.rawArtifactSha256 !== runtimeRawSha256) {
    invalid("Runtime identity raw artifact SHA-256 does not match the exact captured bytes.");
  }
  validateRuntimeBridge(
    contract,
    runtimeArtifact.document,
    runtimeRawSha256,
    projection,
    baseline,
    baselineRawSha256,
  );
  validatePreservationEvidence(contract, projection, baseline);
  return stopResult(contract, { pending: false, baselineComplete: true, structural: true });
}

function readBoundedRegularFile(inputPath, label, maximumBytes) {
  const resolved = path.resolve(inputPath);
  try {
    if (inputPath !== resolved || fs.realpathSync.native(resolved) !== resolved) {
      invalid(`${label} path must be exact absolute canonical and non-symlinked.`);
    }
  } catch (error) {
    if (error instanceof Error && /path must be exact/.test(error.message)) throw error;
    invalid(`${label} canonical path is unavailable: ${String(error?.message ?? error)}`);
  }
  let descriptor;
  try {
    descriptor = fs.openSync(
      resolved,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    );
  } catch (error) {
    invalid(`${label} is unavailable as a no-follow regular file: ${String(error?.message ?? error)}`);
  }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n
        || before.size < 2n || before.size > BigInt(maximumBytes)) {
      invalid(`${label} must be one bounded regular single-link file.`);
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, null);
      if (count === 0) invalid(`${label} was truncated during its bounded read.`);
      offset += count;
    }
    const trailing = Buffer.alloc(1);
    if (fs.readSync(descriptor, trailing, 0, 1, null) !== 0) {
      invalid(`${label} grew beyond its bounded snapshot.`);
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    for (const field of ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]) {
      if (before[field] !== after[field]) invalid(`${label} identity changed during its bounded read.`);
    }
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
}

function parseArguments(argv) {
  const usage = "Usage: verify --contract FILE --baseline FILE --baseline-sha256 HEX --runtime-identity FILE --runtime-identity-sha256 HEX (verify-only)";
  if (argv[0] !== "verify") invalid(usage);
  const values = new Map();
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!["--contract", "--baseline", "--baseline-sha256", "--runtime-identity", "--runtime-identity-sha256"].includes(key)
        || typeof value !== "string" || value.startsWith("--") || values.has(key)) {
      invalid(usage);
    }
    values.set(key, value);
  }
  if (values.size !== 5 || argv.length !== 11) {
    invalid(usage);
  }
  return values;
}

function cli(argv) {
  const values = parseArguments(argv);
  const contractBytes = readBoundedRegularFile(values.get("--contract"), "Contract input", MAX_CONTRACT_BYTES);
  const baselineBytes = readBoundedRegularFile(values.get("--baseline"), "Baseline input", MAX_BASELINE_BYTES);
  const runtimeIdentityBytes = readBoundedRegularFile(
    values.get("--runtime-identity"),
    "Runtime identity input",
    MAX_CONTRACT_BYTES,
  );
  const contract = parseJsonArtifactBytes(
    contractBytes,
    "Contract input",
    MAX_CONTRACT_BYTES,
  ).document;
  return verifyV1BrownfieldApplicationDataCutover({
    contract,
    baselineBytes,
    baselineArtifactSha256: values.get("--baseline-sha256"),
    runtimeIdentityBytes,
    runtimeIdentityArtifactSha256: values.get("--runtime-identity-sha256"),
  });
}

const invoked = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invoked) {
  try {
    const result = cli(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
  }
  process.exitCode = 78;
}
