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
  CANONICAL_COMPOSE_FILE_ORDER,
  CANONICAL_COMPOSE_FILE_ORDERS,
  CURRENT_CONTRACTS,
  LOCAL_PRIVATE_CANONICAL_COMPOSE_FILE_ORDER,
  LOCAL_PRIVATE_PROTECTED_RESOURCE_MAP,
  PRODUCTION_PROJECT_NAME,
  PROTECTED_RESOURCE_MAP,
  PROTECTED_RESOURCE_MAPS,
  QUEUE_OWNERSHIP,
  RUNTIME_IDENTITY_SCHEMA,
  RUNTIME_SERVICES,
  RUNTIME_VOLUMES,
  STAGING_PROJECT_NAME,
  canonicalJson,
  sealRuntimeIdentityDocument,
  sha256Canonical,
  verifyV1BrownfieldRuntimeIdentity,
} from "./v1-brownfield-runtime-identity.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, "..");
const SCRIPT = path.join(scriptDir, "v1-brownfield-runtime-identity.mjs");
const TEMPLATE = path.join(root, "governance", "v1-brownfield-runtime-identity.json");
const SCHEMA = path.join(root, "governance", "schemas", "v1-brownfield-runtime-identity.schema.json");

const h = (seed) => crypto.createHash("sha256").update(`runtime-identity:${seed}`).digest("hex");

function labels(logicalName) {
  return {
    "com.docker.compose.project": PRODUCTION_PROJECT_NAME,
    "com.docker.compose.version": "2.99.0-synthetic",
    "com.docker.compose.volume": logicalName,
  };
}

function fillContainer(container, index) {
  const completed = {
    ...container,
    containerId: h(`container-id:${index}`),
    imageReference: `registry.example/platform/${container.service}@sha256:${h(`manifest:${index}`)}`,
    imageId: `sha256:${h(`image-id:${index}`)}`,
    configHash: h(`config:${index}`),
    mountsSha256: h(`mounts:${index}`),
    networkAttachmentsSha256: h(`container-networks:${index}`),
    inspectionArtifactSha256: h(`container-inspection:${index}`),
  };
  completed.containerCasSha256 = sha256Canonical(completed);
  return completed;
}

function fillVolume(volume, index) {
  const completed = {
    ...volume,
    driver: "local",
    scope: "local",
    options: {},
    labels: labels(volume.logicalName),
    createdAt: `2026-08-11T00:00:0${index}.000Z`,
    mountpoint: `/var/lib/docker/volumes/${volume.physicalName}/_data`,
    inspectionArtifactSha256: h(`volume-inspection:${index}`),
  };
  completed.volumeCasSha256 = sha256Canonical(completed);
  return completed;
}

function completeSyntheticDocument() {
  const document = JSON.parse(fs.readFileSync(TEMPLATE, "utf8"));
  document.synthetic = true;
  document.evidenceClass = "SYNTHETIC-TEST";
  document.status = "SYNTHETIC-COMPLETE-NOT-AUTHORIZED";
  document.stagingBoundary.sourceSetSha256 = h("staging-source-set");
  document.schedulerBoundary.contractArtifactSha256 = h("scheduler-contract");
  document.schedulerBoundary.identitySetSha256 = h("scheduler-identities");
  document.schedulerBoundary.queueMigrationSha256 = h("scheduler-queue");
  document.schedulerBoundary.applicationDataParentBindingSha256 = h("scheduler-parent-bind");

  const compose = document.productionBoundary.compose;
  compose.rawFullRenderBytesSha256 = h("raw-full-render-bytes");
  compose.fileOrderSha256 = sha256Canonical(compose.fileOrder);
  compose.profilesSha256 = sha256Canonical(compose.profiles);
  compose.environmentSha256 = h("environment-bytes");
  compose.projectNameSha256 = sha256Canonical(compose.projectName);
  compose.serviceSetSha256 = sha256Canonical(compose.serviceNames);
  compose.configSha256 = h("rendered-config");
  compose.networksSha256 = sha256Canonical(compose.networkNames);
  compose.attachmentsSha256 = h("all-network-attachments");
  compose.resourceMapSha256 = sha256Canonical(compose.resourceMap);
  compose.noHostedPolicyBytesSha256 = h("no-hosted-policy-bytes");

  document.productionBoundary.containers = document.productionBoundary.containers.map(fillContainer);
  document.productionBoundary.volumes = document.productionBoundary.volumes.map(fillVolume);
  document.productionBoundary.queueOwnership.observationArtifactSha256 = h("queue-observation");
  document.productionBoundary.queueOwnership.writerEnumerationSha256 = sha256Canonical({
    owners: document.productionBoundary.queueOwnership.owners,
    extraParentOrChildReadWriteWriters:
      document.productionBoundary.queueOwnership.extraParentOrChildReadWriteWriters,
  });
  document.productionBoundary.queueOwnership.completeParentAndChildWriterEnumeration = true;

  const parent = document.productionBoundary.applicationDataParent;
  parent.sourcePath = "/home/platform_infrastructure/platform-infrastructure/projects-portal/state";
  parent.canonicalPath = parent.sourcePath;
  parent.sourceIdentitySha256 = h("application-data-source-identity");
  parent.baselineBindingSha256 = h("application-data-baseline-binding");
  parent.consumerSetSha256 = h("application-data-consumer-set");
  parent.observationArtifactSha256 = h("application-data-observation");
  for (const attachment of parent.finalAttachments) attachment.sourcePath = parent.sourcePath;
  document.documentId = "0".repeat(64);
  return sealRuntimeIdentityDocument(document);
}

function mutateAndReseal(mutator) {
  const document = completeSyntheticDocument();
  mutator(document);
  document.documentId = "0".repeat(64);
  return sealRuntimeIdentityDocument(document);
}

test("RI01 canonical bridge freezes staging and final namespaces and exact resource identities", () => {
  assert.equal(RUNTIME_IDENTITY_SCHEMA, "platform.v1-brownfield-runtime-identity/v1");
  assert.equal(STAGING_PROJECT_NAME, "platform_infra_v1_control");
  assert.equal(PRODUCTION_PROJECT_NAME, "platform_infra_vps");
  assert.deepEqual(CANONICAL_COMPOSE_FILE_ORDER, [
    "compose.yaml",
    "compose.secrets.yaml",
    "compose.waf.yaml",
    "compose.vps.yaml",
    "compose.vps-waf.yaml",
    "compose.backup-scheduler.yaml",
    "compose.runtime.yaml",
    "compose.networks.yaml",
    "compose.runtime-isolation.yaml",
    "compose.runtime-identity.yaml",
  ]);
  assert.deepEqual(LOCAL_PRIVATE_CANONICAL_COMPOSE_FILE_ORDER, [
    "compose.yaml",
    "compose.secrets.yaml",
    "compose.waf.yaml",
    "compose.vps.yaml",
    "compose.vps-waf.yaml",
    "compose.backup-scheduler.yaml",
    "compose.runtime.yaml",
    "compose.networks.yaml",
    "compose.runtime-isolation.yaml",
    "compose.local-private.yaml",
    "compose.runtime-identity.yaml",
  ]);
  assert.deepEqual(CANONICAL_COMPOSE_FILE_ORDERS, {
    VPS: CANONICAL_COMPOSE_FILE_ORDER,
    LOCAL_PRIVATE: LOCAL_PRIVATE_CANONICAL_COMPOSE_FILE_ORDER,
  });
  assert.ok(Object.values(CANONICAL_COMPOSE_FILE_ORDERS)
    .every((fileOrder) => fileOrder.at(-1) === "compose.runtime-identity.yaml"));
  assert.deepEqual(PROTECTED_RESOURCE_MAPS, {
    VPS: PROTECTED_RESOURCE_MAP,
    LOCAL_PRIVATE: LOCAL_PRIVATE_PROTECTED_RESOURCE_MAP,
  });
  assert.deepEqual(
    RUNTIME_SERVICES.map(({ service, containerName }) => [service, containerName]),
    [
      ["docker-action-activation-sidecar", "enterprise-docker-action-activation-sidecar"],
      ["docker-action-broker", "enterprise-docker-action-broker"],
      ["backup-scheduler", "enterprise-backup-scheduler"],
      ["control-center", "enterprise-control-center"],
    ],
  );
  assert.deepEqual(RUNTIME_VOLUMES.map(({ logicalName, physicalName }) => [logicalName, physicalName]), [
    ["backup_scheduler_jobs", "platform_infra_vps_backup_scheduler_jobs"],
    ["backup_scheduler_logs", "platform_infra_vps_backup_scheduler_logs"],
    ["docker_action_activation_cas", "platform_infra_vps_docker_action_activation_cas"],
    ["docker_action_broker_socket", "platform_infra_vps_docker_action_broker_socket"],
    ["docker_action_broker_state", "platform_infra_vps_docker_action_broker_state"],
  ]);
});

test("RI02 governance template is explicit EXTERNAL-PENDING and validates only to STOP", () => {
  const document = JSON.parse(fs.readFileSync(TEMPLATE, "utf8"));
  const result = verifyV1BrownfieldRuntimeIdentity(document);

  assert.equal(document.schema, RUNTIME_IDENTITY_SCHEMA);
  assert.equal(document.synthetic, false);
  assert.equal(document.evidenceClass, "EXTERNAL-PENDING-TEMPLATE");
  assert.equal(document.status, "EXTERNAL-PENDING");
  assert.equal(result.status, "LOCAL-NOT-AUTHORIZED");
  assert.equal(result.externalStatus, "EXTERNAL-PENDING");
  assert.equal(result.observationBindingsComplete, false);
  assert.equal(result.currentContractsConverged, false);
  assert.equal(result.currentContractStatus, "MISMATCH-STOP");
  assert.deepEqual(result.actions, []);
  for (const field of [
    "deploymentAuthority",
    "executionAuthorized",
    "mutationAuthority",
    "localMutationAuthority",
    "executorAvailable",
    "dockerExecutor",
    "networkAuthority",
    "signingAuthority",
    "dataRollbackAuthorized",
  ]) assert.equal(result[field], false, field);

  assert.equal(document.productionBoundary.compose.rawFullRenderBytesSha256, null);
  assert.equal(document.productionBoundary.compose.environmentSha256, null);
  assert.ok(document.productionBoundary.containers.every(({ containerCasSha256 }) => containerCasSha256 === null));
  assert.ok(document.productionBoundary.volumes.every(({ volumeCasSha256 }) => volumeCasSha256 === null));
});

test("RI03 a fully bound synthetic bridge validates structurally but never grants authority", () => {
  const document = completeSyntheticDocument();
  const result = verifyV1BrownfieldRuntimeIdentity(document);

  assert.equal(result.status, "LOCAL-NOT-AUTHORIZED");
  assert.equal(result.externalStatus, "SYNTHETIC-ONLY");
  assert.equal(result.structuralBindingsValidated, true);
  assert.equal(result.syntheticBindingsComplete, true);
  assert.equal(result.observationBindingsComplete, false);
  assert.equal(result.externalEvidenceComplete, false);
  assert.equal(result.authoritativeEvidenceVerified, false);
  for (const field of [
    "rawFullRenderVerificationStatus",
    "runtimeIdentityInspectionStatus",
    "applicationDataBaselineRecomputationStatus",
    "queueWriterEnumerationRecomputationStatus",
  ]) assert.equal(result[field], "EXTERNAL_ROOT_CONSUMER_REQUIRED", field);
  assert.equal(result.currentContractsConverged, false);
  assert.equal(result.executionAuthorized, false);
  assert.equal(result.mutationAuthority, false);
  assert.equal(result.dataRollbackAuthorized, false);
  assert.deepEqual(result.actions, []);
  assert.ok(Object.isFrozen(result));
  assert.doesNotMatch(JSON.stringify(result), /"(?:executionAuthorized|mutationAuthority|dataRollbackAuthorized)":true/);
});

test("RI03a LOCAL_PRIVATE is a separately hashed canonical order with runtime identity last", () => {
  const document = mutateAndReseal((value) => {
    value.productionBoundary.compose.fileOrder = [...LOCAL_PRIVATE_CANONICAL_COMPOSE_FILE_ORDER];
    value.productionBoundary.compose.fileOrderSha256 = sha256Canonical(
      value.productionBoundary.compose.fileOrder,
    );
    value.productionBoundary.compose.resourceMap = structuredClone(
      LOCAL_PRIVATE_PROTECTED_RESOURCE_MAP,
    );
    value.productionBoundary.compose.resourceMapSha256 = sha256Canonical(
      value.productionBoundary.compose.resourceMap,
    );
  });
  const result = verifyV1BrownfieldRuntimeIdentity(document);

  assert.equal(result.structuralBindingsValidated, true);
  assert.equal(document.productionBoundary.compose.fileOrder.at(-2), "compose.local-private.yaml");
  assert.equal(document.productionBoundary.compose.fileOrder.at(-1), "compose.runtime-identity.yaml");
  assert.notEqual(
    document.productionBoundary.compose.fileOrderSha256,
    sha256Canonical(CANONICAL_COMPOSE_FILE_ORDER),
  );
});

test("RI04 staging namespace is permanently NON_EXECUTABLE and cannot masquerade as final", () => {
  for (const [mutate, pattern] of [
    [(value) => { value.stagingBoundary.projectName = PRODUCTION_PROJECT_NAME; }, /staging namespace/i],
    [(value) => { value.stagingBoundary.disposition = "EXECUTABLE"; }, /NON_EXECUTABLE/i],
    [(value) => { value.stagingBoundary.executionAuthorized = true; }, /NON_EXECUTABLE/i],
    [(value) => { value.stagingBoundary.serviceNames.push("control-center"); }, /staging service set/i],
    [(value) => { value.stagingBoundary.volumeNames.push("backup_scheduler_logs"); }, /staging volume set/i],
  ]) {
    assert.throws(() => verifyV1BrownfieldRuntimeIdentity(mutateAndReseal(mutate)), pattern);
  }
});

test("RI05 all four final container names, projects, networks, and CAS fields are closed", () => {
  for (const [mutate, pattern] of [
    [(value) => { value.productionBoundary.containers.pop(); }, /container identity set and order/i],
    [(value) => { value.productionBoundary.containers.push(structuredClone(value.productionBoundary.containers[0])); }, /container identity set and order/i],
    [(value) => { value.productionBoundary.containers[0].containerName = "candidate-sidecar"; }, /container identity/i],
    [(value) => { value.productionBoundary.containers[1].projectName = STAGING_PROJECT_NAME; }, /container identity/i],
    [(value) => { value.productionBoundary.containers[2].networkMode = "bridge"; }, /network mode/i],
    [(value) => { value.productionBoundary.containers[3].networkNames.pop(); }, /network attachment expectation/i],
    [(value) => { value.productionBoundary.containers[0].containerCasSha256 = h("forged"); }, /container CAS/i],
    [(value) => { value.productionBoundary.containers[1].imageReference = "platform/broker:latest"; }, /digest-pinned image/i],
    [(value) => { value.productionBoundary.containers[2].configHash = null; }, /config hash|all external observations.*complete/i],
  ]) assert.throws(() => verifyV1BrownfieldRuntimeIdentity(mutateAndReseal(mutate)), pattern);
});

test("RI06 exact five volumes bind driver, scope, options, labels, mountpoint and CAS", () => {
  for (const [mutate, pattern] of [
    [(value) => { value.productionBoundary.volumes.pop(); }, /volume identity set and order/i],
    [(value) => { value.productionBoundary.volumes.push(structuredClone(value.productionBoundary.volumes[0])); }, /volume identity set and order/i],
    [(value) => { value.productionBoundary.volumes[0].physicalName = "platform_infra_v1_control_backup_scheduler_jobs"; }, /volume identity/i],
    [(value) => { value.productionBoundary.volumes[1].driver = "local-persist"; }, /driver.*local/i],
    [(value) => { value.productionBoundary.volumes[2].scope = "global"; }, /scope.*local/i],
    [(value) => { value.productionBoundary.volumes[3].options = { device: "/" }; }, /options.*empty/i],
    [(value) => { value.productionBoundary.volumes[4].labels["com.docker.compose.project"] = STAGING_PROJECT_NAME; }, /volume labels/i],
    [(value) => { value.productionBoundary.volumes[0].labels.extra = "writer"; }, /labels.*closed schema|volume labels.*closed/i],
    [(value) => { value.productionBoundary.volumes[0].mountpoint = "/var/lib/docker/volumes/other/_data"; }, /mountpoint/i],
    [(value) => { value.productionBoundary.volumes[0].volumeCasSha256 = h("forged-volume-cas"); }, /volume CAS/i],
  ]) assert.throws(() => verifyV1BrownfieldRuntimeIdentity(mutateAndReseal(mutate)), pattern);
});

test("RI07 queue ownership is exactly control-center RW, scheduler RW, broker RO", () => {
  assert.deepEqual(QUEUE_OWNERSHIP.map(({ service, access }) => [service, access]), [
    ["control-center", "RW"],
    ["backup-scheduler", "RW"],
    ["docker-action-broker", "RO"],
  ]);
  for (const [mutate, pattern] of [
    [(value) => { value.productionBoundary.queueOwnership.owners.shift(); }, /queue owner (?:identity )?set and order/i],
    [(value) => { value.productionBoundary.queueOwnership.owners[2].access = "RW"; }, /queue owner identity/i],
    [(value) => { value.productionBoundary.queueOwnership.owners.push({ service: "rogue", containerName: "rogue", access: "RW", target: "/run/platform/backup-jobs/child" }); }, /queue owner (?:identity )?set and order/i],
    [(value) => { value.productionBoundary.queueOwnership.extraParentOrChildReadWriteWriters.push({ service: "rogue", containerName: "rogue", source: "backup_scheduler_jobs", target: "/var/www/project-state" }); }, /extra parent or child read-write writer/i],
    [(value) => { value.productionBoundary.queueOwnership.completeParentAndChildWriterEnumeration = false; }, /complete parent and child writer enumeration/i],
    [(value) => { value.productionBoundary.queueOwnership.writerEnumerationSha256 = h("forged-writer-set"); }, /writer enumeration SHA256/i],
  ]) assert.throws(() => verifyV1BrownfieldRuntimeIdentity(mutateAndReseal(mutate)), pattern);
});

test("RI08 first cutover preserves the exact full APPLICATION-DATA parent without relocation", () => {
  for (const [mutate, pattern] of [
    [(value) => { value.productionBoundary.applicationDataParent.sourcePath = "/srv/platform-infrastructure/projects-portal/state"; }, /canonical path.*source path|silent relocation/i],
    [(value) => { value.productionBoundary.applicationDataParent.canonicalPath = "/srv/platform-infrastructure/projects-portal/state"; }, /silent relocation/i],
    [(value) => { value.productionBoundary.applicationDataParent.classification = "CONFIG"; }, /APPLICATION-DATA/i],
    [(value) => { value.productionBoundary.applicationDataParent.preservedForFirstCutover = false; }, /preserved.*first cutover/i],
    [(value) => { value.productionBoundary.applicationDataParent.relocationAllowed = true; }, /relocation/i],
    [(value) => { value.productionBoundary.applicationDataParent.finalAttachments[0].sourcePath = "/srv/platform-infrastructure/projects-portal/state"; }, /exact observed parent/i],
    [(value) => { value.productionBoundary.applicationDataParent.finalAttachments[0].readOnly = true; }, /application-data attachment/i],
    [(value) => { value.productionBoundary.applicationDataParent.finalAttachments.push(structuredClone(value.productionBoundary.applicationDataParent.finalAttachments[0])); }, /application-data attachment set and order/i],
  ]) assert.throws(() => verifyV1BrownfieldRuntimeIdentity(mutateAndReseal(mutate)), pattern);
});

test("RI09 raw render, ordered files, profile, env, project, service, config, network, attachment and resource map hashes are exact", () => {
  for (const [mutate, pattern] of [
    [(value) => { [value.productionBoundary.compose.fileOrder[0], value.productionBoundary.compose.fileOrder[1]] = [value.productionBoundary.compose.fileOrder[1], value.productionBoundary.compose.fileOrder[0]]; }, /Compose file order/i],
    [(value) => { value.productionBoundary.compose.fileOrder.splice(-1, 0, "compose.local-private.yaml", "compose.local-private.yaml"); }, /Compose file order/i],
    [(value) => { value.productionBoundary.compose.profiles = []; }, /profile set/i],
    [(value) => { value.productionBoundary.compose.projectName = STAGING_PROJECT_NAME; }, /production project/i],
    [(value) => { value.productionBoundary.compose.serviceNames.pop(); }, /service set/i],
    [(value) => { value.productionBoundary.compose.networkNames.pop(); }, /network set/i],
    [(value) => { value.productionBoundary.compose.resourceMap.services.pop(); }, /protected resource map/i],
    [(value) => { value.productionBoundary.compose.resourceMap = structuredClone(LOCAL_PRIVATE_PROTECTED_RESOURCE_MAP); }, /protected resource map/i],
    [(value) => { value.productionBoundary.compose.rawFullRenderBytesSha256 = null; }, /raw full render bytes|all external observations.*complete/i],
    [(value) => { value.productionBoundary.compose.fileOrderSha256 = h("wrong-order"); }, /file order SHA256/i],
    [(value) => { value.productionBoundary.compose.profilesSha256 = h("wrong-profiles"); }, /profiles SHA256/i],
    [(value) => { value.productionBoundary.compose.projectNameSha256 = h("wrong-project"); }, /project name SHA256/i],
    [(value) => { value.productionBoundary.compose.serviceSetSha256 = h("wrong-services"); }, /service set SHA256/i],
    [(value) => { value.productionBoundary.compose.networksSha256 = h("wrong-networks"); }, /network set SHA256/i],
    [(value) => { value.productionBoundary.compose.resourceMapSha256 = h("wrong-resource-map"); }, /resource map SHA256/i],
  ]) assert.throws(() => verifyV1BrownfieldRuntimeIdentity(mutateAndReseal(mutate)), pattern);
});

test("RI10 the three current contracts are an exact mismatch/STOP set and cannot claim convergence", () => {
  const template = JSON.parse(fs.readFileSync(TEMPLATE, "utf8"));
  assert.deepEqual(template.currentContracts, CURRENT_CONTRACTS);
  assert.deepEqual(template.currentContracts.map(({ id, status }) => [id, status]), [
    ["v1-control-plane-staging", "MISMATCH-STOP"],
    ["scheduler-cutover", "MISMATCH-STOP"],
    ["production-runtime-no-hosted", "MISMATCH-STOP"],
  ]);
  for (const [mutate, pattern] of [
    [(value) => { value.currentContracts.pop(); }, /current contract set and order/i],
    [(value) => { value.currentContracts[0].status = "MATCH"; }, /current contract mismatch\/STOP/i],
    [(value) => { value.currentContracts[1].mismatches = []; }, /current contract mismatch\/STOP/i],
    [(value) => { value.currentContracts[2].mismatches[0] = "READY"; }, /current contract set and order|mismatch\/STOP/i],
  ]) assert.throws(() => verifyV1BrownfieldRuntimeIdentity(mutateAndReseal(mutate)), pattern);
});

test("RI11 document and nested objects are closed, sealed, and template observations are all-or-none", () => {
  const extra = completeSyntheticDocument();
  extra.executionAuthorized = true;
  extra.documentId = "0".repeat(64);
  assert.throws(() => sealRuntimeIdentityDocument(extra), /exact closed schema/i);

  const nestedExtra = mutateAndReseal((value) => {
    value.productionBoundary.compose.authority = true;
  });
  assert.throws(() => verifyV1BrownfieldRuntimeIdentity(nestedExtra), /exact closed schema/i);

  const partialTemplate = JSON.parse(fs.readFileSync(TEMPLATE, "utf8"));
  partialTemplate.productionBoundary.compose.environmentSha256 = h("partial");
  partialTemplate.documentId = "0".repeat(64);
  partialTemplate.documentId = sha256Canonical((({ documentId, ...payload }) => payload)(partialTemplate));
  assert.throws(() => verifyV1BrownfieldRuntimeIdentity(partialTemplate), /pending template.*null/i);

  const tampered = completeSyntheticDocument();
  tampered.productionBoundary.compose.configSha256 = h("tampered-after-seal");
  assert.throws(() => verifyV1BrownfieldRuntimeIdentity(tampered), /document ID/i);
});

test("RI12 JSON Schema mirrors the closed top-level and canonical constants", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA, "utf8"));
  const template = JSON.parse(fs.readFileSync(TEMPLATE, "utf8"));
  assert.equal(schema.$id, "https://platform.invalid/schemas/v1-brownfield-runtime-identity.schema.json");
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual([...schema.required].sort(), Object.keys(template).sort());
  assert.deepEqual(schema.properties.schema.const, RUNTIME_IDENTITY_SCHEMA);
  assert.deepEqual(
    schema.$defs.composeFileOrder.oneOf.map(({ prefixItems }) => prefixItems.map(({ const: value }) => value)),
    Object.values(CANONICAL_COMPOSE_FILE_ORDERS),
  );
  assert.deepEqual(
    schema.$defs.protectedResourceMap.properties.secrets.oneOf
      .map(({ prefixItems }) => prefixItems.map(({ const: value }) => value)),
    Object.values(PROTECTED_RESOURCE_MAPS).map(({ secrets }) => secrets),
  );
  assert.deepEqual(schema.$defs.currentContracts.prefixItems.map(({ properties }) => properties.id.const), CURRENT_CONTRACTS.map(({ id }) => id));
  assert.deepEqual(schema.$defs.runtimeContainers.prefixItems.map(({ properties }) => properties.service.const), RUNTIME_SERVICES.map(({ service }) => service));
  assert.deepEqual(schema.$defs.runtimeVolumes.prefixItems.map(({ properties }) => properties.logicalName.const), RUNTIME_VOLUMES.map(({ logicalName }) => logicalName));
  assert.ok(allObjectSchemasClosed(schema), "every object schema must deny additional properties");
});

test("RI13 strict Ajv accepts both contract modes and rejects closed-schema hostile variants", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA, "utf8"));
  const Ajv = Ajv2020.default ?? Ajv2020;
  const addFormats = addFormatsModule.default ?? addFormatsModule;
  const ajv = new Ajv({ allErrors: true, strict: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  const template = JSON.parse(fs.readFileSync(TEMPLATE, "utf8"));
  const synthetic = completeSyntheticDocument();
  const localPrivateSynthetic = mutateAndReseal((value) => {
    value.productionBoundary.compose.fileOrder = [...LOCAL_PRIVATE_CANONICAL_COMPOSE_FILE_ORDER];
    value.productionBoundary.compose.fileOrderSha256 = sha256Canonical(
      value.productionBoundary.compose.fileOrder,
    );
    value.productionBoundary.compose.resourceMap = structuredClone(
      LOCAL_PRIVATE_PROTECTED_RESOURCE_MAP,
    );
    value.productionBoundary.compose.resourceMapSha256 = sha256Canonical(
      value.productionBoundary.compose.resourceMap,
    );
  });
  assert.equal(validate(template), true, JSON.stringify(validate.errors));
  assert.equal(validate(synthetic), true, JSON.stringify(validate.errors));
  assert.equal(validate(localPrivateSynthetic), true, JSON.stringify(validate.errors));

  const observationPaths = nullLeafPaths(template);
  assert.equal(observationPaths.length, 99, "template observation inventory drifted");
  for (const observationPath of observationPaths) {
    const partialPending = structuredClone(template);
    setPath(partialPending, observationPath, structuredClone(getPath(synthetic, observationPath)));
    assert.equal(
      validate(partialPending),
      false,
      `strict schema accepted pending non-null observation ${observationPath.join(".")}`,
    );

    const partialSynthetic = structuredClone(synthetic);
    setPath(partialSynthetic, observationPath, null);
    assert.equal(
      validate(partialSynthetic),
      false,
      `strict schema accepted synthetic null observation ${observationPath.join(".")}`,
    );
  }

  for (const mutate of [
    (value) => { value.authority = true; },
    (value) => { value.stagingBoundary.projectName = PRODUCTION_PROJECT_NAME; },
    (value) => { value.productionBoundary.containers[0].service = "rogue"; },
    (value) => { value.productionBoundary.volumes.pop(); },
    (value) => { value.productionBoundary.volumes[0].driver = "local-persist"; },
    (value) => { value.productionBoundary.volumes[0].scope = "global"; },
    (value) => { value.productionBoundary.volumes[0].labels["com.docker.compose.volume"] = "backup_scheduler_logs"; },
    (value) => { value.productionBoundary.volumes[0].createdAt = "2026-02-31T00:00:00.000Z"; },
    (value) => { value.productionBoundary.volumes[0].mountpoint = "/var/lib/docker/volumes/other/_data"; },
    (value) => { value.productionBoundary.containers[0].imageReference = "registry.example/platform/sidecar:latest"; },
    (value) => { value.productionBoundary.containers[0].imageId = h("unprefixed-image-id"); },
    (value) => { value.productionBoundary.queueOwnership.extraParentOrChildReadWriteWriters.push({ rogue: true }); },
    (value) => { value.productionBoundary.queueOwnership.completeParentAndChildWriterEnumeration = false; },
    (value) => { value.productionBoundary.applicationDataParent.sourcePath = "projects-portal/state"; },
    (value) => { value.productionBoundary.applicationDataParent.canonicalPath = "/srv/platform-infrastructure/projects-portal/state"; },
    (value) => { value.productionBoundary.applicationDataParent.finalAttachments[0].sourcePath = "/srv/platform-infrastructure/projects-portal/state"; },
    (value) => { value.safety.actions.push("compose-up"); },
  ]) {
    const candidate = structuredClone(synthetic);
    mutate(candidate);
    assert.equal(validate(candidate), false, "strict schema accepted a hostile structural mismatch");
  }
});

test("RI13a strict Ajv enforces the same canonical timestamp grammar as the runtime", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA, "utf8"));
  const Ajv = Ajv2020.default ?? Ajv2020;
  const addFormats = addFormatsModule.default ?? addFormatsModule;
  const ajv = new Ajv({ allErrors: true, strict: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  for (const nonCanonical of [
    "2016-12-31T23:59:60.000Z",
    "+010000-01-01T00:00:00.000Z",
    "-000001-01-01T00:00:00.000Z",
  ]) {
    const candidate = completeSyntheticDocument();
    candidate.productionBoundary.volumes[0].createdAt = nonCanonical;
    assert.equal(validate(candidate), false, `strict schema accepted ${nonCanonical}`);
  }
});

test("RI13b runtime rejects timestamp forms excluded by the strict schema", () => {
  for (const nonCanonical of [
    "2016-12-31T23:59:60.000Z",
    "+010000-01-01T00:00:00.000Z",
    "-000001-01-01T00:00:00.000Z",
  ]) {
    const candidate = mutateAndReseal((value) => {
      const volume = value.productionBoundary.volumes[0];
      volume.createdAt = nonCanonical;
      volume.volumeCasSha256 = null;
      volume.volumeCasSha256 = sha256Canonical(volume);
    });
    assert.throws(
      () => verifyV1BrownfieldRuntimeIdentity(candidate),
      /canonical UTC timestamp/i,
    );
  }
});

test("RI13c strict Ajv and runtime accept only the same canonical volume mountpoints", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA, "utf8"));
  const Ajv = Ajv2020.default ?? Ajv2020;
  const addFormats = addFormatsModule.default ?? addFormatsModule;
  const ajv = new Ajv({ allErrors: true, strict: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);

  for (const nonCanonical of [
    "//volumes/platform_infra_vps_backup_scheduler_jobs/_data",
    "/var/lib/docker//volumes/platform_infra_vps_backup_scheduler_jobs/_data",
    "/var/lib/docker/./volumes/platform_infra_vps_backup_scheduler_jobs/_data",
    "/var/lib/docker/../docker/volumes/platform_infra_vps_backup_scheduler_jobs/_data",
    "/var/lib/docker\u0000/volumes/platform_infra_vps_backup_scheduler_jobs/_data",
  ]) {
    const schemaCandidate = completeSyntheticDocument();
    schemaCandidate.productionBoundary.volumes[0].mountpoint = nonCanonical;
    assert.equal(validate(schemaCandidate), false, `strict schema accepted ${JSON.stringify(nonCanonical)}`);

    const runtimeCandidate = mutateAndReseal((value) => {
      const volume = value.productionBoundary.volumes[0];
      volume.mountpoint = nonCanonical;
      volume.volumeCasSha256 = null;
      volume.volumeCasSha256 = sha256Canonical(volume);
    });
    assert.throws(
      () => verifyV1BrownfieldRuntimeIdentity(runtimeCandidate),
      /mountpoint/i,
    );
  }

  const rootRelativeDockerData = mutateAndReseal((value) => {
    const volume = value.productionBoundary.volumes[0];
    volume.mountpoint = "/volumes/platform_infra_vps_backup_scheduler_jobs/_data";
    volume.volumeCasSha256 = null;
    volume.volumeCasSha256 = sha256Canonical(volume);
  });
  assert.equal(validate(rootRelativeDockerData), true, JSON.stringify(validate.errors));
  assert.doesNotThrow(() => verifyV1BrownfieldRuntimeIdentity(rootRelativeDockerData));
});

test("RI14 current source files reproduce all three mismatch/STOP projections", () => {
  const stagingCompose = fs.readFileSync(path.join(root, "compose.v1-control-plane.yaml"), "utf8");
  const stagingPolicy = JSON.parse(fs.readFileSync(path.join(root, "governance", "v1-brownfield-control-plane.json"), "utf8"));
  const scheduler = fs.readFileSync(path.join(root, "scripts", "v1-brownfield-scheduler-cutover.mjs"), "utf8");
  const productionQueueOverlay = fs.readFileSync(path.join(root, "compose.backup-scheduler.yaml"), "utf8");
  const finalIsolationOverlay = fs.readFileSync(path.join(root, "compose.runtime-isolation.yaml"), "utf8");
  const noHosted = JSON.parse(fs.readFileSync(path.join(root, "config", "no-hosted-workloads.lock.json"), "utf8"));

  assert.match(stagingCompose, /^name: platform_infra_v1_control$/m);
  assert.equal(stagingPolicy.projectName, STAGING_PROJECT_NAME);
  assert.deepEqual(stagingPolicy.compose.projectScopedVolumes, [
    "backup_scheduler_jobs",
    "docker_action_activation_cas",
    "docker_action_broker_socket",
    "docker_action_broker_state",
  ]);
  assert.deepEqual(stagingPolicy.mutationServices, STAGING_SERVICE_NAMES_FOR_TEST());
  assert.match(scheduler, /Verify-only V1 brownfield scheduler cutover contract/);
  assert.doesNotMatch(scheduler, /from\s+["']node:child_process["']/);
  assert.doesNotMatch(serviceBlock(productionQueueOverlay, "control-center"), /backup_scheduler_jobs/);
  assert.doesNotMatch(serviceBlock(finalIsolationOverlay, "control-center"), /backup_scheduler_jobs/);
  assert.deepEqual(noHosted.protectedResourceNames, PROTECTED_RESOURCE_MAP);

  const result = verifyV1BrownfieldRuntimeIdentity(JSON.parse(fs.readFileSync(TEMPLATE, "utf8")));
  assert.equal(result.currentContractStatus, "MISMATCH-STOP");
  assert.equal(result.mismatches.length, 8);
  assert.equal(result.actions.length, 0);
});

test("RI15 implementation has no Docker, child process, network, signing, write, or apply boundary", () => {
  const source = fs.readFileSync(SCRIPT, "utf8");
  assert.doesNotMatch(source, /from\s+["']node:(?:child_process|net|http|https|tls|dgram|worker_threads)["']/);
  assert.doesNotMatch(source, /\b(?:exec|execFile|spawn|fork|system)Sync?\s*\(/);
  assert.doesNotMatch(source, /\bfetch\s*\(|docker\s+compose|\/var\/run\/docker\.sock/i);
  assert.doesNotMatch(source, /writeFile|appendFile|createWriteStream|mkdir|rename|unlink|rmSync/);
  assert.doesNotMatch(source, /createPrivateKey|generateKeyPair|\bsign\s*\(/);
  assert.doesNotMatch(source, /function\s+apply|command\s*===?\s*["']apply["']/i);
  assert.match(source, /O_NOFOLLOW/);
  assert.match(source, /O_NONBLOCK/);
  assert.match(source, /fstatSync/);
  assert.match(source, /readSync/);
});

test("RI16 CLI is verify-only and exits 78 for both pending and structurally complete synthetic input", (t) => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "v1-runtime-identity-"));
  t.after(() => fs.rmSync(temporaryRoot, { recursive: true, force: true }));
  for (const [name, document, externalStatus] of [
    ["template", JSON.parse(fs.readFileSync(TEMPLATE, "utf8")), "EXTERNAL-PENDING"],
    ["synthetic", completeSyntheticDocument(), "SYNTHETIC-ONLY"],
  ]) {
    const input = path.join(temporaryRoot, `${name}.json`);
    fs.writeFileSync(input, `${JSON.stringify(document)}\n`, { mode: 0o600 });
    const run = spawnSync(process.execPath, [SCRIPT, "verify", input], {
      cwd: root,
      encoding: "utf8",
      env: { HOME: temporaryRoot, LANG: "C", LC_ALL: "C", PATH: process.env.PATH },
    });
    assert.equal(run.status, 78, `${name}: ${run.stderr}`);
    const output = JSON.parse(run.stdout);
    assert.equal(output.status, "LOCAL-NOT-AUTHORIZED");
    assert.equal(output.externalStatus, externalStatus);
    assert.deepEqual(output.actions, []);
  }

  const before = fs.readdirSync(temporaryRoot).sort();
  const apply = spawnSync(process.execPath, [SCRIPT, "apply", TEMPLATE], {
    cwd: root,
    encoding: "utf8",
    env: { HOME: temporaryRoot, LANG: "C", LC_ALL: "C", PATH: process.env.PATH },
  });
  assert.notEqual(apply.status, 0);
  assert.match(apply.stderr, /verify-only|usage/i);
  assert.deepEqual(fs.readdirSync(temporaryRoot).sort(), before);

  const canonicalInput = path.join(temporaryRoot, "template.json");
  const symbolicInput = path.join(temporaryRoot, "template-symlink.json");
  fs.symlinkSync(canonicalInput, symbolicInput);
  const symbolic = spawnSync(process.execPath, [SCRIPT, "verify", symbolicInput], {
    cwd: root,
    encoding: "utf8",
    env: { HOME: temporaryRoot, LANG: "C", LC_ALL: "C", PATH: process.env.PATH },
  });
  assert.equal(symbolic.status, 78);
  assert.equal(symbolic.stdout, "");
  assert.match(symbolic.stderr, /unavailable|symbolic|regular|identity/i);

  const hardLinkedInput = path.join(temporaryRoot, "template-hardlink.json");
  fs.linkSync(canonicalInput, hardLinkedInput);
  const hardLinked = spawnSync(process.execPath, [SCRIPT, "verify", hardLinkedInput], {
    cwd: root,
    encoding: "utf8",
    env: { HOME: temporaryRoot, LANG: "C", LC_ALL: "C", PATH: process.env.PATH },
  });
  assert.equal(hardLinked.status, 78);
  assert.equal(hardLinked.stdout, "");
  assert.match(hardLinked.stderr, /link|regular|identity/i);
});

test("RI17 canonical JSON and document sealing are deterministic and reject unsafe numbers", () => {
  assert.equal(canonicalJson({ b: 2, a: [true, null, "x"] }), '{"a":[true,null,"x"],"b":2}');
  assert.equal(sha256Canonical({ b: 2, a: 1 }), sha256Canonical({ a: 1, b: 2 }));
  assert.throws(() => canonicalJson({ value: 1.5 }), /safe integer/i);
  const first = completeSyntheticDocument();
  const second = sealRuntimeIdentityDocument(structuredClone(first));
  assert.equal(first.documentId, second.documentId);
});

function allObjectSchemasClosed(value) {
  if (!value || typeof value !== "object") return true;
  if (value.type === "object" && value.additionalProperties !== false) return false;
  return Object.values(value).every(allObjectSchemasClosed);
}

function serviceBlock(source, service) {
  const marker = `\n  ${service}:\n`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing service ${service}`);
  const remainder = source.slice(start + marker.length);
  const end = remainder.search(/\n  [A-Za-z0-9][A-Za-z0-9_-]*:\n/);
  return end === -1 ? remainder : remainder.slice(0, end);
}

function STAGING_SERVICE_NAMES_FOR_TEST() {
  return ["docker-action-activation-sidecar", "docker-action-broker"];
}

function nullLeafPaths(value, prefix = []) {
  if (value === null) return [prefix];
  if (!value || typeof value !== "object") return [];
  return Object.entries(value).flatMap(([key, entry]) => nullLeafPaths(entry, [...prefix, key]));
}

function getPath(value, segments) {
  return segments.reduce((current, segment) => current[segment], value);
}

function setPath(value, segments, replacement) {
  const parent = segments.slice(0, -1).reduce((current, segment) => current[segment], value);
  parent[segments.at(-1)] = replacement;
}
