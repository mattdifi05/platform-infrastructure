#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  exactGitSha,
  exactRepository,
  parseReleaseImage,
} from "./release-artifact-policy.mjs";
import {
  canonicalConsumerChallenge,
  validateArtifactVerificationReceipt,
  validateTrustedDeploymentReceipt,
} from "./deployment-receipt-policy.mjs";
import { verifyGithubAttestation } from "./release-trust.mjs";
import { snapshotJsonArtifact } from "./stable-json-artifact.mjs";
import {
  trustedProducerConfiguration,
  validateTrustedProviderRun,
} from "./trusted-provider-run-policy.mjs";

function invalid(message) {
  throw new Error(message);
}

function exactSha256(value, label) {
  const text = String(value ?? "");
  if (!/^[a-f0-9]{64}$/.test(text)) invalid(`${label} must be one lowercase SHA256.`);
  return text;
}

function exactPositiveInteger(value, label) {
  const number = typeof value === "number" ? value : Number(String(value ?? ""));
  if (!Number.isSafeInteger(number) || number < 1) invalid(`${label} must be a positive integer.`);
  return number;
}

function exactTimestamp(value, label) {
  const text = String(value ?? "");
  if (!text || !Number.isFinite(Date.parse(text))) invalid(`${label} must be a valid timestamp.`);
  return text;
}

function exactObjectKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object.`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    invalid(`${label} fields must match the closed receipt schema.`);
  }
  return value;
}

export function canonicalDastTarget(value) {
  const text = String(value ?? "").trim();
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    invalid("Canonical staging target must be one valid HTTPS origin.");
  }
  if (
    parsed.protocol !== "https:"
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
    || parsed.pathname !== "/"
    || text !== parsed.origin
  ) {
    invalid("Canonical staging target must be one exact HTTPS origin without credentials, path, query, fragment or trailing slash.");
  }
  return text;
}

function canonicalIdentityPath(value) {
  const text = String(value ?? "");
  if (!/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/.test(text) || text.includes("//") || text.includes("..")) {
    invalid("Staging release identity path is invalid.");
  }
  return text;
}

function stagingDastConfiguration(policy) {
  const config = policy?.stagingDast;
  if (config?.status !== "READY") {
    invalid(`EXTERNAL-PENDING: ${config?.reason ?? policy?.reason ?? "staging DAST provider binding is not configured"}`);
  }
  const canonicalTarget = canonicalDastTarget(config.canonicalTarget);
  const releaseIdentityPath = canonicalIdentityPath(config.releaseIdentityPath);
  const requiredStagingReceiptKind = String(config.requiredStagingReceiptKind ?? "");
  const requiredDastReceiptKind = String(config.requiredDastReceiptKind ?? "");
  if (requiredStagingReceiptKind !== "platform-trusted-staging-deployment/v1") {
    invalid("Configured staging deployment receipt kind is unsupported.");
  }
  if (requiredDastReceiptKind !== "platform-dast-verification/v1") {
    invalid("Configured DAST receipt kind is unsupported.");
  }
  const maxStagingReceiptAgeSeconds = exactPositiveInteger(
    config.maxStagingReceiptAgeSeconds,
    "Maximum staging receipt age",
  );
  const maxDastReceiptAgeSeconds = exactPositiveInteger(
    config.maxDastReceiptAgeSeconds,
    "Maximum DAST receipt age",
  );
  if (maxStagingReceiptAgeSeconds > 86400 || maxDastReceiptAgeSeconds > 86400) {
    invalid("Staging and DAST receipt age bounds may not exceed 24 hours.");
  }
  return {
    canonicalTarget,
    releaseIdentityPath,
    requiredStagingReceiptKind,
    requiredDastReceiptKind,
    maxStagingReceiptAgeSeconds,
    maxDastReceiptAgeSeconds,
  };
}

function assertFresh(timestamp, { now = new Date().toISOString(), maxAgeSeconds, label }) {
  const observed = Date.parse(exactTimestamp(timestamp, label));
  const current = Date.parse(exactTimestamp(now, "receipt validation time"));
  if (observed > current + 300_000) invalid(`${label} is in the future.`);
  if (current - observed > maxAgeSeconds * 1000) invalid(`${label} is expired.`);
}

function exactConsumerChallenge(value, {
  repository,
  runId,
  runAttempt,
  job = "deploy-vps",
  challengeNonce,
} = {}) {
  const challenge = canonicalConsumerChallenge(value);
  const expected = canonicalConsumerChallenge({
    consumerRepository: repository,
    consumerRunId: runId,
    consumerRunAttempt: runAttempt,
    consumerJob: job,
    challengeNonce,
  });
  if (JSON.stringify(challenge) !== JSON.stringify(expected)) {
    invalid("Deploy consumer challenge does not match the exact current run/attempt/job/nonce.");
  }
  return challenge;
}

function assertObservationOrder({
  preObservedAt,
  scanStartedAt,
  scanFinishedAt,
  postObservedAt,
  generatedAt,
}) {
  const pre = Date.parse(exactTimestamp(preObservedAt, "pre-scan observation timestamp"));
  const scanStart = Date.parse(exactTimestamp(scanStartedAt, "DAST scan started timestamp"));
  const scanFinish = Date.parse(exactTimestamp(scanFinishedAt, "DAST scan finished timestamp"));
  const post = Date.parse(exactTimestamp(postObservedAt, "post-scan observation timestamp"));
  const generated = Date.parse(exactTimestamp(generatedAt, "DAST receipt generatedAt"));
  if (!(pre < scanStart && scanStart < scanFinish && scanFinish < post && post <= generated)) {
    invalid("DAST temporal order must be pre-observation < scan start < scan finish < post-observation <= receipt emission.");
  }
}

function exactServiceName(value, label = "runtime service") {
  const text = String(value ?? "");
  if (!/^[a-z0-9][a-z0-9_-]{0,62}$/.test(text)) invalid(`${label} is invalid.`);
  return text;
}

function exactRouteHost(value) {
  const text = String(value ?? "");
  if (
    text !== text.toLowerCase()
    || text.length > 253
    || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(text)
    || text.includes("..")
  ) {
    invalid("Active runtime route host is invalid.");
  }
  return text;
}

function exactEntrypoint(value) {
  const text = String(value ?? "");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(text)) invalid("Active runtime route entrypoint is invalid.");
  return text;
}

function exactPort(value, label = "runtime target port") {
  const port = typeof value === "number" ? value : Number(String(value ?? ""));
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) invalid(`${label} is invalid.`);
  return port;
}

function canonicalTargetServingServices(entries) {
  if (!Array.isArray(entries) || entries.length === 0) invalid("Target-serving service set is required.");
  const services = entries.map((service) => exactServiceName(service, "target-serving service"));
  if (new Set(services).size !== services.length) invalid("Target-serving service set contains duplicates.");
  const sorted = [...services].sort((left, right) => left.localeCompare(right));
  if (JSON.stringify(services) !== JSON.stringify(sorted)) {
    invalid("Target-serving service set must be lexicographically ordered.");
  }
  for (const required of ["control-center", "project-router", "traefik"]) {
    if (!services.includes(required)) {
      invalid(`Target-serving service set must include ${required}.`);
    }
  }
  return services;
}

export function canonicalActiveRuntime(value, { targetServingServices = [] } = {}) {
  exactObjectKeys(value, ["projectName", "routes", "services"], "staging active runtime inventory");
  const projectName = String(value.projectName ?? "");
  if (!/^[a-z0-9][a-z0-9_-]{0,62}$/.test(projectName)) invalid("Active runtime project name is invalid.");
  if (!Array.isArray(value.services) || value.services.length === 0) {
    invalid("Active runtime service inventory is required.");
  }
  const services = value.services.map((entry) => {
    exactObjectKeys(entry, [
      "containerId",
      "health",
      "image",
      "imageId",
      "service",
      "state",
    ], "active runtime service");
    const service = exactServiceName(entry.service);
    const containerId = String(entry.containerId ?? "");
    if (!/^[a-f0-9]{64}$/.test(containerId)) invalid(`Active runtime service ${service} container ID is invalid.`);
    const image = parseReleaseImage(entry.image, service).image;
    const imageId = String(entry.imageId ?? "");
    if (!/^sha256:[a-f0-9]{64}$/.test(imageId)) invalid(`Active runtime service ${service} image ID is invalid.`);
    if (entry.state !== "running") invalid(`Active runtime service ${service} is not running.`);
    if (!["healthy", "none"].includes(entry.health)) invalid(`Active runtime service ${service} health is invalid.`);
    return {
      service,
      containerId,
      image,
      imageId,
      state: "running",
      health: entry.health,
    };
  });
  const sortedServices = [...services].sort((left, right) => left.service.localeCompare(right.service));
  if (JSON.stringify(services) !== JSON.stringify(sortedServices)) {
    invalid("Active runtime service inventory must be lexicographically ordered.");
  }
  for (const field of ["service", "containerId"]) {
    if (new Set(services.map((service) => service[field])).size !== services.length) {
      invalid(`Active runtime service ${field} values must be unique.`);
    }
  }
  const serviceNames = new Set(services.map(({ service }) => service));

  if (!Array.isArray(value.routes) || value.routes.length === 0) {
    invalid("Active runtime route inventory is required.");
  }
  const routes = value.routes.map((entry) => {
    exactObjectKeys(entry, ["entrypoint", "host", "service", "targetPort"], "active runtime route");
    const route = {
      host: exactRouteHost(entry.host),
      entrypoint: exactEntrypoint(entry.entrypoint),
      service: exactServiceName(entry.service, "active runtime route service"),
      targetPort: exactPort(entry.targetPort),
    };
    if (!serviceNames.has(route.service)) invalid(`Active runtime route references absent service ${route.service}.`);
    return route;
  });
  const routeKey = (route) => `${route.host}\0${route.entrypoint}\0${route.service}\0${String(route.targetPort).padStart(5, "0")}`;
  const sortedRoutes = [...routes].sort((left, right) => routeKey(left).localeCompare(routeKey(right)));
  if (JSON.stringify(routes) !== JSON.stringify(sortedRoutes)) {
    invalid("Active runtime route inventory must use canonical ordering.");
  }
  if (new Set(routes.map(routeKey)).size !== routes.length) invalid("Active runtime route inventory contains duplicates.");

  if (targetServingServices.length > 0) {
    for (const service of canonicalTargetServingServices(targetServingServices)) {
      if (!serviceNames.has(service)) invalid(`Target-serving service ${service} is absent from active runtime inventory.`);
      if (services.find((entry) => entry.service === service)?.health !== "healthy") {
        invalid(`Target-serving service ${service} must be healthy.`);
      }
    }
  }
  return { projectName, services, routes };
}

function fingerprint(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

export function runtimeInventorySha256(activeRuntime, options = {}) {
  return fingerprint(canonicalActiveRuntime(activeRuntime, options));
}

export function targetServingInventoryHash(activeRuntime, targetServingServices) {
  const exactServices = canonicalTargetServingServices(targetServingServices);
  const runtime = canonicalActiveRuntime(activeRuntime, { targetServingServices: exactServices });
  const serving = new Set(exactServices);
  const inventory = {
    services: runtime.services.filter(({ service }) => serving.has(service)),
    routes: runtime.routes.filter(({ service }) => serving.has(service)),
  };
  if (inventory.routes.length === 0) invalid("Target-serving inventory has no route.");
  return fingerprint(inventory);
}

export function activeRuntimeFingerprint({ activeRuntime, targetServingServices }) {
  return runtimeInventorySha256(activeRuntime, { targetServingServices });
}

function exactProviderProducer(value, authenticated) {
  const keys = ["event", "repository", "runAttempt", "runId", "sourceRef", "workflowPath", "workflowSha"];
  exactObjectKeys(value, keys, "staging deployment producer");
  if (keys.some((key) => value[key] !== authenticated[key])) {
    invalid("Staging deployment receipt producer does not match the authenticated provider run.");
  }
  return { ...authenticated };
}

function canonicalDastProducer(value) {
  const keys = ["event", "job", "repository", "runAttempt", "runId", "sourceRef", "workflowPath", "workflowSha"];
  exactObjectKeys(value, keys, "DAST producer");
  const producer = {
    repository: exactRepository(value.repository),
    workflowPath: String(value.workflowPath ?? ""),
    workflowSha: exactGitSha(value.workflowSha, "DAST workflow SHA"),
    sourceRef: String(value.sourceRef ?? ""),
    event: String(value.event ?? ""),
    runId: String(value.runId ?? ""),
    runAttempt: exactPositiveInteger(value.runAttempt, "DAST run attempt"),
    job: String(value.job ?? ""),
  };
  if (
    producer.workflowPath !== ".github/workflows/enterprise-infra.yml"
    || producer.sourceRef !== "refs/heads/main"
    || producer.event !== "workflow_dispatch"
    || !/^[1-9][0-9]*$/.test(producer.runId)
    || producer.job !== "dast-zap"
  ) {
    invalid("DAST producer is not the exact protected-main enterprise workflow job.");
  }
  return producer;
}

export function validateStagingDeploymentReceipt(receipt, {
  policy,
  repository,
  commitSha,
  treeSha,
  artifactReceipt,
  artifactReceiptSha256,
  deploymentReceipt,
  deploymentReceiptSha256,
  providerMetadata,
  providerRunId,
  providerRunAttempt,
  consumerRunId,
  consumerRunAttempt,
  consumerJob,
  challengeNonce,
  runtimeIntentSha256: expectedRuntimeIntentInput,
  now = new Date().toISOString(),
}) {
  const config = stagingDastConfiguration(policy);
  const expectedRepository = exactRepository(repository);
  const expectedCommit = exactGitSha(commitSha);
  const expectedTree = exactGitSha(treeSha, "tree SHA");
  const expectedArtifactReceiptSha256 = exactSha256(
    artifactReceiptSha256,
    "artifact verification receipt SHA256",
  );
  const expectedDeploymentReceiptSha256 = exactSha256(
    deploymentReceiptSha256,
    "trusted deployment admission receipt SHA256",
  );
  const expectedRuntimeIntentSha256 = exactSha256(
    expectedRuntimeIntentInput,
    "runtime intent SHA256",
  );
  validateArtifactVerificationReceipt(artifactReceipt, {
    repository: expectedRepository,
    commitSha: expectedCommit,
  });
  const challenge = canonicalConsumerChallenge({
    consumerRepository: expectedRepository,
    consumerRunId,
    consumerRunAttempt,
    consumerJob,
    challengeNonce,
  });
  validateTrustedDeploymentReceipt(deploymentReceipt, {
    policy,
    repository: expectedRepository,
    commitSha: expectedCommit,
    treeSha: expectedTree,
    artifactReceiptSha256: expectedArtifactReceiptSha256,
    artifactReceipt,
    sourceArchiveSha256: artifactReceipt.sourceArchiveSha256,
    providerRunId,
    providerRunAttempt,
    consumerChallenge: challenge,
  });
  const authenticatedProducer = validateTrustedProviderRun(providerMetadata, {
    policy,
    runId: providerRunId,
    runAttempt: providerRunAttempt,
  });
  if (authenticatedProducer.repository === expectedRepository) {
    invalid("Trusted staging deployment producer must be independent from the candidate repository.");
  }

  exactObjectKeys(receipt, [
    "activeRuntime",
    "artifactVerificationReceiptSha256",
    "commitSha",
    "consumerChallenge",
    "deployedAt",
    "deploymentAdmissionReceiptSha256",
    "deploymentId",
    "kind",
    "probe",
    "producer",
    "repository",
    "runtimeIntentSha256",
    "runtimeInventorySha256",
    "status",
    "target",
    "targetServingInventoryHash",
    "targetServingServices",
    "treeSha",
    "version",
  ], "trusted staging deployment receipt");
  if (
    receipt.version !== 1
    || receipt.kind !== config.requiredStagingReceiptKind
    || receipt.status !== "READY"
  ) {
    invalid("Trusted staging deployment receipt kind/version/status is invalid.");
  }
  if (
    receipt.repository !== expectedRepository
    || receipt.commitSha !== expectedCommit
    || receipt.treeSha !== expectedTree
  ) {
    invalid("Trusted staging deployment receipt repository/commit/tree binding is mismatched.");
  }
  if (receipt.target !== config.canonicalTarget) {
    invalid("Trusted staging deployment receipt does not bind the canonical staging target.");
  }
  if (receipt.artifactVerificationReceiptSha256 !== expectedArtifactReceiptSha256) {
    invalid("Trusted staging deployment receipt does not bind the exact artifact verification receipt.");
  }
  if (receipt.deploymentAdmissionReceiptSha256 !== expectedDeploymentReceiptSha256) {
    invalid("Trusted staging deployment receipt does not bind the exact deployment admission receipt.");
  }
  if (
    receipt.runtimeIntentSha256 !== expectedRuntimeIntentSha256
    || deploymentReceipt.runtimeIntentSha256 !== expectedRuntimeIntentSha256
  ) {
    invalid("Trusted staging deployment receipt does not bind the exact authenticated runtime intent.");
  }
  exactConsumerChallenge(receipt.consumerChallenge, {
    repository: expectedRepository,
    runId: challenge.consumerRunId,
    runAttempt: challenge.consumerRunAttempt,
    job: challenge.consumerJob,
    challengeNonce: challenge.challengeNonce,
  });
  if (!/^[A-Za-z0-9._:-]{8,200}$/.test(String(receipt.deploymentId ?? ""))) {
    invalid("Trusted staging deployment receipt deploymentId is invalid.");
  }
  assertFresh(receipt.deployedAt, {
    now,
    maxAgeSeconds: config.maxStagingReceiptAgeSeconds,
    label: "Trusted staging deployment receipt",
  });
  const producer = exactProviderProducer(receipt.producer, authenticatedProducer);

  const targetServices = canonicalTargetServingServices(receipt.targetServingServices);
  const activeRuntime = canonicalActiveRuntime(receipt.activeRuntime, {
    targetServingServices: targetServices,
  });
  const expectedRuntimeInventorySha256 = runtimeInventorySha256(activeRuntime, {
    targetServingServices: targetServices,
  });
  const expectedTargetServingInventoryHash = targetServingInventoryHash(activeRuntime, targetServices);
  if (receipt.runtimeInventorySha256 !== expectedRuntimeInventorySha256) {
    invalid("Trusted staging deployment receipt runtime inventory SHA256 is mismatched.");
  }
  if (receipt.targetServingInventoryHash !== expectedTargetServingInventoryHash) {
    invalid("Trusted staging deployment receipt target-serving inventory hash is mismatched.");
  }
  const targetHost = new URL(config.canonicalTarget).hostname;
  if (!activeRuntime.routes.some((route) => route.host === targetHost && targetServices.includes(route.service))) {
    invalid("Trusted staging deployment receipt has no target-serving route for the canonical DAST host.");
  }

  exactObjectKeys(receipt.probe, ["path", "sha256"], "staging release identity probe");
  if (receipt.probe.path !== config.releaseIdentityPath) {
    invalid("Trusted staging deployment receipt probe path is not canonical.");
  }
  const probeSha256 = exactSha256(receipt.probe.sha256, "staging release identity probe SHA256");

  return {
    kind: receipt.kind,
    requiredDastReceiptKind: config.requiredDastReceiptKind,
    repository: expectedRepository,
    commitSha: expectedCommit,
    treeSha: expectedTree,
    target: config.canonicalTarget,
    deploymentId: receipt.deploymentId,
    deployedAt: receipt.deployedAt,
    artifactVerificationReceiptSha256: expectedArtifactReceiptSha256,
    deploymentAdmissionReceiptSha256: expectedDeploymentReceiptSha256,
    consumerChallenge: challenge,
    runtimeIntentSha256: expectedRuntimeIntentSha256,
    runtimeInventorySha256: expectedRuntimeInventorySha256,
    targetServingInventoryHash: expectedTargetServingInventoryHash,
    targetServingServices: targetServices,
    activeRuntime,
    probe: { path: config.releaseIdentityPath, sha256: probeSha256 },
    producer,
    maxDastReceiptAgeSeconds: config.maxDastReceiptAgeSeconds,
  };
}

export function validateStagingProbe(probe, {
  stagingBinding,
  probeSha256,
  observedAt,
}) {
  exactObjectKeys(probe, [
    "activeRuntime",
    "commitSha",
    "consumerChallenge",
    "kind",
    "repository",
    "runtimeIntentSha256",
    "runtimeInventorySha256",
    "status",
    "target",
    "targetServingInventoryHash",
    "targetServingServices",
    "treeSha",
    "version",
  ], "staging release identity probe");
  if (
    probe.version !== 1
    || probe.kind !== "platform-staging-release-identity/v1"
    || probe.status !== "READY"
  ) {
    invalid("Staging release identity probe kind/version/status is invalid.");
  }
  if (
    probe.repository !== stagingBinding.repository
    || probe.commitSha !== stagingBinding.commitSha
    || probe.treeSha !== stagingBinding.treeSha
    || probe.target !== stagingBinding.target
    || probe.runtimeIntentSha256 !== stagingBinding.runtimeIntentSha256
    || probe.runtimeInventorySha256 !== stagingBinding.runtimeInventorySha256
    || probe.targetServingInventoryHash !== stagingBinding.targetServingInventoryHash
  ) {
    invalid("Staging release identity probe candidate/runtime binding is mismatched.");
  }
  exactConsumerChallenge(probe.consumerChallenge, {
    repository: stagingBinding.consumerChallenge.consumerRepository,
    runId: stagingBinding.consumerChallenge.consumerRunId,
    runAttempt: stagingBinding.consumerChallenge.consumerRunAttempt,
    job: stagingBinding.consumerChallenge.consumerJob,
    challengeNonce: stagingBinding.consumerChallenge.challengeNonce,
  });
  const actualProbeSha256 = exactSha256(probeSha256, "staging release identity probe SHA256");
  if (actualProbeSha256 !== stagingBinding.probe.sha256) {
    invalid("Staging release identity probe SHA256 does not match the provider receipt.");
  }
  const targetServices = canonicalTargetServingServices(probe.targetServingServices);
  if (JSON.stringify(targetServices) !== JSON.stringify(stagingBinding.targetServingServices)) {
    invalid("Staging release identity probe target-serving service set is mismatched.");
  }
  const activeRuntime = canonicalActiveRuntime(probe.activeRuntime, {
    targetServingServices: targetServices,
  });
  if (JSON.stringify(activeRuntime) !== JSON.stringify(stagingBinding.activeRuntime)) {
    invalid("Staging release identity probe active runtime inventory is mismatched.");
  }
  if (
    runtimeInventorySha256(activeRuntime, { targetServingServices: targetServices })
      !== stagingBinding.runtimeInventorySha256
    || targetServingInventoryHash(activeRuntime, targetServices)
      !== stagingBinding.targetServingInventoryHash
  ) {
    invalid("Staging release identity probe runtime inventory fingerprint is mismatched.");
  }
  return {
    path: stagingBinding.probe.path,
    sha256: actualProbeSha256,
    observedAt: exactTimestamp(observedAt, "staging release identity observation"),
    runtimeIntentSha256: stagingBinding.runtimeIntentSha256,
    runtimeInventorySha256: stagingBinding.runtimeInventorySha256,
    targetServingInventoryHash: stagingBinding.targetServingInventoryHash,
    targetServingServices: targetServices,
    activeRuntime,
  };
}

function exactReportPath(value, expectedName) {
  const text = String(value ?? "");
  if (text !== expectedName) invalid(`DAST report path must be exact ${expectedName}.`);
  return text;
}

function exactByteCount(value, label) {
  const number = typeof value === "number" ? value : Number(String(value ?? ""));
  if (!Number.isSafeInteger(number) || number < 1 || number > 128 * 1024 * 1024) {
    invalid(`${label} byte count is invalid.`);
  }
  return number;
}

function canonicalReportFile(value, format) {
  exactObjectKeys(value, ["bytes", "path", "sha256"], `DAST ${format} report evidence`);
  const names = {
    json: "zap-baseline.json",
    html: "zap-baseline.html",
    xml: "zap-baseline.xml",
  };
  return {
    path: exactReportPath(value.path, names[format]),
    sha256: exactSha256(value.sha256, `DAST ${format} report SHA256`),
    bytes: exactByteCount(value.bytes, `DAST ${format} report`),
  };
}

function canonicalSemanticVerdict(value) {
  exactObjectKeys(value, [
    "alertCount",
    "highestRiskCode",
    "policy",
    "siteCount",
    "status",
  ], "DAST semantic verdict");
  if (
    value.policy !== "zap-baseline-no-risk-alerts/v1"
    || value.status !== "passed"
    || !Number.isSafeInteger(value.siteCount)
    || value.siteCount < 1
    || value.alertCount !== 0
    || value.highestRiskCode !== 0
  ) {
    invalid("DAST semantic verdict is not a strict no-risk-alert pass.");
  }
  return {
    policy: value.policy,
    status: "passed",
    siteCount: value.siteCount,
    alertCount: 0,
    highestRiskCode: 0,
  };
}

export function analyzeZapJsonReport(value, {
  target,
  scanStartedAt = null,
  scanFinishedAt = null,
}) {
  const expectedTarget = canonicalDastTarget(target);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    invalid("ZAP JSON report must be an object.");
  }
  const reportGenerated = Date.parse(String(value["@generated"] ?? ""));
  if (
    typeof value["@version"] !== "string"
    || !value["@version"].trim()
    || !Number.isFinite(reportGenerated)
  ) {
    invalid("ZAP JSON report lacks valid engine version or generation time.");
  }
  if (scanStartedAt !== null || scanFinishedAt !== null) {
    const started = Date.parse(exactTimestamp(scanStartedAt, "DAST scan started timestamp"));
    const finished = Date.parse(exactTimestamp(scanFinishedAt, "DAST scan finished timestamp"));
    if (!(started < finished && reportGenerated >= started && reportGenerated <= finished)) {
      invalid("ZAP JSON report generation time is outside the exact DAST scan interval.");
    }
  }
  if (!Array.isArray(value.site) || value.site.length < 1) {
    invalid("ZAP JSON report must contain at least one scanned site.");
  }
  let alertCount = 0;
  let highestRiskCode = 0;
  const expected = new URL(expectedTarget);
  for (const site of value.site) {
    if (!site || typeof site !== "object" || Array.isArray(site)) invalid("ZAP JSON report site is invalid.");
    let siteTarget;
    try {
      siteTarget = canonicalDastTarget(site["@name"]);
    } catch {
      invalid("ZAP JSON report site is not the exact canonical target.");
    }
    if (
      siteTarget !== expectedTarget
      || site["@host"] !== expected.hostname
      || String(site["@port"]) !== String(expected.port || 443)
      || String(site["@ssl"]) !== "true"
      || !Array.isArray(site.alerts)
    ) {
      invalid("ZAP JSON report site is not the exact canonical HTTPS target.");
    }
    for (const alert of site.alerts) {
      const riskCode = Number(String(alert?.riskcode ?? ""));
      if (!Number.isSafeInteger(riskCode) || riskCode < 0 || riskCode > 3) {
        invalid("ZAP JSON report contains an invalid risk alert.");
      }
      alertCount += 1;
      highestRiskCode = Math.max(highestRiskCode, riskCode);
    }
  }
  if (alertCount !== 0 || highestRiskCode !== 0) {
    invalid("ZAP JSON report contains a risk alert; strict baseline policy requires zero alerts.");
  }
  return {
    policy: "zap-baseline-no-risk-alerts/v1",
    status: "passed",
    siteCount: value.site.length,
    alertCount,
    highestRiskCode,
  };
}

function canonicalReportEvidence(value, { challenge }) {
  exactObjectKeys(value, [
    "artifactName",
    "engineImage",
    "files",
    "semanticVerdict",
  ], "DAST report evidence");
  const expectedArtifactName = [
    "dast-scan-request",
    challenge.consumerRunId,
    challenge.consumerRunAttempt,
    challenge.challengeNonce,
  ].join("-");
  if (value.artifactName !== expectedArtifactName) {
    invalid("DAST report artifact name is not bound to the current run/attempt/challenge.");
  }
  exactObjectKeys(value.files, ["html", "json", "xml"], "DAST report file inventory");
  return {
    artifactName: expectedArtifactName,
    engineImage: parseReleaseImage(value.engineImage, "DAST_ENGINE_IMAGE").image,
    files: {
      json: canonicalReportFile(value.files.json, "json"),
      html: canonicalReportFile(value.files.html, "html"),
      xml: canonicalReportFile(value.files.xml, "xml"),
    },
    semanticVerdict: canonicalSemanticVerdict(value.semanticVerdict),
  };
}

function exactProbeContinuity(stagingBinding, preProbeBinding, postProbeBinding) {
  if (!preProbeBinding || !postProbeBinding) {
    invalid("Independent pre-scan and post-scan staging observations are mandatory.");
  }
  const expected = {
    runtimeIntentSha256: stagingBinding.runtimeIntentSha256,
    runtimeInventorySha256: stagingBinding.runtimeInventorySha256,
    targetServingInventoryHash: stagingBinding.targetServingInventoryHash,
    targetServingServices: stagingBinding.targetServingServices,
    activeRuntime: stagingBinding.activeRuntime,
  };
  for (const [label, probeBinding] of [["pre-scan", preProbeBinding], ["post-scan", postProbeBinding]]) {
    if (
      probeBinding.path !== stagingBinding.probe.path
      || probeBinding.sha256 !== stagingBinding.probe.sha256
      || JSON.stringify({
        runtimeIntentSha256: probeBinding.runtimeIntentSha256,
        runtimeInventorySha256: probeBinding.runtimeInventorySha256,
        targetServingInventoryHash: probeBinding.targetServingInventoryHash,
        targetServingServices: probeBinding.targetServingServices,
        activeRuntime: probeBinding.activeRuntime,
      }) !== JSON.stringify(expected)
    ) {
      invalid(`DAST scan request cannot use a ${label} observation outside the trusted staging binding.`);
    }
  }
  if (
    preProbeBinding.sha256 !== postProbeBinding.sha256
    || JSON.stringify(preProbeBinding.activeRuntime) !== JSON.stringify(postProbeBinding.activeRuntime)
  ) {
    invalid("Pre-scan and post-scan runtime observations do not prove exact continuity.");
  }
}

export function buildDastScanRequest({
  stagingBinding,
  stagingReceiptSha256,
  providerMetadataSha256,
  preProbeBinding,
  postProbeBinding,
  reportEvidence,
  scanStartedAt,
  scanFinishedAt,
  producer,
  generatedAt = new Date().toISOString(),
}) {
  exactProbeContinuity(stagingBinding, preProbeBinding, postProbeBinding);
  const canonicalProducer = canonicalDastProducer(producer);
  if (
    canonicalProducer.repository !== stagingBinding.repository
    || canonicalProducer.workflowSha !== stagingBinding.commitSha
    || canonicalProducer.runId !== stagingBinding.consumerChallenge.consumerRunId
    || canonicalProducer.runAttempt !== stagingBinding.consumerChallenge.consumerRunAttempt
  ) {
    invalid("DAST scan request producer is not bound to the exact candidate and current consumer challenge.");
  }
  assertObservationOrder({
    preObservedAt: preProbeBinding.observedAt,
    scanStartedAt,
    scanFinishedAt,
    postObservedAt: postProbeBinding.observedAt,
    generatedAt,
  });
  return {
    version: 1,
    kind: "platform-dast-scan-request/v1",
    status: "PENDING-PROVIDER-ATTESTATION",
    repository: stagingBinding.repository,
    commitSha: stagingBinding.commitSha,
    treeSha: stagingBinding.treeSha,
    target: stagingBinding.target,
    artifactVerificationReceiptSha256: stagingBinding.artifactVerificationReceiptSha256,
    deploymentAdmissionReceiptSha256: stagingBinding.deploymentAdmissionReceiptSha256,
    stagingDeploymentReceiptSha256: exactSha256(stagingReceiptSha256, "staging deployment receipt SHA256"),
    stagingProviderMetadataSha256: exactSha256(providerMetadataSha256, "staging provider metadata SHA256"),
    consumerChallenge: stagingBinding.consumerChallenge,
    runtimeIntentSha256: stagingBinding.runtimeIntentSha256,
    runtimeInventorySha256: stagingBinding.runtimeInventorySha256,
    targetServingInventoryHash: stagingBinding.targetServingInventoryHash,
    targetServingServices: stagingBinding.targetServingServices,
    observations: {
      pre: {
        path: preProbeBinding.path,
        sha256: preProbeBinding.sha256,
        observedAt: preProbeBinding.observedAt,
      },
      scan: {
        startedAt: exactTimestamp(scanStartedAt, "DAST scan started timestamp"),
        finishedAt: exactTimestamp(scanFinishedAt, "DAST scan finished timestamp"),
      },
      post: {
        path: postProbeBinding.path,
        sha256: postProbeBinding.sha256,
        observedAt: postProbeBinding.observedAt,
      },
    },
    reportEvidence: canonicalReportEvidence(reportEvidence, {
      challenge: stagingBinding.consumerChallenge,
    }),
    producer: canonicalProducer,
    generatedAt: exactTimestamp(generatedAt, "DAST scan request generatedAt"),
  };
}

function canonicalScanRequest(request) {
  exactObjectKeys(request, [
    "artifactVerificationReceiptSha256",
    "commitSha",
    "consumerChallenge",
    "deploymentAdmissionReceiptSha256",
    "generatedAt",
    "kind",
    "observations",
    "producer",
    "reportEvidence",
    "repository",
    "runtimeIntentSha256",
    "runtimeInventorySha256",
    "stagingDeploymentReceiptSha256",
    "stagingProviderMetadataSha256",
    "status",
    "target",
    "targetServingInventoryHash",
    "targetServingServices",
    "treeSha",
    "version",
  ], "DAST scan request");
  if (
    request.version !== 1
    || request.kind !== "platform-dast-scan-request/v1"
    || request.status !== "PENDING-PROVIDER-ATTESTATION"
  ) {
    invalid("DAST scan request must remain pending provider attestation.");
  }
  const repository = exactRepository(request.repository);
  const commitSha = exactGitSha(request.commitSha);
  const treeSha = exactGitSha(request.treeSha, "tree SHA");
  const target = canonicalDastTarget(request.target);
  const challenge = canonicalConsumerChallenge(request.consumerChallenge);
  const producer = canonicalDastProducer(request.producer);
  if (
    producer.repository !== repository
    || producer.workflowSha !== commitSha
    || producer.runId !== challenge.consumerRunId
    || producer.runAttempt !== challenge.consumerRunAttempt
  ) {
    invalid("DAST scan request producer does not match its candidate/current-run challenge.");
  }
  const targetServices = canonicalTargetServingServices(request.targetServingServices);
  exactObjectKeys(request.observations, ["post", "pre", "scan"], "DAST runtime observations");
  exactObjectKeys(request.observations.pre, ["observedAt", "path", "sha256"], "DAST pre-scan observation");
  exactObjectKeys(request.observations.post, ["observedAt", "path", "sha256"], "DAST post-scan observation");
  exactObjectKeys(request.observations.scan, ["finishedAt", "startedAt"], "DAST scan interval");
  assertObservationOrder({
    preObservedAt: request.observations.pre.observedAt,
    scanStartedAt: request.observations.scan.startedAt,
    scanFinishedAt: request.observations.scan.finishedAt,
    postObservedAt: request.observations.post.observedAt,
    generatedAt: request.generatedAt,
  });
  const canonical = {
    ...request,
    repository,
    commitSha,
    treeSha,
    target,
    artifactVerificationReceiptSha256: exactSha256(
      request.artifactVerificationReceiptSha256,
      "artifact verification receipt SHA256",
    ),
    deploymentAdmissionReceiptSha256: exactSha256(
      request.deploymentAdmissionReceiptSha256,
      "deployment admission receipt SHA256",
    ),
    stagingDeploymentReceiptSha256: exactSha256(
      request.stagingDeploymentReceiptSha256,
      "staging deployment receipt SHA256",
    ),
    stagingProviderMetadataSha256: exactSha256(
      request.stagingProviderMetadataSha256,
      "staging provider metadata SHA256",
    ),
    consumerChallenge: challenge,
    runtimeIntentSha256: exactSha256(request.runtimeIntentSha256, "runtime intent SHA256"),
    runtimeInventorySha256: exactSha256(request.runtimeInventorySha256, "runtime inventory SHA256"),
    targetServingInventoryHash: exactSha256(
      request.targetServingInventoryHash,
      "target-serving inventory hash",
    ),
    targetServingServices: targetServices,
    observations: {
      pre: {
        path: canonicalIdentityPath(request.observations.pre.path),
        sha256: exactSha256(request.observations.pre.sha256, "pre-scan probe SHA256"),
        observedAt: exactTimestamp(request.observations.pre.observedAt, "pre-scan observation"),
      },
      scan: {
        startedAt: exactTimestamp(request.observations.scan.startedAt, "scan startedAt"),
        finishedAt: exactTimestamp(request.observations.scan.finishedAt, "scan finishedAt"),
      },
      post: {
        path: canonicalIdentityPath(request.observations.post.path),
        sha256: exactSha256(request.observations.post.sha256, "post-scan probe SHA256"),
        observedAt: exactTimestamp(request.observations.post.observedAt, "post-scan observation"),
      },
    },
    reportEvidence: canonicalReportEvidence(request.reportEvidence, { challenge }),
    producer,
    generatedAt: exactTimestamp(request.generatedAt, "DAST scan request generatedAt"),
  };
  if (
    canonical.observations.pre.path !== canonical.observations.post.path
    || canonical.observations.pre.sha256 !== canonical.observations.post.sha256
  ) {
    invalid("DAST scan request pre/post observations do not prove exact continuity.");
  }
  return canonical;
}

export function validateDastScanRequest(request, {
  policy = null,
  stagingBinding = null,
  stagingReceiptSha256 = null,
  providerMetadataSha256 = null,
  expectedProducer = null,
  now = new Date().toISOString(),
} = {}) {
  const canonical = canonicalScanRequest(request);
  if (stagingBinding) {
    if (
      canonical.repository !== stagingBinding.repository
      || canonical.commitSha !== stagingBinding.commitSha
      || canonical.treeSha !== stagingBinding.treeSha
      || canonical.target !== stagingBinding.target
      || canonical.artifactVerificationReceiptSha256 !== stagingBinding.artifactVerificationReceiptSha256
      || canonical.deploymentAdmissionReceiptSha256 !== stagingBinding.deploymentAdmissionReceiptSha256
      || canonical.stagingDeploymentReceiptSha256 !== exactSha256(stagingReceiptSha256, "staging receipt SHA256")
      || canonical.stagingProviderMetadataSha256 !== exactSha256(providerMetadataSha256, "staging provider metadata SHA256")
      || canonical.runtimeIntentSha256 !== stagingBinding.runtimeIntentSha256
      || canonical.runtimeInventorySha256 !== stagingBinding.runtimeInventorySha256
      || canonical.targetServingInventoryHash !== stagingBinding.targetServingInventoryHash
      || JSON.stringify(canonical.targetServingServices) !== JSON.stringify(stagingBinding.targetServingServices)
    ) {
      invalid("DAST scan request does not bind the exact authenticated staging runtime.");
    }
    exactConsumerChallenge(canonical.consumerChallenge, {
      repository: stagingBinding.consumerChallenge.consumerRepository,
      runId: stagingBinding.consumerChallenge.consumerRunId,
      runAttempt: stagingBinding.consumerChallenge.consumerRunAttempt,
      job: stagingBinding.consumerChallenge.consumerJob,
      challengeNonce: stagingBinding.consumerChallenge.challengeNonce,
    });
    if (
      canonical.observations.pre.path !== stagingBinding.probe.path
      || canonical.observations.pre.sha256 !== stagingBinding.probe.sha256
      || canonical.observations.post.path !== stagingBinding.probe.path
      || canonical.observations.post.sha256 !== stagingBinding.probe.sha256
    ) {
      invalid("DAST scan request probe continuity is outside the staging receipt.");
    }
  }
  if (expectedProducer) {
    const expected = canonicalDastProducer(expectedProducer);
    if (Object.keys(expected).some((key) => canonical.producer[key] !== expected[key])) {
      invalid("DAST scan request producer does not match the current workflow run.");
    }
  }
  if (policy) {
    const config = stagingDastConfiguration(policy);
    assertFresh(canonical.observations.pre.observedAt, {
      now,
      maxAgeSeconds: config.maxDastReceiptAgeSeconds,
      label: "DAST pre-scan observation",
    });
    assertFresh(canonical.observations.post.observedAt, {
      now,
      maxAgeSeconds: config.maxDastReceiptAgeSeconds,
      label: "DAST post-scan observation",
    });
    assertFresh(canonical.generatedAt, {
      now,
      maxAgeSeconds: config.maxDastReceiptAgeSeconds,
      label: "DAST scan request",
    });
  }
  return request;
}

export function buildDastProviderReceipt({
  scanRequest,
  scanRequestSha256,
  reportArtifactId,
  reportArtifactSha256,
  providerObservedReportEvidence,
  providerProducer,
  providerMetadataSha256,
  generatedAt = new Date().toISOString(),
}) {
  const request = canonicalScanRequest(scanRequest);
  const producer = {
    ...exactProviderProducer(providerProducer, providerProducer),
    job: "dast-countersign",
  };
  if (producer.repository === request.repository) {
    invalid("DAST countersign provider must be independent from the candidate repository.");
  }
  const artifactId = String(reportArtifactId ?? "");
  if (!/^[1-9][0-9]*$/.test(artifactId)) invalid("DAST report artifact ID is invalid.");
  const observedEvidence = canonicalReportEvidence(providerObservedReportEvidence, {
    challenge: request.consumerChallenge,
  });
  if (JSON.stringify(observedEvidence) !== JSON.stringify(request.reportEvidence)) {
    invalid("DAST provider-observed report bytes/semantics do not match the exact scan request.");
  }
  return {
    version: 1,
    kind: "platform-dast-verification/v1",
    status: "passed",
    scanRequestSha256: exactSha256(scanRequestSha256, "DAST scan request SHA256"),
    repository: request.repository,
    commitSha: request.commitSha,
    treeSha: request.treeSha,
    target: request.target,
    consumerChallenge: request.consumerChallenge,
    runtimeIntentSha256: request.runtimeIntentSha256,
    runtimeInventorySha256: request.runtimeInventorySha256,
    targetServingInventoryHash: request.targetServingInventoryHash,
    targetServingServices: request.targetServingServices,
    reportArtifact: {
      id: artifactId,
      name: request.reportEvidence.artifactName,
      archiveSha256: exactSha256(reportArtifactSha256, "DAST report artifact archive SHA256"),
      repository: request.repository,
      runId: request.consumerChallenge.consumerRunId,
      runAttempt: request.consumerChallenge.consumerRunAttempt,
    },
    reportEvidenceSha256: fingerprint(request.reportEvidence),
    validatedReportEvidence: observedEvidence,
    providerValidation: {
      independent: true,
      parser: "platform-provider-zap-report-set/v1",
      status: "passed",
    },
    semanticVerdict: request.reportEvidence.semanticVerdict,
    candidateProducer: request.producer,
    providerMetadataSha256: exactSha256(providerMetadataSha256, "DAST provider metadata SHA256"),
    provider: producer,
    generatedAt: exactTimestamp(generatedAt, "provider DAST receipt generatedAt"),
  };
}

export function validateDastProviderReceipt(receipt, {
  policy,
  scanRequest,
  scanRequestSha256,
  reportArtifactId,
  reportArtifactSha256,
  providerMetadata,
  providerMetadataSha256,
  providerRunId,
  providerRunAttempt,
  now = new Date().toISOString(),
}) {
  const config = stagingDastConfiguration(policy);
  const request = canonicalScanRequest(scanRequest);
  exactObjectKeys(receipt, [
    "candidateProducer",
    "commitSha",
    "consumerChallenge",
    "generatedAt",
    "kind",
    "provider",
    "providerValidation",
    "providerMetadataSha256",
    "reportArtifact",
    "reportEvidenceSha256",
    "repository",
    "runtimeIntentSha256",
    "runtimeInventorySha256",
    "scanRequestSha256",
    "semanticVerdict",
    "status",
    "target",
    "targetServingInventoryHash",
    "targetServingServices",
    "treeSha",
    "validatedReportEvidence",
    "version",
  ], "provider-countersigned DAST receipt");
  if (
    receipt.version !== 1
    || receipt.kind !== config.requiredDastReceiptKind
    || receipt.status !== "passed"
  ) {
    invalid("Provider DAST receipt kind/version/status is invalid.");
  }
  const expectedScanRequestSha256 = exactSha256(scanRequestSha256, "DAST scan request SHA256");
  const expectedProviderMetadataSha256 = exactSha256(
    providerMetadataSha256,
    "DAST provider metadata SHA256",
  );
  if (
    receipt.scanRequestSha256 !== expectedScanRequestSha256
    || receipt.providerMetadataSha256 !== expectedProviderMetadataSha256
  ) {
    invalid("Provider DAST receipt does not bind the exact scan request/provider metadata.");
  }
  const scalarKeys = [
    "repository",
    "commitSha",
    "treeSha",
    "target",
    "runtimeIntentSha256",
    "runtimeInventorySha256",
    "targetServingInventoryHash",
  ];
  exactObjectKeys(receipt.reportArtifact, [
    "id",
    "name",
    "archiveSha256",
    "repository",
    "runAttempt",
    "runId",
  ], "provider-validated DAST report artifact");
  const expectedReportArtifactId = String(reportArtifactId ?? "");
  if (!/^[1-9][0-9]*$/.test(expectedReportArtifactId)) invalid("Expected DAST report artifact ID is invalid.");
  const expectedReportArtifactSha256 = exactSha256(
    reportArtifactSha256,
    "expected DAST report artifact archive SHA256",
  );
  const validatedReportEvidence = canonicalReportEvidence(receipt.validatedReportEvidence, {
    challenge: request.consumerChallenge,
  });
  exactObjectKeys(receipt.providerValidation, [
    "independent",
    "parser",
    "status",
  ], "independent DAST provider validation");
  if (
    receipt.providerValidation.independent !== true
    || receipt.providerValidation.parser !== "platform-provider-zap-report-set/v1"
    || receipt.providerValidation.status !== "passed"
  ) {
    invalid("DAST provider validation is not an independent semantic pass.");
  }
  if (
    scalarKeys.some((key) => receipt[key] !== request[key])
    || JSON.stringify(receipt.consumerChallenge) !== JSON.stringify(request.consumerChallenge)
    || JSON.stringify(receipt.targetServingServices) !== JSON.stringify(request.targetServingServices)
    || JSON.stringify(receipt.candidateProducer) !== JSON.stringify(request.producer)
    || receipt.reportArtifact.id !== expectedReportArtifactId
    || receipt.reportArtifact.archiveSha256 !== expectedReportArtifactSha256
    || receipt.reportArtifact.name !== request.reportEvidence.artifactName
    || receipt.reportArtifact.repository !== request.repository
    || receipt.reportArtifact.runId !== request.consumerChallenge.consumerRunId
    || receipt.reportArtifact.runAttempt !== request.consumerChallenge.consumerRunAttempt
    || receipt.reportEvidenceSha256 !== fingerprint(request.reportEvidence)
    || JSON.stringify(validatedReportEvidence) !== JSON.stringify(request.reportEvidence)
    || JSON.stringify(canonicalSemanticVerdict(receipt.semanticVerdict))
      !== JSON.stringify(request.reportEvidence.semanticVerdict)
  ) {
    invalid("Provider DAST receipt candidate/challenge/runtime/report binding is mismatched.");
  }
  const authenticated = validateTrustedProviderRun(providerMetadata, {
    policy,
    runId: providerRunId,
    runAttempt: providerRunAttempt,
  });
  if (authenticated.repository === request.repository) {
    invalid("DAST countersign provider must be independent from the candidate repository.");
  }
  const expectedProvider = { ...authenticated, job: "dast-countersign" };
  exactObjectKeys(receipt.provider, [
    "event",
    "job",
    "repository",
    "runAttempt",
    "runId",
    "sourceRef",
    "workflowPath",
    "workflowSha",
  ], "DAST countersign provider");
  if (Object.keys(expectedProvider).some((key) => receipt.provider[key] !== expectedProvider[key])) {
    invalid("DAST countersign receipt does not match the authenticated provider run.");
  }
  assertFresh(receipt.generatedAt, {
    now,
    maxAgeSeconds: config.maxDastReceiptAgeSeconds,
    label: "provider-countersigned DAST receipt",
  });
  return receipt;
}

export function verifyDastProviderAttestation({
  receiptPath,
  receiptSha256,
  bundlePath,
  policy,
  verifierBinary = "/usr/local/bin/gh",
}) {
  const producer = trustedProducerConfiguration(policy);
  return verifyGithubAttestation({
    subject: receiptPath,
    expectedSubjectDigest: exactSha256(receiptSha256, "provider DAST receipt SHA256"),
    repository: producer.repository,
    signerWorkflow: `${producer.repository}/${producer.workflowPath}`,
    sourceDigest: producer.workflowSha,
    sourceRef: producer.sourceRef,
    bundle: bundlePath,
    useGithubPublicGoodRoot: true,
  }, { verifierBinary });
}

export const buildDastReceipt = buildDastScanRequest;
export const validateDastReceipt = validateDastProviderReceipt;

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--")) {
      invalid(`Invalid or missing value for ${key ?? "argument"}.`);
    }
    if (Object.hasOwn(result, key.slice(2))) invalid(`Duplicate argument ${key}.`);
    result[key.slice(2)] = value;
  }
  return result;
}

function snapshotFileEvidence(sourcePath, { label, maxBytes }) {
  const resolved = path.resolve(String(sourcePath ?? ""));
  let descriptor;
  let before;
  let after;
  let bytes;
  try {
    if (!sourcePath || typeof fs.constants.O_NOFOLLOW !== "number") invalid(`${label} path is invalid.`);
    descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.size < 1 || before.size > maxBytes) invalid(`${label} size is invalid.`);
    bytes = fs.readFileSync(descriptor);
    after = fs.fstatSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  if (
    bytes.length !== before.size
    || before.dev !== after.dev
    || before.ino !== after.ino
    || before.size !== after.size
    || before.mtimeMs !== after.mtimeMs
    || before.ctimeMs !== after.ctimeMs
  ) {
    invalid(`${label} changed while it was being captured.`);
  }
  return {
    bytes,
    byteCount: bytes.length,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    sourcePath: resolved,
  };
}

function snapshotFileSha256(sourcePath, options) {
  return snapshotFileEvidence(sourcePath, options).sha256;
}

function exactZapReportEvidence(options, binding) {
  const json = snapshotFileEvidence(options.zapJson, {
    label: "DAST JSON report",
    maxBytes: 128 * 1024 * 1024,
  });
  const html = snapshotFileEvidence(options.zapHtml, {
    label: "DAST HTML report",
    maxBytes: 128 * 1024 * 1024,
  });
  const xml = snapshotFileEvidence(options.zapXml, {
    label: "DAST XML report",
    maxBytes: 128 * 1024 * 1024,
  });
  let jsonDocument;
  try {
    jsonDocument = JSON.parse(json.bytes.toString("utf8"));
  } catch (error) {
    invalid(`DAST JSON report is invalid: ${error.message}`);
  }
  const semanticVerdict = analyzeZapJsonReport(jsonDocument, {
    target: binding.target,
    scanStartedAt: options.scanStartedAt,
    scanFinishedAt: options.scanFinishedAt,
  });
  const targetHost = new URL(binding.target).hostname;
  const htmlText = html.bytes.toString("utf8");
  if (
    !/<html[\s>]/i.test(htmlText)
    || !/ZAP Scanning Report/i.test(htmlText)
    || !htmlText.includes(targetHost)
  ) {
    invalid("DAST HTML report does not identify a ZAP scan of the canonical target.");
  }
  const xmlText = xml.bytes.toString("utf8");
  if (
    !/<OWASPZAPReport[\s>]/.test(xmlText)
    || !/<site[\s>]/.test(xmlText)
    || !xmlText.includes(targetHost)
  ) {
    invalid("DAST XML report does not identify a ZAP scan of the canonical target.");
  }
  return canonicalReportEvidence({
    artifactName: options.reportArtifactName,
    engineImage: options.zapImage,
    files: {
      json: { path: "zap-baseline.json", sha256: json.sha256, bytes: json.byteCount },
      html: { path: "zap-baseline.html", sha256: html.sha256, bytes: html.byteCount },
      xml: { path: "zap-baseline.xml", sha256: xml.sha256, bytes: xml.byteCount },
    },
    semanticVerdict,
  }, { challenge: binding.consumerChallenge });
}

function snapshotOpaqueArtifact(sourcePath, { label, maxBytes }) {
  const captured = snapshotFileEvidence(sourcePath, { label, maxBytes });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "platform-dast-evidence."));
  const stablePath = path.join(directory, "evidence.bundle");
  fs.writeFileSync(stablePath, captured.bytes, { flag: "wx", mode: 0o600 });
  return {
    sha256: captured.sha256,
    sourcePath: captured.sourcePath,
    stablePath,
    cleanup() {
      fs.rmSync(directory, { recursive: true, force: true });
    },
  };
}

function expectedDastProducer(options) {
  return canonicalDastProducer({
    repository: options.repo,
    workflowPath: options.workflowPath,
    workflowSha: options.commit,
    sourceRef: options.sourceRef,
    event: options.event,
    runId: options.runId,
    runAttempt: options.runAttempt,
    job: options.job,
  });
}

function createConsumerChallenge(options) {
  if (options.challengeNonce !== undefined) {
    invalid("A deploy consumer challenge nonce may not be supplied to the trusted generator.");
  }
  const challenge = canonicalConsumerChallenge({
    consumerRepository: options.repo,
    consumerRunId: options.consumerRunId,
    consumerRunAttempt: options.consumerRunAttempt,
    consumerJob: options.consumerJob,
    challengeNonce: crypto.randomBytes(32).toString("hex"),
  });
  const outputPath = path.resolve(String(options.challengeOutput ?? ""));
  if (!options.challengeOutput) invalid("Deploy consumer challenge output path is required.");
  fs.writeFileSync(outputPath, `${JSON.stringify(challenge)}\n`, { flag: "wx", mode: 0o600 });
  const challengeSha256 = snapshotFileSha256(outputPath, {
    label: "created deploy consumer challenge",
    maxBytes: 1024 * 1024,
  });
  return { ...challenge, challengeSha256 };
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.challengeOutput) {
    process.stdout.write(`${JSON.stringify(createConsumerChallenge(options))}\n`);
    return;
  }
  if (options.receiptOutput) {
    invalid("Candidate workflows may not self-issue a deploy-authorizing DAST receipt.");
  }
  const snapshots = [];
  try {
    const policy = snapshotJsonArtifact(options.policy, {
      label: "deployment admission policy",
      maxBytes: 1024 * 1024,
    });
    const artifact = snapshotJsonArtifact(options.artifactReceipt, {
      label: "artifact verification receipt",
      maxBytes: 16 * 1024 * 1024,
    });
    const deployment = snapshotJsonArtifact(options.deploymentReceipt, {
      label: "trusted deployment admission receipt",
      maxBytes: 16 * 1024 * 1024,
    });
    const provider = snapshotJsonArtifact(options.providerMetadata, {
      label: "trusted provider run metadata",
      maxBytes: 4 * 1024 * 1024,
    });
    const staging = snapshotJsonArtifact(options.stagingReceipt, {
      label: "trusted staging deployment receipt",
      maxBytes: 16 * 1024 * 1024,
    });
    snapshots.push(policy, artifact, deployment, provider, staging);
    if (artifact.sha256 !== exactSha256(options.artifactReceiptSha256, "artifact receipt SHA256")) {
      invalid("Artifact verification receipt SHA256 mismatch.");
    }
    if (provider.sha256 !== exactSha256(options.providerMetadataSha256, "provider metadata SHA256")) {
      invalid("Trusted provider metadata SHA256 mismatch.");
    }
    if (deployment.sha256 !== exactSha256(options.deploymentReceiptSha256, "deployment admission receipt SHA256")) {
      invalid("Trusted deployment admission receipt SHA256 mismatch.");
    }
    if (staging.sha256 !== exactSha256(options.stagingReceiptSha256, "staging receipt SHA256")) {
      invalid("Trusted staging deployment receipt SHA256 mismatch.");
    }
    const binding = validateStagingDeploymentReceipt(staging.document, {
      policy: policy.document,
      repository: options.repo,
      commitSha: options.commit,
      treeSha: options.tree,
      artifactReceipt: artifact.document,
      artifactReceiptSha256: artifact.sha256,
      deploymentReceipt: deployment.document,
      deploymentReceiptSha256: deployment.sha256,
      providerMetadata: provider.document,
      providerRunId: options.providerRunId,
      providerRunAttempt: options.providerRunAttempt,
      consumerRunId: options.consumerRunId,
      consumerRunAttempt: options.consumerRunAttempt,
      consumerJob: options.consumerJob,
      challengeNonce: options.challengeNonce,
      runtimeIntentSha256: options.runtimeIntentSha256,
      now: options.now,
    });

    if (options.dastReceipt) {
      if (
        !options.scanRequest
        || !options.reportArtifactId
        || !options.reportArtifactSha256
        || !options.dastProviderMetadata
        || !options.dastAttestationBundle
      ) {
        invalid("A provider-countersigned DAST receipt requires its exact scan request, report artifact ID/archive digest, provider metadata and Sigstore bundle.");
      }
      const scanRequest = snapshotJsonArtifact(options.scanRequest, {
        label: "DAST scan request",
        maxBytes: 16 * 1024 * 1024,
      });
      const dast = snapshotJsonArtifact(options.dastReceipt, {
        label: "provider-countersigned DAST receipt",
        maxBytes: 16 * 1024 * 1024,
      });
      const dastProvider = snapshotJsonArtifact(options.dastProviderMetadata, {
        label: "DAST countersign provider run metadata",
        maxBytes: 4 * 1024 * 1024,
      });
      const bundle = snapshotOpaqueArtifact(options.dastAttestationBundle, {
        label: "DAST provider Sigstore attestation bundle",
        maxBytes: 16 * 1024 * 1024,
      });
      snapshots.push(scanRequest, dast, dastProvider, bundle);
      if (scanRequest.sha256 !== exactSha256(options.scanRequestSha256, "DAST scan request SHA256")) {
        invalid("DAST scan request SHA256 mismatch.");
      }
      if (dast.sha256 !== exactSha256(options.dastReceiptSha256, "DAST receipt SHA256")) {
        invalid("DAST receipt SHA256 mismatch.");
      }
      if (
        dastProvider.sha256
          !== exactSha256(options.dastProviderMetadataSha256, "DAST provider metadata SHA256")
      ) {
        invalid("DAST provider metadata SHA256 mismatch.");
      }
      if (
        bundle.sha256
          !== exactSha256(options.dastAttestationBundleSha256, "DAST attestation bundle SHA256")
      ) {
        invalid("DAST attestation bundle SHA256 mismatch.");
      }
      validateDastScanRequest(scanRequest.document, {
        policy: policy.document,
        stagingBinding: binding,
        stagingReceiptSha256: staging.sha256,
        providerMetadataSha256: provider.sha256,
        expectedProducer: expectedDastProducer(options),
        now: options.now,
      });
      validateDastProviderReceipt(dast.document, {
        policy: policy.document,
        scanRequest: scanRequest.document,
        scanRequestSha256: scanRequest.sha256,
        reportArtifactId: options.reportArtifactId,
        reportArtifactSha256: options.reportArtifactSha256,
        providerMetadata: dastProvider.document,
        providerMetadataSha256: dastProvider.sha256,
        providerRunId: options.dastProviderRunId,
        providerRunAttempt: options.dastProviderRunAttempt,
        now: options.now,
      });
      const attestation = verifyDastProviderAttestation({
        receiptPath: dast.snapshotPath,
        receiptSha256: dast.sha256,
        bundlePath: bundle.stablePath,
        policy: policy.document,
        verifierBinary: options.attestationVerifier,
      });
      process.stdout.write(`${JSON.stringify({
        status: "READY",
        repository: binding.repository,
        commitSha: binding.commitSha,
        treeSha: binding.treeSha,
        target: binding.target,
        runtimeIntentSha256: binding.runtimeIntentSha256,
        runtimeInventorySha256: binding.runtimeInventorySha256,
        targetServingInventoryHash: binding.targetServingInventoryHash,
        scanRequestSha256: scanRequest.sha256,
        dastReceiptSha256: dast.sha256,
        attestationVerified: attestation.verified,
      })}\n`);
      return;
    }

    if (!options.preProbe) {
      process.stdout.write(`${JSON.stringify({
        status: "READY",
        repository: binding.repository,
        commitSha: binding.commitSha,
        treeSha: binding.treeSha,
        target: binding.target,
        identityPath: binding.probe.path,
        runtimeIntentSha256: binding.runtimeIntentSha256,
        runtimeInventorySha256: binding.runtimeInventorySha256,
        targetServingInventoryHash: binding.targetServingInventoryHash,
      })}\n`);
      return;
    }

    const preProbe = snapshotJsonArtifact(options.preProbe, {
      label: "pre-scan staging release identity observation",
      maxBytes: 1024 * 1024,
    });
    snapshots.push(preProbe);
    const preProbeBinding = validateStagingProbe(preProbe.document, {
      stagingBinding: binding,
      probeSha256: preProbe.sha256,
      observedAt: options.preObservedAt,
    });
    if (!options.scanRequestOutput) {
      process.stdout.write(`${JSON.stringify({
        status: "READY",
        repository: binding.repository,
        commitSha: binding.commitSha,
        treeSha: binding.treeSha,
        target: binding.target,
        identityPath: binding.probe.path,
        runtimeIntentSha256: binding.runtimeIntentSha256,
        runtimeInventorySha256: binding.runtimeInventorySha256,
        targetServingInventoryHash: binding.targetServingInventoryHash,
        probeSha256: preProbe.sha256,
        observedAt: preProbeBinding.observedAt,
      })}\n`);
      return;
    }
    if (!options.postProbe) {
      invalid("A fresh post-scan staging observation is mandatory before DAST scan request emission.");
    }
    const postProbe = snapshotJsonArtifact(options.postProbe, {
      label: "post-scan staging release identity observation",
      maxBytes: 1024 * 1024,
    });
    snapshots.push(postProbe);
    if (preProbe.sourcePath === postProbe.sourcePath) {
      invalid("Pre-scan and post-scan observations must be captured as two distinct reads.");
    }
    const postProbeBinding = validateStagingProbe(postProbe.document, {
      stagingBinding: binding,
      probeSha256: postProbe.sha256,
      observedAt: options.postObservedAt,
    });

    const generatedAt = options.generatedAt ?? new Date().toISOString();
    const request = buildDastScanRequest({
      stagingBinding: binding,
      stagingReceiptSha256: staging.sha256,
      providerMetadataSha256: provider.sha256,
      preProbeBinding,
      postProbeBinding,
      reportEvidence: exactZapReportEvidence(options, binding),
      scanStartedAt: options.scanStartedAt,
      scanFinishedAt: options.scanFinishedAt,
      producer: expectedDastProducer(options),
      generatedAt,
    });
    validateDastScanRequest(request, {
      policy: policy.document,
      stagingBinding: binding,
      stagingReceiptSha256: staging.sha256,
      providerMetadataSha256: provider.sha256,
      expectedProducer: expectedDastProducer(options),
      now: options.now ?? generatedAt,
    });
    const outputPath = path.resolve(options.scanRequestOutput);
    fs.writeFileSync(outputPath, `${JSON.stringify(request)}\n`, { flag: "wx", mode: 0o600 });
    const scanRequestSha256 = snapshotFileSha256(outputPath, {
      label: "created DAST scan request",
      maxBytes: 16 * 1024 * 1024,
    });
    process.stdout.write(`${JSON.stringify({
      status: "PENDING-PROVIDER-ATTESTATION",
      repository: binding.repository,
      commitSha: binding.commitSha,
      treeSha: binding.treeSha,
      target: binding.target,
      runtimeIntentSha256: binding.runtimeIntentSha256,
      runtimeInventorySha256: binding.runtimeInventorySha256,
      targetServingInventoryHash: binding.targetServingInventoryHash,
      scanRequestSha256,
    })}\n`);
  } finally {
    for (const snapshot of snapshots.reverse()) snapshot.cleanup();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
