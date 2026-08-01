#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseReleaseImage } from "./release-artifact-policy.mjs";
import { canonicalJson } from "./runtime-intent-policy.mjs";
import { snapshotJsonArtifact } from "./stable-json-artifact.mjs";

const REQUEST_MAX_BYTES = 1024 * 1024;
const RECEIPT_MAX_BYTES = 4 * 1024 * 1024;
const REQUEST_OPERATIONS = Object.freeze([
  "authenticate-request-and-provider-sidecar",
  "lock-global-activation",
  "verify-active-selector-cas",
  "open-and-verify-bundle-cas",
  "materialize-immutable-release",
  "verify-source-to-final-render",
  "pull-and-inspect-all-images",
  "verify-persistent-volume-identity",
  "apply-origin-firewall",
  "apply-workload-egress",
  "activate-runtime",
  "verify-runtime-inventory",
  "publish-selector-and-receipt",
  "rollback-on-failure",
]);

function invalid(message) {
  throw new Error(message);
}

function exactObject(value, label, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object.`);
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    invalid(`${label} does not use the exact closed schema.`);
  }
  return value;
}

function exactSha256(value, label) {
  const text = String(value ?? "");
  if (!/^[a-f0-9]{64}$/.test(text)) invalid(`${label} must be one lowercase SHA256.`);
  return text;
}

function exactPositiveInteger(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    invalid(`${label} must be one bounded positive integer.`);
  }
  return value;
}

function exactTimestamp(value, label) {
  const text = String(value ?? "");
  let normalized;
  try {
    normalized = new Date(text).toISOString();
  } catch {
    invalid(`${label} must be one canonical UTC timestamp.`);
  }
  if (normalized !== text) invalid(`${label} must be one canonical UTC timestamp.`);
  return text;
}

function exactCanonicalEqual(actual, expected, label) {
  if (canonicalJson(actual) !== canonicalJson(expected)) invalid(`${label} is not bound to the exact activation request.`);
  return actual;
}

function exactHelper(value, label, expectedPath) {
  exactObject(value, label, ["path", "version", "sha256", "providerAttested"]);
  if (
    value.path !== expectedPath
    || value.version !== 1
    || value.providerAttested !== true
  ) {
    invalid(`${label} is not the exact provider-attested helper.`);
  }
  exactSha256(value.sha256, `${label} SHA256`);
  return value;
}

function validateRequest(request) {
  exactObject(request, "Activation request", [
    "schema",
    "requestId",
    "deploymentTarget",
    "sshPort",
    "releaseContext",
    "releaseContextSha256",
    "runtimeIntentSha256",
    "privilegedRuntime",
    "bundle",
    "activationAdmission",
    "dockerRuntime",
    "requestedOperations",
  ]);
  if (request.schema !== "platform-activation-request/v2") invalid("Activation request schema is invalid.");
  if (!/^activation:[a-f0-9]{64}:[a-f0-9]{64}$/.test(String(request.requestId ?? ""))) {
    invalid("Activation request ID is invalid.");
  }
  const [, deploymentReceiptSha256, contextSha256] = request.requestId.split(":");
  exactSha256(request.releaseContextSha256, "release context SHA256");
  exactSha256(request.runtimeIntentSha256, "runtime intent SHA256");
  if (contextSha256 !== request.releaseContextSha256) invalid("Activation request ID does not bind its release context.");
  exactPositiveInteger(request.sshPort, "SSH port", 65535);

  exactObject(request.deploymentTarget, "Activation deployment target", ["environment", "host", "projectName"]);
  if (
    request.deploymentTarget.environment !== "production"
    || request.deploymentTarget.projectName !== "platform_infra_vps"
    || !/^[A-Za-z0-9.-]+$/.test(String(request.deploymentTarget.host ?? ""))
  ) {
    invalid("Activation deployment target is invalid.");
  }

  const context = exactObject(request.releaseContext, "Activation release context", [
    "schema",
    "repository",
    "commitSha",
    "treeSha",
    "sourceArchiveSha256",
    "releaseId",
    "releaseRoot",
    "stateId",
    "stateRoot",
    "environmentFile",
    "environmentSha256",
    "projectName",
    "decisionId",
    "provider",
    "receipts",
    "runtimeIntentSha256",
    "subjects",
    "hostedLockSha256",
    "noHosted",
    "sourceRenderSha256",
    "combinedRenderSha256",
    "persistentVolumes",
  ]);
  if (
    context.schema !== "platform-trusted-release-context/v2"
    || context.projectName !== request.deploymentTarget.projectName
    || context.runtimeIntentSha256 !== request.runtimeIntentSha256
  ) {
    invalid("Activation release context is not bound to the request target and runtime intent.");
  }
  const computedContextSha256 = crypto.createHash("sha256").update(canonicalJson(context), "utf8").digest("hex");
  if (computedContextSha256 !== request.releaseContextSha256) {
    invalid("Activation release context SHA256 does not authenticate its exact canonical content.");
  }
  exactObject(context.provider, "Activation release provider", ["metadataSha256", "runId", "attempt", "challenge"]);
  exactSha256(context.provider.metadataSha256, "provider metadata SHA256");
  exactPositiveInteger(Number(context.provider.runId), "provider run ID");
  exactPositiveInteger(context.provider.attempt, "provider run attempt");
  exactSha256(context.provider.challenge, "provider challenge");
  exactObject(context.receipts, "Activation release receipts", ["artifactSha256", "deploymentSha256", "dastSha256"]);
  exactSha256(context.receipts.artifactSha256, "artifact receipt SHA256");
  exactSha256(context.receipts.deploymentSha256, "deployment receipt SHA256");
  exactSha256(context.receipts.dastSha256, "DAST receipt SHA256");
  if (context.receipts.deploymentSha256 !== deploymentReceiptSha256) {
    invalid("Activation request ID does not bind its deployment receipt.");
  }
  for (const [key, label] of [
    ["sourceArchiveSha256", "source archive SHA256"],
    ["environmentSha256", "environment SHA256"],
    ["runtimeIntentSha256", "release runtime intent SHA256"],
    ["sourceRenderSha256", "source render SHA256"],
    ["combinedRenderSha256", "combined render SHA256"],
  ]) exactSha256(context[key], label);
  if (!Array.isArray(context.subjects) || context.subjects.length < 1) invalid("Activation subjects are required.");
  const subjectNames = [];
  for (const subject of context.subjects) {
    exactObject(subject, "Activation subject", ["serviceName", "imageReference", "imageId"]);
    if (!/^[a-z0-9][a-z0-9_.-]{0,127}$/.test(String(subject.serviceName ?? ""))) {
      invalid("Activation subject service name is invalid.");
    }
    parseReleaseImage(subject.imageReference, `${subject.serviceName} activation image`);
    if (!/^sha256:[a-f0-9]{64}$/.test(String(subject.imageId ?? ""))) {
      invalid(`${subject.serviceName} activation image ID is invalid.`);
    }
    subjectNames.push(subject.serviceName);
  }
  if (
    new Set(subjectNames).size !== subjectNames.length
    || JSON.stringify(subjectNames) !== JSON.stringify([...subjectNames].sort())
  ) {
    invalid("Activation subjects must use exact unique lexicographically sorted service identities.");
  }
  const scheduler = context.subjects.filter((subject) => subject.serviceName === "backup-scheduler");
  if (
    scheduler.length !== 1
    || !parseReleaseImage(scheduler[0].imageReference, "backup scheduler activation image").name
      .endsWith("/platform-infrastructure-backup-scheduler")
  ) {
    invalid("Activation context must bind the dedicated backup scheduler image reference and runtime image ID.");
  }
  if (!Array.isArray(context.persistentVolumes) || context.persistentVolumes.length !== 1) {
    invalid("Activation release context must bind one exact persistent volume.");
  }
  const volume = exactObject(context.persistentVolumes[0], "Activation persistent volume", [
    "name", "createdAt", "driver", "scope", "options", "labels", "mountpoint", "owner",
  ]);
  exactObject(volume.options, "Activation persistent volume options", []);
  exactObject(volume.labels, "Activation persistent volume labels", [
    "platform.infrastructure.managed", "platform.infrastructure.purpose",
  ]);
  exactObject(volume.owner, "Activation persistent volume owner", ["uid", "gid", "mode"]);

  const runtime = exactObject(request.privilegedRuntime, "Activation privileged runtime", [
    "activationBroker", "originFirewallHelper", "workloadEgressHelper",
  ]);
  exactHelper(runtime.activationBroker, "Activation broker", "/usr/local/libexec/platform-activation-broker");
  exactHelper(runtime.originFirewallHelper, "Origin firewall helper", "/usr/local/libexec/platform-origin-firewall");
  exactHelper(runtime.workloadEgressHelper, "Workload egress helper", "/usr/local/libexec/platform-workload-egress-firewall");
  const helperHashes = new Set(Object.values(runtime).map((helper) => helper.sha256));
  if (helperHashes.size !== 3) invalid("Privileged helper SHA256 identities must be distinct.");

  exactObject(request.bundle, "Activation bundle descriptor", ["schema", "sha256", "sizeBytes", "manifestSha256"]);
  if (request.bundle.schema !== "platform-activation-bundle-descriptor/v1") invalid("Activation bundle descriptor is invalid.");
  exactSha256(request.bundle.sha256, "activation bundle SHA256");
  exactSha256(request.bundle.manifestSha256, "activation bundle manifest SHA256");
  exactPositiveInteger(request.bundle.sizeBytes, "activation bundle size", 384 * 1024 * 1024);
  exactObject(request.activationAdmission, "Activation admission descriptor", ["schema", "sha256", "sizeBytes"]);
  if (request.activationAdmission.schema !== "platform-activation-admission-descriptor/v1") {
    invalid("Activation admission descriptor is invalid.");
  }
  exactSha256(request.activationAdmission.sha256, "activation admission SHA256");
  exactPositiveInteger(request.activationAdmission.sizeBytes, "activation admission size", 16 * 1024 * 1024);
  exactObject(request.dockerRuntime, "Docker runtime identity", [
    "releaseId", "candidateId", "targetId", "treeSha256",
  ]);
  for (const [key, prefix] of [
    ["releaseId", "release"],
    ["candidateId", "candidate"],
    ["targetId", "target"],
  ]) {
    if (!new RegExp(`^${prefix}\\.[a-f0-9]{64}$`).test(String(request.dockerRuntime[key] ?? ""))) {
      invalid(`Docker runtime ${key} is invalid.`);
    }
  }
  exactSha256(request.dockerRuntime.treeSha256, "Docker runtime tree SHA256");
  if (canonicalJson(request.requestedOperations) !== canonicalJson(REQUEST_OPERATIONS)) {
    invalid("Activation request does not use the exact closed operation sequence.");
  }
  return request;
}

export function activationRequestSha256(request) {
  return crypto.createHash("sha256").update(`${canonicalJson(request)}\n`, "utf8").digest("hex");
}

export function validateActivationReceipt(receipt, request, {
  requestArtifactSha256 = null,
  dockerActionContract = null,
  now = Date.now(),
} = {}) {
  validateRequest(request);
  if (
    !dockerActionContract
    || dockerActionContract.ACTIVE_RECEIPT_SCHEMA !== "platform.docker-active-receipt/v2"
    || typeof dockerActionContract.normalizeActiveReceipt !== "function"
    || typeof dockerActionContract.canonicalJson !== "function"
    || typeof dockerActionContract.sha256 !== "function"
  ) {
    invalid("The authoritative Docker active-receipt v2 normalizer is unavailable.");
  }
  const requestSha256 = activationRequestSha256(request);
  if (requestArtifactSha256 !== null && exactSha256(requestArtifactSha256, "activation request artifact SHA256") !== requestSha256) {
    invalid("Activation request artifact is not the exact canonical request.");
  }
  exactObject(receipt, "Activation receipt", [
    "schema",
    "status",
    "activatedAt",
    "requestId",
    "requestSha256",
    "releaseContextSha256",
    "runtimeIntentSha256",
    "bundleSha256",
    "activationAdmissionSha256",
    "deploymentTarget",
    "broker",
    "activeReceipt",
    "activeReceiptSha256",
    "operationResults",
  ]);
  if (receipt.schema !== "platform-activation-receipt/v2" || receipt.status !== "ACTIVE") {
    invalid("Activation receipt is not one successful v2 activation.");
  }
  exactTimestamp(receipt.activatedAt, "activation timestamp");
  const bindings = [
    [receipt.requestId, request.requestId, "Activation receipt request ID"],
    [receipt.requestSha256, requestSha256, "Activation receipt request SHA256"],
    [receipt.releaseContextSha256, request.releaseContextSha256, "Activation receipt release context SHA256"],
    [receipt.runtimeIntentSha256, request.runtimeIntentSha256, "Activation receipt runtime intent SHA256"],
    [receipt.bundleSha256, request.bundle.sha256, "Activation receipt bundle SHA256"],
    [receipt.activationAdmissionSha256, request.activationAdmission.sha256, "Activation receipt admission SHA256"],
  ];
  for (const [actual, expected, label] of bindings) {
    if (actual !== expected) invalid(`${label} is mismatched.`);
  }
  exactCanonicalEqual(receipt.deploymentTarget, request.deploymentTarget, "Activation receipt target");
  exactCanonicalEqual(receipt.broker, request.privilegedRuntime.activationBroker, "Activation receipt broker");
  const activeReceipt = dockerActionContract.normalizeActiveReceipt(receipt.activeReceipt, { now });
  exactCanonicalEqual(receipt.activeReceipt, activeReceipt, "Docker active receipt");
  const activeReceiptSha256 = dockerActionContract.sha256(
    dockerActionContract.canonicalJson(activeReceipt),
  );
  if (receipt.activeReceiptSha256 !== activeReceiptSha256) {
    invalid("Docker active receipt SHA256 is mismatched.");
  }
  for (const [actual, expected, label] of [
    [activeReceipt.activationBundleSha256, request.bundle.sha256, "Docker active receipt activation bundle"],
    [activeReceipt.releaseId, request.dockerRuntime.releaseId, "Docker active receipt release ID"],
    [activeReceipt.candidateId, request.dockerRuntime.candidateId, "Docker active receipt candidate ID"],
    [activeReceipt.targetId, request.dockerRuntime.targetId, "Docker active receipt target ID"],
    [activeReceipt.treeSha256, request.dockerRuntime.treeSha256, "Docker active receipt tree SHA256"],
    [activeReceipt.environment, request.deploymentTarget.environment, "Docker active receipt environment"],
    [activeReceipt.sourceRenderSha256, request.releaseContext.sourceRenderSha256, "Docker active receipt source render"],
    [activeReceipt.combinedRenderSha256, request.releaseContext.combinedRenderSha256, "Docker active receipt combined render"],
    [activeReceipt.dastChainSha256, request.releaseContext.receipts.dastSha256, "Docker active receipt DAST chain"],
    [activeReceipt.issuedAt, receipt.activatedAt, "Docker active receipt issue time"],
  ]) {
    if (actual !== expected) invalid(`${label} is not bound to the activation request.`);
  }
  if (!Array.isArray(receipt.operationResults) || receipt.operationResults.length !== REQUEST_OPERATIONS.length) {
    invalid("Activation receipt must contain the exact operation result sequence.");
  }
  receipt.operationResults.forEach((result, index) => {
    exactObject(result, `Activation operation result ${index}`, ["name", "status"]);
    const expectedName = REQUEST_OPERATIONS[index];
    const expectedStatus = expectedName === "rollback-on-failure" ? "not-required" : "passed";
    if (result.name !== expectedName || result.status !== expectedStatus) {
      invalid("Activation receipt operation result is mismatched or unsuccessful.");
    }
  });
  return receipt;
}

function parseArgs(values) {
  const options = {};
  if (values.length % 2 !== 0) invalid("Activation receipt policy arguments are incomplete.");
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--")) invalid(`Invalid or missing value for ${key ?? "argument"}.`);
    if (Object.hasOwn(options, key.slice(2))) invalid(`Duplicate argument ${key}.`);
    options[key.slice(2)] = value;
  }
  exactObject(options, "Activation receipt policy arguments", ["request", "receipt"]);
  return options;
}

function canonicalWireBytes(document) {
  return Buffer.from(`${canonicalJson(document)}\n`, "utf8");
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const request = snapshotJsonArtifact(options.request, { label: "activation request", maxBytes: REQUEST_MAX_BYTES });
  const receipt = snapshotJsonArtifact(options.receipt, { label: "activation receipt", maxBytes: RECEIPT_MAX_BYTES });
  try {
    if (!fs.readFileSync(request.snapshotPath).equals(canonicalWireBytes(request.document))) {
      invalid("Activation request artifact is not exact canonical JSON.");
    }
    if (!fs.readFileSync(receipt.snapshotPath).equals(canonicalWireBytes(receipt.document))) {
      invalid("Activation receipt artifact is not exact canonical JSON.");
    }
    let dockerActionContract;
    try {
      dockerActionContract = await import(new URL("./docker-action-contract.mjs", import.meta.url));
    } catch (error) {
      invalid(`The integrated Docker active-receipt v2 contract is unavailable: ${String(error?.message ?? error)}`);
    }
    validateActivationReceipt(receipt.document, request.document, {
      requestArtifactSha256: request.sha256,
      dockerActionContract,
    });
    process.stdout.write(`${JSON.stringify({
      status: "ACTIVE",
      requestId: receipt.document.requestId,
      activeReceiptSha256: receipt.document.activeReceiptSha256,
    })}\n`);
  } finally {
    receipt.cleanup();
    request.cleanup();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  });
}
