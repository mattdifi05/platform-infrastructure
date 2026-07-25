#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalReleaseSubjects,
  exactGitSha,
  exactRepository,
  parseReleaseImage,
} from "./release-artifact-policy.mjs";
import { validateArtifactVerificationReceipt } from "./deployment-receipt-policy.mjs";
import { snapshotJsonArtifact } from "./stable-json-artifact.mjs";
import { validateTrustedProviderRun } from "./trusted-provider-run-policy.mjs";

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

function canonicalActiveSubjects(entries) {
  if (!Array.isArray(entries) || entries.length === 0) invalid("Active runtime subject set is required.");
  const subjects = entries.map((entry) => {
    exactObjectKeys(entry, ["key", "image", "imageId"], "active runtime subject");
    const key = String(entry.key ?? "");
    if (!/^[A-Z][A-Z0-9_]{2,63}$/.test(key)) invalid("Active runtime subject key is invalid.");
    const image = parseReleaseImage(entry.image, key).image;
    const imageId = String(entry.imageId ?? "");
    if (!/^sha256:[a-f0-9]{64}$/.test(imageId)) invalid(`Active runtime subject ${key} image ID is invalid.`);
    return { key, image, imageId };
  }).sort((left, right) => left.key.localeCompare(right.key));
  for (const field of ["key", "image", "imageId"]) {
    if (new Set(subjects.map((subject) => subject[field])).size !== subjects.length) {
      invalid(`Active runtime subject ${field} values must be unique.`);
    }
  }
  return subjects;
}

function exactActiveSubjectSet(activeSubjects, artifactSubjects) {
  const actual = activeSubjects.map(({ key, image }) => ({ key, image }));
  const expected = canonicalReleaseSubjects(artifactSubjects)
    .map(({ key, image }) => ({ key, image }))
    .sort((left, right) => left.key.localeCompare(right.key));
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    invalid("Active runtime image subject set does not exactly match the admitted release subject set.");
  }
}

export function activeRuntimeFingerprint({
  repository,
  commitSha,
  treeSha,
  target,
  subjects,
}) {
  const canonical = {
    repository: exactRepository(repository),
    commitSha: exactGitSha(commitSha),
    treeSha: exactGitSha(treeSha, "tree SHA"),
    target: canonicalDastTarget(target),
    subjects: canonicalActiveSubjects(subjects),
  };
  return crypto.createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
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
  providerMetadata,
  providerRunId,
  providerRunAttempt,
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
  validateArtifactVerificationReceipt(artifactReceipt, {
    repository: expectedRepository,
    commitSha: expectedCommit,
  });
  const authenticatedProducer = validateTrustedProviderRun(providerMetadata, {
    policy,
    runId: providerRunId,
    runAttempt: providerRunAttempt,
  });

  exactObjectKeys(receipt, [
    "activeRuntime",
    "artifactVerificationReceiptSha256",
    "commitSha",
    "deployedAt",
    "deploymentId",
    "kind",
    "probe",
    "producer",
    "repository",
    "status",
    "target",
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
  if (!/^[A-Za-z0-9._:-]{8,200}$/.test(String(receipt.deploymentId ?? ""))) {
    invalid("Trusted staging deployment receipt deploymentId is invalid.");
  }
  assertFresh(receipt.deployedAt, {
    now,
    maxAgeSeconds: config.maxStagingReceiptAgeSeconds,
    label: "Trusted staging deployment receipt",
  });
  const producer = exactProviderProducer(receipt.producer, authenticatedProducer);

  exactObjectKeys(receipt.activeRuntime, ["fingerprint", "subjects"], "staging active runtime");
  const activeSubjects = canonicalActiveSubjects(receipt.activeRuntime.subjects);
  exactActiveSubjectSet(activeSubjects, artifactReceipt.subjects);
  const expectedRuntimeFingerprint = activeRuntimeFingerprint({
    repository: expectedRepository,
    commitSha: expectedCommit,
    treeSha: expectedTree,
    target: config.canonicalTarget,
    subjects: activeSubjects,
  });
  if (receipt.activeRuntime.fingerprint !== expectedRuntimeFingerprint) {
    invalid("Trusted staging deployment receipt runtime fingerprint is mismatched.");
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
    activeRuntime: { subjects: activeSubjects, fingerprint: expectedRuntimeFingerprint },
    probe: { path: config.releaseIdentityPath, sha256: probeSha256 },
    producer,
    maxDastReceiptAgeSeconds: config.maxDastReceiptAgeSeconds,
  };
}

export function validateStagingProbe(probe, {
  stagingBinding,
  probeSha256,
}) {
  exactObjectKeys(probe, [
    "activeRuntime",
    "commitSha",
    "kind",
    "repository",
    "status",
    "target",
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
  ) {
    invalid("Staging release identity probe candidate binding is mismatched.");
  }
  const actualProbeSha256 = exactSha256(probeSha256, "staging release identity probe SHA256");
  if (actualProbeSha256 !== stagingBinding.probe.sha256) {
    invalid("Staging release identity probe SHA256 does not match the provider receipt.");
  }
  exactObjectKeys(probe.activeRuntime, ["fingerprint", "subjects"], "probed active runtime");
  const subjects = canonicalActiveSubjects(probe.activeRuntime.subjects);
  if (JSON.stringify(subjects) !== JSON.stringify(stagingBinding.activeRuntime.subjects)) {
    invalid("Staging release identity probe active subject set is mismatched.");
  }
  if (probe.activeRuntime.fingerprint !== stagingBinding.activeRuntime.fingerprint) {
    invalid("Staging release identity probe runtime fingerprint is mismatched.");
  }
  return {
    path: stagingBinding.probe.path,
    sha256: actualProbeSha256,
    activeRuntime: { subjects, fingerprint: probe.activeRuntime.fingerprint },
  };
}

function canonicalScan(value, { requireFingerprint }) {
  const keys = requireFingerprint
    ? ["engineImage", "fingerprint", "reports"]
    : ["engineImage", "reports"];
  exactObjectKeys(value, keys, "DAST scan");
  const engineImage = parseReleaseImage(value.engineImage, "DAST_ENGINE_IMAGE").image;
  exactObjectKeys(value.reports, ["html", "json", "xml"], "DAST scan reports");
  const reports = {
    json: exactSha256(value.reports.json, "DAST JSON report SHA256"),
    html: exactSha256(value.reports.html, "DAST HTML report SHA256"),
    xml: exactSha256(value.reports.xml, "DAST XML report SHA256"),
  };
  const fingerprint = crypto.createHash("sha256")
    .update(JSON.stringify({ engineImage, reports }))
    .digest("hex");
  if (requireFingerprint && value.fingerprint !== fingerprint) {
    invalid("DAST scan fingerprint is mismatched.");
  }
  return { engineImage, reports, fingerprint };
}

export function buildDastReceipt({
  stagingBinding,
  stagingReceiptSha256,
  providerMetadataSha256,
  probeBinding,
  scan,
  producer,
  generatedAt = new Date().toISOString(),
}) {
  const exactStagingReceiptSha256 = exactSha256(
    stagingReceiptSha256,
    "staging deployment receipt SHA256",
  );
  const exactProviderMetadataSha256 = exactSha256(
    providerMetadataSha256,
    "provider metadata SHA256",
  );
  if (
    probeBinding.path !== stagingBinding.probe.path
    || probeBinding.sha256 !== stagingBinding.probe.sha256
    || probeBinding.activeRuntime.fingerprint !== stagingBinding.activeRuntime.fingerprint
    || JSON.stringify(probeBinding.activeRuntime.subjects) !== JSON.stringify(stagingBinding.activeRuntime.subjects)
  ) {
    invalid("DAST receipt cannot be built from a probe outside the trusted staging binding.");
  }
  const canonicalProducer = canonicalDastProducer(producer);
  if (
    canonicalProducer.repository !== stagingBinding.repository
    || canonicalProducer.workflowSha !== stagingBinding.commitSha
  ) {
    invalid("DAST producer is not bound to the exact candidate repository/commit.");
  }
  return {
    version: 1,
    kind: stagingBinding.requiredDastReceiptKind,
    status: "passed",
    repository: stagingBinding.repository,
    commitSha: stagingBinding.commitSha,
    treeSha: stagingBinding.treeSha,
    target: stagingBinding.target,
    artifactVerificationReceiptSha256: stagingBinding.artifactVerificationReceiptSha256,
    stagingDeploymentReceiptSha256: exactStagingReceiptSha256,
    providerMetadataSha256: exactProviderMetadataSha256,
    activeRuntime: stagingBinding.activeRuntime,
    probe: { path: probeBinding.path, sha256: probeBinding.sha256 },
    scan: canonicalScan(scan, { requireFingerprint: false }),
    producer: canonicalProducer,
    generatedAt: exactTimestamp(generatedAt, "DAST receipt generatedAt"),
  };
}

export function validateDastReceipt(receipt, {
  policy,
  stagingBinding,
  stagingReceiptSha256,
  providerMetadataSha256,
  expectedProducer,
  now = new Date().toISOString(),
}) {
  const config = stagingDastConfiguration(policy);
  exactObjectKeys(receipt, [
    "activeRuntime",
    "artifactVerificationReceiptSha256",
    "commitSha",
    "generatedAt",
    "kind",
    "probe",
    "producer",
    "providerMetadataSha256",
    "repository",
    "scan",
    "stagingDeploymentReceiptSha256",
    "status",
    "target",
    "treeSha",
    "version",
  ], "DAST receipt");
  if (
    receipt.version !== 1
    || receipt.kind !== config.requiredDastReceiptKind
    || receipt.status !== "passed"
  ) {
    invalid("DAST receipt kind/version/status is invalid.");
  }
  if (
    receipt.repository !== stagingBinding.repository
    || receipt.commitSha !== stagingBinding.commitSha
    || receipt.treeSha !== stagingBinding.treeSha
    || receipt.target !== stagingBinding.target
  ) {
    invalid("DAST receipt candidate/target binding is mismatched.");
  }
  if (
    receipt.artifactVerificationReceiptSha256 !== stagingBinding.artifactVerificationReceiptSha256
    || receipt.stagingDeploymentReceiptSha256 !== exactSha256(
      stagingReceiptSha256,
      "staging deployment receipt SHA256",
    )
    || receipt.providerMetadataSha256 !== exactSha256(
      providerMetadataSha256,
      "provider metadata SHA256",
    )
  ) {
    invalid("DAST receipt does not bind the exact staging deployment receipt and provider evidence.");
  }
  exactObjectKeys(receipt.activeRuntime, ["fingerprint", "subjects"], "DAST active runtime");
  const subjects = canonicalActiveSubjects(receipt.activeRuntime.subjects);
  if (
    receipt.activeRuntime.fingerprint !== stagingBinding.activeRuntime.fingerprint
    || JSON.stringify(subjects) !== JSON.stringify(stagingBinding.activeRuntime.subjects)
  ) {
    invalid("DAST receipt active runtime binding is mismatched.");
  }
  exactObjectKeys(receipt.probe, ["path", "sha256"], "DAST probe");
  if (
    receipt.probe.path !== stagingBinding.probe.path
    || receipt.probe.sha256 !== stagingBinding.probe.sha256
  ) {
    invalid("DAST receipt probe binding is mismatched.");
  }
  canonicalScan(receipt.scan, { requireFingerprint: true });
  const producer = canonicalDastProducer(receipt.producer);
  const expected = canonicalDastProducer(expectedProducer);
  const producerKeys = Object.keys(expected);
  if (producerKeys.some((key) => producer[key] !== expected[key])) {
    invalid("DAST producer does not match the current authenticated workflow run.");
  }
  assertFresh(receipt.generatedAt, {
    now,
    maxAgeSeconds: config.maxDastReceiptAgeSeconds,
    label: "DAST receipt",
  });
  return receipt;
}

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

function snapshotFileSha256(sourcePath, { label, maxBytes }) {
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
  return crypto.createHash("sha256").update(bytes).digest("hex");
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

function main() {
  const options = parseArgs(process.argv.slice(2));
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
    const provider = snapshotJsonArtifact(options.providerMetadata, {
      label: "trusted provider run metadata",
      maxBytes: 4 * 1024 * 1024,
    });
    const staging = snapshotJsonArtifact(options.stagingReceipt, {
      label: "trusted staging deployment receipt",
      maxBytes: 16 * 1024 * 1024,
    });
    snapshots.push(policy, artifact, provider, staging);
    if (artifact.sha256 !== exactSha256(options.artifactReceiptSha256, "artifact receipt SHA256")) {
      invalid("Artifact verification receipt SHA256 mismatch.");
    }
    if (provider.sha256 !== exactSha256(options.providerMetadataSha256, "provider metadata SHA256")) {
      invalid("Trusted provider metadata SHA256 mismatch.");
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
      providerMetadata: provider.document,
      providerRunId: options.providerRunId,
      providerRunAttempt: options.providerRunAttempt,
      now: options.now,
    });

    if (options.dastReceipt) {
      const dast = snapshotJsonArtifact(options.dastReceipt, {
        label: "DAST receipt",
        maxBytes: 16 * 1024 * 1024,
      });
      snapshots.push(dast);
      if (dast.sha256 !== exactSha256(options.dastReceiptSha256, "DAST receipt SHA256")) {
        invalid("DAST receipt SHA256 mismatch.");
      }
      validateDastReceipt(dast.document, {
        policy: policy.document,
        stagingBinding: binding,
        stagingReceiptSha256: staging.sha256,
        providerMetadataSha256: provider.sha256,
        expectedProducer: expectedDastProducer(options),
        now: options.now,
      });
      process.stdout.write(`${JSON.stringify({
        status: "READY",
        repository: binding.repository,
        commitSha: binding.commitSha,
        treeSha: binding.treeSha,
        target: binding.target,
        runtimeFingerprint: binding.activeRuntime.fingerprint,
        dastReceiptSha256: dast.sha256,
      })}\n`);
      return;
    }

    if (!options.probe) {
      process.stdout.write(`${JSON.stringify({
        status: "READY",
        repository: binding.repository,
        commitSha: binding.commitSha,
        treeSha: binding.treeSha,
        target: binding.target,
        identityPath: binding.probe.path,
        runtimeFingerprint: binding.activeRuntime.fingerprint,
      })}\n`);
      return;
    }

    const probe = snapshotJsonArtifact(options.probe, {
      label: "staging release identity probe",
      maxBytes: 1024 * 1024,
    });
    snapshots.push(probe);
    const probeBinding = validateStagingProbe(probe.document, {
      stagingBinding: binding,
      probeSha256: probe.sha256,
    });
    if (!options.receiptOutput) {
      process.stdout.write(`${JSON.stringify({
        status: "READY",
        repository: binding.repository,
        commitSha: binding.commitSha,
        treeSha: binding.treeSha,
        target: binding.target,
        identityPath: binding.probe.path,
        runtimeFingerprint: binding.activeRuntime.fingerprint,
        probeSha256: probe.sha256,
      })}\n`);
      return;
    }

    const receipt = buildDastReceipt({
      stagingBinding: binding,
      stagingReceiptSha256: staging.sha256,
      providerMetadataSha256: provider.sha256,
      probeBinding,
      scan: {
        engineImage: options.zapImage,
        reports: {
          json: snapshotFileSha256(options.zapJson, { label: "DAST JSON report", maxBytes: 128 * 1024 * 1024 }),
          html: snapshotFileSha256(options.zapHtml, { label: "DAST HTML report", maxBytes: 128 * 1024 * 1024 }),
          xml: snapshotFileSha256(options.zapXml, { label: "DAST XML report", maxBytes: 128 * 1024 * 1024 }),
        },
      },
      producer: expectedDastProducer(options),
      generatedAt: options.now ?? new Date().toISOString(),
    });
    validateDastReceipt(receipt, {
      policy: policy.document,
      stagingBinding: binding,
      stagingReceiptSha256: staging.sha256,
      providerMetadataSha256: provider.sha256,
      expectedProducer: expectedDastProducer(options),
      now: options.now,
    });
    const outputPath = path.resolve(options.receiptOutput);
    fs.writeFileSync(outputPath, `${JSON.stringify(receipt)}\n`, { flag: "wx", mode: 0o600 });
    const dastReceiptSha256 = snapshotFileSha256(outputPath, {
      label: "created DAST receipt",
      maxBytes: 16 * 1024 * 1024,
    });
    process.stdout.write(`${JSON.stringify({
      status: "READY",
      repository: binding.repository,
      commitSha: binding.commitSha,
      treeSha: binding.treeSha,
      target: binding.target,
      runtimeFingerprint: binding.activeRuntime.fingerprint,
      dastReceiptSha256,
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
