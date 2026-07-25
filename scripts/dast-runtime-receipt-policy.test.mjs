#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  buildDastScanRequest,
  canonicalActiveRuntime,
  runtimeInventorySha256,
  targetServingInventoryHash,
  validateDastScanRequest,
  validateStagingDeploymentReceipt,
  validateStagingProbe,
} from "./dast-runtime-receipt-policy.mjs";
import { runtimeIntentSha256 } from "./runtime-intent-policy.mjs";

const hashBytes = (value) => crypto.createHash("sha256").update(value).digest("hex");
const repository = "owner/platform-infrastructure";
const commitSha = "1".repeat(40);
const treeSha = "2".repeat(40);
const target = "https://staging.platform-infrastructure.test";
const targetHost = new URL(target).hostname;
const identityPath = "/.well-known/platform-release.json";
const generatedAt = "2026-07-25T10:00:00.000Z";
const preObservedAt = "2026-07-25T10:01:00.000Z";
const scanStartedAt = "2026-07-25T10:02:00.000Z";
const zapGeneratedAt = "2026-07-25T10:03:00.000Z";
const scanFinishedAt = "2026-07-25T10:04:00.000Z";
const postObservedAt = "2026-07-25T10:05:00.000Z";
const requestGeneratedAt = "2026-07-25T10:06:00.000Z";
const now = "2026-07-25T10:10:00.000Z";
const challengeNonce = "4".repeat(64);
const consumerChallenge = {
  consumerRepository: repository,
  consumerRunId: "7654321",
  consumerRunAttempt: 3,
  consumerJob: "deploy-vps",
  challengeNonce,
};
const provider = {
  repository: "owner/platform-admission",
  workflowPath: ".github/workflows/produce-admission.yml",
  workflowSha: "5".repeat(40),
  sourceRef: "refs/heads/main",
  event: "workflow_dispatch",
  runId: "987654",
  runAttempt: 2,
};
const providerMetadata = {
  id: Number(provider.runId),
  run_attempt: provider.runAttempt,
  repository: { full_name: provider.repository },
  head_repository: { full_name: provider.repository },
  path: provider.workflowPath,
  head_sha: provider.workflowSha,
  head_branch: "main",
  event: provider.event,
  status: "completed",
  conclusion: "success",
};
const policy = {
  version: 1,
  status: "READY",
  trustedVerifierChannel: "external-admission-controller/prod",
  trustedOpsImageRepository: "ghcr.io/owner/platform-infrastructure-ops",
  requiredReceiptKind: "platform-trusted-deployment-admission/v1",
  selfAssertedAnnotationsAccepted: false,
  trustedProducer: {
    repository: provider.repository,
    workflowPath: provider.workflowPath,
    workflowSha: provider.workflowSha,
    sourceRef: provider.sourceRef,
    event: provider.event,
  },
  stagingDast: {
    status: "READY",
    canonicalTarget: target,
    releaseIdentityPath: identityPath,
    requiredStagingReceiptKind: "platform-trusted-staging-deployment/v1",
    requiredDastReceiptKind: "platform-dast-verification/v1",
    maxStagingReceiptAgeSeconds: 3600,
    maxDastReceiptAgeSeconds: 1800,
  },
};
const releaseSubjects = [
  {
    key: "CONTROL_CENTER_IMAGE",
    image: `ghcr.io/owner/platform-infrastructure-control-center@sha256:${"6".repeat(64)}`,
  },
  {
    key: "PROJECT_ROUTER_IMAGE",
    image: `ghcr.io/owner/platform-infrastructure-project-router@sha256:${"7".repeat(64)}`,
  },
];
const artifactReceipt = {
  version: 1,
  kind: "platform-release-artifact-verification/v1",
  status: "EXTERNAL-PENDING",
  artifactVerification: "passed",
  deploymentAdmission: "EXTERNAL-PENDING",
  usageScope: "artifact-verification-only",
  repository,
  commitSha,
  sourceArchiveSha256: "8".repeat(64),
  generatedAt,
  manifestSha256: "9".repeat(64),
  sbomSha256: "a".repeat(64),
  subjects: releaseSubjects,
  provenance: {
    verificationFingerprint: "b".repeat(64),
    manifestVerificationFingerprint: "c".repeat(64),
  },
};
const artifactReceiptSha256 = "d".repeat(64);
const opsRunner = {
  image: `ghcr.io/owner/platform-infrastructure-ops@sha256:${"f".repeat(64)}`,
  imageId: `sha256:${"0".repeat(64)}`,
  verificationFingerprint: "1".repeat(64),
  providerAttested: true,
};
const runtimeIntent = {
  version: 1,
  kind: "platform-runtime-intent/v1",
  repository,
  commitSha,
  treeSha,
  sourceArchiveSha256: artifactReceipt.sourceArchiveSha256,
  projectName: "platform_infra_vps",
  environmentSha256: "3".repeat(64),
  hostedWorkloadLockSha256: null,
  coreComposeSha256: "4".repeat(64),
  combinedComposeSha256: "5".repeat(64),
  services: [
    {
      service: "backup-scheduler",
      image: opsRunner.image,
      admission: { kind: "ops-runner" },
      expectedLocalImageId: opsRunner.imageId,
    },
    {
      service: "control-center",
      image: releaseSubjects[0].image,
      admission: { kind: "artifact-subject", subjectKey: releaseSubjects[0].key },
      expectedLocalImageId: `sha256:${"2".repeat(64)}`,
    },
    {
      service: "project-router",
      image: releaseSubjects[1].image,
      admission: { kind: "artifact-subject", subjectKey: releaseSubjects[1].key },
      expectedLocalImageId: `sha256:${"4".repeat(64)}`,
    },
    {
      service: "traefik",
      image: `docker.io/library/traefik@sha256:${"6".repeat(64)}`,
      admission: { kind: "external-digest", sourceKey: "TRAEFIK_IMAGE" },
      expectedLocalImageId: `sha256:${"7".repeat(64)}`,
    },
  ],
  targetServingServices: ["control-center", "project-router", "traefik"],
};
const runtimeIntentSha = runtimeIntentSha256(runtimeIntent);
const deploymentReceipt = {
  version: 1,
  kind: "platform-trusted-deployment-admission/v1",
  status: "READY",
  artifactVerification: "passed",
  deploymentAdmission: "READY",
  repository,
  commitSha,
  treeSha,
  sourceArchiveSha256: artifactReceipt.sourceArchiveSha256,
  artifactVerificationReceiptSha256: artifactReceiptSha256,
  manifestSha256: artifactReceipt.manifestSha256,
  sbomSha256: artifactReceipt.sbomSha256,
  runtimeIntent,
  runtimeIntentSha256: runtimeIntentSha,
  generatedAt,
  decisionId: "decision:987654",
  verifier: {
    channel: policy.trustedVerifierChannel,
    fingerprint: "e".repeat(64),
    selfAsserted: false,
    verifiedAt: generatedAt,
  },
  producer: provider,
  consumerChallenge,
  opsRunner,
};
const deploymentReceiptSha256 = "2".repeat(64);
const targetServingServices = ["control-center", "project-router", "traefik"];
const activeRuntime = canonicalActiveRuntime({
  projectName: "platform_infra_staging",
  services: [
    {
      service: "control-center",
      containerId: "1".repeat(64),
      image: releaseSubjects[0].image,
      imageId: `sha256:${"2".repeat(64)}`,
      state: "running",
      health: "healthy",
    },
    {
      service: "project-router",
      containerId: "3".repeat(64),
      image: releaseSubjects[1].image,
      imageId: `sha256:${"4".repeat(64)}`,
      state: "running",
      health: "healthy",
    },
    {
      service: "traefik",
      containerId: "5".repeat(64),
      image: `docker.io/library/traefik@sha256:${"6".repeat(64)}`,
      imageId: `sha256:${"7".repeat(64)}`,
      state: "running",
      health: "healthy",
    },
  ],
  routes: [{
    host: targetHost,
    entrypoint: "websecure",
    service: "project-router",
    targetPort: 8080,
  }],
}, { targetServingServices });
const runtimeInventoryHash = runtimeInventorySha256(activeRuntime, { targetServingServices });
const servingInventoryHash = targetServingInventoryHash(activeRuntime, targetServingServices);
const probe = {
  version: 1,
  kind: "platform-staging-release-identity/v1",
  status: "READY",
  repository,
  commitSha,
  treeSha,
  target,
  consumerChallenge,
  runtimeIntentSha256: runtimeIntentSha,
  runtimeInventorySha256: runtimeInventoryHash,
  targetServingInventoryHash: servingInventoryHash,
  targetServingServices,
  activeRuntime,
};
const probeBytes = `${JSON.stringify(probe)}\n`;
const probeSha256 = hashBytes(probeBytes);
const stagingReceipt = {
  version: 1,
  kind: policy.stagingDast.requiredStagingReceiptKind,
  status: "READY",
  repository,
  commitSha,
  treeSha,
  target,
  deploymentId: "staging-deployment:987654",
  deployedAt: generatedAt,
  artifactVerificationReceiptSha256: artifactReceiptSha256,
  deploymentAdmissionReceiptSha256: deploymentReceiptSha256,
  consumerChallenge,
  runtimeIntentSha256: runtimeIntentSha,
  runtimeInventorySha256: runtimeInventoryHash,
  targetServingInventoryHash: servingInventoryHash,
  targetServingServices,
  activeRuntime,
  probe: { path: identityPath, sha256: probeSha256 },
  producer: provider,
};
const stagingReceiptSha256 = "8".repeat(64);
const providerMetadataSha256 = "9".repeat(64);
const candidateProducer = {
  repository,
  workflowPath: ".github/workflows/enterprise-infra.yml",
  workflowSha: commitSha,
  sourceRef: "refs/heads/main",
  event: "workflow_dispatch",
  runId: consumerChallenge.consumerRunId,
  runAttempt: consumerChallenge.consumerRunAttempt,
  job: "dast-zap",
};
const stagingOptions = {
  policy,
  repository,
  commitSha,
  treeSha,
  artifactReceipt,
  artifactReceiptSha256,
  deploymentReceipt,
  deploymentReceiptSha256,
  providerMetadata,
  providerRunId: provider.runId,
  providerRunAttempt: provider.runAttempt,
  consumerRunId: consumerChallenge.consumerRunId,
  consumerRunAttempt: consumerChallenge.consumerRunAttempt,
  consumerJob: consumerChallenge.consumerJob,
  challengeNonce,
  runtimeIntentSha256: runtimeIntentSha,
  now,
};
const stagingBinding = validateStagingDeploymentReceipt(stagingReceipt, stagingOptions);
const preProbeBinding = validateStagingProbe(probe, {
  stagingBinding,
  probeSha256,
  observedAt: preObservedAt,
});
const postProbeBinding = validateStagingProbe(probe, {
  stagingBinding,
  probeSha256,
  observedAt: postObservedAt,
});
const reportEvidence = {
  artifactName: `dast-scan-request-${consumerChallenge.consumerRunId}-${consumerChallenge.consumerRunAttempt}-${challengeNonce}`,
  engineImage: `ghcr.io/zaproxy/zaproxy@sha256:${"a".repeat(64)}`,
  files: {
    json: { path: "zap-baseline.json", sha256: "b".repeat(64), bytes: 1000 },
    html: { path: "zap-baseline.html", sha256: "c".repeat(64), bytes: 2000 },
    xml: { path: "zap-baseline.xml", sha256: "d".repeat(64), bytes: 1500 },
  },
  semanticVerdict: {
    policy: "zap-baseline-no-risk-alerts/v1",
    status: "passed",
    siteCount: 1,
    alertCount: 0,
    highestRiskCode: 0,
  },
};
const scanRequest = buildDastScanRequest({
  stagingBinding,
  stagingReceiptSha256,
  providerMetadataSha256,
  preProbeBinding,
  postProbeBinding,
  reportEvidence,
  scanStartedAt,
  scanFinishedAt,
  producer: candidateProducer,
  generatedAt: requestGeneratedAt,
});
const requestOptions = {
  policy,
  stagingBinding,
  stagingReceiptSha256,
  providerMetadataSha256,
  expectedProducer: candidateProducer,
  now,
};

test("provider-authenticated staging binds complete target-serving runtime inventory", () => {
  assert.equal(stagingBinding.runtimeIntentSha256, runtimeIntentSha);
  assert.equal(stagingBinding.runtimeInventorySha256, runtimeInventoryHash);
  assert.equal(stagingBinding.targetServingInventoryHash, servingInventoryHash);
  assert.deepEqual(stagingBinding.targetServingServices, targetServingServices);
});

test("missing control-center, project-router or traefik fails closed", () => {
  for (const missing of targetServingServices) {
    const reduced = targetServingServices.filter((service) => service !== missing);
    assert.throws(
      () => validateStagingDeploymentReceipt({
        ...stagingReceipt,
        targetServingServices: reduced,
      }, stagingOptions),
      /must include/,
    );
  }
});

test("extra, duplicate or unordered active services and routes fail closed", () => {
  assert.throws(
    () => validateStagingDeploymentReceipt({
      ...stagingReceipt,
      activeRuntime: {
        ...activeRuntime,
        services: [...activeRuntime.services, activeRuntime.services[0]],
      },
    }, stagingOptions),
    /ordered|unique/,
  );
  assert.throws(
    () => validateStagingDeploymentReceipt({
      ...stagingReceipt,
      activeRuntime: {
        ...activeRuntime,
        services: [...activeRuntime.services].reverse(),
      },
    }, stagingOptions),
    /ordered/,
  );
});

test("wrong container, image or health identity fails closed", () => {
  const changed = (patch) => ({
    ...stagingReceipt,
    activeRuntime: {
      ...activeRuntime,
      services: activeRuntime.services.map((service) => (
        service.service === "project-router" ? { ...service, ...patch } : service
      )),
    },
  });
  assert.throws(() => validateStagingDeploymentReceipt(changed({ containerId: "bad" }), stagingOptions), /container ID/);
  assert.throws(() => validateStagingDeploymentReceipt(changed({ imageId: "sha256:bad" }), stagingOptions), /image ID/);
  assert.throws(() => validateStagingDeploymentReceipt(changed({ health: "none" }), stagingOptions), /must be healthy/);
});

test("wrong runtime intent, inventory or target-serving hash fails closed", () => {
  assert.throws(
    () => validateStagingDeploymentReceipt({ ...stagingReceipt, runtimeIntentSha256: "f".repeat(64) }, stagingOptions),
    /runtime intent/,
  );
  assert.throws(
    () => validateStagingDeploymentReceipt({ ...stagingReceipt, runtimeInventorySha256: "f".repeat(64) }, stagingOptions),
    /runtime inventory/,
  );
  assert.throws(
    () => validateStagingDeploymentReceipt({ ...stagingReceipt, targetServingInventoryHash: "f".repeat(64) }, stagingOptions),
    /target-serving/,
  );
});

test("canonical DAST host must have one target-serving route", () => {
  const offTargetRuntime = {
    ...activeRuntime,
    routes: [{ ...activeRuntime.routes[0], host: "other.example.test" }],
  };
  assert.throws(
    () => validateStagingDeploymentReceipt({
      ...stagingReceipt,
      activeRuntime: offTargetRuntime,
      runtimeInventorySha256: runtimeInventorySha256(offTargetRuntime, { targetServingServices }),
      targetServingInventoryHash: targetServingInventoryHash(offTargetRuntime, targetServingServices),
    }, stagingOptions),
    /canonical DAST host/,
  );
});

test("pre and post identity observations bind the exact same full inventory", () => {
  assert.equal(preProbeBinding.sha256, postProbeBinding.sha256);
  assert.deepEqual(preProbeBinding.activeRuntime, activeRuntime);
  assert.throws(
    () => validateStagingProbe({
      ...probe,
      runtimeInventorySha256: "f".repeat(64),
    }, { stagingBinding, probeSha256, observedAt: preObservedAt }),
    /runtime binding/,
  );
});

test("cross-run, cross-attempt and nonce replay fail closed", () => {
  for (const patch of [
    { consumerRunId: "7654322" },
    { consumerRunAttempt: 4 },
    { challengeNonce: "f".repeat(64) },
  ]) {
    assert.throws(
      () => validateStagingDeploymentReceipt(stagingReceipt, { ...stagingOptions, ...patch }),
      /challenge/,
    );
  }
});

test("candidate can emit only a pending provider-attestation request", () => {
  assert.equal(scanRequest.status, "PENDING-PROVIDER-ATTESTATION");
  assert.equal(scanRequest.kind, "platform-dast-scan-request/v1");
  assert.equal(validateDastScanRequest(scanRequest, requestOptions), scanRequest);
});

test("scan request binds report artifact, immutable engine and semantic pass", () => {
  assert.equal(scanRequest.reportEvidence.artifactName, reportEvidence.artifactName);
  assert.equal(scanRequest.reportEvidence.engineImage, reportEvidence.engineImage);
  assert.deepEqual(scanRequest.reportEvidence.semanticVerdict, reportEvidence.semanticVerdict);
  assert.throws(
    () => validateDastScanRequest({
      ...scanRequest,
      reportEvidence: {
        ...scanRequest.reportEvidence,
        semanticVerdict: { ...scanRequest.reportEvidence.semanticVerdict, siteCount: 0 },
      },
    }, requestOptions),
    /semantic verdict/,
  );
});

test("scan report digest, engine and artifact substitutions fail closed", () => {
  for (const reportPatch of [
    { artifactName: "caller-selected" },
    { engineImage: "ghcr.io/zaproxy/zaproxy:latest" },
    {
      files: {
        ...scanRequest.reportEvidence.files,
        json: { ...scanRequest.reportEvidence.files.json, sha256: "not-a-digest" },
      },
    },
  ]) {
    assert.throws(
      () => validateDastScanRequest({
        ...scanRequest,
        reportEvidence: { ...scanRequest.reportEvidence, ...reportPatch },
      }, requestOptions),
      /artifact name|pinned|SHA256/,
    );
  }
});

test("strict temporal continuity rejects reordered observations", () => {
  assert.throws(
    () => validateDastScanRequest({
      ...scanRequest,
      observations: {
        ...scanRequest.observations,
        post: { ...scanRequest.observations.post, observedAt: scanStartedAt },
      },
    }, requestOptions),
    /temporal order/,
  );
});

test("stale scan requests cannot authorize a later provider receipt", () => {
  const stale = {
    ...scanRequest,
    observations: {
      pre: { ...scanRequest.observations.pre, observedAt: "2026-07-25T08:01:00.000Z" },
      scan: { startedAt: "2026-07-25T08:02:00.000Z", finishedAt: "2026-07-25T08:03:00.000Z" },
      post: { ...scanRequest.observations.post, observedAt: "2026-07-25T08:04:00.000Z" },
    },
    generatedAt: "2026-07-25T08:05:00.000Z",
  };
  assert.throws(() => validateDastScanRequest(stale, requestOptions), /expired/);
});

test("wrong candidate workflow producer fails closed", () => {
  assert.throws(
    () => validateDastScanRequest({
      ...scanRequest,
      producer: { ...scanRequest.producer, workflowPath: ".github/workflows/attacker.yml" },
    }, requestOptions),
    /producer/,
  );
});

test("EXTERNAL-PENDING policy cannot accept staging or DAST evidence", () => {
  assert.throws(
    () => validateStagingDeploymentReceipt(stagingReceipt, {
      ...stagingOptions,
      policy: {
        ...policy,
        stagingDast: { ...policy.stagingDast, status: "EXTERNAL-PENDING", canonicalTarget: null },
      },
    }),
    /EXTERNAL-PENDING/,
  );
});

test("offline CLI rejects empty reports and emits only a pending request for real semantic pass", (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "platform-dast-runtime-cli-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const writeJson = (name, value) => {
    const pathname = path.join(directory, name);
    fs.writeFileSync(pathname, `${JSON.stringify(value)}\n`, { mode: 0o600 });
    return pathname;
  };
  const digest = (pathname) => hashBytes(fs.readFileSync(pathname));
  const artifactPath = writeJson("artifact.json", artifactReceipt);
  const runtimeDeployment = {
    ...deploymentReceipt,
    artifactVerificationReceiptSha256: digest(artifactPath),
  };
  const deploymentPath = writeJson("deployment.json", runtimeDeployment);
  const probePath = writeJson("probe.json", probe);
  const runtimeStaging = {
    ...stagingReceipt,
    artifactVerificationReceiptSha256: digest(artifactPath),
    deploymentAdmissionReceiptSha256: digest(deploymentPath),
    probe: { path: identityPath, sha256: digest(probePath) },
  };
  const stagingPath = writeJson("staging.json", runtimeStaging);
  const providerPath = writeJson("provider.json", providerMetadata);
  const policyPath = writeJson("policy.json", policy);
  const prePath = path.join(directory, "pre.json");
  const postPath = path.join(directory, "post.json");
  fs.copyFileSync(probePath, prePath);
  fs.copyFileSync(probePath, postPath);
  const jsonPath = writeJson("zap-baseline.json", {
    "@version": "2.16.1",
    "@generated": zapGeneratedAt,
    site: [{
      "@name": target,
      "@host": targetHost,
      "@port": "443",
      "@ssl": "true",
      alerts: [],
    }],
  });
  const htmlPath = path.join(directory, "zap-baseline.html");
  const xmlPath = path.join(directory, "zap-baseline.xml");
  fs.writeFileSync(htmlPath, `<html><title>ZAP Scanning Report</title><body>${targetHost}</body></html>\n`);
  fs.writeFileSync(xmlPath, `<OWASPZAPReport><site name="${targetHost}"/></OWASPZAPReport>\n`);
  const requestPath = path.join(directory, "request.json");
  const common = [
    "--policy", policyPath,
    "--artifactReceipt", artifactPath,
    "--artifactReceiptSha256", digest(artifactPath),
    "--deploymentReceipt", deploymentPath,
    "--deploymentReceiptSha256", digest(deploymentPath),
    "--providerMetadata", providerPath,
    "--providerMetadataSha256", digest(providerPath),
    "--stagingReceipt", stagingPath,
    "--stagingReceiptSha256", digest(stagingPath),
    "--repo", repository,
    "--commit", commitSha,
    "--tree", treeSha,
    "--providerRunId", provider.runId,
    "--providerRunAttempt", String(provider.runAttempt),
    "--consumerRunId", consumerChallenge.consumerRunId,
    "--consumerRunAttempt", String(consumerChallenge.consumerRunAttempt),
    "--consumerJob", consumerChallenge.consumerJob,
    "--challengeNonce", challengeNonce,
    "--runtimeIntentSha256", runtimeIntentSha,
    "--workflowPath", candidateProducer.workflowPath,
    "--sourceRef", candidateProducer.sourceRef,
    "--event", candidateProducer.event,
    "--runId", candidateProducer.runId,
    "--runAttempt", String(candidateProducer.runAttempt),
    "--job", candidateProducer.job,
    "--now", now,
  ];
  const emitArgs = [
    ...common,
    "--preProbe", prePath,
    "--preObservedAt", preObservedAt,
    "--scanStartedAt", scanStartedAt,
    "--scanFinishedAt", scanFinishedAt,
    "--postProbe", postPath,
    "--postObservedAt", postObservedAt,
    "--generatedAt", requestGeneratedAt,
    "--zapImage", reportEvidence.engineImage,
    "--zapJson", jsonPath,
    "--zapHtml", htmlPath,
    "--zapXml", xmlPath,
    "--reportArtifactName", reportEvidence.artifactName,
    "--scanRequestOutput", requestPath,
  ];
  const result = JSON.parse(execFileSync(process.execPath, [
    "scripts/dast-runtime-receipt-policy.mjs",
    ...emitArgs,
  ], { encoding: "utf8" }));
  assert.equal(result.status, "PENDING-PROVIDER-ATTESTATION");
  assert.equal(JSON.parse(fs.readFileSync(requestPath, "utf8")).status, "PENDING-PROVIDER-ATTESTATION");

  const emptyJson = writeJson("empty.json", {
    "@version": "2.16.1",
    "@generated": zapGeneratedAt,
    site: [],
  });
  assert.throws(() => execFileSync(process.execPath, [
    "scripts/dast-runtime-receipt-policy.mjs",
    ...emitArgs.map((value) => value === jsonPath ? emptyJson : value)
      .map((value) => value === requestPath ? path.join(directory, "empty-request.json") : value),
  ], { encoding: "utf8", stdio: "pipe" }), /Command failed/);
  assert.throws(() => execFileSync(process.execPath, [
    "scripts/dast-runtime-receipt-policy.mjs",
    ...common,
    "--receiptOutput", path.join(directory, "self-issued.json"),
  ], { encoding: "utf8", stdio: "pipe" }), /Command failed/);
});

test("trusted challenge generator creates fresh CSPRNG nonces and rejects caller nonce", (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "platform-dast-challenge-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const generate = (name) => JSON.parse(execFileSync(process.execPath, [
    "scripts/dast-runtime-receipt-policy.mjs",
    "--repo", repository,
    "--consumerRunId", consumerChallenge.consumerRunId,
    "--consumerRunAttempt", String(consumerChallenge.consumerRunAttempt),
    "--consumerJob", consumerChallenge.consumerJob,
    "--challengeOutput", path.join(directory, name),
  ], { encoding: "utf8" }));
  const first = generate("first.json");
  const second = generate("second.json");
  assert.match(first.challengeNonce, /^[a-f0-9]{64}$/);
  assert.notEqual(first.challengeNonce, second.challengeNonce);
  assert.throws(() => execFileSync(process.execPath, [
    "scripts/dast-runtime-receipt-policy.mjs",
    "--repo", repository,
    "--consumerRunId", consumerChallenge.consumerRunId,
    "--consumerRunAttempt", String(consumerChallenge.consumerRunAttempt),
    "--consumerJob", consumerChallenge.consumerJob,
    "--challengeNonce", challengeNonce,
    "--challengeOutput", path.join(directory, "forged.json"),
  ], { encoding: "utf8", stdio: "pipe" }), /Command failed/);
});
