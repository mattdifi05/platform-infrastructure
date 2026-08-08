#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  activationRequestSha256,
  validateActivationReceipt,
} from "./activation-receipt-policy.mjs";
import { canonicalJson } from "./runtime-intent-policy.mjs";

const contractPath = process.env.DOCKER_ACTION_CONTRACT_PATH
  ?? path.resolve(path.dirname(new URL(import.meta.url).pathname), "docker-action-contract.mjs");
const fixturesPath = process.env.DOCKER_ACTION_FIXTURES_PATH
  ?? path.resolve(path.dirname(new URL(import.meta.url).pathname), "docker-action-v2-fixtures.mjs");
let dockerActionContract;
let dockerActionFixtures;
try {
  dockerActionContract = await import(pathToFileURL(contractPath));
  dockerActionFixtures = await import(pathToFileURL(fixturesPath));
} catch (error) {
  throw new Error(
    `Integration blocker: authoritative Docker active-receipt v2 contract/fixtures are absent: ${String(error?.message ?? error)}`,
  );
}

assert.equal(dockerActionContract.ACTIVE_RECEIPT_SCHEMA, "platform.docker-active-receipt/v2");
const brokerNow = dockerActionFixtures.FIXTURE_NOW;
const sha = (character) => character.repeat(64);
const request = {
  schema: "platform-activation-request/v3",
  requestId: `activation:${sha("a")}:${sha("b")}`,
  deploymentTarget: {
    environment: "production",
    host: "example.internal",
    projectName: "platform_infra_vps",
  },
  sshPort: 2222,
  releaseContext: {
    schema: "platform-trusted-release-context/v3",
    repository: "owner/repo",
    commitSha: "c".repeat(40),
    treeSha: "d".repeat(40),
    sourceArchiveSha256: sha("e"),
    releaseId: `${"c".repeat(40)}-${sha("e")}`,
    releaseRoot: `/srv/platform-infrastructure/releases/${"c".repeat(40)}-${sha("e")}`,
    stateId: `${"c".repeat(40)}-${sha("e")}-${sha("f")}`,
    stateRoot: `/srv/platform-infrastructure/release-states/${"c".repeat(40)}-${sha("e")}-${sha("f")}`,
    environmentFile: `/srv/platform-infrastructure/release-states/${"c".repeat(40)}-${sha("e")}-${sha("f")}/environment.env`,
    environmentSha256: sha("f"),
    projectName: "platform_infra_vps",
    decisionId: "decision:12345678",
    provider: {
      metadataSha256: sha("1"),
      runId: "123456",
      attempt: 2,
      challenge: sha("2"),
    },
    receipts: {
      artifactSha256: sha("3"),
      deploymentSha256: sha("a"),
      dastProviderSha256: sha("4"),
      dastAuthorizationSha256: sha("5"),
    },
    dastChainSha256: sha("6"),
    runtimeIntentSha256: sha("7"),
    subjects: [
      {
        serviceName: "app",
        imageReference: `ghcr.io/owner/app@sha256:${sha("6")}`,
        imageId: `sha256:${sha("7")}`,
      },
      {
        serviceName: "backup-scheduler",
        imageReference: `ghcr.io/owner/platform-infrastructure-backup-scheduler@sha256:${sha("8")}`,
        imageId: `sha256:${sha("9")}`,
      },
    ],
    hostedLockSha256: null,
    noHosted: true,
    sourceRenderSha256: sha("0"),
    combinedRenderSha256: sha("1"),
    persistentVolumes: [{
      name: "enterprise_local_registry_data",
      createdAt: "2026-07-21T00:00:00.000Z",
      driver: "local",
      scope: "local",
      options: {},
      labels: {
        "platform.infrastructure.managed": "true",
        "platform.infrastructure.purpose": "local-registry",
      },
      mountpoint: "/var/lib/docker/volumes/enterprise_local_registry_data/_data",
      owner: { uid: 0, gid: 0, mode: "0755" },
    }],
  },
  releaseContextSha256: sha("b"),
  runtimeIntentSha256: sha("7"),
  privilegedRuntime: {
    activationBroker: {
      path: "/usr/local/libexec/platform-activation-broker",
      version: 1,
      sha256: sha("a"),
      providerAttested: true,
    },
    originFirewallHelper: {
      path: "/usr/local/libexec/platform-origin-firewall",
      version: 1,
      sha256: sha("b"),
      providerAttested: true,
    },
    workloadEgressHelper: {
      path: "/usr/local/libexec/platform-workload-egress-firewall",
      version: 1,
      sha256: sha("c"),
      providerAttested: true,
    },
  },
  releaseBundle: {
    schema: "platform-activation-bundle-descriptor/v2",
    sha256: sha("d"),
    sizeBytes: 4096,
    manifestSha256: sha("e"),
  },
  dockerActivationEnvelope: {
    schema: "platform-docker-runtime-activation-envelope-descriptor/v1",
    sha256: sha("f"),
    sizeBytes: 8192,
    payloadType: "application/vnd.platform.docker-runtime-activation.v2+json",
    runtimeIntentId: "runtime.production",
    generation: 2,
    dastAuthorizationSha256: sha("5"),
    dastChainSha256: sha("6"),
  },
  dockerRuntime: {
    releaseId: `release.${sha("a")}`,
    candidateId: `candidate.${sha("b")}`,
    targetId: `target.${sha("c")}`,
    treeSha256: sha("d"),
  },
  requestedOperations: [
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
  ],
};
request.releaseContextSha256 = crypto.createHash("sha256")
  .update(canonicalJson(request.releaseContext), "utf8")
  .digest("hex");
request.requestId = `activation:${sha("a")}:${request.releaseContextSha256}`;

function boundDockerActiveReceipt() {
  const active = dockerActionFixtures.buildRawActiveReceiptV2({ now: brokerNow });
  active.activationBundleSha256 = request.dockerActivationEnvelope.sha256;
  active.releaseId = request.dockerRuntime.releaseId;
  active.candidateId = request.dockerRuntime.candidateId;
  active.targetId = request.dockerRuntime.targetId;
  active.treeSha256 = request.dockerRuntime.treeSha256;
  active.environment = request.deploymentTarget.environment;
  active.sourceRenderSha256 = request.releaseContext.sourceRenderSha256;
  active.combinedRenderSha256 = request.releaseContext.combinedRenderSha256;
  active.dastChainSha256 = request.releaseContext.dastChainSha256;
  for (const container of Object.values(active.resources.containers)) {
    container.labels["com.platform.runtime.candidate-id"] = active.candidateId;
    container.labels["com.platform.runtime.source-render-sha256"] = active.sourceRenderSha256;
  }
  return active;
}

function activeReceiptSha256(activeReceipt) {
  const normalized = dockerActionContract.normalizeActiveReceipt(activeReceipt, { now: brokerNow });
  return dockerActionContract.sha256(dockerActionContract.canonicalJson(normalized));
}

function validReceipt() {
  const activeReceipt = boundDockerActiveReceipt();
  return {
    schema: "platform-activation-receipt/v3",
    status: "ACTIVE",
    activatedAt: activeReceipt.issuedAt,
    requestId: request.requestId,
    requestSha256: activationRequestSha256(request),
    releaseContextSha256: request.releaseContextSha256,
    runtimeIntentSha256: request.runtimeIntentSha256,
    releaseBundleSha256: request.releaseBundle.sha256,
    dockerActivationEnvelopeSha256: request.dockerActivationEnvelope.sha256,
    dastAuthorizationSha256: request.releaseContext.receipts.dastAuthorizationSha256,
    dastChainSha256: request.releaseContext.dastChainSha256,
    deploymentTarget: structuredClone(request.deploymentTarget),
    broker: structuredClone(request.privilegedRuntime.activationBroker),
    activeReceipt,
    activeReceiptSha256: activeReceiptSha256(activeReceipt),
    operationResults: request.requestedOperations.map((name) => ({
      name,
      status: name === "rollback-on-failure" ? "not-required" : "passed",
    })),
  };
}

const validate = (receipt, activationRequest = request) => validateActivationReceipt(receipt, activationRequest, {
  dockerActionContract,
  now: brokerNow,
});
const valid = validReceipt();
assert.deepEqual(validate(valid), valid);
const digestSentinels = [
  request.releaseBundle.sha256,
  request.dockerActivationEnvelope.sha256,
  request.releaseContext.receipts.dastProviderSha256,
  request.releaseContext.receipts.dastAuthorizationSha256,
  request.releaseContext.dastChainSha256,
];
assert.equal(new Set(digestSentinels).size, digestSentinels.length);
assert.equal(Object.keys(valid.activeReceipt.resources.helperProfiles).length, 13);
assert.deepEqual(Object.keys(valid.activeReceipt.resources.serviceEndpoints).sort(), [
  "capture.database.mariadb",
  "capture.database.postgres",
  "capture.storage.minio",
  "offsite.repository",
]);
assert.notEqual(
  valid.activeReceipt.resources.helperProfiles["helper.capture.postgres"].imageRef.split("@").at(-1),
  valid.activeReceipt.resources.helperProfiles["helper.capture.postgres"].imageId,
);

const outerMutations = [
  ["extra receipt key", (value) => { value.attacker = true; }],
  ["non-active status", (value) => { value.status = "FAILED"; }],
  ["wrong request ID", (value) => { value.requestId = `activation:${sha("9")}:${sha("b")}`; }],
  ["wrong request hash", (value) => { value.requestSha256 = sha("9"); }],
  ["wrong release context", (value) => { value.releaseContextSha256 = sha("9"); }],
  ["wrong runtime intent", (value) => { value.runtimeIntentSha256 = sha("9"); }],
  ["wrong release bundle", (value) => { value.releaseBundleSha256 = sha("9"); }],
  ["wrong activation envelope", (value) => { value.dockerActivationEnvelopeSha256 = sha("9"); }],
  ["wrong DAST authorization", (value) => { value.dastAuthorizationSha256 = sha("9"); }],
  ["wrong DAST chain", (value) => { value.dastChainSha256 = sha("9"); }],
  ["wrong target", (value) => { value.deploymentTarget.host = "attacker.internal"; }],
  ["wrong broker", (value) => { value.broker.sha256 = sha("9"); }],
  ["missing operation", (value) => { value.operationResults.pop(); }],
  ["failed operation", (value) => { value.operationResults[0].status = "failed"; }],
];
for (const [label, mutate] of outerMutations) {
  const candidate = validReceipt();
  mutate(candidate);
  assert.throws(() => validate(candidate), undefined, label);
}

for (const [label, mutate] of [
  ["missing helper profile", (value) => { delete value.activeReceipt.resources.helperProfiles["helper.capture.postgres"]; }],
  ["phase helper widening", (value) => { value.activeReceipt.resources.phaseProfiles["prune.plan"].helperProfileIds = ["helper.offsite.restic"]; }],
  ["mutable helper image", (value) => { value.activeReceipt.resources.helperProfiles["helper.capture.postgres"].imageRef = "postgres:latest"; }],
  ["invalid helper image ID", (value) => { value.activeReceipt.resources.helperProfiles["helper.capture.postgres"].imageId = "sha256:invalid"; }],
  ["worker/helper secret conflation", (value) => { value.activeReceipt.resources.helperProfiles["helper.capture.postgres"].secretSetId = "manifest.signing"; }],
  ["private offsite host", (value) => { value.activeReceipt.resources.serviceEndpoints["offsite.repository"].host = "backup.internal"; }],
]) {
  const candidate = validReceipt();
  mutate(candidate);
  assert.throws(() => validate(candidate), undefined, label);
}

for (const [label, mutate] of [
  ["release bundle cannot substitute for envelope", (value) => {
    value.activeReceipt.activationBundleSha256 = request.releaseBundle.sha256;
  }],
  ["provider receipt cannot substitute for chain", (value) => {
    value.activeReceipt.dastChainSha256 = request.releaseContext.receipts.dastProviderSha256;
  }],
  ["authorization cannot substitute for chain", (value) => {
    value.activeReceipt.dastChainSha256 = request.releaseContext.receipts.dastAuthorizationSha256;
  }],
]) {
  const candidate = validReceipt();
  mutate(candidate);
  candidate.activeReceiptSha256 = activeReceiptSha256(candidate.activeReceipt);
  assert.throws(() => validate(candidate), undefined, label);
}

for (const [label, mutate] of [
  ["active receipt digest", (value) => { value.activeReceiptSha256 = sha("9"); }],
  ["active envelope binding", (value) => { value.activeReceipt.activationBundleSha256 = sha("9"); }],
  ["active release binding", (value) => { value.activeReceipt.releaseId = "release.attacker"; }],
  ["active candidate binding", (value) => {
    value.activeReceipt.candidateId = "candidate.attacker";
    for (const container of Object.values(value.activeReceipt.resources.containers)) {
      container.labels["com.platform.runtime.candidate-id"] = value.activeReceipt.candidateId;
    }
  }],
  ["active generation binding", (value) => { value.activeReceipt.generation += 1; }],
  ["active DAST binding", (value) => { value.activeReceipt.dastChainSha256 = sha("9"); }],
]) {
  const candidate = validReceipt();
  mutate(candidate);
  if (label !== "active receipt digest") {
    candidate.activeReceiptSha256 = activeReceiptSha256(candidate.activeReceipt);
  }
  assert.throws(() => validate(candidate), undefined, label);
}

assert.throws(
  () => validateActivationReceipt(valid, request, { now: brokerNow }),
  /authoritative Docker active-receipt v2 normalizer is unavailable/,
);
assert.throws(
  () => validate(valid, { ...request, attacker: true }),
  /request.*closed schema/i,
);
const aliasedDigestRequest = structuredClone(request);
aliasedDigestRequest.releaseBundle.sha256 = aliasedDigestRequest.dockerActivationEnvelope.sha256;
assert.throws(() => validate(valid, aliasedDigestRequest), /digests must be distinct/);
const unhashedSchedulerMutation = structuredClone(request);
unhashedSchedulerMutation.releaseContext.subjects[1].imageId = `sha256:${sha("0")}`;
assert.throws(() => validate(valid, unhashedSchedulerMutation), /context SHA256/);
for (const imageReference of [
  "ghcr.io/owner/platform-infrastructure-backup-scheduler:latest",
  `ghcr.io/owner/attacker@sha256:${sha("8")}`,
]) {
  const candidate = structuredClone(request);
  candidate.releaseContext.subjects[1].imageReference = imageReference;
  candidate.releaseContextSha256 = crypto.createHash("sha256")
    .update(canonicalJson(candidate.releaseContext), "utf8")
    .digest("hex");
  candidate.requestId = `activation:${sha("a")}:${candidate.releaseContextSha256}`;
  assert.throws(() => validate(valid, candidate));
}

process.stdout.write("activation receipt outer/integrated broker policy tests passed 42/42\n");
