#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { canonicalJson, runtimeIntentSha256 } from "./runtime-intent-policy.mjs";
import {
  AUTHORIZATION_KIND,
  RECEIPT_KIND,
  validateHostedPreparationConformanceContract,
  validateHostedPreparationProviderConformance,
} from "./hosted-preparation-provider-conformance.mjs";

const NOW = Date.parse("2026-08-08T12:00:00.000Z");
const AUTHORIZATION_PAYLOAD_TYPE = "application/vnd.platform.hosted-preparation-authorization.v1+json";
const RECEIPT_PAYLOAD_TYPE = "application/vnd.platform.hosted-preparation-receipt.v1+json";
const MODULE = new URL("./hosted-preparation-provider-conformance.mjs", import.meta.url);
const CONTRACT_PATH = new URL("../governance/hosted-preparation-provider-conformance.json", import.meta.url);
const PENDING_CONTRACT = JSON.parse(fs.readFileSync(CONTRACT_PATH, "utf8"));
const providerKeys = crypto.generateKeyPairSync("ed25519");
const rootKeys = crypto.generateKeyPairSync("ed25519");
const wrongKeys = crypto.generateKeyPairSync("ed25519");

function keyId(publicKey) {
  return crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function dssePae(payloadType, payload) {
  const type = Buffer.from(payloadType, "utf8");
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, "ascii"),
    type,
    Buffer.from(` ${payload.length} `, "ascii"),
    payload,
  ]);
}

function artifact(document) {
  return { bytes: Buffer.from(`${canonicalJson(document)}\n`, "utf8") };
}

function envelopeArtifact(payload, payloadType, privateKey, signerKeyId) {
  const payloadBytes = Buffer.from(canonicalJson(payload), "utf8");
  const signature = crypto.sign(null, dssePae(payloadType, payloadBytes), privateKey);
  return artifact({
    payload: payloadBytes.toString("base64"),
    payloadType,
    signatures: [{ keyid: signerKeyId, sig: signature.toString("base64") }],
  });
}

function readyContract() {
  return {
    ...structuredClone(PENDING_CONTRACT),
    status: "READY",
    reason: "Independent provider conformance fixture is configured.",
    authorization: {
      ...PENDING_CONTRACT.authorization,
      providerKeyId: keyId(providerKeys.publicKey),
      providerPublicKeyPem: providerKeys.publicKey.export({ type: "spki", format: "pem" }),
    },
    trustedProducer: {
      repository: "independent/provider-control-plane",
      workflowPath: ".github/workflows/trusted-deployment.yml",
      workflowSha: "9".repeat(40),
      sourceRef: "refs/heads/main",
      event: "workflow_dispatch",
    },
    preparationBroker: {
      path: "/usr/local/libexec/platform-hosted-preparation-broker",
      version: 1,
      sha256: "8".repeat(64),
      providerAttested: true,
    },
  };
}

function fixture(now = NOW) {
  const contract = readyContract();
  const repository = "candidate/platform-infrastructure";
  const commitSha = "1".repeat(40);
  const treeSha = "2".repeat(40);
  const sourceArchiveSha256 = "3".repeat(64);
  const environmentSha256 = "4".repeat(64);
  const artifactVerificationReceiptSha256 = "5".repeat(64);
  const releaseId = `${commitSha}-${sourceArchiveSha256}`;
  const stateId = `${releaseId}-${environmentSha256}`;
  const releaseRoot = `/srv/platform-infrastructure/releases/${releaseId}`;
  const stateRoot = `/srv/platform-infrastructure/release-states/${stateId}`;
  const lockPath = `${stateRoot}/hosted-preparation/hosted-workloads.lock.json`;
  const target = {
    environment: "production",
    host: "vps.example.internal",
    projectName: "platform_infra_vps",
    sshHostKeySha256: "6".repeat(64),
    dockerDaemonId: "daemon.primary-01",
    deploymentUid: 1001,
    deploymentGid: 1001,
  };
  const releaseIdentity = {
    releaseId,
    releaseRoot,
    stateId,
    stateRoot,
    environmentFile: `${stateRoot}/environment.env`,
    environmentSha256,
  };
  const opsRunner = {
    image: `ghcr.io/independent/platform-ops@sha256:${"7".repeat(64)}`,
    imageId: `sha256:${"a".repeat(64)}`,
    verificationFingerprint: "b".repeat(64),
    providerAttested: true,
  };
  const producer = {
    ...contract.trustedProducer,
    runId: "123456",
    runAttempt: 2,
  };
  const consumerChallenge = {
    consumerRepository: repository,
    consumerRunId: "654321",
    consumerRunAttempt: 3,
    consumerJob: "deploy-vps",
    challengeNonce: "c".repeat(64),
  };
  const authorization = {
    version: 1,
    kind: AUTHORIZATION_KIND,
    status: "AUTHORIZED",
    authorizationId: "hosted-preparation:123456",
    operation: "prepare-hosted-workloads-v1",
    repository,
    commitSha,
    treeSha,
    sourceArchiveSha256,
    artifactVerificationReceiptSha256,
    deploymentTarget: target,
    releaseIdentity,
    environmentAuthority: { uid: 0, gid: target.deploymentGid, mode: 0o640, nlink: 1 },
    opsRunner,
    preparationBroker: contract.preparationBroker,
    receiptSigner: {
      algorithm: "ed25519",
      keyId: keyId(rootKeys.publicKey),
      publicKeyPem: rootKeys.publicKey.export({ type: "spki", format: "pem" }),
    },
    consumerChallenge,
    producer,
    nonce: "N".repeat(43),
    issuedAt: new Date(now - 60_000).toISOString(),
    notBefore: new Date(now - 60_000).toISOString(),
    expiresAt: new Date(now + 5 * 60_000).toISOString(),
  };
  const authorizationArtifact = envelopeArtifact(
    authorization,
    AUTHORIZATION_PAYLOAD_TYPE,
    providerKeys.privateKey,
    keyId(providerKeys.publicKey),
  );
  const environmentIdentity = {
    path: releaseIdentity.environmentFile,
    sha256: environmentSha256,
    device: "2049",
    inode: "90001",
    uid: 0,
    gid: target.deploymentGid,
    mode: 0o640,
    nlink: 1,
    size: 4096,
  };
  const sourceRenderSha256 = "d".repeat(64);
  const combinedComposeSha256 = "e".repeat(64);
  const receipt = {
    version: 1,
    kind: RECEIPT_KIND,
    status: "PREPARED",
    authorizationEnvelopeSha256: sha256(authorizationArtifact.bytes),
    authorizationId: authorization.authorizationId,
    nonce: authorization.nonce,
    repository,
    commitSha,
    treeSha,
    sourceArchiveSha256,
    artifactVerificationReceiptSha256,
    deploymentTarget: target,
    releaseIdentity,
    environmentBefore: environmentIdentity,
    environmentAfter: environmentIdentity,
    opsRunner,
    preparationBroker: contract.preparationBroker,
    lock: {
      path: lockPath,
      sha256: "f".repeat(64),
      device: "2049",
      inode: "90002",
      uid: target.deploymentUid,
      gid: target.deploymentGid,
      mode: 0o600,
      nlink: 1,
      size: 32768,
      version: 4,
      validatorVersion: "hosted-contract-v4",
      state: "verified",
      coreRenderSha256: sourceRenderSha256,
      combinedRenderSha256: combinedComposeSha256,
    },
    snapshot: {
      parentPath: path.posix.dirname(lockPath),
      rootPath: `${path.posix.dirname(lockPath)}/snapshots`,
      generationPath: `${path.posix.dirname(lockPath)}/snapshots/generation-00000001`,
      parentIdentity: { device: "2049", inode: "90003", uid: target.deploymentUid, gid: target.deploymentGid, mode: 0o700, nlink: 3 },
      rootIdentity: { device: "2049", inode: "90004", uid: target.deploymentUid, gid: target.deploymentGid, mode: 0o700, nlink: 3 },
      generationIdentity: { device: "2049", inode: "90005", uid: target.deploymentUid, gid: target.deploymentGid, mode: 0o500, nlink: 2 },
      durability: { version: 1, filesFsynced: true, generationDirectoryFsynced: true, rootDirectoryFsynced: true },
    },
    sourceRenderSha256,
    combinedComposeSha256,
    nonMutationProof: {
      activeSelectorBeforeSha256: "0".repeat(64),
      activeSelectorAfterSha256: "0".repeat(64),
      runtimeInventoryBeforeSha256: "1".repeat(64),
      runtimeInventoryAfterSha256: "1".repeat(64),
      firewallStateBeforeSha256: "2".repeat(64),
      firewallStateAfterSha256: "2".repeat(64),
    },
    preparedAt: new Date(now - 30_000).toISOString(),
    expiresAt: new Date(now + 60 * 60_000).toISOString(),
  };
  const receiptArtifact = envelopeArtifact(
    receipt,
    RECEIPT_PAYLOAD_TYPE,
    rootKeys.privateKey,
    keyId(rootKeys.publicKey),
  );
  const runtimeIntent = {
    version: 2,
    kind: "platform-runtime-intent/v2",
    repository,
    commitSha,
    treeSha,
    sourceArchiveSha256,
    projectName: target.projectName,
    environmentSha256,
    hostedWorkloadLockSha256: receipt.lock.sha256,
    sourceRenderSha256,
    combinedComposeSha256,
    persistentVolumes: [{
      name: "enterprise_local_registry_data",
      createdAt: "2026-08-08T11:50:00.000Z",
      driver: "local",
      scope: "local",
      options: {},
      labels: { "platform.infrastructure.managed": "true", "platform.infrastructure.purpose": "local-registry" },
      mountpoint: "/var/lib/docker/volumes/enterprise_local_registry_data/_data",
      owner: { uid: 0, gid: 0, mode: "0700" },
    }],
    services: [{
      service: "app",
      image: `ghcr.io/candidate/app@sha256:${"3".repeat(64)}`,
      admission: { kind: "artifact-subject", subjectKey: "APP_IMAGE" },
      expectedLocalImageId: `sha256:${"4".repeat(64)}`,
    }],
    targetServingServices: ["app"],
  };
  const deploymentReceipt = {
    version: 1,
    kind: "platform-trusted-deployment-admission/v1",
    status: "READY",
    artifactVerification: "passed",
    deploymentAdmission: "READY",
    repository,
    commitSha,
    treeSha,
    sourceArchiveSha256,
    artifactVerificationReceiptSha256,
    manifestSha256: "3".repeat(64),
    sbomSha256: "4".repeat(64),
    generatedAt: new Date(now - 10_000).toISOString(),
    decisionId: "deployment:decision:123456",
    verifier: {
      channel: "independent-provider",
      fingerprint: "5".repeat(64),
      selfAsserted: false,
      verifiedAt: new Date(now - 10_000).toISOString(),
    },
    producer,
    consumerChallenge,
    opsRunner,
    runtimeIntent,
    runtimeIntentSha256: runtimeIntentSha256(runtimeIntent),
    deploymentTarget: {
      environment: target.environment,
      host: target.host,
      projectName: target.projectName,
    },
    privilegedRuntime: {
      activationBroker: { path: "/usr/local/libexec/platform-activation-broker", version: 1, sha256: "6".repeat(64), providerAttested: true },
      originFirewallHelper: { path: "/usr/local/libexec/platform-origin-firewall", version: 1, sha256: "7".repeat(64), providerAttested: true },
      workloadEgressHelper: { path: "/usr/local/libexec/platform-workload-egress-firewall", version: 1, sha256: "8".repeat(64), providerAttested: true },
    },
  };
  return {
    contract,
    authorization,
    authorizationArtifact,
    receipt,
    receiptArtifact,
    deploymentReceipt,
    deploymentReceiptArtifact: artifact(deploymentReceipt),
  };
}

function validate(value = fixture()) {
  return validateHostedPreparationProviderConformance({
    contract: value.contract,
    authorizationArtifact: value.authorizationArtifact,
    receiptArtifact: value.receiptArtifact,
    deploymentReceiptArtifact: value.deploymentReceiptArtifact,
    now: NOW,
  });
}

function resignAuthorization(value, privateKey = providerKeys.privateKey, signerKeyId = keyId(providerKeys.publicKey)) {
  return envelopeArtifact(value, AUTHORIZATION_PAYLOAD_TYPE, privateKey, signerKeyId);
}

function resignReceipt(value, privateKey = rootKeys.privateKey, signerKeyId = keyId(rootKeys.publicKey)) {
  return envelopeArtifact(value, RECEIPT_PAYLOAD_TYPE, privateKey, signerKeyId);
}

test("repository contract remains versioned and EXTERNAL-PENDING without provider evidence", () => {
  assert.deepEqual(validateHostedPreparationConformanceContract(PENDING_CONTRACT, { requireReady: false }), {
    status: "EXTERNAL-PENDING",
  });
  assert.throws(
    () => validateHostedPreparationConformanceContract(PENDING_CONTRACT),
    /EXTERNAL-PENDING/,
  );
});

test("explicit A/R/D artifacts can satisfy only the acyclic structural invariant", () => {
  const result = validate();
  assert.equal(result.status, "STRUCTURALLY_CONSISTENT_NON_AUTHORITATIVE");
  assert.equal(result.authoritativeEvidence, false);
  assert.match(result.authorizationEnvelopeSha256, /^[a-f0-9]{64}$/);
  assert.match(result.preparationReceiptEnvelopeSha256, /^[a-f0-9]{64}$/);
  assert.match(result.finalDeploymentAdmissionSha256, /^[a-f0-9]{64}$/);
});

test("authorization schema forbids final output/runtime bindings", () => {
  const value = fixture();
  value.authorization.hostedWorkloadLockSha256 = "0".repeat(64);
  value.authorizationArtifact = resignAuthorization(value.authorization);
  assert.throws(() => validate(value), /authorization.*exact closed schema/i);

  const runtimeValue = fixture();
  runtimeValue.authorization.runtimeIntentSha256 = "0".repeat(64);
  runtimeValue.authorizationArtifact = resignAuthorization(runtimeValue.authorization);
  assert.throws(() => validate(runtimeValue), /authorization.*exact closed schema/i);
});

test("candidate or wrong provider cannot forge preliminary authorization", () => {
  const value = fixture();
  value.authorizationArtifact = resignAuthorization(value.authorization, wrongKeys.privateKey, keyId(wrongKeys.publicKey));
  assert.throws(() => validate(value), /key ID|signature/);

  const candidate = fixture();
  candidate.authorization.producer = {
    ...candidate.authorization.producer,
    repository: candidate.authorization.repository,
  };
  candidate.authorizationArtifact = resignAuthorization(candidate.authorization);
  assert.throws(() => validate(candidate), /configured independent provider|not independent/);
});

test("provider configuration rejects PKCS#8 private key PEM as public-key input", () => {
  const value = fixture();
  value.contract.authorization.providerPublicKeyPem = providerKeys.privateKey.export({
    type: "pkcs8",
    format: "pem",
  });
  assert.throws(() => validate(value), /canonical SPKI public key PEM/);
});

test("delegated target-root signer rejects PKCS#8 private key PEM", () => {
  const value = fixture();
  value.authorization.receiptSigner.publicKeyPem = rootKeys.privateKey.export({
    type: "pkcs8",
    format: "pem",
  });
  value.authorizationArtifact = resignAuthorization(value.authorization);
  assert.throws(() => validate(value), /canonical SPKI public key PEM/);
});

test("receipt must bind the exact authorization envelope and target-root signature", () => {
  const wrongHash = fixture();
  wrongHash.receipt.authorizationEnvelopeSha256 = "0".repeat(64);
  wrongHash.receiptArtifact = resignReceipt(wrongHash.receipt);
  assert.throws(() => validate(wrongHash), /exact preliminary authorization/);

  const wrongSignature = fixture();
  wrongSignature.receiptArtifact = resignReceipt(wrongSignature.receipt, wrongKeys.privateKey, keyId(wrongKeys.publicKey));
  assert.throws(() => validate(wrongSignature), /key ID|signature/);
});

test("nonce replay, future and expired authorization windows fail closed", () => {
  const replay = fixture();
  replay.receipt.nonce = "R".repeat(43);
  replay.receiptArtifact = resignReceipt(replay.receipt);
  assert.throws(() => validate(replay), /exact preliminary authorization/);

  const future = fixture();
  future.authorization.issuedAt = new Date(NOW + 60_000).toISOString();
  future.authorization.notBefore = new Date(NOW + 60_000).toISOString();
  future.authorization.expiresAt = new Date(NOW + 120_000).toISOString();
  future.authorizationArtifact = resignAuthorization(future.authorization);
  assert.throws(() => validate(future), /time window/);

  const expired = fixture();
  expired.authorization.issuedAt = new Date(NOW - 10 * 60_000).toISOString();
  expired.authorization.notBefore = new Date(NOW - 10 * 60_000).toISOString();
  expired.authorization.expiresAt = new Date(NOW - 60_000).toISOString();
  expired.authorizationArtifact = resignAuthorization(expired.authorization);
  assert.throws(() => validate(expired), /time window/);
});

test("PREPARE rejects environment drift and protected runtime mutation", () => {
  const environmentDrift = fixture();
  environmentDrift.receipt.environmentAfter = {
    ...environmentDrift.receipt.environmentAfter,
    inode: "90009",
  };
  environmentDrift.receiptArtifact = resignReceipt(environmentDrift.receipt);
  assert.throws(() => validate(environmentDrift), /environment identity or bytes changed/);

  const runtimeMutation = fixture();
  runtimeMutation.receipt.nonMutationProof.runtimeInventoryAfterSha256 = "9".repeat(64);
  runtimeMutation.receiptArtifact = resignReceipt(runtimeMutation.receipt);
  assert.throws(() => validate(runtimeMutation), /changed protected runtime state/);
});

test("target, lock and snapshot substitutions fail closed", () => {
  const target = fixture();
  target.receipt.deploymentTarget = { ...target.receipt.deploymentTarget, host: "other.example.internal" };
  target.receiptArtifact = resignReceipt(target.receipt);
  assert.throws(() => validate(target), /target\/release\/ops\/broker projection/);

  const lock = fixture();
  lock.receipt.lock.path = "/tmp/hosted-workloads.lock.json";
  lock.receiptArtifact = resignReceipt(lock.receipt);
  assert.throws(() => validate(lock), /verified target-local Hosted v4 object/);

  const snapshot = fixture();
  snapshot.receipt.snapshot.generationPath = "/tmp/generation-00000001";
  snapshot.receiptArtifact = resignReceipt(snapshot.receipt);
  assert.throws(() => validate(snapshot), /snapshot paths/);
});

test("configured READY policy cannot redirect the fixed root preparation broker", () => {
  const value = fixture();
  value.contract.preparationBroker = {
    ...value.contract.preparationBroker,
    path: "/tmp/provider-broker",
  };
  value.authorization.preparationBroker = value.contract.preparationBroker;
  value.authorizationArtifact = resignAuthorization(value.authorization);
  assert.throws(() => validate(value), /fixed provider-attested preparation broker/);
});

test("final admission must bind the exact environment, lock and raw render projection", () => {
  for (const mutation of [
    (intent) => { intent.environmentSha256 = "0".repeat(64); },
    (intent) => { intent.hostedWorkloadLockSha256 = "1".repeat(64); },
    (intent) => { intent.sourceRenderSha256 = "2".repeat(64); },
    (intent) => { intent.combinedComposeSha256 = "3".repeat(64); },
  ]) {
    const value = fixture();
    mutation(value.deploymentReceipt.runtimeIntent);
    value.deploymentReceipt.runtimeIntentSha256 = runtimeIntentSha256(value.deploymentReceipt.runtimeIntent);
    value.deploymentReceiptArtifact = artifact(value.deploymentReceipt);
    assert.throws(() => validate(value), /runtime intent|environment SHA256 is mismatched/i);
  }
});

test("final admission must be the same independent provider run after PREPARE", () => {
  const crossRun = fixture();
  crossRun.deploymentReceipt.producer = { ...crossRun.deploymentReceipt.producer, runId: "123457" };
  crossRun.deploymentReceiptArtifact = artifact(crossRun.deploymentReceipt);
  assert.throws(() => validate(crossRun), /same authenticated provider run/);

  const predated = fixture();
  predated.deploymentReceipt.generatedAt = new Date(NOW - 40_000).toISOString();
  predated.deploymentReceiptArtifact = artifact(predated.deploymentReceipt);
  assert.throws(() => validate(predated), /after PREPARE/);

  const future = fixture();
  future.deploymentReceipt.generatedAt = new Date(NOW + 1).toISOString();
  future.deploymentReceiptArtifact = artifact(future.deploymentReceipt);
  assert.throws(() => validate(future), /after PREPARE/);
});

test("locally fabricated final admission never becomes authoritative evidence", () => {
  const value = fixture();
  const result = validate(value);
  assert.equal(result.authoritativeEvidence, false);
  assert.equal(result.status, "STRUCTURALLY_CONSISTENT_NON_AUTHORITATIVE");

  value.deploymentReceipt.verifier.selfAsserted = true;
  value.deploymentReceiptArtifact = artifact(value.deploymentReceipt);
  assert.throws(() => validate(value), /self-asserted/);
});

test("CLI requires all artifacts explicitly and returns only non-authoritative validation", () => {
  const value = fixture(Date.now());
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "hosted-preparation-conformance-test-"));
  try {
    const files = {
      contract: path.join(directory, "contract.json"),
      authorization: path.join(directory, "authorization.json"),
      receipt: path.join(directory, "receipt.json"),
      deploymentReceipt: path.join(directory, "deployment.json"),
    };
    fs.writeFileSync(files.contract, `${canonicalJson(value.contract)}\n`, { mode: 0o600 });
    fs.writeFileSync(files.authorization, value.authorizationArtifact.bytes, { mode: 0o600 });
    fs.writeFileSync(files.receipt, value.receiptArtifact.bytes, { mode: 0o600 });
    fs.writeFileSync(files.deploymentReceipt, value.deploymentReceiptArtifact.bytes, { mode: 0o600 });
    const positive = spawnSync(process.execPath, [
      fileURLToPath(MODULE),
      "--contract", files.contract,
      "--authorization", files.authorization,
      "--receipt", files.receipt,
      "--deploymentReceipt", files.deploymentReceipt,
    ], { encoding: "utf8" });
    assert.equal(positive.status, 0, positive.stderr);
    const result = JSON.parse(positive.stdout);
    assert.equal(result.status, "STRUCTURALLY_CONSISTENT_NON_AUTHORITATIVE");
    assert.equal(result.authoritativeEvidence, false);

    const missing = spawnSync(process.execPath, [fileURLToPath(MODULE), "--contract", files.contract], { encoding: "utf8" });
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /Usage/);

    fs.writeFileSync(files.contract, `${canonicalJson(PENDING_CONTRACT)}\n`, { mode: 0o600 });
    const pending = spawnSync(process.execPath, [
      fileURLToPath(MODULE),
      "--contract", files.contract,
      "--authorization", files.authorization,
      "--receipt", files.receipt,
      "--deploymentReceipt", files.deploymentReceipt,
    ], { encoding: "utf8" });
    assert.notEqual(pending.status, 0);
    assert.match(pending.stderr, /EXTERNAL-PENDING/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("product validator exposes no create, mint or signing capability", () => {
  const source = fs.readFileSync(MODULE, "utf8");
  assert.doesNotMatch(source, /crypto\.sign|generateKeyPair|createPrivateKey|--sign|--mint|createAuthorization|createReceipt/);
  assert.match(source, /crypto\.verify/);
  assert.doesNotMatch(source, /writeFileSync|appendFileSync/);
});

process.on("exit", () => {
  if (process.exitCode === undefined || process.exitCode === 0) {
    process.stdout.write("hosted preparation provider conformance tests completed; repository status remains EXTERNAL-PENDING\n");
  }
});
