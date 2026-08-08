#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import {
  DAST_ACTIVATION_AUTHORIZATION_SCHEMA,
  DAST_ACTIVATION_CHAIN_SCHEMA,
  dastActivationChainSha256,
  validateDastActivationAuthorization,
} from "./dast-activation-authorization.mjs";
import { canonicalJson } from "./runtime-intent-policy.mjs";

const sha = (character) => character.repeat(64);
const gitSha = (character) => character.repeat(40);
const repository = "owner/platform-infrastructure";
const consumerChallenge = {
  consumerRepository: repository,
  consumerRunId: "7654321",
  consumerRunAttempt: 3,
  consumerJob: "deploy-vps",
  challengeNonce: sha("a"),
};
const sigstoreSubject = "https://github.com/owner/platform-admission/.github/workflows/produce-admission.yml@refs/heads/main";

const expected = {
  repository,
  commitSha: gitSha("1"),
  treeSha: gitSha("2"),
  target: "https://staging.platform-infrastructure.test",
  runtimeIntentSha256: sha("3"),
  runtimeInventorySha256: sha("4"),
  targetServingInventoryHash: sha("5"),
  consumerChallenge,
  scanRequestSha256: sha("6"),
  providerReceiptSha256: sha("7"),
  providerMetadataSha256: sha("8"),
  providerRunId: "987654",
  providerRunAttempt: 2,
  reportArtifactId: "456789",
  reportArtifactArchiveSha256: sha("9"),
  reportEvidenceSha256: sha("b"),
  sigstoreBundleSha256: sha("c"),
  sigstoreSubject,
};

function challengeSha256(challenge) {
  return crypto.createHash("sha256").update(canonicalJson(challenge)).digest("hex");
}

function authorizationFixture() {
  const chain = {
    schema: DAST_ACTIVATION_CHAIN_SCHEMA,
    repository: expected.repository,
    commitSha: expected.commitSha,
    treeSha: expected.treeSha,
    target: expected.target,
    runtimeIntentSha256: expected.runtimeIntentSha256,
    runtimeInventorySha256: expected.runtimeInventorySha256,
    targetServingInventoryHash: expected.targetServingInventoryHash,
    consumerChallengeSha256: challengeSha256(consumerChallenge),
    scanRequestSha256: expected.scanRequestSha256,
    providerReceiptSha256: expected.providerReceiptSha256,
    providerMetadataSha256: expected.providerMetadataSha256,
    providerRunId: expected.providerRunId,
    providerRunAttempt: expected.providerRunAttempt,
    reportArtifactId: expected.reportArtifactId,
    reportArtifactArchiveSha256: expected.reportArtifactArchiveSha256,
    reportEvidenceSha256: expected.reportEvidenceSha256,
    sigstoreBundleSha256: expected.sigstoreBundleSha256,
    sigstoreSubject: expected.sigstoreSubject,
    verdict: "pass",
  };
  return {
    schema: DAST_ACTIVATION_AUTHORIZATION_SCHEMA,
    status: "READY",
    consumerChallenge: structuredClone(consumerChallenge),
    chain,
    chainSha256: dastActivationChainSha256(chain),
    generatedAt: "2026-08-08T12:34:56.000Z",
  };
}

function mutatedChain(mutate) {
  const authorization = authorizationFixture();
  mutate(authorization.chain);
  authorization.chainSha256 = dastActivationChainSha256(authorization.chain);
  return authorization;
}

test("one exact closed authorization validates without mutation and hashes canonical chain bytes without a newline", () => {
  const authorization = authorizationFixture();
  const beforeAuthorization = structuredClone(authorization);
  const beforeExpected = structuredClone(expected);
  assert.equal(validateDastActivationAuthorization(authorization, expected), authorization);
  assert.deepEqual(authorization, beforeAuthorization);
  assert.deepEqual(expected, beforeExpected);
  assert.equal(
    authorization.chainSha256,
    crypto.createHash("sha256").update(canonicalJson(authorization.chain)).digest("hex"),
  );
  assert.notEqual(
    authorization.chainSha256,
    crypto.createHash("sha256").update(`${canonicalJson(authorization.chain)}\n`).digest("hex"),
  );
});

test("canonical JSON makes chain field insertion order irrelevant", () => {
  const authorization = authorizationFixture();
  authorization.chain = Object.fromEntries(Object.entries(authorization.chain).reverse());
  authorization.chainSha256 = dastActivationChainSha256(authorization.chain);
  assert.equal(validateDastActivationAuthorization(authorization, expected), authorization);
});

test("authorization envelope is a closed exact schema", () => {
  for (const field of ["schema", "status", "consumerChallenge", "chain", "chainSha256", "generatedAt"]) {
    const candidate = authorizationFixture();
    delete candidate[field];
    assert.throws(
      () => validateDastActivationAuthorization(candidate, expected),
      /closed schema/i,
      `missing ${field}`,
    );
  }
  const extra = authorizationFixture();
  extra.untrusted = true;
  assert.throws(() => validateDastActivationAuthorization(extra, expected), /closed schema/i);

  for (const [label, mutate] of [
    ["authorization schema", (value) => { value.schema = "platform-dast-activation-authorization/v2"; }],
    ["authorization status", (value) => { value.status = "passed"; }],
    ["chain digest", (value) => { value.chainSha256 = sha("d"); }],
    ["non-canonical timestamp", (value) => { value.generatedAt = "2026-08-08T12:34:56Z"; }],
    ["invalid timestamp", (value) => { value.generatedAt = "not-a-time"; }],
  ]) {
    const candidate = authorizationFixture();
    mutate(candidate);
    assert.throws(() => validateDastActivationAuthorization(candidate, expected), undefined, label);
  }
});

test("DAST chain is a closed exact schema", () => {
  for (const field of Object.keys(authorizationFixture().chain)) {
    const candidate = authorizationFixture();
    delete candidate.chain[field];
    candidate.chainSha256 = dastActivationChainSha256(candidate.chain);
    assert.throws(
      () => validateDastActivationAuthorization(candidate, expected),
      /closed schema/i,
      `missing chain.${field}`,
    );
  }
  const extra = mutatedChain((chain) => { chain.untrusted = true; });
  assert.throws(() => validateDastActivationAuthorization(extra, expected), /closed schema/i);
});

test("every chain binding rejects substitution even when the attacker recomputes chainSha256", () => {
  const mutations = [
    ["schema", (chain) => { chain.schema = "platform.docker-dast-chain/v1"; }],
    ["repository", (chain) => { chain.repository = "attacker/platform-infrastructure"; }],
    ["commitSha", (chain) => { chain.commitSha = gitSha("d"); }],
    ["treeSha", (chain) => { chain.treeSha = gitSha("e"); }],
    ["target", (chain) => { chain.target = "https://other.platform-infrastructure.test"; }],
    ["runtimeIntentSha256", (chain) => { chain.runtimeIntentSha256 = sha("d"); }],
    ["runtimeInventorySha256", (chain) => { chain.runtimeInventorySha256 = sha("d"); }],
    ["targetServingInventoryHash", (chain) => { chain.targetServingInventoryHash = sha("d"); }],
    ["consumerChallengeSha256", (chain) => { chain.consumerChallengeSha256 = sha("d"); }],
    ["scanRequestSha256", (chain) => { chain.scanRequestSha256 = sha("d"); }],
    ["providerReceiptSha256", (chain) => { chain.providerReceiptSha256 = sha("d"); }],
    ["providerMetadataSha256", (chain) => { chain.providerMetadataSha256 = sha("d"); }],
    ["providerRunId", (chain) => { chain.providerRunId = "987655"; }],
    ["providerRunAttempt", (chain) => { chain.providerRunAttempt = 4; }],
    ["reportArtifactId", (chain) => { chain.reportArtifactId = "456790"; }],
    ["reportArtifactArchiveSha256", (chain) => { chain.reportArtifactArchiveSha256 = sha("d"); }],
    ["reportEvidenceSha256", (chain) => { chain.reportEvidenceSha256 = sha("d"); }],
    ["sigstoreBundleSha256", (chain) => { chain.sigstoreBundleSha256 = sha("d"); }],
    ["sigstoreSubject", (chain) => { chain.sigstoreSubject = "https://github.com/attacker/repo/.github/workflows/dast.yml@refs/heads/main"; }],
    ["verdict", (chain) => { chain.verdict = "fail"; }],
  ];
  for (const [label, mutate] of mutations) {
    assert.throws(
      () => validateDastActivationAuthorization(mutatedChain(mutate), expected),
      undefined,
      label,
    );
  }
});

test("consumer challenge is canonical, exact, closed, and digest-bound", () => {
  const malformed = [
    ["numeric run ID", (challenge) => { challenge.consumerRunId = 7654321; }],
    ["string run attempt", (challenge) => { challenge.consumerRunAttempt = "3"; }],
    ["wrong job", (challenge) => { challenge.consumerJob = "dast-zap"; }],
    ["wrong repository", (challenge) => { challenge.consumerRepository = "attacker/repo"; }],
    ["wrong nonce", (challenge) => { challenge.challengeNonce = sha("d"); }],
    ["extra field", (challenge) => { challenge.untrusted = true; }],
    ["missing field", (challenge) => { delete challenge.challengeNonce; }],
  ];
  for (const [label, mutate] of malformed) {
    const candidate = authorizationFixture();
    mutate(candidate.consumerChallenge);
    candidate.chain.consumerChallengeSha256 = challengeSha256(candidate.consumerChallenge);
    candidate.chainSha256 = dastActivationChainSha256(candidate.chain);
    assert.throws(
      () => validateDastActivationAuthorization(candidate, expected),
      undefined,
      label,
    );
  }

  const staleDigest = authorizationFixture();
  staleDigest.consumerChallenge.challengeNonce = sha("d");
  assert.throws(
    () => validateDastActivationAuthorization(staleDigest, {
      ...expected,
      consumerChallenge: staleDigest.consumerChallenge,
    }),
    /challenge.*digest/i,
  );
});

test("numeric provider and report identities and all scalar forms are canonical", () => {
  const mutations = [
    ["numeric provider run ID value", (chain) => { chain.providerRunId = 987654; }],
    ["zero provider run ID", (chain) => { chain.providerRunId = "0"; }],
    ["leading-zero provider run ID", (chain) => { chain.providerRunId = "0987654"; }],
    ["unsafe provider run ID", (chain) => { chain.providerRunId = "9007199254740992"; }],
    ["string provider run attempt", (chain) => { chain.providerRunAttempt = "2"; }],
    ["zero provider run attempt", (chain) => { chain.providerRunAttempt = 0; }],
    ["numeric report artifact ID value", (chain) => { chain.reportArtifactId = 456789; }],
    ["leading-zero report artifact ID", (chain) => { chain.reportArtifactId = "0456789"; }],
    ["uppercase SHA256", (chain) => { chain.scanRequestSha256 = "A".repeat(64); }],
    ["uppercase Git SHA", (chain) => { chain.commitSha = "A".repeat(40); }],
    ["target trailing slash", (chain) => { chain.target = `${expected.target}/`; }],
    ["target path", (chain) => { chain.target = `${expected.target}/scan`; }],
    ["target credentials", (chain) => { chain.target = "https://user@example.test"; }],
    ["Sigstore subject newline", (chain) => { chain.sigstoreSubject = `${sigstoreSubject}\nattacker`; }],
  ];
  for (const [label, mutate] of mutations) {
    assert.throws(
      () => validateDastActivationAuthorization(mutatedChain(mutate), expected),
      undefined,
      label,
    );
  }
});

test("every expected binding is mandatory and cannot be caller-substituted", () => {
  for (const field of Object.keys(expected)) {
    const missing = { ...expected };
    delete missing[field];
    assert.throws(
      () => validateDastActivationAuthorization(authorizationFixture(), missing),
      undefined,
      `missing expected.${field}`,
    );
  }

  const substitutions = {
    repository: "other/platform-infrastructure",
    commitSha: gitSha("d"),
    treeSha: gitSha("e"),
    target: "https://other.platform-infrastructure.test",
    runtimeIntentSha256: sha("d"),
    runtimeInventorySha256: sha("d"),
    targetServingInventoryHash: sha("d"),
    consumerChallenge: { ...consumerChallenge, challengeNonce: sha("d") },
    scanRequestSha256: sha("d"),
    providerReceiptSha256: sha("d"),
    providerMetadataSha256: sha("d"),
    providerRunId: "987655",
    providerRunAttempt: 4,
    reportArtifactId: "456790",
    reportArtifactArchiveSha256: sha("d"),
    reportEvidenceSha256: sha("d"),
    sigstoreBundleSha256: sha("d"),
    sigstoreSubject: "https://github.com/owner/other/.github/workflows/produce-admission.yml@refs/heads/main",
  };
  for (const [field, substitution] of Object.entries(substitutions)) {
    assert.throws(
      () => validateDastActivationAuthorization(authorizationFixture(), {
        ...expected,
        [field]: substitution,
      }),
      undefined,
      `substituted expected.${field}`,
    );
  }
});

test("non-object authorization and chain values reject", () => {
  for (const value of [null, [], "authorization", 1]) {
    assert.throws(() => validateDastActivationAuthorization(value, expected), /object|schema/i);
  }
  for (const value of [null, [], "chain", 1]) {
    const candidate = authorizationFixture();
    candidate.chain = value;
    assert.throws(() => validateDastActivationAuthorization(candidate, expected), /object|schema/i);
  }
});
