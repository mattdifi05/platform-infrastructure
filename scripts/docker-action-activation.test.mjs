import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson, sha256 } from "./docker-action-contract.mjs";
import {
  ACTIVATION_PAYLOAD_SCHEMA,
  ACTIVATION_PAYLOAD_TYPE,
  ACTIVATION_POLICY_SCHEMA,
  createActivationEnvelope,
  normalizeActivationPolicy,
  verifyActivationEnvelope,
} from "./docker-action-activation.mjs";

const NOW = Date.parse("2026-07-26T12:00:00.000Z");
const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const KEY_ID = sha256(publicKey.export({ type: "spki", format: "der" }));
const POLICY = Object.freeze({
  schema: ACTIVATION_POLICY_SCHEMA,
  status: "active",
  keyId: KEY_ID,
  publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
  issuer: "https://fulcio.provider.example",
  subject: "spiffe://provider.example/admin/platform-activation",
  dastSigstoreSubject: "https://github.com/example/security/.github/workflows/dast.yml@refs/heads/main",
  environment: "production",
  targetId: "platform.primary",
});

test("provider/admin DSSE binds the complete activation and DAST chain", () => {
  const fixture = activationFixture();
  const activation = verifyActivationEnvelope(fixture.envelope, POLICY, fixture.expected, { now: NOW });
  assert.equal(activation.activationId, fixture.payload.activationId);
  assert.equal(activation.envelopeSha256, fixture.expected.activationBundleSha256);
  assert.equal(activation.dastChainSha256, fixture.expected.dastChainSha256);
  assert.equal(activation.dast.verdict, "pass");
});

test("root-owned staging cannot replace the provider key, identity or signature", () => {
  const fixture = activationFixture();
  const wrongKey = crypto.generateKeyPairSync("ed25519");
  const wrongKeyId = sha256(wrongKey.publicKey.export({ type: "spki", format: "der" }));
  const forged = createActivationEnvelope(fixture.payload, wrongKey.privateKey, wrongKeyId);
  const forgedExpected = { ...fixture.expected, activationBundleSha256: sha256(forged) };
  assert.throws(() => verifyActivationEnvelope(forged, POLICY, forgedExpected, { now: NOW }), /key ID|signature/);

  for (const mutation of [
    { issuer: "https://attacker.example" },
    { subject: "spiffe://provider.example/admin/other" },
    { environment: "staging" },
    { targetId: "platform.secondary" },
  ]) {
    const payload = { ...fixture.payload, ...mutation };
    const envelope = createActivationEnvelope(payload, privateKey, KEY_ID);
    assert.throws(
      () => verifyActivationEnvelope(envelope, POLICY, { ...fixture.expected, activationBundleSha256: sha256(envelope) }, { now: NOW }),
      /not policy approved/,
    );
  }
});

test("cross-run, wrong report/archive and wrong Sigstore subject fail closed", () => {
  const fixture = activationFixture();
  const mutations = [
    { providerRunId: "run.other" },
    { reportSha256: "1".repeat(64) },
    { archiveSha256: "2".repeat(64) },
    { bundleSha256: "3".repeat(64) },
    { manifestSha256: "4".repeat(64) },
    { providerMetadataSha256: "5".repeat(64) },
    { sigstoreBundleSha256: "6".repeat(64) },
  ];
  for (const mutation of mutations) {
    const payload = { ...fixture.payload, dast: { ...fixture.payload.dast, ...mutation } };
    const envelope = createActivationEnvelope(payload, privateKey, KEY_ID);
    assert.throws(
      () => verifyActivationEnvelope(envelope, POLICY, { ...fixture.expected, activationBundleSha256: sha256(envelope) }, { now: NOW }),
      /dastChainSha256 does not match/,
    );
  }
  const wrongSubjectPayload = {
    ...fixture.payload,
    dast: { ...fixture.payload.dast, sigstoreSubject: "https://github.com/attacker/workflow" },
  };
  const wrongSubject = createActivationEnvelope(wrongSubjectPayload, privateKey, KEY_ID);
  assert.throws(
    () => verifyActivationEnvelope(wrongSubject, POLICY, { ...fixture.expected, activationBundleSha256: sha256(wrongSubject) }, { now: NOW }),
    /Sigstore subject/,
  );
});

test("cross-environment, release, candidate and render bindings fail closed", () => {
  const fixture = activationFixture();
  for (const [field, wrong] of [
    ["candidateId", "candidate.other"],
    ["releaseId", "release.other"],
    ["runtimeIntentId", "intent.other"],
    ["sourceRenderSha256", "1".repeat(64)],
    ["combinedRenderSha256", "2".repeat(64)],
  ]) {
    const payload = { ...fixture.payload, [field]: wrong };
    const envelope = createActivationEnvelope(payload, privateKey, KEY_ID);
    assert.throws(
      () => verifyActivationEnvelope(envelope, POLICY, { ...fixture.expected, activationBundleSha256: sha256(envelope) }, { now: NOW }),
      new RegExp(`${field} does not match`),
    );
  }
});

test("future, expired and overlong activation windows fail closed", () => {
  const fixture = activationFixture();
  for (const mutation of [
    {
      issuedAt: new Date(NOW + 60_000).toISOString(),
      notBefore: new Date(NOW + 60_000).toISOString(),
      expiresAt: new Date(NOW + 120_000).toISOString(),
    },
    {
      issuedAt: new Date(NOW - 120_000).toISOString(),
      notBefore: new Date(NOW - 120_000).toISOString(),
      expiresAt: new Date(NOW - 1).toISOString(),
    },
    {
      issuedAt: new Date(NOW - 1).toISOString(),
      notBefore: new Date(NOW - 1).toISOString(),
      expiresAt: new Date(NOW + 16 * 60_000).toISOString(),
    },
  ]) {
    const payload = { ...fixture.payload, ...mutation };
    const envelope = createActivationEnvelope(payload, privateKey, KEY_ID);
    assert.throws(
      () => verifyActivationEnvelope(envelope, POLICY, { ...fixture.expected, activationBundleSha256: sha256(envelope) }, { now: NOW }),
      /time window/,
    );
  }
});

test("CAS digest, exact bytes and canonicalization drift are rejected", () => {
  const fixture = activationFixture();
  assert.throws(
    () => verifyActivationEnvelope(fixture.envelope, POLICY, {
      ...fixture.expected,
      activationBundleSha256: "0".repeat(64),
    }, { now: NOW }),
    /CAS digest/,
  );
  const outerWhitespace = Buffer.concat([fixture.envelope.subarray(0, -1), Buffer.from(" \n")]);
  assert.throws(
    () => verifyActivationEnvelope(outerWhitespace, POLICY, {
      ...fixture.expected,
      activationBundleSha256: sha256(outerWhitespace),
    }, { now: NOW }),
    /exact canonical JSON/,
  );

  const nonCanonicalPayload = Buffer.from(`{ "schema": ${JSON.stringify(ACTIVATION_PAYLOAD_SCHEMA)} }`);
  const signature = crypto.sign(null, dssePae(ACTIVATION_PAYLOAD_TYPE, nonCanonicalPayload), privateKey);
  const driftEnvelope = Buffer.from(`${canonicalJson({
    payload: nonCanonicalPayload.toString("base64"),
    payloadType: ACTIVATION_PAYLOAD_TYPE,
    signatures: [{ keyid: KEY_ID, sig: signature.toString("base64") }],
  })}\n`);
  assert.throws(
    () => verifyActivationEnvelope(driftEnvelope, POLICY, {
      ...fixture.expected,
      activationBundleSha256: sha256(driftEnvelope),
    }, { now: NOW }),
    /payload is not exact canonical JSON/,
  );

  const mutated = Buffer.from(fixture.envelope);
  mutated[mutated.length - 3] ^= 1;
  assert.throws(
    () => verifyActivationEnvelope(mutated, POLICY, {
      ...fixture.expected,
      activationBundleSha256: sha256(mutated),
    }, { now: NOW }),
  );
});

test("policy root must be active, exact and Ed25519", () => {
  assert.throws(() => normalizeActivationPolicy({ ...POLICY, status: "external-pending" }), /external-pending/);
  assert.throws(() => normalizeActivationPolicy({ ...POLICY, keyId: "0".repeat(64) }), /pinned key ID/);
  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  assert.throws(() => normalizeActivationPolicy({
    ...POLICY,
    keyId: sha256(rsa.publicKey.export({ type: "spki", format: "der" })),
    publicKeyPem: rsa.publicKey.export({ type: "spki", format: "pem" }),
  }), /Ed25519/);
});

function activationFixture() {
  const dast = {
    archiveSha256: "a".repeat(64),
    bundleSha256: "b".repeat(64),
    manifestSha256: "c".repeat(64),
    providerMetadataSha256: "d".repeat(64),
    providerRunId: "run.20260726",
    reportSha256: "e".repeat(64),
    sigstoreBundleSha256: "f".repeat(64),
    sigstoreSubject: POLICY.dastSigstoreSubject,
    verdict: "pass",
  };
  const payload = {
    schema: ACTIVATION_PAYLOAD_SCHEMA,
    activationId: "activation.1",
    candidateId: "candidate.v1",
    combinedRenderSha256: "1".repeat(64),
    dast,
    environment: POLICY.environment,
    expiresAt: new Date(NOW + 5 * 60_000).toISOString(),
    generation: 1,
    issuedAt: new Date(NOW - 60_000).toISOString(),
    issuer: POLICY.issuer,
    nonce: Buffer.alloc(32, 7).toString("base64url"),
    notBefore: new Date(NOW - 30_000).toISOString(),
    previousActiveSha256: "0".repeat(64),
    releaseId: "release.v1",
    requestId: "123e4567-e89b-42d3-a456-426614174000",
    runtimeIntentId: "intent.v1",
    sourceRenderSha256: "2".repeat(64),
    subject: POLICY.subject,
    targetId: POLICY.targetId,
  };
  const envelope = createActivationEnvelope(payload, privateKey, KEY_ID);
  return {
    payload,
    envelope,
    expected: {
      activationBundleSha256: sha256(envelope),
      candidateId: payload.candidateId,
      combinedRenderSha256: payload.combinedRenderSha256,
      dastChainSha256: sha256(canonicalJson(dast)),
      environment: payload.environment,
      generation: payload.generation,
      releaseId: payload.releaseId,
      runtimeIntentId: payload.runtimeIntentId,
      sourceRenderSha256: payload.sourceRenderSha256,
      targetId: payload.targetId,
    },
  };
}

function dssePae(payloadType, payload) {
  const type = Buffer.from(payloadType);
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `),
    type,
    Buffer.from(` ${payload.length} `),
    payload,
  ]);
}
