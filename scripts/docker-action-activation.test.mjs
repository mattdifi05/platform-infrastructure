import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { canonicalJson, sha256 } from "./docker-action-contract.mjs";
import {
  ACTIVATION_PAYLOAD_SCHEMA,
  ACTIVATION_PAYLOAD_TYPE,
  ACTIVATION_POLICY_SCHEMA,
  DAST_CHAIN_SCHEMA,
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
  assert.equal(activation.envelopeSha256, fixture.expected.activationEnvelopeSha256);
  assert.equal(activation.dastChainSha256, fixture.expected.dastChainSha256);
  assert.equal(activation.dast.verdict, "pass");
});

test("root-owned staging cannot replace the provider key, identity or signature", () => {
  const fixture = activationFixture();
  const wrongKey = crypto.generateKeyPairSync("ed25519");
  const wrongKeyId = sha256(wrongKey.publicKey.export({ type: "spki", format: "der" }));
  const forged = createActivationEnvelope(fixture.payload, wrongKey.privateKey, wrongKeyId);
  const forgedExpected = { ...fixture.expected, activationEnvelopeSha256: sha256(forged) };
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
      () => verifyActivationEnvelope(envelope, POLICY, { ...fixture.expected, activationEnvelopeSha256: sha256(envelope) }, { now: NOW }),
      /not policy approved/,
    );
  }
});

test("cross-run, wrong evidence/archive and wrong Sigstore subject fail closed", () => {
  const fixture = activationFixture();
  const mutations = [
    { providerRunId: "987655" },
    { reportEvidenceSha256: "1".repeat(64) },
    { reportArtifactArchiveSha256: "2".repeat(64) },
    { scanRequestSha256: "3".repeat(64) },
    { providerReceiptSha256: "4".repeat(64) },
    { providerMetadataSha256: "5".repeat(64) },
    { sigstoreBundleSha256: "6".repeat(64) },
  ];
  for (const mutation of mutations) {
    const payload = { ...fixture.payload, dast: { ...fixture.payload.dast, ...mutation } };
    const envelope = createActivationEnvelope(payload, privateKey, KEY_ID);
    assert.throws(
      () => verifyActivationEnvelope(envelope, POLICY, { ...fixture.expected, activationEnvelopeSha256: sha256(envelope) }, { now: NOW }),
      /dastChainSha256 does not match/,
    );
  }
  const wrongSubjectPayload = {
    ...fixture.payload,
    dast: { ...fixture.payload.dast, sigstoreSubject: "https://github.com/attacker/workflow" },
  };
  const wrongSubject = createActivationEnvelope(wrongSubjectPayload, privateKey, KEY_ID);
  assert.throws(
    () => verifyActivationEnvelope(wrongSubject, POLICY, { ...fixture.expected, activationEnvelopeSha256: sha256(wrongSubject) }, { now: NOW }),
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
      () => verifyActivationEnvelope(envelope, POLICY, { ...fixture.expected, activationEnvelopeSha256: sha256(envelope) }, { now: NOW }),
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
      () => verifyActivationEnvelope(envelope, POLICY, { ...fixture.expected, activationEnvelopeSha256: sha256(envelope) }, { now: NOW }),
      /time window/,
    );
  }
});

test("CAS digest, exact bytes and canonicalization drift are rejected", () => {
  const fixture = activationFixture();
  assert.throws(
    () => verifyActivationEnvelope(fixture.envelope, POLICY, {
      ...fixture.expected,
      activationEnvelopeSha256: "0".repeat(64),
    }, { now: NOW }),
    /CAS digest/,
  );
  const outerWhitespace = Buffer.concat([fixture.envelope.subarray(0, -1), Buffer.from(" \n")]);
  assert.throws(
    () => verifyActivationEnvelope(outerWhitespace, POLICY, {
      ...fixture.expected,
      activationEnvelopeSha256: sha256(outerWhitespace),
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
      activationEnvelopeSha256: sha256(driftEnvelope),
    }, { now: NOW }),
    /payload is not exact canonical JSON/,
  );

  const mutated = Buffer.from(fixture.envelope);
  mutated[mutated.length - 3] ^= 1;
  assert.throws(
    () => verifyActivationEnvelope(mutated, POLICY, {
      ...fixture.expected,
      activationEnvelopeSha256: sha256(mutated),
    }, { now: NOW }),
  );
});

test("v1 payload, v1 media type and non-closed DAST chains are rejected", () => {
  const fixture = activationFixture();
  for (const dast of [
    { ...fixture.payload.dast, schema: "platform.docker-dast-chain/v1" },
    { ...fixture.payload.dast, unsupported: true },
  ]) {
    const payload = { ...fixture.payload, dast };
    const envelope = createActivationEnvelope(payload, privateKey, KEY_ID);
    assert.throws(
      () => verifyActivationEnvelope(envelope, POLICY, {
        ...fixture.expected,
        activationEnvelopeSha256: sha256(envelope),
        dastChainSha256: sha256(canonicalJson(dast)),
      }, { now: NOW }),
      /schema|unsupported or missing fields/,
    );
  }

  const v1Payload = { ...fixture.payload, schema: "platform.docker-runtime-activation/v1" };
  const v1PayloadEnvelope = createActivationEnvelope(v1Payload, privateKey, KEY_ID);
  assert.throws(
    () => verifyActivationEnvelope(v1PayloadEnvelope, POLICY, {
      ...fixture.expected,
      activationEnvelopeSha256: sha256(v1PayloadEnvelope),
    }, { now: NOW }),
    /payload schema/,
  );

  const v1TypeEnvelope = JSON.parse(fixture.envelope.toString("utf8"));
  v1TypeEnvelope.payloadType = "application/vnd.platform.docker-runtime-activation.v1+json";
  const v1TypeBytes = Buffer.from(`${canonicalJson(v1TypeEnvelope)}\n`);
  assert.throws(
    () => verifyActivationEnvelope(v1TypeBytes, POLICY, {
      ...fixture.expected,
      activationEnvelopeSha256: sha256(v1TypeBytes),
    }, { now: NOW }),
    /type/,
  );
});

test("authoritative and extended typed digest sentinels cannot be substituted or swapped", () => {
  const fixture = activationFixture();
  const authoritativeSentinels = [
    fixture.expected.activationEnvelopeSha256,
    fixture.payload.releaseBundleSha256,
    fixture.payload.dast.providerReceiptSha256,
    fixture.payload.dastAuthorizationSha256,
    fixture.expected.dastChainSha256,
  ];
  const extendedSentinels = [
    ...authoritativeSentinels,
    fixture.payload.releaseBundleManifestSha256,
    fixture.payload.treeSha256,
  ];
  assert.equal(new Set(authoritativeSentinels).size, 5);
  assert.equal(new Set(extendedSentinels).size, 7);
  for (const rawDigest of extendedSentinels.slice(1)) {
    assert.throws(
      () => verifyActivationEnvelope(fixture.envelope, POLICY, {
        ...fixture.expected,
        activationEnvelopeSha256: rawDigest,
      }, { now: NOW }),
      /CAS digest/,
    );
  }

  for (const [left, right] of [
    ["releaseBundleSha256", "releaseBundleManifestSha256"],
    ["releaseBundleSha256", "dastAuthorizationSha256"],
  ]) {
    const payload = {
      ...fixture.payload,
      [left]: fixture.payload[right],
      [right]: fixture.payload[left],
    };
    const envelope = createActivationEnvelope(payload, privateKey, KEY_ID);
    assert.throws(
      () => verifyActivationEnvelope(envelope, POLICY, {
        ...fixture.expected,
        activationEnvelopeSha256: sha256(envelope),
      }, { now: NOW }),
      /trusted release context/,
    );
  }

  for (const [topLevel, chainField] of [
    ["releaseBundleSha256", "providerReceiptSha256"],
    ["dastAuthorizationSha256", "providerReceiptSha256"],
  ]) {
    const payload = {
      ...fixture.payload,
      [topLevel]: fixture.payload.dast[chainField],
      dast: {
        ...fixture.payload.dast,
        [chainField]: fixture.payload[topLevel],
      },
    };
    const envelope = createActivationEnvelope(payload, privateKey, KEY_ID);
    assert.throws(
      () => verifyActivationEnvelope(envelope, POLICY, {
        ...fixture.expected,
        activationEnvelopeSha256: sha256(envelope),
      }, { now: NOW }),
      /trusted release context|dastChainSha256 does not match/,
    );
  }

  const collidingPayload = {
    ...fixture.payload,
    releaseBundleSha256: fixture.payload.dast.providerReceiptSha256,
  };
  const collidingEnvelope = createActivationEnvelope(collidingPayload, privateKey, KEY_ID);
  assert.throws(
    () => verifyActivationEnvelope(collidingEnvelope, POLICY, {
      ...fixture.expected,
      activationEnvelopeSha256: sha256(collidingEnvelope),
      releaseBundleSha256: collidingPayload.releaseBundleSha256,
    }, { now: NOW }),
    /typed digest identities collide/,
  );
});

test("DAST provider and report identities use canonical bounded integer encodings", () => {
  const fixture = activationFixture();
  for (const mutation of [
    { providerRunId: "01" },
    { providerRunId: String(Number.MAX_SAFE_INTEGER + 1) },
    { providerRunAttempt: "2" },
    { providerRunAttempt: 0 },
    { reportArtifactId: "01" },
    { reportArtifactId: String(Number.MAX_SAFE_INTEGER + 1) },
  ]) {
    const payload = { ...fixture.payload, dast: { ...fixture.payload.dast, ...mutation } };
    const envelope = createActivationEnvelope(payload, privateKey, KEY_ID);
    assert.throws(
      () => verifyActivationEnvelope(envelope, POLICY, {
        ...fixture.expected,
        activationEnvelopeSha256: sha256(envelope),
        dastChainSha256: sha256(canonicalJson(payload.dast)),
      }, { now: NOW }),
      /provider run|report artifact/,
    );
  }
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
    schema: DAST_CHAIN_SCHEMA,
    repository: "example/platform-infrastructure",
    commitSha: "1".repeat(40),
    treeSha: "2".repeat(40),
    target: "https://staging.platform-infrastructure.test",
    runtimeIntentSha256: "9".repeat(64),
    runtimeInventorySha256: "a".repeat(64),
    targetServingInventoryHash: "b".repeat(64),
    consumerChallengeSha256: "c".repeat(64),
    scanRequestSha256: "d".repeat(64),
    providerReceiptSha256: "e".repeat(64),
    providerMetadataSha256: "f".repeat(64),
    providerRunId: "987654",
    providerRunAttempt: 2,
    reportArtifactId: "456789",
    reportArtifactArchiveSha256: "0".repeat(64),
    reportEvidenceSha256: "3".repeat(64),
    sigstoreBundleSha256: "4".repeat(64),
    sigstoreSubject: POLICY.dastSigstoreSubject,
    verdict: "pass",
  };
  const treeSha256 = sha256(Buffer.concat([
    Buffer.from("platform-git-tree-sha1/v1\0", "utf8"),
    Buffer.from(dast.treeSha, "utf8"),
  ]));
  const payload = {
    schema: ACTIVATION_PAYLOAD_SCHEMA,
    activationId: "activation.1",
    candidateId: "candidate.v1",
    combinedRenderSha256: "1".repeat(64),
    dast,
    dastAuthorizationSha256: "8".repeat(64),
    environment: POLICY.environment,
    expiresAt: new Date(NOW + 5 * 60_000).toISOString(),
    generation: 1,
    issuedAt: new Date(NOW - 60_000).toISOString(),
    issuer: POLICY.issuer,
    nonce: Buffer.alloc(32, 7).toString("base64url"),
    notBefore: new Date(NOW - 30_000).toISOString(),
    previousActiveSha256: "0".repeat(64),
    releaseId: "release.v1",
    releaseBundleManifestSha256: "7".repeat(64),
    releaseBundleSha256: "6".repeat(64),
    requestId: "123e4567-e89b-42d3-a456-426614174000",
    runtimeIntentId: "intent.v1",
    sourceRenderSha256: "2".repeat(64),
    subject: POLICY.subject,
    targetId: POLICY.targetId,
    treeSha256,
  };
  const envelope = createActivationEnvelope(payload, privateKey, KEY_ID);
  return {
    payload,
    envelope,
    expected: {
      activationEnvelopeSha256: sha256(envelope),
      candidateId: payload.candidateId,
      combinedRenderSha256: payload.combinedRenderSha256,
      dastAuthorizationSha256: payload.dastAuthorizationSha256,
      dastChainSha256: sha256(canonicalJson(dast)),
      environment: payload.environment,
      generation: payload.generation,
      releaseId: payload.releaseId,
      releaseBundleManifestSha256: payload.releaseBundleManifestSha256,
      releaseBundleSha256: payload.releaseBundleSha256,
      runtimeIntentId: payload.runtimeIntentId,
      sourceRenderSha256: payload.sourceRenderSha256,
      targetId: payload.targetId,
      treeSha256: payload.treeSha256,
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
