import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  assertProviderMfaPolicyReadyForLive,
  evaluateProviderMfaAssurance,
  normalizeProviderMfaPolicy,
  pendingProviderMfaAssurance,
  providerMfaPolicyDigest,
} from "./provider-mfa-assurance.mjs";

const root = path.resolve(import.meta.dirname, "..");
const modulePath = path.join(root, "scripts", "provider-mfa-assurance.mjs");
const manifest = JSON.parse(readFileSync(path.join(root, "cloudflare", "access-admin.example.json"), "utf8"));
const verifierSource = readFileSync(path.join(root, "scripts", "cloudflare-access-admin.mjs"), "utf8");
const goNoGoSource = readFileSync(path.join(root, "scripts", "infra-ops.mjs"), "utf8");

function clone(value) {
  return structuredClone(value);
}

function normalizedPolicy(raw = manifest.mfaAssurancePolicy) {
  return normalizeProviderMfaPolicy(raw, {
    allowedIdentityProviderIds: manifest.allowedIdentityProviderIds,
  });
}

function accessApplications() {
  return manifest.applications.map((app, index) => ({
    ...app,
    result: "access-shape-verified",
    applicationId: `access-app-${index}`,
    policyId: `access-policy-${index}`,
  }));
}

function pendingPayload() {
  const applications = accessApplications();
  return {
    mode: "verifyRemote",
    status: "pending-provider",
    manifest: {
      accountId: manifest.accountId,
      teamName: manifest.teamName,
      mfaAssurancePolicy: normalizedPolicy(),
    },
    applications,
    accessShape: { status: "passed" },
    providerMfaAssurance: pendingProviderMfaAssurance({
      policy: normalizedPolicy(),
      applications,
      accountId: manifest.accountId,
      teamName: manifest.teamName,
    }),
  };
}

test("provider MFA intent is structured and legacy self-attestation is absent", () => {
  assert.equal(Object.hasOwn(manifest, "mfaEnforcedByIdentityProvider"), false);
  assert.equal(manifest.mfaAssurancePolicy?.assuranceBoundary, "external-provider");
  assert.equal(normalizedPolicy().expectedLoginMethodId, manifest.allowedIdentityProviderIds[0]);
});

test("legacy boolean, weak policy shape, and mismatched login method fail closed", () => {
  assert.throws(() => normalizeProviderMfaPolicy(manifest.mfaAssurancePolicy, {
    allowedIdentityProviderIds: manifest.allowedIdentityProviderIds,
    legacySelfAttestation: true,
  }), /self-attestation/);
  const cases = [
    ["expectedIssuer", "http://idp.invalid/", /absolute HTTPS/],
    ["expectedLoginMethodId", "wrong-login-method", /must exactly match/],
    ["acceptedMethods", [], /non-empty array/],
    ["acceptedAuthenticationContexts", [], /non-empty array/],
    ["maxEvidenceAgeSeconds", 0, /integer from 60/],
    ["expectedPolicyRevision", "", /non-empty string/],
  ];
  for (const [field, value, pattern] of cases) {
    const policy = clone(manifest.mfaAssurancePolicy);
    policy[field] = value;
    assert.throws(() => normalizedPolicy(policy), pattern);
  }
});

test("real Access entrypoint rejects legacy MFA self-attestation", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "provider-mfa-self-attestation-"));
  try {
    const legacy = clone(manifest);
    legacy.mfaEnforcedByIdentityProvider = true;
    const manifestPath = path.join(directory, "legacy.json");
    writeFileSync(manifestPath, `${JSON.stringify(legacy)}\n`, { mode: 0o600 });
    const result = spawnSync(process.execPath, [
      path.join(root, "scripts", "cloudflare-access-admin.mjs"),
      "--manifest",
      manifestPath,
    ], { cwd: root, encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /local self-attestation.*not accepted/);
    assert.doesNotMatch(result.stderr, /Cloudflare GET|fetch|CLOUDFLARE_API_TOKEN/i);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("placeholder policy is valid intent but cannot run against a live provider", () => {
  assert.throws(() => assertProviderMfaPolicyReadyForLive(normalizedPolicy()), /Replace provider MFA placeholder/);
});

test("Access verification emits a separate external provider assurance state", () => {
  assert.equal(existsSync(modulePath), true);
  assert.match(verifierSource, /providerMfaAssurance/);
  assert.match(verifierSource, /pending-provider/);
});

test("production admission splits Access shape from provider MFA assurance", () => {
  assert.match(goNoGoSource, /cloudflare-access-shape-verified/);
  assert.match(goNoGoSource, /identity-provider-mfa-assurance/);
});

test("missing authenticated provider proof remains EXTERNAL and pending-provider", () => {
  const payload = pendingPayload();
  assert.equal(payload.status, "pending-provider");
  assert.equal(payload.providerMfaAssurance.ownership, "EXTERNAL");
  assert.equal(payload.providerMfaAssurance.receipt, null);
  assert.deepEqual(evaluateProviderMfaAssurance(payload), {
    status: "pending-provider",
    passed: false,
    reason: "fresh authenticated provider MFA evidence remains external and unavailable",
  });
  assert.equal(evaluateProviderMfaAssurance({}).status, "pending-provider");
});

test("self-issued, unsigned, or locally promoted assurance can never pass", () => {
  const mutations = [
    (assurance) => { assurance.status = "passed"; },
    (assurance) => { assurance.authenticated = true; },
    (assurance) => { assurance.providerBacked = true; },
    (assurance) => { assurance.liveVerified = true; },
    (assurance) => { assurance.receipt = { issuer: assurance.expectedPolicy.expectedIssuer, signature: null }; },
  ];
  for (const mutate of mutations) {
    const payload = pendingPayload();
    mutate(payload.providerMfaAssurance);
    const result = evaluateProviderMfaAssurance(payload);
    assert.equal(result.passed, false);
    assert.equal(result.status, "failed");
  }
});

test("wrong issuer, client, login method, application, context, freshness, or revision claims do not pass", () => {
  const receiptMutations = [
    { issuer: "https://wrong.invalid/" },
    { clientId: "wrong-client" },
    { loginMethodId: "wrong-login" },
    { applicationIds: ["wrong-app"] },
    { authenticationContexts: ["password-only"] },
    { issuedAt: "2000-01-01T00:00:00.000Z" },
    { issuedAt: "2999-01-01T00:00:00.000Z" },
    { policyRevision: "wrong-revision" },
  ];
  for (const claims of receiptMutations) {
    const payload = pendingPayload();
    payload.providerMfaAssurance.receipt = { claims, selfIssued: true, signature: null };
    const result = evaluateProviderMfaAssurance(payload);
    assert.equal(result.passed, false);
    assert.equal(result.status, "failed");
  }
});

test("policy and exact Access resource bindings are integrity checked", () => {
  const policyMismatch = pendingPayload();
  policyMismatch.providerMfaAssurance.expectedPolicy.expectedClientId = "changed-client";
  assert.match(evaluateProviderMfaAssurance(policyMismatch).reason, /digest mismatch/);

  const reboundSelfAssertion = pendingPayload();
  reboundSelfAssertion.providerMfaAssurance.expectedPolicy.expectedClientId = "changed-client";
  reboundSelfAssertion.providerMfaAssurance.policyDigest = providerMfaPolicyDigest(reboundSelfAssertion.providerMfaAssurance.expectedPolicy);
  assert.equal(evaluateProviderMfaAssurance(reboundSelfAssertion).status, "pending-provider");
  assert.equal(evaluateProviderMfaAssurance(reboundSelfAssertion).passed, false);

  for (const field of ["accessApplicationIds", "accessPolicyIds", "applicationDomains"]) {
    const payload = pendingPayload();
    payload.providerMfaAssurance.requiredBindings[field][0] = "wrong-binding";
    assert.match(evaluateProviderMfaAssurance(payload).reason, /not bound to the exact/);
  }
});
