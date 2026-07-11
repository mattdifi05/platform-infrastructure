import assert from "node:assert/strict";
import test from "node:test";
import { providerEvidenceAttestationOptions } from "./provider-evidence-auth.mjs";

const complete = {
  enabled: true,
  evidencePath: "evidence.json",
  evidenceDigest: "a".repeat(64),
  repository: "owner/repo",
  signerWorkflow: "owner/repo/.github/workflows/provider.yml",
  sourceDigest: "b".repeat(40),
  sourceRef: "refs/heads/main",
};

test("self-authored provider flags fail closed", () => {
  assert.throws(() => providerEvidenceAttestationOptions({ ...complete, enabled: false }), /not accepted/);
});

test("authenticated provider evidence binds the exact artifact", () => {
  const result = providerEvidenceAttestationOptions(complete);
  assert.equal(result.expectedSubjectDigest, complete.evidenceDigest);
  assert.match(result.subject, /evidence\.json$/);
});

test("partial offline trust material fails closed", () => {
  assert.throws(() => providerEvidenceAttestationOptions({ ...complete, bundle: "bundle.json" }), /both attestation bundle and trusted root/);
});
