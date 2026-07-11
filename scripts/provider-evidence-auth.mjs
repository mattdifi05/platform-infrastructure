import path from "node:path";

function required(value, label) {
  const text = String(value ?? "").trim();
  if (!text) throw new Error(`${label} is required for authenticated provider evidence.`);
  return text;
}
export function providerEvidenceAttestationOptions(options = {}) {
  if (options.enabled !== true) {
    throw new Error("Self-authored provider evidence is not accepted; cryptographic attestation is required.");
  }
  const bundle = options.bundle ? path.resolve(String(options.bundle)) : null;
  const trustedRoot = options.trustedRoot ? path.resolve(String(options.trustedRoot)) : null;
  if (Boolean(bundle) !== Boolean(trustedRoot)) {
    throw new Error("Offline provider evidence verification requires both attestation bundle and trusted root.");
  }
  return {
    subject: path.resolve(required(options.evidencePath, "Provider evidence file")),
    expectedSubjectDigest: required(options.evidenceDigest, "Provider evidence SHA256"),
    repository: required(options.repository, "Provider evidence repository"),
    signerWorkflow: required(options.signerWorkflow, "Provider evidence signer workflow"),
    sourceDigest: required(options.sourceDigest, "Provider evidence source digest"),
    sourceRef: required(options.sourceRef, "Provider evidence source ref"),
    bundle,
    trustedRoot,
  };
}
