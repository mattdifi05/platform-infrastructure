export const edgeProviderEvidenceSchema = "platform.edge-traversal-evidence/v1";

const SHA256 = /^[a-f0-9]{64}$/;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{7,255}$/;

function invalid(message) {
  throw new Error(message);
}

function canonicalHttpsUrl(value, label) {
  let parsed;
  try {
    parsed = new URL(String(value ?? ""));
  } catch {
    invalid(`${label} is invalid.`);
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash) invalid(`${label} must be a credential-free HTTPS URL without a fragment.`);
  return parsed.href;
}

function timestamp(value, label, nowMs, maxAgeMinutes) {
  const parsed = Date.parse(String(value ?? ""));
  if (!Number.isFinite(parsed)) invalid(`${label} is invalid.`);
  if (parsed > nowMs) invalid(`${label} is in the future.`);
  if (nowMs - parsed > maxAgeMinutes * 60 * 1000) invalid(`${label} is stale.`);
  return parsed;
}

export function validateEdgeProviderEvidence({
  evidence,
  authentication,
  expectedUrl,
  expectedProvider,
  currentCandidateId,
  observedStatus,
  nowMs = Date.now(),
  maxAgeMinutes = 60,
}) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence) || evidence.schema !== edgeProviderEvidenceSchema) {
    invalid("Edge traversal provider evidence schema is invalid.");
  }
  if (evidence.external !== true) invalid("Edge traversal evidence must come from an external provider.");
  if (authentication?.verified !== true || authentication?.status !== "passed" || authentication?.kind !== "github-sigstore-cryptographic-attestation") {
    invalid("Edge traversal evidence lacks authenticated provider attestation.");
  }
  if (!Number.isInteger(authentication.verifiedTimestampCount) || authentication.verifiedTimestampCount <= 0) {
    invalid("Edge traversal evidence attestation lacks a verified transparency timestamp.");
  }
  const provider = String(evidence.provider ?? "").trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]{1,63}$/.test(provider)) invalid("Edge traversal provider identity is invalid.");
  const requiredProvider = String(expectedProvider ?? "").trim().toLowerCase();
  if (requiredProvider !== "any" && provider !== requiredProvider) invalid(`Edge traversal provider mismatch: expected=${requiredProvider}, observed=${provider}.`);
  const candidateId = String(evidence.candidateId ?? "").trim().toLowerCase();
  const expectedCandidateId = String(currentCandidateId ?? "").trim().toLowerCase();
  if (!SHA256.test(candidateId) || !SHA256.test(expectedCandidateId) || candidateId !== expectedCandidateId) {
    invalid("Edge traversal evidence is not bound to the current candidate.");
  }
  const expectedCanonicalUrl = canonicalHttpsUrl(expectedUrl, "Expected edge request URL");
  const requestUrl = canonicalHttpsUrl(evidence.request?.url, "Provider-observed request URL");
  if (requestUrl !== expectedCanonicalUrl) invalid("Provider-observed request URL mismatch.");
  if (evidence.request?.method !== "GET") invalid("Provider-observed request method must be GET.");
  const requestId = String(evidence.request?.id ?? "");
  if (!REQUEST_ID.test(requestId)) invalid("Provider-observed request ID is invalid.");
  const status = Number(evidence.request?.status);
  if (!Number.isInteger(status) || status < 100 || status > 599 || status !== Number(observedStatus)) {
    invalid("Provider-observed request status does not match the benchmark preflight.");
  }
  const ageLimit = Number(maxAgeMinutes);
  if (!Number.isFinite(ageLimit) || ageLimit <= 0 || ageLimit > 1440) invalid("Edge provider evidence max age is invalid.");
  const observedAtMs = timestamp(evidence.request?.observedAt, "Provider-observed request timestamp", nowMs, ageLimit);
  const verifiedAtMs = timestamp(evidence.verifiedAt, "Edge provider verification timestamp", nowMs, ageLimit);
  if (verifiedAtMs < observedAtMs || verifiedAtMs - observedAtMs > 15 * 60 * 1000) {
    invalid("Edge provider verification is not temporally bound to the observed request.");
  }
  return {
    status: "passed",
    verified: true,
    provider,
    candidateId,
    request: {
      id: requestId,
      method: "GET",
      url: requestUrl,
      status,
      observedAt: new Date(observedAtMs).toISOString(),
    },
    verifiedAt: new Date(verifiedAtMs).toISOString(),
    authentication: {
      status: "passed",
      verified: true,
      kind: authentication.kind,
      repository: authentication.repository,
      signerWorkflow: authentication.signerWorkflow,
      sourceDigest: authentication.sourceDigest,
      sourceRef: authentication.sourceRef,
      verifiedTimestampCount: authentication.verifiedTimestampCount,
    },
  };
}
