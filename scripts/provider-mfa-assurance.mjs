import { sha256Canonical } from "./admin-access-inventory.mjs";

const POLICY_SCHEMA_VERSION = 1;
const RECEIPT_SCHEMA_VERSION = 1;

function requiredString(value, label) {
  const clean = String(value ?? "").trim();
  if (!clean) throw new Error(`${label} must be a non-empty string.`);
  return clean;
}

function uniqueStrings(value, label, { lowerCase = false } = {}) {
  if (!Array.isArray(value) || value.length === 0) throw new Error(`${label} must be a non-empty array.`);
  const normalized = value.map((entry, index) => {
    const clean = requiredString(entry, `${label}[${index}]`);
    return lowerCase ? clean.toLowerCase() : clean;
  });
  if (new Set(normalized).size !== normalized.length) throw new Error(`${label} must not contain duplicates.`);
  return normalized.sort();
}

function exactArray(actual, expected) {
  return Array.isArray(actual)
    && actual.length === expected.length
    && actual.every((value, index) => value === expected[index]);
}

function validIssuer(value) {
  let issuer;
  try {
    issuer = new URL(value);
  } catch {
    throw new Error("Provider MFA expectedIssuer must be an absolute HTTPS URL.");
  }
  if (issuer.protocol !== "https:" || issuer.username || issuer.password || issuer.search || issuer.hash) {
    throw new Error("Provider MFA expectedIssuer must be an absolute HTTPS URL without credentials, query, or fragment.");
  }
  return issuer.toString();
}

export function normalizeProviderMfaPolicy(raw, options = {}) {
  if (options.legacySelfAttestation !== undefined) {
    throw new Error("mfaEnforcedByIdentityProvider is a local self-attestation and is not accepted as provider MFA assurance.");
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("Cloudflare Access manifest must define mfaAssurancePolicy.");
  if (raw.schemaVersion !== POLICY_SCHEMA_VERSION) throw new Error(`Provider MFA policy schemaVersion must be ${POLICY_SCHEMA_VERSION}.`);
  if (raw.assuranceBoundary !== "external-provider") throw new Error("Provider MFA assuranceBoundary must be external-provider.");
  const allowedIdentityProviderIds = uniqueStrings(options.allowedIdentityProviderIds, "allowedIdentityProviderIds");
  if (allowedIdentityProviderIds.length !== 1) throw new Error("Provider MFA policy requires exactly one allowed identity provider ID.");

  const policy = {
    schemaVersion: POLICY_SCHEMA_VERSION,
    assuranceBoundary: "external-provider",
    provider: requiredString(raw.provider, "Provider MFA provider"),
    expectedIssuer: validIssuer(requiredString(raw.expectedIssuer, "Provider MFA expectedIssuer")),
    expectedTenantId: requiredString(raw.expectedTenantId, "Provider MFA expectedTenantId"),
    expectedClientId: requiredString(raw.expectedClientId, "Provider MFA expectedClientId"),
    expectedLoginMethodId: requiredString(raw.expectedLoginMethodId, "Provider MFA expectedLoginMethodId"),
    acceptedAuthenticationContexts: uniqueStrings(raw.acceptedAuthenticationContexts, "Provider MFA acceptedAuthenticationContexts"),
    acceptedMethods: uniqueStrings(raw.acceptedMethods, "Provider MFA acceptedMethods", { lowerCase: true }),
    expectedPolicyRevision: requiredString(raw.expectedPolicyRevision, "Provider MFA expectedPolicyRevision"),
    trustedVerifierId: requiredString(raw.trustedVerifierId, "Provider MFA trustedVerifierId"),
    maxEvidenceAgeSeconds: Number(raw.maxEvidenceAgeSeconds),
  };
  if (policy.expectedLoginMethodId !== allowedIdentityProviderIds[0]) {
    throw new Error("Provider MFA expectedLoginMethodId must exactly match the allowed Cloudflare Access login method ID.");
  }
  if (!Number.isInteger(policy.maxEvidenceAgeSeconds) || policy.maxEvidenceAgeSeconds < 60 || policy.maxEvidenceAgeSeconds > 86400) {
    throw new Error("Provider MFA maxEvidenceAgeSeconds must be an integer from 60 through 86400.");
  }
  return policy;
}

export function providerMfaPolicyDigest(policy) {
  return sha256Canonical(policy);
}

function isLivePlaceholder(value) {
  const text = String(value ?? "").trim();
  return !text
    || /^replace-with-/i.test(text)
    || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(text)
    || /(^|\.)example\.(?:com|invalid)(?:\/|$)/i.test(text);
}

export function assertProviderMfaPolicyReadyForLive(policy) {
  const fields = [
    [policy.provider, "provider"],
    [policy.expectedIssuer, "expectedIssuer"],
    [policy.expectedTenantId, "expectedTenantId"],
    [policy.expectedClientId, "expectedClientId"],
    [policy.expectedLoginMethodId, "expectedLoginMethodId"],
    [policy.expectedPolicyRevision, "expectedPolicyRevision"],
    [policy.trustedVerifierId, "trustedVerifierId"],
    ...policy.acceptedAuthenticationContexts.map((value) => [value, "acceptedAuthenticationContexts"]),
    ...policy.acceptedMethods.map((value) => [value, "acceptedMethods"]),
  ];
  const placeholder = fields.find(([value]) => isLivePlaceholder(value));
  if (placeholder) throw new Error(`Replace provider MFA placeholder ${placeholder[1]} before live Access operations.`);
  return policy;
}

function verifiedAccessApplications(applications) {
  return (Array.isArray(applications) ? applications : [])
    .filter((entry) => entry?.result === "access-shape-verified")
    .map((entry) => ({
      applicationId: String(entry.applicationId ?? "").trim(),
      policyId: String(entry.policyId ?? "").trim(),
      name: String(entry.name ?? "").trim(),
      domain: String(entry.domain ?? "").trim().toLowerCase(),
    }));
}

export function pendingProviderMfaAssurance({ policy, applications, accountId, teamName }) {
  const verified = verifiedAccessApplications(applications);
  return {
    schemaVersion: RECEIPT_SCHEMA_VERSION,
    status: "pending-provider",
    assuranceBoundary: "external-provider",
    ownership: "EXTERNAL",
    authenticated: false,
    providerBacked: false,
    liveVerified: false,
    policyDigest: providerMfaPolicyDigest(policy),
    expectedPolicy: policy,
    requiredBindings: {
      accountId: String(accountId ?? ""),
      teamName: String(teamName ?? ""),
      accessApplicationIds: verified.map((entry) => entry.applicationId).filter(Boolean).sort(),
      accessPolicyIds: verified.map((entry) => entry.policyId).filter(Boolean).sort(),
      applicationDomains: verified.map((entry) => entry.domain).filter(Boolean).sort(),
    },
    receipt: null,
    reason: "Fresh authenticated provider MFA evidence was not supplied or verified; assurance remains external.",
  };
}

function failed(reason) {
  return { status: "failed", passed: false, reason };
}

export function evaluateProviderMfaAssurance(payload) {
  const assurance = payload?.providerMfaAssurance;
  if (!assurance || typeof assurance !== "object") {
    return { status: "pending-provider", passed: false, reason: "missing authenticated provider MFA assurance" };
  }
  if (Object.hasOwn(payload?.manifest ?? {}, "mfaEnforcedByIdentityProvider")) {
    return failed("legacy local MFA self-attestation is not admissible");
  }
  if (assurance.schemaVersion !== RECEIPT_SCHEMA_VERSION
    || assurance.assuranceBoundary !== "external-provider"
    || assurance.ownership !== "EXTERNAL") {
    return failed("invalid provider MFA assurance boundary or schema");
  }
  let policy;
  try {
    policy = normalizeProviderMfaPolicy(assurance.expectedPolicy, {
      allowedIdentityProviderIds: [assurance.expectedPolicy?.expectedLoginMethodId],
    });
  } catch (error) {
    return failed(String(error?.message ?? error));
  }
  if (assurance.policyDigest !== providerMfaPolicyDigest(policy)) return failed("provider MFA policy digest mismatch");

  const verified = verifiedAccessApplications(payload?.applications);
  const applicationIds = verified.map((entry) => entry.applicationId).filter(Boolean).sort();
  const policyIds = verified.map((entry) => entry.policyId).filter(Boolean).sort();
  const applicationDomains = verified.map((entry) => entry.domain).filter(Boolean).sort();
  if (verified.length !== (payload?.applications?.length ?? 0)
    || applicationIds.length !== verified.length
    || policyIds.length !== verified.length) {
    return failed("provider MFA binding requires exact verified Access application and policy IDs");
  }
  if (!exactArray(assurance.requiredBindings?.accessApplicationIds, applicationIds)
    || !exactArray(assurance.requiredBindings?.accessPolicyIds, policyIds)
    || !exactArray(assurance.requiredBindings?.applicationDomains, applicationDomains)
    || assurance.requiredBindings?.accountId !== payload?.manifest?.accountId
    || assurance.requiredBindings?.teamName !== payload?.manifest?.teamName) {
    return failed("provider MFA assurance is not bound to the exact Access account, team, applications, and policies");
  }

  if (assurance.status === "passed"
    || assurance.authenticated === true
    || assurance.providerBacked === true
    || assurance.liveVerified === true
    || assurance.receipt !== null) {
    return failed("untrusted provider MFA pass or receipt claim; no authenticated provider verifier is implemented in this boundary");
  }
  if (assurance.status !== "pending-provider"
    || assurance.authenticated !== false
    || assurance.providerBacked !== false
    || assurance.liveVerified !== false) {
    return failed("provider MFA assurance must remain fail-closed pending-provider");
  }
  return {
    status: "pending-provider",
    passed: false,
    reason: "fresh authenticated provider MFA evidence remains external and unavailable",
  };
}
