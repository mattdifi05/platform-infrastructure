import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1";
export const GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com";

function invalid(message) {
  throw new Error(message);
}

function requiredText(value, label) {
  const text = String(value ?? "").trim();
  if (!text || /[\0\r\n]/.test(text)) {
    invalid(`${label} is missing or invalid.`);
  }
  return text;
}

export function normalizeSha256(value, label = "SHA256 digest") {
  const match = String(value ?? "").trim().toLowerCase().match(/^(?:sha256:)?([a-f0-9]{64})$/);
  if (!match) {
    invalid(`${label} must be a complete SHA256 digest.`);
  }
  return match[1];
}

export function normalizeGitSha(value, label = "source digest") {
  const text = requiredText(value, label).toLowerCase();
  if (!/^[a-f0-9]{40}$/.test(text)) {
    invalid(`${label} must be a full 40-character Git commit SHA.`);
  }
  return text;
}

export function normalizeRepository(value) {
  const text = requiredText(value, "GitHub repository");
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(text)) {
    invalid("GitHub repository must use owner/name.");
  }
  return text;
}

export function normalizeGithubRef(value) {
  const text = requiredText(value, "GitHub source ref");
  if (!/^refs\/(?:heads|tags)\/[A-Za-z0-9._/-]+$/.test(text) || text.includes("..") || text.endsWith("/")) {
    invalid("GitHub source ref must be a complete refs/heads/* or refs/tags/* value.");
  }
  return text;
}

export function normalizeSignerWorkflow(value, repository) {
  const text = requiredText(value, "signer workflow");
  const prefix = `${repository}/.github/workflows/`;
  if (!text.startsWith(prefix) || !/\.ya?ml$/.test(text) || text.slice(prefix.length).includes("..")) {
    invalid(`Signer workflow must be an exact workflow path inside ${repository}.`);
  }
  return text;
}

function normalizeSubject(value) {
  const text = requiredText(value, "attestation subject");
  if (text.startsWith("-") || /[\0\r\n]/.test(text)) {
    invalid("Attestation subject cannot be interpreted as a CLI option.");
  }
  if (text.startsWith("oci://")) {
    if (!/@sha256:[a-f0-9]{64}$/i.test(text)) {
      invalid("OCI attestation subjects must be digest-pinned.");
    }
    return text;
  }
  return path.resolve(text);
}

export function normalizeOciSubject(value) {
  const normalized = normalizeSubject(value);
  if (!normalized.startsWith("oci://")) {
    invalid("Expected an OCI attestation subject.");
  }
  const match = normalized.match(/^oci:\/\/(.+)@sha256:([a-f0-9]{64})$/i);
  if (!match || !match[1] || match[1].includes("@")) {
    invalid("OCI attestation subject must contain one exact image name and SHA256 digest.");
  }
  return { subject: normalized, name: match[1], sha256: match[2].toLowerCase() };
}

function existingFile(value, label) {
  const resolved = path.resolve(requiredText(value, label));
  if (!fs.statSync(resolved, { throwIfNoEntry: false })?.isFile()) {
    invalid(`${label} file not found: ${resolved}`);
  }
  return resolved;
}

export function buildGithubAttestationVerifyArgs({
  subject,
  repository,
  signerWorkflow,
  sourceDigest,
  sourceRef,
  bundle = null,
  trustedRoot = null,
  predicateType = SLSA_PROVENANCE_V1,
  certOidcIssuer = GITHUB_ACTIONS_OIDC_ISSUER,
}) {
  const normalizedSubject = normalizeSubject(subject);
  const normalizedRepository = normalizeRepository(repository);
  const normalizedSigner = normalizeSignerWorkflow(signerWorkflow, normalizedRepository);
  const normalizedSourceDigest = normalizeGitSha(sourceDigest);
  const normalizedSourceRef = normalizeGithubRef(sourceRef);
  const normalizedPredicate = requiredText(predicateType, "predicate type");
  const normalizedIssuer = requiredText(certOidcIssuer, "certificate OIDC issuer");
  if ((bundle && !trustedRoot) || (!bundle && trustedRoot)) {
    invalid("Offline verification requires both an attestation bundle and a custom trusted root.");
  }

  const args = [
    "attestation",
    "verify",
    normalizedSubject,
    "--repo",
    normalizedRepository,
    "--signer-workflow",
    normalizedSigner,
    "--source-digest",
    normalizedSourceDigest,
    "--signer-digest",
    normalizedSourceDigest,
    "--source-ref",
    normalizedSourceRef,
    "--cert-oidc-issuer",
    normalizedIssuer,
    "--predicate-type",
    normalizedPredicate,
    "--deny-self-hosted-runners",
    "--format",
    "json",
  ];
  if (bundle) {
    args.push("--bundle", existingFile(bundle, "attestation bundle"));
    args.push("--custom-trusted-root", existingFile(trustedRoot, "trusted root"));
  }
  return args;
}

function statementSubjects(statement) {
  if (!Array.isArray(statement?.subject) || statement.subject.length === 0) {
    invalid("Verified attestation statement has no subjects.");
  }
  return statement.subject.map((subject) => {
    const digest = normalizeSha256(subject?.digest?.sha256, "verified subject digest");
    return {
      name: typeof subject?.name === "string" ? subject.name : null,
      sha256: digest,
    };
  });
}

function canonicalFingerprint(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

export function parseCryptographicallyVerifiedGithubOutput(rawOutput, {
  expectedSubjectDigest,
  expectedSubjectName,
  predicateType = SLSA_PROVENANCE_V1,
} = {}) {
  let document;
  try {
    document = JSON.parse(String(rawOutput));
  } catch (error) {
    invalid(`GitHub attestation verifier returned invalid JSON: ${error.message}`);
  }
  if (!Array.isArray(document) || document.length === 0) {
    invalid("GitHub attestation verifier must return a non-empty result array.");
  }

  const expectedDigest = expectedSubjectDigest ? normalizeSha256(expectedSubjectDigest, "expected subject digest") : null;
  const expectedName = expectedSubjectName ? requiredText(expectedSubjectName, "expected subject name") : null;
  const results = document.map((entry, index) => {
    const verification = entry?.verificationResult;
    if (!verification || typeof verification !== "object") {
      invalid(`Attestation result ${index + 1} lacks verificationResult; self-asserted reports are not accepted.`);
    }
    const certificate = verification.signature?.certificate;
    if (!certificate || typeof certificate !== "object" || Array.isArray(certificate) || Object.keys(certificate).length === 0) {
      invalid(`Attestation result ${index + 1} lacks a verified signing certificate.`);
    }
    if (!Array.isArray(verification.verifiedTimestamps) || verification.verifiedTimestamps.length === 0) {
      invalid(`Attestation result ${index + 1} lacks a verified transparency-log or timestamp witness.`);
    }
    const statement = verification.statement;
    if (!statement || typeof statement !== "object") {
      invalid(`Attestation result ${index + 1} lacks a verified in-toto statement.`);
    }
    if (statement.predicateType !== predicateType) {
      invalid(`Attestation result ${index + 1} has unexpected predicate type ${statement.predicateType ?? "missing"}.`);
    }
    const subjects = statementSubjects(statement);
    return {
      certificateFingerprint: canonicalFingerprint(certificate),
      verifiedTimestampCount: verification.verifiedTimestamps.length,
      subjects,
    };
  });

  const subjects = [];
  const seen = new Set();
  for (const result of results) {
    for (const subject of result.subjects) {
      const key = `${subject.name ?? ""}@${subject.sha256}`;
      if (!seen.has(key)) {
        seen.add(key);
        subjects.push(subject);
      }
    }
  }
  if (expectedDigest && expectedName && !subjects.some((subject) => subject.sha256 === expectedDigest && subject.name === expectedName)) {
    invalid(`Verified attestation does not cover exact subject ${expectedName}@sha256:${expectedDigest}.`);
  }
  if (expectedDigest && !expectedName && !subjects.some((subject) => subject.sha256 === expectedDigest)) {
    invalid(`Verified attestation does not cover expected subject sha256:${expectedDigest}.`);
  }
  return {
    resultCount: results.length,
    subjects,
    certificateFingerprints: [...new Set(results.map((result) => result.certificateFingerprint))],
    verifiedTimestampCount: results.reduce((sum, result) => sum + result.verifiedTimestampCount, 0),
  };
}

function safeVerifierError(value) {
  return String(value ?? "")
    .replace(/(?:Bearer|token)\s+[A-Za-z0-9._~-]+/gi, "[credential redacted]")
    .replace(/[\r\n]+/g, " ")
    .trim()
    .slice(0, 1000);
}

export function verifyGithubAttestation(options, { verifierBinary = "/usr/local/bin/gh" } = {}) {
  const args = buildGithubAttestationVerifyArgs(options);
  const result = spawnSync(verifierBinary, args, {
    encoding: "utf8",
    env: process.env,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error) {
    invalid(`GitHub attestation verifier could not start: ${safeVerifierError(result.error.message)}`);
  }
  if (result.status !== 0) {
    invalid(`GitHub attestation cryptographic verification failed: ${safeVerifierError(result.stderr) || `exit ${result.status}`}`);
  }
  const parsed = parseCryptographicallyVerifiedGithubOutput(result.stdout, {
    expectedSubjectDigest: options.expectedSubjectDigest,
    expectedSubjectName: options.expectedSubjectName,
    predicateType: options.predicateType,
  });
  return {
    status: "passed",
    kind: "github-sigstore-cryptographic-attestation",
    provider: "github-artifact-attestations",
    verified: true,
    completeness: "complete",
    repository: normalizeRepository(options.repository),
    signerWorkflow: normalizeSignerWorkflow(options.signerWorkflow, normalizeRepository(options.repository)),
    sourceDigest: normalizeGitSha(options.sourceDigest),
    sourceRef: normalizeGithubRef(options.sourceRef),
    predicateType: options.predicateType ?? SLSA_PROVENANCE_V1,
    certOidcIssuer: options.certOidcIssuer ?? GITHUB_ACTIONS_OIDC_ISSUER,
    selfHostedRunnerDenied: true,
    offlineBundleVerified: Boolean(options.bundle),
    commitSha: normalizeGitSha(options.sourceDigest),
    commitShaMatched: true,
    ...parsed,
  };
}

export function verifyGithubReleaseImages({ images, ...options }, runtime = {}) {
  if (!Array.isArray(images) || images.length === 0) {
    invalid("At least one release image is required for attestation verification.");
  }
  const attestations = images.map((image) => {
    const normalized = normalizeOciSubject(String(image).startsWith("oci://") ? image : `oci://${image}`);
    return verifyGithubAttestation({
      ...options,
      subject: normalized.subject,
      expectedSubjectDigest: normalized.sha256,
      expectedSubjectName: normalized.name,
    }, runtime);
  });
  const subjects = [];
  const seen = new Set();
  for (const attestation of attestations) {
    for (const subject of attestation.subjects) {
      const key = `${subject.name ?? ""}@${subject.sha256}`;
      if (!seen.has(key)) {
        seen.add(key);
        subjects.push(subject);
      }
    }
  }
  return {
    status: "passed",
    kind: "github-sigstore-cryptographic-attestation",
    provider: "github-artifact-attestations",
    verified: true,
    completeness: "complete",
    repository: attestations[0].repository,
    signerWorkflow: attestations[0].signerWorkflow,
    sourceDigest: attestations[0].sourceDigest,
    sourceRef: attestations[0].sourceRef,
    commitSha: attestations[0].commitSha,
    commitShaMatched: true,
    attestationCount: attestations.length,
    attestations,
    subjects,
    subjectCount: subjects.length,
    certificateFingerprints: [...new Set(attestations.flatMap((attestation) => attestation.certificateFingerprints))],
    verifiedTimestampCount: attestations.reduce((sum, attestation) => sum + attestation.verifiedTimestampCount, 0),
    releaseImages: images.map((image) => normalizeOciSubject(String(image).startsWith("oci://") ? image : `oci://${image}`)).map((subject) => `${subject.name}@sha256:${subject.sha256}`),
    releaseImageDigests: images.map((image) => normalizeSha256(String(image).split("@sha256:").at(-1))),
  };
}
