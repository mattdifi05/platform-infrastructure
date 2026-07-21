import crypto from "node:crypto";
import { validatePinnedCycloneDxReleaseSchema } from "./cyclonedx-schema-policy.mjs";

function invalid(message) {
  throw new Error(message);
}

function exactText(value, label) {
  const text = String(value ?? "").trim();
  if (!text || /[\0\r\n]/.test(text)) invalid(`${label} is missing or invalid.`);
  return text;
}

export function exactGitSha(value, label = "commit SHA") {
  const text = exactText(value, label).toLowerCase();
  if (!/^[a-f0-9]{40}$/.test(text)) invalid(`${label} must be a full 40-character Git SHA.`);
  return text;
}

export function exactRepository(value) {
  const text = exactText(value, "repository");
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(text)) invalid("repository must use exact owner/name syntax.");
  return text;
}

export function parseReleaseImage(value, key = null) {
  const text = exactText(value, key ? `release image ${key}` : "release image");
  const match = text.match(/^([a-z0-9.-]+(?::[0-9]+)?(?:\/[a-z0-9._-]+)+)@sha256:([a-f0-9]{64})$/);
  if (!match || text.includes(":latest")) invalid(`${key ?? "release image"} must be one exact lowercase registry/repository name pinned by SHA256 digest.`);
  return { key: key ?? match[1], image: text, name: match[1], digest: `sha256:${match[2]}`, sha256: match[2] };
}

export function canonicalReleaseSubjects(entries) {
  if (!Array.isArray(entries) || entries.length === 0) invalid("At least one release subject is required.");
  const subjects = entries.map((entry, index) => parseReleaseImage(entry?.image ?? entry, entry?.key ?? `IMAGE_${index + 1}`));
  const keys = subjects.map((subject) => subject.key);
  const images = subjects.map((subject) => subject.image);
  if (new Set(keys).size !== keys.length) invalid("Release subject keys must be unique.");
  if (new Set(images).size !== images.length) invalid("Release image subjects must be unique.");
  return subjects;
}

function propertiesMap(properties, label) {
  if (!Array.isArray(properties)) invalid(`${label} properties must be an array.`);
  const map = new Map();
  for (const property of properties) {
    const name = exactText(property?.name, `${label} property name`);
    if (map.has(name)) invalid(`${label} contains duplicate property ${name}.`);
    map.set(name, String(property?.value ?? ""));
  }
  return map;
}

export function validateCycloneDxReleaseSbom(sbom, { subjects: rawSubjects, repository, commitSha }) {
  const subjects = canonicalReleaseSubjects(rawSubjects);
  const expectedRepository = exactRepository(repository);
  const expectedCommit = exactGitSha(commitSha);
  if (!sbom || typeof sbom !== "object" || Array.isArray(sbom)) invalid("SBOM must be a JSON object.");
  const schemaValidation = validatePinnedCycloneDxReleaseSchema(sbom);
  if (sbom.bomFormat !== "CycloneDX" || sbom.specVersion !== "1.5") invalid("SBOM must be CycloneDX 1.5.");
  if (!Number.isInteger(sbom.version) || sbom.version < 1) invalid("SBOM version must be a positive integer.");
  if (!/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(sbom.serialNumber ?? ""))) {
    invalid("SBOM serialNumber must be a UUID URN.");
  }
  if (!Number.isFinite(Date.parse(String(sbom.metadata?.timestamp ?? "")))) invalid("SBOM metadata.timestamp must be valid.");
  if (sbom.metadata?.component?.type !== "application") invalid("SBOM metadata.component must identify the release application.");
  if (sbom.metadata?.component?.version !== expectedCommit) invalid("SBOM application version is not bound to the release commit.");
  if (sbom.metadata?.component?.purl !== `pkg:github/${expectedRepository}@${expectedCommit}`) invalid("SBOM application purl is not bound to the exact repository and commit.");
  const metadataProperties = propertiesMap(sbom.metadata?.properties, "SBOM metadata");
  if (metadataProperties.get("repository") !== expectedRepository || metadataProperties.get("commitSha") !== expectedCommit) {
    invalid("SBOM metadata repository/commitSha binding is missing or mismatched.");
  }
  if (!Array.isArray(sbom.components) || sbom.components.length !== subjects.length) invalid("SBOM component set must exactly match the release subject set.");

  const expectedByName = new Map(subjects.map((subject) => [subject.name, subject]));
  const seen = new Set();
  for (const component of sbom.components) {
    const name = exactText(component?.name, "SBOM component name");
    const expected = expectedByName.get(name);
    if (!expected || seen.has(name)) invalid(`SBOM contains an unexpected or duplicate component ${name}.`);
    seen.add(name);
    if (component.type !== "container" || component.version !== expected.digest) invalid(`SBOM component ${name} is not bound to its exact image digest.`);
    if (component.purl !== `pkg:oci/${name}@${expected.digest}`) invalid(`SBOM component ${name} has a mismatched OCI purl.`);
    const hashes = Array.isArray(component.hashes) ? component.hashes : [];
    if (!hashes.some((hash) => hash?.alg === "SHA-256" && String(hash?.content ?? "").toLowerCase() === expected.sha256)) {
      invalid(`SBOM component ${name} lacks its exact SHA-256 hash.`);
    }
    const componentProperties = propertiesMap(component.properties, `SBOM component ${name}`);
    if (componentProperties.get("releaseSubjectKey") !== expected.key) invalid(`SBOM component ${name} is not bound to release key ${expected.key}.`);
  }
  return { repository: expectedRepository, commitSha: expectedCommit, subjects, schemaValidation };
}

export function validateCryptographicReleaseVerification(verification, { subjects: rawSubjects, repository, commitSha }) {
  const subjects = canonicalReleaseSubjects(rawSubjects);
  const expectedRepository = exactRepository(repository);
  const expectedCommit = exactGitSha(commitSha);
  if (verification?.status !== "passed" || verification?.verified !== true || verification?.completeness !== "complete") {
    invalid("Cryptographic provenance verification did not complete successfully.");
  }
  if (verification.repository !== expectedRepository || verification.sourceDigest !== expectedCommit || verification.commitSha !== expectedCommit || verification.commitShaMatched !== true) {
    invalid("Cryptographic provenance is not bound to the exact repository and commit.");
  }
  const expectedImages = subjects.map((subject) => subject.image).sort();
  const verifiedImages = Array.isArray(verification.releaseImages) ? [...verification.releaseImages].sort() : [];
  if (JSON.stringify(expectedImages) !== JSON.stringify(verifiedImages)) invalid("Cryptographic provenance subject set does not exactly match release images.");
  if (!Array.isArray(verification.attestations) || verification.attestations.length !== subjects.length) invalid("Each release image must have one cryptographic provenance verification result.");
  return { repository: expectedRepository, commitSha: expectedCommit, subjects };
}

export function validateAttestedReleaseManifest(manifest, { subjects: rawSubjects, repository, commitSha, sbomSha256 }) {
  const subjects = canonicalReleaseSubjects(rawSubjects);
  const expectedRepository = exactRepository(repository);
  const expectedCommit = exactGitSha(commitSha);
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) invalid("Release subject manifest must be a JSON object.");
  if (manifest.version !== 2 || manifest.source !== "cryptographically-verified-subjects") invalid("Release subject manifest must use verified schema version 2.");
  if (manifest.repository !== expectedRepository || manifest.commitSha !== expectedCommit) invalid("Release subject manifest repository/commit binding is mismatched.");
  if (!/^[a-f0-9]{64}$/.test(String(sbomSha256 ?? "")) || manifest.sbom?.sha256 !== sbomSha256) invalid("Attested release manifest does not authenticate the exact SBOM SHA256.");
  if (manifest.sbom?.schema !== "http://cyclonedx.org/schema/bom-1.5.schema.json") invalid("Attested release manifest does not bind CycloneDX 1.5.");
  const manifestSubjects = canonicalReleaseSubjects(manifest.subjects ?? []);
  const expected = subjects.map((subject) => `${subject.key}\u0000${subject.image}`).sort();
  const actual = manifestSubjects.map((subject) => `${subject.key}\u0000${subject.image}`).sort();
  if (JSON.stringify(expected) !== JSON.stringify(actual)) invalid("Attested release manifest subject set is mismatched.");
  return { repository: expectedRepository, commitSha: expectedCommit, subjects };
}

export function sha256Json(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

export function buildReleaseAdmissionReceipt({ subjects, repository, commitSha, sbomSha256, manifestSha256, verification, manifestVerification = null }) {
  const binding = validateCryptographicReleaseVerification(verification, { subjects, repository, commitSha });
  if (!/^[a-f0-9]{64}$/.test(String(sbomSha256 ?? ""))) invalid("SBOM artifact SHA256 is required for the admission receipt.");
  return {
    version: 1,
    kind: "platform-release-artifact-verification/v1",
    status: "EXTERNAL-PENDING",
    artifactVerification: "passed",
    generatedAt: new Date().toISOString(),
    repository: binding.repository,
    commitSha: binding.commitSha,
    subjects: binding.subjects.map(({ key, image, name, digest }) => ({ key, image, name, digest })),
    sbomSha256,
    manifestSha256: /^[a-f0-9]{64}$/.test(String(manifestSha256 ?? "")) ? manifestSha256 : null,
    provenance: {
      provider: verification.provider,
      signerWorkflow: verification.signerWorkflow,
      sourceRef: verification.sourceRef,
      verifiedTimestampCount: verification.verifiedTimestampCount,
      verificationFingerprint: sha256Json(verification),
      manifestVerificationFingerprint: manifestVerification ? sha256Json(manifestVerification) : null,
    },
    deploymentAdmission: "EXTERNAL-PENDING",
    usageScope: "artifact-verification-only",
  };
}
