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

export function approvedReleaseSubjects(entries, repository) {
  const subjects = canonicalReleaseSubjects(entries);
  const expectedRepository = exactRepository(repository);
  const [owner] = expectedRepository.split("/");
  const approved = new Map([
    ["PHP_APACHE_IMAGE", `ghcr.io/${owner.toLowerCase()}/platform-infrastructure-php-apache`],
    ["CONTROL_CENTER_IMAGE", `ghcr.io/${owner.toLowerCase()}/platform-infrastructure-control-center`],
    ["PROJECT_ROUTER_IMAGE", `ghcr.io/${owner.toLowerCase()}/platform-infrastructure-project-router`],
    ["PLATFORM_ALERT_DISPATCHER_IMAGE", `ghcr.io/${owner.toLowerCase()}/platform-infrastructure-alert-dispatcher`],
    ["PLATFORM_BACKUP_SCHEDULER_IMAGE", `ghcr.io/${owner.toLowerCase()}/platform-infrastructure-backup-scheduler`],
  ]);
  for (const subject of subjects) {
    const expectedName = approved.get(subject.key);
    if (!expectedName || subject.name !== expectedName) {
      invalid(`Release subject ${subject.key} is not mapped to its approved OCI repository.`);
    }
  }
  return subjects;
}

function propertiesMap(properties, label) {
  if (!Array.isArray(properties)) invalid(`${label} properties must be an array.`);
  const map = new Map();
  for (const property of properties) {
    const name = exactText(property?.name, `${label} property name`);
    if (map.has(name)) invalid(`${label} contains duplicate property ${name}.`);
    if (typeof property?.value !== "string") invalid(`${label} property ${name} value must be a string.`);
    map.set(name, property.value);
  }
  return map;
}

export function validateCycloneDxReleaseSbom(sbom, { subjects: rawSubjects, repository, commitSha, buildkitSbomSha256 = null }) {
  const subjects = approvedReleaseSubjects(rawSubjects, repository);
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
  if (metadataProperties.get("sbom.source") !== "buildkit-attestation-spdx") invalid("SBOM dependency inventory is not sourced from BuildKit SPDX attestation output.");
  const rawBuildkitSha256 = metadataProperties.get("buildkitSbomSha256");
  if (!/^[a-f0-9]{64}$/.test(String(rawBuildkitSha256 ?? ""))) invalid("SBOM metadata lacks the raw BuildKit SBOM SHA256.");
  if (buildkitSbomSha256 !== null && rawBuildkitSha256 !== buildkitSbomSha256) invalid("SBOM raw BuildKit artifact hash binding is mismatched.");
  const platformText = metadataProperties.get("buildkitPlatforms");
  const platforms = typeof platformText === "string" ? platformText.split(",") : [];
  if (platforms.length === 0 || platforms.some((platform) => !/^linux\/(amd64|arm64)$/.test(platform)) || new Set(platforms).size !== platforms.length) {
    invalid("SBOM BuildKit platform inventory is missing, invalid or duplicated.");
  }
  if (metadataProperties.get("releaseSubjectCount") !== String(subjects.length)) invalid("SBOM release subject count binding is mismatched.");
  if (!Array.isArray(sbom.components) || sbom.components.length === 0) invalid("SBOM components must be a non-empty array.");

  const expectedByName = new Map(subjects.map((subject) => [subject.name, subject]));
  const seen = new Set();
  const subjectComponents = [];
  const dependencyComponents = [];
  for (const component of sbom.components) {
    const componentProperties = propertiesMap(component?.properties, `SBOM component ${String(component?.name ?? "unknown")}`);
    if (componentProperties.has("releaseSubjectKey")) subjectComponents.push({ component, componentProperties });
    else dependencyComponents.push({ component, componentProperties });
  }
  for (const { component, componentProperties } of subjectComponents) {
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
    if (componentProperties.size !== 1 || componentProperties.get("releaseSubjectKey") !== expected.key) invalid(`SBOM component ${name} is not bound only to release key ${expected.key}.`);
  }
  if (seen.size !== subjects.length) invalid("SBOM is missing one or more exact release subject components.");
  if (dependencyComponents.length === 0) invalid("SBOM dependency inventory is empty.");
  const dependencyRefs = new Set();
  for (const { component, componentProperties } of dependencyComponents) {
    const name = exactText(component?.name, "SBOM dependency name");
    exactText(component?.version, `SBOM dependency ${name} version`);
    if (component.type !== "library" || !/^urn:buildkit-spdx:[a-f0-9]{64}$/.test(String(component["bom-ref"] ?? ""))) {
      invalid(`SBOM dependency ${name} is not an exact BuildKit package component.`);
    }
    if (dependencyRefs.has(component["bom-ref"])) invalid(`SBOM dependency ${name} has a duplicate bom-ref.`);
    dependencyRefs.add(component["bom-ref"]);
    if (component.purl !== undefined && (typeof component.purl !== "string" || !/^pkg:\S+$/.test(component.purl))) {
      invalid(`SBOM dependency ${name} has an invalid purl.`);
    }
    if (componentProperties.size !== 4
      || componentProperties.get("sbom.source") !== "buildkit-attestation-spdx"
      || !platforms.includes(componentProperties.get("buildkit.platform"))
      || !/^SPDXRef-[A-Za-z0-9.-]+$/.test(String(componentProperties.get("buildkit.spdxId") ?? ""))
      || !subjects.some((subject) => subject.image === componentProperties.get("releaseSubjectImage"))) {
      invalid(`SBOM dependency ${name} lacks exact BuildKit provenance properties.`);
    }
  }
  if (metadataProperties.get("buildkitPackageCount") !== String(dependencyComponents.length)) invalid("SBOM BuildKit package count binding is mismatched.");
  return {
    repository: expectedRepository,
    commitSha: expectedCommit,
    subjects,
    dependencyCount: dependencyComponents.length,
    buildkitSbomSha256: rawBuildkitSha256,
    platforms,
    dependencyComponents: dependencyComponents.map(({ component }) => component),
    schemaValidation,
  };
}

export function validateCryptographicReleaseVerification(verification, { subjects: rawSubjects, repository, commitSha }) {
  const subjects = approvedReleaseSubjects(rawSubjects, repository);
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
  const perSubjectVerification = subjects.map((subject) => {
    const matches = verification.attestations.filter((attestation) => Array.isArray(attestation?.subjects)
      && attestation.subjects.some((entry) => entry?.name === subject.name && entry?.sha256 === subject.sha256));
    if (matches.length !== 1) invalid(`Release subject ${subject.key} must have one exact verifier result.`);
    const attestation = matches[0];
    if (attestation.status !== "passed" || attestation.verified !== true || attestation.completeness !== "complete"
      || attestation.repository !== expectedRepository || attestation.sourceDigest !== expectedCommit
      || attestation.signerWorkflow !== verification.signerWorkflow || attestation.sourceRef !== verification.sourceRef
      || !/^https:\/\/slsa\.dev\/provenance\/v1$/.test(String(attestation.predicateType ?? ""))
      || !/^https:\/\/token\.actions\.githubusercontent\.com$/.test(String(attestation.certOidcIssuer ?? ""))
      || !Array.isArray(attestation.certificateFingerprints) || attestation.certificateFingerprints.length === 0
      || attestation.certificateFingerprints.some((fingerprint) => !/^[a-f0-9]{64}$/.test(String(fingerprint)))
      || !Number.isInteger(attestation.verifiedTimestampCount) || attestation.verifiedTimestampCount < 1) {
      invalid(`Release subject ${subject.key} verifier receipt is incomplete or mismatched.`);
    }
    return { subject, attestation };
  });
  return { repository: expectedRepository, commitSha: expectedCommit, subjects, perSubjectVerification };
}

export function validateAttestedReleaseManifest(manifest, {
  subjects: rawSubjects,
  repository,
  commitSha,
  sbomSha256,
  buildkitSbomSha256,
  registryResolutionSha256,
  registryDescriptorSha256,
  registryRootDescriptorSha256,
  resolvedPlatforms,
  subjectEvidence = null,
}) {
  const subjects = approvedReleaseSubjects(rawSubjects, repository);
  const expectedRepository = exactRepository(repository);
  const expectedCommit = exactGitSha(commitSha);
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) invalid("Release subject manifest must be a JSON object.");
  if (![3, 4].includes(manifest.version) || manifest.source !== "registry-resolved-cryptographically-verified-subjects") {
    invalid("Release subject manifest must use registry-resolved verified schema version 3 or 4.");
  }
  if (manifest.repository !== expectedRepository || manifest.commitSha !== expectedCommit) invalid("Release subject manifest repository/commit binding is mismatched.");
  if (!/^[a-f0-9]{64}$/.test(String(sbomSha256 ?? "")) || manifest.sbom?.sha256 !== sbomSha256) invalid("Attested release manifest does not authenticate the exact SBOM SHA256.");
  if (manifest.sbom?.schema !== "http://cyclonedx.org/schema/bom-1.5.schema.json") invalid("Attested release manifest does not bind CycloneDX 1.5.");
  const manifestSubjects = canonicalReleaseSubjects(manifest.subjects ?? []);
  const expected = subjects.map((subject) => `${subject.key}\u0000${subject.image}`).sort();
  const actual = manifestSubjects.map((subject) => `${subject.key}\u0000${subject.image}`).sort();
  if (JSON.stringify(expected) !== JSON.stringify(actual)) invalid("Attested release manifest subject set is mismatched.");
  if (manifest.version === 3) {
    if (!/^[a-f0-9]{64}$/.test(String(buildkitSbomSha256 ?? "")) || manifest.sbom?.buildkitSha256 !== buildkitSbomSha256) {
      invalid("Attested release manifest does not bind the raw BuildKit SBOM artifact.");
    }
    if (!/^[a-f0-9]{64}$/.test(String(registryResolutionSha256 ?? ""))
      || manifest.registryResolution?.sha256 !== registryResolutionSha256
      || manifest.registryResolution?.descriptorArtifactSha256 !== registryDescriptorSha256
      || manifest.registryResolution?.descriptorSha256 !== registryRootDescriptorSha256) {
      invalid("Attested release manifest does not bind exact registry resolution evidence.");
    }
    const expectedPlatforms = (resolvedPlatforms ?? []).map(({ platform, digest, size, mediaType, imageId, configSize, configMediaType, manifestArtifactSha256 }) => ({
      platform, descriptorDigest: digest, size, mediaType, imageId, configSize, configMediaType, manifestArtifactSha256,
    })).sort((left, right) => left.platform.localeCompare(right.platform));
    if (expectedPlatforms.length === 0) invalid("Resolved release platform descriptors are required.");
    for (const subject of manifest.subjects) {
      const actualPlatforms = Array.isArray(subject.platforms)
        ? subject.platforms.map(({ platform, descriptorDigest, size, mediaType, imageId, configSize, configMediaType, manifestArtifactSha256 }) => ({ platform, descriptorDigest, size, mediaType, imageId, configSize, configMediaType, manifestArtifactSha256 })).sort((left, right) => left.platform.localeCompare(right.platform))
        : [];
      if (JSON.stringify(actualPlatforms) !== JSON.stringify(expectedPlatforms)) invalid(`Attested release subject ${subject.key} platform descriptors are mismatched.`);
    }
    const platformNames = expectedPlatforms.map((entry) => entry.platform);
    if (JSON.stringify(manifest.registryResolution.platforms) !== JSON.stringify(platformNames)) invalid("Attested release manifest platform set is mismatched.");
  } else {
    if (!/^[a-f0-9]{64}$/.test(String(buildkitSbomSha256 ?? ""))
      || manifest.sbom?.buildkitEvidenceSha256 !== buildkitSbomSha256) {
      invalid("Attested release manifest does not bind the complete BuildKit evidence set.");
    }
    if (!Array.isArray(subjectEvidence) || subjectEvidence.length !== subjects.length) {
      invalid("Exact per-subject registry and BuildKit evidence is required.");
    }
    const expectedEvidence = subjectEvidence.map((entry) => {
      const subject = subjects.find((candidate) => candidate.key === entry?.key);
      if (!subject || entry.image !== subject.image || !/^[a-f0-9]{64}$/.test(String(entry.buildkitSbomSha256 ?? ""))
        || !/^[a-f0-9]{64}$/.test(String(entry.registryResolutionSha256 ?? ""))) {
        invalid("Per-subject release evidence is invalid or mismatched.");
      }
      const resolution = entry.registryResolution;
      if (resolution?.image !== subject.image || resolution?.rootDigest !== subject.digest
        || resolution?.descriptorSha256 !== subject.sha256 || !Array.isArray(resolution?.platforms)
        || resolution.platforms.length === 0) {
        invalid(`Registry resolution for ${subject.key} is not bound to the exact subject.`);
      }
      return {
        key: subject.key,
        image: subject.image,
        buildkitSbomSha256: entry.buildkitSbomSha256,
        registryResolutionSha256: entry.registryResolutionSha256,
        descriptorSha256: resolution.descriptorSha256,
        descriptorArtifactSha256: resolution.descriptorArtifactSha256,
        platforms: resolution.platforms.map((platform) => platform.platform).sort(),
      };
    }).sort((left, right) => left.key.localeCompare(right.key));
    if (JSON.stringify(manifest.subjectEvidence) !== JSON.stringify(expectedEvidence)) {
      invalid("Attested release manifest per-subject evidence set is mismatched.");
    }
    for (const subject of manifest.subjects) {
      const resolution = subjectEvidence.find((entry) => entry.key === subject.key)?.registryResolution;
      const expectedPlatforms = resolution.platforms.map(({ platform, digest, size, mediaType, imageId, configSize, configMediaType, manifestArtifactSha256 }) => ({
        platform, descriptorDigest: digest, size, mediaType, imageId, configSize, configMediaType, manifestArtifactSha256,
      })).sort((left, right) => left.platform.localeCompare(right.platform));
      const actualPlatforms = Array.isArray(subject.platforms)
        ? subject.platforms.map(({ platform, descriptorDigest, size, mediaType, imageId, configSize, configMediaType, manifestArtifactSha256 }) => ({
          platform, descriptorDigest, size, mediaType, imageId, configSize, configMediaType, manifestArtifactSha256,
        })).sort((left, right) => left.platform.localeCompare(right.platform))
        : [];
      if (JSON.stringify(actualPlatforms) !== JSON.stringify(expectedPlatforms)) {
        invalid(`Attested release subject ${subject.key} platform descriptors are mismatched.`);
      }
    }
  }
  return { repository: expectedRepository, commitSha: expectedCommit, subjects };
}

export function sha256Json(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

export function buildReleaseAdmissionReceipt({
  subjects,
  repository,
  commitSha,
  sourceArchiveSha256,
  sbomSha256,
  buildkitSbomSha256 = null,
  registryResolutionSha256 = null,
  registryResolution = null,
  subjectEvidence = null,
  manifestSha256,
  verification,
  manifestVerification = null,
  generatedAt = new Date().toISOString(),
}) {
  const binding = validateCryptographicReleaseVerification(verification, { subjects, repository, commitSha });
  if (!/^[a-f0-9]{64}$/.test(String(sourceArchiveSha256 ?? ""))) invalid("Exact source archive SHA256 is required for the admission receipt.");
  if (!/^[a-f0-9]{64}$/.test(String(sbomSha256 ?? ""))) invalid("SBOM artifact SHA256 is required for the admission receipt.");
  const legacySingleEvidence = subjectEvidence === null;
  const evidence = subjectEvidence ?? [{
    key: binding.subjects[0]?.key,
    image: binding.subjects[0]?.image,
    buildkitSbomSha256,
    registryResolutionSha256,
    registryResolution,
  }];
  if (!Array.isArray(evidence) || evidence.length !== binding.subjects.length) {
    invalid("Exact per-subject registry resolution is required for the admission receipt.");
  }
  const evidenceByKey = new Map(evidence.map((entry) => [entry?.key, entry]));
  if (evidenceByKey.size !== binding.subjects.length) invalid("Per-subject release evidence keys must be exact and unique.");
  for (const subject of binding.subjects) {
    const entry = evidenceByKey.get(subject.key);
    const resolution = entry?.registryResolution;
    if (entry?.image !== subject.image
      || (!legacySingleEvidence && !/^[a-f0-9]{64}$/.test(String(entry?.buildkitSbomSha256 ?? "")))
      || (!legacySingleEvidence && !/^[a-f0-9]{64}$/.test(String(entry?.registryResolutionSha256 ?? "")))
      || resolution?.version !== 2 || resolution?.kind !== "platform-registry-subject-resolution/v2"
      || resolution?.status !== "passed" || resolution?.image !== subject.image
      || resolution?.rootDigest !== subject.digest || resolution?.descriptorSha256 !== subject.sha256
      || !Array.isArray(resolution?.platforms) || resolution.platforms.length === 0
      || resolution.platforms.some((platform) => !/^linux\/(amd64|arm64)$/.test(String(platform?.platform ?? ""))
        || !/^sha256:[a-f0-9]{64}$/.test(String(platform?.digest ?? ""))
        || !/^sha256:[a-f0-9]{64}$/.test(String(platform?.imageId ?? ""))
        || platform.imageId === platform.digest
        || platform.imageId === resolution.rootDigest
        || !Number.isInteger(platform?.size) || platform.size < 1
        || !Number.isInteger(platform?.configSize) || platform.configSize < 1
        || !/^[a-f0-9]{64}$/.test(String(platform?.manifestArtifactSha256 ?? "")))) {
      invalid(`Exact per-subject registry resolution is required for ${subject.key}.`);
    }
  }
  const canonicalEvidenceHashes = binding.subjects.map((subject) => {
    const entry = evidenceByKey.get(subject.key);
    return {
      key: subject.key,
      buildkitSbomSha256: entry.buildkitSbomSha256,
      registryResolutionSha256: entry.registryResolutionSha256,
    };
  }).sort((left, right) => left.key.localeCompare(right.key));
  return {
    version: 1,
    kind: "platform-release-artifact-verification/v1",
    status: "EXTERNAL-PENDING",
    artifactVerification: "passed",
    generatedAt,
    repository: binding.repository,
    commitSha: binding.commitSha,
    sourceArchiveSha256,
    subjects: binding.subjects.map(({ key, image, name, digest }) => ({ key, image, name, digest })),
    subjectVerificationReceipts: binding.perSubjectVerification.map(({ subject, attestation }) => ({
      key: subject.key,
      image: subject.image,
      registry: {
        rootDigest: evidenceByKey.get(subject.key).registryResolution.rootDigest,
        descriptorSha256: evidenceByKey.get(subject.key).registryResolution.descriptorSha256,
        platforms: evidenceByKey.get(subject.key).registryResolution.platforms.map(({
          platform, digest, size, mediaType, imageId, configSize, configMediaType, manifestArtifactSha256,
        }) => ({ platform, digest, size, mediaType, imageId, configSize, configMediaType, manifestArtifactSha256 })),
      },
      attestationReference: {
        provider: verification.provider,
        repository: verification.repository,
        subject: `oci://${subject.image}`,
        signerWorkflow: verification.signerWorkflow,
        sourceDigest: verification.sourceDigest,
        sourceRef: verification.sourceRef,
        predicateType: attestation.predicateType,
        certOidcIssuer: attestation.certOidcIssuer,
      },
      certificateFingerprints: [...attestation.certificateFingerprints].sort(),
      verifiedTimestampCount: attestation.verifiedTimestampCount,
      verifierResultFingerprint: sha256Json(attestation),
    })),
    sbomSha256,
    buildkitSbomSha256: /^[a-f0-9]{64}$/.test(String(buildkitSbomSha256 ?? "")) ? buildkitSbomSha256 : null,
    registryResolutionSha256: binding.subjects.length === 1
      ? canonicalEvidenceHashes[0].registryResolutionSha256
      : sha256Json(canonicalEvidenceHashes),
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
