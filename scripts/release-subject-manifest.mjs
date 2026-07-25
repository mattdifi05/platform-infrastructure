#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  approvedReleaseSubjects,
  sha256Json,
  validateCryptographicReleaseVerification,
  validateCycloneDxReleaseSbom,
} from "./release-artifact-policy.mjs";
import { buildkitSbomSha256 as hashBuildkitSbom, buildkitSpdxInventory } from "./buildkit-sbom-policy.mjs";
import { validateRegistryResolutionReceipt } from "./release-registry-resolution.mjs";
import { verifyGithubReleaseImages } from "./release-trust.mjs";

function invalid(message) { throw new Error(message); }

function parseArgs(args) {
  const out = { images: [], buildkitSboms: [], registryDescriptors: [], registryResolutions: [] };
  for (let index = 0; index < args.length; index += 1) {
    const key = args[index];
    if (!key.startsWith("--")) invalid(`Unexpected argument ${key}.`);
    const value = args[index + 1];
    if (!value || value.startsWith("--")) invalid(`Missing value for ${key}.`);
    index += 1;
    if (key === "--image") out.images.push(value);
    else if (key === "--buildkitSbom") out.buildkitSboms.push(value);
    else if (key === "--registryDescriptor") out.registryDescriptors.push(value);
    else if (key === "--registryResolution") out.registryResolutions.push(value);
    else out[key.slice(2)] = value;
  }
  return out;
}

function imageEntry(value) {
  const separator = String(value).indexOf("=");
  if (separator < 1) invalid("--image must use KEY=registry/repository@sha256:digest.");
  return { key: value.slice(0, separator), image: value.slice(separator + 1) };
}

function keyedPath(value, label) {
  const separator = String(value).indexOf("=");
  if (separator < 1 || separator === value.length - 1) invalid(`${label} must use SUBJECT_KEY=path.`);
  return { key: value.slice(0, separator), pathname: value.slice(separator + 1) };
}

export function createVerifiedReleaseArtifacts({
  entries,
  repository,
  commitSha,
  releaseName,
  workflowRunId,
  workflowRunUrl,
  verification,
  buildkitSbom,
  buildkitSbomBytes,
  registryResolution,
  registryResolutionSha256,
  registryDescriptorBytes,
  subjectEvidence = null,
  expectedPlatforms = ["linux/amd64"],
  generatedAt = new Date().toISOString(),
  serialNumber = `urn:uuid:${crypto.randomUUID()}`,
}) {
  const requestedSubjects = approvedReleaseSubjects(entries, repository);
  validateCryptographicReleaseVerification(verification, { subjects: requestedSubjects, repository, commitSha });
  const rawEvidence = subjectEvidence ?? [{
    key: requestedSubjects[0]?.key,
    buildkitSbom,
    buildkitSbomBytes,
    registryResolution,
    registryResolutionSha256,
    registryDescriptorBytes,
  }];
  if (!Array.isArray(rawEvidence) || rawEvidence.length !== requestedSubjects.length) {
    invalid("Every release subject must have exactly one registry and BuildKit SBOM evidence set.");
  }
  const evidenceByKey = new Map();
  for (const evidence of rawEvidence) {
    if (!evidence?.key || evidenceByKey.has(evidence.key)) invalid("Release subject evidence keys must be present and unique.");
    evidenceByKey.set(evidence.key, evidence);
  }
  const verifiedEvidence = requestedSubjects.map((subject) => {
    const evidence = evidenceByKey.get(subject.key);
    if (!evidence) invalid(`Release subject evidence is missing ${subject.key}.`);
    const resolution = validateRegistryResolutionReceipt(evidence.registryResolution, {
      image: subject.image,
      descriptorBytes: evidence.registryDescriptorBytes,
      expectedPlatforms,
    });
    if (!/^[a-f0-9]{64}$/.test(String(evidence.registryResolutionSha256 ?? ""))) {
      invalid(`Registry resolution receipt SHA256 is required for ${subject.key}.`);
    }
    const buildkitSbomSha256 = hashBuildkitSbom(evidence.buildkitSbomBytes);
    const inventory = buildkitSpdxInventory(evidence.buildkitSbom, { subjects: [subject], expectedPlatforms });
    return {
      subject,
      resolution,
      inventory,
      buildkitSbomSha256,
      registryResolutionSha256: evidence.registryResolutionSha256,
    };
  });
  if (evidenceByKey.size !== requestedSubjects.length) invalid("Release subject evidence contains an unexpected key.");
  const buildkitBindings = verifiedEvidence
    .map(({ subject, buildkitSbomSha256 }) => ({ key: subject.key, sha256: buildkitSbomSha256 }))
    .sort((left, right) => left.key.localeCompare(right.key));
  const rawBuildkitSha256 = requestedSubjects.length === 1
    ? buildkitBindings[0].sha256
    : sha256Json(buildkitBindings);
  const inventory = {
    platforms: [...new Set(verifiedEvidence.flatMap((entry) => entry.inventory.platforms))].sort(),
    components: verifiedEvidence.flatMap((entry) => entry.inventory.components),
  };
  const verifiedByImage = new Map(verification.releaseImages.map((image) => [image, image]));
  const subjects = requestedSubjects.map((requested) => {
    const verifiedImage = verifiedByImage.get(requested.image);
    if (!verifiedImage) invalid(`Verifier output is missing ${requested.image}.`);
    return {
      key: requested.key,
      image: verifiedImage,
      name: requested.name,
      digest: requested.digest,
      platforms: verifiedEvidence.find((entry) => entry.subject.key === requested.key).resolution.platforms
        .map(({ platform, digest: descriptorDigest, size, mediaType }) => ({
        platform, descriptorDigest, size, mediaType,
      })),
    };
  });
  const sbom = {
    $schema: "http://cyclonedx.org/schema/bom-1.5.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber,
    version: 1,
    metadata: {
      timestamp: generatedAt,
      component: { type: "application", name: String(releaseName || commitSha), version: commitSha, purl: `pkg:github/${repository}@${commitSha}` },
      properties: [
        { name: "repository", value: repository },
        { name: "commitSha", value: commitSha },
        { name: "workflowRunId", value: String(workflowRunId ?? "") },
        { name: "sbom.source", value: "buildkit-attestation-spdx" },
        { name: "buildkitSbomSha256", value: rawBuildkitSha256 },
        { name: "buildkitPlatforms", value: inventory.platforms.join(",") },
        { name: "releaseSubjectCount", value: String(subjects.length) },
        { name: "buildkitPackageCount", value: String(inventory.components.length) },
      ],
    },
    components: [
      ...subjects.map((subject) => ({
        type: "container",
        name: subject.name,
        version: subject.digest,
        hashes: [{ alg: "SHA-256", content: subject.digest.slice("sha256:".length) }],
        purl: `pkg:oci/${subject.name}@${subject.digest}`,
        properties: [{ name: "releaseSubjectKey", value: subject.key }],
      })),
      ...inventory.components,
    ],
  };
  validateCycloneDxReleaseSbom(sbom, { subjects, repository, commitSha, buildkitSbomSha256: rawBuildkitSha256 });
  const sbomBytes = `${JSON.stringify(sbom, null, 2)}\n`;
  const sbomSha256 = crypto.createHash("sha256").update(sbomBytes).digest("hex");
  const manifest = {
    version: 4,
    generatedAt,
    releaseName: String(releaseName || commitSha),
    repository,
    commitSha,
    workflowRunId: String(workflowRunId ?? ""),
    workflowRunUrl: String(workflowRunUrl ?? ""),
    source: "registry-resolved-cryptographically-verified-subjects",
    sbom: {
      schema: "http://cyclonedx.org/schema/bom-1.5.schema.json",
      sha256: sbomSha256,
      buildkitEvidenceSha256: rawBuildkitSha256,
    },
    subjectEvidence: verifiedEvidence.map(({ subject, resolution, buildkitSbomSha256, registryResolutionSha256: resolutionSha256 }) => ({
      key: subject.key,
      image: subject.image,
      buildkitSbomSha256,
      registryResolutionSha256: resolutionSha256,
      descriptorSha256: resolution.descriptorSha256,
      descriptorArtifactSha256: resolution.descriptorArtifactSha256,
      platforms: resolution.platforms.map((entry) => entry.platform),
    })).sort((left, right) => left.key.localeCompare(right.key)),
    subjects,
  };
  return {
    manifest,
    sbom,
    subjects,
    evidenceBundle: {
      version: 1,
      kind: "platform-release-subject-evidence-bundle/v1",
      subjects: rawEvidence.map((entry) => {
        const resolutionBytes = entry.registryResolutionBytes
          ?? Buffer.from(`${JSON.stringify(entry.registryResolution, null, 2)}\n`);
        if (crypto.createHash("sha256").update(resolutionBytes).digest("hex") !== entry.registryResolutionSha256) {
          invalid(`Registry resolution bytes are not bound to ${entry.key}.`);
        }
        return {
          key: entry.key,
          image: requestedSubjects.find((subject) => subject.key === entry.key)?.image,
          buildkitSbomBase64: entry.buildkitSbomBytes.toString("base64"),
          buildkitSbomSha256: hashBuildkitSbom(entry.buildkitSbomBytes),
          registryResolutionBase64: resolutionBytes.toString("base64"),
          registryResolutionSha256: entry.registryResolutionSha256,
          registryDescriptorBase64: entry.registryDescriptorBytes.toString("base64"),
          registryDescriptorSha256: crypto.createHash("sha256").update(entry.registryDescriptorBytes).digest("hex"),
        };
      }).sort((left, right) => left.key.localeCompare(right.key)),
    },
  };
}

function readBoundedJson(pathname, label, maxBytes = 128 * 1024 * 1024) {
  const resolved = path.resolve(pathname ?? "");
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > maxBytes) invalid(`${label} must be a bounded regular file.`);
  const bytes = fs.readFileSync(resolved);
  let document;
  try { document = JSON.parse(bytes.toString("utf8")); } catch (error) { invalid(`${label} is invalid JSON: ${error.message}`); }
  return { bytes, document, sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
}

function writeJson(pathname, value) {
  fs.mkdirSync(path.dirname(pathname), { recursive: true });
  const text = `${JSON.stringify(value, null, 2)}\n`;
  fs.writeFileSync(pathname, text, { encoding: "utf8", mode: 0o600 });
  return { text, sha256: crypto.createHash("sha256").update(text).digest("hex") };
}

function evidencePaths(values, subjects, label) {
  if (subjects.length === 1 && values.length === 1 && !values[0].includes("=")) {
    return new Map([[subjects[0].key, values[0]]]);
  }
  const entries = values.map((value) => keyedPath(value, label));
  if (entries.length !== subjects.length || new Set(entries.map((entry) => entry.key)).size !== entries.length) {
    invalid(`${label} must provide exactly one keyed path for every release subject.`);
  }
  return new Map(entries.map((entry) => [entry.key, entry.pathname]));
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.receipt) invalid("Artifact admission receipts can only be finalized after the release manifest attestation is verified.");
  const entries = options.images.map(imageEntry);
  const approved = approvedReleaseSubjects(entries, options.repo);
  const images = approved.map((subject) => subject.image);
  const verification = verifyGithubReleaseImages({
    images,
    repository: options.repo,
    signerWorkflow: options.signerWorkflow,
    sourceDigest: options.sha,
    sourceRef: options.ref,
  });
  const buildkitPaths = evidencePaths(options.buildkitSboms, approved, "--buildkitSbom");
  const resolutionPaths = evidencePaths(options.registryResolutions, approved, "--registryResolution");
  const descriptorPaths = evidencePaths(options.registryDescriptors, approved, "--registryDescriptor");
  const subjectEvidence = approved.map((subject) => {
    const buildkit = readBoundedJson(buildkitPaths.get(subject.key), `BuildKit SBOM ${subject.key}`);
    const registryReceipt = readBoundedJson(resolutionPaths.get(subject.key), `registry resolution receipt ${subject.key}`, 16 * 1024 * 1024);
    const registryDescriptor = readBoundedJson(descriptorPaths.get(subject.key), `registry descriptor ${subject.key}`, 16 * 1024 * 1024);
    return {
      key: subject.key,
      buildkitSbom: buildkit.document,
      buildkitSbomBytes: buildkit.bytes,
      registryResolution: registryReceipt.document,
      registryResolutionBytes: registryReceipt.bytes,
      registryResolutionSha256: registryReceipt.sha256,
      registryDescriptorBytes: registryDescriptor.bytes,
    };
  });
  const artifacts = createVerifiedReleaseArtifacts({
    entries,
    repository: options.repo,
    commitSha: options.sha,
    releaseName: options.releaseName,
    workflowRunId: options.workflowRunId,
    workflowRunUrl: options.workflowRunUrl,
    verification,
    subjectEvidence,
    expectedPlatforms: [options.platform],
  });
  const manifestPath = path.resolve(options.manifest);
  const sbomPath = path.resolve(options.sbom);
  const sbomArtifact = writeJson(sbomPath, artifacts.sbom);
  if (artifacts.manifest.sbom.sha256 !== sbomArtifact.sha256) invalid("Generated SBOM bytes do not match the manifest binding.");
  const manifestArtifact = writeJson(manifestPath, artifacts.manifest);
  if (approved.length > 1 && !options.evidenceBundle) invalid("--evidenceBundle is required for a multi-subject release.");
  if (options.evidenceBundle) writeJson(path.resolve(options.evidenceBundle), artifacts.evidenceBundle);
  process.stdout.write(`${manifestArtifact.sha256}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
