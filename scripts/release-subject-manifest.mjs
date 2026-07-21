#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  approvedReleaseSubjects,
  validateCryptographicReleaseVerification,
  validateCycloneDxReleaseSbom,
} from "./release-artifact-policy.mjs";
import { buildkitSbomSha256 as hashBuildkitSbom, buildkitSpdxInventory } from "./buildkit-sbom-policy.mjs";
import { validateRegistryResolutionReceipt } from "./release-registry-resolution.mjs";
import { verifyGithubReleaseImages } from "./release-trust.mjs";

function invalid(message) { throw new Error(message); }

function parseArgs(args) {
  const out = { images: [] };
  for (let index = 0; index < args.length; index += 1) {
    const key = args[index];
    if (!key.startsWith("--")) invalid(`Unexpected argument ${key}.`);
    const value = args[index + 1];
    if (!value || value.startsWith("--")) invalid(`Missing value for ${key}.`);
    index += 1;
    if (key === "--image") out.images.push(value);
    else out[key.slice(2)] = value;
  }
  return out;
}

function imageEntry(value) {
  const separator = String(value).indexOf("=");
  if (separator < 1) invalid("--image must use KEY=registry/repository@sha256:digest.");
  return { key: value.slice(0, separator), image: value.slice(separator + 1) };
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
  expectedPlatforms = ["linux/amd64"],
  generatedAt = new Date().toISOString(),
  serialNumber = `urn:uuid:${crypto.randomUUID()}`,
}) {
  const requestedSubjects = approvedReleaseSubjects(entries, repository);
  validateCryptographicReleaseVerification(verification, { subjects: requestedSubjects, repository, commitSha });
  if (requestedSubjects.length !== 1) invalid("Each release artifact invocation must bind one image to one registry/SBOM evidence set.");
  const resolution = validateRegistryResolutionReceipt(registryResolution, {
    image: requestedSubjects[0].image,
    descriptorBytes: registryDescriptorBytes,
    expectedPlatforms,
  });
  if (!/^[a-f0-9]{64}$/.test(String(registryResolutionSha256 ?? ""))) invalid("Registry resolution receipt SHA256 is required.");
  const rawBuildkitSha256 = hashBuildkitSbom(buildkitSbomBytes);
  const inventory = buildkitSpdxInventory(buildkitSbom, { subjects: requestedSubjects, expectedPlatforms });
  const verifiedByImage = new Map(verification.releaseImages.map((image) => [image, image]));
  const subjects = requestedSubjects.map((requested) => {
    const verifiedImage = verifiedByImage.get(requested.image);
    if (!verifiedImage) invalid(`Verifier output is missing ${requested.image}.`);
    return {
      key: requested.key,
      image: verifiedImage,
      name: requested.name,
      digest: requested.digest,
      platforms: resolution.platforms.map(({ platform, digest: descriptorDigest, size, mediaType }) => ({
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
    version: 3,
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
      buildkitSha256: rawBuildkitSha256,
    },
    registryResolution: {
      sha256: registryResolutionSha256,
      descriptorSha256: resolution.descriptorSha256,
      descriptorArtifactSha256: resolution.descriptorArtifactSha256,
      platforms: inventory.platforms,
    },
    subjects,
  };
  return { manifest, sbom, subjects };
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

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.receipt) invalid("Artifact admission receipts can only be finalized after the release manifest attestation is verified.");
  const entries = options.images.map(imageEntry);
  const images = approvedReleaseSubjects(entries, options.repo).map((subject) => subject.image);
  const verification = verifyGithubReleaseImages({
    images,
    repository: options.repo,
    signerWorkflow: options.signerWorkflow,
    sourceDigest: options.sha,
    sourceRef: options.ref,
  });
  const buildkit = readBoundedJson(options.buildkitSbom, "BuildKit SBOM");
  const registryReceipt = readBoundedJson(options.registryResolution, "registry resolution receipt", 16 * 1024 * 1024);
  const registryDescriptor = readBoundedJson(options.registryDescriptor, "registry descriptor", 16 * 1024 * 1024);
  const artifacts = createVerifiedReleaseArtifacts({
    entries,
    repository: options.repo,
    commitSha: options.sha,
    releaseName: options.releaseName,
    workflowRunId: options.workflowRunId,
    workflowRunUrl: options.workflowRunUrl,
    verification,
    buildkitSbom: buildkit.document,
    buildkitSbomBytes: buildkit.bytes,
    registryResolution: registryReceipt.document,
    registryResolutionSha256: registryReceipt.sha256,
    registryDescriptorBytes: registryDescriptor.bytes,
    expectedPlatforms: [options.platform],
  });
  const manifestPath = path.resolve(options.manifest);
  const sbomPath = path.resolve(options.sbom);
  const sbomArtifact = writeJson(sbomPath, artifacts.sbom);
  if (artifacts.manifest.sbom.sha256 !== sbomArtifact.sha256) invalid("Generated SBOM bytes do not match the manifest binding.");
  const manifestArtifact = writeJson(manifestPath, artifacts.manifest);
  process.stdout.write(`${manifestArtifact.sha256}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
