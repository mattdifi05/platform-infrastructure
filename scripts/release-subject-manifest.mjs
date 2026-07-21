#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildReleaseAdmissionReceipt,
  canonicalReleaseSubjects,
  validateCryptographicReleaseVerification,
  validateCycloneDxReleaseSbom,
} from "./release-artifact-policy.mjs";
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
  generatedAt = new Date().toISOString(),
  serialNumber = `urn:uuid:${crypto.randomUUID()}`,
}) {
  const requestedSubjects = canonicalReleaseSubjects(entries);
  validateCryptographicReleaseVerification(verification, { subjects: requestedSubjects, repository, commitSha });
  const verifiedByImage = new Map(verification.releaseImages.map((image) => [image, image]));
  const subjects = requestedSubjects.map((requested) => {
    const verifiedImage = verifiedByImage.get(requested.image);
    if (!verifiedImage) invalid(`Verifier output is missing ${requested.image}.`);
    return { key: requested.key, image: verifiedImage, name: requested.name, digest: requested.digest };
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
        { name: "sbom.source", value: "cryptographically-verified-release-subject-index" },
      ],
    },
    components: subjects.map((subject) => ({
      type: "container",
      name: subject.name,
      version: subject.digest,
      hashes: [{ alg: "SHA-256", content: subject.digest.slice("sha256:".length) }],
      purl: `pkg:oci/${subject.name}@${subject.digest}`,
      properties: [{ name: "releaseSubjectKey", value: subject.key }],
    })),
  };
  validateCycloneDxReleaseSbom(sbom, { subjects, repository, commitSha });
  const sbomBytes = `${JSON.stringify(sbom, null, 2)}\n`;
  const sbomSha256 = crypto.createHash("sha256").update(sbomBytes).digest("hex");
  const manifest = {
    version: 2,
    generatedAt,
    releaseName: String(releaseName || commitSha),
    repository,
    commitSha,
    workflowRunId: String(workflowRunId ?? ""),
    workflowRunUrl: String(workflowRunUrl ?? ""),
    source: "cryptographically-verified-subjects",
    sbom: {
      schema: "http://cyclonedx.org/schema/bom-1.5.schema.json",
      sha256: sbomSha256,
    },
    subjects,
  };
  return { manifest, sbom, subjects };
}

function writeJson(pathname, value) {
  fs.mkdirSync(path.dirname(pathname), { recursive: true });
  const text = `${JSON.stringify(value, null, 2)}\n`;
  fs.writeFileSync(pathname, text, { encoding: "utf8", mode: 0o600 });
  return { text, sha256: crypto.createHash("sha256").update(text).digest("hex") };
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const entries = options.images.map(imageEntry);
  const images = canonicalReleaseSubjects(entries).map((subject) => subject.image);
  const verification = verifyGithubReleaseImages({
    images,
    repository: options.repo,
    signerWorkflow: options.signerWorkflow,
    sourceDigest: options.sha,
    sourceRef: options.ref,
  });
  const artifacts = createVerifiedReleaseArtifacts({
    entries,
    repository: options.repo,
    commitSha: options.sha,
    releaseName: options.releaseName,
    workflowRunId: options.workflowRunId,
    workflowRunUrl: options.workflowRunUrl,
    verification,
  });
  const manifestPath = path.resolve(options.manifest);
  const sbomPath = path.resolve(options.sbom);
  const receiptPath = path.resolve(options.receipt);
  const sbomArtifact = writeJson(sbomPath, artifacts.sbom);
  if (artifacts.manifest.sbom.sha256 !== sbomArtifact.sha256) invalid("Generated SBOM bytes do not match the manifest binding.");
  const manifestArtifact = writeJson(manifestPath, artifacts.manifest);
  const receipt = buildReleaseAdmissionReceipt({
    subjects: artifacts.subjects,
    repository: options.repo,
    commitSha: options.sha,
    sbomSha256: sbomArtifact.sha256,
    manifestSha256: manifestArtifact.sha256,
    verification,
  });
  receipt.manifestSha256 = manifestArtifact.sha256;
  writeJson(receiptPath, receipt);
  process.stdout.write(`${manifestArtifact.sha256}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
