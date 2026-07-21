#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseReleaseImage } from "./release-artifact-policy.mjs";

function invalid(message) { throw new Error(message); }
function sha256(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }

function exactPlatforms(values) {
  if (!Array.isArray(values) || values.length === 0) invalid("At least one approved platform is required.");
  const platforms = values.map((value) => String(value));
  if (platforms.some((value) => !/^linux\/(amd64|arm64)$/.test(value))) invalid("Approved platforms must use exact supported os/architecture syntax.");
  if (new Set(platforms).size !== platforms.length) invalid("Approved platforms must be unique.");
  return [...platforms].sort();
}

function descriptorDigest(descriptor, label) {
  if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) invalid(`${label} must be an object.`);
  if (!/^sha256:[a-f0-9]{64}$/.test(String(descriptor.digest ?? ""))) invalid(`${label} digest is invalid.`);
  if (!Number.isInteger(descriptor.size) || descriptor.size < 1) invalid(`${label} size is invalid.`);
  if (!["application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"].includes(descriptor.mediaType)) {
    invalid(`${label} mediaType is not an image manifest.`);
  }
  return descriptor.digest;
}

function platformName(platform) {
  if (!platform || typeof platform !== "object" || Array.isArray(platform)) return null;
  if (typeof platform.os !== "string" || typeof platform.architecture !== "string") return null;
  const variant = platform.variant === undefined ? "" : `/${platform.variant}`;
  return `${platform.os}/${platform.architecture}${variant}`;
}

export function resolveRegistryDescriptor({ image, descriptorBytes, expectedPlatforms, resolvedAt = new Date().toISOString() }) {
  const subject = parseReleaseImage(image);
  if (!Buffer.isBuffer(descriptorBytes) || descriptorBytes.length === 0) invalid("Registry descriptor bytes are required.");
  const descriptorArtifactSha256 = sha256(descriptorBytes);
  const candidates = [descriptorBytes];
  if (descriptorBytes.at(-1) === 0x0a) candidates.push(descriptorBytes.subarray(0, descriptorBytes.length - 1));
  const digestBytes = candidates.find((candidate) => sha256(candidate) === subject.sha256);
  if (!digestBytes) invalid("Registry descriptor bytes do not match the admitted image root digest.");
  const descriptorSha256 = subject.sha256;
  let index;
  try { index = JSON.parse(digestBytes.toString("utf8")); } catch (error) { invalid(`Registry descriptor is invalid JSON: ${error.message}`); }
  if (index?.schemaVersion !== 2 || !["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"].includes(index?.mediaType)) {
    invalid("Registry subject must resolve to an exact OCI/Docker image index.");
  }
  if (!Array.isArray(index.manifests) || index.manifests.length === 0) invalid("Registry index has no descriptors.");
  const approvedPlatforms = exactPlatforms(expectedPlatforms);
  const runtime = [];
  const attestations = [];
  for (const descriptor of index.manifests) {
    const digest = descriptorDigest(descriptor, "Registry child descriptor");
    const platform = platformName(descriptor.platform);
    if (platform && platform !== "unknown/unknown") {
      runtime.push({ platform, digest, size: descriptor.size, mediaType: descriptor.mediaType });
      continue;
    }
    const annotations = descriptor.annotations;
    if (platform !== "unknown/unknown"
      || annotations?.["vnd.docker.reference.type"] !== "attestation-manifest"
      || !/^sha256:[a-f0-9]{64}$/.test(String(annotations?.["vnd.docker.reference.digest"] ?? ""))) {
      invalid("Non-runtime registry descriptors must be exact BuildKit attestation manifests.");
    }
    attestations.push({
      digest,
      size: descriptor.size,
      mediaType: descriptor.mediaType,
      subjectDigest: annotations["vnd.docker.reference.digest"],
    });
  }
  const actualPlatforms = runtime.map((entry) => entry.platform).sort();
  if (JSON.stringify(actualPlatforms) !== JSON.stringify(approvedPlatforms)) invalid("Registry runtime platform set differs from the approved exact platform set.");
  if (new Set(runtime.map((entry) => entry.digest)).size !== runtime.length) invalid("Registry runtime child digests must be unique.");
  if (attestations.length === 0) invalid("Registry index has no BuildKit attestation descriptor.");
  const runtimeDigests = new Set(runtime.map((entry) => entry.digest));
  if (attestations.some((entry) => !runtimeDigests.has(entry.subjectDigest))) invalid("Registry attestation descriptor is not bound to an approved runtime child digest.");
  if (!Number.isFinite(Date.parse(resolvedAt))) invalid("Registry resolution timestamp is invalid.");
  return {
    version: 1,
    kind: "platform-registry-subject-resolution/v1",
    status: "passed",
    resolvedAt,
    image: subject.image,
    rootDigest: subject.digest,
    descriptorSha256,
    descriptorArtifactSha256,
    platforms: runtime.sort((left, right) => left.platform.localeCompare(right.platform)),
    attestationDescriptors: attestations.sort((left, right) => left.digest.localeCompare(right.digest)),
  };
}

export function validateRegistryResolutionReceipt(receipt, { image, descriptorBytes, expectedPlatforms }) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) invalid("Registry resolution receipt must be an object.");
  const expected = resolveRegistryDescriptor({ image, descriptorBytes, expectedPlatforms, resolvedAt: receipt.resolvedAt });
  if (JSON.stringify(receipt) !== JSON.stringify(expected)) invalid("Registry resolution receipt differs from exact descriptor resolution.");
  return expected;
}

function parseArgs(args) {
  const out = { platforms: [] };
  for (let index = 0; index < args.length; index += 1) {
    const key = args[index];
    const value = args[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--")) invalid(`Missing value for ${key ?? "argument"}.`);
    index += 1;
    if (key === "--platform") out.platforms.push(value); else out[key.slice(2)] = value;
  }
  return out;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const descriptorPath = path.resolve(options.descriptor ?? "");
  const receiptPath = path.resolve(options.receipt ?? "");
  const stat = fs.lstatSync(descriptorPath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > 16 * 1024 * 1024) invalid("Registry descriptor must be a bounded regular file.");
  const receipt = resolveRegistryDescriptor({
    image: options.image,
    descriptorBytes: fs.readFileSync(descriptorPath),
    expectedPlatforms: options.platforms,
  });
  fs.mkdirSync(path.dirname(receiptPath), { recursive: true });
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
