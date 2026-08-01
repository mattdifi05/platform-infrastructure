#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "./runtime-intent-policy.mjs";

export const ACTIVATION_BUNDLE_MAGIC = Buffer.from("PLATFORM-ACTIVATION-BUNDLE-V1\n", "ascii");
export const ACTIVATION_BUNDLE_MAX_BYTES = 384 * 1024 * 1024;
export const ACTIVATION_BUNDLE_ENTRY_LIMITS = Object.freeze({
  "artifact-verification.json": 16 * 1024 * 1024,
  "combined-compose.json": 32 * 1024 * 1024,
  "dast-admission.json": 16 * 1024 * 1024,
  "environment.env": 1024 * 1024,
  "exact-source-archive.tar": 256 * 1024 * 1024,
  "hosted-workloads.lock.json": 16 * 1024 * 1024,
  "source-compose.json": 32 * 1024 * 1024,
  "trusted-deployment-admission.json": 16 * 1024 * 1024,
  "trusted-provider-run.json": 4 * 1024 * 1024,
});

const EXPECTED_NAMES = Object.freeze(Object.keys(ACTIVATION_BUNDLE_ENTRY_LIMITS).sort());
const MANIFEST_MAX_BYTES = 64 * 1024;
const NO_HOSTED_LOCK = Object.freeze({
  schema: "platform-no-hosted-workloads/v1",
  noHosted: true,
});

function invalid(message) {
  throw new Error(message);
}

function exactObject(value, label, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object.`);
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    invalid(`${label} does not use the exact closed schema.`);
  }
  return value;
}

function exactSha256(value, label) {
  const text = String(value ?? "");
  if (!/^[a-f0-9]{64}$/.test(text)) invalid(`${label} must be one lowercase SHA256.`);
  return text;
}

function exactSize(value, label, maximum = ACTIVATION_BUNDLE_MAX_BYTES) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    invalid(`${label} is outside the accepted size boundary.`);
  }
  return value;
}

function exactRequestId(value) {
  const text = String(value ?? "");
  if (!/^activation:[a-f0-9]{64}:[a-f0-9]{64}$/.test(text)) invalid("Activation request ID is invalid.");
  return text;
}

function openStableInput(sourcePath, { label, maxBytes }) {
  const resolved = path.resolve(String(sourcePath ?? ""));
  let descriptor;
  try {
    if (typeof fs.constants.O_NOFOLLOW !== "number") invalid(`${label} cannot be opened without following symlinks.`);
    descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size < 1 || stat.size > maxBytes) {
      invalid(`${label} must be one bounded, singly-linked regular file.`);
    }
    return {
      descriptor,
      sourcePath: resolved,
      stat,
      sizeBytes: stat.size,
      cleanup() {
        if (descriptor !== undefined) {
          fs.closeSync(descriptor);
          descriptor = undefined;
        }
      },
    };
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    invalid(`${label} could not be opened safely: ${String(error?.message ?? error)}`);
  }
}

function hashOpenFile(input) {
  const hash = crypto.createHash("sha256");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let offset = 0;
  while (offset < input.sizeBytes) {
    const count = fs.readSync(input.descriptor, buffer, 0, Math.min(buffer.length, input.sizeBytes - offset), offset);
    if (count < 1) invalid(`${input.sourcePath} ended before its admitted size.`);
    hash.update(buffer.subarray(0, count));
    offset += count;
  }
  const after = fs.fstatSync(input.descriptor);
  if (
    after.dev !== input.stat.dev
    || after.ino !== input.stat.ino
    || after.size !== input.stat.size
    || after.mtimeMs !== input.stat.mtimeMs
    || after.ctimeMs !== input.stat.ctimeMs
    || after.nlink !== 1
  ) {
    invalid(`${input.sourcePath} changed while it was hashed.`);
  }
  return hash.digest("hex");
}

function copyOpenFile(input, outputDescriptor, bundleHash) {
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let offset = 0;
  while (offset < input.sizeBytes) {
    const count = fs.readSync(input.descriptor, buffer, 0, Math.min(buffer.length, input.sizeBytes - offset), offset);
    if (count < 1) invalid(`${input.sourcePath} ended before its admitted size.`);
    const chunk = buffer.subarray(0, count);
    fs.writeSync(outputDescriptor, chunk);
    bundleHash.update(chunk);
    offset += count;
  }
  const after = fs.fstatSync(input.descriptor);
  if (
    after.dev !== input.stat.dev
    || after.ino !== input.stat.ino
    || after.size !== input.stat.size
    || after.mtimeMs !== input.stat.mtimeMs
    || after.ctimeMs !== input.stat.ctimeMs
    || after.nlink !== 1
  ) {
    invalid(`${input.sourcePath} changed while it was copied.`);
  }
}

export function validateActivationBundleManifest(manifest, {
  requestId,
  releaseContextSha256,
  runtimeIntentSha256,
  expectedEntryHashes = {},
} = {}) {
  exactObject(manifest, "Activation bundle manifest", [
    "schema",
    "requestId",
    "releaseContextSha256",
    "runtimeIntentSha256",
    "entries",
  ]);
  if (manifest.schema !== "platform-activation-bundle-manifest/v1") {
    invalid("Activation bundle manifest schema is invalid.");
  }
  if (manifest.requestId !== exactRequestId(requestId ?? manifest.requestId)) {
    invalid("Activation bundle manifest request ID is mismatched.");
  }
  if (manifest.releaseContextSha256 !== exactSha256(
    releaseContextSha256 ?? manifest.releaseContextSha256,
    "release context SHA256",
  )) {
    invalid("Activation bundle manifest release context is mismatched.");
  }
  if (manifest.runtimeIntentSha256 !== exactSha256(
    runtimeIntentSha256 ?? manifest.runtimeIntentSha256,
    "runtime intent SHA256",
  )) {
    invalid("Activation bundle manifest runtime intent is mismatched.");
  }
  if (!Array.isArray(manifest.entries) || manifest.entries.length !== EXPECTED_NAMES.length) {
    invalid("Activation bundle manifest must contain the exact fixed entry set.");
  }
  const names = manifest.entries.map((entry) => entry?.name);
  if (JSON.stringify(names) !== JSON.stringify(EXPECTED_NAMES)) {
    invalid("Activation bundle manifest entries must use the exact sorted fixed names.");
  }
  for (const entry of manifest.entries) {
    exactObject(entry, `Activation bundle entry ${entry?.name ?? "<missing>"}`, [
      "name",
      "sha256",
      "sizeBytes",
    ]);
    const maximum = ACTIVATION_BUNDLE_ENTRY_LIMITS[entry.name];
    exactSha256(entry.sha256, `${entry.name} SHA256`);
    exactSize(entry.sizeBytes, `${entry.name} size`, maximum);
    if (Object.hasOwn(expectedEntryHashes, entry.name)
      && entry.sha256 !== exactSha256(expectedEntryHashes[entry.name], `expected ${entry.name} SHA256`)) {
      invalid(`Activation bundle entry ${entry.name} is not hash-bound to the admitted input.`);
    }
  }
  const manifestBytes = Buffer.from(canonicalJson(manifest), "utf8");
  if (manifestBytes.length < 2 || manifestBytes.length > MANIFEST_MAX_BYTES) {
    invalid("Activation bundle manifest exceeds its canonical size boundary.");
  }
  return { manifest, manifestBytes, sha256: crypto.createHash("sha256").update(manifestBytes).digest("hex") };
}

export function exactNoHostedLockBytes() {
  return Buffer.from(canonicalJson(NO_HOSTED_LOCK), "utf8");
}

export function buildActivationBundle({
  outputPath,
  manifestOutputPath,
  requestId,
  releaseContextSha256,
  runtimeIntentSha256,
  entryPaths,
  expectedEntryHashes = {},
}) {
  if (JSON.stringify(Object.keys(entryPaths ?? {}).sort()) !== JSON.stringify(EXPECTED_NAMES)) {
    invalid("Activation bundle inputs must use the exact fixed entry set.");
  }
  const inputs = [];
  let outputDescriptor;
  try {
    for (const name of EXPECTED_NAMES) {
      const input = openStableInput(entryPaths[name], {
        label: name,
        maxBytes: ACTIVATION_BUNDLE_ENTRY_LIMITS[name],
      });
      input.name = name;
      input.sha256 = hashOpenFile(input);
      if (Object.hasOwn(expectedEntryHashes, name)
        && input.sha256 !== exactSha256(expectedEntryHashes[name], `expected ${name} SHA256`)) {
        invalid(`${name} differs from its admitted SHA256.`);
      }
      inputs.push(input);
    }
    const manifest = {
      schema: "platform-activation-bundle-manifest/v1",
      requestId: exactRequestId(requestId),
      releaseContextSha256: exactSha256(releaseContextSha256, "release context SHA256"),
      runtimeIntentSha256: exactSha256(runtimeIntentSha256, "runtime intent SHA256"),
      entries: inputs.map(({ name, sha256, sizeBytes }) => ({ name, sha256, sizeBytes })),
    };
    const validated = validateActivationBundleManifest(manifest, {
      requestId,
      releaseContextSha256,
      runtimeIntentSha256,
      expectedEntryHashes,
    });
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(validated.manifestBytes.length));
    const output = path.resolve(String(outputPath ?? ""));
    const manifestOutput = path.resolve(String(manifestOutputPath ?? ""));
    if (!outputPath || !manifestOutputPath || output === manifestOutput) invalid("Distinct bundle and manifest output paths are required.");
    fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.dirname(manifestOutput), { recursive: true, mode: 0o700 });
    outputDescriptor = fs.openSync(output, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    const bundleHash = crypto.createHash("sha256");
    for (const chunk of [ACTIVATION_BUNDLE_MAGIC, length, validated.manifestBytes]) {
      fs.writeSync(outputDescriptor, chunk);
      bundleHash.update(chunk);
    }
    for (const input of inputs) copyOpenFile(input, outputDescriptor, bundleHash);
    fs.fsyncSync(outputDescriptor);
    fs.closeSync(outputDescriptor);
    outputDescriptor = undefined;
    const sizeBytes = fs.statSync(output).size;
    exactSize(sizeBytes, "activation bundle size");
    const sha256 = bundleHash.digest("hex");
    fs.writeFileSync(manifestOutput, `${canonicalJson(manifest)}\n`, { flag: "wx", mode: 0o600 });
    return {
      schema: "platform-activation-bundle-descriptor/v1",
      sha256,
      sizeBytes,
      manifestSha256: validated.sha256,
      manifest,
    };
  } catch (error) {
    if (outputDescriptor !== undefined) fs.closeSync(outputDescriptor);
    if (outputPath) fs.rmSync(path.resolve(outputPath), { force: true });
    if (manifestOutputPath) fs.rmSync(path.resolve(manifestOutputPath), { force: true });
    throw error;
  } finally {
    for (const input of inputs.reverse()) input.cleanup();
  }
}

function parseArgs(values) {
  const options = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--")) invalid(`Invalid or missing value for ${key ?? "argument"}.`);
    if (Object.hasOwn(options, key.slice(2))) invalid(`Duplicate argument ${key}.`);
    options[key.slice(2)] = value;
  }
  return options;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const entryPaths = Object.fromEntries(EXPECTED_NAMES.map((name) => [
    name,
    options[name.replaceAll(/[-.]/g, "_")],
  ]));
  const descriptor = buildActivationBundle({
    outputPath: options.output,
    manifestOutputPath: options.manifestOutput,
    requestId: options.requestId,
    releaseContextSha256: options.releaseContextSha256,
    runtimeIntentSha256: options.runtimeIntentSha256,
    entryPaths,
  });
  process.stdout.write(`${JSON.stringify({
    schema: descriptor.schema,
    sha256: descriptor.sha256,
    sizeBytes: descriptor.sizeBytes,
    manifestSha256: descriptor.manifestSha256,
  })}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
