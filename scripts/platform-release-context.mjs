#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function text(value, expression) {
  return typeof value === "string" && expression.test(value);
}

function exactFile(candidate) {
  if (!path.isAbsolute(candidate) || path.normalize(candidate) !== candidate) {
    fail("Trusted release context path must be canonical and absolute.");
  }
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  let descriptor;
  try {
    descriptor = fs.openSync(candidate, fs.constants.O_RDONLY | noFollow);
  } catch (error) {
    fail(`Trusted release context cannot be opened safely: ${error?.message ?? "unknown error"}.`);
  }
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    const pathDetails = fs.lstatSync(candidate, { bigint: true });
    const expectedOwner = process.platform === "linux" ? 0n : BigInt(process.getuid?.() ?? Number(before.uid));
    if (!before.isFile() || pathDetails.isSymbolicLink() || !pathDetails.isFile()
        || before.nlink !== 1n || pathDetails.nlink !== 1n
        || before.dev !== pathDetails.dev || before.ino !== pathDetails.ino
        || before.uid !== expectedOwner || pathDetails.uid !== expectedOwner
        || Number(before.mode & 0o777n) !== 0o640 || Number(pathDetails.mode & 0o777n) !== 0o640) {
      fail("Trusted release context must be a stable root-owned mode-0640 single regular file.");
    }
    if (process.platform === "linux"
        && !candidate.startsWith("/srv/platform-infrastructure/release-states/")) {
      fail("Trusted release context is outside the root-owned release-state store.");
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    for (const field of ["dev", "ino", "size", "mtimeNs", "ctimeNs"]) {
      if (before[field] !== after[field]) fail("Trusted release context changed while being read.");
    }
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
}

function assertRootOwnedDirectory(candidate, label) {
  let details;
  try {
    details = fs.lstatSync(candidate);
  } catch (error) {
    fail(`${label} is unavailable: ${error?.message ?? "unknown error"}.`);
  }
  if (!details.isDirectory() || details.isSymbolicLink()
      || fs.realpathSync.native(candidate) !== candidate
      || details.uid !== 0 || (details.mode & 0o022) !== 0) {
    fail(`${label} must be a canonical root-owned non-group/world-writable directory.`);
  }
}

function validate(document, contextPath) {
  const sha = /^[a-f0-9]{64}$/;
  const gitObject = /^([a-f0-9]{40}|[a-f0-9]{64})$/;
  const identifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
  const absolute = /^\/[A-Za-z0-9_./-]+$/;
  if (!exactKeys(document, [
    "schema", "repository", "commitSha", "treeSha", "sourceArchiveSha256",
    "releaseId", "releaseRoot", "stateId", "stateRoot", "environmentFile",
    "environmentSha256", "projectName", "decisionId", "provider", "receipts",
    "runtimeIntentSha256", "subjects", "hostedLockSha256", "noHosted",
    "sourceRenderSha256", "combinedRenderSha256",
  ])) fail("Trusted release context uses an open or incomplete schema.");
  if (document.schema !== "platform-trusted-release-context/v2"
      || !text(document.repository, /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$/)
      || !text(document.commitSha, gitObject)
      || !text(document.treeSha, gitObject)
      || !text(document.sourceArchiveSha256, sha)
      || !text(document.releaseId, identifier)
      || !text(document.releaseRoot, absolute)
      || !text(document.stateId, identifier)
      || !text(document.stateRoot, absolute)
      || !text(document.environmentFile, absolute)
      || !text(document.environmentSha256, sha)
      || document.projectName !== "platform_infra_vps"
      || !text(document.decisionId, identifier)
      || !text(document.runtimeIntentSha256, sha)
      || !text(document.hostedLockSha256, sha)
      || typeof document.noHosted !== "boolean"
      || !text(document.sourceRenderSha256, sha)
      || !text(document.combinedRenderSha256, sha)) {
    fail("Trusted release context contains invalid identity fields.");
  }
  if (path.normalize(document.releaseRoot) !== document.releaseRoot
      || path.normalize(document.stateRoot) !== document.stateRoot
      || path.normalize(document.environmentFile) !== document.environmentFile
      || path.join(document.stateRoot, "trusted-release-context.json") !== contextPath
      || path.basename(document.stateRoot) !== document.stateId) {
    fail("Trusted release context path identities are not canonical.");
  }
  if (process.platform === "linux") {
    if (!document.releaseRoot.startsWith("/srv/platform-infrastructure/releases/")) {
      fail("Trusted release root is outside the immutable release store.");
    }
    assertRootOwnedDirectory("/srv/platform-infrastructure", "Platform infrastructure root");
    assertRootOwnedDirectory("/srv/platform-infrastructure/releases", "Immutable release store");
    assertRootOwnedDirectory("/srv/platform-infrastructure/release-states", "Release-state store");
    assertRootOwnedDirectory(document.releaseRoot, "Trusted release root");
    assertRootOwnedDirectory(document.stateRoot, "Trusted release state root");
  }
  if (!exactKeys(document.provider, ["metadataSha256", "runId", "attempt", "challenge"])
      || !text(document.provider.metadataSha256, sha)
      || !text(document.provider.runId, identifier)
      || !Number.isSafeInteger(document.provider.attempt) || document.provider.attempt < 1
      || !text(document.provider.challenge, sha)) {
    fail("Trusted release context provider admission is invalid.");
  }
  if (!exactKeys(document.receipts, ["artifactSha256", "deploymentSha256", "dastSha256"])
      || !text(document.receipts.artifactSha256, sha)
      || !text(document.receipts.deploymentSha256, sha)
      || !text(document.receipts.dastSha256, sha)) {
    fail("Trusted release context receipt admission is invalid.");
  }
  if (!Array.isArray(document.subjects) || document.subjects.length === 0
      || document.subjects.some((subject) => !exactKeys(subject, ["serviceName", "imageReference", "imageId"])
        || !text(subject.serviceName, /^[a-z][a-z0-9-]{1,62}$/)
        || !text(subject.imageReference, /^[A-Za-z0-9][A-Za-z0-9._:@/-]{2,511}$/)
        || !text(subject.imageId, /^sha256:[a-f0-9]{64}$/))
      || JSON.stringify(document.subjects) !== JSON.stringify(
        [...document.subjects].sort((left, right) => left.serviceName.localeCompare(right.serviceName)),
      )
      || new Set(document.subjects.map(({ serviceName }) => serviceName)).size !== document.subjects.length) {
    fail("Trusted release context subjects must be an exact sorted immutable service map.");
  }
}

if (process.argv.length !== 4 || process.argv[2] !== "read") {
  fail("Usage: platform-release-context.mjs read ABSOLUTE_CONTEXT");
}
const contextPath = process.argv[3];
const bytes = exactFile(contextPath);
let document;
try {
  document = JSON.parse(bytes.toString("utf8"));
} catch {
  fail("Trusted release context is not valid JSON.");
}
validate(document, contextPath);
const activationCoordinatorRoot = process.platform === "linux"
  ? "/srv/platform-infrastructure/platform-activation"
  : path.join(path.dirname(path.dirname(document.stateRoot)), "platform-activation");
process.stdout.write(`${JSON.stringify({ ...document, activationCoordinatorRoot })}\n`);
