#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const PRODUCTION_INFRASTRUCTURE_ROOT = "/srv/platform-infrastructure";

function trustBoundary({
  platform,
  infrastructureRoot,
  expectedOwner,
}) {
  return Object.freeze({
    platform,
    expectedOwner,
    infrastructureRoot,
    releaseStore: path.join(infrastructureRoot, "releases"),
    stateStore: path.join(infrastructureRoot, "release-states"),
    activationCoordinatorRoot: path.join(infrastructureRoot, "platform-activation"),
  });
}

const PRODUCTION_TRUST_BOUNDARY = trustBoundary({
  platform: process.platform,
  infrastructureRoot: PRODUCTION_INFRASTRUCTURE_ROOT,
  expectedOwner: process.platform === "linux" ? 0 : (process.getuid?.() ?? null),
});

function fail(message) {
  throw new Error(message);
}

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function text(value, expression) {
  return typeof value === "string" && expression.test(value);
}

function canonicalAbsolutePath(value) {
  return text(value, /^\/[A-Za-z0-9._/-]+$/)
    && !value.includes("//")
    && !value.split("/").includes("..")
    && path.normalize(value) === value;
}

function validPinnedImage(value) {
  return text(
    value,
    /^([a-z0-9.-]+(?::[0-9]+)?(?:\/[a-z0-9._-]+)+)@sha256:[a-f0-9]{64}$/,
  ) && !value.includes(":latest");
}

function isStrictDescendant(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative !== ""
    && relative !== ".."
    && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative);
}

function exactFile(candidate, boundary) {
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
    const expectedOwner = boundary.expectedOwner === null
      ? before.uid
      : BigInt(boundary.expectedOwner);
    if (!before.isFile() || pathDetails.isSymbolicLink() || !pathDetails.isFile()
        || before.nlink !== 1n || pathDetails.nlink !== 1n
        || before.dev !== pathDetails.dev || before.ino !== pathDetails.ino
        || before.uid !== expectedOwner || pathDetails.uid !== expectedOwner
        || Number(before.mode & 0o777n) !== 0o640 || Number(pathDetails.mode & 0o777n) !== 0o640) {
      fail("Trusted release context must be a stable root-owned mode-0640 single regular file.");
    }
    if (boundary.platform === "linux" && !isStrictDescendant(candidate, boundary.stateStore)) {
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

function assertRootOwnedDirectory(candidate, label, expectedOwner) {
  let details;
  try {
    details = fs.lstatSync(candidate);
  } catch (error) {
    fail(`${label} is unavailable: ${error?.message ?? "unknown error"}.`);
  }
  if (!details.isDirectory() || details.isSymbolicLink()
      || fs.realpathSync.native(candidate) !== candidate
      || details.uid !== expectedOwner || (details.mode & 0o022) !== 0) {
    fail(`${label} must be a canonical root-owned non-group/world-writable directory.`);
  }
}

function validate(document, contextPath, boundary) {
  const sha = /^[a-f0-9]{64}$/;
  const gitObject = /^([a-f0-9]{40}|[a-f0-9]{64})$/;
  const identifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
  const releaseIdentifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,254}$/;
  if (!exactKeys(document, [
    "schema", "repository", "commitSha", "treeSha", "sourceArchiveSha256",
    "releaseId", "releaseRoot", "stateId", "stateRoot", "environmentFile",
    "environmentSha256", "projectName", "decisionId", "provider", "receipts",
    "dastChainSha256", "runtimeIntentSha256", "subjects", "hostedLockSha256",
    "noHosted", "sourceRenderSha256", "combinedRenderSha256", "persistentVolumes",
  ])) fail("Trusted release context uses an open or incomplete schema.");
  if (document.schema !== "platform-trusted-release-context/v3"
      || !text(document.repository, /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$/)
      || !text(document.commitSha, gitObject)
      || !text(document.treeSha, gitObject)
      || !text(document.sourceArchiveSha256, sha)
      || !text(document.releaseId, releaseIdentifier)
      || !canonicalAbsolutePath(document.releaseRoot)
      || !text(document.stateId, releaseIdentifier)
      || !canonicalAbsolutePath(document.stateRoot)
      || !canonicalAbsolutePath(document.environmentFile)
      || !text(document.environmentSha256, sha)
      || document.projectName !== "platform_infra_vps"
      || !text(document.decisionId, identifier)
      || !text(document.dastChainSha256, sha)
      || !text(document.runtimeIntentSha256, sha)
      || typeof document.noHosted !== "boolean"
      || !text(document.sourceRenderSha256, sha)
      || !text(document.combinedRenderSha256, sha)
      || document.sourceRenderSha256 === document.combinedRenderSha256
      || (document.noHosted
        ? document.hostedLockSha256 !== null
        : !text(document.hostedLockSha256, sha))) {
    fail("Trusted release context contains invalid identity fields.");
  }
  const expectedReleaseId = `${document.commitSha}-${document.sourceArchiveSha256}`;
  const expectedStateId = `${expectedReleaseId}-${document.environmentSha256}`;
  const expectedReleaseRoot = boundary.platform === "linux"
    ? path.join(boundary.releaseStore, expectedReleaseId)
    : path.join(path.dirname(path.dirname(document.stateRoot)), "releases", expectedReleaseId);
  const expectedStateRoot = boundary.platform === "linux"
    ? path.join(boundary.stateStore, expectedStateId)
    : document.stateRoot;
  if (document.releaseId !== expectedReleaseId
      || document.stateId !== expectedStateId
      || document.releaseRoot !== expectedReleaseRoot
      || document.stateRoot !== expectedStateRoot
      || document.environmentFile !== path.join(document.stateRoot, "environment.env")
      || path.join(document.stateRoot, "trusted-release-context.json") !== contextPath
      || path.basename(document.stateRoot) !== document.stateId) {
    fail("Trusted release context path identities are not canonical.");
  }
  if (boundary.platform === "linux") {
    if (!isStrictDescendant(document.releaseRoot, boundary.releaseStore)) {
      fail("Trusted release root is outside the immutable release store.");
    }
    if (!isStrictDescendant(document.stateRoot, boundary.stateStore)) {
      fail("Trusted release state root is outside the root-owned release-state store.");
    }
    assertRootOwnedDirectory(
      boundary.infrastructureRoot,
      "Platform infrastructure root",
      boundary.expectedOwner,
    );
    assertRootOwnedDirectory(boundary.releaseStore, "Immutable release store", boundary.expectedOwner);
    assertRootOwnedDirectory(boundary.stateStore, "Release-state store", boundary.expectedOwner);
    assertRootOwnedDirectory(document.releaseRoot, "Trusted release root", boundary.expectedOwner);
    assertRootOwnedDirectory(document.stateRoot, "Trusted release state root", boundary.expectedOwner);
  }
  if (!exactKeys(document.provider, ["metadataSha256", "runId", "attempt", "challenge"])
      || !text(document.provider.metadataSha256, sha)
      || !text(document.provider.runId, identifier)
      || !Number.isSafeInteger(document.provider.attempt) || document.provider.attempt < 1
      || !text(document.provider.challenge, sha)) {
    fail("Trusted release context provider admission is invalid.");
  }
  if (!exactKeys(document.receipts, [
    "artifactSha256", "deploymentSha256", "dastProviderSha256", "dastAuthorizationSha256",
  ])
      || !text(document.receipts.artifactSha256, sha)
      || !text(document.receipts.deploymentSha256, sha)
      || !text(document.receipts.dastProviderSha256, sha)
      || !text(document.receipts.dastAuthorizationSha256, sha)) {
    fail("Trusted release context receipt admission is invalid.");
  }
  if (!Array.isArray(document.subjects) || document.subjects.length === 0
      || document.subjects.some((subject) => !exactKeys(subject, ["serviceName", "imageReference", "imageId"])
        || !text(subject.serviceName, /^[a-z0-9][a-z0-9_.-]{0,127}$/)
        || !validPinnedImage(subject.imageReference)
        || !text(subject.imageId, /^sha256:[a-f0-9]{64}$/))
      || JSON.stringify(document.subjects) !== JSON.stringify(
        [...document.subjects].sort((left, right) => left.serviceName.localeCompare(right.serviceName)),
      )
      || new Set(document.subjects.map(({ serviceName }) => serviceName)).size !== document.subjects.length) {
    fail("Trusted release context subjects must be an exact sorted immutable service map.");
  }
  const scheduler = document.subjects.filter(({ serviceName }) => serviceName === "backup-scheduler");
  if (scheduler.length !== 1
      || !scheduler[0].imageReference.match(
        /^([a-z0-9.-]+(?::[0-9]+)?(?:\/[a-z0-9._-]+)*\/platform-infrastructure-backup-scheduler)@sha256:[a-f0-9]{64}$/,
      )) {
    fail("Trusted release context must bind the dedicated backup scheduler image.");
  }
  if (!Array.isArray(document.persistentVolumes) || document.persistentVolumes.length !== 1) {
    fail("Trusted release context must bind one exact persistent volume.");
  }
  const volume = document.persistentVolumes[0];
  if (!exactKeys(volume, [
    "name", "createdAt", "driver", "scope", "options", "labels", "mountpoint", "owner",
  ])
      || volume.name !== "enterprise_local_registry_data"
      || volume.driver !== "local"
      || volume.scope !== "local"
      || typeof volume.createdAt !== "string"
      || !volume.createdAt
      || !Number.isFinite(Date.parse(volume.createdAt))
      || !exactKeys(volume.options, [])
      || !exactKeys(volume.labels, [
        "platform.infrastructure.managed", "platform.infrastructure.purpose",
      ])
      || volume.labels["platform.infrastructure.managed"] !== "true"
      || volume.labels["platform.infrastructure.purpose"] !== "local-registry"
      || !canonicalAbsolutePath(volume.mountpoint)
      || !volume.mountpoint.endsWith("/enterprise_local_registry_data/_data")
      || !exactKeys(volume.owner, ["uid", "gid", "mode"])
      || volume.owner.uid !== 0
      || volume.owner.gid !== 0
      || !text(volume.owner.mode, /^0[0-7]{3}$/)
      || (Number.parseInt(volume.owner.mode, 8) & 0o022) !== 0) {
    fail("Trusted release context persistent volume identity is invalid.");
  }
}

function readPlatformReleaseContext(contextPath, boundary) {
  const bytes = exactFile(contextPath, boundary);
  let document;
  try {
    document = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("Trusted release context is not valid JSON.");
  }
  validate(document, contextPath, boundary);
  const activationCoordinatorRoot = boundary.platform === "linux"
    ? boundary.activationCoordinatorRoot
    : path.join(path.dirname(path.dirname(document.stateRoot)), "platform-activation");
  return { ...document, activationCoordinatorRoot };
}

export function createPlatformReleaseContextTestReader(options) {
  if (!exactKeys(options, ["infrastructureRoot", "expectedOwner"])) {
    fail("Test release-context boundary must use the exact closed dependency schema.");
  }
  const infrastructureRoot = String(options.infrastructureRoot ?? "");
  if (!canonicalAbsolutePath(infrastructureRoot)) {
    fail("Test release-context infrastructure root must be canonical and absolute.");
  }
  if (!Number.isSafeInteger(options.expectedOwner) || options.expectedOwner < 0) {
    fail("Test release-context expected owner must be one non-negative integer identity.");
  }
  const boundary = trustBoundary({
    platform: "linux",
    infrastructureRoot,
    expectedOwner: options.expectedOwner,
  });
  return (contextPath) => readPlatformReleaseContext(contextPath, boundary);
}

function main() {
  if (process.argv.length !== 4 || process.argv[2] !== "read") {
    fail("Usage: platform-release-context.mjs read ABSOLUTE_CONTEXT");
  }
  process.stdout.write(`${JSON.stringify(
    readPlatformReleaseContext(process.argv[3], PRODUCTION_TRUST_BOUNDARY),
  )}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
