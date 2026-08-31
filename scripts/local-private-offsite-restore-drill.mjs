#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import { backupDocumentDigest, parseBackupManifestDocument } from "../control-center/backup/contracts.mjs";
import { canonicalJson } from "./docker-action-contract.mjs";
import { backupSigningKeyMap, verifyOffsiteManifest } from "./local-private-docker-action-broker.mjs";
import {
  assertLocalPrivateBackupDockerInvocation,
  initializeLocalPrivateBackupInvocation,
} from "./local-private-backup-docker-policy.mjs";
import { locateSnapshotManifest, validateOffsiteRestoreSet } from "./offsite-restore-contract.mjs";

export const LOCAL_PRIVATE_OFFSITE_RESTORE_SCHEMA = "platform.offsite-restore-proof/v1";
const MAX_DOCKER_OUTPUT = 16 * 1024 * 1024;
const activeContainers = new Map();
const activeScratchRoots = new Set();

function fail(message) {
  throw new Error(message);
}

function sha256File(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function syncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function exactPrivateDirectory(directory, { create = false } = {}) {
  if (create && !fs.existsSync(directory)) fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const before = fs.lstatSync(directory);
  if (!before.isDirectory() || before.isSymbolicLink() || before.uid !== process.getuid()
    || before.gid !== process.getgid() || (before.mode & 0o022) !== 0) {
    fail(`off-site restore directory is not private: ${directory}`);
  }
  if ((before.mode & 0o777) !== 0o700) fs.chmodSync(directory, 0o700);
  const after = fs.lstatSync(directory);
  if (!after.isDirectory() || after.isSymbolicLink() || after.uid !== before.uid
    || after.gid !== before.gid || after.dev !== before.dev || after.ino !== before.ino
    || (after.mode & 0o777) !== 0o700) fail(`off-site restore directory identity changed: ${directory}`);
}

function readBoundJson(file, maximumBytes = 16 * 1024 * 1024) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
    || stat.uid !== process.getuid() || stat.gid !== process.getgid()
    || (stat.mode & 0o077) !== 0 || stat.size < 2 || stat.size > maximumBytes) {
    fail(`off-site restore evidence file is invalid: ${file}`);
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fs.readFileSync(file)));
}

function readBoundText(file, maximumBytes = 128 * 1024) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
    || stat.uid !== process.getuid() || stat.gid !== process.getgid()
    || (stat.mode & 0o077) !== 0 || stat.size < 1 || stat.size > maximumBytes) {
    fail(`off-site restore sidecar is invalid: ${file}`);
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(fs.readFileSync(file));
}

function verifyArtifactSidecar(artifactFile, artifact, signature, signingKeys) {
  const exactFields = ["algorithm", "artifact", "keyId", "sha256", "signature", "signedAt", "version"];
  const signedAt = Date.parse(String(signature.signedAt ?? ""));
  if (canonicalJson(Object.keys(signature).sort()) !== canonicalJson(exactFields.sort())
    || signature.version !== 1 || signature.algorithm !== "HMAC-SHA256"
    || signature.artifact !== path.basename(artifactFile) || signature.sha256 !== artifact.sha256
    || signature.keyId !== artifact.signatureKeyId
    || !Number.isFinite(signedAt) || new Date(signedAt).toISOString() !== signature.signedAt
    || !/^[A-Za-z0-9_-]{43}$/.test(String(signature.signature ?? ""))) {
    fail(`restored artifact sidecar differs: ${artifact.resourceId}`);
  }
  const secret = signingKeys.get(signature.keyId);
  const expected = secret
    ? crypto.createHmac("sha256", secret)
      .update(`platform-postgres-backup-v1\n${signature.artifact}\n${signature.sha256}\n`)
      .digest("base64url")
    : "";
  if (!secret || expected.length !== signature.signature.length
    || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature.signature))) {
    fail(`restored artifact HMAC verification failed: ${artifact.resourceId}`);
  }
}

function policyDockerSync(invocation, args, policyOptions = {}, spawnOptions = {}) {
  assertLocalPrivateBackupDockerInvocation(invocation, args, policyOptions);
  return spawnSync("docker", args, spawnOptions);
}

function expectedContainerMounts(invocation, role) {
  const mounts = [
    {
      Destination: "/rclone-config",
      Mode: "",
      RW: true,
      Source: path.join(invocation.roots.brokerStateHost, "rclone-refresh"),
      Type: "bind",
    },
    {
      Destination: "/restic-password/restic_password.txt",
      Mode: "",
      RW: false,
      Source: path.join(invocation.roots.secretsHost, "restic_password.txt"),
      Type: "bind",
    },
  ];
  if (role === "restore") mounts.push({
    Destination: "/restore",
    Mode: "",
    RW: true,
    Source: path.join(invocation.roots.dataHost, ".offsite-restore-proof", invocation.requestSha256),
    Type: "bind",
  });
  return mounts.sort((left, right) => left.Destination.localeCompare(right.Destination));
}

export function validateRestoreContainerInspection(invocation, binding, container) {
  const labels = container?.Config?.Labels;
  const expectedCommand = binding.role === "snapshots"
    ? ["--no-lock", "snapshots", "--json", "--tag", "platform-backups"]
    : ["--no-lock", "restore", invocation.receipt.resources.offsite.restore.snapshotId, "--target", "/restore"];
  const mounts = Array.isArray(container?.Mounts)
    ? container.Mounts.map(({ Destination, Mode, RW, Source, Type }) => ({ Destination, Mode, RW, Source, Type }))
      .sort((left, right) => left.Destination.localeCompare(right.Destination))
    : [];
  const networks = Object.keys(container?.NetworkSettings?.Networks ?? {}).sort();
  const expectedEnvironment = [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/tmp",
    "XDG_CACHE_HOME=/tmp/.cache",
    `RESTIC_REPOSITORY=${invocation.receipt.resources.offsite.repository}`,
    "RESTIC_PASSWORD_FILE=/restic-password/restic_password.txt",
    "RCLONE_CONFIG=/rclone-config/rclone.conf",
  ].sort();
  const environment = Array.isArray(container?.Config?.Env) ? container.Config.Env : [];
  const exact = container?.Id === binding.id && container?.Name === `/${binding.name}`
    && container?.Config?.Image === invocation.receipt.resources.offsite.resticImageId
    && container?.Config?.User === "1000:1000"
    && canonicalJson(container?.Config?.Entrypoint) === canonicalJson(["/usr/bin/restic"])
    && canonicalJson(container?.Config?.Cmd) === canonicalJson(expectedCommand)
    && labels?.["com.platform.local-private.offsite-restore-request-sha256"] === invocation.requestSha256
    && labels?.["com.platform.local-private.offsite-restore-role"] === binding.role
    && container?.HostConfig?.ReadonlyRootfs === true
    && canonicalJson(container?.HostConfig?.CapDrop) === canonicalJson(["ALL"])
    && canonicalJson(container?.HostConfig?.SecurityOpt) === canonicalJson(["no-new-privileges:true"])
    && container?.HostConfig?.PidsLimit === 128
    && container?.HostConfig?.LogConfig?.Type === "none"
    && container?.HostConfig?.NetworkMode === invocation.egressNetwork
    && canonicalJson(container?.HostConfig?.Tmpfs) === canonicalJson({
      "/tmp": "rw,noexec,nosuid,nodev,size=256m,mode=1777",
    })
    && canonicalJson(networks) === canonicalJson([invocation.egressNetwork])
    && canonicalJson(mounts) === canonicalJson(expectedContainerMounts(invocation, binding.role))
    && canonicalJson([...environment].sort()) === canonicalJson(expectedEnvironment);
  if (!exact) fail(`isolated Restic helper identity differs from its request: ${binding.name}`);
  return Object.freeze(binding);
}

function restoreContainerIdentity(invocation, name, role) {
  const listed = policyDockerSync(invocation, [
    "ps", "-aq", "--no-trunc", "--filter", `name=^/${name}$`,
  ], {}, { encoding: "utf8", timeout: 10_000 });
  if (listed.status !== 0 || listed.signal || listed.error) {
    fail(`isolated Restic helper identity query failed: ${name}`);
  }
  const ids = String(listed.stdout ?? "").trim().split(/\s+/).filter(Boolean);
  if (!ids.length) return null;
  if (ids.length !== 1 || !/^[a-f0-9]{64}$/.test(ids[0])) {
    fail(`isolated Restic helper identity is ambiguous: ${name}`);
  }
  const binding = { id: ids[0], name, role };
  const inspected = policyDockerSync(invocation, ["container", "inspect", ids[0]], {
    restoreContainer: binding,
  }, { encoding: "utf8", maxBuffer: 1024 * 1024, timeout: 10_000 });
  if (inspected.status !== 0 || inspected.signal || inspected.error) {
    fail(`isolated Restic helper inspection failed: ${name}`);
  }
  const documents = JSON.parse(String(inspected.stdout ?? ""));
  const container = Array.isArray(documents) && documents.length === 1 ? documents[0] : null;
  return validateRestoreContainerInspection(invocation, binding, container);
}

function removeContainer(invocation, name, role, knownBinding = undefined) {
  const binding = knownBinding ?? restoreContainerIdentity(invocation, name, role);
  if (binding) {
    const removed = policyDockerSync(invocation, ["rm", "-f", binding.id], {
      restoreContainer: binding,
    }, { encoding: "utf8", timeout: 30_000 });
    if (removed.status !== 0 || removed.signal || removed.error) {
      fail(`isolated Restic helper removal failed: ${name}`);
    }
  }
  if (restoreContainerIdentity(invocation, name, role)) {
    fail(`isolated Restic helper cleanup failed: ${name}`);
  }
  activeContainers.delete(name);
}

function assertRemovableTree(root) {
  const walk = (current) => {
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink() || stat.uid !== process.getuid() || stat.gid !== process.getgid()) {
      fail(`isolated restore cleanup encountered an unsafe path: ${current}`);
    }
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(current)) walk(path.join(current, entry));
    } else if (!stat.isFile() || stat.nlink !== 1) {
      fail(`isolated restore cleanup encountered a non-regular path: ${current}`);
    }
  };
  walk(root);
}

function removeScratch(root) {
  if (!fs.existsSync(root)) {
    activeScratchRoots.delete(root);
    return;
  }
  assertRemovableTree(root);
  fs.rmSync(root, { recursive: true, force: true });
  if (fs.existsSync(root)) fail("isolated restore payload cleanup failed");
  activeScratchRoots.delete(root);
}

async function runDocker(name, args, environment, invocation) {
  const role = name.startsWith("gf-restic-snapshots-") ? "snapshots"
    : name.startsWith("gf-restic-restore-") ? "restore" : "";
  if (!role || !/^gf-restic-(?:snapshots|restore)-[a-f0-9]{12}$/.test(name) || activeContainers.has(name)) {
    fail("off-site restore helper container identity is invalid");
  }
  if (restoreContainerIdentity(invocation, name, role)) {
    fail(`off-site restore helper container already exists: ${name}`);
  }
  assertLocalPrivateBackupDockerInvocation(invocation, ["run", "--rm", "--name", name, ...args], {
    env: {
      RESTIC_PASSWORD_FILE: environment.RESTIC_PASSWORD_FILE,
      RESTIC_REPOSITORY: environment.RESTIC_REPOSITORY,
    },
  });
  activeContainers.set(name, { invocation, role });
  try {
    return await new Promise((resolve, reject) => {
      const child = spawn("docker", ["run", "--rm", "--name", name, ...args], {
        env: environment,
        stdio: ["ignore", "pipe", "pipe"],
      });
      const stdout = [];
      const stderr = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let oversized = false;
      const collect = (target, chunk, isStdout) => {
        if (isStdout) stdoutBytes += chunk.length;
        else stderrBytes += chunk.length;
        if (stdoutBytes + stderrBytes > MAX_DOCKER_OUTPUT) {
          oversized = true;
          child.kill("SIGTERM");
          return;
        }
        target.push(chunk);
      };
      child.stdout.on("data", (chunk) => collect(stdout, chunk, true));
      child.stderr.on("data", (chunk) => collect(stderr, chunk, false));
      child.once("error", reject);
      child.once("close", (code, signal) => {
        if (oversized || signal || code !== 0) {
          reject(new Error(`isolated Restic helper failed (${signal ?? code ?? "unknown"})`));
        } else {
          resolve({ stdout: Buffer.concat(stdout, stdoutBytes), stderr: Buffer.concat(stderr, stderrBytes) });
        }
      });
    });
  } finally {
    removeContainer(invocation, name, role);
  }
}

function exactCleanupPaths(invocation, environment) {
  const scratchParent = path.join(invocation.roots.dataContainer, ".offsite-restore-proof");
  const scratch = path.join(scratchParent, invocation.requestSha256);
  const refreshDir = path.dirname(environment.RCLONE_CONFIG);
  if (environment.RCLONE_CONFIG !== "/var/lib/platform-docker-action-broker/rclone-refresh/rclone.conf"
    || refreshDir !== "/var/lib/platform-docker-action-broker/rclone-refresh") {
    fail("off-site restore cleanup staging path is not canonical");
  }
  if (fs.existsSync(scratchParent)) {
    exactPrivateDirectory(scratchParent);
    const names = fs.readdirSync(scratchParent).sort();
    if (canonicalJson(names) !== canonicalJson([])
      && canonicalJson(names) !== canonicalJson([invocation.requestSha256])) {
      fail("off-site restore cleanup found an unexpected scratch entry");
    }
    if (fs.existsSync(scratch)) {
      exactPrivateDirectory(scratch);
      assertRemovableTree(scratch);
    }
  }
  exactPrivateDirectory(refreshDir, { create: true });
  const refreshNames = fs.readdirSync(refreshDir).sort();
  if (canonicalJson(refreshNames) !== canonicalJson([])
    && canonicalJson(refreshNames) !== canonicalJson(["rclone.conf"])) {
    fail("off-site restore cleanup found unexpected rclone staging");
  }
  const stagedFile = environment.RCLONE_CONFIG;
  if (fs.existsSync(stagedFile)) {
    const stat = fs.lstatSync(stagedFile);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
      || stat.uid !== process.getuid() || stat.gid !== process.getgid()
      || (stat.mode & 0o077) !== 0) fail("off-site restore cleanup staging file is unsafe");
  }
  return Object.freeze({ refreshDir, scratch, scratchParent, stagedFile });
}

export function cleanupLocalPrivateOffsiteRestore(invocation, { environment = process.env } = {}) {
  if (!invocation || invocation.action !== "restore.offsite.proof"
    || invocation.command !== "restore-offsite-proof"
    || !/^[a-f0-9]{64}$/.test(String(invocation.requestSha256 ?? ""))) {
    fail("off-site restore cleanup lacks exact LOCAL_PRIVATE broker authority");
  }
  const short = invocation.requestSha256.slice(0, 12);
  const identities = [
    { name: `gf-restic-snapshots-${short}`, role: "snapshots" },
    { name: `gf-restic-restore-${short}`, role: "restore" },
  ].map((item) => ({ ...item, binding: restoreContainerIdentity(invocation, item.name, item.role) }));
  const paths = exactCleanupPaths(invocation, environment);
  for (const identity of identities) {
    removeContainer(invocation, identity.name, identity.role, identity.binding);
  }
  const confirmedPaths = exactCleanupPaths(invocation, environment);
  if (canonicalJson(confirmedPaths) !== canonicalJson(paths)) {
    fail("off-site restore cleanup paths changed after helper removal");
  }
  removeScratch(paths.scratch);
  if (fs.existsSync(paths.scratchParent)) {
    if (fs.readdirSync(paths.scratchParent).length !== 0) fail("off-site restore scratch parent changed during cleanup");
    fs.rmdirSync(paths.scratchParent);
    syncDirectory(path.dirname(paths.scratchParent));
  }
  const refreshNames = fs.readdirSync(paths.refreshDir).sort();
  if (canonicalJson(refreshNames) !== canonicalJson([])
    && canonicalJson(refreshNames) !== canonicalJson(["rclone.conf"])) {
    fail("off-site restore rclone staging changed during cleanup");
  }
  return Object.freeze({
    helperContainersAbsent: true,
    requestSha256: invocation.requestSha256,
    restorePayloadRemoved: true,
    rcloneStagingPreserved: true,
    schema: "platform.offsite-restore-cleanup/v1",
    status: "completed",
  });
}

export function reconcileInterruptedLocalPrivateOffsiteRestore({ environment = process.env } = {}) {
  const invocation = initializeLocalPrivateBackupInvocation({
    environment,
    processArgs: ["reconcile-interrupted"],
  });
  return cleanupLocalPrivateOffsiteRestore(invocation, { environment });
}

function restoredFilePaths(root) {
  const values = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name);
      const stat = fs.lstatSync(full);
      if (stat.isSymbolicLink()) fail(`off-site restore produced a symbolic link: ${full}`);
      if (stat.isDirectory()) walk(full);
      else if (stat.isFile()) values.push(`/${path.relative(root, full).replaceAll("\\", "/")}`);
      else fail(`off-site restore produced a non-regular file: ${full}`);
    }
  };
  walk(root);
  return values.sort();
}

function restoredPath(root, absolutePath) {
  const relative = String(absolutePath).replace(/^\/+/, "");
  const candidate = path.resolve(root, relative);
  if (!candidate.startsWith(`${path.resolve(root)}${path.sep}`)) fail("restored path escaped the isolated root");
  return candidate;
}

export function verifyRestoredOffsiteSet({
  backupSigningKeyFile,
  expected,
  priorReceipt,
  restoreRoot,
  snapshot,
} = {}) {
  if (!snapshot || snapshot.id !== expected.snapshotId) fail("Restic snapshot identity differs from signed admission");
  const located = locateSnapshotManifest({ snapshotPaths: snapshot.paths, snapshotTags: snapshot.tags });
  if (located.manifestId !== expected.manifestId || located.manifestDigest !== expected.manifestDigest) {
    fail("Restic snapshot manifest tags differ from signed admission");
  }
  if (!priorReceipt || priorReceipt.schema !== "platform.offsite-backup-receipt/v1"
    || priorReceipt.status !== "passed" || priorReceipt.repositoryOffsite !== true
    || priorReceipt.credentialsExposed !== false || priorReceipt.snapshotId !== expected.snapshotId
    || priorReceipt.manifestId !== expected.manifestId || priorReceipt.manifestDigest !== expected.manifestDigest) {
    fail("bound off-site backup receipt is not a completed matching upload");
  }
  const manifestFile = restoredPath(restoreRoot, located.manifestPath);
  const { manifest } = verifyOffsiteManifest(manifestFile, backupSigningKeyFile);
  if (manifest.id !== expected.manifestId || manifest.signature.digest !== expected.manifestDigest
    || backupDocumentDigest(parseBackupManifestDocument(manifest)) !== expected.manifestDigest) {
    fail("restored manifest identity differs from signed admission");
  }
  const exact = validateOffsiteRestoreSet({
    manifest,
    restoredPaths: restoredFilePaths(restoreRoot),
    snapshotPaths: snapshot.paths,
    snapshotTags: snapshot.tags,
  });
  const signingKeys = backupSigningKeyMap(fs.readFileSync(backupSigningKeyFile));
  let restoredBytes = 0;
  for (const artifact of manifest.artifacts) {
    const artifactFile = restoredPath(restoreRoot, `/backups/${artifact.path}`);
    const stat = fs.lstatSync(artifactFile);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
      || stat.size !== artifact.sizeBytes || sha256File(artifactFile) !== artifact.sha256) {
      fail(`restored artifact hash or size differs: ${artifact.resourceId}`);
    }
    const checksum = readBoundText(`${artifactFile}.sha256`).trim().split(/\s+/, 1)[0];
    const signature = readBoundJson(`${artifactFile}.sig.json`, 128 * 1024);
    if (checksum !== artifact.sha256) fail(`restored artifact checksum differs: ${artifact.resourceId}`);
    verifyArtifactSidecar(artifactFile, artifact, signature, signingKeys);
    restoredBytes += stat.size;
  }
  const resourceIds = manifest.resources.map((resource) => resource.id).sort();
  const receiptResourceIds = [...(priorReceipt.resourceIds ?? [])].sort();
  if (canonicalJson(resourceIds) !== canonicalJson(receiptResourceIds)
    || priorReceipt.artifactCount !== manifest.artifacts.length
    || exact.resourceIds.length !== resourceIds.length) {
    fail("restored manifest coverage differs from the uploaded receipt");
  }
  return Object.freeze({
    artifactCount: manifest.artifacts.length,
    manifestDigest: manifest.signature.digest,
    manifestId: manifest.id,
    resourceCount: resourceIds.length,
    restoredBytes,
    snapshotId: snapshot.id,
  });
}

function fixedResticArgs(invocation, role, restoreHostPath = null) {
  const secretsHost = invocation.roots.secretsHost;
  const rcloneRefreshHost = path.join(invocation.roots.brokerStateHost, "rclone-refresh");
  const image = invocation.receipt.resources.offsite.resticImageId;
  const base = [
    "--pull", "never",
    "--network", invocation.egressNetwork,
    "--read-only",
    "--user", "1000:1000",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true",
    "--pids-limit", "128",
    "--log-driver", "none",
    "--label", `com.platform.local-private.offsite-restore-request-sha256=${invocation.requestSha256}`,
    "--label", `com.platform.local-private.offsite-restore-role=${role}`,
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777",
    "-e", "HOME=/tmp",
    "-e", "XDG_CACHE_HOME=/tmp/.cache",
    "-e", "RESTIC_REPOSITORY",
    "-e", "RESTIC_PASSWORD_FILE",
    "-e", "RCLONE_CONFIG=/rclone-config/rclone.conf",
    "--mount", `type=bind,src=${rcloneRefreshHost},dst=/rclone-config`,
    "--mount", `type=bind,src=${path.join(secretsHost, "restic_password.txt")},dst=/restic-password/restic_password.txt,readonly`,
  ];
  if (restoreHostPath) base.push("--mount", `type=bind,src=${restoreHostPath},dst=/restore`);
  base.push(image);
  return base;
}

export async function runLocalPrivateOffsiteRestore({ environment = process.env } = {}) {
  const invocation = initializeLocalPrivateBackupInvocation({ environment, processArgs: [] });
  if (!invocation || invocation.action !== "restore.offsite.proof"
    || invocation.command !== "restore-offsite-proof") {
    fail("off-site restore helper lacks exact LOCAL_PRIVATE broker authority");
  }
  const expected = invocation.receipt.resources.offsite.restore;
  const priorReceiptFile = path.join(invocation.roots.dataContainer, "reports", "offsite-backups", expected.receiptFileName);
  if (sha256File(priorReceiptFile) !== expected.receiptFileSha256) {
    fail("off-site backup receipt differs from signed admission");
  }
  const priorReceipt = readBoundJson(priorReceiptFile);
  const scratchParent = path.join(invocation.roots.dataContainer, ".offsite-restore-proof");
  const scratchParentHost = path.join(invocation.roots.dataHost, ".offsite-restore-proof");
  exactPrivateDirectory(scratchParent, { create: true });
  const scratchName = invocation.requestSha256;
  const scratch = path.join(scratchParent, scratchName);
  const scratchHost = path.join(scratchParentHost, scratchName);
  fs.mkdirSync(scratch, { mode: 0o700 });
  exactPrivateDirectory(scratch);
  activeScratchRoots.add(scratch);
  const snapshotsName = `gf-restic-snapshots-${invocation.requestSha256.slice(0, 12)}`;
  const restoreName = `gf-restic-restore-${invocation.requestSha256.slice(0, 12)}`;
  const dockerEnvironment = {
    PATH: environment.PATH,
    RESTIC_PASSWORD_FILE: "/restic-password/restic_password.txt",
    RESTIC_REPOSITORY: invocation.receipt.resources.offsite.repository,
  };
  let verified;
  try {
    const snapshotsResult = await runDocker(snapshotsName, [
      ...fixedResticArgs(invocation, "snapshots"),
      "--no-lock", "snapshots", "--json", "--tag", "platform-backups",
    ], dockerEnvironment, invocation);
    const snapshots = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(snapshotsResult.stdout));
    const matches = Array.isArray(snapshots)
      ? snapshots.filter((snapshot) => snapshot?.id === expected.snapshotId)
      : [];
    if (matches.length !== 1) fail("signed Restic snapshot was not found exactly once");
    await runDocker(restoreName, [
      ...fixedResticArgs(invocation, "restore", scratchHost),
      "--no-lock", "restore", expected.snapshotId, "--target", "/restore",
    ], dockerEnvironment, invocation);
    verified = verifyRestoredOffsiteSet({
      backupSigningKeyFile: environment.BACKUP_SIGNING_KEYS_FILE,
      expected,
      priorReceipt,
      restoreRoot: scratch,
      snapshot: matches[0],
    });
  } finally {
    removeScratch(scratch);
    try { fs.rmdirSync(scratchParent); } catch (error) {
      if (error?.code !== "ENOTEMPTY") throw error;
    }
  }
  if (!verified) fail("off-site restore did not produce verified evidence");
  const summary = {
    artifactCount: verified.artifactCount,
    artifactSignaturesVerified: true,
    exactSetVerified: true,
    manifestDigest: verified.manifestDigest,
    manifestId: verified.manifestId,
    manifestSignatureVerified: true,
    receiptFile: expected.receiptFileName,
    receiptFileSha256: expected.receiptFileSha256,
    resourceCount: verified.resourceCount,
    restoredBytes: verified.restoredBytes,
    restorePayloadRemoved: true,
    schema: LOCAL_PRIVATE_OFFSITE_RESTORE_SCHEMA,
    snapshotId: verified.snapshotId,
    status: "passed",
  };
  return Object.freeze(summary);
}

async function main() {
  const summary = process.argv[2] === "reconcile-interrupted" && process.argv.length === 3
    ? reconcileInterruptedLocalPrivateOffsiteRestore()
    : process.argv.length === 2
      ? await runLocalPrivateOffsiteRestore()
      : fail("unsupported off-site restore helper command");
  process.stdout.write(`${canonicalJson(summary)}\n`);
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.once(signal, () => {
    for (const [name, active] of [...activeContainers]) removeContainer(active.invocation, name, active.role);
    for (const scratch of [...activeScratchRoots]) removeScratch(scratch);
    process.exit(128 + ({ SIGHUP: 1, SIGINT: 2, SIGTERM: 15 }[signal] ?? 0));
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    for (const [name, active] of [...activeContainers]) removeContainer(active.invocation, name, active.role);
    for (const scratch of [...activeScratchRoots]) removeScratch(scratch);
    process.stderr.write(`${error.message ?? error}\n`);
    process.exitCode = 1;
  });
}
