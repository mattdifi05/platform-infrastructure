import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { openSha256FileBounded } from "./bounded-file-hash.mjs";

function invalid(message) {
  throw new Error(message);
}

function randomSibling(filePath, label) {
  return path.join(path.dirname(filePath), `.${path.basename(filePath)}.${label}-${process.pid}-${crypto.randomBytes(12).toString("hex")}`);
}

function ensureAbsent(filePath) {
  try {
    fs.lstatSync(filePath);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  invalid(`Refusing to replace an existing backup publication path: ${filePath}`);
}

function descriptorIdentity(descriptor) {
  const stat = fs.fstatSync(descriptor);
  return { dev: stat.dev, ino: stat.ino, size: stat.size };
}

function assertDescriptorPath(descriptor, filePath, label) {
  let pathStat;
  try {
    pathStat = fs.lstatSync(filePath);
  } catch {
    invalid(`${label} is missing.`);
  }
  const descriptorStat = fs.fstatSync(descriptor);
  if (pathStat.isSymbolicLink() || !pathStat.isFile() || pathStat.dev !== descriptorStat.dev || pathStat.ino !== descriptorStat.ino) {
    invalid(`${label} changed identity.`);
  }
  return true;
}

function writeAll(descriptor, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = fs.writeSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (written <= 0) invalid("Unable to write backup publication sidecar.");
    offset += written;
  }
}

function readAll(descriptor, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const read = fs.readSync(descriptor, bytes, offset, size - offset, offset);
    if (read <= 0) invalid("Backup publication sidecar was truncated.");
    offset += read;
  }
  return bytes;
}

function createSidecarLease(filePath, content) {
  const bytes = Buffer.from(content);
  const flags = fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW ?? 0);
  const descriptor = fs.openSync(filePath, flags, 0o600);
  try {
    writeAll(descriptor, bytes);
    fs.fsyncSync(descriptor);
    fs.fchmodSync(descriptor, 0o400);
    return {
      descriptor,
      filePath,
      bytes,
      identity: descriptorIdentity(descriptor),
      assertAt(candidatePath, label) {
        assertDescriptorPath(descriptor, candidatePath, label);
        const stat = fs.fstatSync(descriptor);
        if (stat.size !== bytes.length || !readAll(descriptor, stat.size).equals(bytes)) invalid(`${label} content changed.`);
      },
      close() {
        fs.closeSync(descriptor);
      },
    };
  } catch (error) {
    fs.closeSync(descriptor);
    fs.rmSync(filePath, { force: true });
    throw error;
  }
}

function validateSignature(result, artifactName, hash) {
  const keyId = String(result?.keyId ?? "").trim();
  const document = result?.document;
  if (!keyId || !document || typeof document !== "object" || Array.isArray(document)) invalid("Backup signature factory returned invalid metadata.");
  if (document.keyId !== keyId || document.artifact !== artifactName || document.sha256 !== hash) {
    invalid("Backup signature metadata is not bound to the staged artifact.");
  }
  if (!String(document.signature ?? "").trim()) invalid("Backup signature metadata has no signature value.");
  return { keyId, document };
}

function removeIfPresent(filePath) {
  try {
    fs.unlinkSync(filePath);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

export function publishBackupArtifact({
  stagingPath,
  publishedPath,
  allowSeparateStagingDirectory = false,
  createSignature,
  onChecksumStaged,
  onPublished,
  hashOptions,
} = {}) {
  const staging = path.resolve(String(stagingPath ?? ""));
  const published = path.resolve(String(publishedPath ?? ""));
  const stagingDirectory = path.dirname(staging);
  const publishedDirectory = path.dirname(published);
  const separateStagingDirectory = stagingDirectory !== publishedDirectory;
  if (!stagingPath || !publishedPath || staging === published
    || (separateStagingDirectory && allowSeparateStagingDirectory !== true)) {
    invalid("Backup staging and publication paths must be distinct siblings unless a separate staging directory is explicitly admitted.");
  }
  if (separateStagingDirectory) {
    const stagingDirectoryStat = fs.statSync(stagingDirectory);
    const publishedDirectoryStat = fs.statSync(publishedDirectory);
    if (!stagingDirectoryStat.isDirectory() || !publishedDirectoryStat.isDirectory()
      || stagingDirectoryStat.dev !== publishedDirectoryStat.dev) {
      invalid("Separate backup staging and publication directories must be directories on one filesystem.");
    }
  }
  if (typeof createSignature !== "function") invalid("Backup signature factory is required.");
  if (onChecksumStaged !== undefined && typeof onChecksumStaged !== "function") invalid("onChecksumStaged must be a function.");
  if (onPublished !== undefined && typeof onPublished !== "function") invalid("onPublished must be a function.");

  const checksumPath = `${published}.sha256`;
  const signaturePath = `${published}.sig.json`;
  for (const filePath of [published, checksumPath, signaturePath]) ensureAbsent(filePath);

  const checksumTemp = randomSibling(path.join(stagingDirectory, path.basename(checksumPath)), "staging");
  const signatureTemp = randomSibling(path.join(stagingDirectory, path.basename(signaturePath)), "staging");
  let artifactLease;
  let checksumLease;
  let signatureLease;
  let publishedArtifact = false;
  let publishedChecksum = false;
  let publishedSignature = false;
  let returned = false;

  const assertStaging = () => {
    try {
      artifactLease.assertUnchanged();
      artifactLease.assertPathIdentity(staging);
    } catch {
      invalid("Backup staging artifact changed after hashing.");
    }
  };

  try {
    artifactLease = openSha256FileBounded(staging, hashOptions);
    const artifactName = path.basename(published);
    const hash = artifactLease.sha256;
    const sizeBytes = artifactLease.sizeBytes;
    checksumLease = createSidecarLease(checksumTemp, `${hash}  ${artifactName}\n`);
    onChecksumStaged?.({ stagingPath: staging, checksumStagingPath: checksumTemp, hash, sizeBytes });
    assertStaging();

    const signature = validateSignature(createSignature({ artifactName, sha256: hash, sizeBytes }), artifactName, hash);
    assertStaging();
    signatureLease = createSidecarLease(signatureTemp, `${JSON.stringify(signature.document, null, 2)}\n`);
    assertStaging();

    fs.fchmodSync(artifactLease.descriptor, 0o400);
    const immutableDigest = artifactLease.rehash();
    if (immutableDigest.sha256 !== hash || immutableDigest.sizeBytes !== sizeBytes) invalid("Backup staging artifact changed before publication.");

    fs.linkSync(checksumTemp, checksumPath);
    publishedChecksum = true;
    checksumLease.assertAt(checksumPath, "Published backup checksum sidecar");
    fs.linkSync(signatureTemp, signaturePath);
    publishedSignature = true;
    signatureLease.assertAt(signaturePath, "Published backup signature sidecar");
    fs.linkSync(staging, published);
    publishedArtifact = true;
    try {
      artifactLease.assertPathIdentity(published);
    } catch {
      invalid("Published artifact changed identity.");
    }

    removeIfPresent(staging);
    removeIfPresent(checksumTemp);
    removeIfPresent(signatureTemp);

    const assertCurrent = () => {
      try {
        artifactLease.assertPathIdentity(published);
      } catch {
        invalid("Published artifact changed identity.");
      }
      const current = artifactLease.rehash();
      if (current.sha256 !== hash || current.sizeBytes !== sizeBytes) invalid("Published artifact changed content.");
      checksumLease.assertAt(checksumPath, "Published backup checksum sidecar");
      signatureLease.assertAt(signaturePath, "Published backup signature sidecar");
      return true;
    };

    let closed = false;
    const result = {
      hostPath: published,
      hash,
      sizeBytes,
      signature: { hash, keyId: signature.keyId, signaturePath },
      assertCurrent,
      close() {
        if (closed) return;
        closed = true;
        artifactLease.close();
        checksumLease.close();
        signatureLease.close();
      },
    };
    assertCurrent();
    onPublished?.(result);
    assertCurrent();
    returned = true;
    return result;
  } finally {
    if (!returned) {
      if (publishedArtifact) removeIfPresent(published);
      if (publishedChecksum) removeIfPresent(checksumPath);
      if (publishedSignature) removeIfPresent(signaturePath);
      removeIfPresent(checksumTemp);
      removeIfPresent(signatureTemp);
      if (artifactLease) {
        try {
          artifactLease.assertPathIdentity(staging);
          removeIfPresent(staging);
        } catch {
          // A replaced path is not owned by this publication attempt.
        }
      }
      artifactLease?.close();
      checksumLease?.close();
      signatureLease?.close();
    }
  }
}
