import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

function invalid(message) {
  throw new Error(message);
}

export function snapshotFileArtifact(sourcePath, {
  label = "artifact",
  maxBytes = 128 * 1024 * 1024,
  afterCapture = null,
} = {}) {
  const resolved = path.resolve(String(sourcePath ?? ""));
  if (!sourcePath || !Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    invalid(`${label} snapshot arguments are invalid.`);
  }

  let descriptor;
  let before;
  let after;
  let bytes;
  try {
    const noFollow = fs.constants.O_NOFOLLOW;
    if (typeof noFollow !== "number") invalid(`${label} cannot be opened without symlink following.`);
    descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | noFollow);
    before = fs.fstatSync(descriptor);
    if (!before.isFile()) invalid(`${label} must be a regular file.`);
    if (before.size < 1 || before.size > maxBytes) invalid(`${label} exceeds the accepted size boundary.`);
    bytes = fs.readFileSync(descriptor);
    after = fs.fstatSync(descriptor);
  } catch (error) {
    invalid(`${label} could not be captured safely: ${String(error?.message ?? error)}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }

  if (
    bytes.length !== before.size
    || before.dev !== after.dev
    || before.ino !== after.ino
    || before.size !== after.size
    || before.mtimeMs !== after.mtimeMs
    || before.ctimeMs !== after.ctimeMs
  ) {
    invalid(`${label} changed while it was being captured.`);
  }
  if (afterCapture !== null) {
    if (typeof afterCapture !== "function") invalid(`${label} afterCapture hook is invalid.`);
    afterCapture();
  }

  const sha256 = crypto.createHash("sha256").update(bytes).digest("hex");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "platform-release-artifact-"));
  fs.chmodSync(directory, 0o700);
  const snapshotPath = path.join(directory, path.basename(resolved) || "artifact");
  fs.writeFileSync(snapshotPath, bytes, { flag: "wx", mode: 0o600 });

  let cleaned = false;
  return {
    sourcePath: resolved,
    snapshotPath,
    bytes,
    sha256,
    sizeBytes: bytes.length,
    cleanup() {
      if (!cleaned) {
        cleaned = true;
        fs.rmSync(directory, { recursive: true, force: true });
      }
    },
  };
}

export function snapshotJsonArtifact(sourcePath, options = {}) {
  const artifact = snapshotFileArtifact(sourcePath, {
    label: options.label ?? "JSON artifact",
    maxBytes: options.maxBytes,
    afterCapture: options.afterCapture,
  });
  try {
    artifact.document = JSON.parse(artifact.bytes.toString("utf8").replace(/^\uFEFF/, ""));
    delete artifact.bytes;
    return artifact;
  } catch (error) {
    artifact.cleanup();
    invalid(`Invalid JSON in ${options.label ?? "JSON artifact"}: ${String(error?.message ?? error)}`);
  }
}
