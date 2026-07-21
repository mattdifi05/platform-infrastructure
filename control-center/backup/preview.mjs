import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import path from "node:path";

const SHA256 = /^[a-f0-9]{64}$/;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._@ -]{0,179}$/;
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MAX_CHECKSUM_BYTES = 4096;
const MAX_SIGNATURE_BYTES = 16384;
const DENIED_MESSAGE = "Contenuto non mostrato: l'anteprima non soddisfa lo schema pubblico allowlist.";

function denied(reason) {
  return {
    mode: "metadata-only",
    content: "",
    reason,
    message: DENIED_MESSAGE,
  };
}

function boundedRegularFile(filePath, maxBytes) {
  let initial;
  try {
    initial = lstatSync(filePath);
  } catch {
    return { denied: "unavailable" };
  }
  if (!initial.isFile() || initial.isSymbolicLink()) return { denied: "not-regular" };
  if (initial.size > maxBytes) return { denied: "oversize" };
  let fd = null;
  try {
    fd = openSync(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.size > maxBytes) return { denied: "not-regular-or-oversize" };
    if (opened.dev !== initial.dev || opened.ino !== initial.ino || opened.size !== initial.size || opened.mtimeMs !== initial.mtimeMs) {
      return { denied: "changed-before-read" };
    }
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) return { denied: "truncated-read" };
      offset += count;
    }
    const finished = fstatSync(fd);
    if (finished.dev !== opened.dev || finished.ino !== opened.ino || finished.size !== opened.size || finished.mtimeMs !== opened.mtimeMs) {
      return { denied: "changed-during-read" };
    }
    return { bytes };
  } catch {
    return { denied: "read-failed" };
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

function strictUtf8(bytes) {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (/\0/.test(text) || /[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(text)) return null;
    return text;
  } catch {
    return null;
  }
}

function checksumPreview(filePath, relativePath) {
  const captured = boundedRegularFile(filePath, MAX_CHECKSUM_BYTES);
  if (!captured.bytes) return denied(captured.denied);
  const text = strictUtf8(captured.bytes);
  if (text === null) return denied("binary-or-invalid-utf8");
  const lines = text.trim().split(/\r?\n/);
  if (lines.length !== 1) return denied("unexpected-checksum-shape");
  const match = lines[0].match(/^([a-f0-9]{64})\s+[* ]?(.+)$/i);
  const artifact = String(match?.[2] ?? "").trim();
  const expectedArtifact = path.basename(String(relativePath).slice(0, -".sha256".length));
  if (!match || !SAFE_NAME.test(artifact) || artifact.includes("..") || path.basename(artifact) !== artifact || artifact !== expectedArtifact) {
    return denied("invalid-checksum-record");
  }
  return {
    mode: "allowlisted-preview",
    content: JSON.stringify({ sha256: match[1].toLowerCase(), artifactNameMatched: true }, null, 2),
    reason: null,
    message: "Anteprima checksum limitata allo schema pubblico allowlist.",
  };
}

function signaturePreview(filePath, relativePath) {
  const captured = boundedRegularFile(filePath, MAX_SIGNATURE_BYTES);
  if (!captured.bytes) return denied(captured.denied);
  const text = strictUtf8(captured.bytes);
  if (text === null) return denied("binary-or-invalid-utf8");
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return denied("malformed-json");
  }
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    return denied("invalid-signature-object");
  }
  const allowed = new Set(["version", "algorithm", "keyId", "artifact", "sha256", "signature", "signedAt"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) return denied("unknown-signature-field");
  const artifact = String(value.artifact ?? "");
  const expectedArtifact = path.basename(String(relativePath).slice(0, -".sig.json".length));
  const signedAt = Date.parse(String(value.signedAt ?? ""));
  if (
    value.version !== 1
    || value.algorithm !== "HMAC-SHA256"
    || !SAFE_KEY_ID.test(String(value.keyId ?? ""))
    || !SAFE_NAME.test(artifact)
    || artifact.includes("..")
    || path.basename(artifact) !== artifact
    || artifact !== expectedArtifact
    || !SHA256.test(String(value.sha256 ?? ""))
    || typeof value.signature !== "string"
    || value.signature.length < 32
    || value.signature.length > 512
    || !Number.isFinite(signedAt)
  ) {
    return denied("invalid-signature-schema");
  }
  const publicFields = {
    version: 1,
    algorithm: "HMAC-SHA256",
    sha256: String(value.sha256).toLowerCase(),
    signedAt: new Date(signedAt).toISOString(),
    signaturePresent: true,
  };
  return {
    mode: "allowlisted-preview",
    content: JSON.stringify(publicFields, null, 2),
    reason: null,
    message: "Anteprima firma limitata ai campi pubblici allowlist; il valore della firma e' omesso.",
  };
}

export function safeBackupPreview(filePath, relativePath) {
  const lower = String(relativePath ?? "").toLowerCase();
  if (lower.endsWith(".sig.json")) return signaturePreview(filePath, relativePath);
  if (lower.endsWith(".sha256")) return checksumPreview(filePath, relativePath);
  return denied("unclassified-format");
}

export const backupPreviewLimits = Object.freeze({
  checksumBytes: MAX_CHECKSUM_BYTES,
  signatureBytes: MAX_SIGNATURE_BYTES,
});
