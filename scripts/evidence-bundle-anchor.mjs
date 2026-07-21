import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const SHA256 = /^[a-f0-9]{64}$/;

export function verifyOwnerPinnedBundleManifest({ manifestBytes, expectedManifestSha256 }) {
  if (!Buffer.isBuffer(manifestBytes) && typeof manifestBytes !== "string") {
    throw new Error("Evidence bundle manifest bytes are required.");
  }
  const expected = String(expectedManifestSha256 ?? "").trim().toLowerCase().replace(/^sha256:/, "");
  if (!SHA256.test(expected)) {
    throw new Error("An independently owner-pinned evidence bundle manifest SHA-256 is required.");
  }
  const actual = crypto.createHash("sha256").update(manifestBytes).digest("hex");
  if (actual !== expected) {
    throw new Error("Evidence bundle manifest does not match the independently owner-pinned SHA-256.");
  }
  return {
    status: "passed",
    trustMode: "owner-pinned-manifest-sha256",
    manifestSha256: actual,
  };
}

function closedWorldRelativePath(value) {
  const normalized = String(value ?? "").replaceAll("\\", "/");
  if (!normalized || normalized.startsWith("/") || normalized.split("/").some((part) => !part || part === "." || part === "..")) {
    throw new Error(`invalid bundle path: ${value}`);
  }
  return normalized;
}

function allowedDirectories(filePaths) {
  const directories = new Set();
  for (const filePath of filePaths) {
    let directory = path.posix.dirname(filePath);
    while (directory && directory !== ".") {
      directories.add(directory);
      directory = path.posix.dirname(directory);
    }
  }
  return directories;
}

export function verifyClosedWorldBundleFiles({ bundleDir, manifestEntryPaths }) {
  const root = path.resolve(String(bundleDir ?? ""));
  const rootStat = fs.lstatSync(root, { throwIfNoEntry: false });
  if (!rootStat?.isDirectory() || rootStat.isSymbolicLink()) throw new Error("evidence bundle root must be a real directory");
  const entryPaths = Array.isArray(manifestEntryPaths) ? manifestEntryPaths.map(closedWorldRelativePath) : [];
  const allowedFiles = new Set(["manifest.json", "manifest.md", "summary.json", ...entryPaths]);
  if (allowedFiles.size !== entryPaths.length + 3) throw new Error("duplicate or reserved manifest entry path");
  const allowedDirs = allowedDirectories(allowedFiles);
  const observedFiles = new Set();
  let directoryCount = 0;
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    for (const name of fs.readdirSync(current)) {
      const absolute = path.join(current, name);
      const relative = path.relative(root, absolute).replaceAll("\\", "/");
      const stat = fs.lstatSync(absolute, { throwIfNoEntry: false });
      if (!stat || stat.isSymbolicLink()) throw new Error(`unexpected bundle path: ${relative}`);
      if (stat.isDirectory()) {
        if (!allowedDirs.has(relative)) throw new Error(`unexpected bundle path: ${relative}`);
        directoryCount += 1;
        stack.push(absolute);
      } else if (stat.isFile()) {
        if (!allowedFiles.has(relative)) throw new Error(`unexpected bundle path: ${relative}`);
        observedFiles.add(relative);
      } else {
        throw new Error(`unexpected bundle path: ${relative}`);
      }
    }
  }
  const missing = [...allowedFiles].filter((entry) => !observedFiles.has(entry));
  if (missing.length) throw new Error(`missing bundle path: ${missing.join(", ")}`);
  return { status: "passed", fileCount: observedFiles.size, directoryCount };
}
