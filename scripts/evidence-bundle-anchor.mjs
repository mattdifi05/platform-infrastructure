import crypto from "node:crypto";

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
