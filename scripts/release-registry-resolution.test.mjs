#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { resolveRegistryDescriptor, validateRegistryResolutionReceipt } from "./release-registry-resolution.mjs";

const runtimeDigest = `sha256:${"b".repeat(64)}`;
const index = {
  schemaVersion: 2,
  mediaType: "application/vnd.oci.image.index.v1+json",
  manifests: [
    { mediaType: "application/vnd.oci.image.manifest.v1+json", digest: runtimeDigest, size: 1234, platform: { os: "linux", architecture: "amd64" } },
    {
      mediaType: "application/vnd.oci.image.manifest.v1+json", digest: `sha256:${"c".repeat(64)}`, size: 567,
      platform: { os: "unknown", architecture: "unknown" },
      annotations: { "vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": runtimeDigest },
    },
  ],
};
const bytes = Buffer.from(JSON.stringify(index));
const root = crypto.createHash("sha256").update(bytes).digest("hex");
const image = `ghcr.io/owner/app@sha256:${root}`;
const receipt = resolveRegistryDescriptor({ image, descriptorBytes: bytes, expectedPlatforms: ["linux/amd64"], resolvedAt: "2026-07-21T00:00:00Z" });

assert.deepEqual(receipt.platforms.map((entry) => entry.platform), ["linux/amd64"]);
assert.equal(validateRegistryResolutionReceipt(receipt, { image, descriptorBytes: bytes, expectedPlatforms: ["linux/amd64"] }).rootDigest, `sha256:${root}`);
const newlineReceipt = resolveRegistryDescriptor({ image, descriptorBytes: Buffer.concat([bytes, Buffer.from("\n")]), expectedPlatforms: ["linux/amd64"] });
assert.equal(newlineReceipt.descriptorSha256, root);
assert.notEqual(newlineReceipt.descriptorArtifactSha256, root);
assert.throws(() => resolveRegistryDescriptor({ image, descriptorBytes: bytes, expectedPlatforms: ["linux/arm64"] }), /platform set/);
assert.throws(() => resolveRegistryDescriptor({ image: `ghcr.io/owner/app@sha256:${"d".repeat(64)}`, descriptorBytes: bytes, expectedPlatforms: ["linux/amd64"] }), /root digest/);
const detached = structuredClone(index);
detached.manifests[1].annotations["vnd.docker.reference.digest"] = `sha256:${"d".repeat(64)}`;
const detachedBytes = Buffer.from(JSON.stringify(detached));
const detachedImage = `ghcr.io/owner/app@sha256:${crypto.createHash("sha256").update(detachedBytes).digest("hex")}`;
assert.throws(() => resolveRegistryDescriptor({ image: detachedImage, descriptorBytes: detachedBytes, expectedPlatforms: ["linux/amd64"] }), /not bound/);
process.stdout.write("release registry resolution tests passed 6/6\n");
