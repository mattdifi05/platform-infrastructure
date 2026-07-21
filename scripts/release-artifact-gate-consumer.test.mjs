#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createVerifiedReleaseArtifacts } from "./release-subject-manifest.mjs";
import { resolveRegistryDescriptor } from "./release-registry-resolution.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "release-gate-consumer-"));

function writeJson(name, value) {
  const pathname = path.join(temporary, name);
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  fs.writeFileSync(pathname, bytes, { mode: 0o600 });
  return { pathname, bytes, sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
}

try {
  const repository = "owner/repo";
  const commitSha = "b".repeat(40);
  const runtimeDigest = `sha256:${"c".repeat(64)}`;
  const descriptor = {
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [
      {
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: runtimeDigest,
        size: 123,
        platform: { os: "linux", architecture: "amd64" },
      },
      {
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: `sha256:${"d".repeat(64)}`,
        size: 456,
        platform: { os: "unknown", architecture: "unknown" },
        annotations: {
          "vnd.docker.reference.type": "attestation-manifest",
          "vnd.docker.reference.digest": runtimeDigest,
        },
      },
    ],
  };
  const descriptorBytes = Buffer.from(JSON.stringify(descriptor));
  const descriptorPath = path.join(temporary, "registry-descriptor.json");
  fs.writeFileSync(descriptorPath, descriptorBytes, { mode: 0o600 });
  const rootDigest = crypto.createHash("sha256").update(descriptorBytes).digest("hex");
  const image = `ghcr.io/owner/platform-infrastructure-php-apache@sha256:${rootDigest}`;
  const entries = [{ key: "PHP_APACHE_IMAGE", image }];
  const registryResolution = resolveRegistryDescriptor({
    image,
    descriptorBytes,
    expectedPlatforms: ["linux/amd64"],
    resolvedAt: "2026-07-21T00:00:00Z",
  });
  const registryArtifact = writeJson("registry-resolution.json", registryResolution);
  const buildkitSbom = {
    "linux/amd64": {
      SPDX: {
        spdxVersion: "SPDX-2.3",
        SPDXID: "SPDXRef-DOCUMENT",
        dataLicense: "CC0-1.0",
        documentNamespace: "https://example.invalid/spdx/release-gate",
        creationInfo: { created: "2026-07-21T00:00:00Z" },
        packages: [{
          SPDXID: "SPDXRef-Package-openssl",
          name: "openssl",
          versionInfo: "3.0.0",
          externalRefs: [{ referenceType: "purl", referenceLocator: "pkg:apk/alpine/openssl@3.0.0" }],
        }],
      },
    },
  };
  const buildkitArtifact = writeJson("buildkit-sbom.spdx.json", buildkitSbom);
  const generationVerification = {
    status: "passed",
    verified: true,
    completeness: "complete",
    repository,
    sourceDigest: commitSha,
    commitSha,
    commitShaMatched: true,
    provider: "github-artifact-attestations",
    signerWorkflow: `${repository}/.github/workflows/release-attestation.yml`,
    sourceRef: "refs/heads/main",
    releaseImages: [image],
    attestations: [{
      status: "passed",
      verified: true,
      completeness: "complete",
      repository,
      signerWorkflow: `${repository}/.github/workflows/release-attestation.yml`,
      sourceDigest: commitSha,
      sourceRef: "refs/heads/main",
      predicateType: "https://slsa.dev/provenance/v1",
      certOidcIssuer: "https://token.actions.githubusercontent.com",
      certificateFingerprints: ["f".repeat(64)],
      verifiedTimestampCount: 1,
      subjects: [{ name: "ghcr.io/owner/platform-infrastructure-php-apache", sha256: rootDigest }],
    }],
  };
  const artifacts = createVerifiedReleaseArtifacts({
    entries,
    repository,
    commitSha,
    releaseName: "consumer-test",
    workflowRunId: "1",
    workflowRunUrl: "https://example.invalid/run/1",
    verification: generationVerification,
    buildkitSbom,
    buildkitSbomBytes: buildkitArtifact.bytes,
    registryResolution,
    registryResolutionSha256: registryArtifact.sha256,
    registryDescriptorBytes: descriptorBytes,
    expectedPlatforms: ["linux/amd64"],
    generatedAt: "2026-07-21T00:00:00.000Z",
    serialNumber: "urn:uuid:123e4567-e89b-42d3-a456-426614174000",
  });
  const manifestArtifact = writeJson("release-subjects.json", artifacts.manifest);
  const sbomArtifact = writeJson("release-sbom.cdx.json", artifacts.sbom);
  assert.equal(manifestArtifact.sha256.length, 64);
  assert.equal(sbomArtifact.sha256, artifacts.manifest.sbom.sha256);

  const fakeGh = path.join(temporary, "fake-gh.mjs");
  fs.writeFileSync(fakeGh, `#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
const subject = process.argv[4];
const predicateIndex = process.argv.indexOf("--predicate-type");
const predicateType = process.argv[predicateIndex + 1];
let name;
let digest;
if (subject.startsWith("oci://")) {
  const match = subject.match(/^oci:\\/\\/(.+)@sha256:([a-f0-9]{64})$/);
  name = match[1];
  digest = match[2];
} else {
  name = subject;
  digest = crypto.createHash("sha256").update(fs.readFileSync(subject)).digest("hex");
}
process.stdout.write(JSON.stringify([{ verificationResult: {
  signature: { certificate: { testCertificate: true } },
  verifiedTimestamps: [{ source: "test" }],
  statement: { predicateType, subject: [{ name, digest: { sha256: digest } }] },
} }]));
`, { mode: 0o700 });

  const commonArgs = [
    path.join(root, "scripts", "infra-ops.mjs"),
    "release-artifact-gate",
    "--imageManifest", manifestArtifact.pathname,
    "--sbom", sbomArtifact.pathname,
    "--buildkitSbom", buildkitArtifact.pathname,
    "--registryDescriptor", descriptorPath,
    "--registryResolution", registryArtifact.pathname,
    "--releaseSha", commitSha,
    "--repo", repository,
    "--sourceRef", "refs/heads/main",
  ];
  const environment = {
    ...process.env,
    PLATFORM_RELEASE_TRUST_TEST_MODE: "1",
    GITHUB_CLI_BIN: fakeGh,
    GH_TOKEN: "release-gate-consumer-test-token",
  };
  const positive = spawnSync(process.execPath, commonArgs, { cwd: root, env: environment, encoding: "utf8" });
  assert.equal(positive.status, 1);
  assert.match(positive.stderr, /EXTERNAL-PENDING/);
  assert.doesNotMatch(positive.stderr, /Exact per-subject registry resolution is required/);

  const tampered = structuredClone(registryResolution);
  tampered.platforms[0].size += 1;
  const tamperedArtifact = writeJson("registry-resolution-tampered.json", tampered);
  const negativeArgs = [...commonArgs];
  negativeArgs[negativeArgs.indexOf(registryArtifact.pathname)] = tamperedArtifact.pathname;
  const negative = spawnSync(process.execPath, negativeArgs, { cwd: root, env: environment, encoding: "utf8" });
  assert.equal(negative.status, 1);
  assert.match(negative.stderr, /differs from exact descriptor resolution/);
  assert.doesNotMatch(negative.stderr, /EXTERNAL-PENDING/);

  process.stdout.write("release artifact gate consumer tests passed 2/2; trusted channel remains EXTERNAL-PENDING\n");
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
