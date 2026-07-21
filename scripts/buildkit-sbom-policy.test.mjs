#!/usr/bin/env node
import assert from "node:assert/strict";
import { assertExactBuildkitComponentSet, buildkitSpdxInventory } from "./buildkit-sbom-policy.mjs";

const image = `ghcr.io/owner/app@sha256:${"a".repeat(64)}`;
const raw = {
  "linux/amd64": {
    SPDX: {
      spdxVersion: "SPDX-2.3", SPDXID: "SPDXRef-DOCUMENT", dataLicense: "CC0-1.0",
      documentNamespace: "https://example.invalid/spdx/1", creationInfo: { created: "2026-07-21T00:00:00Z" },
      packages: [{
        SPDXID: "SPDXRef-Package-openssl", name: "openssl", versionInfo: "3.0.0",
        externalRefs: [{ referenceType: "purl", referenceLocator: "pkg:apk/alpine/openssl@3.0.0" }],
        checksums: [{ algorithm: "SHA256", checksumValue: "b".repeat(64) }],
      }],
    },
  },
};
const inventory = buildkitSpdxInventory(raw, { subjects: [{ key: "APP_IMAGE", image }], expectedPlatforms: ["linux/amd64"] });
assert.equal(inventory.components.length, 1);
assert.equal(inventory.components[0].purl, "pkg:apk/alpine/openssl@3.0.0");
assert.equal(buildkitSpdxInventory(raw["linux/amd64"], { subjects: [{ key: "APP_IMAGE", image }], expectedPlatforms: ["linux/amd64"] }).components.length, 1);
assert.throws(() => buildkitSpdxInventory({}, { subjects: [{ key: "APP_IMAGE", image }], expectedPlatforms: ["linux/amd64"] }), /platform set/);
const empty = structuredClone(raw); empty["linux/amd64"].SPDX.packages = [];
assert.throws(() => buildkitSpdxInventory(empty, { subjects: [{ key: "APP_IMAGE", image }], expectedPlatforms: ["linux/amd64"] }), /no package inventory/);
const duplicate = structuredClone(raw); duplicate["linux/amd64"].SPDX.packages.push(structuredClone(duplicate["linux/amd64"].SPDX.packages[0]));
assert.throws(() => buildkitSpdxInventory(duplicate, { subjects: [{ key: "APP_IMAGE", image }], expectedPlatforms: ["linux/amd64"] }), /duplicated/);
const noVersion = structuredClone(raw); delete noVersion["linux/amd64"].SPDX.packages[0].versionInfo;
assert.equal(buildkitSpdxInventory(noVersion, { subjects: [{ key: "APP_IMAGE", image }], expectedPlatforms: ["linux/amd64"] }).components[0].version, "NOASSERTION");
const sameCountAltered = structuredClone(inventory.components); sameCountAltered[0].version = "attacker-version";
assert.throws(() => assertExactBuildkitComponentSet(inventory.components, sameCountAltered), /differ from/);
process.stdout.write("BuildKit SBOM policy tests passed 7/7\n");
