import crypto from "node:crypto";
import { canonicalReleaseSubjects } from "./release-artifact-policy.mjs";

function invalid(message) { throw new Error(message); }
function exactText(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value || /[\0\r\n]/.test(value)) invalid(`${label} is invalid.`);
  return value;
}
function digest(value) { return crypto.createHash("sha256").update(value).digest("hex"); }

function packagePurl(pkg) {
  const refs = Array.isArray(pkg.externalRefs) ? pkg.externalRefs : [];
  const purls = refs
    .filter((entry) => entry?.referenceType === "purl" && typeof entry.referenceLocator === "string" && /^pkg:\S+$/.test(entry.referenceLocator))
    .map((entry) => entry.referenceLocator);
  if (new Set(purls).size !== purls.length) invalid(`BuildKit SPDX package ${pkg.SPDXID} contains duplicate purl references.`);
  return [...purls].sort()[0] ?? null;
}

function packageHashes(pkg) {
  const checksums = Array.isArray(pkg.checksums) ? pkg.checksums : [];
  const hashes = checksums
    .filter((entry) => entry?.algorithm === "SHA256")
    .map((entry) => String(entry.checksumValue ?? "").toLowerCase());
  if (hashes.some((value) => !/^[a-f0-9]{64}$/.test(value))) invalid(`BuildKit SPDX package ${pkg.SPDXID} has an invalid SHA256 checksum.`);
  if (new Set(hashes).size !== hashes.length) invalid(`BuildKit SPDX package ${pkg.SPDXID} has duplicate SHA256 checksums.`);
  return hashes.map((content) => ({ alg: "SHA-256", content }));
}

export function buildkitSpdxInventory(raw, { subjects: rawSubjects, expectedPlatforms }) {
  const subjects = canonicalReleaseSubjects(rawSubjects);
  if (subjects.length !== 1) invalid("One BuildKit SBOM artifact must bind exactly one release image subject.");
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) invalid("BuildKit SBOM output must be an object keyed by platform.");
  if (!Array.isArray(expectedPlatforms) || expectedPlatforms.length === 0) invalid("BuildKit SBOM expected platforms are required.");
  const platforms = expectedPlatforms.map((value) => exactText(value, "BuildKit platform")).sort();
  if (new Set(platforms).size !== platforms.length || platforms.some((value) => !/^linux\/(amd64|arm64)$/.test(value))) {
    invalid("BuildKit SBOM platform set is invalid or duplicated.");
  }
  const byPlatform = Object.keys(raw).length === 1 && Object.hasOwn(raw, "SPDX") && platforms.length === 1
    ? { [platforms[0]]: raw }
    : raw;
  if (JSON.stringify(Object.keys(byPlatform).sort()) !== JSON.stringify(platforms)) invalid("BuildKit SBOM platform set differs from registry resolution.");
  const components = [];
  for (const platform of platforms) {
    const document = byPlatform[platform]?.SPDX;
    if (!document || typeof document !== "object" || Array.isArray(document)) invalid(`BuildKit SBOM ${platform} lacks an SPDX document.`);
    if (!/^SPDX-2\.[23]$/.test(String(document.spdxVersion ?? ""))
      || document.SPDXID !== "SPDXRef-DOCUMENT"
      || document.dataLicense !== "CC0-1.0"
      || !Number.isFinite(Date.parse(String(document.creationInfo?.created ?? "")))
      || typeof document.documentNamespace !== "string"
      || !/^https?:\/\/\S+$/.test(document.documentNamespace)) {
      invalid(`BuildKit SBOM ${platform} SPDX document identity is invalid.`);
    }
    if (!Array.isArray(document.packages) || document.packages.length === 0) invalid(`BuildKit SBOM ${platform} contains no package inventory.`);
    const spdxIds = document.packages.map((pkg) => exactText(pkg?.SPDXID, `BuildKit SPDX package ID for ${platform}`));
    if (spdxIds.some((value) => !/^SPDXRef-[A-Za-z0-9.-]+$/.test(value)) || new Set(spdxIds).size !== spdxIds.length) {
      invalid(`BuildKit SBOM ${platform} package IDs are invalid or duplicated.`);
    }
    for (const pkg of document.packages) {
      const name = exactText(pkg.name, `BuildKit SPDX package ${pkg.SPDXID} name`);
      const version = pkg.versionInfo === undefined || pkg.versionInfo === null || pkg.versionInfo === ""
        ? "NOASSERTION"
        : exactText(pkg.versionInfo, `BuildKit SPDX package ${pkg.SPDXID} version`);
      const component = {
        type: "library",
        "bom-ref": `urn:buildkit-spdx:${digest(`${subjects[0].image}\u0000${platform}\u0000${pkg.SPDXID}`)}`,
        name,
        version,
        properties: [
          { name: "sbom.source", value: "buildkit-attestation-spdx" },
          { name: "buildkit.platform", value: platform },
          { name: "buildkit.spdxId", value: pkg.SPDXID },
          { name: "releaseSubjectImage", value: subjects[0].image },
        ],
      };
      const purl = packagePurl(pkg);
      if (purl) component.purl = purl;
      const hashes = packageHashes(pkg);
      if (hashes.length) component.hashes = hashes;
      components.push(component);
    }
  }
  if (new Set(components.map((component) => component["bom-ref"])).size !== components.length) invalid("BuildKit package component references are not unique.");
  return { subjects, platforms, components };
}

export function buildkitSbomSha256(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) invalid("BuildKit SBOM bytes are required.");
  return digest(bytes);
}

export function canonicalBuildkitComponentSet(components) {
  if (!Array.isArray(components)) invalid("BuildKit component set must be an array.");
  return components.map((component) => ({
    type: component.type,
    "bom-ref": component["bom-ref"],
    name: component.name,
    version: component.version,
    purl: component.purl ?? null,
    hashes: Array.isArray(component.hashes)
      ? component.hashes.map(({ alg, content }) => ({ alg, content })).sort((left, right) => `${left.alg}:${left.content}`.localeCompare(`${right.alg}:${right.content}`))
      : [],
    properties: Array.isArray(component.properties)
      ? component.properties.map(({ name, value }) => ({ name, value })).sort((left, right) => left.name.localeCompare(right.name))
      : [],
  })).sort((left, right) => left["bom-ref"].localeCompare(right["bom-ref"]));
}

export function assertExactBuildkitComponentSet(expected, actual) {
  if (JSON.stringify(canonicalBuildkitComponentSet(expected)) !== JSON.stringify(canonicalBuildkitComponentSet(actual))) {
    invalid("CycloneDX dependency components differ from the raw BuildKit SPDX inventory.");
  }
}
