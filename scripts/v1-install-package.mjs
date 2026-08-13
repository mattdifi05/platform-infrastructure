#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const FORMAT = "RAW-CONCATENATED-MEMBERS/V1";
export const MANIFEST_SCHEMA = "platform.v1-install-package-manifest/v1";

export const MEMBER_SPECS = Object.freeze([
  Object.freeze({
    destination: "/usr/local/libexec/platform-activation-broker",
    packageMember: "bin/platform-activation-broker",
    kind: "EXECUTABLE",
    mode: "0555",
  }),
  Object.freeze({
    destination: "/usr/local/libexec/platform-v1-brownfield-admission",
    packageMember: "bin/platform-v1-brownfield-admission",
    kind: "EXECUTABLE",
    mode: "0555",
  }),
  Object.freeze({
    destination: "/usr/local/libexec/platform-hosted-preparation-broker",
    packageMember: "bin/platform-hosted-preparation-broker",
    kind: "EXECUTABLE",
    mode: "0555",
  }),
  Object.freeze({
    destination: "/usr/local/libexec/platform-origin-firewall",
    packageMember: "bin/platform-origin-firewall",
    kind: "EXECUTABLE",
    mode: "0555",
  }),
  Object.freeze({
    destination: "/usr/local/libexec/platform-workload-egress-firewall",
    packageMember: "bin/platform-workload-egress-firewall",
    kind: "EXECUTABLE",
    mode: "0555",
  }),
  Object.freeze({
    destination: "/etc/sudoers.d/platform-activation-broker",
    packageMember: "etc/sudoers.d/platform-activation-broker",
    kind: "SUDOERS",
    mode: "0440",
  }),
]);

const VERIFICATION_SCHEMA = "platform.v1-install-package-verification/v1";
const PACKAGE_MIN_BYTES = MEMBER_SPECS.length;
const PACKAGE_MAX_BYTES = 4 * 1024 * 1024;
const MANIFEST_MIN_BYTES = 2;
const MANIFEST_MAX_BYTES = 4 * 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const FORBIDDEN_INPUT_FIELD =
  /(?:authority|authoriz|privatekey|secretkey|sign|mint|write|network|process)/;

function invalid(message) {
  throw new Error(message);
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      invalid("Canonical JSON accepts only plain JSON objects.");
    }
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, stable(value[key])]),
    );
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) return value;
  invalid("Canonical JSON contains an unsupported value.");
}

export function canonicalJson(value) {
  return JSON.stringify(stable(value));
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function shaBytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function shaCanonical(value) {
  return shaBytes(Buffer.from(canonicalJson(value), "utf8"));
}

function exactObject(value, label, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    invalid(`${label} must be one plain JSON object.`);
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    invalid(`${label} must be one plain JSON object.`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) invalid(`${label} does not use the exact closed schema.`);
  return value;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    invalid(`${label} must be one lowercase SHA256.`);
  }
  return value;
}

function exactSafeInteger(value, label, minimum, maximum) {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) invalid(`${label} must be one safe integer from ${minimum} through ${maximum}.`);
  return value;
}

function exactInputPath(value, label) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 4096 ||
    value.includes("\0") ||
    !path.isAbsolute(value)
  ) invalid(`${label} must be one explicit absolute filesystem path.`);
  return value;
}

function rejectForbiddenInputFields(value, location = "manifest") {
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      rejectForbiddenInputFields(entry, `${location}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (FORBIDDEN_INPUT_FIELD.test(normalized)) {
      invalid(`${location}.${key} is a forbidden input field.`);
    }
    rejectForbiddenInputFields(child, `${location}.${key}`);
  }
}

function openReadOnlyNoFollow(filePath, label) {
  if (
    !Number.isInteger(fs.constants.O_NOFOLLOW) ||
    fs.constants.O_NOFOLLOW === 0
  ) invalid(`${label} cannot be opened because O_NOFOLLOW is unavailable.`);
  if (
    !Number.isInteger(fs.constants.O_NONBLOCK) ||
    fs.constants.O_NONBLOCK === 0
  ) invalid(`${label} cannot be opened because O_NONBLOCK is unavailable.`);
  const closeOnExec = Number.isInteger(fs.constants.O_CLOEXEC)
    ? fs.constants.O_CLOEXEC
    : 0;
  const flags =
    fs.constants.O_RDONLY |
    fs.constants.O_NOFOLLOW |
    fs.constants.O_NONBLOCK |
    closeOnExec;
  try {
    return fs.openSync(filePath, flags);
  } catch (error) {
    invalid(`${label} could not be opened read-only through O_NOFOLLOW: ${error.code ?? "OPEN_FAILED"}.`);
  }
}

function fdIdentity(fd, label, minimumBytes, maximumBytes) {
  let stat;
  try {
    stat = fs.fstatSync(fd, { bigint: true });
  } catch (error) {
    invalid(`${label} descriptor could not be inspected: ${error.code ?? "FSTAT_FAILED"}.`);
  }
  const typeMask = BigInt(fs.constants.S_IFMT);
  const regularType = BigInt(fs.constants.S_IFREG);
  if ((stat.mode & typeMask) !== regularType) {
    invalid(`${label} must be a regular file.`);
  }
  if (stat.nlink !== 1n) invalid(`${label} link count must be exactly one; the file must be singly linked.`);
  const minimum = BigInt(minimumBytes);
  const maximum = BigInt(maximumBytes);
  if (stat.size < minimum || stat.size > maximum) {
    invalid(`${label} size must be from ${minimumBytes} through ${maximumBytes} bytes.`);
  }
  return Object.freeze({
    ctimeNs: String(stat.ctimeNs),
    device: String(stat.dev),
    gid: String(stat.gid),
    inode: String(stat.ino),
    mode: String(stat.mode),
    mtimeNs: String(stat.mtimeNs),
    nlink: String(stat.nlink),
    sizeBytes: Number(stat.size),
    uid: String(stat.uid),
  });
}

function sameIdentity(left, right) {
  const keys = Object.keys(left);
  return (
    keys.length === Object.keys(right).length &&
    keys.every((key) => left[key] === right[key])
  );
}

function preadExact(fd, offset, sizeBytes, label) {
  const bytes = Buffer.allocUnsafe(sizeBytes);
  let consumed = 0;
  while (consumed < sizeBytes) {
    let count;
    try {
      count = fs.readSync(
        fd,
        bytes,
        consumed,
        sizeBytes - consumed,
        offset + consumed,
      );
    } catch (error) {
      invalid(`${label} exact positional read failed: ${error.code ?? "PREAD_FAILED"}.`);
    }
    if (count === 0) invalid(`${label} was truncated during its exact positional read.`);
    consumed += count;
  }
  return bytes;
}

function parseCanonicalManifest(bytes) {
  let text;
  try {
    text = utf8Decoder.decode(bytes);
  } catch {
    invalid("Package manifest is not strict UTF-8 canonical JSON.");
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    invalid("Package manifest is not valid canonical JSON.");
  }
  if (canonicalJson(value) !== text) {
    invalid("Package manifest bytes are not the exact canonical JSON encoding.");
  }
  rejectForbiddenInputFields(value);
  return value;
}

function validateManifestShape(value, packageIdentity, packageSha256) {
  exactObject(value, "Package manifest", [
    "format",
    "members",
    "packageSha256",
    "packageSizeBytes",
    "schema",
  ]);
  if (value.schema !== MANIFEST_SCHEMA) invalid("Package manifest schema is not the fixed V1 schema.");
  if (value.format !== FORMAT) invalid("Package format is not RAW-CONCATENATED-MEMBERS/V1.");
  exactSha256(value.packageSha256, "Manifest package SHA256");
  if (value.packageSha256 !== packageSha256) {
    invalid("Manifest package SHA256 does not match the snapshotted package bytes.");
  }
  exactSafeInteger(
    value.packageSizeBytes,
    "Manifest package size",
    PACKAGE_MIN_BYTES,
    PACKAGE_MAX_BYTES,
  );
  if (value.packageSizeBytes !== packageIdentity.sizeBytes) {
    invalid("Manifest package size does not match the snapshotted package size.");
  }
  if (!Array.isArray(value.members) || value.members.length !== MEMBER_SPECS.length) {
    invalid("Package manifest must contain exactly six members.");
  }

  let expectedOffset = 0;
  for (let index = 0; index < MEMBER_SPECS.length; index += 1) {
    const member = value.members[index];
    const spec = MEMBER_SPECS[index];
    exactObject(member, `Package member ${index}`, [
      "destination",
      "gid",
      "index",
      "kind",
      "mode",
      "nlink",
      "offset",
      "packageMember",
      "sha256",
      "sizeBytes",
      "uid",
      "version",
    ]);
    if (
      member.destination !== spec.destination ||
      member.packageMember !== spec.packageMember ||
      member.index !== index ||
      member.kind !== spec.kind ||
      member.uid !== 0 ||
      member.gid !== 0 ||
      member.mode !== spec.mode ||
      member.nlink !== 1 ||
      member.version !== 1
    ) invalid(`Package member ${index} does not match its exact fixed identity and metadata.`);
    exactSafeInteger(member.offset, `Package member ${index} offset`, 0, PACKAGE_MAX_BYTES - 1);
    exactSafeInteger(member.sizeBytes, `Package member ${index} size`, 1, PACKAGE_MAX_BYTES);
    exactSha256(member.sha256, `Package member ${index} SHA256`);
    if (member.offset !== expectedOffset) {
      invalid(`Package member ${index} offset is not contiguous; gaps and overlap are forbidden.`);
    }
    const end = member.offset + member.sizeBytes;
    if (!Number.isSafeInteger(end) || end > PACKAGE_MAX_BYTES) {
      invalid(`Package member ${index} range exceeds the safe package boundary.`);
    }
    expectedOffset = end;
  }
  if (expectedOffset !== value.packageSizeBytes) {
    invalid("The final member end does not equal package size; trailing or unclaimed bytes are forbidden.");
  }
  return value;
}

function verifyMemberRanges(packageFd, packageBytes, members) {
  for (let index = 0; index < members.length; index += 1) {
    const member = members[index];
    const range = preadExact(
      packageFd,
      member.offset,
      member.sizeBytes,
      `Package member ${index}`,
    );
    const snapshotRange = packageBytes.subarray(
      member.offset,
      member.offset + member.sizeBytes,
    );
    if (!range.equals(snapshotRange)) {
      invalid(`Package member ${index} changed between exact positional reads.`);
    }
    if (shaBytes(range) !== member.sha256) {
      invalid(`Package member ${index} SHA256 does not match its exact byte range.`);
    }
  }
}

export function verifyV1InstallPackage(options) {
  rejectForbiddenInputFields(options, "options");
  exactObject(options, "Verification options", [
    "expectedManifestSha256",
    "expectedPackageSha256",
    "manifestPath",
    "packagePath",
  ]);
  const packagePath = exactInputPath(options.packagePath, "Package path");
  const manifestPath = exactInputPath(options.manifestPath, "Manifest path");
  const expectedPackageSha256 = exactSha256(
    options.expectedPackageSha256,
    "Expected caller-bound package SHA256",
  );
  const expectedManifestSha256 = exactSha256(
    options.expectedManifestSha256,
    "Expected caller-bound manifest SHA256",
  );

  let packageFd;
  let manifestFd;
  try {
    packageFd = openReadOnlyNoFollow(packagePath, "Package file");
    manifestFd = openReadOnlyNoFollow(manifestPath, "Manifest file");

    const packageBefore = fdIdentity(
      packageFd,
      "Package file",
      PACKAGE_MIN_BYTES,
      PACKAGE_MAX_BYTES,
    );
    const manifestBefore = fdIdentity(
      manifestFd,
      "Manifest file",
      MANIFEST_MIN_BYTES,
      MANIFEST_MAX_BYTES,
    );
    if (
      packageBefore.device === manifestBefore.device &&
      packageBefore.inode === manifestBefore.inode
    ) invalid("Package and manifest descriptors must identify distinct files.");
    const manifestBytes = preadExact(
      manifestFd,
      0,
      manifestBefore.sizeBytes,
      "Manifest file",
    );
    const packageBytes = preadExact(
      packageFd,
      0,
      packageBefore.sizeBytes,
      "Package file",
    );

    const manifestSha256 = shaBytes(manifestBytes);
    const packageSha256 = shaBytes(packageBytes);
    if (manifestSha256 !== expectedManifestSha256) {
      invalid("Manifest bytes do not match the caller-bound manifest SHA256.");
    }
    if (packageSha256 !== expectedPackageSha256) {
      invalid("Package bytes do not match the caller-bound package SHA256.");
    }

    const manifest = validateManifestShape(
      parseCanonicalManifest(manifestBytes),
      packageBefore,
      packageSha256,
    );
    verifyMemberRanges(packageFd, packageBytes, manifest.members);

    const packageAfter = fdIdentity(
      packageFd,
      "Package file",
      PACKAGE_MIN_BYTES,
      PACKAGE_MAX_BYTES,
    );
    const manifestAfter = fdIdentity(
      manifestFd,
      "Manifest file",
      MANIFEST_MIN_BYTES,
      MANIFEST_MAX_BYTES,
    );
    if (!sameIdentity(packageBefore, packageAfter)) {
      invalid("Package file changed while being snapshotted; stable identity is required.");
    }
    if (!sameIdentity(manifestBefore, manifestAfter)) {
      invalid("Manifest file changed while being snapshotted; stable identity is required.");
    }

    return deepFreeze({
      applicationDataMutationAuthority: false,
      databaseMutationAuthority: false,
      deployAuthority: false,
      format: FORMAT,
      installAuthority: false,
      manifestSnapshotIdentitySha256: shaCanonical(manifestBefore),
      materializationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
      memberCount: MEMBER_SPECS.length,
      membersSha256: shaCanonical(manifest.members),
      mutationAuthority: false,
      networkAuthority: false,
      packageManifestSha256: manifestSha256,
      packageManifestSizeBytes: manifestBefore.sizeBytes,
      packageSha256,
      packageSizeBytes: packageBefore.sizeBytes,
      packageSnapshotIdentitySha256: shaCanonical(packageBefore),
      processAuthority: false,
      schema: VERIFICATION_SCHEMA,
      status: "FORMAT-VERIFIED-NON-AUTHORITATIVE",
      writeAuthority: false,
    });
  } finally {
    if (manifestFd !== undefined) fs.closeSync(manifestFd);
    if (packageFd !== undefined) fs.closeSync(packageFd);
  }
}

function parseCli(argv) {
  const names = new Map([
    ["--package", "packagePath"],
    ["--manifest", "manifestPath"],
    ["--expected-package-sha256", "expectedPackageSha256"],
    ["--expected-manifest-sha256", "expectedManifestSha256"],
  ]);
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index];
    if (!names.has(option)) invalid(`Unknown option: ${String(option)}.`);
    if (index + 1 >= argv.length) invalid(`Option ${option} requires one explicit value.`);
    const key = names.get(option);
    if (Object.hasOwn(options, key)) invalid(`Option ${option} may be supplied only once.`);
    options[key] = argv[index + 1];
  }
  if (Object.keys(options).length !== names.size) {
    invalid(
      "All four inputs are required: --package, --manifest, --expected-package-sha256, and --expected-manifest-sha256.",
    );
  }
  return options;
}

function isMain() {
  return (
    typeof process.argv[1] === "string" &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
  );
}

if (isMain()) {
  try {
    const result = verifyV1InstallPackage(parseCli(process.argv.slice(2)));
    process.stdout.write(`${canonicalJson(result)}\n`);
    process.exitCode = 78;
  } catch (error) {
    process.stderr.write(`v1-install-package: ${error.message}\n`);
    process.exitCode = 64;
  }
}
