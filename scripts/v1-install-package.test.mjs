import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  FORMAT,
  MANIFEST_SCHEMA,
  MEMBER_SPECS,
  canonicalJson,
  verifyV1InstallPackage,
} from "./v1-install-package.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.dirname(HERE);
const MODULE = path.join(HERE, "v1-install-package.mjs");
const SCHEMA = path.join(
  REPO,
  "governance",
  "schemas",
  "v1-install-package-manifest.schema.json",
);
const COMMON_SCHEMA = path.join(
  REPO,
  "governance",
  "schemas",
  "v1-brownfield-common-tuple.schema.json",
);
const CORE_VERIFIER = path.join(HERE, "v1-brownfield-admission.mjs");
const require = createRequire(path.join(REPO, "vendor", "json-schema", "package.json"));
const Ajv2020 = require("ajv/dist/2020");
const addFormats = require("ajv-formats");

const EXPECTED_SPECS = Object.freeze([
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

function h(value) {
  return crypto
    .createHash("sha256")
    .update(Buffer.isBuffer(value) ? value : String(value))
    .digest("hex");
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, stable(value[key])]),
    );
  }
  return value;
}

function expectedCanonicalJson(value) {
  return JSON.stringify(stable(value));
}

function buildFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-install-package-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const payloads = EXPECTED_SPECS.map((spec, index) =>
    Buffer.from(
      spec.kind === "SUDOERS"
        ? "platform-activation-broker ALL=(root) NOPASSWD: /usr/local/libexec/platform-activation-broker activate\n"
        : `#!/bin/sh\n# package member ${index}\nexit 78\n`,
      "utf8",
    ),
  );
  const packageBytes = Buffer.concat(payloads);
  let offset = 0;
  const members = payloads.map((bytes, index) => {
    const spec = EXPECTED_SPECS[index];
    const member = {
      destination: spec.destination,
      gid: 0,
      index,
      kind: spec.kind,
      mode: spec.mode,
      nlink: 1,
      offset,
      packageMember: spec.packageMember,
      sha256: h(bytes),
      sizeBytes: bytes.length,
      uid: 0,
      version: 1,
    };
    offset += bytes.length;
    return member;
  });
  const manifest = {
    format: "RAW-CONCATENATED-MEMBERS/V1",
    members,
    packageSha256: h(packageBytes),
    packageSizeBytes: packageBytes.length,
    schema: "platform.v1-install-package-manifest/v1",
  };
  const packagePath = path.join(root, "package.raw");
  const manifestPath = path.join(root, "manifest.json");
  fs.writeFileSync(packagePath, packageBytes, { mode: 0o400 });
  const manifestBytes = Buffer.from(expectedCanonicalJson(manifest), "utf8");
  fs.writeFileSync(manifestPath, manifestBytes, { mode: 0o400 });
  return {
    root,
    packagePath,
    manifestPath,
    packageBytes,
    manifest,
    expectedPackageSha256: h(packageBytes),
    expectedManifestSha256: h(manifestBytes),
  };
}

function writeManifest(fixture) {
  const bytes = Buffer.from(expectedCanonicalJson(fixture.manifest), "utf8");
  fs.chmodSync(fixture.manifestPath, 0o600);
  fs.writeFileSync(fixture.manifestPath, bytes, { mode: 0o400 });
  fs.chmodSync(fixture.manifestPath, 0o400);
  fixture.expectedManifestSha256 = h(bytes);
}

function verify(fixture, overrides = {}) {
  return verifyV1InstallPackage({
    packagePath: fixture.packagePath,
    manifestPath: fixture.manifestPath,
    expectedPackageSha256: fixture.expectedPackageSha256,
    expectedManifestSha256: fixture.expectedManifestSha256,
    ...overrides,
  });
}

test("valid raw package is format-verified but grants no authority", (t) => {
  const fixture = buildFixture(t);
  const result = verify(fixture);

  assert.deepEqual(Object.keys(result).sort(), [
    "applicationDataMutationAuthority",
    "databaseMutationAuthority",
    "deployAuthority",
    "format",
    "installAuthority",
    "manifestSnapshotIdentitySha256",
    "materializationStatus",
    "memberCount",
    "membersSha256",
    "mutationAuthority",
    "networkAuthority",
    "packageManifestSha256",
    "packageManifestSizeBytes",
    "packageSha256",
    "packageSizeBytes",
    "packageSnapshotIdentitySha256",
    "processAuthority",
    "schema",
    "status",
    "writeAuthority",
  ].sort());
  assert.equal(result.schema, "platform.v1-install-package-verification/v1");
  assert.equal(result.status, "FORMAT-VERIFIED-NON-AUTHORITATIVE");
  assert.equal(result.format, "RAW-CONCATENATED-MEMBERS/V1");
  assert.equal(result.packageSha256, fixture.expectedPackageSha256);
  assert.equal(result.packageManifestSha256, fixture.expectedManifestSha256);
  assert.equal(result.packageSizeBytes, fixture.packageBytes.length);
  assert.equal(result.memberCount, 6);
  assert.match(result.membersSha256, /^[a-f0-9]{64}$/);
  assert.match(result.packageSnapshotIdentitySha256, /^[a-f0-9]{64}$/);
  assert.match(result.manifestSnapshotIdentitySha256, /^[a-f0-9]{64}$/);
  for (const key of [
    "applicationDataMutationAuthority",
    "databaseMutationAuthority",
    "deployAuthority",
    "installAuthority",
    "mutationAuthority",
    "networkAuthority",
    "processAuthority",
    "writeAuthority",
  ]) assert.equal(result[key], false, `${key} must remain false`);
  assert.equal(result.materializationStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert(Object.isFrozen(result));
});

test("runtime constants are immutable and exactly match the six-member contract", () => {
  assert.equal(FORMAT, "RAW-CONCATENATED-MEMBERS/V1");
  assert.equal(MANIFEST_SCHEMA, "platform.v1-install-package-manifest/v1");
  assert.deepEqual(MEMBER_SPECS, EXPECTED_SPECS);
  assert(Object.isFrozen(MEMBER_SPECS));
  for (const spec of MEMBER_SPECS) assert(Object.isFrozen(spec));
});

test("canonical JSON rejects whitespace, reordered encoding, duplicate keys, and trailing newline", (t) => {
  for (const mutate of [
    (fixture) => ` ${expectedCanonicalJson(fixture.manifest)}`,
    (fixture) => `\uFEFF${expectedCanonicalJson(fixture.manifest)}`,
    (fixture) => JSON.stringify({
      schema: fixture.manifest.schema,
      packageSizeBytes: fixture.manifest.packageSizeBytes,
      packageSha256: fixture.manifest.packageSha256,
      members: fixture.manifest.members,
      format: fixture.manifest.format,
    }),
    (fixture) => expectedCanonicalJson(fixture.manifest) + "\n",
    (fixture) => {
      const encoded = expectedCanonicalJson(fixture.manifest);
      return encoded.replace(
        '"format":"RAW-CONCATENATED-MEMBERS/V1"',
        '"format":"RAW-CONCATENATED-MEMBERS/V1","format":"RAW-CONCATENATED-MEMBERS/V1"',
      );
    },
  ]) {
    const fixture = buildFixture(t);
    const bytes = Buffer.from(mutate(fixture), "utf8");
    fs.chmodSync(fixture.manifestPath, 0o600);
    fs.writeFileSync(fixture.manifestPath, bytes);
    fixture.expectedManifestSha256 = h(bytes);
    assert.throws(() => verify(fixture), /canonical JSON/i);
  }
});

test("manifest and every member are exact closed objects", (t) => {
  const top = buildFixture(t);
  top.manifest.comment = "not authorized";
  writeManifest(top);
  assert.throws(() => verify(top), /closed schema/i);

  const nested = buildFixture(t);
  nested.manifest.members[0].comment = "not authorized";
  writeManifest(nested);
  assert.throws(() => verify(nested), /closed schema/i);
});

test("authority, private-key, signing, mint, write, network, and process fields are toxic", (t) => {
  for (const field of [
    "authority",
    "installAuthorization",
    "privateKey",
    "signingKey",
    "signature",
    "mintReceipt",
    "writeFiles",
    "networkAccess",
    "processCommand",
  ]) {
    const fixture = buildFixture(t);
    fixture.manifest[field] = false;
    writeManifest(fixture);
    assert.throws(() => verify(fixture), /forbidden input field/i, field);
  }

  const nested = buildFixture(t);
  nested.manifest.members[2].signature = "00";
  writeManifest(nested);
  assert.throws(() => verify(nested), /forbidden input field/i);
});

test("the member sequence fixes destination, package member, index, kind, metadata, and version", (t) => {
  const mutations = [
    ["destination", "/tmp/broker"],
    ["packageMember", "bin/other"],
    ["index", 1],
    ["kind", "DATA"],
    ["uid", 1000],
    ["gid", 1000],
    ["mode", "0755"],
    ["nlink", 2],
    ["version", 2],
  ];
  for (const [field, value] of mutations) {
    const fixture = buildFixture(t);
    fixture.manifest.members[0][field] = value;
    writeManifest(fixture);
    assert.throws(() => verify(fixture), /member 0|fixed|exact/i, field);
  }

  const sudoers = buildFixture(t);
  sudoers.manifest.members[5].kind = "EXECUTABLE";
  writeManifest(sudoers);
  assert.throws(() => verify(sudoers), /member 5|fixed|exact/i);
});

test("exactly six members are required in the fixed order", (t) => {
  const missing = buildFixture(t);
  missing.manifest.members.pop();
  writeManifest(missing);
  assert.throws(() => verify(missing), /exactly six/i);

  const extra = buildFixture(t);
  extra.manifest.members.push(structuredClone(extra.manifest.members[5]));
  writeManifest(extra);
  assert.throws(() => verify(extra), /exactly six/i);

  const swapped = buildFixture(t);
  [swapped.manifest.members[0], swapped.manifest.members[1]] =
    [swapped.manifest.members[1], swapped.manifest.members[0]];
  writeManifest(swapped);
  assert.throws(() => verify(swapped), /member 0|fixed|index/i);
});

test("member ranges start at zero and reject gaps, overlap, zero size, and unsafe integers", (t) => {
  for (const [index, field, value, expression] of [
    [0, "offset", 1, /first member|offset|contiguous/i],
    [1, "offset", 999, /gap|contiguous|offset/i],
    [1, "offset", 0, /overlap|contiguous|offset/i],
    [0, "sizeBytes", 0, /size/i],
    [0, "offset", Number.MAX_SAFE_INTEGER + 1, /safe integer|offset/i],
    [0, "sizeBytes", Number.MAX_SAFE_INTEGER + 1, /safe integer|size/i],
  ]) {
    const fixture = buildFixture(t);
    fixture.manifest.members[index][field] = value;
    writeManifest(fixture);
    assert.throws(() => verify(fixture), expression);
  }
});

test("final member end must equal package size with no trailing or unclaimed bytes", (t) => {
  const shortMap = buildFixture(t);
  shortMap.manifest.members[5].sizeBytes -= 1;
  writeManifest(shortMap);
  assert.throws(() => verify(shortMap), /trailing|final|package size/i);

  const wrongDeclaredSize = buildFixture(t);
  wrongDeclaredSize.manifest.packageSizeBytes += 1;
  writeManifest(wrongDeclaredSize);
  assert.throws(() => verify(wrongDeclaredSize), /package size/i);

  const trailingFile = buildFixture(t);
  fs.chmodSync(trailingFile.packagePath, 0o600);
  fs.appendFileSync(trailingFile.packagePath, "x");
  const bytes = fs.readFileSync(trailingFile.packagePath);
  trailingFile.expectedPackageSha256 = h(bytes);
  trailingFile.manifest.packageSha256 = trailingFile.expectedPackageSha256;
  trailingFile.manifest.packageSizeBytes = bytes.length;
  writeManifest(trailingFile);
  assert.throws(() => verify(trailingFile), /trailing|final|package size/i);
});

test("caller bindings independently pin package and manifest SHA256", (t) => {
  const fixture = buildFixture(t);
  assert.throws(
    () => verify(fixture, { expectedPackageSha256: h("substituted package") }),
    /caller-bound package SHA256/i,
  );
  assert.throws(
    () => verify(fixture, { expectedManifestSha256: h("substituted manifest") }),
    /caller-bound manifest SHA256/i,
  );
  assert.throws(
    () => verify(fixture, { expectedPackageSha256: "A".repeat(64) }),
    /lowercase SHA256/i,
  );
});

test("manifest package binding and exact per-range hashes are recomputed", (t) => {
  const internal = buildFixture(t);
  internal.manifest.packageSha256 = h("not the package");
  writeManifest(internal);
  assert.throws(() => verify(internal), /manifest package SHA256/i);

  const member = buildFixture(t);
  member.manifest.members[3].sha256 = h("not member 3");
  writeManifest(member);
  assert.throws(() => verify(member), /member 3 SHA256/i);

  const changedBytes = buildFixture(t);
  const packageBytes = Buffer.from(changedBytes.packageBytes);
  packageBytes[changedBytes.manifest.members[2].offset] ^= 1;
  fs.chmodSync(changedBytes.packagePath, 0o600);
  fs.writeFileSync(changedBytes.packagePath, packageBytes);
  changedBytes.expectedPackageSha256 = h(packageBytes);
  changedBytes.manifest.packageSha256 = changedBytes.expectedPackageSha256;
  writeManifest(changedBytes);
  assert.throws(() => verify(changedBytes), /member 2 SHA256/i);
});

test("package and manifest must be regular singly-linked non-symlink files", (t) => {
  const packageLink = buildFixture(t);
  const packageSymlink = path.join(packageLink.root, "package-link");
  fs.symlinkSync(packageLink.packagePath, packageSymlink);
  assert.throws(
    () => verify(packageLink, { packagePath: packageSymlink }),
    /O_NOFOLLOW|symbolic link|open package/i,
  );

  const manifestLink = buildFixture(t);
  const manifestSymlink = path.join(manifestLink.root, "manifest-link");
  fs.symlinkSync(manifestLink.manifestPath, manifestSymlink);
  assert.throws(
    () => verify(manifestLink, { manifestPath: manifestSymlink }),
    /O_NOFOLLOW|symbolic link|open manifest/i,
  );

  const hardlinked = buildFixture(t);
  fs.linkSync(hardlinked.packagePath, path.join(hardlinked.root, "package-hardlink"));
  assert.throws(() => verify(hardlinked), /package.*link count|singly linked/i);

  const directory = buildFixture(t);
  assert.throws(
    () => verify(directory, { manifestPath: directory.root }),
    /manifest.*regular file/i,
  );
});

test("package and manifest descriptors must identify distinct files", (t) => {
  const fixture = buildFixture(t);
  assert.throws(
    () => verify(fixture, {
      manifestPath: fixture.packagePath,
      expectedManifestSha256: fixture.expectedPackageSha256,
    }),
    /package and manifest.*distinct/i,
  );
});

test("FIFO inputs fail as non-regular without blocking before fstat", (t) => {
  const fixture = buildFixture(t);
  const cli = (packagePath, manifestPath) => spawnSync(process.execPath, [
    MODULE,
    "--package", packagePath,
    "--manifest", manifestPath,
    "--expected-package-sha256", fixture.expectedPackageSha256,
    "--expected-manifest-sha256", fixture.expectedManifestSha256,
  ], { encoding: "utf8", timeout: 500 });

  const packageFifo = path.join(fixture.root, "package.fifo");
  assert.equal(spawnSync("/usr/bin/mkfifo", [packageFifo]).status, 0);
  const packageResult = cli(packageFifo, fixture.manifestPath);
  assert.notEqual(packageResult.error?.code, "ETIMEDOUT", "package FIFO blocked before fstat");
  assert.equal(packageResult.status, 64, packageResult.stderr);
  assert.match(packageResult.stderr, /package.*regular file/i);

  const manifestFifo = path.join(fixture.root, "manifest.fifo");
  assert.equal(spawnSync("/usr/bin/mkfifo", [manifestFifo]).status, 0);
  const manifestResult = cli(fixture.packagePath, manifestFifo);
  assert.notEqual(manifestResult.error?.code, "ETIMEDOUT", "manifest FIFO blocked before fstat");
  assert.equal(manifestResult.status, 64, manifestResult.stderr);
  assert.match(manifestResult.stderr, /manifest.*regular file/i);
});

test("strict file-size bounds reject empty and oversized inputs before parsing", (t) => {
  const emptyManifest = buildFixture(t);
  fs.chmodSync(emptyManifest.manifestPath, 0o600);
  fs.truncateSync(emptyManifest.manifestPath, 0);
  emptyManifest.expectedManifestSha256 = h(Buffer.alloc(0));
  assert.throws(() => verify(emptyManifest), /manifest.*size/i);

  const emptyPackage = buildFixture(t);
  fs.chmodSync(emptyPackage.packagePath, 0o600);
  fs.truncateSync(emptyPackage.packagePath, 0);
  emptyPackage.expectedPackageSha256 = h(Buffer.alloc(0));
  assert.throws(() => verify(emptyPackage), /package.*size/i);

  const oversizedManifest = buildFixture(t);
  fs.chmodSync(oversizedManifest.manifestPath, 0o600);
  fs.truncateSync(oversizedManifest.manifestPath, 4 * 1024 * 1024 + 1);
  assert.throws(() => verify(oversizedManifest), /manifest.*size/i);

  const oversizedPackage = buildFixture(t);
  fs.chmodSync(oversizedPackage.packagePath, 0o600);
  fs.truncateSync(oversizedPackage.packagePath, 4 * 1024 * 1024 + 1);
  assert.throws(() => verify(oversizedPackage), /package.*size/i);
});

test("FD identity must remain stable across exact positional reads", (t) => {
  const fixture = buildFixture(t);
  const originalReadSync = fs.readSync;
  let mutated = false;
  fs.readSync = function (...args) {
    const count = originalReadSync.apply(this, args);
    if (!mutated) {
      mutated = true;
      fs.chmodSync(fixture.packagePath, 0o600);
      fs.appendFileSync(fixture.packagePath, "race");
    }
    return count;
  };
  try {
    assert.throws(() => verify(fixture), /changed while being snapshotted|stable identity/i);
  } finally {
    fs.readSync = originalReadSync;
  }
});

test("schema mirrors the runtime closed six-member contract", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA, "utf8"));
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(schema.required.sort(), [
    "format",
    "members",
    "packageSha256",
    "packageSizeBytes",
    "schema",
  ].sort());
  assert.equal(schema.properties.schema.const, MANIFEST_SCHEMA);
  assert.equal(schema.properties.format.const, FORMAT);
  assert.equal(schema.properties.members.minItems, 6);
  assert.equal(schema.properties.members.maxItems, 6);
  assert.equal(schema.properties.members.items, false);
  assert.equal(schema.properties.members.prefixItems.length, 6);
  assert.equal(schema.$defs.member.additionalProperties, false);
  assert.deepEqual(schema.$defs.member.required.sort(), [
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
  ].sort());
  const schemaSpecs = schema.properties.members.prefixItems.map((entry) => {
    const properties = entry.allOf[1].properties;
    return {
      destination: properties.destination.const,
      packageMember: properties.packageMember.const,
      kind: properties.kind.const,
      mode: properties.mode.const,
    };
  });
  assert.deepEqual(schemaSpecs, EXPECTED_SPECS);
});

test("strict Ajv2020 compiles the schema and enforces real positive and negative manifests", (t) => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA, "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: true, validateFormats: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  const fixture = buildFixture(t);
  assert.equal(validate(fixture.manifest), true, ajv.errorsText(validate.errors));

  const missing = structuredClone(fixture.manifest);
  delete missing.packageSha256;
  assert.equal(validate(missing), false, "schema accepted a missing required field");

  const extra = structuredClone(fixture.manifest);
  extra.installAuthority = false;
  assert.equal(validate(extra), false, "schema accepted an authority field");

  const wrongFixedField = structuredClone(fixture.manifest);
  wrongFixedField.members[3].destination = "/usr/local/libexec/other";
  assert.equal(validate(wrongFixedField), false, "schema accepted a wrong fixed member destination");

  const seventh = structuredClone(fixture.manifest);
  seventh.members.push(structuredClone(seventh.members[5]));
  assert.equal(validate(seventh), false, "schema accepted a seventh package member");
});

test("package bounds cannot widen the frozen core verifier accept-set", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA, "utf8"));
  const common = JSON.parse(fs.readFileSync(COMMON_SCHEMA, "utf8"));
  const coreSource = fs.readFileSync(CORE_VERIFIER, "utf8");
  const corePackageMaximum =
    common.$defs.installPlan.properties.packageBytesSizeBytes.maximum;
  const coreManifestMaximum =
    common.$defs.installPlan.properties.packageManifestSizeBytes.maximum;
  assert.equal(corePackageMaximum, 4 * 1024 * 1024);
  assert.equal(coreManifestMaximum, 4 * 1024 * 1024);
  assert.match(coreSource, /const MAX_ARTIFACT_BYTES = 4 \* 1024 \* 1024;/);
  assert.equal(schema.properties.packageSizeBytes.maximum, corePackageMaximum);
  assert.equal(schema.$defs.member.properties.offset.maximum, corePackageMaximum - 1);
  assert.equal(schema.$defs.member.properties.sizeBytes.maximum, corePackageMaximum);
});

test("module contains no mutation, network, process-launch, signing, or private-key API", () => {
  const source = fs.readFileSync(MODULE, "utf8");
  for (const expression of [
    /node:child_process/,
    /node:(?:net|http|https|tls|dgram)/,
    /\bfetch\s*\(/,
    /\b(?:spawn|exec|execFile|fork)Sync?\s*\(/,
    /\b(?:writeFile|appendFile|createWriteStream|truncate|chmod|chown|rename|unlink|mkdir|rmdir|rm|copyFile)Sync?\s*\(/,
    /crypto\.(?:sign|generateKeyPair|generateKeyPairSync|privateDecrypt)\s*\(/,
  ]) assert.doesNotMatch(source, expression);
});

test("CLI requires explicit closed inputs and exits 78 even for a valid package", (t) => {
  const fixture = buildFixture(t);
  const valid = spawnSync(process.execPath, [
    MODULE,
    "--package",
    fixture.packagePath,
    "--manifest",
    fixture.manifestPath,
    "--expected-package-sha256",
    fixture.expectedPackageSha256,
    "--expected-manifest-sha256",
    fixture.expectedManifestSha256,
  ], { encoding: "utf8" });
  assert.equal(valid.status, 78, valid.stderr);
  assert.equal(valid.stderr, "");
  assert.equal(JSON.parse(valid.stdout).status, "FORMAT-VERIFIED-NON-AUTHORITATIVE");
  assert.equal(JSON.parse(valid.stdout).installAuthority, false);

  const missing = spawnSync(process.execPath, [MODULE], { encoding: "utf8" });
  assert.equal(missing.status, 64);
  assert.match(missing.stderr, /required|usage/i);
  assert.equal(missing.stdout, "");

  const unknown = spawnSync(process.execPath, [
    MODULE,
    "--package", fixture.packagePath,
    "--manifest", fixture.manifestPath,
    "--expected-package-sha256", fixture.expectedPackageSha256,
    "--expected-manifest-sha256", fixture.expectedManifestSha256,
    "--install", "true",
  ], { encoding: "utf8" });
  assert.equal(unknown.status, 64);
  assert.match(unknown.stderr, /unknown option/i);
  assert.equal(unknown.stdout, "");
});

test("exported canonical JSON is deterministic and accepts only plain JSON values", () => {
  assert.equal(canonicalJson({ z: 1, a: { y: 2, b: 3 } }), '{"a":{"b":3,"y":2},"z":1}');
  assert.throws(() => canonicalJson({ bad: undefined }), /unsupported/i);
  assert.throws(() => canonicalJson({ bad: Number.POSITIVE_INFINITY }), /unsupported/i);
  assert.throws(() => canonicalJson(new Date()), /plain JSON object/i);
});
