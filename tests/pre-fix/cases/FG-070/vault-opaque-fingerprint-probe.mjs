#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const EXPECTED_HASHES = new Map([
  ["scripts/infra-secret-manager.mjs", "4a46a1aa4c5b26c3669ba5a439ab7cf27c3dc6f21e773ac92ce30266abbd7385"],
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["README.md", "27ae730ec95e41ace8ee74e4bed8ded858d5acc69e634a3e0e9c34340bfe8d33"],
  ["RUNBOOK.md", "0bc7013e73d9e616f81682443b072dc50fa46d2e0b64e508e46ef2dd89d9d590"],
]);

const SECRET_NAME = "demo_access_code";
const SYNTHETIC_DICTIONARY = ["0000", "1111", "2468", "4821", "9876"];
const SYNTHETIC_VALUE = SYNTHETIC_DICTIONARY[3];
const WRONG_DICTIONARY = SYNTHETIC_DICTIONARY.filter((candidate) => candidate !== SYNTHETIC_VALUE);
const sourceArgument = process.argv[2];
const labArgument = process.argv[3];
if (!sourceArgument || !labArgument) {
  throw new Error("usage: vault-opaque-fingerprint-probe.mjs WRAPPER_OWNED_SOURCE WRAPPER_OWNED_LAB");
}

const {
  sourceRoot,
  labRoot,
  sentinelPath,
  sentinelText,
  sentinelDevice,
  sentinelInode,
} = validateWrapperOwnedPaths(sourceArgument, labArgument);
const sourceBefore = directoryDigest(sourceRoot);
console.log("[+] wrapper-owned source and synthetic lab verified");

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(
    sha256File(path.join(sourceRoot, relativePath)),
    expected,
    `${relativePath} is not the expected vulnerable source`,
  );
}
console.log(`[+] verified ${EXPECTED_HASHES.size} embedded vulnerable-source hashes`);

const managerPath = path.join(sourceRoot, "scripts/infra-secret-manager.mjs");
const infraOpsPath = path.join(sourceRoot, "scripts/infra-ops.mjs");
const readmePath = path.join(sourceRoot, "README.md");
const runbookPath = path.join(sourceRoot, "RUNBOOK.md");
const managerSource = fs.readFileSync(managerPath, "utf8");
const infraOpsSource = fs.readFileSync(infraOpsPath, "utf8");
const readmeSource = fs.readFileSync(readmePath, "utf8");
const runbookSource = fs.readFileSync(runbookPath, "utf8");

assert.match(managerSource, /minLength: positiveInteger\([\s\S]*?previousRecord\.minLength, 1, "minLength"\)/);
const fingerprintSource = sourceSlice(managerSource, "function fingerprint(value) {", "\n\nfunction kmsKeyId");
assert.match(fingerprintSource, /createHash\("sha256"\)\.update\(value\)\.digest\("hex"\)\.slice\(0, 16\)/);
assert.doesNotMatch(fingerprintSource, /createHmac|secret|key/i);
const writeStoreSource = sourceSlice(managerSource, "function writeStore(", "\n\nfunction audit(");
assert.match(writeStoreSource, /updatedAt: previousRecord\.fingerprint === fingerprint\(value\)/);
assert.match(writeStoreSource, /fingerprint: fingerprint\(value\)/);
const statusSource = sourceSlice(managerSource, "async function status() {", "\n\nasync function kmsStatus");
assert.match(statusSource, /fingerprint=\$\{record\.fingerprint\}/);
const backupSource = sourceSlice(infraOpsSource, "async function backupSecretManagerMetadata", "\n\nasync function restoreTestSecretManagerMetadata");
assert.match(backupSource, /\["infra-secret-manager-store\.json"/);
assert.match(backupSource, /runSecretManager\(\["status"\]/);
assert.match(backupSource, /"status\.txt"/);
assert.doesNotMatch(backupSource, /\["infra-secret-manager-master\.key"/);
assert.match(readmeSource, /status` mostra solo metadati, owner, scope e fingerprint/);
assert.match(runbookSource, /status` and evidence reports print only metadata and fingerprints/);
console.log("[+] vulnerable policy vault_min_length_default=1 fingerprint=sha256-prefix-64");

const secretsDir = path.join(labRoot, "manager-secrets");
const homeDir = path.join(labRoot, "synthetic-home");
const tempDir = path.join(labRoot, "synthetic-tmp");
const storePath = path.join(labRoot, "infra-secret-manager-store.json");
const masterKeyPath = path.join(labRoot, "infra-secret-manager-master.key");
const auditLogPath = path.join(labRoot, "infra-secret-manager-audit.log");
fs.mkdirSync(secretsDir, { recursive: false, mode: 0o700 });
fs.mkdirSync(homeDir, { recursive: false, mode: 0o700 });
fs.mkdirSync(tempDir, { recursive: false, mode: 0o700 });

const commonArgs = [
  "--secretsDir", secretsDir,
  "--store", storePath,
  "--masterKey", masterKeyPath,
  "--auditLog", auditLogPath,
];
const setResult = runManager([
  "set",
  "--name", SECRET_NAME,
  "--stdin",
  "--owner", "synthetic-lab",
  ...commonArgs,
], `${SYNTHETIC_VALUE}\n`);
assert.equal(setResult.status, 0, `synthetic manager set failed: ${oneLine(setResult.stderr)}`);

const store = JSON.parse(fs.readFileSync(storePath, "utf8"));
const record = store?.secrets?.[SECRET_NAME];
assert.ok(record, "synthetic vault record is missing");
assert.equal(record.kind, "opaque");
assert.equal(record.scope, "vault");
assert.equal(record.minLength, 1);
assert.match(record.fingerprint, /^[a-f0-9]{16}$/);
assert.equal(record.fingerprint, plaintextFingerprint(SYNTHETIC_VALUE));
assert.equal(record.encryption?.algorithm, "AES-256-GCM");
assert.match(record.encryption?.ciphertext ?? "", /^[A-Za-z0-9_-]+$/);
assert.equal(Object.hasOwn(record, "value"), false);
assert.equal(fs.existsSync(masterKeyPath), true);
console.log("[+] synthetic store created scope=vault fingerprint_bits=64 ciphertext_present=true");

const statusResult = runManager(["status", ...commonArgs]);
assert.equal(statusResult.status, 0, `synthetic manager status failed: ${oneLine(statusResult.stderr)}`);
const statusMatch = new RegExp(`^${SECRET_NAME}:.* fingerprint=([a-f0-9]{16})(?:\\s|$)`, "m").exec(statusResult.stdout);
assert.ok(statusMatch, "status output did not export the synthetic fingerprint");
assert.equal(statusMatch[1], record.fingerprint);

const offlineRoot = path.join(labRoot, "offline-artifact");
fs.mkdirSync(offlineRoot, { recursive: false, mode: 0o700 });
const offlineStorePath = path.join(offlineRoot, "infra-secret-manager-store.json");
const offlineStatusPath = path.join(offlineRoot, "status.txt");
fs.writeFileSync(offlineStorePath, `${JSON.stringify(store, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
fs.writeFileSync(offlineStatusPath, statusResult.stdout, { encoding: "utf8", mode: 0o600 });
assert.equal(fs.existsSync(path.join(offlineRoot, "infra-secret-manager-master.key")), false);

const offlineStore = JSON.parse(fs.readFileSync(offlineStorePath, "utf8"));
const persistedFingerprint = offlineStore.secrets[SECRET_NAME].fingerprint;
const exportedStatus = fs.readFileSync(offlineStatusPath, "utf8");
const exportedFingerprint = new RegExp(`^${SECRET_NAME}:.* fingerprint=([a-f0-9]{16})(?:\\s|$)`, "m").exec(exportedStatus)?.[1];
const storeMatches = dictionaryMatches(persistedFingerprint, SYNTHETIC_DICTIONARY);
const statusMatches = dictionaryMatches(exportedFingerprint, SYNTHETIC_DICTIONARY);
assert.deepEqual(storeMatches, [SYNTHETIC_VALUE]);
assert.deepEqual(statusMatches, [SYNTHETIC_VALUE]);
console.log(`[VULNERABLE] persisted_store dictionary_candidates=${SYNTHETIC_DICTIONARY.length} recovered=true offline_artifact_master_key=false`);
console.log(`[VULNERABLE] exported_status dictionary_candidates=${SYNTHETIC_DICTIONARY.length} recovered=true offline_artifact_master_key=false`);

assert.deepEqual(dictionaryMatches(persistedFingerprint, WRONG_DICTIONARY), []);
console.log(`[CONTROL] wrong_dictionary candidates=${WRONG_DICTIONARY.length} recovered=false`);

const migratedRecord = structuredClone(record);
delete migratedRecord.fingerprint;
const migratedMetadata = {
  name: SECRET_NAME,
  kind: migratedRecord.kind,
  scope: migratedRecord.scope,
  owner: migratedRecord.owner,
  updatedAt: migratedRecord.updatedAt,
  encryption: migratedRecord.encryption,
};
assert.equal(extractPlaintextGuessOracle(migratedMetadata), null);
console.log("[FIXED] migrated_metadata plaintext_derived_fingerprint_present=false offline_guess_oracle=false");

const verifierKey = crypto.randomBytes(32);
const wrongKey = crypto.randomBytes(32);
const internalTag = keyedInternalTag(verifierKey, SECRET_NAME, SYNTHETIC_VALUE);
const wrongKeyMatches = SYNTHETIC_DICTIONARY.some(
  (candidate) => crypto.timingSafeEqual(keyedInternalTag(wrongKey, SECRET_NAME, candidate), internalTag),
);
const authorizedMatch = crypto.timingSafeEqual(
  keyedInternalTag(verifierKey, SECRET_NAME, SYNTHETIC_VALUE),
  internalTag,
);
assert.equal(wrongKeyMatches, false);
assert.equal(authorizedMatch, true);
assert.equal(Object.hasOwn(migratedMetadata, "internalTag"), false);
console.log("[FIXED] keyed_internal_tag domain=infra-secret-manager/fingerprint/v2 wrong_key_matches=false authorized_match=true exported=false");

assert.equal(directoryDigest(sourceRoot), sourceBefore, "the archived source changed during the probe");
const sentinelAfter = fs.lstatSync(sentinelPath);
assert.equal(sentinelAfter.isFile(), true, "the ownership sentinel is no longer a regular file");
assert.equal(sentinelAfter.isSymbolicLink(), false, "the ownership sentinel became a symlink");
assert.equal(sentinelAfter.dev, sentinelDevice, "the ownership sentinel device changed during the probe");
assert.equal(sentinelAfter.ino, sentinelInode, "the ownership sentinel inode changed during the probe");
assert.equal(fs.readFileSync(sentinelPath, "utf8"), sentinelText, "the ownership sentinel changed during the probe");
console.log("[+] source_tree_unchanged=true synthetic_only=true");
console.log("[+] no real Vault, secret, backup, credential, network, live target, or candidate working tree was read or changed");

function runManager(argumentsList, input = undefined) {
  return spawnSync(process.execPath, [managerPath, ...argumentsList], {
    encoding: "utf8",
    input,
    env: {
      ...process.env,
      HOME: homeDir,
      TMPDIR: tempDir,
      HTTP_PROXY: "",
      HTTPS_PROXY: "",
      ALL_PROXY: "",
      NO_PROXY: "*",
    },
    maxBuffer: 2 * 1024 * 1024,
  });
}

function plaintextFingerprint(value) {
  return crypto.createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function dictionaryMatches(expected, candidates) {
  if (typeof expected !== "string" || !/^[a-f0-9]{16}$/.test(expected)) return [];
  return candidates.filter((candidate) => plaintextFingerprint(candidate) === expected);
}

function extractPlaintextGuessOracle(metadata) {
  const candidate = metadata?.fingerprint;
  return typeof candidate === "string" && /^[a-f0-9]{16}$/.test(candidate) ? candidate : null;
}

function keyedInternalTag(key, name, value) {
  return crypto.createHmac("sha256", key)
    .update("infra-secret-manager/fingerprint/v2\0", "utf8")
    .update(name, "utf8")
    .update("\0", "utf8")
    .update(value, "utf8")
    .digest();
}

function validateWrapperOwnedPaths(sourceInput, labInput) {
  const wrapperInput = requiredEnvironment("FG070_WRAPPER_TEMP_ROOT");
  const sentinelInput = requiredEnvironment("FG070_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("FG070_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperInput);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(path.basename(wrapperReal), /^fg070-(?:guard|run)\.[A-Za-z0-9]+$/);

  const sourcePath = path.resolve(sourceInput);
  const sourceStat = fs.lstatSync(sourcePath, { throwIfNoEntry: false });
  assert.ok(sourceStat?.isDirectory(), "archived source directory is missing");
  assert.equal(sourceStat.isSymbolicLink(), false, "archived source must not be a symlink");
  const sourceReal = fs.realpathSync(sourcePath);
  assert.equal(sourceReal, path.join(wrapperReal, "source"), "source must be the exact wrapper-owned source child");

  const labPath = path.resolve(labInput);
  const labStat = fs.lstatSync(labPath, { throwIfNoEntry: false });
  assert.ok(labStat?.isDirectory(), "synthetic lab directory is missing");
  assert.equal(labStat.isSymbolicLink(), false, "synthetic lab must not be a symlink");
  const labReal = fs.realpathSync(labPath);
  assert.equal(labReal, path.join(wrapperReal, "lab"), "lab must be the exact wrapper-owned lab child");

  const sentinelPath = path.resolve(sentinelInput);
  const sentinelStat = fs.lstatSync(sentinelPath, { throwIfNoEntry: false });
  assert.ok(sentinelStat?.isFile(), "ownership sentinel is missing");
  assert.equal(sentinelStat.isSymbolicLink(), false, "ownership sentinel must not be a symlink");
  const sentinelReal = fs.realpathSync(sentinelPath);
  assert.equal(path.dirname(sentinelReal), wrapperReal, "ownership sentinel is outside the wrapper root");
  assert.match(path.basename(sentinelReal), /^\.fg070-owner\.[A-Za-z0-9]+$/);
  const tokenFromName = path.basename(sentinelReal).slice(".fg070-owner.".length);
  assert.equal(ownershipToken, tokenFromName, "ownership token does not match sentinel name");
  const sentinelText = `FG070-OWNER:${ownershipToken}\n`;
  assert.equal(fs.readFileSync(sentinelReal, "utf8"), sentinelText, "ownership sentinel content is invalid");

  return {
    sourceRoot: sourceReal,
    labRoot: labReal,
    sentinelPath: sentinelReal,
    sentinelText,
    sentinelDevice: sentinelStat.dev,
    sentinelInode: sentinelStat.ino,
  };
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required; invoke through run-from-git-archive.sh`);
  }
  return value;
}

function sourceSlice(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker.trim()}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker.trim()}`);
  return source.slice(start, end);
}

function oneLine(value) {
  return String(value ?? "").trim().split(/\r?\n/)[0] ?? "unknown error";
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function directoryDigest(root) {
  const digest = crypto.createHash("sha256");
  walk(root, "");
  return digest.digest("hex");

  function walk(current, relative) {
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) {
      digest.update(`L\0${relative}\0${fs.readlinkSync(current)}\0`);
      return;
    }
    if (stat.isDirectory()) {
      digest.update(`D\0${relative}\0${stat.mode & 0o7777}\0`);
      for (const name of fs.readdirSync(current).sort()) {
        walk(path.join(current, name), relative ? `${relative}/${name}` : name);
      }
      return;
    }
    assert.equal(stat.isFile(), true, `unsupported archived entry: ${relative}`);
    digest.update(`F\0${relative}\0${stat.mode & 0o7777}\0`);
    digest.update(fs.readFileSync(current));
    digest.update("\0");
  }
}
