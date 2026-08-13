#!/usr/bin/env node
import fs from "node:fs";
import { fileURLToPath } from "node:url";

export const V1_INSTALL_CANDIDATE_COMMIT = "832bf2baec47055342af7e7f73425444381b91e0";
export const V1_INSTALL_CANDIDATE_TREE = "91cee2380809cb0691b9ac47cafa2a673d434caa";
export const V1_INSTALL_SOURCE_ARCHIVE_SHA256 = "6eabff5f3fdbb4b129519d23a2dd9864f65477c5f0e1ecb58e1b8a9a79af3007";
export const V1_INSTALL_READY_BUT_DISABLED = Object.freeze([
  "PROVIDER_ADMISSION",
  "DNS_PUBLICATION",
  "DAST",
  "SIGSTORE_PROMOTION",
  "DOCKER_CONTROL_PLANE",
]);

const RECEIPT_SCHEMA = "platform.v1-brownfield-install-receipt/v1";
const MAX_RECEIPT_BYTES = 64 * 1024;
const EXACT_FIELDS = Object.freeze([
  "activationAuthorized",
  "authorizationSource",
  "backupEvidenceAuthoritative",
  "candidateCommit",
  "candidateTree",
  "dataMutation",
  "dockerMutation",
  "readyButDisabled",
  "releaseRoot",
  "schema",
  "sourceArchiveSha256",
  "status",
]);

function invalid(message) {
  throw new Error(message);
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function lowercaseSha256(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    invalid(`${label} must be one lowercase SHA-256 digest.`);
  }
  return value;
}

function exactCandidate(value, expected, label) {
  if (value !== expected) invalid(`${label} does not match the frozen V1 candidate.`);
}

export function verifyV1InstallReceipt({ file, candidateCommit, candidateTree, sourceArchiveSha256 }) {
  exactCandidate(candidateCommit, V1_INSTALL_CANDIDATE_COMMIT, "Expected candidate commit");
  exactCandidate(candidateTree, V1_INSTALL_CANDIDATE_TREE, "Expected candidate tree");
  exactCandidate(sourceArchiveSha256, V1_INSTALL_SOURCE_ARCHIVE_SHA256, "Expected source archive SHA-256");

  const filename = String(file ?? "").trim();
  if (!filename) invalid("V1 install receipt path is required.");
  let stat;
  try {
    stat = fs.lstatSync(filename);
  } catch {
    invalid("V1 install receipt is missing.");
  }
  if (!stat.isFile() || stat.isSymbolicLink()) invalid("V1 install receipt must be a regular non-symlink file.");
  if (stat.size < 2 || stat.size > MAX_RECEIPT_BYTES) invalid("V1 install receipt size is invalid.");

  const raw = fs.readFileSync(filename, "utf8");
  if (raw.includes("\0") || raw.includes("\r")) invalid("V1 install receipt encoding is invalid.");
  let receipt;
  try {
    receipt = JSON.parse(raw);
  } catch {
    invalid("V1 install receipt is not valid JSON.");
  }
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) invalid("V1 install receipt must be one JSON object.");
  if (`${stableJson(receipt)}\n` !== raw) invalid("V1 install receipt is not canonical JSON.");
  if (JSON.stringify(Object.keys(receipt).sort()) !== JSON.stringify(EXACT_FIELDS)) {
    invalid("V1 install receipt has missing or unexpected fields.");
  }
  if (receipt.schema !== RECEIPT_SCHEMA) invalid("V1 install receipt schema is invalid.");
  if (!new Set(["INSTALL_ONLY_COMPLETE", "ALREADY_INSTALLED"]).has(receipt.status)) {
    invalid("V1 install receipt status is invalid.");
  }
  exactCandidate(receipt.candidateCommit, candidateCommit, "Receipt candidate commit");
  exactCandidate(receipt.candidateTree, candidateTree, "Receipt candidate tree");
  lowercaseSha256(receipt.sourceArchiveSha256, "Receipt source archive");
  exactCandidate(receipt.sourceArchiveSha256, sourceArchiveSha256, "Receipt source archive SHA-256");
  const expectedReleaseRoot = `/srv/platform-infrastructure/releases/${candidateCommit}-${sourceArchiveSha256}`;
  if (receipt.releaseRoot !== expectedReleaseRoot) invalid("V1 install receipt release root is not content-bound to the frozen candidate.");
  for (const field of ["activationAuthorized", "dockerMutation", "dataMutation"]) {
    if (receipt[field] !== false) invalid(`V1 install receipt ${field} must be false.`);
  }
  if (receipt.authorizationSource !== "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY") {
    invalid("V1 install receipt authorization source is invalid.");
  }
  if (receipt.backupEvidenceAuthoritative !== false) {
    invalid("V1 install receipt backup evidence must remain non-authoritative.");
  }
  if (JSON.stringify(receipt.readyButDisabled) !== JSON.stringify(V1_INSTALL_READY_BUT_DISABLED)) {
    invalid("V1 install receipt READY_BUT_DISABLED set is not exact.");
  }
  return Object.freeze({ ...receipt, readyButDisabled: Object.freeze([...receipt.readyButDisabled]) });
}

function options(arguments_) {
  if (arguments_[0] !== "verify") invalid("Usage: v1-brownfield-install-receipt.mjs verify --file FILE --candidateCommit SHA --candidateTree SHA --sourceArchiveSha256 SHA256");
  const allowed = new Set(["file", "candidateCommit", "candidateTree", "sourceArchiveSha256"]);
  const parsed = {};
  for (let index = 1; index < arguments_.length; index += 2) {
    const flag = arguments_[index];
    const value = arguments_[index + 1];
    if (!flag?.startsWith("--") || value === undefined || value.startsWith("--")) invalid("V1 install receipt options must be value-bearing.");
    const name = flag.slice(2);
    if (!allowed.has(name) || Object.hasOwn(parsed, name)) invalid(`Unknown or duplicate V1 install receipt option: ${flag}.`);
    parsed[name] = value;
  }
  for (const name of allowed) if (!Object.hasOwn(parsed, name)) invalid(`V1 install receipt is missing --${name}.`);
  return parsed;
}

function main() {
  verifyV1InstallReceipt(options(process.argv.slice(2)));
  process.stdout.write("V1 install-only receipt verified.\n");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
