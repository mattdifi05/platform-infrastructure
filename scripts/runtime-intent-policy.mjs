import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { exactGitSha, exactRepository, parseReleaseImage } from "./release-artifact-policy.mjs";

export const PRODUCTION_PROJECT_NAME = "platform_infra_vps";

function invalid(message) {
  throw new Error(message);
}

function exactObject(value, label, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object.`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) invalid(`${label} does not use the exact closed schema.`);
  return value;
}

function exactSha256(value, label) {
  const text = String(value ?? "");
  if (!/^[a-f0-9]{64}$/.test(text)) invalid(`${label} must be one lowercase SHA256.`);
  return text;
}

function exactImageId(value, label) {
  const text = String(value ?? "");
  if (!/^sha256:[a-f0-9]{64}$/.test(text)) invalid(`${label} must be one exact local image ID.`);
  return text;
}

function exactName(value, label) {
  const text = String(value ?? "");
  if (!/^[a-z0-9][a-z0-9_.-]{0,127}$/.test(text)) invalid(`${label} is invalid.`);
  return text;
}

function exactSubjectKey(value, label) {
  const text = String(value ?? "");
  if (!/^[A-Z][A-Z0-9_]{0,127}$/.test(text)) invalid(`${label} is invalid.`);
  return text;
}

function sortedUnique(values, label, validate) {
  if (!Array.isArray(values) || values.length === 0) invalid(`${label} must be a non-empty array.`);
  const result = values.map((value, index) => validate(value, `${label}[${index}]`));
  if (new Set(result).size !== result.length) invalid(`${label} contains duplicates.`);
  const sorted = [...result].sort();
  if (JSON.stringify(result) !== JSON.stringify(sorted)) invalid(`${label} must be lexicographically sorted.`);
  return result;
}

export function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) invalid("Canonical JSON numbers must be safe integers.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    invalid("Canonical JSON accepts only plain JSON values.");
  }
  const keys = Object.keys(value).sort();
  if (keys.some((key) => value[key] === undefined)) invalid("Canonical JSON cannot contain undefined values.");
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

export function runtimeIntentSha256(intent) {
  return crypto.createHash("sha256").update(canonicalJson(intent)).digest("hex");
}

export function validateRuntimeIntent(intent, {
  repository,
  commitSha,
  treeSha,
  sourceArchiveSha256,
  artifactSubjects,
  opsRunner,
  projectName = PRODUCTION_PROJECT_NAME,
  environmentSha256 = null,
} = {}) {
  exactObject(intent, "Runtime intent", [
    "version",
    "kind",
    "repository",
    "commitSha",
    "treeSha",
    "sourceArchiveSha256",
    "projectName",
    "environmentSha256",
    "hostedWorkloadLockSha256",
    "coreComposeSha256",
    "combinedComposeSha256",
    "services",
    "targetServingServices",
  ]);
  if (intent.version !== 1 || intent.kind !== "platform-runtime-intent/v1") invalid("Runtime intent kind/version is invalid.");
  const expectedRepository = exactRepository(repository);
  const expectedCommit = exactGitSha(commitSha);
  const expectedTree = exactGitSha(treeSha, "tree SHA");
  const expectedArchive = exactSha256(sourceArchiveSha256, "source archive SHA256");
  if (
    intent.repository !== expectedRepository
    || intent.commitSha !== expectedCommit
    || intent.treeSha !== expectedTree
    || intent.sourceArchiveSha256 !== expectedArchive
  ) {
    invalid("Runtime intent repository/commit/tree/source archive binding is mismatched.");
  }
  if (intent.projectName !== projectName || projectName !== PRODUCTION_PROJECT_NAME) {
    invalid(`Runtime intent projectName must be ${PRODUCTION_PROJECT_NAME}.`);
  }
  exactSha256(intent.environmentSha256, "runtime intent environment SHA256");
  if (environmentSha256 !== null && intent.environmentSha256 !== exactSha256(environmentSha256, "expected environment SHA256")) {
    invalid("Runtime intent environment SHA256 is mismatched.");
  }
  if (intent.hostedWorkloadLockSha256 !== null) exactSha256(intent.hostedWorkloadLockSha256, "hosted workload lock SHA256");
  exactSha256(intent.coreComposeSha256, "core Compose SHA256");
  exactSha256(intent.combinedComposeSha256, "combined Compose SHA256");

  const admittedSubjects = Array.isArray(artifactSubjects)
    ? artifactSubjects.map((entry) => parseReleaseImage(entry?.image, entry?.key))
    : invalid("Artifact release subjects are required.");
  if (admittedSubjects.length === 0) invalid("Artifact release subjects are required.");
  const subjectsByKey = new Map(admittedSubjects.map((entry) => [entry.key, entry]));
  if (subjectsByKey.size !== admittedSubjects.length) invalid("Artifact release subject keys must be unique.");
  const admittedOpsImage = parseReleaseImage(opsRunner?.image, "PLATFORM_OPS_IMAGE");
  exactImageId(opsRunner?.imageId, "ops runner image ID");

  if (!Array.isArray(intent.services) || intent.services.length === 0) invalid("Runtime intent services must be a non-empty array.");
  const services = [];
  const seenServices = new Set();
  const usedSubjects = new Set();
  let opsRunnerUses = 0;
  for (const entry of intent.services) {
    exactObject(entry, "Runtime intent service", ["service", "image", "admission", "expectedLocalImageId"]);
    const service = exactName(entry.service, "runtime intent service name");
    if (seenServices.has(service)) invalid(`Runtime intent service ${service} is duplicated.`);
    seenServices.add(service);
    const image = parseReleaseImage(entry.image, `${service} image`);
    exactImageId(entry.expectedLocalImageId, `${service} expected local image ID`);
    const admission = entry.admission;
    if (admission?.kind === "artifact-subject") {
      exactObject(admission, `${service} artifact admission`, ["kind", "subjectKey"]);
      const subjectKey = exactSubjectKey(admission.subjectKey, `${service} artifact subject key`);
      const subject = subjectsByKey.get(subjectKey);
      if (!subject || subject.image !== image.image) invalid(`${service} is not bound to its exact artifact release subject.`);
      if (usedSubjects.has(subjectKey)) invalid(`Artifact release subject ${subjectKey} is used by multiple services.`);
      usedSubjects.add(subjectKey);
    } else if (admission?.kind === "ops-runner") {
      exactObject(admission, `${service} ops admission`, ["kind"]);
      if (image.image !== admittedOpsImage.image || entry.expectedLocalImageId !== opsRunner.imageId) {
        invalid(`${service} is not bound to the exact provider-attested ops runner image and image ID.`);
      }
      opsRunnerUses += 1;
    } else if (admission?.kind === "external-digest") {
      exactObject(admission, `${service} external image admission`, ["kind", "sourceKey"]);
      exactSubjectKey(admission.sourceKey, `${service} external image source key`);
    } else {
      invalid(`${service} has an unsupported runtime image admission kind.`);
    }
    services.push({ service, image: image.image });
  }
  const serviceOrder = intent.services.map((entry) => entry.service);
  if (JSON.stringify(serviceOrder) !== JSON.stringify([...serviceOrder].sort())) invalid("Runtime intent services must be lexicographically sorted.");
  if (
    usedSubjects.size !== subjectsByKey.size
    || [...subjectsByKey.keys()].some((key) => !usedSubjects.has(key))
  ) {
    invalid("Runtime intent does not consume the exact complete artifact release subject set.");
  }
  if (opsRunnerUses !== 1) invalid("Runtime intent must consume the provider-attested ops runner exactly once.");

  const targetServingServices = sortedUnique(intent.targetServingServices, "Runtime intent target serving services", exactName);
  if (targetServingServices.some((service) => !seenServices.has(service))) {
    invalid("Runtime intent target serving services are not an exact subset of runtime services.");
  }
  return {
    repository: expectedRepository,
    commitSha: expectedCommit,
    treeSha: expectedTree,
    sourceArchiveSha256: expectedArchive,
    environmentSha256: intent.environmentSha256,
    subjects: admittedSubjects,
    services,
    targetServingServices,
    sha256: runtimeIntentSha256(intent),
  };
}

function main() {
  const values = process.argv.slice(2);
  if (values.length !== 2 || values[0] !== "--hash") invalid("Usage: runtime-intent-policy.mjs --hash <runtime-intent.json>");
  const filename = path.resolve(values[1]);
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 16 * 1024 * 1024) {
    invalid("Runtime intent input must be one bounded regular file.");
  }
  const bytes = fs.readFileSync(filename);
  let intent;
  try {
    const text = bytes.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(bytes)) invalid("Runtime intent input must be valid UTF-8.");
    intent = JSON.parse(text);
  } catch (error) {
    invalid(`Runtime intent input is invalid JSON: ${error.message}`);
  }
  process.stdout.write(`${runtimeIntentSha256(intent)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
