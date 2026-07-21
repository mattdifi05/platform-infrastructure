import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(path.join(root, "vendor", "json-schema", "package.json"));
const Ajv = require("ajv");
const Ajv2020 = require("ajv/dist/2020");
const addFormats = require("ajv-formats");

function invalid(message) { throw new Error(message); }

function validateWithAjv(document, schema, { draft2020 = false, dependencies = new Map(), label }) {
  const ajv = draft2020
    ? new Ajv2020({ strict: false, allErrors: true, validateFormats: true })
    : new Ajv({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);
  ajv.addFormat("iri-reference", { type: "string", validate: (value) => !/[\0\r\n\s]/.test(value) });
  ajv.addFormat("idn-email", { type: "string", validate: (value) => /^[^\s@]+@[^\s@]+$/.test(value) });
  for (const [name, dependency] of dependencies) ajv.addSchema(dependency, name);
  const validate = ajv.compile(schema);
  if (!validate(document)) {
    const detail = (validate.errors ?? []).slice(0, 5).map((error) => `${error.instancePath || "/"} ${error.message}`).join("; ");
    invalid(`${label} validation failed: ${detail}`);
  }
}

export function loadPinnedCycloneDxReleaseSchema() {
  const lockPath = path.join(root, "governance", "cyclonedx-schema-lock.json");
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  if (lock.specification !== "CycloneDX" || lock.specVersion !== "1.5" || lock.officialSchemaId !== "http://cyclonedx.org/schema/bom-1.5.schema.json") {
    invalid("CycloneDX schema lock metadata is invalid.");
  }
  if (!/^[a-f0-9]{64}$/.test(String(lock.vendoredProfileSha256 ?? ""))) invalid("CycloneDX vendored profile checksum is not pinned.");
  const readPinned = (relative, expected, label, { json = true } = {}) => {
    const resolved = path.resolve(root, relative);
    if (!resolved.startsWith(`${root}${path.sep}`)) invalid(`${label} escapes the repository.`);
    const bytes = fs.readFileSync(resolved);
    const sha256 = crypto.createHash("sha256").update(bytes).digest("hex");
    if (sha256 !== expected) invalid(`${label} checksum mismatch.`);
    return { resolved, sha256, document: json ? JSON.parse(bytes.toString("utf8")) : null };
  };
  const official = readPinned(lock.officialSchema, lock.officialSchemaSha256, "CycloneDX official schema");
  if (official.document.$id !== lock.officialSchemaId) invalid("CycloneDX official schema ID does not match the lock.");
  const officialDirectory = path.dirname(lock.officialSchema);
  const resources = new Map();
  for (const [name, checksum] of Object.entries(lock.officialDependencies ?? {})) {
    resources.set(name, readPinned(path.join(officialDirectory, name), checksum, `CycloneDX schema dependency ${name}`).document);
  }
  readPinned(lock.upstreamReceipt, lock.upstreamReceiptSha256, "CycloneDX upstream receipt");
  readPinned(path.join(path.dirname(lock.officialSchema), "LICENSE"), lock.upstreamLicenseSha256, "CycloneDX upstream license", { json: false });
  const profile = readPinned(lock.vendoredProfile, lock.vendoredProfileSha256, "CycloneDX Platform profile");
  return { lock, official, profile, resources };
}

export function validatePinnedCycloneDxReleaseSchema(document) {
  const loaded = loadPinnedCycloneDxReleaseSchema();
  validateWithAjv(document, loaded.official.document, { dependencies: loaded.resources, label: "Official CycloneDX 1.5 schema" });
  validateWithAjv(document, loaded.profile.document, { draft2020: true, label: "Platform release profile" });
  return {
    schemaId: loaded.lock.officialSchemaId,
    specVersion: loaded.lock.specVersion,
    upstreamCommit: loaded.lock.upstreamCommit,
    officialSchemaSha256: loaded.official.sha256,
    profileSha256: loaded.profile.sha256,
  };
}

export function validatePlatformReleaseProfileOnly(document) {
  const loaded = loadPinnedCycloneDxReleaseSchema();
  validateWithAjv(document, loaded.profile.document, { draft2020: true, label: "Platform release profile" });
  return true;
}
