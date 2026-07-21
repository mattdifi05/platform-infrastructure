import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function invalid(message) { throw new Error(message); }

function actualType(value) {
  if (Array.isArray(value)) return "array";
  if (value === null) return "null";
  if (Number.isInteger(value)) return "integer";
  return typeof value;
}

function validateNode(value, schema, location) {
  if ("const" in schema && value !== schema.const) invalid(`${location} must equal ${JSON.stringify(schema.const)}.`);
  if (schema.type) {
    const type = actualType(value);
    const accepted = schema.type === "number" ? ["number", "integer"] : [schema.type];
    if (!accepted.includes(type)) invalid(`${location} must have type ${schema.type}, got ${type}.`);
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) invalid(`${location} is shorter than minLength.`);
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) invalid(`${location} does not match its pinned schema pattern.`);
    if (schema.format === "date-time" && !Number.isFinite(Date.parse(value))) invalid(`${location} is not a valid date-time.`);
  }
  if (typeof value === "number" && schema.minimum !== undefined && value < schema.minimum) invalid(`${location} is below its schema minimum.`);
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) invalid(`${location} has fewer than ${schema.minItems} items.`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) invalid(`${location} has more than ${schema.maxItems} items.`);
    if (schema.items) value.forEach((item, index) => validateNode(item, schema.items, `${location}[${index}]`));
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(value, required)) invalid(`${location} is missing required property ${required}.`);
    }
    const properties = schema.properties ?? {};
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.hasOwn(properties, key)) invalid(`${location} contains unsupported property ${key}.`);
      }
    }
    for (const [key, childSchema] of Object.entries(properties)) {
      if (Object.hasOwn(value, key)) validateNode(value[key], childSchema, `${location}.${key}`);
    }
  }
}

export function loadPinnedCycloneDxReleaseSchema() {
  const lockPath = path.join(root, "governance", "cyclonedx-schema-lock.json");
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  if (lock.specification !== "CycloneDX" || lock.specVersion !== "1.5" || lock.officialSchemaId !== "http://cyclonedx.org/schema/bom-1.5.schema.json") {
    invalid("CycloneDX schema lock metadata is invalid.");
  }
  if (!/^[a-f0-9]{64}$/.test(String(lock.vendoredProfileSha256 ?? ""))) invalid("CycloneDX vendored profile checksum is not pinned.");
  const schemaPath = path.resolve(root, lock.vendoredProfile);
  if (!schemaPath.startsWith(`${root}${path.sep}`)) invalid("CycloneDX vendored profile escapes the repository.");
  const bytes = fs.readFileSync(schemaPath);
  const actualSha256 = crypto.createHash("sha256").update(bytes).digest("hex");
  if (actualSha256 !== lock.vendoredProfileSha256) invalid("CycloneDX vendored profile checksum mismatch.");
  const schema = JSON.parse(bytes.toString("utf8"));
  return { lock, schema, schemaPath, actualSha256 };
}

export function validatePinnedCycloneDxReleaseSchema(document) {
  const loaded = loadPinnedCycloneDxReleaseSchema();
  validateNode(document, loaded.schema, "SBOM");
  return { schemaId: loaded.lock.officialSchemaId, specVersion: loaded.lock.specVersion, profileSha256: loaded.actualSha256 };
}
