#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { buildPrincipalMigrationPlan } from "../control-center/database/ownership.mjs";

const args = parseArgs(process.argv.slice(2));
if (args.apply || args.execute) fail("This command is read-only and never executes database mutations.");
const databasesFile = requiredPath(args["databases-file"] || process.env.PROJECT_DATABASES_FILE, "databases-file");
const registryFile = args["registry-file"] || process.env.PROJECT_DATABASE_PRINCIPALS_FILE || "";
const databases = readJson(databasesFile, "database state");
const registry = registryFile && existsSync(path.resolve(registryFile))
  ? readJson(path.resolve(registryFile), "database principal registry")
  : { version: 1, bindings: {} };
const plan = {
  version: 1,
  generatedAt: new Date().toISOString(),
  mode: "read-only-dual-credential-plan",
  mutationExecuted: false,
  databases: buildPrincipalMigrationPlan(databases, registry.bindings || {}),
};
plan.summary = {
  total: plan.databases.length,
  managed: plan.databases.filter((entry) => entry.status === "managed").length,
  migrationRequired: plan.databases.filter((entry) => entry.status === "migration-required").length,
};
const output = `${JSON.stringify(plan, null, 2)}\n`;
if (args.output) {
  writeFileSync(path.resolve(args.output), output, { mode: 0o600, flag: "wx" });
} else {
  process.stdout.write(output);
}

function readJson(file, label) {
  try {
    const value = JSON.parse(readFileSync(file, "utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid shape");
    return value;
  } catch {
    fail(`Unable to read valid ${label}.`);
  }
}

function requiredPath(value, label) {
  if (!value) fail(`Use --${label}.`);
  const resolved = path.resolve(value);
  if (!existsSync(resolved)) fail(`${label} does not exist.`);
  return resolved;
}

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (!value.startsWith("--")) continue;
    const key = value.slice(2);
    if (["apply", "execute"].includes(key)) {
      result[key] = true;
      continue;
    }
    result[key] = values[index + 1] || "";
    index += 1;
  }
  return result;
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
