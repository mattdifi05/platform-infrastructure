#!/usr/bin/env node
// Standalone fail-closed semantic authority for the V1 LOCAL_PRIVATE GREENFIELD
// Compose projection (project platform_infra_greenfield). It validates one
// rendered `docker compose config --format json` document against:
//   - the greenfield namespace module (physical name ownership),
//   - its own digest binding recorded in the greenfield lock file,
//   - the protected resource inventory of that lock,
//   - and the shared runtime isolation contract.
// Unlike no-hosted-core-policy.mjs this validator is self-contained on purpose:
// the brownfield policy is frozen and must never learn about greenfield.

import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import {
  evaluateGreenfieldNamespace,
  GREENFIELD_PROJECT_NAME,
  GREENFIELD_CORE_SERVICES,
  GREENFIELD_AUXILIARY_SERVICES,
} from "./greenfield-namespace.mjs";
import { evaluateRuntimeIsolation } from "./runtime-isolation-policy.mjs";

export const CORE_SEMANTIC_POLICY_SCHEMA = "platform-no-hosted-core-capability-policy/v2";
const DISABLING_PROFILES = new Set([
  "admin",
  "dns",
  "raw-host-metrics-disabled",
  "local-runtime-disabled",
  "legacy-shared-runtime-disabled",
]);
const IMAGE_DIGEST_PATTERN = /@sha256:[a-f0-9]{64}$/;
const FORBIDDEN_BIND_SOURCE_FRAGMENTS = ["/backups/"];
const FORBIDDEN_BIND_SOURCE_SUFFIXES = [".pem.key"];

function policySelfSha256() {
  try {
    return crypto
      .createHash("sha256")
      .update(fs.readFileSync(fileURLToPath(import.meta.url)))
      .digest("hex");
  } catch {
    return null;
  }
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sortedEquals(left, right) {
  return JSON.stringify([...(left ?? [])].sort()) === JSON.stringify([...(right ?? [])].sort());
}

function dedupe(values) {
  return [...new Set(values)];
}

// The greenfield overlay pins every data volume to an explicit physical name
// in the dedicated greenfield_* namespace. Docker would have derived exactly
// <project>_<logical> for unpinned volumes, so before folding the shared
// runtime isolation contract (which expects the derived form) the explicit
// pins are projected back onto their compose-default equivalents. This keeps
// both validators strict: any drift away from the pinned greenfield_* names is
// rejected by evaluateGreenfieldNamespace, and every structural isolation rule
// still applies unchanged.
function projectCanonicalVolumeNames(config) {
  const projected = structuredClone(config);
  if (!plainObject(projected.volumes) || typeof projected.name !== "string") {
    return projected;
  }
  for (const [logical, declaration] of Object.entries(projected.volumes)) {
    if (plainObject(declaration)) {
      declaration.name = `${projected.name}_${logical}`;
    }
  }
  return projected;
}

export function evaluateGreenfieldCoreAuthority(lock, config, environment = new Map()) {
  const violations = [];
  if (!plainObject(lock)) {
    return { violations: ["lock-shape"], normalizedSummary: null };
  }
  if (lock.version !== 4
      || lock.validatorVersion !== "hosted-contract-v4"
      || lock.state !== "verified"
      || lock.brokerPolicySha256 !== "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945") {
    violations.push("lock-shape");
  }
  if (lock.projectName !== GREENFIELD_PROJECT_NAME) {
    violations.push("lock:project-name");
  }
  const binding = lock.coreSemanticPolicy;
  if (!plainObject(binding)
      || !sortedEquals(Object.keys(binding), ["schema", "sha256"])
      || binding.schema !== CORE_SEMANTIC_POLICY_SCHEMA
      || binding.sha256 !== policySelfSha256()
      || typeof binding.sha256 !== "string") {
    violations.push("policy-binding");
  }

  const protectedNames = lock.protectedResourceNames;
  const inventoryValid = plainObject(protectedNames)
    && sortedEquals(Object.keys(protectedNames), ["configs", "networks", "secrets", "services", "volumes"])
    && Object.values(protectedNames).every((names) => Array.isArray(names) && names.every((name) => typeof name === "string" && name.length > 0));
  if (!inventoryValid) {
    violations.push("lock:protected-resource-names");
    return { violations: dedupe(violations), normalizedSummary: null };
  }
  if (!sortedEquals(protectedNames.services, GREENFIELD_CORE_SERVICES)) {
    violations.push("lock:services");
  }

  if (!plainObject(config) || !plainObject(config.services)) {
    return { violations: dedupe([...violations, "config-shape"]), normalizedSummary: null };
  }
  if (config.name !== GREENFIELD_PROJECT_NAME) {
    violations.push("render:project-name");
  }

  violations.push(...evaluateGreenfieldNamespace(config));

  const services = config.services;
  const serviceNames = Object.keys(services);
  const protectedServices = protectedNames.services;
  const auxiliary = new Set(GREENFIELD_AUXILIARY_SERVICES);
  for (const name of protectedServices) {
    if (!Object.hasOwn(services, name)) {
      violations.push(`service:${name}:missing`);
    }
  }
  for (const [name, definition] of Object.entries(services)) {
    const service = plainObject(definition) ? definition : {};
    const image = typeof service.image === "string" ? service.image : "";
    if (!IMAGE_DIGEST_PATTERN.test(image)) {
      violations.push(`service:${name}:image-digest`);
    }
    if (service.privileged === true) {
      violations.push(`service:${name}:privileged`);
    }
    for (const mount of Array.isArray(service.volumes) ? service.volumes : []) {
      const source = typeof mount === "string"
        ? String(mount).split(":")[0]
        : (plainObject(mount) && mount.type === "bind" ? String(mount.source ?? "") : null);
      if (source === null || source.length === 0) continue;
      if (FORBIDDEN_BIND_SOURCE_FRAGMENTS.some((fragment) => source.includes(fragment))
          || FORBIDDEN_BIND_SOURCE_SUFFIXES.some((suffix) => source.endsWith(suffix))) {
        violations.push(`service:${name}:forbidden-bind-source`);
        break;
      }
    }
    if (protectedServices.includes(name)) continue;
    if (!auxiliary.has(name)) {
      violations.push(`service:${name}:unexpected`);
      continue;
    }
    const profiles = Array.isArray(service.profiles) ? service.profiles.map(String) : [];
    if (!profiles.some((profile) => DISABLING_PROFILES.has(profile))) {
      violations.push(`service:${name}:profile-required`);
    }
  }

  if (!sortedEquals(Object.keys(config.configs ?? {}), protectedNames.configs)) {
    violations.push("configs:inventory");
  }
  if (!sortedEquals(Object.keys(config.networks ?? {}), protectedNames.networks)) {
    violations.push("networks:inventory");
  }
  for (const [logical, declaration] of Object.entries(config.networks ?? {})) {
    const physical = plainObject(declaration) && typeof declaration.name === "string" ? declaration.name : "";
    if (!physical.startsWith(`${GREENFIELD_PROJECT_NAME}_`)) {
      violations.push(`network:${logical}:physical-prefix`);
    }
  }
  if (!sortedEquals(Object.keys(config.volumes ?? {}), protectedNames.volumes)) {
    violations.push("volumes:inventory");
  }
  for (const [logical, declaration] of Object.entries(config.volumes ?? {})) {
    if (!plainObject(declaration)) continue;
    const physical = typeof declaration.name === "string" ? declaration.name : "";
    if (physical.startsWith("enterprise_") || physical.startsWith("platform_infra_vps_")) {
      violations.push(`volume:${logical}:physical-forbidden`);
    }
    if (declaration.external === true) {
      violations.push(`volume:${logical}:external`);
    }
  }

  const secrets = config.secrets ?? {};
  if (Object.keys(secrets).length !== protectedNames.secrets.length) {
    violations.push("secrets:count");
  }
  const secretsRoot = typeof environment.get === "function" ? environment.get("PLATFORM_SECRETS_ROOT") ?? "" : "";
  for (const [logical, declaration] of Object.entries(secrets)) {
    const name = plainObject(declaration) && typeof declaration.name === "string" ? declaration.name : "";
    const file = plainObject(declaration) && typeof declaration.file === "string" ? declaration.file : "";
    const ownedName = name.startsWith(`${GREENFIELD_PROJECT_NAME}_`);
    const rootedFile = secretsRoot.length > 0 && file.startsWith(`${secretsRoot}/`);
    if (!ownedName && !rootedFile) {
      violations.push(`secret:${logical}:authority`);
    }
  }

  const runtimeReport = evaluateRuntimeIsolation(projectCanonicalVolumeNames(config), {});
  violations.push(...runtimeReport.failures.map((failure) => `runtime-isolation:${failure}`));

  return {
    violations: dedupe(violations),
    normalizedSummary: {
      serviceCount: serviceNames.length,
      networkCount: Object.keys(config.networks ?? {}).length,
      volumeCount: Object.keys(config.volumes ?? {}).length,
      secretCount: Object.keys(secrets).length,
    },
  };
}

function parseArguments(argv) {
  if (argv.length !== 8) {
    throw new Error("arguments");
  }
  const parsed = {};
  const allowed = new Set(["--root", "--lock", "--config", "--env"]);
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    if (!allowed.has(flag) || Object.hasOwn(parsed, flag.slice(2)) || argv[index + 1].length === 0) {
      throw new Error("arguments");
    }
    parsed[flag.slice(2)] = argv[index + 1];
  }
  return parsed;
}

function parseDotenv(text) {
  const environment = new Map();
  for (const line of String(text ?? "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const separator = trimmed.indexOf("=");
    if (separator < 1) continue;
    environment.set(trimmed.slice(0, separator).trim(), trimmed.slice(separator + 1).trim());
  }
  return environment;
}

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, "utf8"));
}

function main() {
  try {
    const {
      root,
      lock: lockPath,
      config: configPath,
      env: environmentPath,
    } = parseArguments(process.argv.slice(2));
    const result = evaluateGreenfieldCoreAuthority(
      readJson(lockPath),
      readJson(configPath),
      parseDotenv(fs.readFileSync(environmentPath, "utf8")),
    );
    if (result.violations.length > 0) {
      process.stderr.write(`greenfield semantic authority rejected: ${result.violations.join(",")}\n`);
      process.exitCode = 65;
      return;
    }
    process.stdout.write(`${JSON.stringify({ violations: [], normalizedSummary: result.normalizedSummary })}\n`);
  } catch {
    process.stderr.write("greenfield semantic authority input invalid\n");
    process.exitCode = 65;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();
