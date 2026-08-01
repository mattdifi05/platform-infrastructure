#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const EXPECTED_HASHES = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["compose.networks.yaml", "f6cfb3b3857c1fd85414fbd7dc29c78a5f96ca9e7d309d8849cbb3400f66d759"],
]);

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function isStrictChild(parent, child) {
  const relative = path.relative(parent, child);
  return Boolean(relative)
    && relative !== ".."
    && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative);
}

function checkedRealDirectory(rawPath, label) {
  const unresolved = path.resolve(rawPath);
  const before = fs.lstatSync(unresolved);
  assert(before.isDirectory() && !before.isSymbolicLink(), `${label} must be a physical directory`);
  const physical = fs.realpathSync(unresolved);
  const after = fs.lstatSync(physical);
  assert(after.isDirectory() && !after.isSymbolicLink(), `${label} changed type during validation`);
  assert(before.dev === after.dev && before.ino === after.ino, `${label} changed identity during validation`);
  return physical;
}

function checkedRegularFile(filePath, label) {
  const entry = fs.lstatSync(filePath);
  assert(entry.isFile() && !entry.isSymbolicLink(), `${label} must be a physical regular file`);
  return fs.readFileSync(filePath);
}

function snapshotFlatDirectory(root) {
  const rootStat = fs.lstatSync(root);
  assert(rootStat.isDirectory() && !rootStat.isSymbolicLink(), "pre-existing target must remain a physical directory");
  const entries = fs.readdirSync(root).sort().map((name) => {
    const target = path.join(root, name);
    const stat = fs.lstatSync(target);
    assert(stat.isFile() && !stat.isSymbolicLink(), "pre-existing control may contain only physical regular files");
    const bytes = fs.readFileSync(target);
    return {
      name,
      dev: String(stat.dev),
      ino: String(stat.ino),
      mode: stat.mode,
      size: stat.size,
      hash: sha256(bytes),
    };
  });
  return JSON.stringify({
    dev: String(rootStat.dev),
    ino: String(rootStat.ino),
    mode: rootStat.mode,
    entries,
  });
}

function functionBlock(source, declaration, nextDeclaration) {
  const start = source.indexOf(declaration);
  assert(start >= 0, `missing source declaration: ${declaration}`);
  const end = source.indexOf(nextDeclaration, start + declaration.length);
  assert(end > start, `missing source boundary after: ${declaration}`);
  return source.slice(start, end);
}

function claimFreshFixture(target, token) {
  if (fs.existsSync(target)) {
    const error = new Error("target-exists");
    error.code = "TARGET_EXISTS";
    throw error;
  }
  fs.mkdirSync(target, { mode: 0o700 });
  fs.writeFileSync(
    path.join(target, `.network-set-lab-owner-${token}`),
    `network-set-lab:${token}\n`,
    { encoding: "ascii", flag: "wx", mode: 0o600 },
  );
}

function requiredNetworkSet(core, combined) {
  const missing = [];
  for (const [serviceName, coreService] of Object.entries(core.services ?? {})) {
    const actual = new Set(Object.keys(combined.services?.[serviceName]?.networks ?? {}));
    for (const required of Object.keys(coreService.networks ?? {})) {
      if (!actual.has(required)) missing.push(`${serviceName}:${required}`);
    }
  }
  if (missing.length > 0) throw new Error(`missing required protected networks: ${missing.join(",")}`);
  return true;
}

function candidateOutcome(validateRenderedWorkloads, core, combined, lock) {
  try {
    validateRenderedWorkloads({ core, combined, lock });
    return { accepted: true, error: "" };
  } catch (error) {
    return { accepted: false, error: String(error?.message ?? error) };
  }
}

function fixedOutcome(validateRenderedWorkloads, core, combined, lock) {
  try {
    requiredNetworkSet(core, combined);
    validateRenderedWorkloads({ core, combined, lock });
    return { accepted: true, error: "" };
  } catch (error) {
    return { accepted: false, error: String(error?.message ?? error) };
  }
}

const digest = "a".repeat(64);
const core = {
  services: {
    postgres: {
      image: `registry.example/postgres@sha256:${digest}`,
      networks: {
        platform_db_admin: null,
        platform_postgres: null,
      },
    },
  },
  networks: {
    platform_db_admin: { internal: true },
    platform_postgres: { internal: true },
  },
};

const lock = {
  workloads: [{
    id: "example-app",
    services: [{ name: "example-app-worker", role: "worker", routes: [] }],
    secrets: [],
  }],
};

const baseWorker = {
  image: `registry.example/example/worker@sha256:${digest}`,
  read_only: true,
  init: true,
  restart: "unless-stopped",
  security_opt: ["no-new-privileges:true"],
  cap_drop: ["ALL"],
  user: "1000:1000",
  pids_limit: 128,
  cpu_shares: 256,
  blkio_config: { weight: 300 },
  ulimits: { nofile: { soft: 8192, hard: 8192 } },
  cpus: 0.5,
  mem_limit: String(256 * 1024 * 1024),
  mem_reservation: String(64 * 1024 * 1024),
  healthcheck: { test: ["CMD", "node", "healthcheck.mjs"] },
  networks: { example_app_bus: null },
  labels: {
    "com.platform.workload-id": "example-app",
    "com.platform.workload-role": "worker",
  },
};

function renderedFixture(protectedNetworks, { sharePostgresZone = false } = {}) {
  const worker = structuredClone(baseWorker);
  const networks = {
    ...structuredClone(core.networks),
    example_app_bus: { internal: true },
  };
  if (sharePostgresZone) {
    worker.networks.example_app_postgres = null;
    networks.example_app_postgres = { internal: true };
  }
  return {
    services: {
      postgres: {
        ...structuredClone(core.services.postgres),
        networks: structuredClone(protectedNetworks),
      },
      "example-app-worker": worker,
    },
    networks,
  };
}

function missingNetworks(combined) {
  const actual = new Set(Object.keys(combined.services.postgres.networks ?? {}));
  return Object.keys(core.services.postgres.networks).filter((name) => !actual.has(name));
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 4) {
    console.error("usage: protected-network-set-probe.mjs SOURCE_ROOT WRAPPER_ROOT OWNER_SENTINEL PREEXISTING_ROOT");
    return 2;
  }

  const [sourceArg, wrapperArg, ownerSentinelArg, preexistingArg] = args;
  const wrapperRoot = checkedRealDirectory(wrapperArg, "wrapper root");
  const sourceRoot = checkedRealDirectory(sourceArg, "source root");
  const preexistingRoot = checkedRealDirectory(preexistingArg, "pre-existing root");
  assert(isStrictChild(wrapperRoot, sourceRoot), "source root escaped wrapper root");
  assert(isStrictChild(wrapperRoot, preexistingRoot), "pre-existing root escaped wrapper root");

  const ownerSentinel = path.resolve(ownerSentinelArg);
  assert(path.dirname(ownerSentinel) === wrapperRoot, "owner sentinel escaped wrapper root");
  const tokenMatch = /^\.network-set-owner-([a-f0-9]{64})$/.exec(path.basename(ownerSentinel));
  assert(tokenMatch, "invalid owner sentinel name");
  const token = tokenMatch[1];
  const sentinelBytes = checkedRegularFile(ownerSentinel, "owner sentinel");
  assert(sentinelBytes.equals(Buffer.from(`network-set:${token}\n`, "ascii")), "owner sentinel content mismatch");

  const loadedSources = new Map();
  for (const [relative, expected] of EXPECTED_HASHES) {
    const target = path.join(sourceRoot, relative);
    assert(isStrictChild(sourceRoot, path.resolve(target)), `source path escaped root: ${relative}`);
    const bytes = checkedRegularFile(target, relative);
    const actual = sha256(bytes);
    assert(actual === expected, `source hash mismatch for ${relative}: ${actual}`);
    loadedSources.set(relative, bytes.toString("utf8"));
  }

  const contractSource = loadedSources.get("scripts/hosted-workload-contract.mjs");
  const platformGuard = functionBlock(
    contractSource,
    "function assertPlatformServicesUnchanged(core, combined, workloadIds) {",
    "function assertResourceLimits(name, service) {",
  );
  assert(platformGuard.includes("same(objectWithoutNetworks(coreService), objectWithoutNetworks(combinedService))"), "network-excluding equality trace changed");
  assert(platformGuard.includes("const additions = [...combinedNetworks].filter((network) => !coreNetworks.has(network));"), "addition-only network trace changed");
  assert(!platformGuard.includes("!combinedNetworks.has(network)"), "candidate unexpectedly checks missing protected networks");

  const prepareSource = loadedSources.get("scripts/prepare-hosted-workloads.sh");
  assert(prepareSource.includes('config --format json > "$core_render"'), "core render path changed");
  assert(prepareSource.includes('config --format json > "$combined_render"'), "combined render path changed");
  assert(prepareSource.includes("scripts/hosted-workload-contract.mjs verify-render"), "render-verification path changed");

  const composeWrapperSource = loadedSources.get("scripts/compose-vps.sh");
  const coreFilesAt = composeWrapperSource.indexOf("compose+=(\n  -p");
  const workloadFilesAt = composeWrapperSource.indexOf('compose+=(-f "$workload_file")');
  assert(coreFilesAt >= 0 && workloadFilesAt > coreFilesAt, "workload overlay ordering changed");

  const networkSource = loadedSources.get("compose.networks.yaml");
  assert(/postgres:\n\s+networks: !override\n\s+- platform_db_admin\n\s+- platform_postgres/.test(networkSource), "protected postgres network baseline changed");
  assert(/platform_postgres:\n\s+name: [^\n]+\n\s+internal: true/.test(networkSource), "protected postgres network definition changed");

  const preexistingBefore = snapshotFlatDirectory(preexistingRoot);
  let preexistingRejected = false;
  try {
    claimFreshFixture(preexistingRoot, token);
  } catch (error) {
    preexistingRejected = error?.code === "TARGET_EXISTS";
  }
  assert(preexistingRejected, "probe did not reject a pre-existing fixture target");
  assert(snapshotFlatDirectory(preexistingRoot) === preexistingBefore, "pre-existing target changed during refusal");

  const labRoot = path.join(wrapperRoot, `network-set-model-${token.slice(0, 16)}`);
  assert(!fs.existsSync(labRoot), "owned model lab unexpectedly exists");
  claimFreshFixture(labRoot, token);

  const modulePath = path.join(sourceRoot, "scripts", "hosted-workload-contract.mjs");
  const candidateModule = await import(`${pathToFileURL(modulePath).href}?sha256=${EXPECTED_HASHES.get("scripts/hosted-workload-contract.mjs")}`);
  assert(typeof candidateModule.validateRenderedWorkloads === "function", "candidate validator export is missing");
  const validateRenderedWorkloads = candidateModule.validateRenderedWorkloads;

  const scenarios = [
    {
      name: "baseline",
      combined: renderedFixture({ platform_db_admin: null, platform_postgres: null }),
      vulnerable: false,
    },
    {
      name: "removal",
      combined: renderedFixture({ platform_db_admin: null }),
      vulnerable: true,
    },
    {
      name: "replacement",
      combined: renderedFixture({ platform_db_admin: null, example_app_postgres: null }, { sharePostgresZone: true }),
      vulnerable: true,
    },
    {
      name: "emptying",
      combined: renderedFixture({}),
      vulnerable: true,
    },
    {
      name: "alias_substitution",
      combined: renderedFixture({
        platform_db_admin: null,
        example_app_postgres: { aliases: ["platform_postgres"] },
      }, { sharePostgresZone: true }),
      vulnerable: true,
    },
    {
      name: "permitted_addition",
      combined: renderedFixture({
        platform_db_admin: null,
        platform_postgres: null,
        example_app_postgres: null,
      }, { sharePostgresZone: true }),
      vulnerable: false,
    },
  ];

  const results = scenarios.map((scenario) => {
    const candidate = candidateOutcome(validateRenderedWorkloads, core, scenario.combined, lock);
    const fixed = fixedOutcome(validateRenderedWorkloads, core, scenario.combined, lock);
    const missing = missingNetworks(scenario.combined);
    assert(candidate.accepted, `${scenario.name}: candidate unexpectedly rejected: ${candidate.error}`);
    if (scenario.vulnerable) {
      assert(missing.length > 0, `${scenario.name}: vulnerable scenario has no missing required network`);
      assert(!fixed.accepted && fixed.error.includes("missing required protected networks"), `${scenario.name}: fixed guard unexpectedly accepted`);
    } else {
      assert(missing.length === 0, `${scenario.name}: control lost a required network`);
      assert(fixed.accepted, `${scenario.name}: fixed guard unexpectedly rejected: ${fixed.error}`);
    }
    return { ...scenario, candidate, fixed, missing };
  });

  const mutation = renderedFixture({ platform_db_admin: null, platform_postgres: null });
  mutation.services.postgres.privileged = true;
  const mutationResult = candidateOutcome(validateRenderedWorkloads, core, mutation, lock);
  assert(!mutationResult.accepted && mutationResult.error.includes("changed protected platform service"), "closest non-network mutation control lost sensitivity");

  const unauthorized = renderedFixture({
    platform_db_admin: null,
    platform_postgres: null,
    foreign_network: null,
  });
  unauthorized.networks.foreign_network = { internal: true };
  const unauthorizedResult = candidateOutcome(validateRenderedWorkloads, core, unauthorized, lock);
  assert(!unauthorizedResult.accepted && unauthorizedResult.error.includes("non-workload network"), "closest unauthorized-addition control lost sensitivity");
  assert(snapshotFlatDirectory(preexistingRoot) === preexistingBefore, "pre-existing target changed after model execution");

  console.log(`[+] pinned-source hashes contract=${EXPECTED_HASHES.get("scripts/hosted-workload-contract.mjs")} prepare=${EXPECTED_HASHES.get("scripts/prepare-hosted-workloads.sh")} compose_wrapper=${EXPECTED_HASHES.get("scripts/compose-vps.sh")} network_overlay=${EXPECTED_HASHES.get("compose.networks.yaml")}`);
  console.log("[+] source-trace protected_service=postgres required=platform_db_admin,platform_postgres comparison=networks-excluded policy=additions-only");
  for (const result of results.filter((item) => item.vulnerable)) {
    const alias = result.name === "alias_substitution" ? " alias=platform_postgres" : "";
    console.log(`[VULNERABLE] ${result.name} candidate=ACCEPTED fixed_guard=REJECTED missing=${result.missing.join(",")}${alias}`);
  }
  console.log("[+] negative-control baseline candidate=ACCEPTED fixed_guard=ACCEPTED required_set=preserved");
  console.log("[+] negative-control permitted_addition candidate=ACCEPTED fixed_guard=ACCEPTED required_set=preserved added=example_app_postgres");
  console.log("[+] closest-controls non_network_mutation=REJECTED unauthorized_network_addition=REJECTED");
  console.log("[+] safety probe_child_processes=0 compose_processes=0 container_processes=0 containers=0 networks=0 services=0 live_access=0 network_attempts=0");
  console.log("[+] result=VULNERABLE_PROTECTED_NETWORK_SET_INTEGRITY");
  return 0;
}

try {
  process.exitCode = await main();
} catch (error) {
  console.error(`probe failed: ${error?.stack || error}`);
  process.exitCode = 1;
}
