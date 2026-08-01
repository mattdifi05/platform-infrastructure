#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const EXPECTED_SOURCES = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/hosted-workload-contract.test.mjs", "a5a92058fe2378695ce43af1067683d873cb7367eff0d98664cc0ff0fa3dde41"],
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
]);

function fail(message) {
  throw new Error(message);
}

function requireCondition(condition, message) {
  if (!condition) fail(message);
}

function sha256Bytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sha256File(filePath) {
  return sha256Bytes(fs.readFileSync(filePath));
}

function identity(filePath) {
  const stat = fs.lstatSync(filePath);
  return `${stat.dev}:${stat.ino}`;
}

function isWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === "" || (!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`));
}

function regularFileNoLink(filePath, label) {
  const stat = fs.lstatSync(filePath, { throwIfNoEntry: false });
  requireCondition(Boolean(stat), `${label} is missing`);
  requireCondition(stat.isFile() && !stat.isSymbolicLink(), `${label} must be a regular non-symlink file`);
  return stat;
}

function functionSlice(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  requireCondition(start >= 0 && end > start, `source markers are missing: ${startMarker}`);
  return source.slice(start, end);
}

function verifySourceProof(sourceRoot) {
  const sourceHashes = {};
  for (const [relativePath, expectedHash] of EXPECTED_SOURCES) {
    const fullPath = path.join(sourceRoot, relativePath);
    regularFileNoLink(fullPath, relativePath);
    const actualHash = sha256File(fullPath);
    requireCondition(actualHash === expectedHash, `source hash mismatch for ${relativePath}`);
    sourceHashes[relativePath] = actualHash;
    process.stdout.write(`[SOURCE] path=${relativePath} sha256=${actualHash}\n`);
  }

  const contract = fs.readFileSync(path.join(sourceRoot, "scripts/hosted-workload-contract.mjs"), "utf8");
  const contractTest = fs.readFileSync(path.join(sourceRoot, "scripts/hosted-workload-contract.test.mjs"), "utf8");
  const prepare = fs.readFileSync(path.join(sourceRoot, "scripts/prepare-hosted-workloads.sh"), "utf8");
  const compose = fs.readFileSync(path.join(sourceRoot, "scripts/compose-vps.sh"), "utf8");

  const resolver = functionSlice(contract, "export function resolveCatalog", "function objectWithoutNetworks");
  const environmentGuard = functionSlice(contract, "function assertEnvironmentSecrets", "function assertSecrets");
  const serviceGuard = functionSlice(contract, "function assertWorkloadService", "export function validateRenderedWorkloads");

  requireCondition(resolver.includes("workloadEnvironmentRecord(environmentPath, manifest.id)"), "declared environment lock record is absent");
  requireCondition(!resolver.includes("env_file"), "resolver unexpectedly handles service env_file");
  requireCondition(environmentGuard.includes("Object.entries(service.environment ?? {})"), "rendered environment loop is absent");
  requireCondition(environmentGuard.includes("PASSWORD|TOKEN|SECRET|DATABASE_URL|NATS_URL"), "expected terminal-name filter is absent");
  requireCondition(serviceGuard.includes("assertEnvironmentSecrets(name, serviceDefinition)"), "service environment validation call is absent");
  requireCondition(!serviceGuard.includes("env_file"), "service validator unexpectedly handles env_file");
  requireCondition(contractTest.includes('test("exact hardened workload render passes"'), "known-good upstream fixture is absent");

  const combinedRender = prepare.indexOf('bash "$SCRIPT_DIR/compose-vps.sh" config --format json > "$combined_render"');
  const verifyRender = prepare.indexOf("scripts/hosted-workload-contract.mjs verify-render");
  requireCondition(combinedRender >= 0 && verifyRender > combinedRender, "combined Compose render does not precede contract verification");
  const workloadOverlay = compose.indexOf('compose+=(-f "$workload_file")');
  const composeExec = compose.indexOf('exec "${compose[@]}" --profile backup "$@"');
  requireCondition(workloadOverlay >= 0 && composeExec > workloadOverlay, "workload overlay does not reach Compose execution");

  process.stdout.write(`[SOURCE] revision=${REVISION} tree=${TREE} files=${EXPECTED_SOURCES.size} provenance=git-archive\n`);
  process.stdout.write("[PASS] source proof declared env is locked, service env_file is unhandled, and combined Compose rendering precedes validation\n");
  return sourceHashes;
}

function writeOwnedFile(fixtureRoot, relativePath, value) {
  const target = path.resolve(fixtureRoot, relativePath);
  requireCondition(isWithin(fixtureRoot, target) && target !== fixtureRoot, `owned write escaped fixture: ${relativePath}`);
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const prior = fs.lstatSync(target, { throwIfNoEntry: false });
  requireCondition(!prior || (!prior.isSymbolicLink() && prior.isFile()), `refusing unsafe owned write: ${relativePath}`);
  fs.writeFileSync(target, value, { mode: 0o600 });
  return target;
}

function parseStrictSyntheticEnvironment(text) {
  const out = {};
  for (const [index, rawLine] of String(text).split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    requireCondition(separator > 0, `synthetic environment line ${index + 1} is not KEY=value`);
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1);
    requireCondition(/^[A-Z][A-Z0-9_]*$/.test(key), `synthetic environment key is invalid: ${key}`);
    requireCondition(!(key in out), `duplicate synthetic environment key: ${key}`);
    out[key] = value;
  }
  requireCondition(Object.keys(out).length > 0, "synthetic environment is empty");
  return out;
}

function readOnlyApprovedSyntheticEnv(requestedPath, fixtureRoot, approvedPhysicalFiles) {
  const lexicalPath = path.resolve(requestedPath);
  const physicalFixture = fs.realpathSync(fixtureRoot);
  requireCondition(isWithin(physicalFixture, lexicalPath), "synthetic env lexical path escaped the probe fixture");
  const terminal = fs.lstatSync(lexicalPath, { throwIfNoEntry: false });
  requireCondition(Boolean(terminal) && (terminal.isFile() || terminal.isSymbolicLink()), "synthetic env path is not a file or controlled symlink");
  const physicalPath = fs.realpathSync(lexicalPath);
  requireCondition(isWithin(physicalFixture, physicalPath), "synthetic env physical path escaped the probe fixture");
  requireCondition(approvedPhysicalFiles.has(physicalPath), "refusing to read a synthetic env file not created by this probe");
  regularFileNoLink(physicalPath, "approved synthetic env target");
  const bytes = fs.readFileSync(physicalPath);
  return {
    environment: parseStrictSyntheticEnvironment(bytes.toString("utf8")),
    sha256: sha256Bytes(bytes),
    lexicalPath,
    physicalPath,
  };
}

function fixedEnvFileOracle({ value, composeDirectory, workloadRoot, lock }) {
  requireCondition(typeof value === "string" && value.length > 0, "fixed oracle requires one env_file path");
  requireCondition(!path.isAbsolute(value), "fixed oracle rejects absolute env_file paths");
  requireCondition(!value.split(/[\\/]/).includes(".."), "fixed oracle rejects traversing env_file paths");

  const physicalRoot = fs.realpathSync(workloadRoot);
  const lexicalPath = path.resolve(composeDirectory, value);
  requireCondition(isWithin(physicalRoot, lexicalPath), "fixed oracle rejects env_file outside workload root");

  const relativeParts = path.relative(physicalRoot, lexicalPath).split(path.sep).filter(Boolean);
  let cursor = physicalRoot;
  for (const part of relativeParts) {
    cursor = path.join(cursor, part);
    const component = fs.lstatSync(cursor, { throwIfNoEntry: false });
    requireCondition(Boolean(component), "fixed oracle rejects missing env_file component");
    requireCondition(!component.isSymbolicLink(), "fixed oracle rejects symlinked env_file components");
  }
  regularFileNoLink(lexicalPath, "fixed-oracle env_file");
  const physicalPath = fs.realpathSync(lexicalPath);
  requireCondition(isWithin(physicalRoot, physicalPath), "fixed oracle rejects physical env_file escape");

  const record = (lock.files ?? []).find((item) => path.resolve(item.path) === physicalPath);
  requireCondition(Boolean(record), "fixed oracle requires a catalog-locked env_file");
  requireCondition(record.sha256 === sha256File(physicalPath), "fixed oracle rejects changed env_file bytes");
  return { physicalPath, recordKind: record.kind };
}

function fixedOracleRejects(input) {
  try {
    fixedEnvFileOracle(input);
    return false;
  } catch {
    return true;
  }
}

function expectValidatorReject(validateRenderedWorkloads, input, pattern) {
  try {
    validateRenderedWorkloads(input);
  } catch (error) {
    requireCondition(pattern.test(String(error.message)), `unexpected validator rejection: ${error.message}`);
    return String(error.message);
  }
  fail("validator unexpectedly accepted negative control");
}

function fixtureModels(environment, envFilePath, includeEnvFile) {
  const digest = "a".repeat(64);
  const core = {
    services: {
      "project-router": {
        image: `registry.example/router@sha256:${digest}`,
        networks: { platform_routing: null },
      },
    },
    networks: { platform_routing: { internal: true } },
  };
  const workloadService = {
    image: `registry.example/example/app@sha256:${digest}`,
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
    networks: { example_app_ingress: null },
    labels: {
      "com.platform.workload-id": "example-app",
      "com.platform.workload-role": "web",
    },
    environment: structuredClone(environment),
  };
  if (includeEnvFile) workloadService.env_file = [envFilePath];
  const combined = {
    services: {
      "project-router": {
        ...structuredClone(core.services["project-router"]),
        networks: { platform_routing: null, example_app_ingress: null },
      },
      "example-app-web": workloadService,
    },
    networks: {
      platform_routing: { internal: true },
      example_app_ingress: { internal: true },
    },
  };
  return { core, combined };
}

function cleanupOwnedFixture(target, ownership) {
  if (target !== ownership.root) return false;
  const stat = fs.lstatSync(target, { throwIfNoEntry: false });
  if (!stat?.isDirectory() || stat.isSymbolicLink() || identity(target) !== ownership.rootIdentity) return false;
  const sentinel = path.join(target, ".can193-probe-owner");
  const sentinelStat = fs.lstatSync(sentinel, { throwIfNoEntry: false });
  if (!sentinelStat?.isFile() || sentinelStat.isSymbolicLink()) return false;
  if (identity(sentinel) !== ownership.sentinelIdentity) return false;
  if (fs.readFileSync(sentinel, "utf8") !== `can193-probe:${ownership.token}\n`) return false;
  fs.rmSync(target, { recursive: true });
  return !fs.existsSync(target);
}

async function main() {
  const [sourceInput, wrapperInput, sentinelInput, ownerToken, extra] = process.argv.slice(2);
  requireCondition(Boolean(sourceInput && wrapperInput && sentinelInput && ownerToken) && extra === undefined, "probe requires its source-pinned wrapper");
  requireCondition(/^[a-f0-9]{64}$/.test(ownerToken), "invalid wrapper ownership token");

  const wrapperRoot = fs.realpathSync(wrapperInput);
  const sourceRoot = fs.realpathSync(sourceInput);
  requireCondition(sourceRoot === path.join(wrapperRoot, "source"), "source archive is outside the wrapper root");
  requireCondition(sentinelInput === path.join(wrapperRoot, ".hosted-env-boundary-wrapper-owner"), "unexpected wrapper sentinel path");
  regularFileNoLink(sentinelInput, "wrapper ownership sentinel");
  requireCondition(fs.readFileSync(sentinelInput, "utf8") === `hosted-env-boundary:${ownerToken}\n`, "wrapper ownership sentinel mismatch");

  const sourceHashes = verifySourceProof(sourceRoot);
  const contractPath = path.join(sourceRoot, "scripts/hosted-workload-contract.mjs");
  const contract = await import(`${pathToFileURL(contractPath).href}?can193=${REVISION}`);
  const { resolveCatalog, validateRenderedWorkloads, verifyLockFiles } = contract;
  requireCondition(typeof resolveCatalog === "function", "exact resolveCatalog export is unavailable");
  requireCondition(typeof validateRenderedWorkloads === "function", "exact validateRenderedWorkloads export is unavailable");
  requireCondition(typeof verifyLockFiles === "function", "exact verifyLockFiles export is unavailable");

  const guardRoot = path.join(wrapperRoot, "preexisting-cleanup-control");
  fs.mkdirSync(guardRoot, { mode: 0o700 });
  const guardMarker = path.join(guardRoot, "preserve.marker");
  fs.writeFileSync(guardMarker, "PRESERVE-CAN193\n", { mode: 0o600 });
  const guardBefore = {
    identity: identity(guardMarker),
    size: fs.lstatSync(guardMarker).size,
    sha256: sha256File(guardMarker),
  };

  const fixtureRoot = path.join(wrapperRoot, "can193-owned-fixture");
  requireCondition(!fs.existsSync(fixtureRoot), "owned fixture path already exists");
  fs.mkdirSync(fixtureRoot, { mode: 0o700 });
  const fixtureSentinel = path.join(fixtureRoot, ".can193-probe-owner");
  fs.writeFileSync(fixtureSentinel, `can193-probe:${ownerToken}\n`, { mode: 0o600 });
  const ownership = {
    root: fixtureRoot,
    rootIdentity: identity(fixtureRoot),
    sentinelIdentity: identity(fixtureSentinel),
    token: ownerToken,
  };

  const refusedUnownedCleanup = !cleanupOwnedFixture(guardRoot, ownership);
  const guardAfter = {
    identity: identity(guardMarker),
    size: fs.lstatSync(guardMarker).size,
    sha256: sha256File(guardMarker),
  };
  requireCondition(refusedUnownedCleanup && JSON.stringify(guardBefore) === JSON.stringify(guardAfter), "cleanup guard changed the unowned marker");
  process.stdout.write(`[GUARD] unowned_cleanup_refused=true preexisting_sha256=${guardAfter.sha256}\n`);

  let completed = false;
  try {
    const workloadRoot = path.join(fixtureRoot, "workload-root");
    const appRoot = path.join(workloadRoot, "example-app");
    const syntheticHostRoot = path.join(fixtureRoot, "synthetic-host");
    fs.mkdirSync(appRoot, { recursive: true, mode: 0o700 });
    fs.mkdirSync(syntheticHostRoot, { recursive: true, mode: 0o700 });

    const externalInitialText = [
      "AWS_ACCESS_KEY_ID=SYNTHETIC_CAN193_ACCESS_ID",
      "AWS_SECRET_ACCESS_KEY=SYNTHETIC_CAN193_ACCESS_KEY",
      "CLOUDFLARE_API_KEY=SYNTHETIC_CAN193_PROVIDER_KEY",
      "",
    ].join("\n");
    const externalMutatedText = [
      "AWS_ACCESS_KEY_ID=SYNTHETIC_CAN193_ROTATED_ID",
      "AWS_SECRET_ACCESS_KEY=SYNTHETIC_CAN193_ROTATED_KEY",
      "CLOUDFLARE_API_KEY=SYNTHETIC_CAN193_ROTATED_PROVIDER_KEY",
      "",
    ].join("\n");
    const declaredText = "EXAMPLE_APP_SMTP_HOST=mail.synthetic.invalid\n";

    const externalEnv = writeOwnedFile(fixtureRoot, "synthetic-host/credential-shaped.env", externalInitialText);
    const declaredEnv = writeOwnedFile(fixtureRoot, "workload-root/example-app/declared.env", declaredText);
    const manifestPath = writeOwnedFile(fixtureRoot, "workload-root/example-app/manifest.json", `${JSON.stringify({
      version: 1,
      id: "example-app",
      composeFile: "compose.platform.yaml",
      secrets: [],
      migrationRoots: [],
      services: [{ name: "example-app-web", role: "web", routes: [{ slug: "example", port: 3000 }] }],
    }, null, 2)}\n`);
    const composePath = writeOwnedFile(fixtureRoot, "workload-root/example-app/compose.platform.yaml", [
      "services:",
      "  example-app-web:",
      `    env_file: ${externalEnv}`,
      "",
    ].join("\n"));
    const catalogPath = writeOwnedFile(fixtureRoot, "catalog.json", `${JSON.stringify({
      version: 1,
      workloads: [{ manifest: "example-app/manifest.json", environmentFile: "example-app/declared.env" }],
    }, null, 2)}\n`);
    const coreEnv = writeOwnedFile(fixtureRoot, "core.env", "COMPOSE_PROJECT_NAME=can193_synthetic\n");

    requireCondition(fs.realpathSync(manifestPath) === path.join(appRoot, "manifest.json"), "manifest fixture path mismatch");
    requireCondition(fs.realpathSync(composePath) === path.join(appRoot, "compose.platform.yaml"), "compose fixture path mismatch");
    requireCondition(fs.realpathSync(declaredEnv) === path.join(appRoot, "declared.env"), "declared env fixture path mismatch");

    const approvedPhysicalFiles = new Set([fs.realpathSync(externalEnv), fs.realpathSync(declaredEnv)]);
    const lock = resolveCatalog({
      catalogPath,
      workloadRoot,
      coreEnvFile: coreEnv,
      coreFiles: [],
      projectName: "can193_synthetic",
    });
    const externalRecorded = lock.files.some((record) => path.resolve(record.path) === fs.realpathSync(externalEnv));
    requireCondition(!externalRecorded, "external service env_file unexpectedly entered the exact lock");

    const external = readOnlyApprovedSyntheticEnv(externalEnv, fixtureRoot, approvedPhysicalFiles);
    const absoluteModels = fixtureModels(external.environment, externalEnv, true);
    validateRenderedWorkloads({ ...absoluteModels, lock });
    const postRenderModels = fixtureModels(external.environment, externalEnv, false);
    validateRenderedWorkloads({ ...postRenderModels, lock });
    const absoluteFixedReject = fixedOracleRejects({ value: externalEnv, composeDirectory: appRoot, workloadRoot, lock });
    requireCondition(absoluteFixedReject, "fixed oracle accepted absolute external env_file");
    process.stdout.write(`[VULNERABLE CAN-193] case=absolute-external-env-file lock_recorded=false field_present=accepted post_render=accepted fixed_oracle=reject keys=${Object.keys(external.environment).sort().join(",")}\n`);

    const traversalValue = "../../synthetic-host/credential-shaped.env";
    const traversalPath = path.resolve(appRoot, traversalValue);
    const traversal = readOnlyApprovedSyntheticEnv(traversalPath, fixtureRoot, approvedPhysicalFiles);
    validateRenderedWorkloads({ ...fixtureModels(traversal.environment, traversalValue, true), lock });
    requireCondition(fixedOracleRejects({ value: traversalValue, composeDirectory: appRoot, workloadRoot, lock }), "fixed oracle accepted traversal env_file");
    process.stdout.write("[VULNERABLE] case=relative-traversal physical_outside_workload=true validator=accepted fixed_oracle=reject\n");

    const linkedEnv = path.join(appRoot, "linked.env");
    fs.symlinkSync(path.relative(appRoot, externalEnv), linkedEnv);
    const linked = readOnlyApprovedSyntheticEnv(linkedEnv, fixtureRoot, approvedPhysicalFiles);
    validateRenderedWorkloads({ ...fixtureModels(linked.environment, "linked.env", true), lock });
    requireCondition(fixedOracleRejects({ value: "linked.env", composeDirectory: appRoot, workloadRoot, lock }), "fixed oracle accepted symlinked env_file");
    process.stdout.write("[VULNERABLE] case=symlinked-contained-name physical_outside_workload=true validator=accepted fixed_oracle=reject\n");

    const suffixControl = fixtureModels({ DATABASE_PASSWORD: "SYNTHETIC_CAN193_CONTROL" }, externalEnv, false);
    const suffixMessage = expectValidatorReject(validateRenderedWorkloads, { ...suffixControl, lock }, /sensitive environment variable DATABASE_PASSWORD/);
    requireCondition(suffixMessage.includes("DATABASE_PASSWORD"), "negative suffix control did not identify the key");
    process.stdout.write("[CONTROL] case=blocked-terminal-name key=DATABASE_PASSWORD validator=reject\n");

    const safePolicy = fixedEnvFileOracle({ value: "declared.env", composeDirectory: appRoot, workloadRoot, lock });
    const safe = readOnlyApprovedSyntheticEnv(declaredEnv, fixtureRoot, approvedPhysicalFiles);
    validateRenderedWorkloads({ ...fixtureModels(safe.environment, "declared.env", true), lock });
    process.stdout.write(`[NEGATIVE CONTROL] case=contained-locked-env-file record_kind=${safePolicy.recordKind} validator=accepted fixed_oracle=accepted\n`);

    fs.writeFileSync(externalEnv, externalMutatedText, { mode: 0o600 });
    const lockStillValid = verifyLockFiles(lock);
    requireCondition(lockStillValid === true, "exact lock unexpectedly failed after untracked env_file mutation");
    const mutated = readOnlyApprovedSyntheticEnv(externalEnv, fixtureRoot, approvedPhysicalFiles);
    validateRenderedWorkloads({ ...fixtureModels(mutated.environment, externalEnv, false), lock });
    requireCondition(mutated.sha256 !== external.sha256, "synthetic mutation did not change env_file bytes");
    process.stdout.write("[VULNERABLE] case=untracked-env-file-mutation lock_still_valid=true post_render=accepted bytes_changed=true\n");

    const receipt = {
      revision: REVISION,
      tree: TREE,
      sourceHashes,
      sourceProof: {
        declaredEnvironmentLocked: true,
        serviceEnvFileUnhandled: true,
        composeBeforeValidation: true,
      },
      cases: {
        absolute: { externalRecorded, currentAccepted: true, fixedRejected: absoluteFixedReject },
        traversal: { currentAccepted: true, fixedRejected: true },
        symlink: { currentAccepted: true, fixedRejected: true },
        suffixControl: { key: "DATABASE_PASSWORD", currentRejected: true },
        containedNegativeControl: { currentAccepted: true, fixedAccepted: true },
        mutation: { lockStillValid: true, currentAccepted: true, bytesChanged: true },
      },
      syntheticHashes: {
        initialExternal: external.sha256,
        mutatedExternal: mutated.sha256,
        declared: safe.sha256,
      },
      safety: {
        fixtureConfinedReads: true,
        realEnvironmentReads: 0,
        dockerCalls: 0,
        networkAttempts: 0,
        liveMutations: 0,
        sourceMutations: 0,
      },
    };
    process.stdout.write(`[RECEIPT] sha256=${sha256Bytes(JSON.stringify(receipt))} scope=wrapper-owned-synthetic-fixture\n`);
    process.stdout.write("[SAFE] real_env_reads=0 credentials_read=0 docker_calls=0 network_attempts=0 services_started=0 live_mutations=0 source_mutations=0\n");
    completed = true;
  } finally {
    const removed = cleanupOwnedFixture(fixtureRoot, ownership);
    requireCondition(removed, "owned fixture cleanup or sentinel validation failed");
    requireCondition(fs.existsSync(guardMarker) && JSON.stringify(guardBefore) === JSON.stringify({
      identity: identity(guardMarker),
      size: fs.lstatSync(guardMarker).size,
      sha256: sha256File(guardMarker),
    }), "preexisting guard marker changed during probe cleanup");
    process.stdout.write("[+] cleanup sentinel_owned_fixture_removed=true preexisting_marker_preserved=true\n");
  }

  requireCondition(completed, "probe did not complete");
  process.stdout.write("[+] result=VULNERABLE canonical_id=CAN-193\n");
}

main().catch((error) => {
  process.stderr.write(`[!] ${error.message}\n`);
  process.exitCode = 1;
});
