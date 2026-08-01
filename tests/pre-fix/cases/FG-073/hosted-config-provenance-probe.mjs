#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const EXPECTED_HASHES = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["scripts/hosted-workload-contract.test.mjs", "a5a92058fe2378695ce43af1067683d873cb7367eff0d98664cc0ff0fa3dde41"],
]);

const [mode, sourceArgument, runRootArgument, wrapperArgument, sentinelArgument] = process.argv.slice(2);
if (!mode || !sourceArgument || !runRootArgument || !wrapperArgument || !sentinelArgument) {
  throw new Error("direct invocation denied: use run-from-git-archive.sh with its wrapper-owned archive");
}
assert.ok(mode === "guard" || mode === "run", "mode must be guard or run");

const wrapperRoot = exactPhysicalDirectory(wrapperArgument, "wrapper root");
const runRoot = exactPhysicalDirectory(runRootArgument, "run root");
assert.equal(path.dirname(runRoot), wrapperRoot, "run root must be an exact wrapper child");
assert.match(path.basename(runRoot), mode === "guard" ? /^guard\.[A-Za-z0-9]+$/ : /^run\.[A-Za-z0-9]+$/);

const sourceRoot = exactPhysicalDirectory(sourceArgument, "source archive");
assert.equal(sourceRoot, path.join(wrapperRoot, "source"), "source archive must be the exact wrapper child");

const sentinelPath = path.resolve(sentinelArgument);
const sentinelStat = fs.lstatSync(sentinelPath);
assert.equal(sentinelStat.isFile(), true, "wrapper ownership sentinel is not a regular file");
assert.equal(sentinelStat.isSymbolicLink(), false, "wrapper ownership sentinel is a symbolic link");
assert.equal(fs.realpathSync(sentinelPath), sentinelPath, "wrapper ownership sentinel must use its physical path");
assert.equal(path.dirname(sentinelPath), wrapperRoot, "wrapper ownership sentinel escaped its root");
const sentinelMatch = path.basename(sentinelPath).match(/^\.fg073-wrapper-owner-([0-9a-f]{64})$/);
assert.ok(sentinelMatch, "wrapper ownership sentinel name is invalid");
const ownerToken = sentinelMatch[1];
assert.equal(
  fs.readFileSync(sentinelPath, "utf8"),
  `fg073-hosted-config:${ownerToken}\n`,
  "wrapper ownership sentinel content is invalid",
);

for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expectedHash, `${relativePath} is not the expected source`);
}

const outputRoot = path.join(runRoot, "poc-output");
if (fs.existsSync(outputRoot)) {
  throw new Error("refusing to overwrite pre-existing output target: poc-output");
}
if (mode === "guard") {
  throw new Error("guard mode requires a pre-existing output target");
}

const outputOwnership = claimOwnedDirectory(outputRoot, runRoot, ownerToken);
let receiptHash = null;

try {
  const contractSource = readSource("scripts/hosted-workload-contract.mjs");
  const composeVpsSource = readSource("scripts/compose-vps.sh");
  const prepareSource = readSource("scripts/prepare-hosted-workloads.sh");
  const contractTestSource = readSource("scripts/hosted-workload-contract.test.mjs");

  const environmentValidatorSource = sliceBetween(
    contractSource,
    "export function validateWorkloadEnvironmentText(text, workloadId, label = \"workload environment\") {",
    "\nfunction workloadEnvironmentRecord(filePath, workloadId) {",
  );
  const catalogResolverSource = sliceBetween(
    contractSource,
    "export function resolveCatalog({ catalogPath, workloadRoot, coreEnvFile, coreFiles, projectName }) {",
    "\nfunction objectWithoutNetworks(service) {",
  );
  const environmentControlSource = sliceBetween(
    contractSource,
    "function assertEnvironmentSecrets(name, service) {",
    "\nfunction assertSecrets(name, service, manifest, combined) {",
  );
  const secretControlSource = sliceBetween(
    contractSource,
    "function assertSecrets(name, service, manifest, combined) {",
    "\nfunction assertVolumes(name, service, workloadId) {",
  );
  const serviceValidatorSource = sliceBetween(
    contractSource,
    "function assertWorkloadService({ serviceDefinition, manifestService, manifest, combined }) {",
    "\nexport function validateRenderedWorkloads({ core, combined, lock }) {",
  );
  const renderedValidatorSource = sliceBetween(
    contractSource,
    "export function validateRenderedWorkloads({ core, combined, lock }) {",
    "\nexport function verifyLockFiles(lock) {",
  );

  assert.match(environmentValidatorSource, /PASSWORD\|TOKEN\|SECRET\|DATABASE_URL\|NATS_URL/);
  assert.match(environmentValidatorSource, /unsupported interpolation or control characters/);
  assert.match(catalogResolverSource, /fileRecord\(path\.resolve\(coreEnvFile\), "core-environment"\)/);
  assert.match(catalogResolverSource, /fileRecord\(composePath, "workload-compose"\)/);
  assert.doesNotMatch(catalogResolverSource, /config(?:s|Source|File)/);
  assert.match(environmentControlSource, /Object\.entries\(service\.environment \?\? \{\}\)/);
  assert.match(environmentControlSource, /use a Docker secret file/);
  assert.match(secretControlSource, /service\.secrets \?\? \[\]/);
  assert.match(secretControlSource, /combined\.secrets\?\.\[source\]\?\.external !== true/);
  assert.doesNotMatch(serviceValidatorSource, /\bconfigs\b/);
  assert.doesNotMatch(renderedValidatorSource, /\bconfigs\b/);
  assert.doesNotMatch(contractTestSource, /\bconfigs\b/);

  const coreEnvOptionIndex = composeVpsSource.indexOf('--env-file "$ENV_FILE"');
  const workloadEnvOptionIndex = composeVpsSource.indexOf('compose+=(--env-file "$workload_env_file")');
  const workloadComposeIndex = composeVpsSource.indexOf('compose+=(-f "$workload_file")');
  assert.ok(coreEnvOptionIndex >= 0, "core env option is absent");
  assert.ok(workloadEnvOptionIndex > coreEnvOptionIndex, "workload env should be appended after the core env");
  assert.ok(workloadComposeIndex > workloadEnvOptionIndex, "workload Compose file should be appended after env options");
  assert.match(prepareSource, /compose-vps\.sh" config --format json > "\$combined_render"/);
  assert.match(prepareSource, /--combinedRender "\$combined_render"/);
  assert.match(prepareSource, /--envFile "\$ENV_FILE"/);

  const candidateModulePath = path.join(sourceRoot, "scripts/hosted-workload-contract.mjs");
  const candidateModule = await import(`${pathToFileURL(candidateModulePath).href}?source=${EXPECTED_HASHES.get("scripts/hosted-workload-contract.mjs")}`);
  const { validateRenderedWorkloads, validateWorkloadManifest } = candidateModule;
  assert.equal(typeof validateRenderedWorkloads, "function");
  assert.equal(typeof validateWorkloadManifest, "function");

  const fixture = buildFixture(validateWorkloadManifest);
  const baseline = validateRenderedWorkloads({ core: fixture.core, combined: fixture.combined(), lock: fixture.lock });
  assert.equal(baseline.routes.length, 1);

  const directEnvironment = fixture.combined();
  directEnvironment.services[fixture.webService].environment.SYNTHETIC_PLATFORM_TOKEN = "synthetic-marker-only";
  assert.throws(
    () => validateRenderedWorkloads({ core: fixture.core, combined: directEnvironment, lock: fixture.lock }),
    /sensitive environment variable/,
  );

  const nonExternalSecret = fixture.combined();
  nonExternalSecret.secrets[fixture.allowedSecret] = { file: "synthetic-path-not-read" };
  assert.throws(
    () => validateRenderedWorkloads({ core: fixture.core, combined: nonExternalSecret, lock: fixture.lock }),
    /must be external/,
  );

  const environmentConfigName = "example-app-platform-env";
  const environmentConfig = fixture.combined();
  environmentConfig.configs = {
    [environmentConfigName]: { environment: "SYNTHETIC_PLATFORM_SECRET" },
  };
  environmentConfig.services[fixture.webService].configs = [{
    source: environmentConfigName,
    target: "/run/configs/platform-value",
    mode: "0444",
  }];
  const environmentAcceptance = validateRenderedWorkloads({
    core: fixture.core,
    combined: environmentConfig,
    lock: fixture.lock,
  });
  assert.equal(environmentAcceptance.routes.length, 1);

  const contentConfigName = "example-app-platform-content";
  const syntheticPlatformValue = "SYNTHETIC_PLATFORM_VALUE_NOT_A_REAL_SECRET";
  const contentConfig = fixture.combined();
  contentConfig.configs = {
    [contentConfigName]: { content: `token=${syntheticPlatformValue}` },
  };
  contentConfig.services[fixture.webService].configs = [{
    source: contentConfigName,
    target: "/run/configs/platform-content",
    mode: "0444",
  }];
  const contentAcceptance = validateRenderedWorkloads({
    core: fixture.core,
    combined: contentConfig,
    lock: fixture.lock,
  });
  assert.equal(contentAcceptance.routes.length, 1);

  const syntheticEnvironment = Object.freeze(Object.assign(Object.create(null), {
    SYNTHETIC_PLATFORM_SECRET: syntheticPlatformValue,
  }));
  const modelEnvironmentBytes = modelComposeConfigBytes(
    environmentConfig.configs[environmentConfigName],
    syntheticEnvironment,
  );
  const modelContentBytes = modelComposeConfigBytes(
    { content: "token=${SYNTHETIC_PLATFORM_SECRET}" },
    syntheticEnvironment,
  );
  assert.equal(modelEnvironmentBytes, syntheticEnvironment.SYNTHETIC_PLATFORM_SECRET);
  assert.equal(modelContentBytes, `token=${syntheticEnvironment.SYNTHETIC_PLATFORM_SECRET}`);
  assert.equal(contentConfig.configs[contentConfigName].content, modelContentBytes);

  const safeBytes = "synthetic non-sensitive workload configuration\n";
  const safeHash = sha256Text(safeBytes);
  const safeRequest = {
    workloadId: "example-app",
    configName: "example-app-safe-config",
    definition: { file: "config/application.ini" },
    mount: { source: "example-app-safe-config", target: "/run/configs/application.ini", mode: "0400" },
    provenance: {
      workloadId: "example-app",
      logicalPath: "config/application.ini",
      regularFile: true,
      symlink: false,
      physicalContained: true,
      immutable: true,
      expectedSha256: safeHash,
      actualSha256: safeHash,
    },
  };
  const safeDecision = fixedConfigAdmission(safeRequest);
  assert.deepEqual(safeDecision, { decision: "accepted", reason: "contained-workload-owned-hash-locked-file" });

  const platformVariableDecision = fixedConfigAdmission({
    ...safeRequest,
    definition: { environment: "SYNTHETIC_PLATFORM_SECRET" },
  });
  assert.deepEqual(platformVariableDecision, { decision: "rejected", reason: "environment-backed-config" });

  const literalContentDecision = fixedConfigAdmission({
    ...safeRequest,
    definition: { content: "synthetic-literal-credential-marker" },
  });
  assert.deepEqual(literalContentDecision, { decision: "rejected", reason: "inline-content-config" });

  const externalDecision = fixedConfigAdmission({
    ...safeRequest,
    definition: { external: true, name: "synthetic-provider-config" },
  });
  assert.deepEqual(externalDecision, { decision: "rejected", reason: "external-config" });

  const outOfRootDecision = fixedConfigAdmission({
    ...safeRequest,
    definition: { file: "/synthetic/outside/config.ini" },
    provenance: { ...safeRequest.provenance, logicalPath: "/synthetic/outside/config.ini", physicalContained: false },
  });
  assert.deepEqual(outOfRootDecision, { decision: "rejected", reason: "config-path-not-contained" });

  const symlinkDecision = fixedConfigAdmission({
    ...safeRequest,
    provenance: { ...safeRequest.provenance, regularFile: false, symlink: true },
  });
  assert.deepEqual(symlinkDecision, { decision: "rejected", reason: "config-source-symlink" });

  const mutableDecision = fixedConfigAdmission({
    ...safeRequest,
    provenance: { ...safeRequest.provenance, immutable: false, actualSha256: sha256Text(`${safeBytes}changed`) },
  });
  assert.deepEqual(mutableDecision, { decision: "rejected", reason: "config-source-mutable" });

  const wrongOwnerDecision = fixedConfigAdmission({
    ...safeRequest,
    provenance: { ...safeRequest.provenance, workloadId: "different-app" },
  });
  assert.deepEqual(wrongOwnerDecision, { decision: "rejected", reason: "config-source-not-workload-owned" });

  const generatedAt = new Date().toISOString();
  const receipt = {
    schema: "hosted-config-secret-provenance-poc/v1",
    generatedAt,
    finding: "CAN-219",
    input: {
      revision: REVISION,
      tree: TREE,
      archiveSha256: process.env.FG073_ARCHIVE_SHA256 ?? null,
    },
    sourceHashes: Object.fromEntries(EXPECTED_HASHES),
    sourceProof: {
      coreEnvSuppliedToCompose: true,
      workloadComposeIncludedInCombinedRender: true,
      directSensitiveServiceEnvironmentRejected: true,
      nonExternalServiceSecretRejected: true,
      serviceConfigsChecked: false,
      topLevelConfigsChecked: false,
      checkedInConfigRegressionTests: 0,
      environmentConfigAccepted: environmentAcceptance.routes.length === 1,
      renderedContentConfigAccepted: contentAcceptance.routes.length === 1,
    },
    semanticModel: {
      kind: "synthetic-compose-semantics-model-only",
      environmentConfigSha256: sha256Text(modelEnvironmentBytes),
      contentConfigSha256: sha256Text(modelContentBytes),
      realCoreEnvironmentRead: false,
      composeRuntimeExecuted: false,
      containerMountExecuted: false,
    },
    fixedControl: {
      platformVariable: platformVariableDecision,
      literalContent: literalContentDecision,
      external: externalDecision,
      outOfRoot: outOfRootDecision,
      symlink: symlinkDecision,
      mutable: mutableDecision,
      wrongOwner: wrongOwnerDecision,
      safeHashLockedFile: safeDecision,
    },
    externalConditions: {
      literalSensitiveValueInCoreEnvironment: "NOT-TESTED",
      compatibleComposeConfigProvider: "NOT-EXECUTED",
      deploymentOfAcceptedOverlay: "NOT-TESTED",
    },
    safety: {
      coreEnvironmentReads: 0,
      secretReads: 0,
      dockerCalls: 0,
      composeCalls: 0,
      deployments: 0,
      mounts: 0,
      networkCalls: 0,
      sourceMutations: 0,
    },
    result: "VULNERABLE-SOURCE-GAP-CONDITIONAL",
    finalGate: "PENDING-ENVIRONMENT-AND-RUNTIME",
  };

  const receiptPath = path.join(outputRoot, "hosted-config-provenance-receipt.json");
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  assert.deepEqual(JSON.parse(fs.readFileSync(receiptPath, "utf8")), receipt);
  receiptHash = sha256File(receiptPath);

  console.log("[+] confinement wrapper_realpath_exact=true source_exact_child=true sentinel_valid=true");
  console.log("[+] source_hashes contract=true compose_vps=true prepare=true tests=true");
  console.log("[SOURCE] core_env_supplied_to_compose=true service_configs_checked=false top_level_configs_checked=false");
  console.log("[CONTROL] direct_sensitive_service_environment=REJECTED non_external_service_secret=REJECTED");
  console.log("[VULNERABLE] environment_config_accepted=true rendered_content_config_accepted=true");
  console.log("[MODEL] synthetic_environment_to_config_bytes=true synthetic_content_interpolation_to_config_bytes=true runtime=NOT-EXECUTED");
  console.log("[FIXED-CONTROL] platform_variable=REJECTED literal_content=REJECTED external=REJECTED symlink=REJECTED mutable=REJECTED safe_hash_locked_file=ACCEPTED");
  console.log("[CONDITIONAL] literal_sensitive_core_value=NOT-TESTED compose_runtime_materialization=NOT-EXECUTED");
  console.log(`[RECEIPT] generated_at=${generatedAt} sha256=${receiptHash}`);
  console.log("[+] result=VULNERABLE-SOURCE-GAP-CONDITIONAL final_gate=PENDING-ENVIRONMENT-AND-RUNTIME");
  console.log("[+] safety core_env_reads=0 secret_reads=0 docker_calls=0 compose_calls=0 deployments=0 mounts=0 network_calls=0 source_mutations=0");
} finally {
  cleanupOwnedDirectory(outputOwnership);
}

assert.match(receiptHash ?? "", /^[a-f0-9]{64}$/);
assert.equal(fs.existsSync(outputRoot), false, "sentinel-owned output was not removed");
console.log("[+] cleanup sentinel_owned_output_removed=true");

function buildFixture(validateWorkloadManifest) {
  const digest = "a".repeat(64);
  const manifest = validateWorkloadManifest({
    version: 1,
    id: "example-app",
    composeFile: "compose.platform.yaml",
    secrets: ["example-app-database-url"],
    migrationRoots: ["postgres/migrations"],
    services: [
      { name: "example-app-web", role: "web", routes: [{ slug: "example", port: 3000 }] },
      { name: "example-app-worker", role: "worker" },
    ],
  });
  const baseService = {
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
    labels: { "com.platform.workload-id": "example-app", "com.platform.workload-role": "web" },
  };
  const core = {
    services: {
      "project-router": {
        image: `registry.example/router@sha256:${digest}`,
        networks: { platform_routing: null },
      },
    },
    networks: { platform_routing: { internal: true } },
  };
  const combined = () => ({
    services: {
      "project-router": {
        ...core.services["project-router"],
        networks: { platform_routing: null, example_app_ingress: null },
      },
      "example-app-web": {
        ...structuredClone(baseService),
        secrets: [{ source: "example-app-database-url", target: "example-app-database-url" }],
        environment: { DATABASE_URL_FILE: "/run/secrets/example-app-database-url" },
      },
      "example-app-worker": {
        ...structuredClone(baseService),
        networks: { example_app_bus: null },
        labels: { "com.platform.workload-id": "example-app", "com.platform.workload-role": "worker" },
      },
    },
    networks: {
      platform_routing: { internal: true },
      example_app_ingress: { internal: true },
      example_app_bus: { internal: true },
    },
    secrets: { "example-app-database-url": { external: true } },
  });
  return {
    core,
    combined,
    lock: { workloads: [manifest] },
    webService: "example-app-web",
    allowedSecret: "example-app-database-url",
  };
}

function modelComposeConfigBytes(definition, syntheticEnvironment) {
  assert.equal(Object.getPrototypeOf(syntheticEnvironment), null, "synthetic environment must have a null prototype");
  if (Object.hasOwn(definition, "environment")) {
    const name = String(definition.environment);
    assert.equal(Object.hasOwn(syntheticEnvironment, name), true, "synthetic variable is absent");
    return String(syntheticEnvironment[name]);
  }
  if (Object.hasOwn(definition, "content")) {
    return String(definition.content).replace(/\$\{([A-Z][A-Z0-9_]*)\}/g, (_match, name) => {
      assert.equal(Object.hasOwn(syntheticEnvironment, name), true, `synthetic interpolation variable is absent: ${name}`);
      return String(syntheticEnvironment[name]);
    });
  }
  throw new Error("semantic model supports only synthetic environment or content definitions");
}

function fixedConfigAdmission(request) {
  const { definition, provenance, workloadId, configName, mount } = request;
  if (Object.hasOwn(definition, "environment")) return { decision: "rejected", reason: "environment-backed-config" };
  if (Object.hasOwn(definition, "content")) return { decision: "rejected", reason: "inline-content-config" };
  if (definition.external === true) return { decision: "rejected", reason: "external-config" };
  if (typeof definition.file !== "string" || path.posix.isAbsolute(definition.file) || definition.file.split("/").includes("..")) {
    return { decision: "rejected", reason: "config-path-not-contained" };
  }
  if (provenance.symlink === true) return { decision: "rejected", reason: "config-source-symlink" };
  if (provenance.regularFile !== true) return { decision: "rejected", reason: "config-source-not-regular" };
  if (provenance.physicalContained !== true || provenance.logicalPath !== definition.file) {
    return { decision: "rejected", reason: "config-path-not-contained" };
  }
  if (provenance.workloadId !== workloadId) return { decision: "rejected", reason: "config-source-not-workload-owned" };
  if (provenance.immutable !== true) return { decision: "rejected", reason: "config-source-mutable" };
  if (!/^[a-f0-9]{64}$/.test(provenance.expectedSha256) || provenance.actualSha256 !== provenance.expectedSha256) {
    return { decision: "rejected", reason: "config-hash-mismatch" };
  }
  if (mount.source !== configName || !String(mount.target).startsWith("/run/configs/") || mount.mode !== "0400") {
    return { decision: "rejected", reason: "config-mount-not-exact" };
  }
  return { decision: "accepted", reason: "contained-workload-owned-hash-locked-file" };
}

function readSource(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function sliceBetween(source, start, end) {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex);
  assert.ok(startIndex >= 0 && endIndex > startIndex, `unable to slice ${start}`);
  assert.equal(source.indexOf(start, startIndex + start.length), -1, `ambiguous slice start for ${start}`);
  return source.slice(startIndex, endIndex);
}

function exactPhysicalDirectory(argument, label) {
  const resolved = path.resolve(argument);
  const stat = fs.lstatSync(resolved);
  assert.equal(stat.isDirectory(), true, `${label} is not a directory`);
  assert.equal(stat.isSymbolicLink(), false, `${label} must not be a symbolic link`);
  const physical = fs.realpathSync(resolved);
  assert.equal(physical, resolved, `${label} argument must be its exact physical path`);
  return physical;
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function sha256Text(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function claimOwnedDirectory(targetPath, expectedParent, token) {
  assert.equal(path.dirname(targetPath), expectedParent, "output target escaped its expected parent");
  assert.equal(fs.existsSync(targetPath), false, "output target already exists");
  fs.mkdirSync(targetPath, { mode: 0o700 });
  const targetStat = fs.lstatSync(targetPath);
  assert.equal(targetStat.isDirectory(), true);
  assert.equal(targetStat.isSymbolicLink(), false);
  assert.equal(fs.realpathSync(targetPath), targetPath);
  const ownershipSentinel = path.join(targetPath, `.fg073-output-owner-${token}`);
  fs.writeFileSync(ownershipSentinel, `fg073-output:${token}\n`, { mode: 0o600, flag: "wx" });
  const innerSentinelStat = fs.lstatSync(ownershipSentinel);
  return {
    targetPath,
    targetDevice: targetStat.dev,
    targetInode: targetStat.ino,
    ownershipSentinel,
    sentinelDevice: innerSentinelStat.dev,
    sentinelInode: innerSentinelStat.ino,
    token,
  };
}

function cleanupOwnedDirectory(ownership) {
  const targetStat = fs.lstatSync(ownership.targetPath);
  assert.equal(targetStat.isDirectory(), true, "cleanup target is not a directory");
  assert.equal(targetStat.isSymbolicLink(), false, "refusing cleanup through target symlink");
  assert.equal(fs.realpathSync(ownership.targetPath), ownership.targetPath, "cleanup target physical path changed");
  assert.equal(targetStat.dev, ownership.targetDevice, "cleanup target device changed");
  assert.equal(targetStat.ino, ownership.targetInode, "cleanup target inode changed");

  const innerStat = fs.lstatSync(ownership.ownershipSentinel);
  assert.equal(innerStat.isFile(), true, "output ownership sentinel is not a file");
  assert.equal(innerStat.isSymbolicLink(), false, "output ownership sentinel is a symlink");
  assert.equal(innerStat.dev, ownership.sentinelDevice, "output ownership sentinel device changed");
  assert.equal(innerStat.ino, ownership.sentinelInode, "output ownership sentinel inode changed");
  assert.equal(
    fs.readFileSync(ownership.ownershipSentinel, "utf8"),
    `fg073-output:${ownership.token}\n`,
    "output ownership sentinel content changed",
  );

  const permittedEntries = new Set([
    path.basename(ownership.ownershipSentinel),
    "hosted-config-provenance-receipt.json",
  ]);
  for (const entry of fs.readdirSync(ownership.targetPath)) {
    assert.equal(permittedEntries.has(entry), true, `unexpected cleanup entry: ${entry}`);
    const entryPath = path.join(ownership.targetPath, entry);
    assert.equal(fs.lstatSync(entryPath).isSymbolicLink(), false, `refusing cleanup of symlink: ${entry}`);
  }

  fs.rmSync(ownership.targetPath, { recursive: true });
}
