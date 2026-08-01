#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const EXPECTED_HASHES = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["scripts/hosted-workload-lock.sh", "f87317c017f541796f4144442a07c3c98e0b280aafb11396bd64852571390674"],
]);

const sourceRoot = path.resolve(process.argv[2] ?? "");
if (!process.argv[2] || !fs.statSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error("usage: transitive-lock-probe.mjs /path/to/archived/source");
}

function sha256Bytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sha256File(filePath) {
  return sha256Bytes(fs.readFileSync(filePath));
}

for (const [relativePath, expected] of EXPECTED_HASHES) {
  const actual = sha256File(path.join(sourceRoot, relativePath));
  assert.equal(actual, expected, `${relativePath} is not the expected vulnerable source`);
}
console.log("[+] verified 4 embedded vulnerable-source hashes");

const activationScript = fs.readFileSync(path.join(sourceRoot, "scripts/compose-vps.sh"), "utf8");
assert.match(
  activationScript,
  /compose\+=\(-f "\$workload_file"\)/,
  "activation must pass each locked primary Compose path to a fresh Compose invocation",
);
console.log("[+] verified activation reparses each locked primary Compose path");

const contractUrl = pathToFileURL(path.join(sourceRoot, "scripts/hosted-workload-contract.mjs"));
const {
  resolveCatalog,
  validateRenderedWorkloads,
  verifyLockFiles,
} = await import(contractUrl.href);

const probeRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hosted-lock-fixture-"));

function write(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

function json(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function snapshotFiles(root) {
  const snapshot = new Map();
  function visit(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile()) snapshot.set(path.relative(root, absolute), sha256File(absolute));
      else throw new Error(`unexpected non-regular fixture entry: ${entry.name}`);
    }
  }
  visit(root);
  return snapshot;
}

function changedPaths(before, after) {
  return [...new Set([...before.keys(), ...after.keys()])]
    .filter((name) => before.get(name) !== after.get(name))
    .sort();
}

function baseRenderedService(environment = { DEMO_MODE: "benign" }) {
  return {
    image: `example/demo@sha256:${"a".repeat(64)}`,
    privileged: false,
    read_only: true,
    init: true,
    restart: "unless-stopped",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    user: "1000:1000",
    healthcheck: { test: ["CMD", "true"] },
    cpus: 0.5,
    mem_limit: 134217728,
    mem_reservation: 67108864,
    pids_limit: 64,
    cpu_shares: 128,
    blkio_config: { weight: 100 },
    ulimits: { nofile: 4096 },
    environment,
    networks: { demo_ingress: {} },
    labels: {
      "com.platform.workload-id": "demo",
      "com.platform.workload-role": "web",
    },
  };
}

function renderedModel(environment) {
  return {
    services: { "demo-app": baseRenderedService(environment) },
    networks: { demo_ingress: { internal: true } },
  };
}

function semanticDigest(value) {
  return sha256Bytes(JSON.stringify(value));
}

function resolveFixture(caseRoot, primaryDocument) {
  const workloadRoot = path.join(caseRoot, "workloads");
  const workload = path.join(workloadRoot, "demo");
  const primaryPath = path.join(workload, "compose.json");
  const catalogPath = path.join(caseRoot, "catalog.json");
  const coreEnvFile = path.join(caseRoot, "core.env");
  const coreFile = path.join(caseRoot, "core.json");

  write(catalogPath, json({
    version: 1,
    workloads: [{ manifest: "demo/manifest.json", environmentFile: "demo/declared.env" }],
  }));
  write(coreEnvFile, "PLATFORM_MODE=synthetic\n");
  write(coreFile, json({ services: {}, networks: {} }));
  write(path.join(workload, "manifest.json"), json({
    version: 1,
    id: "demo",
    composeFile: "compose.json",
    services: [{ name: "demo-app", role: "web", routes: [] }],
    secrets: [],
    migrationRoots: [],
  }));
  write(path.join(workload, "declared.env"), "DEMO_MODE=benign\n");
  write(primaryPath, json(primaryDocument));

  const lock = resolveCatalog({
    catalogPath,
    workloadRoot,
    coreEnvFile,
    coreFiles: [coreFile],
    projectName: "synthetic-proof",
  });
  return { lock, primaryPath, workload };
}

function readExtends(primaryPath) {
  const primary = JSON.parse(fs.readFileSync(primaryPath, "utf8"));
  const reference = primary.services["demo-app"].extends;
  const dependency = JSON.parse(fs.readFileSync(path.resolve(path.dirname(primaryPath), reference.file), "utf8"));
  return { privileged: dependency.services[reference.service].privileged };
}

function readInclude(primaryPath) {
  const primary = JSON.parse(fs.readFileSync(primaryPath, "utf8"));
  const dependency = JSON.parse(fs.readFileSync(path.resolve(path.dirname(primaryPath), primary.include[0]), "utf8"));
  return { privileged: dependency.services["demo-app"].privileged };
}

function readEnvFile(primaryPath) {
  const primary = JSON.parse(fs.readFileSync(primaryPath, "utf8"));
  const relative = primary.services["demo-app"].env_file;
  const environment = Object.fromEntries(
    fs.readFileSync(path.resolve(path.dirname(primaryPath), relative), "utf8")
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => {
        const separator = line.indexOf("=");
        return [line.slice(0, separator), line.slice(separator + 1)];
      }),
  );
  return environment;
}

const cases = [
  {
    name: "extends.file",
    dependencyName: "extends-base.json",
    primary: { services: { "demo-app": { extends: { file: "./extends-base.json", service: "base" } } } },
    benign: json({ services: { base: { privileged: false } } }),
    changed: json({ services: { base: { privileged: true } } }),
    read: readExtends,
    describe: (value) => `privileged=${value.privileged}`,
    apply: (combined, value) => { combined.services["demo-app"].privileged = value.privileged; },
  },
  {
    name: "top-level include",
    dependencyName: "included.json",
    primary: { include: ["./included.json"] },
    benign: json({ services: { "demo-app": { privileged: false } } }),
    changed: json({ services: { "demo-app": { privileged: true } } }),
    read: readInclude,
    describe: (value) => `privileged=${value.privileged}`,
    apply: (combined, value) => { combined.services["demo-app"].privileged = value.privileged; },
  },
  {
    name: "service env_file",
    dependencyName: "service.env",
    primary: { services: { "demo-app": { env_file: "./service.env" } } },
    benign: "DEMO_MODE=benign\n",
    changed: "DEMO_MODE=CHANGED\n",
    read: readEnvFile,
    describe: (value) => `DEMO_MODE=${value.DEMO_MODE}`,
    apply: (combined, value) => { combined.services["demo-app"].environment = value; },
  },
];

try {
  for (const [index, testCase] of cases.entries()) {
    const caseRoot = path.join(probeRoot, `case-${index + 1}`);
    const { lock, primaryPath, workload } = resolveFixture(caseRoot, testCase.primary);
    const dependencyPath = path.join(workload, testCase.dependencyName);
    write(dependencyPath, testCase.benign);

    assert.equal(lock.files.some((record) => path.resolve(record.path) === dependencyPath), false);
    verifyLockFiles(lock);

    const benignSemantic = testCase.read(primaryPath);
    const combined = renderedModel(testCase.name === "service env_file" ? benignSemantic : undefined);
    testCase.apply(combined, benignSemantic);
    validateRenderedWorkloads({ core: { services: {}, networks: {} }, combined, lock });
    const verifiedLock = {
      ...lock,
      state: "verified",
      combinedRenderSha256: semanticDigest(combined),
    };

    const primaryBefore = sha256File(primaryPath);
    const before = snapshotFiles(caseRoot);
    write(dependencyPath, testCase.changed);
    const after = snapshotFiles(caseRoot);
    assert.deepEqual(changedPaths(before, after), [path.relative(caseRoot, dependencyPath)]);
    assert.equal(sha256File(primaryPath), primaryBefore);

    verifyLockFiles(verifiedLock);
    const changedSemantic = testCase.read(primaryPath);
    assert.notDeepEqual(changedSemantic, benignSemantic);
    const rereadCombined = structuredClone(combined);
    testCase.apply(rereadCombined, changedSemantic);
    assert.notEqual(semanticDigest(rereadCombined), verifiedLock.combinedRenderSha256);

    console.log(`[PASS] ${testCase.name}: dependency absent; benign render validated`);
    console.log(`[PASS] ${testCase.name}: only omitted dependency changed; primary hash unchanged`);
    console.log(`[VULNERABLE] ${testCase.name}: verifyLockFiles passed; second read ${testCase.describe(changedSemantic)}`);
    console.log(`[VULNERABLE] ${testCase.name}: stored combinedRenderSha256 was not rebound or compared`);
  }
  console.log("[+] source-level primitive reproduced for 3/3 dependency syntaxes");
  console.log("[i] no Docker daemon, Compose CLI, container, network, secret, or live state was used");
} finally {
  fs.rmSync(probeRoot, { recursive: true, force: true });
}
