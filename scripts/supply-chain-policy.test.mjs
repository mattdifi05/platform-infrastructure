import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { evaluateSupplyChain } from "./supply-chain-policy.mjs";

const root = path.resolve(import.meta.dirname, "..");

test("tracked supply-chain lock matches all consumers", () => {
  const report = evaluateSupplyChain(root);
  assert.equal(report.status, "passed", report.failures.join("\n"));
});

test("tag-only GitHub Action is rejected", (t) => {
  const fixture = createFixture(t);
  mutate(path.join(fixture, ".github/workflows/enterprise-infra.yml"), (text) => text.replace(/actions\/checkout@[a-f0-9]{40}/, "actions/checkout@v7"));
  assertFailure(fixture, "action-immutable-");
});

test("mutable Compose image is rejected", (t) => {
  const fixture = createFixture(t);
  mutate(path.join(fixture, "compose.yaml"), (text) => text.replace(/coredns\/coredns:1\.13\.1@sha256:[a-f0-9]{64}/, "coredns/coredns:latest"));
  assertFailure(fixture, "compose-image-compose.yaml");
});

test("Imagick checksum drift is rejected", (t) => {
  const fixture = createFixture(t);
  mutate(path.join(fixture, "docker/php-apache.Dockerfile"), (text) => text.replace(/ARG IMAGICK_SHA256=[a-f0-9]{64}/, `ARG IMAGICK_SHA256=${"0".repeat(64)}`));
  assertFailure(fixture, "imagick-checksum");
});

test("browser runner Docker socket regression is rejected", (t) => {
  const fixture = createFixture(t);
  mutate(path.join(fixture, "scripts/infra-ops.mjs"), (text) => text.replace("async function browserE2eTests() {", "async function browserE2eTests() {\n  // /var/run/docker.sock regression fixture"));
  assertFailure(fixture, "browser-runner-no-socket");
});

test("missing secret exclusion is rejected", (t) => {
  const fixture = createFixture(t);
  mutate(path.join(fixture, ".dockerignore"), (text) => text.replace(/^secrets\r?\n/m, ""));
  assertFailure(fixture, "dockerignore-secrets");
});

test("action lock drift is rejected", (t) => {
  const fixture = createFixture(t);
  const lockPath = path.join(fixture, "governance/supply-chain-lock.json");
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  lock.actions["actions/checkout"].commit = "1".repeat(40);
  fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  assertFailure(fixture, "action-lock-");
});

function createFixture(t) {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "platform-supply-chain-"));
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  for (const relativePath of [
    ".dockerignore",
    ".env.example",
    ".github/workflows",
    "docker",
    "governance/supply-chain-lock.json",
    "php-apache/php/conf.d/zz-production.ini",
    "scripts/dast-zap-baseline.sh",
    "scripts/infra-ops.mjs",
  ]) {
    const source = path.join(root, relativePath);
    const destination = path.join(fixture, relativePath);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.cpSync(source, destination, { recursive: true });
  }
  for (const file of fs.readdirSync(root).filter((name) => /^compose(?:\..+)?\.ya?ml$/.test(name))) {
    fs.copyFileSync(path.join(root, file), path.join(fixture, file));
  }
  return fixture;
}

function mutate(file, transform) {
  const before = fs.readFileSync(file, "utf8");
  const after = transform(before);
  assert.notEqual(after, before, `fixture mutation did not change ${file}`);
  fs.writeFileSync(file, after);
}

function assertFailure(fixture, expectedId) {
  const report = evaluateSupplyChain(fixture);
  assert.equal(report.status, "failed");
  assert.ok(report.failures.some((failure) => failure.includes(expectedId)), report.failures.join("\n"));
}
