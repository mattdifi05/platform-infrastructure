import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const compose = fs.readFileSync(path.join(root, "compose.yaml"), "utf8");
const fileSecrets = fs.readFileSync(path.join(root, "compose.secrets.yaml"), "utf8");
const managedSecrets = fs.readFileSync(path.join(root, "compose.managed-secrets.yaml"), "utf8");

test("FG-054 Compose starts Redis only from generated per-workload ACLs", () => {
  const bootstrap = serviceBlock(compose, "broker-auth-bootstrap");
  const redis = serviceBlock(compose, "redis");
  assert.match(bootstrap, /network_mode: none/);
  assert.match(bootstrap, /hosted-workloads\.lock\.json:ro/);
  assert.match(bootstrap, /render-workload-broker-config\.mjs/);
  assert.match(bootstrap, /redis-users\.acl/);
  assert.match(redis, /--aclfile \/run\/platform-broker\/redis-users\.acl/);
  assert.match(redis, /condition: service_completed_successfully/);
  assert.match(redis, /REDIS_USERNAME: platform/);
  assert.doesNotMatch(redis, /--requirepass/);
  for (const overlay of [fileSecrets, managedSecrets]) {
    assert.match(serviceBlock(overlay, "broker-auth-bootstrap"), /- redis_password/);
    assert.match(serviceBlock(overlay, "redis"), /REDIS_USERNAME: platform/);
    assert.doesNotMatch(serviceBlock(overlay, "redis"), /--requirepass/);
  }
});

test("FG-055 broker-auth-bootstrap capability + secret contract is minimal and exact", () => {
  const bootstrap = serviceBlock(compose, "broker-auth-bootstrap");

  // Exact, ordered capability contract: CHOWN + DAC_READ_SEARCH only, nothing else.
  assert.deepEqual(yamlList(bootstrap, "cap_add"), ["CHOWN", "DAC_READ_SEARCH"]);
  assert.deepEqual(yamlList(bootstrap, "cap_drop"), ["ALL"]);

  // Runtime hardening must remain present (behavioral proof is the live
  // open()-as-root diagnostic; this is the structural contract).
  assert.match(bootstrap, /network_mode:\s*none/);
  assert.match(bootstrap, /read_only:\s*true/);
  assert.match(bootstrap, /no-new-privileges:true/);
  assert.doesNotMatch(bootstrap, /privileged:\s*true/);

  // LOCAL_PRIVATE secret projection stays exact: named secret mapped from the
  // secrets root, never embedded plaintext, never mode-widened. The broker
  // references the named secrets in the overlay service blocks and the overlay
  // projects them from a fixed file/external source.
  for (const overlay of [fileSecrets, managedSecrets]) {
    const svc = serviceBlock(overlay, "broker-auth-bootstrap");
    assert.match(svc, /- redis_password/);
    assert.match(svc, /- nats_password/);
  }
  assertSecretProjection(fileSecrets, "redis_password", "redis_password.txt");
  assertSecretProjection(managedSecrets, "redis_password", "redis_password.txt");
  assertSecretProjection(fileSecrets, "nats_password", "nats_password.txt");
  assertSecretProjection(managedSecrets, "nats_password", "nats_password.txt");

  // NATS must consume the generated accounts without global credential flags.
  const nats = serviceBlock(compose, "nats");
  assert.match(nats, /user: "1000:1000"/);
  assert.match(nats, /nats_auth_config:\/run\/platform-broker:ro/);
  assert.match(nats, /--config/);
  assert.match(nats, /nats-server\.conf/);
  assert.doesNotMatch(nats, /--user|--pass|NATS_PASSWORD|nats_password/);
  assert.doesNotMatch(nats, /\.\/nats\/nats-server\.conf/);
  const natsBlock = serviceBlock(compose, "nats");
  assert.match(natsBlock, /depends_on:\s*broker-auth-bootstrap:\s*condition: service_completed_successfully/);
});

function serviceBlock(source, name) {
  const marker = `\n  ${name}:\n`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing service ${name}`);
  const rest = source.slice(start + marker.length);
  const end = rest.search(/\n  [a-zA-Z0-9][a-zA-Z0-9_-]*:\n/);
  return end === -1 ? rest : rest.slice(0, end);
}

function yamlList(block, key) {
  const marker = `${key}:`;
  const start = block.indexOf(marker);
  if (start === -1) return null;
  const rest = block.slice(start + marker.length);
  const items = [];
  for (const line of rest.split("\n")) {
    const m = line.match(/^\s+-\s+(.+?)\s*$/);
    if (m) {
      items.push(m[1]);
    } else if (line.trim() === "") {
      continue;
    } else {
      break;
    }
  }
  return items;
}

function secretProjectionBlock(source, name) {
  const marker = `\n  ${name}:\n`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing secret ${name}`);
  const rest = source.slice(start + marker.length);
  const end = rest.search(/\n  [a-zA-Z0-9_-]+:\n/);
  return end === -1 ? rest : rest.slice(0, end);
}

function assertSecretProjection(overlay, name, fileName) {
  const block = secretProjectionBlock(overlay, name);
  assert.doesNotMatch(block, /content:/, `${name} must not embed copied plaintext`);
  assert.doesNotMatch(block, /mode:/, `${name} must not widen file mode`);
  const fileRef = new RegExp(`file:\\s*\\S*${fileName}`).test(block);
  const externalRef = /external:\s*true/.test(block);
  assert.ok(
    fileRef || externalRef,
    `${name} must project from a fixed secrets-root file or external reference (got: ${block.trim()})`,
  );
}
