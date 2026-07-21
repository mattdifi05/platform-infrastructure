import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const compose = fs.readFileSync(path.join(root, "compose.yaml"), "utf8");
const fileSecrets = fs.readFileSync(path.join(root, "compose.secrets.yaml"), "utf8");
const managedSecrets = fs.readFileSync(path.join(root, "compose.managed-secrets.yaml"), "utf8");
const composeVps = fs.readFileSync(path.join(root, "scripts", "compose-vps.sh"), "utf8");

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

test("FG-055 Compose starts NATS from generated accounts without global credential flags", () => {
  const bootstrap = serviceBlock(compose, "broker-auth-bootstrap");
  const nats = serviceBlock(compose, "nats");
  assert.match(bootstrap, /- all/);
  assert.match(bootstrap, /- CHOWN/);
  assert.match(bootstrap, /nats_password/);
  assert.match(bootstrap, /nats-server\.conf/);
  assert.match(bootstrap, /nats_auth_config:\/out\/nats/);
  assert.match(nats, /user: "1000:1000"/);
  assert.match(nats, /nats_auth_config:\/run\/platform-broker:ro/);
  assert.match(nats, /--config/);
  assert.match(nats, /nats-server\.conf/);
  assert.doesNotMatch(nats, /--user|--pass|NATS_PASSWORD|nats_password/);
  assert.doesNotMatch(nats, /\.\/nats\/nats-server\.conf/);
  for (const overlay of [fileSecrets, managedSecrets]) {
    assert.match(serviceBlock(overlay, "broker-auth-bootstrap"), /- nats_password/);
    assert.doesNotMatch(overlay, /^  nats:\n/m);
  }
  const bootstrapRun = composeVps.indexOf('run --rm --no-deps broker-auth-bootstrap');
  const finalExec = composeVps.indexOf('exec "${compose[@]}" --profile backup "$@"');
  assert.ok(bootstrapRun >= 0 && finalExec > bootstrapRun, "VPS up must regenerate broker auth before the final Compose command");
});

function serviceBlock(source, name) {
  const marker = `\n  ${name}:\n`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing service ${name}`);
  const rest = source.slice(start + marker.length);
  const end = rest.search(/\n  [a-zA-Z0-9][a-zA-Z0-9_-]*:\n/);
  return end === -1 ? rest : rest.slice(0, end);
}
