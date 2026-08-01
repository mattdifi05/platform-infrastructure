#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const EXPECTED_HASHES = new Map([
  ["compose.waf.yaml", "592f106ab0ff139f9246e0a104b483b7c3a82643d841f565227d95676364e28e"],
  ["promtail/config.yml", "a11d0fbc45c071dee224db48e6a0adfe03f9c349fbc9d250ec8efb561874914c"],
  ["compose.yaml", "ed630eee1be8350142493307c2647aa98ce67324c93c127a9370a19a24a9d6c7"],
  ["loki/config.yml", "627221822a5541bea60135703417e8959dcf8f38d732a2b0773ec7e9b7ae9237"],
  ["control-center/server.mjs", "0e660c3278ebe6d85c83e6852ef0afee6be10e7a434c3b37f0f33154969549b6"],
  ["SECURITY.md", "b72a0abd090dfa15832d5af3e389edeee50cf5128cbd515e7c74b6a72f4d9cb3"],
]);

const sourceRoot = path.resolve(process.argv[2] ?? "");
if (!process.argv[2] || !fs.statSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error("usage: waf-log-pipeline-probe.mjs /path/to/archived/source");
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expected, `${relativePath} is not the expected vulnerable source`);
}
console.log("[+] verified 6 embedded vulnerable-source hashes");

const wafConfig = read("compose.waf.yaml");
const promtailConfig = read("promtail/config.yml");
const composeConfig = read("compose.yaml");
const lokiConfig = read("loki/config.yml");
const controlCenter = read("control-center/server.mjs");

const auditEngine = composeEnvironmentValue(wafConfig, "MODSEC_AUDIT_ENGINE");
const auditLog = composeEnvironmentValue(wafConfig, "MODSEC_AUDIT_LOG");
const auditFormat = composeEnvironmentValue(wafConfig, "MODSEC_AUDIT_LOG_FORMAT");
const auditParts = composeEnvironmentValue(wafConfig, "MODSEC_AUDIT_LOG_PARTS");
const bodyAccess = composeEnvironmentValue(wafConfig, "MODSEC_REQ_BODY_ACCESS");
assert.equal(auditEngine, "RelevantOnly");
assert.equal(auditLog, "/dev/stdout");
assert.equal(auditFormat, "JSON");
assert.equal(auditParts, "ABIJFHZ");
assert.equal(bodyAccess, "On");
assert.ok(auditParts.includes("B"), "request-header audit part B is not configured");
assert.ok(auditParts.includes("I"), "request-body audit part I is not configured");
assert.match(controlCenter, /<input type="password" name="value"/);
assert.match(controlCenter, /payload\.value \|\| payload\.plainValue/);

const expression = singleQuotedYamlValue(promtailConfig, "expression");
const replacement = singleQuotedYamlValue(promtailConfig, "replace");
assert.ok(expression.startsWith("(?i)"), "expected Promtail case-insensitive expression");
const compatibilityRegex = new RegExp(expression.slice(4), "gi");
assert.equal(replacement, '$1"[REDACTED]"');
assert.doesNotMatch(expression, /(?:^|\W)(?:value|plainValue|body)(?:\W|$)/i);

const markers = {
  value: "SYNTHETIC_VALUE_7A31",
  plainValue: "SYNTHETIC_PLAINVALUE_7A31",
  authorization: "SYNTHETIC_AUTHORIZATION_7A31",
  cookie: "SYNTHETIC_COOKIE_7A31",
  password: "SYNTHETIC_PASSWORD_7A31",
  token: "SYNTHETIC_TOKEN_7A31",
};

const auditFixture = {
  transaction: {
    request: {
      method: "POST",
      uri: "/synthetic/vault-fixture",
      headers: {
        authorization: `Bearer ${markers.authorization}`,
        cookie: `session=${markers.cookie}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: `value=${markers.value}&plainValue=${markers.plainValue}`,
    },
    audit_data: { messages: ["synthetic relevant-event fixture"] },
  },
};
const wafStdoutLine = JSON.stringify(auditFixture);
assert.ok(wafStdoutLine.includes(markers.value));
assert.ok(wafStdoutLine.includes(markers.plainValue));
assert.ok(wafStdoutLine.includes(markers.authorization));
assert.ok(wafStdoutLine.includes(markers.cookie));
console.log(`[WAF-STDOUT] audit=${auditEngine} parts=${auditParts} bodyAccess=${bodyAccess} body_markers=2 header_markers=2`);

const dockerEnvelope = JSON.stringify({
  log: `${wafStdoutLine}\n`,
  stream: "stdout",
  time: "2030-01-01T00:00:00.000000000Z",
});
const dockerStageLine = unwrapDockerEnvelope(dockerEnvelope);
const promtailLine = dockerStageLine.replace(compatibilityRegex, replacement);

const namedFieldFixture = JSON.stringify({ password: markers.password, token: markers.token });
const namedFieldOutput = namedFieldFixture.replace(compatibilityRegex, replacement);
assert.ok(!namedFieldOutput.includes(markers.password));
assert.ok(!namedFieldOutput.includes(markers.token));
assert.ok(!promtailLine.includes(markers.authorization));
assert.ok(!promtailLine.includes(markers.cookie));
assert.ok(promtailLine.includes(markers.value));
assert.ok(promtailLine.includes(markers.plainValue));
console.log("[PROMTAIL] named_fields_redacted=2/2 header_markers_redacted=2/2 generic_body_markers_survive=2/2");

assert.match(promtailConfig, /__path__:\s*\/var\/lib\/docker\/containers\/\*\/\*-json\.log/);
assert.match(composeConfig, /\/var\/lib\/docker\/containers:\/var\/lib\/docker\/containers:ro/);
const lokiTarget = yamlScalar(promtailConfig, "url");
const retention = yamlScalar(lokiConfig, "retention_period");
assert.equal(lokiTarget, "http://loki:3100/loki/api/v1/push");
assert.equal(retention, "168h");
assert.match(lokiConfig, /retention_enabled:\s*true/);

const wouldBeLokiPush = {
  streams: [{
    stream: { job: "docker", source: "offline-fixture" },
    values: [["0", promtailLine]],
  }],
};
const lokiModelText = JSON.stringify(wouldBeLokiPush);
assert.ok(lokiModelText.includes(markers.value));
assert.ok(lokiModelText.includes(markers.plainValue));
console.log(`[LOKI-MODEL] target=${lokiTarget} retention=${retention} surviving_body_markers=2/2 sent=false`);

const safeBaseline = JSON.stringify({
  transaction: {
    request: {
      method: auditFixture.transaction.request.method,
      uri: auditFixture.transaction.request.uri,
      headers_redacted: true,
      body_logged: false,
    },
  },
});
for (const marker of Object.values(markers)) assert.ok(!safeBaseline.includes(marker));
console.log("[SAFE-BASELINE] headers_removed=true body_logged=false synthetic_markers=0");
console.log("[+] offline compatibility model only; no HTTP, Docker, WAF, Promtail, Loki, socket, network, or secret was used");

function read(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function composeEnvironmentValue(text, key) {
  const match = text.match(new RegExp(`^\\s+${escapeRegex(key)}:\\s*(.+?)\\s*$`, "m"));
  assert.ok(match, `missing ${key}`);
  const raw = match[1];
  const fallback = raw.match(/^\$\{[^:}]+:-([^}]*)\}$/);
  if (fallback) return fallback[1];
  if (raw.startsWith('"') && raw.endsWith('"')) return JSON.parse(raw);
  return raw;
}

function singleQuotedYamlValue(text, key) {
  const match = text.match(new RegExp(`^\\s+${escapeRegex(key)}:\\s*'([^']*)'\\s*$`, "m"));
  assert.ok(match, `missing single-quoted ${key}`);
  return match[1];
}

function yamlScalar(text, key) {
  const match = text.match(new RegExp(`^\\s+(?:-\\s*)?${escapeRegex(key)}:\\s*([^#\\s]+)`, "m"));
  assert.ok(match, `missing ${key}`);
  return match[1];
}

function unwrapDockerEnvelope(line) {
  const parsed = JSON.parse(line);
  assert.equal(parsed.stream, "stdout");
  return String(parsed.log).replace(/\n$/, "");
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
