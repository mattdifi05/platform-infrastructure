#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import vm from "node:vm";

const EXPECTED_REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const EXPECTED_SOURCE_SHA256 = "2f0c9ea5239935857caab3f233ff43cdb81a34d8ab77cfc1a7a00c2a1b7b91b1";

const args = parseArgs(process.argv.slice(2));
assert.equal(args.revision, EXPECTED_REVISION, "unexpected baseline revision");
const modulePath = path.resolve(args.module);
const source = readFileSync(modulePath, "utf8");
assert.equal(sha256(source), EXPECTED_SOURCE_SHA256, "OIDC source is not the pinned vulnerable blob");

const readConfig = sliceBetween(
  source,
  "export function readAuthConfig(env = process.env) {",
  "\nclass OidcPasskeyAuth",
);
assert.match(readConfig, /const issuer = requiredHttpsUrl\(env\.CONTROL_CENTER_OIDC_ISSUER/);
assert.match(readConfig, /const authorizationEndpoint = requiredHttpsUrl\(env\.CONTROL_CENTER_OIDC_AUTHORIZATION_ENDPOINT/);
assert.match(readConfig, /const tokenEndpoint = requiredUrl\(env\.CONTROL_CENTER_OIDC_TOKEN_ENDPOINT/);
assert.match(readConfig, /const jwksUri = requiredUrl\(env\.CONTROL_CENTER_OIDC_JWKS_URI/);
assert.match(readConfig, /const redirectUri = requiredHttpsUrl\(env\.CONTROL_CENTER_OIDC_REDIRECT_URI/);

const requiredText = sliceBetween(source, "function requiredText(value, name) {", "\nfunction requiredUrl(value, name) {");
const requiredUrl = sliceBetween(source, "function requiredUrl(value, name) {", "\nfunction requiredHttpsUrl(value, name) {");
const requiredHttpsUrl = sliceBetween(source, "function requiredHttpsUrl(value, name) {", "\nfunction requiredClaim(value, name) {");
const api = vm.runInNewContext(
  [
    "class AuthConfigurationError extends Error {}",
    requiredText,
    requiredUrl,
    requiredHttpsUrl,
    "({ requiredUrl, requiredHttpsUrl })",
  ].join("\n"),
  { URL },
  { filename: "pinned-oidc-url-controls.mjs", timeout: 1_000 },
);

assert.equal(api.requiredUrl("http://127.0.0.1:8080/token", "token"), "http://127.0.0.1:8080/token");
assert.equal(api.requiredUrl("http://127.0.0.1:8080/jwks", "jwks"), "http://127.0.0.1:8080/jwks");
assert.equal(api.requiredHttpsUrl("https://identity.example.test/realms/platform", "issuer"), "https://identity.example.test/realms/platform");
assert.throws(() => api.requiredHttpsUrl("http://identity.example.test/realms/platform", "issuer"), /must use HTTPS/);
assert.throws(() => api.requiredUrl("file:///tmp/token", "token"), /must use HTTP or HTTPS/);
assert.throws(() => api.requiredUrl("relative/token", "token"), /absolute URL/);

process.stdout.write(`[PASS] exact_source revision=${args.revision} sha256=${EXPECTED_SOURCE_SHA256}\n`);
process.stdout.write("[VULNERABLE] CAN-095 token_endpoint_control=requiredUrl plaintext_http=accepted\n");
process.stdout.write("[VULNERABLE] CAN-096 jwks_uri_control=requiredUrl plaintext_http=accepted\n");
process.stdout.write("[CONTROL] issuer_and_redirect=requiredHttpsUrl plaintext_http=rejected\n");
process.stdout.write("[CONTROL] file_and_relative_urls=rejected\n");
process.stdout.write("[SAFE] scope=offline-source-model network=0 listener=0 fetch=0 npm=0 secrets=0 live=0\n");

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value === "--module") result.module = values[++index];
    else if (value === "--revision") result.revision = values[++index];
    else throw new Error(`unknown argument: ${value}`);
  }
  if (!result.module) throw new Error("--module is required");
  if (!result.revision) throw new Error("--revision is required");
  return result;
}

function sliceBetween(value, startMarker, endMarker) {
  const start = value.indexOf(startMarker);
  const end = value.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  assert.equal(value.indexOf(startMarker, start + startMarker.length), -1, `ambiguous source marker: ${startMarker}`);
  return value.slice(start, end);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
