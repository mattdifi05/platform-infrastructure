#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const EXPECTED_HASHES = new Map([
  ["control-center/server.mjs", "0e660c3278ebe6d85c83e6852ef0afee6be10e7a434c3b37f0f33154969549b6"],
  ["control-center/auth/oidc.mjs", "2f0c9ea5239935857caab3f233ff43cdb81a34d8ab77cfc1a7a00c2a1b7b91b1"],
  ["control-center/tests/control-center.test.mjs", "bbc1ec255c1f3a3a6114bbca0180eab45fa2630fec51c0b2ed7998e8773a5c29"],
  ["control-center/AUTHENTICATION.md", "1e22e3474fe4cde9711c0e4d2a0aabdb3bf74e12dc1415cb4f9915f28f3b9bda"],
]);

const CASES = [
  {
    id: "recognized-token-control",
    text: "token=SYNTHETIC_CONTROL_VALUE\nhealthy=true",
    marker: "SYNTHETIC_CONTROL_VALUE",
    shouldLeak: false,
  },
  {
    id: "generic-json-field",
    text: '{"value":"SYNTHETIC_GENERIC_VALUE"}',
    marker: "SYNTHETIC_GENERIC_VALUE",
    shouldLeak: true,
  },
  {
    id: "quoted-json-password",
    text: '{"password":"SYNTHETIC_JSON_VALUE"}',
    marker: "SYNTHETIC_JSON_VALUE",
    shouldLeak: true,
  },
  {
    id: "multiline-password",
    text: "password:\n  SYNTHETIC_MULTILINE_VALUE",
    marker: "SYNTHETIC_MULTILINE_VALUE",
    shouldLeak: true,
  },
  {
    id: "multiline-private-key-body",
    text: "-----BEGIN PRIVATE KEY-----\nc3ludGhldGljLXByaXZhdGUta2V5LW1hdGVyaWFs\n-----END PRIVATE KEY-----",
    marker: "c3ludGhldGljLXByaXZhdGUta2V5LW1hdGVyaWFs",
    shouldLeak: true,
  },
  {
    id: "base64-encoded-credential",
    text: "auth_blob=c3ludGhldGljLWNyZWRlbnRpYWwtbWF0ZXJpYWw=",
    marker: "c3ludGhldGljLWNyZWRlbnRpYWwtbWF0ZXJpYWw=",
    shouldLeak: true,
  },
  {
    id: "percent-encoded-token",
    text: "payload=token%3DSYNTHETIC_PERCENT_VALUE",
    marker: "SYNTHETIC_PERCENT_VALUE",
    shouldLeak: true,
  },
  {
    id: "unfamiliar-credential-name",
    text: "client_assertion=SYNTHETIC_ASSERTION_VALUE",
    marker: "SYNTHETIC_ASSERTION_VALUE",
    shouldLeak: true,
  },
];

const sourceRoot = path.resolve(process.argv[2] ?? "");
if (!process.argv[2] || !fs.statSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error("usage: backup-preview-redaction-probe.mjs /path/to/archived/source");
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expected, `${relativePath} is not the expected vulnerable source`);
}
console.log("[+] verified 4 embedded vulnerable-source hashes");

const serverSource = fs.readFileSync(path.join(sourceRoot, "control-center/server.mjs"), "utf8");
const testSource = fs.readFileSync(path.join(sourceRoot, "control-center/tests/control-center.test.mjs"), "utf8");
assert.match(serverSource, /route\(parts, "control", "backups", "preview"\)\) return json\(res, readBackupPreview/);
assert.ok(
  serverSource.includes('return /\\.(json|md|txt|sha256|sig\\.json|sql|sql\\.gz|dump|tar\\.gz)$/i.test(pathValue);'),
  "preview extension allowlist changed",
);
assert.match(testSource, /token=backup-secret-should-not-leak/);
assert.match(testSource, /backupPreview\.content, \/token=\\\[redacted\\\]\//);

const serverModule = [
  sliceBetween(serverSource, "function sanitizeMessage(", "function safeIsDirectory("),
  sliceBetween(serverSource, "function redactBackupPreviewText(", "function uniqueBackupResources("),
  "export { redactBackupPreviewText, sanitizeEvent };",
].join("\n");
const serverLogic = await import(`data:text/javascript;base64,${Buffer.from(serverModule).toString("base64")}`);
console.log("[+] loaded exact archived redaction and response-sanitization functions");

let networkAttempts = 0;
let poolAttempts = 0;
let jwtVerifyAttempts = 0;
const originalFetch = globalThis.fetch;
globalThis.fetch = async () => {
  networkAttempts += 1;
  throw new Error("network access is forbidden in this proof");
};
globalThis.__BACKUP_PREVIEW_POC__ = {
  poolAttempt() { poolAttempts += 1; },
  jwtVerifyAttempt() { jwtVerifyAttempts += 1; },
};

let auth;
try {
  const authSource = stubUnexercisedAuthImports(fs.readFileSync(path.join(sourceRoot, "control-center/auth/oidc.mjs"), "utf8"));
  const { createControlCenterAuth } = await import(`data:text/javascript;base64,${Buffer.from(authSource).toString("base64")}`);
  auth = await createControlCenterAuth({ env: testEnvironment() });

  const previewUrl = new URL("https://portal.example.test/control/backups/preview?path=synthetic/report.json");
  for (const role of ["viewer", "owner"]) {
    const decision = auth.authorize(
      { method: "GET" },
      previewUrl,
      {
        ok: true,
        status: 200,
        role,
        identity: { authTime: new Date(0) },
      },
    );
    assert.equal(decision.ok, true, `${role} was unexpectedly denied the preview GET`);
    console.log(`[+] authorization role=${role} preview-get=allowed`);
  }

  let vulnerable = 0;
  for (const role of ["viewer", "owner"]) {
    for (const testCase of CASES) {
      const response = previewResponse(serverLogic, testCase.text);
      const leaked = response.content.includes(testCase.marker);
      assert.equal(leaked, testCase.shouldLeak, `${role}/${testCase.id} produced an unexpected disclosure result`);
      if (testCase.shouldLeak) {
        vulnerable += 1;
        console.log(`[VULNERABLE] role=${role} case=${testCase.id} marker-survived=yes lines-redacted=${response.linesRedacted}`);
      } else {
        console.log(`[+] role=${role} case=${testCase.id} marker-survived=no lines-redacted=${response.linesRedacted}`);
      }
    }
  }

  assert.equal(vulnerable, (CASES.length - 1) * 2);
  assert.equal(networkAttempts, 0);
  assert.equal(poolAttempts, 0);
  assert.equal(jwtVerifyAttempts, 0);
  console.log(`[+] summary vulnerable-role-case-pairs=${vulnerable} controls=2`);
  console.log("[+] no backup, secret, live service, network, PostgreSQL, or OIDC provider was accessed");
  console.log("[+] result=VULNERABLE");
} finally {
  if (auth) await auth.close();
  globalThis.fetch = originalFetch;
  delete globalThis.__BACKUP_PREVIEW_POC__;
}

function previewResponse({ redactBackupPreviewText, sanitizeEvent }, text) {
  const preview = redactBackupPreviewText(text);
  return sanitizeEvent({
    path: "synthetic/report.json",
    name: "report.json",
    type: "json",
    sizeBytes: Buffer.byteLength(text),
    mode: "safe-redacted-preview",
    content: preview.content,
    linesRedacted: preview.linesRedacted,
    message: preview.truncated ? "Anteprima limitata e redatta." : "Anteprima redatta.",
  });
}

function sliceBetween(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  assert.ok(end > start, `invalid source marker order: ${startMarker}`);
  return source.slice(start, end);
}

function stubUnexercisedAuthImports(source) {
  const joseImport = 'import { createRemoteJWKSet, jwtVerify } from "jose";';
  const pgImport = 'import pg from "pg";';
  assert.equal(source.split(joseImport).length - 1, 1, "unexpected jose import shape");
  assert.equal(source.split(pgImport).length - 1, 1, "unexpected pg import shape");
  return source
    .replace(joseImport, `
const createRemoteJWKSet = () => async () => { throw new Error("JWKS lookup is outside this proof"); };
const jwtVerify = async () => {
  globalThis.__BACKUP_PREVIEW_POC__.jwtVerifyAttempt();
  throw new Error("JWT verification is outside this proof");
};`)
    .replace(pgImport, `
const pg = { Pool: class {
  constructor() {
    globalThis.__BACKUP_PREVIEW_POC__.poolAttempt();
    throw new Error("PostgreSQL is outside this proof");
  }
} };`);
}

function testEnvironment() {
  return {
    NODE_ENV: "test",
    CONTROL_CENTER_ENV: "production",
    CONTROL_CENTER_BIND_HOST: "127.0.0.1",
    CONTROL_CENTER_AUTH_MODE: "oidc-passkey",
    CONTROL_CENTER_AUTH_STORE: "memory",
    CONTROL_CENTER_OIDC_ISSUER: "https://identity.example.test/realms/platform",
    CONTROL_CENTER_OIDC_AUTHORIZATION_ENDPOINT: "https://identity.example.test/realms/platform/protocol/openid-connect/auth",
    CONTROL_CENTER_OIDC_TOKEN_ENDPOINT: "http://127.0.0.1/token-not-contacted",
    CONTROL_CENTER_OIDC_JWKS_URI: "http://127.0.0.1/jwks-not-contacted",
    CONTROL_CENTER_OIDC_REDIRECT_URI: "https://portal.example.test/auth/callback",
    CONTROL_CENTER_OIDC_CLIENT_ID: "platform-control-center",
    CONTROL_CENTER_OIDC_REQUIRED_ACR: "urn:platform:loa:passkey",
    CONTROL_CENTER_OIDC_REQUIRED_AMR: "webauthn",
  };
}
