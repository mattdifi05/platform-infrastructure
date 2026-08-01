#!/usr/bin/env node
import assert from "node:assert/strict";
import { buildDastAdmissionReceipt, canonicalDastTarget, validateDastAdmissionReceipt } from "./dast-admission-policy.mjs";

const sha = (character) => character.repeat(64);
const base = {
  repository: "owner/repo",
  commitSha: "a".repeat(40),
  treeSha: "b".repeat(40),
  runtimeIntentSha256: sha("c"),
  consumerRunId: "123456",
  consumerRunAttempt: 2,
  challengeNonce: sha("d"),
  target: "https://staging.example.com:443/api/",
  report: {
    sha256: sha("e"),
    sizeBytes: 4096,
    document: {
      "@version": "2.16.1",
      site: [{
        "@name": "https://staging.example.com",
        "@host": "staging.example.com",
        "@port": "443",
        "@ssl": "true",
        alerts: [{ instances: [{ uri: "https://staging.example.com/api/health", method: "GET" }] }],
      }],
    },
  },
  generatedAt: "2026-08-01T12:34:56.000Z",
};
const receipt = buildDastAdmissionReceipt(base);
assert.deepEqual(validateDastAdmissionReceipt(receipt, base), receipt);
assert.equal(receipt.report.name, "zap-baseline.json");
assert.equal(receipt.consumerChallenge.consumerJob, "deploy-vps");
assert.deepEqual(receipt.target, { url: "https://staging.example.com/api/", origin: "https://staging.example.com" });

for (const [label, mutate] of [
  ["extension", (value) => { value.extension = true; }],
  ["non-passed", (value) => { value.status = "warning"; }],
  ["wrong candidate", (value) => { value.commitSha = "f".repeat(40); }],
  ["wrong runtime intent", (value) => { value.runtimeIntentSha256 = sha("f"); }],
  ["wrong report hash", (value) => { value.report.sha256 = sha("f"); }],
  ["wrong report name", (value) => { value.report.name = "attacker.json"; }],
  ["wrong consumer run", (value) => { value.consumerChallenge.consumerRunId = "654321"; }],
  ["wrong consumer job", (value) => { value.consumerChallenge.consumerJob = "attacker"; }],
  ["invalid nonce", (value) => { value.consumerChallenge.challengeNonce = "short"; }],
]) {
  const candidate = structuredClone(receipt);
  mutate(candidate);
  assert.throws(() => validateDastAdmissionReceipt(candidate, base), undefined, label);
}

assert.deepEqual(canonicalDastTarget("https://STAGING.example.com:443/api/"), receipt.target);
assert.throws(() => canonicalDastTarget("https://staging.example.com/api/#fragment"), /without credentials, query, or fragment/);
assert.throws(() => canonicalDastTarget("https://user@staging.example.com/api/"), /without credentials, query, or fragment/);

for (const [label, mutate] of [
  ["other site", (document) => { document.site[0]["@name"] = "https://other.example.com"; document.site[0]["@host"] = "other.example.com"; }],
  ["extra site", (document) => { document.site.push({ "@name": "https://other.example.com", "@host": "other.example.com", "@port": "443", "@ssl": "true", alerts: [] }); }],
  ["empty sites", (document) => { document.site = []; }],
  ["missing sites", (document) => { delete document.site; }],
  ["cross-authority instance", (document) => { document.site[0].alerts[0].instances[0].uri = "https://other.example.com/"; }],
]) {
  const report = structuredClone(base.report);
  mutate(report.document);
  assert.throws(() => validateDastAdmissionReceipt(receipt, { ...base, report }), undefined, label);
}

process.stdout.write("DAST admission policy tests passed 21/21\n");
