import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { validateEdgeProviderEvidence } from "./edge-provider-evidence.mjs";

const nowMs = Date.parse("2026-07-21T12:00:00.000Z");
const candidateId = "a".repeat(64);
const evidence = {
  schema: "platform.edge-traversal-evidence/v1",
  external: true,
  provider: "cloudflare",
  candidateId,
  verifiedAt: "2026-07-21T11:59:30.000Z",
  request: {
    id: "edge-request-0123456789",
    method: "GET",
    url: "https://api.example.com/health?proof=unique",
    status: 200,
    observedAt: "2026-07-21T11:59:00.000Z",
  },
};
const authentication = {
  status: "passed",
  verified: true,
  kind: "github-sigstore-cryptographic-attestation",
  repository: "owner/repo",
  signerWorkflow: "owner/repo/.github/workflows/edge-evidence.yml",
  sourceDigest: "b".repeat(40),
  sourceRef: "refs/heads/main",
  verifiedTimestampCount: 1,
};
const valid = { evidence, authentication, expectedUrl: evidence.request.url, expectedProvider: "cloudflare", currentCandidateId: candidateId, observedStatus: 200, nowMs };

test("accepts fresh authenticated edge evidence bound to URL request and candidate", () => {
  const result = validateEdgeProviderEvidence(valid);
  assert.equal(result.verified, true);
  assert.equal(result.provider, "cloudflare");
  assert.equal(result.request.id, evidence.request.id);
});

test("origin headers and self-authored assertions never authenticate edge traversal", () => {
  assert.throws(() => validateEdgeProviderEvidence({ ...valid, authentication: null }), /lacks authenticated/);
  assert.throws(() => validateEdgeProviderEvidence({ ...valid, evidence: { ...evidence, authentication }, authentication: null }), /lacks authenticated/);
  assert.throws(() => validateEdgeProviderEvidence({ ...valid, authentication: { ...authentication, verifiedTimestampCount: 0 } }), /transparency timestamp/);
});

test("rejects wrong URL request status provider candidate and time", () => {
  const mutations = [
    { expectedUrl: "https://origin.example.com/health?proof=unique" },
    { observedStatus: 503 },
    { expectedProvider: "fastly" },
    { currentCandidateId: "c".repeat(64) },
    { evidence: { ...evidence, request: { ...evidence.request, observedAt: "2026-07-21T12:01:00.000Z" } } },
    { evidence: { ...evidence, verifiedAt: "2026-07-21T10:00:00.000Z" } },
    { evidence: { ...evidence, request: { ...evidence.request, id: "short" } } },
  ];
  for (const mutation of mutations) assert.throws(() => validateEdgeProviderEvidence({ ...valid, ...mutation }), /mismatch|does not match|current candidate|future|stale|invalid/);
});

test("load benchmark treats response headers as diagnostics and requires attestation", () => {
  const source = fs.readFileSync(path.join(import.meta.dirname, "infra-ops.mjs"), "utf8");
  const body = source.slice(source.indexOf("function authenticatedEdgeProviderEvidence"), source.indexOf("function writeLoadBenchmarkReport"));
  assert.match(body, /headerDiagnostics/);
  assert.match(body, /validateEdgeProviderEvidence/);
  assert.match(body, /EXTERNAL-PENDING/);
  assert.doesNotMatch(body, /if \(requireEdgeEvidence && !providerMatched\)/);
});
