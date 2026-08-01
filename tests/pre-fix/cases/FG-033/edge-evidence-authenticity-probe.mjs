#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const sourceRoot = process.argv[2];
if (!sourceRoot) {
  process.stderr.write("usage: node edge-evidence-authenticity-probe.mjs ARCHIVED_SOURCE_ROOT\n");
  process.exit(2);
}

const expectedHashes = new Map([
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["governance/production-go-no-go.json", "b439dec1c3e5cc47d22c3f452991b5bd985464fca2fd4f7988b6222352fbc8ca"],
  ["README.md", "27ae730ec95e41ace8ee74e4bed8ded858d5acc69e634a3e0e9c34340bfe8d33"],
]);

function sha256(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

for (const [relativePath, expected] of expectedHashes) {
  const actual = sha256(path.join(sourceRoot, relativePath));
  assert.equal(actual, expected, `source digest mismatch for ${relativePath}`);
}

const source = fs.readFileSync(path.join(sourceRoot, "scripts/infra-ops.mjs"), "utf8");
const policy = JSON.parse(fs.readFileSync(path.join(sourceRoot, "governance/production-go-no-go.json"), "utf8"));

function exactSection(startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  assert.equal(start, source.lastIndexOf(startMarker), `ambiguous source marker: ${startMarker}`);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  return source.slice(start, end).trim();
}

const executableSource = [
  exactSection("function selectedEdgeHeaders(headers = {})", "\n\nfunction detectEdgeProvider(headers = {})"),
  exactSection("function detectEdgeProvider(headers = {})", "\n\nasync function loadTargetEvidence("),
  exactSection("async function loadTargetEvidence(", "\n\nfunction writeLoadBenchmarkReport("),
  exactSection("function isPrivateOrLocalHost(hostname)", "\n\nfunction classifyResticRepository("),
  exactSection("function publicEvidenceUrl(urlValue)", "\n\nfunction legacyPlatformEvidenceHost(urlValue)"),
  exactSection("function legacyPlatformEvidenceHost(urlValue)", "\n\nconst GO_NO_GO_CHECK_STATUSES"),
  exactSection("const GO_NO_GO_CHECK_STATUSES", "\n\nfunction goNoGoStatusCounts("),
].join("\n\n");

let activeHeaders = {};
let requestCalls = 0;
let clock = 0;
const sandbox = vm.createContext({
  URL,
  performance: { now: () => { clock += 7; return clock; } },
  request: async (method, url, options) => {
    assert.equal(method, "GET");
    assert.equal(url, "https://api.service.invalid/health");
    assert.equal(options.timeoutMs, 1000);
    requestCalls += 1;
    return { status: 200, headers: structuredClone(activeHeaders) };
  },
  fail: (message) => { throw new Error(message); },
});
vm.runInContext(executableSource, sandbox, { filename: "pinned-edge-evidence-functions.mjs" });

async function exactTargetEvidence(headers) {
  activeHeaders = headers;
  return sandbox.loadTargetEvidence({
    url: "https://api.service.invalid/health",
    mode: "edge",
    requirePublicTarget: true,
    requireEdgeEvidence: true,
    expectedEdgeProvider: "cloudflare",
    timeoutMs: 1000,
  });
}

await assert.rejects(
  () => exactTargetEvidence({ server: "origin-service" }),
  /edge evidence missing or mismatched: expected=cloudflare, observed=none/,
);
process.stdout.write("[EXACT-BASELINE] origin_headers=plain accepted=false observed=none\n");

const forgedCases = [
  { signal: "cf-ray", headers: { server: "origin-service", "cf-ray": "forged-ray" } },
  { signal: "cf-cache-status", headers: { server: "origin-service", "cf-cache-status": "HIT" } },
  { signal: "server-substring", headers: { server: "origin-service cloudflare-compatible" } },
];

let forgedTarget = null;
for (const testCase of forgedCases) {
  const target = await exactTargetEvidence(testCase.headers);
  assert.equal(target.public, true);
  assert.equal(target.edge.provider, "cloudflare");
  assert.equal(target.edge.expectedProvider, "cloudflare");
  assert.equal(target.edge.providerMatched, true);
  forgedTarget ??= target;
  process.stdout.write(
    `[EXACT-HEADER] signal=${testCase.signal} provider=${target.edge.provider} provider_matched=${target.edge.providerMatched} accepted=true\n`,
  );
}

const loadBlock = exactSection(
  "const latestLoadReport = latestJsonReport(\"load\", \"load-benchmark-\");",
  "\n\n  const latestReleaseReport = latestJsonReport(\"release\", \"release-evidence-\");",
);
const runExactLoadGate = vm.runInContext(`
  (context) => {
    const {
      policy,
      latestJsonReport,
      reportFreshDetail,
      maxAge,
      publicEvidenceUrl,
      legacyPlatformEvidenceHost,
      addGoNoGoCheck,
    } = context;
    const checks = [];
    ${loadBlock}
    return checks.at(-1);
  }
`, sandbox, { filename: "pinned-load-go-no-go-block.mjs" });

const report = {
  filePath: "synthetic-load-report.json",
  payload: {
    generatedAt: "2030-01-01T00:00:00.000Z",
    status: "passed",
    url: "https://api.service.invalid/health",
    target: forgedTarget,
    profiles: [50, 100, 500].map((users) => ({
      users,
      metric: { errors: 0, p95: 100, maxP95Ms: 1000 },
    })),
  },
};
const latestJsonReport = (_directory, _prefix, predicate = () => true) => (
  predicate(report.payload, report.filePath) ? report : null
);
const exactGate = runExactLoadGate({
  policy,
  latestJsonReport,
  reportFreshDetail: () => ({ fresh: true, detail: "bounded fixture" }),
  maxAge: policy.maxAgeHours,
  publicEvidenceUrl: sandbox.publicEvidenceUrl,
  legacyPlatformEvidenceHost: sandbox.legacyPlatformEvidenceHost,
  addGoNoGoCheck: sandbox.addGoNoGoCheck,
});
assert.equal(exactGate.name, "public-load-benchmark");
assert.equal(exactGate.status, "passed");
assert.match(exactGate.detail, /edgeEvidence=cloudflare/);
process.stdout.write(
  `[EXACT-GO-NO-GO] check=${exactGate.name} status=${exactGate.status} edge_evidence=cloudflare other_inputs=bounded-passing-fixture\n`,
);

function referenceAttestationGate(payload, receipt) {
  const hostname = new URL(payload.url).hostname;
  if (receipt?.authentication?.verified !== true) return { accepted: false, reason: "missing-authenticated-receipt" };
  if (receipt.provider !== "cloudflare" || receipt.observedPeerProvider !== "cloudflare") {
    return { accepted: false, reason: "provider-or-peer-mismatch" };
  }
  if (receipt.hostname !== hostname || receipt.url !== payload.url) {
    return { accepted: false, reason: "target-binding-mismatch" };
  }
  return { accepted: true, reason: "provider-and-peer-attested" };
}

const forgedReference = referenceAttestationGate(report.payload, null);
assert.deepEqual(forgedReference, { accepted: false, reason: "missing-authenticated-receipt" });
process.stdout.write(
  `[REFERENCE-GATE] forged_report_accepted=${forgedReference.accepted} reason=${forgedReference.reason}\n`,
);

const modeledTrustedReceipt = {
  provider: "cloudflare",
  observedPeerProvider: "cloudflare",
  hostname: "api.service.invalid",
  url: "https://api.service.invalid/health",
  authentication: { verified: true, kind: "provider-api-and-independent-peer-attestation" },
};
const attestedReference = referenceAttestationGate(report.payload, modeledTrustedReceipt);
assert.deepEqual(attestedReference, { accepted: true, reason: "provider-and-peer-attested" });
process.stdout.write(
  `[REFERENCE-GATE] attested_report_accepted=${attestedReference.accepted} reason=${attestedReference.reason}\n`,
);

assert.equal(requestCalls, 4);
process.stdout.write(
  `[SAFETY] request_stub_calls=${requestCalls} network_used=false dns_used=false provider_api_used=false report_written=false\n`,
);
process.stdout.write("edge evidence authenticity probe passed\n");
