#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const EXPECTED_HASHES = new Map([
  ["cloudflare/access-admin.example.json", "dff6bc2ef134bce187330f9cf74148ffd84cd8cb6d9c9a82b9df609566283968"],
  ["scripts/cloudflare-access-admin.mjs", "58977b1797b81f2bd9f1567ff48b1390dbb4b4d5d8c83edbba7b7036c630ba21"],
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["traefik/dynamic/admin-routes.yml", "0c712f00c4ca5b35cc22ad66ac6bcbd7ad091f1cf82b66904b8124b8ddc1b931"],
  ["governance/production-readiness.json", "3daac5be3fb1f211cc1e77a70c2a9285d76b1dcc2f0fd2834ea861ce2502f41d"],
  ["CURRENT-OPERATING-MODEL.md", "8428cec848730aada6f19f4342045b4d8dd68394e326c84ccdc3106bfcc8d0c8"],
]);

const sourceArgument = process.argv[2];
if (!sourceArgument) {
  throw new Error("usage: access-surface-inventory-probe.mjs WRAPPER_OWNED_SOURCE");
}

const {
  sourceRoot,
  wrapperRoot,
  sentinelPath,
  sentinelText,
  sentinelDevice,
  sentinelInode,
} = validateWrapperOwnedSource(sourceArgument);
const treeBefore = directoryDigest(sourceRoot);
console.log("[+] wrapper-owned source boundary verified");

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(
    sha256File(path.join(sourceRoot, relativePath)),
    expected,
    `${relativePath} is not the expected vulnerable source`,
  );
}
console.log(`[+] verified ${EXPECTED_HASHES.size} embedded vulnerable-source hashes`);

const manifestPath = path.join(sourceRoot, "cloudflare/access-admin.example.json");
const accessScriptPath = path.join(sourceRoot, "scripts/cloudflare-access-admin.mjs");
const infraOpsPath = path.join(sourceRoot, "scripts/infra-ops.mjs");
const routesPath = path.join(sourceRoot, "traefik/dynamic/admin-routes.yml");
const readinessPath = path.join(sourceRoot, "governance/production-readiness.json");
const operatingModelPath = path.join(sourceRoot, "CURRENT-OPERATING-MODEL.md");

const trackedManifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const accessSource = fs.readFileSync(accessScriptPath, "utf8");
const infraSource = fs.readFileSync(infraOpsPath, "utf8");
const routeSource = fs.readFileSync(routesPath, "utf8");
const readiness = JSON.parse(fs.readFileSync(readinessPath, "utf8"));
const operatingModel = fs.readFileSync(operatingModelPath, "utf8");

assert.equal(trackedManifest.applications.length, 8, "the tracked manifest application count changed");
const routeMatch = routeSource.match(/enterprise-phppgadmin:\s*\n\s*rule:\s*Host\(`([^`]+)`\)/);
assert.ok(routeMatch, "the dedicated phpPgAdmin route was not found");
const requiredRoute = routeMatch[1].toLowerCase();
assert.equal(requiredRoute, "phppgadmin.platform-infrastructure.com");

const trackedApps = trackedManifest.applications.map((app) => ({
  ...app,
  domain: String(app.domain).replace(/\.example\.com$/i, ".platform-infrastructure.com").toLowerCase(),
}));
const trackedDomains = trackedApps.map((app) => app.domain);
assert.equal(new Set(trackedDomains).size, trackedDomains.length, "the tracked manifest unexpectedly contains a duplicate domain");
assert.equal(trackedDomains.includes(requiredRoute), false, "the vulnerable manifest unexpectedly contains phpPgAdmin");
const expectedDomains = new Set([...trackedDomains, requiredRoute]);

const readinessRequirement = readiness.requirements.find((item) => item.id === "admin-access-mfa-vpn");
assert.ok(readinessRequirement, "the admin access readiness requirement is missing");
assert.match(readinessRequirement.liveProof, /every admin surface/i);
assert.match(operatingModel, /phpPgAdmin and Traefik dashboard must not be public internet surfaces\./);

assert.match(accessSource, /if \(applications\.length === 0\) throw new Error\("Cloudflare Access manifest must define at least one admin application\."\);/);
assert.match(accessSource, /const normalizedApps = applications\.map\(\(app\) => \{/);
assert.match(accessSource, /for \(const app of manifest\.applications\) \{/);
assert.match(accessSource, /Cloudflare Access admin applications match the manifest\./);
assert.doesNotMatch(accessSource, /node:(?:http|https|net|tls|dgram)/, "the pinned verifier gained an unmocked socket module");
assert.equal((accessSource.match(/\bfetch\s*\(/g) ?? []).length, 1, "the pinned verifier network-call shape changed");

const consumerSource = sourceSlice(
  infraSource,
  "  const cloudflareApps = cloudflareAccess?.payload?.applications ?? [];",
  "  const cloudflarePendingProvider = Boolean(",
);
assert.match(consumerSource, /cloudflareApps\.length > 0/);
assert.match(consumerSource, /cloudflareApps\.every\(\(app\) => app\.result === "verified"\)/);
const gateSource = sourceSlice(
  infraSource,
  "  addGoNoGoCheck(checks, {\n    name: \"cloudflare-access-admin-verified\",",
  "\n\n  const blockingRequired = checks.filter",
);
assert.match(gateSource, /cloudflareAccess\.payload\.status === "passed" && cloudflareVerified/);

console.log(
  `[+] tracked_manifest_apps=${trackedApps.length} reconciled_expected_apps=${expectedDomains.size} required_route=${requiredRoute} manifest_contains_route=false`,
);

const empty = runVerifierCase("empty-manifest", []);
assert.equal(empty.accepted, false);
assert.equal(empty.mock.fetchCalls, 0);
assert.match(empty.stderr, /must define at least one admin application/);
console.log("[CONTROL] empty-manifest verifier=rejected mock_fetch_calls=0");

const omitted = runVerifierCase("omitted-phppgadmin", trackedApps);
assert.equal(omitted.accepted, true);
assert.equal(omitted.payload.applications.length, trackedApps.length);
assert.equal(omitted.payload.applications.some((app) => app.domain === requiredRoute), false);
assert.equal(accessGatePasses(omitted.payload), true);
console.log(
  `[VULNERABLE] omitted-phppgadmin manifest_apps=${trackedApps.length} expected_apps=${expectedDomains.size} verifier=passed evidence=passed access_gate=passed mock_fetch_calls=${omitted.mock.fetchCalls}`,
);

const portalApp = trackedApps.find((app) => app.domain === "portal.platform-infrastructure.com");
assert.ok(portalApp, "tracked portal application is missing");
const duplicatedApps = [structuredClone(portalApp), structuredClone(portalApp)];
const duplicated = runVerifierCase("duplicate-domain", duplicatedApps);
const duplicateUniqueDomains = new Set(duplicatedApps.map((app) => app.domain)).size;
const duplicateCount = duplicatedApps.length - duplicateUniqueDomains;
assert.equal(duplicated.accepted, true);
assert.equal(duplicateCount, 1);
assert.equal(accessGatePasses(duplicated.payload), true);
console.log(
  `[VULNERABLE] duplicate-domain manifest_apps=${duplicatedApps.length} unique_domains=${duplicateUniqueDomains} duplicates=${duplicateCount} verifier=passed evidence=passed access_gate=passed mock_fetch_calls=${duplicated.mock.fetchCalls}`,
);

const unknownApps = [{ name: "Untracked Admin", domain: "unknown-admin.platform-infrastructure.com" }];
const unknown = runVerifierCase("unknown-application", unknownApps);
const unknownCount = unknownApps.filter((app) => !expectedDomains.has(app.domain)).length;
assert.equal(unknown.accepted, true);
assert.equal(unknownCount, 1);
assert.equal(accessGatePasses(unknown.payload), true);
console.log(
  `[VULNERABLE] unknown-application manifest_apps=${unknownApps.length} unknown_domains=${unknownCount} verifier=passed evidence=passed access_gate=passed mock_fetch_calls=${unknown.mock.fetchCalls}`,
);

assert.equal(directoryDigest(sourceRoot), treeBefore, "the source snapshot changed during the offline probe");
const sentinelAfter = fs.lstatSync(sentinelPath);
assert.equal(sentinelAfter.isFile(), true, "the ownership sentinel is no longer a regular file");
assert.equal(sentinelAfter.isSymbolicLink(), false, "the ownership sentinel became a symlink");
assert.equal(sentinelAfter.dev, sentinelDevice, "the ownership sentinel device changed during the probe");
assert.equal(sentinelAfter.ino, sentinelInode, "the ownership sentinel inode changed during the probe");
assert.equal(fs.readFileSync(sentinelPath, "utf8"), sentinelText, "the ownership sentinel changed during the probe");
console.log("[+] summary vulnerable=3 controls=1 source_tree_unchanged=true temp_writes_confined=true");
console.log("[+] no SSH, DNS, socket, HTTP, Cloudflare account, credential, deployment, or live target was accessed");

function runVerifierCase(caseName, applications) {
  assert.match(caseName, /^[a-z0-9-]+$/);
  const caseRoot = fs.mkdtempSync(path.join(wrapperRoot, `fg051-case-${caseName}.`));
  const caseReal = fs.realpathSync(caseRoot);
  assert.equal(path.dirname(caseReal), wrapperRoot, "case directory escaped the wrapper root");
  assert.equal(fs.lstatSync(caseReal).isSymbolicLink(), false, "case directory must not be a symlink");

  const syntheticManifest = {
    accountId: "11111111111111111111111111111111",
    teamName: "platform-offline-probe",
    adminSessionDuration: "8h",
    mfaEnforcedByIdentityProvider: true,
    allowedIdentityProviderIds: ["11111111-1111-1111-1111-111111111111"],
    allowedEmails: ["operator@platform-infrastructure.invalid"],
    allowedEmailDomains: [],
    applications,
  };
  const syntheticManifestPath = path.join(caseReal, "synthetic-manifest.json");
  const mockReceiptPath = path.join(caseReal, "mock-receipt.json");
  fs.writeFileSync(syntheticManifestPath, `${JSON.stringify(syntheticManifest, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });

  const pocDirectory = path.dirname(fileURLToPath(import.meta.url));
  const mockPath = path.join(pocDirectory, "mock-cloudflare-fetch.mjs");
  const child = spawnSync(
    process.execPath,
    ["--import", mockPath, accessScriptPath, "--manifest", syntheticManifestPath, "--verifyRemote"],
    {
      cwd: caseReal,
      encoding: "utf8",
      timeout: 15_000,
      maxBuffer: 4 * 1024 * 1024,
      env: {
        PATH: process.env.PATH ?? "",
        HOME: caseReal,
        TMPDIR: caseReal,
        LANG: "C",
        LC_ALL: "C",
        NODE_OPTIONS: "",
        CLOUDFLARE_API_TOKEN: "offline-synthetic-token",
        FG051_MOCK_MANIFEST: syntheticManifestPath,
        FG051_MOCK_RECEIPT: mockReceiptPath,
      },
    },
  );
  assert.equal(child.error, undefined, `${caseName} child process failed to start`);
  assert.equal(child.signal, null, `${caseName} child process was terminated`);
  assert.ok(fs.existsSync(mockReceiptPath), `${caseName} mock receipt is missing`);
  const mock = JSON.parse(fs.readFileSync(mockReceiptPath, "utf8"));
  assert.equal(mock.unexpectedRequests, 0, `${caseName} issued an unexpected request`);
  assert.equal(mock.network, "blocked-by-fetch-override");

  if (applications.length === 0) {
    assert.notEqual(child.status, 0, "the empty manifest unexpectedly passed");
    assert.equal(fs.existsSync(path.join(caseReal, "reports")), false, "the rejected case wrote an evidence report");
    return { accepted: false, stdout: child.stdout, stderr: child.stderr, mock };
  }

  assert.equal(child.status, 0, `${caseName} verifier failed: ${child.stderr}`);
  assert.match(child.stdout, /Cloudflare Access admin applications match the manifest\./);
  assert.match(child.stdout, /network=blocked/);
  assert.equal(mock.fetchCalls, applications.length + 1, `${caseName} mock call count changed`);
  const reportDirectory = path.join(caseReal, "reports", "cloudflare-access");
  const reports = fs.readdirSync(reportDirectory).filter((name) => name.endsWith(".json"));
  assert.equal(reports.length, 1, `${caseName} expected one JSON evidence report`);
  const payload = JSON.parse(fs.readFileSync(path.join(reportDirectory, reports[0]), "utf8"));
  assert.equal(payload.mode, "verifyRemote");
  assert.equal(payload.status, "passed");
  assert.equal(payload.issues.length, 0);
  assert.equal(payload.applications.length, applications.length);
  assert.ok(payload.applications.every((app) => app.result === "verified"));
  assert.ok(Date.now() - Date.parse(payload.generatedAt) < 60_000, `${caseName} evidence is not fresh`);
  return { accepted: true, stdout: child.stdout, stderr: child.stderr, mock, payload };
}

function accessGatePasses(payload) {
  const policy = { requireCloudflareAccessVerify: true };
  const cloudflareApps = payload?.applications ?? [];
  const cloudflareVerified = !policy.requireCloudflareAccessVerify || (
    payload?.mode === "verifyRemote"
    && cloudflareApps.length > 0
    && cloudflareApps.every((app) => app.result === "verified")
  );
  const fresh = Date.now() - Date.parse(payload.generatedAt) < 60_000;
  return Boolean(payload && fresh && payload.status === "passed" && cloudflareVerified);
}

function validateWrapperOwnedSource(sourceInput) {
  const wrapperInput = requiredEnvironment("FG051_WRAPPER_TEMP_ROOT");
  const sentinelInput = requiredEnvironment("FG051_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("FG051_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperInput);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(
    path.basename(wrapperReal),
    /^fg051-(?:guard|run)\.[A-Za-z0-9]+$/,
    "wrapper temporary root does not have the expected mktemp name",
  );

  const sourcePath = path.resolve(sourceInput);
  const sourceStat = fs.lstatSync(sourcePath, { throwIfNoEntry: false });
  assert.ok(sourceStat?.isDirectory(), "archived source directory is missing");
  assert.equal(sourceStat.isSymbolicLink(), false, "archived source must not be a symlink");
  const sourceReal = fs.realpathSync(sourcePath);
  assert.equal(sourceReal, path.join(wrapperReal, "source"), "source must be the exact wrapper-owned source child");

  const sentinelPath = path.resolve(sentinelInput);
  const sentinelStat = fs.lstatSync(sentinelPath, { throwIfNoEntry: false });
  assert.ok(sentinelStat?.isFile(), "ownership sentinel is missing");
  assert.equal(sentinelStat.isSymbolicLink(), false, "ownership sentinel must not be a symlink");
  const sentinelReal = fs.realpathSync(sentinelPath);
  assert.equal(path.dirname(sentinelReal), wrapperReal, "ownership sentinel is outside the wrapper root");
  assert.match(path.basename(sentinelReal), /^\.fg051-owner\.[A-Za-z0-9]+$/);
  const tokenFromName = path.basename(sentinelReal).slice(".fg051-owner.".length);
  assert.equal(ownershipToken, tokenFromName, "ownership token does not match sentinel name");
  const sentinelText = `FG051-OWNER:${ownershipToken}\n`;
  assert.equal(fs.readFileSync(sentinelReal, "utf8"), sentinelText, "ownership sentinel content is invalid");

  return {
    sourceRoot: sourceReal,
    wrapperRoot: wrapperReal,
    sentinelPath: sentinelReal,
    sentinelText,
    sentinelDevice: sentinelStat.dev,
    sentinelInode: sentinelStat.ino,
  };
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required; invoke through run-from-git-archive.sh`);
  }
  return value;
}

function sourceSlice(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker.trim()}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker.trim()}`);
  return source.slice(start, end);
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function directoryDigest(root) {
  const digest = crypto.createHash("sha256");
  walk(root, "");
  return digest.digest("hex");

  function walk(current, relative) {
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) {
      digest.update(`L\0${relative}\0${fs.readlinkSync(current)}\0`);
      return;
    }
    if (stat.isDirectory()) {
      digest.update(`D\0${relative}\0`);
      for (const name of fs.readdirSync(current).sort()) {
        walk(path.join(current, name), relative ? `${relative}/${name}` : name);
      }
      return;
    }
    assert.equal(stat.isFile(), true, `unsupported archived entry: ${relative}`);
    digest.update(`F\0${relative}\0`);
    digest.update(fs.readFileSync(current));
    digest.update("\0");
  }
}
