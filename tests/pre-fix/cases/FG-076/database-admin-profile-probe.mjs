#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const PROTECTED_SERVICES = ["phpmyadmin", "phppgadmin"];
const EXPECTED_OVERLAY_ORDER = [
  "compose.yaml",
  "compose.secrets.yaml",
  "compose.waf.yaml",
  "compose.vps.yaml",
  "compose.vps-waf.yaml",
  "compose.backup-scheduler.yaml",
  "compose.runtime.yaml",
  "compose.networks.yaml",
  "compose.runtime-isolation.yaml",
];
const EXPECTED_HASHES = new Map([
  ["compose.yaml", "ed630eee1be8350142493307c2647aa98ce67324c93c127a9370a19a24a9d6c7"],
  ["compose.secrets.yaml", "52897c0e6f650f360b673fff67a1dac1fe312f8c9ec8843890686ad62b4a6c60"],
  ["compose.waf.yaml", "592f106ab0ff139f9246e0a104b483b7c3a82643d841f565227d95676364e28e"],
  ["compose.vps.yaml", "c8954158a542825fe276742d3b943818603c2cc764764da98fd81859de3f1415"],
  ["compose.vps-waf.yaml", "01635f0a117de50fd60aa95aa5b6bf42416aa0a39ffe606462e1a6a839c2f008"],
  ["compose.backup-scheduler.yaml", "cf2ad09cd02f3a04c512450f0c730ec6637ac86646d9037c0be118a12c95c748"],
  ["compose.runtime.yaml", "b7b546bbb8587b54d39a0a53d22db4f020afcc707c33338eee264c4407d30505"],
  ["compose.networks.yaml", "f6cfb3b3857c1fd85414fbd7dc29c78a5f96ca9e7d309d8849cbb3400f66d759"],
  ["compose.runtime-isolation.yaml", "69d7383d8f0d499d0580514e30944a6819e14631619f536587420696d2238fc6"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["traefik/dynamic/admin-routes.yml", "0c712f00c4ca5b35cc22ad66ac6bcbd7ad091f1cf82b66904b8124b8ddc1b931"],
  ["traefik/dynamic/middlewares.yml", "79ae033e15398379b4fec860ff658091c9518f995a533a9ee78ee5b1e9d0a11b"],
]);

const sourceArgument = process.argv[2];
const labArgument = process.argv[3];
if (!sourceArgument || !labArgument) {
  throw new Error(
    "usage: database-admin-profile-probe.mjs WRAPPER_OWNED_SOURCE WRAPPER_OWNED_LAB",
  );
}

const {
  sourceRoot,
  labRoot,
  sentinelPath,
  sentinelText,
  sentinelDevice,
  sentinelInode,
} = validateWrapperOwnedPaths(sourceArgument, labArgument);
const sourceBefore = directoryDigest(sourceRoot);
console.log("[+] wrapper-owned source and lab boundaries verified");

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(
    sha256File(path.join(sourceRoot, relativePath)),
    expected,
    `${relativePath} is not the expected vulnerable source`,
  );
}
console.log(`[+] verified ${EXPECTED_HASHES.size} embedded vulnerable-source hashes`);

const composeWrapper = readSource("scripts/compose-vps.sh");
const overlayOrder = extractOverlayOrder(composeWrapper);
assert.deepEqual(overlayOrder, EXPECTED_OVERLAY_ORDER);
assert.match(composeWrapper, /exec "\$\{compose\[@\]\}" --profile backup "\$@"/);
assert.doesNotMatch(composeWrapper, /--profile admin/);
console.log(`[TRACE] overlay_order=${overlayOrder.join(">")} selected_profile=backup`);

const overlaySources = new Map(
  overlayOrder.map((relativePath) => [relativePath, readSource(relativePath)]),
);
const canonicalStates = renderProtectedServices(overlayOrder, overlaySources);

for (const service of PROTECTED_SERVICES) {
  const state = canonicalStates[service];
  assert.deepEqual(state.profiles, []);
  assert.equal(state.restart, "unless-stopped");
  assert.equal(isActive(state, new Set(["backup"])), true);
  assert.deepEqual(
    state.profileTrace.map((entry) => `${entry.file}:${entry.operation}:${entry.value.join(",")}`),
    [
      "compose.yaml:merge:admin",
      "compose.vps.yaml:merge:admin",
      "compose.runtime.yaml:reset:",
    ],
  );
  console.log(
    `[VULNERABLE] service=${service} profiles=[] restart=unless-stopped active_without_admin=true`,
  );
}

const runtimeSource = overlaySources.get("compose.runtime.yaml");
assert.ok(runtimeSource);
for (const service of PROTECTED_SERVICES) {
  const runtimeBlock = extractServiceBlock(runtimeSource, service);
  assert.match(runtimeBlock, /^    profiles: !reset \[\]$/m);
  assert.match(runtimeBlock, /^    restart: unless-stopped$/m);
}

const adminRoutes = readSource("traefik/dynamic/admin-routes.yml");
const middlewares = readSource("traefik/dynamic/middlewares.yml");
const vpsWaf = overlaySources.get("compose.vps-waf.yaml");
const networks = overlaySources.get("compose.networks.yaml");
assert.ok(vpsWaf && networks);
assert.match(runtimeSource, /admin-routes\.yml:\/etc\/traefik\/dynamic\/admin-routes\.yml:ro/);
assert.match(vpsWaf, /WAF_HTTP_BIND:-0\.0\.0\.0:80/);
assert.match(vpsWaf, /WAF_HTTPS_BIND:-0\.0\.0\.0:443/);
assert.match(adminRoutes, /Host\(`portal\.platform-infrastructure\.com`\) && PathPrefix\(`\/phpmyadmin`\)/);
assert.match(adminRoutes, /Host\(`portal\.platform-infrastructure\.com`\) && PathPrefix\(`\/phppgadmin`\)/);
assert.doesNotMatch(
  `${adminRoutes}\n${middlewares}`,
  /forwardAuth|ipAllowList|ipWhiteList|oauth|oidc|authelia/i,
);
for (const service of PROTECTED_SERVICES) {
  const block = extractServiceBlock(networks, service);
  assert.match(block, /- platform_routing/);
  assert.match(block, /- platform_db_admin/);
}
console.log(
  "[ROUTES] public_edge_defaults=true portal_admin_paths=2 identity_middleware=false database_admin_network=true",
);

const vpsOnlyOrder = overlayOrder.filter((item) => item !== "compose.runtime.yaml");
const vpsOnlyStates = renderProtectedServices(vpsOnlyOrder, overlaySources);
for (const service of PROTECTED_SERVICES) {
  assert.deepEqual(vpsOnlyStates[service].profiles, ["admin"]);
  assert.equal(vpsOnlyStates[service].restart, "no");
  assert.equal(isActive(vpsOnlyStates[service], new Set(["backup"])), false);
}

const reordered = [
  ...overlayOrder.slice(0, overlayOrder.indexOf("compose.vps.yaml")),
  "compose.runtime.yaml",
  "compose.vps.yaml",
  ...overlayOrder.slice(overlayOrder.indexOf("compose.vps.yaml") + 1)
    .filter((item) => item !== "compose.runtime.yaml"),
];
const reorderedStates = renderProtectedServices(reordered, overlaySources);
for (const service of PROTECTED_SERVICES) {
  assert.deepEqual(reorderedStates[service].profiles, ["admin"]);
  assert.equal(reorderedStates[service].restart, "no");
  assert.equal(isActive(reorderedStates[service], new Set(["backup"])), false);
}

const fixedSources = new Map(overlaySources);
let fixedRuntime = runtimeSource;
for (const service of PROTECTED_SERVICES) {
  fixedRuntime = removeServiceBlock(fixedRuntime, service);
}
fixedSources.set("compose.runtime.yaml", fixedRuntime);
const fixedStates = renderProtectedServices(overlayOrder, fixedSources);
for (const service of PROTECTED_SERVICES) {
  assert.deepEqual(fixedStates[service].profiles, ["admin"]);
  assert.equal(fixedStates[service].restart, "no");
  assert.equal(isActive(fixedStates[service], new Set(["backup"])), false);
  assert.equal(isActive(fixedStates[service], new Set(["backup", "admin"])), true);
}

assert.deepEqual(
  evaluatePolicy(canonicalStates, new Set(["backup"]), false),
  { ok: false, reason: "default-active:phpmyadmin" },
);
assert.deepEqual(
  evaluatePolicy(fixedStates, new Set(["backup"]), false),
  { ok: true, reason: "protected-services-disabled" },
);
assert.deepEqual(
  evaluatePolicy(fixedStates, new Set(["backup", "admin"]), false),
  { ok: false, reason: "identity-gate-missing:phpmyadmin" },
);
assert.deepEqual(
  evaluatePolicy(fixedStates, new Set(["backup", "admin"]), true),
  { ok: true, reason: "explicit-authenticated-admin" },
);
console.log(
  "[CONTROL] vps_gate_only=disabled runtime_before_vps=disabled fixed_default=disabled explicit_admin_without_identity=rejected explicit_authenticated_admin=accepted",
);

const traceArtifact = {
  schemaVersion: 1,
  sourceRevision: REVISION,
  sourceTree: TREE,
  overlayOrder,
  selectedProfiles: ["backup"],
  canonicalStates,
  fixedStates,
  routeExposure: {
    publicEdgeDefaults: true,
    portalAdminPaths: 2,
    identityMiddleware: false,
    databaseAdminNetwork: true,
  },
};
const tracePath = path.join(labRoot, "profile-trace.json");
fs.writeFileSync(tracePath, `${JSON.stringify(traceArtifact, null, 2)}\n`, {
  encoding: "utf8",
  flag: "wx",
  mode: 0o600,
});
const roundTrip = JSON.parse(fs.readFileSync(tracePath, "utf8"));
assert.deepEqual(roundTrip.overlayOrder, overlayOrder);
assert.equal(roundTrip.canonicalStates.phpmyadmin.profiles.length, 0);
assert.equal(roundTrip.fixedStates.phpmyadmin.profiles[0], "admin");

assert.equal(directoryDigest(sourceRoot), sourceBefore, "the source snapshot changed during the PoC");
const sentinelAfter = fs.lstatSync(sentinelPath);
assert.equal(sentinelAfter.isFile(), true, "the ownership sentinel is no longer a regular file");
assert.equal(sentinelAfter.isSymbolicLink(), false, "the ownership sentinel became a symlink");
assert.equal(sentinelAfter.dev, sentinelDevice, "the ownership sentinel device changed during the PoC");
assert.equal(sentinelAfter.ino, sentinelInode, "the ownership sentinel inode changed during the PoC");
assert.equal(fs.readFileSync(sentinelPath, "utf8"), sentinelText, "the ownership sentinel changed during the PoC");

console.log(
  "[+] summary forced_default_activation_reproduced=true fixed_profile_gate_enforced=true source_tree_unchanged=true",
);
console.log(
  "[+] runtime_limit static_compose_semantics_only=true compose_binary=false database=false docker=false network=false live=false",
);

function renderProtectedServices(order, sources) {
  const output = {};
  for (const service of PROTECTED_SERVICES) {
    const state = { profiles: [], restart: null, profileTrace: [], restartTrace: [] };
    for (const file of order) {
      const source = sources.get(file);
      assert.equal(typeof source, "string", `missing overlay source: ${file}`);
      const block = extractServiceBlock(source, service, { optional: true });
      if (block === null) continue;
      const profilePatch = parseProfiles(block);
      if (profilePatch.present) {
        if (profilePatch.reset) {
          state.profiles = [];
          state.profileTrace.push({ file, operation: "reset", value: [] });
        } else {
          state.profiles = [...new Set([...state.profiles, ...profilePatch.values])].sort();
          state.profileTrace.push({ file, operation: "merge", value: profilePatch.values });
        }
      }
      const restartPatch = parseRestart(block);
      if (restartPatch !== null) {
        state.restart = restartPatch;
        state.restartTrace.push({ file, value: restartPatch });
      }
    }
    output[service] = state;
  }
  return output;
}

function evaluatePolicy(states, selectedProfiles, identityGatePresent) {
  for (const service of PROTECTED_SERVICES) {
    const state = states[service];
    const active = isActive(state, selectedProfiles);
    if (active && !selectedProfiles.has("admin")) {
      return { ok: false, reason: `default-active:${service}` };
    }
    if (!active) continue;
    if (state.restart !== "no") {
      return { ok: false, reason: `persistent-restart:${service}` };
    }
    if (!identityGatePresent) {
      return { ok: false, reason: `identity-gate-missing:${service}` };
    }
  }
  if (selectedProfiles.has("admin")) {
    return { ok: true, reason: "explicit-authenticated-admin" };
  }
  return { ok: true, reason: "protected-services-disabled" };
}

function isActive(state, selectedProfiles) {
  return state.profiles.length === 0
    || state.profiles.some((profile) => selectedProfiles.has(profile));
}

function extractOverlayOrder(source) {
  const values = [];
  const pattern = /^\s+-f (compose[^\s]*\.yaml)$/gm;
  for (const match of source.matchAll(pattern)) values.push(match[1]);
  return values;
}

function extractServiceBlock(source, service, { optional = false } = {}) {
  const lines = source.split("\n");
  const escaped = service.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const startPattern = new RegExp(`^  ${escaped}:\\s*$`);
  const start = lines.findIndex((line) => startPattern.test(line));
  if (start === -1) {
    if (optional) return null;
    throw new Error(`service block not found: ${service}`);
  }
  let end = start + 1;
  while (end < lines.length) {
    const line = lines[end];
    if (/^\S/.test(line) || /^  [A-Za-z0-9_.-]+:\s*(?:#.*)?$/.test(line)) break;
    end += 1;
  }
  return lines.slice(start, end).join("\n");
}

function removeServiceBlock(source, service) {
  const lines = source.split("\n");
  const block = extractServiceBlock(source, service);
  const blockLines = block.split("\n");
  const start = lines.findIndex((line) => line === blockLines[0]);
  assert.notEqual(start, -1);
  lines.splice(start, blockLines.length);
  return lines.join("\n");
}

function parseProfiles(block) {
  if (/^    profiles: !reset \[\]\s*$/m.test(block)) {
    return { present: true, reset: true, values: [] };
  }
  const lines = block.split("\n");
  const index = lines.findIndex((line) => /^    profiles:\s*$/.test(line));
  if (index === -1) return { present: false, reset: false, values: [] };
  const values = [];
  for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
    const match = lines[cursor].match(/^      -\s+(.+?)\s*$/);
    if (!match) break;
    values.push(unquote(match[1]));
  }
  assert.ok(values.length > 0, "profiles list was present but empty without !reset");
  return { present: true, reset: false, values };
}

function parseRestart(block) {
  const match = block.match(/^    restart:\s*(.+?)\s*$/m);
  return match ? unquote(match[1]) : null;
}

function unquote(value) {
  if (
    (value.startsWith('"') && value.endsWith('"'))
    || (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

function readSource(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function validateWrapperOwnedPaths(sourceInput, labInput) {
  const wrapperInput = requiredEnvironment("FG076_WRAPPER_TEMP_ROOT");
  const sentinelInput = requiredEnvironment("FG076_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("FG076_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperInput);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(
    path.basename(wrapperReal),
    /^fg076-(?:guard|run)\.[A-Za-z0-9]+$/,
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
  assert.match(path.basename(sentinelReal), /^\.fg076-owner\.[A-Za-z0-9]+$/);
  const tokenFromName = path.basename(sentinelReal).slice(".fg076-owner.".length);
  assert.equal(ownershipToken, tokenFromName, "ownership token does not match sentinel name");
  const sentinelText = `FG076-OWNER:${ownershipToken}\n`;
  assert.equal(fs.readFileSync(sentinelReal, "utf8"), sentinelText, "ownership sentinel content is invalid");

  const labPath = path.resolve(labInput);
  const labStat = fs.lstatSync(labPath, { throwIfNoEntry: false });
  assert.ok(labStat?.isDirectory(), "wrapper laboratory directory is missing");
  assert.equal(labStat.isSymbolicLink(), false, "wrapper laboratory directory must not be a symlink");
  const labReal = fs.realpathSync(labPath);
  assert.equal(labReal, path.join(wrapperReal, "lab"), "lab must be the exact wrapper-owned lab child");
  assert.deepEqual(fs.readdirSync(labReal), [], "wrapper laboratory directory must start empty");

  return {
    sourceRoot: sourceReal,
    labRoot: labReal,
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
