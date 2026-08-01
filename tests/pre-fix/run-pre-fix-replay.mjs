#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const BASELINE_COMMIT = "68cd05895b8d479ffb8167344282e7d922958bfc";
export const BASELINE_TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
export const DEFINITION_SCHEMA = "platform.pre-fix-replay-definition/v2";
export const RECEIPT_SCHEMA = "platform.pre-fix-negative-replay-receipt/v2";
export const SANDBOX_SCHEMA = "platform.pre-fix-replay-sandbox/v2";
export const EXPECTED_CASE_IDS = Object.freeze(
  Array.from({ length: 77 }, (_, index) => `FG-${String(index + 1).padStart(3, "0")}`),
);

const modulePath = fileURLToPath(import.meta.url);
export const PRE_FIX_ROOT = path.dirname(modulePath);
export const REPOSITORY_ROOT = path.resolve(PRE_FIX_ROOT, "../..");
export const REGISTRY_PATH = path.join(PRE_FIX_ROOT, "definition-registry.jsonl");
export const SANDBOX_PROFILE_PATH = path.join(PRE_FIX_ROOT, "sandbox-profile.json");
export const SOURCE_MAP_PATH = path.join(PRE_FIX_ROOT, "security-fix-groups-v1.jsonl");
export const SOURCE_MAP_SHA256 = "82eb9a2f436afaf521b2d73a91537612f5f543e05af0dd35f2af494fcc26a725";
const MAX_REGISTRY_BYTES = 2 * 1024 * 1024;
const MAX_SOURCE_MAP_BYTES = 2 * 1024 * 1024;
const MAX_CASE_OUTPUT_BYTES = 8 * 1024 * 1024;
const DEFAULT_CASE_TIMEOUT_MS = 120_000;
const DENIED_USER_SECRET_ROOTS = Object.freeze([".ssh", ".aws", ".docker", ".kube", ".gnupg", ".codex"]);

function fail(message) {
  throw new Error(message);
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(value, required, optional, label) {
  if (!isPlainObject(value)) fail(`${label} must be an object`);
  const allowed = new Set([...required, ...optional]);
  for (const key of required) {
    if (!Object.hasOwn(value, key)) fail(`${label}.${key} is required`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(`${label}.${key} is not allowed`);
  }
}

function assertRelativeTrackedPath(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    fail(`${label} must be a non-empty path`);
  }
  if (path.isAbsolute(value) || value.split("/").includes("..") || value.includes("\\")) {
    fail(`${label} must be a normalized repository-relative path`);
  }
}

export function validateDefinition(definition) {
  assertExactKeys(
    definition,
    [
      "schema",
      "case_id",
      "slug",
      "canonical_ids",
      "baseline",
      "target_worktree_write",
      "ephemeral_write",
      "proof_scope",
      "residuals",
      "anchors",
      "test_boundary",
      "seed_tree_sha256",
      "entrypoint",
      "provenance",
    ],
    [],
    "definition",
  );
  if (definition.schema !== DEFINITION_SCHEMA) fail(`unsupported definition schema: ${definition.schema}`);
  if (!/^FG-(?:00[1-9]|0[1-6][0-9]|07[0-7])$/.test(definition.case_id)) {
    fail(`invalid case_id: ${definition.case_id}`);
  }
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(definition.slug)) fail(`invalid slug for ${definition.case_id}`);
  if (!Array.isArray(definition.canonical_ids) || definition.canonical_ids.length === 0) {
    fail(`${definition.case_id} must preserve at least one canonical finding id`);
  }
  if (new Set(definition.canonical_ids).size !== definition.canonical_ids.length) {
    fail(`${definition.case_id} has duplicate canonical ids`);
  }
  if (!definition.canonical_ids.every((id) => /^CAN-[0-9]{3}$/.test(id))) {
    fail(`${definition.case_id} has an invalid canonical id`);
  }
  assertExactKeys(definition.baseline, ["commit", "tree"], [], `${definition.case_id}.baseline`);
  if (definition.baseline.commit !== BASELINE_COMMIT || definition.baseline.tree !== BASELINE_TREE) {
    fail(`${definition.case_id} is not bound to the authoritative detached baseline`);
  }
  if (definition.target_worktree_write !== false || definition.ephemeral_write !== true) {
    fail(`${definition.case_id} has an unsafe filesystem-write declaration`);
  }
  assertExactKeys(
    definition.proof_scope,
    ["kind", "classification", "claim", "method", "expected_observation", "limitations"],
    [],
    `${definition.case_id}.proof_scope`,
  );
  if (definition.proof_scope.kind !== "exact-baseline-negative-reproduction") {
    fail(`${definition.case_id} has the wrong proof scope`);
  }
  if (!['offline-product-consumer', 'offline-source-control', 'offline-source-model'].includes(definition.proof_scope.classification)) {
    fail(`${definition.case_id} has an invalid proof-scope classification`);
  }
  if (!Array.isArray(definition.proof_scope.limitations) || definition.proof_scope.limitations.length === 0) {
    fail(`${definition.case_id} must state proof limitations`);
  }
  if (!Array.isArray(definition.residuals) || definition.residuals.length === 0) {
    fail(`${definition.case_id} must state residual proof obligations`);
  }
  if (!Array.isArray(definition.anchors) || definition.anchors.length < 3) {
    fail(`${definition.case_id} must have root-control, tracked-seed, and baseline-consumer anchors`);
  }
  for (const [index, anchor] of definition.anchors.entries()) {
    assertExactKeys(anchor, ["kind", "value"], ["sha256"], `${definition.case_id}.anchors[${index}]`);
    if (!['root_control', 'tracked_seed', 'baseline_consumer'].includes(anchor.kind)) {
      fail(`${definition.case_id} has an unsupported anchor kind`);
    }
    if (typeof anchor.value !== "string" || anchor.value.length === 0) fail(`${definition.case_id} has an empty anchor`);
    if (anchor.kind !== "root_control") assertRelativeTrackedPath(anchor.value, `${definition.case_id}.${anchor.kind}`);
    if (anchor.kind !== "root_control" && !Object.hasOwn(anchor, "sha256")) {
      fail(`${definition.case_id} ${anchor.kind} anchor requires a digest`);
    }
    if (Object.hasOwn(anchor, "sha256") && !/^[0-9a-f]{64}$/.test(anchor.sha256)) {
      fail(`${definition.case_id} has an invalid anchor digest`);
    }
  }
  if (!definition.anchors.some((anchor) => anchor.kind === "baseline_consumer")) {
    fail(`${definition.case_id} has no baseline consumer Git anchor`);
  }
  if (typeof definition.test_boundary !== "string" || definition.test_boundary.length < 8) {
    fail(`${definition.case_id} has no meaningful test boundary`);
  }
  if (!/^[0-9a-f]{64}$/.test(definition.seed_tree_sha256)) {
    fail(`${definition.case_id} has an invalid seed tree digest`);
  }
  assertExactKeys(definition.provenance, ["source", "source_map_sha256", "migration"], [], `${definition.case_id}.provenance`);
  if (!/^[0-9a-f]{64}$/.test(definition.provenance.source_map_sha256)) {
    fail(`${definition.case_id} has an invalid source-map digest`);
  }
  assertExactKeys(definition.entrypoint, ["kind", "cwd"], ["target", "script", "args"], `${definition.case_id}.entrypoint`);
  assertRelativeTrackedPath(definition.entrypoint.cwd, `${definition.case_id}.entrypoint.cwd`);
  if (definition.entrypoint.cwd !== `tests/pre-fix/cases/${definition.case_id}`) {
    fail(`${definition.case_id} entrypoint cwd does not match its case identity`);
  }
  if (definition.entrypoint.kind === "make") {
    if (typeof definition.entrypoint.target !== "string" || !/^[a-z][a-z0-9-]*$/.test(definition.entrypoint.target)) {
      fail(`${definition.case_id} has an invalid make target`);
    }
    if (Object.hasOwn(definition.entrypoint, "script") || Object.hasOwn(definition.entrypoint, "args")) {
      fail(`${definition.case_id} make entrypoint has node-only fields`);
    }
  } else if (definition.entrypoint.kind === "node") {
    assertRelativeTrackedPath(definition.entrypoint.script, `${definition.case_id}.entrypoint.script`);
    if (!definition.entrypoint.script.startsWith(`${definition.entrypoint.cwd}/`)) {
      fail(`${definition.case_id} node script escapes its case directory`);
    }
    if (!Array.isArray(definition.entrypoint.args) || !definition.entrypoint.args.every((arg) => typeof arg === "string")) {
      fail(`${definition.case_id} node args must be strings`);
    }
    for (const argument of definition.entrypoint.args) {
      const placeholders = argument.match(/\{\{[A-Z_]+\}\}/g) ?? [];
      if (placeholders.some((placeholder) => !["{{BASELINE_ROOT}}", "{{CONTRACT}}"].includes(placeholder))) {
        fail(`${definition.case_id} has an unsupported entrypoint placeholder`);
      }
    }
    if (Object.hasOwn(definition.entrypoint, "target")) fail(`${definition.case_id} node entrypoint has a make target`);
  } else {
    fail(`${definition.case_id} has an unsupported entrypoint kind`);
  }
  return definition;
}

export async function loadRegistry(registryPath = REGISTRY_PATH) {
  const info = await stat(registryPath);
  if (!info.isFile() || info.size <= 0 || info.size > MAX_REGISTRY_BYTES) fail("definition registry size is invalid");
  const raw = await readFile(registryPath, "utf8");
  if (!raw.endsWith("\n")) fail("definition registry must end with a newline");
  const definitions = raw.trimEnd().split("\n").map((line, index) => {
    try {
      return validateDefinition(JSON.parse(line));
    } catch (error) {
      throw new Error(`definition registry line ${index + 1}: ${error.message}`);
    }
  });
  const ids = definitions.map((definition) => definition.case_id);
  if (JSON.stringify(ids) !== JSON.stringify(EXPECTED_CASE_IDS)) {
    fail("definition registry must contain FG-001 through FG-077 exactly once and in order");
  }
  if (new Set(definitions.map((definition) => definition.slug)).size !== definitions.length) {
    fail("definition registry slugs must be unique");
  }
  return definitions;
}

export async function loadSourceMap(sourceMapPath = SOURCE_MAP_PATH) {
  const info = await stat(sourceMapPath);
  if (!info.isFile() || info.size <= 0 || info.size > MAX_SOURCE_MAP_BYTES) fail("source map size is invalid");
  const raw = await readFile(sourceMapPath, "utf8");
  if (!raw.endsWith("\n")) fail("source map must end with a newline");
  if (sha256(raw) !== SOURCE_MAP_SHA256) fail("source map does not match its authoritative digest");
  const entries = raw.trimEnd().split("\n").map((line, index) => {
    let entry;
    try {
      entry = JSON.parse(line);
    } catch (error) {
      throw new Error(`source map line ${index + 1}: ${error.message}`);
    }
    assertExactKeys(
      entry,
      ["group_id", "slug", "canonical_ids", "root_control", "remediation", "test_boundary"],
      [],
      `source map line ${index + 1}`,
    );
    if (entry.group_id !== EXPECTED_CASE_IDS[index]) fail(`source map line ${index + 1} has the wrong group identity`);
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(entry.slug)) fail(`${entry.group_id} source-map slug is invalid`);
    if (!Array.isArray(entry.canonical_ids) || entry.canonical_ids.length === 0 ||
        !entry.canonical_ids.every((id) => /^CAN-[0-9]{3}$/.test(id))) {
      fail(`${entry.group_id} source-map canonical ids are invalid`);
    }
    for (const key of ["root_control", "remediation", "test_boundary"]) {
      if (typeof entry[key] !== "string" || entry[key].length < 8) fail(`${entry.group_id} source-map ${key} is invalid`);
    }
    return entry;
  });
  if (entries.length !== EXPECTED_CASE_IDS.length) fail("source map must contain exactly 77 rows");
  const canonicalIds = entries.flatMap((entry) => entry.canonical_ids);
  if (canonicalIds.length !== 135 || new Set(canonicalIds).size !== canonicalIds.length) {
    fail("source map must preserve exactly 135 unique canonical finding ids");
  }
  return entries;
}

export function verifyRegistrySourceMap(definitions, sourceMap) {
  if (definitions.length !== sourceMap.length) fail("registry and source map lengths differ");
  for (const [index, definition] of definitions.entries()) {
    const source = sourceMap[index];
    const rootControls = definition.anchors.filter((anchor) => anchor.kind === "root_control");
    if (
      definition.case_id !== source.group_id ||
      definition.slug !== source.slug ||
      JSON.stringify(definition.canonical_ids) !== JSON.stringify(source.canonical_ids) ||
      definition.test_boundary !== source.test_boundary ||
      rootControls.length !== 1 ||
      rootControls[0].value !== source.root_control ||
      definition.provenance.source_map_sha256 !== SOURCE_MAP_SHA256
    ) {
      fail(`${definition.case_id} registry identity disagrees with the authoritative source map`);
    }
  }
  return true;
}

export function validateSandboxProfile(profile) {
  assertExactKeys(
    profile,
    [
      "schema",
      "implementation",
      "mode",
      "claim_scope",
      "default_policy",
      "network",
      "docker",
      "live",
      "provider",
      "secrets",
      "deny_network",
      "deny_file_write_by_default",
      "target_worktree_write",
      "ephemeral_write",
      "filesystem_write",
      "allowed_write_scope",
      "inherit_environment",
      "process_exec_enforcement",
      "secret_read_enforcement",
      "denied_user_secret_roots",
      "expected_executables",
      "blocked_commands",
      "forbidden_capabilities",
    ],
    [],
    "sandbox_profile",
  );
  if (profile.schema !== SANDBOX_SCHEMA || profile.implementation !== "macos-sandbox-exec" || profile.mode !== "offline-contained") {
    fail("unsupported sandbox profile");
  }
  if (
    profile.default_policy !== "allow" ||
    profile.claim_scope !== "approved-tracked-seeds" ||
    profile.network !== false ||
    profile.docker !== false ||
    profile.live !== false ||
    profile.provider !== false ||
    profile.secrets !== false ||
    profile.deny_network !== true ||
    profile.deny_file_write_by_default !== true ||
    profile.target_worktree_write !== false ||
    profile.ephemeral_write !== true ||
    profile.inherit_environment !== false
  ) {
    fail("sandbox profile weakens the replay boundary");
  }
  if (
    profile.process_exec_enforcement !== "PATH-only-command-guards" ||
    profile.secret_read_enforcement !== "deny-listed-common-user-secret-roots" ||
    JSON.stringify(profile.denied_user_secret_roots) !== JSON.stringify(DENIED_USER_SECRET_ROOTS)
  ) {
    fail("sandbox containment scope is not explicit or exact");
  }
  if (!Array.isArray(profile.expected_executables) || profile.expected_executables.length === 0) {
    fail("sandbox profile must list the expected trusted-seed executables");
  }
  assertExactKeys(
    profile.filesystem_write,
    ["target_worktree", "baseline_worktree", "ephemeral_scratch", "external_artifacts"],
    [],
    "sandbox_profile.filesystem_write",
  );
  if (
    profile.filesystem_write.target_worktree !== false ||
    profile.filesystem_write.baseline_worktree !== false ||
    profile.filesystem_write.ephemeral_scratch !== true ||
    profile.filesystem_write.external_artifacts !== true
  ) {
    fail("sandbox filesystem-write semantics are inconsistent");
  }
  if (!Array.isArray(profile.blocked_commands) || !profile.blocked_commands.includes("docker") || !profile.blocked_commands.includes("ssh")) {
    fail("sandbox profile must block Docker and SSH commands");
  }
  return profile;
}

export async function loadSandboxProfile(profilePath = SANDBOX_PROFILE_PATH) {
  return validateSandboxProfile(JSON.parse(await readFile(profilePath, "utf8")));
}

async function collectSeedFiles(directory, relative = "") {
  const names = await readdir(path.join(directory, relative));
  const entries = [];
  for (const name of names.sort()) {
    const childRelative = relative ? `${relative}/${name}` : name;
    const childPath = path.join(directory, childRelative);
    const info = await lstat(childPath);
    if (info.isSymbolicLink()) fail(`tracked seed contains a symlink: ${childRelative}`);
    if (info.isDirectory()) {
      entries.push(...await collectSeedFiles(directory, childRelative));
    } else if (info.isFile()) {
      entries.push({
        path: childRelative,
        mode: (info.mode & 0o111) === 0 ? "100644" : "100755",
        sha256: sha256(await readFile(childPath)),
      });
    } else {
      fail(`tracked seed contains a special file: ${childRelative}`);
    }
  }
  return entries;
}

export async function computeSeedTreeSha256(caseDirectory) {
  const entries = await collectSeedFiles(caseDirectory);
  if (entries.length === 0) fail(`tracked seed directory is empty: ${caseDirectory}`);
  return sha256(entries.map((entry) => `${entry.path}\0${entry.mode}\0${entry.sha256}\n`).join(""));
}

export async function materializeEphemeralCaseSeed(definition, {
  repositoryRoot = REPOSITORY_ROOT,
  scratchRoot,
} = {}) {
  validateDefinition(definition);
  if (definition.entrypoint.kind !== "make") fail(`${definition.case_id} does not require an ephemeral case seed`);
  if (typeof scratchRoot !== "string" || !path.isAbsolute(scratchRoot)) {
    fail(`${definition.case_id} ephemeral scratch root must be absolute`);
  }
  await mkdir(scratchRoot, { recursive: true, mode: 0o700 });
  const canonicalScratchRoot = await realpath(scratchRoot);
  const source = path.resolve(repositoryRoot, definition.entrypoint.cwd);
  const expectedSource = path.resolve(repositoryRoot, `tests/pre-fix/cases/${definition.case_id}`);
  if (source !== expectedSource) fail(`${definition.case_id} tracked seed source is not case-confined`);
  const target = path.join(canonicalScratchRoot, "case-seed");
  await cp(source, target, {
    recursive: true,
    force: false,
    errorOnExist: true,
    dereference: false,
    verbatimSymlinks: true,
  });
  const copiedDigest = await computeSeedTreeSha256(target);
  if (copiedDigest !== definition.seed_tree_sha256) {
    fail(`${definition.case_id} ephemeral case seed digest mismatch`);
  }
  return { root: await realpath(target), sha256: copiedDigest };
}

async function runCommand(command, args, { cwd, env, timeoutMs = 30_000, maxOutputBytes = MAX_CASE_OUTPUT_BYTES } = {}) {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    let outputBytes = 0;
    let timedOut = false;
    let exceededOutput = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    const collect = (target) => (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > maxOutputBytes) {
        exceededOutput = true;
        child.kill("SIGKILL");
        return;
      }
      target.push(chunk);
    };
    child.stdout.on("data", collect(stdout));
    child.stderr.on("data", collect(stderr));
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      resolve({
        code,
        signal,
        timedOut,
        exceededOutput,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
}

async function git(repository, args) {
  const result = await runCommand("/usr/bin/git", ["-C", repository, ...args], {
    cwd: repository,
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
  });
  if (result.code !== 0) fail(`git ${args.join(" ")} failed: ${result.stderr.trim()}`);
  return result.stdout.trim();
}

async function resolveDeveloperTool(name) {
  if (!/^[a-z][a-z0-9-]*$/.test(name)) fail(`invalid developer tool name: ${name}`);
  const result = await runCommand("/usr/bin/xcrun", ["-f", name], {
    cwd: REPOSITORY_ROOT,
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
  });
  if (result.code !== 0) fail(`unable to resolve ${name} through xcrun: ${result.stderr.trim()}`);
  const resolved = await realpath(result.stdout.trim());
  if (!(await stat(resolved)).isFile()) fail(`xcrun returned a non-file for ${name}`);
  return resolved;
}

export function assertBaselineIdentity(identity) {
  if (identity.commit !== BASELINE_COMMIT || identity.tree !== BASELINE_TREE) {
    fail(`baseline identity mismatch: expected ${BASELINE_COMMIT}/${BASELINE_TREE}, got ${identity.commit}/${identity.tree}`);
  }
  if (identity.status !== "") fail("detached baseline worktree must be clean before replay");
  return identity;
}

export async function resolveBaselineIdentity(baselineRoot) {
  const resolved = await realpath(baselineRoot);
  const identity = {
    root: resolved,
    commit: await git(resolved, ["rev-parse", "HEAD"]),
    tree: await git(resolved, ["rev-parse", "HEAD^{tree}"]),
    status: await git(resolved, ["status", "--porcelain=v1", "--untracked-files=all"]),
  };
  const branch = await git(resolved, ["symbolic-ref", "-q", "HEAD"]).catch(() => "");
  if (branch !== "") fail("baseline must be a detached checkout, not a branch worktree");
  return assertBaselineIdentity(identity);
}

async function inspectObjectHardlinks(objectsRoot, relative = "") {
  const names = await readdir(path.join(objectsRoot, relative));
  let fileCount = 0;
  let maximumLinkCount = 0;
  for (const name of names) {
    const childRelative = relative ? `${relative}/${name}` : name;
    const childPath = path.join(objectsRoot, childRelative);
    const info = await lstat(childPath);
    if (info.isSymbolicLink()) fail(`baseline clone object store contains a symlink: ${childRelative}`);
    if (info.isDirectory()) {
      const nested = await inspectObjectHardlinks(objectsRoot, childRelative);
      fileCount += nested.fileCount;
      maximumLinkCount = Math.max(maximumLinkCount, nested.maximumLinkCount);
    } else if (info.isFile()) {
      fileCount += 1;
      maximumLinkCount = Math.max(maximumLinkCount, info.nlink);
      if (info.nlink !== 1) fail(`baseline clone object is hardlinked: ${childRelative}`);
    } else {
      fail(`baseline clone object store contains a special file: ${childRelative}`);
    }
  }
  return { fileCount, maximumLinkCount };
}

export async function materializeDetachedBaselineClone(sourceRepository, cloneRoot) {
  const sourceRoot = await realpath(sourceRepository);
  const sourceCommit = await git(sourceRoot, ["rev-parse", `${BASELINE_COMMIT}^{commit}`]);
  const sourceTree = await git(sourceRoot, ["rev-parse", `${BASELINE_COMMIT}^{tree}`]);
  if (sourceCommit !== BASELINE_COMMIT || sourceTree !== BASELINE_TREE) {
    fail("local baseline source does not contain the authoritative commit and tree");
  }
  const parent = path.dirname(cloneRoot);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const cloneResult = await runCommand(
    "/usr/bin/git",
    ["clone", "--quiet", "--no-hardlinks", "--no-checkout", "--", sourceRoot, cloneRoot],
    {
      cwd: parent,
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_TERMINAL_PROMPT: "0",
      },
      timeoutMs: 120_000,
    },
  );
  if (cloneResult.code !== 0) fail(`local no-hardlinks clone failed: ${cloneResult.stderr.trim()}`);
  await git(cloneRoot, ["checkout", "--quiet", "--detach", BASELINE_COMMIT]);
  await git(cloneRoot, ["remote", "remove", "origin"]);
  const dotGit = await lstat(path.join(cloneRoot, ".git"));
  if (!dotGit.isDirectory()) fail("baseline materialization is not a standalone clone");
  const alternatesPath = path.join(cloneRoot, ".git", "objects", "info", "alternates");
  const alternates = await readFile(alternatesPath, "utf8").catch((error) => {
    if (error.code === "ENOENT") return "";
    throw error;
  });
  if (alternates.trim() !== "") fail("baseline clone uses a shared object-store alternate");
  const hardlinkInspection = await inspectObjectHardlinks(path.join(cloneRoot, ".git", "objects"));
  if (hardlinkInspection.fileCount === 0 || hardlinkInspection.maximumLinkCount !== 1) {
    fail("baseline clone has no independently copied Git objects");
  }
  const identity = await resolveBaselineIdentity(cloneRoot);
  return {
    ...identity,
    materialization: "git-clone-no-hardlinks-local",
    object_files_checked: hardlinkInspection.fileCount,
    maximum_object_link_count: hardlinkInspection.maximumLinkCount,
    shared_object_alternates: false,
  };
}

export async function resolveRunnerIdentity(repositoryRoot = REPOSITORY_ROOT) {
  const status = await git(repositoryRoot, ["status", "--porcelain=v1", "--untracked-files=all"]);
  if (status !== "") fail(`runner worktree must be clean at HEAD:\n${status}`);
  const tracked = await git(repositoryRoot, ["ls-files", "--", "tests/pre-fix"]);
  if (tracked === "") fail("runner inputs are not tracked at HEAD");
  return {
    root: await realpath(repositoryRoot),
    commit: await git(repositoryRoot, ["rev-parse", "HEAD"]),
    tree: await git(repositoryRoot, ["rev-parse", "HEAD^{tree}"]),
  };
}

async function gitTrackedDescriptor(repositoryRoot, relativePath) {
  assertRelativeTrackedPath(relativePath, "tracked descriptor path");
  const line = await git(repositoryRoot, ["ls-tree", "HEAD", "--", relativePath]);
  const match = line.match(/^([0-7]{6}) blob ([0-9a-f]{40,64})\t(.+)$/);
  if (!match || match[3] !== relativePath) fail(`tracked input is not an exact Git blob at HEAD: ${relativePath}`);
  return {
    path: relativePath,
    mode: match[1],
    git_blob: match[2],
    sha256: sha256(await readFile(path.join(repositoryRoot, relativePath))),
  };
}

async function executableDescriptor(executablePath) {
  const resolved = await realpath(executablePath);
  const info = await stat(resolved);
  if (!info.isFile()) fail(`executable is not a regular file: ${executablePath}`);
  return {
    path: resolved,
    sha256: sha256(await readFile(resolved)),
  };
}

function replacePlaceholder(argument, replacements) {
  return argument.replaceAll("{{BASELINE_ROOT}}", replacements.BASELINE_ROOT).replaceAll("{{CONTRACT}}", replacements.CONTRACT);
}

export function createCaseInvocation(definition, {
  baselineRoot,
  repositoryRoot = REPOSITORY_ROOT,
  ephemeralCaseDirectory,
  nodePath = process.execPath,
  makePath = "/usr/bin/make",
  toolPathDirectories = [],
}) {
  validateDefinition(definition);
  const trackedCwd = path.resolve(repositoryRoot, definition.entrypoint.cwd);
  const expectedCwd = path.resolve(repositoryRoot, `tests/pre-fix/cases/${definition.case_id}`);
  if (trackedCwd !== expectedCwd) fail(`${definition.case_id} resolved cwd escapes its tracked case directory`);
  const commonMakeVariables = [
    `SOURCE_REPO=${baselineRoot}`,
    `SOURCE_ROOT=${baselineRoot}`,
    `CANDIDATE_ROOT=${baselineRoot}`,
    `CONTRACT=${path.join(baselineRoot, "scripts/hosted-workload-contract.mjs")}`,
    `REPOSITORY=${baselineRoot}`,
    `REPO=${baselineRoot}`,
    `REVISION=${BASELINE_COMMIT}`,
    "EXPECT=vulnerable",
    `CASE_ID=${definition.case_id}`,
  ];
  if (definition.entrypoint.kind === "make") {
    const cwd = ephemeralCaseDirectory === undefined ? trackedCwd : path.resolve(ephemeralCaseDirectory);
    return {
      command: makePath,
      args: ["--no-print-directory", "-s", definition.entrypoint.target, ...commonMakeVariables],
      cwd,
      toolPathDirectories,
    };
  }
  const script = path.resolve(repositoryRoot, definition.entrypoint.script);
  if (!script.startsWith(`${expectedCwd}${path.sep}`)) fail(`${definition.case_id} resolved script escapes its case directory`);
  const replacements = {
    BASELINE_ROOT: baselineRoot,
    CONTRACT: path.join(baselineRoot, "scripts/hosted-workload-contract.mjs"),
  };
  return {
    command: nodePath,
    args: [script, ...definition.entrypoint.args.map((argument) => replacePlaceholder(argument, replacements))],
    cwd: trackedCwd,
    toolPathDirectories,
  };
}

function escapeSandboxString(value) {
  return value.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

export function createSandboxPolicy({ scratchRoot, userHome = process.env.HOME ?? "" }) {
  const protectedReadRoots = DENIED_USER_SECRET_ROOTS
    .filter(() => userHome !== "")
    .map((suffix) => `(deny file-read* (subpath "${escapeSandboxString(path.join(userHome, suffix))}"))`);
  return [
    "(version 1)",
    "(allow default)",
    "(deny network*)",
    "(deny file-write*",
    "  (require-all",
    `    (require-not (subpath "${escapeSandboxString(scratchRoot)}"))`,
    '    (require-not (literal "/dev/null"))))',
    ...protectedReadRoots,
    "",
  ].join("\n");
}

async function prepareCommandGuards(guardRoot, blockedCommands) {
  await mkdir(guardRoot, { recursive: true, mode: 0o700 });
  for (const command of blockedCommands) {
    if (!/^[a-z][a-z0-9-]*$/.test(command)) fail(`unsafe blocked command name: ${command}`);
    const guard = path.join(guardRoot, command);
    await writeFile(guard, `#!/bin/sh\nprintf '%s\\n' 'blocked by pre-fix replay sandbox: ${command}' >&2\nexit 126\n`, { mode: 0o700 });
    await chmod(guard, 0o700);
  }
}

function createSandboxEnvironment({ scratchRoot, guardRoot, caseId, toolPathDirectories = [] }) {
  const nodeDirectory = path.dirname(process.execPath);
  const pathDirectories = [...new Set([guardRoot, nodeDirectory, ...toolPathDirectories, "/usr/bin", "/bin", "/usr/sbin", "/sbin"])];
  return {
    PATH: pathDirectories.join(":"),
    HOME: path.join(scratchRoot, "home"),
    TMPDIR: path.join(scratchRoot, "tmp"),
    USER: "pre-fix-replay",
    LOGNAME: "pre-fix-replay",
    SHELL: "/bin/sh",
    LANG: "C",
    LC_ALL: "C",
    TZ: "UTC",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
    SSH_AUTH_SOCK: "",
    DOCKER_HOST: "",
    PREFIX_REPLAY_CASE: caseId,
  };
}

export async function runSandboxedCommand(invocation, {
  scratchRoot,
  caseId,
  profile,
  timeoutMs = DEFAULT_CASE_TIMEOUT_MS,
  sandboxExecutable = "/usr/bin/sandbox-exec",
} = {}) {
  validateSandboxProfile(profile);
  if (process.platform !== "darwin") fail("the authoritative replay requires macOS sandbox-exec");
  const sandboxInfo = await stat(sandboxExecutable).catch(() => null);
  if (!sandboxInfo?.isFile()) fail("/usr/bin/sandbox-exec is unavailable");
  await mkdir(scratchRoot, { recursive: true, mode: 0o700 });
  const canonicalScratchRoot = await realpath(scratchRoot);
  await mkdir(path.join(canonicalScratchRoot, "home"), { recursive: true, mode: 0o700 });
  await mkdir(path.join(canonicalScratchRoot, "tmp"), { recursive: true, mode: 0o700 });
  const guardRoot = path.join(canonicalScratchRoot, "command-guards");
  await prepareCommandGuards(guardRoot, profile.blocked_commands);
  const sandboxPolicyPath = path.join(canonicalScratchRoot, "profile.sb");
  await writeFile(sandboxPolicyPath, createSandboxPolicy({ scratchRoot: canonicalScratchRoot }), { mode: 0o600 });
  const env = createSandboxEnvironment({
    scratchRoot: canonicalScratchRoot,
    guardRoot,
    caseId,
    toolPathDirectories: invocation.toolPathDirectories,
  });
  return await runCommand(
    sandboxExecutable,
    [
      "-f",
      sandboxPolicyPath,
      "/usr/bin/env",
      `PREFIX_REPLAY_CASE=${caseId}`,
      invocation.command,
      ...invocation.args,
    ],
    { cwd: invocation.cwd, env, timeoutMs },
  );
}

export async function assertExternalOutputDirectory(outputDirectory, protectedRoots) {
  if (typeof outputDirectory !== "string" || outputDirectory.length === 0 || outputDirectory.includes("\0")) {
    fail("output directory must be a non-empty path");
  }
  const absolute = path.resolve(outputDirectory);
  const canonicalProtectedRoots = await Promise.all(protectedRoots.map((protectedRoot) => realpath(protectedRoot)));
  const assertOutsideProtectedRoots = (candidate) => {
    for (const root of canonicalProtectedRoots) {
      if (candidate === root || candidate.startsWith(`${root}${path.sep}`)) {
        fail(`output directory must be external to protected worktree: ${candidate}`);
      }
    }
  };
  assertOutsideProtectedRoots(absolute);

  let outputInfo = await lstat(absolute).catch((error) => {
    if (error.code === "ENOENT") return null;
    throw error;
  });
  if (outputInfo?.isSymbolicLink()) fail(`output directory must not be a symbolic link: ${absolute}`);
  if (outputInfo !== null && !outputInfo.isDirectory()) fail(`output path must be a directory: ${absolute}`);
  if (outputInfo === null) {
    const parent = path.dirname(absolute);
    const parentInfo = await lstat(parent).catch((error) => {
      if (error.code === "ENOENT") fail(`output directory parent must already exist: ${parent}`);
      throw error;
    });
    if (parentInfo.isSymbolicLink() || !parentInfo.isDirectory()) {
      fail(`output directory parent must be a real directory: ${parent}`);
    }
    const canonicalParent = await realpath(parent);
    const canonicalCandidate = path.join(canonicalParent, path.basename(absolute));
    assertOutsideProtectedRoots(canonicalCandidate);
    await mkdir(canonicalCandidate, { mode: 0o700 });
  }

  outputInfo = await lstat(absolute);
  if (outputInfo.isSymbolicLink() || !outputInfo.isDirectory()) {
    fail(`output directory changed identity during validation: ${absolute}`);
  }
  const resolved = await realpath(absolute);
  assertOutsideProtectedRoots(resolved);
  if ((await readdir(resolved)).length !== 0) fail(`output directory must be empty: ${resolved}`);
  return resolved;
}

async function writeJsonAtomic(targetPath, value) {
  const temporary = `${targetPath}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await import("node:fs/promises").then(({ rename }) => rename(temporary, targetPath));
}

async function appendResult(targetPath, result) {
  const { appendFile } = await import("node:fs/promises");
  await appendFile(targetPath, `${JSON.stringify(result)}\n`, { mode: 0o600 });
}

export async function verifyTrackedSeeds(definitions, repositoryRoot = REPOSITORY_ROOT) {
  for (const definition of definitions) {
    const caseDirectory = path.join(repositoryRoot, definition.entrypoint.cwd);
    const actual = await computeSeedTreeSha256(caseDirectory);
    if (actual !== definition.seed_tree_sha256) {
      fail(`${definition.case_id} tracked seed digest mismatch: expected ${definition.seed_tree_sha256}, got ${actual}`);
    }
    const trackedSeed = definition.anchors.find((anchor) => anchor.kind === "tracked_seed");
    const trackedPath = path.join(repositoryRoot, trackedSeed.value);
    if (sha256(await readFile(trackedPath)) !== trackedSeed.sha256) {
      fail(`${definition.case_id} tracked seed anchor digest mismatch`);
    }
  }
}

export async function verifyBaselineConsumerAnchors(definitions, baselineRoot) {
  for (const definition of definitions) {
    const anchors = definition.anchors.filter((anchor) => anchor.kind === "baseline_consumer");
    if (anchors.length === 0) fail(`${definition.case_id} has no baseline consumer anchors`);
    for (const anchor of anchors) {
      const target = path.join(baselineRoot, anchor.value);
      const info = await lstat(target);
      if (!info.isFile() || info.isSymbolicLink()) fail(`${definition.case_id} baseline consumer anchor is not a regular file`);
      if (sha256(await readFile(target)) !== anchor.sha256) {
        fail(`${definition.case_id} baseline consumer anchor digest mismatch: ${anchor.value}`);
      }
    }
  }
}

function stableSemanticResult(result) {
  return {
    case_id: result.case_id,
    slug: result.slug,
    status: result.status,
    exit_code: result.exit_code,
    signal: result.signal,
    timed_out: result.timed_out,
    exceeded_output: result.exceeded_output,
    normalized_stdout_sha256: result.normalized_stdout_sha256,
    normalized_stderr_sha256: result.normalized_stderr_sha256,
    seed_tree_sha256: result.seed_tree_sha256,
    target_worktree_write: result.target_worktree_write,
    ephemeral_write: result.ephemeral_write,
  };
}

export function normalizeEvidenceText(value, volatilePaths) {
  let normalized = value.replaceAll("\r\n", "\n");
  for (const [label, volatilePath] of volatilePaths) {
    normalized = normalized.replaceAll(volatilePath, `<${label}>`);
    normalized = normalized.replaceAll(volatilePath.replace(/^\/private/, ""), `<${label}>`);
  }
  normalized = normalized.replaceAll(/\/private\/var\/folders\/[^\s'"`]+/g, "<SYSTEM_TEMP_PATH>");
  normalized = normalized.replaceAll(/\/var\/folders\/[^\s'"`]+/g, "<SYSTEM_TEMP_PATH>");
  normalized = normalized.replaceAll(/\((?:[0-9]+(?:\.[0-9]+)?)ms\)/g, "(<VOLATILE_DURATION_MS>)");
  normalized = normalized.replaceAll(/(\bduration_ms )[0-9]+(?:\.[0-9]+)?/g, "$1<VOLATILE_DURATION_MS>");
  normalized = normalized.replaceAll(/\b(wall_ms|cpu_ms|elapsed_ms|parse_ms)=[0-9]+(?:\.[0-9]+)?/g, "$1=<VOLATILE_DURATION_MS>");
  normalized = normalized.replaceAll(/\bheap_delta_bytes=-?[0-9]+/g, "heap_delta_bytes=<VOLATILE_BYTES>");
  normalized = normalized.replaceAll(/\bsha_changed=[0-9a-f]{12}->[0-9a-f]{12}\b/g, "sha_changed=<VOLATILE_SHA>-><VOLATILE_SHA>");
  normalized = normalized.replaceAll(/\bgenerated_at=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z\b/g, "generated_at=<VOLATILE_TIMESTAMP>");
  normalized = normalized.replaceAll(/(\[RECEIPT\][^\n]*\bsha256=)[0-9a-f]{64}\b/g, "$1<VOLATILE_SHA256>");
  normalized = normalized.replaceAll(/\bdevice_inode=[0-9]+:[0-9]+\b/g, "device_inode=<VOLATILE_DEVICE_INODE>");
  return normalized;
}

async function executeReplayOnBaseline({
  baselineRoot,
  baselineSourceRoot,
  baselineMaterialization,
  outputDirectory,
  selectedCaseIds = EXPECTED_CASE_IDS,
  caseTimeoutMs = DEFAULT_CASE_TIMEOUT_MS,
  repositoryRoot = REPOSITORY_ROOT,
  registryPath = REGISTRY_PATH,
  sandboxProfilePath = SANDBOX_PROFILE_PATH,
  sourceMapPath = SOURCE_MAP_PATH,
} = {}) {
  if (!baselineRoot) fail("materialized baseline root is required");
  if (!outputDirectory) fail("--output-dir is required");
  const replayStartedAt = new Date().toISOString();
  const runnerIdentity = await resolveRunnerIdentity(repositoryRoot);
  const baselineIdentity = await resolveBaselineIdentity(baselineRoot);
  const profile = await loadSandboxProfile(sandboxProfilePath);
  const definitions = await loadRegistry(registryPath);
  const sourceMap = await loadSourceMap(sourceMapPath);
  verifyRegistrySourceMap(definitions, sourceMap);
  await verifyTrackedSeeds(definitions, repositoryRoot);
  await verifyBaselineConsumerAnchors(definitions, baselineIdentity.root);
  const selectedSet = new Set(selectedCaseIds);
  if (selectedSet.size !== selectedCaseIds.length || selectedCaseIds.some((id) => !EXPECTED_CASE_IDS.includes(id))) {
    fail("selected case ids must be unique FG-001 through FG-077 identities");
  }
  const selectedDefinitions = definitions.filter((definition) => selectedSet.has(definition.case_id));
  if (selectedDefinitions.length !== selectedCaseIds.length) fail("one or more selected case ids are missing from the registry");
  const outputRoot = await assertExternalOutputDirectory(outputDirectory, [repositoryRoot, baselineIdentity.root, baselineSourceRoot]);
  const resultsPath = path.join(outputRoot, "results.jsonl");
  await writeFile(resultsPath, "", { mode: 0o600 });
  const profileSha256 = sha256(await readFile(sandboxProfilePath));
  const registrySha256 = sha256(await readFile(registryPath));
  const sourceMapSha256 = sha256(await readFile(sourceMapPath));
  const trackedInputs = {
    runner: await gitTrackedDescriptor(repositoryRoot, "tests/pre-fix/run-pre-fix-replay.mjs"),
    registry: await gitTrackedDescriptor(repositoryRoot, "tests/pre-fix/definition-registry.jsonl"),
    sandbox_profile: await gitTrackedDescriptor(repositoryRoot, "tests/pre-fix/sandbox-profile.json"),
    source_map: await gitTrackedDescriptor(repositoryRoot, "tests/pre-fix/security-fix-groups-v1.jsonl"),
  };
  const sandboxExecutable = await executableDescriptor("/usr/bin/sandbox-exec");
  const makePath = await resolveDeveloperTool("make");
  const gitPath = await resolveDeveloperTool("git");
  const toolPathDirectories = [...new Set([path.dirname(makePath), path.dirname(gitPath)])];
  const results = [];
  for (const [index, definition] of selectedDefinitions.entries()) {
    const caseArtifacts = path.join(outputRoot, definition.case_id);
    const scratchRoot = path.join(caseArtifacts, "scratch");
    await mkdir(caseArtifacts, { recursive: true, mode: 0o700 });
    const startedAt = new Date().toISOString();
    const started = process.hrtime.bigint();
    let invocation;
    let primaryExecutable;
    let execution;
    try {
      const ephemeralSeed = definition.entrypoint.kind === "make"
        ? await materializeEphemeralCaseSeed(definition, { repositoryRoot, scratchRoot })
        : null;
      invocation = createCaseInvocation(definition, {
        baselineRoot: baselineIdentity.root,
        repositoryRoot,
        ephemeralCaseDirectory: ephemeralSeed?.root,
        makePath,
        toolPathDirectories,
      });
      primaryExecutable = await executableDescriptor(invocation.command);
      execution = await runSandboxedCommand(invocation, {
        scratchRoot,
        caseId: definition.case_id,
        profile,
        timeoutMs: caseTimeoutMs,
      });
    } finally {
      await rm(scratchRoot, { recursive: true, force: true });
    }
    const durationMs = Number(process.hrtime.bigint() - started) / 1_000_000;
    const finishedAt = new Date().toISOString();
    const baselineStatusAfter = await git(baselineIdentity.root, ["status", "--porcelain=v1", "--untracked-files=all"]);
    if (baselineStatusAfter !== "") fail(`${definition.case_id} changed the detached baseline despite the sandbox`);
    const runnerStatusAfter = await git(repositoryRoot, ["status", "--porcelain=v1", "--untracked-files=all"]);
    if (runnerStatusAfter !== "") fail(`${definition.case_id} changed the runner worktree despite the sandbox`);
    await writeFile(path.join(caseArtifacts, "stdout.log"), execution.stdout, { mode: 0o600 });
    await writeFile(path.join(caseArtifacts, "stderr.log"), execution.stderr, { mode: 0o600 });
    const status = execution.code === 0 && !execution.timedOut && !execution.exceededOutput ? "PASS" : "FAIL";
    const normalizedStdout = normalizeEvidenceText(execution.stdout, [
      ["BASELINE_CLONE", baselineIdentity.root],
      ["OUTPUT_ROOT", outputRoot],
      ["CASE_SCRATCH", scratchRoot],
      ["RUNNER_WORKTREE", repositoryRoot],
    ]);
    const normalizedStderr = normalizeEvidenceText(execution.stderr, [
      ["BASELINE_CLONE", baselineIdentity.root],
      ["OUTPUT_ROOT", outputRoot],
      ["CASE_SCRATCH", scratchRoot],
      ["RUNNER_WORKTREE", repositoryRoot],
    ]);
    const executionLog = [
      JSON.stringify({
        schema: "platform.pre-fix-negative-replay-log-envelope/v2",
        case_id: definition.case_id,
        baseline_commit: baselineIdentity.commit,
        baseline_tree: baselineIdentity.tree,
        runner_commit: runnerIdentity.commit,
        seed_tree_sha256: definition.seed_tree_sha256,
        executable_sha256: primaryExecutable.sha256,
      }),
      "--- stdout ---",
      execution.stdout,
      "--- stderr ---",
      execution.stderr,
    ].join("\n");
    const executionLogPath = path.join(caseArtifacts, "execution.log");
    await writeFile(executionLogPath, executionLog, { mode: 0o600 });
    const result = {
      schema: "platform.pre-fix-negative-replay-case-result/v2",
      execution_index: index + 1,
      execution_id: `${definition.case_id}:${sha256(`${runnerIdentity.commit}\0${baselineIdentity.commit}\0${definition.seed_tree_sha256}`).slice(0, 24)}`,
      case_id: definition.case_id,
      slug: definition.slug,
      started_at: startedAt,
      finished_at: finishedAt,
      status,
      exit_code: execution.code,
      signal: execution.signal,
      timed_out: execution.timedOut,
      exceeded_output: execution.exceededOutput,
      duration_ms: Math.round(durationMs * 1000) / 1000,
      stdout_sha256: sha256(execution.stdout),
      stderr_sha256: sha256(execution.stderr),
      normalized_stdout_sha256: sha256(normalizedStdout),
      normalized_stderr_sha256: sha256(normalizedStderr),
      command: invocation.command,
      argv: invocation.args,
      executable: primaryExecutable,
      seed_tree_sha256: definition.seed_tree_sha256,
      proof_scope: definition.proof_scope,
      residuals: definition.residuals,
      anchors: definition.anchors,
      consumer_git_anchors: definition.anchors
        .filter((anchor) => anchor.kind === "baseline_consumer")
        .map((anchor) => ({
          commit: baselineIdentity.commit,
          tree: baselineIdentity.tree,
          path: anchor.value,
          sha256: anchor.sha256,
        })),
      target_worktree_write: false,
      ephemeral_write: true,
      forbidden_access: { network: false, docker: false, live: false, provider: false, secrets: false },
      access_claim_scope: profile.claim_scope,
      log_envelope: {
        schema: "platform.pre-fix-negative-replay-log-envelope/v2",
        path: `${definition.case_id}/execution.log`,
        sha256: sha256(executionLog),
        stdout_sha256: sha256(execution.stdout),
        stderr_sha256: sha256(execution.stderr),
        normalized_stdout_sha256: sha256(normalizedStdout),
        normalized_stderr_sha256: sha256(normalizedStderr),
      },
      artifact_paths: {
        stdout: `${definition.case_id}/stdout.log`,
        stderr: `${definition.case_id}/stderr.log`,
        log: `${definition.case_id}/execution.log`,
      },
    };
    results.push(result);
    await appendResult(resultsPath, result);
  }
  const postBaseline = await resolveBaselineIdentity(baselineIdentity.root);
  const postRunner = await resolveRunnerIdentity(repositoryRoot);
  if (postBaseline.commit !== baselineIdentity.commit || postBaseline.tree !== baselineIdentity.tree) {
    fail("baseline identity changed during replay");
  }
  if (postRunner.commit !== runnerIdentity.commit || postRunner.tree !== runnerIdentity.tree) {
    fail("runner identity changed during replay");
  }
  const passed = results.filter((result) => result.status === "PASS").length;
  const stableResults = results.map(stableSemanticResult);
  const replayFinishedAt = new Date().toISOString();
  const summary = {
    schema: RECEIPT_SCHEMA,
    started_at: replayStartedAt,
    finished_at: replayFinishedAt,
    verdict: passed === results.length ? "PASS" : "FAIL",
    baseline: {
      commit: baselineIdentity.commit,
      tree: baselineIdentity.tree,
      detached: true,
      materialization: baselineMaterialization.materialization,
      object_files_checked: baselineMaterialization.object_files_checked,
      maximum_object_link_count: baselineMaterialization.maximum_object_link_count,
      shared_object_alternates: baselineMaterialization.shared_object_alternates,
      clean_before: true,
      clean_after: true,
    },
    runner: { commit: runnerIdentity.commit, tree: runnerIdentity.tree, clean_before: true, clean_after: true },
    tracked_inputs: trackedInputs,
    registry_sha256: registrySha256,
    source_map_sha256: sourceMapSha256,
    sandbox_profile_sha256: profileSha256,
    sandbox: {
      schema: profile.schema,
      mode: profile.mode,
      claim_scope: profile.claim_scope,
      implementation: profile.implementation,
      executable: sandboxExecutable,
      network: false,
      docker: false,
      live: false,
      provider: false,
      secrets: false,
      process_exec_enforcement: profile.process_exec_enforcement,
      secret_read_enforcement: profile.secret_read_enforcement,
      denied_user_secret_roots: profile.denied_user_secret_roots,
      forbidden_access: ["network", "docker", "live", "provider", "listed_user_secret_roots", "target_worktree_write", "baseline_worktree_write"],
      target_worktree_write: false,
      ephemeral_write: true,
      environment_inherited: false,
    },
    trust_assumptions: [
      "The checkout, approved tracked seed PoCs, Node executable, runner command, bootstrap, and CI are trusted.",
      "The sandbox enforces network and filesystem-write boundaries but does not claim containment of arbitrary hostile code introduced before the trusted bootstrap.",
      "Process-exec guards are PATH-based; approved tracked seeds are trusted not to bypass them with undeclared absolute executables.",
    ],
    access_claim_scope: profile.claim_scope,
    filesystem_write: {
      target_worktree: false,
      baseline_worktree: false,
      runner_worktree: false,
      ephemeral_scratch: true,
      external_artifacts: true,
    },
    forbidden_access: { network: false, docker: false, live: false, provider: false, secrets: false },
    output: {
      external_to_runner_worktree: true,
      external_to_baseline_worktree: true,
      external_to_baseline_source: true,
      tracked: false,
    },
    target_worktree_write: false,
    ephemeral_write: true,
    counts: {
      expected: selectedDefinitions.length,
      executed: results.length,
      passed,
      failed: results.length - passed,
    },
    case_ids: results.map((result) => result.case_id),
    semantic_results_sha256: sha256(`${stableResults.map((result) => JSON.stringify(result)).join("\n")}\n`),
    proof_scope: {
      kind: "exact-baseline-negative-reproduction",
      statement: "Each selected FG runs as a distinct migrated seed PoC against the exact detached pre-fix source tree; this is source-level negative evidence, not deployed-runtime evidence.",
      classifications: Object.fromEntries(
        ["offline-product-consumer", "offline-source-control", "offline-source-model"].map((classification) => [
          classification,
          selectedDefinitions.filter((definition) => definition.proof_scope.classification === classification).length,
        ]),
      ),
      excludes: [
        "post-fix remediation correctness",
        "live deployment state",
        "provider or production attestation",
      ],
    },
    residuals: [
      "A PASS proves only that the exact detached pre-fix source tree satisfies each tracked seed's negative oracle; it is not runtime or live-state proof.",
      "Positive, regression, hostile, integration, provider, and post-deploy evidence remain separate gates.",
      "Generic containment of malicious tracked seed code is outside the declared threat model; the access attestations apply only to the approved exact seed corpus.",
    ],
  };
  await writeJsonAtomic(path.join(outputRoot, "summary.json"), summary);
  return { summary, results, outputRoot };
}

export async function runReplay({ baselineSource, ...options } = {}) {
  if (!baselineSource) fail("--baseline-source is required");
  const baselineSourceRoot = await realpath(baselineSource);
  const cloneParent = await mkdtemp(path.join(tmpdir(), "pre-fix-baseline-no-hardlinks-"));
  const cloneRoot = path.join(cloneParent, "baseline");
  try {
    const baselineMaterialization = await materializeDetachedBaselineClone(baselineSourceRoot, cloneRoot);
    return await executeReplayOnBaseline({
      ...options,
      baselineRoot: cloneRoot,
      baselineSourceRoot,
      baselineMaterialization,
    });
  } finally {
    await rm(cloneParent, { recursive: true, force: true });
  }
}

function parseCli(argv) {
  const parsed = { selectedCaseIds: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const next = () => {
      index += 1;
      if (index >= argv.length) fail(`${argument} requires a value`);
      return argv[index];
    };
    if (argument === "--baseline-source") parsed.baselineSource = next();
    else if (argument === "--output-dir") parsed.outputDirectory = next();
    else if (argument === "--case") parsed.selectedCaseIds.push(next());
    else if (argument === "--case-timeout-ms") {
      parsed.caseTimeoutMs = Number(next());
      if (!Number.isSafeInteger(parsed.caseTimeoutMs) || parsed.caseTimeoutMs < 1_000 || parsed.caseTimeoutMs > 600_000) {
        fail("--case-timeout-ms must be an integer from 1000 through 600000");
      }
    } else if (argument === "--help") parsed.help = true;
    else fail(`unknown argument: ${argument}`);
  }
  if (parsed.selectedCaseIds.length === 0) parsed.selectedCaseIds = [...EXPECTED_CASE_IDS];
  return parsed;
}

function printHelp() {
  process.stdout.write([
    "Usage: node tests/pre-fix/run-pre-fix-replay.mjs --baseline-source PATH --output-dir PATH [--case FG-NNN]",
    "",
    `Required baseline commit: ${BASELINE_COMMIT}`,
    `Required baseline tree:   ${BASELINE_TREE}`,
    "The runner makes a detached local git clone --no-hardlinks in system temp.",
    "The output directory must be empty and external to the source and runner worktrees.",
    "",
  ].join("\n"));
}

async function main() {
  const options = parseCli(process.argv.slice(2));
  if (options.help) {
    printHelp();
    return;
  }
  const { summary, outputRoot } = await runReplay(options);
  process.stdout.write(`${JSON.stringify({ verdict: summary.verdict, counts: summary.counts, output_root: outputRoot })}\n`);
  if (summary.verdict !== "PASS") process.exitCode = 1;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    process.stderr.write(`[pre-fix-replay] ${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  });
}
