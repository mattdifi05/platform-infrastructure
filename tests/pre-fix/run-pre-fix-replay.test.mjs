import assert from "node:assert/strict";
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  BASELINE_COMMIT,
  BASELINE_TREE,
  EXPECTED_CASE_IDS,
  PRE_FIX_ROOT,
  REPOSITORY_ROOT,
  assertExternalOutputDirectory,
  assertBaselineIdentity,
  computeSeedTreeSha256,
  createCaseInvocation,
  createSandboxPolicy,
  loadRegistry,
  loadSandboxProfile,
  materializeDetachedBaselineClone,
  materializeEphemeralCaseSeed,
  normalizeEvidenceText,
  runReplay,
  runSandboxedCommand,
  sha256,
  validateDefinition,
  validateSandboxProfile,
  verifyBaselineConsumerAnchors,
  verifyTrackedSeeds,
} from "./run-pre-fix-replay.mjs";

test("schema v2 registry preserves exactly 77 distinct FG identities", async () => {
  const definitions = await loadRegistry();
  assert.equal(definitions.length, 77);
  assert.deepEqual(definitions.map((definition) => definition.case_id), EXPECTED_CASE_IDS);
  assert.equal(new Set(definitions.map((definition) => definition.slug)).size, 77);
  assert.deepEqual(
    Object.fromEntries([...new Set(definitions.map((definition) => definition.proof_scope.classification))]
      .sort()
      .map((classification) => [classification, definitions.filter((definition) => definition.proof_scope.classification === classification).length])),
    {
      "offline-product-consumer": 47,
      "offline-source-control": 3,
      "offline-source-model": 27,
    },
  );
  for (const definition of definitions) {
    assert.equal(definition.target_worktree_write, false);
    assert.equal(definition.ephemeral_write, true);
    assert.equal(definition.baseline.commit, BASELINE_COMMIT);
    assert.equal(definition.baseline.tree, BASELINE_TREE);
    assert.equal(definition.proof_scope.kind, "exact-baseline-negative-reproduction");
    assert.ok(definition.residuals.length >= 1);
    assert.deepEqual(definition.anchors.slice(0, 2).map((anchor) => anchor.kind), ["root_control", "tracked_seed"]);
    assert.ok(definition.anchors.some((anchor) => anchor.kind === "baseline_consumer"));
  }
});

test("every migrated seed tree and primary probe matches its registry digest", async () => {
  const definitions = await loadRegistry();
  await verifyTrackedSeeds(definitions);
  for (const definition of definitions) {
    const caseDirectory = path.join(REPOSITORY_ROOT, definition.entrypoint.cwd);
    assert.equal(await computeSeedTreeSha256(caseDirectory), definition.seed_tree_sha256);
    const anchor = definition.anchors.find((candidate) => candidate.kind === "tracked_seed");
    assert.equal(sha256(await readFile(path.join(REPOSITORY_ROOT, anchor.value))), anchor.sha256);
  }
});

test("registry validation fails closed on filesystem-write and baseline drift", async () => {
  const [definition] = await loadRegistry();
  assert.throws(
    () => validateDefinition({ ...definition, target_worktree_write: true }),
    /unsafe filesystem-write declaration/,
  );
  assert.throws(
    () => validateDefinition({ ...definition, baseline: { ...definition.baseline, tree: "0".repeat(40) } }),
    /authoritative detached baseline/,
  );
  assert.throws(
    () => assertBaselineIdentity({ commit: BASELINE_COMMIT, tree: BASELINE_TREE, status: "?? unexpected" }),
    /must be clean/,
  );
});

test("entrypoints are case-confined and produce distinct FG argv", async () => {
  const definitions = await loadRegistry();
  const baselineRoot = "/tmp/example-detached-baseline";
  const invocations = definitions.map((definition) => createCaseInvocation(definition, { baselineRoot }));
  assert.equal(new Set(invocations.map((invocation, index) => {
    const definition = definitions[index];
    return `${definition.case_id}\0${invocation.command}\0${invocation.args.join("\0")}`;
  })).size, 77);
  for (const [index, invocation] of invocations.entries()) {
    const definition = definitions[index];
    assert.equal(invocation.cwd, path.join(REPOSITORY_ROOT, "tests/pre-fix/cases", definition.case_id));
    if (definition.entrypoint.kind === "make") {
      assert.ok(invocation.args.includes(`CASE_ID=${definition.case_id}`));
    } else {
      assert.ok(invocation.args.some((argument) => argument === baselineRoot));
    }
  }
});

test("make seeds execute from a byte-identical ephemeral scratch copy", async () => {
  const definitions = await loadRegistry();
  const definition = definitions.find((candidate) => candidate.case_id === "FG-026");
  const root = await mkdtemp(path.join(tmpdir(), "pre-fix-seed-copy-test-"));
  try {
    const materialized = await materializeEphemeralCaseSeed(definition, { scratchRoot: root });
    assert.ok(materialized.root.startsWith(`${await realpath(root)}${path.sep}`));
    assert.equal(materialized.sha256, definition.seed_tree_sha256);
    const invocation = createCaseInvocation(definition, {
      baselineRoot: "/tmp/example-detached-baseline",
      ephemeralCaseDirectory: materialized.root,
    });
    assert.equal(invocation.cwd, materialized.root);
    assert.equal(await computeSeedTreeSha256(materialized.root), definition.seed_tree_sha256);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("semantic normalization removes only declared volatile telemetry", () => {
  const first = [
    "ok (12.34ms)",
    "duration_ms 98.7",
    "wall_ms=1.2 cpu_ms=3 elapsed_ms=4.5 parse_ms=6 heap_delta_bytes=-44",
    "sha_changed=aaaaaaaaaaaa->bbbbbbbbbbbb",
    "[RECEIPT] generated_at=2026-08-01T19:38:53.569Z sha256=" + "c".repeat(64),
    "device_inode=16777231:57725522",
  ].join("\n");
  const second = [
    "ok (99ms)",
    "duration_ms 1",
    "wall_ms=7 cpu_ms=8.9 elapsed_ms=10 parse_ms=11.2 heap_delta_bytes=55",
    "sha_changed=dddddddddddd->eeeeeeeeeeee",
    "[RECEIPT] generated_at=2027-01-02T03:04:05.006Z sha256=" + "f".repeat(64),
    "device_inode=1:2",
  ].join("\n");
  assert.equal(normalizeEvidenceText(first, []), normalizeEvidenceText(second, []));
  assert.match(normalizeEvidenceText(first, []), /<VOLATILE_DURATION_MS>/);
});

test("sandbox profile denies network and target writes while declaring ephemeral writes", async () => {
  const profile = await loadSandboxProfile();
  assert.equal(validateSandboxProfile(profile), profile);
  const policy = createSandboxPolicy({ scratchRoot: "/tmp/pre-fix-scratch", userHome: "/Users/example" });
  assert.match(policy, /\(deny network\*\)/);
  assert.match(policy, /\(deny file-write\*/);
  assert.match(policy, /pre-fix-scratch/);
  assert.match(policy, /\.ssh/);
  assert.equal(profile.target_worktree_write, false);
  assert.equal(profile.ephemeral_write, true);
  assert.equal(profile.mode, "offline-contained");
  assert.deepEqual(profile.filesystem_write, {
    target_worktree: false,
    baseline_worktree: false,
    ephemeral_scratch: true,
    external_artifacts: true,
  });
});

test("external output validation rejects symlink aliases into protected roots", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "pre-fix-output-boundary-test-"));
  const protectedRoot = path.join(root, "protected");
  const outsideRoot = path.join(root, "outside");
  const protectedTarget = path.join(protectedRoot, "empty-target");
  try {
    await mkdir(protectedTarget, { recursive: true });
    await mkdir(outsideRoot);
    const leafAlias = path.join(outsideRoot, "leaf-alias");
    await symlink(protectedTarget, leafAlias);
    await assert.rejects(
      assertExternalOutputDirectory(leafAlias, [protectedRoot]),
      /must not be a symbolic link/,
    );

    const parentAlias = path.join(outsideRoot, "parent-alias");
    await symlink(protectedRoot, parentAlias);
    const aliasedChild = path.join(parentAlias, "new-output");
    await assert.rejects(
      assertExternalOutputDirectory(aliasedChild, [protectedRoot]),
      /parent must be a real directory/,
    );
    await assert.rejects(lstat(path.join(protectedRoot, "new-output")), /ENOENT/);

    const external = path.join(outsideRoot, "evidence");
    assert.equal(await assertExternalOutputDirectory(external, [protectedRoot]), await realpath(external));
    assert.ok((await lstat(external)).isDirectory());
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("baseline materialization is detached, exact, and contains no hardlinked Git objects", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "pre-fix-clone-test-"));
  try {
    const identity = await materializeDetachedBaselineClone(REPOSITORY_ROOT, path.join(root, "baseline"));
    assert.equal(identity.commit, BASELINE_COMMIT);
    assert.equal(identity.tree, BASELINE_TREE);
    assert.equal(identity.materialization, "git-clone-no-hardlinks-local");
    assert.ok(identity.object_files_checked > 0);
    assert.equal(identity.maximum_object_link_count, 1);
    assert.equal(identity.shared_object_alternates, false);
    await verifyBaselineConsumerAnchors(await loadRegistry(), identity.root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("macOS sandbox permits only scratch writes and rejects a loopback listener", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("authoritative sandbox-exec integration is macOS-only");
    return;
  }
  const root = await mkdtemp(path.join(tmpdir(), "pre-fix-sandbox-test-"));
  const scratchRoot = path.join(root, "scratch");
  const forbiddenPath = path.join(root, "outside-scratch");
  const allowedPath = path.join(scratchRoot, "allowed");
  const profile = await loadSandboxProfile();
  const program = [
    "const fs=require('node:fs');",
    "const net=require('node:net');",
    "fs.writeFileSync(process.argv[1], 'allowed');",
    "let denied=false;",
    "try { fs.writeFileSync(process.argv[2], 'forbidden'); } catch (error) { denied=true; }",
    "if (!denied) process.exit(71);",
    "const server=net.createServer();",
    "server.once('error', () => { process.stdout.write('write-denied network-denied\\n'); process.exit(0); });",
    "server.listen(0, '127.0.0.1', () => { server.close(); process.exit(72); });",
  ].join("");
  try {
    const result = await runSandboxedCommand(
      { command: process.execPath, args: ["-e", program, allowedPath, forbiddenPath], cwd: root },
      { scratchRoot, caseId: "FG-001", profile, timeoutMs: 10_000 },
    );
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /write-denied network-denied/);
    assert.equal(await readFile(allowedPath, "utf8"), "allowed");
    await assert.rejects(readFile(forbiddenPath), /ENOENT/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("two committed representative replays have identical semantic evidence", {
  skip: process.env.PREFIX_RUN_COMMITTED_REPLAY_INTEGRATION !== "1",
}, async () => {
  const root = await mkdtemp(path.join(tmpdir(), "pre-fix-determinism-test-"));
  const selectedCaseIds = ["FG-001", "FG-004", "FG-005", "FG-026", "FG-030"];
  try {
    const first = await runReplay({
      baselineSource: REPOSITORY_ROOT,
      outputDirectory: path.join(root, "run-a"),
      selectedCaseIds,
    });
    const second = await runReplay({
      baselineSource: REPOSITORY_ROOT,
      outputDirectory: path.join(root, "run-b"),
      selectedCaseIds,
    });
    assert.equal(first.summary.verdict, "PASS");
    assert.equal(second.summary.verdict, "PASS");
    assert.equal(first.summary.semantic_results_sha256, second.summary.semantic_results_sha256);
    assert.deepEqual(
      first.results.map(({ case_id, normalized_stdout_sha256, normalized_stderr_sha256 }) => ({ case_id, normalized_stdout_sha256, normalized_stderr_sha256 })),
      second.results.map(({ case_id, normalized_stdout_sha256, normalized_stderr_sha256 }) => ({ case_id, normalized_stdout_sha256, normalized_stderr_sha256 })),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
