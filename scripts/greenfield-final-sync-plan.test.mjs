import assert from "node:assert/strict";
import test from "node:test";
import { buildFinalSyncSequence, validateDeltaZero, serializeFinalSyncPlan } from "./greenfield-final-sync-plan.mjs";
import { finalSyncWriterRegistry } from "./greenfield-state-projection.mjs";

const EXPECTED_WRITERS = Object.freeze([
  "app-bind-trees",
  "control-center-state",
  "mariadb",
  "minio",
  "nats-data",
  "postgres-keycloak",
  "postgres-stexor",
]);

test("final sync sequence covers exactly the registry writers", () => {
  const sequence = buildFinalSyncSequence();
  const writers = sequence.phases[0].writers.map((writer) => writer.writerId);
  assert.deepEqual(writers.sort(), [...EXPECTED_WRITERS].sort());
  assert.equal(writers.length, finalSyncWriterRegistry().length);
});

test("phases are ordered and quiesce precedes capture for every writer", () => {
  const sequence = buildFinalSyncSequence();
  assert.deepEqual(
    sequence.phases.map((phase) => phase.phase),
    ["QUIESCE_WRITERS", "FINAL_CAPTURE", "VERIFY_CAPTURE", "RESTORE_FINAL", "VERIFY_DELTA", "RESUME_OR_CUTOVER"],
  );
  for (const phase of sequence.phases) {
    if (phase.phase === "QUIESCE_WRITERS") {
      for (const writer of phase.writers) {
        assert.ok(writer.steps.length >= 1, `quiesce steps missing for ${writer.writerId}`);
        assert.ok(writer.steps.every((step) => /quiesce|stop/i.test(step)));
      }
    }
    if (phase.phase === "FINAL_CAPTURE") {
      for (const writer of phase.writers) {
        assert.match(writer.steps[0], /^capture:/);
      }
    }
  }
});

test("sequence serialization is byte-stable and free of brownfield names", () => {
  const a = serializeFinalSyncPlan(buildFinalSyncSequence());
  const b = serializeFinalSyncPlan(buildFinalSyncSequence());
  assert.equal(a, b);
  assert.ok(!a.includes("enterprise_"));
  assert.ok(!a.includes("platform_infra_vps"));
});

function fp(family, items) {
  return { family, items };
}

test("delta-zero validator accepts exact match across families", () => {
  const pre = [
    fp("postgres-stexor", [{ id: "public.jobs", count: 3 }]),
    fp("mariadb", [{ id: "wp.posts", count: 9 }]),
  ];
  const post = JSON.parse(JSON.stringify(pre));
  assert.deepEqual(validateDeltaZero({ preCutoverFingerprints: pre, postRestoreFingerprints: post }), []);
});

test("delta-zero validator names the violating writer", () => {
  const pre = [fp("postgres-stexor", [{ id: "public.jobs", count: 3 }])];
  const post = [fp("postgres-stexor", [{ id: "public.jobs", count: 4 }])];
  const violations = validateDeltaZero({ preCutoverFingerprints: pre, postRestoreFingerprints: post });
  assert.equal(violations.length, 1);
  assert.equal(violations[0].writerId, "postgres-stexor");
  assert.equal(violations[0].id, "public.jobs");
  assert.match(violations[0].directive, /MUST EQUAL/);
});

test("post-cutover family without baseline is a violation", () => {
  const violations = validateDeltaZero({
    preCutoverFingerprints: [],
    postRestoreFingerprints: [fp("minio", [{ id: "bucket/a", size: 12 }])],
  });
  assert.equal(violations.length, 1);
  assert.match(violations[0].reason, /missing pre-cutover baseline/);
});
