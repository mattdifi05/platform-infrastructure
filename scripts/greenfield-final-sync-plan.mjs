// Greenfield final synchronized capture plan: zero-window delta between the
// last brownfield writes and the greenfield cutover.

import { CAPTURE_CONTRACTS, compareFingerprints } from "./greenfield-backup-restore-executor.mjs";
import { finalSyncWriterRegistry } from "./greenfield-state-projection.mjs";

export const SCHEMA = "platform.greenfield-final-sync-plan/v1";

const PHASE_ORDER = Object.freeze([
  "QUIESCE_WRITERS",
  "FINAL_CAPTURE",
  "VERIFY_CAPTURE",
  "RESTORE_FINAL",
  "VERIFY_DELTA",
  "RESUME_OR_CUTOVER",
]);

const WRITER_TO_FAMILY = Object.freeze({
  "postgres-stexor": "postgres-stexor",
  "postgres-keycloak": "postgres-keycloak",
  mariadb: "mariadb",
  minio: "minio",
  "app-bind-trees": "app-bind-trees",
  "control-center-state": "control-center-state",
});

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const key of Object.keys(value)) {
      deepFreeze(value[key]);
    }
    Object.freeze(value);
  }
  return value;
}

export function buildFinalSyncSequence() {
  const registry = finalSyncWriterRegistry();
  const registryIds = registry.map((writer) => writer.writerId).sort();
  const coveredIds = Object.keys(WRITER_TO_FAMILY).sort();
  const uncovered = registryIds.filter((id) => !coveredIds.includes(id));
  if (uncovered.length > 0 || coveredIds.length !== registryIds.length) {
    throw new Error(`final sync sequence has uncovered writers: ${uncovered.join(", ") || "registry/coverage mismatch"}`);
  }
  for (const writerId of coveredIds) {
    if (!Object.hasOwn(CAPTURE_CONTRACTS, WRITER_TO_FAMILY[writerId])) {
      throw new Error(`no capture contract for writer ${writerId}`);
    }
  }

  const phases = PHASE_ORDER.map((phase) => ({
    phase,
    writers: registryIds.map((writerId) => {
      const writer = registry.find((entry) => entry.writerId === writerId);
      const family = WRITER_TO_FAMILY[writerId];
      return deepFreeze({
        writerId,
        family,
        steps:
          phase === "QUIESCE_WRITERS"
            ? [...writer.steps.filter((step) => /quiesce|stop/i.test(step))]
            : phase === "FINAL_CAPTURE"
              ? [`capture:${family} per ${CAPTURE_CONTRACTS[family].artifacts.join("+")}`]
              : phase === "VERIFY_CAPTURE"
                ? [`verify fingerprint after capture:${family}`]
                : phase === "RESTORE_FINAL"
                  ? [`restore-final into greenfield target:${family}`]
                  : phase === "VERIFY_DELTA"
                    ? [`delta must be zero for:${family}`]
                    : [`resume-or-cut-over writer:${family}`],
      });
    }),
  }));

  return deepFreeze({ schema: SCHEMA, phases });
}

const ZERO_DELTA_DIRECTIVE =
  "DATA CREATED BEFORE CUTOVER MUST EQUAL DATA AFTER CUTOVER";

export function validateDeltaZero({ preCutoverFingerprints, postRestoreFingerprints }) {
  const violations = [];
  const preByFamily = new Map(preCutoverFingerprints.map((entry) => [entry.family, entry]));
  const postByFamily = new Map(postRestoreFingerprints.map((entry) => [entry.family, entry]));
  for (const [family] of preByFamily) {
    const result = compareFingerprints({
      pre: preByFamily.get(family),
      post: postByFamily.get(family),
    });
    if (result.status !== "MATCH") {
      for (const delta of result.deltas) {
        violations.push({
          family,
          writerId: Object.keys(WRITER_TO_FAMILY).find((key) => WRITER_TO_FAMILY[key] === family) ?? family,
          id: delta.id,
          before: delta.before,
          after: delta.after,
          directive: ZERO_DELTA_DIRECTIVE,
        });
      }
      if (result.reason) {
        violations.push({ family, reason: result.reason, directive: ZERO_DELTA_DIRECTIVE });
      }
    }
  }
  for (const [family] of postByFamily) {
    if (!preByFamily.has(family)) {
      violations.push({ family, reason: "post-cutover family missing pre-cutover baseline", directive: ZERO_DELTA_DIRECTIVE });
    }
  }
  return violations;
}

export function serializeFinalSyncPlan(plan) {
  return `${JSON.stringify(plan, null, 2)}\n`;
}
