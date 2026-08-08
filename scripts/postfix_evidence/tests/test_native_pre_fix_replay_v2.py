"""Focused contract tests for the native pre-fix replay-v2 adapter."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts.postfix_evidence import build_postfix_package as builder_module
from scripts.postfix_evidence import native_pre_fix_replay_v2 as native_module
from scripts.postfix_evidence import validate_postfix_package as validator_module
from scripts.postfix_evidence.common import ContractError, canonical_json_bytes
from scripts.postfix_evidence.native_pre_fix_replay_v2 import (
    DESCRIPTOR_SCHEMA,
    EXPECTED_ARTIFACT_PATHS,
    EXPECTED_CASE_IDS,
    LEGACY_MODE,
    NATIVE_MODE,
    NATIVE_PACKAGE_DESCRIPTOR_PATH,
    NATIVE_PACKAGE_ROOTS,
    NATIVE_TRACKED_INPUT_ARCHIVE_PATHS,
    NativeRegistryValidation,
    ReplayArtifact,
    NativeReplaySet,
    NativeReplaySnapshot,
    _ReplayInvocationState,
    _snapshot_source_artifacts,
    _validate_case_invocation,
    _validate_case_result,
    _validate_replay_pair,
    _validate_replay_timeline,
    _validate_summary,
    classify_pre_fix_registry,
    native_input_hashes,
    parse_native_replay_descriptor,
    semantic_projection_bytes,
    validate_semantic_replay_pair,
    validate_native_packaged_replay_set,
    validate_native_source_replay_set,
)


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _artifact_rows(marker: str) -> list[dict[str, object]]:
    return [
        {
            "path": relative,
            "size": len(f"{marker}:{relative}".encode()),
            "sha256": _digest(f"{marker}:{relative}".encode()),
        }
        for relative in EXPECTED_ARTIFACT_PATHS
    ]


RUN_ID_A = "a" * 64
RUN_ID_B = "b" * 64


def _descriptor(
    run_id_a: str = RUN_ID_A,
    run_id_b: str = RUN_ID_B,
) -> dict[str, object]:
    return {
        "schema": DESCRIPTOR_SCHEMA,
        "replays": [
            {
                "replay_id": "A",
                "run_id": run_id_a,
                "artifacts": _artifact_rows("A"),
            },
            {
                "replay_id": "B",
                "run_id": run_id_b,
                "artifacts": _artifact_rows("B"),
            },
        ],
    }


def _descriptor_with_run_ids(
    run_id_a: str = RUN_ID_A,
    run_id_b: str = RUN_ID_B,
) -> dict[str, object]:
    return _descriptor(run_id_a, run_id_b)


def _legacy_row(case_id: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "group_id": case_id,
        "test_case_id": f"PRE-FIX-{case_id}",
        "runner_kind": "manual-harness",
        "cwd": "tests/pre-fix",
        "argv": ["node", "probe.mjs", case_id],
        "test_definition_at_final_commit": {
            "path": "tests/pre-fix/probe.mjs",
            "mode": "100644",
            "sha256": "0" * 64,
        },
        "consumer_paths_at_baseline": ["tracked.txt"],
    }


def _native_row(case_id: str) -> dict[str, object]:
    return {
        "schema": "platform.pre-fix-replay-definition/v2",
        "case_id": case_id,
        "slug": case_id.lower(),
        "canonical_ids": ["CAN-001"],
        "baseline": {"commit": "0" * 40, "tree": "1" * 40},
        "target_worktree_write": False,
        "ephemeral_write": True,
        "proof_scope": {},
        "residuals": ["residual"],
        "anchors": [],
        "test_boundary": "boundary",
        "seed_tree_sha256": "2" * 64,
        "entrypoint": {},
        "provenance": {},
    }


def _semantic_result(case_id: str, marker: str = "same") -> dict[str, object]:
    return {
        "case_id": case_id,
        "slug": case_id.lower(),
        "status": "PASS",
        "exit_code": 0,
        "signal": None,
        "timed_out": False,
        "exceeded_output": False,
        "normalized_stdout_sha256": _digest(f"stdout:{marker}:{case_id}".encode()),
        "normalized_stderr_sha256": _digest(f"stderr:{marker}:{case_id}".encode()),
        "seed_tree_sha256": _digest(f"seed:{case_id}".encode()),
        "target_worktree_write": False,
        "ephemeral_write": True,
    }


FINAL_COMMIT = "3" * 40
FINAL_TREE = "4" * 40
BASELINE_COMMIT = "5" * 40
BASELINE_TREE = "6" * 40
SEED_SHA256 = "7" * 64
EXECUTABLE_SHA256 = "8" * 64


def _make_definition(case_id: str = "FG-001") -> dict[str, object]:
    return {
        "case_id": case_id,
        "slug": "hosted-external-volume-ownership",
        "seed_tree_sha256": SEED_SHA256,
        "proof_scope": {
            "kind": "exact-baseline-negative-reproduction",
            "classification": "offline-product-consumer",
        },
        "residuals": ["post-fix replay remains separate"],
        "anchors": [
            {
                "kind": "baseline_consumer",
                "value": "scripts/consumer.mjs",
                "sha256": "9" * 64,
            }
        ],
        "entrypoint": {
            "kind": "make",
            "cwd": f"tests/pre-fix/cases/{case_id}",
            "target": "run",
        },
    }


def _make_argv(case_id: str = "FG-001", root: str = "/private/tmp/baseline") -> list[str]:
    return [
        "--no-print-directory",
        "-s",
        "run",
        f"SOURCE_REPO={root}",
        f"SOURCE_ROOT={root}",
        f"CANDIDATE_ROOT={root}",
        f"CONTRACT={root}/scripts/hosted-workload-contract.mjs",
        f"REPOSITORY={root}",
        f"REPO={root}",
        f"REVISION={BASELINE_COMMIT}",
        "EXPECT=vulnerable",
        f"CASE_ID={case_id}",
    ]


def _case_fixture() -> tuple[dict[str, object], dict[str, bytes], dict[str, object]]:
    case_id = "FG-001"
    definition = _make_definition(case_id)
    stdout = b"negative reproduction PASS\n"
    stderr = b""
    log_header = {
        "schema": "platform.pre-fix-negative-replay-log-envelope/v2",
        "run_id": RUN_ID_A,
        "case_id": case_id,
        "baseline_commit": BASELINE_COMMIT,
        "baseline_tree": BASELINE_TREE,
        "runner_commit": FINAL_COMMIT,
        "seed_tree_sha256": SEED_SHA256,
        "executable_sha256": EXECUTABLE_SHA256,
    }
    execution_log = (
        json.dumps(log_header, separators=(",", ":")).encode()
        + b"\n--- stdout ---\n"
        + stdout
        + b"\n--- stderr ---\n"
        + stderr
    )
    execution_identity = (
        RUN_ID_A
        + "\0"
        + FINAL_COMMIT
        + "\0"
        + BASELINE_COMMIT
        + "\0"
        + SEED_SHA256
    ).encode()
    row: dict[str, object] = {
        "schema": "platform.pre-fix-negative-replay-case-result/v2",
        "run_id": RUN_ID_A,
        "execution_index": 1,
        "execution_id": f"{case_id}:{_digest(execution_identity)[:24]}",
        "case_id": case_id,
        "slug": definition["slug"],
        "started_at": "2026-08-08T10:00:00.001Z",
        "finished_at": "2026-08-08T10:00:00.002Z",
        "status": "PASS",
        "exit_code": 0,
        "signal": None,
        "timed_out": False,
        "exceeded_output": False,
        "duration_ms": 1.0,
        "stdout_sha256": _digest(stdout),
        "stderr_sha256": _digest(stderr),
        "normalized_stdout_sha256": _digest(stdout),
        "normalized_stderr_sha256": _digest(stderr),
        "command": "/usr/bin/make",
        "argv": _make_argv(case_id),
        "executable": {
            "path": "/usr/bin/make",
            "sha256": EXECUTABLE_SHA256,
        },
        "seed_tree_sha256": SEED_SHA256,
        "proof_scope": definition["proof_scope"],
        "residuals": definition["residuals"],
        "anchors": definition["anchors"],
        "consumer_git_anchors": [
            {
                "commit": BASELINE_COMMIT,
                "tree": BASELINE_TREE,
                "path": "scripts/consumer.mjs",
                "sha256": "9" * 64,
            }
        ],
        "target_worktree_write": False,
        "ephemeral_write": True,
        "forbidden_access": {
            "network": False,
            "docker": False,
            "live": False,
            "provider": False,
            "secrets": False,
        },
        "access_claim_scope": "approved-tracked-seeds",
        "log_envelope": {
            "schema": "platform.pre-fix-negative-replay-log-envelope/v2",
            "path": f"{case_id}/execution.log",
            "sha256": _digest(execution_log),
            "stdout_sha256": _digest(stdout),
            "stderr_sha256": _digest(stderr),
            "normalized_stdout_sha256": _digest(stdout),
            "normalized_stderr_sha256": _digest(stderr),
        },
        "artifact_paths": {
            "stdout": f"{case_id}/stdout.log",
            "stderr": f"{case_id}/stderr.log",
            "log": f"{case_id}/execution.log",
        },
    }
    files = {
        f"{case_id}/stdout.log": stdout,
        f"{case_id}/stderr.log": stderr,
        f"{case_id}/execution.log": execution_log,
    }
    return row, files, definition


def _validate_case(
    row: dict[str, object],
    *,
    files: dict[str, bytes] | None = None,
    expected_run_id: str = RUN_ID_A,
) -> dict[str, object]:
    _, default_files, definition = _case_fixture()
    return _validate_case_result(
        replay_id="A",
        index=0,
        result=row,
        definition=definition,
        files=default_files if files is None else files,
        final_commit=FINAL_COMMIT,
        baseline_commit=BASELINE_COMMIT,
        baseline_tree=BASELINE_TREE,
        expected_run_id=expected_run_id,
    )


def _summary_fixture() -> tuple[dict[str, object], NativeRegistryValidation, bytes, bytes]:
    registry_bytes = b"registry\n"
    source_map_bytes = b"source-map\n"
    sandbox_bytes = b"sandbox\n"
    definitions = {
        case_id: {
            "proof_scope": {"classification": "offline-product-consumer"}
        }
        for case_id in EXPECTED_CASE_IDS
    }
    descriptors = {
        key: {
            "path": f"tests/pre-fix/{key}",
            "mode": "100644",
            "git_blob": "a" * 40,
            "sha256": "b" * 64,
        }
        for key in ("runner", "registry", "sandbox_profile", "source_map")
    }
    registry = NativeRegistryValidation(
        definitions=definitions,
        tracked_input_descriptors=descriptors,
        tracked_input_bytes={
            "runner": b"runner\n",
            "registry": registry_bytes,
            "sandbox_profile": sandbox_bytes,
            "source_map": source_map_bytes,
        },
        sandbox_profile={"denied_user_secret_roots": [".ssh"]},
    )
    summary: dict[str, object] = {
        "schema": "platform.pre-fix-negative-replay-receipt/v2",
        "run_id": RUN_ID_A,
        "started_at": "2026-08-08T09:59:59.999Z",
        "finished_at": "2026-08-08T10:00:01.000Z",
        "verdict": "PASS",
        "baseline": {
            "commit": BASELINE_COMMIT,
            "tree": BASELINE_TREE,
            "detached": True,
            "materialization": "git-clone-no-hardlinks-local",
            "object_files_checked": 1,
            "maximum_object_link_count": 1,
            "shared_object_alternates": False,
            "clean_before": True,
            "clean_after": True,
        },
        "runner": {
            "commit": FINAL_COMMIT,
            "tree": FINAL_TREE,
            "clean_before": True,
            "clean_after": True,
        },
        "tracked_inputs": descriptors,
        "registry_sha256": _digest(registry_bytes),
        "source_map_sha256": _digest(source_map_bytes),
        "sandbox_profile_sha256": _digest(sandbox_bytes),
        "sandbox": {
            "schema": "platform.pre-fix-replay-sandbox/v2",
            "mode": "offline-contained",
            "claim_scope": "approved-tracked-seeds",
            "implementation": "macos-sandbox-exec",
            "executable": {"path": "/usr/bin/sandbox-exec", "sha256": "c" * 64},
            "network": False,
            "docker": False,
            "live": False,
            "provider": False,
            "secrets": False,
            "process_exec_enforcement": "PATH-only-command-guards",
            "secret_read_enforcement": "deny-listed-common-user-secret-roots",
            "denied_user_secret_roots": [".ssh"],
            "forbidden_access": [
                "network",
                "docker",
                "live",
                "provider",
                "listed_user_secret_roots",
                "target_worktree_write",
                "baseline_worktree_write",
            ],
            "target_worktree_write": False,
            "ephemeral_write": True,
            "environment_inherited": False,
        },
        "trust_assumptions": ["one", "two", "three"],
        "access_claim_scope": "approved-tracked-seeds",
        "filesystem_write": {
            "target_worktree": False,
            "baseline_worktree": False,
            "runner_worktree": False,
            "ephemeral_scratch": True,
            "external_artifacts": True,
        },
        "forbidden_access": {
            "network": False,
            "docker": False,
            "live": False,
            "provider": False,
            "secrets": False,
        },
        "output": {
            "external_to_runner_worktree": True,
            "external_to_baseline_worktree": True,
            "external_to_baseline_source": True,
            "tracked": False,
        },
        "target_worktree_write": False,
        "ephemeral_write": True,
        "counts": {"expected": 77, "executed": 77, "passed": 77, "failed": 0},
        "case_ids": list(EXPECTED_CASE_IDS),
        "semantic_results_sha256": "d" * 64,
        "proof_scope": {
            "kind": "exact-baseline-negative-reproduction",
            "statement": "bounded replay",
            "classifications": {
                "offline-product-consumer": 77,
                "offline-source-control": 0,
                "offline-source-model": 0,
            },
            "excludes": [
                "post-fix remediation correctness",
                "live deployment state",
                "provider or production attestation",
            ],
        },
        "residuals": ["one", "two", "three"],
    }
    return summary, registry, registry_bytes, source_map_bytes


def _validate_test_summary(summary: dict[str, object]) -> dict[str, object]:
    _, registry, registry_bytes, source_map_bytes = _summary_fixture()
    return _validate_summary(
        replay_id="A",
        value=summary,
        registry=registry,
        registry_bytes=registry_bytes,
        group_map_bytes=source_map_bytes,
        final_commit=FINAL_COMMIT,
        final_tree=FINAL_TREE,
        baseline_commit=BASELINE_COMMIT,
        baseline_tree=BASELINE_TREE,
        expected_run_id=RUN_ID_A,
    )


def _synthetic_replay_set() -> NativeReplaySet:
    descriptor_bytes = canonical_json_bytes(_descriptor())
    semantic_digest = _digest(b"")
    replays: dict[str, NativeReplaySnapshot] = {}
    for replay_id in ("A", "B"):
        artifacts: dict[str, ReplayArtifact] = {}
        for relative in EXPECTED_ARTIFACT_PATHS:
            payload = f"{replay_id}:{relative}".encode()
            artifacts[relative] = ReplayArtifact(
                relative_path=relative,
                size=len(payload),
                sha256=_digest(payload),
                payload=payload,
            )
        replays[replay_id] = NativeReplaySnapshot(
            replay_id=replay_id,
            run_id=RUN_ID_A if replay_id == "A" else RUN_ID_B,
            artifacts=artifacts,
            summary={},
            results=(),
            semantic_projection=(),
            semantic_projection_sha256=semantic_digest,
            artifact_index_sha256=_digest(f"index:{replay_id}".encode()),
        )
    return NativeReplaySet(
        descriptor_bytes=descriptor_bytes,
        descriptor_sha256=_digest(descriptor_bytes),
        replays=replays,
        tracked_input_bytes={
            "runner": b"runner-input\n",
            "registry": b"registry-input\n",
            "sandbox_profile": b"sandbox-input\n",
            "source_map": b"source-map-input\n",
        },
    )


def _synthetic_package_files(replay_set: NativeReplaySet) -> dict[str, bytes]:
    files = {
        relative: replay_set.tracked_input_bytes[key]
        for key, relative in NATIVE_TRACKED_INPUT_ARCHIVE_PATHS.items()
    }
    for replay_id, replay in replay_set.replays.items():
        prefix = NATIVE_PACKAGE_ROOTS[replay_id].as_posix()
        for relative, artifact in replay.artifacts.items():
            files[f"{prefix}/{relative}"] = artifact.payload
    return files


class NativeReplayV2ContractTests(unittest.TestCase):
    def test_dispatch_requires_one_schema_across_all_77_rows(self) -> None:
        native = [_native_row(case_id) for case_id in EXPECTED_CASE_IDS]
        self.assertEqual(classify_pre_fix_registry(native), NATIVE_MODE)
        mixed = copy.deepcopy(native)
        mixed[-1] = _legacy_row(EXPECTED_CASE_IDS[-1])
        with self.assertRaisesRegex(ContractError, "mixed|schema"):
            classify_pre_fix_registry(mixed)
        unknown = copy.deepcopy(native)
        unknown[0]["schema"] = "platform.pre-fix-replay-definition/v3"
        with self.assertRaisesRegex(ContractError, "unknown|schema"):
            classify_pre_fix_registry(unknown)

    def test_dispatch_preserves_legacy_set_semantics_for_reordered_rows(self) -> None:
        legacy = [_legacy_row(case_id) for case_id in EXPECTED_CASE_IDS]
        legacy = legacy[1::2] + legacy[::2]
        self.assertNotEqual(
            [row["group_id"] for row in legacy],
            list(EXPECTED_CASE_IDS),
        )
        self.assertEqual(classify_pre_fix_registry(legacy), LEGACY_MODE)

        duplicate = copy.deepcopy(legacy)
        duplicate[-1]["group_id"] = duplicate[0]["group_id"]
        with self.assertRaisesRegex(ContractError, "identit|FG-001|FG-077|set"):
            classify_pre_fix_registry(duplicate)

        native = [_native_row(case_id) for case_id in EXPECTED_CASE_IDS]
        native[0], native[1] = native[1], native[0]
        with self.assertRaisesRegex(ContractError, "ordered|FG-001|FG-077"):
            classify_pre_fix_registry(native)

    def test_descriptor_hashes_every_one_of_466_artifacts(self) -> None:
        parsed = parse_native_replay_descriptor(canonical_json_bytes(_descriptor()))
        self.assertEqual(
            sum(len(entry["artifacts"]) for entry in parsed.values()),
            466,
        )

        missing = _descriptor()
        missing["replays"][0]["artifacts"].pop()
        with self.assertRaisesRegex(ContractError, "233|artifact"):
            parse_native_replay_descriptor(canonical_json_bytes(missing))

        extra = _descriptor()
        extra["replays"][1]["artifacts"].append(
            {"path": "unexpected.log", "size": 1, "sha256": "0" * 64}
        )
        with self.assertRaisesRegex(ContractError, "233|artifact"):
            parse_native_replay_descriptor(canonical_json_bytes(extra))

    def test_descriptor_rejects_duplicate_or_reordered_artifact_identity(self) -> None:
        descriptor = _descriptor()
        descriptor["replays"][0]["artifacts"][0]["path"] = descriptor[
            "replays"
        ][0]["artifacts"][1]["path"]
        with self.assertRaisesRegex(ContractError, "path|ordered|exact"):
            parse_native_replay_descriptor(canonical_json_bytes(descriptor))

    def test_descriptor_rejects_noncanonical_raw_paths_before_normalization(self) -> None:
        for canonical, mutant in (
            ("summary.json", "./summary.json"),
            ("FG-001/execution.log", "FG-001//execution.log"),
        ):
            with self.subTest(mutant=mutant):
                descriptor = _descriptor()
                paths = [
                    row["path"]
                    for row in descriptor["replays"][0]["artifacts"]
                ]
                descriptor["replays"][0]["artifacts"][paths.index(canonical)][
                    "path"
                ] = mutant
                with self.assertRaisesRegex(
                    ContractError, "canonical|path|exact"
                ):
                    parse_native_replay_descriptor(
                        canonical_json_bytes(descriptor)
                    )

    def test_descriptor_requires_explicit_lowercase_64_hex_run_ids(self) -> None:
        parsed = parse_native_replay_descriptor(
            canonical_json_bytes(_descriptor_with_run_ids())
        )
        self.assertEqual(parsed["A"]["run_id"], RUN_ID_A)
        self.assertEqual(parsed["B"]["run_id"], RUN_ID_B)
        for mutant in ("a" * 63, "A" * 64, "g" * 64, True):
            with self.subTest(mutant=mutant):
                descriptor = _descriptor_with_run_ids()
                descriptor["replays"][0]["run_id"] = mutant
                with self.assertRaisesRegex(ContractError, "run.?id|64|hex"):
                    parse_native_replay_descriptor(
                        canonical_json_bytes(descriptor)
                    )

    def test_pair_rejects_duplicate_run_identity_before_semantic_equality(self) -> None:
        semantic_digest = _digest(b"")
        duplicate = {
            replay_id: SimpleNamespace(
                run_id=RUN_ID_A,
                semantic_projection=(),
                semantic_projection_sha256=semantic_digest,
            )
            for replay_id in ("A", "B")
        }
        with self.assertRaisesRegex(ContractError, "run.?id|independent|A/B"):
            _validate_replay_pair(duplicate)

        distinct = dict(duplicate)
        distinct["B"] = SimpleNamespace(
            run_id=RUN_ID_B,
            semantic_projection=(),
            semantic_projection_sha256=semantic_digest,
        )
        _validate_replay_pair(distinct)

    def test_semantic_pair_accepts_raw_difference_but_rejects_projection_drift(self) -> None:
        projection_a = [_semantic_result(case_id) for case_id in EXPECTED_CASE_IDS]
        projection_b = copy.deepcopy(projection_a)
        digest = _digest(semantic_projection_bytes(projection_a))
        validate_semantic_replay_pair(
            projection_a,
            digest,
            projection_b,
            digest,
        )

        projection_b[-1]["normalized_stdout_sha256"] = "f" * 64
        with self.assertRaisesRegex(ContractError, "A/B|semantic"):
            validate_semantic_replay_pair(
                projection_a,
                digest,
                projection_b,
                _digest(semantic_projection_bytes(projection_b)),
            )

    def test_semantic_projection_uses_runner_key_order_not_sorted_json(self) -> None:
        rows = [_semantic_result(case_id) for case_id in EXPECTED_CASE_IDS]
        payload = semantic_projection_bytes(rows)
        first = payload.splitlines()[0]
        self.assertTrue(first.startswith(b'{"case_id":'))
        self.assertNotEqual(payload, b"".join(canonical_json_bytes(row) for row in rows))

    def test_legacy_dispatch_rejects_boolean_schema_version(self) -> None:
        rows = [_legacy_row(case_id) for case_id in EXPECTED_CASE_IDS]
        rows[0]["schema_version"] = True
        with self.assertRaisesRegex(ContractError, "unknown|schema"):
            classify_pre_fix_registry(rows)

    def test_exact_233_file_source_tree_fits_the_enumeration_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            handoff = Path(temporary)
            root = handoff / "pre-fix-replays/v2/A"
            descriptor_rows: list[dict[str, object]] = []
            for relative in EXPECTED_ARTIFACT_PATHS:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                payload = f"artifact:{relative}\n".encode()
                target.write_bytes(payload)
                descriptor_rows.append(
                    {"path": relative, "size": len(payload), "sha256": _digest(payload)}
                )
            snapshot = _snapshot_source_artifacts(
                handoff_root=handoff,
                replay_id="A",
                descriptor_rows=tuple(descriptor_rows),
            )
            self.assertEqual(set(snapshot), set(EXPECTED_ARTIFACT_PATHS))

    def test_native_input_hashes_bind_all_four_raw_tracked_inputs(self) -> None:
        replays = {
            replay_id: NativeReplaySnapshot(
                replay_id=replay_id,
                run_id=RUN_ID_A if replay_id == "A" else RUN_ID_B,
                artifacts={},
                summary={},
                results=(),
                semantic_projection=(),
                semantic_projection_sha256=_digest(f"semantic:{replay_id}".encode()),
                artifact_index_sha256=_digest(f"index:{replay_id}".encode()),
            )
            for replay_id in ("A", "B")
        }
        tracked = {
            "runner": b"runner",
            "registry": b"registry",
            "sandbox_profile": b"sandbox",
            "source_map": b"source-map",
        }
        hashes = native_input_hashes(
            NativeReplaySet(
                descriptor_bytes=b"descriptor",
                descriptor_sha256=_digest(b"descriptor"),
                replays=replays,
                tracked_input_bytes=tracked,
            )
        )
        for key, payload in tracked.items():
            self.assertEqual(
                hashes[f"pre_fix_native_tracked_input:{key}"],
                _digest(payload),
            )

    def test_case_result_rejects_bool_integer_coercion(self) -> None:
        row, _, _ = _case_fixture()
        row["execution_index"] = True
        row["exit_code"] = False
        with self.assertRaisesRegex(ContractError, "semantics|integer|type"):
            _validate_case(row)

    def test_case_result_binds_command_argv_and_timestamp_causality(self) -> None:
        row, _, _ = _case_fixture()
        self.assertEqual(_validate_case(row), row)

        row, _, _ = _case_fixture()
        row["command"] = "/bin/true"
        with self.assertRaisesRegex(ContractError, "command|executable|invocation"):
            _validate_case(row)

        row, _, _ = _case_fixture()
        row["argv"][3] = "SOURCE_REPO=/private/tmp/other"
        with self.assertRaisesRegex(ContractError, "argv|invocation|baseline"):
            _validate_case(row)

        row, _, _ = _case_fixture()
        row["started_at"], row["finished_at"] = (
            row["finished_at"],
            row["started_at"],
        )
        with self.assertRaisesRegex(ContractError, "time|timestamp|causal"):
            _validate_case(row)

    def test_run_id_binds_summary_result_execution_id_and_log_header(self) -> None:
        summary, _, _, _ = _summary_fixture()
        summary["run_id"] = RUN_ID_B
        with self.assertRaisesRegex(ContractError, "run.?id|v2 PASS"):
            _validate_test_summary(summary)

        row, _, _ = _case_fixture()
        row["run_id"] = RUN_ID_B
        row["execution_id"] = (
            f"FG-001:{_digest((RUN_ID_B + chr(0) + FINAL_COMMIT + chr(0) + BASELINE_COMMIT + chr(0) + SEED_SHA256).encode())[:24]}"
        )
        with self.assertRaisesRegex(ContractError, "run.?id|semantics"):
            _validate_case(row)

        row, files, _ = _case_fixture()
        old_preimage = (
            FINAL_COMMIT + "\0" + BASELINE_COMMIT + "\0" + SEED_SHA256
        ).encode()
        row["execution_id"] = f"FG-001:{_digest(old_preimage)[:24]}"
        with self.assertRaisesRegex(ContractError, "execution|semantics"):
            _validate_case(row, files=files)

        row, files, _ = _case_fixture()
        log_path = "FG-001/execution.log"
        header_payload, remainder = files[log_path].split(b"\n", 1)
        header = json.loads(header_payload)
        header["run_id"] = RUN_ID_B
        files[log_path] = (
            json.dumps(header, separators=(",", ":")).encode() + b"\n" + remainder
        )
        row["log_envelope"]["sha256"] = _digest(files[log_path])
        with self.assertRaisesRegex(ContractError, "execution log|run.?id"):
            _validate_case(row, files=files)

    def test_invocation_accepts_both_exact_node_argv_forms_and_one_root(self) -> None:
        state = _ReplayInvocationState()
        _validate_case_invocation(
            definition=_make_definition("FG-001"),
            command="/Applications/Xcode.app/Contents/Developer/usr/bin/make",
            argv=_make_argv("FG-001"),
            executable={
                "path": "/Applications/Xcode.app/Contents/Developer/usr/bin/make",
                "sha256": "a" * 64,
            },
            baseline_commit=BASELINE_COMMIT,
            case_id="FG-001",
            state=state,
        )
        runner_root = "/private/tmp/final-candidate"
        node_path = "/private/tmp/runtime/bin/node"
        for case_id, script_name, template_args, observed_args in (
            (
                "FG-011",
                "verify-docker-proxy-authority.mjs",
                ["{{BASELINE_ROOT}}"],
                ["/private/tmp/baseline"],
            ),
            (
                "FG-013",
                "hosted-network-physical-ownership-poc.mjs",
                ["--source-root", "{{BASELINE_ROOT}}"],
                ["--source-root", "/private/tmp/baseline"],
            ),
        ):
            script = f"tests/pre-fix/cases/{case_id}/{script_name}"
            definition = {
                "entrypoint": {
                    "kind": "node",
                    "cwd": f"tests/pre-fix/cases/{case_id}",
                    "script": script,
                    "args": template_args,
                }
            }
            _validate_case_invocation(
                definition=definition,
                command=node_path,
                argv=[f"{runner_root}/{script}", *observed_args],
                executable={"path": node_path, "sha256": "b" * 64},
                baseline_commit=BASELINE_COMMIT,
                case_id=case_id,
                state=state,
            )
        self.assertEqual(state.baseline_root, "/private/tmp/baseline")
        self.assertEqual(state.runner_root, runner_root)

        changed = {
            "entrypoint": {
                "kind": "node",
                "cwd": "tests/pre-fix/cases/FG-019",
                "script": (
                    "tests/pre-fix/cases/FG-019/"
                    "hosted-egress-network-discovery-poc.mjs"
                ),
                "args": ["--source-root", "{{BASELINE_ROOT}}"],
            }
        }
        with self.assertRaisesRegex(ContractError, "runner root|invocation"):
            _validate_case_invocation(
                definition=changed,
                command=node_path,
                argv=[
                    "/private/tmp/other/tests/pre-fix/cases/FG-019/"
                    "hosted-egress-network-discovery-poc.mjs",
                    "--source-root",
                    "/private/tmp/baseline",
                ],
                executable={"path": node_path, "sha256": "b" * 64},
                baseline_commit=BASELINE_COMMIT,
                case_id="FG-019",
                state=state,
            )

    def test_replay_timeline_accepts_equal_boundaries_and_rejects_overlap(self) -> None:
        summary = {
            "started_at": "2026-08-08T10:00:00.001Z",
            "finished_at": "2026-08-08T10:00:00.004Z",
        }
        results = [
            {
                "case_id": "FG-001",
                "started_at": "2026-08-08T10:00:00.001Z",
                "finished_at": "2026-08-08T10:00:00.002Z",
            },
            {
                "case_id": "FG-002",
                "started_at": "2026-08-08T10:00:00.002Z",
                "finished_at": "2026-08-08T10:00:00.004Z",
            },
        ]
        _validate_replay_timeline(replay_id="A", summary=summary, results=results)

        overlapping = copy.deepcopy(results)
        overlapping[1]["started_at"] = "2026-08-08T10:00:00.001Z"
        with self.assertRaisesRegex(ContractError, "timestamp|causal"):
            _validate_replay_timeline(
                replay_id="A", summary=summary, results=overlapping
            )

        invalid = copy.deepcopy(results)
        invalid[0]["started_at"] = "2026-13-08T10:00:00.001Z"
        with self.assertRaisesRegex(ContractError, "timestamp"):
            _validate_replay_timeline(replay_id="A", summary=summary, results=invalid)

    def test_summary_rejects_bool_counts_bounds_and_wrong_sandbox_executable(self) -> None:
        summary, _, _, _ = _summary_fixture()
        summary["baseline"]["maximum_object_link_count"] = True
        with self.assertRaisesRegex(ContractError, "baseline|integer|type"):
            _validate_test_summary(summary)

        summary, _, _, _ = _summary_fixture()
        summary["counts"]["failed"] = False
        with self.assertRaisesRegex(ContractError, "77/77|count|integer|type"):
            _validate_test_summary(summary)

        summary, _, _, _ = _summary_fixture()
        summary["started_at"], summary["finished_at"] = (
            summary["finished_at"],
            summary["started_at"],
        )
        with self.assertRaisesRegex(ContractError, "time|timestamp|causal"):
            _validate_test_summary(summary)

        summary, _, _, _ = _summary_fixture()
        summary["sandbox"]["executable"]["path"] = "/bin/true"
        with self.assertRaisesRegex(ContractError, "sandbox|executable"):
            _validate_test_summary(summary)

    def test_native_writer_byte_copies_descriptor_inputs_and_all_466_artifacts(self) -> None:
        replay_set = _synthetic_replay_set()
        data = SimpleNamespace(
            pre_fix_mode=NATIVE_MODE,
            native_pre_fix_replays=replay_set,
            handoff_file_bytes={
                "pre_fix_negative_receipt": replay_set.descriptor_bytes
            },
        )
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            builder_module._write_native_pre_fix_replays(data, destination)
            self.assertEqual(
                (destination / NATIVE_PACKAGE_DESCRIPTOR_PATH).read_bytes(),
                replay_set.descriptor_bytes,
            )
            for key, relative in NATIVE_TRACKED_INPUT_ARCHIVE_PATHS.items():
                self.assertEqual(
                    (destination / relative).read_bytes(),
                    replay_set.tracked_input_bytes[key],
                )
            copied = 0
            for replay_id, replay in replay_set.replays.items():
                for relative, artifact in replay.artifacts.items():
                    copied += 1
                    self.assertEqual(
                        (
                            destination
                            / Path(*NATIVE_PACKAGE_ROOTS[replay_id].parts)
                            / relative
                        ).read_bytes(),
                        artifact.payload,
                    )
            self.assertEqual(copied, 466)
            self.assertFalse(
                (destination / "evidence/test/pre_fix_negative_receipt.json").exists()
            )
            self.assertFalse((destination / "evidence/test/pre-fix").exists())

        replay_set = _synthetic_replay_set()
        original = replay_set.replays["A"].artifacts["summary.json"]
        replay_set.replays["A"].artifacts["summary.json"] = ReplayArtifact(
            relative_path=original.relative_path,
            size=original.size,
            sha256=original.sha256,
            payload=b"tampered",
        )
        data.native_pre_fix_replays = replay_set
        data.handoff_file_bytes = {
            "pre_fix_negative_receipt": replay_set.descriptor_bytes
        }
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ContractError, "changed|tamper"):
                builder_module._write_native_pre_fix_replays(
                    data, Path(temporary)
                )

    def test_native_allowlist_rejects_omission_and_extra(self) -> None:
        receipt_rows = [{"receipt_id": "TR-NATIVE-001"}]
        expected = validator_module.expected_package_payload_paths(
            receipt_rows,
            _descriptor(),
            pre_fix_mode=NATIVE_MODE,
        )
        native_payloads = {
            relative
            for relative in expected
            if relative.startswith("evidence/test/pre-fix-native-v2/")
        }
        self.assertEqual(len(native_payloads), 466)
        self.assertIn(NATIVE_PACKAGE_DESCRIPTOR_PATH, expected)
        self.assertNotIn("evidence/test/pre_fix_negative_receipt.json", expected)
        self.assertNotIn("evidence/test/pre-fix/FG-001.log", expected)

        guard = getattr(validator_module, "_require_exact_package_allowlist", None)
        self.assertIsNotNone(guard)
        guard(observed=expected, expected=expected)
        with self.assertRaisesRegex(ContractError, "allowlist|missing"):
            guard(observed=set(expected) - {NATIVE_PACKAGE_DESCRIPTOR_PATH}, expected=expected)
        with self.assertRaisesRegex(ContractError, "allowlist|extra"):
            guard(observed={*expected, "evidence/test/unexpected.bin"}, expected=expected)

    def test_native_packaged_snapshot_rejects_missing_tampered_or_changed_inputs(self) -> None:
        replay_set = _synthetic_replay_set()
        package_files = _synthetic_package_files(replay_set)
        registry = NativeRegistryValidation(
            definitions={},
            tracked_input_descriptors={},
            tracked_input_bytes=replay_set.tracked_input_bytes,
            sandbox_profile={},
        )

        def replay_snapshot(**kwargs: object) -> NativeReplaySnapshot:
            replay_id = str(kwargs["replay_id"])
            expected_run_id = str(kwargs["expected_run_id"])
            replay = replay_set.replays[replay_id]
            if replay.run_id != expected_run_id:
                raise ContractError(
                    f"native replay {replay_id}: descriptor/summary run_id mismatch"
                )
            return replay

        call = {
            "descriptor_bytes": replay_set.descriptor_bytes,
            "package_files": package_files,
            "registry_rows": [],
            "registry_bytes": b"registry",
            "group_map_rows": [],
            "group_map_bytes": b"group-map",
            "candidate_repo": Path("/unused/candidate"),
            "final_commit": FINAL_COMMIT,
            "final_tree": FINAL_TREE,
            "baseline_commit": BASELINE_COMMIT,
            "baseline_tree": BASELINE_TREE,
        }
        with mock.patch.object(
            native_module,
            "validate_native_definition_registry",
            return_value=registry,
        ), mock.patch.object(
            native_module,
            "_validate_replay_files",
            side_effect=replay_snapshot,
        ):
            validated = validate_native_packaged_replay_set(**call)
            self.assertEqual(set(validated.replays), {"A", "B"})

            changed_descriptor = canonical_json_bytes(
                _descriptor("c" * 64, RUN_ID_B)
            )
            with self.assertRaisesRegex(ContractError, "run.?id|descriptor"):
                validate_native_packaged_replay_set(
                    **{**call, "descriptor_bytes": changed_descriptor}
                )

            missing = dict(package_files)
            del missing[
                f"{NATIVE_PACKAGE_ROOTS['A'].as_posix()}/FG-001/stdout.log"
            ]
            with self.assertRaisesRegex(ContractError, "missing"):
                validate_native_packaged_replay_set(
                    **{**call, "package_files": missing}
                )

            tampered = dict(package_files)
            tampered[
                f"{NATIVE_PACKAGE_ROOTS['B'].as_posix()}/FG-077/stderr.log"
            ] = b"tampered"
            with self.assertRaisesRegex(ContractError, "hash changed"):
                validate_native_packaged_replay_set(
                    **{**call, "package_files": tampered}
                )

            changed_input = dict(package_files)
            changed_input[
                NATIVE_TRACKED_INPUT_ARCHIVE_PATHS["runner"]
            ] = b"changed"
            with self.assertRaisesRegex(ContractError, "tracked input changed"):
                validate_native_packaged_replay_set(
                    **{**call, "package_files": changed_input}
                )

    def test_native_source_validation_propagates_descriptor_run_ids_and_rejects_duplicate(self) -> None:
        replay_set = _synthetic_replay_set()
        registry = NativeRegistryValidation(
            definitions={},
            tracked_input_descriptors={},
            tracked_input_bytes=replay_set.tracked_input_bytes,
            sandbox_profile={},
        )
        observed: dict[str, str] = {}
        leaf_run_ids = {"A": RUN_ID_A, "B": RUN_ID_B}

        def replay_snapshot(**kwargs: object) -> NativeReplaySnapshot:
            replay_id = str(kwargs["replay_id"])
            expected_run_id = str(kwargs["expected_run_id"])
            observed[replay_id] = expected_run_id
            if expected_run_id != leaf_run_ids[replay_id]:
                raise ContractError(
                    f"native replay {replay_id}: descriptor/summary run_id mismatch"
                )
            return replace(
                replay_set.replays[replay_id],
                run_id=expected_run_id,
            )

        call = {
            "descriptor_bytes": replay_set.descriptor_bytes,
            "handoff_root": Path("/unused/handoff"),
            "registry_rows": [],
            "registry_bytes": b"registry",
            "group_map_rows": [],
            "group_map_bytes": b"group-map",
            "candidate_repo": Path("/unused/candidate"),
            "final_commit": FINAL_COMMIT,
            "final_tree": FINAL_TREE,
            "baseline_commit": BASELINE_COMMIT,
            "baseline_tree": BASELINE_TREE,
        }
        with mock.patch.object(
            native_module,
            "validate_native_definition_registry",
            return_value=registry,
        ), mock.patch.object(
            native_module,
            "_snapshot_source_artifacts",
            return_value={},
        ), mock.patch.object(
            native_module,
            "_validate_replay_files",
            side_effect=replay_snapshot,
        ):
            validated = validate_native_source_replay_set(**call)
            self.assertEqual(observed, {"A": RUN_ID_A, "B": RUN_ID_B})
            self.assertEqual(validated.replays["A"].run_id, RUN_ID_A)
            self.assertEqual(validated.replays["B"].run_id, RUN_ID_B)

            changed_descriptor = canonical_json_bytes(
                _descriptor("c" * 64, RUN_ID_B)
            )
            with self.assertRaisesRegex(ContractError, "run.?id|descriptor"):
                validate_native_source_replay_set(
                    **{**call, "descriptor_bytes": changed_descriptor}
                )

            leaf_run_ids["B"] = RUN_ID_A
            duplicate = canonical_json_bytes(_descriptor(RUN_ID_A, RUN_ID_A))
            with self.assertRaisesRegex(ContractError, "run.?id|independent|A/B"):
                validate_native_source_replay_set(
                    **{**call, "descriptor_bytes": duplicate}
                )

    def test_native_packaged_trust_root_requires_byte_exact_descriptor(self) -> None:
        guard = getattr(
            validator_module, "_validate_packaged_pre_fix_projection", None
        )
        self.assertIsNotNone(guard)
        descriptor = _descriptor()
        source = canonical_json_bytes(descriptor)
        guard(
            pre_fix_mode=NATIVE_MODE,
            source_pre_fix_bytes=source,
            packaged_pre_fix_bytes=source,
            packaged_pre_fix=descriptor,
        )
        semantically_equal_but_raw_different = json.dumps(
            descriptor,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
        self.assertNotEqual(semantically_equal_but_raw_different, source)
        with self.assertRaisesRegex(ContractError, "byte-exact|trust root"):
            guard(
                pre_fix_mode=NATIVE_MODE,
                source_pre_fix_bytes=source,
                packaged_pre_fix_bytes=semantically_equal_but_raw_different,
                packaged_pre_fix=descriptor,
            )

    def test_package_tree_budget_is_mode_specific_without_large_fixture(self) -> None:
        helper = getattr(builder_module, "_package_tree_index", None)
        self.assertIsNotNone(helper)
        with mock.patch.object(builder_module, "tree_index", return_value={}) as indexed:
            helper(Path("/tmp/native"), NATIVE_MODE)
            self.assertEqual(
                indexed.call_args.kwargs["max_total_bytes"],
                896 * 1024 * 1024,
            )
            helper(Path("/tmp/legacy"), LEGACY_MODE)
            self.assertEqual(
                indexed.call_args.kwargs["max_total_bytes"],
                128 * 1024 * 1024,
            )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(
                builder_module,
                "tree_index",
                return_value={
                    "payload.bin": {"sha256": "e" * 64, "size": 1}
                },
            ) as indexed:
                builder_module._write_package_manifest(root, NATIVE_MODE)
                self.assertEqual(
                    indexed.call_args.kwargs["max_total_bytes"],
                    896 * 1024 * 1024,
                )
            self.assertEqual(
                (root / "MANIFEST.sha256").read_text(),
                f"{'e' * 64}  payload.bin\n",
            )


if __name__ == "__main__":
    unittest.main()
