"""Validate and preserve native schema-v2 pre-fix replay artifacts.

The adapter consumes two already-completed offline Runner replays.  It never
executes a replay, accesses Docker or the network, or rewrites Runner output.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Literal

from scripts.postfix_evidence.common import (
    ByteBudget,
    ContractError,
    SHA1_RE,
    SHA256_RE,
    canonical_json_bytes,
    exact_keys,
    git,
    git_blob,
    git_text,
    load_json_bytes,
    load_jsonl_bytes,
    nonempty_string,
    read_regular_under,
    safe_relative,
    scan_secret_bytes,
    sha256_bytes,
    string_list,
    tree_index,
)


LEGACY_MODE = "legacy-v1"
NATIVE_MODE = "native-v2"
PreFixMode = Literal["legacy-v1", "native-v2"]

DESCRIPTOR_SCHEMA = "platform.pre-fix-negative-replay-set/v2"
DEFINITION_SCHEMA = "platform.pre-fix-replay-definition/v2"
SUMMARY_SCHEMA = "platform.pre-fix-negative-replay-receipt/v2"
RESULT_SCHEMA = "platform.pre-fix-negative-replay-case-result/v2"
LOG_ENVELOPE_SCHEMA = "platform.pre-fix-negative-replay-log-envelope/v2"
SANDBOX_SCHEMA = "platform.pre-fix-replay-sandbox/v2"

REPLAY_IDS = ("A", "B")
EXPECTED_CASE_IDS = tuple(
    f"FG-{number:03d}" for number in range(1, 78)
)
EXPECTED_ARTIFACT_PATHS = tuple(
    sorted(
        (
            "summary.json",
            "results.jsonl",
            *(
                f"{case_id}/{name}.log"
                for case_id in EXPECTED_CASE_IDS
                for name in ("execution", "stderr", "stdout")
            ),
        )
    )
)

# The descriptor cannot redirect either trust root.  Final assembly places the
# completed Runner directories at these exact paths below the handoff root.
NATIVE_SOURCE_ROOTS = {
    "A": PurePosixPath("pre-fix-replays/v2/A"),
    "B": PurePosixPath("pre-fix-replays/v2/B"),
}
NATIVE_PACKAGE_ROOTS = {
    "A": PurePosixPath("evidence/test/pre-fix-native-v2/A"),
    "B": PurePosixPath("evidence/test/pre-fix-native-v2/B"),
}
NATIVE_PACKAGE_DESCRIPTOR_PATH = "evidence/test/pre_fix_replay_set_v2.json"
NATIVE_SCHEMA_NAME = "native-pre-fix-replay-set-v2.schema.json"

NATIVE_TRACKED_INPUT_REPO_PATHS = {
    "runner": "tests/pre-fix/run-pre-fix-replay.mjs",
    "registry": "tests/pre-fix/definition-registry.jsonl",
    "sandbox_profile": "tests/pre-fix/sandbox-profile.json",
    "source_map": "tests/pre-fix/security-fix-groups-v1.jsonl",
}
NATIVE_TRACKED_INPUT_ARCHIVE_PATHS = {
    key: f"receipts/input/pre-fix-native-v2/{Path(relative).name}"
    for key, relative in NATIVE_TRACKED_INPUT_REPO_PATHS.items()
}

MIB = 1024 * 1024
NATIVE_DESCRIPTOR_MAX_BYTES = 2 * MIB
NATIVE_SUMMARY_MAX_BYTES = 2 * MIB
NATIVE_RESULTS_MAX_BYTES = 32 * MIB
NATIVE_ARTIFACT_MAX_BYTES = 16 * MIB
NATIVE_REPLAY_TOTAL_MAX_BYTES = 384 * MIB
NATIVE_REPLAY_SET_TOTAL_MAX_BYTES = 768 * MIB
NATIVE_REGISTRY_MAX_BYTES = 16 * MIB
NATIVE_TRACKED_INPUT_MAX_BYTES = 16 * MIB
NATIVE_REPLAY_TREE_MAX_ENTRIES = len(EXPECTED_ARTIFACT_PATHS) + len(
    EXPECTED_CASE_IDS
)

_UTC_MILLISECOND_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:"
    r"[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
)
_CASE_ID_RE = re.compile(r"^FG-(?:00[1-9]|0[1-6][0-9]|07[0-7])$")
_CAN_ID_RE = re.compile(r"^CAN-[0-9]{3}$")
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_RUN_ID_RE = re.compile(r"^[0-9a-f]{64}$")

LEGACY_REGISTRY_KEYS = frozenset(
    {
        "schema_version",
        "group_id",
        "test_case_id",
        "runner_kind",
        "cwd",
        "argv",
        "test_definition_at_final_commit",
        "consumer_paths_at_baseline",
    }
)
NATIVE_REGISTRY_KEYS = frozenset(
    {
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
    }
)

_STABLE_RESULT_KEYS = (
    "case_id",
    "slug",
    "status",
    "exit_code",
    "signal",
    "timed_out",
    "exceeded_output",
    "normalized_stdout_sha256",
    "normalized_stderr_sha256",
    "seed_tree_sha256",
    "target_worktree_write",
    "ephemeral_write",
)


@dataclass(frozen=True)
class ReplayArtifact:
    relative_path: str
    size: int
    sha256: str
    payload: bytes


@dataclass(frozen=True)
class NativeReplaySnapshot:
    replay_id: str
    run_id: str
    artifacts: dict[str, ReplayArtifact]
    summary: dict[str, Any]
    results: tuple[dict[str, Any], ...]
    semantic_projection: tuple[dict[str, Any], ...]
    semantic_projection_sha256: str
    artifact_index_sha256: str


@dataclass(frozen=True)
class NativeReplaySet:
    descriptor_bytes: bytes
    descriptor_sha256: str
    replays: dict[str, NativeReplaySnapshot]
    tracked_input_bytes: dict[str, bytes]


@dataclass(frozen=True)
class NativeRegistryValidation:
    definitions: dict[str, dict[str, Any]]
    tracked_input_descriptors: dict[str, dict[str, Any]]
    tracked_input_bytes: dict[str, bytes]
    sandbox_profile: dict[str, Any]


@dataclass
class _ReplayInvocationState:
    baseline_root: str | None = None
    runner_root: str | None = None
    make_executable: tuple[str, str] | None = None
    node_executable: tuple[str, str] | None = None


def classify_pre_fix_registry(rows: list[dict[str, Any]]) -> PreFixMode:
    """Choose one receipt contract only after classifying every registry row."""
    if not isinstance(rows, list) or len(rows) != 77:
        raise ContractError("pre-fix registry schema: expected exactly 77 rows")
    modes: list[str] = []
    identities: list[str] = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            raise ContractError(
                f"pre-fix registry schema: row {index} is not an object"
            )
        keys = frozenset(row)
        if (
            keys == LEGACY_REGISTRY_KEYS
            and type(row.get("schema_version")) is int
            and row.get("schema_version") == 1
        ):
            modes.append(LEGACY_MODE)
            identities.append(str(row.get("group_id")))
        elif keys == NATIVE_REGISTRY_KEYS and row.get("schema") == DEFINITION_SCHEMA:
            modes.append(NATIVE_MODE)
            identities.append(str(row.get("case_id")))
        else:
            raise ContractError(
                f"pre-fix registry schema: unknown or hybrid row {index}"
            )
    if len(set(modes)) != 1:
        raise ContractError("pre-fix registry schema: mixed legacy/native rows")
    mode = modes[0]
    if mode == NATIVE_MODE and identities != list(EXPECTED_CASE_IDS):
        raise ContractError(
            "pre-fix registry schema: native identities must be ordered FG-001 through FG-077"
        )
    if mode == LEGACY_MODE and set(identities) != set(EXPECTED_CASE_IDS):
        raise ContractError(
            "pre-fix registry schema: legacy identities must be the exact FG-001 through FG-077 set"
        )
    return mode  # type: ignore[return-value]


def parse_native_replay_descriptor(
    payload: bytes,
) -> dict[str, dict[str, Any]]:
    if len(payload) > NATIVE_DESCRIPTOR_MAX_BYTES:
        raise ContractError("native replay descriptor: byte limit exceeded")
    value = load_json_bytes(payload, label="native replay descriptor")
    exact_keys(value, {"schema", "replays"}, label="native replay descriptor")
    if value["schema"] != DESCRIPTOR_SCHEMA:
        raise ContractError("native replay descriptor: unsupported schema")
    replays = value["replays"]
    if not isinstance(replays, list) or len(replays) != 2:
        raise ContractError("native replay descriptor: expected exact A/B replay pair")
    result: dict[str, dict[str, Any]] = {}
    total_size = 0
    for replay_index, replay_id in enumerate(REPLAY_IDS):
        replay = exact_keys(
            replays[replay_index],
            {"replay_id", "run_id", "artifacts"},
            label=f"native replay descriptor {replay_id}",
        )
        if replay["replay_id"] != replay_id:
            raise ContractError("native replay descriptor: replay order is not exact A/B")
        run_id = replay["run_id"]
        if not isinstance(run_id, str) or _RUN_ID_RE.fullmatch(run_id) is None:
            raise ContractError(
                f"native replay descriptor {replay_id}: invalid 64-hex run_id"
            )
        artifacts = replay["artifacts"]
        if not isinstance(artifacts, list) or len(artifacts) != 233:
            raise ContractError(
                f"native replay descriptor {replay_id}: expected exactly 233 artifacts"
            )
        normalized: list[dict[str, Any]] = []
        for artifact_index, artifact in enumerate(artifacts, start=1):
            row = exact_keys(
                artifact,
                {"path", "size", "sha256"},
                label=(
                    f"native replay descriptor {replay_id} artifact "
                    f"{artifact_index}"
                ),
            )
            raw_relative = row["path"]
            relative = safe_relative(
                raw_relative,
                label=f"native replay descriptor {replay_id} artifact path",
            ).as_posix()
            if raw_relative != relative:
                raise ContractError(
                    f"native replay descriptor {replay_id}: artifact path is not canonical"
                )
            size = row["size"]
            digest = row["sha256"]
            if type(size) is not int or size < 0 or size > NATIVE_ARTIFACT_MAX_BYTES:
                raise ContractError(
                    f"native replay descriptor {replay_id}: invalid artifact size"
                )
            if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
                raise ContractError(
                    f"native replay descriptor {replay_id}: invalid artifact SHA-256"
                )
            total_size += size
            if total_size > NATIVE_REPLAY_SET_TOTAL_MAX_BYTES:
                raise ContractError("native replay descriptor: aggregate byte limit exceeded")
            normalized.append({"path": relative, "size": size, "sha256": digest})
        actual_paths = [row["path"] for row in normalized]
        if actual_paths != list(EXPECTED_ARTIFACT_PATHS):
            raise ContractError(
                f"native replay descriptor {replay_id}: artifact paths are not the exact ordered set"
            )
        result[replay_id] = {
            "run_id": run_id,
            "artifacts": tuple(normalized),
        }
    return result


def semantic_projection_bytes(rows: Iterable[dict[str, Any]]) -> bytes:
    """Match the Runner's JSON.stringify stable-result JSONL byte contract."""
    chunks: list[bytes] = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            raise ContractError(f"native replay semantic row {index}: expected object")
        if tuple(row) != _STABLE_RESULT_KEYS or set(row) != set(_STABLE_RESULT_KEYS):
            raise ContractError(
                f"native replay semantic row {index}: wrong or reordered projection keys"
            )
        try:
            chunks.append(
                (
                    json.dumps(
                        row,
                        ensure_ascii=False,
                        allow_nan=False,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
            )
        except (TypeError, ValueError) as error:
            raise ContractError(
                f"native replay semantic row {index}: invalid JSON value"
            ) from error
    return b"".join(chunks)


def validate_semantic_replay_pair(
    projection_a: Iterable[dict[str, Any]],
    claimed_a: str,
    projection_b: Iterable[dict[str, Any]],
    claimed_b: str,
) -> str:
    rows_a = tuple(projection_a)
    rows_b = tuple(projection_b)
    payload_a = semantic_projection_bytes(rows_a)
    payload_b = semantic_projection_bytes(rows_b)
    digest_a = sha256_bytes(payload_a)
    digest_b = sha256_bytes(payload_b)
    if claimed_a != digest_a or claimed_b != digest_b:
        raise ContractError("native replay semantic digest is not independently reproducible")
    if payload_a != payload_b:
        raise ContractError("native replay A/B semantic projections differ")
    return digest_a


def _git_regular_blob(
    repo: Path,
    commit: str,
    relative: str,
    *,
    label: str,
    max_bytes: int = NATIVE_TRACKED_INPUT_MAX_BYTES,
) -> tuple[dict[str, Any], bytes]:
    safe = safe_relative(relative, label=label).as_posix()
    listing = git_text(repo, "ls-tree", commit, "--", safe)
    match = re.fullmatch(
        rf"(100644|100755) blob ([0-9a-f]{{40}})\t{re.escape(safe)}",
        listing,
    )
    if match is None:
        raise ContractError(f"{label}: path is not an exact regular Git blob")
    mode, object_id = match.groups()
    payload = git_blob(
        repo,
        f"{commit}:{safe}",
        label=label,
        max_bytes=max_bytes,
    )
    return (
        {
            "path": safe,
            "mode": mode,
            "git_blob": object_id,
            "sha256": sha256_bytes(payload),
        },
        payload,
    )


def _seed_tree_sha256(repo: Path, commit: str, case_id: str) -> str:
    prefix = f"tests/pre-fix/cases/{case_id}"
    raw = git(repo, "ls-tree", "-r", "-z", commit, "--", prefix)
    records = raw.split(b"\x00")
    if records and records[-1] == b"":
        records.pop()
    if not records:
        raise ContractError(f"native registry {case_id}: tracked seed tree is empty")
    rows: list[tuple[str, str, str]] = []
    pattern = re.compile(rb"^(100644|100755) blob ([0-9a-f]{40})\t(.+)$")
    blob_budget = ByteBudget(f"native registry {case_id} seed blobs", 64 * MIB)
    for record in records:
        match = pattern.fullmatch(record)
        if match is None:
            raise ContractError(
                f"native registry {case_id}: seed contains a non-regular Git entry"
            )
        mode_bytes, object_bytes, path_bytes = match.groups()
        try:
            path = path_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ContractError(
                f"native registry {case_id}: seed path is not UTF-8"
            ) from error
        expected_prefix = f"{prefix}/"
        if not path.startswith(expected_prefix):
            raise ContractError(f"native registry {case_id}: seed path escaped its case")
        relative = safe_relative(
            path[len(expected_prefix) :],
            label=f"native registry {case_id} seed path",
        ).as_posix()
        object_id = object_bytes.decode("ascii")
        payload = git_blob(
            repo,
            object_id,
            label=f"native registry {case_id} seed blob",
            max_bytes=NATIVE_ARTIFACT_MAX_BYTES,
            budget=blob_budget,
        )
        rows.append((relative, mode_bytes.decode("ascii"), sha256_bytes(payload)))
    rows.sort(key=lambda item: item[0])
    framed = "".join(
        f"{relative}\0{mode}\0{digest}\n" for relative, mode, digest in rows
    ).encode("utf-8")
    return sha256_bytes(framed)


def _validate_sandbox_profile(value: Any) -> dict[str, Any]:
    profile = exact_keys(
        value,
        {
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
        },
        label="native sandbox profile",
    )
    if (
        profile["schema"] != SANDBOX_SCHEMA
        or profile["implementation"] != "macos-sandbox-exec"
        or profile["mode"] != "offline-contained"
        or profile["claim_scope"] != "approved-tracked-seeds"
        or profile["default_policy"] != "allow"
        or profile["network"] is not False
        or profile["docker"] is not False
        or profile["live"] is not False
        or profile["provider"] is not False
        or profile["secrets"] is not False
        or profile["deny_network"] is not True
        or profile["deny_file_write_by_default"] is not True
        or profile["target_worktree_write"] is not False
        or profile["ephemeral_write"] is not True
        or profile["inherit_environment"] is not False
        or profile["process_exec_enforcement"] != "PATH-only-command-guards"
        or profile["secret_read_enforcement"]
        != "deny-listed-common-user-secret-roots"
    ):
        raise ContractError("native sandbox profile: containment boundary changed")
    writes = exact_keys(
        profile["filesystem_write"],
        {
            "target_worktree",
            "baseline_worktree",
            "ephemeral_scratch",
            "external_artifacts",
        },
        label="native sandbox profile filesystem_write",
    )
    if (
        writes["target_worktree"] is not False
        or writes["baseline_worktree"] is not False
        or writes["ephemeral_scratch"] is not True
        or writes["external_artifacts"] is not True
    ):
        raise ContractError("native sandbox profile: scoped filesystem writes changed")
    string_list(
        profile["denied_user_secret_roots"],
        label="native sandbox denied secret roots",
    )
    string_list(
        profile["expected_executables"],
        label="native sandbox expected executables",
    )
    blocked = string_list(
        profile["blocked_commands"],
        label="native sandbox blocked commands",
    )
    if not {"docker", "ssh"}.issubset(blocked):
        raise ContractError("native sandbox profile: Docker/SSH guards are absent")
    string_list(
        profile["forbidden_capabilities"],
        label="native sandbox forbidden capabilities",
    )
    return profile


def validate_native_definition_registry(
    *,
    rows: list[dict[str, Any]],
    registry_bytes: bytes,
    group_map_rows: list[dict[str, Any]],
    group_map_bytes: bytes,
    candidate_repo: Path,
    final_commit: str,
    final_tree: str,
    baseline_commit: str,
    baseline_tree: str,
) -> NativeRegistryValidation:
    if classify_pre_fix_registry(rows) != NATIVE_MODE:
        raise ContractError("native registry: all-row dispatch did not select native v2")
    group_by_id = {row["group_id"]: row for row in group_map_rows}
    if list(group_by_id) != list(EXPECTED_CASE_IDS):
        raise ContractError("native registry: authoritative group map order changed")
    source_map_sha256 = sha256_bytes(group_map_bytes)

    tracked_descriptors: dict[str, dict[str, Any]] = {}
    tracked_bytes: dict[str, bytes] = {}
    for key, relative in NATIVE_TRACKED_INPUT_REPO_PATHS.items():
        descriptor, payload = _git_regular_blob(
            candidate_repo,
            final_commit,
            relative,
            label=f"native tracked input {key}",
        )
        tracked_descriptors[key] = descriptor
        tracked_bytes[key] = payload
    if tracked_bytes["registry"] != registry_bytes:
        raise ContractError("native registry: handoff bytes differ from final HEAD")
    if tracked_bytes["source_map"] != group_map_bytes:
        raise ContractError(
            "native registry: tracked source map is not byte-identical to the authoritative group map"
        )
    sandbox = _validate_sandbox_profile(
        load_json_bytes(tracked_bytes["sandbox_profile"], label="native sandbox profile")
    )

    definitions: dict[str, dict[str, Any]] = {}
    canonical_projection: list[str] = []
    for index, case_id in enumerate(EXPECTED_CASE_IDS):
        row = rows[index]
        exact_keys(row, NATIVE_REGISTRY_KEYS, label=f"native registry {case_id}")
        group = group_by_id[case_id]
        if (
            row["schema"] != DEFINITION_SCHEMA
            or row["case_id"] != case_id
            or row["slug"] != group["slug"]
            or row["canonical_ids"] != group["canonical_ids"]
            or row["test_boundary"] != group["test_boundary"]
            or row["target_worktree_write"] is not False
            or row["ephemeral_write"] is not True
        ):
            raise ContractError(
                f"native registry {case_id}: authoritative identity or write boundary changed"
            )
        if not isinstance(row["slug"], str) or _SLUG_RE.fullmatch(row["slug"]) is None:
            raise ContractError(f"native registry {case_id}: invalid slug")
        canonical_ids = string_list(
            row["canonical_ids"], label=f"native registry {case_id} canonical IDs"
        )
        if any(_CAN_ID_RE.fullmatch(item) is None for item in canonical_ids):
            raise ContractError(f"native registry {case_id}: invalid canonical ID")
        canonical_projection.extend(canonical_ids)
        baseline = exact_keys(
            row["baseline"], {"commit", "tree"}, label=f"native registry {case_id} baseline"
        )
        if baseline != {"commit": baseline_commit, "tree": baseline_tree}:
            raise ContractError(f"native registry {case_id}: baseline identity changed")
        proof = exact_keys(
            row["proof_scope"],
            {
                "kind",
                "classification",
                "claim",
                "method",
                "expected_observation",
                "limitations",
            },
            label=f"native registry {case_id} proof scope",
        )
        if proof["kind"] != "exact-baseline-negative-reproduction" or proof[
            "classification"
        ] not in {
            "offline-product-consumer",
            "offline-source-control",
            "offline-source-model",
        }:
            raise ContractError(f"native registry {case_id}: invalid proof scope")
        for field in ("claim", "method", "expected_observation"):
            nonempty_string(proof[field], label=f"native registry {case_id} {field}")
        string_list(proof["limitations"], label=f"native registry {case_id} limitations")
        string_list(row["residuals"], label=f"native registry {case_id} residuals")

        anchors = row["anchors"]
        if not isinstance(anchors, list) or len(anchors) < 3:
            raise ContractError(f"native registry {case_id}: anchors are incomplete")
        root_controls: list[str] = []
        tracked_seed_count = 0
        consumer_count = 0
        for anchor_index, anchor_value in enumerate(anchors, start=1):
            if not isinstance(anchor_value, dict):
                raise ContractError(f"native registry {case_id}: malformed anchor")
            if set(anchor_value) not in ({"kind", "value"}, {"kind", "value", "sha256"}):
                raise ContractError(f"native registry {case_id}: malformed anchor keys")
            kind = anchor_value.get("kind")
            value = nonempty_string(
                anchor_value.get("value"),
                label=f"native registry {case_id} anchor {anchor_index}",
            )
            if kind == "root_control":
                if "sha256" in anchor_value:
                    raise ContractError(f"native registry {case_id}: root-control digest is unexpected")
                root_controls.append(value)
                continue
            if kind not in {"tracked_seed", "baseline_consumer"}:
                raise ContractError(f"native registry {case_id}: unknown anchor kind")
            digest = anchor_value.get("sha256")
            if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
                raise ContractError(f"native registry {case_id}: invalid anchor digest")
            relative = safe_relative(value, label=f"native registry {case_id} anchor path").as_posix()
            anchor_commit = final_commit if kind == "tracked_seed" else baseline_commit
            descriptor, _ = _git_regular_blob(
                candidate_repo,
                anchor_commit,
                relative,
                label=f"native registry {case_id} {kind}",
                max_bytes=NATIVE_ARTIFACT_MAX_BYTES,
            )
            if descriptor["sha256"] != digest:
                raise ContractError(f"native registry {case_id}: anchor digest changed")
            if kind == "tracked_seed":
                tracked_seed_count += 1
            else:
                consumer_count += 1
        if root_controls != [group["root_control"]] or tracked_seed_count < 1 or consumer_count < 1:
            raise ContractError(f"native registry {case_id}: anchor projection changed")

        seed_digest = row["seed_tree_sha256"]
        if not isinstance(seed_digest, str) or SHA256_RE.fullmatch(seed_digest) is None:
            raise ContractError(f"native registry {case_id}: invalid seed-tree digest")
        if _seed_tree_sha256(candidate_repo, final_commit, case_id) != seed_digest:
            raise ContractError(f"native registry {case_id}: seed-tree digest changed")

        if not isinstance(row["entrypoint"], dict):
            raise ContractError(f"native registry {case_id}: invalid entrypoint")
        entrypoint = exact_keys(
            row["entrypoint"],
            set(row["entrypoint"]),
            label=f"native registry {case_id} entrypoint",
        )
        if set(entrypoint) not in (
            {"kind", "cwd", "target"},
            {"kind", "cwd", "script", "args"},
        ):
            raise ContractError(f"native registry {case_id}: invalid entrypoint keys")
        cwd = safe_relative(entrypoint.get("cwd"), label=f"native registry {case_id} cwd").as_posix()
        if cwd != f"tests/pre-fix/cases/{case_id}":
            raise ContractError(f"native registry {case_id}: entrypoint escaped its case")
        if entrypoint.get("kind") == "make":
            if not isinstance(entrypoint.get("target"), str) or re.fullmatch(
                r"[a-z][a-z0-9-]*", entrypoint["target"]
            ) is None:
                raise ContractError(f"native registry {case_id}: invalid Make target")
        elif entrypoint.get("kind") == "node":
            script = safe_relative(
                entrypoint.get("script"), label=f"native registry {case_id} node script"
            ).as_posix()
            if not script.startswith(f"{cwd}/"):
                raise ContractError(f"native registry {case_id}: node script escaped its case")
            args = entrypoint.get("args")
            if not isinstance(args, list) or any(
                not isinstance(arg, str)
                or "\x00" in arg
                or "\n" in arg
                or "\r" in arg
                or any(
                    placeholder not in {"{{BASELINE_ROOT}}", "{{CONTRACT}}"}
                    for placeholder in re.findall(r"\{\{[A-Z_]+\}\}", arg)
                )
                for arg in args
            ):
                raise ContractError(f"native registry {case_id}: invalid node arguments")
        else:
            raise ContractError(f"native registry {case_id}: unsupported entrypoint")

        provenance = exact_keys(
            row["provenance"],
            {"source", "source_map_sha256", "migration"},
            label=f"native registry {case_id} provenance",
        )
        if provenance["source_map_sha256"] != source_map_sha256:
            raise ContractError(f"native registry {case_id}: source-map digest changed")
        nonempty_string(provenance["source"], label=f"native registry {case_id} source")
        nonempty_string(provenance["migration"], label=f"native registry {case_id} migration")
        definitions[case_id] = row

    if len(canonical_projection) != 135 or len(set(canonical_projection)) != 135:
        raise ContractError("native registry: canonical projection is not 135 unique CAN IDs")
    if final_tree != git_text(candidate_repo, "rev-parse", f"{final_commit}^{{tree}}"):
        raise ContractError("native registry: final candidate tree changed")
    return NativeRegistryValidation(
        definitions=definitions,
        tracked_input_descriptors=tracked_descriptors,
        tracked_input_bytes=tracked_bytes,
        sandbox_profile=sandbox,
    )


def _fixed_source_root(handoff_root: Path, replay_id: str) -> Path:
    try:
        canonical_root = handoff_root.resolve(strict=True)
    except OSError as error:
        raise ContractError("native replay source: handoff root is unavailable") from error
    if handoff_root.is_symlink() or not canonical_root.is_dir():
        raise ContractError("native replay source: handoff root must be a real directory")
    cursor = canonical_root
    for part in NATIVE_SOURCE_ROOTS[replay_id].parts:
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except OSError as error:
            raise ContractError(
                f"native replay {replay_id}: fixed source root is unavailable"
            ) from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ContractError(
                f"native replay {replay_id}: fixed source root contains an unsafe component"
            )
    try:
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(canonical_root)
    except (OSError, ValueError) as error:
        raise ContractError(
            f"native replay {replay_id}: fixed source root escaped the handoff"
        ) from error
    return resolved


def _descriptor_index(
    rows: tuple[dict[str, Any], ...]
) -> dict[str, dict[str, Any]]:
    return {
        row["path"]: {"sha256": row["sha256"], "size": row["size"]}
        for row in rows
    }


def _snapshot_source_artifacts(
    *,
    handoff_root: Path,
    replay_id: str,
    descriptor_rows: tuple[dict[str, Any], ...],
) -> dict[str, bytes]:
    source_root = _fixed_source_root(handoff_root, replay_id)
    expected = _descriptor_index(descriptor_rows)
    observed_before = tree_index(
        source_root,
        max_file_bytes=NATIVE_ARTIFACT_MAX_BYTES,
        max_total_bytes=NATIVE_REPLAY_TOTAL_MAX_BYTES,
        max_entries=NATIVE_REPLAY_TREE_MAX_ENTRIES,
    )
    if observed_before != expected:
        raise ContractError(
            f"native replay {replay_id}: descriptor does not hash the exact source tree"
        )
    budget = ByteBudget(
        f"native replay {replay_id} artifact snapshot",
        NATIVE_REPLAY_TOTAL_MAX_BYTES,
    )
    snapshots: dict[str, bytes] = {}
    for row in descriptor_rows:
        relative = row["path"]
        payload = read_regular_under(
            source_root,
            relative,
            label=f"native replay {replay_id}:{relative}",
            max_bytes=NATIVE_ARTIFACT_MAX_BYTES,
            budget=budget,
        )
        if len(payload) != row["size"] or sha256_bytes(payload) != row["sha256"]:
            raise ContractError(
                f"native replay {replay_id}: artifact changed during snapshot at {relative}"
            )
        scan_secret_bytes(payload, label=f"native replay {replay_id}:{relative}")
        snapshots[relative] = payload
    observed_after = tree_index(
        source_root,
        max_file_bytes=NATIVE_ARTIFACT_MAX_BYTES,
        max_total_bytes=NATIVE_REPLAY_TOTAL_MAX_BYTES,
        max_entries=NATIVE_REPLAY_TREE_MAX_ENTRIES,
    )
    if observed_after != observed_before:
        raise ContractError(f"native replay {replay_id}: source tree changed during snapshot")
    return snapshots


def _snapshot_packaged_artifacts(
    *,
    package_files: dict[str, bytes],
    replay_id: str,
    descriptor_rows: tuple[dict[str, Any], ...],
) -> dict[str, bytes]:
    prefix = NATIVE_PACKAGE_ROOTS[replay_id].as_posix()
    snapshots: dict[str, bytes] = {}
    total = 0
    for row in descriptor_rows:
        relative = row["path"]
        package_relative = f"{prefix}/{relative}"
        try:
            payload = package_files[package_relative]
        except KeyError as error:
            raise ContractError(
                f"native replay {replay_id}: packaged artifact is missing at {relative}"
            ) from error
        total += len(payload)
        if total > NATIVE_REPLAY_TOTAL_MAX_BYTES:
            raise ContractError(
                f"native replay {replay_id}: packaged artifact budget exceeded"
            )
        if len(payload) != row["size"] or sha256_bytes(payload) != row["sha256"]:
            raise ContractError(
                f"native replay {replay_id}: packaged artifact hash changed at {relative}"
            )
        snapshots[relative] = payload
    return snapshots


def _timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_MILLISECOND_RE.fullmatch(value) is None:
        raise ContractError(f"{label}: invalid UTC millisecond timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ContractError(f"{label}: invalid UTC millisecond timestamp") from error


def _sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ContractError(f"{label}: invalid SHA-256")
    return value


def _executable_descriptor(value: Any, *, label: str) -> dict[str, str]:
    row = exact_keys(value, {"path", "sha256"}, label=label)
    path = nonempty_string(row["path"], label=f"{label} path")
    if not Path(path).is_absolute() or "\x00" in path or "\n" in path:
        raise ContractError(f"{label}: executable path is unsafe")
    return {"path": path, "sha256": _sha256(row["sha256"], label=label)}


def _normalized_absolute_path(value: Any, *, label: str) -> str:
    path = nonempty_string(value, label=label)
    if (
        not Path(path).is_absolute()
        or "\x00" in path
        or "\n" in path
        or "\r" in path
        or path.startswith("//")
        or os.path.normpath(path) != path
    ):
        raise ContractError(f"{label}: path is not an exact normalized absolute path")
    return path


def _bind_invocation_executable(
    state: _ReplayInvocationState,
    *,
    role: str,
    command: str,
    executable: dict[str, str],
    case_id: str,
) -> None:
    if command != executable["path"] or Path(command).name != role:
        raise ContractError(
            f"native replay invocation: {case_id} command/executable is not exact {role}"
        )
    pair = (command, executable["sha256"])
    attribute = f"{role}_executable"
    previous = getattr(state, attribute)
    if previous is None:
        setattr(state, attribute, pair)
    elif previous != pair:
        raise ContractError(
            f"native replay invocation: {role} executable changed within the replay"
        )


def _validate_case_invocation(
    *,
    definition: dict[str, Any],
    command: str,
    argv: list[str],
    executable: dict[str, str],
    baseline_commit: str,
    case_id: str,
    state: _ReplayInvocationState,
) -> None:
    entrypoint = definition["entrypoint"]
    kind = entrypoint["kind"]
    if kind == "make":
        _bind_invocation_executable(
            state,
            role="make",
            command=command,
            executable=executable,
            case_id=case_id,
        )
        if len(argv) != 12 or not argv[3].startswith("SOURCE_REPO="):
            raise ContractError(
                f"native replay invocation: invalid Make argv for {case_id}"
            )
        baseline_root = _normalized_absolute_path(
            argv[3].removeprefix("SOURCE_REPO="),
            label=f"native replay invocation {case_id} baseline root",
        )
        expected = [
            "--no-print-directory",
            "-s",
            entrypoint["target"],
            f"SOURCE_REPO={baseline_root}",
            f"SOURCE_ROOT={baseline_root}",
            f"CANDIDATE_ROOT={baseline_root}",
            (
                "CONTRACT="
                f"{baseline_root}/scripts/hosted-workload-contract.mjs"
            ),
            f"REPOSITORY={baseline_root}",
            f"REPO={baseline_root}",
            f"REVISION={baseline_commit}",
            "EXPECT=vulnerable",
            f"CASE_ID={case_id}",
        ]
        if argv != expected:
            raise ContractError(
                f"native replay invocation: Make argv changed for {case_id}"
            )
        if state.baseline_root is None:
            state.baseline_root = baseline_root
        elif state.baseline_root != baseline_root:
            raise ContractError(
                "native replay invocation: baseline root changed within the replay"
            )
        return

    if kind != "node" or state.baseline_root is None:
        raise ContractError(
            f"native replay invocation: unsupported or unbound entrypoint for {case_id}"
        )
    _bind_invocation_executable(
        state,
        role="node",
        command=command,
        executable=executable,
        case_id=case_id,
    )
    if not argv:
        raise ContractError(f"native replay invocation: missing Node argv for {case_id}")
    script_path = _normalized_absolute_path(
        argv[0], label=f"native replay invocation {case_id} Node script"
    )
    script_relative = entrypoint["script"]
    script_suffix = f"/{script_relative}"
    if not script_path.endswith(script_suffix):
        raise ContractError(
            f"native replay invocation: Node script changed for {case_id}"
        )
    runner_root = script_path[: -len(script_suffix)] or "/"
    runner_root = _normalized_absolute_path(
        runner_root, label=f"native replay invocation {case_id} runner root"
    )
    if state.runner_root is None:
        state.runner_root = runner_root
    elif state.runner_root != runner_root:
        raise ContractError(
            "native replay invocation: runner root changed within the replay"
        )
    baseline_root = state.baseline_root
    replacements = {
        "{{BASELINE_ROOT}}": baseline_root,
        "{{CONTRACT}}": f"{baseline_root}/scripts/hosted-workload-contract.mjs",
    }
    expected_args: list[str] = []
    for argument in entrypoint["args"]:
        rendered = argument
        for placeholder, replacement in replacements.items():
            rendered = rendered.replace(placeholder, replacement)
        expected_args.append(rendered)
    expected_script = (PurePosixPath(runner_root) / script_relative).as_posix()
    expected = [expected_script, *expected_args]
    if argv != expected:
        raise ContractError(
            f"native replay invocation: Node argv changed for {case_id}"
        )


def _validate_summary(
    *,
    replay_id: str,
    value: Any,
    registry: NativeRegistryValidation,
    registry_bytes: bytes,
    group_map_bytes: bytes,
    final_commit: str,
    final_tree: str,
    baseline_commit: str,
    baseline_tree: str,
    expected_run_id: str,
) -> dict[str, Any]:
    summary = exact_keys(
        value,
        {
            "schema",
            "run_id",
            "started_at",
            "finished_at",
            "verdict",
            "baseline",
            "runner",
            "tracked_inputs",
            "registry_sha256",
            "source_map_sha256",
            "sandbox_profile_sha256",
            "sandbox",
            "trust_assumptions",
            "access_claim_scope",
            "filesystem_write",
            "forbidden_access",
            "output",
            "target_worktree_write",
            "ephemeral_write",
            "counts",
            "case_ids",
            "semantic_results_sha256",
            "proof_scope",
            "residuals",
        },
        label=f"native replay {replay_id} summary",
    )
    if (
        summary["schema"] != SUMMARY_SCHEMA
        or summary["run_id"] != expected_run_id
        or summary["verdict"] != "PASS"
    ):
        raise ContractError(f"native replay {replay_id}: summary is not a v2 PASS")
    summary_started = _timestamp(
        summary["started_at"], label=f"native replay {replay_id} start"
    )
    summary_finished = _timestamp(
        summary["finished_at"], label=f"native replay {replay_id} finish"
    )
    if summary_started > summary_finished:
        raise ContractError(f"native replay {replay_id}: summary timestamp causality changed")

    baseline = exact_keys(
        summary["baseline"],
        {
            "commit",
            "tree",
            "detached",
            "materialization",
            "object_files_checked",
            "maximum_object_link_count",
            "shared_object_alternates",
            "clean_before",
            "clean_after",
        },
        label=f"native replay {replay_id} baseline",
    )
    if (
        baseline["commit"] != baseline_commit
        or baseline["tree"] != baseline_tree
        or baseline["detached"] is not True
        or baseline["materialization"] != "git-clone-no-hardlinks-local"
        or type(baseline["object_files_checked"]) is not int
        or baseline["object_files_checked"] <= 0
        or type(baseline["maximum_object_link_count"]) is not int
        or baseline["maximum_object_link_count"] != 1
        or baseline["shared_object_alternates"] is not False
        or baseline["clean_before"] is not True
        or baseline["clean_after"] is not True
    ):
        raise ContractError(f"native replay {replay_id}: baseline isolation changed")

    runner = exact_keys(
        summary["runner"],
        {"commit", "tree", "clean_before", "clean_after"},
        label=f"native replay {replay_id} runner",
    )
    if (
        runner["commit"] != final_commit
        or runner["tree"] != final_tree
        or runner["clean_before"] is not True
        or runner["clean_after"] is not True
    ):
        raise ContractError(f"native replay {replay_id}: runner is not bound to final HEAD/tree")
    tracked = exact_keys(
        summary["tracked_inputs"],
        NATIVE_TRACKED_INPUT_REPO_PATHS,
        label=f"native replay {replay_id} tracked inputs",
    )
    if tracked != registry.tracked_input_descriptors:
        raise ContractError(f"native replay {replay_id}: tracked Git descriptors changed")
    if (
        summary["registry_sha256"] != sha256_bytes(registry_bytes)
        or summary["source_map_sha256"] != sha256_bytes(group_map_bytes)
        or summary["sandbox_profile_sha256"]
        != sha256_bytes(registry.tracked_input_bytes["sandbox_profile"])
    ):
        raise ContractError(f"native replay {replay_id}: tracked input hashes changed")

    sandbox = exact_keys(
        summary["sandbox"],
        {
            "schema",
            "mode",
            "claim_scope",
            "implementation",
            "executable",
            "network",
            "docker",
            "live",
            "provider",
            "secrets",
            "process_exec_enforcement",
            "secret_read_enforcement",
            "denied_user_secret_roots",
            "forbidden_access",
            "target_worktree_write",
            "ephemeral_write",
            "environment_inherited",
        },
        label=f"native replay {replay_id} sandbox",
    )
    sandbox_executable = _executable_descriptor(
        sandbox["executable"], label=f"native replay {replay_id} sandbox executable"
    )
    if sandbox_executable["path"] != "/usr/bin/sandbox-exec":
        raise ContractError(
            f"native replay {replay_id}: sandbox executable identity changed"
        )
    expected_forbidden = [
        "network",
        "docker",
        "live",
        "provider",
        "listed_user_secret_roots",
        "target_worktree_write",
        "baseline_worktree_write",
    ]
    if (
        sandbox["schema"] != SANDBOX_SCHEMA
        or sandbox["mode"] != "offline-contained"
        or sandbox["claim_scope"] != "approved-tracked-seeds"
        or sandbox["implementation"] != "macos-sandbox-exec"
        or any(sandbox[key] is not False for key in ("network", "docker", "live", "provider", "secrets"))
        or sandbox["process_exec_enforcement"] != "PATH-only-command-guards"
        or sandbox["secret_read_enforcement"] != "deny-listed-common-user-secret-roots"
        or sandbox["denied_user_secret_roots"]
        != registry.sandbox_profile["denied_user_secret_roots"]
        or sandbox["forbidden_access"] != expected_forbidden
        or sandbox["target_worktree_write"] is not False
        or sandbox["ephemeral_write"] is not True
        or sandbox["environment_inherited"] is not False
    ):
        raise ContractError(f"native replay {replay_id}: sandbox receipt changed")

    assumptions = string_list(
        summary["trust_assumptions"],
        label=f"native replay {replay_id} trust assumptions",
    )
    if len(assumptions) != 3:
        raise ContractError(f"native replay {replay_id}: trust assumptions changed")
    if summary["access_claim_scope"] != "approved-tracked-seeds":
        raise ContractError(f"native replay {replay_id}: access claim scope changed")
    writes = exact_keys(
        summary["filesystem_write"],
        {
            "target_worktree",
            "baseline_worktree",
            "runner_worktree",
            "ephemeral_scratch",
            "external_artifacts",
        },
        label=f"native replay {replay_id} filesystem_write",
    )
    if (
        writes["target_worktree"] is not False
        or writes["baseline_worktree"] is not False
        or writes["runner_worktree"] is not False
        or writes["ephemeral_scratch"] is not True
        or writes["external_artifacts"] is not True
    ):
        raise ContractError(f"native replay {replay_id}: scoped filesystem writes changed")
    forbidden = exact_keys(
        summary["forbidden_access"],
        {"network", "docker", "live", "provider", "secrets"},
        label=f"native replay {replay_id} forbidden access",
    )
    if any(forbidden[key] is not False for key in forbidden):
        raise ContractError(f"native replay {replay_id}: forbidden access occurred")
    output = exact_keys(
        summary["output"],
        {
            "external_to_runner_worktree",
            "external_to_baseline_worktree",
            "external_to_baseline_source",
            "tracked",
        },
        label=f"native replay {replay_id} output",
    )
    if (
        output["external_to_runner_worktree"] is not True
        or output["external_to_baseline_worktree"] is not True
        or output["external_to_baseline_source"] is not True
        or output["tracked"] is not False
    ):
        raise ContractError(f"native replay {replay_id}: output boundary changed")
    if summary["target_worktree_write"] is not False or summary["ephemeral_write"] is not True:
        raise ContractError(f"native replay {replay_id}: write declaration changed")
    counts = exact_keys(
        summary["counts"],
        {"expected", "executed", "passed", "failed"},
        label=f"native replay {replay_id} counts",
    )
    if any(type(counts[key]) is not int for key in counts) or counts != {
        "expected": 77,
        "executed": 77,
        "passed": 77,
        "failed": 0,
    }:
        raise ContractError(f"native replay {replay_id}: replay is not 77/77 PASS")
    if summary["case_ids"] != list(EXPECTED_CASE_IDS):
        raise ContractError(f"native replay {replay_id}: case identity order changed")
    _sha256(
        summary["semantic_results_sha256"],
        label=f"native replay {replay_id} semantic results",
    )
    proof = exact_keys(
        summary["proof_scope"],
        {"kind", "statement", "classifications", "excludes"},
        label=f"native replay {replay_id} proof scope",
    )
    expected_classifications = {
        classification: sum(
            definition["proof_scope"]["classification"] == classification
            for definition in registry.definitions.values()
        )
        for classification in (
            "offline-product-consumer",
            "offline-source-control",
            "offline-source-model",
        )
    }
    if (
        proof["kind"] != "exact-baseline-negative-reproduction"
        or not isinstance(proof["statement"], str)
        or not isinstance(proof["classifications"], dict)
        or any(
            type(value) is not int for value in proof["classifications"].values()
        )
        or proof["classifications"] != expected_classifications
        or proof["excludes"]
        != [
            "post-fix remediation correctness",
            "live deployment state",
            "provider or production attestation",
        ]
    ):
        raise ContractError(f"native replay {replay_id}: proof scope changed")
    residuals = string_list(
        summary["residuals"], label=f"native replay {replay_id} residuals"
    )
    if len(residuals) != 3:
        raise ContractError(f"native replay {replay_id}: residual set changed")
    return summary


def _stable_result(result: dict[str, Any]) -> dict[str, Any]:
    return {key: result[key] for key in _STABLE_RESULT_KEYS}


def _validate_case_result(
    *,
    replay_id: str,
    index: int,
    result: Any,
    definition: dict[str, Any],
    files: dict[str, bytes],
    final_commit: str,
    baseline_commit: str,
    baseline_tree: str,
    expected_run_id: str,
    invocation_state: _ReplayInvocationState | None = None,
) -> dict[str, Any]:
    case_id = EXPECTED_CASE_IDS[index]
    row = exact_keys(
        result,
        {
            "schema",
            "run_id",
            "execution_index",
            "execution_id",
            "case_id",
            "slug",
            "started_at",
            "finished_at",
            "status",
            "exit_code",
            "signal",
            "timed_out",
            "exceeded_output",
            "duration_ms",
            "stdout_sha256",
            "stderr_sha256",
            "normalized_stdout_sha256",
            "normalized_stderr_sha256",
            "command",
            "argv",
            "executable",
            "seed_tree_sha256",
            "proof_scope",
            "residuals",
            "anchors",
            "consumer_git_anchors",
            "target_worktree_write",
            "ephemeral_write",
            "forbidden_access",
            "access_claim_scope",
            "log_envelope",
            "artifact_paths",
        },
        label=f"native replay {replay_id} result {case_id}",
    )
    execution_identity = (
        expected_run_id
        + "\0"
        + final_commit
        + "\0"
        + baseline_commit
        + "\0"
        + definition["seed_tree_sha256"]
    ).encode("utf-8")
    expected_execution_id = (
        f"{case_id}:{sha256_bytes(execution_identity)[:24]}"
    )
    if type(row["execution_index"]) is not int or type(row["exit_code"]) is not int:
        raise ContractError(
            f"native replay {replay_id}: result integer types changed for {case_id}"
        )
    if (
        row["schema"] != RESULT_SCHEMA
        or row["run_id"] != expected_run_id
        or row["execution_index"] != index + 1
        or row["execution_id"] != expected_execution_id
        or row["case_id"] != case_id
        or row["slug"] != definition["slug"]
        or row["status"] != "PASS"
        or row["exit_code"] != 0
        or row["signal"] is not None
        or row["timed_out"] is not False
        or row["exceeded_output"] is not False
        or row["seed_tree_sha256"] != definition["seed_tree_sha256"]
        or row["proof_scope"] != definition["proof_scope"]
        or row["residuals"] != definition["residuals"]
        or row["anchors"] != definition["anchors"]
        or row["target_worktree_write"] is not False
        or row["ephemeral_write"] is not True
        or row["access_claim_scope"] != "approved-tracked-seeds"
    ):
        raise ContractError(f"native replay {replay_id}: result semantics changed for {case_id}")
    case_started = _timestamp(
        row["started_at"], label=f"native replay {replay_id} {case_id} start"
    )
    case_finished = _timestamp(
        row["finished_at"], label=f"native replay {replay_id} {case_id} finish"
    )
    if case_started > case_finished:
        raise ContractError(
            f"native replay {replay_id}: timestamp causality changed for {case_id}"
        )
    duration = row["duration_ms"]
    if (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(duration)
        or duration < 0
    ):
        raise ContractError(f"native replay {replay_id}: invalid duration for {case_id}")
    for key in (
        "stdout_sha256",
        "stderr_sha256",
        "normalized_stdout_sha256",
        "normalized_stderr_sha256",
    ):
        _sha256(row[key], label=f"native replay {replay_id} {case_id} {key}")
    command = _normalized_absolute_path(
        row["command"], label=f"native replay {replay_id} {case_id} command"
    )
    argv = row["argv"]
    if not isinstance(argv, list) or any(
        not isinstance(argument, str)
        or "\x00" in argument
        or "\n" in argument
        or "\r" in argument
        for argument in argv
    ):
        raise ContractError(f"native replay {replay_id}: unsafe argv for {case_id}")
    executable = _executable_descriptor(
        row["executable"], label=f"native replay {replay_id} {case_id} executable"
    )
    _validate_case_invocation(
        definition=definition,
        command=command,
        argv=argv,
        executable=executable,
        baseline_commit=baseline_commit,
        case_id=case_id,
        state=invocation_state or _ReplayInvocationState(),
    )
    forbidden = exact_keys(
        row["forbidden_access"],
        {"network", "docker", "live", "provider", "secrets"},
        label=f"native replay {replay_id} {case_id} forbidden access",
    )
    if any(forbidden[key] is not False for key in forbidden):
        raise ContractError(f"native replay {replay_id}: forbidden access for {case_id}")

    expected_consumers = [
        {
            "commit": baseline_commit,
            "tree": baseline_tree,
            "path": anchor["value"],
            "sha256": anchor["sha256"],
        }
        for anchor in definition["anchors"]
        if anchor["kind"] == "baseline_consumer"
    ]
    if row["consumer_git_anchors"] != expected_consumers:
        raise ContractError(f"native replay {replay_id}: consumer anchors changed for {case_id}")
    artifact_paths = exact_keys(
        row["artifact_paths"],
        {"stdout", "stderr", "log"},
        label=f"native replay {replay_id} {case_id} artifact paths",
    )
    expected_artifact_paths = {
        "stdout": f"{case_id}/stdout.log",
        "stderr": f"{case_id}/stderr.log",
        "log": f"{case_id}/execution.log",
    }
    if artifact_paths != expected_artifact_paths:
        raise ContractError(f"native replay {replay_id}: artifact paths escaped for {case_id}")
    stdout = files[expected_artifact_paths["stdout"]]
    stderr = files[expected_artifact_paths["stderr"]]
    execution_log = files[expected_artifact_paths["log"]]
    if sha256_bytes(stdout) != row["stdout_sha256"] or sha256_bytes(stderr) != row["stderr_sha256"]:
        raise ContractError(f"native replay {replay_id}: stdout/stderr hash changed for {case_id}")

    envelope = exact_keys(
        row["log_envelope"],
        {
            "schema",
            "path",
            "sha256",
            "stdout_sha256",
            "stderr_sha256",
            "normalized_stdout_sha256",
            "normalized_stderr_sha256",
        },
        label=f"native replay {replay_id} {case_id} log envelope",
    )
    if envelope != {
        "schema": LOG_ENVELOPE_SCHEMA,
        "path": f"{case_id}/execution.log",
        "sha256": sha256_bytes(execution_log),
        "stdout_sha256": row["stdout_sha256"],
        "stderr_sha256": row["stderr_sha256"],
        "normalized_stdout_sha256": row["normalized_stdout_sha256"],
        "normalized_stderr_sha256": row["normalized_stderr_sha256"],
    }:
        raise ContractError(f"native replay {replay_id}: log envelope changed for {case_id}")
    log_header = {
        "schema": LOG_ENVELOPE_SCHEMA,
        "run_id": expected_run_id,
        "case_id": case_id,
        "baseline_commit": baseline_commit,
        "baseline_tree": baseline_tree,
        "runner_commit": final_commit,
        "seed_tree_sha256": definition["seed_tree_sha256"],
        "executable_sha256": executable["sha256"],
    }
    expected_log = (
        json.dumps(log_header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        + b"\n--- stdout ---\n"
        + stdout
        + b"\n--- stderr ---\n"
        + stderr
    )
    if execution_log != expected_log:
        raise ContractError(f"native replay {replay_id}: execution log changed for {case_id}")
    return row


def _validate_replay_timeline(
    *,
    replay_id: str,
    summary: dict[str, Any],
    results: Iterable[dict[str, Any]],
) -> None:
    summary_started = _timestamp(
        summary["started_at"], label=f"native replay {replay_id} summary start"
    )
    summary_finished = _timestamp(
        summary["finished_at"], label=f"native replay {replay_id} summary finish"
    )
    previous_finished = summary_started
    for result in results:
        case_id = result["case_id"]
        case_started = _timestamp(
            result["started_at"], label=f"native replay {replay_id} {case_id} start"
        )
        case_finished = _timestamp(
            result["finished_at"], label=f"native replay {replay_id} {case_id} finish"
        )
        if (
            case_started < previous_finished
            or case_finished < case_started
            or case_finished > summary_finished
        ):
            raise ContractError(
                f"native replay {replay_id}: sequential timestamp causality changed"
            )
        previous_finished = case_finished


def _validate_replay_files(
    *,
    replay_id: str,
    files: dict[str, bytes],
    descriptor_rows: tuple[dict[str, Any], ...],
    registry: NativeRegistryValidation,
    registry_bytes: bytes,
    group_map_bytes: bytes,
    final_commit: str,
    final_tree: str,
    baseline_commit: str,
    baseline_tree: str,
    expected_run_id: str,
) -> NativeReplaySnapshot:
    summary_payload = files["summary.json"]
    results_payload = files["results.jsonl"]
    if len(summary_payload) > NATIVE_SUMMARY_MAX_BYTES or len(results_payload) > NATIVE_RESULTS_MAX_BYTES:
        raise ContractError(f"native replay {replay_id}: summary/results byte limit exceeded")
    if not summary_payload.endswith(b"\n") or not results_payload.endswith(b"\n"):
        raise ContractError(f"native replay {replay_id}: summary/results lack terminal newline")
    summary = _validate_summary(
        replay_id=replay_id,
        value=load_json_bytes(summary_payload, label=f"native replay {replay_id} summary"),
        registry=registry,
        registry_bytes=registry_bytes,
        group_map_bytes=group_map_bytes,
        final_commit=final_commit,
        final_tree=final_tree,
        baseline_commit=baseline_commit,
        baseline_tree=baseline_tree,
        expected_run_id=expected_run_id,
    )
    raw_results = load_jsonl_bytes(results_payload, label=f"native replay {replay_id} results")
    if len(raw_results) != 77:
        raise ContractError(f"native replay {replay_id}: expected exactly 77 results")
    results: list[dict[str, Any]] = []
    projection: list[dict[str, Any]] = []
    invocation_state = _ReplayInvocationState()
    for index, case_id in enumerate(EXPECTED_CASE_IDS):
        result = _validate_case_result(
            replay_id=replay_id,
            index=index,
            result=raw_results[index],
            definition=registry.definitions[case_id],
            files=files,
            final_commit=final_commit,
            baseline_commit=baseline_commit,
            baseline_tree=baseline_tree,
            expected_run_id=expected_run_id,
            invocation_state=invocation_state,
        )
        results.append(result)
        projection.append(_stable_result(result))
    _validate_replay_timeline(
        replay_id=replay_id,
        summary=summary,
        results=results,
    )
    semantic_payload = semantic_projection_bytes(projection)
    semantic_digest = sha256_bytes(semantic_payload)
    if summary["semantic_results_sha256"] != semantic_digest:
        raise ContractError(f"native replay {replay_id}: semantic projection digest changed")
    artifact_index = _descriptor_index(descriptor_rows)
    return NativeReplaySnapshot(
        replay_id=replay_id,
        run_id=expected_run_id,
        artifacts={
            relative: ReplayArtifact(
                relative_path=relative,
                size=len(payload),
                sha256=sha256_bytes(payload),
                payload=payload,
            )
            for relative, payload in files.items()
        },
        summary=summary,
        results=tuple(results),
        semantic_projection=tuple(projection),
        semantic_projection_sha256=semantic_digest,
        artifact_index_sha256=sha256_bytes(canonical_json_bytes(artifact_index)),
    )


def _validate_replay_pair(replays: dict[str, NativeReplaySnapshot]) -> None:
    if replays["A"].run_id == replays["B"].run_id:
        raise ContractError(
            "native replay A/B run_id values do not prove independent invocations"
        )
    validate_semantic_replay_pair(
        replays["A"].semantic_projection,
        replays["A"].semantic_projection_sha256,
        replays["B"].semantic_projection,
        replays["B"].semantic_projection_sha256,
    )


def validate_native_source_replay_set(
    *,
    descriptor_bytes: bytes,
    handoff_root: Path,
    registry_rows: list[dict[str, Any]],
    registry_bytes: bytes,
    group_map_rows: list[dict[str, Any]],
    group_map_bytes: bytes,
    candidate_repo: Path,
    final_commit: str,
    final_tree: str,
    baseline_commit: str,
    baseline_tree: str,
) -> NativeReplaySet:
    descriptor = parse_native_replay_descriptor(descriptor_bytes)
    registry = validate_native_definition_registry(
        rows=registry_rows,
        registry_bytes=registry_bytes,
        group_map_rows=group_map_rows,
        group_map_bytes=group_map_bytes,
        candidate_repo=candidate_repo,
        final_commit=final_commit,
        final_tree=final_tree,
        baseline_commit=baseline_commit,
        baseline_tree=baseline_tree,
    )
    replays: dict[str, NativeReplaySnapshot] = {}
    for replay_id in REPLAY_IDS:
        descriptor_entry = descriptor[replay_id]
        files = _snapshot_source_artifacts(
            handoff_root=handoff_root,
            replay_id=replay_id,
            descriptor_rows=descriptor_entry["artifacts"],
        )
        replays[replay_id] = _validate_replay_files(
            replay_id=replay_id,
            files=files,
            descriptor_rows=descriptor_entry["artifacts"],
            registry=registry,
            registry_bytes=registry_bytes,
            group_map_bytes=group_map_bytes,
            final_commit=final_commit,
            final_tree=final_tree,
            baseline_commit=baseline_commit,
            baseline_tree=baseline_tree,
            expected_run_id=descriptor_entry["run_id"],
        )
    _validate_replay_pair(replays)
    return NativeReplaySet(
        descriptor_bytes=descriptor_bytes,
        descriptor_sha256=sha256_bytes(descriptor_bytes),
        replays=replays,
        tracked_input_bytes=registry.tracked_input_bytes,
    )


def validate_native_packaged_replay_set(
    *,
    descriptor_bytes: bytes,
    package_files: dict[str, bytes],
    registry_rows: list[dict[str, Any]],
    registry_bytes: bytes,
    group_map_rows: list[dict[str, Any]],
    group_map_bytes: bytes,
    candidate_repo: Path,
    final_commit: str,
    final_tree: str,
    baseline_commit: str,
    baseline_tree: str,
) -> NativeReplaySet:
    descriptor = parse_native_replay_descriptor(descriptor_bytes)
    registry = validate_native_definition_registry(
        rows=registry_rows,
        registry_bytes=registry_bytes,
        group_map_rows=group_map_rows,
        group_map_bytes=group_map_bytes,
        candidate_repo=candidate_repo,
        final_commit=final_commit,
        final_tree=final_tree,
        baseline_commit=baseline_commit,
        baseline_tree=baseline_tree,
    )
    for key, relative in NATIVE_TRACKED_INPUT_ARCHIVE_PATHS.items():
        if package_files.get(relative) != registry.tracked_input_bytes[key]:
            raise ContractError(
                f"native replay package: archived tracked input changed for {key}"
            )
    replays: dict[str, NativeReplaySnapshot] = {}
    for replay_id in REPLAY_IDS:
        descriptor_entry = descriptor[replay_id]
        files = _snapshot_packaged_artifacts(
            package_files=package_files,
            replay_id=replay_id,
            descriptor_rows=descriptor_entry["artifacts"],
        )
        replays[replay_id] = _validate_replay_files(
            replay_id=replay_id,
            files=files,
            descriptor_rows=descriptor_entry["artifacts"],
            registry=registry,
            registry_bytes=registry_bytes,
            group_map_bytes=group_map_bytes,
            final_commit=final_commit,
            final_tree=final_tree,
            baseline_commit=baseline_commit,
            baseline_tree=baseline_tree,
            expected_run_id=descriptor_entry["run_id"],
        )
    _validate_replay_pair(replays)
    return NativeReplaySet(
        descriptor_bytes=descriptor_bytes,
        descriptor_sha256=sha256_bytes(descriptor_bytes),
        replays=replays,
        tracked_input_bytes=registry.tracked_input_bytes,
    )


def native_input_hashes(replay_set: NativeReplaySet) -> dict[str, str]:
    return {
        "pre_fix_mode": sha256_bytes(NATIVE_MODE.encode("ascii")),
        "pre_fix_native_descriptor": replay_set.descriptor_sha256,
        **{
            f"pre_fix_native_replay:{replay_id}:artifact_index": replay_set.replays[
                replay_id
            ].artifact_index_sha256
            for replay_id in REPLAY_IDS
        },
        **{
            f"pre_fix_native_replay:{replay_id}:semantic_projection": replay_set.replays[
                replay_id
            ].semantic_projection_sha256
            for replay_id in REPLAY_IDS
        },
        **{
            f"pre_fix_native_tracked_input:{key}": sha256_bytes(payload)
            for key, payload in sorted(replay_set.tracked_input_bytes.items())
        },
    }


def expected_native_package_paths() -> frozenset[str]:
    return frozenset(
        {
            NATIVE_PACKAGE_DESCRIPTOR_PATH,
            f"schemas/{NATIVE_SCHEMA_NAME}",
            *NATIVE_TRACKED_INPUT_ARCHIVE_PATHS.values(),
            *(
                f"{NATIVE_PACKAGE_ROOTS[replay_id].as_posix()}/{relative}"
                for replay_id in REPLAY_IDS
                for relative in EXPECTED_ARTIFACT_PATHS
            ),
        }
    )
