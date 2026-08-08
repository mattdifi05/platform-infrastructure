#!/usr/bin/env python3
"""Build a deterministic two-replay Ultra post-fix evidence package."""

from __future__ import annotations

import argparse
import copy
import ctypes
import errno
import json
import os
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from scripts.postfix_evidence.common import (
    ContractError,
    canonical_json_bytes,
    scan_secret_bytes,
    sha256_bytes,
    run_process_bounded,
    tree_index,
    write_bytes,
    write_json,
    write_jsonl,
)
from scripts.postfix_evidence.native_pre_fix_replay_v2 import (
    LEGACY_MODE,
    NATIVE_MODE,
    NATIVE_PACKAGE_DESCRIPTOR_PATH,
    NATIVE_PACKAGE_ROOTS,
    NATIVE_SCHEMA_NAME,
    NATIVE_TRACKED_INPUT_ARCHIVE_PATHS,
    REPLAY_IDS as NATIVE_REPLAY_IDS,
    native_input_hashes,
)
from scripts.postfix_evidence.validate_postfix_package import (
    BASELINE_MANIFEST_ARCHIVE_PATH,
    COHORT_HANDOFF_ARCHIVE_PATHS,
    GROUP_MAP_ARCHIVE_PATH,
    HANDOFF_ARCHIVE_PATHS,
    HANDOFF_MANIFEST_ARCHIVE_PATH,
    PACKAGE_NATIVE_TOTAL_MAX_BYTES,
    PACKAGE_TOTAL_MAX_BYTES,
    REPLAY_RECEIPT_PATHS,
    TOOL_SOURCE_NAMES,
    TOOL_SOURCE_PACKAGE_PATHS,
    ValidatedInputs,
    _derive_finding_map,
    expected_package_payload_paths,
    expected_baseline_binding,
    replay_source_snapshot_sha256,
    revalidate_candidate_final_state,
)


WORKER_STDOUT_MAX_BYTES = 4 * 1024 * 1024
WORKER_STDERR_MAX_BYTES = 1 * 1024 * 1024
WORKER_OUTPUT_TOTAL_MAX_BYTES = (
    WORKER_STDOUT_MAX_BYTES + WORKER_STDERR_MAX_BYTES
)
WORKER_STDIN_MAX_BYTES = 1024
CLEANUP_MAX_ENTRIES = 10_000
CLEANUP_MAX_DEPTH = 128


def _package_total_max_bytes(pre_fix_mode: str) -> int:
    if pre_fix_mode == LEGACY_MODE:
        return PACKAGE_TOTAL_MAX_BYTES
    if pre_fix_mode == NATIVE_MODE:
        return PACKAGE_NATIVE_TOTAL_MAX_BYTES
    raise ContractError("package tree: unsupported pre-fix evidence mode")


def _package_tree_index(
    root: Path,
    pre_fix_mode: str,
    *,
    exclude: Iterable[str] = (),
) -> dict[str, dict[str, Any]]:
    return tree_index(
        root,
        exclude=exclude,
        max_total_bytes=_package_total_max_bytes(pre_fix_mode),
    )


def _write_package_manifest(root: Path, pre_fix_mode: str) -> None:
    index = _package_tree_index(
        root,
        pre_fix_mode,
        exclude={"MANIFEST.sha256"},
    )
    payload = "".join(
        f"{row['sha256']}  {relative}\n"
        for relative, row in sorted(index.items())
    )
    write_bytes(root / "MANIFEST.sha256", payload.encode("utf-8"))


def _copy_verified_log(payload: bytes, expected_sha256: str, destination: Path) -> None:
    if len(payload) > 10 * 1024 * 1024:
        raise ContractError("evidence log: file exceeds the 10 MiB package limit")
    if sha256_bytes(payload) != expected_sha256:
        raise ContractError("evidence log: source changed after validation")
    scan_secret_bytes(payload, label="evidence log")
    write_bytes(destination, payload)


def _rewrite_test_receipts(data: ValidatedInputs, destination: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for original in sorted(data.test_receipt_rows, key=lambda row: row["receipt_id"]):
        row = copy.deepcopy(original)
        receipt_id = row["receipt_id"]
        relative = f"evidence/test/logs/{receipt_id}.log"
        expected = row["log"]["sha256"]
        _copy_verified_log(data.test_log_bytes[receipt_id], expected, destination / relative)
        row["log"] = {"path": relative, "sha256": expected}
        rows.append(row)
    return rows


def _rewrite_pre_fix_receipt(data: ValidatedInputs, destination: Path) -> dict[str, Any]:
    receipt = copy.deepcopy(data.pre_fix_receipt)
    executions = []
    for original in sorted(receipt["executions"], key=lambda row: row["group_id"]):
        row = copy.deepcopy(original)
        group_id = row["group_id"]
        relative = f"evidence/test/pre-fix/{group_id}.log"
        expected = row["log"]["sha256"]
        _copy_verified_log(data.pre_fix_log_bytes[group_id], expected, destination / relative)
        row["log"] = {"path": relative, "sha256": expected}
        executions.append(row)
    receipt["executions"] = executions
    return receipt


def _write_native_pre_fix_replays(data: ValidatedInputs, destination: Path) -> None:
    replay_set = data.native_pre_fix_replays
    if data.pre_fix_mode != NATIVE_MODE or replay_set is None:
        raise ContractError("native replay render: validated replay set is absent")
    if replay_set.descriptor_bytes != data.handoff_file_bytes[
        "pre_fix_negative_receipt"
    ]:
        raise ContractError("native replay render: descriptor changed after validation")
    write_bytes(
        destination / NATIVE_PACKAGE_DESCRIPTOR_PATH,
        replay_set.descriptor_bytes,
    )
    for key, relative in NATIVE_TRACKED_INPUT_ARCHIVE_PATHS.items():
        payload = replay_set.tracked_input_bytes[key]
        scan_secret_bytes(payload, label=f"native replay tracked input {key}")
        write_bytes(destination / relative, payload)
    for replay_id in NATIVE_REPLAY_IDS:
        replay = replay_set.replays[replay_id]
        prefix = NATIVE_PACKAGE_ROOTS[replay_id]
        for relative, artifact in sorted(replay.artifacts.items()):
            if (
                len(artifact.payload) != artifact.size
                or sha256_bytes(artifact.payload) != artifact.sha256
            ):
                raise ContractError(
                    f"native replay render: {replay_id}/{relative} changed after validation"
                )
            scan_secret_bytes(
                artifact.payload,
                label=f"native replay {replay_id}:{relative}",
            )
            write_bytes(destination / Path(*prefix.parts) / relative, artifact.payload)


def _render_readme(data: ValidatedInputs) -> bytes:
    verdicts = data.verdicts
    lines = [
        "# Ultra post-fix evidence package",
        "",
        "This package is a deterministic, two-replay evidence assembly bound to one clean final candidate HEAD.",
        "It does not modify or supersede the authoritative pre-fix baseline.",
        "",
        f"- Candidate security verdict: `{verdicts['candidate_security']['value']}`",
        f"- Merge verdict: `{verdicts['merge']['value']}`",
        f"- GO-to-deploy verdict: `{verdicts['go_to_deploy']['value']}`",
        f"- Full production-go verdict: `{verdicts['full_production_go']['value']}`",
        f"- Ready for commit/push/deploy authorization: `{verdicts['ready_for_commit_push_deploy_authorization']}`",
        "",
        "No push, merge, deploy, provider mutation, Docker operation, network operation, or live mutation was performed by the builder.",
        "Provider/live residuals remain explicit under `evidence/validation/provider_live_residuals.jsonl`.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _render_core(
    destination: Path,
    data: ValidatedInputs,
    tool_sources: dict[str, bytes],
) -> None:
    write_bytes(destination / "README.md", _render_readme(data))
    write_json(
        destination / "baseline/baseline_binding.json",
        expected_baseline_binding(data.baseline, data.group_map_sha256),
    )
    write_jsonl(destination / "baseline/security_fix_groups_v1.jsonl", data.group_map_rows)
    write_jsonl(
        destination / "evidence/validation/canonical_candidate_registry.jsonl",
        data.baseline.registry,
    )
    write_json(destination / "schemas/matrix-schema-v1.json", data.baseline.matrix_schema)
    write_bytes(
        destination / "schemas/handoff-v1.schema.json",
        tool_sources["handoff-v1.schema.json"],
    )
    if data.pre_fix_mode == NATIVE_MODE:
        write_bytes(
            destination / f"schemas/{NATIVE_SCHEMA_NAME}",
            tool_sources[NATIVE_SCHEMA_NAME],
        )
    write_bytes(destination / BASELINE_MANIFEST_ARCHIVE_PATH, data.baseline.manifest_bytes)
    write_bytes(destination / GROUP_MAP_ARCHIVE_PATH, data.group_map_bytes)
    write_bytes(destination / HANDOFF_MANIFEST_ARCHIVE_PATH, data.handoff_bytes)
    for key, relative in HANDOFF_ARCHIVE_PATHS.items():
        write_bytes(destination / relative, data.handoff_file_bytes[key])
    for key, relative in COHORT_HANDOFF_ARCHIVE_PATHS.items():
        write_bytes(destination / relative, data.cohort_handoff_bytes[key])
    for name, relative in TOOL_SOURCE_PACKAGE_PATHS.items():
        write_bytes(destination / relative, tool_sources[name])

    write_jsonl(
        destination / "evidence/remediation/finding_classification_ledger.jsonl",
        sorted(data.classification_rows, key=lambda row: row["id"]),
    )
    fix_rows = sorted(data.fix_group_rows, key=lambda row: row["group_id"])
    write_jsonl(destination / "evidence/remediation/fix_group_ledger_v1.jsonl", fix_rows)
    rewritten_tests = _rewrite_test_receipts(data, destination)
    write_jsonl(destination / "evidence/test/test_receipt_registry_v1.jsonl", rewritten_tests)
    receipt_index = {row["receipt_id"]: row for row in rewritten_tests}
    write_jsonl(
        destination / "evidence/remediation/finding_fix_commit_test_v1.jsonl",
        _derive_finding_map(fix_rows, receipt_index),
    )
    write_jsonl(
        destination / "evidence/remediation/local_condition_closure.jsonl",
        sorted(data.local_closure_rows, key=lambda row: row["id"]),
    )
    write_json(
        destination / "evidence/remediation/documentation_alignment_receipt.json",
        data.documentation_receipt,
    )
    if data.pre_fix_mode == LEGACY_MODE:
        if data.native_pre_fix_replays is not None:
            raise ContractError("pre-fix render: legacy/native state is ambiguous")
        write_json(
            destination / "evidence/test/pre_fix_negative_receipt.json",
            _rewrite_pre_fix_receipt(data, destination),
        )
    elif data.pre_fix_mode == NATIVE_MODE:
        _write_native_pre_fix_replays(data, destination)
    else:
        raise ContractError("pre-fix render: unsupported evidence mode")

    semantic_bytes = data.handoff_file_bytes["semantic_completion_receipt"]
    if sha256_bytes(semantic_bytes) != data.handoff_file_sha256["semantic_completion_receipt"]:
        raise ContractError("semantic completion receipt changed after source validation")
    write_bytes(destination / "evidence/validation/semantic_completion_receipt.json", semantic_bytes)
    write_jsonl(
        destination / "evidence/validation/provider_live_residuals.jsonl",
        sorted(data.residual_rows, key=lambda row: row["id"]),
    )
    matrices_bytes = data.handoff_file_bytes["required_matrices"]
    if sha256_bytes(matrices_bytes) != data.handoff_file_sha256["required_matrices"]:
        raise ContractError("required matrices changed after source validation")
    write_bytes(destination / "required_matrices.md", matrices_bytes)
    write_json(destination / "four_verdicts_v1.json", data.verdicts)
    write_json(
        destination / "receipts/candidate_identity.json",
        {
            "schema_version": 1,
            "final_commit": data.candidate_final_commit,
            "final_tree": data.candidate_final_tree,
            "worktree_clean": True,
            "cohort_final_equivalence": sorted(data.equivalence_records, key=lambda row: row["group_id"]),
        },
    )


def _validated_input_hashes(data: ValidatedInputs) -> dict[str, str]:
    hashes = {
        "baseline_manifest": data.baseline.manifest_sha256,
        "security_fix_group_map": data.group_map_sha256,
        "handoff_manifest": data.handoff_sha256,
        **{
            f"handoff:{key}": value
            for key, value in sorted(data.handoff_file_sha256.items())
        },
        **{
            f"cohort_handoff:{key}": value
            for key, value in sorted(data.cohort_handoff_sha256.items())
        },
    }
    if data.pre_fix_mode == NATIVE_MODE:
        if data.native_pre_fix_replays is None:
            raise ContractError("native replay input hashes: replay set is absent")
        hashes.update(native_input_hashes(data.native_pre_fix_replays))
    return hashes


def _scan_validated_inputs(data: ValidatedInputs) -> None:
    scan_secret_bytes(data.handoff_bytes, label="handoff manifest")
    for key, payload in sorted(data.handoff_file_bytes.items()):
        scan_secret_bytes(payload, label=f"handoff input {key}")
    for key, payload in sorted(data.cohort_handoff_bytes.items()):
        scan_secret_bytes(payload, label=f"raw cohort handoff {key}")
    for receipt_id, payload in sorted(data.test_log_bytes.items()):
        scan_secret_bytes(payload, label=f"test log {receipt_id}")
    for group_id, payload in sorted(data.pre_fix_log_bytes.items()):
        scan_secret_bytes(payload, label=f"pre-fix log {group_id}")
    if data.pre_fix_mode == NATIVE_MODE:
        replay_set = data.native_pre_fix_replays
        if replay_set is None:
            raise ContractError("native replay scan: replay set is absent")
        scan_secret_bytes(replay_set.descriptor_bytes, label="native replay descriptor")
        for key, payload in sorted(replay_set.tracked_input_bytes.items()):
            scan_secret_bytes(payload, label=f"native replay tracked input {key}")
        for replay_id, replay in sorted(replay_set.replays.items()):
            for relative, artifact in sorted(replay.artifacts.items()):
                scan_secret_bytes(
                    artifact.payload,
                    label=f"native replay {replay_id}:{relative}",
                )


def _replay_attestation(
    data: ValidatedInputs,
    *,
    semantic_receipt_sha256: str,
    core_index: dict[str, dict[str, Any]],
    tool_sources: dict[str, bytes],
) -> dict[str, Any]:
    input_hashes = _validated_input_hashes(data)
    tool_hashes = {
        name: sha256_bytes(payload)
        for name, payload in sorted(tool_sources.items())
    }
    source_snapshot = replay_source_snapshot_sha256(
        candidate_final_commit=data.candidate_final_commit,
        candidate_final_tree=data.candidate_final_tree,
        evidence_cutoff_at=data.evidence_cutoff_at,
        semantic_receipt_sha256=semantic_receipt_sha256,
        input_sha256=input_hashes,
        tool_source_sha256=tool_hashes,
    )
    return {
        "schema_version": 1,
        "pre_fix_mode": data.pre_fix_mode,
        "candidate_final_commit": data.candidate_final_commit,
        "candidate_final_tree": data.candidate_final_tree,
        "evidence_cutoff_at": data.evidence_cutoff_at,
        "semantic_receipt_sha256": semantic_receipt_sha256,
        "source_snapshot_sha256": source_snapshot,
        "core_index_sha256": sha256_bytes(canonical_json_bytes(core_index)),
        "core_entry_count": len(core_index),
        "counts": data.counts,
        "input_sha256": input_hashes,
        "tool_source_sha256": tool_hashes,
        "expected_payload_paths": sorted(
            expected_package_payload_paths(
                data.test_receipt_rows,
                data.pre_fix_receipt,
                pre_fix_mode=data.pre_fix_mode,
            )
        ),
    }


def _build_receipt(
    attestation: dict[str, Any],
    replay_receipts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "tool": "ultra-postfix-evidence-builder",
        "candidate_final_commit": attestation["candidate_final_commit"],
        "candidate_final_tree": attestation["candidate_final_tree"],
        "evidence_cutoff_at": attestation["evidence_cutoff_at"],
        "semantic_receipt_sha256": attestation[
            "semantic_receipt_sha256"
        ],
        "source_snapshot_sha256": attestation[
            "source_snapshot_sha256"
        ],
        "core_index_sha256": attestation["core_index_sha256"],
        "counts": attestation["counts"],
        "input_sha256": attestation["input_sha256"],
        "tool_source_sha256": attestation["tool_source_sha256"],
        "validated_replay_ids": sorted(replay_receipts),
        "replay_receipt_sha256": {
            replay_id: sha256_bytes(canonical_json_bytes(receipt, pretty=True))
            for replay_id, receipt in sorted(replay_receipts.items())
        },
    }


def _subprocess_environment() -> dict[str, str]:
    return {
        "HOME": "/var/empty" if Path("/var/empty").is_dir() else os.sep,
        "LC_ALL": "C",
        "PATH": os.defpath,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
    }


def _run_json_process(command: list[str], *, label: str) -> dict[str, Any]:
    completed = run_process_bounded(
        command,
        label=label,
        cwd=Path(__file__).parents[2],
        env=_subprocess_environment(),
        timeout=1200,
        max_stdout_bytes=WORKER_STDOUT_MAX_BYTES,
        max_stderr_bytes=WORKER_STDERR_MAX_BYTES,
        max_total_output_bytes=WORKER_OUTPUT_TOTAL_MAX_BYTES,
        max_stdin_bytes=WORKER_STDIN_MAX_BYTES,
    )
    try:
        value = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        if completed.returncode != 0:
            raise ContractError(f"{label}: isolated process failed") from error
        raise ContractError(f"{label}: isolated process returned invalid JSON") from error
    if completed.returncode != 0:
        if (
            isinstance(value, dict)
            and value.get("ok") is False
            and isinstance(value.get("error"), str)
            and 0 < len(value["error"]) <= 4096
            and "\x00" not in value["error"]
        ):
            raise ContractError(f"{label}: {value['error']}")
        raise ContractError(f"{label}: isolated process failed")
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise ContractError(f"{label}: isolated process did not attest success")
    value = dict(value)
    del value["ok"]
    return value


def _run_replay_worker(
    replay_id: str,
    destination: Path,
    *,
    baseline: Path,
    group_map: Path,
    handoff: Path,
    candidate_repo: Path,
    semantic_receipt_sha256: str,
) -> dict[str, Any]:
    return _run_json_process(
        [
            sys.executable,
            "-m",
            "scripts.postfix_evidence.render_postfix_replay",
            "--baseline",
            os.fspath(baseline),
            "--group-map",
            os.fspath(group_map),
            "--handoff",
            os.fspath(handoff),
            "--candidate-repo",
            os.fspath(candidate_repo),
            "--destination",
            os.fspath(destination),
            "--semantic-receipt-sha256",
            semantic_receipt_sha256,
        ],
        label=f"replay {replay_id} render",
    )


def _run_package_validator(
    replay_id: str,
    package: Path,
    *,
    baseline: Path,
    group_map: Path,
    candidate_repo: Path,
    semantic_receipt_sha256: str,
) -> dict[str, Any]:
    return {
        "ok": True,
        **_run_json_process(
            [
                sys.executable,
                "-m",
                "scripts.postfix_evidence.validate_postfix_package",
                "--package",
                os.fspath(package),
                "--baseline",
                os.fspath(baseline),
                "--group-map",
                os.fspath(group_map),
                "--candidate-repo",
                os.fspath(candidate_repo),
                "--semantic-receipt-sha256",
                semantic_receipt_sha256,
            ],
            label=f"replay {replay_id} package validation",
        ),
    }


@dataclass(frozen=True)
class _OutputParentReservation:
    requested_path: Path
    canonical_path: Path
    fd: int
    device: int
    inode: int
    owner_uid: int
    mode: int


def _open_output_parent(path: Path) -> _OutputParentReservation:
    requested = Path(os.path.abspath(path))
    try:
        canonical = requested.resolve(strict=True)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        parent_fd = os.open(canonical, flags)
        info = os.fstat(parent_fd)
    except OSError as error:
        raise ContractError("output: parent directory is unavailable") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o022
    ):
        os.close(parent_fd)
        raise ContractError(
            "output: parent must be an owner-controlled non-writable directory"
        )
    return _OutputParentReservation(
        requested_path=requested,
        canonical_path=canonical,
        fd=parent_fd,
        device=info.st_dev,
        inode=info.st_ino,
        owner_uid=info.st_uid,
        mode=stat.S_IMODE(info.st_mode),
    )


def _verify_output_parent(
    reservation: _OutputParentReservation,
    *,
    destination_name: str,
    candidate_root: Path,
    baseline_root: Path,
) -> None:
    try:
        current = reservation.requested_path.resolve(strict=True)
        path_info = os.stat(current, follow_symlinks=False)
        fd_info = os.fstat(reservation.fd)
    except OSError as error:
        raise ContractError("output: parent identity changed during build") from error
    expected_identity = (
        reservation.device,
        reservation.inode,
        reservation.owner_uid,
        reservation.mode,
    )
    path_identity = (
        path_info.st_dev,
        path_info.st_ino,
        path_info.st_uid,
        stat.S_IMODE(path_info.st_mode),
    )
    fd_identity = (
        fd_info.st_dev,
        fd_info.st_ino,
        fd_info.st_uid,
        stat.S_IMODE(fd_info.st_mode),
    )
    if (
        current != reservation.canonical_path
        or path_identity != expected_identity
        or fd_identity != expected_identity
        or not stat.S_ISDIR(path_info.st_mode)
        or not stat.S_ISDIR(fd_info.st_mode)
    ):
        raise ContractError("output: parent identity changed during build")
    destination = current / destination_name
    for forbidden_root, label in (
        (candidate_root, "candidate repository"),
        (baseline_root, "authoritative baseline"),
    ):
        try:
            destination.relative_to(forbidden_root)
        except ValueError:
            pass
        else:
            raise ContractError(
                f"output: publication boundary moved inside the {label}"
            )


def _create_temporary_directory_at(
    reservation: _OutputParentReservation,
    *,
    prefix: str,
) -> tuple[str, Path]:
    for _ in range(128):
        name = f"{prefix}{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=reservation.fd)
        except FileExistsError:
            continue
        except OSError as error:
            raise ContractError("output: unable to create replay directory") from error
        return name, reservation.canonical_path / name
    raise ContractError("output: unable to reserve a unique replay directory")


def _remove_tree_at(
    parent_fd: int,
    name: str,
    *,
    _entry_count: list[int] | None = None,
    _depth: int = 0,
) -> None:
    if (
        not isinstance(name, str)
        or name in {"", ".", ".."}
        or "/" in name
        or "\x00" in name
        or _depth > CLEANUP_MAX_DEPTH
    ):
        raise ContractError("output: unsafe cleanup boundary")
    entry_count = [0] if _entry_count is None else _entry_count
    try:
        child_fd = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        return
    except OSError as error:
        if error.errno not in {errno.ELOOP, errno.ENOTDIR}:
            raise ContractError("output: cleanup entry could not be opened") from error
        try:
            os.unlink(name, dir_fd=parent_fd)
        except FileNotFoundError:
            return
        except OSError as unlink_error:
            raise ContractError(
                "output: non-directory cleanup entry could not be removed"
            ) from unlink_error
        return
    try:
        try:
            iterator = os.scandir(child_fd)
        except OSError as error:
            raise ContractError("output: cleanup directory could not be enumerated") from error
        with iterator:
            for entry in iterator:
                entry_count[0] += 1
                if entry_count[0] > CLEANUP_MAX_ENTRIES:
                    raise ContractError("output: cleanup entry limit exceeded")
                _remove_tree_at(
                    child_fd,
                    entry.name,
                    _entry_count=entry_count,
                    _depth=_depth + 1,
                )
    finally:
        os.close(child_fd)
    try:
        os.rmdir(name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise ContractError("output: cleanup directory could not be removed") from error


def _atomic_publish_directory_no_replace(
    parent_fd: int,
    source_name: str,
    destination_name: str,
) -> None:
    """Atomically publish one sibling directory without replacing a target."""
    libc = ctypes.CDLL(None, use_errno=True)
    old_path = os.fsencode(source_name)
    new_path = os.fsencode(destination_name)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        rename_no_replace = libc.renameatx_np
        rename_no_replace.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename_no_replace.restype = ctypes.c_int
        result = rename_no_replace(
            parent_fd,
            old_path,
            parent_fd,
            new_path,
            0x00000004,
        )
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        rename_no_replace = libc.renameat2
        rename_no_replace.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename_no_replace.restype = ctypes.c_int
        result = rename_no_replace(
            parent_fd,
            old_path,
            parent_fd,
            new_path,
            0x00000001,
        )
    else:
        raise ContractError(
            "output: atomic no-replace publication is unsupported"
        )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ContractError("output: destination appeared during build")
    raise ContractError(
        f"output: atomic no-replace publication failed (errno={error_number})"
    )


def build_package(
    *,
    baseline: Path,
    group_map: Path,
    handoff: Path,
    candidate_repo: Path,
    output: Path,
    semantic_receipt_sha256: str,
) -> dict[str, Any]:
    if output.exists() or output.is_symlink():
        raise ContractError("output: destination already exists; overwrite is forbidden")
    try:
        candidate_root = candidate_repo.resolve(strict=True)
        baseline_root = baseline.resolve(strict=True)
        output_absolute = output.resolve(strict=False)
        output_absolute.relative_to(candidate_root)
    except ValueError:
        pass
    except OSError as error:
        raise ContractError("output: candidate or baseline trust root is unavailable") from error
    else:
        raise ContractError("output: package must be external to the candidate repository")
    try:
        output_absolute.relative_to(baseline_root)
    except ValueError:
        pass
    else:
        raise ContractError("output: package must not be created inside the authoritative baseline")
    output.parent.mkdir(parents=True, exist_ok=True)
    reservation = _open_output_parent(output.parent)
    replay_a_name = ""
    replay_b_name = ""
    published = False
    try:
        _verify_output_parent(
            reservation,
            destination_name=output.name,
            candidate_root=candidate_root,
            baseline_root=baseline_root,
        )
        replay_a_name, replay_a = _create_temporary_directory_at(
            reservation,
            prefix=".postfix-replay-a-",
        )
        replay_b_name, replay_b = _create_temporary_directory_at(
            reservation,
            prefix=".postfix-replay-b-",
        )
        _verify_output_parent(
            reservation,
            destination_name=output.name,
            candidate_root=candidate_root,
            baseline_root=baseline_root,
        )
        attestation_a = _run_replay_worker(
            "A",
            replay_a,
            baseline=baseline,
            group_map=group_map,
            handoff=handoff,
            candidate_repo=candidate_repo,
            semantic_receipt_sha256=semantic_receipt_sha256,
        )
        attestation_b = _run_replay_worker(
            "B",
            replay_b,
            baseline=baseline,
            group_map=group_map,
            handoff=handoff,
            candidate_repo=candidate_repo,
            semantic_receipt_sha256=semantic_receipt_sha256,
        )
        if attestation_a != attestation_b:
            raise ContractError(
                "replay: fresh-process source/core attestations differ"
            )
        pre_fix_mode = attestation_a["pre_fix_mode"]
        if pre_fix_mode not in {LEGACY_MODE, NATIVE_MODE}:
            raise ContractError("replay: unsupported pre-fix evidence mode")
        index_a = _package_tree_index(replay_a, pre_fix_mode)
        index_b = _package_tree_index(replay_b, pre_fix_mode)
        core_hash = sha256_bytes(canonical_json_bytes(index_a))
        if (
            index_a != index_b
            or core_hash != attestation_a["core_index_sha256"]
            or len(index_a) != attestation_a["core_entry_count"]
        ):
            raise ContractError("replay: independent core builds are not byte-identical")
        replay_receipts = {
            replay_id: {
                "schema_version": 1,
                "replay_id": replay_id,
                "execution_model": "fresh-process",
                "fresh_source_validation": True,
                "fresh_core_render": True,
                "package_validation_required_before_publish": True,
                "candidate_final_commit": attestation_a[
                    "candidate_final_commit"
                ],
                "candidate_final_tree": attestation_a[
                    "candidate_final_tree"
                ],
                "source_snapshot_sha256": attestation_a[
                    "source_snapshot_sha256"
                ],
                "core_index_sha256": core_hash,
                "core_entry_count": len(index_a),
            }
            for replay_id in sorted(REPLAY_RECEIPT_PATHS)
        }
        build_receipt = _build_receipt(
            attestation_a,
            replay_receipts,
        )
        for replay in (replay_a, replay_b):
            for replay_id, relative in REPLAY_RECEIPT_PATHS.items():
                write_json(replay / relative, replay_receipts[replay_id])
            write_json(replay / "receipts/build_receipt.json", build_receipt)
            actual_paths = set(_package_tree_index(replay, pre_fix_mode))
            expected_paths = set(attestation_a["expected_payload_paths"])
            if actual_paths != expected_paths:
                raise ContractError("package allowlist: builder produced missing or extra files")
            _write_package_manifest(replay, pre_fix_mode)
        validation_a = _run_package_validator(
            "A",
            replay_a,
            baseline=baseline,
            group_map=group_map,
            candidate_repo=candidate_repo,
            semantic_receipt_sha256=semantic_receipt_sha256,
        )
        validation_b = _run_package_validator(
            "B",
            replay_b,
            baseline=baseline,
            group_map=group_map,
            candidate_repo=candidate_repo,
            semantic_receipt_sha256=semantic_receipt_sha256,
        )
        if validation_a != validation_b:
            raise ContractError(
                "replay: independent package validation results differ"
            )
        if _package_tree_index(replay_a, pre_fix_mode) != _package_tree_index(
            replay_b, pre_fix_mode
        ):
            raise ContractError("replay: complete package builds are not byte-identical")
        revalidate_candidate_final_state(
            candidate_repo,
            expected_commit=attestation_a["candidate_final_commit"],
            expected_tree=attestation_a["candidate_final_tree"],
            expected_tool_source_sha256=attestation_a[
                "tool_source_sha256"
            ],
        )
        _verify_output_parent(
            reservation,
            destination_name=output.name,
            candidate_root=candidate_root,
            baseline_root=baseline_root,
        )
        _atomic_publish_directory_no_replace(
            reservation.fd,
            replay_a_name,
            output.name,
        )
        published = True
        try:
            _verify_output_parent(
                reservation,
                destination_name=output.name,
                candidate_root=candidate_root,
                baseline_root=baseline_root,
            )
            revalidate_candidate_final_state(
                candidate_repo,
                expected_commit=attestation_a["candidate_final_commit"],
                expected_tree=attestation_a["candidate_final_tree"],
                expected_tool_source_sha256=attestation_a[
                    "tool_source_sha256"
                ],
            )
        except ContractError:
            _remove_tree_at(reservation.fd, output.name)
            raise
        return validation_a
    finally:
        cleanup_error: ContractError | None = None
        for replay_name in (replay_a_name, replay_b_name):
            if not replay_name:
                continue
            try:
                _remove_tree_at(reservation.fd, replay_name)
            except ContractError as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None and published:
            try:
                _remove_tree_at(reservation.fd, output.name)
            except ContractError as error:
                cleanup_error = error
        os.close(reservation.fd)
        if cleanup_error is not None:
            raise cleanup_error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--group-map", type=Path, required=True)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--candidate-repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--semantic-receipt-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        result = build_package(
            baseline=arguments.baseline,
            group_map=arguments.group_map,
            handoff=arguments.handoff,
            candidate_repo=arguments.candidate_repo,
            output=arguments.output,
            semantic_receipt_sha256=arguments.semantic_receipt_sha256,
        )
    except ContractError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
