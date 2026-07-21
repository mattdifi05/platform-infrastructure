"""Shared primitives for deterministic, fail-closed post-fix evidence tooling."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_SECOND_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class ContractError(RuntimeError):
    """Raised when an input or output violates the evidence contract."""


class _DuplicateKey(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value}")


def strict_json_bytes(payload: bytes, *, label: str) -> Any:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ContractError(f"{label}: input is not UTF-8") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, _DuplicateKey, ValueError) as error:
        raise ContractError(f"{label}: malformed or duplicate-key JSON") from error


def read_regular_bytes(path: Path, *, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise ContractError(f"{label}: required file is unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ContractError(f"{label}: required path is not a regular non-symlink file")
    try:
        payload = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise ContractError(f"{label}: required file could not be read") from error
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after:
        raise ContractError(f"{label}: file changed while it was read")
    return payload


def load_json(path: Path, *, label: str) -> Any:
    return strict_json_bytes(read_regular_bytes(path, label=label), label=label)


def load_jsonl(path: Path, *, label: str) -> list[dict[str, Any]]:
    payload = read_regular_bytes(path, label=label)
    rows: list[dict[str, Any]] = []
    for line_number, raw in enumerate(payload.splitlines(), start=1):
        if not raw.strip():
            raise ContractError(f"{label}: blank JSONL line {line_number}")
        value = strict_json_bytes(raw, label=f"{label}:{line_number}")
        if not isinstance(value, dict):
            raise ContractError(f"{label}:{line_number}: JSONL row is not an object")
        rows.append(value)
    if not rows:
        raise ContractError(f"{label}: JSONL file is empty")
    return rows


def canonical_json_bytes(value: Any, *, pretty: bool = False) -> bytes:
    options: dict[str, Any] = {
        "sort_keys": True,
        "ensure_ascii": False,
        "allow_nan": False,
    }
    if pretty:
        options["indent"] = 2
    else:
        options["separators"] = (",", ":")
    return (json.dumps(value, **options) + "\n").encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path, *, label: str | None = None) -> str:
    return sha256_bytes(read_regular_bytes(path, label=label or path.name))


def exact_keys(value: Any, expected: Iterable[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label}: expected an object")
    expected_set = set(expected)
    actual = set(value)
    if actual != expected_set:
        missing = sorted(expected_set - actual)
        extra = sorted(actual - expected_set)
        raise ContractError(f"{label}: wrong keys (missing={missing}, extra={extra})")
    return value


def nonempty_string(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{label}: expected a nonempty string")
    return value


def string_list(value: Any, *, label: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ContractError(f"{label}: expected {'a' if allow_empty else 'a nonempty'} string list")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ContractError(f"{label}: expected strings only")
    if len(set(value)) != len(value):
        raise ContractError(f"{label}: duplicate list value")
    return list(value)


def safe_relative(value: Any, *, label: str) -> PurePosixPath:
    text = nonempty_string(value, label=label)
    if "\\" in text or "\x00" in text:
        raise ContractError(f"{label}: unsafe relative path")
    pure = PurePosixPath(text)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ContractError(f"{label}: unsafe relative path")
    return pure


def resolve_regular(root: Path, relative: Any, *, label: str) -> Path:
    pure = safe_relative(relative, label=label)
    try:
        root_resolved = root.resolve(strict=True)
        target = (root / Path(*pure.parts)).resolve(strict=True)
        target.relative_to(root_resolved)
    except (OSError, ValueError) as error:
        raise ContractError(f"{label}: path escapes its trust root or is unavailable") from error
    cursor = root_resolved
    for part in pure.parts:
        cursor = cursor / part
        try:
            mode = cursor.lstat().st_mode
        except OSError as error:
            raise ContractError(f"{label}: path is unavailable") from error
        if stat.S_ISLNK(mode):
            raise ContractError(f"{label}: symlinks are not accepted")
    read_regular_bytes(target, label=label)
    return target


def write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o644)


def write_json(path: Path, value: Any, *, pretty: bool = True) -> None:
    write_bytes(path, canonical_json_bytes(value, pretty=pretty))


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    write_bytes(path, b"".join(canonical_json_bytes(row) for row in rows))


def tree_index(root: Path, *, exclude: Iterable[str] = ()) -> dict[str, dict[str, Any]]:
    excluded = set(exclude)
    result: dict[str, dict[str, Any]] = {}
    try:
        entries = sorted(root.rglob("*"))
    except OSError as error:
        raise ContractError("package: unable to enumerate tree") from error
    for path in entries:
        relative = path.relative_to(root).as_posix()
        try:
            info = path.lstat()
        except OSError as error:
            raise ContractError(f"package: unable to inspect {relative}") from error
        if stat.S_ISLNK(info.st_mode):
            raise ContractError(f"package: symlink is forbidden at {relative}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ContractError(f"package: non-regular entry is forbidden at {relative}")
        if relative in excluded:
            continue
        result[relative] = {
            "sha256": sha256_file(path, label=f"package:{relative}"),
            "size": info.st_size,
        }
    return result


def write_manifest(root: Path) -> None:
    index = tree_index(root, exclude={"MANIFEST.sha256"})
    payload = "".join(f"{row['sha256']}  {relative}\n" for relative, row in sorted(index.items()))
    write_bytes(root / "MANIFEST.sha256", payload.encode("utf-8"))


def validate_manifest(root: Path, *, exact: bool, required: Iterable[str] = ()) -> dict[str, str]:
    manifest_path = root / "MANIFEST.sha256"
    payload = read_regular_bytes(manifest_path, label="manifest")
    rows: dict[str, str] = {}
    for line_number, raw in enumerate(payload.decode("utf-8").splitlines(), start=1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00]+)", raw)
        if match is None:
            raise ContractError(f"manifest: malformed row {line_number}")
        digest, relative_text = match.groups()
        pure = safe_relative(relative_text, label=f"manifest:{line_number}")
        relative = pure.as_posix()
        if relative == "MANIFEST.sha256" or relative in rows:
            raise ContractError(f"manifest: duplicate or self-referential row {line_number}")
        target = resolve_regular(root, relative, label=f"manifest:{relative}")
        if sha256_file(target, label=f"manifest:{relative}") != digest:
            raise ContractError(f"manifest: hash mismatch for {relative}")
        rows[relative] = digest
    required_set = set(required)
    if not required_set.issubset(rows):
        raise ContractError(f"manifest: required entries missing: {sorted(required_set - set(rows))}")
    if exact:
        actual = set(tree_index(root, exclude={"MANIFEST.sha256"}))
        if set(rows) != actual:
            raise ContractError("manifest: file set is not exact")
    return rows


def git(repo: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(repo), *arguments],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise ContractError("git: executable or repository unavailable") from error
    if completed.returncode != 0:
        raise ContractError(f"git: command failed ({arguments[0] if arguments else 'unknown'})")
    return completed.stdout


def git_text(repo: Path, *arguments: str) -> str:
    try:
        return git(repo, *arguments).decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ContractError("git: non-UTF-8 output") from error


def resolve_commit(repo: Path, value: Any, *, label: str) -> str:
    commit = nonempty_string(value, label=label)
    if SHA1_RE.fullmatch(commit) is None:
        raise ContractError(f"{label}: expected a full lower-case SHA-1")
    resolved = git_text(repo, "rev-parse", "--verify", f"{commit}^{{commit}}")
    if resolved != commit:
        raise ContractError(f"{label}: commit does not resolve exactly")
    return commit


def git_head(repo: Path) -> str:
    return resolve_commit(repo, git_text(repo, "rev-parse", "HEAD"), label="candidate HEAD")


def git_tree(repo: Path, commit: str) -> str:
    value = git_text(repo, "rev-parse", f"{commit}^{{tree}}")
    if SHA1_RE.fullmatch(value) is None:
        raise ContractError("git: invalid tree identity")
    return value


def ensure_ancestor(repo: Path, ancestor: str, descendant: str, *, label: str) -> None:
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(repo), "merge-base", "--is-ancestor", ancestor, descendant],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        raise ContractError(f"{label}: unable to check reachability") from error
    if completed.returncode != 0:
        raise ContractError(f"{label}: commit is not reachable from final HEAD")


def stable_patch_id(repo: Path, commit: str) -> str:
    patch = git(repo, "show", "--pretty=format:", "--binary", "--no-ext-diff", commit)
    if not patch.strip():
        raise ContractError("commit equivalence: empty commits are not accepted")
    try:
        completed = subprocess.run(
            ["git", "patch-id", "--stable"],
            input=patch,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise ContractError("commit equivalence: git patch-id unavailable") from error
    if completed.returncode != 0:
        raise ContractError("commit equivalence: patch-id failed")
    fields = completed.stdout.decode("ascii", "strict").split()
    if not fields or SHA1_RE.fullmatch(fields[0]) is None:
        raise ContractError("commit equivalence: invalid patch-id")
    return fields[0]


def tree_delta_sha256(repo: Path, commit: str) -> str:
    parent = git_text(repo, "rev-parse", f"{commit}^")
    delta = git(repo, "diff-tree", "--no-commit-id", "-r", "--raw", "-z", parent, commit)
    if not delta:
        raise ContractError("commit equivalence: empty tree delta")
    return sha256_bytes(delta)


def commit_equivalence(repo: Path, cohort: str, final: str) -> dict[str, Any]:
    if cohort == final:
        raise ContractError("commit equivalence: cohort-only SHA is not a final integration mapping")
    cohort_patch = stable_patch_id(repo, cohort)
    final_patch = stable_patch_id(repo, final)
    cohort_delta = tree_delta_sha256(repo, cohort)
    final_delta = tree_delta_sha256(repo, final)
    patch_equal = cohort_patch == final_patch
    delta_equal = cohort_delta == final_delta
    if not patch_equal and not delta_equal:
        raise ContractError("commit equivalence: cohort and final commits are not patch-equivalent")
    return {
        "cohort_commit": cohort,
        "final_commit": final,
        "cohort_patch_id": cohort_patch,
        "final_patch_id": final_patch,
        "cohort_tree_delta_sha256": cohort_delta,
        "final_tree_delta_sha256": final_delta,
        "accepted_by": "stable-patch-id" if patch_equal else "exact-tree-delta",
    }


def evidence_repo_path(value: str) -> str:
    path = value.split("#", 1)[0]
    path = re.sub(r":(?:[0-9]+)(?:[-,][0-9]+)*$", "", path)
    return safe_relative(path, label="candidate evidence path").as_posix()


def ensure_path_at_commit(repo: Path, commit: str, evidence: str) -> None:
    relative = evidence_repo_path(evidence)
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(repo), "cat-file", "-e", f"{commit}:{relative}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        raise ContractError("candidate evidence: unable to inspect Git object") from error
    if completed.returncode != 0:
        raise ContractError(f"candidate evidence: path is absent at final commit: {relative}")
