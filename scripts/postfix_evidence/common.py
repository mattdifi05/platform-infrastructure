"""Shared primitives for deterministic, fail-closed post-fix evidence tooling."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
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


def _directory_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise ContractError("file snapshot: O_NOFOLLOW/O_DIRECTORY are unavailable")
    return os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)


def _file_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ContractError("file snapshot: O_NOFOLLOW is unavailable")
    return os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)


def _open_canonical_directory(path: Path, *, label: str) -> int:
    """Open a directory by walking its canonical absolute path with no symlinks."""
    try:
        canonical = path.resolve(strict=True)
    except OSError as error:
        raise ContractError(f"{label}: trust directory is unavailable") from error
    if not canonical.is_absolute():
        raise ContractError(f"{label}: trust directory is not absolute")
    try:
        current = os.open(os.sep, _directory_flags())
        for part in canonical.parts[1:]:
            next_fd = os.open(part, _directory_flags(), dir_fd=current)
            os.close(current)
            current = next_fd
        info = os.fstat(current)
        if not stat.S_ISDIR(info.st_mode):
            raise ContractError(f"{label}: trust root is not a directory")
        return current
    except ContractError:
        try:
            os.close(current)
        except (OSError, UnboundLocalError):
            pass
        raise
    except OSError as error:
        try:
            os.close(current)
        except (OSError, UnboundLocalError):
            pass
        raise ContractError(f"{label}: trust directory could not be opened safely") from error


def _read_fd(fd: int, *, label: str) -> bytes:
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError(f"{label}: required path is not a regular non-symlink file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(fd)
    except ContractError:
        raise
    except OSError as error:
        raise ContractError(f"{label}: required file could not be read") from error
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    payload = b"".join(chunks)
    if identity_before != identity_after or len(payload) != before.st_size:
        raise ContractError(f"{label}: file changed while it was read")
    return payload


def read_regular_under(root: Path, relative: Any, *, label: str) -> bytes:
    """Read one file under a trust root via dirfd traversal and one stable FD."""
    pure = safe_relative(relative, label=label)
    root_fd = _open_canonical_directory(root, label=label)
    current = root_fd
    try:
        for part in pure.parts[:-1]:
            next_fd = os.open(part, _directory_flags(), dir_fd=current)
            if current != root_fd:
                os.close(current)
            current = next_fd
        file_fd = os.open(pure.parts[-1], _file_flags(), dir_fd=current)
        try:
            return _read_fd(file_fd, label=label)
        finally:
            os.close(file_fd)
    except ContractError:
        raise
    except OSError as error:
        raise ContractError(f"{label}: required file is unavailable or unsafe") from error
    finally:
        if current != root_fd:
            os.close(current)
        os.close(root_fd)


def read_regular_bytes(path: Path, *, label: str) -> bytes:
    if path.name in {"", ".", ".."}:
        raise ContractError(f"{label}: required file path is invalid")
    return read_regular_under(path.parent, path.name, label=label)


def load_json_bytes(payload: bytes, *, label: str) -> Any:
    return strict_json_bytes(payload, label=label)


def load_json(path: Path, *, label: str) -> Any:
    return load_json_bytes(read_regular_bytes(path, label=label), label=label)


def load_jsonl_bytes(payload: bytes, *, label: str) -> list[dict[str, Any]]:
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


def load_jsonl(path: Path, *, label: str) -> list[dict[str, Any]]:
    return load_jsonl_bytes(read_regular_bytes(path, label=label), label=label)


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


@dataclass(frozen=True)
class ManifestSnapshot:
    rows: dict[str, str]
    files: dict[str, bytes]
    manifest_bytes: bytes


def validate_manifest_snapshot(
    root: Path,
    *,
    exact: bool,
    required: Iterable[str] = (),
) -> ManifestSnapshot:
    payload = read_regular_under(root, "MANIFEST.sha256", label="manifest")
    rows: dict[str, str] = {}
    files: dict[str, bytes] = {}
    for line_number, raw in enumerate(payload.decode("utf-8").splitlines(), start=1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00]+)", raw)
        if match is None:
            raise ContractError(f"manifest: malformed row {line_number}")
        digest, relative_text = match.groups()
        pure = safe_relative(relative_text, label=f"manifest:{line_number}")
        relative = pure.as_posix()
        if relative == "MANIFEST.sha256" or relative in rows:
            raise ContractError(f"manifest: duplicate or self-referential row {line_number}")
        file_payload = read_regular_under(root, relative, label=f"manifest:{relative}")
        if sha256_bytes(file_payload) != digest:
            raise ContractError(f"manifest: hash mismatch for {relative}")
        rows[relative] = digest
        files[relative] = file_payload
    required_set = set(required)
    if not required_set.issubset(rows):
        raise ContractError(f"manifest: required entries missing: {sorted(required_set - set(rows))}")
    if exact:
        actual = set(tree_index(root, exclude={"MANIFEST.sha256"}))
        if set(rows) != actual:
            raise ContractError("manifest: file set is not exact")
    return ManifestSnapshot(rows=rows, files=files, manifest_bytes=payload)


def validate_manifest(root: Path, *, exact: bool, required: Iterable[str] = ()) -> dict[str, str]:
    return validate_manifest_snapshot(root, exact=exact, required=required).rows


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


def commit_delta_records(repo: Path, commit: str) -> list[dict[str, Any]]:
    parent = git_text(repo, "rev-parse", f"{commit}^")
    raw = git(
        repo,
        "diff-tree",
        "--no-commit-id",
        "-r",
        "--no-renames",
        "--raw",
        "-z",
        parent,
        commit,
    )
    if not raw:
        raise ContractError("commit equivalence: empty tree delta")
    fields = raw.split(b"\x00")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 2 != 0:
        raise ContractError("commit equivalence: malformed raw tree delta")
    records: list[dict[str, Any]] = []
    header_re = re.compile(
        rb"^:([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([A-Z])$"
    )
    zero = "0" * 40
    for index in range(0, len(fields), 2):
        match = header_re.fullmatch(fields[index])
        if match is None:
            raise ContractError("commit equivalence: unsupported tree delta record")
        try:
            path = fields[index + 1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ContractError("commit equivalence: non-UTF-8 changed path") from error
        safe_relative(path, label="commit equivalence changed path")
        old_mode, new_mode, old_object, new_object, status = (
            value.decode("ascii") for value in match.groups()
        )

        def content_hash(object_id: str, mode: str) -> str | None:
            if object_id == zero:
                return None
            if mode == "160000":
                return sha256_bytes(object_id.encode("ascii"))
            return sha256_bytes(git(repo, "cat-file", "blob", object_id))

        records.append(
            {
                "path": path,
                "status": status,
                "old_mode": old_mode,
                "new_mode": new_mode,
                "old_object": None if old_object == zero else old_object,
                "new_object": None if new_object == zero else new_object,
                "old_content_sha256": content_hash(old_object, old_mode),
                "new_content_sha256": content_hash(new_object, new_mode),
            }
        )
    return sorted(records, key=lambda row: row["path"])


def commit_equivalence(repo: Path, cohort: str, final: str) -> dict[str, Any]:
    if cohort == final:
        raise ContractError("commit equivalence: cohort-only SHA is not a final integration mapping")
    cohort_delta = commit_delta_records(repo, cohort)
    final_delta = commit_delta_records(repo, final)
    if cohort_delta != final_delta:
        raise ContractError(
            "commit equivalence: cohort and final commits differ in exact tree delta path/mode/content"
        )
    return {
        "cohort_commit": cohort,
        "final_commit": final,
        "tree_delta_sha256": sha256_bytes(canonical_json_bytes(cohort_delta)),
        "changed_paths": [row["path"] for row in cohort_delta],
        "accepted_by": "exact-tree-delta-path-mode-content",
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
