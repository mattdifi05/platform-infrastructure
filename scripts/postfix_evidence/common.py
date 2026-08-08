"""Shared primitives for deterministic, fail-closed post-fix evidence tooling."""

from __future__ import annotations

import contextvars
import errno
import functools
import hashlib
import io
import json
import os
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_SECOND_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
GIT_STDOUT_MAX_BYTES = 32 * 1024 * 1024
GIT_STDERR_MAX_BYTES = 1 * 1024 * 1024
GIT_OUTPUT_TOTAL_MAX_BYTES = GIT_STDOUT_MAX_BYTES + GIT_STDERR_MAX_BYTES
GIT_STDIN_MAX_BYTES = 32 * 1024 * 1024
GIT_BLOB_MAX_BYTES = 16 * 1024 * 1024
TREE_MAX_ENTRIES = 10_000
TREE_MAX_RELATIVE_PATH_BYTES = 4096
TREE_MAX_DEPTH = 128
MANIFEST_MAX_ENTRIES = 10_000
SUBPROCESS_COMMAND_MAX_BYTES = 256 * 1024

_PROCESS_SUPERVISOR_SOURCE = r"""
import json
import os
import signal
import struct
import subprocess
import sys

control_fd = int(sys.argv[1])
command = json.loads(sys.argv[2])
try:
    child = subprocess.Popen(
        command,
        stdin=0,
        stdout=1,
        stderr=2,
        close_fds=True,
    )
    returncode = child.wait()
except BaseException:
    returncode = 127
for descriptor in (0, 1, 2):
    try:
        os.close(descriptor)
    except OSError:
        pass
os.write(control_fd, struct.pack("!i", returncode))
os.close(control_fd)
while True:
    signal.pause()
"""


class ContractError(RuntimeError):
    """Raised when an input or output violates the evidence contract."""


_IMMUTABLE_GIT_OBJECTISH_RE = re.compile(
    r"^[0-9a-f]{40}(?:(?:\^|\^\{(?:commit|tree)\})|(?::[^\x00\n]+))?$"
)
_IMMUTABLE_GIT_QUERY_CACHE: contextvars.ContextVar[
    dict[tuple[Any, ...], tuple[int, bytes, bytes]] | None
] = contextvars.ContextVar("postfix_immutable_git_query_cache", default=None)


def _is_immutable_git_query(arguments: tuple[str, ...]) -> bool:
    """Return whether one Git query is fully addressed by immutable object IDs."""
    if not arguments:
        return False
    command = arguments[0]
    if command == "cat-file" and len(arguments) == 3:
        return (
            arguments[1] in {"-s", "-e", "blob"}
            and _IMMUTABLE_GIT_OBJECTISH_RE.fullmatch(arguments[2]) is not None
        )
    if command == "rev-parse":
        operands = arguments[1:]
        if operands[:1] == ("--verify",):
            operands = operands[1:]
        return (
            len(operands) == 1
            and _IMMUTABLE_GIT_OBJECTISH_RE.fullmatch(operands[0]) is not None
        )
    if command == "merge-base" and arguments[1:2] == ("--is-ancestor",):
        return (
            len(arguments) == 4
            and SHA1_RE.fullmatch(arguments[2]) is not None
            and SHA1_RE.fullmatch(arguments[3]) is not None
        )
    if command == "diff-tree" and len(arguments) >= 3:
        return (
            SHA1_RE.fullmatch(arguments[-2]) is not None
            and SHA1_RE.fullmatch(arguments[-1]) is not None
        )
    if command == "ls-tree" and len(arguments) >= 2:
        return SHA1_RE.fullmatch(arguments[1]) is not None
    return False


def with_immutable_git_query_cache(function: Any) -> Any:
    """Deduplicate immutable Git object queries for one validation boundary."""
    @functools.wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if _IMMUTABLE_GIT_QUERY_CACHE.get() is not None:
            return function(*args, **kwargs)
        token = _IMMUTABLE_GIT_QUERY_CACHE.set({})
        try:
            return function(*args, **kwargs)
        finally:
            _IMMUTABLE_GIT_QUERY_CACHE.reset(token)

    return wrapped


@dataclass
class ByteBudget:
    label: str
    max_bytes: int
    consumed_bytes: int = 0

    def reserve(self, size: int) -> None:
        if (
            type(size) is not int
            or size < 0
            or type(self.max_bytes) is not int
            or self.max_bytes <= 0
            or self.consumed_bytes + size > self.max_bytes
        ):
            raise ContractError(f"{self.label}: cumulative byte budget exceeded")
        self.consumed_bytes += size


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


def _read_fd(
    fd: int,
    *,
    label: str,
    max_bytes: int,
    budget: ByteBudget | None = None,
) -> bytes:
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ContractError(f"{label}: invalid byte limit")
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError(f"{label}: required path is not a regular non-symlink file")
        if before.st_size > max_bytes:
            raise ContractError(f"{label}: file exceeds the byte limit")
        if budget is not None:
            budget.reserve(before.st_size)
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, max_bytes + 1 - consumed))
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > max_bytes:
                raise ContractError(f"{label}: file exceeds the byte limit")
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


def read_regular_under(
    root: Path,
    relative: Any,
    *,
    label: str,
    max_bytes: int,
    budget: ByteBudget | None = None,
) -> bytes:
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
            return _read_fd(
                file_fd,
                label=label,
                max_bytes=max_bytes,
                budget=budget,
            )
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


def read_regular_bytes(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    budget: ByteBudget | None = None,
) -> bytes:
    if path.name in {"", ".", ".."}:
        raise ContractError(f"{label}: required file path is invalid")
    return read_regular_under(
        path.parent,
        path.name,
        label=label,
        max_bytes=max_bytes,
        budget=budget,
    )


def load_json_bytes(payload: bytes, *, label: str) -> Any:
    return strict_json_bytes(payload, label=label)


def load_json(path: Path, *, label: str, max_bytes: int) -> Any:
    return load_json_bytes(
        read_regular_bytes(path, label=label, max_bytes=max_bytes),
        label=label,
    )


def load_jsonl_bytes(
    payload: bytes,
    *,
    label: str,
    max_rows: int,
    max_line_bytes: int,
) -> list[dict[str, Any]]:
    if type(max_rows) is not int or max_rows <= 0:
        raise ContractError(f"{label}: invalid JSONL row limit")
    if type(max_line_bytes) is not int or max_line_bytes <= 0:
        raise ContractError(f"{label}: invalid JSONL line byte limit")
    rows: list[dict[str, Any]] = []
    for line_number, raw in enumerate(io.BytesIO(payload), start=1):
        if line_number > max_rows:
            raise ContractError(f"{label}: JSONL row limit exceeded")
        if len(raw) > max_line_bytes:
            raise ContractError(
                f"{label}:{line_number}: JSONL line byte limit exceeded"
            )
        if not raw.strip():
            raise ContractError(f"{label}: blank JSONL line {line_number}")
        value = strict_json_bytes(raw, label=f"{label}:{line_number}")
        if not isinstance(value, dict):
            raise ContractError(f"{label}:{line_number}: JSONL row is not an object")
        rows.append(value)
    if not rows:
        raise ContractError(f"{label}: JSONL file is empty")
    return rows


def load_jsonl(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    max_rows: int,
    max_line_bytes: int,
) -> list[dict[str, Any]]:
    return load_jsonl_bytes(
        read_regular_bytes(path, label=label, max_bytes=max_bytes),
        label=label,
        max_rows=max_rows,
        max_line_bytes=max_line_bytes,
    )


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


_SECRET_HEADER_RE = re.compile(
    rb"(?im)^[ \t]*(?:authorization[ \t]*:[ \t]*(?:bearer|basic)|cookie[ \t]*:|set-cookie[ \t]*:)[ \t]*([^\r\n]+)"
)
_SECRET_IDENTIFIER_PATTERN = (
    rb"(?:"
    rb"(?:[A-Za-z0-9][A-Za-z0-9_.-]*[._-])?"
    rb"(?:password|passwd|api[_-]?key|api[_-]?token|access[_-]?token|"
    rb"refresh[_-]?token|client[_-]?secret|private[_-]?key|"
    rb"secret[_-]?access[_-]?key)"
    rb"|[A-Za-z0-9][A-Za-z0-9_.-]*[._-](?:token|secret)"
    rb")"
)
_SECRET_EQUALS_ASSIGNMENT_RE = re.compile(
    rb"(?im)(?:^[ \t]*|[({,;][ \t]*|export[ \t]+)"
    rb"(?:(?:const|let|var|readonly|final)[ \t]+)?[\"']?"
    + _SECRET_IDENTIFIER_PATTERN
    + rb"[\"']?[ \t]*=[ \t]*[\"']?([^\"'\s,;})]{4,})"
    + rb"(?=[\"'\s,;})]|$)"
)
_SECRET_COLON_ASSIGNMENT_RE = re.compile(
    rb"(?im)(?:^[ \t]*|[({,;][ \t]*)[\"']?"
    + _SECRET_IDENTIFIER_PATTERN
    + rb"[\"']?[ \t]*:[ \t]*[\"']?([^\"'\s,;})]{4,})"
    + rb"(?=[\"'\s,;})]|$)(?![ \t]*=)"
)
_SECRET_TYPED_ASSIGNMENT_RE = re.compile(
    rb"(?im)(?:^[ \t]*|[({,;][ \t]*)"
    rb"(?:(?:const|let|var|readonly|final)[ \t]+)?"
    + _SECRET_IDENTIFIER_PATTERN
    + rb"[ \t]*:[ \t]*[A-Za-z_$][A-Za-z0-9_.$\[\]|?, <>\"]{0,80}"
    + rb"[ \t]*=[ \t]*[\"']?([^\"'\s,;}]{4,})"
)
_SECRET_PYTHON_LITERAL_ASSIGNMENT_RE = re.compile(
    rb"(?ims)(?:^[ \t]*|[({,;][ \t]*|export[ \t]+)"
    rb"(?:(?:const|let|var|readonly|final)[ \t]+)?[\"']?"
    + _SECRET_IDENTIFIER_PATTERN
    + rb"[\"']?(?:[ \t]*:[ \t]*[A-Za-z_$][A-Za-z0-9_.$\[\]|?, <>\"]{0,80})?"
    + rb"[ \t]*=(?:[ \t\r\n]*\(){0,3}[ \t\r\n]*"
    + rb"((?:br|rb|fr|rf|b|r|u|f)?(?:\"\"\".*?\"\"\"|'''.*?'''|\"[^\r\n\"]*\"|'[^\r\n']*'))"
)
_PYTHON_LITERAL_RE = re.compile(
    rb"(?is)^(?:br|rb|fr|rf|b|r|u|f)?"
    rb"(?P<quote>\"\"\"|'''|\"|')(?P<body>.*)(?P=quote)$"
)
_AUTHENTICATED_URL_RE = re.compile(
    rb"(?i)(?:postgres(?:ql)?|mysql|mariadb|redis|mongodb(?:\+srv)?|https?)://[^\s/:@]+:([^\s/@]+)@"
)
_KNOWN_TOKEN_RE = re.compile(
    rb"(?<![A-Za-z0-9])(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
    rb"sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{16,}|"
    rb"xox[baprs]-[A-Za-z0-9-]{20,}|"
    rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
    rb"(?![A-Za-z0-9])"
)
_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN RSA " + b"PRIVATE KEY-----",
    b"-----BEGIN EC " + b"PRIVATE KEY-----",
    b"-----BEGIN DSA " + b"PRIVATE KEY-----",
    b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----",
    b"-----BEGIN PGP " + b"PRIVATE KEY BLOCK-----",
)
_SECRET_PLACEHOLDERS = {
    b"false",
    b"true",
    b"none",
    b"null",
    b"redacted",
    b"masked",
    b"removed",
    b"placeholder",
    b"changeme",
    b"not-set",
    b"unset",
}


def _is_secret_placeholder(value: bytes) -> bool:
    normalized = value.strip().strip(b"\"'").lower()
    return (
        normalized in _SECRET_PLACEHOLDERS
        or normalized.startswith((b"<redacted", b"${", b"{{"))
        or (normalized and set(normalized) <= {ord("*"), ord("x"), ord("-")})
    )


def _is_runtime_secret_reference(value: bytes) -> bool:
    normalized = value.strip().strip(b"\"'").lstrip(b"(").lower()
    return normalized == b"await" or normalized.startswith(
        (
            b"args.",
            b"config.",
            b"deno.env",
            b"getenv(",
            b"import.meta.env",
            b"os.environ",
            b"process.env",
            b"readsecret(",
            b"secrets.",
        )
    )


def _python_literal_body(value: bytes) -> bytes | None:
    match = _PYTHON_LITERAL_RE.fullmatch(value.strip())
    return None if match is None else match.group("body")


def scan_secret_bytes(payload: bytes, *, label: str) -> None:
    """Reject credential material without echoing the matched value."""
    for marker in _PRIVATE_KEY_MARKERS:
        if marker in payload:
            raise ContractError(f"{label}: private key material detected")
    if _KNOWN_TOKEN_RE.search(payload):
        raise ContractError(f"{label}: credential token detected")
    for match in _SECRET_PYTHON_LITERAL_ASSIGNMENT_RE.finditer(payload):
        body = _python_literal_body(match.group(1))
        if body is None or not _is_secret_placeholder(body):
            raise ContractError(f"{label}: credential assignment detected")
    for pattern, kind in (
        (_SECRET_HEADER_RE, "sensitive HTTP authentication/cookie header"),
        (_SECRET_EQUALS_ASSIGNMENT_RE, "credential assignment"),
        (_SECRET_COLON_ASSIGNMENT_RE, "credential assignment"),
        (_SECRET_TYPED_ASSIGNMENT_RE, "typed credential assignment"),
        (_AUTHENTICATED_URL_RE, "credential-bearing URL"),
    ):
        for match in pattern.finditer(payload):
            value = match.group(1)
            if (
                "assignment" in kind
                and _is_runtime_secret_reference(value)
            ):
                continue
            if not _is_secret_placeholder(value):
                raise ContractError(f"{label}: {kind} detected")


def sha256_file(
    path: Path,
    *,
    label: str | None = None,
    max_bytes: int,
) -> str:
    return sha256_bytes(
        read_regular_bytes(
            path,
            label=label or path.name,
            max_bytes=max_bytes,
        )
    )


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
    if "\\" in text or "\x00" in text or "\n" in text or "\r" in text:
        raise ContractError(f"{label}: unsafe relative path")
    pure = PurePosixPath(text)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ContractError(f"{label}: unsafe relative path")
    return pure


def resolve_regular(
    root: Path,
    relative: Any,
    *,
    label: str,
    max_bytes: int,
) -> Path:
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
    read_regular_bytes(target, label=label, max_bytes=max_bytes)
    return target


def write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o644)


def write_json(path: Path, value: Any, *, pretty: bool = True) -> None:
    write_bytes(path, canonical_json_bytes(value, pretty=pretty))


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    write_bytes(path, b"".join(canonical_json_bytes(row) for row in rows))


def tree_index(
    root: Path,
    *,
    exclude: Iterable[str] = (),
    max_file_bytes: int = 16 * 1024 * 1024,
    max_total_bytes: int = 128 * 1024 * 1024,
    max_entries: int = TREE_MAX_ENTRIES,
    max_relative_path_bytes: int = TREE_MAX_RELATIVE_PATH_BYTES,
) -> dict[str, dict[str, Any]]:
    if (
        type(max_entries) is not int
        or max_entries <= 0
        or type(max_relative_path_bytes) is not int
        or max_relative_path_bytes <= 0
    ):
        raise ContractError("package: invalid tree enumeration limit")
    excluded = set(exclude)
    result: dict[str, dict[str, Any]] = {}
    budget = ByteBudget("package tree", max_total_bytes)
    entry_count = 0

    def identity(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def walk(directory_fd: int, parts: tuple[str, ...]) -> None:
        nonlocal entry_count
        if len(parts) > TREE_MAX_DEPTH:
            raise ContractError("package: tree depth limit exceeded")
        try:
            iterator = os.scandir(directory_fd)
        except OSError as error:
            raise ContractError("package: unable to enumerate tree") from error
        with iterator:
            for entry in iterator:
                entry_count += 1
                if entry_count > max_entries:
                    raise ContractError("package: tree entry limit exceeded")
                child_parts = (*parts, entry.name)
                relative = "/".join(child_parts)
                if "\n" in relative or "\r" in relative or "\x00" in relative:
                    raise ContractError(
                        "package: relative path contains a control character"
                    )
                try:
                    path_bytes = relative.encode("utf-8")
                except UnicodeEncodeError as error:
                    raise ContractError(
                        "package: relative path is not canonical UTF-8"
                    ) from error
                if len(path_bytes) > max_relative_path_bytes:
                    raise ContractError(
                        "package: relative path exceeds the byte limit"
                    )
                try:
                    entry_info = entry.stat(follow_symlinks=False)
                except OSError as error:
                    raise ContractError(
                        f"package: unable to inspect {relative}"
                    ) from error
                if stat.S_ISLNK(entry_info.st_mode):
                    raise ContractError(
                        f"package: symlink is forbidden at {relative}"
                    )
                if stat.S_ISDIR(entry_info.st_mode):
                    try:
                        child_fd = os.open(
                            entry.name,
                            _directory_flags(),
                            dir_fd=directory_fd,
                        )
                        opened_info = os.fstat(child_fd)
                    except OSError as error:
                        raise ContractError(
                            f"package: unable to open directory {relative}"
                        ) from error
                    try:
                        if identity(entry_info) != identity(opened_info):
                            raise ContractError(
                                f"package: directory changed during enumeration at {relative}"
                            )
                        walk(child_fd, child_parts)
                    finally:
                        os.close(child_fd)
                    continue
                if not stat.S_ISREG(entry_info.st_mode):
                    raise ContractError(
                        f"package: non-regular entry is forbidden at {relative}"
                    )
                if relative in excluded:
                    continue
                try:
                    file_fd = os.open(
                        entry.name,
                        _file_flags(),
                        dir_fd=directory_fd,
                    )
                    opened_info = os.fstat(file_fd)
                except OSError as error:
                    raise ContractError(
                        f"package: unable to open {relative}"
                    ) from error
                try:
                    if identity(entry_info) != identity(opened_info):
                        raise ContractError(
                            f"package: file changed during enumeration at {relative}"
                        )
                    payload = _read_fd(
                        file_fd,
                        label=f"package:{relative}",
                        max_bytes=max_file_bytes,
                        budget=budget,
                    )
                finally:
                    os.close(file_fd)
                result[relative] = {
                    "sha256": sha256_bytes(payload),
                    "size": len(payload),
                }

    root_fd = _open_canonical_directory(root, label="package")
    try:
        walk(root_fd, ())
    finally:
        os.close(root_fd)
    return dict(sorted(result.items()))


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
    max_manifest_bytes: int,
    max_file_bytes: int,
    max_total_bytes: int,
    capture_all: bool,
    max_entries: int = MANIFEST_MAX_ENTRIES,
) -> ManifestSnapshot:
    if type(max_entries) is not int or max_entries <= 0:
        raise ContractError("manifest: invalid entry limit")
    budget = ByteBudget("manifest snapshot", max_total_bytes)
    payload = read_regular_under(
        root,
        "MANIFEST.sha256",
        label="manifest",
        max_bytes=max_manifest_bytes,
        budget=budget,
    )
    rows: dict[str, str] = {}
    files: dict[str, bytes] = {}
    required_set = set(required)
    for line_number, raw in enumerate(payload.decode("utf-8").splitlines(), start=1):
        if line_number > max_entries:
            raise ContractError("manifest: entry limit exceeded")
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00]+)", raw)
        if match is None:
            raise ContractError(f"manifest: malformed row {line_number}")
        digest, relative_text = match.groups()
        pure = safe_relative(relative_text, label=f"manifest:{line_number}")
        relative = pure.as_posix()
        if relative == "MANIFEST.sha256" or relative in rows:
            raise ContractError(f"manifest: duplicate or self-referential row {line_number}")
        file_payload = read_regular_under(
            root,
            relative,
            label=f"manifest:{relative}",
            max_bytes=max_file_bytes,
            budget=budget,
        )
        if sha256_bytes(file_payload) != digest:
            raise ContractError(f"manifest: hash mismatch for {relative}")
        rows[relative] = digest
        if capture_all or relative in required_set:
            files[relative] = file_payload
    if not required_set.issubset(rows):
        raise ContractError(f"manifest: required entries missing: {sorted(required_set - set(rows))}")
    if exact:
        actual = set(
            tree_index(
                root,
                exclude={"MANIFEST.sha256"},
                max_file_bytes=max_file_bytes,
                max_total_bytes=max_total_bytes,
                max_entries=max_entries,
            )
        )
        if set(rows) != actual:
            raise ContractError("manifest: file set is not exact")
    return ManifestSnapshot(rows=rows, files=files, manifest_bytes=payload)


def validate_manifest(
    root: Path,
    *,
    exact: bool,
    required: Iterable[str] = (),
    max_manifest_bytes: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> dict[str, str]:
    return validate_manifest_snapshot(
        root,
        exact=exact,
        required=required,
        max_manifest_bytes=max_manifest_bytes,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
        capture_all=False,
    ).rows


def _certify_isolated_process_group(
    process: subprocess.Popen[bytes],
) -> int:
    """Certify the new session requested at Popen before accepting output."""
    expected_pgid = process.pid
    if expected_pgid == os.getpgrp() or expected_pgid == os.getpid():
        try:
            process.kill()
        finally:
            process.wait()
        raise ContractError("subprocess: child process group is not isolated")
    try:
        observed_pgid = os.getpgid(process.pid)
    except ProcessLookupError:
        # Popen(start_new_session=True) completed successfully, but an
        # extremely short-lived leader may already be a waitable zombie.
        return expected_pgid
    except OSError as error:
        try:
            process.kill()
        finally:
            process.wait()
        raise ContractError(
            "subprocess: child process group could not be certified"
        ) from error
    if observed_pgid != expected_pgid or observed_pgid == os.getpgrp():
        try:
            process.kill()
        finally:
            process.wait()
        raise ContractError("subprocess: child process group is not isolated")
    return observed_pgid


def _kill_process_group(
    process: subprocess.Popen[bytes],
    isolated_pgid: int,
) -> None:
    """Kill the certified child group before reaping its leader."""
    if (
        isolated_pgid != process.pid
        or isolated_pgid == os.getpgrp()
        or isolated_pgid == os.getpid()
    ):
        raise ContractError("subprocess: refusing an unsafe process-group kill")
    try:
        os.killpg(isolated_pgid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError as error:
        if error.errno == errno.ESRCH:
            return
        raise ContractError(
            "subprocess: isolated process group could not be terminated"
        ) from error


def run_process_bounded(
    command: list[str],
    *,
    label: str,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    input_bytes: bytes | None = None,
    capture_stdout: bool = True,
    capture_stderr: bool = True,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    max_total_output_bytes: int,
    max_stdin_bytes: int,
) -> subprocess.CompletedProcess[bytes]:
    """Run one isolated process while bounding every in-memory byte stream."""
    limits = (
        max_stdout_bytes,
        max_stderr_bytes,
        max_total_output_bytes,
        max_stdin_bytes,
    )
    if (
        not command
        or any(not isinstance(item, str) or "\x00" in item for item in command)
        or any(type(limit) is not int or limit <= 0 for limit in limits)
        or max_total_output_bytes
        > max_stdout_bytes + max_stderr_bytes
        or timeout <= 0
    ):
        raise ContractError(f"{label}: invalid subprocess contract")
    stdin_payload = input_bytes or b""
    if len(stdin_payload) > max_stdin_bytes:
        raise ContractError(f"{label}: subprocess input byte budget exceeded")
    command_payload = json.dumps(
        command,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    if len(command_payload.encode("utf-8")) > SUBPROCESS_COMMAND_MAX_BYTES:
        raise ContractError(f"{label}: subprocess command byte budget exceeded")
    try:
        control_read_fd, control_write_fd = os.pipe()
    except OSError as error:
        raise ContractError(
            f"{label}: subprocess control channel is unavailable"
        ) from error
    supervisor_command = [
        sys.executable,
        "-I",
        "-S",
        "-c",
        _PROCESS_SUPERVISOR_SOURCE,
        str(control_write_fd),
        command_payload,
    ]
    try:
        process = subprocess.Popen(
            supervisor_command,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            pass_fds=(control_write_fd,),
        )
    except OSError as error:
        os.close(control_read_fd)
        os.close(control_write_fd)
        raise ContractError(f"{label}: subprocess is unavailable") from error
    os.close(control_write_fd)

    try:
        isolated_pgid = _certify_isolated_process_group(process)
    except BaseException:
        os.close(control_read_fd)
        raise
    selector = selectors.DefaultSelector()
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    control_buffer = bytearray()
    stdout_size = 0
    stderr_size = 0
    stdin_offset = 0
    deadline = time.monotonic() + timeout
    overflow = False
    timed_out = False
    protocol_error = False
    group_terminated = False
    control_stream: Any = None

    def unregister_and_close(stream: Any) -> None:
        try:
            selector.unregister(stream)
        except (KeyError, ValueError):
            pass
        try:
            stream.close()
        except OSError:
            pass

    try:
        if process.stdout is not None:
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        if process.stderr is not None:
            os.set_blocking(process.stderr.fileno(), False)
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        control_stream = os.fdopen(control_read_fd, "rb", buffering=0)
        os.set_blocking(control_stream.fileno(), False)
        selector.register(control_stream, selectors.EVENT_READ, "control")
        if process.stdin is not None:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                events = selector.select(min(remaining, 1.0))
            except OSError:
                events = []
            for key, _ in events:
                stream = key.fileobj
                if key.data == "stdin":
                    try:
                        written = os.write(
                            stream.fileno(),
                            stdin_payload[stdin_offset : stdin_offset + 64 * 1024],
                        )
                    except (BrokenPipeError, OSError):
                        unregister_and_close(stream)
                        continue
                    stdin_offset += written
                    if stdin_offset == len(stdin_payload):
                        unregister_and_close(stream)
                    continue
                if key.data == "control":
                    try:
                        chunk = os.read(stream.fileno(), 16)
                    except BlockingIOError:
                        continue
                    except OSError:
                        protocol_error = True
                        unregister_and_close(stream)
                        continue
                    if not chunk:
                        unregister_and_close(stream)
                        continue
                    control_buffer.extend(chunk)
                    if len(control_buffer) > 4:
                        protocol_error = True
                        break
                    continue
                try:
                    chunk = os.read(stream.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                except OSError:
                    unregister_and_close(stream)
                    continue
                if not chunk:
                    unregister_and_close(stream)
                    continue
                if key.data == "stdout":
                    stdout_size += len(chunk)
                    if capture_stdout:
                        stdout_buffer.extend(chunk)
                else:
                    stderr_size += len(chunk)
                    if capture_stderr:
                        stderr_buffer.extend(chunk)
                if (
                    stdout_size > max_stdout_bytes
                    or stderr_size > max_stderr_bytes
                    or stdout_size + stderr_size
                    > max_total_output_bytes
                ):
                    overflow = True
                    break
            if overflow or protocol_error:
                break

        _kill_process_group(process, isolated_pgid)
        group_terminated = True
        try:
            returncode = process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            raise ContractError(f"{label}: subprocess could not be reaped") from error
        if overflow:
            raise ContractError(
                f"{label}: subprocess output byte budget exceeded"
            )
        if timed_out:
            raise ContractError(f"{label}: subprocess timed out")
        if protocol_error or len(control_buffer) != 4:
            raise ContractError(
                f"{label}: subprocess control protocol failed"
            )
        target_returncode = struct.unpack("!i", control_buffer)[0]
        return subprocess.CompletedProcess(
            command,
            target_returncode,
            bytes(stdout_buffer),
            bytes(stderr_buffer),
        )
    finally:
        cleanup_error: ContractError | None = None
        if not group_terminated:
            try:
                _kill_process_group(process, isolated_pgid)
                group_terminated = True
            except ContractError as error:
                cleanup_error = error
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cleanup_error = ContractError(
                f"{label}: subprocess could not be reaped"
            )
        for stream in (
            process.stdin,
            process.stdout,
            process.stderr,
            control_stream,
        ):
            if stream is not None:
                unregister_and_close(stream)
        if control_stream is None:
            try:
                os.close(control_read_fd)
            except OSError:
                pass
        selector.close()
        if cleanup_error is not None:
            raise cleanup_error


def _git_environment() -> dict[str, str]:
    """Return a closed Git environment with history rewriting disabled."""
    return {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "0",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/var/empty" if Path("/var/empty").is_dir() else os.sep,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
    }


def _run_git_process(
    repo: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    stdout: Any = subprocess.PIPE,
    stderr: Any = subprocess.PIPE,
) -> subprocess.CompletedProcess[bytes]:
    executable = shutil.which("git", path=os.defpath)
    if executable is None:
        raise ContractError("git: trusted executable is unavailable")
    try:
        canonical_repo = repo.resolve(strict=True)
    except OSError as error:
        raise ContractError("git: repository is unavailable") from error
    if not canonical_repo.is_dir() or "\n" in os.fspath(canonical_repo):
        raise ContractError("git: repository path is unsafe")
    safe_config = (
        ("core.attributesFile", os.devnull),
        ("core.bare", "false"),
        ("core.excludesFile", os.devnull),
        ("core.fsmonitor", "false"),
        ("core.hooksPath", os.devnull),
        ("core.untrackedCache", "false"),
        ("core.worktree", os.fspath(canonical_repo)),
        ("credential.helper", ""),
        ("submodule.recurse", "false"),
    )
    command = [executable]
    for key, value in safe_config:
        command.extend(("-c", f"{key}={value}"))
    command.extend(("-C", os.fspath(canonical_repo), *arguments))
    environment = _git_environment()
    environment["GIT_WORK_TREE"] = os.fspath(canonical_repo)
    if stdout not in {subprocess.PIPE, subprocess.DEVNULL} or stderr not in {
        subprocess.PIPE,
        subprocess.DEVNULL,
    }:
        raise ContractError("git: unsupported subprocess stream contract")
    query_cache = _IMMUTABLE_GIT_QUERY_CACHE.get()
    query_key: tuple[Any, ...] | None = None
    if (
        query_cache is not None
        and input_bytes is None
        and _is_immutable_git_query(arguments)
    ):
        query_key = (
            os.fspath(canonical_repo),
            arguments,
            stdout,
            stderr,
        )
        cached = query_cache.get(query_key)
        if cached is not None:
            return subprocess.CompletedProcess(
                command,
                cached[0],
                cached[1],
                cached[2],
            )
    completed = run_process_bounded(
        command,
        label="git",
        cwd=canonical_repo,
        env=environment,
        timeout=120,
        input_bytes=input_bytes,
        capture_stdout=stdout == subprocess.PIPE,
        capture_stderr=stderr == subprocess.PIPE,
        max_stdout_bytes=GIT_STDOUT_MAX_BYTES,
        max_stderr_bytes=GIT_STDERR_MAX_BYTES,
        max_total_output_bytes=GIT_OUTPUT_TOTAL_MAX_BYTES,
        max_stdin_bytes=GIT_STDIN_MAX_BYTES,
    )
    if query_key is not None and completed.returncode == 0:
        query_cache[query_key] = (
            completed.returncode,
            completed.stdout,
            completed.stderr,
        )
    return completed


def git(repo: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    completed = _run_git_process(
        repo,
        *arguments,
        input_bytes=input_bytes,
    )
    if completed.returncode != 0:
        raise ContractError(f"git: command failed ({arguments[0] if arguments else 'unknown'})")
    return completed.stdout


def git_text(repo: Path, *arguments: str) -> str:
    try:
        return git(repo, *arguments).decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ContractError("git: non-UTF-8 output") from error


def git_optional_text(repo: Path, *arguments: str) -> str | None:
    completed = _run_git_process(repo, *arguments)
    if completed.returncode == 1:
        return None
    if completed.returncode != 0:
        raise ContractError(
            f"git: command failed ({arguments[0] if arguments else 'unknown'})"
        )
    try:
        return completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ContractError("git: non-UTF-8 output") from error


def git_blob(
    repo: Path,
    objectish: str,
    *,
    label: str,
    max_bytes: int = GIT_BLOB_MAX_BYTES,
    budget: ByteBudget | None = None,
) -> bytes:
    """Read one Git blob only after a bounded object-size gate."""
    if (
        not isinstance(objectish, str)
        or not objectish
        or "\x00" in objectish
        or "\n" in objectish
        or type(max_bytes) is not int
        or max_bytes <= 0
        or max_bytes > GIT_STDOUT_MAX_BYTES
    ):
        raise ContractError(f"{label}: invalid Git blob contract")
    size_text = git_text(repo, "cat-file", "-s", objectish)
    if re.fullmatch(r"[0-9]+", size_text) is None:
        raise ContractError(f"{label}: Git blob size is invalid")
    size = int(size_text)
    if size > max_bytes:
        raise ContractError(f"{label}: Git blob exceeds the byte limit")
    if budget is not None:
        budget.reserve(size)
    payload = git(repo, "cat-file", "blob", objectish)
    if len(payload) != size:
        raise ContractError(f"{label}: Git blob size changed during read")
    return payload


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
    completed = _run_git_process(
        repo,
        "merge-base",
        "--is-ancestor",
        ancestor,
        descendant,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode != 0:
        raise ContractError(f"{label}: commit is not reachable from final HEAD")


def commit_delta_records(
    repo: Path,
    commit: str,
    *,
    blob_budget: ByteBudget | None = None,
) -> list[dict[str, Any]]:
    if blob_budget is None:
        blob_budget = ByteBudget(
            "commit delta Git blobs",
            128 * 1024 * 1024,
        )
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
            return sha256_bytes(
                git_blob(
                    repo,
                    object_id,
                    label="commit equivalence blob",
                    budget=blob_budget,
                )
            )

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
    blob_budget = ByteBudget(
        "commit equivalence Git blobs",
        128 * 1024 * 1024,
    )
    cohort_delta = commit_delta_records(
        repo,
        cohort,
        blob_budget=blob_budget,
    )
    final_delta = commit_delta_records(
        repo,
        final,
        blob_budget=blob_budget,
    )
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
    completed = _run_git_process(
        repo,
        "cat-file",
        "-e",
        f"{commit}:{relative}",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode != 0:
        raise ContractError(f"candidate evidence: path is absent at final commit: {relative}")
