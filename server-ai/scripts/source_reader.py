#!/usr/bin/env python3
"""Private, read-only source/Git reader for canonical managed project roots."""

from __future__ import annotations

import base64
import bisect
import ctypes
import fnmatch
import hashlib
import hmac
import json
import os
import platform
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import time
from typing import Any, Iterator

try:
    from server_ai_reader_common import ReaderError, exact_object, load_token, serve
except ImportError:  # local tests
    from common import ReaderError, exact_object, load_token, serve


PROJECTS_ROOT = Path("/projects")
PLATFORM_ROOT = Path("/platform")
PLATFORM_PROJECT_ID = "platform"
PROJECT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
DENIED_COMPONENTS = frozenset({
    ".git", ".svn", ".hg", ".idea", ".vscode", ".pnpm-store", "node_modules", "vendor",
    ".next", "dist", "build", "coverage", "uploads", "cache", "tmp", "backups", "backup", "secrets", "credentials",
})
DENIED_NAMES = re.compile(
    r"^(?:\.env(?:\..*)?|auth\.json|\.npmrc|\.pypirc|id_(?:rsa|ed25519)|.*(?:dump|backup).*\.sql|.*\.(?:pem|key|p12|pfx|jks|keystore|sqlite|db|dump|bak))$",
    re.IGNORECASE,
)
SECRET_ASSIGNMENT = re.compile(r'''(?ix)
    (?P<prefix>["']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|private[_-]?key)["']?\s*(?:=>|=|:)\s*)
    (?P<quote>["']?)(?P<value>[^\s,;"']{4,}|[^"']{4,})(?P=quote)
''')
AUTH_LINE = re.compile(r"(?im)^(?P<prefix>\s*(?:authorization|cookie|set-cookie)\s*[:=]\s*).*$")
URL_CREDENTIAL = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s@]+@")
JWT = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])")
PRIVATE_KEY_BLOCK = re.compile(r"(?ms)^-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?^-----END [^-\r\n]*PRIVATE KEY-----\s*$")
LANGUAGES = {
    ".php": "php", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript", ".py": "python",
    ".html": "html", ".css": "css", ".scss": "scss", ".json": "json",
    ".yaml": "yaml", ".yml": "yaml", ".md": "markdown", ".sql": "sql",
    ".sh": "shell", ".xml": "xml", ".toml": "toml", ".ini": "ini",
}
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_READ_BYTES = 32 * 1024
MAX_SCAN_FILES = 50_000
MAX_PROJECTS = 64
MAX_SEARCH_BYTES = 8 * 1024 * 1024
MAX_GIT_BYTES = 128 * 1024
SCAN_SECONDS = 1.5
OPENAT2 = 437
RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08


class OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]


LIBC = ctypes.CDLL(None, use_errno=True)


def _openat2(root_fd: int, relative: str, flags: int) -> int:
    how = OpenHow(flags=flags | os.O_CLOEXEC | os.O_NOFOLLOW, mode=0,
                  resolve=RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV)
    value = LIBC.syscall(OPENAT2, root_fd, relative.encode("utf-8"), ctypes.byref(how), ctypes.sizeof(how))
    if value < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), relative)
    return value


def _relative(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value or "\\" in value:
        raise ReaderError("INPUT_LIMIT")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReaderError("DENIED_PATH")
    lowered = [part.casefold() for part in path.parts]
    if any(part in DENIED_COMPONENTS for part in lowered) or DENIED_NAMES.fullmatch(path.name):
        raise ReaderError("DENIED_PATH")
    return path.as_posix()


def _redact(text: str) -> str:
    def block(match: re.Match[str]) -> str:
        value = match.group(0)
        return "\n".join("[REDACTED]" for _ in value.split("\n"))
    text = PRIVATE_KEY_BLOCK.sub(block, text)
    text = AUTH_LINE.sub(lambda match: f"{match.group('prefix')}[REDACTED]", text)
    text = URL_CREDENTIAL.sub(r"\1[REDACTED]@", text)
    text = JWT.sub("[REDACTED]", text)
    return SECRET_ASSIGNMENT.sub(lambda match: f"{match.group('prefix')}[REDACTED]", text)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _bounded_process(command: list[str], environment: dict[str, str], timeout: int, max_bytes: int,
                     *, pass_fds: tuple[int, ...] = ()) -> tuple[int, bytes]:
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=environment, start_new_session=True, pass_fds=pass_fds)
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            events = selector.select(min(0.1, remaining))
            if not events and process.poll() is not None:
                events = selector.select(0)
                if not events:
                    break
            for key, _mask in events:
                chunk = os.read(key.fd, min(16 * 1024, max_bytes + 1 - total))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise OverflowError
                chunks.append(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        return process.wait(timeout=remaining), b"".join(chunks)
    except (TimeoutError, subprocess.TimeoutExpired):
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait()
        raise ReaderError("TIMEOUT", 408) from None
    except OverflowError:
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait()
        raise ReaderError("RESULT_LIMIT", 413) from None
    finally:
        selector.close()
        process.stdout.close()


class SourceReader:
    def __init__(self, projects_root: Path = PROJECTS_ROOT, token: bytes | None = None,
                 platform_root: Path | None = PLATFORM_ROOT):
        self.projects_root = Path(projects_root)
        if not self.projects_root.is_absolute():
            raise RuntimeError("source reader project root is invalid")
        self.platform_root = Path(platform_root) if platform_root is not None else None
        if self.platform_root is not None and not self.platform_root.is_absolute():
            raise RuntimeError("source reader platform root is invalid")
        self.token = token if token is not None else load_token()
        if len(self.token) < 32:
            raise RuntimeError("source reader token is invalid")

    def _projects_descriptor(self) -> int:
        try:
            descriptor = os.open(self.projects_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                raise OSError
            return descriptor
        except OSError:
            try:
                os.close(descriptor)
            except (NameError, OSError):
                pass
            raise ReaderError("PROJECT_UNAVAILABLE", 404) from None

    def _project_ids(self) -> list[str]:
        descriptor = self._projects_descriptor()
        deadline = time.monotonic() + SCAN_SECONDS
        result: list[str] = []
        try:
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    if time.monotonic() > deadline:
                        raise ReaderError("RESULT_LIMIT", 413)
                    if entry.name == PLATFORM_PROJECT_ID or not PROJECT_ID.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False):
                        continue
                    try:
                        child = _openat2(descriptor, entry.name, os.O_RDONLY | os.O_DIRECTORY)
                    except OSError:
                        continue
                    else:
                        os.close(child)
                        if len(result) >= MAX_PROJECTS:
                            raise ReaderError("RESULT_LIMIT", 413)
                        result.append(entry.name)
        finally:
            os.close(descriptor)
        if self.platform_root is not None:
            platform_descriptor = -1
            try:
                platform_descriptor = os.open(self.platform_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
                platform_info = os.fstat(platform_descriptor)
                if not stat.S_ISDIR(platform_info.st_mode):
                    raise OSError
            except OSError:
                if platform_descriptor >= 0:
                    os.close(platform_descriptor)
            else:
                os.close(platform_descriptor)
                if len(result) >= MAX_PROJECTS:
                    raise ReaderError("RESULT_LIMIT", 413)
                result.append(PLATFORM_PROJECT_ID)
        result.sort()
        return result

    def _root(self, project_id: Any) -> tuple[str, Path, int]:
        if not isinstance(project_id, str) or not PROJECT_ID.fullmatch(project_id):
            raise ReaderError("PROJECT_UNAVAILABLE", 404)
        if project_id == PLATFORM_PROJECT_ID:
            if self.platform_root is None:
                raise ReaderError("PROJECT_UNAVAILABLE", 404)
            try:
                descriptor = os.open(self.platform_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
                info = os.fstat(descriptor)
                if not stat.S_ISDIR(info.st_mode):
                    raise OSError
            except OSError:
                try:
                    os.close(descriptor)
                except (NameError, OSError):
                    pass
                raise ReaderError("PROJECT_UNAVAILABLE", 404) from None
            return project_id, self.platform_root, descriptor
        parent = self._projects_descriptor()
        descriptor = -1
        try:
            descriptor = _openat2(parent, project_id, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            raise ReaderError("PROJECT_UNAVAILABLE", 404) from None
        finally:
            os.close(parent)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                raise OSError
        except OSError:
            if descriptor >= 0:
                os.close(descriptor)
            raise ReaderError("PROJECT_UNAVAILABLE", 404) from None
        return project_id, self.projects_root / project_id, descriptor

    def _open_file(self, root_fd: int, relative: str) -> tuple[int, os.stat_result]:
        descriptor = -1
        try:
            descriptor = _openat2(root_fd, relative, os.O_RDONLY | os.O_NONBLOCK)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size < 0 or info.st_size > MAX_FILE_BYTES:
                raise ReaderError("DENIED_PATH")
            return descriptor, info
        except ReaderError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except OSError as error:
            if descriptor >= 0:
                os.close(descriptor)
            raise ReaderError("NOT_FOUND" if error.errno in {2, 20} else "DENIED_PATH", 404) from None

    def _read(self, root_fd: int, relative: str) -> tuple[bytes, os.stat_result, str]:
        descriptor, info = self._open_file(root_fd, relative)
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        remaining = info.st_size
        try:
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                digest.update(chunk)
                chunks.append(chunk)
        finally:
            os.close(descriptor)
        data = b"".join(chunks)
        if len(data) != info.st_size or b"\x00" in data[:8192]:
            raise ReaderError("DENIED_PATH")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise ReaderError("DENIED_PATH") from None
        return data, info, digest.hexdigest()

    def _source_id(self, project_id: str, relative: str, digest: str) -> str:
        payload = f"source\0{project_id}\0{relative}\0{digest}".encode()
        return _b64(hmac.digest(self.token, payload, "sha256"))

    def _cursor(self, project_id: str, relative: str) -> str:
        payload = json.dumps({"v": 1, "p": project_id, "a": relative}, separators=(",", ":")).encode()
        return _b64(payload + hmac.digest(self.token, payload, "sha256"))

    def _decode_cursor(self, project_id: str, cursor: Any) -> str:
        if cursor is None or cursor == "":
            return ""
        if not isinstance(cursor, str) or len(cursor) > 1024 or not re.fullmatch(r"[A-Za-z0-9_-]+", cursor):
            raise ReaderError("INPUT_LIMIT")
        try:
            raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
            payload, signature = raw[:-32], raw[-32:]
            if len(payload) > 768 or not hmac.compare_digest(signature, hmac.digest(self.token, payload, "sha256")):
                raise ValueError
            value = json.loads(payload)
            if value != {"v": 1, "p": project_id, "a": value.get("a")}:
                raise ValueError
            return _relative(value["a"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            raise ReaderError("INPUT_LIMIT") from None

    def _catalog_cursor(self, after: str) -> str:
        payload = json.dumps({"v": 1, "k": "catalog", "a": after}, separators=(",", ":")).encode()
        return _b64(payload + hmac.digest(self.token, payload, "sha256"))

    def _decode_catalog_cursor(self, cursor: Any) -> str:
        if cursor is None or cursor == "":
            return ""
        if not isinstance(cursor, str) or len(cursor) > 1024 or not re.fullmatch(r"[A-Za-z0-9_-]+", cursor):
            raise ReaderError("INPUT_LIMIT")
        try:
            raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
            payload, signature = raw[:-32], raw[-32:]
            if len(payload) > 768 or not hmac.compare_digest(signature, hmac.digest(self.token, payload, "sha256")):
                raise ValueError
            value = json.loads(payload)
            if value != {"v": 1, "k": "catalog", "a": value.get("a")} or not PROJECT_ID.fullmatch(value["a"]):
                raise ValueError
            return value["a"]
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            raise ReaderError("INPUT_LIMIT") from None

    def projects_catalog(self, body: dict[str, Any]) -> dict[str, Any]:
        exact_object(body, {"cursor", "limit"}, set())
        limit = body.get("limit", MAX_PROJECTS)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_PROJECTS:
            raise ReaderError("INPUT_LIMIT")
        after = self._decode_catalog_cursor(body.get("cursor"))
        projects = self._project_ids()
        offset = bisect.bisect(projects, after) if after else 0
        selected = projects[offset:offset + limit]
        next_cursor = self._catalog_cursor(selected[-1]) if offset + len(selected) < len(projects) and selected else None
        return {
            "available": True,
            "projects": [{"id": project_id, "filesAvailable": True} for project_id in selected],
            "nextCursor": next_cursor,
        }

    def _ignore_patterns(self, root_fd: int) -> list[tuple[str, bool]]:
        try:
            data, _info, _digest = self._read(root_fd, ".gitignore")
        except ReaderError:
            return []
        if len(data) > 64 * 1024:
            raise ReaderError("RESULT_LIMIT", 413)
        patterns = []
        for raw in data.decode("utf-8").splitlines()[:1000]:
            value = raw.strip()
            if not value or value.startswith("#") or value.startswith("!"):
                continue
            directory = value.endswith("/")
            value = value.strip("/")
            if value and len(value) <= 256 and "\x00" not in value:
                patterns.append((value, directory))
        return patterns

    @staticmethod
    def _ignored(relative: str, is_dir: bool, patterns: list[tuple[str, bool]]) -> bool:
        parts = PurePosixPath(relative).parts
        for pattern, directory in patterns:
            if directory and not is_dir and not any(fnmatch.fnmatchcase("/".join(parts[:index]), pattern) for index in range(1, len(parts))):
                continue
            if "/" in pattern:
                if fnmatch.fnmatchcase(relative, pattern) or directory and relative.startswith(pattern.rstrip("/") + "/"):
                    return True
            elif any(fnmatch.fnmatchcase(part, pattern) for part in parts):
                return True
        return False

    def _paths(self, root_fd: int) -> list[str]:
        deadline = time.monotonic() + SCAN_SECONDS
        paths: list[str] = []
        stack = [""]
        visited = 0
        patterns = self._ignore_patterns(root_fd)
        while stack:
            if time.monotonic() > deadline or visited >= MAX_SCAN_FILES:
                raise ReaderError("RESULT_LIMIT", 413)
            relative_dir = stack.pop()
            descriptor = os.dup(root_fd) if not relative_dir else _openat2(root_fd, relative_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                entries = sorted(os.scandir(descriptor), key=lambda item: item.name.casefold(), reverse=True)
                for entry in entries:
                    visited += 1
                    if visited > MAX_SCAN_FILES:
                        raise ReaderError("RESULT_LIMIT", 413)
                    relative = f"{relative_dir}/{entry.name}" if relative_dir else entry.name
                    try:
                        safe = _relative(relative)
                    except ReaderError:
                        continue
                    is_dir = entry.is_dir(follow_symlinks=False)
                    if self._ignored(safe, is_dir, patterns):
                        continue
                    if is_dir:
                        stack.append(safe)
                    elif entry.is_file(follow_symlinks=False):
                        paths.append(safe)
            finally:
                os.close(descriptor)
        paths.sort()
        return paths

    def _citation(self, project_id: str, relative: str, info: os.stat_result, digest: str,
                  *, start: int | None = None, end: int | None = None, content: str | None = None) -> dict[str, Any]:
        value: dict[str, Any] = {
            "sourceId": self._source_id(project_id, relative, digest), "kind": "file",
            "title": relative, "path": relative, "sha256": digest,
        }
        if start is not None:
            value.update({"startLine": start, "endLine": end})
        if content is not None:
            value["content"] = content
        return value

    def files_index(self, body: dict[str, Any]) -> dict[str, Any]:
        exact_object(body, {"projectId", "cursor", "limit"}, {"projectId", "limit"})
        limit = body["limit"]
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ReaderError("INPUT_LIMIT")
        project_id, _root, root_fd = self._root(body["projectId"])
        try:
            after = self._decode_cursor(project_id, body.get("cursor"))
            paths = self._paths(root_fd)
            offset = bisect.bisect(paths, after) if after else 0
            selected = paths[offset:offset + limit]
            entries = []
            for relative in selected:
                # A repository can legitimately contain a hardlink, FIFO-like
                # race, unreadable encoding, or an oversized file.  Those
                # entries stay denied, but must not make the whole bounded
                # manifest unavailable to otherwise safe files.
                try:
                    _data, info, digest = self._read(root_fd, relative)
                except ReaderError:
                    continue
                entries.append({
                    **self._citation(project_id, relative, info, digest),
                    "size": info.st_size, "mtimeMs": round(info.st_mtime_ns / 1_000_000),
                    "language": LANGUAGES.get(PurePosixPath(relative).suffix.casefold(), "text"),
                })
            next_cursor = self._cursor(project_id, selected[-1]) if offset + len(selected) < len(paths) and selected else None
            return {"available": True, "projectId": project_id, "entries": entries, "nextCursor": next_cursor}
        finally:
            os.close(root_fd)

    def files_read(self, body: dict[str, Any]) -> dict[str, Any]:
        exact_object(body, {"projectId", "path", "startLine", "endLine", "expectedSha256"}, {"projectId", "path", "startLine", "endLine"})
        relative = _relative(body["path"])
        start, end = body["startLine"], body["endLine"]
        if any(not isinstance(value, int) or isinstance(value, bool) for value in (start, end)) or start < 1 or end < start or end - start > 5000:
            raise ReaderError("INPUT_LIMIT")
        expected = body.get("expectedSha256")
        if expected is not None and (not isinstance(expected, str) or not SHA256.fullmatch(expected)):
            raise ReaderError("INPUT_LIMIT")
        project_id, _root, root_fd = self._root(body["projectId"])
        try:
            data, info, digest = self._read(root_fd, relative)
            if expected and not hmac.compare_digest(expected, digest):
                raise ReaderError("STALE_SOURCE", 409)
            lines = data.decode("utf-8").splitlines()
            actual_end = min(end, len(lines))
            content = "\n".join(lines[start - 1:actual_end])
            encoded = content.encode("utf-8")
            if len(encoded) > MAX_READ_BYTES:
                encoded = encoded[:MAX_READ_BYTES]
                content = encoded.decode("utf-8", "ignore")
                actual_end = start + content.count("\n")
            item = self._citation(project_id, relative, info, digest, start=start, end=max(start, actual_end), content=_redact(content))
            return {"available": True, "projectId": project_id, "items": [item]}
        finally:
            os.close(root_fd)

    def files_search(self, body: dict[str, Any]) -> dict[str, Any]:
        exact_object(body, {"projectId", "query", "maxResults"}, {"projectId", "query", "maxResults"})
        query, maximum = body["query"], body["maxResults"]
        if not isinstance(query, str) or not query.strip() or len(query) > 400 or not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 16:
            raise ReaderError("INPUT_LIMIT")
        needle = query.strip().casefold()
        project_id, _root, root_fd = self._root(body["projectId"])
        total = 0
        items = []
        deadline = time.monotonic() + SCAN_SECONDS * 2
        try:
            for relative in self._paths(root_fd):
                if time.monotonic() > deadline or total >= MAX_SEARCH_BYTES:
                    break
                try:
                    data, info, digest = self._read(root_fd, relative)
                except ReaderError:
                    continue
                total += len(data)
                text = data.decode("utf-8")
                offset = text.casefold().find(needle)
                if offset < 0:
                    continue
                before = text[:offset]
                start = before.count("\n") + 1
                excerpt = text[offset:offset + 2048]
                end = start + excerpt.count("\n")
                items.append(self._citation(project_id, relative, info, digest, start=start, end=end, content=_redact(excerpt)))
                if len(items) >= maximum:
                    break
            return {"available": True, "projectId": project_id, "items": items}
        finally:
            os.close(root_fd)

    def _git(self, project_id: str, arguments: list[str], timeout: int = 5, *, allow_null: bool = False) -> str:
        _project, root, root_fd = self._root(project_id)
        try:
            try:
                self._validate_git_metadata(root_fd)
            except OSError:
                raise ReaderError("GIT_UNAVAILABLE") from None
            command = [
                "/usr/bin/git", "--no-optional-locks", "-c", "core.hooksPath=/dev/null",
                "-c", "core.fsmonitor=false", "-c", "core.pager=cat", "-c", "diff.external=",
                "-c", "protocol.allow=never",
            ]
            if project_id == PLATFORM_PROJECT_ID:
                command.extend(["-c", "safe.directory=/platform"])
            command.extend(["-C", f"/proc/self/fd/{root_fd}", *arguments])
            environment = {
                "PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat",
                "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_CEILING_DIRECTORIES": "/projects",
            }
            returncode, stdout = _bounded_process(command, environment, timeout, MAX_GIT_BYTES, pass_fds=(root_fd,))
            if returncode != 0 or not allow_null and b"\x00" in stdout[:8192]:
                raise ReaderError("GIT_UNAVAILABLE")
            return stdout.decode("utf-8", "replace")
        finally:
            os.close(root_fd)

    def _validate_git_metadata(self, root_fd: int) -> None:
        for relative in (".git", ".git/objects", ".git/refs"):
            descriptor = _openat2(root_fd, relative, os.O_RDONLY | os.O_DIRECTORY)
            os.close(descriptor)
        config, _info, _digest = self._read(root_fd, ".git/config")
        text = config.decode("utf-8")
        if (re.search(r"(?im)^\s*\[\s*include(?:if)?\b", text)
                or re.search(r"(?im)^\s*(?:path|worktree|hooksPath|fsmonitor|sshCommand|proxy|alternateObjectDirectories)\s*=", text)):
            raise ReaderError("GIT_UNAVAILABLE")
        for relative in (".git/objects/info/alternates", ".git/objects/info/http-alternates", ".git/commondir"):
            try:
                descriptor = _openat2(root_fd, relative, os.O_RDONLY | os.O_NONBLOCK)
            except OSError:
                continue
            else:
                os.close(descriptor)
                raise ReaderError("GIT_UNAVAILABLE")

    def git_status(self, body: dict[str, Any]) -> dict[str, Any]:
        exact_object(body, {"projectId"}, {"projectId"})
        project_id = body["projectId"]
        raw = self._git(project_id, ["status", "--porcelain=v1", "-z", "--untracked-files=no"], allow_null=True)
        records = raw.split("\x00")
        safe_records = []
        index = 0
        while index < len(records) and records[index]:
            record = records[index]
            if len(record) < 4:
                raise ReaderError("GIT_UNAVAILABLE")
            status_code, path_value = record[:2], record[3:]
            paths = [path_value]
            if "R" in status_code or "C" in status_code:
                index += 1
                if index >= len(records) or not records[index]:
                    raise ReaderError("GIT_UNAVAILABLE")
                paths.append(records[index])
            try:
                safe_paths = [_relative(value) for value in paths]
            except ReaderError:
                index += 1
                continue
            safe_records.append(f"{status_code} {' -> '.join(safe_paths)}")
            index += 1
        output = "\n".join(safe_records)
        digest = hashlib.sha256(output.encode()).hexdigest()
        item = {"sourceId": self._source_id(project_id, "git/status", digest), "kind": "git", "title": "Git status", "path": "", "sha256": digest, "content": _redact(output[:MAX_READ_BYTES])}
        return {"available": True, "projectId": project_id, "items": [item]}

    def git_log(self, body: dict[str, Any]) -> dict[str, Any]:
        exact_object(body, {"projectId", "limit"}, {"projectId"})
        limit = body.get("limit", 20)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ReaderError("INPUT_LIMIT")
        project_id = body["projectId"]
        output = self._git(project_id, ["log", "--no-show-signature", f"--max-count={limit}", "--format=%H%x09%aI%x09%s"])
        digest = hashlib.sha256(output.encode()).hexdigest()
        item = {"sourceId": self._source_id(project_id, "git/log", digest), "kind": "git", "title": "Git log", "path": "", "sha256": digest, "content": _redact(output[:MAX_READ_BYTES])}
        return {"available": True, "projectId": project_id, "items": [item]}

    def git_branch(self, body: dict[str, Any]) -> dict[str, Any]:
        exact_object(body, {"projectId"}, {"projectId"})
        project_id = body["projectId"]
        output = self._git(project_id, ["branch", "--show-current"])
        branch = output.strip()
        if branch and not re.fullmatch(r"[A-Za-z0-9._/-]{1,255}", branch):
            raise ReaderError("GIT_UNAVAILABLE")
        digest = hashlib.sha256(branch.encode()).hexdigest()
        item = {"sourceId": self._source_id(project_id, "git/branch", digest), "kind": "git", "title": "Git branch", "path": "", "sha256": digest, "content": branch}
        return {"available": True, "projectId": project_id, "items": [item]}

    def git_file_history(self, body: dict[str, Any]) -> dict[str, Any]:
        exact_object(body, {"projectId", "path", "limit"}, {"projectId", "path"})
        project_id = body["projectId"]
        relative = _relative(body["path"])
        limit = body.get("limit", 20)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ReaderError("INPUT_LIMIT")
        output = self._git(project_id, ["log", "--no-show-signature", f"--max-count={limit}", "--format=%H%x09%aI%x09%s", "--", relative])
        digest = hashlib.sha256(output.encode()).hexdigest()
        item = {"sourceId": self._source_id(project_id, f"git/history/{relative}", digest), "kind": "git", "title": f"Git history: {relative}", "path": relative, "sha256": digest, "content": _redact(output[:MAX_READ_BYTES])}
        return {"available": True, "projectId": project_id, "items": [item]}

    def git_blame(self, body: dict[str, Any]) -> dict[str, Any]:
        exact_object(body, {"projectId", "path", "startLine", "endLine"}, {"projectId", "path", "startLine", "endLine"})
        project_id = body["projectId"]
        relative = _relative(body["path"])
        start, end = body["startLine"], body["endLine"]
        if any(not isinstance(value, int) or isinstance(value, bool) for value in (start, end)) or start < 1 or end < start or end - start > 500:
            raise ReaderError("INPUT_LIMIT")
        output = self._git(project_id, ["blame", "--porcelain", "--no-progress", "-L", f"{start},{end}", "--", relative])
        digest = hashlib.sha256(output.encode()).hexdigest()
        item = {"sourceId": self._source_id(project_id, f"git/blame/{relative}/{start}/{end}", digest), "kind": "git", "title": f"Git blame: {relative}", "path": relative, "startLine": start, "endLine": end, "sha256": digest, "content": _redact(output[:MAX_READ_BYTES])}
        return {"available": True, "projectId": project_id, "items": [item]}

    def git_diff(self, body: dict[str, Any]) -> dict[str, Any]:
        exact_object(body, {"projectId", "path"}, {"projectId", "path"})
        project_id = body["projectId"]
        relative = _relative(body["path"])
        output = self._git(project_id, ["diff", "--no-ext-diff", "--no-textconv", "--unified=3", "--", relative])
        digest = hashlib.sha256(output.encode()).hexdigest()
        item = {"sourceId": self._source_id(project_id, f"git/diff/{relative}", digest), "kind": "git", "title": f"Git diff: {relative}", "path": relative, "sha256": digest, "content": _redact(output[:MAX_READ_BYTES])}
        return {"available": True, "projectId": project_id, "items": [item]}

    def routes(self):
        return {
            "/v1/projects/catalog": self.projects_catalog,
            "/v1/files/index": self.files_index, "/v1/files/search": self.files_search,
            "/v1/files/read": self.files_read, "/v1/git/status": self.git_status,
            "/v1/git/log": self.git_log, "/v1/git/diff": self.git_diff,
            "/v1/git/branch": self.git_branch, "/v1/git/file-history": self.git_file_history,
            "/v1/git/blame": self.git_blame,
        }


def main() -> None:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise RuntimeError("source reader requires Linux x86_64 openat2")
    reader = SourceReader()
    serve(8110, reader.token, reader.routes())


if __name__ == "__main__":
    main()
