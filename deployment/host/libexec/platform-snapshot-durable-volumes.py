#!/usr/bin/python3
"""Stage two small durable volumes for a signed, encrypted FTPS supplement.

This one-off operator tool reads production files but writes only beneath the
root-owned FTPS spool. It never changes the source volumes or live containers.
"""

import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile


WORK = Path("/var/lib/platform-ftps-backup")
SOURCE = WORK / "supplement-source"
DESTINATION = SOURCE / "durable-volumes"
GRAFANA_DB = Path("/var/lib/docker/volumes/greenfield_grafana_data/_data/grafana.db")
ATTACHMENTS = Path("/var/lib/docker/volumes/platform_server_ai_attachments/_data")
STUDENT_DATA = Path("/home/platform_infrastructure/v1-fresh-data/students-beta")
ALERTMANAGER_DATA = Path("/var/lib/docker/volumes/greenfield_alertmanager_data/_data")
MAX_ATTACHMENTS = 1000
MAX_ATTACHMENT_BYTES = 32_000_000
MAX_GRAFANA_BYTES = 32_000_000
MAX_STUDENT_BYTES = 24_000_000
MAX_ALERTMANAGER_BYTES = 2_000_000


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular(path, maximum):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
        raise RuntimeError("Unsafe or oversized durable source")
    return info


def bounded_tree(root_path, maximum_count, maximum_bytes, excluded=frozenset()):
    if root_path.is_symlink() or not root_path.is_dir():
        raise RuntimeError("Durable volume is unavailable")
    root_info = root_path.lstat()
    if not stat.S_ISDIR(root_info.st_mode):
        raise RuntimeError("Invalid durable root")
    found = []
    directories_found = [(Path('.'), root_info)]
    for root, directories, filenames in os.walk(root_path, followlinks=False):
        for directory in directories:
            path = Path(root) / directory
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise RuntimeError("Attachment directory symlink rejected")
            directories_found.append((path.relative_to(root_path), info))
        for filename in filenames:
            path = Path(root) / filename
            relative = path.relative_to(root_path)
            if relative.as_posix() in excluded:
                continue
            info = regular(path, maximum_bytes)
            found.append((path, relative, info))
    if len(found) > maximum_count or sum(item[2].st_size for item in found) > maximum_bytes:
        raise RuntimeError("Durable volume exceeds supplement bound")
    return (sorted(found, key=lambda item: item[1].as_posix()),
            sorted(directories_found, key=lambda item: item[0].as_posix()))


def metadata(info):
    return {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}


def tree_fingerprint(files, directories):
    return ([(item[1].as_posix(), item[2].st_ino, item[2].st_size, item[2].st_mtime_ns)
             for item in files],
            [(item[0].as_posix(), item[1].st_ino, item[1].st_mode) for item in directories])


def copy_tree(source, target, label, maximum_count, maximum_bytes, excluded=frozenset()):
    files, directories = bounded_tree(source, maximum_count, maximum_bytes, excluded)
    entries = []
    for relative, info in directories:
        destination = target / label / relative
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(destination, 0o700)
        entries.append({"name": (Path(label) / relative).as_posix(), "type": "directory", **metadata(info)})
    for path, relative, info in files:
        destination = target / label / relative
        copy_attachment(path, destination, info)
        entries.append({"name": (Path(label) / relative).as_posix(), "type": "file",
                        "bytes": destination.stat().st_size, "sha256": file_digest(destination), **metadata(info)})
    after = bounded_tree(source, maximum_count, maximum_bytes, excluded)
    if tree_fingerprint(files, directories) != tree_fingerprint(*after):
        raise RuntimeError("Durable volume changed during snapshot")
    return entries


def copy_attachment(source, destination, expected):
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination.parent, 0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    input_descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(input_descriptor)
        if (opened.st_ino, opened.st_size, opened.st_mtime_ns) != (expected.st_ino, expected.st_size, expected.st_mtime_ns):
            raise RuntimeError("Attachment changed before snapshot")
        descriptor = os.open(destination, flags, 0o600)
        with os.fdopen(input_descriptor, "rb") as input_stream, os.fdopen(descriptor, "wb") as output:
            input_descriptor = -1
            copied = 0
            for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                copied += len(chunk)
                if copied > MAX_ATTACHMENT_BYTES:
                    raise RuntimeError("Attachment grew beyond bound")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    finally:
        if input_descriptor >= 0:
            os.close(input_descriptor)
    actual = source.lstat()
    if (actual.st_ino, actual.st_size, actual.st_mtime_ns) != (expected.st_ino, expected.st_size, expected.st_mtime_ns):
        raise RuntimeError("Attachment changed during snapshot")
    if destination.stat().st_size != expected.st_size or file_digest(source) != file_digest(destination):
        raise RuntimeError("Attachment snapshot checksum differs")
    final = source.lstat()
    if (final.st_ino, final.st_size, final.st_mtime_ns) != (expected.st_ino, expected.st_size, expected.st_mtime_ns):
        raise RuntimeError("Attachment changed after checksum")


def snapshot_sqlite(source_path, destination, maximum_bytes):
    source_info = regular(source_path, maximum_bytes)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination.parent, 0o700)
    uri = source_path.as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=20) as source, sqlite3.connect(destination) as target:
        source.execute("PRAGMA query_only=ON")
        source.backup(target, pages=256, sleep=0.05)
        if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("Grafana SQLite snapshot failed integrity_check")
    os.chmod(destination, 0o600)
    if regular(destination, maximum_bytes).st_size == 0:
        raise RuntimeError("SQLite snapshot is empty")
    with destination.open("rb") as stream:
        os.fsync(stream.fileno())
    return source_info


def main():
    os.umask(0o077)
    if os.geteuid() != 0 or SOURCE.is_symlink() or not SOURCE.is_dir() or DESTINATION.exists() or DESTINATION.is_symlink():
        raise RuntimeError("Root-owned fresh supplement source required")
    if SOURCE.stat().st_uid != 0 or SOURCE.stat().st_mode & 0o077:
        raise RuntimeError("Unprotected supplement source")
    scratch = Path(tempfile.mkdtemp(prefix="durable-snapshot-", dir=WORK))
    os.chmod(scratch, 0o700)
    try:
        payload = scratch / "durable-volumes"
        payload.mkdir(mode=0o700)
        entries = copy_tree(ATTACHMENTS, payload, "attachments", MAX_ATTACHMENTS, MAX_ATTACHMENT_BYTES)
        entries += copy_tree(STUDENT_DATA, payload, "student-data", 1000, MAX_STUDENT_BYTES,
                             frozenset({"students.sqlite", "students.sqlite-wal", "students.sqlite-shm"}))
        entries += copy_tree(ALERTMANAGER_DATA, payload, "alertmanager", 100, MAX_ALERTMANAGER_BYTES)
        grafana_directory = GRAFANA_DB.parent.lstat()
        if not stat.S_ISDIR(grafana_directory.st_mode) or GRAFANA_DB.parent.is_symlink():
            raise RuntimeError("Grafana volume root is unavailable")
        entries.append({"name": "grafana", "type": "directory", **metadata(grafana_directory)})
        for name, source, maximum in (("grafana/grafana.db", GRAFANA_DB, MAX_GRAFANA_BYTES),
                                      ("student-data/students.sqlite", STUDENT_DATA / "students.sqlite", MAX_STUDENT_BYTES)):
            destination = payload / name
            source_info = snapshot_sqlite(source, destination, maximum)
            entries.append({"name": name, "type": "file", "bytes": destination.stat().st_size,
                            "sha256": file_digest(destination), "sqliteIntegrity": "ok", **metadata(source_info)})
        if sum(item.get("bytes", 0) for item in entries) > 60_000_000:
            raise RuntimeError("Durable payload exceeds supplement bound")
        index = {"schema": "platform.durable-volume-supplement/v2",
                 "capturedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 "productionModified": False, "files": entries}
        index_path = payload / "index.json"
        index_path.write_text(json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n")
        os.chmod(index_path, 0o600)
        for root, directories, files in os.walk(payload):
            for directory in directories:
                os.chmod(Path(root) / directory, 0o700)
            for filename in files:
                os.chmod(Path(root) / filename, 0o600)
        os.replace(payload, DESTINATION)
        for directory in (SOURCE, WORK):
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        print(json.dumps({"status": "staged", "fileCount": len(entries),
                          "bytes": sum(item.get("bytes", 0) for item in entries),
                          "indexSha256": file_digest(DESTINATION / "index.json"),
                          "productionModified": False}))
    finally:
        shutil.rmtree(scratch)


if __name__ == "__main__":
    main()
