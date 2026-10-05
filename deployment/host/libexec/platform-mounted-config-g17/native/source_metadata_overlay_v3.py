#!/usr/bin/env python3
"""Local-only, fail-closed source metadata overlay prototype.

The overlay carries metadata and an optional encrypted host capsule; it never
contains source file payloads. It may only be built after the 57 live trees
match the immutable v1 restored trees by path, type, bytes, and symlink target.
This is a forward g16 protocol candidate, not a production publisher.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import gzip
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import tarfile

SCHEMA = "platform.source-metadata-overlay/v3"
BASE_ARCHIVE_SHA256 = "77de6d262d269db484aa48fbe63ca064a151a9c5ecc081374bf9be4d3e034987"
BASE_ARCHIVE_BYTES = 14_123_697_104
FIXED_LIVE_ROOT = Path("/home/platform_infrastructure/v1-fresh-data/src")
EXPECTED_SOURCES_SHA256 = "7ca377a9e7e724c4aa475d2fda8f75402c4836113dd83af405c0d597732d3605"
EXPECTED_SOURCE_MAP_SHA256 = "f0a0157cb3c985790f4fbe3eb465a8ad757b7ee4e1b5b2e42dbab43b03aaa6a0"
MAX_SOURCES = 57
MAX_MEMBERS = 1_000_000
MAX_TOTAL_XATTR_BYTES = 256 * 1024 * 1024
MAX_EXTENSION_BYTES = 2_000_000_000
MAX_METADATA_UNCOMPRESSED = 512 * 1024 * 1024
MAX_METADATA_COMPRESSED = 513 * 1024 * 1024
MAX_CAPSULE_BYTES = 256 * 1024 * 1024
MAX_XATTR_COUNT = 128
MAX_XATTR_NAME = 1024
MAX_XATTR_VALUE = 65536
MAX_XATTR_MEMBER = 262144
FIXED_GPG_KEY = Path("/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase")
FIXED_GPG_UID = 1000
FIXED_GPG_GID = 1000
RESOURCE_RE = re.compile(r"source:[a-z0-9][a-z0-9._-]{0,179}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
EXPIRATION_CATALOG_SHA256 = "31a788278a35f189770996f4c224e1c67f9a7bb3223447e90ac7ae85354665f2"
EXPIRATION_BASE_PROOF_SHA256 = "a98afab03659fb1f833c8890dcaeb5876d454f80bc3d6f878a432174456b3be6"
EXPIRATION_RESOURCE = "source:stream"
EXPIRATION_BYTES = 239_265
EXPIRATION_COUNT = 15
EXPIRATION_PATH_RE = re.compile(r"private/cache/tmdb/([0-9a-f]{2})/([0-9a-f]{40})\.json\Z")


class Blocked(ValueError):
    pass


def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _xattrs(path: Path) -> list[dict]:
    try:
        names = os.listxattr(path, follow_symlinks=False)
        if len(names) > MAX_XATTR_COUNT:
            raise Blocked("xattr count bound exceeded")
        rows, total = [], 0
        for name in names:
            raw_name = os.fsencode(name)
            raw_value = os.getxattr(path, name, follow_symlinks=False)
            total += len(raw_name) + len(raw_value)
            if not raw_name or len(raw_name) > MAX_XATTR_NAME or len(raw_value) > MAX_XATTR_VALUE or total > MAX_XATTR_MEMBER:
                raise Blocked("xattr bounds exceeded")
            rows.append({"nameB64": base64.b64encode(raw_name).decode("ascii"),
                         "valueB64": base64.b64encode(raw_value).decode("ascii")})
        return sorted(rows, key=lambda r: r["nameB64"])
    except Blocked:
        raise
    except (OSError, AttributeError) as exc:
        raise Blocked("xattrs unavailable or unreadable") from exc


def inventory(root: Path) -> list[dict]:
    """Nofollow inventory, including all content identities and metadata."""
    root = Path(root).absolute()
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise Blocked("source root must be a canonical directory")
    rows = []
    stack = [(root, ".")]
    while stack:
        path, rel = stack.pop()
        info = path.lstat()
        mode = info.st_mode
        if stat.S_ISDIR(mode): kind = "directory"
        elif stat.S_ISREG(mode): kind = "file"
        elif stat.S_ISLNK(mode): kind = "symlink"
        else: raise Blocked("special source member")
        row = {"path": rel, "type": kind, "uid": info.st_uid, "gid": info.st_gid,
               "mode": stat.S_IMODE(mode), "mtimeNs": info.st_mtime_ns,
               "xattrs": _xattrs(path)}
        if kind == "file":
            row.update(size=info.st_size, sha256=sha_file(path),
                       hardlinkMaterialization="independent-file-copy")
        elif kind == "symlink":
            row["target"] = os.readlink(path)
        rows.append(row)
        if kind == "directory":
            try:
                children = sorted(os.scandir(path), key=lambda e: os.fsencode(e.name), reverse=True)
            except OSError as exc:
                raise Blocked("source directory unreadable") from exc
            for entry in children:
                # Keep raw filesystem names reversible and reject unsafe relpaths.
                name = os.fsdecode(os.fsencode(entry.name))
                if name in ("", ".", "..") or "/" in name or "\x00" in name:
                    raise Blocked("unsafe source name")
                try: name.encode("utf-8")
                except UnicodeEncodeError as exc: raise Blocked("non-UTF-8 source path unsupported") from exc
                child_rel = name if rel == "." else f"{rel}/{name}"
                stack.append((Path(entry.path), child_rel))
        if len(rows) > MAX_MEMBERS:
            raise Blocked("member count bound exceeded")
    rows.sort(key=lambda r: os.fsencode(r["path"]))
    return rows


def byte_identity(rows: list[dict]) -> list[dict]:
    """Project to the v1 invariant: exact names, types, bytes, and link targets."""
    return [{k: row[k] for k in ("path", "type", "size", "sha256", "target") if k in row}
            for row in rows]


def load_expected_sources(path: Path, live_root: Path | None) -> dict[str, str]:
    """Load the fixed, digest-pinned resourceId-to-live-basename map."""
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1 or sha_file(path) != EXPECTED_SOURCES_SHA256:
        raise Blocked("expected-sources catalog digest mismatch")
    live_root = Path(live_root).absolute() if live_root is not None else None
    if live_root is not None and (live_root.is_symlink() or live_root.resolve() != live_root or not live_root.is_dir()):
        raise Blocked("live source root is not canonical")
    try: data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc: raise Blocked("expected-sources catalog unreadable") from exc
    if data.get("schema") != "platform.isolated-stack-expected-sources/v1" or not isinstance(data.get("sources"), list) or len(data["sources"]) != MAX_SOURCES:
        raise Blocked("expected-sources schema/count mismatch")
    mapping = {}; common_root = None
    for row in data["sources"]:
        rid, source_path = row.get("resourceId"), row.get("sourcePath")
        if not isinstance(rid, str) or not RESOURCE_RE.fullmatch(rid) or not isinstance(source_path, str):
            raise Blocked("expected-sources row invalid")
        p = Path(source_path)
        if not p.is_absolute() or (live_root is not None and p.parent != live_root) or p.name in ("", ".", "..") or p.name in mapping.values():
            raise Blocked("expected-sources path escapes or duplicates root")
        if common_root is None: common_root = p.parent
        if p.parent != common_root: raise Blocked("expected-sources rows do not share a root")
        mapping[rid] = p.name
    if len(mapping) != MAX_SOURCES or len(set(mapping.values())) != MAX_SOURCES:
        raise Blocked("expected-sources mapping not unique")
    if hashlib.sha256(canonical({k: mapping[k] for k in sorted(mapping)})).hexdigest() != EXPECTED_SOURCE_MAP_SHA256:
        raise Blocked("expected-sources resource map digest mismatch")
    return mapping


def _read_source_map(root: Path, resource_to_dir: dict[str, str]) -> dict[str, Path]:
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise Blocked("source map root unsafe")
    found = {}
    if len(resource_to_dir) != MAX_SOURCES or len(set(resource_to_dir.values())) != MAX_SOURCES:
        raise Blocked("pinned source mapping must contain 57 unique paths")
    actual = {p.name for p in root.iterdir()}
    expected = set(resource_to_dir.values())
    if root == FIXED_LIVE_ROOT:
        if actual != expected | {".pnpm-store", "fireport"}:
            raise Blocked("fixed live root entries differ from pinned 57 sources and two declared extras")
        cache=root/".pnpm-store"; cache_info=cache.lstat()
        if (cache.is_symlink() or not stat.S_ISDIR(cache_info.st_mode) or cache_info.st_uid!=1000 or
                stat.S_IMODE(cache_info.st_mode)!=0o755):
            raise Blocked("declared pnpm cache is not the fixed UID1000 mode0755 directory")
        alias=root/"fireport"; alias_info=alias.lstat()
        if (not stat.S_ISLNK(alias_info.st_mode) or alias_info.st_uid!=1000 or
                os.readlink(alias)!="fiplatform" or alias.resolve(strict=True)!=(root/"fiplatform")):
            raise Blocked("declared fireport root alias differs from exact fiplatform symlink")
    elif actual != expected:
        raise Blocked("source directory set differs from pinned expected-sources map")
    for rid, dirname in resource_to_dir.items():
        entry = root / dirname
        if entry.is_symlink() or not entry.is_dir(): raise Blocked("expected source directory invalid")
        found[rid] = entry
    return found


def capture_live_root_entries(root: Path) -> list[dict]:
    """Record the sole authenticated root alias and explicitly exclude its derived cache."""
    root=Path(root).absolute()
    if root!=FIXED_LIVE_ROOT:
        return []
    _read_source_map(root,load_expected_sources(Path(__file__).with_name("expected-sources.json"),root))
    alias=root/"fireport"; info=alias.lstat()
    return [{"path":".pnpm-store","type":"directory","uid":1000,"mode":0o755,
             "policy":"exclude-derived-cache"},
            {"path":"fireport","type":"symlink","uid":info.st_uid,"gid":info.st_gid,
             "mode":stat.S_IMODE(info.st_mode),"mtimeNs":info.st_mtime_ns,"xattrs":_xattrs(alias),
             "target":"fiplatform","policy":"recreate-root-alias"}]


def validate_live_root_entries(entries: list[dict] | None) -> None:
    if entries==[]:
        return
    expected_cache={"path":".pnpm-store","type":"directory","uid":1000,"mode":0o755,
                    "policy":"exclude-derived-cache"}
    if not isinstance(entries,list) or len(entries)!=2 or entries[0]!=expected_cache:
        raise Blocked("root extra entries do not match the fixed cache exclusion and alias policy")
    alias=entries[1]
    if (not isinstance(alias,dict) or set(alias)!={"path","type","uid","gid","mode","mtimeNs","xattrs","target","policy"} or
        alias.get("path")!="fireport" or alias.get("type")!="symlink" or alias.get("target")!="fiplatform" or
        alias.get("policy")!="recreate-root-alias" or alias.get("uid")!=1000 or
        type(alias.get("gid")) is not int or alias.get("mode")!=0o777 or type(alias.get("mtimeNs")) is not int):
        raise Blocked("fireport alias metadata is invalid")
    _validate_metadata_record({"resource":"source:fireport","path":".","type":"symlink",
        "uid":alias["uid"],"gid":alias["gid"],"mode":alias["mode"],"mtimeNs":alias["mtimeNs"],
        "xattrs":alias["xattrs"],"target":alias["target"]})


def apply_live_root_entries(entries: list[dict], destination_root: Path) -> None:
    """Recreate only the authenticated root alias on a private restored tree."""
    validate_live_root_entries(entries)
    if entries==[]:return
    alias=entries[1]
    destination_root=Path(destination_root).absolute()
    if (destination_root.is_symlink() or not destination_root.is_dir() or destination_root.resolve()!=destination_root or
        destination_root.stat().st_uid!=os.geteuid() or destination_root.stat().st_mode&0o077):
        raise Blocked("alias destination must be a canonical caller-private directory")
    target=destination_root/"fireport"
    if target.exists() or target.is_symlink():raise Blocked("root alias destination already exists")
    if not (destination_root/"fiplatform").is_dir():raise Blocked("fiplatform target is missing from restored source root")
    os.symlink("fiplatform",target)
    os.chown(target,alias["uid"],alias["gid"],follow_symlinks=False)
    for attr in alias["xattrs"]:
        os.setxattr(target,base64.b64decode(attr["nameB64"],validate=True),
                    base64.b64decode(attr["valueB64"],validate=True),follow_symlinks=False)
    os.utime(target,ns=(alias["mtimeNs"],alias["mtimeNs"]),follow_symlinks=False)
    info=target.lstat()
    actual_attrs=[]
    for name in os.listxattr(target,follow_symlinks=False):
        raw_name=os.fsencode(name);raw_value=os.getxattr(target,name,follow_symlinks=False)
        actual_attrs.append({"nameB64":base64.b64encode(raw_name).decode("ascii"),
                             "valueB64":base64.b64encode(raw_value).decode("ascii")})
    actual_attrs.sort(key=lambda row:row["nameB64"])
    if (not stat.S_ISLNK(info.st_mode) or info.st_uid!=alias["uid"] or info.st_gid!=alias["gid"] or
            stat.S_IMODE(info.st_mode)!=alias["mode"] or info.st_mtime_ns!=alias["mtimeNs"] or
            actual_attrs!=alias["xattrs"] or os.readlink(target)!="fiplatform"):
        raise Blocked("recreated root alias verification failed")


def load_expiration_descriptor(path: Path | None = None) -> dict:
    """Load the sole approved one-off Stream cache expiration catalog."""
    path = Path(path) if path is not None else Path(__file__).with_name("stream-expired-cache-descriptor-actual.json")
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        raise Blocked("expiration catalog is not a single regular file")
    if sha_file(path) != EXPIRATION_CATALOG_SHA256:
        raise Blocked("expiration catalog digest is not the reviewed one-off descriptor")
    try:
        descriptor = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise Blocked("expiration catalog unreadable") from exc
    validate_expiration_descriptor(descriptor)
    return descriptor


def approved_expiration_entries() -> list[dict]:
    return validate_expiration_descriptor(load_expiration_descriptor())


def validate_expiration_descriptor(descriptor: dict) -> list[dict]:
    if not isinstance(descriptor, dict) or set(descriptor) != {"baseArchiveSha256", "baseSourceProofSha256", "changeCount", "files", "productionModified", "resourceId", "schema"}:
        raise Blocked("expiration descriptor has unknown fields")
    if (descriptor.get("schema") != "platform.approved-source-derived-cache-expiration/v1" or
        descriptor.get("resourceId") != EXPIRATION_RESOURCE or descriptor.get("productionModified") is not False or
        descriptor.get("baseArchiveSha256") != BASE_ARCHIVE_SHA256 or
        descriptor.get("baseSourceProofSha256") != EXPIRATION_BASE_PROOF_SHA256 or
        descriptor.get("changeCount") != EXPIRATION_COUNT):
        raise Blocked("expiration descriptor binding mismatch")
    entries = descriptor.get("files")
    if not isinstance(entries, list) or len(entries) != EXPIRATION_COUNT:
        raise Blocked("expiration descriptor must contain exactly 15 files")
    seen = set(); total = 0; normalized = []
    for row in entries:
        if not isinstance(row, dict) or set(row) != {"baseBytes", "baseSha256", "observed", "path", "resourceId", "type"}:
            raise Blocked("expiration descriptor entry fields invalid")
        match = EXPIRATION_PATH_RE.fullmatch(str(row.get("path", "")))
        if (not match or match.group(1) != match.group(2)[:2] or row.get("resourceId") != EXPIRATION_RESOURCE or
            row.get("type") != "file" or row.get("observed") != "absent" or
            type(row.get("baseBytes")) is not int or not 0 < row["baseBytes"] <= 1_000_000 or
            not HEX64.fullmatch(str(row.get("baseSha256", "")))):
            raise Blocked("expiration descriptor entry is outside the fixed TMDB cache policy")
        if row["path"] in seen:
            raise Blocked("duplicate expired cache path")
        seen.add(row["path"]); total += row["baseBytes"]; normalized.append(row)
    if total != EXPIRATION_BYTES or normalized != sorted(normalized, key=lambda r: r["path"]):
        raise Blocked("expiration descriptor byte total or order mismatch")
    return normalized


def filtered_base_identity(rows: list[dict], expiration_entries: list[dict]) -> list[dict]:
    expired = {row["path"] for row in expiration_entries}
    return byte_identity([row for row in rows if row["path"] not in expired])


def prune_expired_cache_files(private_root: Path, expiration_entries: list[dict]) -> None:
    """Remove only descriptor-bound regular files from a fresh private copy."""
    root = Path(private_root).absolute()
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise Blocked("private Stream copy root is not canonical")
    if expiration_entries == []:
        return
    approved = approved_expiration_entries()
    if expiration_entries != approved:
        raise Blocked("prune list differs from the pinned 15-file one-off descriptor")
    for entry in expiration_entries:
        if not isinstance(entry, dict):
            raise Blocked("expired cache descriptor entry invalid")
        rel = PurePosixPath(entry["path"])
        if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
            raise Blocked("expired cache path unsafe")
        current = root
        for part in rel.parts[:-1]:
            current = current / part
            try: info = current.lstat()
            except OSError as exc: raise Blocked("expired cache parent missing") from exc
            if not stat.S_ISDIR(info.st_mode):
                raise Blocked("expired cache parent is not a nofollow directory")
        target = current / rel.parts[-1]
        try: info = target.lstat()
        except OSError as exc: raise Blocked("expected expired cache file missing") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_size != entry["baseBytes"] or sha_file(target) != entry["baseSha256"]:
            raise Blocked("expired cache file identity differs from authenticated base descriptor")
        target.unlink()
        fd = os.open(current, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try: os.fsync(fd)
        finally: os.close(fd)


def capture_overlay(live_root: Path, v1_root: Path, parent_manifest_digest: str,
                    base_cipher_sha256: str, base_receipt_sha256: str,
                    capsule: Path | None, capsule_sha256: str | None,
                    capsule_proof_sha256: str | None,
                    resource_to_dir: dict[str, str],
                    base_archive_sha256: str = BASE_ARCHIVE_SHA256,
                    base_archive_bytes: int = BASE_ARCHIVE_BYTES) -> dict:
    """Capture metadata only if current live bytes equal the exact v1 restore."""
    if (not HEX64.fullmatch(parent_manifest_digest) or not HEX64.fullmatch(base_cipher_sha256) or
        not HEX64.fullmatch(base_receipt_sha256) or not HEX64.fullmatch(base_archive_sha256) or
        type(base_archive_bytes) is not int or not 0 < base_archive_bytes <= 70_000_000_000):
        raise Blocked("full parent/base SHA-256 and archive-size bindings required")
    live = _read_source_map(live_root, resource_to_dir)
    baseline = _read_source_map(v1_root, resource_to_dir)
    root_entries_before=capture_live_root_entries(live_root)
    if hashlib.sha256(canonical({k: resource_to_dir[k] for k in sorted(resource_to_dir)})).hexdigest() != EXPECTED_SOURCE_MAP_SHA256:
        raise Blocked("source mapping was not loaded from pinned expected-sources catalog")
    if set(live) != set(baseline):
        raise Blocked("source resource set differs from v1 restore")
    approved_entries = []
    if base_archive_sha256 == BASE_ARCHIVE_SHA256 and base_archive_bytes == BASE_ARCHIVE_BYTES:
        approved_entries = approved_expiration_entries()
    before = {}
    for rid in sorted(live):
        before[rid] = inventory(live[rid])
        base_rows = inventory(baseline[rid])
        if rid == EXPIRATION_RESOURCE:
            live_paths = {row["path"] for row in before[rid]}
            base_by_path = {row["path"]: row for row in base_rows}
            if approved_entries:
                expired_paths = {row["path"] for row in approved_entries}
                missing = expired_paths - live_paths
                if missing and missing != expired_paths:
                    raise Blocked("only a partial subset of the approved Stream cache expirations is missing")
                for entry in approved_entries:
                    row = base_by_path.get(entry["path"])
                    if row is None or row.get("type") != "file" or row.get("size") != entry["baseBytes"] or row.get("sha256") != entry["baseSha256"]:
                        raise Blocked("approved cache descriptor does not match immutable v1 Stream source")
                if missing == expired_paths and filtered_base_identity(base_rows, approved_entries) != byte_identity(before[rid]):
                    raise Blocked("live Stream differs beyond the exact approved 15 expired cache files")
                if not missing and byte_identity(before[rid]) != byte_identity(base_rows):
                    raise Blocked("live Stream differs from v1 despite no approved cache expiry")
                expiration_entries = approved_entries if missing else []
            else:
                if byte_identity(before[rid]) != byte_identity(base_rows):
                    raise Blocked(f"live source differs from v1 bytes/names/targets: {rid}")
                expiration_entries = []
        elif byte_identity(before[rid]) != byte_identity(base_rows):
            raise Blocked(f"live source differs from v1 bytes/names/targets: {rid}")
    if capsule is not None:
        if not capsule_sha256 or not capsule_proof_sha256 or not HEX64.fullmatch(capsule_sha256) or not HEX64.fullmatch(capsule_proof_sha256):
            raise Blocked("capsule requires full ciphertext and proof digests")
        if capsule.is_symlink() or not capsule.is_file() or capsule.stat().st_nlink != 1 or sha_file(capsule) != capsule_sha256:
            raise Blocked("capsule identity mismatch")
    elif capsule_sha256 or capsule_proof_sha256:
        raise Blocked("capsule digests supplied without capsule")
    # A second full walk catches concurrent writes/renames during capture.
    for rid in sorted(live):
        after = inventory(live[rid])
        if before[rid] != after:
            raise Blocked(f"live source changed during metadata capture: {rid}")
    root_entries_after=capture_live_root_entries(live_root)
    if root_entries_before!=root_entries_after:
        raise Blocked("live root alias/cache declaration changed during metadata capture")
    records = [{"resource": rid, **row} for rid in sorted(before) for row in before[rid]]
    xattr_bytes = sum(len(base64.b64decode(x["nameB64"])) + len(base64.b64decode(x["valueB64"]))
                      for row in records for x in row["xattrs"])
    if xattr_bytes > MAX_TOTAL_XATTR_BYTES:
        raise Blocked("total xattr bound exceeded")
    return {
        "schema": SCHEMA, "protocolGeneration": 16,
        "parent": {"manifestDigest": parent_manifest_digest},
        "base": {"kind": "full-runtime-v1", "ciphertextSha256": base_cipher_sha256,
                 "receiptSha256": base_receipt_sha256, "archiveSha256": base_archive_sha256,
                 "archiveBytes": base_archive_bytes, "payloadIncluded": False},
        "sourceCapture": {"mode": "metadata-overlay-only", "sourceCount": 57,
                          "recordCount": len(records), "hardlinkPolicy": "materialized-independent-files",
                          "byteInvariant": ("exact-v1-path-type-bytes-symlink-targets-after-approved-cache-expiry" if expiration_entries else "exact-v1-path-type-bytes-symlink-targets"),
                          "expectedSourcesSha256": EXPECTED_SOURCES_SHA256,
                          "sourceMapSha256": EXPECTED_SOURCE_MAP_SHA256,
                          "liveRootEntries": root_entries_before,
                          "expiredDerivedCacheFiles": ({"catalogSha256": EXPIRATION_CATALOG_SHA256,
                                                       "entries": expiration_entries} if expiration_entries else [])},
        "records": records,
        "capsule": ({"ciphertextSha256": capsule_sha256, "proofSha256": capsule_proof_sha256,
                     "sizeBytes": capsule.stat().st_size, "member": "host-capsule/current.gpg"} if capsule else None),
        "claims": {"offsiteVerified": False, "fullyRecoverable": False,
                   "wholeStackRestoreVerified": False}
    }


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_receipt(payload: dict, hmac_key: bytes) -> tuple[dict, bytes]:
    if len(hmac_key) < 32:
        raise Blocked("HMAC key must have at least 256 bits")
    records = payload.get("records")
    if not isinstance(records, list) or len(records) > MAX_MEMBERS:
        raise Blocked("record list missing or over bound")
    source_capture = payload.get("sourceCapture")
    expiry_binding = source_capture.get("expiredDerivedCacheFiles") if isinstance(source_capture, dict) else None
    base_binding = payload.get("base", {})
    if expiry_binding == []:
        if source_capture.get("byteInvariant") != "exact-v1-path-type-bytes-symlink-targets":
            raise Blocked("no-expiry capture must explicitly assert exact v1 byte identity")
    else:
        approved_expiry = approved_expiration_entries()
        if (not isinstance(expiry_binding, dict) or set(expiry_binding) != {"catalogSha256", "entries"} or
            expiry_binding.get("catalogSha256") != EXPIRATION_CATALOG_SHA256 or expiry_binding.get("entries") != approved_expiry or
            base_binding.get("archiveSha256") != BASE_ARCHIVE_SHA256 or base_binding.get("archiveBytes") != BASE_ARCHIVE_BYTES):
            raise Blocked("receipt signing requires the fixed approved expiration descriptor and historical base")
    expected_map = load_expected_sources(Path(__file__).with_name("expected-sources.json"), None)
    expected_ids = set(expected_map)
    if {r.get("resource") for r in records if isinstance(r, dict)} != expected_ids:
        raise Blocked("metadata resource IDs differ from pinned expected-sources catalog")
    seen = set(); path_types = {}; root_ids = set()
    for row in records:
        _validate_metadata_record(row)
        key = (row["resource"], row["path"])
        if key in seen: raise Blocked("duplicate metadata record path")
        seen.add(key); path_types.setdefault(row["resource"], {})[row["path"]] = row["type"]
        if row["path"] == ".": root_ids.add(row["resource"])
    if root_ids != expected_ids: raise Blocked("metadata roots differ from pinned expected-sources catalog")
    for resource, paths in path_types.items():
        for rel in paths:
            if rel == ".": continue
            parent = str(PurePosixPath(rel).parent) or "."
            if paths.get(parent) != "directory": raise Blocked("metadata parent is missing or not a directory")
    raw = io.BytesIO()
    for record in records:
        raw.write(canonical(record) + b"\n")
        if raw.tell() > MAX_METADATA_UNCOMPRESSED: raise Blocked("metadata index exceeds 512 MiB")
    raw_bytes = raw.getvalue()
    compressed = gzip.compress(raw_bytes, compresslevel=6, mtime=0)
    payload = dict(payload)
    payload.pop("records", None)
    payload["metadataIndex"] = {
        "member": "metadata/records.ndjson.gz", "encoding": "gzip-ndjson-json-canonical-v1",
        "sha256": hashlib.sha256(compressed).hexdigest(), "compressedBytes": len(compressed),
        "rawSha256": hashlib.sha256(raw_bytes).hexdigest(), "rawBytes": len(raw_bytes),
        "recordCount": len(records), "maxRawBytes": MAX_METADATA_UNCOMPRESSED,
    }
    digest = hashlib.sha256(canonical(payload)).hexdigest()
    return ({"schema": "platform.source-metadata-overlay-receipt/v3", "payload": payload,
            "payloadSha256": digest,
            "hmacSha256": hmac.new(hmac_key, canonical(payload), hashlib.sha256).hexdigest()}, compressed)


def verify_receipt(receipt: dict, hmac_key: bytes, expected_parent: str,
                   expected_base_cipher: str, expected_base_receipt: str,
                   expected_archive_sha256: str = BASE_ARCHIVE_SHA256,
                   expected_archive_bytes: int = BASE_ARCHIVE_BYTES) -> None:
    if receipt.get("schema") != "platform.source-metadata-overlay-receipt/v3": raise Blocked("receipt schema mismatch")
    if set(receipt) != {"schema", "payload", "payloadSha256", "hmacSha256"}: raise Blocked("receipt has unknown fields")
    payload = receipt.get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA or payload.get("protocolGeneration") != 16:
        raise Blocked("unsupported typed extension")
    if set(payload) != {"schema", "protocolGeneration", "parent", "base", "sourceCapture", "metadataIndex", "capsule", "claims"}:
        raise Blocked("typed extension has unknown fields")
    if payload.get("parent", {}).get("manifestDigest") != expected_parent: raise Blocked("parent mismatch")
    base = payload.get("base", {})
    if set(base) != {"kind", "ciphertextSha256", "receiptSha256", "archiveSha256", "archiveBytes", "payloadIncluded"}:
        raise Blocked("base binding has unknown fields")
    if base.get("ciphertextSha256") != expected_base_cipher or base.get("receiptSha256") != expected_base_receipt or base.get("payloadIncluded") is not False:
        raise Blocked("base supplement mismatch")
    if (base.get("archiveSha256") != expected_archive_sha256 or base.get("archiveBytes") != expected_archive_bytes or
        not isinstance(base.get("archiveSha256"), str) or not HEX64.fullmatch(base["archiveSha256"]) or
        type(base.get("archiveBytes")) is not int or not 0 < base["archiveBytes"] <= 70_000_000_000):
        raise Blocked("base archive identity mismatch")
    if receipt.get("payloadSha256") != hashlib.sha256(canonical(payload)).hexdigest(): raise Blocked("payload digest mismatch")
    actual = hmac.new(hmac_key, canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(receipt.get("hmacSha256", "")), actual): raise Blocked("receipt authentication failed")
    if payload.get("claims") != {"offsiteVerified": False, "fullyRecoverable": False, "wholeStackRestoreVerified": False}:
        raise Blocked("candidate may not assert production recovery")
    index = payload.get("metadataIndex")
    if isinstance(index, dict) and set(index) != {"member", "encoding", "sha256", "compressedBytes", "rawSha256", "rawBytes", "recordCount", "maxRawBytes"}:
        raise Blocked("metadata index has unknown fields")
    if (not isinstance(index, dict) or index.get("member") != "metadata/records.ndjson.gz" or
        index.get("encoding") != "gzip-ndjson-json-canonical-v1" or
        not isinstance(index.get("sha256"), str) or not HEX64.fullmatch(index["sha256"]) or
        type(index.get("compressedBytes")) is not int or not 0 <= index["compressedBytes"] <= MAX_EXTENSION_BYTES or
        type(index.get("rawBytes")) is not int or not 0 <= index["rawBytes"] <= MAX_METADATA_UNCOMPRESSED or
        index.get("maxRawBytes") != MAX_METADATA_UNCOMPRESSED or type(index.get("recordCount")) is not int or
        not 1 <= index["recordCount"] <= MAX_MEMBERS or not HEX64.fullmatch(str(index.get("rawSha256", "")))):
        raise Blocked("metadata index descriptor invalid")
    if payload.get("sourceCapture", {}).get("recordCount") != index["recordCount"]: raise Blocked("record count mismatch")
    source_capture = payload.get("sourceCapture", {})
    if not isinstance(source_capture, dict) or set(source_capture) != {"mode", "sourceCount", "recordCount", "hardlinkPolicy", "byteInvariant", "expectedSourcesSha256", "sourceMapSha256", "liveRootEntries", "expiredDerivedCacheFiles"}:
        raise Blocked("source capture descriptor has unknown fields")
    if (source_capture.get("sourceCount") != MAX_SOURCES or
        source_capture.get("mode") != "metadata-overlay-only" or
        source_capture.get("hardlinkPolicy") != "materialized-independent-files" or
        source_capture.get("expectedSourcesSha256") != EXPECTED_SOURCES_SHA256 or
        source_capture.get("sourceMapSha256") != EXPECTED_SOURCE_MAP_SHA256):
        raise Blocked("source capture policy mismatch")
    validate_live_root_entries(source_capture.get("liveRootEntries"))
    expiry = source_capture.get("expiredDerivedCacheFiles")
    if expiry == []:
        if source_capture.get("byteInvariant") != "exact-v1-path-type-bytes-symlink-targets":
            raise Blocked("no-expiry receipt does not assert exact v1 byte identity")
    else:
        if (not isinstance(expiry, dict) or set(expiry) != {"catalogSha256", "entries"} or
            expiry.get("catalogSha256") != EXPIRATION_CATALOG_SHA256 or
            base.get("archiveSha256") != BASE_ARCHIVE_SHA256 or base.get("archiveBytes") != BASE_ARCHIVE_BYTES or
            validate_expiration_descriptor(load_expiration_descriptor()) != expiry.get("entries")):
            raise Blocked("receipt cache expiration entries differ from the pinned historical descriptor")
    capsule = payload.get("capsule")
    if isinstance(capsule, dict) and set(capsule) != {"ciphertextSha256", "proofSha256", "sizeBytes", "member"}:
        raise Blocked("capsule binding has unknown fields")
    if (not isinstance(capsule, dict) or capsule.get("member") != "host-capsule/current.gpg" or
        not HEX64.fullmatch(str(capsule.get("ciphertextSha256", ""))) or
        not HEX64.fullmatch(str(capsule.get("proofSha256", ""))) or
        type(capsule.get("sizeBytes")) is not int or not 0 < capsule["sizeBytes"] <= MAX_CAPSULE_BYTES):
        raise Blocked("capsule typed binding invalid")


def package_extension(receipt: dict, metadata_gzip: bytes, capsule: Path, output: Path) -> tuple[str, int]:
    """Create an unencrypted local package for the forward g16 publisher."""
    capsule = Path(capsule)
    if capsule.is_symlink() or not capsule.is_file() or capsule.stat().st_nlink != 1:
        raise Blocked("unsafe capsule input")
    ref = receipt.get("payload", {}).get("capsule")
    if not isinstance(ref, dict) or ref.get("ciphertextSha256") != sha_file(capsule):
        raise Blocked("capsule is not bound by typed receipt")
    index = receipt.get("payload", {}).get("metadataIndex", {})
    if (not isinstance(metadata_gzip, bytes) or len(metadata_gzip) != index.get("compressedBytes") or
        hashlib.sha256(metadata_gzip).hexdigest() != index.get("sha256")):
        raise Blocked("metadata index is not bound by typed receipt")
    size = capsule.stat().st_size + len(canonical(receipt)) + len(metadata_gzip)
    if size > MAX_EXTENSION_BYTES: raise Blocked("overlay extension exceeds 2GB bound")
    output = Path(output)
    if output.exists() or output.is_symlink(): raise Blocked("package output already exists")
    _private_output_parent(output)
    with tarfile.open(output, "w:gz", format=tarfile.USTAR_FORMAT) as tf:
        receipt_bytes = canonical(receipt) + b"\n"
        import io
        info = tarfile.TarInfo("receipt.json")
        info.size = len(receipt_bytes); info.mode = 0o600; info.uid = info.gid = 0
        tf.addfile(info, io.BytesIO(receipt_bytes))
        meta_info = tarfile.TarInfo("metadata/records.ndjson.gz")
        meta_info.size = len(metadata_gzip); meta_info.mode = 0o600; meta_info.uid = meta_info.gid = 0
        tf.addfile(meta_info, io.BytesIO(metadata_gzip))
        tf.add(capsule, arcname="host-capsule/current.gpg", recursive=False)
    os.chmod(output, 0o600)
    final_size = output.stat().st_size
    if final_size > MAX_EXTENSION_BYTES:
        output.unlink(missing_ok=True)
        raise Blocked("compressed overlay extension exceeds 2GB bound")
    return sha_file(output), final_size


def _validate_metadata_record(row: dict) -> None:
    if not isinstance(row, dict): raise Blocked("invalid metadata record")
    rid, rel, kind = row.get("resource"), row.get("path"), row.get("type")
    if not isinstance(rid, str) or not RESOURCE_RE.fullmatch(rid): raise Blocked("invalid resource id")
    if not isinstance(rel, str) or rel.startswith("/") or "\\" in rel or "\x00" in rel or (rel != "." and any(p in ("", ".", "..") for p in rel.split("/"))):
        raise Blocked("unsafe relative path")
    if kind not in ("directory", "file", "symlink"): raise Blocked("invalid object type")
    if (type(row.get("uid")) is not int or row["uid"] < 0 or type(row.get("gid")) is not int or row["gid"] < 0 or
        type(row.get("mode")) is not int or not 0 <= row["mode"] <= 0o7777 or
        type(row.get("mtimeNs")) is not int or not -(2**63) < row["mtimeNs"] < 2**63):
        raise Blocked("invalid ownership or timestamp")
    attrs = row.get("xattrs")
    if not isinstance(attrs, list) or len(attrs) > MAX_XATTR_COUNT: raise Blocked("invalid xattr list")
    attr_names = set(); attr_total = 0
    for attr in attrs:
        if not isinstance(attr, dict): raise Blocked("invalid xattr entry")
        try:
            name = base64.b64decode(attr["nameB64"], validate=True)
            value = base64.b64decode(attr["valueB64"], validate=True)
        except (KeyError, ValueError, TypeError): raise Blocked("invalid xattr encoding") from None
        if not name or len(name) > MAX_XATTR_NAME or len(value) > MAX_XATTR_VALUE or name in attr_names:
            raise Blocked("xattr bounds or duplicate name")
        attr_names.add(name); attr_total += len(name) + len(value)
    if attr_total > MAX_XATTR_MEMBER: raise Blocked("per-record xattr bound exceeded")
    if kind == "file" and (type(row.get("size")) is not int or row["size"] < 0 or not isinstance(row.get("sha256"), str) or not HEX64.fullmatch(row["sha256"]) or row.get("hardlinkMaterialization") != "independent-file-copy"):
        raise Blocked("invalid file content identity")
    if kind == "symlink" and (not isinstance(row.get("target"), str) or not row["target"] or row["target"].startswith("/") or "\x00" in row["target"]):
        raise Blocked("symlink target invalid")
    if kind == "symlink":
        stack = [] if rel == "." else rel.split("/")[:-1]
        for part in row["target"].split("/"):
            if part in ("", "."): continue
            if part == "..":
                if not stack: raise Blocked("symlink target escapes source root")
                stack.pop()
            else: stack.append(part)


def validate_metadata_gzip(path: Path, index: dict, expected_resource_ids: set[str],
                           expired_paths: set[str] | None = None) -> list[str]:
    raw_digest = hashlib.sha256(); raw_bytes = 0; count = 0; total_xattrs = 0
    last_resource = None; last_path = None
    types: dict[str, dict[str, str]] = {}; roots = set()
    try:
        with gzip.open(path, "rb") as stream:
            while True:
                line = stream.readline(1024 * 1024 + 1)
                if not line: break
                if len(line) > 1024 * 1024 or not line.endswith(b"\n"):
                    raise Blocked("metadata record line bound or termination invalid")
                raw_bytes += len(line)
                if raw_bytes > MAX_METADATA_UNCOMPRESSED: raise Blocked("metadata decompression limit exceeded")
                raw_digest.update(line)
                try: row = json.loads(line)
                except json.JSONDecodeError as exc: raise Blocked("metadata record JSON invalid") from exc
                if canonical(row) + b"\n" != line: raise Blocked("metadata record is not canonical")
                _validate_metadata_record(row)
                rid, rel = row["resource"], row["path"]
                if rid == EXPIRATION_RESOURCE and expired_paths and rel in expired_paths:
                    raise Blocked("metadata unexpectedly reintroduces an approved expired cache path")
                if last_resource is not None and (rid < last_resource or (rid == last_resource and os.fsencode(rel) <= os.fsencode(last_path))):
                    raise Blocked("metadata records not strictly ordered")
                last_resource, last_path = rid, rel
                types.setdefault(rid, {})[rel] = row["type"]
                if rel == ".":
                    if row["type"] != "directory": raise Blocked("source root record must be a directory")
                    roots.add(rid)
                for attr in row["xattrs"]:
                    total_xattrs += len(base64.b64decode(attr["nameB64"])) + len(base64.b64decode(attr["valueB64"]))
                count += 1
                if count > MAX_MEMBERS or total_xattrs > MAX_TOTAL_XATTR_BYTES:
                    raise Blocked("metadata aggregate bound exceeded")
    except (OSError, EOFError) as exc:
        raise Blocked("metadata gzip stream invalid") from exc
    if raw_bytes != index["rawBytes"] or raw_digest.hexdigest() != index["rawSha256"] or count != index["recordCount"]:
        raise Blocked("metadata uncompressed identity/count mismatch")
    if set(types) != expected_resource_ids or roots != expected_resource_ids:
        raise Blocked("metadata resource IDs differ from pinned expected-sources catalog")
    for rid, paths in types.items():
        for rel in paths:
            if rel == ".": continue
            parent = str(PurePosixPath(rel).parent)
            if parent == "": parent = "."
            if paths.get(parent) != "directory": raise Blocked("metadata path parent missing or not directory")
    return sorted(types)


def read_package(package: Path, capsule_out: Path, metadata_out: Path, hmac_key: bytes,
                 expected_parent: str, expected_base_cipher: str,
                 expected_base_receipt: str, expected_source_map_sha256: str,
                 expected_archive_sha256: str = BASE_ARCHIVE_SHA256,
                 expected_archive_bytes: int = BASE_ARCHIVE_BYTES,
                 return_membership: bool = False) -> dict:
    """Read restricted USTAR+gzip package with an aggregate decompression bound."""
    package = Path(package)
    if package.is_symlink() or not package.is_file() or package.stat().st_nlink != 1 or package.stat().st_size > MAX_EXTENSION_BYTES:
        raise Blocked("unsafe or oversized extension package")
    metadata_out = Path(metadata_out); capsule_out = Path(capsule_out)
    _private_output_parent(metadata_out); _private_output_parent(capsule_out)
    if metadata_out.exists() or metadata_out.is_symlink() or capsule_out.exists() or capsule_out.is_symlink():
        raise Blocked("package output already exists")
    try:
        receipt=None;source_resource_ids=None;expected_order=["receipt.json","metadata/records.ndjson.gz","host-capsule/current.gpg"]
        total_raw=0
        with package.open('rb') as raw, gzip.GzipFile(fileobj=raw,mode='rb') as stream:
            def read_exact(size):
                nonlocal total_raw
                if type(size) is not int or size<0 or total_raw+size>1_000_000_000:
                    raise Blocked('decompressed tar stream exceeds 1GB bound')
                chunks=[];remaining=size
                while remaining:
                    block=stream.read(min(65536,remaining))
                    if not block:raise Blocked('truncated USTAR stream')
                    chunks.append(block);remaining-=len(block);total_raw+=len(block)
                return b''.join(chunks)
            for index_no,name in enumerate(expected_order):
                header=read_exact(512)
                if header==bytes(512):raise Blocked('early tar terminator')
                stored_name=header[:100].split(b'\0',1)[0]
                prefix=header[345:500].split(b'\0',1)[0]
                if prefix or stored_name.decode('ascii','strict')!=name:
                    raise Blocked('USTAR member path or prefix invalid')
                typeflag=header[156:157]
                if typeflag not in (b'\0',b'0') or header[157:257].strip(b'\0'):
                    raise Blocked('USTAR links and extended headers are forbidden')
                try:
                    checksum=int(header[148:156].rstrip(b'\0 ').decode('ascii'),8)
                    size=int(header[124:136].rstrip(b'\0 ').decode('ascii'),8)
                except (ValueError,UnicodeDecodeError):raise Blocked('USTAR numeric field invalid') from None
                checksum_header=bytearray(header);checksum_header[148:156]=b' '*8
                if sum(checksum_header)!=checksum:raise Blocked('USTAR header checksum mismatch')
                limit=(8*1024*1024 if index_no==0 else MAX_METADATA_COMPRESSED if index_no==1 else MAX_CAPSULE_BYTES)
                if size>limit:raise Blocked('USTAR member size exceeds its bound')
                if index_no==0:
                    raw_receipt=read_exact(size)
                    try:receipt=json.loads(raw_receipt)
                    except json.JSONDecodeError as exc:raise Blocked('overlay receipt JSON invalid') from exc
                    verify_receipt(receipt,hmac_key,expected_parent,expected_base_cipher,expected_base_receipt,
                                   expected_archive_sha256,expected_archive_bytes)
                    if (expected_source_map_sha256!=EXPECTED_SOURCE_MAP_SHA256 or
                        receipt['payload']['sourceCapture']['sourceMapSha256']!=EXPECTED_SOURCE_MAP_SHA256):
                        raise Blocked('expected source map binding mismatch')
                    expected_size=None
                else:
                    descriptor=receipt['payload']['metadataIndex'] if index_no==1 else receipt['payload']['capsule']
                    expected_size=descriptor['compressedBytes'] if index_no==1 else descriptor['sizeBytes']
                    if size!=expected_size:raise Blocked('USTAR member size differs from receipt')
                    out_path=metadata_out if index_no==1 else capsule_out
                    expected_sha=descriptor['sha256'] if index_no==1 else descriptor['ciphertextSha256']
                    fd=os.open(out_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
                    digest=hashlib.sha256();remaining=size
                    try:
                        with os.fdopen(fd,'wb') as output:
                            while remaining:
                                block=read_exact(min(65536,remaining));output.write(block);digest.update(block);remaining-=len(block)
                            output.flush();os.fsync(output.fileno())
                        if digest.hexdigest()!=expected_sha:raise Blocked('extension member digest mismatch')
                        if index_no==1:
                            expected_map=load_expected_sources(Path(__file__).with_name('expected-sources.json'),None)
                            expiry=receipt['payload']['sourceCapture']['expiredDerivedCacheFiles']
                            expired_paths={row['path'] for row in expiry['entries']} if isinstance(expiry,dict) else set()
                            source_resource_ids=validate_metadata_gzip(out_path,descriptor,set(expected_map),expired_paths)
                    except Exception:
                        try:out_path.unlink()
                        except OSError:pass
                        raise
                padding=(-size)%512
                if padding:
                    pad=read_exact(padding)
                    if any(pad):raise Blocked('USTAR padding must be zero')
            terminator=read_exact(1024)
            if any(terminator):raise Blocked('USTAR end marker invalid')
            while True:
                tail=stream.read(65536)
                if not tail:break
                total_raw+=len(tail)
                if total_raw>1_000_000_000:raise Blocked('decompressed tar stream exceeds 1GB bound')
                if any(tail):raise Blocked('trailing nonzero USTAR data')
        if receipt is None:raise Blocked('overlay receipt missing')
        if return_membership:
            if not isinstance(source_resource_ids,list):raise Blocked("source membership derivation missing")
            return receipt,source_resource_ids
        return receipt
    except (OSError,EOFError,gzip.BadGzipFile,UnicodeDecodeError) as exc:
        for output in (metadata_out,capsule_out):
            try:output.unlink()
            except OSError:pass
        raise Blocked('extension package unreadable') from exc


def apply_to_private_copy(v1_root: Path, records: list[dict], destination: Path,
                          resource_to_dir: dict[str, str], expiration_entries: list[dict] | None = None) -> None:
    """Apply records to private copies, then verify exact metadata and file bytes."""
    source_map = _read_source_map(v1_root, resource_to_dir)
    dest = Path(destination).absolute()
    _private_output_parent(dest)
    if dest.parent != Path(destination).parent.absolute():
        raise Blocked("destination path is not canonical")
    if dest.exists() or dest.is_symlink(): raise Blocked("destination already exists")
    dest.mkdir(mode=0o700, parents=False)
    by_source: dict[str, list[dict]] = {}
    for row in records:
        rid = row.get("resource")
        if rid not in source_map: raise Blocked("record references unknown source")
        by_source.setdefault(rid, []).append(row)
    if set(by_source) != set(source_map): raise Blocked("metadata does not cover 57 sources")
    expiration_entries = expiration_entries if expiration_entries is not None else []
    if expiration_entries and expiration_entries != approved_expiration_entries():
        raise Blocked("private copy expiration list differs from the SHA-pinned approved descriptor")
    for rid, base in source_map.items():
        target = dest / resource_to_dir[rid]
        shutil.copytree(base, target, symlinks=True, copy_function=shutil.copyfile)
        rows = by_source[rid]
        expected_paths = {r["path"] for r in rows}
        base_rows = inventory(base)
        if rid == EXPIRATION_RESOURCE:
            if expiration_entries:
                prune_expired_cache_files(target, expiration_entries)
            base_paths = {row["path"] for row in base_rows} - {row["path"] for row in expiration_entries}
        else:
            base_paths = {row["path"] for row in base_rows}
        if len(expected_paths) != len(rows) or expected_paths != base_paths:
            raise Blocked("record path set differs from pruned private v1 copy")
        # Non-directories first, then directories deepest-first so directory
        # timestamps survive child metadata operations.
        ordered = sorted(rows, key=lambda r: (r["type"] == "directory", -r["path"].count("/")))
        for row in ordered:
            rel = row["path"]
            path = target if rel == "." else target.joinpath(*PurePosixPath(rel).parts)
            if path.is_symlink() and row["type"] != "symlink": raise Blocked("nofollow type mismatch")
            info = path.lstat()
            kind = "directory" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "special"
            if kind != row["type"]: raise Blocked("private copy type mismatch")
            os.chown(path, int(row["uid"]), int(row["gid"]), follow_symlinks=False)
            wanted_xattrs = {base64.b64decode(x["nameB64"], validate=True) for x in row["xattrs"]}
            for current_name in os.listxattr(path, follow_symlinks=False):
                raw_current = os.fsencode(current_name)
                if raw_current not in wanted_xattrs:
                    os.removexattr(path, current_name, follow_symlinks=False)
            for x in row["xattrs"]:
                os.setxattr(path, base64.b64decode(x["nameB64"], validate=True),
                            base64.b64decode(x["valueB64"], validate=True), follow_symlinks=False)
            if kind != "symlink": os.chmod(path, int(row["mode"]), follow_symlinks=False)
            os.utime(path, ns=(int(row["mtimeNs"]), int(row["mtimeNs"])), follow_symlinks=False)
        verified = inventory(target)
        expected = [{k: r[k] for k in ("path", "type", "uid", "gid", "mode", "mtimeNs", "xattrs", "size", "sha256", "target", "hardlinkMaterialization") if k in r}
                    for r in rows]
        actual = [{k: r[k] for k in ("path", "type", "uid", "gid", "mode", "mtimeNs", "xattrs", "size", "sha256", "target", "hardlinkMaterialization") if k in r}
                  for r in verified]
        if actual != expected: raise Blocked("private overlay application verification failed")


def _load_key(path: Path) -> bytes:
    path = Path(path)
    if path != FIXED_GPG_KEY: raise Blocked("key path is not the pinned recovery key")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != FIXED_GPG_UID or
            before.st_gid != FIXED_GPG_GID or stat.S_IMODE(before.st_mode) != 0o600 or
            before.st_nlink != 1 or before.st_size <= 0 or before.st_size > 65536):
            raise Blocked("recovery key ownership or mode differs from the pinned file")
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or (before.st_dev, before.st_ino, before.st_uid, before.st_gid,
            before.st_mode, before.st_nlink) != (current.st_dev, current.st_ino, current.st_uid,
            current.st_gid, current.st_mode, current.st_nlink):
            raise Blocked("recovery key path changed during open")
        if path.resolve(strict=True) != path:
            raise Blocked("recovery key path is not canonical")
        for parent in (path.parent, *path.parent.parents):
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise Blocked("recovery key has an aliased parent")
        chunks = []; total = 0
        while True:
            block = os.read(fd, 4096)
            if not block: break
            total += len(block)
            if total > 65536: raise Blocked("recovery key exceeds bound")
            chunks.append(block)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise Blocked("recovery key changed while reading")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _private_output_parent(path: Path) -> Path:
    parent = path.parent.absolute()
    if parent.is_symlink() or not parent.is_dir() or parent.resolve() != parent:
        raise Blocked("output parent must be a canonical directory")
    info = parent.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise Blocked("output parent must be caller-owned mode 0700")
    return parent


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    cap = sub.add_parser("capture")
    for name in ("live-root", "v1-root", "expected-sources", "parent-manifest", "base-cipher-sha256", "base-receipt-sha256", "hmac-key", "capsule", "capsule-sha256", "capsule-proof-sha256", "out"):
        cap.add_argument("--" + name, required=True)
    args = p.parse_args()
    if args.cmd == "capture":
        resource_to_dir = load_expected_sources(Path(args.expected_sources), Path(args.live_root))
        payload = capture_overlay(Path(args.live_root), Path(args.v1_root), args.parent_manifest,
                                  args.base_cipher_sha256, args.base_receipt_sha256,
                                  Path(args.capsule), args.capsule_sha256,
                                  args.capsule_proof_sha256, resource_to_dir)
        receipt, metadata = sign_receipt(payload, _load_key(Path(args.hmac_key)))
        out = Path(args.out)
        package_extension(receipt, metadata, Path(args.capsule), out)
        print(json.dumps({"status": "candidate-generated", "recordCount": payload["sourceCapture"]["recordCount"],
                          "claims": payload["claims"]}, sort_keys=True))


if __name__ == "__main__":
    main()
