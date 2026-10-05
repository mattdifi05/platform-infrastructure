#!/usr/bin/python3
"""Capture the reviewed G17 91 mounted-config trees as root-private metadata only.

No file contents or secret values are copied into the capture. Regular-file
contents are represented by size and SHA-256; xattr values are represented by
SHA-256. The output is intended to be added as a typed G16 overlay member and
read back with the host capsule from the same publication cycle.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import uuid

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
CATALOG = PACKAGE / 'native' / 'config-source-paths-g17.json'
HISTORICAL_CATALOG = PACKAGE / 'native' / 'config-source-paths.json'
PLAN = PACKAGE / 'native' / 'g16-private240-plan.json'
G17_DELTA = PACKAGE / 'native' / 'g17-private242-plan-delta.json'
FILESYSTEM = PACKAGE / 'native' / 'filesystem.py'
CATALOG_SHA = '03352c464fafda05646aade73191a5a09f38246d9aa54e31ccecfd7b3d99d1df'
HISTORICAL_CATALOG_SHA = 'f5cea1410282bcf5df8b722b11b7e1ccb67cc497c5fc401bab549152b5b52e69'
PLAN_SHA = '593f5d1ae2b535401ee769e633fe435726a8c68661e20dfdc980458dc8d6dbe2'
G17_DELTA_SHA = 'e9bc5250e89951d854cf7ffa044865f145e90c5092402ebeda85feeae5e29e71'
FILESYSTEM_SHA = '2fc936b9a8ecb5b64c8d22199f82c416567a20ce62d17d9763d3298266679d81'
PARENT_ID = 'manifest-scheduled-platform-20260929-182357-1f9954'
PARENT_DIGEST = 'baf72a7c4ff5d2266b71afe4865ebffeb8be6c363dfc31c12f3a865389009b2c'
OUTPUT = Path('/var/lib/platform-host-recovery/mounted-config-tree-records.json')
MAX_RECORDS = 1_000_000
MAX_OUTPUT_BYTES = 512 * 1024 * 1024
MAX_TREE_BYTES = 70_000_000_000
PROVIDER_COUNTS = {
    'parent-capsule-exact-binding': 76,
    'fresh-capsule-regular-file': 10,
    'authenticated-students-secret-file': 5,
}
HEX = re.compile(r'^[0-9a-f]{64}$')
REDACTED_SOURCE = '/home/platform_infrastructure/v1-fresh-runtime/critical'
REDACTED_MEMBER = 'v1-local-private_confidential-backup-passphrase'


class Blocked(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise Blocked('PINNED_INPUT_NOT_REGULAR')
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            h.update(block)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise Blocked('PINNED_INPUT_CHANGED_DURING_HASH')
    finally:
        os.close(fd)
    return h.hexdigest()


def load_filesystem(path=FILESYSTEM):
    if sha_file(Path(path)) != FILESYSTEM_SHA:
        raise Blocked('FILESYSTEM_HELPER_PIN')
    spec = importlib.util.spec_from_file_location('mounted_config_v5_filesystem', path)
    if spec is None or spec.loader is None:
        raise Blocked('FILESYSTEM_HELPER_IMPORT')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixed_sources(catalog_path=CATALOG, plan_path=PLAN, delta_path=G17_DELTA):
    if (sha_file(Path(catalog_path)) != CATALOG_SHA or sha_file(Path(plan_path)) != PLAN_SHA or
            sha_file(Path(delta_path)) != G17_DELTA_SHA or
            sha_file(HISTORICAL_CATALOG) != HISTORICAL_CATALOG_SHA):
        raise Blocked('CATALOG_OR_PLAN_PIN')
    catalog = json.loads(Path(catalog_path).read_bytes())
    historical = json.loads(HISTORICAL_CATALOG.read_bytes())
    plan = json.loads(Path(plan_path).read_bytes())
    delta = json.loads(Path(delta_path).read_bytes())
    historical_origin = {'manifestId': PARENT_ID, 'manifestDigest': PARENT_DIGEST,
                         'catalogSha256': HISTORICAL_CATALOG_SHA}
    expected_added = {
        '/home/platform_infrastructure/v1-fresh-runtime/secrets/grafana_secret_key.txt': '/run/secrets/grafana_secret_key',
        '/home/platform_infrastructure/v1-fresh-runtime/maintenance/20260927/grafana-13.2.3-preserved.ini': '/etc/grafana/grafana.ini',
    }
    if (catalog.get('schema') != 'platform.g17-mounted-config-source-paths/v1' or
            catalog.get('historicalRegistryOrigin') != historical_origin or
            len(catalog.get('sources', [])) != 91 or len(plan.get('mounts', [])) != 240 or
            delta.get('schema') != 'platform.g17-private242-mount-delta/v1' or
            delta.get('historicalPrivatePlanSha256') != PLAN_SHA or
            delta.get('historicalMountCount') != 240 or delta.get('expectedG17MountCount') != 242 or
            len(delta.get('grafanaAddedMounts', [])) != 2):
        raise Blocked('CONFIG_SCOPE_NOT_FIXED')
    old_sources = {(r['sourcePath'], r['resourceId']) for r in historical['sources']}
    new_sources = {(r['sourcePath'], r['resourceId']) for r in catalog['sources']}
    if (historical.get('schema') != 'platform.active87-mounted-config-source-paths/v4' or
            historical.get('manifestId') != PARENT_ID or historical.get('manifestDigest') != PARENT_DIGEST or
            len(old_sources) != 89 or new_sources - old_sources != {
                (source, 'mounted-config:' + hashlib.sha256(source.encode()).hexdigest())
                for source in expected_added} or not old_sources.issubset(new_sources)):
        raise Blocked('G17_CONFIG_REGISTRY_DELTA')
    added_mounts = delta.get('grafanaAddedMounts')
    if (not isinstance(added_mounts, list) or len(added_mounts) != 2 or
            {row.get('source'): row.get('target') for row in added_mounts} != expected_added or
            any(row.get('container') != 'gf-grafana' or row.get('readOnly') is not True or
                row.get('provider') != 'fresh-capsule-regular-file' for row in added_mounts)):
        raise Blocked('G17_GRAFANA_MOUNT_DELTA')
    providers = {}
    for row in plan['mounts'] + added_mounts:
        providers.setdefault(row.get('source'), set()).add(row.get('provider'))
    out = []
    seen = set()
    for row in catalog['sources']:
        source, rid = row.get('sourcePath'), row.get('resourceId')
        if (not isinstance(source, str) or not source.startswith('/') or source in seen or
                '..' in Path(source).parts or '\\' in source or '\x00' in source or
                rid != 'mounted-config:' + hashlib.sha256(source.encode()).hexdigest()):
            raise Blocked('CONFIG_SOURCE_ROW')
        classes = providers.get(source, set())
        if len(classes) != 1 or next(iter(classes)) not in PROVIDER_COUNTS:
            raise Blocked('CONFIG_PROVIDER_AMBIGUOUS')
        seen.add(source)
        out.append({'sourcePath': source, 'resourceId': rid, 'provider': next(iter(classes))})
    counts = {k: sum(row['provider'] == k for row in out) for k in PROVIDER_COUNTS}
    if counts != PROVIDER_COUNTS or len(seen) != 91:
        raise Blocked('CONFIG_PROVIDER_COUNTS')
    credential = '/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase'
    covering = [p for p in seen if credential == p or credential.startswith(p.rstrip('/') + '/')]
    if covering != [REDACTED_SOURCE]:
        raise Blocked('CREDENTIAL_ANCESTOR_COVERAGE')
    return sorted(out, key=lambda row: row['sourcePath'])


def _source_root(host_root: Path, source_path: str) -> Path:
    if not host_root.is_absolute() or host_root.resolve(strict=True) != host_root or host_root.is_symlink():
        raise Blocked('HOST_ROOT_NOT_CANONICAL')
    rel = Path(source_path.lstrip('/'))
    if not rel.parts or any(p in ('', '.', '..') for p in rel.parts):
        raise Blocked('CONFIG_PATH_UNSAFE')
    root = host_root.joinpath(*rel.parts)
    if root.is_symlink() or root.resolve(strict=True) != root:
        raise Blocked('CONFIG_SOURCE_ALIAS')
    return root


def capture_document(cycle_id: str, host_root: Path, *, fs=None,
                     catalog_path=CATALOG, plan_path=PLAN, require_root=True,
                     platform=None, started_at=None) -> dict:
    """Capture exact current trees and verify they did not drift during scan."""
    if require_root and (os.geteuid() != 0 or (platform or sys.platform) != 'linux'):
        raise Blocked('CAPTURE_REQUIRES_ROOT_LINUX')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', cycle_id):
        raise Blocked('CYCLE_ID_INVALID')
    fs = fs or load_filesystem()
    sources = fixed_sources(catalog_path, plan_path)
    before = {}
    entries = []
    excluded_sensitive = []
    total_records = 0
    total_bytes = 0
    for row in sources:
        root = _source_root(Path(host_root), row['sourcePath'])
        if row['sourcePath'] == REDACTED_SOURCE:
            secret_path = root / REDACTED_MEMBER
            if secret_path.is_symlink():
                raise Blocked('CREDENTIAL_PATH_ALIAS')
            secret_stat = secret_path.lstat()
            expected_uid, expected_gid = (1000, 1000) if require_root else (os.getuid(), os.getgid())
            if (not stat.S_ISREG(secret_stat.st_mode) or secret_stat.st_uid != expected_uid or
                    secret_stat.st_gid != expected_gid or stat.S_IMODE(secret_stat.st_mode) != 0o600 or
                    secret_stat.st_nlink != 1):
                raise Blocked('CREDENTIAL_METADATA_CUSTODY')
            excluded_sensitive.append({
                'sourcePath': row['sourcePath'], 'relativePath': REDACTED_MEMBER,
                'type': 'regular-file', 'uid': secret_stat.st_uid, 'gid': secret_stat.st_gid,
                'mode': stat.S_IMODE(secret_stat.st_mode), 'bytes': secret_stat.st_size,
                'mtimeNs': secret_stat.st_mtime_ns, 'nlink': secret_stat.st_nlink,
                'contentRead': False, 'contentHash': None, 'xattrsRead': False,
            })
            excluded_relative = (REDACTED_MEMBER,)
            seal = fs.tree_seal(root, excluded_relative=excluded_relative)
            tree_records = fs.records(root, excluded_relative=excluded_relative)
        else:
            excluded_relative = ()
            seal = fs.tree_seal(root)
            tree_records = fs.records(root)
        digest = sha_bytes(canonical(tree_records))
        if fs.tree_seal(root, excluded_relative=excluded_relative) != seal:
            raise Blocked('CONFIG_TREE_DRIFT_DURING_CAPTURE')
        total_records += len(tree_records)
        total_bytes += sum(r.get('bytes', 0) for r in tree_records if r.get('kind') == 'file')
        if total_records > MAX_RECORDS or total_bytes > MAX_TREE_BYTES:
            raise Blocked('CONFIG_CAPTURE_RESOURCE_BOUND')
        before[row['sourcePath']] = (seal, digest)
        entries.append({
            'sourcePath': row['sourcePath'], 'resourceId': row['resourceId'],
            'scopeMappingClass': row['provider'],
            'treeDigest': digest,
            'recordSetSha256': digest,
            'recordCount': len(tree_records),
            'regularBytes': sum(r.get('bytes', 0) for r in tree_records if r.get('kind') == 'file'),
            'records': tree_records,
        })
    # Re-seal every source after the full 91-tree walk. This detects changes
    # made after an individual tree was scanned but before the capture closes.
    for row in sources:
        root = _source_root(Path(host_root), row['sourcePath'])
        excluded_relative = (REDACTED_MEMBER,) if row['sourcePath'] == REDACTED_SOURCE else ()
        if fs.tree_seal(root, excluded_relative=excluded_relative) != before[row['sourcePath']][0]:
            raise Blocked('CONFIG_TREE_DRIFT_AFTER_CAPTURE')
    # Only lstat the exact excluded credential again. Never open it, hash it,
    # inspect xattrs, or alter its owner/mode.
    secret_path = Path(host_root) / REDACTED_SOURCE.lstrip('/') / REDACTED_MEMBER
    secret_after = secret_path.lstat()
    item = excluded_sensitive[0]
    if (stat.S_ISLNK(secret_after.st_mode) or not stat.S_ISREG(secret_after.st_mode) or
            (secret_after.st_uid, secret_after.st_gid, stat.S_IMODE(secret_after.st_mode),
             secret_after.st_size, secret_after.st_mtime_ns, secret_after.st_nlink) !=
            (item['uid'], item['gid'], item['mode'], item['bytes'], item['mtimeNs'], item['nlink'])):
        raise Blocked('CREDENTIAL_METADATA_CHANGED_DURING_CAPTURE')
    document = {
        'schema': 'platform.mounted-config-tree-capture/v1',
        'status': 'captured-local-unpublished',
        'cycleId': cycle_id,
        'capturedAt': started_at or dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z'),
        # The new FULL parent does not exist at capture time. This is the
        # immutable registry origin only; the signed overlay receipt later
        # binds the newly authenticated FULL parent.
        'historicalRegistryOrigin': {'manifestId': PARENT_ID, 'manifestDigest': PARENT_DIGEST,
                                     'catalogSha256': HISTORICAL_CATALOG_SHA},
        'catalogSha256': CATALOG_SHA,
        'planSha256': PLAN_SHA,
        'sourceCount': 91,
        'recordCount': total_records,
        'regularBytes': total_bytes,
        'providerCounts': PROVIDER_COUNTS,
        'excludedSensitiveEntries': excluded_sensitive,
        'recoveryLimitations': {'originalGpgCredentialArchived': False,
            'separateGpgCredentialCustodyRequiredForRestore': True},
        'sources': entries,
        'claims': {'sameCycleCapsuleVerified': False, 'offsiteVerified': False,
                   'productionModified': False},
    }
    encoded = canonical(document) + b'\n'
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise Blocked('CONFIG_SIDECAR_SIZE_LIMIT')
    return document


def write_atomic(path: Path, document: dict) -> tuple[str, int]:
    path = Path(path)
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent or path.is_symlink():
        raise Blocked('OUTPUT_PATH_NOT_CANONICAL')
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o077:
        raise Blocked('OUTPUT_PARENT_NOT_ROOT_PRIVATE')
    if path.exists():
        old = path.lstat()
        if (not stat.S_ISREG(old.st_mode) or old.st_uid != 0 or old.st_mode & 0o077 or
                old.st_nlink != 1 or old.st_size > MAX_OUTPUT_BYTES):
            raise Blocked('PREVIOUS_SIDECAR_NOT_OWNED_PRIVATE_FILE')
    raw = canonical(document) + b'\n'
    if len(raw) > MAX_OUTPUT_BYTES:
        raise Blocked('CONFIG_SIDECAR_SIZE_LIMIT')
    fd, tmp_name = tempfile.mkstemp(prefix='.mounted-config-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, path)
        dfd = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return sha_bytes(raw), len(raw)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()
    try:
        if os.geteuid() != 0 or sys.platform != 'linux':
            raise Blocked('CAPTURE_REQUIRES_ROOT_LINUX')
        cycle_id = os.environ.get('INVOCATION_ID') or uuid.uuid4().hex
        doc = capture_document(cycle_id, Path('/'))
        digest, size = write_atomic(OUTPUT, doc)
        print(json.dumps({'status': 'captured-local-unpublished', 'cycleId': doc['cycleId'],
                          'sourceCount': doc['sourceCount'], 'recordCount': doc['recordCount'],
                          'bytes': size, 'sha256': digest, 'offsiteVerified': False}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({'status': 'blocked', 'reason': str(exc)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
