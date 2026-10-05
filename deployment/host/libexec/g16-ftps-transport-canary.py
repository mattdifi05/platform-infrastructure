#!/usr/bin/python3
"""Root-run isolated FTPS/GPG/parser canary for the generation-16 wire format.

This is a transport and reader canary, not a source-capture or restore proof.
It uses an invented HMAC/GPG key and a unique account-root directory. It will
not run until root supplies a normalized proof of final G15 receipt/readback
and explicitly passes --root-reviewed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import ftplib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import stat
import subprocess
import tempfile
import sys
import tempfile
import tarfile
import time
import uuid


DEFAULT_HELPER_DIR = Path('/usr/local/libexec/platform-g16-candidate')
CONFIG = Path('/etc/platform-ftps-backup/config.json')
STAGING = Path('/var/lib/platform-g16-canary-20260930')
JOURNAL_DIR = STAGING / 'remote-namespaces'
PUBLISH_SERVICE = 'platform-publish-completeness-20260930.service'
FREEZE = Path('/var/lib/platform-backup-schedule/offsite-freeze.json')
LOCK_PATHS = (
    Path('/var/lib/platform-server-ai-admin/operator-deploy.lock'),
    Path('/var/lib/platform-backup-schedule/operation.lock'),
    Path('/var/lib/platform-ftps-backup/transfer.lock'),
)
EXPECTED_ENDPOINT = ('92.113.28.106', 21, 'hstgr.io', '/server-platform-backups')
CAP = 70_000_000_000
PART_BYTES = 1_000_000


def _required_owner() -> int:
    # Live entrypoints require root. Caller ownership is allowed only by the
    # isolated helper tests on an unprivileged development host.
    return 0 if os.geteuid() == 0 else os.geteuid()


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _load_g15_gate(path: Path) -> dict:
    path = Path(path)
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError('ROOT_PRIVATE_G15_FINAL_GATE_REQUIRED')
    proof = json.loads(path.read_text())
    required = {
        'schema': 'platform.g16-canary-g15-gate/v1',
        'status': 'passed',
        'finalReceiptCommitted': True,
        'fullRemoteReadbackVerified': True,
        'allCiphertextPartHashesVerified': True,
    }
    if any(proof.get(key) != value for key, value in required.items()):
        raise RuntimeError('G15_FINAL_RECEIPT_AND_READBACK_GATE_NOT_PASSED')
    if not isinstance(proof.get('manifestId'), str) or not isinstance(proof.get('manifestDigest'), str):
        raise RuntimeError('G15_GATE_PARENT_BINDING_MISSING')
    if len(proof['manifestDigest']) != 64 or any(c not in '0123456789abcdef' for c in proof['manifestDigest']):
        raise RuntimeError('G15_GATE_PARENT_DIGEST_INVALID')
    return proof


def _load_helper(helper_dir: Path):
    helper_dir = Path(helper_dir)
    directory_info = helper_dir.lstat()
    if helper_dir.is_symlink() or not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != 0 or directory_info.st_mode & 0o022:
        raise RuntimeError('ROOT_OWNED_CANDIDATE_HELPER_DIRECTORY_REQUIRED')
    path = helper_dir / 'platform-ftps-backup.py'
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError('ROOT_PINNED_G16_HELPER_REQUIRED')
    spec = importlib.util.spec_from_file_location('platform_ftps_backup_g16_canary', path)
    if spec is None or spec.loader is None:
        raise RuntimeError('PINNED_G16_HELPER_IMPORT_FAILED')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verify_candidate_closure(helper_dir: Path):
    helper_dir = Path(helper_dir)
    pins_path = helper_dir / 'g16-pins.json'
    if not pins_path.exists(): pins_path = Path('/usr/local/libexec/g16-pins.json')
    pins_info = pins_path.lstat()
    if pins_path.is_symlink() or not stat.S_ISREG(pins_info.st_mode) or pins_info.st_uid != 0 or pins_info.st_mode & 0o022:
        raise RuntimeError('ROOT_PINNED_G16_MODULE_MAP_REQUIRED')
    pins = json.loads(pins_path.read_text())
    if pins.get('schema') != 'platform.native-g16-module-pins/v1' or not isinstance(pins.get('files'), dict):
        raise RuntimeError('G16_MODULE_MAP_SCHEMA_INVALID')
    def installed_path(name):
        destination = pins.get('installPaths', {}).get(name)
        if destination:
            target = Path(destination)
            if target.exists(): return target
            if destination.startswith('/usr/local/libexec/platform-mounted-config-v5/'):
                candidate = helper_dir.parent / destination.removeprefix('/usr/local/libexec/')
                if candidate.exists(): return candidate
            if destination.startswith('/usr/local/libexec/'):
                candidate = helper_dir / destination.removeprefix('/usr/local/libexec/')
                if candidate.exists(): return candidate
        return helper_dir / name
    for name, expected in pins['files'].items():
        path = installed_path(name)
        info = path.lstat()
        if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022 or info.st_nlink != 1 or _sha(path) != expected):
            raise RuntimeError('G16_TRANSITIVE_MODULE_PIN_MISMATCH')
    extension_path = helper_dir / 'g16-capsule-paths-extension.json'
    if not extension_path.exists(): extension_path = Path('/usr/local/libexec/g16-capsule-paths-extension.json')
    ext_info = extension_path.lstat()
    if extension_path.is_symlink() or not stat.S_ISREG(ext_info.st_mode) or ext_info.st_uid != 0 or ext_info.st_mode & 0o022:
        raise RuntimeError('G16_CAPSULE_CLOSURE_EXTENSION_REQUIRED')
    extension = json.loads(extension_path.read_text())
    if (extension.get('schema') != 'platform.g16-host-capsule-paths-extension/v1' or
            extension.get('g16TransitivePinsSha256') != _sha(pins_path)):
        raise RuntimeError('G16_CAPSULE_CLOSURE_PIN_BINDING_INVALID')
    local_names = {
        'expected-sources.json': 'expected-sources.json',
        'g16-pins.json': 'g16-pins.json',
        'g16_overlay_native.py': 'g16_overlay_native.py',
        'platform-ftps-backup.py': 'platform-ftps-backup.py',
        'platform-ftps-restore.py': 'platform-ftps-restore-current.py',
        'prescan_source_metadata_g16_v3.py': 'prescan_source_metadata_g16_v3.py',
        'source_metadata_overlay_producer_g16.py': 'source_metadata_overlay_producer_g16.py',
        'source_metadata_overlay_v3.py': 'source_metadata_overlay_v3.py',
        'stream-expired-cache-descriptor-actual.json': 'stream-expired-cache-descriptor-actual.json',
    }
    listed = extension.get('fileSha256')
    if not isinstance(listed, dict):
        raise RuntimeError('G16_CAPSULE_CLOSURE_FILE_MAP_INVALID')
    for remote_path, local_name in local_names.items():
        key = pins.get('installPaths', {}).get(remote_path, '/usr/local/libexec/' + remote_path)
        local = installed_path(remote_path)
        info = local.lstat()
        if (local.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022 or info.st_nlink != 1 or listed.get(key) != _sha(local)):
            raise RuntimeError('G16_CAPSULE_CLOSURE_FILE_PIN_MISMATCH')


def _open_locks():
    held = []
    for path in LOCK_PATHS:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
            os.close(fd)
            raise RuntimeError('ROOT_PRIVATE_CANARY_LOCK_REQUIRED')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise RuntimeError('BACKUP_OR_DEPLOY_LOCK_BUSY') from None
        held.append(fd)
    return held


def _require_safe_preconditions(gate_path: Path):
    if os.geteuid() != 0:
        raise RuntimeError('ROOT_REQUIRED')
    _load_g15_gate(gate_path)
    if FREEZE.exists() or FREEZE.is_symlink():
        raise RuntimeError('OFFSITE_FREEZE_ACTIVE')
    active = subprocess.run(['systemctl', 'show', '--property=ActiveState', '--value', PUBLISH_SERVICE],
                            text=True, capture_output=True, check=True).stdout.strip()
    if active == 'active':
        raise RuntimeError('G15_PUBLISH_SERVICE_STILL_ACTIVE')
    if STAGING.is_symlink() or (STAGING.exists() and (STAGING.stat().st_uid != 0 or STAGING.stat().st_mode & 0o077)):
        raise RuntimeError('FIXED_ROOT_PRIVATE_STAGING_REQUIRED')
    STAGING.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STAGING, 0o700)
    if CONFIG.is_symlink() or not CONFIG.is_file():
        raise RuntimeError('FTPS_CONFIG_PATH_UNSAFE')
    config_info = CONFIG.lstat()
    if config_info.st_uid != 0 or config_info.st_mode & 0o077:
        raise RuntimeError('ROOT_PRIVATE_FTPS_CONFIG_REQUIRED')
    cfg = json.loads(CONFIG.read_text())
    if (cfg.get('host'), cfg.get('port'), cfg.get('tlsName'), cfg.get('folder')) != EXPECTED_ENDPOINT:
        raise RuntimeError('FIXED_FTPS_ENDPOINT_CHANGED')
    return cfg


def _connect(cfg, path: str):
    ftp = ftplib.FTP_TLS(context=ssl.create_default_context(), timeout=90)
    try:
        ftp.connect(cfg['host'], cfg['port'])
        ftp.host = cfg['tlsName']
        ftp.auth()
        ftp.login(cfg['username'], cfg['password'])
        ftp.prot_p()
        ftp.cwd(path)
        if ftp.pwd() != path:
            raise RuntimeError('EXACT_CANARY_NAMESPACE_REQUIRED')
        return ftp
    except BaseException:
        ftp.close()
        raise


def _signed_json(helper, ftp, name, document, limit=1_048_576):
    raw = helper.canonical(document)
    if len(raw) > limit:
        raise RuntimeError('CANARY_RECEIPT_SIZE_BOUND')
    helper.upload_bytes(ftp, name, raw)


def _private_directory(path: Path, *, create=False):
    path = Path(path)
    if create:
        existed = path.exists()
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.geteuid() == 0:
            os.chown(path, 0, 0)
        os.chmod(path, 0o700)
        # Persist a newly-created directory in its parent before any remote
        # operation can depend on the journal/scratch tree surviving a crash.
        if not existed:
            _fsync_directory(path.parent)
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != _required_owner() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError('ROOT_PRIVATE_CANARY_JOURNAL_DIRECTORY_REQUIRED')
    return path


def _fsync_directory(path: Path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    try: os.fsync(fd)
    finally: os.close(fd)


def _write_private_file(path: Path, data: bytes):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        if os.geteuid() == 0: os.fchown(fd, 0, 0)
        view = memoryview(data)
        while view: view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_directory(path.parent)


def _write_journal(path: Path, document: dict):
    """Durably replace one root-only journal; the file contains no credentials."""
    path = Path(path)
    parent = _private_directory(path.parent, create=True)
    if path.exists() or path.is_symlink():
        old = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(old.st_mode) or old.st_uid != _required_owner() or old.st_nlink != 1 or stat.S_IMODE(old.st_mode) != 0o600:
            raise RuntimeError('CANARY_JOURNAL_TARGET_UNSAFE')
    raw = json.dumps(document, sort_keys=True, separators=(',', ':')).encode() + b'\n'
    temp = parent / ('.' + path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        if os.geteuid() == 0: os.fchown(fd, 0, 0)
        view = memoryview(raw)
        while view: view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, path)
    directory_fd = os.open(parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try: os.fsync(directory_fd)
    finally: os.close(directory_fd)


def _declare_remote_object(journal_path: Path, journal: dict, scratch: Path,
                           name: str, data: bytes):
    if not isinstance(name, str) or not name or '/' in name or '\\' in name or name in {'.', '..'}:
        raise RuntimeError('CANARY_REMOTE_OBJECT_NAME_UNSAFE')
    if not isinstance(data, bytes) or len(data) > 32 * 1024 * 1024:
        raise RuntimeError('CANARY_REMOTE_OBJECT_SIZE_BOUND')
    scratch = Path(scratch)
    _private_directory(scratch)
    expected_dir = scratch / 'expected-remote-objects'
    _private_directory(expected_dir, create=True)
    digest = hashlib.sha256(data).hexdigest()
    expected_path = expected_dir / digest
    if expected_path.exists():
        st = expected_path.lstat()
        if expected_path.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid != _required_owner() or st.st_nlink != 1 or st.st_size != len(data) or _sha(expected_path) != digest:
            raise RuntimeError('CANARY_EXPECTED_OBJECT_COLLISION')
    else:
        fd = os.open(expected_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            if os.geteuid() == 0: os.fchown(fd, 0, 0)
            view = memoryview(data)
            while view: view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        dfd = os.open(expected_dir, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try: os.fsync(dfd)
        finally: os.close(dfd)
    journal.setdefault('objects', {})[name] = {
        'bytes': len(data), 'sha256': digest,
        'expectedFile': str(expected_path),
    }
    _write_journal(journal_path, journal)


def _load_owned_journal(path: Path):
    path = Path(path)
    expected_parent = _private_directory(JOURNAL_DIR)
    if path.parent.resolve() != expected_parent.resolve():
        raise RuntimeError('CANARY_JOURNAL_OUTSIDE_FIXED_DIRECTORY')
    st = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid != _required_owner() or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > 2 * 1024 * 1024:
        raise RuntimeError('CANARY_JOURNAL_NOT_ROOT_PRIVATE')
    doc = json.loads(path.read_bytes())
    run_id = doc.get('runId')
    if (doc.get('schema') != 'platform.g16-canary-owned-namespace/v1' or
            doc.get('status') not in {'in-progress', 'cleaned'} or
            not isinstance(run_id, str) or len(run_id) != 32 or any(c not in '0123456789abcdef' for c in run_id) or
            doc.get('folder') != '/g16-transport-canary-' + run_id or
            not isinstance(doc.get('objects'), dict) or len(doc['objects']) > 256):
        raise RuntimeError('CANARY_JOURNAL_SCHEMA_OR_IDENTITY_INVALID')
    if doc['status'] == 'cleaned':
        if doc.get('remoteDeleted') is not True:
            raise RuntimeError('CANARY_CLEANED_JOURNAL_NOT_FINAL')
        return doc
    scratch = Path(doc.get('scratchPath', ''))
    if scratch.parent.resolve() != STAGING.resolve() or scratch.name != 'g16-transport-' + run_id:
        raise RuntimeError('CANARY_JOURNAL_SCRATCH_BINDING_INVALID')
    scratch_st = scratch.lstat()
    if scratch.is_symlink() or not stat.S_ISDIR(scratch_st.st_mode) or scratch_st.st_uid != _required_owner() or stat.S_IMODE(scratch_st.st_mode) != 0o700:
        raise RuntimeError('CANARY_JOURNAL_SCRATCH_UNSAFE')
    expected_dir = scratch / 'expected-remote-objects'
    _private_directory(expected_dir)
    for name, item in doc['objects'].items():
        if not isinstance(name, str) or not name or '/' in name or '\\' in name or name in {'.', '..'} or not isinstance(item, dict) or set(item) != {'bytes', 'sha256', 'expectedFile'}:
            raise RuntimeError('CANARY_JOURNAL_OBJECT_INVALID')
        expected = Path(item['expectedFile'])
        if expected.parent.resolve() != expected_dir.resolve() or expected.name != item['sha256']:
            raise RuntimeError('CANARY_JOURNAL_EXPECTED_FILE_PATH_INVALID')
        expected_st = expected.lstat()
        if (expected.is_symlink() or not stat.S_ISREG(expected_st.st_mode) or expected_st.st_uid != _required_owner() or expected_st.st_nlink != 1 or
                stat.S_IMODE(expected_st.st_mode) != 0o600 or expected_st.st_size != item['bytes'] or _sha(expected) != item['sha256']):
            raise RuntimeError('CANARY_JOURNAL_EXPECTED_FILE_HASH_INVALID')
    return doc


def _verify_remote_prefix(ftp, name: str, item: dict):
    """A failed STOR may be a prefix only; accept no bytes outside our durable intent."""
    expected = Path(item['expectedFile'])
    expected_st = expected.lstat()
    if expected.is_symlink() or not stat.S_ISREG(expected_st.st_mode) or expected_st.st_uid != _required_owner() or expected_st.st_nlink != 1 or expected_st.st_size != item['bytes'] or _sha(expected) != item['sha256']:
        raise RuntimeError('CANARY_EXPECTED_OBJECT_CHANGED')
    count = 0
    with expected.open('rb') as source:
        def compare(chunk):
            nonlocal count
            if count + len(chunk) > item['bytes']:
                raise RuntimeError('CANARY_REMOTE_OBJECT_OVERSIZE')
            wanted = source.read(len(chunk))
            if wanted != chunk:
                raise RuntimeError('CANARY_REMOTE_OBJECT_NOT_OWNED_PREFIX')
            count += len(chunk)
        ftp.retrbinary('RETR ' + name, compare, blocksize=65536)
    return count


def _validate_owned_remote_inventory(ftp, helper, journal: dict):
    helper.verify_owner(ftp)
    listing = helper.inventory(ftp)
    if helper.MARKER not in listing or set(listing) - {helper.MARKER} - set(journal['objects']):
        raise RuntimeError('CANARY_RECOVERY_REMOTE_OBJECT_SET_UNKNOWN')
    marker = helper.get_json(ftp, helper.MARKER, 4096)
    expected_marker = {'schema': 'platform.ftps-owner/v1', 'owner': 'server-platform-vpn',
                       'folder': journal['folder'], 'quotaBytes': CAP}
    if marker != expected_marker:
        raise RuntimeError('CANARY_RECOVERY_OWNER_MARKER_MISMATCH')
    for name, size in listing.items():
        if name == helper.MARKER:
            continue
        item = journal['objects'][name]
        if size > item['bytes']:
            raise RuntimeError('CANARY_RECOVERY_REMOTE_SIZE_EXCEEDS_INTENT')
        _verify_remote_prefix(ftp, name, item)
    return listing


def _validate_owned_remote_inventory_for_recovery(ftp, helper, journal: dict):
    """Accept a marker only when complete, or its exact journaled STOR prefix."""
    listing = helper.inventory(ftp)
    marker_name = helper.MARKER
    if marker_name not in listing:
        return listing, False
    if set(listing) - {marker_name} - set(journal['objects']):
        raise RuntimeError('CANARY_RECOVERY_REMOTE_OBJECT_SET_UNKNOWN')
    marker_item = journal['objects'].get(marker_name)
    if not isinstance(marker_item, dict):
        raise RuntimeError('CANARY_RECOVERY_UNJOURNALED_OWNER_MARKER')
    marker_size = listing[marker_name]
    if marker_size > marker_item['bytes']:
        raise RuntimeError('CANARY_RECOVERY_OWNER_MARKER_OVERSIZE')
    marker_prefix = _verify_remote_prefix(ftp, marker_name, marker_item)
    if marker_prefix != marker_size:
        raise RuntimeError('CANARY_RECOVERY_OWNER_MARKER_LISTING_SIZE_MISMATCH')
    if marker_prefix != marker_item['bytes']:
        return listing, False
    marker = helper.get_json(ftp, marker_name, 4096)
    expected_marker = {'schema': 'platform.ftps-owner/v1', 'owner': 'server-platform-vpn',
                       'folder': journal['folder'], 'quotaBytes': CAP}
    if marker != expected_marker:
        raise RuntimeError('CANARY_RECOVERY_OWNER_MARKER_MISMATCH')
    for name, size in listing.items():
        if name == marker_name:
            continue
        item = journal['objects'][name]
        if size > item['bytes']:
            raise RuntimeError('CANARY_RECOVERY_REMOTE_SIZE_EXCEEDS_INTENT')
        _verify_remote_prefix(ftp, name, item)
    return listing, True


def recover_owned_namespace(gate_path: Path, helper_dir: Path, journal_path: Path) -> dict:
    """Remove only a journaled UUID namespace with a matching owner marker and exact object prefixes."""
    cfg = _require_safe_preconditions(gate_path)
    journal = _load_owned_journal(journal_path)
    if journal['status'] == 'cleaned':
        return {'status': 'already-cleaned', 'runId': journal['runId'], 'remoteObjectsChanged': False}
    lock_fds = _open_locks()
    ftp = None
    try:
        _verify_candidate_closure(helper_dir)
        helper = _load_helper(helper_dir)
        helper.FOLDER = journal['folder']
        ftp = _connect(cfg, '/')
        root_listing = {name: facts for name, facts in ftp.mlsd() if name not in {'.', '..'}}
        facts = root_listing.get(journal['folder'].lstrip('/'))
        if facts is None:
            journal['status'] = 'cleaned'; journal['phase'] = 'remote-folder-absent'; journal['remoteDeleted'] = True
            _write_journal(journal_path, journal)
            return {'status': 'remote-folder-absent', 'runId': journal['runId'], 'remoteObjectsChanged': False}
        if facts.get('type') != 'dir':
            raise RuntimeError('CANARY_RECOVERY_UUID_PATH_NOT_DIRECTORY')
        ftp.cwd(journal['folder'])
        if ftp.pwd() != journal['folder']:
            raise RuntimeError('CANARY_RECOVERY_WRONG_REMOTE_DIRECTORY')
        current = helper.inventory(ftp)
        if helper.MARKER not in current:
            # A durable directory-created journal proves the exact UUID MKD
            # completed before marker intent existed. Empty is the only safe
            # state to remove. The marker-delete-intent case covers a crash
            # after deleting the already-verified marker.
            empty_creation_phases = {'directory-create-intent', 'directory-created'}
            empty_creation_is_owned = (
                journal.get('phase') in empty_creation_phases and
                journal.get('remotePathObservedAbsent') is True and
                not journal['objects'])
            empty_marker_intent_is_owned = (
                journal.get('phase') == 'owner-marker-intent' and
                journal.get('remotePathObservedAbsent') is True and
                set(journal['objects']) == {helper.MARKER})
            marker_delete_is_owned = journal.get('phase') == 'marker-delete-intent'
            if not (not current and (empty_creation_is_owned or empty_marker_intent_is_owned or marker_delete_is_owned)):
                raise RuntimeError('CANARY_RECOVERY_OWNER_MARKER_MISSING')
            ftp.cwd('/')
            ftp.rmd(journal['folder'])
            journal['status'] = 'cleaned'; journal['phase'] = 'remote-folder-removed'; journal['remoteDeleted'] = True
            _write_journal(journal_path, journal)
            return {'status': 'cleaned-empty-journaled-namespace', 'runId': journal['runId'],
                    'folder': journal['folder'], 'verifiedObjectCount': 0, 'remoteObjectsChanged': True}
        listing, marker_complete = _validate_owned_remote_inventory_for_recovery(ftp, helper, journal)
        if not marker_complete:
            if (journal.get('phase') not in {'owner-marker-intent', 'marker-delete-intent'} or
                    set(current) != {helper.MARKER}):
                raise RuntimeError('CANARY_RECOVERY_PARTIAL_MARKER_NOT_OWNED')
            # The only object is a byte-for-byte prefix of the marker whose
            # bytes were fsynced and journaled before STOR.
            journal['phase'] = 'marker-delete-intent'; _write_journal(journal_path, journal)
            ftp.delete(helper.MARKER)
            if helper.inventory(ftp):
                raise RuntimeError('CANARY_RECOVERY_DIRECTORY_NOT_EMPTY')
            ftp.cwd('/'); ftp.rmd(journal['folder'])
            journal['status'] = 'cleaned'; journal['phase'] = 'remote-folder-removed'; journal['remoteDeleted'] = True
            _write_journal(journal_path, journal)
            return {'status': 'cleaned-partial-owner-marker-namespace', 'runId': journal['runId'],
                    'folder': journal['folder'], 'verifiedObjectCount': 1, 'remoteObjectsChanged': True}
        for name in sorted(set(listing) - {helper.MARKER}):
            ftp.delete(name)
        journal['phase'] = 'marker-delete-intent'; _write_journal(journal_path, journal)
        ftp.delete(helper.MARKER)
        if helper.inventory(ftp):
            raise RuntimeError('CANARY_RECOVERY_DIRECTORY_NOT_EMPTY')
        ftp.cwd('/')
        ftp.rmd(journal['folder'])
        journal['status'] = 'cleaned'; journal['phase'] = 'remote-folder-removed'; journal['remoteDeleted'] = True
        _write_journal(journal_path, journal)
        return {'status': 'cleaned-exact-owned-namespace', 'runId': journal['runId'],
                'folder': journal['folder'], 'verifiedObjectCount': len(listing), 'remoteObjectsChanged': True}
    finally:
        if ftp is not None:
            try: ftp.close()
            except Exception: pass
        for fd in lock_fds:
            try: os.close(fd)
            except OSError: pass


def _base_fixture(helper, parent, fixture_key):
    archive = b'G16 canary fixture only; no production restore data.\n'
    cipher = b'G16 synthetic base ciphertext; never decrypt or restore.\n'
    digest = hashlib.sha256(cipher).hexdigest()
    parent_receipt_sha = hashlib.sha256(helper.canonical(helper.sign(parent))).hexdigest()
    payload = {
        # The selected historical G15 base receipt is v2.  Keep the canary's
        # synthetic base aligned with that real reader contract; v3 adds a
        # pre-upload archive proof that this invented legacy fixture cannot
        # honestly provide.
        'schema': helper.COMPLETENESS_V2_SCHEMA,
        'status': 'passed',
        'kind': 'runtime-completeness-material',
        'parentManifestId': parent['manifestId'],
        'parentManifestDigest': parent['manifestDigest'],
        'parentReceiptSha256': parent_receipt_sha,
        'parentEncryptedSha256': parent['encryptedSha256'],
        'backupAt': parent['backupAt'],
        'ciphertext': parent['bundle'] + '.supplement-full-' + digest[:16] + '.tar.gpg',
        'encryptedBytes': len(cipher),
        'encryptedSha256': digest,
        'files': [
            {'name': 'coverage.json', 'bytes': 2, 'sha256': hashlib.sha256(b'{}').hexdigest()},
            {'name': 'RECOVERY.md', 'bytes': len(b'fixture only, no restore'),
             'sha256': hashlib.sha256(b'fixture only, no restore').hexdigest()},
            {'name': 'full-runtime.tar.gz', 'bytes': len(archive), 'sha256': hashlib.sha256(archive).hexdigest()},
        ],
        'verifiedAt': helper.now(),
        'parts': [{'name': parent['bundle'] + '.supplement-full-' + digest[:16] + '.tar.gpg.part000',
                   'bytes': len(cipher), 'sha256': digest}],
        'fullyRecoverable': False,
        'knownGaps': ['synthetic canary fixture; no production source, database, image, or restore evidence'],
    }
    return payload, cipher


def _synthetic_mounted_capture(helper_dir: Path, work: Path, cycle_id: str):
    """Create an invented 89-source capture under this canary's private scratch."""
    candidate=Path(helper_dir).resolve()
    v5_native=candidate/'platform-mounted-config-v5'/'native'
    if not v5_native.is_dir():v5_native=candidate
    host_dir=v5_native.parent/'host'
    capture_path = host_dir / 'capture_mounted_config_trees.py'
    spec = importlib.util.spec_from_file_location('canary_capture_mounted_config_trees', capture_path)
    if spec is None or spec.loader is None: raise RuntimeError('PINNED_V5_CAPTURE_MODULE_MISSING')
    capture = importlib.util.module_from_spec(spec); spec.loader.exec_module(capture)
    root = work / 'synthetic-host'; root.mkdir(mode=0o700)
    file_classes = {'fresh-capsule-regular-file', 'authenticated-students-secret-file'}
    for row in capture.fixed_sources():
        path = root.joinpath(*Path(row['sourcePath'].lstrip('/')).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        if row['provider'] in file_classes:
            path.write_bytes(('synthetic-canary:' + row['resourceId']).encode())
            os.chmod(path, 0o600)
        else:
            path.mkdir(parents=True, exist_ok=True)
    # The exact key-shaped leaf is synthetic data in this private scratch only;
    # capture's typed exclusion proves it is not read or serialized.
    key = root / 'home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase'
    key.parent.mkdir(parents=True, exist_ok=True); key.write_bytes(b'canary-only-credential-never-read'); os.chmod(key, 0o600)
    return capture.capture_document(cycle_id, root, require_root=False), root


def _encrypt_synthetic_mounted_capsule(sidecar, sidecar_bytes, document, root, key_path, work):
    """Build a valid fixture capsule for the same 89-record sidecar reader."""
    archive = work / 'synthetic-host-capsule.tar.gz'
    entries = {}
    for source in document['sources']:
        source_root = root.joinpath(*Path(source['sourcePath'].lstrip('/')).parts)
        for record in source['records']:
            rel = record['path']
            member_name = 'host' + source['sourcePath'] + ('' if rel == '.' else '/' + rel)
            entries.setdefault(member_name, (source_root, record))
    with tarfile.open(archive, 'w:gz', format=tarfile.PAX_FORMAT) as tf:
        for name, (source_root, record) in sorted(entries.items()):
            info = tarfile.TarInfo(name)
            info.uid = record['uid']; info.gid = record['gid']; info.mode = record['mode']
            info.mtime = record['mtimeNs'] // 1_000_000_000
            kind = record['kind']
            path = source_root if record['path'] == '.' else source_root / record['path']
            if kind == 'directory':
                info.type = tarfile.DIRTYPE; info.size = 0; tf.addfile(info)
            elif kind == 'symlink':
                info.type = tarfile.SYMTYPE; info.linkname = record['target']; info.size = 0; tf.addfile(info)
            elif kind == 'file':
                data = path.read_bytes(); info.type = tarfile.REGTYPE; info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            else:
                raise RuntimeError('CANARY_UNSUPPORTED_SYNTHETIC_RECORD')
        sidecar_info = tarfile.TarInfo('host/var/lib/platform-host-recovery/mounted-config-tree-records.json')
        sidecar_info.uid = 0; sidecar_info.gid = 0; sidecar_info.mode = 0o600
        sidecar_info.size = len(sidecar_bytes)
        tf.addfile(sidecar_info, io.BytesIO(sidecar_bytes))
    cipher = work / 'synthetic-host-capsule.gpg'
    runtime_parent = '/run' if sys.platform.startswith('linux') else '/tmp'
    runtime_root = Path(tempfile.mkdtemp(prefix='g16-', dir=runtime_parent)).resolve()
    os.chmod(runtime_root, 0o700)
    sidecar.GPG_RUNTIME_ROOT = runtime_root
    home = None
    try:
        home = sidecar.new_short_gpg_home()
        subprocess.run(['gpg', '--no-options', '--homedir', str(home), '--batch', '--yes',
                        '--pinentry-mode', 'loopback', '--passphrase-file', str(key_path),
                        '--symmetric', '--cipher-algo', 'AES256', '--output', str(cipher), str(archive)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=120)
    finally:
        if home is not None:
            sidecar.cleanup_short_gpg_home(home)
        runtime_root.rmdir()
    os.chmod(cipher, 0o600)
    return cipher


def _build_overlay(helper, overlay, producer, helper_dir, parent, base, base_receipt_sha, key_path, work):
    expected_sources = Path(helper_dir) / 'expected-sources.json'
    if not expected_sources.is_file():
        expected_sources = (Path(helper_dir) / 'platform-mounted-config-v5' / 'native' /
                            'expected-sources.json')
    if not expected_sources.is_file():
        expected_sources = (Path(helper_dir).parent / 'platform-mounted-config-v5' / 'native' /
                            'expected-sources.json')
    mapping = overlay.load_expected_sources(expected_sources, None)
    records = [{'resource': rid, 'path': '.', 'type': 'directory', 'uid': 0, 'gid': 0,
                'mode': 0o755, 'mtimeNs': 1, 'xattrs': []} for rid in sorted(mapping)]
    sidecar_doc, synthetic_root = _synthetic_mounted_capture(
        helper_dir, work, 'canary-cycle:' + uuid.uuid4().hex)
    candidate = Path(helper_dir).resolve()
    sidecar_root = candidate / 'platform-mounted-config-v5' / 'native'
    if not sidecar_root.is_dir(): sidecar_root = candidate
    sidecar_spec = importlib.util.spec_from_file_location(
        'canary_sidecar_for_capsule', sidecar_root / 'mounted_config_sidecar_v5.py')
    if sidecar_spec is None or sidecar_spec.loader is None: raise RuntimeError('PINNED_V5_SIDECAR_MISSING')
    sidecar_module = importlib.util.module_from_spec(sidecar_spec); sidecar_spec.loader.exec_module(sidecar_module)
    sidecar_bytes = sidecar_module.canonical(sidecar_doc) + b'\n'
    capsule = _encrypt_synthetic_mounted_capsule(sidecar_module, sidecar_bytes, sidecar_doc,
                                                   synthetic_root, key_path, work)
    capsule_proof = {'schema': 'platform.g16-canary-synthetic-capsule/v1', 'status': 'passed',
                     'encryptedSha256': _sha(capsule), 'fullyRecoverable': False, 'syntheticFixture': True}
    capsule_proof_path = work / 'synthetic-capsule-proof.json'
    capsule_proof_path.write_text(json.dumps(capsule_proof, sort_keys=True, separators=(',', ':')))
    os.chmod(capsule_proof_path, 0o600)
    capsule_proof_sha = _sha(capsule_proof_path)
    archive_item = next(x for x in base['files'] if x['name'] == 'full-runtime.tar.gz')
    inner = {
        'schema': overlay.SCHEMA, 'protocolGeneration': 16,
        'parent': {'manifestDigest': parent['manifestDigest']},
        'base': {'kind': 'full-runtime-v1', 'ciphertextSha256': base['encryptedSha256'],
                 'receiptSha256': base_receipt_sha, 'archiveSha256': archive_item['sha256'],
                 'archiveBytes': archive_item['bytes'], 'payloadIncluded': False},
        'sourceCapture': {'mode': 'metadata-overlay-only', 'sourceCount': 57,
                          'recordCount': len(records), 'hardlinkPolicy': 'materialized-independent-files',
                          'byteInvariant': 'exact-v1-path-type-bytes-symlink-targets',
                          'expectedSourcesSha256': overlay.EXPECTED_SOURCES_SHA256,
                          'sourceMapSha256': overlay.EXPECTED_SOURCE_MAP_SHA256,
                          'liveRootEntries': [], 'expiredDerivedCacheFiles': []},
        'records': records,
        'capsule': {'ciphertextSha256': _sha(capsule), 'proofSha256': capsule_proof_sha,
                    'sizeBytes': capsule.stat().st_size, 'member': 'host-capsule/current.gpg'},
        'claims': {'offsiteVerified': False, 'fullyRecoverable': False, 'wholeStackRestoreVerified': False},
    }
    key_bytes=key_path.read_bytes()
    v4_receipt, metadata_gzip = overlay.sign_receipt(inner, key_bytes)
    candidate=Path(helper_dir).resolve()
    v5_native=candidate/'platform-mounted-config-v5'/'native'
    if not v5_native.is_dir():v5_native=candidate
    sidecar_path=v5_native/'mounted_config_sidecar_v5.py'
    sidecar_spec=importlib.util.spec_from_file_location('canary_mounted_config_sidecar_v5',sidecar_path)
    if sidecar_spec is None or sidecar_spec.loader is None: raise RuntimeError('PINNED_V5_SIDECAR_MISSING')
    sidecar=importlib.util.module_from_spec(sidecar_spec);sidecar_spec.loader.exec_module(sidecar)
    # Reuse the exact signed sidecar embedded inside the nested capsule.
    sidecar=sidecar_module
    v5_payload=sidecar.extend_signed_payload(v4_receipt['payload'],sidecar_bytes,sidecar_doc)
    receipt=sidecar.sign_v5_receipt(v5_payload,key_bytes)
    package=work/'synthetic-source-overlay.tar.gz'
    package_sha,_package_bytes,file_manifest=sidecar.build_v5_package(
        receipt,metadata_gzip,capsule,sidecar_bytes,package)
    outer={
        'schema':'platform.ftps-source-metadata-overlay/v4','status':'passed','kind':'source-metadata-overlay-v4',
        'parentManifestId':parent['manifestId'],'parentManifestDigest':parent['manifestDigest'],
        'parentReceiptSha256':hashlib.sha256(helper.canonical(helper.sign(parent))).hexdigest(),
        'parentEncryptedSha256':parent['encryptedSha256'],'backupAt':parent['backupAt'],
        'ciphertext':'pending','encryptedBytes':0,'encryptedSha256':'0'*64,'parts':[],
        'verifiedAt':helper.now(),'fullyRecoverable':False,
        'knownGaps':['synthetic transport canary only; no production capture or restore claim'],
        'baseCompletenessCiphertext':base['ciphertext'],
        'baseCompletenessEncryptedSha256':base['encryptedSha256'],
        'baseCompletenessReceiptSha256':base_receipt_sha,
        'baseArchiveSha256':archive_item['sha256'],'baseArchiveBytes':archive_item['bytes'],
        'overlayPackageSha256':package_sha,
        'overlayReceiptSha256':hashlib.sha256(sidecar.canonical(receipt)).hexdigest(),
        'sourceMapSha256':v4_receipt['payload']['sourceCapture']['sourceMapSha256'],
        'metadataIndexSha256':v4_receipt['payload']['metadataIndex']['sha256'],
        'metadataIndexRawSha256':v4_receipt['payload']['metadataIndex']['rawSha256'],
        'metadataIndexCompressedBytes':v4_receipt['payload']['metadataIndex']['compressedBytes'],
        'metadataIndexRawBytes':v4_receipt['payload']['metadataIndex']['rawBytes'],
        'metadataRecordCount':v4_receipt['payload']['metadataIndex']['recordCount'],
        'capsuleSha256':v4_receipt['payload']['capsule']['ciphertextSha256'],
        'capsuleProofSha256':v4_receipt['payload']['capsule']['proofSha256'],
        'files':file_manifest,'mountedConfigCapture':sidecar.descriptor(sidecar_bytes,sidecar_doc),
    }
    key_fd=os.open(key_path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        cipher=producer.encrypt_split(helper,package,outer,work,key_fd,parent,part_bytes=PART_BYTES)
    finally:
        os.close(key_fd)
    helper.verify_supplement(helper.sign_supplement(outer),parent,staged=True)
    return outer,receipt,cipher


def run(gate_path: Path, helper_dir: Path, *, simulated_transport: bool = False,
        simulated_gpg: bool = False) -> dict:
    cfg = _require_safe_preconditions(gate_path)
    _private_directory(STAGING, create=True)
    _private_directory(JOURNAL_DIR, create=True)
    lock_fds = _open_locks()
    run_id = uuid.uuid4().hex
    root = STAGING / ('g16-transport-' + run_id)
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    _fsync_directory(STAGING)
    _private_directory(root / 'expected-remote-objects', create=True)
    journal_path = JOURNAL_DIR / (run_id + '.json')
    canary_name = 'g16-transport-canary-' + run_id
    folder = '/' + canary_name
    journal = {
        'schema': 'platform.g16-canary-owned-namespace/v1', 'status': 'in-progress',
        'runId': run_id, 'folder': folder, 'scratchPath': str(root), 'phase': 'prepared',
        'createdAt': dt.datetime.now(dt.timezone.utc).isoformat(), 'objects': {},
        'remotePathObservedAbsent': False, 'remoteCreated': False, 'remoteDeleted': False,
    }
    key_path = root / 'synthetic-key'
    _write_private_file(key_path, os.urandom(48).hex().encode('ascii') + b'\n')
    work = root / 'work'; work.mkdir(mode=0o700)
    _fsync_directory(root)
    _verify_candidate_closure(helper_dir)
    helper = _load_helper(helper_dir)
    helper.KEY = key_path
    # install() snapshots the module namespace into its dispatcher object.
    # Reinstall after replacing KEY so the G16 reader receives only this
    # canary-scoped key, never the production credential path.
    helper._g16_module.install(helper.__dict__)
    metadata_loader = helper._g16_module._load_mounted_config_module
    def _canary_mounted_loader():
        module = metadata_loader()
        decrypt = module.decrypt_and_verify_capsule
        module.decrypt_and_verify_capsule = lambda capsule_cipher, sidecar_bytes, sidecar_document, gnupg_home, expected_sha: decrypt(
            capsule_cipher, sidecar_bytes, sidecar_document, gnupg_home, expected_sha, key_path=key_path)
        module.GPG_KEY_PATH = key_path
        return module
    helper._g16_module._load_mounted_config_module = _canary_mounted_loader
    producer_path = Path(helper_dir) / 'source_metadata_overlay_producer_g16.py'
    if not producer_path.exists():
        producer_path = (Path(helper_dir) / 'platform-mounted-config-v5' / 'native' /
                         'source_metadata_overlay_producer_g16.py')
    producer_dir = str(producer_path.parent.resolve())
    if producer_dir not in sys.path:
        sys.path.insert(0, producer_dir)
    module_spec = importlib.util.spec_from_file_location('source_metadata_overlay_producer_g16', producer_path)
    if module_spec is None or module_spec.loader is None: raise RuntimeError('PINNED_G16_PRODUCER_MISSING')
    producer = importlib.util.module_from_spec(module_spec); module_spec.loader.exec_module(producer)
    overlay = helper._g16_module._load_metadata_module()
    created = False
    connections = []
    success = False
    proof = None
    helper.KEY = key_path
    helper.FOLDER = folder

    def connect_canary():
        ftp = _connect(cfg, folder)
        connections.append(ftp)
        return ftp

    helper.connect = connect_canary
    try:
        root_ftp = _connect(cfg, '/')
        connections.append(root_ftp)
        root_ftp.cwd(cfg['folder'])
        usage = sum(int(facts['size']) for _, facts in root_ftp.mlsd() if facts.get('type') == 'file')
        if usage + 4_000_000 >= CAP:
            raise RuntimeError('FTPS_ACCOUNT_CAPACITY_HEADROOM_TOO_LOW')
        root_ftp.cwd('/')
        if canary_name in {name for name, _ in root_ftp.mlsd()}:
            raise RuntimeError('RANDOM_CANARY_NAMESPACE_COLLISION')
        journal['remotePathObservedAbsent'] = True
        journal['phase'] = 'directory-create-intent'
        _write_journal(journal_path, journal)
        # Persist the exact unguessable remote path before the first mutating FTP command.
        root_ftp.mkd(folder); created = True
        journal['remoteCreated'] = True; journal['phase'] = 'directory-created'
        _write_journal(journal_path, journal)
        root_ftp.cwd(folder)
        marker = {'schema': 'platform.ftps-owner/v1', 'owner': 'server-platform-vpn',
                  'folder': folder, 'quotaBytes': CAP}
        marker_bytes = helper.canonical(marker)
        journal['phase'] = 'owner-marker-intent'
        _declare_remote_object(journal_path, journal, root, helper.MARKER, marker_bytes)
        helper.upload_bytes(root_ftp, helper.MARKER, marker_bytes)
        journal['phase'] = 'owner-marker-written'; _write_journal(journal_path, journal)
        root_ftp.quit()

        parent_blob = b'G16 FTPS canary parent bytes only.\n'
        parent_digest = hashlib.sha256(parent_blob).hexdigest()
        manifest_id = 'manifest-g16canary-' + uuid.uuid4().hex[:12]
        bundle = 'backup-' + manifest_id + '.tar.gpg'
        parent = {
            'schema': 'platform.ftps-recovery-point/v2', 'status': 'passed',
            'manifestId': manifest_id, 'manifestDigest': hashlib.sha256(os.urandom(32)).hexdigest(),
            'backupAt': helper.now(), 'bundle': bundle, 'encryptedBytes': len(parent_blob),
            'encryptedSha256': parent_digest,
            'parts': [{'name': bundle + '.part000', 'bytes': len(parent_blob), 'sha256': parent_digest}],
        }
        ftp = connect_canary()
        helper.verify_owner(ftp)
        parent_receipt_bytes = helper.canonical(helper.sign(parent))
        _declare_remote_object(journal_path, journal, root, bundle + '.part000', parent_blob)
        _declare_remote_object(journal_path, journal, root, bundle + '.receipt.json', parent_receipt_bytes)
        helper.upload_bytes(ftp, bundle + '.part000', parent_blob)
        helper.upload_bytes(ftp, bundle + '.receipt.json', parent_receipt_bytes)
        base, base_blob = _base_fixture(helper, parent, key_path.read_bytes())
        base_objects = helper.supplement_objects(base)
        if len(base_objects) != len(base['parts']) or sum(base_objects.values()) != len(base_blob):
            raise RuntimeError('CANARY_BASE_OBJECT_BINDING_INVALID')
        base_offset = 0
        for object_name, object_size in base_objects.items():
            object_bytes = base_blob[base_offset:base_offset + object_size]
            if len(object_bytes) != object_size:
                raise RuntimeError('CANARY_BASE_PART_TRUNCATED')
            part_index = len([name for name in base_objects if name < object_name])
            if hashlib.sha256(object_bytes).hexdigest() != base['parts'][part_index]['sha256']:
                raise RuntimeError('CANARY_BASE_PART_HASH_MISMATCH')
            _declare_remote_object(journal_path, journal, root, object_name, object_bytes)
            helper.upload_bytes(ftp, object_name, object_bytes)
            base_offset += object_size
        if base_offset != len(base_blob):
            raise RuntimeError('CANARY_BASE_PART_TOTAL_MISMATCH')
        ftp.close()
        base_receipt_bytes = helper.supplement_receipt_bytes(base)
        base_receipt_name = base['ciphertext'] + '.receipt.json'
        _declare_remote_object(journal_path, journal, root, base_receipt_name, base_receipt_bytes)
        _declare_remote_object(journal_path, journal, root, base_receipt_name + '.partial', base_receipt_bytes)
        ftp = helper.publish_supplement_receipt(base, parent)
        ftp.close()

        base_receipt_sha = hashlib.sha256(helper.canonical(helper.sign_supplement(base))).hexdigest()
        payload, _inner_receipt, cipher = _build_overlay(helper, overlay, producer, helper_dir, parent, base,
                                                          base_receipt_sha, key_path, work)
        first = payload['parts'][0]
        local_first = work / first['name']
        partial_bytes = max(1, first['bytes'] // 2)
        for part in payload['parts']:
            _declare_remote_object(journal_path, journal, root, part['name'], (work / part['name']).read_bytes())
        overlay_receipt_bytes = helper.supplement_receipt_bytes(payload)
        overlay_receipt_name = payload['ciphertext'] + '.receipt.json'
        _declare_remote_object(journal_path, journal, root, overlay_receipt_name, overlay_receipt_bytes)
        _declare_remote_object(journal_path, journal, root, overlay_receipt_name + '.partial', overlay_receipt_bytes)
        journal['phase'] = 'overlay-object-set-predeclared'; _write_journal(journal_path, journal)
        with local_first.open('rb') as source:
            fragment = source.read(partial_bytes)
        ftp = connect_canary()
        helper.upload_bytes(ftp, first['name'], fragment)
        producer.reserve_overlay(helper, ftp, payload, parent, owned_names=[first['name']])
        producer.upload_part_resumable(helper, ftp, local_first, first['name'], first['bytes'])
        ftp.close()

        for part in payload['parts'][1:]:
            ftp = connect_canary()
            producer.upload_part_resumable(helper, ftp, work / part['name'], part['name'], part['bytes'])
            ftp.close()
        for part in payload['parts']:
            ftp = connect_canary(); digest = hashlib.sha256(); count = 0
            def collect(chunk):
                nonlocal count
                count += len(chunk); digest.update(chunk)
                if count > part['bytes']: raise RuntimeError('CANARY_REMOTE_PART_EXCEEDED')
            ftp.retrbinary('RETR ' + part['name'], collect, blocksize=65536)
            ftp.close()
            if count != part['bytes'] or digest.hexdigest() != part['sha256']:
                raise RuntimeError('CANARY_PART_READBACK_HASH_FAILED')

        ftp = helper.publish_supplement_receipt(payload, parent)
        listing = helper.inventory(ftp)
        parents = helper.points(ftp, listing)
        if len(parents) != 1 or parents[0] != parent:
            raise RuntimeError('CANARY_PARENT_POINT_CHANGED')
        attachments = helper.point_supplements(ftp, listing, parents)[bundle]
        if len(attachments) != 2 or not any(item['kind'] == 'source-metadata-overlay-v4' for item in attachments):
            raise RuntimeError('CANARY_TYPED_ATTACHMENT_NOT_READABLE')
        downloaded_cipher = root / 'downloaded-overlay.gpg'
        digest = hashlib.sha256()
        with downloaded_cipher.open('xb') as output:
            def save_chunk(chunk): output.write(chunk); digest.update(chunk)
            for part in payload['parts']:
                ftp.retrbinary('RETR ' + part['name'], save_chunk, blocksize=65536)
            output.flush(); os.fsync(output.fileno())
        if digest.hexdigest() != payload['encryptedSha256']:
            raise RuntimeError('CANARY_CIPHERTEXT_READBACK_HASH_FAILED')
        ftp.close()
        plain = root / 'downloaded-overlay.tar.gz'
        mounted_module = helper._g16_module._load_mounted_config_module()
        home = mounted_module.new_short_gpg_home()
        try:
            subprocess.run(['gpg', '--no-options', '--homedir', str(home), '--batch', '--pinentry-mode', 'loopback',
                            '--passphrase-file', str(key_path), '--decrypt', '--output', str(plain), str(downloaded_cipher)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=120)
        finally:
            mounted_module.cleanup_short_gpg_home(home)
        if _sha(plain) != payload['overlayPackageSha256']:
            raise RuntimeError('CANARY_DECRYPTED_PACKAGE_HASH_FAILED')
        extracted = root / 'reader-output'
        reader_result = helper.restore_supplement_archive(plain, extracted, payload)
        if reader_result.get('files') != 4 or reader_result.get('fullyRecoverable') is not False:
            raise RuntimeError('CANARY_G16_READER_PARSE_FAILED')
        ftp = connect_canary()
        helper.verify_owner(ftp)
        final_listing = helper.inventory(ftp)
        allowed = {helper.MARKER, bundle + '.part000', bundle + '.receipt.json',
                   *helper.supplement_objects(base), base['ciphertext'] + '.receipt.json'}
        allowed.update(part['name'] for part in payload['parts'])
        allowed.add(payload['ciphertext'] + '.receipt.json')
        if set(final_listing) != allowed:
            raise RuntimeError('CANARY_NAMESPACE_HAS_UNKNOWN_OR_PARTIAL_OBJECTS')
        _validate_owned_remote_inventory(ftp, helper, journal)
        for name in sorted(allowed - {helper.MARKER}):
            ftp.delete(name)
        journal['phase'] = 'marker-delete-intent'; _write_journal(journal_path, journal)
        ftp.delete(helper.MARKER)
        ftp.cwd('/'); ftp.rmd(folder); ftp.quit(); created = False
        journal['status'] = 'cleaned'; journal['phase'] = 'remote-folder-removed'; journal['remoteDeleted'] = True
        _write_journal(journal_path, journal)
        dispatcher_path = Path(helper_dir) / 'g16_overlay_native.py'
        if not dispatcher_path.is_file():
            dispatcher_path = (Path(helper_dir) / 'platform-mounted-config-v5' / 'native' /
                               'g16_overlay_native.py')
        if not dispatcher_path.is_file():
            dispatcher_path = (Path(helper_dir).parent / 'platform-mounted-config-v5' / 'native' /
                               'g16_overlay_native.py')
        proof = {
            'schema': 'platform.g16-live-ftps-transport-canary/v1',
            'status': 'passed', 'verifiedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
            'realFtpsVerified': not simulated_transport, 'simulatedTransport': simulated_transport,
            'transport': 'in-memory fake FTPS' if simulated_transport else 'explicit FTPS',
            'tlsName': cfg['tlsName'], 'realGpgVerified': not simulated_gpg,
            'simulatedGpg': simulated_gpg,
            'typedG16ReceiptVerified': True, 'nativeReaderParsedDownloadedPackage': True,
            'interruptedPartResumedWithAppend': True, 'everyCiphertextPartReadbackVerified': True,
            'parentAndBaseSynthetic': True, 'syntheticHmacAndGpgKeys': True,
            'productionSigningKeyRead': False, 'productionParentModified': False,
            'productionSourceCapturePerformed': False, 'fullyRecoverable': False,
            'remoteCanaryNamespaceRemoved': True, 'partCount': len(payload['parts']),
            'encryptedBytes': payload['encryptedBytes'], 'parentManifestId': manifest_id,
            'g16HelperSha256': _sha(Path(helper_dir) / 'platform-ftps-backup.py'),
            'g16DispatcherSha256': _sha(dispatcher_path),
            'namespaceJournalSha256': _sha(journal_path),
        }
        success = True
        return proof
    finally:
        for ftp in connections:
            try: ftp.close()
            except Exception: pass
        for fd in lock_fds:
            try: os.close(fd)
            except OSError: pass
        if success:
            shutil.rmtree(root)
            if proof is not None:
                out = STAGING / 'g16-live-ftps-transport-canary-proof.json'
                temp = out.with_name(out.name + '.tmp')
                with temp.open('x') as stream:
                    os.chmod(temp, 0o600)
                    json.dump(proof, stream, sort_keys=True, separators=(',', ':'))
                    stream.flush(); os.fsync(stream.fileno())
                os.replace(temp, out)
                fd = os.open(STAGING, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)); os.fsync(fd); os.close(fd)
        elif created:
            # Preserve the isolated namespace and private scratch for explicit
            # root reconciliation; never delete until downloaded-reader success.
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root-reviewed', action='store_true', required=True)
    parser.add_argument('--g15-final-gate', type=Path, required=True,
                        help='root-private normalized final G15 receipt/readback proof')
    parser.add_argument('--helper-dir', type=Path, default=DEFAULT_HELPER_DIR,
                        help='root-owned staged G16 candidate directory; does not replace active G15 helper')
    parser.add_argument('--recover-owned-namespace', type=Path,
                        help='reconcile only the exact journaled canary UUID after verifying its marker and every remote byte prefix')
    args = parser.parse_args()
    if args.recover_owned_namespace:
        result = recover_owned_namespace(args.g15_final_gate, args.helper_dir, args.recover_owned_namespace)
    else:
        result = run(args.g15_final_gate, args.helper_dir)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
