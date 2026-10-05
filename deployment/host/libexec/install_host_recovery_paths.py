#!/usr/bin/python3
"""Root-only atomic additive update for the bounded host-capsule path policy.

This installer edits only /etc/platform-host-recovery/paths.json. It preserves
the existing file as a private rollback copy, refuses a changed baseline,
leaves the capsule bounds intact, and does not reload or start any service.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

CONFIG = Path('/etc/platform-host-recovery/paths.json')
BACKUP_DIR = Path('/var/lib/platform-host-recovery')
EXTENSION = Path(__file__).with_name('host-recovery-paths-extension.json')
EXPECTED_CURRENT_CONFIG_SHA256 = 'fcba81876d4cbc5645e5f92c8712c894684075e24d396075ac2e208f05ff3864'
EXPECTED_EXTENSION_SHA256 = '3a3fa55ee39c8a66230d391e1e677a9f5ac9f077f719695ae43c6cd4143bf70c'
CAPSULE_BOUNDS = {'maximumTotalBytes': 1073741824, 'maximumEntries': 30000}
EXCLUDES = ['.git', 'node_modules', '__pycache__']


class InstallBlocked(RuntimeError):
    pass


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def private_directory(path):
    path = Path(path)
    info = path.lstat()
    if (path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
            info.st_mode & 0o077):
        raise InstallBlocked('ROOT_PRIVATE_BACKUP_DIRECTORY_REQUIRED')
    return info


def read_extension(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or digest_file(path) != EXPECTED_EXTENSION_SHA256:
        raise InstallBlocked('EXTENSION_DIGEST_MISMATCH')
    try:
        value = json.loads(path.read_text())
        required = value['addRequiredPaths']
        paths = value['addPaths']
    except (OSError, KeyError, TypeError, ValueError):
        raise InstallBlocked('EXTENSION_INVALID') from None
    if (value.get('schema') != 'platform.host-recovery-paths-extension/v1' or
            value.get('preserveBounds') != CAPSULE_BOUNDS or
            not isinstance(required, list) or not isinstance(paths, list) or
            not all(isinstance(x, str) and x.startswith('/') and '..' not in Path(x).parts
                    for x in required + paths)):
        raise InstallBlocked('EXTENSION_INVALID')
    return value, required, paths


def safe_current(path):
    path = Path(path)
    info = path.lstat()
    if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > 4 * 1024 * 1024):
        raise InstallBlocked('CURRENT_CONFIG_UNSAFE')
    return info, path.read_bytes()


def write_private_new(path, payload):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            fd = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _copy_xattrs(source, target):
    attrs = {}
    listxattr = getattr(os, 'listxattr', None)
    getxattr = getattr(os, 'getxattr', None)
    setxattr = getattr(os, 'setxattr', None)
    if listxattr is None or getxattr is None or setxattr is None:
        return attrs
    for name in sorted(listxattr(source, follow_symlinks=False)):
        value = getxattr(source, name, follow_symlinks=False)
        setxattr(target, name, value, follow_symlinks=False)
        attrs[name] = hashlib.sha256(value).hexdigest()
    return attrs


def apply_extension(config_path=CONFIG, extension_path=EXTENSION,
                    backup_dir=BACKUP_DIR, expected_sha=EXPECTED_CURRENT_CONFIG_SHA256):
    config_path = Path(config_path)
    extension, add_required, add_paths = read_extension(extension_path)
    info, original = safe_current(config_path)
    try:
        current = json.loads(original)
    except ValueError:
        raise InstallBlocked('CURRENT_CONFIG_INVALID') from None
    if (current.get('schema') != 'platform.host-recovery-capture-config/v1' or
            current.get('maximumTotalBytes') != CAPSULE_BOUNDS['maximumTotalBytes'] or
            current.get('maximumEntries') != CAPSULE_BOUNDS['maximumEntries'] or
            current.get('excludeNames') != EXCLUDES or
            not isinstance(current.get('requiredPaths'), list) or
            not isinstance(current.get('paths'), list)):
        raise InstallBlocked('CURRENT_CONFIG_SCHEMA_OR_BOUND_DRIFT')
    if (set(add_required).issubset(current['requiredPaths']) and
            set(add_paths).issubset(current['paths'])):
        return {'status': 'already-installed', 'currentConfigSha256': digest_bytes(original),
                'addedRequiredPathCount': 0, 'addedCapturePathCount': 0,
                'changedPaths': False}
    if digest_bytes(original) != expected_sha:
        raise InstallBlocked('CURRENT_CONFIG_SHA256_DIFFERS_FROM_REVIEWED_BASELINE')
    backup_dir = Path(backup_dir)
    private_directory(backup_dir)
    rollback = backup_dir / ('paths.json.before-recurring-' + expected_sha + '.json')
    if rollback.exists() or rollback.is_symlink():
        rollback_info = rollback.lstat()
        if (rollback.is_symlink() or not stat.S_ISREG(rollback_info.st_mode) or
                rollback_info.st_uid != 0 or rollback_info.st_nlink != 1 or
                rollback_info.st_mode & 0o077 or rollback.read_bytes() != original):
            raise InstallBlocked('ROLLBACK_COPY_ALREADY_EXISTS_DIFFERENT')
    else:
        write_private_new(rollback, original)
        sync_directory(backup_dir)

    before_required = list(current['requiredPaths'])
    before_paths = list(current['paths'])
    current['requiredPaths'] = before_required + [p for p in add_required if p not in before_required]
    current['paths'] = before_paths + [p for p in add_paths if p not in before_paths]
    rendered = (json.dumps(current, indent=2, ensure_ascii=False) + '\n').encode()
    parent = config_path.parent
    tmp = parent / ('.' + config_path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, stat.S_IMODE(info.st_mode))
    try:
        os.fchown(fd, info.st_uid, info.st_gid)
        os.fchmod(fd, stat.S_IMODE(info.st_mode))
        with os.fdopen(fd, 'wb') as stream:
            fd = -1
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        expected_xattrs = _copy_xattrs(config_path, tmp)
        os.chmod(tmp, stat.S_IMODE(info.st_mode), follow_symlinks=False)
        sync_fd = os.open(tmp, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(sync_fd)
        finally:
            os.close(sync_fd)
        os.replace(tmp, config_path)
        sync_directory(parent)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        tmp.unlink(missing_ok=True)
        raise
    final_info = config_path.lstat()
    if (final_info.st_uid != info.st_uid or final_info.st_gid != info.st_gid or
            stat.S_IMODE(final_info.st_mode) != stat.S_IMODE(info.st_mode)):
        raise InstallBlocked('CONFIG_METADATA_PRESERVATION_FAILED_ROLLBACK_AVAILABLE')
    actual_xattrs = {}
    listxattr = getattr(os, 'listxattr', None)
    getxattr = getattr(os, 'getxattr', None)
    if listxattr is not None and getxattr is not None:
        for name in sorted(listxattr(config_path, follow_symlinks=False)):
            actual_xattrs[name] = hashlib.sha256(
                getxattr(config_path, name, follow_symlinks=False)).hexdigest()
    if actual_xattrs != expected_xattrs:
        raise InstallBlocked('CONFIG_XATTR_PRESERVATION_FAILED_ROLLBACK_AVAILABLE')
    return {'status': 'installed', 'previousConfigSha256': digest_bytes(original),
            'currentConfigSha256': digest_file(config_path), 'rollbackCopy': str(rollback),
            'originalUid': info.st_uid, 'originalGid': info.st_gid,
            'originalMode': oct(stat.S_IMODE(info.st_mode)),
            'originalXattrNames': sorted(getattr(os, 'listxattr', lambda *_a, **_k: [])(
                config_path, follow_symlinks=False)),
            'addedRequiredPathCount': len(set(add_required) - set(before_required)),
            'addedCapturePathCount': len(set(add_paths) - set(before_paths)),
            'changedPaths': True, 'servicesRestarted': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-current-sha256', default=EXPECTED_CURRENT_CONFIG_SHA256)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        raise SystemExit('ROOT_REQUIRED')
    private_directory(BACKUP_DIR)
    result = apply_extension(expected_sha=args.expected_current_sha256)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except InstallBlocked as error:
        raise SystemExit(str(error)) from None
