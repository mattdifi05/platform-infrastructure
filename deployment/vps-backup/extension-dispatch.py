#!/usr/bin/python3
"""Run a separately installed, root-protected backup extension for signed profiles.

The clean installation has only infrastructure resources. An existing signed
profile with extra fields must keep using its original host-specific code.
"""
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys

CONFIG = pathlib.Path('/etc/platform-vps-backup')
PROFILE = CONFIG / 'profile.json'
EXTENSION = CONFIG / 'extensions' / 'legacy-vps-backup'
BASE_FIELDS = frozenset({
    'hostname', 'machineId', 'generation', 'previousAdmissionSha256',
    'enrolledAt', 'pins', 'volumeCount', 'captureRoots',
    'productionRestoreAuthorized', 'captureAuthorized', 'pauseAuthorized',
    'offsiteAuthorized', 'databaseRecovery', 'recoveryKeysCustodied',
    'controlCenterImageCompatibility',
})
REQUIRED_FIELDS = BASE_FIELDS - {'controlCenterImageCompatibility'}
COMMANDS = frozenset({
    'platform-vps-backup-runner.py', 'panel-queue.py', 'ftps-sync.py',
    'production-restore.py',
})


def protected(path, directory=False):
    info = path.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022 or path.is_symlink():
        raise RuntimeError('Backup extension path is not root protected')
    if directory and not stat.S_ISDIR(info.st_mode):
        raise RuntimeError('Backup extension directory is invalid')
    if not directory and not stat.S_ISREG(info.st_mode):
        raise RuntimeError('Backup extension file is invalid')
    return path


def signed_profile_needs_extension():
    if not PROFILE.exists() and not PROFILE.is_symlink():
        if (CONFIG / 'profile.sig').exists() or (CONFIG / 'profile.sig').is_symlink():
            raise RuntimeError('Backup signature exists without a profile')
        return False  # Fresh enrollment has no signed profile yet.
    protected(CONFIG, True)
    protected(PROFILE)
    signature = protected(CONFIG / 'profile.sig')
    public = protected(CONFIG / 'authority-public.pem')
    if PROFILE.stat().st_size > 262144:
        raise RuntimeError('Backup profile is too large')
    verified = subprocess.run(
        ['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(public),
         '-rawin', '-in', str(PROFILE), '-sigfile', str(signature)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
    )
    if verified.returncode:
        raise RuntimeError('Backup profile signature is invalid')
    profile = json.loads(PROFILE.read_text())
    if not isinstance(profile, dict) or not REQUIRED_FIELDS.issubset(profile):
        raise RuntimeError('Backup profile structure is invalid')
    return bool(set(profile) - BASE_FIELDS)


def extension_script(command):
    if command not in COMMANDS:
        raise RuntimeError('Unsupported backup extension command')
    if not signed_profile_needs_extension():
        return None
    protected(CONFIG / 'extensions', True)
    protected(EXTENSION, True)
    manifest = protected(EXTENSION / 'manifest.json')
    if manifest.stat().st_size > 131072:
        raise RuntimeError('Backup extension manifest is too large')
    document = json.loads(manifest.read_text())
    if document.get('schema') != 'platform.vps-backup-code-extension/v1':
        raise RuntimeError('Backup extension manifest schema differs')
    entries = document.get('files')
    if not isinstance(entries, list) or not 4 <= len(entries) <= 64:
        raise RuntimeError('Backup extension file list is invalid')
    seen = set()
    for entry in entries:
        relative = entry.get('path') if isinstance(entry, dict) else None
        digest = entry.get('sha256') if isinstance(entry, dict) else None
        if (not isinstance(relative, str) or not relative.startswith(
                ('deployment/vps-backup/', 'control-center/backup/', 'scripts/'))
                or str(pathlib.PurePosixPath(relative)) != relative
                or pathlib.PurePosixPath(relative).suffix not in ('.py', '.mjs')
                or not re.fullmatch('[a-f0-9]{64}', digest or '')
                or relative in seen or '..' in pathlib.PurePosixPath(relative).parts):
            raise RuntimeError('Backup extension file identity is invalid')
        seen.add(relative)
        file = EXTENSION
        for part in pathlib.PurePosixPath(relative).parts[:-1]:
            file = protected(file / part, True)
        file = protected(file / pathlib.PurePosixPath(relative).name)
        if hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Backup extension code differs from manifest')
    relative = 'deployment/vps-backup/' + command
    if relative not in seen:
        raise RuntimeError('Required backup extension command is absent')
    return EXTENSION / relative


def dispatch_if_needed(command):
    target = extension_script(command)
    if target is not None:
        os.execv(sys.executable, [sys.executable, '-B', str(target), *sys.argv[1:]])
