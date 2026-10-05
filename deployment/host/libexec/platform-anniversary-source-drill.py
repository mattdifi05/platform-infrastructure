#!/usr/bin/env python3
"""Exact-point active source restore drill with atomic rollback.

This script is deliberately pinned to one source and one container. It never
promotes the whole catalog or changes the active backup admission.
"""

import ctypes
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import uuid

PLAN = 'fce4ae8db3ff4bfda52ec6764b6c7289'
MANIFEST_ID = 'manifest-scheduled-platform-20260929-182357-1f9954'
MANIFEST_DIGEST = 'baf72a7c4ff5d2266b71afe4865ebffeb8be6c363dfc31c12f3a865389009b2c'
RECEIPT_SHA = '1868a512b5a47fe9cc4808622dfb4707d8fe988b0a1d523f801c12ad4c419030'
RESOURCE = 'source:anniversary'
NAME = 'anniversary'
CONTAINER = 'php-anniversary'
IMAGE_ID = 'sha256:f33cc9484d318484b0edba3383e65d999d8df505e5ca143ae58fc41d1945d465'
LIVE = Path('/home/platform_infrastructure/v1-fresh-data/src/anniversary')
WORK = Path('/var/lib/platform-active-restore-20260929')
STAGE = WORK / 'anniversary-source-stage'
JOURNAL = WORK / 'anniversary-source-drill.json'
OPERATION_LOCK = Path('/var/lib/platform-backup-schedule/operation.lock')
PLAN_RESULT = Path('/var/lib/platform-manual-restore-candidate') / PLAN / 'stage-result.json'
EXTRA_FILES = frozenset({'private/database/seed.sql', 'private/database/schema.sql'})
AT_FDCWD = -100
RENAME_EXCHANGE = 2


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def protected_json(path):
    item = path.lstat()
    if not stat.S_ISREG(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o077 or item.st_size > 2_000_000:
        raise RuntimeError('unprotected recovery proof')
    return json.loads(path.read_bytes())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(journal):
    item = WORK.lstat()
    if not stat.S_ISDIR(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o077:
        raise RuntimeError('unprotected journal directory')
    temporary = WORK / ('.anniversary-drill-' + uuid.uuid4().hex)
    with temporary.open('xb') as stream:
        stream.write((json.dumps(journal, sort_keys=True) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, JOURNAL)
    sync_directory(WORK)


def docker(*arguments, timeout=90):
    result = subprocess.run(['docker', *arguments], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('docker operation failed: ' + arguments[0])
    return result.stdout.strip()


def inspect_container():
    container = json.loads(docker('inspect', CONTAINER))[0]
    if container['Image'] != IMAGE_ID:
        raise RuntimeError('container image changed')
    mounts = {(m['Source'], m['Destination'], m['RW']) for m in container['Mounts']}
    if ((str(LIVE), '/var/www/projects/anniversary', False) not in mounts or
        (str(LIVE / 'public/assets/uploads'), '/var/www/projects/anniversary/public/assets/uploads', True) not in mounts):
        raise RuntimeError('source mount binding changed')
    return container


def no_other_writers():
    identifiers = docker('ps', '-aq').splitlines()
    if len(identifiers) > 200:
        raise RuntimeError('docker inventory unbounded')
    for container in json.loads(docker('inspect', *identifiers, timeout=45)):
        for mount in container['Mounts']:
            source = PurePosixPath(mount['Source'])
            if mount['RW'] and (source == PurePosixPath(LIVE) or PurePosixPath(LIVE) in source.parents):
                if container['Name'] != '/' + CONTAINER or source != PurePosixPath(LIVE / 'public/assets/uploads'):
                    raise RuntimeError('unexpected source writer')


def prepared_archive():
    result = protected_json(PLAN_RESULT)
    manifest = result['manifest']
    proof = result['proof']
    if (result.get('productionModified') is not False or proof.get('status') != 'passed' or
        proof.get('receiptSha256') != RECEIPT_SHA or
        proof.get('everyArtifactShaAndHmacVerified') is not True or
        proof.get('actualRemoteDownloadVerified') is not True or
        manifest.get('id') != MANIFEST_ID or
        manifest.get('signature', {}).get('digest') != MANIFEST_DIGEST):
        raise RuntimeError('exact prepared FTPS point unavailable')
    artifacts = [item for item in manifest['artifacts'] if item['resourceId'] == RESOURCE]
    if len(artifacts) != 1:
        raise RuntimeError('source artifact missing or ambiguous')
    artifact = artifacts[0]
    restored = Path(result['restoredPath'])
    if restored.name != 'backups' or not restored.parent.name.startswith('recovered-') or restored.parent.parent != Path('/var/lib/platform-ftps-backup'):
        raise RuntimeError('restored path changed')
    path = restored / artifact['path']
    if path.is_symlink() or not path.is_file() or path.stat().st_size != artifact['sizeBytes'] or digest(path) != artifact['sha256']:
        raise RuntimeError('artifact checksum changed')
    return path, artifact


def archive_members(archive):
    members = archive.getmembers()
    if not members or len(members) > 1000:
        raise RuntimeError('unexpected archive member count')
    seen = set()
    total = 0
    for member in members:
        path = PurePosixPath(member.name)
        if (path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != NAME or
            member.name in seen or not (member.isdir() or member.isfile()) or
            member.uid != 1000 or member.gid != 1000 or member.mode & 0o7000):
            raise RuntimeError('unsafe source archive member')
        seen.add(member.name)
        if member.isfile():
            total += member.size
        if total > 200_000_000:
            raise RuntimeError('source expansion exceeds bound')
    if NAME not in seen:
        raise RuntimeError('source archive root missing')
    return members


def extras_in_live(members):
    seen = {str(PurePosixPath(*PurePosixPath(m.name).parts[1:])) for m in members}
    extras = {str(path.relative_to(LIVE)) for path in LIVE.rglob('*') if str(path.relative_to(LIVE)) not in seen}
    if extras != EXTRA_FILES or any(not (LIVE / item).is_file() for item in extras):
        raise RuntimeError('unexpected live files outside source archive')
    return extras


def extract_source(archive_path):
    if STAGE.exists():
        raise RuntimeError('existing source stage requires reconciliation')
    with tarfile.open(archive_path, 'r:gz') as archive:
        members = archive_members(archive)
        extras = extras_in_live(members)
        STAGE.mkdir(mode=0o700)
        directories = []
        for member in members:
            relative = PurePosixPath(*PurePosixPath(member.name).parts[1:])
            destination = STAGE if str(relative) == '.' else STAGE.joinpath(*relative.parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                directories.append((destination, member.mode))
            else:
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with archive.extractfile(member) as source, destination.open('xb') as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                os.chown(destination, member.uid, member.gid)
                os.chmod(destination, member.mode)
        for relative in sorted(extras):
            source = LIVE / relative
            destination = STAGE / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(source, destination, follow_symlinks=False)
            item = source.stat()
            os.chown(destination, item.st_uid, item.st_gid)
            if digest(source) != digest(destination):
                raise RuntimeError('live extra changed during copy')
        for destination, mode in sorted(directories, key=lambda item: len(item[0].parts), reverse=True):
            os.chown(destination, 1000, 1000)
            os.chmod(destination, mode)
        sync_directory(STAGE)
        sync_directory(WORK)
        return len(members), sum(m.size for m in members if m.isfile()), sorted(extras)


def exchange(first, second):
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.renameat2(AT_FDCWD, os.fsencode(first), AT_FDCWD, os.fsencode(second), RENAME_EXCHANGE)
    if result != 0:
        raise OSError(ctypes.get_errno(), 'atomic source exchange failed')
    sync_directory(first.parent)
    sync_directory(second.parent)


def wait_healthy():
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        container = inspect_container()
        if container['State'].get('Health', {}).get('Status') == 'healthy':
            # Apache's Docker health only tests syntax. Also request the app.
            response = docker('exec', CONTAINER, 'curl', '-fsS', '--max-time', '5',
                              '-o', '/dev/null', '-H', 'Host: anniversary.localhost.com',
                              'http://127.0.0.1/', timeout=12)
            return response
        if not container['State']['Running']:
            raise RuntimeError('container exited')
        time.sleep(2)
    raise RuntimeError('container health timeout')


def stop():
    if inspect_container()['State']['Running']:
        docker('stop', '--time', '30', CONTAINER, timeout=50)
    if inspect_container()['State']['Running']:
        raise RuntimeError('container did not stop')


def start():
    if not inspect_container()['State']['Running']:
        docker('start', CONTAINER, timeout=45)
    wait_healthy()


def placement(journal):
    live = LIVE.stat()
    stage = STAGE.stat()
    original = journal['originalInode']
    restored = journal['restoredInode']
    if live.st_dev != stage.st_dev or live.st_dev != journal['device']:
        raise RuntimeError('source filesystem changed')
    if (live.st_ino, stage.st_ino) == (original, restored):
        return 'original'
    if (live.st_ino, stage.st_ino) == (restored, original):
        return 'restored'
    raise RuntimeError('source inode binding changed')


def rollback(journal):
    stop()
    if placement(journal) == 'restored':
        exchange(LIVE, STAGE)
    if placement(journal) != 'original':
        raise RuntimeError('original source not restored')
    journal['phase'] = 'original-restored'
    journal['originalRestoredAt'] = now()
    save(journal)
    start()
    journal['phase'] = 'original-healthy'
    journal['productionOperational'] = True
    journal['originalHealthyAt'] = now()
    save(journal)


def run():
    if JOURNAL.exists() or STAGE.exists():
        raise RuntimeError('existing source drill requires reconciliation')
    wait_healthy()
    no_other_writers()
    archive, artifact = prepared_archive()
    count, extracted_bytes, extras = extract_source(archive)
    original_stat = LIVE.stat()
    restored_stat = STAGE.stat()
    if original_stat.st_dev != restored_stat.st_dev:
        raise RuntimeError('atomic exchange unavailable across filesystems')
    journal = {'schema': 'platform.source-active-restore-drill/v1',
               'manifestId': MANIFEST_ID, 'manifestDigest': MANIFEST_DIGEST,
               'receiptSha256': RECEIPT_SHA, 'resourceId': RESOURCE,
               'artifactSha256': artifact['sha256'], 'startedAt': now(),
               'status': 'running', 'phase': 'staged', 'device': original_stat.st_dev,
               'originalInode': original_stat.st_ino, 'restoredInode': restored_stat.st_ino,
               'archiveMemberCount': count, 'extractedBytes': extracted_bytes,
               'preservedExcludedFiles': extras}
    save(journal)
    try:
        stop()
        journal['phase'] = 'quiesced'
        save(journal)
        exchange(LIVE, STAGE)
        journal['phase'] = 'restored-live'
        journal['restoredLiveAt'] = now()
        save(journal)
        start()
        journal['phase'] = 'restored-healthy'
        journal['restoredHealthyAt'] = now()
        save(journal)
        rollback(journal)
        journal['status'] = 'passed'
        journal['phase'] = 'completed'
        journal['completedAt'] = now()
        save(journal)
        return journal
    except Exception:
        journal['status'] = 'recovering'
        journal['errorCode'] = 'ACTIVE_SOURCE_DRILL_FAILED'
        save(journal)
        try:
            rollback(journal)
            journal['status'] = 'failed-rolled-back'
            journal['phase'] = 'completed'
            save(journal)
        except Exception:
            journal['status'] = 'recovery-required'
            save(journal)
        raise


def recover():
    journal = protected_json(JOURNAL)
    if journal.get('schema') != 'platform.source-active-restore-drill/v1' or journal.get('resourceId') != RESOURCE:
        raise RuntimeError('journal binding changed')
    if journal.get('status') == 'passed' and placement(journal) == 'original':
        return journal
    rollback(journal)
    journal['status'] = 'recovered'
    journal['phase'] = 'completed'
    journal['completedAt'] = now()
    save(journal)
    return journal


def main():
    if os.geteuid() != 0 or sys.argv[1:] not in (['--run'], ['--recover']):
        raise SystemExit('root and --run or --recover required')
    WORK.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(OPERATION_LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        value = run() if sys.argv[1:] == ['--run'] else recover()
    print(json.dumps(value, sort_keys=True))


if __name__ == '__main__':
    main()
