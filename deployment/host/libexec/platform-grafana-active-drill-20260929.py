#!/usr/bin/python3
"""Bounded production Grafana restore drill; always return to the original DB.

Requires the exact FTPS parent and supplement to have passed remote roundtrips.
Only Grafana is stopped. A root-owned hardlink to the quiescent original database
is preserved before replacement; --recover reverts an interrupted drill.
"""

import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
import uuid


MANIFEST_ID = 'manifest-scheduled-platform-20260929-182357-1f9954'
MANIFEST_DIGEST = 'baf72a7c4ff5d2266b71afe4865ebffeb8be6c363dfc31c12f3a865389009b2c'
STATE = Path('/home/platform_infrastructure/v1-fresh-runtime/state/host-recovery')
WORK = Path('/var/lib/platform-active-restore-20260929')
SOURCE = Path('/var/lib/platform-ftps-backup/supplement-source/durable-volumes')
LIVE = Path('/var/lib/docker/volumes/greenfield_grafana_data/_data/grafana.db')
CONTAINER = 'gf-grafana'
IMAGE_ID = 'sha256:1a53ce20f2de502aa77d37085a6e9fd97e1fb6315992b72432ef8bd07ec50352'
OPERATION_LOCK = Path('/var/lib/platform-backup-schedule/operation.lock')
JOURNAL = WORK / 'grafana-drill.json'
SAFETY = WORK / 'grafana-original.db'


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise RuntimeError('Unsafe recovery proof')
    return json.loads(path.read_text())


def save(value):
    WORK.mkdir(mode=0o700, exist_ok=True)
    info = WORK.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError('Recovery journal directory is unprotected')
    temporary = WORK / ('.grafana-drill-' + uuid.uuid4().hex)
    with temporary.open('xb') as stream:
        stream.write((json.dumps(value, sort_keys=True) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, JOURNAL)
    directory = os.open(WORK, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def docker(*args, timeout=90):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Docker operation failed: ' + args[0])
    return result.stdout.strip()


def inspect():
    item = json.loads(docker('inspect', CONTAINER))[0]
    mounts = [m for m in item['Mounts'] if m['Destination'] == '/var/lib/grafana']
    if item['Image'] != IMAGE_ID or len(mounts) != 1 or mounts[0]['Source'] != str(LIVE.parent):
        raise RuntimeError('Grafana runtime binding changed')
    return item


def exclusive_volume():
    identifiers = docker('ps', '-aq').splitlines()
    if not identifiers or len(identifiers) > 200:
        raise RuntimeError('Unexpected Docker inventory size')
    containers = json.loads(docker('inspect', *identifiers, timeout=30))
    holders = [item['Name'] for item in containers
               for mount in item['Mounts'] if mount['Source'] == str(LIVE.parent)]
    if holders != ['/gf-grafana']:
        raise RuntimeError('Grafana volume has unexpected container holders')


def wait_health():
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        item = inspect()
        if item['State'].get('Health', {}).get('Status') == 'healthy':
            health = json.loads(docker('exec', CONTAINER, 'wget', '-q', '-O', '-',
                                       'http://127.0.0.1:3000/api/health', timeout=10))
            if health.get('database') != 'ok':
                raise RuntimeError('Grafana database health differs')
            return
        if not item['State']['Running']:
            raise RuntimeError('Grafana exited during restore drill')
        time.sleep(2)
    raise RuntimeError('Grafana health deadline expired')


def sqlite_integrity(path):
    with sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True) as db:
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise RuntimeError('Grafana SQLite integrity check failed')
        return int(db.execute('SELECT count(*) FROM dashboard').fetchone()[0])


def ftps_helper():
    path = Path('/usr/local/libexec/platform-ftps-backup.py')
    item = path.lstat()
    if not stat.S_ISREG(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o022:
        raise RuntimeError('FTPS verifier binding changed')
    spec = importlib.util.spec_from_file_location('grafana_drill_ftps', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verified_source():
    parent_proof = safe_json(STATE / 'ftps-proof.json')
    sidecar_proof = safe_json(STATE / 'ftps-supplement-proof.json')
    if (parent_proof.get('status') != 'passed' or parent_proof.get('manifestId') != MANIFEST_ID or
        parent_proof.get('manifestDigest') != MANIFEST_DIGEST or
        not all(parent_proof.get(k) is True for k in ('actualDownloadVerified', 'decryptVerified',
                                                        'everyArtifactShaAndHmacVerified', 'tlsVerified',
                                                        'outsidePublicHtml'))):
        raise RuntimeError('Exact parent FTPS restore proof unavailable')
    if (sidecar_proof.get('status') != 'passed' or sidecar_proof.get('parentManifestId') != MANIFEST_ID or
        sidecar_proof.get('originalPointUnchanged') is not True):
        raise RuntimeError('Exact supplement proof unavailable')
    ftps = ftps_helper()
    connection = ftps.connect()
    try:
        listing = ftps.inventory(connection)
        remote_parent = ftps.verify(ftps.get_json(connection, parent_proof['bundle'] + '.receipt.json'))
        if remote_parent['manifestId'] != MANIFEST_ID or remote_parent['manifestDigest'] != MANIFEST_DIGEST:
            raise RuntimeError('Parent FTPS receipt differs')
        signed = sidecar_proof['receipt']
        payload = ftps.verify_supplement(signed, remote_parent)
        if ftps.get_json(connection, payload['ciphertext'] + '.receipt.json', ftps.SUPPLEMENT_RECEIPT_LIMIT) != signed:
            raise RuntimeError('Remote supplement receipt differs')
        if listing.get(payload['ciphertext']) != payload['encryptedBytes']:
            raise RuntimeError('Remote supplement ciphertext size differs')
    finally:
        connection.quit()
    index_file = SOURCE / 'index.json'
    expected = next((x for x in payload['files'] if x['name'] == 'durable-volumes/index.json'), None)
    if expected is None or index_file.is_symlink() or sha(index_file) != expected['sha256']:
        raise RuntimeError('Authenticated durable index differs')
    index = safe_json(index_file)
    if index.get('schema') != 'platform.durable-volume-supplement/v2':
        raise RuntimeError('Durable index schema differs')
    selected = [x for x in index['files'] if x['name'] == 'grafana/grafana.db' and x['type'] == 'file']
    if len(selected) != 1:
        raise RuntimeError('Grafana source is ambiguous')
    item = selected[0]
    source = SOURCE / item['name']
    source_info = source.lstat()
    if (not stat.S_ISREG(source_info.st_mode) or source_info.st_uid != 0 or
        source_info.st_mode & 0o077 or source_info.st_size != item['bytes'] or
        sha(source) != item['sha256']):
        raise RuntimeError('Verified Grafana source differs')
    return source, item, sqlite_integrity(source)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def quiesce():
    if inspect()['State']['Running']:
        docker('stop', '--time', '30', CONTAINER, timeout=50)
    if inspect()['State']['Running']:
        raise RuntimeError('Grafana did not stop')


def start():
    if not inspect()['State']['Running']:
        docker('start', CONTAINER, timeout=40)
    wait_health()


def replace_with(source, uid, gid, mode):
    temporary = LIVE.parent / ('.grafana-drill-' + uuid.uuid4().hex)
    try:
        with source.open('rb') as incoming, temporary.open('xb') as output:
            shutil.copyfileobj(incoming, output, 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        os.chown(temporary, uid, gid)
        os.chmod(temporary, mode)
        if sha(temporary) != sha(source):
            raise RuntimeError('Grafana staged database hash differs')
        os.replace(temporary, LIVE)
        sync_directory(LIVE.parent)
    finally:
        temporary.unlink(missing_ok=True)


def quarantine_new_wal():
    for suffix in ('-wal', '-shm'):
        path = LIVE.with_name(LIVE.name + suffix)
        if path.exists():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or path.is_symlink():
                raise RuntimeError('Unexpected Grafana SQLite sidecar')
            destination = WORK / ('restored-grafana.db' + suffix)
            if destination.exists():
                raise RuntimeError('Grafana sidecar quarantine already exists')
            os.rename(path, destination)


def rollback(journal):
    if not SAFETY.exists() or sha(SAFETY) != journal['originalSha256']:
        raise RuntimeError('Grafana safety snapshot unavailable')
    quiesce()
    quarantine_new_wal()
    replace_with(SAFETY, journal['originalUid'], journal['originalGid'], journal['originalMode'])
    if sha(LIVE) != journal['originalSha256']:
        raise RuntimeError('Grafana original database not restored')
    journal.update(phase='original-restored', restoredOriginalAt=now())
    save(journal)
    start()
    journal.update(phase='original-healthy', originalHealthyAt=now())
    save(journal)


def apply():
    source, item, restored_dashboards = verified_source()
    item_before = inspect()
    if item_before['State'].get('Health', {}).get('Status') != 'healthy':
        raise RuntimeError('Grafana is not healthy before drill')
    exclusive_volume()
    if JOURNAL.exists() or SAFETY.exists():
        raise RuntimeError('Existing Grafana drill requires reconciliation')
    WORK.mkdir(mode=0o700, exist_ok=True)
    journal = {'schema': 'platform.grafana-active-restore-drill/v1', 'manifestId': MANIFEST_ID,
               'startedAt': now(), 'phase': 'planned', 'status': 'running',
               'restoredDashboardCount': restored_dashboards}
    save(journal)
    replaced = False
    stopped = False
    try:
        stopped = True
        quiesce()
        for suffix in ('-wal', '-shm'):
            if LIVE.with_name(LIVE.name + suffix).exists():
                raise RuntimeError('Quiescent Grafana has an unhandled SQLite sidecar')
        original = LIVE.lstat()
        if not stat.S_ISREG(original.st_mode) or LIVE.is_symlink() or original.st_nlink != 1:
            raise RuntimeError('Original Grafana database binding changed')
        original_sha = sha(LIVE)
        os.link(LIVE, SAFETY)
        if sha(SAFETY) != original_sha:
            raise RuntimeError('Original Grafana safety snapshot differs')
        journal.update(phase='safety-verified', originalSha256=original_sha,
                       originalUid=original.st_uid, originalGid=original.st_gid,
                       originalMode=stat.S_IMODE(original.st_mode), safetyAt=now())
        save(journal)
        replace_with(source, item['uid'], item['gid'], item['mode'])
        replaced = True
        journal.update(phase='restored', restoredAt=now())
        save(journal)
        start()
        journal.update(phase='restored-healthy', restoredHealthyAt=now())
        save(journal)
        rollback(journal)
        journal.update(phase='completed', status='passed', completedAt=now(),
                       originalDatabasePreserved=True, productionOperational=True)
        save(journal)
        return journal
    except Exception as error:
        journal.update(status='failed', errorCode=type(error).__name__, failedAt=now())
        save(journal)
        if replaced and SAFETY.exists():
            try:
                rollback(journal)
                journal.update(phase='rolled-back-after-failure', productionOperational=True)
                save(journal)
            except Exception:
                journal.update(phase='manual-recovery-required', productionOperational=False)
                save(journal)
        elif stopped:
            try:
                start()
                journal.update(phase='original-resumed-after-failure', productionOperational=True)
                save(journal)
            except Exception:
                journal.update(phase='manual-recovery-required', productionOperational=False)
                save(journal)
        raise


def recover():
    journal = safe_json(JOURNAL)
    if journal.get('schema') != 'platform.grafana-active-restore-drill/v1' or not journal.get('originalSha256'):
        raise RuntimeError('No recoverable Grafana safety snapshot')
    if journal.get('phase') in ('completed', 'operator-recovered'):
        return journal
    rollback(journal)
    journal.update(phase='operator-recovered', status='passed', recoveredAt=now(),
                   productionOperational=True)
    save(journal)
    return journal


def main():
    if os.geteuid() != 0 or sys.argv[1:] not in (['--plan'], ['--apply'], ['--recover']):
        raise SystemExit('Root invocation with --plan, --apply, or --recover required')
    os.umask(0o077)
    if sys.argv[1:] == ['--plan']:
        source, item, dashboards = verified_source()
        current = inspect()
        print(json.dumps({'status': 'ready', 'manifestId': MANIFEST_ID,
                          'restoredBytes': item['bytes'], 'restoredDashboardCount': dashboards,
                          'currentHealthy': current['State'].get('Health', {}).get('Status') == 'healthy',
                          'willReturnToOriginal': True}))
        return
    with OPERATION_LOCK.open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = apply() if sys.argv[1:] == ['--apply'] else recover()
        print(json.dumps({'status': result['status'], 'phase': result['phase'],
                          'manifestId': result['manifestId'],
                          'productionOperational': result.get('productionOperational')}))


if __name__ == '__main__':
    main()
