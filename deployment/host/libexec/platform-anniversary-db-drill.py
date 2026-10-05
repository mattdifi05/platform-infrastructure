#!/usr/bin/env python3
"""Restore the signed Anniversary MariaDB point on the active host, then roll back.

Both the pre-apply dump and its round-trip validation are mandatory. The app is
quiesced for the entire window. This is one typed resource drill, not a server
wide restore capability.
"""

import datetime as dt
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

PLAN = 'fce4ae8db3ff4bfda52ec6764b6c7289'
MANIFEST_ID = 'manifest-scheduled-platform-20260929-182357-1f9954'
MANIFEST_DIGEST = 'baf72a7c4ff5d2266b71afe4865ebffeb8be6c363dfc31c12f3a865389009b2c'
RECEIPT_SHA = '1868a512b5a47fe9cc4808622dfb4707d8fe988b0a1d523f801c12ad4c419030'
RESOURCE = 'database:anniversary-mariadb-anniversary'
DATABASE = 'anniversary'
TABLES = ('chapter_unlocks', 'future_items', 'moments', 'timeline_chapters')
APP = 'php-anniversary'
ISOLATED = 'platform-restore-maria-20260929-182357-1f9954'
MARIA_IMAGE = 'sha256:90375fe59893928cf4582cb3aabcdcdc4124f8754f51000cab514711051c245a'
APP_IMAGE = 'sha256:f33cc9484d318484b0edba3383e65d999d8df505e5ca143ae58fc41d1945d465'
WORK = Path('/var/lib/platform-active-restore-20260929')
JOURNAL = WORK / 'anniversary-db-drill.json'
SAFETY = WORK / 'anniversary-original.sql'
OPERATION_LOCK = Path('/var/lib/platform-backup-schedule/operation.lock')
PLAN_RESULT = Path('/var/lib/platform-manual-restore-candidate') / PLAN / 'stage-result.json'
ROOT_SECRET = '/run/secrets/mariadb_root_password'
LIVE_SQL = 'export MYSQL_PWD="$(cat ' + ROOT_SECRET + ')"; exec mariadb -uroot --binary-mode'
LIVE_DUMP = 'export MYSQL_PWD="$(cat ' + ROOT_SECRET + ')"; exec mariadb-dump -uroot --single-transaction --quick --routines --events --triggers --hex-blob --databases ' + DATABASE


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def protected_json(path):
    item = path.lstat()
    if not stat.S_ISREG(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o077 or item.st_size > 2_000_000:
        raise RuntimeError('unprotected restore proof')
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
    temporary = WORK / ('.anniversary-db-' + uuid.uuid4().hex)
    with temporary.open('xb') as stream:
        stream.write((json.dumps(journal, sort_keys=True) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, JOURNAL)
    sync_directory(WORK)


def docker(*arguments, input_bytes=None, timeout=90):
    result = subprocess.run(['docker', *arguments], input=input_bytes,
                            capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('docker operation failed: ' + arguments[0])
    return result.stdout


def inspected(name, image):
    item = json.loads(docker('inspect', name))[0]
    if item['Image'] != image:
        raise RuntimeError('container image binding changed')
    return item


def wait_app():
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        item = inspected(APP, APP_IMAGE)
        if item['State'].get('Health', {}).get('Status') == 'healthy':
            docker('exec', APP, 'curl', '-fsS', '--max-time', '5', '-o', '/dev/null',
                   '-H', 'Host: anniversary.localhost.com', 'http://127.0.0.1/', timeout=12)
            return
        if not item['State']['Running']:
            raise RuntimeError('app exited')
        time.sleep(2)
    raise RuntimeError('app health timeout')


def stop_app():
    if inspected(APP, APP_IMAGE)['State']['Running']:
        docker('stop', '--time', '30', APP, timeout=50)
    if inspected(APP, APP_IMAGE)['State']['Running']:
        raise RuntimeError('app did not stop')


def start_app():
    if not inspected(APP, APP_IMAGE)['State']['Running']:
        docker('start', APP, timeout=45)
    wait_app()


def sql_bytes(raw):
    if len(raw) > 20_000_000:
        raise RuntimeError('database SQL exceeds bound')
    text = raw.decode('utf-8')
    databases = re.findall(r'(?m)^CREATE DATABASE[^;]*;', text)
    uses = re.findall(r'(?m)^USE `([^`]+)`;', text)
    created = re.findall(r'(?m)^CREATE TABLE `([^`]+)`', text)
    dropped = re.findall(r'(?m)^DROP TABLE IF EXISTS `([^`]+)`', text)
    if (len(databases) != 1 or '`' + DATABASE + '`' not in databases[0] or
        uses != [DATABASE] or tuple(sorted(created)) != TABLES or
        tuple(sorted(dropped)) != TABLES or
        re.search(r'(?i)\b(DROP\s+DATABASE|GRANT|REVOKE|CREATE\s+USER|ALTER\s+USER)\b', text)):
        raise RuntimeError('database dump scope changed')
    return {'tables': list(TABLES), 'bytes': len(raw), 'sha256': sha(raw)}


def prepared_sql():
    result = protected_json(PLAN_RESULT)
    manifest = result['manifest']
    proof = result['proof']
    if (result.get('productionModified') is not False or proof.get('status') != 'passed' or
        proof.get('receiptSha256') != RECEIPT_SHA or
        proof.get('actualRemoteDownloadVerified') is not True or
        proof.get('everyArtifactShaAndHmacVerified') is not True or
        manifest.get('id') != MANIFEST_ID or
        manifest.get('signature', {}).get('digest') != MANIFEST_DIGEST):
        raise RuntimeError('exact prepared FTPS point unavailable')
    artifacts = [item for item in manifest['artifacts'] if item['resourceId'] == RESOURCE]
    if len(artifacts) != 1:
        raise RuntimeError('database artifact ambiguous')
    artifact = artifacts[0]
    restored = Path(result['restoredPath'])
    if restored.name != 'backups' or not restored.parent.name.startswith('recovered-') or restored.parent.parent != Path('/var/lib/platform-ftps-backup'):
        raise RuntimeError('restored path changed')
    path = restored / artifact['path']
    if path.is_symlink() or not path.is_file() or path.stat().st_size != artifact['sizeBytes']:
        raise RuntimeError('database artifact changed')
    compressed = path.read_bytes()
    if sha(compressed) != artifact['sha256']:
        raise RuntimeError('database artifact checksum changed')
    raw = gzip.decompress(compressed)
    return raw, sql_bytes(raw), artifact


def live_query(statement):
    # The SQL travels as an argv value, never as shell source. In particular,
    # identifier backticks must not become shell command substitutions.
    command = 'export MYSQL_PWD="$(cat ' + ROOT_SECRET + ')"; exec mariadb -uroot -NBe "$1"'
    return docker('exec', 'gf-mariadb', 'sh', '-lc', command, '_', statement,
                  timeout=20).decode().strip()


def table_counts(container, live=False):
    statement = '; '.join('SELECT COUNT(*) FROM `' + DATABASE + '`.`' + table + '`' for table in TABLES) + ';'
    if live:
        lines = live_query(statement).splitlines()
    else:
        lines = docker('exec', container, 'mariadb', '-uroot', '-NBe', statement, timeout=20).decode().strip().splitlines()
    if len(lines) != len(TABLES) or not all(value.isdigit() for value in lines):
        raise RuntimeError('database table count query failed')
    return dict(zip(TABLES, map(int, lines)))


def no_live_db_sessions():
    active = live_query("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE DB='anniversary' AND ID<>CONNECTION_ID()")
    if active != '0':
        raise RuntimeError('active database clients remain')


def capture_safety():
    if SAFETY.exists():
        raise RuntimeError('existing database safety snapshot')
    raw = docker('exec', 'gf-mariadb', 'sh', '-lc', LIVE_DUMP, timeout=60)
    metadata = sql_bytes(raw)
    fd = os.open(SAFETY, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(WORK)
    return metadata


def isolated_roundtrip(raw):
    item = inspected(ISOLATED, MARIA_IMAGE)
    if item['HostConfig']['NetworkMode'] != 'none':
        raise RuntimeError('isolated database has network')
    if not item['State']['Running']:
        docker('start', ISOLATED, timeout=60)
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                docker('exec', ISOLATED, 'mariadb', '-uroot', '-NBe', 'SELECT 1', timeout=5)
                break
            except RuntimeError:
                time.sleep(2)
        else:
            raise RuntimeError('isolated database did not start')
        docker('exec', '-i', ISOLATED, 'mariadb', '-uroot', '--binary-mode', input_bytes=raw, timeout=60)
        return table_counts(ISOLATED)
    finally:
        if inspected(ISOLATED, MARIA_IMAGE)['State']['Running']:
            docker('stop', '--time', '20', ISOLATED, timeout=40)


def live_import(raw):
    docker('exec', '-i', 'gf-mariadb', 'sh', '-lc', LIVE_SQL, input_bytes=raw, timeout=60)


def rollback(journal):
    if not SAFETY.is_file() or SAFETY.is_symlink():
        raise RuntimeError('safety SQL missing')
    original = SAFETY.read_bytes()
    if sha(original) != journal['originalSha256']:
        raise RuntimeError('safety SQL hash changed')
    stop_app()
    no_live_db_sessions()
    live_import(original)
    if table_counts('gf-mariadb', live=True) != journal['originalCounts']:
        raise RuntimeError('original database counts not restored')
    journal['phase'] = 'original-restored'
    journal['originalRestoredAt'] = now()
    save(journal)
    start_app()
    journal['phase'] = 'original-healthy'
    journal['productionOperational'] = True
    journal['originalHealthyAt'] = now()
    save(journal)


def run():
    if JOURNAL.exists() or SAFETY.exists():
        raise RuntimeError('existing database drill requires reconciliation')
    if inspected('gf-mariadb', MARIA_IMAGE)['State'].get('Health', {}).get('Status') != 'healthy':
        raise RuntimeError('live MariaDB unhealthy')
    wait_app()
    restored, metadata, artifact = prepared_sql()
    journal = {'schema': 'platform.database-active-restore-drill/v1',
               'manifestId': MANIFEST_ID, 'manifestDigest': MANIFEST_DIGEST,
               'receiptSha256': RECEIPT_SHA, 'resourceId': RESOURCE,
               'artifactSha256': artifact['sha256'], 'startedAt': now(),
               'phase': 'planned', 'status': 'running', 'restoredSql': metadata}
    save(journal)
    try:
        stop_app()
        journal['phase'] = 'quiesced'
        save(journal)
        no_live_db_sessions()
        safety = capture_safety()
        journal['originalSha256'] = safety['sha256']
        journal['originalCounts'] = table_counts('gf-mariadb', live=True)
        journal['phase'] = 'safety-captured'
        save(journal)
        if isolated_roundtrip(SAFETY.read_bytes()) != journal['originalCounts']:
            raise RuntimeError('safety roundtrip differs')
        journal['phase'] = 'safety-tested'
        save(journal)
        expected = isolated_roundtrip(restored)
        journal['restoredCounts'] = expected
        journal['phase'] = 'restored-tested-isolated'
        save(journal)
        live_import(restored)
        journal['phase'] = 'restored-live'
        journal['restoredLiveAt'] = now()
        save(journal)
        if table_counts('gf-mariadb', live=True) != expected:
            raise RuntimeError('restored live table counts differ')
        start_app()
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
        journal['errorCode'] = 'ACTIVE_DATABASE_DRILL_FAILED'
        save(journal)
        try:
            if 'originalSha256' in journal:
                rollback(journal)
            else:
                start_app()
            journal['status'] = 'failed-rolled-back'
            journal['phase'] = 'completed'
            save(journal)
        except Exception:
            journal['status'] = 'recovery-required'
            save(journal)
        raise


def recover():
    journal = protected_json(JOURNAL)
    if journal.get('schema') != 'platform.database-active-restore-drill/v1' or journal.get('resourceId') != RESOURCE:
        raise RuntimeError('journal binding changed')
    if journal.get('status') == 'passed':
        return journal
    if 'originalSha256' in journal:
        rollback(journal)
    else:
        start_app()
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
