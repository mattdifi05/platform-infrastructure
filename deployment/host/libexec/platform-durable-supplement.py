#!/usr/bin/python3
"""Publish the bounded durable-volume supplement for the just-finished FTPS point.

Root-only schedule phase. The FTPS helper authenticates the parent, encrypts,
uploads, downloads, decrypts, and verifies every member before publication.
"""

import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import uuid


WORK = Path('/var/lib/platform-ftps-backup')
STATE = Path('/home/platform_infrastructure/v1-fresh-runtime/state/host-recovery')
SOURCE = WORK / 'supplement-source'
HISTORY = WORK / 'supplement-source-history'
SNAPSHOT = Path('/usr/local/libexec/platform-snapshot-durable-volumes.py')
RECOVERY = Path('/usr/local/share/platform-backup/RECOVERY-durable.md')
EXPECTED_SNAPSHOT_SHA256 = '6679a3a40320c65eea5efdb44885aa4deecc268846f336823ce46693078ec519'
EXPECTED_RECOVERY_SHA256 = 'deefff7b966ce3be53f1ecd817566f001432cc4a736ef298a8f32e85be7a362a'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def protected(path, directory=False, private=True):
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    forbidden = 0o077 if private else 0o022
    if not expected(info.st_mode) or info.st_uid != 0 or info.st_mode & forbidden or path.is_symlink():
        raise RuntimeError('Unprotected durable supplement input')
    if not directory and info.st_nlink != 1:
        raise RuntimeError('Linked durable supplement input')


def load_helper():
    helper = Path('/usr/local/libexec/platform-ftps-backup.py')
    protected(helper, private=False)
    spec = importlib.util.spec_from_file_location('durable_ftps', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def current_point(ftps):
    proof_path = STATE / 'ftps-proof.json'
    proof = json.loads(proof_path.read_text())
    expected = ['manifestId', 'manifestDigest', 'bundle', 'backupAt']
    if (proof.get('status') != 'passed' or
        any(not proof.get(key) for key in expected) or
        not all(proof.get(key) is True for key in
                ('actualDownloadVerified', 'decryptVerified', 'everyArtifactShaAndHmacVerified',
                 'manifestHmacVerified', 'tlsVerified', 'outsidePublicHtml'))):
        raise RuntimeError('Current FTPS point lacks complete restore verification')
    if not ftps.NAME.fullmatch(proof['bundle']) or proof['manifestId'] not in proof['bundle']:
        raise RuntimeError('Current FTPS proof has unsafe point identity')
    stamp = datetime.datetime.fromisoformat(proof['backupAt'].replace('Z', '+00:00'))
    if (datetime.datetime.now(datetime.timezone.utc) - stamp).total_seconds() > 24 * 3600:
        raise RuntimeError('FTPS proof is stale')
    return proof


def remote_state(ftps, proof):
    connection = ftps.connect()
    try:
        listing = ftps.inventory(connection)
        parents = ftps.points(connection, listing)
        matches = [item for item in parents if item['bundle'] == proof['bundle'] and
                   item['manifestId'] == proof['manifestId'] and
                   item['manifestDigest'] == proof['manifestDigest']]
        if len(matches) != 1:
            raise RuntimeError('Current FTPS parent is unavailable or differs')
        # Authenticate all retained parents. Other parents may have their own
        # supplements, which the verifier otherwise treats as orphan receipts.
        supplements = ftps.point_supplements(connection, listing, parents)
        return any(item['kind'] == 'host-recovery-helper-delta' for item in supplements[matches[0]['bundle']])
    finally:
        connection.quit()


def fresh_source():
    protected(WORK, True)
    for path, digest in ((SNAPSHOT, EXPECTED_SNAPSHOT_SHA256),
                         (RECOVERY, EXPECTED_RECOVERY_SHA256)):
        protected(path)
        if not digest or sha(path) != digest:
            raise RuntimeError('Durable supplement source binding differs')
    for path in (Path('/usr/local/libexec/platform-ftps-backup.py'),
                 Path('/usr/local/libexec/platform-ftps-restore.py')):
        protected(path, private=False)
    HISTORY.mkdir(mode=0o700, exist_ok=True)
    protected(HISTORY, True)
    if SOURCE.exists():
        protected(SOURCE, True)
        archive = HISTORY / (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
        os.rename(SOURCE, archive)
    SOURCE.mkdir(mode=0o700)
    for name, source in (('platform-ftps-backup.py', Path('/usr/local/libexec/platform-ftps-backup.py')),
                         ('platform-ftps-restore.py', Path('/usr/local/libexec/platform-ftps-restore.py')),
                         ('RECOVERY.md', RECOVERY)):
        destination = SOURCE / name
        with source.open('rb') as incoming, destination.open('xb') as output:
            shutil.copyfileobj(incoming, output, 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(destination, 0o600)
    spec = importlib.util.spec_from_file_location('durable_snapshot', SNAPSHOT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main()
    index = json.loads((SOURCE / 'durable-volumes/index.json').read_text())
    if index.get('schema') != 'platform.durable-volume-supplement/v2':
        raise RuntimeError('Durable snapshot index differs')
    return len(index['files'])


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise SystemExit('Root scheduled invocation only')
    os.umask(0o077)
    ftps = load_helper()
    proof = current_point(ftps)
    ledger = WORK / 'supplement-inflight.json'
    if not ledger.exists() and remote_state(ftps, proof):
        print(json.dumps({'status': 'passed', 'alreadyPublished': True,
                          'manifestId': proof['manifestId']}))
        return
    count = None if ledger.exists() else fresh_source()
    ftps.publish_helper_supplement(proof['bundle'])
    result = json.loads((STATE / 'ftps-supplement-proof.json').read_text())
    if (result.get('status') != 'passed' or
        result.get('parentManifestId') != proof['manifestId'] or
        result.get('originalPointUnchanged') is not True):
        raise RuntimeError('Durable supplement publication failed')
    print(json.dumps({'status': 'passed', 'manifestId': proof['manifestId'],
                      'stagedIndexEntries': count, 'remoteBytes': result['remoteBytes'],
                      'actualDownloadDecryptVerified': True}))


if __name__ == '__main__':
    main()
