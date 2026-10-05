#!/usr/bin/python3
"""Retire only the previous private capture after current capsule verification."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import types

WORK = Path('/var/lib/platform-host-recovery')
CURRENT = WORK / 'extra-mounted-trees'
OUTPUT = Path('/home/platform_infrastructure/v1-fresh-runtime/state/host-recovery')
CAPSULE = OUTPUT / 'host-recovery-current.tar.gz.gpg'
PROOF = OUTPUT / 'host-recovery-proof.json'
CONFIG = Path('/etc/platform-host-recovery/paths.json')
KEY = Path('/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase')
HELPER = Path('/usr/local/libexec/platform-host-recovery-extra-mounted-trees.py')
HELPER_SHA = '336da4bb00e7f8e80b7ca7462d19b395025961623f0968e9241af00aa34c0fbe'
LIMITS = {'current.tar': 192 * 1024**2, 'index.json': 32 * 1024**2, 'capture-proof.json': 1_000_000}
PREFIX = 'host/var/lib/platform-host-recovery/extra-mounted-trees/'


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def protected(path, limit, uid=0, gid=None, mode=None):
    require(path.resolve(strict=True) == path, 'ALIASED_PATH')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
            and 0 < info.st_size <= limit and not info.st_mode & 0o027, 'FILE_PROTECTION')
    require(gid is None or info.st_gid == gid, 'FILE_GROUP')
    require(mode is None or stat.S_IMODE(info.st_mode) == mode, 'FILE_MODE')
    return info


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def timestamp(value):
    result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(result.tzinfo is not None, 'TIMEZONE_REQUIRED')
    return result


class HashedStream:
    def __init__(self, stream):
        self.stream, self.hash, self.size = stream, hashlib.sha256(), 0

    def read(self, size=-1):
        require(0 <= size <= 2 * 1024**2, 'STREAM_READ_BOUND')
        data = self.stream.read(size)
        self.size += len(data)
        require(self.size <= 2_000_000_000, 'PLAINTEXT_BYTE_BOUND')
        self.hash.update(data)
        return data


def verify_members(proof, helper):
    # GPG alone opens the existing credential. No credential copy/hash/read here.
    custody = protected(KEY, 1_000_000, uid=1000, gid=1000, mode=0o600)
    home = WORK / 'gnupg'
    info = home.lstat()
    require(home.resolve(strict=True) == home and stat.S_ISDIR(info.st_mode)
            and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'GPG_HOME')
    command = ['gpg', '--no-options', '--homedir', str(home), '--batch', '--no-tty',
               '--pinentry-mode', 'loopback', '--passphrase-file', str(KEY),
               '--decrypt', '--output', '-', str(CAPSULE)]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    found, documents = {}, {}
    try:
        stream = HashedStream(process.stdout)
        with tarfile.open(fileobj=stream, mode='r|gz') as archive:
            for count, member in enumerate(archive, 1):
                require(count <= 30000, 'CAPSULE_ENTRY_BOUND')
                name = member.name.removeprefix('./')
                if not name.startswith(PREFIX) or name[len(PREFIX):] not in LIMITS:
                    continue
                leaf = name[len(PREFIX):]
                require(leaf not in found and member.isfile() and not member.islnk()
                        and 0 < member.size <= LIMITS[leaf] and member.uid == 0
                        and member.mode == 0o600, 'CAPSULE_MEMBER')
                source = archive.extractfile(member)
                digest, total, chunks = hashlib.sha256(), 0, []
                for chunk in iter(lambda: source.read(1024**2), b''):
                    total += len(chunk)
                    require(total <= member.size, 'MEMBER_BYTE_BOUND')
                    digest.update(chunk)
                    if leaf != 'current.tar':
                        chunks.append(chunk)
                require(total == member.size, 'MEMBER_TRUNCATED')
                found[leaf] = (digest.hexdigest(), total)
                if chunks:
                    documents[leaf] = json.loads(b''.join(chunks))
        while stream.read(1024**2):
            pass
        require(process.wait(timeout=30) == 0, 'GPG_FAILED')
        require(stream.hash.hexdigest() == proof['plaintextArchiveSha256'], 'PLAINTEXT_SHA')
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
    require(protected(KEY, 1_000_000, uid=1000, gid=1000, mode=0o600) == custody,
            'CREDENTIAL_CUSTODY_CHANGED')
    require(set(found) == set(LIMITS), 'MISSING_MEMBERS')
    capture, index = documents['capture-proof.json'], documents['index.json']
    require(capture.get('schema') == 'platform.extra-mounted-trees-capture/v1'
            and capture.get('treeCount') == 9 and capture.get('runtimeFixtureCount') == 2
            and capture.get('completeBeforeAfterEqual') is True
            and capture.get('productionDataWrites') is False
            and capture.get('servicesStopped') is False
            and capture.get('globalAtomicSnapshot') is False and capture.get('exclusions') == [],
            'CAPTURE_PROOF')
    require(capture.get('archive') == {'file': 'current.tar', 'sha256': found['current.tar'][0],
                                     'bytes': found['current.tar'][1]}
            and capture.get('indexSha256') == found['index.json'][0], 'CAPTURE_BINDING')
    require(index.get('schema') == 'platform.extra-mounted-trees-index/v1'
            and set(index.get('capture', {}).get('trees', {})) == set(helper.ROOTS) | set(helper.FIXTURES)
            and index.get('runtimeFixtures') == sorted(helper.FIXTURES)
            and index.get('baselineCatalogSha256') == helper.CATALOG_SHA256
            and capture.get('baselineCatalogSha256') == helper.CATALOG_SHA256, 'INDEX_SCOPE')
    require(timestamp(capture['startedAt']) <= timestamp(capture['completedAt'])
            and 0 <= (timestamp(proof['capturedAt']) - timestamp(capture['completedAt'])).total_seconds() <= 900,
            'CAPTURE_CYCLE')
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bootstrap-allow-old-proof', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0 and sys.platform == 'linux', 'LINUX_ROOT_REQUIRED')
    os.umask(0o077)
    lock = os.open(WORK / 'capture.lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = os.fstat(lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o077, 'LOCK_PROTECTION')
        protected(PROOF, 1_000_000)
        proof_bytes = PROOF.read_bytes()
        proof = json.loads(proof_bytes)
        protected(CONFIG, 1_000_000)
        config_sha = sha(CONFIG)
        require(proof.get('schema') == 'platform.host-recovery-capsule/v1'
                and proof.get('status') == 'passed' and proof.get('decryptRoundtripVerified') is True
                and proof.get('everyRequiredPathIncluded') is True
                and proof.get('configSha256') == config_sha, 'HOST_PROOF')
        age = (datetime.datetime.now(datetime.timezone.utc) - timestamp(proof['capturedAt'])).total_seconds()
        require(age >= 0 and (args.bootstrap_allow_old_proof or age <= 900), 'HOST_PROOF_STALE')
        require(protected(CAPSULE, 2_000_000_000).st_size == proof.get('encryptedBytes')
                and sha(CAPSULE) == proof.get('encryptedSha256'), 'CIPHERTEXT_BINDING')
        protected(HELPER, 1_000_000)
        helper_bytes = HELPER.read_bytes()
        require(hashlib.sha256(helper_bytes).hexdigest() == HELPER_SHA, 'FINALIZER_PIN')
        module = types.ModuleType('verified_extra_tree_finalizer')
        module.__file__ = str(HELPER)
        exec(compile(helper_bytes, str(HELPER), 'exec'), module.__dict__)
        bindings = verify_members(proof, module)
        require(module.DESTINATION == CURRENT and module.PREVIOUS == WORK / 'extra-mounted-trees-previous',
                'FINALIZER_PATHS')
        require(CURRENT.resolve(strict=True) == CURRENT and CURRENT.is_dir(), 'CURRENT_PATH')
        for leaf, (digest, size) in bindings.items():
            require(protected(CURRENT / leaf, LIMITS[leaf], mode=0o600).st_size == size
                    and sha(CURRENT / leaf) == digest, 'CURRENT_MEMBER_BINDING')
        require(PROOF.read_bytes() == proof_bytes and sha(CONFIG) == config_sha
                and sha(CAPSULE) == proof['encryptedSha256'], 'CAPSULE_CHANGED')
        result = module.finalize_previous_after_verified_cycle()
        require(result.get('status') in ('no-previous', 'previous-retired-after-verified-cycle'), 'FINALIZER_RESULT')
        print(json.dumps({'status': result['status'], 'capsuleVerified': True, 'treeCount': 9}))
    finally:
        os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        reason = str(error) if type(error) is RuntimeError else 'EXTRA_CAPTURE_RETIREMENT_NOT_VERIFIED'
        print(json.dumps({'status': 'blocked', 'reason': reason}))
        sys.exit(1)
