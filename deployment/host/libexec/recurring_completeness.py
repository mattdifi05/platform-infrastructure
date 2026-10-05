#!/usr/bin/python3
"""Root-only recurring completeness cycle; plan is read-only, no restore path.

The cycle is designed to run after the ordinary scheduled catalog backup has a
fresh, authenticated local+FTPS proof. It captures the complete runtime state,
verifies the captures in isolation, stages the fixed 12-file supplement, then
delegates upload/readback to the exact installed root publisher. It never prunes
or cleans old cycle directories. It is local candidate code and is not installed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import uuid
from zoneinfo import ZoneInfo

ROOT = Path('/var/lib/platform-completeness-recurring')
BACKUP_WORK = Path('/var/lib/platform-ftps-backup')
PUBLISH_STAGING = BACKUP_WORK / 'completeness-source'
OPERATOR_STATE = Path('/home/platform_infrastructure/v1-fresh-runtime/local-private-backup')
FTPS_HELPER = Path('/usr/local/libexec/platform-ftps-backup.py')
PUBLISHER = Path('/usr/local/libexec/platform-completeness-publisher.py')
RESTORE_HELPER = Path('/usr/local/libexec/platform-ftps-restore.py')
PRODUCER = Path('/usr/local/libexec/completeness_producer.py')
PUBLISHER_SOURCE = Path('/usr/local/libexec/platform-completeness-publisher.py')
ACL_COLLECTOR = Path('/usr/local/libexec/collect_acl_inventory.py')
BUILDER_SOURCE = Path('/usr/local/libexec/completeness_bundle_source_metadata_v2.py')
VOLUME_SOURCE = Path('/usr/local/libexec/recurring-cold-volume-capture.py')
IMAGE_VERIFIER_SOURCE = Path('/usr/local/libexec/recurring-isolated-image-load-metadata-v2.py')
SOURCE_VERIFIER = Path('/usr/local/libexec/offline_verify_source_metadata_v2.py')
BACKUP_ROOT = Path('/home/platform_infrastructure/v1-fresh-runtime/local-private-backup/data/backups')
SOURCE_ROOT = Path('/home/platform_infrastructure/v1-fresh-data/src')
ACL_ROOT = Path('/var/lib/platform-acl-inventory-20260930')
HOST_RECOVERY_CONFIG = Path('/etc/platform-host-recovery/paths.json')
HOST_RECOVERY_PROOF = Path('/home/platform_infrastructure/v1-fresh-runtime/state/host-recovery/host-recovery-proof.json')
HOST_RECOVERY_CAPSULE = Path('/home/platform_infrastructure/v1-fresh-runtime/state/host-recovery/host-recovery-current.tar.gz.gpg')
HOST_RECOVERY_KEY = Path('/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase')
HOST_CAPSULE_VERIFY_TMP = Path('/run')
HOST_RECOVERY_EXTENSION = Path(__file__).with_name('host-recovery-paths-extension.json')
EXTRA_DATABASE_CAPSULE_MEMBER = 'host/var/lib/platform-host-recovery/extra-database-exports/current.tar'
HOST_EXTRA_DATABASE_BUNDLE = Path('/var/lib/platform-host-recovery/extra-database-exports/current.tar')
MAX_EXTRA_DATABASE_BUNDLE_BYTES = 536_870_912 + 2_000_000
LOCK_PATHS = (
    Path('/var/lib/platform-server-ai-admin/operator-deploy.lock'),
    Path('/var/lib/platform-backup-schedule/operation.lock'),
)
TRANSFER_LOCK = BACKUP_WORK / 'transfer.lock'
PENDING_NAMES = ('upload-inflight.json', 'upload-preserved.json',
                 'supplement-inflight.json', 'retention-inflight.json')
ACTIVE_UNITS = ('platform-publish-completeness-20260930.service',
                'platform-completeness-window-20260930.service')
MAX_BYTES = 70_000_000_000
MAX_POINTS = 6
MAX_AGE_SECONDS = 14 * 86400
SCHEDULE = ('Monday', 'Wednesday', 'Friday')
SCHEDULE_RETRY_WINDOW_SECONDS = 6 * 60 * 60
SCHEDULE_RETRY_INTERVAL_SECONDS = 60
TRANSIENT_SCHEDULE_BLOCKS = {
    'GLOBAL_OPERATION_BUSY',
    'PUBLICATION_WINDOW_ALREADY_ACTIVE',
    'PENDING_TRANSFER_OR_RETENTION_STATE',
    'NATIVE_BACKUP_OPERATION_ACTIVE',
}
PARENT_NAME = re.compile(r'backup-(manifest-[a-z0-9][a-z0-9-]{15,127})\.tar\.gpg')
ALLOWED_CAPTURE_ROOT = Path('/var/lib/platform-completeness-recurring')
HELPER_PINS = {
    'builder': 'af99c2a56a9f0c5757cf00ac37ff3d7e1bad7bed4e2d0834638c038665823d0e',
    'cold': '1fcdcd6c3e2cd89b83c0997544c6cb8827af09a50a5ce976dc8caae9f535e5bf',
    'package': '70550e35420bdcb04e686154baeec36c03918bbe9299e9f953e8250d4b25ebf8',
    'adapter': 'de8afc787d8e50d91788de96c0eb84c316c3ff4136f8470bb064c87f6129b654',
    'source_verify': 'bfae1a0eed9ee39690afeaced484e0fdbf7627387c5e633a9fa8eef278d60ce2',
    'image': 'd5442864acd52a99903f5801183f68b7d71a4a42b76b391e5c81461f9f562510',
    'acl': '5436f5eb7cf8b7ebf4ba4c9e4c257f9db2a00f35e7f062875b1094c1549d6911',
}


class CycleBlocked(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise CycleBlocked(code)


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value):
    if not isinstance(value, str):
        raise CycleBlocked('INVALID_BACKUP_TIME')
    try:
        result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise CycleBlocked('INVALID_BACKUP_TIME') from None
    if result.tzinfo is None:
        raise CycleBlocked('NAIVE_BACKUP_TIME')
    return result.astimezone(dt.timezone.utc)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def private_json(path, *, required=True, max_bytes=4 * 1024 * 1024):
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        if required:
            raise CycleBlocked('REQUIRED_PRIVATE_EVIDENCE_MISSING') from None
        return None
    if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size <= 0 or
            info.st_size > max_bytes):
        raise CycleBlocked('UNSAFE_PRIVATE_EVIDENCE')
    try:
        return json.loads(path.read_bytes())
    except (OSError, ValueError):
        raise CycleBlocked('INVALID_PRIVATE_EVIDENCE') from None


def atomic_json(path, value):
    path = Path(path)
    fd, temp_path = None, path.with_name('.' + path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            fd = None
            json.dump(value, stream, sort_keys=True, separators=(',', ':'))
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except BaseException:
        if fd is not None:
            os.close(fd)
        temp_path.unlink(missing_ok=True)
        raise


def load_module(name, path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise CycleBlocked('PINNED_HELPER_MISSING')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def pinned_helper(name):
    installed = {
        'builder': BUILDER_SOURCE, 'cold': VOLUME_SOURCE,
        'package': Path('/usr/local/libexec/recurring-package-cold-volumes.py'),
        'adapter': Path('/usr/local/libexec/source_adapter.py'),
        'source_verify': SOURCE_VERIFIER, 'image': IMAGE_VERIFIER_SOURCE,
        'acl': ACL_COLLECTOR,
    }
    candidate_root = Path(__file__).resolve().parents[1]
    candidate = {
        'builder': candidate_root / 'source-metadata-v2-candidate/completeness_bundle_source_metadata_v2.py',
        'cold': candidate_root / 'source-replace-candidate/cold_volume_capture.py',
        'package': candidate_root / 'source-replace-candidate/package_cold_volumes.py',
        'adapter': candidate_root / 'source-replace-candidate/source_adapter.py',
        'source_verify': candidate_root / 'source-metadata-v2-candidate/offline_verify_source_metadata_v2.py',
        'image': candidate_root / 'source-metadata-v2-candidate/isolated_image_load_metadata_v2.py',
        'acl': candidate_root / 'acl-inventory-candidate/collect_acl_inventory.py',
    }
    path = installed[name] if installed[name].is_file() else candidate[name]
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise CycleBlocked('PINNED_HELPER_MISSING') from None
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
        raise CycleBlocked('PINNED_HELPER_UNSAFE')
    if sha256(path) != HELPER_PINS[name]:
        raise CycleBlocked('PINNED_HELPER_DIGEST_MISMATCH')
    return path


def checked_systemd_state(unit, runner=subprocess.check_output):
    output = runner(['systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'Result',
                     '-p', 'ExecMainStatus', '--no-pager'], text=True, timeout=15)
    return dict(line.split('=', 1) for line in output.splitlines() if '=' in line)


def reject_active_services(probe=checked_systemd_state):
    for unit in ACTIVE_UNITS:
        state = probe(unit)
        if state.get('ActiveState') in ('active', 'activating', 'reloading'):
            raise CycleBlocked('PUBLICATION_WINDOW_ALREADY_ACTIVE')


def acquire_lock(path, *, exclusive=True):
    path = Path(path)
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
            info.st_mode & 0o022):
        os.close(fd)
        raise CycleBlocked('UNSAFE_GLOBAL_LOCK')
    try:
        fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise CycleBlocked('GLOBAL_OPERATION_BUSY') from None
    return fd


def release_locks(fds):
    for fd in reversed(fds):
        os.close(fd)


def check_pending_state(work=BACKUP_WORK):
    freeze_paths = (work / 'offsite-freeze.json',
                    Path('/var/lib/platform-backup-schedule/offsite-freeze.json'))
    if any(path.exists() or path.is_symlink() for path in freeze_paths):
        raise CycleBlocked('OFFSITE_PUBLICATION_FROZEN')
    for name in PENDING_NAMES:
        path = work / name
        if path.exists() or path.is_symlink():
            raise CycleBlocked('PENDING_TRANSFER_OR_RETENTION_STATE')
    state_path = OPERATOR_STATE / 'broker-state' / 'active-operation.json'
    if state_path.exists() or state_path.is_symlink():
        raise CycleBlocked('NATIVE_BACKUP_OPERATION_ACTIVE')


def check_transfer_idle():
    # All publisher and scheduled-transfer paths take this lock exclusively.
    # Taking it exclusively here detects both read and write holders.
    fd = acquire_lock(TRANSFER_LOCK, exclusive=True)
    os.close(fd)


def admission_binding(publisher_module):
    active = publisher_module.verify_authority(
        load_module('current_ftps_helper', FTPS_HELPER))
    if (not isinstance(active, dict) or active.get('generation') != 16 or
            not re.fullmatch('[a-f0-9]{64}', str(active.get('admissionSha256', '')))):
        raise CycleBlocked('ADMISSION_BINDING_DRIFT')
    return active


def _validate_points(points, inventory, now=None):
    now = now or utcnow()
    if not 1 <= len(points) <= MAX_POINTS:
        raise CycleBlocked('REMOTE_POINT_COUNT_OUT_OF_POLICY')
    for point in points:
        if not PARENT_NAME.fullmatch(str(point.get('bundle', ''))):
            raise CycleBlocked('INVALID_REMOTE_POINT_NAME')
        age = (now - parse_time(point.get('backupAt'))).total_seconds()
        if age < -300 or age > MAX_AGE_SECONDS:
            raise CycleBlocked('REMOTE_POINT_RETENTION_OUT_OF_POLICY')
        if point.get('status') != 'passed' or not re.fullmatch('[a-f0-9]{64}', str(point.get('manifestDigest', ''))):
            raise CycleBlocked('REMOTE_POINT_NOT_AUTHENTICATED')
        if inventory.get(point['bundle'] + '.receipt.json') is None:
            raise CycleBlocked('REMOTE_POINT_RECEIPT_MISSING')
    if sum(inventory.values()) > MAX_BYTES:
        raise CycleBlocked('REMOTE_CAP_ALREADY_EXCEEDED')


def select_parent(ftps, work=BACKUP_WORK, now=None):
    """Bind newest locally restore-verified proof to the same newest FTPS point."""
    proof = private_json(work / 'latest-proof.json')
    required_true = ('restoreVerified', 'manifestSignatureVerified', 'actualDownloadVerified',
                     'everyPartShaVerified', 'decryptVerified', 'everyArtifactShaAndHmacVerified')
    if proof.get('status') != 'passed' or any(proof.get(k) is not True for k in required_true):
        raise CycleBlocked('LATEST_LOCAL_POINT_LACKS_VERIFIED_RESTORE_PROOF')
    if not PARENT_NAME.fullmatch(str(proof.get('bundle', ''))):
        raise CycleBlocked('LATEST_LOCAL_POINT_NAME_INVALID')
    connection = ftps.connect()
    try:
        ftps.verify_owner(connection)
        inventory = ftps.inventory(connection)
        points = ftps.points(connection, inventory)
        _validate_points(points, inventory, now)
        points = sorted(points, key=lambda p: parse_time(p['backupAt']), reverse=True)
        newest = points[0]
        if (newest.get('bundle') != proof.get('bundle') or
                newest.get('manifestId') != proof.get('manifestId') or
                newest.get('manifestDigest') != proof.get('manifestDigest') or
                newest.get('encryptedSha256') != proof.get('encryptedSha256')):
            raise CycleBlocked('LATEST_SELECTED_PARENT_DIFFERS_FROM_VERIFIED_PROOF')
        exact_receipt = ftps.get_json(connection, newest['bundle'] + '.receipt.json')
        if ftps.verify(exact_receipt) != newest:
            raise CycleBlocked('LATEST_PARENT_RECEIPT_CHANGED')
        receipt_sha = hashlib.sha256(ftps.canonical(exact_receipt)).hexdigest()
        return {'point': newest, 'proof': proof, 'receipt': exact_receipt,
                'receiptSha256': receipt_sha, 'inventoryBytes': sum(inventory.values()),
                'pointCount': len(points), 'inventory': inventory}
    finally:
        try:
            connection.quit()
        except Exception:
            connection.close()


def validate_manifest(manifest, parent):
    if (manifest.get('id') != parent['manifestId'] or
            manifest.get('signature', {}).get('digest') != parent['manifestDigest']):
        raise CycleBlocked('SELECTED_MANIFEST_BINDING_CHANGED')
    resources = manifest.get('resources', [])
    artifacts = manifest.get('artifacts', [])
    ids = [r.get('id') for r in resources]
    if len(resources) != 28 or len(set(ids)) != 28 or 'source:stream' not in ids:
        raise CycleBlocked('CATALOG_RESOURCE_SCOPE_DRIFT')
    source_ids = {r['id'] for r in resources if r.get('kind') == 'source'}
    db_ids = {r['id'] for r in resources if r.get('kind') == 'database'}
    if len(source_ids) != 16 or len(db_ids) != 8:
        raise CycleBlocked('SOURCE_OR_DATABASE_SCOPE_DRIFT')
    for resource in resources:
        if resource.get('kind') == 'source':
            name = resource.get('sourceDirectory')
            if (not isinstance(name, str) or name != resource['id'].split(':', 1)[1] or
                    name in ('', '.', '..') or '/' in name or '\\' in name):
                raise CycleBlocked('SOURCE_DIRECTORY_BINDING_DRIFT')
    if len({a.get('resourceId') for a in artifacts}) != len(artifacts):
        raise CycleBlocked('DUPLICATE_MANIFEST_ARTIFACT')
    return resources, source_ids, db_ids


def validate_local_copy_count(manifests_dir, verifier, parent_id):
    manifests_dir = Path(manifests_dir)
    if manifests_dir.is_symlink() or not manifests_dir.is_dir():
        raise CycleBlocked('LOCAL_MANIFEST_DIRECTORY_UNSAFE')
    verified = []
    for path in sorted(manifests_dir.glob('manifest-*.json')):
        if path.is_symlink():
            raise CycleBlocked('LOCAL_MANIFEST_SYMLINK')
        try:
            value = verifier(path)
        except Exception:
            continue
        if value:
            verified.append(path)
    if len(verified) != 2 or not any(p.stem == parent_id for p in verified):
        raise CycleBlocked('LOCAL_TWO_COPY_RETENTION_NOT_SATISFIED')
    return [str(p) for p in verified]


def service_inventory(runner=subprocess.check_output):
    ids = runner(['docker', 'ps', '-q'], text=True, timeout=30).split()
    if not ids:
        raise CycleBlocked('NO_RUNNING_CONTAINERS')
    containers = json.loads(runner(['docker', 'inspect', *ids], text=True, timeout=60))
    rows = []
    for c in containers:
        state = c.get('State', {})
        if state.get('Running') is not True or state.get('Health', {}).get('Status') == 'unhealthy':
            raise CycleBlocked('CONTAINER_HEALTH_OR_RUNNING_DRIFT')
        rows.append({'id': c['Id'], 'name': c['Name'].lstrip('/'), 'imageId': c['Image'],
                     'startedAt': state.get('StartedAt'), 'running': state['Running'],
                     'restartPolicy': c.get('HostConfig', {}).get('RestartPolicy', {}).get('Name')})
    return sorted(rows, key=lambda x: x['id'])


def compare_inventory(before, after):
    if before != after:
        raise CycleBlocked('LIVE_RESOURCE_OR_IMAGE_DRIFT_DURING_CAPTURE')


def validate_source_metadata_v2(report, source_proof):
    source_entries=[entry for entry in report.get('entries', [])
                    if entry.get('kind') == 'full-current-source-snapshot']
    require(report.get('sourceMetadataVersion') == 2 and len(source_entries) == 16 and
            all(entry.get('metadataPolicy') == 'pax-xattrs-mtime-ns-v2' and
                entry.get('hardlinkPolicy') == 'materialized-independent-files'
                for entry in source_entries), 'SOURCE_METADATA_V2_REPORT_REQUIRED')
    require(source_proof.get('schema') == 'platform.isolated-full-source-proof/v2' and
            source_proof.get('sourceMetadataVersion') == 2 and
            source_proof.get('nanosecondMtimesVerified') is True and
            type(source_proof.get('xattrsVerified')) is int and
            type(source_proof.get('posixAclXattrsVerified')) is int and
            source_proof.get('hardlinksPreserved') is False and
            type(source_proof.get('hardlinkGroupsMaterialized')) is int,
            'SOURCE_METADATA_V2_RESTORE_PROOF_REQUIRED')


def validate_gf_postgres_uid70_probe(image_proof, inventory):
    expected={row['imageId'] for row in inventory if row.get('name') == 'gf-postgres'}
    probe=image_proof.get('gfPostgresUid70ShellProbe', {})
    require(len(expected) == 1 and probe.get('status') == 'passed' and
            probe.get('user') == '70' and probe.get('network') == 'none' and
            probe.get('entrypoint') == '/bin/sh' and probe.get('workdir') == '/' and
            probe.get('imageId') in expected and
            image_proof.get('applicationContainersStarted') == 0,
            'GF_POSTGRES_UID70_BARE_EXEC_PROOF_REQUIRED')


def cycle_path(parent_id, root=ROOT):
    if not re.fullmatch(r'manifest-[a-z0-9][a-z0-9-]{15,127}', parent_id):
        raise CycleBlocked('INVALID_CYCLE_PARENT_ID')
    root = Path(root)
    if root != ALLOWED_CAPTURE_ROOT:
        raise CycleBlocked('CAPTURE_ROOT_NOT_FIXED')
    path = root / parent_id
    if path.exists() or path.is_symlink():
        raise CycleBlocked('CYCLE_DIRECTORY_ALREADY_EXISTS_PRESERVE_FOR_REVIEW')
    return path


def read_only_plan(parent, remote_bytes, point_count, local_copies, inventory):
    return {'schema': 'platform.recurring-completeness-plan/v1',
            'status': 'ready-to-capture' if remote_bytes < MAX_BYTES else 'blocked',
            'selectedParent': {'manifestId': parent['manifestId'],
                               'manifestDigest': parent['manifestDigest'],
                               'bundle': parent['bundle'],
                               'receiptSha256': parent['receiptSha256']},
            'sourceCount': 16, 'streamIncluded': True, 'databaseAclCount': 8,
            'coldVolumeCount': 6, 'nativeImageCount': len({r['imageId'] for r in inventory}),
            'remoteBytesBeforeCapture': remote_bytes,
            'remoteHeadroomBytes': MAX_BYTES - remote_bytes,
            'remotePointCount': point_count, 'maxRemotePoints': MAX_POINTS,
            'maxAgeDays': 14, 'schedule': list(SCHEDULE),
            'localVerifiedCopies': len(local_copies), 'requiredLocalCopies': 2,
            'pruneOrCleanup': False, 'productionWrite': False,
            'restoreOrApply': False, 'crossResourceAtomicity': False,
            'nextSteps': ['capture all 16 full source trees', 'cold-copy six fixed writable mounts',
                          'export/load-verify current linux/amd64 images',
                          'collect ACL inventory for all eight manifest databases',
                          'stage exact 12-file supplement and delegate publication to pinned root publisher']}


def _load_cycle_modules(cycle):
    files = {name: pinned_helper(name) for name in
             ('builder', 'cold', 'package', 'source_verify', 'image', 'acl')}
    # `source_adapter.py` is imported by the cold helper; it is pinned and loaded
    # from the same exact helper directory before importing that module.
    pinned_helper('adapter')
    # cold_volume_capture imports source_adapter by its sibling module name.
    helper_dir = str(files['cold'].parent)
    if helper_dir not in sys.path:
        sys.path.insert(0, helper_dir)
    mods = {name: load_module('recurring_' + name, path) for name, path in files.items()}
    # The proven helpers were originally bound to a one-off 30-Sep staging root.
    # Rebind only process-local module constants into this unique, never-reused run.
    cold = mods['cold']
    cold.ROOT = cycle
    cold.DEST = cycle / 'cold-volume-snapshots'
    cold.JOURNAL = cycle / 'cold-volume-capture.json'
    cold.HERE = Path(__file__).resolve()
    sys.modules['cold_volume_capture'] = cold
    package = mods['package']
    package.ROOT = cycle
    package.DEST = cold.DEST
    package.JOURNAL = cold.JOURNAL
    package.FIXED = cold.FIXED
    package.atomic = cold.atomic
    package.volume_tree = cold.volume_tree
    image = mods['image']
    image.ROOT = cycle
    image.SCRATCH = cycle / 'isolated-image-daemon'
    image.HERE = Path(__file__).resolve()
    image.EXPORT = cycle / 'docker-running-images.tar'
    return mods


def _write_private_json(path, value):
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise CycleBlocked('OUTPUT_ALREADY_EXISTS_PRESERVE_FOR_REVIEW')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, separators=(',', ':'))
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def capture_cold_volumes(cold, root):
    cold.DEST.mkdir(mode=0o700)
    rows = cold.preflight()
    state = {'schema': 'platform.six-volume-cold-capture/v1', 'status': 'running',
             'pid': os.getpid(), 'startedAt': cold.now(), 'active': None,
             'snapshots': [], 'fullyRecoverable': False, 'productionDataRestored': False,
             'serviceLifecycleChanged': True, 'offsitePublished': False}
    cold.atomic(cold.JOURNAL, state)
    for row in rows:
        current = cold.inspect(row['id'])
        cold.identity(row, current)
        if not current['State']['Running'] or current['State']['StartedAt'] != row['initialStartedAt']:
            raise CycleBlocked('WRITER_STATE_CHANGED_BEFORE_COLD_COPY')
        state['active'] = row
        cold.atomic(cold.JOURNAL, state)
        watchdog_unit = 'platform-recurring-cold-' + row['subject']
        cold.command(['systemd-run', '--quiet', '--collect', '--unit', watchdog_unit,
                      '--on-active=150s', '--timer-property=AccuracySec=1s',
                      '/usr/bin/python3', str(Path(__file__).resolve()), '--watchdog',
                      '--root', str(root), '--watchdog-subject', row['subject'],
                      '--watchdog-id', row['id']])
        result = cold.stopped_copy(row, cold.DEST / row['subject'])
        cold.wait_health(row)
        cold.command(['systemctl', 'stop', watchdog_unit + '.timer'])
        state['snapshots'].append({**row, **result, 'restartedHealthyAt': cold.now()})
        state['active'] = None
        cold.atomic(cold.JOURNAL, state)
    state.update(status='passed', completedAt=cold.now(), snapshotCount=len(state['snapshots']))
    cold.atomic(cold.JOURNAL, state)
    return state


def package_and_verify_volumes(package, cold, cycle):
    """Call the pinned existing packager after rebinding its one-off paths."""
    old_archive = cycle / 'cold-volume-snapshots.tar.gz'
    archive = cycle / 'cold-volumes.tar.gz'
    if old_archive.exists() or old_archive.is_symlink() or archive.exists() or archive.is_symlink():
        raise CycleBlocked('VOLUME_ARCHIVE_EXISTS_PRESERVE_FOR_REVIEW')
    old_stdout = sys.stdout
    sink = open(os.devnull, 'w')
    try:
        sys.stdout = sink
        package.main()
    finally:
        sys.stdout = old_stdout
        sink.close()
    if not old_archive.is_file() or old_archive.is_symlink():
        raise CycleBlocked('PINNED_VOLUME_PACKAGER_OUTPUT_MISSING')
    os.replace(old_archive, archive)
    proof = private_json(cycle / 'isolated-volume-restore-proof.json')
    if (proof.get('status') != 'passed' or proof.get('snapshotCount') != 6 or
            proof.get('archiveBytes') != archive.stat().st_size or
            proof.get('archiveSha256') != sha256(archive) or
            proof.get('aclAndXattrPreserved') is not True or
            proof.get('sourceVolumesModified') is not False):
        raise CycleBlocked('PINNED_VOLUME_PACKAGER_PROOF_INVALID')
    return proof


def export_current_images(cycle, inventory, runner=subprocess.run):
    image_ids = sorted({row['imageId'] for row in inventory})
    if len(image_ids) != 34:
        raise CycleBlocked('RUNNING_IMAGE_COUNT_DRIFT')
    archive = cycle / 'docker-running-images.tar'
    if archive.exists() or archive.is_symlink():
        raise CycleBlocked('IMAGE_ARCHIVE_EXISTS_PRESERVE_FOR_REVIEW')
    result = runner(['docker', 'image', 'save', '--platform=linux/amd64',
                     '--output', str(archive), *image_ids], check=False, timeout=2400,
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise CycleBlocked('DOCKER_IMAGE_EXPORT_FAILED')
    if not archive.is_file() or archive.is_symlink() or archive.stat().st_nlink != 1:
        raise CycleBlocked('UNSAFE_IMAGE_ARCHIVE')
    return archive


def _write_capture_inventory(path, rows):
    _write_private_json(path, {'containers': [
        {'id': r['id'], 'name': r['name'], 'running': r['running'], 'imageId': r['imageId']}
        for r in rows]})


def resolve_parent_material(ftps, selection):
    parent = selection['point']
    data_dir = Path(ftps.d.DATA)
    manifest_path = data_dir / 'manifests' / (parent['manifestId'] + '.json')
    verified = ftps.d.verify(data_dir, manifest_path.name)
    if (verified.get('manifestId') != parent['manifestId'] or
            verified.get('manifestDigest') != parent['manifestDigest'] or
            verified.get('manifestSignatureVerified') is not True or
            verified.get('restoreVerified') is not True):
        raise CycleBlocked('LOCAL_MANIFEST_NOT_RESTORE_VERIFIED')
    manifest = json.loads(manifest_path.read_text())
    resources, source_ids, db_ids = validate_manifest(manifest, parent)
    artifacts = {a['resourceId']: a for a in manifest['artifacts']}
    specs = []
    for resource in resources:
        if resource.get('kind') != 'source':
            continue
        rid = resource['id']
        artifact = artifacts.get(rid)
        if not artifact:
            raise CycleBlocked('SOURCE_ARTIFACT_BINDING_MISSING')
        root = SOURCE_ROOT / resource['sourceDirectory']
        baseline = data_dir / artifact['path']
        specs.append((rid, str(root), str(baseline), artifact['path'], artifact['sha256']))
    if {x[0] for x in specs} != source_ids or len(specs) != 16:
        raise CycleBlocked('DYNAMIC_SOURCE_ROOT_BINDING_DRIFT')
    return data_dir, manifest_path, manifest, specs, db_ids


def host_recovery_path_additions(extension=HOST_RECOVERY_EXTENSION):
    """Read the reviewed path-only extension; it contains no credential values."""
    try:
        document = json.loads(Path(extension).read_text())
        required = document['addRequiredPaths']
        paths = document['addPaths']
        bounds = document['preserveBounds']
    except (OSError, KeyError, TypeError, ValueError):
        raise CycleBlocked('HOST_RECOVERY_EXTENSION_INVALID') from None
    if (document.get('schema') != 'platform.host-recovery-paths-extension/v1' or
            not isinstance(required, list) or not isinstance(paths, list) or
            not all(isinstance(x, str) and x.startswith('/') and '..' not in Path(x).parts
                    for x in required + paths) or
            bounds != {'maximumTotalBytes': 1073741824, 'maximumEntries': 30000}):
        raise CycleBlocked('HOST_RECOVERY_EXTENSION_INVALID')
    return set(required), set(paths)


def validate_host_recovery_config(config_path=HOST_RECOVERY_CONFIG,
                                  extension=HOST_RECOVERY_EXTENSION):
    """Fail closed until the deployed bounded capsule config includes reviewed paths."""
    required_additions, path_additions = host_recovery_path_additions(extension)
    config = private_json(config_path)
    if (not isinstance(config.get('requiredPaths'), list) or
            not isinstance(config.get('paths'), list) or
            not required_additions.issubset(set(config['requiredPaths'])) or
            not path_additions.issubset(set(config['paths'])) or
            config.get('maximumTotalBytes') != 1073741824 or
            config.get('maximumEntries') != 30000 or
            config.get('excludeNames') != ['.git', 'node_modules', '__pycache__']):
        raise CycleBlocked('HOST_RECOVERY_CONFIG_SCOPE_OR_BOUND_DRIFT')
    return sha256(config_path)


def validate_host_capsule_before_parent(parent, config_digest,
                                        proof_path=HOST_RECOVERY_PROOF,
                                        capsule_path=HOST_RECOVERY_CAPSULE, now=None,
                                        capsule_reader=None):
    proof = private_json(proof_path)
    if (proof.get('schema') != 'platform.host-recovery-capsule/v1' or
            proof.get('status') != 'passed' or proof.get('configSha256') != config_digest or
            proof.get('everyRequiredPathIncluded') is not True or
            proof.get('decryptRoundtripVerified') is not True or
            proof.get('sharedStatePlaintext') is not False or
            proof.get('containsSensitiveMaterial') is not True or
            type(proof.get('entryCount')) is not int or proof['entryCount'] > 30000 or
            type(proof.get('sourceBytes')) is not int or proof['sourceBytes'] > 1073741824):
        raise CycleBlocked('FRESH_EXTENDED_HOST_CAPSULE_PROOF_REQUIRED')
    captured_at = parse_time(proof.get('capturedAt'))
    parent_at = parse_time(parent.get('backupAt'))
    local_now = (now or utcnow()).astimezone(ZoneInfo('Europe/Rome'))
    if (captured_at > parent_at or captured_at.astimezone(ZoneInfo('Europe/Rome')).date() != local_now.date() or
            (local_now - captured_at.astimezone(ZoneInfo('Europe/Rome'))).total_seconds() > 18 * 3600):
        raise CycleBlocked('HOST_CAPSULE_MUST_PRECEDE_SAME_DAY_PARENT')
    info = Path(capsule_path).lstat()
    if (Path(capsule_path).is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size != proof.get('encryptedBytes') or
            sha256(capsule_path) != proof.get('encryptedSha256')):
        raise CycleBlocked('EXTENDED_HOST_CAPSULE_BYTES_UNVERIFIED')
    # Keep the immutable proof document identical to the on-disk object. The
    # tree verifier reopens that exact file and independently streams the
    # decrypted capsule; derived summaries are attached only after verification.
    reader = capsule_reader or verify_extra_database_capsule
    extra_database_capture = reader(capsule_path, proof)
    verifier = load_module('verified_extra_mounted_trees_capsule', pinned_helper('tree_verify'))
    extra_tree_capture = verifier.verify(
        capsule_path, proof, HOST_RECOVERY_KEY, HOST_CAPSULE_VERIFY_TMP,
        capsule_proof_path=proof_path, file_staging_index_path=None)
    return {**proof, 'extraDatabaseCapture': extra_database_capture,
            'extraMountedTreesCapture': extra_tree_capture}


class _BoundedHashReader:
    def __init__(self, source, limit, limit_error='EXTRA_DATABASE_BUNDLE_SIZE_LIMIT'):
        self.source = source
        self.limit = limit
        self.limit_error = limit_error
        self.count = 0
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        value = self.source.read(size)
        self.count += len(value)
        if self.count > self.limit:
            raise CycleBlocked(self.limit_error)
        self.digest.update(value)
        return value


def _verify_extra_database_bundle(bundle_stream, capsule_captured_at):
    expected = {
        'control_center.dump': ('control_center', 'postgres', 'postgres-custom'),
        'phpmyadmin.sql': ('phpmyadmin', 'mariadb', 'mariadb-sql'),
        'proof.json': None,
    }
    bundle_digest = _BoundedHashReader(bundle_stream, MAX_EXTRA_DATABASE_BUNDLE_BYTES)
    found = set()
    inner_proof = None
    dumps = {}
    try:
        with tarfile.open(fileobj=bundle_digest, mode='r|') as bundle:
            for member in bundle:
                if member.name not in expected or member.name in found:
                    raise CycleBlocked('EXTRA_DATABASE_BUNDLE_MEMBER_SET_INVALID')
                if (not member.isfile() or member.size <= 0 or member.mode != 0o600 or
                        member.uid != 0 or member.gid != 0):
                    raise CycleBlocked('EXTRA_DATABASE_BUNDLE_MEMBER_METADATA_INVALID')
                if member.name == 'proof.json':
                    if member.size > 1_000_000:
                        raise CycleBlocked('EXTRA_DATABASE_PROOF_SIZE_LIMIT')
                    stream = bundle.extractfile(member)
                    inner_proof = json.load(stream)
                    found.add(member.name)
                else:
                    if member.size > MAX_EXTRA_DATABASE_BUNDLE_BYTES:
                        raise CycleBlocked('EXTRA_DATABASE_DUMP_SIZE_LIMIT')
                    stream = bundle.extractfile(member)
                    digest = hashlib.sha256()
                    count = 0
                    prefix = bytearray()
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        count += len(chunk)
                        if count > member.size:
                            raise CycleBlocked('EXTRA_DATABASE_DUMP_SIZE_MISMATCH')
                        digest.update(chunk)
                        if len(prefix) < 8192:
                            prefix.extend(chunk[:8192 - len(prefix)])
                    if count != member.size:
                        raise CycleBlocked('EXTRA_DATABASE_DUMP_SIZE_MISMATCH')
                    if member.name == 'control_center.dump' and not prefix.startswith(b'PGDMP'):
                        raise CycleBlocked('EXTRA_DATABASE_POSTGRES_FORMAT_INVALID')
                    if member.name == 'phpmyadmin.sql' and not (b'MariaDB dump' in prefix or b'MySQL dump' in prefix):
                        raise CycleBlocked('EXTRA_DATABASE_MARIADB_FORMAT_INVALID')
                    dumps[member.name] = {'bytes': count, 'sha256': digest.hexdigest()}
                    found.add(member.name)
        for block in iter(lambda: bundle_digest.read(1024 * 1024), b''):
            pass
    except CycleBlocked:
        raise
    except (OSError, tarfile.TarError, ValueError, TypeError, json.JSONDecodeError):
        raise CycleBlocked('EXTRA_DATABASE_BUNDLE_INVALID') from None
    if found != set(expected) or not isinstance(inner_proof, dict):
        raise CycleBlocked('EXTRA_DATABASE_BUNDLE_INCOMPLETE')
    if (inner_proof.get('schema') != 'platform.host-extra-database-exports/v1' or
            inner_proof.get('status') != 'passed' or inner_proof.get('readOnly') is not True or
            inner_proof.get('productionDatabaseWrites') is not False or
            inner_proof.get('containerBindingsStable') is not True or
            inner_proof.get('schemaCountsStableDuringCapture') is not True or
            inner_proof.get('databaseCount') != 2 or inner_proof.get('combinedDumpBytes') != sum(
                item['bytes'] for item in dumps.values()) or
            inner_proof.get('bundleFilename') != 'current.tar' or
            inner_proof.get('maximumCombinedDumpBytes') != 536_870_912 or
            inner_proof.get('combinedDumpBytes', 536_870_913) > 536_870_912):
        raise CycleBlocked('EXTRA_DATABASE_PROOF_INCOMPLETE')
    try:
        completed = parse_time(inner_proof['captureCompletedAt'])
        started = parse_time(inner_proof['captureStartedAt'])
        capsule_time = parse_time(capsule_captured_at)
    except (KeyError, TypeError, ValueError):
        raise CycleBlocked('EXTRA_DATABASE_CAPTURE_TIME_INVALID') from None
    lag = (capsule_time - completed).total_seconds()
    if started > completed or lag < 0 or lag > 15 * 60:
        raise CycleBlocked('EXTRA_DATABASE_CAPTURE_NOT_LATEST_FOR_CAPSULE')
    rows = inner_proof.get('databases')
    if not isinstance(rows, list) or len(rows) != 2:
        raise CycleBlocked('EXTRA_DATABASE_PROOF_DATABASE_SET_INVALID')
    by_name = {row.get('name'): row for row in rows if isinstance(row, dict)}
    if set(by_name) != {'control_center', 'phpmyadmin'}:
        raise CycleBlocked('EXTRA_DATABASE_PROOF_DATABASE_SET_INVALID')
    summaries = []
    for member_name, (database, engine, dump_format) in (
            ('control_center.dump', expected['control_center.dump']),
            ('phpmyadmin.sql', expected['phpmyadmin.sql'])):
        row = by_name[database]
        dump = row.get('dump', {})
        schemas = row.get('schemas')
        if (row.get('engine') != engine or row.get('containerName') != ('gf-postgres' if engine == 'postgres' else 'gf-mariadb') or
                not re.fullmatch(r'[a-f0-9]{64}', str(row.get('containerId', ''))) or
                not re.fullmatch(r'sha256:[a-f0-9]{64}', str(row.get('imageId', ''))) or
                row.get('readOnlyCatalogStable') is not True or not isinstance(schemas, list) or
                not schemas or not all(isinstance(item, dict) and
                                       type(item.get('tableCount')) is int and item['tableCount'] >= 0
                                       for item in schemas) or row.get('schemaCount') != len(schemas) or
                row.get('tableCount') != sum(item.get('tableCount', -1) for item in schemas) or
                row.get('tableCount', 0) <= 0 or dump.get('filename') != member_name or
                dump.get('format') != dump_format or dump.get('mode') != '0600' or
                dump.get('bytes') != dumps[member_name]['bytes'] or
                dump.get('sha256') != dumps[member_name]['sha256']):
            raise CycleBlocked('EXTRA_DATABASE_DUMP_PROOF_BINDING_INVALID')
        summaries.append({'database': database, 'engine': engine,
                          'containerId': row['containerId'], 'imageId': row['imageId'],
                          'tableCount': row['tableCount'], 'dumpBytes': dumps[member_name]['bytes'],
                          'dumpSha256': dumps[member_name]['sha256']})
    return {'status': 'passed', 'databaseCount': 2,
            'captureCompletedAt': inner_proof['captureCompletedAt'],
            'bundleBytes': bundle_digest.count,
            'bundleSha256': bundle_digest.digest.hexdigest(),
            'databases': summaries}


def verify_extra_database_capsule(capsule_path, capsule_proof, popen=subprocess.Popen):
    """Decrypt into a pipe and verify both DB dumps embedded in this exact capsule."""
    key_info = HOST_RECOVERY_KEY.lstat()
    if (HOST_RECOVERY_KEY.is_symlink() or not stat.S_ISREG(key_info.st_mode) or
            key_info.st_uid != 0 or key_info.st_nlink != 1 or key_info.st_mode & 0o077):
        raise CycleBlocked('HOST_RECOVERY_KEY_NOT_PRIVATE')
    tmp_info = HOST_CAPSULE_VERIFY_TMP.lstat()
    if (HOST_CAPSULE_VERIFY_TMP.is_symlink() or not stat.S_ISDIR(tmp_info.st_mode) or
            tmp_info.st_uid != 0 or tmp_info.st_mode & 0o022):
        raise CycleBlocked('HOST_CAPSULE_VERIFY_TMP_UNSAFE')
    scratch = Path(tempfile.mkdtemp(prefix='host-capsule-verify-', dir=HOST_CAPSULE_VERIFY_TMP))
    os.chmod(scratch, 0o700)
    try:
        return _decrypt_and_verify_extra_database_capsule(capsule_path, capsule_proof,
                                                          scratch, popen)
    finally:
        if scratch.parent != HOST_CAPSULE_VERIFY_TMP:
            raise CycleBlocked('HOST_CAPSULE_VERIFY_TMP_BOUNDARY_CHANGED')
        shutil.rmtree(scratch)


def _decrypt_and_verify_extra_database_capsule(capsule_path, capsule_proof, homedir, popen):
    if (type(capsule_proof.get('encryptedBytes')) is not int or
            not 0 < capsule_proof['encryptedBytes'] <= 2_000_000_000 or
            not re.fullmatch(r'[a-f0-9]{64}', str(capsule_proof.get('plaintextArchiveSha256', '')))):
        raise CycleBlocked('HOST_CAPSULE_PROOF_PLAINTEXT_BINDING_INVALID')
    command = ['gpg', '--no-options', '--batch', '--yes', '--pinentry-mode', 'loopback',
               '--passphrase-file', str(HOST_RECOVERY_KEY), '--homedir', str(homedir),
               '--decrypt', '--output', '-', str(capsule_path)]
    process = None
    try:
        process = popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, close_fds=True)
        plaintext = _BoundedHashReader(
            process.stdout, min(capsule_proof.get('encryptedBytes', 0), 2_000_000_000),
            'HOST_CAPSULE_PLAINTEXT_SIZE_LIMIT')
        result = _verify_extra_database_capsule_stream(plaintext, capsule_proof)
        for block in iter(lambda: plaintext.read(1024 * 1024), b''):
            pass
        if plaintext.digest.hexdigest() != capsule_proof.get('plaintextArchiveSha256'):
            raise CycleBlocked('HOST_CAPSULE_PLAINTEXT_DIGEST_MISMATCH')
        status = process.wait(timeout=180)
        if status != 0:
            raise CycleBlocked('HOST_CAPSULE_DECRYPT_FAILED')
        if sha256(capsule_path) != capsule_proof.get('encryptedSha256'):
            raise CycleBlocked('HOST_CAPSULE_CHANGED_DURING_CONTENT_VERIFICATION')
        result['liveBundleBinding'] = verify_live_extra_database_bundle(result)
        return result
    except CycleBlocked:
        if process is not None and process.poll() is None:
            process.kill(); process.wait()
        raise
    except (OSError, subprocess.SubprocessError, tarfile.TarError, EOFError):
        if process is not None and process.poll() is None:
            process.kill(); process.wait()
        raise CycleBlocked('HOST_CAPSULE_CONTENT_VERIFICATION_FAILED') from None


def _verify_extra_database_capsule_stream(plaintext_stream, capsule_proof):
    try:
        with tarfile.open(fileobj=plaintext_stream, mode='r|gz') as archive:
            seen = False
            result = None
            for count, member in enumerate(archive, start=1):
                if count > 30000:
                    raise CycleBlocked('HOST_CAPSULE_MEMBER_COUNT_LIMIT')
                if member.name == EXTRA_DATABASE_CAPSULE_MEMBER:
                    if (seen or not member.isfile() or member.uid != 0 or member.gid != 0 or
                            member.mode != 0o600 or
                            member.size > MAX_EXTRA_DATABASE_BUNDLE_BYTES):
                        raise CycleBlocked('EXTRA_DATABASE_CAPSULE_MEMBER_INVALID')
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise CycleBlocked('EXTRA_DATABASE_CAPSULE_MEMBER_UNREADABLE')
                    result = _verify_extra_database_bundle(stream, capsule_proof['capturedAt'])
                    seen = True
    except CycleBlocked:
        raise
    except (OSError, tarfile.TarError, EOFError, KeyError, TypeError):
        raise CycleBlocked('HOST_CAPSULE_CONTENT_VERIFICATION_FAILED') from None
    if not seen:
        raise CycleBlocked('CURRENT_EXTRA_DATABASE_BUNDLE_MISSING_FROM_CAPSULE')
    return result


def verify_live_extra_database_bundle(captured, path=HOST_EXTRA_DATABASE_BUNDLE,
                                      strict_root=True):
    path = Path(path)
    owner = 0 if strict_root else os.geteuid()
    try:
        for ancestor in [path.parent, *path.parent.parents]:
            ancestor_info = ancestor.lstat()
            if (not stat.S_ISDIR(ancestor_info.st_mode) or
                    (strict_root and ancestor.is_symlink()) or
                    (strict_root and (ancestor_info.st_uid != 0 or ancestor_info.st_mode & 0o022))):
                raise CycleBlocked('LIVE_EXTRA_DATABASE_BUNDLE_ANCESTOR_UNSAFE')
        before = path.lstat()
        if (path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_uid != owner or
                before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or
                before.st_size != captured.get('bundleBytes')):
            raise CycleBlocked('LIVE_EXTRA_DATABASE_BUNDLE_BINDING_INVALID')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except CycleBlocked:
        raise
    except OSError:
        raise CycleBlocked('LIVE_EXTRA_DATABASE_BUNDLE_BINDING_INVALID') from None
    digest = hashlib.sha256()
    try:
        opened = os.fstat(fd)
        if (opened.st_dev != before.st_dev or opened.st_ino != before.st_ino or
                opened.st_size != before.st_size or opened.st_uid != before.st_uid or
                opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != 0o600):
            raise CycleBlocked('LIVE_EXTRA_DATABASE_BUNDLE_CHANGED')
        for block in iter(lambda: os.read(fd, 1024 * 1024), b''):
            digest.update(block)
        after = os.fstat(fd)
        if (after.st_dev != opened.st_dev or after.st_ino != opened.st_ino or
                after.st_size != opened.st_size or after.st_mtime_ns != opened.st_mtime_ns or
                digest.hexdigest() != captured.get('bundleSha256')):
            raise CycleBlocked('LIVE_EXTRA_DATABASE_BUNDLE_CHANGED')
    finally:
        os.close(fd)
    return {'status': 'same-bytes-as-captured-capsule', 'bytes': before.st_size,
            'sha256': captured['bundleSha256']}


def verify_parent_host_capsule(data_dir, manifest, expected_proof):
    """Require the signed catalog's control-center-state tar to contain this capsule."""
    artifacts = [item for item in manifest.get('artifacts', [])
                 if item.get('resourceId') == 'platform-state:control-center-state']
    if len(artifacts) != 1:
        raise CycleBlocked('SIGNED_CONTROL_CENTER_STATE_ARTIFACT_REQUIRED')
    artifact = artifacts[0]
    archive = Path(data_dir) / artifact.get('path', '')
    if (archive.is_symlink() or not archive.is_file() or archive.stat().st_nlink != 1 or
            sha256(archive) != artifact.get('sha256')):
        raise CycleBlocked('SIGNED_CONTROL_CENTER_STATE_BYTES_UNVERIFIED')
    capsule_suffix = '/host-recovery/host-recovery-current.tar.gz.gpg'
    proof_suffix = '/host-recovery/host-recovery-proof.json'
    found_capsule = found_proof = False
    seen = set()
    try:
        with tarfile.open(archive, 'r:*') as tar:
            for count, member in enumerate(tar, start=1):
                if count > 250000:
                    raise CycleBlocked('CONTROL_CENTER_STATE_MEMBER_BOUND')
                name = member.name.removeprefix('./')
                parts = Path(name).parts
                if Path(name).is_absolute() or '..' in parts or not (member.isdir() or member.isfile() or member.issym()):
                    raise CycleBlocked('UNSAFE_CONTROL_CENTER_STATE_MEMBER')
                if name in seen:
                    raise CycleBlocked('DUPLICATE_CONTROL_CENTER_STATE_MEMBER')
                seen.add(name)
                if member.isfile() and (name.endswith(capsule_suffix) or name.endswith(proof_suffix)):
                    stream = tar.extractfile(member)
                    if stream is None:
                        raise CycleBlocked('CONTROL_CENTER_STATE_MEMBER_UNREADABLE')
                    digest = hashlib.sha256()
                    size = 0
                    data = bytearray() if name.endswith(proof_suffix) else None
                    while True:
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > (2_000_000 if data is not None else 2_000_000_000):
                            raise CycleBlocked('CONTROL_CENTER_CAPSULE_MEMBER_SIZE_BOUND')
                        digest.update(chunk)
                        if data is not None:
                            data.extend(chunk)
                    if data is None:
                        if (found_capsule or size != expected_proof.get('encryptedBytes') or
                                digest.hexdigest() != expected_proof.get('encryptedSha256')):
                            raise CycleBlocked('PARENT_CAPSULE_MEMBER_DIFFERS_FROM_PROOF')
                        found_capsule = True
                    else:
                        if found_proof:
                            raise CycleBlocked('DUPLICATE_PARENT_CAPSULE_PROOF')
                        try:
                            embedded = json.loads(data)
                        except ValueError:
                            raise CycleBlocked('INVALID_PARENT_CAPSULE_PROOF') from None
                        expected_capsule_proof = {key: value for key, value in expected_proof.items()
                                                  if key not in {'extraDatabaseCapture', 'extraMountedTreesCapture'}}
                        if embedded != expected_capsule_proof:
                            raise CycleBlocked('PARENT_CAPSULE_PROOF_DIFFERS_FROM_CURRENT_PROOF')
                        found_proof = True
    except (OSError, tarfile.TarError):
        raise CycleBlocked('SIGNED_CONTROL_CENTER_STATE_ARCHIVE_INVALID') from None
    if not found_capsule or not found_proof:
        raise CycleBlocked('SIGNED_CONTROL_CENTER_STATE_LACKS_EXTENDED_CAPSULE')
    return {'artifactPath': artifact['path'], 'artifactSha256': artifact['sha256'],
            'capsuleSha256': expected_proof['encryptedSha256'],
            'capsuleBytes': expected_proof['encryptedBytes'],
            'proofIncluded': True, 'capsuleIncluded': True}


def stage_exact_material(cycle, parent, report_path, volume_archive, source_proof,
                         volume_proof, image_proof, helper_paths, staging=PUBLISH_STAGING):
    if not staging.exists():
        staging.mkdir(mode=0o700)
        os.chmod(staging, 0o700)
    point_dir = staging / parent['manifestId']
    if point_dir.exists() or point_dir.is_symlink():
        raise CycleBlocked('EXISTING_POINT_MATERIAL_PRESERVED_NO_OVERWRITE')
    for path in (staging, staging.parent, BACKUP_WORK):
        info = path.lstat()
        if (path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o077):
            raise CycleBlocked('PRIVATE_ROOT_STAGING_REQUIRED')
    point_dir.mkdir(mode=0o700)
    mapping = {
        'full-runtime.tar.gz': cycle / 'full-runtime.tar.gz',
        'full-runtime-report.json': report_path,
        'cold-volumes.tar.gz': volume_archive,
        'source-restore-proof.json': source_proof,
        'volume-restore-proof.json': volume_proof,
        'image-load-proof.json': image_proof,
    }
    for name, source in mapping.items():
        info = source.lstat()
        if source.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
            raise CycleBlocked('PROTECTED_CAPTURE_FILE_REQUIRED')
        shutil.copyfile(source, point_dir / name, follow_symlinks=False)
        os.chmod(point_dir / name, 0o600)
        with (point_dir / name).open('rb') as stream:
            os.fsync(stream.fileno())
    recovery_dir = point_dir / 'recovery'
    recovery_dir.mkdir(mode=0o700)
    for src, name in helper_paths:
        info = src.lstat()
        if src.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
            raise CycleBlocked('PINNED_RECOVERY_READER_REQUIRED')
        shutil.copyfile(src, recovery_dir / name, follow_symlinks=False)
        os.chmod(recovery_dir / name, 0o600)
        with (recovery_dir / name).open('rb') as stream:
            os.fsync(stream.fileno())
    hashes = {}
    sizes = {}
    for path in sorted(p for p in point_dir.rglob('*') if p.is_file()):
        rel = path.relative_to(point_dir).as_posix()
        hashes[rel] = sha256(path)
        sizes[rel] = path.stat().st_size
    coverage = {'schema': 'platform.completeness-material-coverage/v1',
                'manifestId': parent['manifestId'], 'manifestDigest': parent['manifestDigest'],
                'sourceCount': 16, 'streamIncluded': True, 'nativeImageCount': 34,
                'coldVolumeCount': 6, 'fullyRecoverable': False, 'atomicSnapshot': False,
                'fileSha256': hashes,
                'knownGaps': ['cross-resource-atomic-consistency-not-established',
                              'database-owner-acl-replay-not-proven-for-complete-production-set',
                              'complete-isolated-stack-startup-not-proven',
                              'global-active-promotion-and-rollback-not-proven',
                              'host-bootstrap-and-external-secret-custody-not-complete',
                              'authority-and-replay-state-must-remain-current']}
    _write_private_json(point_dir / 'coverage.json', coverage)
    rec = ('Private recurring completeness material bound to ' + parent['manifestId'] +
           ' / ' + parent['manifestDigest'] + '.\n'
           'The tar contains all current source trees, one native image archive, and ACL inventory.\n'
           'Cold volumes are a separate archive with numeric owner, ACL and xattr metadata.\n'
           'Restore complete source directories; do not overlay the catalog source tar.\n'
           'The isolated proofs verify extraction and image import, not whole-stack startup.\n'
           'Preserve current admission, authority, generation, replay and operation journals.\n'
           'fullyRecoverable=false; see coverage.json knownGaps.\n')
    fd = os.open(point_dir / 'RECOVERY.md', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(rec)
        stream.flush()
        os.fsync(stream.fileno())
    for directory in (recovery_dir, point_dir):
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    expected_names = {'full-runtime.tar.gz', 'full-runtime-report.json', 'cold-volumes.tar.gz',
                      'source-restore-proof.json', 'volume-restore-proof.json', 'image-load-proof.json',
                      'coverage.json', 'RECOVERY.md', 'recovery/platform-ftps-backup.py',
                      'recovery/platform-ftps-restore.py', 'recovery/completeness_producer.py',
                      'recovery/platform-completeness-publisher.py'}
    found = {p.relative_to(point_dir).as_posix() for p in point_dir.rglob('*') if p.is_file()}
    if found != expected_names:
        raise CycleBlocked('EXACT_TWELVE_FILE_SET_REQUIRED')
    return point_dir


def _check_output_space(path, need):
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise CycleBlocked('PRIVATE_CAPTURE_ROOT_REQUIRED')
    if shutil.disk_usage(path).free < need:
        raise CycleBlocked('LOCAL_TWO_COPY_STAGING_HEADROOM')


def _remote_file_age_ok(parent, now=None):
    now = now or utcnow()
    age = (now - parse_time(parent['backupAt'])).total_seconds()
    if age > MAX_AGE_SECONDS or age < -300:
        raise CycleBlocked('SELECTED_PARENT_OUTSIDE_RETENTION_WINDOW')


def scheduled_point_guard(parent, now=None):
    """Require a fresh catalog point on the scheduled local M/W/F run date."""
    now = now or utcnow()
    local_now = now.astimezone(ZoneInfo('Europe/Rome'))
    if local_now.strftime('%A') not in SCHEDULE:
        raise CycleBlocked('OUTSIDE_AUTHORIZED_MWF_CADENCE')
    point_time = parse_time(parent['backupAt']).astimezone(ZoneInfo('Europe/Rome'))
    if point_time.date() != local_now.date() or (local_now - point_time).total_seconds() > 18 * 3600:
        raise CycleBlocked('SAME_DAY_VERIFIED_CATALOG_POINT_REQUIRED')


def plan_on_host(*, run=False, scheduled=False):
    if os.geteuid() != 0:
        raise CycleBlocked('ROOT_REQUIRED')
    check_transfer_idle()
    if run:
        os.umask(0o077)
    reject_active_services()
    check_pending_state()
    publisher = load_module('production_publisher', PUBLISHER)
    ftps = load_module('current_ftps_helper', FTPS_HELPER)
    selected = select_parent(ftps)
    parent = selected['point']
    _remote_file_age_ok(parent)
    host_config_digest = validate_host_recovery_config()
    host_capsule_proof = validate_host_capsule_before_parent(parent, host_config_digest)
    if scheduled:
        scheduled_point_guard(parent)
    active_admission = admission_binding(publisher)
    local_manifest_count = validate_local_copy_count(
        Path(ftps.d.DATA) / 'manifests',
        lambda path: ftps.d.verify(ftps.d.DATA, path.name), parent['manifestId'])
    data_dir, manifest_path, manifest, source_specs, db_ids = resolve_parent_material(ftps, selected)
    host_capsule_binding = verify_parent_host_capsule(data_dir, manifest, host_capsule_proof)
    before_inventory = service_inventory()
    image_count = len({row['imageId'] for row in before_inventory})
    if image_count != 34:
        raise CycleBlocked('RUNNING_IMAGE_COUNT_DRIFT')
    cycle = cycle_path(parent['manifestId'])
    _check_output_space(ROOT, 90_000_000_000)
    plan_parent = dict(parent, receiptSha256=selected['receiptSha256'])
    plan = read_only_plan(plan_parent, selected['inventoryBytes'], selected['pointCount'],
                          local_manifest_count, before_inventory)
    plan.update({'status': 'ready-to-capture', 'cycleDirectory': str(cycle),
                 'manifestPath': str(manifest_path), 'sourceRoot': str(SOURCE_ROOT),
                 'databaseIds': sorted(db_ids), 'sourceSpecCount': len(source_specs),
                 'admission': active_admission, 'expectedContainerCount': len(before_inventory),
                 'existingPointReceiptSha256': selected['receiptSha256'],
                 'hostCapsuleConfigSha256': host_config_digest,
                 'hostCapsuleCompletedAt': host_capsule_proof['capturedAt'],
                 'hostCapsuleExtraDatabaseCapture': host_capsule_proof['extraDatabaseCapture'],
                 'manifestDatabaseAclCount': plan['databaseAclCount'],
                 'hostCapsuleExtraDatabaseCount': host_capsule_proof['extraDatabaseCapture']['databaseCount'],
                 'hostCapsuleCatalogBinding': host_capsule_binding,
                 'extendedHostRecoveryPathsIncluded': True,
                 'capacityPolicy': {'maxRemoteBytes': MAX_BYTES, 'noPrune': True,
                                    'maxPoints': MAX_POINTS, 'maxAgeSeconds': MAX_AGE_SECONDS,
                                    'requiredLocalCopies': 2}})
    if run:
        publication = execute_cycle(plan, ftps, publisher, selected, data_dir, manifest_path,
                                    manifest, source_specs, before_inventory, cycle)
        plan['publication'] = publication
        plan['status'] = 'published'
    return plan


def _capture_directories(root=None):
    root = Path(ROOT if root is None else root)
    if root.is_symlink():
        return {'<unsafe-root>'}
    if not root.is_dir():
        return set()
    return {path.name for path in root.iterdir()}


def run_scheduled_cycle(*, attempt=plan_on_host, sleep_fn=time.sleep,
                        monotonic=time.monotonic, retry_window=SCHEDULE_RETRY_WINDOW_SECONDS,
                        retry_interval=SCHEDULE_RETRY_INTERVAL_SECONDS):
    """Retry only pre-capture lock contention; never retry after a cycle starts."""
    deadline = monotonic() + retry_window
    while True:
        existing = _capture_directories()
        try:
            return attempt(run=True, scheduled=True)
        except CycleBlocked as error:
            code = str(error)
            if code not in TRANSIENT_SCHEDULE_BLOCKS:
                raise
            if _capture_directories() != existing:
                # A new directory is a durable partial capture; retain and report it.
                raise
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise CycleBlocked('SCHEDULE_RETRY_WINDOW_EXHAUSTED:' + code) from None
            sleep_fn(min(retry_interval, remaining))


def execute_cycle(plan, ftps, publisher, selected, data_dir, manifest_path, manifest,
                  source_specs, initial_inventory, cycle):
    """Root-only captured-and-published path. Never called by --plan or tests."""
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    require(not cycle.exists() and not cycle.is_symlink(), 'CYCLE_DIRECTORY_ALREADY_EXISTS')
    locks = []
    try:
        for path in LOCK_PATHS:
            locks.append(acquire_lock(path, exclusive=True))
        check_pending_state()
        admission = admission_binding(publisher)
        if admission != plan['admission']:
            raise CycleBlocked('ADMISSION_DRIFT_BEFORE_CAPTURE')
        cycle.mkdir(mode=0o700)
        os.chmod(cycle, 0o700)
        modules = _load_cycle_modules(cycle)
        # Read-only image/resource view first; use the exact live image IDs as Docker input.
        image_inventory_path = cycle / 'running-images-portable.json'
        _write_capture_inventory(image_inventory_path, initial_inventory)
        image_archive = export_current_images(cycle, initial_inventory)
        # ACL collector executes fixed catalog-only queries; no table data is read or written.
        acl_path = cycle / 'acl-inventory.json'
        acl_result = modules['acl'].collect(manifest)
        modules['acl'].write_private(acl_path, acl_result)
        # Cold capture is sequential, with a watchdog and health check for each writer.
        cold_state = capture_cold_volumes(modules['cold'], cycle)
        volume_proof = package_and_verify_volumes(modules['package'], modules['cold'], cycle)
        # Capture all 16 full source roots and bind to exact artifacts in the selected parent.
        builder = modules['builder']
        archive = cycle / 'full-runtime.tar.gz'
        budget = MAX_BYTES - selected['inventoryBytes']
        report = builder.build(str(archive), source_specs, [image_archive], image_inventory_path,
                               acl_path, budget, manifest_path, manifest['signature']['digest'],
                               selected['inventoryBytes'], source_mode='full-current-source-snapshot')
        report_path = archive.with_suffix(archive.suffix + '.json')
        # Verify source extraction independently against the captured report and exact parent.
        source_out = cycle / 'isolated-source-restored'
        source_proof_path = cycle / 'isolated-source-proof.json'
        source_proof = modules['source_verify'].verify(archive, report_path, source_out,
                                                       manifest['signature']['digest'], strict_root=True)
        validate_source_metadata_v2(report, source_proof)
        _write_private_json(source_proof_path, source_proof)
        # Bind a fresh private-daemon load to this run's exact image and source archives.
        image_module = modules['image']
        image_proof_path = cycle / 'isolated-image-load-proof.json'
        image_module.EXPORT_SHA = next(e['sha256'] for e in report['entries']
                                       if e.get('kind') == 'docker-image-archive')
        # The proven one-off verifier reads this conventional report basename.
        # Bind it to this cycle's generated report without changing the helper.
        image_report = cycle / 'full-current-portable-plaintext.tar.gz.json'
        if image_report.exists() or image_report.is_symlink():
            raise CycleBlocked('IMAGE_REPORT_PATH_EXISTS')
        shutil.copyfile(report_path, image_report, follow_symlinks=False)
        os.chmod(image_report, 0o600)
        saved_argv = sys.argv
        saved_subprocess = image_module.subprocess
        class DaemonArgProxy:
            def __getattr__(self, name):
                return getattr(saved_subprocess, name)
            def run(self, command, *args, **kwargs):
                command = list(command)
                if command and command[0] == 'systemd-run':
                    command += ['--root', str(cycle)]
                return saved_subprocess.run(command, *args, **kwargs)
        image_module.subprocess = DaemonArgProxy()
        try:
            sys.argv = [str(image_module.__file__)]
            image_module.main()
        finally:
            sys.argv = saved_argv
            image_module.subprocess = saved_subprocess
        image_proof = private_json(image_proof_path)
        validate_gf_postgres_uid70_probe(image_proof, initial_inventory)
        compare_inventory(initial_inventory, service_inventory())
        if admission_binding(publisher) != admission:
            raise CycleBlocked('ADMISSION_DRIFT_AFTER_CAPTURE')
        selected_after = select_parent(ftps)
        if (selected_after['point']['manifestId'] != selected['point']['manifestId'] or
                selected_after['point']['manifestDigest'] != selected['point']['manifestDigest'] or
                selected_after['receiptSha256'] != selected['receiptSha256']):
            raise CycleBlocked('LATEST_VERIFIED_PARENT_DRIFT_AFTER_CAPTURE')
        helper_paths = [(FTPS_HELPER, 'platform-ftps-backup.py'),
                        (RESTORE_HELPER, 'platform-ftps-restore.py'),
                        (PRODUCER, 'completeness_producer.py'),
                        (PUBLISHER_SOURCE, 'platform-completeness-publisher.py')]
        source_dir = stage_exact_material(cycle, selected['point'], report_path,
                                          cycle / 'cold-volumes.tar.gz', source_proof_path,
                                          cycle / 'isolated-volume-restore-proof.json',
                                          image_proof_path, helper_paths)
        # The root publisher owns final capacity reservation, multipart upload,
        # cryptographic readback, receipt commit and retained-point inventory.
        transfer_lock = acquire_lock(TRANSFER_LOCK, exclusive=True)
        os.close(transfer_lock)
        _remote_file_age_ok(selected['point'])
        publisher_module = publisher
        helper = ftps
        result = publisher_module.publish(helper, selected['point']['bundle'])
        if (result.get('offsitePublished') is not True or result.get('realFtpsVerified') is not True or
                result.get('fullyRecoverable') is not False or result.get('manifestId') != selected['point']['manifestId']):
            raise CycleBlocked('ROOT_PUBLISHER_RESULT_INCOMPLETE')
        # Forward g16 step: the signed deployment must install a native helper
        # with all producer/reader pins before this path can run. Bind the new
        # metadata-only package to this exact verified source extraction and
        # the capsule captured for this cycle; a failure leaves the base point
        # intact and the cycle reported incomplete.
        if selected['point']['manifestId'] == 'manifest-scheduled-platform-20260929-182357-1f9954':
            raise CycleBlocked('G17_REQUIRES_NEW_SIGNED_FULL_PARENT')
        if not hasattr(helper, 'publish_source_overlay_g18'):
            raise CycleBlocked('G18_NATIVE_HELPER_NOT_INSTALLED')
        overlay_result = helper.publish_source_overlay_g18(
            selected['point']['bundle'], str(cycle / 'isolated-source-restored'),
            str(cycle / 'isolated-source-proof.json'))
        if overlay_result.get('status') != 'published-readback-verified' or overlay_result.get('offsiteVerified') is not True:
            raise CycleBlocked('G18_SOURCE_OVERLAY_READBACK_INCOMPLETE')
        result['sourceMetadataOverlay'] = overlay_result
        # Retire only the exact previous private host-tree capture after this
        # parent and its typed overlay have both passed signed readback.
        capture_helper = Path('/usr/local/libexec/platform-host-recovery-extra-mounted-trees.py')
        expected_capture = '336da4bb00e7f8e80b7ca7462d19b395025961623f0968e9241af00aa34c0fbe'
        capture_info = capture_helper.lstat()
        if (capture_helper.is_symlink() or not stat.S_ISREG(capture_info.st_mode) or
                capture_info.st_uid != 0 or capture_info.st_mode & 0o022 or
                capture_info.st_nlink != 1 or sha256(capture_helper) != expected_capture):
            raise CycleBlocked('EXTRA_TREE_CAPTURE_HELPER_PIN')
        capture_module = load_module('verified_extra_tree_capture_finalize', capture_helper)
        finalized = capture_module.finalize_previous_after_verified_cycle()
        if finalized.get('status') not in ('no-previous', 'previous-retired-after-verified-cycle'):
            raise CycleBlocked('EXTRA_TREE_PREVIOUS_NOT_FINALIZED')
        result['previousExtraTreeCapture'] = finalized
        return result
    finally:
        release_locks(locks)


def watchdog_main(root, subject, container_id):
    if os.geteuid() != 0:
        raise CycleBlocked('ROOT_REQUIRED')
    cold_path = pinned_helper('cold')
    adapter_path = pinned_helper('adapter')
    if str(adapter_path.parent) not in sys.path:
        sys.path.insert(0, str(adapter_path.parent))
    cold = load_module('cold_volume_watchdog', cold_path)
    cycle = Path(root)
    if cycle.parent != ROOT or cycle.is_symlink() or not cycle.exists():
        raise CycleBlocked('WATCHDOG_CYCLE_BINDING_INVALID')
    cold.ROOT = cycle
    cold.DEST = cycle / 'cold-volume-snapshots'
    cold.JOURNAL = cycle / 'cold-volume-capture.json'
    cold.HERE = Path(__file__).resolve()
    cold.watchdog(subject, container_id)


def cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', action='store_true', help='read-only live preflight; no capture or upload')
    parser.add_argument('--run', action='store_true', help='root-only capture and publication cycle')
    parser.add_argument('--scheduled-run', action='store_true',
                        help='bounded M/W/F run that retries only pre-capture lock contention')
    parser.add_argument('--watchdog', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--daemon', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--root')
    parser.add_argument('--watchdog-subject')
    parser.add_argument('--watchdog-id')
    args = parser.parse_args(argv)
    if args.daemon:
        if not args.root:
            raise CycleBlocked('DAEMON_CYCLE_BINDING_REQUIRED')
        cycle = Path(args.root)
        if cycle.parent != ROOT or cycle.is_symlink() or not cycle.is_dir():
            raise CycleBlocked('DAEMON_CYCLE_BINDING_INVALID')
        image_path = pinned_helper('image')
        image = load_module('recurring_image_daemon', image_path)
        image.ROOT = cycle
        image.SCRATCH = cycle / 'isolated-image-daemon'
        image.HERE = Path(__file__).resolve()
        image.EXPORT = cycle / 'docker-running-images.tar'
        image.daemon()
        return 0
    if args.watchdog:
        if not args.root or not args.watchdog_subject or not args.watchdog_id:
            raise CycleBlocked('WATCHDOG_BINDING_REQUIRED')
        watchdog_main(args.root, args.watchdog_subject, args.watchdog_id)
        return 0
    if sum((args.plan, args.run, args.scheduled_run)) != 1:
        parser.error('choose exactly one of --plan, --run, or --scheduled-run')
    result = run_scheduled_cycle() if args.scheduled_run else plan_on_host(run=args.run)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(cli())
    except CycleBlocked as error:
        raise SystemExit(str(error)) from None
