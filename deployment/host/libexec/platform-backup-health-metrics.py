#!/usr/bin/python3
"""Expose complete catalog/offsite outcomes; partial dump success is insufficient."""
import datetime
import json
import os
import pathlib
import re
import tempfile
import time

BASE = pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/local-private-backup/data')
OUTPUT = BASE / 'runtime-state/node-exporter-textfile/platform-backup-health.prom'


def timestamp(value):
    if not isinstance(value, str):
        return 0
    try:
        return datetime.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except (ValueError, OverflowError):
        return 0


def records(directory):
    if not directory.exists():
        return
    entries = list(directory.glob('*.json'))
    if len(entries) > 4096:
        raise ValueError('report directory exceeds bounded inventory')
    for path in entries:
        if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        try:
            record = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(record, dict):
            yield record


def collect(base):
    metrics = {}
    admission_path = base.parent / 'trust/admission.json'
    admission_expiry = 0
    try:
        if not admission_path.is_symlink() and admission_path.stat().st_size <= 128 * 1024:
            admission_expiry = timestamp(json.loads(admission_path.read_text()).get('payload', {}).get('expiresAt'))
    except (OSError, json.JSONDecodeError):
        pass
    metrics['platform_backup_admission_expiry_timestamp_seconds'] = admission_expiry
    recovery_root = base.parent.parent / 'state/host-recovery'
    for label, filename, field, required in (
            ('host_recovery', 'host-recovery-proof.json', 'capturedAt', 'decryptRoundtripVerified'),
            ('local_dedup', 'local-dedup-proof.json', 'verifiedAt', 'restoreVerified')):
        value = 0
        try:
            proof_file = recovery_root / filename
            if not proof_file.is_symlink() and proof_file.stat().st_size <= 128 * 1024:
                proof = json.loads(proof_file.read_text())
                if proof.get('status') == 'passed' and proof.get(required) is True:
                    value = timestamp(proof.get(field))
        except (OSError, json.JSONDecodeError):
            pass
        metrics['platform_backup_' + label + '_last_success_timestamp_seconds'] = value
    rustfs_root = base.parent.parent / 'state/rustfs-recovery'
    redis_root = base.parent.parent / 'state/redis-recovery'
    for label, folder, filename, field in (
            ('rustfs', rustfs_root, 'latest.json', 'verifiedAt'),
            ('redis', redis_root, 'latest.json', 'verifiedAt'),
            ('schedule', recovery_root, 'schedule-proof.json', 'finishedAt')):
        proof = {}
        try:
            file = folder / filename
            if not file.is_symlink() and file.stat().st_size <= 128 * 1024:
                proof = json.loads(file.read_text())
        except (OSError, json.JSONDecodeError):
            pass
        verified = label != 'rustfs' or (proof.get('restoreBootVerified') is True and proof.get('s3SemanticRestoreVerified') is True and proof.get('decryptRoundtripVerified') is True)
        if label == 'redis':
            verified = proof.get('allInstancesIsolatedRestoreVerified') is True and proof.get('decryptRoundtripVerified') is True and len(proof.get('instances', [])) == 2 and all(p.get('rdbCheckPassed') is True and p.get('isolatedBootPassed') is True for p in proof['instances'])
        metrics['platform_backup_' + label + '_last_success_timestamp_seconds'] = timestamp(proof.get(field)) if proof.get('status') == 'passed' and verified else 0
        metrics['platform_backup_' + label + '_last_attempt_success'] = 0 if proof.get('status') == 'failed' else 1
    for label, folder in [('rustfs', rustfs_root), ('redis', redis_root)]:
        try:
            attempt = json.loads((folder / 'last-attempt.json').read_text())
            if attempt.get('status') == 'failed':
                metrics['platform_backup_' + label + '_last_attempt_success'] = 0
        except (OSError, json.JSONDecodeError):
            pass
    catalog_success = []
    for record in records(base / 'reports/backup-jobs'):
        if (record.get('schema') == 'platform.backup-job/v1'
                and record.get('status') == 'passed'
                and record.get('operation') == 'backup'
                and record.get('scope') == {'kind': 'platform', 'id': 'platform'}
                and record.get('manifestPath') and record.get('resourceIds')):
            catalog_success.append(timestamp(record.get('finishedAt')))
    catalog_attempts = []
    for state in ('done', 'failed'):
        for record in records(base / 'backup-jobs' / state):
            if (record.get('operation') == 'backup'
                    and record.get('scope') == {'kind': 'platform', 'id': 'platform'}):
                catalog_attempts.append((timestamp(record.get('finishedAt')), int(state == 'done')))
    offsite_success = []
    for record in records(base / 'reports/offsite-backups'):
        if (record.get('schema') == 'platform.offsite-backup-receipt/v1'
                and record.get('status') == 'passed' and record.get('repositoryOffsite') is True
                and record.get('snapshotId') and record.get('manifestId') and record.get('artifactCount', 0) > 0):
            offsite_success.append(timestamp(record.get('finishedAt')))
    offsite_attempts = [(value, 1) for value in offsite_success]
    broker_failures = []
    for record in records(base.parent / 'broker-state/terminal'):
        response = record.get('response', {})
        if (record.get('schema') == 'platform.local-private-broker-terminal/v1'
                and response.get('action') == 'backup.offsite.sync'
                and response.get('status') in ('rejected', 'failed')):
            failure = (timestamp(record.get('recordedAt')), 0)
            offsite_attempts.append(failure)
            broker_failures.append(failure)
    log = base / 'scheduler-logs/restic-offsite.log'
    if log.exists():
        with log.open() as stream:
            for line in stream:
                match = re.match(r'^\[([^]]+)\] unprivileged timer offsite-backup-restic returned exit (\d+)\s*$', line)
                if match:
                    offsite_attempts.append((timestamp(match[1]), 0))
    for pipeline, successes, attempts in (
            ('catalog', catalog_success, catalog_attempts),
            ('offsite', offsite_success, offsite_attempts)):
        last_attempt, success = max(attempts, default=(0, 0))
        metrics['platform_backup_' + pipeline + '_last_success_timestamp_seconds'] = max(successes, default=0)
        metrics['platform_backup_' + pipeline + '_last_attempt_timestamp_seconds'] = last_attempt
        metrics['platform_backup_' + pipeline + '_last_attempt_success'] = success
    try:
        destination = json.loads((recovery_root / 'offsite-destination.json').read_text())
    except (OSError, json.JSONDecodeError):
        destination = {}
    if destination.get('backend') == 'ftps-encrypted-bundles':
        metrics['platform_backup_legacy_onedrive_last_success_timestamp_seconds'] = metrics['platform_backup_offsite_last_success_timestamp_seconds']
        proof = {}; attempt = {}; retention = {}
        for filename, target in [('ftps-proof.json', proof), ('ftps-last-attempt.json', attempt), ('ftps-retention-proof.json', retention)]:
            try:
                source = recovery_root / filename
                if not source.is_symlink() and source.stat().st_size <= 131072:
                    target.update(json.loads(source.read_text()))
            except (OSError, json.JSONDecodeError):
                pass
        verified = proof.get('status') == 'passed' and all(proof.get(k) is True for k in ['tlsVerified', 'actualDownloadVerified', 'decryptVerified', 'manifestHmacVerified', 'everyArtifactShaAndHmacVerified'])
        metrics['platform_backup_offsite_last_success_timestamp_seconds'] = timestamp(proof.get('backupAt')) if verified else 0
        ftps_attempt = (timestamp(attempt.get('finishedAt', attempt.get('startedAt'))), int(attempt.get('status') == 'passed'))
        broker_failure = max(broker_failures, default=(0, 0))
        broker_is_latest = broker_failure[0] > 0 and broker_failure[0] >= ftps_attempt[0]
        last_attempt = broker_failure if broker_is_latest else ftps_attempt
        metrics['platform_backup_offsite_last_attempt_timestamp_seconds'] = last_attempt[0]
        metrics['platform_backup_offsite_last_attempt_success'] = last_attempt[1]
        metrics['platform_backup_offsite_last_attempt_from_broker'] = int(broker_is_latest)
        metrics['platform_backup_offsite_last_attempt_from_ftps'] = int(not broker_is_latest and ftps_attempt[0] > 0)
        metrics['platform_backup_offsite_managed_bytes'] = proof.get('remoteBytes', 0) if verified else 0
        metrics['platform_backup_ftps_retention_last_attempt_success'] = 0 if retention.get('status') == 'failed' else 1
        metrics['platform_backup_offsite_maximum_bytes'] = 70000000000
        metrics['platform_backup_offsite_retained_points'] = proof.get('retainedPointCount', 0) if verified else 0
    return metrics


def main():
    values = collect(BASE)
    values['platform_backup_health_collection_timestamp_seconds'] = time.time()
    output = ''.join('# TYPE ' + name + ' gauge\n' + name + ' ' + str(value) + '\n' for name, value in sorted(values.items()))
    descriptor, temporary = tempfile.mkstemp(prefix='.platform-backup-health-', dir=OUTPUT.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, OUTPUT)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == '__main__':
    main()
