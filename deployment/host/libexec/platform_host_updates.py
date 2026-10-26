"""Explicit Debian/Ubuntu package maintenance; caller owns auth, durable records and flock.

No command executes at import. Persist all plans in root-owned operation storage;
never trust a client-supplied plan. Reboot scheduling is a separate post-response step.
"""
import hashlib
import json
import os
import pathlib
import re
import selectors
import subprocess
import threading
import time
import uuid

PLAN_TTL = 900
_ACTIVE_CHILD = None
_PACKAGE = re.compile(r'^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?$')
_VERSION = re.compile(r'^[a-zA-Z0-9.+:~_-]+$')
_BOOT_ID = pathlib.Path('/proc/sys/kernel/random/boot_id')
_REBOOT_REQUIRED = pathlib.Path('/var/run/reboot-required')
_REBOOT_PACKAGES = pathlib.Path('/var/run/reboot-required.pkgs')


class HostUpdateError(RuntimeError):
    pass


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _emit(progress, **value):
    if progress:
        progress(value)


def _status(line, progress):
    # apt's machine protocol: kind:package:percent:message. Colons in the
    # human message are allowed; no human output is used to infer completion.
    if line.startswith('{'):
        try:
            event = json.loads(line)
            if isinstance(event, dict) and event.get('type') == 'progress' and isinstance(event.get('value'), dict):
                _emit(progress, **event['value'])
        except ValueError:
            pass
        return
    match = re.match(r'^(pmstatus|pmerror|pmconffile|dlstatus):(.+?):([0-9.]+):(.*)$', line.strip())
    if match:
        parts = match.groups()
        try:
            percent = float(parts[2])
        except ValueError:
            return
        _emit(progress, stage='packages', package=parts[1], percent=max(0, min(100, percent)),
              state='failed' if parts[0] == 'pmerror' else 'running', protocol=parts[0])


def active_maintenance():
    return _ACTIVE_CHILD is not None and _ACTIVE_CHILD.poll() is None


def _detach_child(process):
    global _ACTIVE_CHILD
    _ACTIVE_CHILD = process
    def drain():
        try:
            while process.stdout.read(65536):
                pass
            process.wait()
        finally:
            process.stdout.close()
    threading.Thread(target=drain, daemon=True).start()


def _run(args, progress=None, timeout=3600):
    if active_maintenance():
        raise HostUpdateError('previous package process is still running; reconciliation required')
    env = {**os.environ, 'LC_ALL': 'C', 'LANG': 'C', 'DEBIAN_FRONTEND': 'noninteractive'}
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline, chunks, pending = time.monotonic() + timeout, [], b''
    size = 0
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                # Do not kill dpkg mid-transaction: leave the process running and
                # report unknown completion for reconciliation. Caller must retain
                # its global operation exclusion until this child exits.
                _detach_child(process)
                _emit(progress, stage='reconciliation', state='running', childPid=process.pid)
                raise HostUpdateError('maintenance timeout: completion unknown; package process may still be running; reconciliation required')
            for key, _ in selector.select(timeout=min(1, max(0, deadline - time.monotonic()))):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                size += len(block)
                if size > 16 * 1024 * 1024:
                    _detach_child(process)
                    raise HostUpdateError('package output limit exceeded: completion unknown; reconciliation required')
                chunks.append(block)
                pending += block
                while b'\n' in pending:
                    line, pending = pending.split(b'\n', 1)
                    _status(line.decode('utf-8', 'replace'), progress)
        code = process.wait(timeout=max(1, deadline - time.monotonic()))
        text = b''.join(chunks).decode('utf-8', 'replace')
        if code:
            # Raw apt output can contain proxy URLs or repository credentials.
            raise HostUpdateError('package command failed (exit ' + str(code) + '); no rollback claimed; inspect privileged host logs')
        return text
    finally:
        selector.close()
        if process.poll() is not None:
            process.stdout.close()


def _boot_id():
    value = _BOOT_ID.read_text().strip()
    if not re.fullmatch(r'[a-f0-9-]{36}', value):
        raise HostUpdateError('host boot identity unavailable')
    return value


def _installed():
    rows = _run(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n'], timeout=60)
    result = {}
    for line in rows.splitlines():
        parts = line.split('\t')
        if len(parts) == 3 and parts[2] == 'installed':
            if not _PACKAGE.fullmatch(parts[0]) or not _VERSION.fullmatch(parts[1]):
                raise HostUpdateError('invalid installed package metadata')
            result[parts[0]] = parts[1]
    if not result:
        raise HostUpdateError('installed package inventory unavailable')
    return result


def package_manager_busy():
    """Observe kernel lock ownership; never acquire, remove or replace apt locks."""
    identities = set()
    for name in ['/var/lib/dpkg/lock', '/var/lib/dpkg/lock-frontend', '/var/lib/apt/lists/lock', '/var/cache/apt/archives/lock']:
        try:
            info = os.stat(name)
        except FileNotFoundError:
            continue
        identities.add((os.major(info.st_dev), os.minor(info.st_dev), info.st_ino))
    try:
        records = pathlib.Path('/proc/locks').read_text().splitlines()
    except OSError as error:
        raise HostUpdateError('package lock state unavailable; reboot blocked') from error
    for line in records:
        fields = line.split()
        if '->' in fields:  # A waiting process does not own this lock.
            continue
        for field in fields:
            match = re.fullmatch(r'([a-fA-F0-9]+):([a-fA-F0-9]+):([0-9]+)', field)
            if match and (int(match[1], 16), int(match[2], 16), int(match[3])) in identities:
                return True
    return False


def _trusted_reboot_file(path):
    import stat
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise HostUpdateError('untrusted reboot-required metadata')
    return True


def inventory():
    packages = []
    if _trusted_reboot_file(_REBOOT_PACKAGES):
        packages = sorted({line.strip() for line in _REBOOT_PACKAGES.read_text()[:65536].splitlines() if _PACKAGE.fullmatch(line.strip())})
    return {'schema': 'platform-host-updates/v1', 'bootId': _boot_id(),
            'rebootRequired': _trusted_reboot_file(_REBOOT_REQUIRED), 'rebootPackages': packages,
            'provider': 'apt', 'releaseUpgradeSupported': False, 'maintenanceRunning': active_maintenance()}


def _canonical_package(name, installed):
    """Map apt's shortened Multi-Arch names to one exact dpkg inventory key."""
    if name in installed:
        return name
    base, separator, architecture = name.partition(':')
    candidates = [key for key in installed if key.partition(':')[0] == base]
    if separator:
        # Never substitute a different explicit architecture. The sole unqualified
        # inventory identity is acceptable only when no qualified sibling exists.
        candidates = candidates if len(candidates) == 1 and ':' not in candidates[0] else []
    if len(candidates) != 1:
        raise HostUpdateError('package alias is missing or ambiguous in installed inventory')
    return candidates[0]


def _simulation(text, installed):
    packages, kept, collecting = [], [], False
    for line in text.splitlines():
        if line.startswith('Remv '):
            raise HostUpdateError('package plan would remove packages')
        if line.startswith('The following packages have been kept back:'):
            collecting = True
            continue
        if collecting:
            if line.startswith('  '):
                kept.extend(name for name in line.split() if _PACKAGE.fullmatch(name))
            else:
                collecting = False
        if not line.startswith('Inst '):
            continue
        match = re.match(r'^Inst ([^ ]+)(?: \[([^]]+)\])? \(([^ ]+)', line)
        if not match:
            raise HostUpdateError('unsupported apt simulation output')
        name, old, target = match.groups()
        if not _PACKAGE.fullmatch(name) or not _VERSION.fullmatch(target):
            raise HostUpdateError('invalid package candidate')
        try:
            name = _canonical_package(name, installed)
        except HostUpdateError as error:
            raise HostUpdateError('package plan adds packages or package alias is ambiguous') from error
        current = installed.get(name)
        if current is None or old is not None and old != current:
            raise HostUpdateError('package plan adds packages or inventory changed')
        packages.append({'name': name, 'currentVersion': current, 'targetVersion': target})
    if len({row['name'] for row in packages}) != len(packages):
        raise HostUpdateError('duplicate package candidate')
    return sorted(packages, key=lambda row: row['name']), sorted(set(kept))


def check(progress=None):
    _emit(progress, stage='refresh', state='running')
    _run(['apt-get', '-o', 'DPkg::Lock::Timeout=30', 'update', '--error-on=any'], progress, timeout=600)
    _emit(progress, stage='inventory', state='running')
    installed = _installed()
    text = _run(['apt-get', '-s', '-o', 'DPkg::Lock::Timeout=30', 'upgrade'], timeout=120)
    packages, kept = _simulation(text, installed)
    return {**inventory(), 'checkedAt': int(time.time()), 'packages': packages, 'keptBack': kept,
            'installedFingerprint': _digest(installed), 'candidateFingerprint': _digest(packages)}


def _seal(value):
    value['revision'] = _digest(value)
    return value


def plan(check_result=None, ttl=PLAN_TTL):
    value = check_result if check_result is not None else check()
    now = int(time.time())
    if now - value['checkedAt'] > 300 or value['checkedAt'] > now + 5:
        raise HostUpdateError('package check expired')
    return _seal({'schema': 'platform-host-package-plan/v1', 'planId': uuid.uuid4().hex,
                  'createdAt': now, 'expiresAt': now + min(max(int(ttl), 1), PLAN_TTL),
                  'bootId': value['bootId'], 'packages': value['packages'], 'keptBack': value['keptBack'],
                  'installedFingerprint': value['installedFingerprint'], 'candidateFingerprint': value['candidateFingerprint'],
                  'confirmationRequired': 'UPDATE', 'steps': ['Verify exact package versions', 'Upgrade planned packages', 'Verify installed versions'],
                  'risks': ['Services may restart during package configuration.', 'Package failures require host recovery; automatic rollback is unavailable.'],
                  'rebootRequired': value['rebootRequired']})


def _validate(value, schema):
    unsigned = dict(value)
    revision = unsigned.pop('revision', None)
    if revision != _digest(unsigned) or value.get('schema') != schema:
        raise HostUpdateError('immutable host plan mismatch')
    if int(time.time()) >= value['expiresAt']:
        raise HostUpdateError('host plan expired')
    if value['bootId'] != _boot_id():
        raise HostUpdateError('host boot changed; create a fresh plan')


def _persist_package_recovery(value, automatic, state):
    # Root-only crash recovery record, separate from the immutable approval plan.
    _private_directory()
    identity = value['planId']
    if not re.fullmatch(r'[a-f0-9]{32}', identity):
        raise HostUpdateError('invalid package recovery identity')
    record = {'planId': identity, 'revision': value['revision'], 'automaticPackages': automatic,
              'state': state, 'updatedAt': int(time.time())}
    temporary = _PLAN_DIRECTORY / (identity + '.' + uuid.uuid4().hex + '.tmp')
    target = _PLAN_DIRECTORY / (identity + '.recovery.json')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(record, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        directory = os.open(_PLAN_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def apply(value, progress=None):
    _validate(value, 'platform-host-package-plan/v1')
    _emit(progress, stage='verify', state='running')
    installed = _installed()
    if _digest(installed) != value['installedFingerprint']:
        raise HostUpdateError('installed package versions changed; create a fresh plan')
    packages, kept = _simulation(_run(['apt-get', '-s', '-o', 'DPkg::Lock::Timeout=30', 'upgrade'], timeout=120), installed)
    if _digest(packages) != value['candidateFingerprint'] or packages != value['packages'] or kept != value['keptBack']:
        raise HostUpdateError('package candidates changed; create a fresh plan')
    if not packages:
        return {'state': 'succeeded', 'packages': [], 'rebootRequired': inventory()['rebootRequired']}
    pins = [row['name'] + '=' + row['targetVersion'] for row in packages]
    command = ['apt-get', '-o', 'DPkg::Lock::Timeout=30', '--no-remove', '--only-upgrade', 'install', *pins]
    exact, _ = _simulation(_run(command[:1] + ['-s'] + command[1:], timeout=120), installed)
    if exact != packages:
        raise HostUpdateError('exact package upgrade differs from approved plan')
    automatic_before = _run(['apt-mark', 'showauto'], timeout=60).splitlines()
    if any(not _PACKAGE.fullmatch(name) for name in automatic_before):
        raise HostUpdateError('invalid automatic package metadata')
    automatic_names = {_canonical_package(name, installed) for name in automatic_before}
    automatic = sorted({row['name'] for row in packages} & automatic_names)
    _persist_package_recovery(value, automatic, 'prepared')
    _emit(progress, stage='upgrade', state='running', packageCount=len(packages))
    upgrade_error = None
    try:
        _run(command[:1] + ['-y', '-o', 'Dpkg::Options::=--force-confold', '-o', 'APT::Status-Fd=1'] + command[1:], progress, timeout=7200)
    except HostUpdateError as error:
        upgrade_error = error
    if automatic:
        _emit(progress, stage='restore-package-marks', state='running')
        try:
            _run(['apt-mark', 'auto', '--', *automatic], timeout=60)
        except HostUpdateError as error:
            _persist_package_recovery(value, automatic, 'mark-restoration-required')
            _emit(progress, stage='restore-package-marks', state='failed', recoveryRequired=True)
            raise HostUpdateError('automatic package mark restoration failed; recovery required; upgrade completion must be verified') from error
    _persist_package_recovery(value, automatic, 'upgrade-failed-marks-restored' if upgrade_error else 'marks-restored')
    if upgrade_error is not None:
        raise upgrade_error
    actual = _installed()
    results = [{**row, 'state': 'succeeded' if actual.get(row['name']) == row['targetVersion'] else 'failed'} for row in packages]
    if any(row['state'] != 'succeeded' for row in results):
        raise HostUpdateError('installed package verification failed; no rollback claimed')
    _emit(progress, stage='complete', state='succeeded')
    return {'state': 'succeeded', 'packages': results, 'rebootRequired': inventory()['rebootRequired']}


def reboot_plan(ttl=300):
    value, now = inventory(), int(time.time())
    if not value['rebootRequired']:
        raise HostUpdateError('reboot is not required')
    return _seal({'schema': 'platform-host-reboot-plan/v1', 'planId': uuid.uuid4().hex,
                  'createdAt': now, 'expiresAt': now + min(max(int(ttl), 1), 300), 'bootId': value['bootId'],
                  'confirmationRequired': 'REBOOT', 'rebootRequired': value['rebootRequired'],
                  'steps': ['Persist reboot intent', 'Schedule reboot after request acceptance', 'Verify new boot and service health'],
                  'risks': ['The host and its applications will be temporarily unavailable.']})


def prepare_reboot(value, persist_intent, confirmation):
    if active_maintenance() or package_manager_busy():
        raise HostUpdateError('package maintenance still running; reboot blocked')
    _validate(value, 'platform-host-reboot-plan/v1')
    if not inventory()['rebootRequired']:
        raise HostUpdateError('reboot is no longer required')
    if confirmation != 'REBOOT':
        raise HostUpdateError('explicit REBOOT confirmation required')
    intent = {'schema': 'platform-host-reboot-intent/v1', 'planId': value['planId'],
              'bootIdBefore': value['bootId'], 'createdAt': int(time.time()), 'state': 'queued'}
    persist_intent(intent)  # Must complete durably before returning accepted.
    return intent


def schedule_reboot(intent):
    """Call ONLY after the HTTP accepted response has been flushed by the bridge."""
    if active_maintenance() or package_manager_busy():
        raise HostUpdateError('package maintenance still running; reboot blocked')
    if not inventory()['rebootRequired']:
        raise HostUpdateError('reboot is no longer required')
    if intent.get('schema') != 'platform-host-reboot-intent/v1' or intent.get('state') != 'queued' or intent.get('bootIdBefore') != _boot_id():
        raise HostUpdateError('invalid or stale reboot intent')
    if not re.fullmatch(r'[a-f0-9]{32}', intent.get('planId', '')):
        raise HostUpdateError('invalid reboot plan identity')
    _run(['systemd-run', '--unit=platform-host-reboot-' + intent['planId'], '--on-active=5s', '--', '/usr/bin/systemctl', 'reboot'], timeout=30)
    return {**intent, 'state': 'waiting-reboot'}


def reconcile_reboot(intent, health_check=None):
    if _boot_id() == intent.get('bootIdBefore'):
        return {**intent, 'state': 'waiting-reboot'}
    health = health_check() if health_check else None
    return {**intent, 'bootIdAfter': _boot_id(), 'state': 'succeeded' if health is True else 'verifying-services', 'servicesHealthy': health}


# The hardened HTTP bridge cannot write /var/lib/apt or /var/lib/dpkg. Only these
# two fixed actions run in a separately created root systemd unit.
_PLAN_DIRECTORY = pathlib.Path('/var/lib/platform-updates/host-plans')
_WORKER = '/usr/local/libexec/platform_host_updates.py'


def _private_directory():
    import stat
    _PLAN_DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = _PLAN_DIRECTORY.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise HostUpdateError('host plan directory must be a root-owned private directory')


def write_plan_file(value):
    """Persist a server-produced plan; return its exact worker-approved pathname."""
    _private_directory()
    identity = value.get('planId', '')
    if not re.fullmatch(r'[a-f0-9]{32}', identity):
        raise HostUpdateError('invalid host plan identity')
    target = _PLAN_DIRECTORY / (identity + '.json')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(value, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        directory = os.open(_PLAN_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return str(target)


def _read_plan_file(filename):
    import stat
    target = pathlib.Path(filename)
    if target.parent != _PLAN_DIRECTORY or not re.fullmatch(r'[a-f0-9]{32}\.json', target.name):
        raise HostUpdateError('host plan path outside private plan store')
    _private_directory()
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 1024 * 1024:
            raise HostUpdateError('host plan must be a private root-owned regular file')
        value = json.load(handle)
    if value.get('planId') != target.stem:
        raise HostUpdateError('host plan filename identity mismatch')
    return value


def run_transient(action, plan_file=None, progress=None, operation_id=None):
    """Delegate only fixed OS actions outside the bridge filesystem sandbox."""
    if action not in ('check', 'apply'):
        raise HostUpdateError('unsupported transient host action')
    identity = operation_id or uuid.uuid4().hex
    if not re.fullmatch(r'[a-f0-9]{32}', identity):
        raise HostUpdateError('invalid host operation identity')
    arguments = ['/usr/bin/python3', _WORKER, '--worker', action, '--operation-id', identity]
    if action == 'apply':
        _read_plan_file(plan_file)  # Reject paths before crossing the unit boundary.
        arguments.extend(['--plan-file', str(plan_file)])
    elif plan_file is not None:
        raise HostUpdateError('check does not accept a plan pathname')
    command = ['systemd-run', '--wait', '--pipe', '--collect', '--service-type=exec',
               '--property=NoNewPrivileges=yes', '--property=PrivateTmp=yes', '--property=User=root',
               '--unit=platform-host-updates-' + identity, '--', *arguments]
    output = _run(command, progress, timeout=7800 if action == 'apply' else 900)
    result = None
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and event.get('type') == 'result':
            result = event.get('value')
    if not isinstance(result, dict):
        raise HostUpdateError('host worker did not return a verified result')
    return result


def _operation_path(operation_id):
    if not re.fullmatch(r'[a-f0-9]{32}', str(operation_id)):
        raise HostUpdateError('invalid host operation identity')
    return _PLAN_DIRECTORY / ('worker-' + operation_id + '.json')


def _persist_worker_status(value):
    _private_directory()
    target = _operation_path(value['operationId'])
    temporary = _PLAN_DIRECTORY / (target.name + '.' + uuid.uuid4().hex + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as handle:
            json.dump(value, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        descriptor = os.open(_PLAN_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def worker_status(operation_id):
    """Read the producer-owned record; a disconnected consumer is not failure."""
    import stat
    target = _operation_path(operation_id)
    _private_directory()
    try:
        descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor) as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 4 * 1024 * 1024:
            raise HostUpdateError('invalid private host worker record')
        value = json.load(handle)
    if value.get('schema') != 'platform-host-worker-status/v1' or value.get('operationId') != operation_id:
        raise HostUpdateError('host worker record identity mismatch')
    return value


def worker_alive(operation_id):
    _operation_path(operation_id)
    try:
        state = _run(['systemctl', 'show', '--property=ActiveState', '--value',
                      'platform-host-updates-' + operation_id + '.service'], timeout=15).strip()
        if state in ('active', 'activating', 'deactivating', 'reloading'):
            return True
        if state not in ('inactive', 'failed', ''):
            return None
        return None if package_manager_busy() else False
    except (HostUpdateError, OSError):
        return None


def _silence_stdout():
    # Replace fd 1 as well as swallowing the exception: Python's final flush of
    # the broken buffered stream would otherwise terminate with exit status 120.
    import sys
    descriptor = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(descriptor, sys.stdout.fileno())
    finally:
        os.close(descriptor)


def _worker_print(event):
    try:
        print(json.dumps(event), flush=True)
    except BrokenPipeError:
        _silence_stdout()


def _execute_worker(action, operation_id, plan_file=None):
    _operation_path(operation_id)
    value = _read_plan_file(plan_file) if action == 'apply' else None
    state = {'schema': 'platform-host-worker-status/v1', 'operationId': operation_id,
             'action': action, 'planId': value['planId'] if value else None,
             'state': 'running', 'updatedAt': int(time.time())}
    _persist_worker_status(state)
    def progress(event):
        state.update(progress=event, updatedAt=int(time.time()))
        try:
            _persist_worker_status(state)
        except (OSError, HostUpdateError):
            # Keep draining apt/dpkg even if storage fails. A final durable write
            # is still mandatory before the worker may report success.
            state['spoolWriteFailed'] = True
        _worker_print({'type': 'progress', 'value': event})
    try:
        if action == 'check':
            result = check(progress)
        else:
            result = apply(value, progress)
            if _run(['dpkg', '--audit'], timeout=60).strip():
                raise HostUpdateError('dpkg audit is not clean; package recovery required')
            result.update(planId=value['planId'], packageVersionsVerified=True,
                          dpkgAuditClean=True, marksRestored=True)
        state.update(state='succeeded', result=result, updatedAt=int(time.time()))
        _persist_worker_status(state)
        _worker_print({'type': 'result', 'value': result})
        return result
    except (HostUpdateError, OSError, ValueError):
        state.update(state='failed', error='Host maintenance requires verification; no rollback claimed.', updatedAt=int(time.time()))
        _persist_worker_status(state)
        _worker_print({'type': 'error', 'error': state['error']})
        raise


def _main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', choices=['check', 'apply'], required=True)
    parser.add_argument('--operation-id', required=True)
    parser.add_argument('--plan-file')
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        raise HostUpdateError('host maintenance worker requires root')
    if arguments.worker == 'check' and arguments.plan_file:
        raise HostUpdateError('check does not accept a plan pathname')
    return _execute_worker(arguments.worker, arguments.operation_id, arguments.plan_file)


if __name__ == '__main__':
    try:
        _main()
    except (HostUpdateError, OSError, ValueError):
        raise SystemExit(1)
