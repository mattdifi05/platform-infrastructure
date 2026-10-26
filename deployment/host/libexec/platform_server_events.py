"""Bounded read-only host diagnostics. No application logs, ENV or repair actions."""
import copy
import datetime
import hashlib
import json
import os
import re
import selectors
import subprocess
import threading
import time

SYSTEM_UNITS = (
    'docker.service', 'containerd.service', 'ssh.service', 'sshd.service',
    'systemd-journald.service', 'systemd-networkd.service', 'systemd-resolved.service',
    'ufw.service', 'fail2ban.service', 'cloudflared.service',
    'platform-runtime-updates.service', 'platform-vault-runtime.service',
    'platform-admin.service', 'platform-admin-vps.service',
    'platform-application-operator.service', 'platform-dns-probe.service',
    'platform-db-tls-metrics.service', 'platform-cloudflared-vps.service',
)
DOCKER_FORMAT = ('{"id":{{json .Id}},"name":{{json .Name}},"state":{{json .State.Status}},'
                 '"running":{{json .State.Running}},"oom":{{json .State.OOMKilled}},'
                 '"exitCode":{{json .State.ExitCode}},"error":{{if .State.Error}}true{{else}}false{{end}},'
                 '"finishedAt":{{json .State.FinishedAt}},'
                 '"health":{{with index .State "Health"}}{{json .Status}}{{else}}null{{end}},'
                 '"restart":{{json .HostConfig.RestartPolicy.Name}},'
                 '"service":{{json (index .Config.Labels "com.docker.compose.service")}}}')


class SourceUnavailable(RuntimeError):
    pass


def read_command(arguments, timeout=3, max_bytes=262144):
    """Bound both execution and stdout; killing this diagnostic never kills a service."""
    child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    deadline, chunks, size = time.monotonic() + timeout, [], 0
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SourceUnavailable('diagnostic timeout')
            for key, _ in selector.select(remaining):
                data = os.read(key.fileobj.fileno(), 8192)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                size += len(data)
                if size > max_bytes:
                    raise SourceUnavailable('diagnostic output limit')
                chunks.append(data)
        if child.wait(timeout=max(.01, deadline - time.monotonic())):
            raise SourceUnavailable('diagnostic unavailable')
        return b''.join(chunks).decode('utf-8', errors='replace')
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SourceUnavailable('diagnostic unavailable') from error
    finally:
        selector.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2)
        child.stdout.close()


def redact(value, limit=400):
    value = str(value)[:8192]
    value = re.sub(r'-----BEGIN [^-]+-----.*?(?:-----END [^-]+-----|$)', '[chiave rimossa]', value, flags=re.S)
    value = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', value)
    value = re.sub(r'(?i)\b(?:bearer|basic)\s+[^\s,;]+', '[autenticazione rimossa]', value)
    value = re.sub(r'(?i)\b([a-z0-9_]*(?:password|passwd|secret|token|api[-_]?key|authorization|credential|private[-_]?key)[a-z0-9_]*)\b[\"\x27]?\s*[:=]\s*(?:"[^"]*"|\x27[^\x27]*\x27|[^\s,;]+)', r'\1=[rimosso]', value)
    value = re.sub(r'(?i)\b[a-z][a-z0-9+.-]{1,20}://[^\s<>"\x27]+', '[URL rimossa]', value)
    value = re.sub(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b', '[credenziale rimossa]', value)
    value = re.sub(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b', '[token rimosso]', value)
    value = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '[email rimossa]', value)
    value = re.sub(r'(?i)\b(user(?:name)?|account|login)\b[\"\x27]?(?:\s*[:=]\s*[\"\x27]?|\s+)([a-z0-9_.@-]+)', r'\1=[utente]', value)
    value = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP rimosso]', value)
    value = re.sub(r'(?i)(?<![\w])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]+', '[IP rimosso]', value)
    value = re.sub(r'(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '[ID rimosso]', value)
    value = re.sub(r'\b[A-Za-z0-9_+/=-]{40,}\b', '[valore rimosso]', value)
    value = re.sub(r'/(?:home|Users)/[^/\s]+', '/home/[utente]', value)
    value = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', value)
    return re.sub(r'\s+', ' ', value).strip()[:limit]


def iso(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat()


def event(severity, source, service, message, code, observed, active=True):
    service, message, code = redact(service, 100), redact(message), redact(code, 80)
    identity = hashlib.sha256(json.dumps([source, service, code, message]).encode()).hexdigest()[:32]
    return {'id': 'event-' + identity, 'severity': severity, 'source': source, 'service': service,
            'message': message, 'code': code, 'count': 1, 'firstSeen': iso(observed), 'lastSeen': iso(observed), 'active': active}


def deduplicate(rows):
    output = {}
    for row in rows:
        if row['id'] not in output:
            output[row['id']] = copy.deepcopy(row)
        else:
            item = output[row['id']]
            item['count'] += row['count']
            item['firstSeen'] = min(item['firstSeen'], row['firstSeen'])
            item['lastSeen'] = max(item['lastSeen'], row['lastSeen'])
    return list(output.values())


def host_metrics():
    stats = os.statvfs('/')
    values = {'diskPercent': (1 - stats.f_bavail / stats.f_blocks) * 100 if stats.f_blocks else None,
              'inodePercent': (1 - stats.f_favail / stats.f_files) * 100 if stats.f_files else None}
    with open('/proc/meminfo') as handle:
        memory = {key: int(value.split()[0]) for line in handle for key, _, value in [line.partition(':')] if key in ['MemTotal', 'MemAvailable']}
    values['memoryPercent'] = (1 - memory['MemAvailable'] / memory['MemTotal']) * 100 if memory.get('MemTotal') and 'MemAvailable' in memory else None
    return values


def operation_scopes(row):
    kind = row.get('kind', 'apply')
    if kind.startswith('host-'):
        return {kind}
    components = {item.get('componentId') for item in row.get('componentResults', []) if isinstance(item, dict) and item.get('componentId')}
    return {'runtime:' + str(value) for value in components} if components else {'runtime:' + str(row.get('componentId') or kind)}


class ServerEventsCollector:
    def __init__(self, run=read_command, read_operations=lambda: [], metrics=host_metrics, now=time.time, ttl=12):
        self.run, self.read_operations, self.metrics, self.now, self.ttl = run, read_operations, metrics, now, ttl
        self.lock, self.cached, self.cached_at = threading.Lock(), None, 0
        self.active, self.resolved = {}, []

    def __call__(self):
        with self.lock:
            observed = self.now()
            if self.cached is not None and 0 <= observed - self.cached_at < self.ttl:
                return copy.deepcopy(self.cached)
            issues, events, sources, available = [], [], [], set()
            def collect(identity, reader):
                try:
                    active, recent = reader(observed)
                    for item in active:
                        item['_sourceId'] = identity
                    issues.extend(active); events.extend(recent)
                    sources.append({'id': identity, 'available': True})
                    available.add(identity)
                except Exception:
                    sources.append({'id': identity, 'available': False, 'reason': 'Lettura non disponibile; stato non verificato.'})
                    warning = event('warning', identity if identity != 'journal' else 'systemd', identity,
                                    'Fonte diagnostica non disponibile: impossibile verificare lo stato.', 'source-unavailable', observed)
                    warning['_sourceId'] = identity
                    issues.append(warning)
            collect('systemd', self.systemd)
            collect('docker', self.docker)
            collect('journal', self.journal)
            collect('updates', self.updates)
            collect('host', self.host)
            current = {}
            for item in deduplicate(issues):
                prior = self.active.get(item['id'])
                if prior:
                    item['firstSeen'] = prior['firstSeen']
                    item['count'] = prior['count']
                current[item['id']] = item
            for identity, prior in self.active.items():
                if identity not in current and prior.get('_sourceId') in available and prior['code'] != 'source-unavailable':
                    recovered = copy.deepcopy(prior)
                    recovered.update(id='resolved-' + identity[-32:], active=False, message='Risolto: ' + prior['message'], lastSeen=iso(observed))
                    self.resolved.append(recovered)
                elif identity not in current and prior.get('_sourceId') not in available:
                    current[identity] = prior  # Retain observation internally; never claim it resolved on a read failure.
            self.active = current
            current_rows = [row for row in issues if row['id'] in current]
            # Use merged firstSeen/count without returning unverified old source state.
            current_rows = [copy.deepcopy(current[row['id']]) for row in deduplicate(current_rows)]
            self.resolved = [row for row in self.resolved if row['lastSeen'] >= iso(observed - 86400)][-50:]
            recent = deduplicate(events + self.resolved)
            current_rows.sort(key=lambda row: (row['severity'] != 'error', row['source'], row['service']))
            recent.sort(key=lambda row: row['lastSeen'], reverse=True)
            partial = len(available) != len(sources) or len(current_rows) > 40 or len(recent) > 80
            payload = {'schema': 'server-events/v1', 'available': bool(available), 'partial': partial, 'checkedAt': iso(observed),
                       'issues': current_rows[:40], 'events': recent[:80], 'sources': sources}
            for item in payload['issues'] + payload['events']:
                item.pop('_sourceId', None)
            while len(json.dumps(payload, separators=(',', ':')).encode()) > 120 * 1024:
                payload['partial'] = True
                (payload['events'] if payload['events'] else payload['issues']).pop()
            self.cached, self.cached_at = copy.deepcopy(payload), self.now()
            return payload

    def systemd(self, observed):
        data = json.loads(self.run(['systemctl', 'list-units', '--state=failed', '--all', '--no-legend', '--no-pager', '--plain', '--output=json'], timeout=3))
        if not isinstance(data, list) or len(data) > 200:
            raise SourceUnavailable()
        return [event('error', 'systemd', row['unit'], 'Unità systemd in stato failed.', 'unit-failed', observed)
                for row in data if isinstance(row, dict) and row.get('active') == 'failed' and isinstance(row.get('unit'), str)], []

    def docker(self, observed):
        identities = self.run(['docker', 'ps', '-aq', '--no-trunc'], timeout=2, max_bytes=16384).split()
        if len(identities) > 200 or any(not re.fullmatch('[a-f0-9]{64}', identity) for identity in identities):
            raise SourceUnavailable()
        if not identities:
            return [], []
        lines = self.run(['docker', 'inspect', '--format', DOCKER_FORMAT, *identities], timeout=3).splitlines()
        if len(lines) != len(identities):
            raise SourceUnavailable()
        issues, recent = [], []
        for line in lines:
            row = json.loads(line)
            name = str(row.get('name', '')).lstrip('/')
            service = str(row.get('service') or name)
            if '-rollback-' in name or '-update-' in name or service.endswith(('-init', '-bootstrap')):
                continue
            if row.get('state') == 'restarting':
                issues.append(event('error', 'docker', name, 'Il container continua a riavviarsi.', 'container-restarting', observed))
            if row.get('running') and row.get('health') == 'unhealthy':
                issues.append(event('error', 'docker', name, 'Il controllo di salute del container non riesce.', 'container-unhealthy', observed))
            if row.get('oom') and not row.get('running'):
                issues.append(event('error', 'docker', name, 'Container arrestato per memoria esaurita.', 'container-oom', observed))
            elif row.get('state') in ['dead', 'exited'] and (row.get('error') or row.get('exitCode') not in [0, 137, 143] and row.get('restart') in ['always', 'on-failure']):
                issues.append(event('error', 'docker', name, 'Container arrestato in modo inatteso.', 'container-unexpected-exit', observed))
        return issues, recent

    def journal(self, observed):
        matches = ['_TRANSPORT=kernel']
        for unit in SYSTEM_UNITS:
            matches.extend(['+', '_SYSTEMD_UNIT=' + unit])
        text = self.run(['journalctl', '--boot=0', '--since=-24h', '--priority=0..4', '--lines=100', '--output=json', '--no-pager', *matches], timeout=3)
        rows = text.splitlines()
        if len(rows) > 100:
            raise SourceUnavailable()
        events = []
        for line in rows:
            row = json.loads(line)
            kernel = row.get('_TRANSPORT') == 'kernel'
            unit = row.get('_SYSTEMD_UNIT')
            if not kernel and unit not in SYSTEM_UNITS:
                continue
            priority = int(row.get('PRIORITY', 7))
            if priority > 4 or priority < 0:
                continue
            timestamp = int(row.get('__REALTIME_TIMESTAMP', int(observed * 1000000))) / 1000000
            if not observed - 86400 <= timestamp <= observed + 300:
                continue
            if not isinstance(row.get('MESSAGE'), str):
                continue
            events.append(event('error' if priority <= 3 else 'warning', 'host' if kernel else 'systemd',
                                'kernel' if kernel else unit, row['MESSAGE'], 'journal-error' if priority <= 3 else 'journal-warning', timestamp, False))
        return [], events

    def updates(self, observed):
        rows = self.read_operations()
        if not isinstance(rows, list) or len(rows) > 200:
            raise SourceUnavailable()
        resolved, active, recent = set(), [], []
        for row in rows:  # Existing operation store returns newest first.
            scopes = operation_scopes(row)
            service = ', '.join(sorted(scopes))
            if row.get('status') in ['failed', 'interrupted', 'rolled-back', 'rolled_back']:
                try:
                    seen = datetime.datetime.fromisoformat(row['finishedAt'].replace('Z', '+00:00')).timestamp()
                    if observed - 86400 <= seen <= observed + 300:
                        recent.append(event('warning', 'updates', service, 'Manutenzione precedente non riuscita (storico).', 'update-failed-history', seen, False))
                except (KeyError, TypeError, ValueError):
                    pass
            if row.get('status') == 'succeeded' or row.get('operatorReconciled'):
                resolved.update(scopes)
                continue
            if scopes <= resolved:
                continue
            if row.get('status') in ['queued', 'running'] and not row.get('recoveryRequired'):
                resolved.update(scopes)
                continue
            if row.get('recoveryRequired'):
                active.append(event('error', 'updates', service, 'Una manutenzione richiede una verifica amministrativa prima di procedere.', 'update-recovery-required', observed))
                resolved.update(scopes)
            elif row.get('status') in ['failed', 'interrupted', 'rolled-back', 'rolled_back']:
                active.append(event('warning', 'updates', service, 'L’ultima manutenzione non è riuscita; consultare lo stato degli aggiornamenti.', 'update-failed', observed))
                resolved.update(scopes)
        return active, recent

    def host(self, observed):
        values = self.metrics()
        output = []
        for key, code, message, threshold in [('diskPercent', 'disk-critical', 'Spazio del filesystem host quasi esaurito.', 95),
                                               ('inodePercent', 'inodes-critical', 'Inode del filesystem host quasi esauriti.', 95),
                                               ('memoryPercent', 'memory-critical', 'Memoria disponibile della VPS criticamente bassa.', 97)]:
            value = values.get(key)
            if isinstance(value, (int, float)) and threshold <= value <= 100:
                output.append(event('error' if value >= 99 else 'warning', 'host', 'VPS', message, code, observed))
        return output, []


def create_collector(**options):
    return ServerEventsCollector(**options)
