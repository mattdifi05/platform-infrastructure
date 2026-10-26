#!/usr/bin/env python3
"""Owner-operated runtime maintenance. No shell, SQL, arbitrary image or file API."""
import concurrent.futures
import copy
import datetime
import fcntl
import hashlib
import hmac
import http.client
import http.server
import importlib.util
import json
import os
import pathlib
import re
import shutil
import socket
import socketserver
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time
import traceback
import uuid

from platform_runtime_releases import resolve_release, compare_versions
try:
    from platform_server_events import create_collector as create_server_events_collector
except ImportError:
    create_server_events_collector = None
try:
    import platform_host_updates as host_updates
except ImportError:
    host_updates = None

ROOT = pathlib.Path(os.environ.get('PLATFORM_UPDATES_STATE', '/var/lib/platform-updates'))
CONFIG = pathlib.Path(os.environ.get('PLATFORM_UPDATES_CONFIG', '/etc/platform-infrastructure/updates/config.json'))
SOCKET = os.environ.get('PLATFORM_UPDATES_SOCKET', '/run/platform-updates/updates.sock')
KEY = pathlib.Path(os.environ.get('PLATFORM_UPDATES_KEY', '/etc/platform-infrastructure/updates/bridge-key'))
EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=1)
GATE = threading.Lock()
HOST_JOB_GUARD = threading.Lock()
HOST_JOB_THREADS = set()
SERVER_EVENTS_GUARD = threading.Lock()
SERVER_EVENTS_COLLECTOR = None
DIGEST = re.compile(r'^sha256:[a-f0-9]{64}$')
IDENTIFIER = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$')


class Rejected(Exception):
    def __init__(self, code, message, status=409):
        super().__init__(message)
        self.code, self.status = code, status


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def protected(filename):
    p = pathlib.Path(filename)
    if not p.is_absolute() or p.resolve() != p:
        raise Rejected('unsupported', 'Percorso di manutenzione non protetto.', 503)
    for ancestor in [p, *p.parents]:
        s = ancestor.lstat()
        if s.st_uid != 0 or s.st_mode & 0o022 or stat.S_ISLNK(s.st_mode):
            raise Rejected('unsupported', 'Configurazione di manutenzione non protetta.', 503)
    return p


def atomic(path, data, mode=0o600):
    path = pathlib.Path(path)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + '.')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            os.fchmod(f.fileno(), mode)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def db():
    c = sqlite3.connect(ROOT / 'operations.sqlite', timeout=15)
    c.row_factory = sqlite3.Row
    return c


def initialize():
    os.umask(0o077)
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS nonces (id TEXT PRIMARY KEY, at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, value TEXT NOT NULL, PRIMARY KEY(kind,id));
        CREATE TABLE IF NOT EXISTS idempotency (id TEXT PRIMARY KEY, plan TEXT NOT NULL, job TEXT NOT NULL);
        ''')
    for item in records('operation'):
        if item['status'] in ['queued', 'running']:
            if item.get('kind') == 'host-reboot' and load('host-reboot', item['id']):
                continue  # Boot identity and service health decide completion below.
            if item.get('kind') in ['host-upgrade', 'host-check']:
                continue  # A root transient worker may survive this bridge process.
            host_upgrade = item.get('kind') == 'host-upgrade'
            item.update(status='interrupted', recoveryRequired=host_upgrade or (ROOT / item['id'] / 'rollback.json').exists(), stage='Aggiornamento OS interrotto: verificare lo stato APT; nessun rollback' if host_upgrade else 'Interrotta: verifica lo stato reale prima di riprovare', finishedAt=stamp())
            save('operation', item['id'], item)

    reconcile_host_jobs(force=True)


def save(kind, key, value):
    with db() as c:
        c.execute('INSERT OR REPLACE INTO records VALUES(?,?,?)', (kind, key, json.dumps(value)))


def load(kind, key, default=None):
    with db() as c:
        row = c.execute('SELECT value FROM records WHERE kind=? AND id=?', (kind, key)).fetchone()
    return json.loads(row['value']) if row else default


def records(kind):
    with db() as c:
        rows = c.execute('SELECT value FROM records WHERE kind=? ORDER BY rowid DESC LIMIT 100', (kind,)).fetchall()
    return [json.loads(x['value']) for x in rows]


def recovery_required():
    with db() as c:
        rows = c.execute("SELECT value FROM records WHERE kind='operation'").fetchall()
    return any(json.loads(x['value']).get('recoveryRequired') for x in rows)


def run(argv, timeout=60, include_stderr=False):
    result = subprocess.run(argv, capture_output=True, timeout=timeout)
    if result.returncode:
        logs = ROOT / 'logs'
        logs.mkdir(mode=0o700, exist_ok=True)
        with (logs / 'commands.log').open('ab') as logfile:
            logfile.write(encode({'at': stamp(), 'command': argv, 'code': result.returncode}) + b'\n' + result.stdout[-65536:] + result.stderr[-65536:] + b'\n')
        # stdout/stderr can contain environment, credentials, paths or application logs.
        raise Rejected('updates_unavailable', 'Comando di manutenzione non riuscito; dettagli nel registro locale protetto.', 503)
    return (result.stdout + (result.stderr if include_stderr else b'')).decode(errors='replace')


class DockerConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/var/run/docker.sock')


def docker(method, endpoint, body=None):
    conn = DockerConnection('localhost', timeout=90)
    try:
        raw = encode(body) if body is not None else None
        conn.request(method, '/v1.53' + endpoint, raw, {'Content-Type': 'application/json'})
        response = conn.getresponse()
        data = response.read(16 * 1024 * 1024)
        if response.status >= 400:
            logs = ROOT / 'logs'
            logs.mkdir(mode=0o700, exist_ok=True)
            with (logs / 'docker.log').open('ab') as logfile:
                logfile.write(encode({'at': stamp(), 'method': method, 'endpoint': endpoint, 'status': response.status}) + b'\n' + data[:65536] + b'\n')
            raise Rejected('updates_unavailable', 'Operazione Docker non riuscita.', 503)
        return json.loads(data) if data else None
    finally:
        conn.close()


def inspect(name):
    try:
        return docker('GET', '/containers/' + name + '/json')
    except Rejected:
        return None


def configuration():
    value = json.loads(protected(CONFIG).read_text())
    if value.get('schema') != 'platform-runtime-updates/v1' or not isinstance(value.get('components'), list):
        raise Rejected('unsupported', 'Catalogo di manutenzione non valido.', 503)
    ids = set()
    for row in value['components']:
        if not IDENTIFIER.fullmatch(row.get('id', '')) or row['id'] in ids:
            raise Rejected('unsupported', 'Identificativi di manutenzione non validi.', 503)
        ids.add(row['id'])
        if not isinstance(row.get('containers'), list) or any(not IDENTIFIER.fullmatch(x) for x in row['containers']):
            raise Rejected('unsupported', 'Inventario di manutenzione non valido.', 503)
        if row.get('strategy') not in ['image', 'php-build', 'node-layer', 'reviewed-build', 'observe']:
            raise Rejected('unsupported', 'Strategia di manutenzione non valida.', 503)
    return value


def component(component_id):
    row = next((x for x in configuration()['components'] if x['id'] == component_id), None)
    if not row:
        raise Rejected('invalid_component', 'Componente non presente.', 404)
    return row


def database_family(row):
    return row['category'] == 'Database' or row.get('repository') in {'library/postgres', 'library/mysql', 'library/mariadb', 'library/redis', 'library/mongo', 'library/cassandra', 'library/elasticsearch'}


def data_sensitive(row):
    return database_family(row) or row.get('requiresRecovery') is True


def observed_versions(row):
    rows = [r for r in (inspect(x) for x in row['containers']) if r is not None]
    versions = []
    for r in rows:
        env = dict(x.split('=', 1) for x in r['Config'].get('Env', []) if '=' in x)
        version = env.get(row.get('versionEnv', ''), '')
        if version and row.get('versionEnv') == 'MARIADB_VERSION':
            version = version.split(':')[-1].split('+')[0]
        if r['State']['Running'] and row.get('probe'):
            try:
                output = run(['docker', 'exec', r['Id'], *row['probe']], timeout=10, include_stderr=True)
                match = re.search(r'(?<!\d)(\d+\.\d+(?:\.\d+)?)(?!\d)', output)
                version = match.group(1) if match else ''
            except Rejected:
                version = ''
        if not version and row.get('versionLabel'):
            labels = docker('GET', '/images/' + r['Image'] + '/json')['Config'].get('Labels') or {}
            version = labels.get(row['versionLabel'], '')
        versions.append(version if re.fullmatch(r'(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))?', str(version)) else '')
    unique = sorted(set(v for v in versions if v), key=version_key)
    known = bool(rows) and len(rows) == len(row['containers']) and all(versions)
    return rows, unique, known


def version_key(value):
    return tuple(int(x) for x in value.split('.')[:3]) + (0,) * max(0, 3 - len(value.split('.')))


def observed(row):
    rows, versions, known = observed_versions(row)
    return rows, versions[-1] if known else None


def common_release(row, cached, version, alignment):
    # Legacy caches may still contain an intermediate candidate: never surface it.
    latest = cached.get('latestStable')
    release = None
    if latest and version and row['strategy'] != 'observe':
        comparison = compare_versions(latest['version'], version)
        db_major_change = database_family(row) and version_key(latest['version'])[0] != version_key(version)[0]
        if not db_major_change and (comparison > 0 or comparison == 0 and alignment):
            release = latest
    return release, latest


def fingerprint(rows):
    return digest([{'id': r['Id'], 'image': r['Image'], 'running': r['State']['Running'], 'config': r['Config'], 'host': r['HostConfig'], 'mounts': r['Mounts'], 'networks': {name: {'IPAMConfig': net.get('IPAMConfig'), 'Aliases': net.get('Aliases')} for name, net in r['NetworkSettings']['Networks'].items()}} for r in sorted(rows, key=lambda r: r['Name'])])


def catalog():
    output = []
    checked = load('cache', 'releases', {})
    for row in configuration()['components']:
        actual, versions, known = observed_versions(row)
        version = versions[-1] if known else None
        alignment = known and len(versions) > 1
        cached = checked.get('components', {}).get(row['id'], {})
        release, latest = common_release(row, cached, version, alignment)
        eligible = bool(version and release and row['strategy'] != 'observe')
        if release and version:
            comparison = compare_versions(release['version'], version)
            eligible = eligible and (comparison > 0 or comparison == 0 and alignment)
        reason = row.get('blockedReason') or cached.get('reason')
        mixed_db_major = database_family(row) and len({version_key(v)[0] for v in versions}) > 1
        db_major_change = database_family(row) and version and latest and version_key(latest['version'])[0] != version_key(version)[0]
        if mixed_db_major or db_major_change:
            eligible, reason = False, 'Serve una migrazione dedicata per aggiornare la serie principale del database.'
        elif data_sensitive(row) and row.get('recoveryPolicy') != 'offline-snapshot-v1':
            eligible, reason = False, 'Serve un percorso verificato di recupero dei dati prima di aggiornare il database.'
        status = 'update-available' if eligible else 'current' if version and latest and compare_versions(version, latest['version']) >= 0 and not alignment else 'unsupported' if row['strategy'] == 'observe' or mixed_db_major or db_major_change else 'alignment-required' if alignment else 'unavailable'
        if not actual:
            status, reason = 'not-installed', 'Componente non presente sulla VPS.'
        elif not known:
            reason = 'Versione non verificabile per tutte le istanze della famiglia.'
        elif status == 'current':
            reason = None
        elif mixed_db_major or db_major_change:
            pass
        elif eligible:
            reason = None
        elif row['strategy'] == 'observe':
            reason = row.get('blockedReason') or 'Componente dedicato: serve manutenzione assistita.'
        elif latest and release and latest['version'] != release['version']:
            reason = 'Una serie diversa richiede un percorso di compatibilità separato.'
        elif latest and version and not release and compare_versions(latest['version'], version) > 0:
            status, reason = 'unsupported', 'La nuova serie richiede una verifica di compatibilità dedicata.'
        elif alignment and not eligible:
            reason = reason or 'Nessuna versione stabile comune verificata uguale o successiva a tutte le istanze.'
        if isinstance(reason, str) and reason.startswith('unavailable:'):
            reason = 'Fonte ufficiale non disponibile o release non pubblicata per questo componente.'
        images = {r['Image'] for r in actual}
        output.append({'id': row['id'], 'label': row['label'], 'category': row['category'], 'installed': bool(actual), 'current': {'version': versions[0] if known and len(versions) == 1 else None, 'versions': versions if known else [], 'imageDigest': next(iter(images)) if len(images) == 1 else None, 'verifiedAt': stamp()}, 'needsAlignment': alignment, 'latestStable': latest, 'candidateRelease': release, 'services': [r['Name'].lstrip('/') for r in actual], 'status': status, 'canUpdate': eligible, 'blockedReason': reason, '_fingerprint': fingerprint(actual)})
    revision = digest({'components': [{k: v for k, v in x.items() if k != 'current'} | {'version': x['current']['version'], 'versions': x['current']['versions'], 'image': x['current']['imageDigest']} for x in output], 'checkedAt': checked.get('checkedAt')})
    for item in output:
        item.pop('_fingerprint')
    operations = [item for item in records('operation') if not item.get('kind', '').startswith('host-')]
    return {'schema': 'runtime-updates/v1', 'available': True, 'canCheck': True, 'canApply': not recovery_required(), 'busy': any(item['status'] in ['queued', 'running'] for item in records('operation')), 'revision': revision, 'checkedAt': checked.get('checkedAt'), 'components': output, 'operations': operations[:12]}


def operation_update(job_id, **changes):
    item = load('operation', job_id)
    item.update(changes)
    save('operation', job_id, item)


def check_job(job_id):
    config = configuration()['components']
    operation_update(job_id, status='running', stage='Verifica delle fonti ufficiali', totalSteps=len(config), completedSteps=0)
    cache = {'checkedAt': stamp(), 'components': {}}
    def check(row):
        actual, versions, known = observed_versions(row)
        version = versions[-1] if known else None
        if not actual or not version or not row.get('repository'):
            return row['id'], {'reason': row.get('blockedReason', 'Versione o fonte stabile non disponibile.')}
        return row['id'], resolve_release({**row, 'includeCurrent': len(versions) > 1}, version)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            for i, result in enumerate(pool.map(check, config)):
                name, value = result
                cache['components'][name] = value
                operation_update(job_id, stage='Verificato ' + name, completedSteps=i + 1)
        save('cache', 'releases', cache)
        operation_update(job_id, status='succeeded', stage='Verifica completata', finishedAt=stamp())
    except Exception:
        operation_update(job_id, status='failed', stage='Verifica non riuscita', error='Fonti ufficiali temporaneamente non disponibili.', finishedAt=stamp())


def traefik_routing_configuration(old, row, check_http=True):
    """Require durable file-provider inputs and an admitted, exact router probe."""
    def reject():
        raise Rejected('unsupported', 'Traefik richiede configurazioni persistenti e una verifica HTTP delle rotte: manutenzione assistita.', 422)
    if not old['State']['Running']:
        reject()  # Never start a stopped ingress merely to discover its writable layer.
    def covered(path):
        return any(m.get('Type') in ['bind', 'volume'] and m.get('RW') is False and
                   (path == m['Destination'].rstrip('/') or path.startswith(m['Destination'].rstrip('/') + '/')) for m in old['Mounts'])
    def content(path):
        if not isinstance(path, str) or not path.startswith('/') or os.path.normpath(path) != path or not covered(path):
            reject()
        value = run(['docker', 'exec', old['Id'], 'cat', path], timeout=10)
        if len(value.encode()) > 1024 * 1024:
            reject()
        return value
    flags = {}
    args = (old['Config'].get('Entrypoint') or []) + (old['Config'].get('Cmd') or [])
    for i, arg in enumerate(args):
        if arg.startswith('--'):
            key, separator, value = arg[2:].partition('=')
            if not separator and i + 1 < len(args) and not args[i + 1].startswith('--'):
                value = args[i + 1]
            flags[key.lower()] = value
    env = dict(x.split('=', 1) for x in old['Config'].get('Env', []) if '=' in x)
    values, files = {}, {}
    static = flags.get('configfile') or env.get('TRAEFIK_CONFIGFILE')
    if static:
        document = content(static)
        files[static] = hashlib.sha256(document.encode()).hexdigest()
        # Read only simple canonical YAML/TOML scalar paths. Unsupported syntax
        # is assisted rather than guessed; no YAML constructors or code execute.
        stack, section = [], ''
        for line in document.splitlines():
            section_match = re.fullmatch(r'\s*\[([a-zA-Z.]+)\]\s*', line)
            if section_match:
                section = section_match.group(1).lower()
            toml = re.fullmatch(r'\s*(directory|filename)\s*=\s*["\']([^"\']+)["\']\s*(?:#.*)?', line)
            if toml and section == 'providers.file':
                values[toml.group(1)] = toml.group(2)
            yaml = re.fullmatch(r'( *)([A-Za-z][A-Za-z0-9_-]*):\s*(.*?)\s*', line)
            if yaml:
                depth, key, scalar = len(yaml.group(1)), yaml.group(2).lower(), yaml.group(3)
                while stack and stack[-1][0] >= depth:
                    stack.pop()
                chain = '.'.join([entry[1] for entry in stack] + [key])
                if chain in ['providers.file.directory', 'providers.file.filename']:
                    scalar = scalar.split(' #', 1)[0].strip().strip('"\'')
                    values[key] = scalar
                stack.append((depth, key))
    for key in ['directory', 'filename']:
        values[key] = flags.get('providers.file.' + key) or env.get('TRAEFIK_PROVIDERS_FILE_' + key.upper()) or values.get(key)
    dynamic = []
    if values.get('directory'):
        directory = values['directory']
        if not directory.startswith('/') or os.path.normpath(directory) != directory:
            reject()
        links = run(['docker', 'exec', old['Id'], 'find', directory, '-type', 'l'], timeout=10)
        if links.strip():
            reject()
        dynamic.extend(path for path in run(['docker', 'exec', old['Id'], 'find', directory, '-type', 'f'], timeout=10).splitlines() if path.endswith(('.yml', '.yaml', '.toml')))
    if values.get('filename'):
        dynamic.append(values['filename'])
    if not dynamic or len(dynamic) > 100:
        reject()
    hosts = set()
    for path in sorted(set(dynamic)):
        document = content(path)
        files[path] = hashlib.sha256(document.encode()).hexdigest()
        hosts.update(match[1].lower() for match in re.findall(r"Host\(\s*([`\"'])(([a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+)\1\s*\)", document))
    probes = row.get('routeProbes')
    if not isinstance(probes, list) or not 1 <= len(probes) <= 10:
        reject()
    for probe in probes:
        if not isinstance(probe, dict) or set(probe) != {'host', 'port', 'path', 'expectedStatuses'}:
            reject()
        host, port, path, statuses = (probe[key] for key in ['host', 'port', 'path', 'expectedStatuses'])
        if not isinstance(host, str) or host.lower() not in hosts or not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}', host) or type(port) is not int or not 1 <= port <= 65535 or not isinstance(path, str) or not re.fullmatch(r'/[^\s?#]*', path) or not isinstance(statuses, list) or not statuses or any(type(status) is not int or status not in [200, 401] for status in statuses):
            reject()
    if check_http:
        verify_routing_http(probes)
    return {'files': files, 'probes': probes}


def verify_routing_http(probes, attempts=1):
    for attempt in range(attempts):
        valid = True
        for probe in probes:
            connection = http.client.HTTPConnection('127.0.0.1', probe['port'], timeout=3)
            try:
                connection.request('GET', probe['path'], headers={'Host': probe['host'], 'Connection': 'close'})
                if connection.getresponse().status not in probe['expectedStatuses']:
                    valid = False
            except (OSError, http.client.HTTPException):
                valid = False
            finally:
                connection.close()
        if valid:
            return
        if attempt + 1 < attempts:
            time.sleep(1)
    raise Rejected('updates_unavailable', 'La verifica HTTP della rotta prevista non è riuscita.', 503)


def routing_checks(row, actual, expected=None):
    if row.get('repository') != 'library/traefik':
        return {}
    checks = {old['Id']: traefik_routing_configuration(old, row) for old in actual}
    if expected is not None and checks != expected:
        raise Rejected('stale_plan', 'La configurazione delle rotte è cambiata dopo il piano.')
    for old in actual:
        old['requiredRoutingConfig'] = checks[old['Id']]
    return checks


def planned_family(component_id, revision, item):
    if not item['canUpdate']:
        raise Rejected('unsupported', item['blockedReason'] or 'Nessun aggiornamento compatibile disponibile.', 422)
    row = component(component_id)
    actual, _ = observed(row)
    target = item['candidateRelease']
    config_checks = routing_checks(row, actual)
    if data_sensitive(row):
        for old in actual:
            recovery_sources(old)  # Reject unsupported persistent mounts before downtime.
    value = {'planId': uuid.uuid4().hex, 'revision': revision, 'expiresAt': datetime.datetime.fromtimestamp(time.time() + 900, datetime.timezone.utc).isoformat(), 'componentId': component_id, 'targetVersion': target['version'], 'targetDigest': target['imageDigest'], 'affectedServices': item['services'], 'steps': ['Verifica dello stato attuale', 'Download e preparazione del runtime', 'Aggiornamento dei servizi selezionati', 'Verifica di avvio e funzionamento', 'Registrazione del risultato'], 'risks': ['I servizi selezionati saranno brevemente indisponibili. Dati e configurazioni vengono mantenuti.'] + (['Il servizio sarà fermato per creare una copia consistente dei suoi dati sul server. Le applicazioni collegate possono essere temporaneamente indisponibili.', 'Viene mantenuta una copia protetta per il recupero; dopo un avvio della nuova versione non viene eseguito alcun downgrade automatico dei dati.', 'Aggiornamento compatibile della stessa serie. Per cambiare serie serve una migrazione dedicata.'] if data_sensitive(row) else []), 'confirmationRequired': 'UPDATE'}
    return {'public': value, 'component': row, 'target': target, 'fingerprint': fingerprint(actual), 'routingChecks': config_checks}



def plan(component_id, revision):
    current = catalog()
    if current['revision'] != revision:
        raise Rejected('stale_revision', 'Inventario cambiato. Verifica nuovamente il piano.')
    if component_id != 'all':
        item = next((x for x in current['components'] if x['id'] == component_id), None)
        if item is None:
            raise Rejected('invalid_component', 'Componente non presente.', 404)
        stored = planned_family(component_id, revision, item)
    else:
        selected = sorted((x for x in current['components'] if x['canUpdate']), key=lambda x: (x['category'] == 'Database', x['id']))
        if not selected:
            raise Rejected('unsupported', 'Nessun aggiornamento applicabile disponibile.', 422)
        families = [planned_family(item['id'], revision, item) for item in selected]
        components = [{'id': x['component']['id'], 'label': x['component']['label'], 'targetVersion': x['public']['targetVersion'], 'targetDigest': x['public']['targetDigest'], 'affectedServices': x['public']['affectedServices']} for x in families]
        value = {'planId': uuid.uuid4().hex, 'revision': revision, 'expiresAt': min(x['public']['expiresAt'] for x in families),
                 'componentId': 'all', 'kind': 'batch', 'components': components,
                 'targetVersion': 'Aggiornamenti compatibili', 'targetDigest': 'sha256:' + digest(components),
                 'affectedServices': [service for x in components for service in x['affectedServices']],
                 'steps': ['Preparazione e verifica isolata di tutte le immagini', 'Aggiornamento e verifica servizio per servizio', 'Registrazione del risultato di ogni famiglia'],
                 'risks': ['I servizi saranno brevemente indisponibili durante il proprio aggiornamento.', 'Al primo errore il gruppo si ferma. Le famiglie già completate restano aggiornate.', 'Per database e servizi con dati persistenti resta obbligatorio il recupero verificato; nessun downgrade automatico dopo un nuovo avvio.'],
                 'confirmationRequired': 'UPDATE'}
        stored = {'public': value, 'families': families}
    save('plan', stored['public']['planId'], stored)
    return stored['public']


def image_candidate(row, target, directory, source_image=None):
    ref = target['imageReference'] + '@' + target['imageDigest']
    run(['docker', 'pull', ref], timeout=600)
    if row['strategy'] == 'image':
        return docker('GET', '/images/' + ref.replace('/', '%2F') + '/json')['Id']
    if row['strategy'] == 'node-layer':
        if source_image is None:
            actual, _ = observed(row)
            images = {x['Image'] for x in actual}
            if len(images) != 1:
                raise Rejected('unsupported', 'Immagine applicativa non univoca per la preparazione.', 422)
            source_image = next(iter(images))
        # Keep each exact deployed application and its native dependencies.
        base_tag = 'platform/runtime-base:' + directory.name
        run(['docker', 'image', 'tag', source_image, base_tag])
        content = 'FROM ' + ref + ' AS runtime\nRUN mkdir /platform-runtime-libs && if [ -f /usr/lib/libatomic.so.1 ]; then cp -L /usr/lib/libatomic.so.1 /platform-runtime-libs/; fi\nFROM ' + base_tag + '\nCOPY --from=runtime /usr/local/bin/node /usr/local/bin/node\nCOPY --from=runtime /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm\nCOPY --from=runtime /platform-runtime-libs/ /usr/lib/\nENV NODE_VERSION=' + target['version'] + '\n'
        (directory / 'Dockerfile').write_text(content)
        command = ['docker', 'build', '--tag', 'platform/runtime-update:' + directory.name, str(directory)]
    else:
        context = protected(row['buildContext'])
        source = protected(row['dockerfile'])
        content = source.read_text()
        if row['strategy'] == 'php-build':
            command = ['docker', 'build', '--file', str(source), '--build-arg', 'PHP_IMAGE=' + ref, '--tag', 'platform/runtime-update:' + directory.name, str(context)]
        else:
            lines = content.splitlines()
            if not lines or not lines[0].startswith('FROM '):
                raise Rejected('unsupported', 'Builder del componente non riconosciuto.', 422)
            suffix = ' AS runtime' if ' AS runtime' in lines[0] else ''
            lines[0] = 'FROM ' + ref + suffix
            (directory / 'Dockerfile').write_text('\n'.join(lines) + '\n')
            command = ['docker', 'build', '--file', str(directory / 'Dockerfile'), '--tag', 'platform/runtime-update:' + directory.name, str(context)]
    run(command, timeout=1800)
    return run(['docker', 'image', 'inspect', '--format', '{{.Id}}', 'platform/runtime-update:' + directory.name]).strip()


def node_preflight(old, image, version):
    # Run only Node and direct .node loads, never application entrypoints or npm hooks.
    # No service environment, real mounts, Docker socket or external network is passed.
    workdir = old['Config'].get('WorkingDir') or '/'
    module_root = os.path.normpath(workdir + '/node_modules')
    image_config = docker('GET', '/images/' + image + '/json')['Config']
    for mount in image_config.get('Volumes') or {}:
        path = os.path.normpath(mount)
        manifest = os.path.normpath(workdir + '/package.json')
        if module_root == path or module_root.startswith(path.rstrip('/') + '/') or path.startswith(module_root.rstrip('/') + '/') or manifest == path or manifest.startswith(path.rstrip('/') + '/'):
            raise Rejected('unsupported', 'Un volume nasconde le dipendenze native: serve una verifica assistita.', 422)
    script = r"""
const fs = require('node:fs'), path = require('node:path');
if (process.versions.node !== process.argv[1]) process.exit(2);
const manifest = path.resolve(process.cwd(), 'package.json');
if (fs.existsSync(manifest)) {
  if (fs.statSync(manifest).size > 1024 * 1024) throw new Error('Package manifest limit');
  const pkg = JSON.parse(fs.readFileSync(manifest, 'utf8'));
  const engine = pkg.engines && pkg.engines.node;
  if (engine !== undefined) {
    if (typeof engine !== 'string' || !engine || engine.length > 512) throw new Error('Invalid Node engine declaration');
    const semver = require('/usr/local/lib/node_modules/npm/node_modules/semver');
    if (!semver.satisfies(process.versions.node, engine)) throw new Error('Declared Node engine is incompatible');
  }
}
const start = path.resolve(process.cwd(), 'node_modules');
let count = 0, entries = 0;
if (fs.existsSync(start)) {
  const root = fs.realpathSync(start), pending = [root], seen = new Set();
  while (pending.length) {
    const directory = pending.pop();
    if (seen.has(directory)) continue;
    seen.add(directory);
    for (const name of fs.readdirSync(directory)) {
      if (++entries > 100000) throw new Error('Dependency scan limit');
      const item = fs.realpathSync(path.join(directory, name));
      if (item !== root && !item.startsWith(root + path.sep)) throw new Error('Dependency outside module tree');
      const stat = fs.statSync(item);
      if (stat.isDirectory()) pending.push(item);
      else if (stat.isFile() && item.endsWith('.node')) {
        if (++count > 2048) throw new Error('Native dependency scan limit');
        require(item);
      }
    }
  }
}
console.log(JSON.stringify({version: process.versions.node, nativeModules: count}));
"""
    output = run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                  '--security-opt', 'no-new-privileges', '--pids-limit', '64', '--memory', '512m', '--cpus', '1',
                  '--env', 'NODE_OPTIONS=', '--env', 'NODE_PATH=', '--env', 'LD_PRELOAD=',
                  '--user', old['Config'].get('User') or '0:0', '--workdir', workdir,
                  '--entrypoint', 'node', image, '-e', script, version], timeout=60)
    try:
        result = json.loads(output)
        valid = result['version'] == version and isinstance(result['nativeModules'], int) and result['nativeModules'] >= 0
    except (ValueError, KeyError, TypeError):
        valid = False
    if not valid:
        raise Rejected('unsupported', 'Verifica isolata del runtime o delle dipendenze native non riuscita.', 422)


def endpoints(row):
    return {name: {key: net[key] for key in ['IPAMConfig', 'Aliases', 'Links', 'DriverOpts'] if net.get(key) is not None} for name, net in row['NetworkSettings']['Networks'].items() if name not in ['none', 'host']}


def recovery_sources(old):
    sources = []
    for mount in old['Mounts']:
        if mount.get('RW') is not True or mount['Type'] == 'tmpfs':
            continue
        if mount['Type'] not in ['bind', 'volume'] or not mount.get('Source'):
            raise Rejected('unsupported', 'Volume persistente non supportato per il recupero.', 422)
        source = pathlib.Path(mount['Source'])
        if source.resolve() != source or not source.is_dir() or not any(source.is_relative_to(pathlib.Path(base)) for base in ['/srv/platform-infrastructure', '/var/lib/docker/volumes']):
            raise Rejected('unsupported', 'Il database richiede un percorso di recupero dedicato.', 422)
        sources.append(source)
    if not sources:
        raise Rejected('unsupported', 'Dati persistenti del database non identificati.', 422)
    return sources


def snapshot_database(old, directory):
    sources = recovery_sources(old)
    sizes = [int(run(['du', '-sb', '--', str(p)]).split()[0]) for p in sources]
    total = sum(sizes)
    quota = configuration().get('recoveryLimitBytes', 20 * 1024 ** 3)
    used = int(run(['du', '-sb', '--', str(ROOT)]).split()[0])
    if total + used > quota or shutil.disk_usage(ROOT).free < total + 2 * 1024 ** 3:
        raise Rejected('unsupported', 'Spazio insufficiente per un punto di recupero consistente.', 422)
    recovery = directory / ('recovery-' + old['Id'][:12])
    recovery.mkdir(mode=0o700)
    manifest = []
    for i, source in enumerate(sources):
        target = recovery / str(i)
        run(['cp', '-a', '--reflink=auto', '--', str(source), str(target)], timeout=1800)
        manifest.append({'source': str(source), 'snapshot': str(target), 'bytes': sizes[i]})
    run(['sync', '-f', str(recovery)])
    atomic(recovery / 'manifest.json', encode({'createdAt': stamp(), 'containerId': old['Id'], 'mounts': manifest}))


def recreate(old, image, backups, journal=lambda: None, before_start=None, on_stage=lambda stage: None):
    name = old['Name'].lstrip('/')
    backup = name + '-update-' + uuid.uuid4().hex[:10]
    saved = {'old': old, 'backupName': backup, 'newId': None, 'phase': 'prepared'}
    backups.append(saved)
    journal()  # Durable before the first change, including restart policy.
    docker('POST', '/containers/' + old['Id'] + '/update', {'RestartPolicy': {'Name': 'no'}})
    if old['State']['Running']:
        on_stage('Arresto del servizio')
        docker('POST', '/containers/' + old['Id'] + '/stop?t=30')
    if before_start:
        on_stage('Creazione del punto di recupero')
        before_start(old)
    docker('POST', '/containers/' + old['Id'] + '/rename?name=' + backup)
    saved['phase'] = 'renamed'
    journal()
    for network in endpoints(old):
        docker('POST', '/networks/' + network + '/disconnect', {'Container': old['Id'], 'Force': True})
    config = copy.deepcopy(old['Config'])
    config['Image'] = image
    # Old application's explicit env is retained, except observed runtime metadata.
    image_config = docker('GET', '/images/' + image + '/json')['Config']
    fresh_env = dict(x.split('=', 1) for x in image_config.get('Env', []) if '=' in x)
    runtime_keys = {'PHP_VERSION', 'PHP_URL', 'PHP_ASC_URL', 'PHP_SHA256', 'NODE_VERSION', 'PG_VERSION', 'PG_MAJOR', 'MARIADB_VERSION', 'REDIS_VERSION'}
    config['Env'] = [x.split('=', 1)[0] + '=' + fresh_env[x.split('=', 1)[0]] if x.split('=', 1)[0] in runtime_keys and x.split('=', 1)[0] in fresh_env else x for x in config.get('Env', [])]
    config['HostConfig'] = copy.deepcopy(old['HostConfig'])
    config['NetworkingConfig'] = {'EndpointsConfig': endpoints(old)}
    on_stage('Creazione del servizio aggiornato')
    result = docker('POST', '/containers/create?name=' + name, config)
    saved['newId'] = result['Id']
    journal()
    if old['State']['Running']:
        saved['newStarted'] = True
        journal()  # Database start may write data even if its health check fails.
        on_stage('Avvio del servizio aggiornato')
        docker('POST', '/containers/' + saved['newId'] + '/start')
    return saved['newId']


def verify(old, new_id, row, version):
    deadline = time.time() + 120
    while time.time() < deadline:
        new = inspect(new_id)
        if not new:
            break
        if sorted(new['Mounts'], key=lambda x: x['Destination']) != sorted(old['Mounts'], key=lambda x: x['Destination']):
            raise Rejected('updates_unavailable', 'I mount del servizio non corrispondono.', 503)
        if not old['State']['Running']:
            return new
        state = new['State']
        health = state.get('Health', {}).get('Status')
        if health is None and state.get('StartedAt'):
            started = datetime.datetime.fromisoformat(state['StartedAt'].replace('Z', '+00:00')).timestamp()
            if time.time() - started < 3:
                time.sleep(1)
                continue
        if state['Running'] and health in [None, 'healthy']:
            if row.get('probe'):
                output = run(['docker', 'exec', new_id, *row['probe']], timeout=15, include_stderr=True)
                if not re.search(r'(?<![\d.])' + re.escape(version) + r'(?![\d.])', output):
                    raise Rejected('updates_unavailable', 'Il runtime avviato non corrisponde alla versione scelta.', 503)
            if row.get('repository') == 'library/traefik':
                routing = traefik_routing_configuration(new, row, check_http=False)
                if routing != old.get('requiredRoutingConfig'):
                    raise Rejected('updates_unavailable', 'La configurazione delle rotte non è stata conservata.', 503)
                verify_routing_http(routing['probes'], attempts=10)
            if row['strategy'] == 'php-build':
                run(['docker', 'exec', new_id, 'apache2ctl', 'configtest'])
                before = set(old.get('runtimeModules') or run(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'php', old['Image'], '-m']).splitlines())
                after = set(run(['docker', 'exec', new_id, 'php', '-m']).splitlines())
                if before - after:
                    raise Rejected('updates_unavailable', 'Il runtime non conserva tutte le estensioni PHP.', 503)
                code = run(['docker', 'exec', new_id, 'curl', '-sS', '--max-time', '15', '-o', '/dev/null', '-w', '%{http_code}', 'http://127.0.0.1/'])
                if code.startswith('5') or code == '000':
                    raise Rejected('updates_unavailable', 'Verifica HTTP del runtime non riuscita.', 503)
            if row.get('repository') == 'library/nginx':
                run(['docker', 'exec', new_id, 'nginx', '-t'])
            old_mounts = sorted(old['Mounts'], key=lambda x: x['Destination'])
            if sorted(new['Mounts'], key=lambda x: x['Destination']) != old_mounts:
                raise Rejected('updates_unavailable', 'I mount del servizio non corrispondono.', 503)
            return new
        if not state['Running'] and state.get('ExitCode'):
            break
        time.sleep(2)
    raise Rejected('updates_unavailable', 'Il servizio non ha superato la verifica di avvio.', 503)


def refresh_admission(old_rows, new_rows):
    path = pathlib.Path('/etc/platform-vps-backup/profile.json')
    if not path.exists():
        return
    previous, signature = path.read_bytes(), path.with_name('profile.sig').read_bytes()
    p = json.loads(previous)
    changes = {r['Name']: r for r in new_rows}
    old = {r['Name']: r for r in old_rows}
    pins = {x['name']: x for x in p['pins']}
    enrolled = set(changes) & set(pins)
    if not enrolled:
        return
    def pin(r):
        return {'name': r['Name'], 'id': r['Id'], 'image': r['Image'], 'mounts': r['Mounts']}
    for name in enrolled:
        if pins[name] != pin(old[name]):
            raise Rejected('stale_plan', 'Il profilo del servizio è cambiato. Richiesta manutenzione assistita.')
    public = path.parent / 'authority-public.pem'
    authority = path.parent / 'authority-private.pem'
    run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(public), '-rawin', '-in', str(path), '-sigfile', str(path.with_name('profile.sig'))])
    predecessor = hashlib.sha256(previous).hexdigest()
    history = path.parent / 'admission-history' / predecessor
    history.mkdir(mode=0o700, exist_ok=True)
    for filename, raw in [('profile.json', previous), ('profile.sig', signature)]:
        dest = history / filename
        if dest.exists() and dest.read_bytes() != raw:
            raise Rejected('stale_plan', 'Storico di autorizzazione non corrispondente.')
        atomic(dest, raw)
    p['pins'] = [pin(changes[x['name']]) if x['name'] in enrolled else x for x in p['pins']]
    def update_receipts(value):
        if isinstance(value, dict):
            if value.get('name') in enrolled and {'id', 'image', 'mounts'} <= value.keys():
                r = changes[value['name']]
                value.update(pin(r))
                if 'labels' in value:
                    value['labels'] = r['Config'].get('Labels') or {}
            else:
                for child in value.values():
                    update_receipts(child)
        elif isinstance(value, list):
            for child in value:
                update_receipts(child)
    for key in ['extraPrivateApplications', 'scriptaRuntime', 'scriptaManagement', 'stexorCalendarRuntime', 'stexorCalendarManagement']:
        update_receipts(p.get(key))
    p.update(generation=p['generation'] + 1, previousAdmissionSha256=predecessor, enrolledAt=stamp())
    with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
        proposed, sig = pathlib.Path(tmp) / 'profile.json', pathlib.Path(tmp) / 'profile.sig'
        proposed.write_bytes(json.dumps(p, sort_keys=True, indent=2).encode() + b'\n')
        run(['openssl', 'pkeyutl', '-sign', '-inkey', str(authority), '-rawin', '-in', str(proposed), '-out', str(sig)])
        run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(public), '-rawin', '-in', str(proposed), '-sigfile', str(sig)])
        if path.read_bytes() != previous:
            raise Rejected('stale_plan', 'Autorizzazione modificata durante la manutenzione.')
        try:
            atomic(path.with_name('profile.sig'), sig.read_bytes())
            atomic(path, proposed.read_bytes())
        except Exception:
            atomic(path, previous)
            atomic(path.with_name('profile.sig'), signature)
            raise


def apply_job(job_id, stored):
    directory = ROOT / job_id
    directory.mkdir(mode=0o700)
    families = stored.get('families') or [stored]
    batch = 'families' in stored
    services = [{'componentId': family['component']['id'], 'service': service, 'status': 'queued', 'stage': 'In attesa'} for family in families for service in family['public']['affectedServices']]
    results = [{'componentId': family['component']['id'], 'status': 'queued'} for family in families]
    current_component = current_service = None
    completed_families = 0
    backups, row, committed = [], None, False
    total = len(services)
    def report(stage, **changes):
        completed = sum(x['status'] in ['verified', 'succeeded'] for x in services)
        operation_update(job_id, stage=stage[:80], currentComponent=current_component, currentService=current_service,
                         completedServices=completed, totalServices=total, serviceResults=services, componentResults=results,
                         **({'completedSteps': completed, 'totalSteps': total} if batch else {}), **changes)
    def service_result(service, **changes):
        next(x for x in services if x['componentId'] == current_component and x['service'] == service).update(changes)
    report('Verifica dello stato attuale', status='running', **({} if batch else {'completedSteps': 0}))
    lock_path = pathlib.Path('/var/lib/platform-vps-backup/operation.lock')
    lock_path.parent.mkdir(mode=0o700, exist_ok=True)
    with lock_path.open('a') as lock:
        try:
            wait_operation_lock(lock, job_id, stored['public'].get('expiresAt'))
            operation_update(job_id, status='running', stage='Verifica dello stato attuale')
            prepared = []
            # Bind every selected family before preparing any image.
            for family in families:
                row, target = family['component'], family['target']
                current_component = row['id']
                actual, _ = observed(row)
                if fingerprint(actual) != family['fingerprint']:
                    raise Rejected('stale_plan', 'I servizi sono cambiati dopo la preparazione del piano.')
                routing_checks(row, actual, family.get('routingChecks'))
                work = directory / row['id'] if batch else directory
                if batch:
                    work.mkdir(mode=0o700)
                atomic(work / 'before.json', encode(actual))
                prepared.append({'stored': family, 'directory': work, 'actual': actual})
            # Prepare the entire batch before the first live service mutation.
            for family in prepared:
                item = family['stored']; row, target = item['component'], item['target']
                work, actual = family['directory'], family['actual']
                current_component, current_service = row['id'], None
                next(x for x in results if x['componentId'] == row['id'])['status'] = 'preparing'
                report('Download e preparazione: ' + row['label'], **({} if batch else {'completedSteps': 1}))
                images = {}
                if row['strategy'] == 'node-layer':
                    for source_image in sorted({old['Image'] for old in actual}):
                        candidate_directory = work / (job_id + '-' + source_image[-12:])
                        candidate_directory.mkdir(mode=0o700)
                        images[source_image] = image_candidate(row, target, candidate_directory, source_image)
                    for old in actual:
                        current_service = old['Name'].lstrip('/')
                        service_result(current_service, status='checking', stage='Verifica isolata del runtime e delle dipendenze')
                        report('Verifica isolata: ' + current_service)
                        node_preflight(old, images[old['Image']], target['version'])
                        service_result(current_service, status='queued', stage='Pronto per aggiornamento')
                else:
                    image = image_candidate(row, target, work)
                    images = {old['Image']: image for old in actual}
                family['images'] = images
            for family in prepared:
                fresh, _ = observed(family['stored']['component'])
                if fingerprint(fresh) != family['stored']['fingerprint']:
                    raise Rejected('stale_plan', 'I servizi sono cambiati durante la preparazione del runtime.')
                routing_checks(family['stored']['component'], fresh, family['stored'].get('routingChecks'))
            for family in prepared:
                item = family['stored']; row, target = item['component'], item['target']
                work, actual, images = family['directory'], family['actual'], family['images']
                current_component, current_service = row['id'], None
                backups, committed = [], False
                fresh, _ = observed(row)
                if fingerprint(fresh) != item['fingerprint']:
                    raise Rejected('stale_plan', 'I servizi sono cambiati prima dell’aggiornamento della famiglia.')
                routing_checks(row, actual, item.get('routingChecks'))
                next(x for x in results if x['componentId'] == row['id'])['status'] = 'updating'
                new_rows = []
                for old in actual:
                    current_service = old['Name'].lstrip('/')
                    service_result(current_service, status='updating', stage='Preparazione del servizio', startedAt=stamp())
                    report('Aggiornamento: ' + current_service, **({} if batch else {'completedSteps': 2}))
                    if row['strategy'] == 'php-build' and old['State']['Running']:
                        old['runtimeModules'] = run(['docker', 'exec', old['Id'], 'php', '-m']).splitlines()
                    def journal():
                        atomic(work / 'rollback.json', encode(backups))
                        if batch:
                            atomic(directory / 'rollback.json', encode({'componentId': row['id'], 'directory': row['id']}))
                    def phase(stage):
                        service_result(current_service, stage=stage)
                        report(stage + ': ' + current_service)
                    new_id = recreate(old, images[old['Image']], backups, journal=journal,
                                      before_start=(lambda previous: snapshot_database(previous, work)) if data_sensitive(row) else None,
                                      on_stage=phase)
                    service_result(current_service, status='verifying', stage='Verifica del servizio')
                    report('Verifica: ' + current_service)
                    new_rows.append(verify(old, new_id, row, target['version']))
                    service_result(current_service, status='verified', stage='Verificato; registrazione della famiglia in attesa')
                    report('Servizio verificato: ' + current_service)
                current_service = None
                report('Verifica finale e autorizzazioni: ' + row['label'], **({} if batch else {'completedSteps': 4}))
                refresh_admission(actual, new_rows)
                # Once signed, logging errors must never roll this family back.
                committed = True
                for old in actual:
                    service_result(old['Name'].lstrip('/'), status='succeeded', stage='Aggiornamento verificato', finishedAt=stamp())
                next(x for x in results if x['componentId'] == row['id'])['status'] = 'succeeded'
                completed_families += 1
                save('desired', row['id'], {'version': target['version'], 'image': next(iter(set(images.values()))) if len(set(images.values())) == 1 else None, 'images': images, 'source': target, 'containers': [x['Name'] for x in new_rows], 'updatedAt': stamp()})
                report('Famiglia aggiornata: ' + row['label'])
            current_component = current_service = None
            report('Aggiornamento verificato', status='succeeded', **({} if batch else {'completedSteps': 5}), finishedAt=stamp())
        except Exception as error:
            atomic(directory / 'error.log', traceback.format_exc().encode())
            failed_rollback = False
            if not committed:
                for backup in reversed(backups):
                    old = backup['old']
                    try:
                        if data_sensitive(row) and backup.get('newStarted'):
                            failed_rollback = True
                            continue  # Never downgrade an engine over data the new version may have written.
                        if backup['newId'] and inspect(backup['newId']):
                            docker('DELETE', '/containers/' + backup['newId'] + '?force=true')
                        if backup['phase'] == 'renamed':
                            docker('POST', '/containers/' + old['Id'] + '/rename?name=' + old['Name'].lstrip('/'))
                        for network, config in endpoints(old).items():
                            if network not in inspect(old['Id'])['NetworkSettings']['Networks']:
                                docker('POST', '/networks/' + network + '/connect', {'Container': old['Id'], 'EndpointConfig': config})
                        docker('POST', '/containers/' + old['Id'] + '/update', {'RestartPolicy': old['HostConfig']['RestartPolicy']})
                        if old['State']['Running']:
                            docker('POST', '/containers/' + old['Id'] + '/start')
                    except Exception:
                        failed_rollback = True
            for service in services:
                if service['status'] == 'succeeded':
                    continue
                changed = any(x['old']['Name'].lstrip('/') == service['service'] for x in backups) if service['componentId'] == current_component else False
                service.update(status=('failed' if failed_rollback else 'rolled-back') if changed else 'skipped', stage='Intervento assistito richiesto' if failed_rollback and changed else 'Runtime precedente mantenuto' if changed else 'Non aggiornato', finishedAt=stamp())
            for result in results:
                if result['status'] != 'succeeded':
                    result['status'] = 'failed' if result['componentId'] == current_component else 'skipped'
            success = committed and completed_families == len(families)
            busy = isinstance(error, Rejected) and error.code == 'operation_conflict'
            expired = isinstance(error, Rejected) and error.code == 'plan_expired'
            report('Host occupato: nessun servizio modificato' if busy else 'Piano scaduto: nessun servizio modificato' if expired else 'Runtime aggiornato; registro locale da verificare' if success else 'Intervento assistito richiesto' if failed_rollback else 'Aggiornamento interrotto; consulta il risultato dei servizi',
                   status='succeeded' if success else 'rolled-back' if backups and not failed_rollback and not completed_families else 'failed',
                   recoveryRequired=failed_rollback, **({} if batch else {'completedSteps': 5} if success else {}),
                   **({} if success else {'error': 'Host occupato da altra manutenzione. Riprova più tardi.' if busy else 'Verifica non riuscita. Consulta il registro protetto della manutenzione.'}), finishedAt=stamp())
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def submit(kind, stored=None, idempotency_key=None):
    job_id = uuid.uuid4().hex
    job = {'id': job_id, 'kind': kind, 'status': 'queued', 'stage': 'In preparazione', 'completedSteps': 0, 'totalSteps': (len(stored['public']['affectedServices']) if 'families' in stored else 5) if kind == 'apply' else 1, 'startedAt': stamp()}
    if kind == 'apply':
        families = stored.get('families') or [stored]
        services = [{'componentId': family['component']['id'], 'service': service, 'status': 'queued', 'stage': 'In attesa'} for family in families for service in family['public']['affectedServices']]
        job.update(currentComponent=None, currentService=None, completedServices=0, totalServices=len(services), serviceResults=services, componentResults=[{'componentId': family['component']['id'], 'status': 'queued'} for family in families])
    with db() as c:
        c.execute('INSERT INTO records VALUES(?,?,?)', ('operation', job_id, json.dumps(job)))
        if idempotency_key:
            c.execute('INSERT INTO idempotency VALUES(?,?,?)', (idempotency_key, stored['public']['planId'], job_id))
    EXECUTOR.submit(apply_job if kind == 'apply' else check_job, job_id, *([stored] if stored is not None else []))
    return {'operationId': job_id, 'status': 'queued'}


def host_os_release():
    fields = {}
    path = pathlib.Path('/etc/os-release')
    if path.is_file():
        for line in path.read_text()[:16384].splitlines():
            key, separator, value = line.partition('=')
            if separator:
                fields[key] = value.strip('"\'')
    return {'id': fields.get('ID', 'linux'), 'name': fields.get('NAME', 'Linux'), 'version': fields.get('VERSION_ID', ''), 'kernel': os.uname().release}


def host_catalog():
    operations = [item for item in records('operation') if item.get('kind', '').startswith('host-')]
    unavailable = {'schema': 'host-updates/v1', 'available': False, 'revision': None, 'os': host_os_release(), 'checkedAt': None,
                   'updateCount': 0, 'keptBackCount': 0, 'rebootRequired': False, 'canCheck': False, 'canApply': False, 'canReboot': False, 'operations': operations[:12]}
    if host_updates is None:
        return unavailable
    try:
        inventory = host_updates.inventory()
        cached = load('cache', 'host-releases')
        if cached and cached.get('bootId') != inventory['bootId']:
            cached = None
        fresh = bool(cached and 0 <= time.time() - cached['checkedAt'] <= 300)
        busy = any(item['status'] in ['queued', 'running'] for item in records('operation'))
        revision = digest({'bootId': inventory['bootId'], 'rebootRequired': inventory['rebootRequired'],
                           'checkedAt': cached.get('checkedAt') if cached else None,
                           'installedFingerprint': cached.get('installedFingerprint') if cached else None,
                           'candidateFingerprint': cached.get('candidateFingerprint') if cached else None})
        return {**unavailable, 'available': True, 'revision': revision,
                'checkedAt': datetime.datetime.fromtimestamp(cached['checkedAt'], datetime.timezone.utc).isoformat() if cached else None,
                'updateCount': len(cached['packages']) if cached else 0, 'keptBackCount': len(cached['keptBack']) if cached else 0,
                'rebootRequired': inventory['rebootRequired'], 'canCheck': not busy,
                'canApply': fresh and bool(cached['packages']) and not busy and not recovery_required(),
                'canReboot': inventory['rebootRequired'] and not busy and not recovery_required(), 'busy': busy}
    except Exception:
        return unavailable


def snapshot_running_services():
    rows = docker('GET', '/containers/json?all=true')
    if not isinstance(rows, list) or len(rows) > 1000:
        raise Rejected('updates_unavailable', 'Inventario dei servizi non disponibile.', 503)
    return [{'id': row['Id'], 'name': row['Names'][0].lstrip('/'), 'image': row['ImageID']} for row in rows if row['State'] == 'running']


def reboot_services_healthy(expected):
    try:
        for service in expected:
            actual = inspect(service['name'])
            if not actual or actual['Id'] != service['id'] or actual['Image'] != service['image'] or not actual['State']['Running'] or actual['State'].get('Health', {}).get('Status') not in [None, 'healthy']:
                return False
        for row in configuration()['components']:
            if row.get('repository') == 'library/traefik' and row.get('routeProbes'):
                verify_routing_http(row['routeProbes'])
        return True
    except Exception:
        return False


def reconcile_host_reboots(force=False):
    if host_updates is None:
        return
    for record in records('operation'):
        if record.get('kind') != 'host-reboot' or record['status'] not in ['queued', 'running', 'failed']:
            continue
        private = load('host-reboot', record['id'])
        if not private:
            continue
        if not private.get('acknowledged') and host_updates.inventory()['bootId'] == private['intent']['bootIdBefore']:
            continue
        if not force and time.time() - record.get('lastReconcileAt', 0) < 5:
            continue
        try:
            intent = host_updates.reconcile_reboot(private['intent'], health_check=lambda: reboot_services_healthy(private['services']))
            private['intent'] = intent
            save('host-reboot', record['id'], private)
            succeeded = intent['state'] == 'succeeded'
            completed = 3 if succeeded else 2 if intent.get('bootIdAfter') else 1
            operation_update(record['id'], status='succeeded' if succeeded else 'running',
                             stage='Riavvio e servizi verificati' if succeeded else 'Verifica dei servizi dopo il riavvio' if completed == 2 else 'In attesa del riavvio del server',
                             completedSteps=completed, totalSteps=3, lastReconcileAt=time.time(), recoveryRequired=False,
                             **({'finishedAt': stamp()} if succeeded else {}))
        except Exception:
            operation_update(record['id'], status='running', stage='Riavvio: verifica dello stato del server in attesa', lastReconcileAt=time.time())


def host_plan(kind, revision):
    current = host_catalog()
    if not current['available']:
        raise Rejected('updates_unavailable', 'Gestione aggiornamenti OS non disponibile.', 503)
    if revision != current['revision']:
        raise Rejected('stale_revision', 'Stato del server cambiato. Verifica un nuovo piano.')
    if kind == 'host-upgrade' and not current['canApply']:
        raise Rejected('unsupported', 'Verifica prima gli aggiornamenti OS disponibili.', 422)
    if kind == 'host-reboot' and not current['canReboot']:
        raise Rejected('unsupported', 'Il riavvio non è richiesto o la manutenzione è occupata.', 422)
    try:
        native = host_updates.plan(load('cache', 'host-releases')) if kind == 'host-upgrade' else host_updates.reboot_plan()
    except host_updates.HostUpdateError:
        raise Rejected('unsupported', 'Il piano OS non è applicabile; verifica nuovamente lo stato.', 422)
    public = {'kind': kind, 'planId': native['planId'], 'revision': revision,
              'expiresAt': datetime.datetime.fromtimestamp(native['expiresAt'], datetime.timezone.utc).isoformat(),
              'packageCount': len(native.get('packages', [])), 'steps': native['steps'], 'risks': native['risks'],
              'confirmationRequired': 'REBOOT' if kind == 'host-reboot' else 'UPDATE'}
    save('host-plan', public['planId'], {'public': public, 'native': native})
    return public


def verify_host_result(native, result):
    if not isinstance(result, dict) or result.get('state') != 'succeeded' or result.get('planId') != native.get('planId'):
        return False
    if not all(result.get(key) is True for key in ['packageVersionsVerified', 'dpkgAuditClean', 'marksRestored']):
        return False
    rows = result.get('packages')
    if not isinstance(rows, list):
        return False
    expected = {item['name']: item['targetVersion'] for item in native['packages']}
    actual = {item.get('name'): item.get('targetVersion') for item in rows if isinstance(item, dict) and item.get('state') == 'succeeded'}
    return len(actual) == len(rows) == len(expected) and actual == expected


def stored_host_execution(record):
    value = load('host-execution', record['id'])
    if value:
        return value
    with db() as connection:
        binding = connection.execute('SELECT plan FROM idempotency WHERE job=?', (record['id'],)).fetchone()
    stored = load('host-plan', binding['plan']) if binding else None
    return {'kind': record['kind'], 'native': stored['native'] if stored else None, 'dispatched': True}


def host_progress(job_id, kind, event):
    stages = {'refresh': 'Aggiornamento delle fonti APT', 'inventory': 'Verifica pacchetti installati', 'verify': 'Verifica del piano OS',
              'upgrade': 'Aggiornamento pacchetti OS', 'packages': 'Configurazione pacchetti OS', 'complete': 'Verifica finale dei pacchetti OS'}
    changes = {'stage': stages.get(event.get('stage'), 'Manutenzione del sistema operativo')}
    percent = event.get('percent')
    if kind == 'host-upgrade' and isinstance(percent, (int, float)) and not isinstance(percent, bool) and 0 <= percent <= 100:
        changes.update(completedSteps=min(99, int(percent)), totalSteps=100)
    operation_update(job_id, **changes)


def finish_host_upgrade(job_id, execution, result):
    native = execution.get('native')
    if not native or not verify_host_result(native, result):
        raise Rejected('updates_unavailable', 'Verifiche finali dei pacchetti OS incomplete.', 503)
    # Keep the verified result durable while Docker and ingress restart. This is
    # evidence from the fixed root worker, never a browser-supplied package list.
    execution['verifiedResult'] = result
    execution.setdefault('serviceVerificationStartedAt', time.time())
    save('host-execution', job_id, execution)
    baseline = execution.get('services')
    if not isinstance(baseline, list):
        operation_update(job_id, status='interrupted', recoveryRequired=True, completedSteps=99, totalSteps=100,
                         stage='Pacchetti verificati; baseline servizi assente: verifica assistita',
                         error='Serve una verifica amministrativa dei servizi precedenti.', lastHostReconcileAt=time.time(), finishedAt=stamp())
        return
    if not reboot_services_healthy(baseline):
        expired = time.time() - execution['serviceVerificationStartedAt'] >= 60
        operation_update(job_id, status='failed' if expired else 'running', recoveryRequired=expired or load('operation', job_id).get('recoveryRequired') is True,
                         stage='Pacchetti aggiornati; servizi non verificati: intervento richiesto' if expired else 'Pacchetti verificati; attesa avvio e verifica dei servizi',
                         completedSteps=99, totalSteps=100, lastHostReconcileAt=time.time(),
                         **({'error': 'Verifica amministrativa richiesta per i servizi del server.', 'finishedAt': stamp()} if expired else {'finishedAt': None}))
        return
    save('cache', 'host-releases', None)
    operation_update(job_id, status='succeeded', recoveryRequired=False, error=None,
                     stage='Aggiornamento OS e servizi verificati', completedSteps=100, totalSteps=100,
                     rebootRequired=result.get('rebootRequired') is True, lastHostReconcileAt=time.time(), finishedAt=stamp())


def reconcile_host_jobs(operation_id=None, force=False):
    if host_updates is None:
        return False
    reconciled = False
    for record in records('operation'):
        if record.get('kind') not in ['host-upgrade', 'host-check'] or record['status'] == 'succeeded':
            continue
        if record['status'] not in ['queued', 'running'] and not record.get('recoveryRequired'):
            continue
        if operation_id and record['id'] != operation_id:
            continue
        if not force and time.time() - record.get('lastHostReconcileAt', 0) < 5:
            continue
        job_id, kind = record['id'], record['kind']
        with HOST_JOB_GUARD:
            local = job_id in HOST_JOB_THREADS
        try:
            status = host_updates.worker_status(job_id)
            alive = host_updates.worker_alive(job_id)
            if not isinstance(status, dict):
                status = None
            execution = stored_host_execution(record)
            native = execution.get('native')
            if kind == 'host-upgrade' and isinstance(execution.get('verifiedResult'), dict):
                finish_host_upgrade(job_id, execution, execution['verifiedResult'])
                reconciled = True
                continue
            valid = status and status.get('schema') == 'platform-host-worker-status/v1' and status.get('operationId') == job_id and status.get('action') == ('apply' if kind == 'host-upgrade' else 'check')
            valid = valid and (kind != 'host-upgrade' or native and status.get('planId') == native.get('planId'))
            if valid and status.get('state') == 'succeeded':
                result = status.get('result')
                if kind == 'host-upgrade':
                    finish_host_upgrade(job_id, execution, result)
                    reconciled = True
                    continue
                if not isinstance(result, dict) or not isinstance(result.get('packages'), list) or not isinstance(result.get('checkedAt'), int):
                    raise Rejected('updates_unavailable', 'Verifica OS incompleta.', 503)
                save('cache', 'host-releases', result)
                operation_update(job_id, status='succeeded', recoveryRequired=False, error=None,
                                 stage='Verifica OS completata' if kind == 'host-check' else 'Aggiornamento OS verificato',
                                 completedSteps=1 if kind == 'host-check' else 100, totalSteps=1 if kind == 'host-check' else 100,
                                 rebootRequired=result.get('rebootRequired') is True, lastHostReconcileAt=time.time(), finishedAt=stamp())
                reconciled = True
                continue
            if alive is True:
                if valid and isinstance(status.get('progress'), dict):
                    host_progress(job_id, kind, status['progress'])
                operation_update(job_id, status='running', recoveryRequired=record.get('recoveryRequired') is True or status is not None and not valid, error=None, finishedAt=None,
                                 lastHostReconcileAt=time.time(), **({} if valid and status.get('progress') else {'stage': 'Worker OS ancora attivo; riconnessione al progresso'}))
                reconciled = True
                continue
            if valid and status.get('state') == 'running' and alive is None:
                operation_update(job_id, status='running', recoveryRequired=True, stage='Stato worker OS non confermato; attesa esito persistente', lastHostReconcileAt=time.time())
                reconciled = True
                continue
            if local and not valid:
                continue  # Dispatch may not have created its first spool record yet.
            operation_update(job_id, status='failed' if valid and status.get('state') == 'failed' else 'interrupted', recoveryRequired=kind == 'host-upgrade',
                             stage='Aggiornamento OS interrotto: verificare lo stato APT; nessun rollback' if kind == 'host-upgrade' else 'Verifica OS interrotta; riprovare',
                             error='Verifica amministrativa richiesta: manca un esito OS completo e verificato.', lastHostReconcileAt=time.time(), finishedAt=stamp())
            reconciled = True
        except Exception:
            if not local:
                operation_update(job_id, status='interrupted', recoveryRequired=kind == 'host-upgrade', stage='Stato OS non verificabile: verifica amministrativa richiesta',
                                 error='Impossibile confermare tutte le verifiche finali OS.', lastHostReconcileAt=time.time(), finishedAt=stamp())
                reconciled = True
    return reconciled


def wait_operation_lock(lock, job_id, expires_at=None, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        if expires_at is not None:
            expires = datetime.datetime.fromisoformat(expires_at).timestamp() if isinstance(expires_at, str) else expires_at
            if time.time() >= expires:
                raise Rejected('plan_expired', 'Piano scaduto durante l’attesa della manutenzione.', 410)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            operation_update(job_id, waitingForMaintenance=False)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise Rejected('operation_conflict', 'Host occupato da altra manutenzione. Riprova più tardi.', 409)
            operation_update(job_id, status='queued', stage='In attesa della manutenzione host in corso', waitingForMaintenance=True)
            time.sleep(1)


def host_job(job_id, kind, stored=None):
    lock_path = pathlib.Path('/var/lib/platform-vps-backup/operation.lock')
    lock_path.parent.mkdir(mode=0o700, exist_ok=True)
    began_upgrade = False
    with HOST_JOB_GUARD:
        HOST_JOB_THREADS.add(job_id)
    if not load('host-execution', job_id):
        save('host-execution', job_id, {'kind': kind, 'native': stored['native'] if stored else None, 'dispatched': False})
    with lock_path.open('a') as lock:
        try:
            wait_operation_lock(lock, job_id, stored['native']['expiresAt'] if stored else None)
            operation_update(job_id, status='running', stage='Verifica degli aggiornamenti OS' if kind == 'host-check' else 'Preparazione aggiornamento OS')
            def progress(event):
                nonlocal began_upgrade
                if event.get('stage') == 'upgrade':
                    began_upgrade = True
                host_progress(job_id, kind, event)
            execution = load('host-execution', job_id)
            if kind == 'host-upgrade':
                execution['services'] = snapshot_running_services()
            execution['dispatched'] = True
            save('host-execution', job_id, execution)
            if kind == 'host-check':
                result = host_updates.run_transient('check', progress=progress, operation_id=job_id)
                save('cache', 'host-releases', result)
            else:
                path = host_updates.write_plan_file(stored['native'])
                result = host_updates.run_transient('apply', plan_file=path, progress=progress, operation_id=job_id)
                finish_host_upgrade(job_id, execution, result)
                return
            operation_update(job_id, status='succeeded', recoveryRequired=False, error=None, stage='Verifica OS completata' if kind == 'host-check' else 'Aggiornamento OS verificato',
                             completedSteps=1 if kind == 'host-check' else 100, totalSteps=1 if kind == 'host-check' else 100,
                             rebootRequired=result.get('rebootRequired') is True, finishedAt=stamp())
        except Exception as error:
            logs = ROOT / 'logs'; logs.mkdir(mode=0o700, exist_ok=True)
            atomic(logs / (job_id + '-host.log'), traceback.format_exc().encode())
            if not reconcile_host_jobs(job_id, force=True):
                busy = isinstance(error, Rejected) and error.code == 'operation_conflict'
                expired = isinstance(error, Rejected) and error.code == 'plan_expired'
                operation_update(job_id, status='failed', recoveryRequired=began_upgrade or kind == 'host-upgrade' and load('host-execution', job_id, {}).get('dispatched') is True,
                                 stage='Host occupato: nessun aggiornamento eseguito' if busy else 'Piano OS scaduto: nessun aggiornamento eseguito' if expired else 'Aggiornamento OS non riuscito: verificare lo stato APT' if began_upgrade else 'Manutenzione OS non riuscita',
                                 error='Host occupato da altra manutenzione. Riprova più tardi.' if busy else 'Verifica amministrativa richiesta; nessun rollback automatico dei pacchetti OS.' if began_upgrade else 'Verifica OS non riuscita. Riprova dopo aver controllato lo stato del server.', finishedAt=stamp())
        finally:
            with HOST_JOB_GUARD:
                HOST_JOB_THREADS.discard(job_id)
            fcntl.flock(lock, fcntl.LOCK_UN)


def host_reboot_job(job_id):
    lock_path = pathlib.Path('/var/lib/platform-vps-backup/operation.lock')
    lock_path.parent.mkdir(mode=0o700, exist_ok=True)
    with lock_path.open('a') as lock:
        try:
            private = load('host-reboot', job_id)
            stored = load('host-plan', private['intent']['planId'])
            wait_operation_lock(lock, job_id, stored['native']['expiresAt'] if stored else None)
            private['intent'] = host_updates.schedule_reboot(private['intent'])
            save('host-reboot', job_id, private)
            operation_update(job_id, status='running', stage='Riavvio programmato; attesa nuova connessione', completedSteps=1, totalSteps=3)
        except Exception as error:
            blocked = isinstance(error, Rejected) and error.code in ['operation_conflict', 'plan_expired']
            operation_update(job_id, status='failed', recoveryRequired=not blocked,
                             stage='Host occupato o piano scaduto: riavvio non programmato' if blocked else 'Riavvio non confermato: verifica amministrativa richiesta',
                             error='Riprova con un piano aggiornato dopo la manutenzione.' if blocked else 'Verifica lo stato del server prima di riprovare.', finishedAt=stamp())
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def acknowledge_host_reboot(job_id):
    with GATE:
        private = load('host-reboot', job_id)
        record = load('operation', job_id)
        if not private or private.get('acknowledged') or private['intent'].get('state') != 'queued' or record['status'] not in ['queued', 'running']:
            return
        private['acknowledged'] = True
        save('host-reboot', job_id, private)
        EXECUTOR.submit(host_reboot_job, job_id)


def submit_host(kind, stored=None, idempotency_key=None):
    job_id = uuid.uuid4().hex
    job = {'id': job_id, 'kind': kind, 'status': 'queued', 'stage': 'In preparazione', 'completedSteps': 0,
           'totalSteps': 3 if kind == 'host-reboot' else 100 if kind == 'host-upgrade' else 1, 'startedAt': stamp()}
    services = snapshot_running_services() if kind == 'host-reboot' else None
    def persist(intent=None):
        with db() as connection:
            connection.execute('INSERT INTO records VALUES(?,?,?)', ('operation', job_id, json.dumps(job)))
            if kind in ['host-upgrade', 'host-check']:
                connection.execute('INSERT INTO records VALUES(?,?,?)', ('host-execution', job_id, json.dumps({'kind': kind, 'native': stored['native'] if stored else None, 'dispatched': False})))
            if intent is not None:
                connection.execute('INSERT INTO records VALUES(?,?,?)', ('host-reboot', job_id, json.dumps({'intent': intent, 'services': services, 'acknowledged': False})))
            if idempotency_key:
                connection.execute('INSERT INTO idempotency VALUES(?,?,?)', (idempotency_key, stored['public']['planId'], job_id))
    if kind == 'host-reboot':
        try:
            host_updates.prepare_reboot(stored['native'], persist, 'REBOOT')
        except host_updates.HostUpdateError:
            raise Rejected('unsupported', 'Riavvio non applicabile: verifica manutenzione e stato del server.', 422)
    else:
        persist()
        EXECUTOR.submit(host_job, job_id, kind, stored)
    return {'operationId': job_id, 'status': 'queued'}


def handle_host(body, after_response=None):
    action = body['action']
    if action == 'host-catalog':
        reconcile_host_jobs()
        reconcile_host_reboots()
        return host_catalog()
    if host_updates is None:
        raise Rejected('updates_unavailable', 'Gestione aggiornamenti OS non disponibile.', 503)
    with GATE:
        if recovery_required():
            raise Rejected('operation_conflict', 'Una manutenzione interrotta richiede verifica amministrativa.')
        if action in ['host-apply', 'host-reboot-apply']:
            expected_kind = 'host-reboot' if action == 'host-reboot-apply' else 'host-upgrade'
            if body['confirmation'] != ('REBOOT' if expected_kind == 'host-reboot' else 'UPDATE'):
                raise Rejected('confirmation_required', 'Conferma esplicita richiesta.', 422)
            with db() as connection:
                prior = connection.execute('SELECT plan,job FROM idempotency WHERE id=?', (body['idempotencyKey'],)).fetchone()
            if prior:
                if prior['plan'] != body['planId']:
                    raise Rejected('idempotency_conflict', 'Identificativo di richiesta già usato.')
                record = load('operation', prior['job'])
                if record.get('kind') != expected_kind:
                    raise Rejected('idempotency_conflict', 'Identificativo di richiesta già usato per un’altra operazione.')
                if record.get('kind') == 'host-reboot' and after_response:
                    after_response(lambda: acknowledge_host_reboot(record['id']))
                return {'operationId': record['id'], 'status': record['status']}
        if any(item['status'] in ['queued', 'running'] for item in records('operation')):
            raise Rejected('operation_conflict', 'È già in corso una manutenzione.')
        if action == 'host-check':
            return submit_host('host-check')
        kind = 'host-reboot' if action.startswith('host-reboot-') else 'host-upgrade'
        if action in ['host-plan', 'host-reboot-plan']:
            return host_plan(kind, body['revision'])
        stored = load('host-plan', body['planId'])
        if not stored or stored['public']['kind'] != kind:
            raise Rejected('not_found', 'Piano OS non disponibile.', 404)
        if body['confirmation'] != ('REBOOT' if kind == 'host-reboot' else 'UPDATE'):
            raise Rejected('confirmation_required', 'Conferma esplicita richiesta.', 422)
        if stored['native']['expiresAt'] <= time.time():
            raise Rejected('plan_expired', 'Piano OS scaduto.', 410)
        if body['revision'] != stored['public']['revision'] or host_catalog()['revision'] != body['revision']:
            raise Rejected('stale_revision', 'Stato del server cambiato. Verifica un nuovo piano.')
        result = submit_host(kind, stored, body['idempotencyKey'])
        if kind == 'host-reboot' and after_response:
            after_response(lambda: acknowledge_host_reboot(result['operationId']))
        return result


def server_events():
    global SERVER_EVENTS_COLLECTOR
    with SERVER_EVENTS_GUARD:
        if SERVER_EVENTS_COLLECTOR is None and create_server_events_collector is not None:
            SERVER_EVENTS_COLLECTOR = create_server_events_collector(read_operations=lambda: records('operation'))
        collector = SERVER_EVENTS_COLLECTOR
    if collector is None:
        return {'schema': 'server-events/v1', 'available': False, 'partial': True, 'checkedAt': stamp(), 'issues': [], 'events': [],
                'sources': [{'id': identity, 'available': False, 'reason': 'Raccoglitore diagnostico non disponibile.'} for identity in ['host', 'systemd', 'docker', 'journal', 'updates']]}
    return collector()


def handle(body, after_response=None):
    allowed = {'server-events': set(), 'catalog': set(), 'check': set(), 'plan': {'componentId', 'revision'}, 'apply': {'componentId', 'revision', 'planId', 'confirmation', 'idempotencyKey'}, 'operation': {'operationId'}}
    allowed.update({'host-catalog': set(), 'host-check': set(), 'host-plan': {'revision'}, 'host-apply': {'revision', 'planId', 'confirmation', 'idempotencyKey'}, 'host-reboot-plan': {'revision'}, 'host-reboot-apply': {'revision', 'planId', 'confirmation', 'idempotencyKey'}})
    if not isinstance(body, dict) or not isinstance(body.get('action'), str) or body.get('action') not in allowed or set(body) != allowed[body['action']] | {'action'}:
        raise Rejected('invalid_request', 'Richiesta non valida.', 400)
    action = body['action']
    for key in ['componentId', 'planId', 'operationId']:
        if key in body and (not isinstance(body[key], str) or not IDENTIFIER.fullmatch(body[key])):
            raise Rejected('invalid_request', 'Identificativo non valido.', 400)
    for key in ['revision', 'idempotencyKey']:
        if key in body and (not isinstance(body[key], str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}', body[key])):
            raise Rejected('invalid_request', 'Richiesta non valida.', 400)
    if action == 'server-events':
        return server_events()
    if action.startswith('host-'):
        return handle_host(body, after_response)
    if action == 'catalog':
        return catalog()
    if action == 'operation':
        reconcile_host_jobs(operation_id=body['operationId'])
        reconcile_host_reboots()
        value = load('operation', body['operationId'])
        if value is None:
            raise Rejected('not_found', 'Operazione non presente.', 404)
        return value
    with GATE:
        if action in ['plan', 'apply'] and recovery_required():
            raise Rejected('operation_conflict', 'Una manutenzione interrotta richiede verifica amministrativa.')
        if action == 'apply':
            with db() as c:
                prior = c.execute('SELECT plan,job FROM idempotency WHERE id=?', (body['idempotencyKey'],)).fetchone()
            if prior:
                if prior['plan'] != body['planId']:
                    raise Rejected('idempotency_conflict', 'Identificativo di richiesta già usato.')
                job = load('operation', prior['job'])
                if job.get('kind') != 'apply':
                    raise Rejected('idempotency_conflict', 'Identificativo di richiesta già usato per un’altra operazione.')
                return {'operationId': job['id'], 'status': job['status']}
        if any(x['status'] in ['queued', 'running'] for x in records('operation')):
            raise Rejected('operation_conflict', 'È già in corso una manutenzione.')
        if action == 'check':
            return submit('check')
        if body['componentId'] != 'all':
            component(body['componentId'])
        if action == 'plan':
            return plan(body['componentId'], body['revision'])
        stored = load('plan', body['planId'])
        if not stored or stored['public']['componentId'] != body['componentId']:
            raise Rejected('not_found', 'Piano non disponibile.', 404)
        if body['confirmation'] != 'UPDATE':
            raise Rejected('confirmation_required', 'Conferma richiesta.', 422)
        if datetime.datetime.fromisoformat(stored['public']['expiresAt']).timestamp() < time.time():
            raise Rejected('plan_expired', 'Piano scaduto.', 410)
        if body['revision'] != stored['public']['revision'] or catalog()['revision'] != body['revision']:
            raise Rejected('stale_revision', 'Stato cambiato dopo il piano.')
        return submit('apply', stored, idempotency_key=body['idempotencyKey'])


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        status = 200
        after_response = []
        try:
            self.connection.settimeout(10)
            size = int(self.headers.get('Content-Length', '0'))
            if self.path != '/v1/updates' or self.headers.get('Transfer-Encoding') or not 0 < size <= 16384:
                raise Rejected('invalid_request', 'Richiesta non valida.', 400)
            raw = self.rfile.read(size)
            if not hmac.compare_digest(self.headers.get('x-platform-signature', ''), hmac.new(self.server.key, raw, hashlib.sha256).hexdigest()):
                raise Rejected('forbidden', 'Autenticazione del servizio rifiutata.', 403)
            envelope = json.loads(raw)
            if set(envelope) != {'body', 'timestamp', 'nonce'} or type(envelope['timestamp']) is not int or abs(time.time() * 1000 - envelope['timestamp']) > 60000 or not re.fullmatch('[a-f0-9]{32}', envelope['nonce']):
                raise Rejected('forbidden', 'Richiesta scaduta o non valida.', 403)
            with db() as c:
                c.execute('DELETE FROM nonces WHERE at<?', (time.time() - 120,))
                try:
                    c.execute('INSERT INTO nonces VALUES(?,?)', (envelope['nonce'], time.time()))
                except sqlite3.IntegrityError:
                    raise Rejected('forbidden', 'Richiesta già utilizzata.', 403)
            value = handle(envelope['body'], after_response=after_response.append)
        except Rejected as e:
            status, value = e.status, {'error': {'code': e.code, 'message': str(e), 'status': e.status}}
        except Exception:
            status, value = 503, {'error': {'code': 'updates_unavailable', 'message': 'Servizio di manutenzione non disponibile.', 'status': 503}}
        output = encode(value)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(output)))
        self.end_headers()
        self.wfile.write(output)
        self.wfile.flush()
        if status < 400:
            for callback in after_response:
                try:
                    callback()
                except Exception:
                    pass  # The persisted intent remains available for reconciliation.


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    configuration()
    initialize()
    reconcile_host_jobs(force=True)
    reconcile_host_reboots(force=True)
    docker_config = ROOT / 'docker-config'
    docker_config.mkdir(mode=0o700, exist_ok=True)
    os.environ.setdefault('DOCKER_CONFIG', str(docker_config))
    key = protected(KEY).read_bytes()
    if len(key) != 32:
        raise RuntimeError('Invalid updates capability')
    p = pathlib.Path(SOCKET)
    p.parent.mkdir(mode=0o750, exist_ok=True)
    os.chown(p.parent, 0, 1000)
    if p.exists():
        if not stat.S_ISSOCK(p.lstat().st_mode):
            raise RuntimeError('Updates endpoint is not a socket')
        p.unlink()
    with Server(SOCKET, Handler) as server:
        server.key = key
        os.chown(p, 0, 1000)
        os.chmod(p, 0o660)
        server.serve_forever()


if __name__ == '__main__':
    main()
