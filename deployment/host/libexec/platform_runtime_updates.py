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

ROOT = pathlib.Path(os.environ.get('PLATFORM_UPDATES_STATE', '/var/lib/platform-updates'))
CONFIG = pathlib.Path(os.environ.get('PLATFORM_UPDATES_CONFIG', '/etc/platform-infrastructure/updates/config.json'))
SOCKET = os.environ.get('PLATFORM_UPDATES_SOCKET', '/run/platform-updates/updates.sock')
KEY = pathlib.Path(os.environ.get('PLATFORM_UPDATES_KEY', '/etc/platform-infrastructure/updates/bridge-key'))
EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=1)
GATE = threading.Lock()
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
            item.update(status='interrupted', recoveryRequired=(ROOT / item['id'] / 'rollback.json').exists(), stage='Interrotta: verifica lo stato reale prima di riprovare', finishedAt=stamp())
            save('operation', item['id'], item)


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


def data_sensitive(row):
    return row['category'] == 'Database' or row.get('requiresRecovery') is True


def observed(row):
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
        versions.append(version)
    unique = sorted(set(v for v in versions if v))
    if len({r['Image'] for r in rows}) > 1 and any(not v for v in versions):
        return rows, None
    return rows, unique[0] if len(unique) == 1 and unique[0] else None


def fingerprint(rows):
    return digest([{'id': r['Id'], 'image': r['Image'], 'config': r['Config'], 'host': r['HostConfig'], 'mounts': r['Mounts'], 'networks': {name: {'IPAMConfig': net.get('IPAMConfig'), 'Aliases': net.get('Aliases')} for name, net in r['NetworkSettings']['Networks'].items()}} for r in sorted(rows, key=lambda r: r['Name'])])


def catalog():
    output = []
    checked = load('cache', 'releases', {})
    for row in configuration()['components']:
        actual, version = observed(row)
        cached = checked.get('components', {}).get(row['id'], {})
        release, latest = cached.get('candidateRelease'), cached.get('latestStable')
        eligible = bool(actual and len(actual) == len(row['containers']) and version and release and row['strategy'] != 'observe')
        if release and version and compare_versions(release['version'], version) <= 0:
            eligible = False
        reason = row.get('blockedReason') or cached.get('reason')
        if data_sensitive(row) and row.get('recoveryPolicy') != 'offline-snapshot-v1':
            eligible, reason = False, 'Serve un percorso verificato di recupero dei dati prima di aggiornare il database.'
        status = 'update-available' if eligible else 'current' if version and latest and compare_versions(version, latest['version']) >= 0 else 'unsupported' if row['strategy'] == 'observe' else 'unavailable'
        if not actual:
            status, reason = 'not-installed', 'Componente non presente sulla VPS.'
        elif version is None:
            reason = 'Versione non verificabile o versioni diverse fra le istanze.'
        elif latest and release and latest['version'] != release['version']:
            reason = 'Una serie diversa richiede un percorso di compatibilità separato.'
        if status == 'current':
            reason = None
        elif latest and version and not release and compare_versions(latest['version'], version) > 0:
            status, reason = 'unsupported', 'La nuova serie richiede una verifica di compatibilità dedicata.'
        elif isinstance(reason, str) and reason.startswith('unavailable:'):
            reason = 'Fonte ufficiale non disponibile o release non pubblicata per questo componente.'
        output.append({'id': row['id'], 'label': row['label'], 'category': row['category'], 'installed': bool(actual), 'current': {'version': version, 'imageDigest': actual[0]['Image'] if actual else None, 'verifiedAt': stamp()}, 'latestStable': latest, 'candidateRelease': release, 'services': [r['Name'].lstrip('/') for r in actual], 'status': status, 'canUpdate': eligible, 'blockedReason': reason, '_fingerprint': fingerprint(actual)})
    revision = digest({'components': [{k: v for k, v in x.items() if k != 'current'} | {'version': x['current']['version'], 'image': x['current']['imageDigest']} for x in output], 'checkedAt': checked.get('checkedAt')})
    for item in output:
        item.pop('_fingerprint')
    operations = records('operation')
    return {'schema': 'runtime-updates/v1', 'available': True, 'canCheck': True, 'canApply': not recovery_required(), 'revision': revision, 'checkedAt': checked.get('checkedAt'), 'components': output, 'operations': operations[:12]}


def operation_update(job_id, **changes):
    item = load('operation', job_id)
    item.update(changes)
    save('operation', job_id, item)


def check_job(job_id):
    config = configuration()['components']
    operation_update(job_id, status='running', stage='Verifica delle fonti ufficiali', totalSteps=len(config), completedSteps=0)
    cache = {'checkedAt': stamp(), 'components': {}}
    def check(row):
        actual, version = observed(row)
        if not actual or not version or not row.get('repository'):
            return row['id'], {'reason': row.get('blockedReason', 'Versione o fonte stabile non disponibile.')}
        return row['id'], resolve_release(row, version)
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


def plan(component_id, revision):
    current = catalog()
    if current['revision'] != revision:
        raise Rejected('stale_revision', 'Inventario cambiato. Verifica nuovamente il piano.')
    item = next(x for x in current['components'] if x['id'] == component_id)
    if not item['canUpdate']:
        raise Rejected('unsupported', item['blockedReason'] or 'Nessun aggiornamento compatibile disponibile.', 422)
    row = component(component_id)
    actual, _ = observed(row)
    target = item['candidateRelease']
    if data_sensitive(row):
        for old in actual:
            recovery_sources(old)  # Reject unsupported persistent mounts before downtime.
    value = {'planId': uuid.uuid4().hex, 'revision': revision, 'expiresAt': datetime.datetime.fromtimestamp(time.time() + 900, datetime.timezone.utc).isoformat(), 'componentId': component_id, 'targetVersion': target['version'], 'targetDigest': target['imageDigest'], 'affectedServices': item['services'], 'steps': ['Verifica dello stato attuale', 'Download e preparazione del runtime', 'Aggiornamento dei servizi selezionati', 'Verifica di avvio e funzionamento', 'Registrazione del risultato'], 'risks': ['I servizi selezionati saranno brevemente indisponibili. Dati e configurazioni vengono mantenuti.'] + (['Il servizio sarà fermato per creare una copia consistente dei suoi dati sul server. Le applicazioni collegate possono essere temporaneamente indisponibili.', 'Viene mantenuta una copia protetta per il recupero; dopo un avvio della nuova versione non viene eseguito alcun downgrade automatico dei dati.', 'Aggiornamento compatibile della stessa serie. Per cambiare serie serve una migrazione dedicata.'] if data_sensitive(row) else []), 'confirmationRequired': 'UPDATE'}
    save('plan', value['planId'], {'public': value, 'component': row, 'target': target, 'fingerprint': fingerprint(actual)})
    return value


def image_candidate(row, target, directory):
    ref = target['imageReference'] + '@' + target['imageDigest']
    run(['docker', 'pull', ref], timeout=600)
    if row['strategy'] == 'image':
        return docker('GET', '/images/' + ref.replace('/', '%2F') + '/json')['Id']
    if row['strategy'] == 'node-layer':
        actual, _ = observed(row)
        image_ids = {x['Image'] for x in actual}
        if len(image_ids) != 1:
            raise Rejected('unsupported', 'Le immagini applicative devono essere aggiornate separatamente.', 422)
        # Keep the exact deployed application and its native dependencies. Same major only.
        base_tag = 'platform/runtime-base:' + directory.name
        run(['docker', 'image', 'tag', actual[0]['Image'], base_tag])
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


def recreate(old, image, backups, journal=lambda: None, before_start=None):
    name = old['Name'].lstrip('/')
    backup = name + '-update-' + uuid.uuid4().hex[:10]
    saved = {'old': old, 'backupName': backup, 'newId': None, 'phase': 'prepared'}
    backups.append(saved)
    journal()  # Durable before the first change, including restart policy.
    docker('POST', '/containers/' + old['Id'] + '/update', {'RestartPolicy': {'Name': 'no'}})
    if old['State']['Running']:
        docker('POST', '/containers/' + old['Id'] + '/stop?t=30')
    if before_start:
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
    result = docker('POST', '/containers/create?name=' + name, config)
    saved['newId'] = result['Id']
    journal()
    if old['State']['Running']:
        saved['newStarted'] = True
        journal()  # Database start may write data even if its health check fails.
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
    backups = []
    committed = False
    operation_update(job_id, status='running', stage='Verifica dello stato attuale', completedSteps=0)
    lock_path = pathlib.Path('/var/lib/platform-vps-backup/operation.lock')
    lock_path.parent.mkdir(mode=0o700, exist_ok=True)
    with lock_path.open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            row, target = stored['component'], stored['target']
            actual, _ = observed(row)
            if fingerprint(actual) != stored['fingerprint']:
                raise Rejected('stale_plan', 'I servizi sono cambiati dopo la preparazione del piano.')
            # The complete snapshot stays root-only; never returned by the API.
            atomic(directory / 'before.json', encode(actual))
            operation_update(job_id, stage='Download e preparazione del runtime', completedSteps=1)
            image = image_candidate(row, target, directory)
            if row['strategy'] == 'node-layer':
                output = run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--entrypoint', 'node', image, '--version'])
                if target['version'] not in output:
                    raise Rejected('updates_unavailable', 'Il runtime candidato non è compatibile con il sistema del servizio.', 503)
            fresh, _ = observed(row)
            if fingerprint(fresh) != stored['fingerprint']:
                raise Rejected('stale_plan', 'I servizi sono cambiati durante la preparazione del runtime.')
            operation_update(job_id, stage='Aggiornamento dei servizi selezionati', completedSteps=2)
            new_rows = []
            for old in actual:
                if row['strategy'] == 'php-build' and old['State']['Running']:
                    old['runtimeModules'] = run(['docker', 'exec', old['Id'], 'php', '-m']).splitlines()
                new_id = recreate(old, image, backups, journal=lambda: atomic(directory / 'rollback.json', encode(backups)), before_start=(lambda previous: snapshot_database(previous, directory)) if data_sensitive(row) else None)
                new_rows.append(verify(old, new_id, row, target['version']))
            operation_update(job_id, stage='Verifica finale e autorizzazioni', completedSteps=4)
            refresh_admission(actual, new_rows)
            # After this boundary failures in logging must not undo a signed success.
            committed = True
            save('desired', row['id'], {'version': target['version'], 'image': image, 'source': target, 'containers': [x['Name'] for x in new_rows], 'updatedAt': stamp()})
            operation_update(job_id, status='succeeded', stage='Aggiornamento verificato', completedSteps=5, finishedAt=stamp())
        except Exception:
            atomic(directory / 'error.log', traceback.format_exc().encode())
            if committed:
                operation_update(job_id, status='succeeded', stage='Runtime aggiornato; registro locale da verificare', completedSteps=5, finishedAt=stamp())
                return
            failed_rollback = False
            for backup in reversed(backups):
                old = backup['old']
                try:
                    if data_sensitive(row) and backup.get('newStarted'):
                        failed_rollback = True
                        continue  # Never run an older DB over potentially upgraded data.
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
            operation_update(job_id, status='failed' if not backups or failed_rollback else 'rolled-back', recoveryRequired=failed_rollback, stage='Intervento assistito richiesto' if failed_rollback else 'Aggiornamento non riuscito; runtime precedente mantenuto', error='Verifica non riuscita. Consulta il registro protetto della manutenzione.' if not failed_rollback else 'Ripristino automatico incompleto: richiede intervento amministrativo.', finishedAt=stamp())
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def submit(kind, stored=None, idempotency_key=None):
    job_id = uuid.uuid4().hex
    job = {'id': job_id, 'kind': kind, 'status': 'queued', 'stage': 'In preparazione', 'completedSteps': 0, 'totalSteps': 5 if kind == 'apply' else 1, 'startedAt': stamp()}
    with db() as c:
        c.execute('INSERT INTO records VALUES(?,?,?)', ('operation', job_id, json.dumps(job)))
        if idempotency_key:
            c.execute('INSERT INTO idempotency VALUES(?,?,?)', (idempotency_key, stored['public']['planId'], job_id))
    EXECUTOR.submit(apply_job if kind == 'apply' else check_job, job_id, *([stored] if stored is not None else []))
    return {'operationId': job_id, 'status': 'queued'}


def handle(body):
    allowed = {'catalog': set(), 'check': set(), 'plan': {'componentId', 'revision'}, 'apply': {'componentId', 'revision', 'planId', 'confirmation', 'idempotencyKey'}, 'operation': {'operationId'}}
    if not isinstance(body, dict) or not isinstance(body.get('action'), str) or body.get('action') not in allowed or set(body) != allowed[body['action']] | {'action'}:
        raise Rejected('invalid_request', 'Richiesta non valida.', 400)
    action = body['action']
    for key in ['componentId', 'planId', 'operationId']:
        if key in body and (not isinstance(body[key], str) or not IDENTIFIER.fullmatch(body[key])):
            raise Rejected('invalid_request', 'Identificativo non valido.', 400)
    for key in ['revision', 'idempotencyKey']:
        if key in body and (not isinstance(body[key], str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}', body[key])):
            raise Rejected('invalid_request', 'Richiesta non valida.', 400)
    if action == 'catalog':
        return catalog()
    if action == 'operation':
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
                return {'operationId': job['id'], 'status': job['status']}
        if any(x['status'] in ['queued', 'running'] for x in records('operation')):
            raise Rejected('operation_conflict', 'È già in corso una manutenzione.')
        if action == 'check':
            return submit('check')
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
            value = handle(envelope['body'])
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


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    configuration()
    initialize()
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
