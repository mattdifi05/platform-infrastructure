#!/usr/bin/env python3
"""Finite root metadata publisher. Preparation only; no managed adoption or data reads."""
import concurrent.futures
import datetime
import fcntl
import hashlib
import json
import importlib.util
import os
import pathlib
import re
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.request

CONFIG = pathlib.Path('/etc/platform-vps-backup')
WORK = pathlib.Path('/var/lib/platform-vps-backup')
PUBLIC = WORK / 'public'
SCRATCH = pathlib.Path('/run/platform-scripta-observer')
INSTALL = pathlib.Path('/usr/local/libexec/platform-vps-backup/deployment/vps-backup')
APP_ROOT = '/srv/platform-infrastructure/scripta-students'
APP_NAMES = {'/node-scriptastudents': 'backend', '/scripta-postgres': 'postgres',
             '/students-beta-redis': 'redis', '/scriptastudents-ingress': 'ingress'}
HASH = re.compile(r'[a-f0-9]{64}')
IMAGE = re.compile(r'sha256:[a-f0-9]{64}')
MANIFEST = re.compile(r'manifest-vps-[0-9]{8}t[0-9]{6}z-[a-f0-9]{12}')
DOCKER = ['docker', '--host', 'unix:///run/docker.sock']
INSPECT = ('{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
           '"Mounts":{{json .Mounts}},"Labels":{{json .Config.Labels}},'
           '"Running":{{json .State.Running}},"Paused":{{json .State.Paused}},'
           '"Health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}"unknown"{{end}},'
           '"RestartCount":{{json .RestartCount}}}')
NATIVE_PROBE = r"""
const fs=require('node:fs');
const {Pool}=require('pg');const {createClient}=require('redis');
const deadline=setTimeout(()=>process.exit(1),11000);deadline.unref();
function file(path,secret=false){const s=fs.lstatSync(path);if(!s.isFile()||s.isSymbolicLink()||s.size>131072||(secret&&(s.uid!==1000||(s.mode&63))))throw Error('File');return fs.readFileSync(path,'utf8').trim()}
const ca=file('/run/tls/ca.crt');
async function postgres(){let pool;try{const u=new URL(file('/run/secrets/database-url',true));if(u.protocol!=='postgresql:'||u.hostname!=='scripta-postgres'||u.port!=='5432'||u.username!=='scripta_app'||u.pathname!=='/students_beta_app'||u.hash||u.searchParams.get('sslmode')!=='verify-full'||u.searchParams.get('sslrootcert')!=='/run/tls/ca.crt')throw Error('Scope');pool=new Pool({host:u.hostname,port:5432,database:'students_beta_app',user:'scripta_app',password:decodeURIComponent(u.password),ssl:{ca,servername:'scripta-postgres',rejectUnauthorized:true},max:1,connectionTimeoutMillis:3000,query_timeout:3000,statement_timeout:3000,application_name:'scripta-metadata-observer',options:'-c default_transaction_read_only=on'});pool.on('error',()=>{});const r=await pool.query(`SELECT current_setting('server_version') AS version,current_database() AS name,current_user AS role,coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),false) AS tls,r.rolsuper AS super,r.rolcreatedb AS create_db,r.rolcreaterole AS create_role,r.rolreplication AS replication,r.rolbypassrls AS bypass_rls,(SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()) AS owner,EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid) AS inherited_role FROM pg_roles r WHERE r.rolname=current_user`);return{connected:true,...r.rows[0]}}catch{return{connected:false}}finally{if(pool)await pool.end().catch(()=>{})}}
async function cache(){let c;try{const u=new URL(file('/run/secrets/redis-url',true));if(u.protocol!=='rediss:'||u.hostname!=='students-beta-redis'||u.port!=='6379'||u.username!=='default'||u.pathname!=='/0'||u.search||u.hash)throw Error('Scope');c=createClient({url:u.href,disableOfflineQueue:true,socket:{tls:true,ca,servername:'students-beta-redis',rejectUnauthorized:true,connectTimeout:3000,reconnectStrategy:false}});c.on('error',()=>{});await c.connect();const sections=await Promise.all(['server','memory','persistence','keyspace'].map(x=>c.info(x)));return{connected:true,tls:true,sections}}catch{return{connected:false}}finally{if(c)try{c.destroy()}catch{}}}
Promise.all([postgres(),cache()]).then(([database,redis])=>{clearTimeout(deadline);process.stdout.write(JSON.stringify({database,redis}))}).catch(()=>process.exit(1));
""".encode()


def require(condition):
    if not condition:
        raise RuntimeError('Observation refused')


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def protected(path, directory=False, private=False):
    path = pathlib.Path(path)
    info = path.lstat()
    require(not path.is_symlink() and info.st_uid == 0 and not info.st_mode & (0o077 if private else 0o022)
            and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)))
    return path


def read(path, limit=1048576, private=False):
    path = protected(path, private=private)
    before = path.lstat()
    require(before.st_size <= limit)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        actual = os.fstat(stream.fileno())
        require((actual.st_dev, actual.st_ino, actual.st_size, actual.st_uid, actual.st_mode) ==
                (before.st_dev, before.st_ino, before.st_size, before.st_uid, before.st_mode))
        data = stream.read(limit + 1)
        require(len(data) <= limit)
    return data


def run(args, data=None, timeout=10):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    require(result.returncode == 0 and len(result.stdout) <= 1048576)
    return result.stdout


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode() + b'\n'


def timestamp(value, now=None):
    require(isinstance(value, str))
    date = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(date.tzinfo is not None)
    epoch = date.timestamp()
    require(epoch <= (time.time() if now is None else now) + 30)
    return epoch


def validate_profile(profile, machine):
    require(isinstance(profile, dict) and profile.get('hostname') == 'platform-server-public'
            and profile.get('machineId') == machine and type(profile.get('generation')) is int and profile['generation']>=1)
    if profile['generation']==1:require(profile.get('previousAdmissionSha256')=='0'*64)
    else:
        spec=importlib.util.spec_from_file_location('admitted_runner',INSTALL/'platform-vps-backup-runner.py');runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner);runner.validate_admission_chain(profile)
    extension = profile.get('scriptaRuntime')
    require(isinstance(extension, dict) and extension.get('schema') == 'scripta-reviewed-runtime/v1'
            and extension.get('project') == 'scriptastudents_vps'
            and isinstance(extension.get('previousProfileSha256'), str) and HASH.fullmatch(extension['previousProfileSha256']))
    rows = extension.get('containers')
    require(isinstance(rows, list) and len(rows) == 4 and {r.get('name') for r in rows} == set(APP_NAMES))
    require(len({r.get('id') for r in rows}) == 4)
    for row in rows:
        require(set(row) == {'name', 'id', 'image', 'mounts', 'labels'} and isinstance(row['id'], str)
                and HASH.fullmatch(row['id']) and isinstance(row['image'], str) and IMAGE.fullmatch(row['image'])
                and isinstance(row['labels'], dict) and row['labels'].get('com.docker.compose.project') == 'scriptastudents_vps'
                and row['labels'].get('com.docker.compose.service') == APP_NAMES[row['name']])
        require(isinstance(row['mounts'], list))
        for mount in row['mounts']:
            require(mount.get('Type') == 'tmpfs' or mount.get('Type') == 'bind' and isinstance(mount.get('Source'), str)
                    and mount['Source'].startswith(APP_ROOT + '/') and '..' not in pathlib.PurePosixPath(mount['Source']).parts
                    and str(pathlib.PurePosixPath(mount['Source'])) == mount['Source'])
        pins = [p for p in profile.get('pins', []) if p.get('name') == row['name']]
        require(len(pins) == 1 and pins[0] == {key: row[key] for key in ('name', 'id', 'image', 'mounts')})
    require(extension.get('persistentRoots') == [APP_ROOT + '/data/legacy', APP_ROOT + '/data/redis']
            and extension.get('postgresData') == APP_ROOT + '/data/postgres')
    backend = next(r for r in rows if r['name'] == '/node-scriptastudents')
    for source, destination in ((APP_ROOT + '/secrets', '/run/secrets'), (APP_ROOT + '/tls/ca.crt', '/run/tls/ca.crt')):
        require(any(m.get('Type') == 'bind' and m.get('Source') == source and m.get('Destination') == destination and m.get('RW') is False for m in backend['mounts']))
    return sorted(rows, key=lambda r: r['name'])


def inspect(expected, management=None):
    admitted = list(expected)
    if management is not None:
        require(isinstance(management, dict) and management.get('schema') == 'scripta-management/v1' and management.get('projectId') == 'scriptastudents')
        admin = management.get('adminContainer')
        require(isinstance(admin, dict) and set(admin) == {'name', 'id', 'image', 'mounts', 'labels'} and admin.get('name') == '/phppgadmin'
                and isinstance(admin.get('id'), str) and HASH.fullmatch(admin['id']) and isinstance(admin.get('image'), str) and IMAGE.fullmatch(admin['image'])
                and admin['labels'].get('com.docker.compose.project') == 'scriptastudents_vps' and admin['labels'].get('com.docker.compose.service') == 'phppgadmin')
        admitted.append(admin)
    scope = run(DOCKER + ['ps', '-aq', '--no-trunc', '--filter', 'label=com.docker.compose.project=scriptastudents_vps']).decode().split()
    require(set(scope) == {r['id'] for r in admitted} and len(scope) == len(admitted))
    rows = [json.loads(line) for line in run(DOCKER + ['inspect', '--format', INSPECT, *scope]).decode().splitlines()]
    require(len(rows) == len(admitted) and {r['Id'] for r in rows} == set(scope))
    for row in rows:
        pin = next((p for p in admitted if p['name'] == row.get('Name')), None)
        require(pin is not None and pin == {'name': row['Name'], 'id': row['Id'], 'image': row['Image'], 'mounts': row['Mounts'], 'labels': row['Labels']})
        require(type(row['Running']) is bool and type(row['Paused']) is bool and row['Health'] in ('healthy', 'unhealthy', 'starting', 'unknown')
                and type(row['RestartCount']) is int and row['RestartCount'] >= 0)
    return sorted([r for r in rows if r['Name'] in APP_NAMES], key=lambda r: r['Name'])


def aggregate(raw):
    require(isinstance(raw, str) and len(raw) <= 131072)
    result = {}
    for line in raw.splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition(':')
        require(separator and key not in result)
        result[key] = value
    return result


def metric(value):
    require(isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]*', value))
    number = int(value)
    require(number <= 9007199254740991)
    return number


def native_metadata(raw):
    require(isinstance(raw, dict) and set(raw) == {'database', 'redis'})
    pg, redis = raw['database'], raw['redis']
    require(isinstance(pg, dict) and type(pg.get('connected')) is bool and isinstance(redis, dict) and type(redis.get('connected')) is bool)
    database = {'engine': 'postgres', 'name': 'students_beta_app', 'role': 'scripta_app', 'version': '0.0', 'connected': False, 'tls': False}
    cache = {'version': '0.0', 'connected': False, 'tls': False, 'aof': False, 'keyCount': 0, 'usedBytes': 0, 'maxBytes': 0}
    if pg['connected']:
        require(set(pg) == {'connected', 'version', 'name', 'role', 'tls', 'super', 'create_db', 'create_role', 'replication', 'bypass_rls', 'owner', 'inherited_role'}
                and isinstance(pg['version'], str) and re.fullmatch(r'18\.6(?:\s.*)?', pg['version'])
                and pg['name'] == 'students_beta_app' and pg['role'] == pg['owner'] == 'scripta_app'
                and pg['tls'] is True and all(pg[k] is False for k in ('super', 'create_db', 'create_role', 'replication', 'bypass_rls', 'inherited_role')))
        database.update(version='18.6', connected=True, tls=pg['tls'])
    else:
        require(set(pg) == {'connected'})
    if redis['connected']:
        require(set(redis) == {'connected', 'tls', 'sections'} and redis['tls'] is True and isinstance(redis['sections'], list) and len(redis['sections']) == 4)
        server, memory, persistence, keyspace = [aggregate(s) for s in redis['sections']]
        require(re.fullmatch(r'8\.6\.[0-9]+', server.get('redis_version', '')))
        keys = 0
        for name, values in keyspace.items():
            require(re.fullmatch(r'db[0-9]+', name))
            pairs = [item.partition('=') for item in values.split(',')]
            require(all(separator for _, separator, _ in pairs))
            fields = {key: value for key, _, value in pairs}
            require(len(fields) == len(pairs) and set(fields) in ({'keys', 'expires', 'avg_ttl'}, {'keys', 'expires', 'avg_ttl', 'subexpiry'}))
            keys += metric(fields['keys'])
            metric(fields['expires']); metric(fields['avg_ttl'])
            if 'subexpiry' in fields:
                metric(fields['subexpiry'])
        require(keys <= 9007199254740991)
        cache.update(version=server['redis_version'], connected=True, tls=True, aof=persistence.get('aof_enabled') == '1',
                     keyCount=keys, usedBytes=metric(memory.get('used_memory')), maxBytes=metric(memory.get('maxmemory')))
    else:
        require(set(redis) == {'connected'})
    return database, cache


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def api_health():
    try:
        opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        request = urllib.request.Request('https://api.scriptastudents.com/api/health',
                                         headers={'Accept': 'application/json', 'User-Agent': 'ScriptaServiceObserver/1.0'})
        with opener.open(request, timeout=4) as response:
            body = response.read(8193)
            require(response.status == 200 and len(body) <= 8192)
            value = json.loads(body)
            return value == {'status': 'ok', 'app': 'scriptastudents', 'version': '1.0.0', 'postgres': 'ok', 'redis': 'ok'}
    except Exception:
        return False


def native_probe(backend):
    if not backend['Running'] or backend['Paused']:
        return native_metadata({'database': {'connected': False}, 'redis': {'connected': False}})
    raw = run(DOCKER + ['exec', '-i', backend['Id'], 'node', '--max-old-space-size=64', '-'], NATIVE_PROBE, timeout=15)
    return native_metadata(json.loads(raw))


def resources(profile):
    names = {m['Name'] for p in profile['pins'] for m in p['mounts'] if m['Type'] == 'volume'}
    require(profile.get('volumeCount') == 13 and len(names) == 13)
    ids = ['volume-' + name.replace('_', '-') for name in sorted(names)] + ['host-config', 'runtime-images', 'scriptastudents-persistent']
    if profile.get('workcalendarRuntime'):ids.append('workcalendar-persistent')
    return [{'id': 'platform-state:' + name, 'externalId': name, 'kind': 'platform-state', 'projectId': 'platform', 'name': name} for name in ids]


def resource_set(value):
    require(isinstance(value, list) and len({r['id'] for r in value}) == len(value))
    return canonical(sorted(value, key=lambda r: r['id']))


def verify_manifest(manifest):
    with tempfile.NamedTemporaryFile(prefix='manifest-', suffix='.json', dir=SCRATCH) as file:
        os.chmod(file.name, 0o600)
        file.write(canonical(manifest)); file.flush()
        reply = run(['node', str(INSTALL / 'native-manifest.mjs'), 'verify', file.name, str(CONFIG / 'manifest-key')])
    return json.loads(reply)


def backup_coverage(catalog, profile, profile_sha, offsite, verify=verify_manifest, now=None):
    require(isinstance(catalog, dict) and catalog.get('host') == 'platform-server-public'
            and catalog.get('schema') == 'platform.vps-backup-catalog/v1' and catalog.get('restoreProfileDigest') == profile_sha
            and resource_set(catalog.get('resources')) == resource_set(resources(profile)))
    timestamp(catalog.get('updatedAt'), now)
    points = catalog.get('points')
    require(isinstance(points, list) and len(points) <= 6)
    covered = {'covered': False, 'offsiteVerified': False, 'manifestId': None, 'verifiedAt': None}
    current = resource_set(resources(profile))
    preceding=resource_set([r for r in resources(profile)if r['id']!='platform-state:workcalendar-persistent'])
    genesis=resource_set([r for r in resources(profile)if r['id']not in('platform-state:scriptastudents-persistent','platform-state:workcalendar-persistent')])
    for point in points:
        require(isinstance(point, dict) and point.get('offsiteVerified') is True)
        timestamp(point.get('verifiedAt'), now)
        manifest = point.get('manifest')
        require(isinstance(manifest, dict) and isinstance(manifest.get('id'), str) and MANIFEST.fullmatch(manifest['id']))
        if manifest.get('scope') == {'kind': 'application', 'id': 'scriptastudents'}:
            require(profile.get('scriptaManagement', {}).get('projectId') == 'scriptastudents')
            proof = verify(manifest)
            require(proof.get('manifestId') == manifest['id'] and proof.get('manifestDigest') == manifest.get('signature', {}).get('digest')
                    and proof.get('coverageComplete') is True and proof.get('artifactCount') == len(manifest.get('resources', [])))
            continue  # An application point never proves full-platform coverage.
        if manifest.get('scope')=={'kind':'application','id':'workcalendar'}:
            require(profile.get('workcalendarManagement',{}).get('projectId')=='workcalendar')
            proof=verify(manifest)
            require(proof.get('manifestId')==manifest['id']and proof.get('manifestDigest')==manifest.get('signature',{}).get('digest')and proof.get('coverageComplete')is True and proof.get('artifactCount')==len(manifest.get('resources',[])))
            continue
        scope = resource_set(manifest.get('resources'))
        require(scope in (current, preceding, genesis))
        proof = verify(manifest)
        require(proof.get('manifestId') == manifest['id'] and proof.get('manifestDigest') == manifest.get('signature', {}).get('digest')
                and proof.get('coverageComplete') is True and proof.get('artifactCount') == len(manifest['resources']))
        if scope != current or point.get('restoreCompatible') is False or not offsite or offsite.get('manifestId') != manifest['id']:
            continue
        require(offsite.get('schema') == 'platform.ftps-recovery-point/v2' and offsite.get('host') == 'platform-server-public'
                and offsite.get('status') == 'passed' and offsite.get('manifestDigest') == proof['manifestDigest']
                and offsite.get('artifactCount') == len(resources(profile)) and offsite.get('bundle') == 'backup-' + manifest['id'] + '.tar.gpg'
                and offsite.get('remoteFolder') == '/platform-server-public-backups'
                and all(offsite.get(k) is True for k in ('tlsVerified', 'outsidePublicHtml', 'actualDownloadVerified', 'decryptVerified', 'manifestHmacVerified', 'everyArtifactShaAndHmacVerified'))
                and offsite.get('productionModified') is False)
        timestamp(offsite.get('verifiedAt'), now)
        require(point['verifiedAt'] == offsite['verifiedAt'])
        covered = {'covered': True, 'offsiteVerified': True, 'manifestId': manifest['id'], 'verifiedAt': offsite['verifiedAt']}
    return covered


def document(profile_sha, rows, metadata, reachable, backup):
    database, redis = metadata
    return {'schema': 'platform.observed-applications/v1', 'host': 'platform-server-public', 'profileSha256': profile_sha,
            'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'application': {
                'id': 'scripta-students', 'name': 'Scripta Students', 'version': '1.0', 'apiOrigin': 'https://api.scriptastudents.com',
                'siteOrigin': 'https://scriptastudents.com', 'apiReachable': reachable,
                'services': [{'name': r['Name'].lstrip('/'), 'containerId': r['Id'], 'image': r['Image'],
                              'running': r['Running'] and not r['Paused'], 'health': r['Health'], 'restartCount': r['RestartCount']} for r in rows],
                'database': database, 'redis': redis, 'backup': backup}}


def atomic_publication(body, expected_old, recheck):
    target = PUBLIC / 'applications-observed.json'
    fd, name = tempfile.mkstemp(prefix='.applications-observed-', dir=PUBLIC)
    temporary = pathlib.Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(canonical(body)); stream.flush(); os.fsync(stream.fileno())
            os.fchown(stream.fileno(), 0, 1000); os.fchmod(stream.fileno(), 0o640); os.fsync(stream.fileno())
        recheck()
        actual = sha_bytes(read(target, 65536)) if target.exists() or target.is_symlink() else None
        require(actual == expected_old)
        os.replace(temporary, target)
        descriptor = os.open(PUBLIC, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def publish():
    require(os.geteuid() == 0)
    os.umask(0o077)
    protected(CONFIG, directory=True, private=True)
    protected(WORK, directory=True, private=True)
    protected(PUBLIC, directory=True)
    info = PUBLIC.lstat()
    require(info.st_gid == 1000 and stat.S_IMODE(info.st_mode) == 0o750)
    SCRATCH.mkdir(mode=0o700, exist_ok=True)
    protected(SCRATCH, directory=True, private=True)
    for path in (INSTALL / 'native-manifest.mjs', INSTALL.parent.parent / 'control-center/backup/contracts.mjs'):
        protected(path)
        for parent in path.parents:
            protected(parent, directory=True)
    for name in ('manifest-key', 'profile.sig'):
        protected(CONFIG / name, private=True)
    protected(CONFIG / 'authority-public.pem')
    lock_path = protected(WORK / 'operation.lock', private=True)
    with os.fdopen(os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {'status': 'skipped', 'reason': 'backup-operation-active'}
        require(not (WORK / 'paused.json').exists() and not (WORK / 'paused.json').is_symlink())
        journal = WORK / 'production-restore.json'
        if journal.exists() or journal.is_symlink():
            value = json.loads(read(journal, private=True))
            require(value.get('status') in ('done', 'rolled-back') and value.get('runtimeHealthVerified') is True)
        profile_bytes = read(CONFIG / 'profile.json', private=True)
        signature = read(CONFIG / 'profile.sig', private=True)
        profile = json.loads(profile_bytes)
        expected = validate_profile(profile, sha_bytes(pathlib.Path('/etc/machine-id').read_bytes()))
        run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(CONFIG / 'authority-public.pem'), '-rawin', '-in', str(CONFIG / 'profile.json'), '-sigfile', str(CONFIG / 'profile.sig')])
        profile_sha = sha_bytes(profile_bytes)
        rows = inspect(expected, profile.get('scriptaManagement'))
        catalog_bytes = read(PUBLIC / 'catalog.json')
        full_receipt = WORK / 'latest-full-offsite.json'
        offsite_path = full_receipt if full_receipt.exists() else WORK / 'latest-offsite.json'
        offsite_bytes = read(offsite_path, private=True) if offsite_path.exists() or offsite_path.is_symlink() else None
        catalog = json.loads(catalog_bytes)
        backup = backup_coverage(catalog, profile, profile_sha, json.loads(offsite_bytes) if offsite_bytes else None)
        target = PUBLIC / 'applications-observed.json'
        previous = sha_bytes(read(target, 65536)) if target.exists() or target.is_symlink() else None
        started = time.monotonic()
        backend = next(r for r in rows if r['Name'] == '/node-scriptastudents')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            metrics = pool.submit(native_probe, backend)
            api = pool.submit(api_health)
            metadata, reachable = metrics.result(), api.result()
        require(time.monotonic() - started < 25)
        def recheck():
            require(read(CONFIG / 'profile.json', private=True) == profile_bytes and read(CONFIG / 'profile.sig', private=True) == signature
                    and read(PUBLIC / 'catalog.json') == catalog_bytes)
            current_offsite = read(offsite_path, private=True) if offsite_path.exists() or offsite_path.is_symlink() else None
            require(current_offsite == offsite_bytes)
            inspect(expected, profile.get('scriptaManagement'))
            check_dir = protected(PUBLIC, directory=True).lstat()
            require(check_dir.st_gid == 1000 and stat.S_IMODE(check_dir.st_mode) == 0o750)
        observation = document(profile_sha, rows, metadata, reachable, backup)
        atomic_publication(observation, previous, recheck)
        return {'status': 'published', 'application': 'scripta-students', 'profileSha256': profile_sha,
                'observedAt': observation['observedAt'], 'services': 4, 'offsiteVerified': backup['offsiteVerified'], 'management': 'external-readonly'}


if __name__ == '__main__':
    try:
        print(json.dumps(publish()))
    except Exception as error:
        print(json.dumps({'status': 'refused', 'class': type(error).__name__, 'management': 'external-readonly'}))
        raise SystemExit(1)
