#!/usr/bin/env python3
"""Root-owned, opt-in application cloning and health-gated private activation."""
import concurrent.futures
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import shutil
import socket
import socketserver
import sqlite3
import stat
import subprocess
import threading
import time
import uuid

PROFILE = '/etc/platform-infrastructure/application-operator.json'
STATE = Path('/var/lib/platform-application-operator')
SOCKET = '/run/platform-application-operator/operator.sock'
ID = re.compile(r'[a-z][a-z0-9-]{0,47}')
DBID = re.compile(r'[a-z][a-z0-9_]{0,47}')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}')

class Rejected(Exception):
    pass

class Cancelled(Exception):
    pass


def exact(obj, keys):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise Rejected('Invalid fields')


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise Rejected('Invalid application ID')
    return value


def relative(value):
    if not isinstance(value, str) or not value or '\\' in value:
        raise Rejected('Invalid relative path')
    p = PurePosixPath(value)
    if p.is_absolute() or any(x in ('', '.', '..') for x in value.split('/')):
        raise Rejected('Invalid relative path')
    return value


def protected(path, directory=False):
    p = Path(path)
    if not p.is_absolute() or str(p) != str(path) or p.resolve() != p:
        raise Rejected('Redirected configuration path')
    for item in [p, *p.parents]:
        s = item.lstat()
        if s.st_uid != 0 or s.st_mode & 0o022 or stat.S_ISLNK(s.st_mode):
            raise Rejected('Path must be root-owned and protected')
    s = p.stat()
    if directory and not stat.S_ISDIR(s.st_mode):
        raise Rejected('Expected directory')
    if not directory and (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size > 1048576):
        raise Rejected('Invalid configuration file')
    return p


def encryption_path(binding):
    path = Path(binding['sourcePath'])
    if not path.is_absolute() or str(path) != binding['sourcePath'] or path.resolve() != path:
        raise Rejected('Encryption secret path is redirected')
    protected(path.parent, directory=True)
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != binding['ownerUid'] or s.st_mode & 0o022 or s.st_nlink != 1 or not 16 <= s.st_size <= 16384:
        raise Rejected('Encryption secret admission metadata changed')
    return path


def load_profile():
    p = protected(PROFILE)
    with p.open() as f:
        config = json.load(f)
    required_config = {'version', 'peerUid', 'peerContainerId', 'cloneRoot', 'routingNetwork', 'ingress', 'apps'}
    if not isinstance(config, dict) or not required_config <= set(config) or set(config) - required_config - {'cloneRecoveryAdmitted'}:
        raise Rejected('Invalid root operator profile fields')
    if type(config.get('cloneRecoveryAdmitted', False)) is not bool:
        raise Rejected('Clone recovery admission must be a root-reviewed boolean')
    if config['version'] != 1 or type(config['peerUid']) is not int or config['peerUid'] < 1:
        raise Rejected('Invalid profile version or peer UID')
    if not isinstance(config['peerContainerId'], str) or not re.fullmatch(r'[a-f0-9]{64}', config['peerContainerId']):
        raise Rejected('Full admitted Control Center container identity required')
    root = protected(config['cloneRoot'], directory=True)
    if str(root) != '/var/lib/platform-application-operator/clones':
        raise Rejected('Clone root must be the operator-owned directory')
    if not isinstance(config['routingNetwork'], str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,80}', config['routingNetwork']):
        raise Rejected('Explicit internal routing network required')
    ingress = config['ingress']
    exact(ingress, ['container', 'containerId', 'imageId', 'configRoot'])
    identifier(ingress['container'])
    if not re.fullmatch(r'[a-f0-9]{64}', ingress['containerId']) or not DIGEST.fullmatch(ingress['imageId']) or ingress['configRoot'] != '/var/lib/platform-application-operator/ingress':
        raise Rejected('Invalid admitted private ingress')
    protected(ingress['configRoot'], directory=True)
    if not isinstance(config['apps'], dict):
        raise Rejected('Invalid application registry')
    for name, app in config['apps'].items():
        identifier(name)
        required = {'container', 'containerId', 'imageId', 'domain', 'baseDomain', 'sourceRoot', 'include',
                    'exclude', 'sqlite', 'dataRoots', 'database', 'runtime'}
        if not isinstance(app, dict) or not required <= set(app) or set(app) - required - {'secretBindings', 'cache', 'frontend'}:
            raise Rejected('Invalid application admission fields')
        identifier(app['container'])
        if not re.fullmatch(r'[a-f0-9]{64}', app['containerId']) or not DIGEST.fullmatch(app['imageId']):
            raise Rejected('Missing admitted container/image identity')
        if not re.fullmatch(r'(?=.{1,200}$)[a-z0-9]+(?:[.-][a-z0-9]+)+', app['domain']):
            raise Rejected('Invalid source domain')
        if not re.fullmatch(r'(?=.{1,200}$)[a-z0-9]+(?:[.-][a-z0-9]+)+', app['baseDomain']) or not (app['domain'] == app['baseDomain'] or app['domain'].endswith('.' + app['baseDomain'])):
            raise Rejected('Domain must belong to admitted base domain')
        src = Path(app['sourceRoot'])
        if not src.is_absolute() or src.resolve() != src or not src.is_dir() or root == src or root in src.parents or src in root.parents:
            raise Rejected('Source and destination roots overlap or are redirected')
        for key in ('include', 'exclude', 'sqlite'):
            if not isinstance(app[key], list) or any(not isinstance(x, str) for x in app[key]):
                raise Rejected('Invalid file manifest')
            for x in app[key]: relative(x)
        if not app['include']:
            raise Rejected('An explicit source allowlist is required')
        if not isinstance(app['dataRoots'], list): raise Rejected('Explicit persistent data root manifest required')
        destinations = set()
        for data in app['dataRoots']:
            exact(data, ['sourceRoot', 'mountPath', 'include', 'exclude', 'sqlite'])
            data_root = Path(data['sourceRoot'])
            if not data_root.is_absolute() or data_root.resolve() != data_root or not data_root.is_dir() or root == data_root or root in data_root.parents or data_root in root.parents:
                raise Rejected('Invalid persistent source root')
            if not re.fullmatch(r'/application-data/[a-z][a-z0-9-]{0,47}', data['mountPath']) or data['mountPath'] in destinations:
                raise Rejected('Persistent clone mounts must be unique application-data children')
            destinations.add(data['mountPath'])
            for key in ('include', 'exclude', 'sqlite'):
                if not isinstance(data[key], list): raise Rejected('Invalid persistent file manifest')
                for item in data[key]: relative(item)
            if not data['include']: raise Rejected('Empty persistent file allowlist')
        runtime = app['runtime']
        exact(runtime, ['argv', 'uid', 'gid', 'environment', 'mountPath', 'databaseBinding', 'healthcheck', 'port'])
        if not isinstance(runtime['argv'], list) or not runtime['argv'] or any(not isinstance(x, str) or '\x00' in x for x in runtime['argv']):
            raise Rejected('Invalid admitted foreground command')
        if type(runtime['port']) is not int or not 1 <= runtime['port'] <= 65535:
            raise Rejected('Explicit application HTTP port required')
        if not runtime['argv'][0].startswith('/'):
            raise Rejected('An absolute admitted executable is required')
        if any(type(runtime[k]) is not int or runtime[k] < 1 for k in ('uid', 'gid')):
            raise Rejected('Non-root runtime identity required')
        if runtime['mountPath'] != '/application' or not isinstance(runtime['environment'], dict):
            raise Rejected('Invalid runtime projection')
        # This is a public, reviewed configuration only, never source-container Env.
        for k, v in runtime['environment'].items():
            if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', k) or not isinstance(v, str) or '\x00' in v or re.search(r'PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|DSN|URL', k):
                raise Rejected('Secrets and endpoints cannot be inherited in environment')
        if not isinstance(runtime['healthcheck'], list) or not runtime['healthcheck'] or not runtime['healthcheck'][0].startswith('/') or any(not isinstance(x, str) or '\x00' in x for x in runtime['healthcheck']):
            raise Rejected('Explicit executable healthcheck required')
        binding = runtime['databaseBinding']
        if binding is not None:
            exact(binding, ['environmentName', 'format'])
            if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,55}_FILE', binding['environmentName']) or binding['format'] not in ('postgres-url', 'mysql-url'):
                raise Rejected('Only new FILE database credentials may be projected')
        db = app['database']
        bindings = app.get('secretBindings', [])
        if not isinstance(bindings, list) or len(bindings) > 4:
            raise Rejected('Invalid encryption secret admission')
        names = {binding['environmentName']} if binding else set()
        for secret in bindings:
            exact(secret, ['sourcePath', 'environmentName', 'purpose', 'ownerUid'])
            envname = secret['environmentName']
            if secret['purpose'] != 'data-encryption' or not isinstance(envname, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,55}_FILE', envname) or not re.search(r'ENCRYPTION|ACCOUNT_SECRET|DATA_KEY', envname) or re.search(r'SMTP|OPENAI|GROQ|APNS|OAUTH|GOOGLE|APPLE|TOKEN', envname) or envname in names:
                raise Rejected('Only explicitly admitted at-rest encryption FILE secrets may be retained')
            names.add(envname)
            if type(secret['ownerUid']) is not int or secret['ownerUid'] not in (0, runtime['uid']):
                raise Rejected('Encryption file owner must be explicitly root-admitted')
            encryption_path(secret)
        cache = app.get('cache')
        if cache is not None:
            exact(cache, ['container', 'containerId', 'imageId', 'environmentName'])
            identifier(cache['container'])
            if not re.fullmatch(r'[a-f0-9]{64}', cache['containerId']) or not DIGEST.fullmatch(cache['imageId']) or cache['environmentName'] != 'STUDENTS_REDIS_URL_FILE' or cache['environmentName'] in names:
                raise Rejected('Pinned fresh Redis FILE admission required')
        frontend = app.get('frontend')
        if frontend is not None:
            exact(frontend, ['container', 'containerId', 'imageId', 'sourceRoot', 'include', 'exclude', 'sitePath', 'indexPath', 'uid', 'gid'])
            identifier(frontend['container'])
            if not re.fullmatch(r'[a-f0-9]{64}', frontend['containerId']) or not DIGEST.fullmatch(frontend['imageId']) or any(type(frontend[k]) is not int or frontend[k] < 1 for k in ('uid', 'gid')):
                raise Rejected('Invalid static companion admission')
            site = Path(frontend['sourceRoot'])
            if not site.is_absolute() or site.resolve() != site or not site.is_dir() or root == site or root in site.parents or site in root.parents:
                raise Rejected('Invalid static source root')
            for key in ('include', 'exclude'):
                if not isinstance(frontend[key], list): raise Rejected('Invalid static manifest')
                for item in frontend[key]: relative(item)
            if not frontend['include']: raise Rejected('Static copy allowlist required')
            for key in ('sitePath', 'indexPath'):
                relative(frontend[key])
                if not re.fullmatch(r'[A-Za-z0-9_./-]+', frontend[key]) or not any(frontend[key] == item or frontend[key].startswith(item + '/') for item in frontend['include']):
                    raise Rejected('Static serving paths must belong to the copy allowlist')
        if db is not None:
            exact(db, ['engine', 'container', 'containerId', 'imageId', 'name'])
            if db['engine'] not in ('postgres', 'mariadb') or not DBID.fullmatch(db['name']):
                raise Rejected('Unsupported database projection')
            if not DIGEST.fullmatch(db['imageId']) or binding is None or binding['format'] != ('postgres-url' if db['engine'] == 'postgres' else 'mysql-url'):
                raise Rejected('Pinned DB image and matching FILE binding required')
            identifier(db['container'])
            if not re.fullmatch(r'[a-f0-9]{64}', db['containerId']):
                raise Rejected('Database container pin required')
    return config


def run(argv, data=None, output=None, timeout=600):
    """No shell evaluation on the host; never return command stderr or secrets."""
    try:
        p = subprocess.run(argv, input=data, stdout=output if output is not None else subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                           env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    except (OSError, subprocess.TimeoutExpired):
        raise Rejected('Native operation unavailable or timed out') from None
    if p.returncode:
        raise Rejected('Native operation failed; destination retained for operator inspection')
    return p.stdout


def inspect_container(name, expected):
    info = json.loads(run(['docker', 'inspect', name]))[0]
    if info['Name'] != '/' + name or info['Id'] != expected:
        raise Rejected('Registered container identity changed')
    return info


def plan(config, source, target):
    if config.get('cloneRecoveryAdmitted', False) is not True:
        raise Rejected('Clone recovery has not been root-admitted')
    identifier(source); identifier(target)
    if source == target or source not in config['apps'] or target in config['apps']:
        raise Rejected('Source must be registered and destination must be new')
    app = config['apps'][source]
    current = inspect_container(app['container'], app['containerId'])
    if current['Image'] != app['imageId'] or not current['State']['Running']:
        raise Rejected('Admitted source must be current and running')
    declared = {app['sourceRoot'], *(d['sourceRoot'] for d in app['dataRoots'])}
    mounted = {m.get('Source') for m in current.get('Mounts', []) if m.get('Type') in ('bind', 'volume')}
    writable = {m.get('Source') for m in current.get('Mounts', []) if m.get('Type') in ('bind', 'volume') and m.get('RW')}
    if not declared <= mounted or not writable <= declared:
        raise Rejected('Source/persistent mounts differ from explicit registered copy roots')
    image = json.loads(run(['docker', 'image', 'inspect', app['imageId']]))[0]
    if image.get('Config', {}).get('Volumes'):
        raise Rejected('Images with implicit volumes cannot be projected')
    if app['database']:
        db = app['database']
        dbinfo = inspect_container(db['container'], db['containerId'])
        if dbinfo['Image'] != db['imageId'] or not dbinfo['State']['Running']:
            raise Rejected('Database source identity changed')
    for secret in app.get('secretBindings', []):
        src = Path(secret['sourcePath'])
        if not any(m.get('RW') is False and (src == Path(m.get('Source', '')) or Path(m.get('Source', '')) in src.parents) for m in current.get('Mounts', []) if m.get('Type') == 'bind'):
            raise Rejected('Encryption secret is not an admitted read-only source mount')
    if app.get('cache'):
        cache = app['cache']
        info = inspect_container(cache['container'], cache['containerId'])
        if info['Image'] != cache['imageId'] or not info['State']['Running']:
            raise Rejected('Redis source image identity changed')
        image = json.loads(run(['docker', 'image', 'inspect', cache['imageId']]))[0]
        if not set((image.get('Config') or {}).get('Volumes') or {}) <= {'/data'}:
            raise Rejected('Redis image has unreviewed implicit volumes')
    if app.get('frontend'):
        frontend = app['frontend']
        info = inspect_container(frontend['container'], frontend['containerId'])
        if info['Image'] != frontend['imageId'] or not info['State']['Running']:
            raise Rejected('Static companion source identity changed')
        for item in frontend['include']:
            included = Path(frontend['sourceRoot']) / item
            if not any(m.get('RW') is False and (included == Path(m.get('Source', '')) or Path(m.get('Source', '')) in included.parents) for m in info.get('Mounts', []) if m.get('Type') == 'bind'):
                raise Rejected('Static allowlist differs from admitted read-only mounts')
        image = json.loads(run(['docker', 'image', 'inspect', frontend['imageId']]))[0]
        if (image.get('Config') or {}).get('Volumes'):
            raise Rejected('Static image has unreviewed implicit volumes')
    net = json.loads(run(['docker', 'network', 'inspect', config['routingNetwork']]))[0]
    if net.get('Internal') is not True:
        raise Rejected('Routing network must be internal; public egress is forbidden')
    return {'sourceId': source, 'targetId': target, 'domain': ('local.' if app['domain'] == app['baseDomain'] else 'local-') + app['domain'],
            'imageId': app['imageId'], 'containerName': 'clone-' + target,
            'network': 'clone-' + target, 'egressEnabled': False, 'startsWorkload': False,
            'publication': 'not-published', 'databaseEngine': app['database']['engine'] if app['database'] else None}


def forbidden(rel, exclusions):
    parts = PurePosixPath(rel).parts
    if any(x == '.git' or x.startswith('.env') or x.lower().endswith(('.pem', '.key', '.p12', '.pfx')) for x in parts):
        return True
    return any(rel == x or rel.startswith(x + '/') for x in exclusions)


def copy_tree(source, destination, includes, exclusions, sqlite_paths, check):
    """Walk descriptor-relative: reject symlinks, devices, sockets and hard links."""
    destination.mkdir(mode=0o700)
    rootfd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    db_exclusions = [p + suffix for p in sqlite_paths for suffix in ('', '-wal', '-shm', '-journal')]
    def walk(fd, name, rel):
        check()
        if forbidden(rel, exclusions + db_exclusions): return
        s = os.stat(name, dir_fd=fd, follow_symlinks=False)
        dst = destination / rel
        if stat.S_ISDIR(s.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                dst.mkdir(mode=0o700, parents=True, exist_ok=True)
                for item in sorted(os.listdir(child)): walk(child, item, rel + '/' + item)
            finally: os.close(child)
        elif stat.S_ISREG(s.st_mode) and s.st_nlink == 1:
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                actual = os.fstat(child)
                if not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1:
                    raise Rejected('Source file identity changed')
                dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with os.fdopen(child, 'rb', closefd=False) as inp, dst.open('xb') as out:
                    while True:
                        check(); chunk = inp.read(1024 * 1024)
                        if not chunk: break
                        out.write(chunk)
                os.chmod(dst, 0o700 if s.st_mode & 0o111 else 0o600)
            finally: os.close(child)
        else: raise Rejected('Source contains a symlink, hard link or special file')
    try:
        for rel in includes:
            relative(rel)
            fd = os.dup(rootfd)
            try:
                for part in PurePosixPath(rel).parts[:-1]:
                    nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd); fd = nxt
                walk(fd, PurePosixPath(rel).name, rel)
            finally: os.close(fd)
        for rel in sqlite_paths:
            check(); relative(rel)
            if forbidden(rel, exclusions): raise Rejected('SQLite path excluded by policy')
            src = Path(source) / rel
            protected(src.parent, directory=True)
            if src.resolve() != src or not src.is_file() or src.stat().st_nlink != 1:
                raise Rejected('SQLite source is redirected')
            dst = destination / rel
            dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with contextlib.closing(sqlite3.connect(src.as_uri() + '?mode=ro', uri=True)) as inp:
                with contextlib.closing(sqlite3.connect(dst)) as out:
                    inp.backup(out, pages=256, progress=lambda *_: check(), sleep=0.01)
            os.chmod(dst, 0o600)
    finally: os.close(rootfd)


# Static shell adapters execute only installed DB clients and native FILE credentials.
MARIA_ADMIN = 'export MYSQL_PWD="$(cat "$MARIADB_ROOT_PASSWORD_FILE")"; exec mariadb --protocol=socket -uroot --batch --skip-column-names'
MARIA_DUMP = 'export MYSQL_PWD="$(cat "$MARIADB_ROOT_PASSWORD_FILE")"; exec mariadb-dump --protocol=socket -uroot --single-transaction --skip-lock-tables --skip-triggers --skip-add-locks --skip-comments "$1"'
PG_RESTORE = 'IFS= read -r PGPASSWORD; export PGPASSWORD; exec pg_restore -h 127.0.0.1 -U "$1" -d "$2" --no-owner --no-acl --exit-on-error'
MARIA_RESTORE = 'IFS= read -r MYSQL_PWD; export MYSQL_PWD; exec mariadb -h 127.0.0.1 -u "$1" "$2"'


def database_clone(db, jobid, directory, network, check):
    name = 'clone_' + uuid.UUID(jobid).hex
    container = 'clone-db-' + uuid.UUID(jobid).hex
    password = secrets.token_hex(32)
    admin_password = secrets.token_hex(32)
    credentials = {'engine': db['engine'], 'database': name, 'username': name, 'password': password, 'hostname': container}
    with (directory / 'database.json').open('x') as f:
        os.chmod(f.name, 0o600); json.dump(credentials, f)
    admin_file = directory / 'database-admin-password'
    admin_file.write_text(admin_password); admin_file.chmod(0o400)
    data_dir = directory / 'database-data'; data_dir.mkdir(mode=0o700)
    source = db['container']; inspect_container(source, db['containerId']); check()
    dump = directory / 'database.snapshot'
    engine = db['engine']
    with dump.open('xb') as out:
        os.chmod(dump, 0o600)
        if engine == 'postgres':
            run(['docker', 'exec', '-u', 'postgres', source, 'pg_dump', '-U', 'postgres', '-d', db['name'], '-Fc', '--no-owner', '--no-acl'], output=out)
        else:
            # Only transactional tables give a consistent single-transaction snapshot.
            query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='" + db['name'] + "' AND table_type='BASE TABLE' AND engine <> 'InnoDB';"
            count = run(['docker', 'exec', '-i', source, 'sh', '-c', MARIA_ADMIN], data=query.encode()).strip()
            if count != b'0': raise Rejected('MariaDB source has non-transactional tables')
            query = "SELECT (SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema='" + db['name'] + "') + (SELECT COUNT(*) FROM information_schema.routines WHERE routine_schema='" + db['name'] + "') + (SELECT COUNT(*) FROM information_schema.events WHERE event_schema='" + db['name'] + "');"
            if run(['docker', 'exec', '-i', source, 'sh', '-c', MARIA_ADMIN], data=query.encode()).strip() != b'0':
                raise Rejected('MariaDB routines, triggers or events need an explicit reviewed adapter')
            run(['docker', 'exec', source, 'sh', '-c', MARIA_DUMP, 'dump', db['name']], output=out)
    check()
    image = json.loads(run(['docker', 'image', 'inspect', db['imageId']]))[0]
    volumes = set((image.get('Config') or {}).get('Volumes') or {})
    allowed = {'/var/lib/postgresql', '/var/lib/postgresql/data'} if engine == 'postgres' else {'/var/lib/mysql'}
    if not volumes <= allowed or len(volumes) > 1: raise Rejected('Database image has unreviewed implicit volumes')
    target = next(iter(volumes), '/var/lib/postgresql' if engine == 'postgres' else '/var/lib/mysql')
    # Hardened engine entrypoints may drop privilege before initializing the
    # bind mount. Resolve the native account from the admitted image itself.
    account = 'postgres' if engine == 'postgres' else 'mysql'
    owner = []
    for flag in ('-u', '-g'):
        value = run(['docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
                     '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                     '--label', 'platform.application-clone=' + jobid,
                     '--entrypoint', '/usr/bin/id', db['imageId'], flag, account], timeout=15).strip()
        if not re.fullmatch(rb'[1-9][0-9]{0,8}', value):
            raise Rejected('Database image must expose a non-root native account')
        owner.append(int(value))
    os.chown(data_dir, *owner)
    args = ['docker', 'create', '--pull', 'never', '--name', container, '--network', network, '--restart', 'no',
            '--label', 'platform.application-clone=' + jobid, '--security-opt', 'no-new-privileges:true',
            '--memory', '1g', '--cpus', '1', '--pids-limit', '256',
            '--mount', f'type=bind,src={admin_file},dst=/run/clone-admin-password,readonly',
            '--mount', f"type=bind,src={data_dir},dst={target}"]
    # DB images are separately root-admitted; never clone source HostConfig or Env.
    if engine == 'postgres':
        args += ['--env', 'POSTGRES_PASSWORD_FILE=/run/clone-admin-password', '--env', 'POSTGRES_USER=postgres', '--env', 'POSTGRES_DB=postgres', '--env', 'PGDATA=' + target + '/clone-data', '--env', 'POSTGRES_HOST_AUTH_METHOD=scram-sha-256']
    else:
        args += ['--env', 'MARIADB_ROOT_PASSWORD_FILE=/run/clone-admin-password']
    args += [db['imageId']]
    cid = run(args).decode().strip()
    if not re.fullmatch(r'[a-f0-9]{64}', cid): raise Rejected('Unexpected database container identity')
    run(['docker', 'start', container]); check()
    ready = False
    for _ in range(60):
        check()
        try:
            if engine == 'postgres':
                run(['docker', 'exec', '-u', 'postgres', container, 'psql', '-X', '-U', 'postgres', '-d', 'postgres', '-tAc', 'SELECT 1'], timeout=5)
            else:
                run(['docker', 'exec', '-i', container, 'sh', '-c', MARIA_ADMIN], data=b'SELECT 1;', timeout=5)
            ready = True; break
        except Rejected: time.sleep(1)
    if not ready: raise Rejected('Dedicated clone database did not become ready')
    if engine == 'postgres':
        sql = f"CREATE ROLE {name} LOGIN PASSWORD '{password}';\nCREATE DATABASE {name} OWNER {name};\nREVOKE ALL ON DATABASE {name} FROM PUBLIC;\n"
        run(['docker', 'exec', '-i', '-u', 'postgres', container, 'psql', '-X', '-U', 'postgres', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1'], data=sql.encode())
        argv = ['docker', 'exec', '-i', container, 'sh', '-c', PG_RESTORE, 'restore', name, name]
    else:
        sql = f"CREATE DATABASE `{name}`;\nCREATE USER '{name}'@'%' IDENTIFIED BY '{password}';\nGRANT ALL ON `{name}`.* TO '{name}'@'%';\n"
        run(['docker', 'exec', '-i', container, 'sh', '-c', MARIA_ADMIN], data=sql.encode())
        argv = ['docker', 'exec', '-i', container, 'sh', '-c', MARIA_RESTORE, 'restore', name, name]
    check()
    with dump.open('rb') as inp:
        with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as p:
            try:
                p.stdin.write((password + '\n').encode())
                while True:
                    check(); chunk = inp.read(1024 * 1024)
                    if not chunk: break
                    p.stdin.write(chunk)
                p.stdin.close()
                if p.wait(timeout=600): raise Rejected('Database restore failed')
            except BaseException:
                p.kill(); p.wait(); raise
    dump.unlink()
    return {'engine': engine, 'name': name, 'containerId': cid, 'containerName': container}


def fresh_cache(cache, rid, directory, network, uid, gid, check):
    """Fresh ephemeral Redis: no source state, environment or credentials."""
    name = 'clone-cache-' + uuid.UUID(rid).hex
    password = secrets.token_hex(32)
    configdir = directory / 'cache-config'; configdir.mkdir(mode=0o750); os.chown(configdir, 0, gid)
    path = configdir / 'redis.conf'
    path.write_text('bind 0.0.0.0\nport 6379\nprotected-mode yes\nsave ""\nappendonly no\ndir /data\nrequirepass ' + password + '\n')
    path.chmod(0o440); os.chown(path, 0, gid)
    cid = run(['docker', 'create', '--pull', 'never', '--name', name, '--network', network,
               '--read-only', '--user', f'{uid}:{gid}', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges:true', '--pids-limit', '64', '--memory', '128m', '--cpus', '0.5',
               '--restart', 'no', '--label', 'platform.application-clone=' + rid,
               '--tmpfs', '/data:rw,noexec,nosuid,size=64m',
               '--mount', f'type=bind,src={configdir},dst=/run/clone-cache,readonly',
               '--entrypoint', '/usr/local/bin/redis-server', cache['imageId'], '/run/clone-cache/redis.conf']).decode().strip()
    if not re.fullmatch(r'[a-f0-9]{64}', cid): raise Rejected('Unexpected Redis container identity')
    run(['docker', 'start', cid])
    for _ in range(30):
        check()
        try:
            reply = run(['docker', 'exec', '-i', cid, '/usr/local/bin/redis-cli', '-x', 'AUTH'], data=password.encode(), timeout=3)
            if reply.strip() == b'OK':
                return {'containerName': name, 'containerId': cid, 'state': 'fresh-empty'}, f'redis://:{password}@{name}:6379'
        except Rejected: pass
        time.sleep(1)
    raise Rejected('Fresh Redis failed readiness verification')


def static_frontend(frontend, rid, target, directory, network, backend, port, hostname, check):
    copied = directory / 'static-site'
    copy_tree(frontend['sourceRoot'], copied, frontend['include'], frontend['exclude'], [], check)
    for root, dirs, files in os.walk(copied):
        os.chown(root, frontend['uid'], frontend['gid'])
        for name in files: os.chown(Path(root) / name, frontend['uid'], frontend['gid'])
    if not (copied / frontend['sitePath']).is_dir() or not (copied / frontend['indexPath']).is_file():
        raise Rejected('Admitted static site or index was not copied')
    config = directory / 'static-nginx.conf'
    proxy = f'proxy_pass http://{backend}:{port}; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https;'
    config.write_text('pid /tmp/nginx.pid; error_log /dev/stderr; events {} http { include /etc/nginx/mime.types; '
                      'client_body_temp_path /tmp/client; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fastcgi; '
                      'uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi; access_log /dev/stdout; '
                      f'server {{ listen 8080; server_name {hostname}; root /site/{frontend["sitePath"]}; '
                      'location = / { rewrite ^ /__clone_index.html last; } '
                      f'location = /__clone_index.html {{ internal; alias /site/{frontend["indexPath"]}; }} '
                      f'location /api/ {{ {proxy} }} '
                      f'location / {{ try_files $uri @api; }} location @api {{ {proxy} }} }} }}')
    config.chmod(0o644)
    name = 'clone-web-' + target
    cid = run(['docker', 'create', '--pull', 'never', '--name', name, '--network', network,
               '--read-only', '--user', f'{frontend["uid"]}:{frontend["gid"]}', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges:true', '--pids-limit', '64', '--memory', '128m', '--cpus', '0.5',
               '--restart', 'no', '--label', 'platform.application-clone=' + rid,
               '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
               '--mount', f'type=bind,src={copied},dst=/site,readonly',
               '--mount', f'type=bind,src={config},dst=/run/clone-nginx.conf,readonly',
               '--health-cmd', 'exec /usr/bin/wget -q -O /dev/null http://127.0.0.1:8080/',
               '--health-interval', '2s', '--health-timeout', '3s', '--health-retries', '3',
               '--entrypoint', '/usr/sbin/nginx', frontend['imageId'], '-c', '/run/clone-nginx.conf', '-g', 'daemon off;']).decode().strip()
    if not re.fullmatch(r'[a-f0-9]{64}', cid): raise Rejected('Unexpected static companion identity')
    return {'containerName': name, 'containerId': cid, 'port': 8080}


class Operator:
    def __init__(self, config, state=STATE):
        self.config, self.state = config, Path(state)
        self.state.mkdir(mode=0o700, exist_ok=True)
        self.lock = threading.Lock()
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        with self.connection() as c:
            c.execute('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, source TEXT, target TEXT UNIQUE, status TEXT, cancel INTEGER DEFAULT 0, result TEXT)')
            # Never automatically replay an interrupted DB mutation.
            interrupted = c.execute("SELECT id,target FROM jobs WHERE status IN ('queued','running','activating')").fetchall()
            c.execute("UPDATE jobs SET status='interrupted' WHERE status IN ('queued','running','activating')")
        for rid, target in interrupted: self.stop_clones(rid, target)

    @contextlib.contextmanager
    def connection(self):
        c = sqlite3.connect(self.state / 'jobs.sqlite', timeout=10)
        try:
            with c: yield c
        finally: c.close()

    def status(self, request):
        with self.connection() as c:
            row = c.execute('SELECT id,source,target,status,result FROM jobs WHERE id=?', (request,)).fetchone()
        if not row: raise Rejected('Unknown request')
        return dict(zip(['requestId', 'sourceId', 'targetId', 'status', 'result'], [*row[:4], json.loads(row[4]) if row[4] else None]))

    def handle(self, body):
        operation = body.get('operation') if isinstance(body, dict) else None
        if operation == 'list':
            exact(body, ['operation'])
            return {'apps': [{'id': name, 'domain': app['domain'], 'baseDomain': app['baseDomain']} for name, app in sorted(self.config['apps'].items())] if self.config.get('cloneRecoveryAdmitted', False) is True else []}
        if operation == 'activate':
            exact(body, ['operation', 'requestId', 'publication'])
        elif operation in ('status', 'cancel'):
            exact(body, ['operation', 'requestId'])
        elif operation in ('plan', 'clone'):
            exact(body, ['operation', 'requestId', 'sourceId', 'targetId'])
            if self.config.get('cloneRecoveryAdmitted', False) is not True:
                raise Rejected('Clone recovery has not been root-admitted')
        else: raise Rejected('Unsupported operation')
        try:
            rid = str(uuid.UUID(body['requestId']))
        except (ValueError, TypeError, AttributeError): raise Rejected('Invalid request ID')
        if rid != body['requestId']: raise Rejected('Noncanonical request ID')
        if operation == 'status': return self.status(rid)
        if operation == 'activate': return self.activate(rid, body['publication'])
        if operation == 'cancel':
            current = self.status(rid)
            with self.connection() as c: c.execute('UPDATE jobs SET cancel=1 WHERE id=?', (rid,))
            if current['status'] in ('staged', 'available', 'activation_failed'):
                self.stop_clones(rid, current['targetId'])
                self.unpublish(current['targetId'], rid)
                with self.connection() as c: c.execute("UPDATE jobs SET status='cancelled' WHERE id=?", (rid,))
            return self.status(rid)
        source, target = body['sourceId'], body['targetId']
        projection = plan(self.config, source, target)
        if operation == 'plan': return projection
        with self.lock, self.connection() as c:
            old = c.execute('SELECT source,target FROM jobs WHERE id=?', (rid,)).fetchone()
            if old:
                if old != (source, target): raise Rejected('Idempotency key belongs to different request')
            else:
                if (Path(self.config['cloneRoot']) / target).exists(): raise Rejected('Destination already exists')
                try: c.execute('INSERT INTO jobs(id,source,target,status) VALUES (?,?,?,?)', (rid, source, target, 'queued'))
                except sqlite3.IntegrityError: raise Rejected('Destination reserved') from None
                c.commit(); self.pool.submit(self.execute, rid, source, target)
        return self.status(rid)

    def check(self, rid):
        with self.connection() as c:
            if c.execute('SELECT cancel FROM jobs WHERE id=?', (rid,)).fetchone()[0]: raise Cancelled()

    def stop_clones(self, rid, target):
        for name in ('clone-' + target, 'clone-web-' + target, 'clone-db-' + uuid.UUID(rid).hex, 'clone-cache-' + uuid.UUID(rid).hex):
            try:
                info = json.loads(run(['docker', 'inspect', name]))[0]
                if info.get('Config', {}).get('Labels', {}).get('platform.application-clone') == rid:
                    run(['docker', 'stop', '--time', '5', info['Id']], timeout=15)
            except Exception: pass

    def ingress(self):
        config = self.config['ingress']
        info = inspect_container(config['container'], config['containerId'])
        if info['Image'] != config['imageId'] or not info['State']['Running']:
            raise Rejected('Admitted ingress identity changed')
        if not any(m.get('Source') == config['configRoot'] and m.get('Destination') == '/etc/nginx/conf.d' and m.get('RW') is False for m in info.get('Mounts', [])):
            raise Rejected('Ingress configuration mount is not read-only and admitted')
        networks = info.get('NetworkSettings', {}).get('Networks', {})
        bindings = info.get('HostConfig', {}).get('PortBindings', {})
        if set(networks) != {self.config['routingNetwork']} or bindings != {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18181'}]}:
            raise Rejected('Ingress must use only the admitted network and loopback listener')
        net = json.loads(run(['docker', 'network', 'inspect', self.config['routingNetwork']]))[0]
        if net.get('Internal') is not True:
            raise Rejected('Ingress routing network must remain internal')
        return config

    def publish(self, target, hostname, container, port, rid):
        config = self.ingress()
        identifier(target)
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', container): raise Rejected('Invalid clone container')
        if not re.fullmatch(r'(?=.{1,253}$)[a-z0-9]+(?:[.-][a-z0-9]+)+', hostname) or type(port) is not int or not 1 <= port <= 65535:
            raise Rejected('Invalid private route')
        path = Path(config['configRoot']) / ('clone-' + target + '.conf')
        text = (f'# application-clone:{rid}\nserver {{\n listen 8080;\n server_name {hostname};\n'
                f' location / {{ proxy_pass http://{container}:{port}; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }}\n}}\n')
        with path.open('x') as f:
            os.chmod(path, 0o644); f.write(text); f.flush(); os.fsync(f.fileno())
        try:
            run(['docker', 'exec', config['containerId'], 'nginx', '-t'], timeout=10)
            run(['docker', 'exec', config['containerId'], 'nginx', '-s', 'reload'], timeout=10)
        except Exception:
            path.unlink(); raise

    def unpublish(self, target, rid):
        # Never touch a general nginx config or any original application route.
        if 'ingress' not in self.config: return
        identifier(target)
        path = Path(self.config['ingress']['configRoot']) / ('clone-' + target + '.conf')
        if path.exists():
            if path.is_symlink() or not path.is_file(): raise Rejected('Private route path was replaced')
            with path.open('rb') as f:
                if f.readline(128) != ('# application-clone:' + rid + '\n').encode(): raise Rejected('Private route belongs to another request')
            config = self.ingress()
            path.unlink()
            run(['docker', 'exec', config['containerId'], 'nginx', '-t'], timeout=10)
            run(['docker', 'exec', config['containerId'], 'nginx', '-s', 'reload'], timeout=10)

    def activate(self, rid, publication):
        # SO_PEERCRED plus the pinned Docker cgroup authenticate Control Center. The CC
        # owner route must perform provider readback, not forward browser claims.
        exact(publication, ['hostname', 'verifiedAt', 'accessApplicationId'])
        if type(publication['verifiedAt']) not in (float, int) or not 0 <= time.time() - publication['verifiedAt'] <= 60:
            raise Rejected('Fresh private-publication verification required')
        try: uuid.UUID(publication['accessApplicationId'])
        except (ValueError, TypeError, AttributeError): raise Rejected('Access application identity required')
        with self.lock:
            job = self.status(rid)
            if job['status'] == 'available': return job
            if job['status'] != 'staged' or publication['hostname'] != job['result']['domain']:
                raise Rejected('Clone is not staged for this hostname')
            result = job['result']
            net = json.loads(run(['docker', 'network', 'inspect', self.config['routingNetwork']]))[0]
            if net.get('Internal') is not True: raise Rejected('Routing network is not internal')
            info = inspect_container(result['containerName'], result['containerId'])
            if info['Config'].get('Labels', {}).get('platform.application-clone') != rid:
                raise Rejected('Clone ownership changed')
            try:
                self.check(rid)
                with self.connection() as c: c.execute("UPDATE jobs SET status='activating' WHERE id=?", (rid,))
                route = result.get('frontend') or {'containerId': result['containerId'], 'containerName': result['containerName'], 'port': self.config['apps'][job['sourceId']]['runtime']['port']}
                run(['docker', 'network', 'connect', self.config['routingNetwork'], route['containerId']])
                run(['docker', 'start', result['containerId']])
                healthy = False
                for _ in range(60):
                    self.check(rid)
                    current = inspect_container(result['containerName'], result['containerId'])
                    state = current['State']
                    if state.get('Running') and state.get('Health', {}).get('Status') == 'healthy': healthy = True; break
                    if not state.get('Running'): break
                    time.sleep(1)
                if not healthy: raise Rejected('Clone failed its admitted healthcheck')
                if result.get('frontend'):
                    front = result['frontend']
                    info = inspect_container(front['containerName'], front['containerId'])
                    if info.get('Config', {}).get('Labels', {}).get('platform.application-clone') != rid:
                        raise Rejected('Static companion ownership changed')
                    run(['docker', 'start', front['containerId']])
                    healthy = False
                    for _ in range(60):
                        self.check(rid)
                        info = inspect_container(front['containerName'], front['containerId'])
                        if info['State'].get('Running') and info['State'].get('Health', {}).get('Status') == 'healthy': healthy = True; break
                        if not info['State'].get('Running'): break
                        time.sleep(1)
                    if not healthy: raise Rejected('Static companion failed health verification')
                self.check(rid)
                self.publish(job['targetId'], result['domain'], route['containerName'], route['port'], rid)
                self.check(rid)
                result.update({'publication': 'private-access-verified', 'activationRequired': False, 'accessApplicationId': publication['accessApplicationId'], 'publicationVerifiedAt': publication['verifiedAt']})
                with self.connection() as c: c.execute("UPDATE jobs SET status='available',result=? WHERE id=?", (json.dumps(result), rid))
            except Exception:
                self.stop_clones(rid, job['targetId'])
                try: self.unpublish(job['targetId'], rid)
                except Exception: pass
                with self.connection() as c: c.execute("UPDATE jobs SET status='activation_failed' WHERE id=?", (rid,))
                raise Rejected('Activation failed; clone stopped') from None
            return self.status(rid)

    def execute(self, rid, source, target):
        result = None
        try:
            with self.connection() as c: c.execute("UPDATE jobs SET status='running' WHERE id=?", (rid,))
            projection = plan(self.config, source, target); self.check(rid)
            directory = Path(self.config['cloneRoot']) / target
            directory.mkdir(mode=0o700)
            app = self.config['apps'][source]
            check = lambda: self.check(rid)
            copy_tree(app['sourceRoot'], directory / 'application', app['include'], app['exclude'], app['sqlite'], check)
            data_copies = []
            for index, data in enumerate(app['dataRoots']):
                copied = directory / ('persistent-' + str(index))
                copy_tree(data['sourceRoot'], copied, data['include'], data['exclude'], data['sqlite'], check)
                data_copies.append((copied, data['mountPath']))
            network = projection['network']
            run(['docker', 'network', 'create', '--internal', '--label', 'platform.application-clone=' + rid, network])
            db = database_clone(app['database'], rid, directory, network, check) if app['database'] else None
            check()
            runtime = app['runtime']
            cache, cache_url = fresh_cache(app['cache'], rid, directory, network, runtime['uid'], runtime['gid'], check) if app.get('cache') else (None, None)
            argv = ['docker', 'create', '--pull', 'never', '--name', projection['containerName'], '--network', network, '--read-only',
                    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--pids-limit', '128',
                    '--memory', '512m', '--cpus', '1', '--user', f"{runtime['uid']}:{runtime['gid']}",
                    '--restart', 'no', '--label', 'platform.application-clone=' + rid,
                    '--mount', f"type=bind,src={directory / 'application'},dst=/application",
                    '--workdir', '/application', '--entrypoint', runtime['argv'][0]]
            for copied in [directory / 'application', *[item[0] for item in data_copies]]:
                for root, dirs, files in os.walk(copied):
                    os.chown(root, runtime['uid'], runtime['gid'])
                    for name in files: os.chown(Path(root) / name, runtime['uid'], runtime['gid'])
            for copied, mount in data_copies: argv += ['--mount', f'type=bind,src={copied},dst={mount}']
            argv += ['--health-cmd', 'exec ' + shlex.join(runtime['healthcheck']), '--health-interval', '2s', '--health-timeout', '3s', '--health-retries', '3', '--health-start-period', '5s', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m']
            file_environment = {}
            if db or cache or app.get('secretBindings'):
                app_secrets = directory / 'application-credentials'; app_secrets.mkdir(mode=0o750)
                os.chown(app_secrets, 0, runtime['gid'])
                argv += ['--mount', f'type=bind,src={app_secrets},dst=/run/clone-credentials,readonly']
            def credential(filename, value, envname):
                secret = app_secrets / filename
                with secret.open('xb') as out: out.write(value)
                secret.chmod(0o440); os.chown(secret, 0, runtime['gid'])
                file_environment[envname] = '/run/clone-credentials/' + filename
            if db:
                credentials = json.loads((directory / 'database.json').read_text())
                scheme = 'postgresql' if db['engine'] == 'postgres' else 'mysql'
                url = f"{scheme}://{credentials['username']}:{credentials['password']}@{credentials['hostname']}/{credentials['database']}"
                credential('database-url', url.encode(), runtime['databaseBinding']['environmentName'])
            if cache:
                credential('redis-url', cache_url.encode(), app['cache']['environmentName'])
            for index, binding in enumerate(app.get('secretBindings', [])):
                path = encryption_path(binding)
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    metadata = os.fstat(fd)
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != binding['ownerUid'] or metadata.st_mode & 0o022 or metadata.st_nlink != 1 or not 16 <= metadata.st_size <= 16384:
                        raise Rejected('Encryption secret identity changed')
                    with os.fdopen(fd, 'rb', closefd=False) as inp: value = inp.read(16385)
                    if not 16 <= len(value) <= 16384: raise Rejected('Encryption secret changed size')
                    credential('encryption-' + str(index), value, binding['environmentName'])
                finally: os.close(fd)
            image = json.loads(run(['docker', 'image', 'inspect', app['imageId']]))[0]
            for item in image.get('Config', {}).get('Env', []) or []:
                key = item.split('=', 1)[0]
                if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key): raise Rejected('Invalid image environment name')
                argv += ['--env', key + '=']
            for k, v in sorted(runtime['environment'].items()): argv += ['--env', k + '=' + v]
            for key, value in sorted(file_environment.items()): argv += ['--env', key + '=' + value]
            # Clear inherited image ENV; image files themselves must be root-reviewed as secret-free.
            argv += [app['imageId'], *runtime['argv'][1:]]
            container = run(argv).decode().strip()
            if not re.fullmatch(r'[a-f0-9]{64}', container): raise Rejected('Unexpected container identity')
            frontend = static_frontend(app['frontend'], rid, target, directory, network, projection['containerName'], runtime['port'], projection['domain'], check) if app.get('frontend') else None
            result = {**projection, 'containerId': container, 'database': db, 'cache': cache, 'frontend': frontend,
                      'activationRequired': True, 'note': 'Staged: activation requires fresh protected-publication readback from the authenticated Control Center peer'}
            status = 'staged'
        except Cancelled:
            status = 'cancelled'; self.stop_clones(rid, target)
        except Exception as error:
            status = 'failed'; self.stop_clones(rid, target)
            result = {'error': str(error) if isinstance(error, Rejected) else 'Native clone operation failed; inspect private destination state'}
        with self.connection() as c:
            c.execute('UPDATE jobs SET status=?,result=? WHERE id=?', (status, json.dumps(result) if result else None, rid))


def peer_cgroup(pid, uid):
    """Read the kernel peer PID's cgroup through its pinned proc directory."""
    if type(pid) is not int or pid < 1:
        raise Rejected('Invalid native peer PID')
    directory = os.open('/proc/' + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if os.fstat(directory).st_uid != uid:
            raise Rejected('Peer process ownership changed')
        fd = os.open('cgroup', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                data = stream.read(16385)
            if len(data) > 16384:
                raise Rejected('Unexpected peer cgroup metadata')
            return data.decode('ascii')
        finally: os.close(fd)
    finally: os.close(directory)


def authorize_peer(config, pid, uid):
    if uid != config['peerUid']:
        raise Rejected('Unauthorized peer identity')
    expected = config['peerContainerId']
    groups = peer_cgroup(pid, uid)
    matched = False
    for line in groups.splitlines():
        fields = line.split(':', 2)
        if len(fields) != 3 or not fields[2].startswith('/'):
            raise Rejected('Invalid native peer cgroup metadata')
        parts = PurePosixPath(fields[2]).parts
        if ('docker-' + expected + '.scope') in parts:
            matched = True
        if any(parts[i] == 'docker' and parts[i + 1] == expected for i in range(len(parts) - 1)):
            matched = True
    if not matched:
        raise Rejected('Peer is outside admitted Control Center container')
    info = json.loads(run(['docker', 'inspect', expected]))[0]
    if info.get('Id') != expected or info.get('State', {}).get('Running') is not True:
        raise Rejected('Admitted Control Center container identity changed')


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        try:
            import struct
            pid, uid, _ = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if self.path != '/v1/operator': raise Rejected('Unauthorized endpoint')
            authorize_peer(self.server.operator.config, pid, uid)
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 4096 or self.headers.get('Transfer-Encoding'): raise Rejected('Invalid request size')
            self.connection.settimeout(5)
            result = self.server.operator.handle(json.loads(self.rfile.read(size)))
            code = 200
        except Exception as error:
            code, result = 400, {'error': str(error) if isinstance(error, Rejected) else 'Request rejected'}
        payload = json.dumps(result).encode()
        self.send_response(code); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(payload))); self.end_headers(); self.wfile.write(payload)


def main():
    os.umask(0o077)
    config = load_profile()
    import fcntl
    lock = open(STATE / 'operator.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    operator = Operator(config)
    path = Path(SOCKET)
    path.parent.mkdir(mode=0o750, exist_ok=True)
    if path.exists():
        if not stat.S_ISSOCK(path.lstat().st_mode): raise Rejected('Unexpected socket path')
        path.unlink()
    with Server(SOCKET, Handler) as server:
        server.operator = operator
        os.chown(SOCKET, config['peerUid'], 0); os.chmod(SOCKET, 0o600)
        server.serve_forever()


if __name__ == '__main__': main()
