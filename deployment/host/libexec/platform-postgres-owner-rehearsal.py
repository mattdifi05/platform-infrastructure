#!/usr/bin/env python3
"""Prove PostgreSQL owner-aware imports in an offline scratch container."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

PLAN_RESULT = Path('/var/lib/platform-manual-restore-candidate/fce4ae8db3ff4bfda52ec6764b6c7289/stage-result.json')
ISOLATED = 'platform-restore-pg-20260929-182357-1f9954'
IMAGE = 'sha256:0d243609c225531478249a5220f9a8e899f1e9b045a2a981d26dc2cc98a6b591'
CASES = (
    ('database:platform-postgres-keycloak', 'keycloak', 'restore_probe_keycloak'),
    ('database:scriptastudents-postgres-students-beta-app', 'pi_p_students_b_91b7dbc8de57', 'restore_probe_students'),
)


def docker(*args, stdin=None):
    command = ['docker', *args]
    result = subprocess.run(command, stdin=stdin, capture_output=True)
    if result.returncode:
        raise RuntimeError('isolated Docker step failed: ' + args[0] + ': ' + result.stderr.decode(errors='replace')[:180])
    return result.stdout.decode().strip()


def sql(statement, database=None):
    args = ['exec', '-u', 'postgres', ISOLATED, 'psql']
    if database:
        args += ['-d', database]
    return docker(*args, '-Atc', statement)


def wait_ready():
    for _ in range(30):
        try:
            if sql('SELECT 1') == '1':
                return
        except RuntimeError:
            time.sleep(2)
    raise RuntimeError('isolated PostgreSQL did not become ready')


def main():
    if os.geteuid() != 0:
        raise RuntimeError('root required')
    result = json.loads(PLAN_RESULT.read_bytes())
    if result['proof']['receiptSha256'] != '1868a512b5a47fe9cc4808622dfb4707d8fe988b0a1d523f801c12ad4c419030':
        raise RuntimeError('FTPS plan differs')
    manifest = result['manifest']
    if manifest['signature']['digest'] != 'baf72a7c4ff5d2266b71afe4865ebffeb8be6c363dfc31c12f3a865389009b2c':
        raise RuntimeError('manifest differs')
    container = json.loads(docker('inspect', ISOLATED))[0]
    if container['Image'] != IMAGE or container['HostConfig']['NetworkMode'] != 'none' or container['State']['Running']:
        raise RuntimeError('isolated container binding differs')
    artifacts = {item['resourceId']: item for item in manifest['artifacts']}
    for resource, _, _ in CASES:
        item = artifacts[resource]
        path = Path(result['restoredPath']) / item['path']
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if path.is_symlink() or path.stat().st_size != item['sizeBytes'] or digest != item['sha256']:
            raise RuntimeError('FTPS artifact differs')
    docker('start', ISOLATED)
    created = []
    rows = []
    try:
        wait_ready()
        for resource, role, scratch in CASES:
            if not re.fullmatch('[a-z0-9_]+', role) or not re.fullmatch('[a-z0-9_]+', scratch):
                raise RuntimeError('identifier differs')
            if sql("SELECT count(*) FROM pg_roles WHERE rolname='" + role + "'") != '0' or sql("SELECT count(*) FROM pg_database WHERE datname='" + scratch + "'") != '0':
                raise RuntimeError('scratch role or database already exists')
            sql('CREATE ROLE ' + role + ' NOLOGIN')
            created.append(('role', role))
            sql('CREATE DATABASE ' + scratch + ' OWNER ' + role)
            created.append(('database', scratch))
            item = artifacts[resource]
            path = Path(result['restoredPath']) / item['path']
            with path.open('rb') as stream:
                # pg_restore without a filename reads stdin. `-` is NOT a valid
                # filename in this version.
                docker('exec', '-i', '-u', 'postgres', ISOLATED, 'pg_restore',
                       '--no-owner', '--no-acl', '--role=' + role,
                       '--dbname=' + scratch, stdin=stream)
            db_owner = sql('SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()', scratch)
            objects = sql("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S')", scratch)
            mismatch = sql("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S') AND pg_get_userbyid(c.relowner)<>'" + role + "'", scratch)
            table = sql("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename LIMIT 1", scratch)
            if not re.fullmatch('[a-z0-9_]+', table):
                raise RuntimeError('table identifier differs')
            readable = sql('SET ROLE ' + role + '; SELECT count(*) FROM public."' + table + '"', scratch).splitlines()[-1]
            rows.append({'resourceId': resource, 'databaseOwnerCorrect': db_owner == role,
                         'objectCount': int(objects), 'ownerMismatches': int(mismatch),
                         'applicationRoleCanRead': readable.isdigit()})
        print(json.dumps({'schema': 'platform.isolated-postgres-owner-restore/v1',
                          'productionModified': False, 'network': 'none', 'results': rows}, sort_keys=True))
    finally:
        errors = []
        for kind, name in reversed(created):
            try:
                sql(('DROP DATABASE ' if kind == 'database' else 'DROP ROLE ') + name)
            except Exception as error:
                errors.append((kind, type(error).__name__))
        docker('stop', '--time', '20', ISOLATED)
        if errors:
            raise RuntimeError('isolated scratch cleanup failed: ' + repr(errors))


if __name__ == '__main__':
    main()
