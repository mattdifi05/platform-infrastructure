#!/usr/bin/env python3
"""Read-only database ACL/role metadata inventory for the eight signed-manifest DBs.

The SQL uses a fixed column allowlist and never queries password/auth columns.
Only run on the root host after confirming the selected manifest signature.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import stat
import subprocess

EXPECTED = {
    ('postgres', 'stexor', 'database:account-postgres-stexor'),
    ('postgres', 'keycloak', 'database:platform-postgres-keycloak'),
    ('postgres', 'students_beta_app', 'database:scriptastudents-postgres-students-beta-app'),
    ('mariadb', 'anniversary', 'database:anniversary-mariadb-anniversary'),
    ('mariadb', 'fiplatform', 'database:fiplatform-mariadb-fiplatform'),
    ('mariadb', 'u778675014_fip', 'database:fiplatform-mariadb-u778675014-fip'),
    ('mariadb', 'stream', 'database:stream-mariadb-stream'),
    ('mariadb', 'workcalendar', 'database:workcalendar-mariadb-workcalendar'),
}
IDENT = re.compile(r'^[A-Za-z0-9_]+$')
MAX_OUTPUT = 16 * 1024 * 1024

PG_SQL = r"""
BEGIN READ ONLY;
SELECT json_build_object('kind','database','name',datname,'owner',pg_get_userbyid(datdba),'acl',datacl::text,'allowConnections',datallowconn)
FROM pg_database WHERE datname=current_database();
SELECT json_build_object('kind','role','name',rolname,'superuser',rolsuper,'inherit',rolinherit,'createRole',rolcreaterole,'createDb',rolcreatedb,'login',rolcanlogin,'replication',rolreplication,'bypassRls',rolbypassrls,'connectionLimit',rolconnlimit)
FROM pg_roles ORDER BY rolname;
SELECT json_build_object('kind','membership','role',r.rolname,'member',m.rolname,'grantor',g.rolname,'admin',a.admin_option,'inherit',a.inherit_option,'set',a.set_option)
FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member JOIN pg_roles g ON g.oid=a.grantor ORDER BY r.rolname,m.rolname,g.rolname;
SELECT json_build_object('kind','schema','name',nspname,'owner',pg_get_userbyid(nspowner),'acl',nspacl::text)
FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema' ORDER BY nspname;
SELECT json_build_object('kind','relation','schema',n.nspname,'name',c.relname,'relationKind',c.relkind,'owner',pg_get_userbyid(c.relowner),'acl',c.relacl::text,'rowSecurity',c.relrowsecurity,'forceRowSecurity',c.relforcerowsecurity)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' ORDER BY n.nspname,c.relname;
SELECT json_build_object('kind','function','schema',n.nspname,'name',p.proname,'identityArguments',pg_get_function_identity_arguments(p.oid),'owner',pg_get_userbyid(p.proowner),'acl',p.proacl::text)
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' ORDER BY n.nspname,p.proname,p.oid;
SELECT json_build_object('kind','type','schema',n.nspname,'name',t.typname,'typeKind',t.typtype,'owner',pg_get_userbyid(t.typowner),'acl',t.typacl::text)
FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' ORDER BY n.nspname,t.typname;
SELECT json_build_object('kind','defaultAcl','role',pg_get_userbyid(a.defaclrole),'schema',n.nspname,'objectType',a.defaclobjtype,'acl',a.defaclacl::text)
FROM pg_default_acl a LEFT JOIN pg_namespace n ON n.oid=a.defaclnamespace ORDER BY a.defaclrole,n.nspname,a.defaclobjtype;
SELECT json_build_object('kind','language','name',lanname,'owner',pg_get_userbyid(lanowner),'acl',lanacl::text)
FROM pg_language ORDER BY lanname;
SELECT json_build_object('kind','grant','scope','database','name',d.datname,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,'grantor',pg_get_userbyid(a.grantor),'privilege',a.privilege_type,'grantable',a.is_grantable)
FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) a WHERE d.datname=current_database() ORDER BY a.grantee,a.privilege_type;
SELECT json_build_object('kind','grant','scope','schema','schema',n.nspname,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,'grantor',pg_get_userbyid(a.grantor),'privilege',a.privilege_type,'grantable',a.is_grantable)
FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' ORDER BY n.nspname,a.grantee,a.privilege_type;
SELECT json_build_object('kind','grant','scope','relation','schema',n.nspname,'name',c.relname,'relationKind',c.relkind,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,'grantor',pg_get_userbyid(a.grantor),'privilege',a.privilege_type,'grantable',a.is_grantable)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' ORDER BY n.nspname,c.relname,a.grantee,a.privilege_type;
SELECT json_build_object('kind','grant','scope','function','schema',n.nspname,'name',p.proname,'identityArguments',pg_get_function_identity_arguments(p.oid),'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,'grantor',pg_get_userbyid(a.grantor),'privilege',a.privilege_type,'grantable',a.is_grantable)
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' ORDER BY n.nspname,p.proname,a.grantee,a.privilege_type;
SELECT json_build_object('kind','grant','scope','type','schema',n.nspname,'name',t.typname,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,'grantor',pg_get_userbyid(a.grantor),'privilege',a.privilege_type,'grantable',a.is_grantable)
FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace CROSS JOIN LATERAL aclexplode(t.typacl) a WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' ORDER BY n.nspname,t.typname,a.grantee,a.privilege_type;
SELECT json_build_object('kind','grant','scope','language','name',l.lanname,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,'grantor',pg_get_userbyid(a.grantor),'privilege',a.privilege_type,'grantable',a.is_grantable)
FROM pg_language l CROSS JOIN LATERAL aclexplode(l.lanacl) a ORDER BY l.lanname,a.grantee,a.privilege_type;
SELECT json_build_object('kind','grant','scope','defaultAcl','role',pg_get_userbyid(d.defaclrole),'schema',n.nspname,'objectType',d.defaclobjtype,'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,'grantor',pg_get_userbyid(a.grantor),'privilege',a.privilege_type,'grantable',a.is_grantable)
FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace CROSS JOIN LATERAL aclexplode(d.defaclacl) a ORDER BY d.defaclrole,n.nspname,d.defaclobjtype,a.grantee,a.privilege_type;
COMMIT;
"""

MARIA_SQL = r"""
START TRANSACTION READ ONLY;
SELECT JSON_OBJECT('kind','database','name',DATABASE());
SELECT JSON_OBJECT('kind','account','user',User,'host',Host,'isRole',is_role,'defaultRole',default_role,'maxQuestions',max_questions,'maxUpdates',max_updates,'maxConnections',max_connections,'maxUserConnections',max_user_connections) FROM mysql.user ORDER BY User,Host;
SELECT JSON_OBJECT('kind','roleMapping','user',User,'host',Host,'role',Role,'admin',Admin_option) FROM mysql.roles_mapping ORDER BY User,Host,Role;
SELECT JSON_OBJECT('kind','globalGrant','grantee',GRANTEE,'privilege',PRIVILEGE_TYPE,'grantable',IS_GRANTABLE) FROM information_schema.USER_PRIVILEGES ORDER BY GRANTEE,PRIVILEGE_TYPE;
SELECT JSON_OBJECT('kind','schemaGrant','grantee',GRANTEE,'schema',TABLE_SCHEMA,'privilege',PRIVILEGE_TYPE,'grantable',IS_GRANTABLE) FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA=DATABASE() ORDER BY GRANTEE,PRIVILEGE_TYPE;
SELECT JSON_OBJECT('kind','tableGrant','grantee',GRANTEE,'schema',TABLE_SCHEMA,'table',TABLE_NAME,'privilege',PRIVILEGE_TYPE,'grantable',IS_GRANTABLE) FROM information_schema.TABLE_PRIVILEGES WHERE TABLE_SCHEMA=DATABASE() ORDER BY GRANTEE,TABLE_NAME,PRIVILEGE_TYPE;
SELECT JSON_OBJECT('kind','columnGrant','grantee',GRANTEE,'schema',TABLE_SCHEMA,'table',TABLE_NAME,'column',COLUMN_NAME,'privilege',PRIVILEGE_TYPE,'grantable',IS_GRANTABLE) FROM information_schema.COLUMN_PRIVILEGES WHERE TABLE_SCHEMA=DATABASE() ORDER BY GRANTEE,TABLE_NAME,COLUMN_NAME,PRIVILEGE_TYPE;
SELECT JSON_OBJECT('kind','routineGrant','user',User,'host',Host,'schema',Db,'routine',Routine_name,'routineType',Routine_type,'privileges',Proc_priv,'grantor',Grantor) FROM mysql.procs_priv WHERE Db=DATABASE() ORDER BY User,Host,Routine_name;
SELECT JSON_OBJECT('kind','routineDefiner','schema',ROUTINE_SCHEMA,'name',ROUTINE_NAME,'routineType',ROUTINE_TYPE,'definer',DEFINER,'security',SECURITY_TYPE) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() ORDER BY ROUTINE_NAME;
SELECT JSON_OBJECT('kind','viewDefiner','schema',TABLE_SCHEMA,'name',TABLE_NAME,'definer',DEFINER,'security',SECURITY_TYPE) FROM information_schema.VIEWS WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME;
SELECT JSON_OBJECT('kind','triggerDefiner','schema',TRIGGER_SCHEMA,'name',TRIGGER_NAME,'definer',DEFINER) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() ORDER BY TRIGGER_NAME;
SELECT JSON_OBJECT('kind','eventDefiner','schema',EVENT_SCHEMA,'name',EVENT_NAME,'definer',DEFINER) FROM information_schema.EVENTS WHERE EVENT_SCHEMA=DATABASE() ORDER BY EVENT_NAME;
COMMIT;
"""


class InventoryError(Exception):
    pass


def manifest_databases(manifest):
    if manifest.get('schema') != 'platform.backup-manifest/v1' or manifest.get('coverage', {}).get('complete') is not True:
        raise InventoryError('INVALID_MANIFEST')
    selected = [(item['engine'], item['name'], item['id']) for item in manifest.get('resources', []) if item.get('kind') == 'database']
    if len(selected) != 8 or set(selected) != EXPECTED or any(not IDENT.fullmatch(name) for _, name, _ in selected):
        raise InventoryError('DATABASE_SCOPE_MISMATCH')
    return sorted(selected)


def parse_rows(raw, engine, database):
    if len(raw) > MAX_OUTPUT:
        raise InventoryError('INVENTORY_TOO_LARGE')
    rows = []
    allowed = ({'database','role','membership','schema','relation','function','type','defaultAcl','language','grant'} if engine == 'postgres'
               else {'database','account','roleMapping','globalGrant','schemaGrant','tableGrant','columnGrant','routineGrant','routineDefiner','viewDefiner','triggerDefiner','eventDefiner'})
    try:
        lines = raw.decode('utf-8').splitlines()
    except UnicodeDecodeError:
        raise InventoryError('INVALID_QUERY_RESULT') from None
    for line in lines:
        try:
            value = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            raise InventoryError('INVALID_QUERY_RESULT') from None
        if not isinstance(value, dict) or value.get('kind') not in allowed or any('password' in key.lower() or 'authentication' in key.lower() or 'verifier' in key.lower() for key in value):
            raise InventoryError('UNSAFE_QUERY_RESULT')
        rows.append(value)
    if not rows or not any(x.get('kind') == 'database' and x.get('name') == database for x in rows) or (engine == 'mariadb' and not any(x.get('kind') == 'account' for x in rows)):
        raise InventoryError('INCOMPLETE_QUERY_RESULT')
    return rows


def docker_query(engine, database):
    if engine == 'postgres':
        command = ['docker','exec','-i','-u','postgres','gf-postgres','psql','-X','-A','-t','-q','-v','ON_ERROR_STOP=1','-U','postgres','-d',database]
        sql = PG_SQL
    else:
        # The password is read inside the DB container and never passed in argv,
        # returned, logged or written to this inventory.
        command = ['docker','exec','-i','gf-mariadb','sh','-c',
                   'export MYSQL_PWD="$(cat /run/secrets/mariadb_root_password)"; exec mariadb -uroot --batch --raw --skip-column-names --database="$1"',
                   'acl-inventory',database]
        sql = MARIA_SQL
    try:
        process = subprocess.run(command, input=sql.encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise InventoryError('QUERY_UNAVAILABLE') from None
    if process.returncode:
        raise InventoryError('QUERY_FAILED')
    return parse_rows(process.stdout, engine, database)


def collect(manifest, query=docker_query):
    databases = manifest_databases(manifest)
    result = {'schema':'platform.database-acl-inventory/v1', 'manifestId':manifest['id'],
              'manifestSignatureDigest':manifest.get('signature', {}).get('digest'),
              'manifestSignatureVerifiedByCollector':False,
              'capturedAt':dt.datetime.now(dt.timezone.utc).isoformat(), 'databaseCount':8, 'databases':[]}
    for engine, database, resource_id in databases:
        rows = query(engine, database)
        result['databases'].append({'resourceId':resource_id,'engine':engine,'database':database,'rows':rows})
    return result


def write_private(path, result):
    path = Path(path)
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise InventoryError('UNSAFE_OUTPUT_PATH')
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o077:
        raise InventoryError('UNPROTECTED_OUTPUT_DIRECTORY')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(result, stream, sort_keys=True, separators=(',', ':'))
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('ROOT_HOST_REQUIRED')
    try:
        info = args.manifest.lstat()
        parent = args.manifest.parent.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or
            not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077 or
            info.st_uid != parent.st_uid):
            raise InventoryError('UNPROTECTED_MANIFEST')
        manifest = json.loads(args.manifest.read_text())
        result = collect(manifest)
        write_private(args.output, result)
    except (InventoryError, OSError, ValueError) as error:
        raise SystemExit(error.args[0] if isinstance(error, InventoryError) else 'INVENTORY_FAILED') from None
    print('ACL_INVENTORY_WRITTEN databaseCount=8')


if __name__ == '__main__':
    main()
