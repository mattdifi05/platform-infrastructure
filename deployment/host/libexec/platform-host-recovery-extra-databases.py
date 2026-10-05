#!/usr/bin/python3
"""Read-only atomic export of two databases omitted from the signed catalog.

This root-only pre-capsule helper never writes to a database. Exports and a
metadata proof are atomically published together as one bounded tar artifact.
"""
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import uuid

OUTPUT_DIR=Path('/var/lib/platform-host-recovery/extra-database-exports')
CURRENT=OUTPUT_DIR/'current.tar'
MAX_TOTAL_EXPORT_BYTES=536_870_912
MAX_SCHEMA_ROWS=128
MAX_SCHEMA_NAME_CHARS=128
DUMP_TIMEOUT_SECONDS=1200
INSPECT_FORMAT='{{.Id}}\t{{.Image}}\t{{.State.Running}}\t{{.Name}}'
MARIA_QUERY_SCRIPT=(
    'export MYSQL_PWD="$(cat /run/secrets/mariadb_root_password)"; '
    'exec mariadb -uroot --batch --raw --skip-column-names -e "$1"'
)
MARIA_DUMP_SCRIPT=(
    'export MYSQL_PWD="$(cat /run/secrets/mariadb_root_password)"; '
    'exec mariadb-dump -uroot --single-transaction --quick --routines --events '
    '--triggers --hex-blob --databases phpmyadmin'
)

DATABASES=(
    {'name':'control_center','engine':'postgres','container':'gf-postgres',
     'catalogCommand':['docker','exec','gf-postgres','psql','-X','-v','ON_ERROR_STOP=1',
                       '-U','postgres','-d','control_center','-At','-F','\t','-c',
                       "SELECT n.nspname, COUNT(c.oid) FILTER (WHERE c.relkind IN ('r','p')) "
                       "FROM pg_namespace n LEFT JOIN pg_class c ON c.relnamespace=n.oid "
                       "WHERE n.nspname NOT IN ('pg_catalog','information_schema') "
                       "GROUP BY n.nspname ORDER BY n.nspname"],
     'dumpCommand':['docker','exec','gf-postgres','pg_dump','-Fc','-U','postgres','-d','control_center'],
     'filename':'control_center.dump','format':'postgres-custom'},
    {'name':'phpmyadmin','engine':'mariadb','container':'gf-mariadb',
     'catalogCommand':['docker','exec','gf-mariadb','sh','-ec',MARIA_QUERY_SCRIPT,
                       'extra-database-capture',
                       "SELECT TABLE_SCHEMA, COUNT(*) FROM information_schema.tables "
                       "WHERE TABLE_SCHEMA = 'phpmyadmin' AND TABLE_TYPE = 'BASE TABLE' "
                       "GROUP BY TABLE_SCHEMA ORDER BY TABLE_SCHEMA"],
     'dumpCommand':['docker','exec','gf-mariadb','sh','-ec',MARIA_DUMP_SCRIPT],
     'filename':'phpmyadmin.sql','format':'mariadb-sql'}
)


class CaptureBlocked(RuntimeError):
    pass


def sha256_file(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def run_text(command,timeout=60):
    try:
        return subprocess.check_output(command,stdin=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                       text=True,timeout=timeout)
    except (OSError,subprocess.SubprocessError):
        raise CaptureBlocked('READ_ONLY_DOCKER_QUERY_FAILED') from None


def run_dump(command,destination,timeout=DUMP_TIMEOUT_SECONDS):
    try:
        with Path(destination).open('xb') as output:
            os.chmod(destination,0o600)
            result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=output,
                                  stderr=subprocess.DEVNULL,timeout=timeout,check=False,
                                  close_fds=True)
            output.flush();os.fsync(output.fileno())
    except (OSError,subprocess.SubprocessError):
        raise CaptureBlocked('READ_ONLY_DOCKER_DUMP_FAILED') from None
    if result.returncode!=0:
        raise CaptureBlocked('READ_ONLY_DOCKER_DUMP_FAILED')


def _private_directory(path,strict_root=True):
    path=Path(path).absolute()
    if path.is_symlink() or path.resolve()!=path or not path.is_dir():
        raise CaptureBlocked('EXPORT_DIRECTORY_UNSAFE')
    info=path.lstat()
    owner=0 if strict_root else os.geteuid()
    if info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=0o700:
        raise CaptureBlocked('EXPORT_DIRECTORY_NOT_PRIVATE')
    cur=Path('/')
    for part in path.parts[1:]:
        cur=cur/part;parent_info=cur.lstat()
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            raise CaptureBlocked('EXPORT_DIRECTORY_ANCESTOR_UNSAFE')
        if strict_root and (parent_info.st_uid!=0 or parent_info.st_mode&0o022):
            raise CaptureBlocked('EXPORT_DIRECTORY_ANCESTOR_UNSAFE')
    return path


def _ensure_output_directory(path,strict_root=True):
    path=Path(path).absolute()
    parent=path.parent
    if not parent.is_dir() or parent.is_symlink():raise CaptureBlocked('EXPORT_PARENT_REQUIRED')
    if not path.exists():
        path.mkdir(mode=0o700)
        os.chmod(path,0o700)
        if strict_root:os.chown(path,0,0)
        fd=os.open(parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    return _private_directory(path,strict_root)


def _safe_current(path,strict_root):
    path=Path(path)
    if not path.exists() and not path.is_symlink():return None
    info=path.lstat();owner=0 if strict_root else os.geteuid()
    if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or
            info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600):
        raise CaptureBlocked('PREVIOUS_EXPORT_UNSAFE_PRESERVED')
    return {'sha256':sha256_file(path),'bytes':info.st_size}


def _container_binding(name,runner):
    raw=runner(['docker','inspect','--format='+INSPECT_FORMAT,name],timeout=30).strip()
    parts=raw.split('\t')
    if len(parts)!=4:
        raise CaptureBlocked('DATABASE_CONTAINER_BINDING_INVALID')
    container_id,image_id,running,observed_name=parts
    if (not re.fullmatch(r'[a-f0-9]{64}',container_id) or
            not re.fullmatch(r'sha256:[a-f0-9]{64}',image_id) or running!='true' or
            observed_name!='/'+name):
        raise CaptureBlocked('DATABASE_CONTAINER_BINDING_INVALID')
    return {'containerName':name,'containerId':container_id,'imageId':image_id}


def _catalog_rows(database,runner):
    raw=runner(database['catalogCommand'],timeout=60)
    if len(raw.encode('utf-8'))>MAX_SCHEMA_ROWS*(MAX_SCHEMA_NAME_CHARS+32):
        raise CaptureBlocked('DATABASE_SCHEMA_CATALOG_SIZE_LIMIT')
    rows=[]
    for line in raw.splitlines():
        parts=line.split('\t')
        if (len(parts)!=2 or not parts[0] or len(parts[0])>MAX_SCHEMA_NAME_CHARS or
                any(ord(char)<32 or ord(char)==127 for char in parts[0]) or
                not parts[1].isdigit()):
            raise CaptureBlocked('DATABASE_SCHEMA_CATALOG_INVALID')
        rows.append({'schema':parts[0],'tableCount':int(parts[1])})
    if (not rows or len(rows)>MAX_SCHEMA_ROWS or
            len({row['schema'] for row in rows})!=len(rows)):
        raise CaptureBlocked('DATABASE_SCHEMA_CATALOG_EMPTY_OR_DUPLICATED')
    if database['engine']=='mariadb' and [row['schema'] for row in rows]!=[database['name']]:
        raise CaptureBlocked('MARIADB_DATABASE_SCOPE_MISMATCH')
    return rows


def _validate_dump(database,path):
    size=Path(path).stat().st_size
    if size<=0:raise CaptureBlocked('DATABASE_DUMP_EMPTY')
    with Path(path).open('rb') as stream:prefix=stream.read(8192)
    if database['format']=='postgres-custom':
        if not prefix.startswith(b'PGDMP'):
            raise CaptureBlocked('POSTGRES_CUSTOM_DUMP_HEADER_INVALID')
    elif not (b'MariaDB dump' in prefix or b'MySQL dump' in prefix):
        raise CaptureBlocked('MARIADB_DUMP_HEADER_INVALID')
    return {'filename':database['filename'],'bytes':size,'sha256':sha256_file(path),
            'format':database['format'],'mode':'0600'}


def _write_archive(archive_path,stage,proof):
    payload=json.dumps(proof,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()+b'\n'
    proof_path=stage/'proof.json'
    fd=os.open(proof_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(payload);stream.flush();os.fsync(stream.fileno())
    names=['control_center.dump','phpmyadmin.sql','proof.json']
    tmp=Path(archive_path)
    with tmp.open('xb') as raw:
        os.chmod(tmp,0o600)
        with tarfile.open(fileobj=raw,mode='w',format=tarfile.PAX_FORMAT) as tf:
            for name in names:
                path=stage/name;info=path.stat();member=tarfile.TarInfo(name)
                member.type=tarfile.REGTYPE;member.size=info.st_size;member.mode=0o600
                member.uid=os.geteuid();member.gid=os.getegid();member.mtime=int(info.st_mtime)
                with path.open('rb') as stream:tf.addfile(member,stream)
        raw.flush();os.fsync(raw.fileno())
    os.chmod(tmp,0o600)
    with tarfile.open(tmp,'r:') as tf:
        members=tf.getmembers();found={member.name for member in members}
        if (len(members)!=len(names) or found!=set(names) or
                any(not member.isfile() or member.mode!=0o600 or member.uid!=os.geteuid() or
                    member.gid!=os.getegid() for member in members)):
            raise CaptureBlocked('EXTRA_DATABASE_BUNDLE_MEMBERS_INVALID')
        archived_proof=json.load(tf.extractfile('proof.json'))
        if archived_proof!=proof:raise CaptureBlocked('EXTRA_DATABASE_PROOF_MEMBER_MISMATCH')
        for db in proof['databases']:
            member=tf.getmember(db['dump']['filename']);stream=tf.extractfile(member)
            h=hashlib.sha256();size=0
            for block in iter(lambda:stream.read(1024*1024),b''):
                size+=len(block);h.update(block)
            if size!=db['dump']['bytes'] or h.hexdigest()!=db['dump']['sha256']:
                raise CaptureBlocked('EXTRA_DATABASE_DUMP_MEMBER_MISMATCH')
    return {'bytes':tmp.stat().st_size,'sha256':sha256_file(tmp)}


def collect(output_dir=OUTPUT_DIR,strict_root=True,runner=run_text,dump_runner=run_dump,
            now=lambda:dt.datetime.now(dt.timezone.utc)):
    if os.geteuid()!=0 and strict_root:raise CaptureBlocked('ROOT_REQUIRED')
    output_dir=_ensure_output_directory(output_dir,strict_root)
    current=output_dir/'current.tar'
    previous=_safe_current(current,strict_root)
    stage=Path(tempfile.mkdtemp(prefix='.extra-db-capture-',dir=output_dir));os.chmod(stage,0o700)
    start=now();started=time.monotonic()
    try:
        bindings={db['name']:_container_binding(db['container'],runner) for db in DATABASES}
        databases=[];total=0
        for db in DATABASES:
            before=_catalog_rows(db,runner)
            dump_path=stage/db['filename']
            dump_runner(db['dumpCommand'],dump_path,DUMP_TIMEOUT_SECONDS)
            dump_info=_validate_dump(db,dump_path)
            total+=dump_info['bytes']
            if total>MAX_TOTAL_EXPORT_BYTES:
                raise CaptureBlocked('EXTRA_DATABASE_EXPORT_SIZE_LIMIT')
            after=_catalog_rows(db,runner)
            binding_after=_container_binding(db['container'],runner)
            if before!=after or binding_after!=bindings[db['name']]:
                raise CaptureBlocked('DATABASE_SCHEMA_OR_CONTAINER_DRIFT_DURING_EXPORT')
            databases.append({'name':db['name'],'engine':db['engine'],**bindings[db['name']],
                              'schemas':before,'schemaCount':len(before),
                              'tableCount':sum(row['tableCount'] for row in before),
                              'readOnlyCatalogStable':True,'dump':dump_info})
        completed=now()
        proof={'schema':'platform.host-extra-database-exports/v1','status':'passed',
               'readOnly':True,'productionDatabaseWrites':False,'databaseCount':len(databases),
               'captureStartedAt':start.isoformat(),'captureCompletedAt':completed.isoformat(),
               'elapsedSeconds':round(time.monotonic()-started,3),
               'maximumCombinedDumpBytes':MAX_TOTAL_EXPORT_BYTES,
               'combinedDumpBytes':total,'databases':databases,
               'containerBindingsStable':True,'schemaCountsStableDuringCapture':True,
               'bundleFilename':'current.tar','previousBundlePreservedOnFailure':True}
        temp_bundle=stage/'current.tar.partial'
        bundle=_write_archive(temp_bundle,stage,proof)
        fd=os.open(temp_bundle,os.O_RDONLY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        os.replace(temp_bundle,current)
        dfd=os.open(output_dir,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|os.O_NOFOLLOW)
        try:os.fsync(dfd)
        finally:os.close(dfd)
        final={'schema':'platform.host-extra-database-exports-proof/v1','status':'passed',
               'bundle':str(current),'bundleBytes':current.stat().st_size,
               'bundleSha256':sha256_file(current),'databaseCount':2,
               'combinedDumpBytes':total,'readOnly':True,'productionDatabaseWrites':False,
               'captureCompletedAt':completed.isoformat(),
               'previousBundleSha256':previous['sha256'] if previous else None}
        return final
    finally:
        shutil.rmtree(stage,ignore_errors=True)


if __name__=='__main__':
    if os.geteuid()!=0:raise SystemExit('ROOT_REQUIRED')
    try:
        result=collect()
        print(json.dumps(result,sort_keys=True,separators=(',',':')))
    except CaptureBlocked as error:
        raise SystemExit(str(error)) from None
