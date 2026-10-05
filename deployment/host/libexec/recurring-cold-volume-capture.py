#!/usr/bin/python3
"""Fixed six-volume cold copies, one writer at a time, with a systemd watchdog.

No restore or live file mutation. The source directories are never written.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time
from source_adapter import _tree_records, tree_hash

ROOT = Path('/var/lib/platform-completeness-candidate-20260930')
HERE = ROOT / 'source-verifier/cold_volume_capture.py'
DEST = ROOT / 'cold-volume-snapshots'
JOURNAL = ROOT / 'cold-volume-capture.json'
FIXED = (
    ('keycloak-gzip-cache-only','gf-keycloak','/var/lib/docker/volumes/greenfield_keycloak_data/_data','/opt/keycloak/data'),
    ('loki-logs','gf-loki','/var/lib/docker/volumes/greenfield_loki_data/_data','/loki'),
    ('jetstream-currently-empty','gf-nats','/var/lib/docker/volumes/greenfield_nats_data/_data','/data'),
    ('prometheus-metrics','gf-prometheus','/var/lib/docker/volumes/greenfield_prometheus_data/_data','/prometheus'),
    ('rustfs-logs','gf-rustfs','/var/lib/docker/volumes/platform_rustfs_logs/_data','/logs'),
    ('stream-sessions','php-stream','/home/platform_infrastructure/v1-fresh-runtime/stream-sessions','/var/lib/php/sessions'),
)


def now(): return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic(path,value):
    tmp=path.with_name('.'+path.name+'.'+str(os.getpid())+'.tmp')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(value,stream,sort_keys=True,separators=(',',':'));stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path)
        fd=os.open(path.parent,os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally: tmp.unlink(missing_ok=True)


def command(args,timeout=30):
    return subprocess.check_output(args,text=True,timeout=timeout,stderr=subprocess.DEVNULL)


def inspect(cid): return json.loads(command(['docker','inspect',cid]))[0]


def identity(row,current):
    if current['Id']!=row['id'] or current['Name'].lstrip('/')!=row['container']:
        raise RuntimeError('CONTAINER_IDENTITY_CHANGED')


def volume_tree(root):
    records=_tree_records(root)
    if len(records)>50000 or sum(r.get('size',0) for r in records)>2_000_000_000:
        raise RuntimeError('VOLUME_COPY_BOUND')
    # cp -a also preserves ACL and extended attributes. Bind these without
    # disclosing attribute values in the external evidence.
    for record in records:
        path=Path(root) if record['path']=='.' else Path(root)/record['path']
        info=path.lstat();record['mtimeNs']=info.st_mtime_ns
        attributes=[]
        for name in sorted(os.listxattr(path,follow_symlinks=False)):
            value=os.getxattr(path,name,follow_symlinks=False)
            attributes.append({'name':name,'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest()})
        record['xattrs']=attributes
    return {'treeSha256':tree_hash(records),'entryCount':len(records),
            'regularBytes':sum(r.get('size',0) for r in records)}


def stopped_copy(row,target,backend=command,probe=inspect,hasher=volume_tree):
    """Restart is attempted even if stop, copy or hashing raises an exception."""
    stopped_at=None
    try:
        backend(['docker','stop','--time','40',row['id']],65)
        cold=probe(row['id']);identity(row,cold)
        if cold['State']['Running'] or cold['State'].get('OOMKilled') or cold['State']['ExitCode'] not in (0,143):
            raise RuntimeError('WRITER_NOT_CLEANLY_STOPPED')
        stopped_at=cold['State']['FinishedAt']
        before=hasher(row['source'])
        backend(['cp','-a','--reflink=auto','--',row['source'],str(target)],45)
        after=hasher(row['source']);copied=hasher(target)
        current=probe(row['id']);identity(row,current)
        if (current['State']['Running'] or current['State']['FinishedAt']!=stopped_at or
            current['State']['StartedAt']!=cold['State']['StartedAt']):
            raise RuntimeError('WRITER_RESUMED_DURING_COPY')
        if before!=after or copied!=before: raise RuntimeError('COLD_COPY_VERIFICATION_FAILED')
        return {**copied,'stoppedAt':stopped_at,'verifiedColdAt':now(),
                'snapshot':str(target),'consistency':'single-writer-clean-stop'}
    finally:
        current=probe(row['id']);identity(row,current)
        if not current['State']['Running']: backend(['docker','start',row['id']],45)


def preflight():
    ids=command(['docker','ps','-q']).split()
    containers=json.loads(command(['docker','inspect',*ids]))
    found={c['Name'].lstrip('/'):c for c in containers}
    rows=[]
    for subject,name,source,destination in FIXED:
        c=found.get(name)
        if not c or not c['State']['Running'] or c['State'].get('Health',{}).get('Status')!='healthy':
            raise RuntimeError('SIX_INITIAL_HEALTHY_WRITERS_REQUIRED')
        root=Path(source)
        if root.is_symlink() or not root.is_dir() or root.resolve()!=root:
            raise RuntimeError('FIXED_REAL_VOLUME_REQUIRED')
        if not any(m['RW'] and m['Source']==source and m['Destination']==destination for m in c['Mounts']):
            raise RuntimeError('FIXED_MOUNT_BINDING_CHANGED')
        for other in containers:
            for m in other['Mounts']:
                mount=Path(m['Source'])
                overlaps=(mount==root or mount in root.parents or root in mount.parents)
                if m['RW'] and overlaps and other['Id']!=c['Id']:
                    raise RuntimeError('ADDITIONAL_VOLUME_WRITER')
        rows.append({'subject':subject,'container':name,'id':c['Id'],'source':source,
                     'destination':destination,'initialStartedAt':c['State']['StartedAt']})
    if shutil.disk_usage(ROOT).free<8_000_000_000: raise RuntimeError('COLD_COPY_DISK_HEADROOM')
    return rows


def watchdog(expected_subject,expected_id):
    data=json.loads(JOURNAL.read_text());active=data.get('active')
    if not active: return
    if active.get('subject')!=expected_subject or active.get('id')!=expected_id: return
    allowed={subject:(name,source,destination) for subject,name,source,destination in FIXED}
    row=active
    if (row.get('subject') not in allowed or (row['container'],row['source'],row['destination'])!=allowed[row['subject']] or
        not isinstance(row['id'],str) or len(row['id'])!=64 or any(x not in '0123456789abcdef' for x in row['id'])):
        raise RuntimeError('WATCHDOG_IDENTITY_NOT_ALLOWED')
    for _ in range(3):
        try:
            current=inspect(row['id']);identity(row,current)
            if not current['State']['Running']: command(['docker','start',row['id']],45)
            if inspect(row['id'])['State']['Running']:
                print(json.dumps({'watchdog':'writer-running','container':row['container']}),flush=True);return
        except (subprocess.SubprocessError,RuntimeError): pass
        time.sleep(5)
    raise RuntimeError('WATCHDOG_RESTART_UNCONFIRMED')


def wait_health(row):
    deadline=time.monotonic()+120
    while True:
        c=inspect(row['id']);identity(row,c)
        health=c['State'].get('Health',{}).get('Status')
        if c['State']['Running'] and health=='healthy': return
        if not c['State']['Running'] or health=='unhealthy' or time.monotonic()>deadline:
            raise RuntimeError('WRITER_RESTART_HEALTH_FAILED')
        time.sleep(3)


def main():
    p=argparse.ArgumentParser();p.add_argument('--watchdog',action='store_true')
    p.add_argument('--watchdog-subject');p.add_argument('--watchdog-id')
    p.add_argument('--after-capture-pid',type=int)
    p.add_argument('--watchdog-check',action='store_true');a=p.parse_args()
    if os.geteuid()!=0: raise SystemExit('ROOT_REQUIRED')
    os.umask(0o077)
    info=ROOT.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:
        raise SystemExit('ROOT_PRIVATE_STAGING_REQUIRED')
    if a.watchdog_check:
        atomic(ROOT/'watchdog-self-check.json',{'status':'passed','checkedAt':now(),
               'pid':os.getpid(),'productionServiceModified':False})
        return
    if a.watchdog:
        if not a.watchdog_subject or not a.watchdog_id: raise SystemExit('WATCHDOG_BINDING_REQUIRED')
        watchdog(a.watchdog_subject,a.watchdog_id);return
    deadline=time.monotonic()+1800
    while True:
        capture=json.loads((ROOT/'full-current-portable-status.json').read_text())
        if a.after_capture_pid and capture.get('pid')!=a.after_capture_pid:
            raise SystemExit('CAPTURE_PROCESS_CHANGED')
        if capture.get('status')=='local-plaintext-completed': break
        if (not a.after_capture_pid or capture.get('status')!='running' or
            time.monotonic()>deadline): raise SystemExit('COMPLETE_SOURCE_CAPTURE_REQUIRED')
        os.kill(a.after_capture_pid,0);time.sleep(15)
    if capture.get('status')!='local-plaintext-completed': raise SystemExit('COMPLETE_SOURCE_CAPTURE_REQUIRED')
    check=ROOT/'watchdog-self-check.json'
    if not check.is_file() or json.loads(check.read_text()).get('status')!='passed':
        raise SystemExit('INDEPENDENT_WATCHDOG_CHECK_REQUIRED')
    locks=[]
    for path in (ROOT/'cold-volume.lock',Path('/var/lib/platform-ftps-backup/transfer.lock')):
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);locks.append(fd)
        info=os.fstat(fd)
        if info.st_uid!=0 or info.st_mode&0o077 or not stat.S_ISREG(info.st_mode):
            raise SystemExit('PRIVATE_LOCK_REQUIRED')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if DEST.exists() or JOURNAL.exists(): raise SystemExit('FRESH_COLD_COPY_REQUIRED')
    rows=preflight();DEST.mkdir(mode=0o700)
    state={'schema':'platform.six-volume-cold-capture/v1','status':'running','pid':os.getpid(),
           'startedAt':now(),'active':None,'snapshots':[],'fullyRecoverable':False,
           'productionDataRestored':False,'serviceLifecycleChanged':True,'offsitePublished':False}
    atomic(JOURNAL,state)
    try:
        for row in rows:
            current=inspect(row['id']);identity(row,current)
            if not current['State']['Running'] or current['State']['StartedAt']!=row['initialStartedAt']:
                raise RuntimeError('PRE_STOP_RUNTIME_DRIFT')
            state['active']=row;atomic(JOURNAL,state)
            unit='platform-cold-copy-20260930-'+row['subject']
            command(['systemd-run','--quiet','--collect','--unit',unit,'--on-active=150s',
                     '--timer-property=AccuracySec=1s','/usr/bin/python3',str(HERE),'--watchdog',
                     '--watchdog-subject',row['subject'],'--watchdog-id',row['id']])
            result=stopped_copy(row,DEST/row['subject'])
            wait_health(row)
            command(['systemctl','stop',unit+'.timer'])
            state['snapshots'].append({**row,**result,'restartedHealthyAt':now()})
            state['active']=None;atomic(JOURNAL,state)
        state.update(status='passed',completedAt=now(),snapshotCount=len(state['snapshots']))
        atomic(JOURNAL,state)
        print(json.dumps({'status':'passed','snapshotCount':len(state['snapshots']),
                          'regularBytes':sum(r['regularBytes'] for r in state['snapshots']),
                          'fullyRecoverable':False,'offsitePublished':False}),flush=True)
    except BaseException as error:
        state.update(status='failed',completedAt=now(),reason=str(error)[:512]);atomic(JOURNAL,state)
        print(json.dumps({'status':'failed','reason':str(error)[:512],'active':state.get('active',{}),
                          'fullyRecoverable':False}),flush=True)
        raise SystemExit(1)
    finally:
        for fd in locks: os.close(fd)


if __name__=='__main__': main()
