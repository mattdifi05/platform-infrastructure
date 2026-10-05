#!/usr/bin/python3
"""Verify a bound image export in a separate network-private Docker daemon."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time

ROOT=Path('/var/lib/platform-completeness-candidate-20260930')
# libnetwork creates nested Unix sockets; keep this path below sun_path bounds.
SCRATCH=Path('/var/lib/platform-image-drill-20260930')
HERE=ROOT/'source-verifier/isolated_image_load.py'
UNIT='platform-image-load-isolated-20260930'
EXPORT=Path('/var/lib/platform-acl-inventory-20260930/docker-running-images-20260930.tar')
EXPORT_SHA='d686b5ae87de4284a48f958a1473f9931cbb8df8878ec680847f589eb5a5d247'
DAEMON_UMASK=0o022


def private_dir(path):
    info=path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:
        raise RuntimeError('ROOT_PRIVATE_IMAGE_STAGING_REQUIRED')


def save(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(data,stream,sort_keys=True,separators=(',',':'));stream.flush();os.fsync(stream.fileno())


def run(args,timeout=30):
    return subprocess.check_output(args,text=True,timeout=timeout,stderr=subprocess.DEVNULL)


def host_inventory():
    ids=run(['docker','ps','-q']).split()
    containers=json.loads(run(['docker','inspect',*ids]))
    return sorted((c['Name'].lstrip('/'),c['Id'],c['Image']) for c in containers)


def daemon():
    private_dir(SCRATCH)
    # Let image/container runtime paths retain normal executable/traversal
    # permissions; their scratch parent stays root-only mode 0700.
    os.umask(DAEMON_UMASK)
    child=subprocess.Popen(['/usr/bin/containerd','--config',str(SCRATCH/'containerd.toml')],
                            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    deadline=time.monotonic()+45
    while not (SCRATCH/'containerd.sock').exists():
        if child.poll() is not None or time.monotonic()>deadline: raise RuntimeError('PRIVATE_CONTAINERD_START_FAILED')
        time.sleep(.2)
    os.execv('/usr/bin/dockerd',['/usr/bin/dockerd','--config-file',str(SCRATCH/'docker.json')])


def main():
    p=argparse.ArgumentParser();p.add_argument('--daemon',action='store_true');a=p.parse_args()
    if os.geteuid()!=0: raise SystemExit('ROOT_REQUIRED')
    os.umask(0o077);private_dir(ROOT)
    if a.daemon: daemon();return
    if not all(shutil.which(name) for name in ('dockerd','containerd','docker','systemd-run')):
        raise SystemExit('EXISTING_DOCKER_TOOLS_REQUIRED')
    if SCRATCH.exists(): raise SystemExit('NEW_PRIVATE_DAEMON_REQUIRED')
    report=json.loads((ROOT/'full-current-portable-plaintext.tar.gz.json').read_text())
    entries=[e for e in report['entries'] if e['kind']=='docker-image-archive']
    if len(entries)!=1 or entries[0]['sha256']!=EXPORT_SHA: raise SystemExit('CAPTURED_IMAGE_BINDING_CHANGED')
    if EXPORT.is_symlink() or not EXPORT.is_file() or EXPORT.stat().st_uid!=0 or EXPORT.stat().st_mode&0o077:
        raise SystemExit('PRIVATE_IMAGE_EXPORT_REQUIRED')
    with EXPORT.open('rb') as stream: export_hash=hashlib.file_digest(stream,'sha256').hexdigest()
    if export_hash!=EXPORT_SHA:
        raise SystemExit('IMAGE_EXPORT_HASH_MISMATCH')
    initial=host_inventory();expected={image for _,_,image in initial}
    bound={c['imageId'] for c in json.loads((ROOT/'running-images-portable.json').read_text())['containers']}
    if expected!=bound or len(expected)!=34: raise SystemExit('LIVE_IMAGE_BINDING_DRIFT')
    if shutil.disk_usage(ROOT).free<30_000_000_000: raise SystemExit('IMAGE_DRILL_DISK_HEADROOM')
    SCRATCH.mkdir(mode=0o700)
    containerd_config=('version = 3\nroot = "'+str(SCRATCH/'containerd-data')+'"\n'
                      'state = "'+str(SCRATCH/'containerd-run')+'"\n'
                      'disabled_plugins = ["io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime", "io.containerd.grpc.v1.cri"]\n'
                      '[grpc]\naddress = "'+str(SCRATCH/'containerd.sock')+'"\n')
    (SCRATCH/'containerd.toml').write_text(containerd_config)
    socket=SCRATCH/'docker.sock'
    config={'data-root':str(SCRATCH/'docker-data'),'exec-root':str(SCRATCH/'docker-run'),
            'pidfile':str(SCRATCH/'dockerd.pid'),'hosts':['unix://'+str(socket)],
            'containerd':str(SCRATCH/'containerd.sock'),'containerd-namespace':'platform-backup-drill',
            'containerd-plugins-namespace':'platform-backup-drill-plugins',
            'bridge':'none','iptables':False,'ip6tables':False,'ip-forward':False,'ip-masq':False,
            'userland-proxy':False,'features':{'containerd-snapshotter':True}}
    save(SCRATCH/'docker.json',config)
    run(['dockerd','--validate','--config-file',str(SCRATCH/'docker.json')])
    started=False;proof=None
    try:
        run(['systemd-run','--quiet','--collect','--unit',UNIT,'--property=PrivateNetwork=yes',
             '--property=PrivateMounts=yes','--property=KillMode=control-group','--property=RuntimeMaxSec=900',
             '--property=TimeoutStopSec=45','--property=UMask=0022',
             '/usr/bin/python3',str(HERE),'--daemon'])
        started=True;deadline=time.monotonic()+90
        cli=['docker','--host','unix://'+str(socket)]
        while True:
            try:
                if socket.exists(): run(cli+['info','--format','{{.ID}}'],5);break
            except subprocess.SubprocessError: pass
            state=subprocess.run(['systemctl','is-active',UNIT],capture_output=True,text=True,timeout=10)
            if state.stdout.strip() in ('inactive','failed','unknown'):
                raise RuntimeError('PRIVATE_DOCKER_EXITED_DURING_STARTUP')
            if time.monotonic()>deadline: raise RuntimeError('PRIVATE_DOCKER_START_TIMEOUT')
            time.sleep(1)
        pid=int(run(['systemctl','show',UNIT,'--property=MainPID','--value']).strip())
        if pid<=1 or os.stat('/proc/'+str(pid)+'/ns/net').st_ino==os.stat('/proc/self/ns/net').st_ino:
            raise RuntimeError('PRIVATE_NETWORK_NAMESPACE_NOT_CONFIRMED')
        if run(cli+['image','ls','-aq']).strip() or run(cli+['ps','-aq']).strip():
            raise RuntimeError('PRIVATE_DAEMON_NOT_EMPTY')
        load=run(cli+['image','load','--platform=linux/amd64','--input',str(EXPORT)],600)
        restored_ids=run(cli+['image','ls','-aq','--no-trunc']).split()
        restored=json.loads(run(cli+['image','inspect',*restored_ids]))
        actual={r['Id'] for r in restored}
        if actual!=expected or any((r['Os'],r['Architecture'])!=('linux','amd64') for r in restored):
            raise RuntimeError('ISOLATED_IMAGE_ID_OR_PLATFORM_MISMATCH')
        postgres=[image for name,_,image in initial if name=='gf-postgres']
        if len(postgres)!=1 or postgres[0] not in actual:
            raise RuntimeError('GF_POSTGRES_IMAGE_BINDING_REQUIRED')
        # The observed failure was specific to gf-postgres when running its
        # shell as UID 70; do not run arbitrary commands in unrelated/distroless images.
        run(cli+['run','--rm','--network','none','--user','70','--workdir','/',
                 '--entrypoint','/bin/sh',
                 postgres[0],'-c','test -x /bin/sh'],60)
        if host_inventory()!=initial: raise RuntimeError('HOST_INVENTORY_DRIFT_DURING_IMAGE_TEST')
        proof={'schema':'platform.isolated-native-image-load/v1','status':'passed','imageCount':len(actual),
               'imageIds':sorted(actual),'platform':'linux/amd64','archiveSha256':EXPORT_SHA,
               'sourceArchiveSha256':report['archiveSha256'],'hostContainersPreserved':True,
               'privateNetworkNamespaceConfirmed':True,'productionDockerSocketUsedForWrites':False,
               'containersStarted':1,'applicationContainersStarted':0,
               'gfPostgresUid70ShellProbe':{'status':'passed','imageId':postgres[0],
                   'user':'70','entrypoint':'/bin/sh','command':'test -x /bin/sh',
                   'network':'none','workdir':'/'},
               'fullyRecoverable':False,'networkDownloadUsed':False,
               'completedAt':dt.datetime.now(dt.timezone.utc).isoformat()}
    finally:
        if started:
            state=subprocess.run(['systemctl','is-active',UNIT],capture_output=True,text=True,timeout=30)
            if state.stdout.strip() not in ('inactive','failed','unknown'):
                run(['systemctl','stop',UNIT],90)
        if started:
            state=subprocess.run(['systemctl','is-active',UNIT],capture_output=True,text=True,timeout=30)
            if state.stdout.strip() not in ('inactive','failed','unknown'):
                raise RuntimeError('PRIVATE_DAEMON_SHUTDOWN_UNCONFIRMED')
    if proof:
        proof['privateDaemonStopped']=True
        save(ROOT/'isolated-image-load-proof.json',proof)
        print(json.dumps({k:v for k,v in proof.items() if k!='imageIds'},sort_keys=True),flush=True)


if __name__=='__main__': main()
