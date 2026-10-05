#!/usr/bin/python3
"""One-shot root capturer. Reads fixed live trees; writes only a new private bundle.

No service control, Docker, network, live restore or exclusion rules. A changed
source aborts the entire bundle. Output directory must not exist; the directory
containing current.tar, index.json and proof.json becomes visible atomically.
"""
import base64
import ctypes
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tempfile

CATALOG_SHA256 = '71d8598b06fcccfe776a3ced6497cff5d9f796f73e31fb787de8248dd88c8bf5'
DESTINATION = Path('/var/lib/platform-host-recovery/extra-mounted-trees')
PREVIOUS = Path('/var/lib/platform-host-recovery/extra-mounted-trees-previous')
ROOTS = {
 'backup-reports': '/home/platform_infrastructure/v1-fresh-runtime/local-private-backup/data/reports',
 'infra-docs': '/home/platform_infrastructure/v11-main-43fe7f4',
 'project-reader-repository': '/var/lib/platform-infrastructure/server-ai-background-20260907/repo',
 'searxng-search': '/home/platform_infrastructure/server-ai-provision-20260906/config/server-ai/search',
 'alloy-state': '/home/platform_infrastructure/v1-fresh-runtime/maintenance/20260927/alloy-state',
 'nats-auth-config': '/var/lib/docker/volumes/greenfield_nats_auth_config/_data',
 'redis-auth-config': '/var/lib/docker/volumes/greenfield_redis_auth_config/_data',
 'phppgadmin-nginx-log': '/var/lib/docker/volumes/5121738e7e30cc5e4d26a634cec3c1a26fc773b65c57d2ad766dfefe8f71ee72/_data',
 'phppgadmin-mail-log': '/var/lib/docker/volumes/2de2c9b42bc79d334614b20a551ee91bff74b844da13453e0491f143455d93f9/_data',
}
FIXTURES = {
 'phppgadmin-sites': '/var/lib/docker/volumes/59568063b97001cf8b4c9e8761f66312ee1414c64b4aadf63926348f530d1303/_data',
 'phppgadmin-mail-spool': '/var/lib/docker/volumes/d800f7c2273e16ff83a72128bd657d7abd7af90e1fedb4a3576aa220073340ff/_data',
}
CONFIG_FILES = {'nats-auth-config': 'nats-server.conf', 'redis-auth-config': 'redis-users.acl'}
MAX_ENTRIES = 20000
MAX_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 192 * 1024 * 1024
MAX_XATTR_BYTES = 8 * 1024 * 1024
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
DIRFLAGS = FLAGS | os.O_DIRECTORY

class Blocked(RuntimeError): pass

def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
def digest(data): return hashlib.sha256(data).hexdigest()
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def signature(st):
    return tuple(getattr(st, k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns','st_nlink'))

def open_root(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts: raise Blocked('NONCANONICAL_ROOT')
    fd = os.open('/', DIRFLAGS)
    try:
        for part in path.parts[1:]:
            nxt = os.open(part, DIRFLAGS, dir_fd=fd)
            os.close(fd); fd = nxt
        return fd
    except BaseException:
        os.close(fd); raise

def attrs(fd):
    """Read xattrs from the already opened inode, including binary POSIX ACLs."""
    if hasattr(os, 'listxattr'):
        names = os.listxattr(fd)
        get = lambda name: os.getxattr(fd, name)
    elif sys.platform == 'darwin':
        libc = ctypes.CDLL(None, use_errno=True)
        listing = libc.flistxattr; listing.argtypes = [ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]; listing.restype = ctypes.c_ssize_t
        getter = libc.fgetxattr; getter.argtypes = [ctypes.c_int,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint32,ctypes.c_int]; getter.restype = ctypes.c_ssize_t
        count = listing(fd,None,0,0)
        if not 0 <= count <= 65536: raise Blocked('XATTR_LIST_BOUND')
        buf = ctypes.create_string_buffer(count)
        if listing(fd,buf,count,0) != count: raise Blocked('XATTR_LIST_CHANGED')
        names = [v for v in buf.raw.split(b'\0') if v]
        def get(name):
            size = getter(fd,os.fsencode(name),None,0,0,0)
            if not 0 <= size <= 65536: raise Blocked('XATTR_VALUE_BOUND')
            value = ctypes.create_string_buffer(size)
            if getter(fd,os.fsencode(name),value,size,0,0) != size: raise Blocked('XATTR_VALUE_CHANGED')
            return value.raw
    else: raise Blocked('XATTR_API_REQUIRED')
    if len(names) > 128: raise Blocked('XATTR_COUNT_BOUND')
    result = []
    for name in names:
        value = get(name); name = os.fsencode(name)
        if len(name) > 1024 or len(value) > 65536: raise Blocked('XATTR_BOUND')
        result.append({'nameB64':base64.b64encode(name).decode(), 'valueB64':base64.b64encode(value).decode()})
    return sorted(result,key=lambda r:r['nameB64'])

def metadata(st, rel, kind, xattrs):
    return {'path':rel,'type':kind,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),
            'mtimeNs':st.st_mtime_ns,'ctimeNs':st.st_ctime_ns,'device':st.st_dev,'inode':st.st_ino,
            'links':st.st_nlink,'xattrs':xattrs}

def tar_info(name, row):
    info = tarfile.TarInfo(name)
    info.uid=row['uid']; info.gid=row['gid']; info.mode=row['mode']
    secs, nanos = divmod(abs(row['mtimeNs']), 1000000000)
    timestamp=('-' if row['mtimeNs']<0 else '')+f'{secs}.{nanos:09d}'
    info.mtime=row['mtimeNs']//1000000000; info.pax_headers={'mtime':timestamp,
        'PLATFORM.xattrs.json':canonical(row['xattrs']).decode(), 'PLATFORM.mtimeNs':str(row['mtimeNs'])}
    info.type=tarfile.DIRTYPE if row['type']=='directory' else tarfile.REGTYPE
    info.size=row.get('bytes',0)
    return info

class HashReader:
    def __init__(self, stream): self.stream=stream; self.hash=hashlib.sha256(); self.bytes=0
    def read(self, amount):
        value=self.stream.read(amount); self.hash.update(value); self.bytes+=len(value); return value


def scan(roots, fixtures, archive=None):
    trees={}; budget={'entries':0,'bytes':0,'xattrs':0}; inode_paths={}; hardlinks={}
    def visit(fd, rel, name, device, depth, rows, fixture):
        before=os.fstat(fd)
        if depth>64 or before.st_dev!=device: raise Blocked('TREE_DEPTH_OR_DEVICE_BOUND')
        directory=stat.S_ISDIR(before.st_mode)
        if not directory and not stat.S_ISREG(before.st_mode): raise Blocked('SPECIAL_MEMBER')
        row=metadata(before,rel,'directory' if directory else 'file',attrs(fd))
        budget['entries']+=1
        budget['xattrs']+=sum(len(base64.b64decode(x['nameB64']))+len(base64.b64decode(x['valueB64'])) for x in row['xattrs'])
        if budget['entries']>MAX_ENTRIES or budget['xattrs']>MAX_XATTR_BYTES: raise Blocked('TREE_METADATA_BOUND')
        rows.append(row)
        member='trees/'+name+('' if rel=='.' else '/'+rel)
        if directory:
            if archive is not None and not fixture: archive.addfile(tar_info(member,row))
            names=sorted(os.listdir(fd))
            if len(names)>MAX_ENTRIES: raise Blocked('DIRECTORY_ENTRY_BOUND')
            for child in names:
                child.encode('utf-8',errors='strict')
                if child in ('','.','..') or len(child.encode())>4096: raise Blocked('UNSAFE_NAME')
                sub=child if rel=='.' else rel+'/'+child
                item=os.stat(child,dir_fd=fd,follow_symlinks=False)
                if fixture and name=='phppgadmin-mail-spool' and sub=='trigger':
                    if not stat.S_ISFIFO(item.st_mode) or item.st_nlink!=1: raise Blocked('TRIGGER_MUST_BE_FIFO')
                    # Nonblocking metadata-only FD: no FIFO bytes are ever read.
                    pipe_fd=os.open(child,FLAGS,dir_fd=fd)
                    try:
                        if signature(os.fstat(pipe_fd))!=signature(item): raise Blocked('FIFO_REPLACED')
                        pipe_attrs=attrs(pipe_fd)
                        if signature(os.fstat(pipe_fd))!=signature(item): raise Blocked('FIFO_CHANGED')
                    finally: os.close(pipe_fd)
                    rows.append(metadata(item,sub,'fifo',pipe_attrs)); budget['entries']+=1
                    budget['xattrs']+=sum(len(base64.b64decode(x['nameB64']))+len(base64.b64decode(x['valueB64'])) for x in pipe_attrs)
                    if budget['entries']>MAX_ENTRIES or budget['xattrs']>MAX_XATTR_BYTES: raise Blocked('TREE_METADATA_BOUND')
                    continue
                if not (stat.S_ISDIR(item.st_mode) or stat.S_ISREG(item.st_mode)): raise Blocked('SOURCE_SYMLINK_OR_SPECIAL')
                child_fd=os.open(child,DIRFLAGS if stat.S_ISDIR(item.st_mode) else FLAGS,dir_fd=fd)
                try:
                    if signature(os.fstat(child_fd))!=signature(item): raise Blocked('SOURCE_REPLACED_BEFORE_OPEN')
                    visit(child_fd,sub,name,device,depth+1,rows,fixture)
                finally: os.close(child_fd)
        else:
            if fixture: raise Blocked('RUNTIME_FIXTURE_HAS_DATA')
            budget['bytes']+=before.st_size
            if before.st_size>MAX_FILE_BYTES or budget['bytes']>MAX_BYTES: raise Blocked('CONTENT_BYTE_BOUND')
            row['bytes']=before.st_size
            inode=(before.st_dev,before.st_ino)
            with os.fdopen(os.dup(fd),'rb') as stream:
                reader=HashReader(stream)
                info=tar_info(member,row)
                if archive is not None and inode not in inode_paths: archive.addfile(info,reader)
                else:
                    while reader.read(1024*1024): pass
                    if archive is not None:
                        info.type=tarfile.LNKTYPE; info.linkname=inode_paths[inode]; info.size=0; archive.addfile(info)
                if reader.bytes!=before.st_size or reader.read(1): raise Blocked('CONTENT_SIZE_CHANGED')
                row['sha256']=reader.hash.hexdigest()
            inode_paths.setdefault(inode,member); hardlinks.setdefault(inode,[]).append(row)
        if signature(os.fstat(fd))!=signature(before) or attrs(fd)!=row['xattrs']: raise Blocked('SOURCE_CHANGED_DURING_READ')
    for name, path in sorted({**roots,**fixtures}.items()):
        fd=open_root(path)
        try:
            rows=[]; visit(fd,'.',name,os.fstat(fd).st_dev,0,rows,name in fixtures)
            rows.sort(key=lambda r:r['path']); trees[name]={'source':str(path),'entries':rows}
        finally: os.close(fd)
    for rows in hardlinks.values():
        if any(r['links']!=len(rows) for r in rows): raise Blocked('HARDLINK_OUTSIDE_CAPTURE')
    if 'phppgadmin-sites' in fixtures:
        if [(r['path'],r['type']) for r in trees['phppgadmin-sites']['entries']]!=[('.','directory')]: raise Blocked('SITES_NOT_EMPTY')
    if 'phppgadmin-mail-spool' in fixtures:
        expected=[('.','directory'),('failed','directory'),('queue','directory'),('tmp','directory'),('trigger','fifo')]
        if [(r['path'],r['type']) for r in trees['phppgadmin-mail-spool']['entries']]!=expected: raise Blocked('MAIL_SPOOL_NOT_EMPTY_RUNTIME')
    return {'trees':trees,'totals':budget}


def validate_configs(snapshot, archive_path):
    with tarfile.open(archive_path,'r:') as archive:
        for name, filename in CONFIG_FILES.items():
            rows=snapshot['trees'][name]['entries']
            if [(r['path'],r['type']) for r in rows]!=[('.','directory'),(filename,'file'),(filename+'.sha256','file')]: raise Blocked('CONFIG_MEMBER_SET_CHANGED')
            footer=archive.extractfile('trees/'+name+'/'+filename+'.sha256').read(4097)
            match=re.fullmatch(rb'([0-9a-f]{64})[ \t]+\*?([^\r\n]+)\n?',footer)
            if not match or match[1].decode()!=rows[1]['sha256'] or Path(os.fsdecode(match[2])).name!=filename: raise Blocked('CONFIG_CHECKSUM_FOOTER_MISMATCH')

def write_file(path,data):
    with open(path,'xb') as stream:
        os.fchmod(stream.fileno(),0o600); stream.write(data); stream.flush(); os.fsync(stream.fileno())

def sync_dir(path):
    fd=open_root(path)
    try: os.fsync(fd)
    finally: os.close(fd)

def capture(roots, fixtures, destination, verify_configs=True):
    destination=Path(destination)
    if destination.exists() or destination.is_symlink():
        if destination != DESTINATION or PREVIOUS.exists() or PREVIOUS.is_symlink(): raise Blocked('DESTINATION_OR_PREVIOUS_EXISTS')
        # Keep the previous authenticated inputs until the new parent point and
        # typed overlay have completed. The recurring coordinator removes this
        # exact sibling only after verified offsite success.
        previous = PREVIOUS
    else:
        previous = None
    parent_fd=open_root(destination.parent)
    try:
        info=os.fstat(parent_fd)
        if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)&0o022: raise Blocked('DESTINATION_PARENT_NOT_PROTECTED')
    finally: os.close(parent_fd)
    stage=Path(tempfile.mkdtemp(prefix='.extra-capture-',dir=destination.parent)); os.chmod(stage,0o700)
    started=now()
    try:
        tarpath=stage/'current.tar'
        with open(tarpath,'xb') as stream:
            os.fchmod(stream.fileno(),0o600)
            with tarfile.open(fileobj=stream,mode='w',format=tarfile.PAX_FORMAT) as archive:
                before=scan(roots,fixtures,archive)
                after=scan(roots,fixtures)
                if before!=after: raise Blocked('SOURCE_DRIFT_COMPLETE_SCAN')
                index={'schema':'platform.extra-mounted-trees-index/v1','baselineCatalogSha256':CATALOG_SHA256,
                       'capture':before,'runtimeFixtures':sorted(fixtures),'fixturePolicy':'private-only-source-fifo-metadata-no-read',
                       'xattrEncoding':'PLATFORM.xattrs.json base64; restore must explicitly apply and verify',
                       'hardlinkPolicy':'preserved-within-complete-capture'}
                indexbytes=canonical(index)
                member=tarfile.TarInfo('index.json'); member.mode=0o600; member.size=len(indexbytes)
                archive.addfile(member,io.BytesIO(indexbytes))
            stream.flush(); os.fsync(stream.fileno())
        if tarpath.stat().st_size>MAX_ARCHIVE_BYTES: raise Blocked('ARCHIVE_BYTE_BOUND')
        if verify_configs: validate_configs(before,tarpath)
        h=hashlib.sha256()
        with tarpath.open('rb') as stream:
            for block in iter(lambda:stream.read(1024*1024),b''): h.update(block)
        proof={'schema':'platform.extra-mounted-trees-capture/v1','startedAt':started,'completedAt':now(),
               'baselineCatalogSha256':CATALOG_SHA256,'treeCount':len(roots),'runtimeFixtureCount':len(fixtures),
               'productionDataWrites':False,'servicesStopped':False,'completeBeforeAfterEqual':True,
               'globalAtomicSnapshot':False,'exclusions':[], 'archive':{'file':'current.tar','bytes':tarpath.stat().st_size,'sha256':h.hexdigest()},
               'indexSha256':digest(indexbytes),'totals':before['totals'],'authenticatedOffsite':False}
        write_file(stage/'index.json',indexbytes); write_file(stage/'capture-proof.json',canonical(proof)); sync_dir(stage)
        if destination.exists() or destination.is_symlink():
            if previous is None or PREVIOUS.exists() or PREVIOUS.is_symlink(): raise Blocked('DESTINATION_APPEARED')
            os.rename(destination, PREVIOUS); sync_dir(destination.parent)
        try:
            os.rename(stage,destination); sync_dir(destination.parent)
        except BaseException:
            if previous is not None and PREVIOUS.exists() and not destination.exists():
                os.rename(PREVIOUS,destination); sync_dir(destination.parent)
            raise
        return proof
    finally:
        if stage.exists(): shutil.rmtree(stage)

def finalize_previous_after_verified_cycle():
    # Called only by the pinned recurring coordinator after signed parent and
    # typed-overlay remote readback succeed. Validate an exact private bundle.
    if not PREVIOUS.exists() and not PREVIOUS.is_symlink(): return {'status':'no-previous'}
    if PREVIOUS.is_symlink() or not PREVIOUS.is_dir(): raise Blocked('PREVIOUS_NOT_CANONICAL')
    info=PREVIOUS.lstat()
    if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700: raise Blocked('PREVIOUS_NOT_PRIVATE')
    names=sorted(x.name for x in PREVIOUS.iterdir())
    if names not in (['capture-proof.json','current.tar','index.json'], ['current.tar','index.json','proof.json']): raise Blocked('PREVIOUS_MEMBER_SET')
    proof_name='capture-proof.json' if 'capture-proof.json' in names else 'proof.json'
    proof=json.loads((PREVIOUS/proof_name).read_bytes())
    if proof.get('schema')!='platform.extra-mounted-trees-capture/v1' or proof.get('archive',{}).get('file')!='current.tar': raise Blocked('PREVIOUS_PROOF_INVALID')
    expected={'current.tar':proof['archive']['sha256'],'index.json':proof['indexSha256']}
    for name,digest_value in expected.items():
        path=PREVIOUS/name; st=path.lstat()
        if path.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1 or digest(path.read_bytes())!=digest_value: raise Blocked('PREVIOUS_MEMBER_DIGEST')
    proof_path=PREVIOUS/proof_name; st=proof_path.lstat()
    if proof_path.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1: raise Blocked('PREVIOUS_PROOF_PROTECTION')
    for name in names:
        (PREVIOUS/name).unlink()
    PREVIOUS.rmdir(); sync_dir(PREVIOUS.parent)
    return {'status':'previous-retired-after-verified-cycle'}

def main():
    if sys.platform!='linux' or os.geteuid()!=0: raise Blocked('LINUX_ROOT_REQUIRED')
    os.umask(0o077)
    proof=capture(ROOTS,FIXTURES,DESTINATION)
    print(json.dumps({'status':'captured-private-only','trees':proof['treeCount'],'runtimeFixtures':proof['runtimeFixtureCount'],
                      'archiveBytes':proof['archive']['bytes'],'archiveSha256':proof['archive']['sha256']}))

if __name__=='__main__':
    try: main()
    except Exception as error:
        # Never print arbitrary OS paths/content or credential checksum values.
        print(json.dumps({'status':'blocked','errorType':type(error).__name__,
                          'reason':str(error) if isinstance(error,Blocked) else 'PRIVATE_CAPTURE_FAILED'})); sys.exit(1)
