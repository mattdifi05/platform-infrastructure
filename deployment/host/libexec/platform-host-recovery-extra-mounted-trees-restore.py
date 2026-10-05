#!/usr/bin/python3
"""Verify and materialize an exact extra-tree bundle into NEW private staging.

Never writes a live mount. Expected input digests must come from independently
verified capture/capsule evidence; a local drill does not establish offsite proof.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tarfile
import tempfile

CAPTURE_SHA256='336da4bb00e7f8e80b7ca7462d19b395025961623f0968e9241af00aa34c0fbe'
code=Path(__file__).with_name('platform-host-recovery-extra-mounted-trees.py')
if code.is_symlink() or code.resolve()!=code.absolute() or not code.is_file(): raise RuntimeError('CAPTURE_DEPENDENCY_PATH')
if hashlib.sha256(code.read_bytes()).hexdigest()!=CAPTURE_SHA256: raise RuntimeError('CAPTURE_DEPENDENCY_HASH')
info=code.stat()
if info.st_uid!=os.geteuid() or info.st_mode&0o022 or info.st_nlink!=1: raise RuntimeError('CAPTURE_DEPENDENCY_PROTECTION')
spec=importlib.util.spec_from_file_location('extra_capture',code); cap=importlib.util.module_from_spec(spec);spec.loader.exec_module(cap)
Blocked=cap.Blocked
DESTINATION=Path('/var/lib/platform-isolated-stack-20260930/recovered-inputs/extra-mounted-trees')
MAX_INDEX_BYTES=32*1024*1024
FIELDS={'path','type','uid','gid','mode','mtimeNs','ctimeNs','device','inode','links','xattrs'}


def hash_stream(stream):
    h=hashlib.sha256()
    for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def sha_path(path):
    with path.open('rb') as f:return hash_stream(f)

def pinned_input(directory,name,expected,limit):
    if not isinstance(expected,str) or len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected): raise Blocked('EXPECTED_DIGEST_REQUIRED')
    fd=cap.open_root(directory)
    try:
        parent=os.fstat(fd)
        if parent.st_uid!=os.geteuid() or parent.st_mode&0o077: raise Blocked('INPUT_DIRECTORY_NOT_PRIVATE')
        source=os.open(name,cap.FLAGS,dir_fd=fd)
        try:
            before=os.fstat(source)
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_mode&0o077 or before.st_nlink!=1 or before.st_size>limit: raise Blocked('INPUT_FILE_PROTECTION_OR_BOUND')
            with os.fdopen(os.dup(source),'rb') as stream: actual=hash_stream(stream)
            if cap.signature(before)!=cap.signature(os.fstat(source)) or actual!=expected: raise Blocked('INPUT_IDENTITY_MISMATCH')
            os.lseek(source,0,os.SEEK_SET)
            return source,before
        except BaseException: os.close(source);raise
    finally: os.close(fd)


def raw_prescan(stream):
    """Bound PAX/GNU payloads before tarfile can allocate or interpret them."""
    stream.seek(0); blocks=0; ended=False
    while True:
        header=stream.read(512)
        if not header: raise Blocked('TAR_END_MARKERS_MISSING')
        if len(header)!=512: raise Blocked('TAR_HEADER_TRUNCATED')
        if header==b'\0'*512:
            if stream.read(512)!=b'\0'*512: raise Blocked('TAR_SECOND_END_MARKER_MISSING')
            while True:
                tail=stream.read(65536)
                if not tail:break
                if any(tail):raise Blocked('TAR_NONZERO_TRAILING_BYTES')
            ended=True;break
        blocks+=1
        if blocks>2*cap.MAX_ENTRIES+8:raise Blocked('TAR_HEADER_COUNT_BOUND')
        for field in (header[124:136],header[148:156]):
            if any(v not in b'01234567 \0' for v in field):raise Blocked('TAR_NUMERIC_ENCODING')
        size=int(header[124:136].strip(b'\0 ') or b'0',8)
        checksum=int(header[148:156].strip(b'\0 ') or b'0',8)
        if checksum!=sum(header[:148])+8*32+sum(header[156:]):raise Blocked('TAR_HEADER_CHECKSUM')
        kind=header[156:157]
        if kind not in (b'0',b'\0',b'5',b'1',b'x'):raise Blocked('TAR_EXTENSION_OR_SPECIAL_FORBIDDEN')
        if (kind==b'x' and size>1024*1024) or (kind!=b'x' and size>max(cap.MAX_FILE_BYTES,MAX_INDEX_BYTES)):raise Blocked('TAR_MEMBER_BOUND')
        if kind in (b'5',b'1') and size:raise Blocked('TAR_NONFILE_PAYLOAD')
        remaining=((size+511)//512)*512
        if kind==b'x':
            raw=stream.read(remaining)
            if len(raw)!=remaining:raise Blocked('PAX_TRUNCATED')
            payload=raw[:size];offset=0;keys=set()
            while offset<len(payload):
                space=payload.find(b' ',offset,offset+12)
                if space<0 or not payload[offset:space].isdigit():raise Blocked('PAX_LENGTH_ENCODING')
                count=int(payload[offset:space]);end=offset+count
                if count<5 or end>len(payload) or payload[end-1:end]!=b'\n':raise Blocked('PAX_LENGTH_BOUND')
                key,separator,value=payload[space+1:end-1].partition(b'=')
                if not separator or key in keys or key not in (b'mtime',b'PLATFORM.mtimeNs',b'PLATFORM.xattrs.json',b'path',b'linkpath',b'uid',b'gid'):raise Blocked('PAX_KEY_FORBIDDEN')
                if key!=b'PLATFORM.xattrs.json' and len(value)>4096:raise Blocked('PAX_VALUE_BOUND')
                keys.add(key);offset=end
            remaining=0
        while remaining:
            chunk=stream.read(min(65536,remaining))
            if not chunk:raise Blocked('TAR_PAYLOAD_TRUNCATED')
            remaining-=len(chunk)
    if not ended:raise Blocked('TAR_UNTERMINATED')
    stream.seek(0)


def safe_rel(value):
    if not isinstance(value,str) or len(value.encode())>4096:raise Blocked('INDEX_PATH_BOUND')
    if value=='.':return value
    p=PurePosixPath(value)
    if p.is_absolute() or any(x in ('','.','..') for x in value.split('/')) or str(p)!=value or '\0' in value:raise Blocked('INDEX_PATH_UNSAFE')
    return value


def validate_index(index, roots, fixtures):
    if set(index)!={'schema','baselineCatalogSha256','capture','runtimeFixtures','fixturePolicy','xattrEncoding','hardlinkPolicy'} or index['schema']!='platform.extra-mounted-trees-index/v1' or index['baselineCatalogSha256']!=cap.CATALOG_SHA256:raise Blocked('INDEX_SCHEMA')
    if index['runtimeFixtures']!=sorted(fixtures) or index['fixturePolicy']!='private-only-source-fifo-metadata-no-read' or index['hardlinkPolicy']!='preserved-within-complete-capture':raise Blocked('INDEX_POLICY')
    if index['xattrEncoding']!='PLATFORM.xattrs.json base64; restore must explicitly apply and verify':raise Blocked('INDEX_XATTR_POLICY')
    capture=index['capture']
    if set(capture)!={'trees','totals'} or set(capture['trees'])!=set(roots)|set(fixtures):raise Blocked('INDEX_TREE_SET')
    expected={}; groups={}; budget={'entries':0,'bytes':0,'xattrs':0}
    for name,source in sorted({**roots,**fixtures}.items()):
        tree=capture['trees'][name]
        if set(tree)!={'source','entries'} or tree['source']!=str(source) or not isinstance(tree['entries'],list):raise Blocked('INDEX_SOURCE_BINDING')
        rows=tree['entries']; names=set()
        if rows!=sorted(rows,key=lambda r:r['path']):raise Blocked('INDEX_ORDER')
        for row in rows:
            path=safe_rel(row['path']); kind=row['type']; fields=FIELDS|({'bytes','sha256'} if kind=='file' else set())
            if set(row)!=fields or path in names or kind not in ('directory','file','fifo'):raise Blocked('INDEX_MEMBER_FIELDS')
            names.add(path);budget['entries']+=1
            if any(type(row[k]) is not int for k in ('uid','gid','mode','mtimeNs','ctimeNs','device','inode','links')) or not 0<=row['mode']<=0o7777 or min(row['uid'],row['gid'])<0:raise Blocked('INDEX_NUMERIC_METADATA')
            if kind=='fifo' and (name!='phppgadmin-mail-spool' or path!='trigger' or name not in fixtures):raise Blocked('INDEX_FIFO_SCOPE')
            if name in fixtures and kind=='file':raise Blocked('INDEX_FIXTURE_HAS_DATA')
            attrs=row['xattrs'];seenattrs=set()
            if not isinstance(attrs,list) or len(attrs)>128:raise Blocked('INDEX_XATTR_COUNT')
            for attr in attrs:
                if set(attr)!={'nameB64','valueB64'}:raise Blocked('INDEX_XATTR_FIELDS')
                key=base64.b64decode(attr['nameB64'],validate=True);val=base64.b64decode(attr['valueB64'],validate=True)
                if not key or b'\0' in key or len(key)>1024 or len(val)>65536 or key in seenattrs:raise Blocked('INDEX_XATTR_BOUND')
                seenattrs.add(key);budget['xattrs']+=len(key)+len(val)
            if kind=='file':
                if type(row['bytes']) is not int or not 0<=row['bytes']<=cap.MAX_FILE_BYTES or len(row['sha256'])!=64 or any(c not in '0123456789abcdef' for c in row['sha256']):raise Blocked('INDEX_CONTENT')
                budget['bytes']+=row['bytes'];groups.setdefault((row['device'],row['inode']),[]).append(row)
            if name in roots:expected['trees/'+name+('' if path=='.' else '/'+path)]=row
        if not rows or rows[0]['path']!='.' or rows[0]['type']!='directory':raise Blocked('INDEX_ROOT_REQUIRED')
        types={r['path']:r['type'] for r in rows}
        for row in rows[1:]:
            parent=str(PurePosixPath(row['path']).parent)
            if types.get(parent)!='directory':raise Blocked('INDEX_PARENT_NOT_DIRECTORY')
        if name=='phppgadmin-sites' and list(types.items())!=[('.','directory')]:raise Blocked('INDEX_SITES_NOT_EMPTY')
        if name=='phppgadmin-mail-spool' and types!={'.':'directory','failed':'directory','queue':'directory','tmp':'directory','trigger':'fifo'}:raise Blocked('INDEX_SPOOL_SCOPE')
    if budget!=capture['totals'] or budget['entries']>cap.MAX_ENTRIES or budget['bytes']>cap.MAX_BYTES or budget['xattrs']>cap.MAX_XATTR_BYTES:raise Blocked('INDEX_TOTAL_BOUND')
    for rows in groups.values():
        if any(r['links']!=len(rows) for r in rows):raise Blocked('INDEX_HARDLINK_INCOMPLETE')
        keys=('uid','gid','mode','mtimeNs','xattrs','bytes','sha256')
        if any(any(r[k]!=rows[0][k] for k in keys) for r in rows):raise Blocked('INDEX_HARDLINK_METADATA_CONFLICT')
    return expected


def apply_metadata(path,row):
    if os.geteuid()==0:os.chown(path,row['uid'],row['gid'],follow_symlinks=False)
    elif (path.stat().st_uid,path.stat().st_gid)!=(row['uid'],row['gid']):raise Blocked('ROOT_REQUIRED_FOR_OWNER_RESTORE')
    os.chmod(path,row['mode'],follow_symlinks=False)
    fd=os.open(path,cap.DIRFLAGS if row['type']=='directory' else cap.FLAGS)
    try:
        wanted={base64.b64decode(a['nameB64']):base64.b64decode(a['valueB64']) for a in row['xattrs']}
        actual={base64.b64decode(a['nameB64']):base64.b64decode(a['valueB64']) for a in cap.attrs(fd)}
        if hasattr(os,'setxattr'):
            for key in set(actual)-set(wanted):os.removexattr(fd,key)
            for key,val in wanted.items():os.setxattr(fd,key,val)
        elif actual!=wanted:raise Blocked('NATIVE_XATTR_WRITE_API_REQUIRED')
        os.utime(fd,ns=(row['mtimeNs'],row['mtimeNs']))
        if row['type']!='fifo':os.fsync(fd)
        st=os.fstat(fd)
        if (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),st.st_mtime_ns)!=(row['uid'],row['gid'],row['mode'],row['mtimeNs']) or cap.attrs(fd)!=row['xattrs']:raise Blocked('RESTORED_METADATA_DIFFERS')
    finally:os.close(fd)


def restore(directory,destination,archive_sha,index_sha,proof_sha,roots=cap.ROOTS,fixtures=cap.FIXTURES):
    directory=Path(directory);destination=Path(destination)
    if destination.exists() or destination.is_symlink():raise Blocked('DESTINATION_ALREADY_EXISTS')
    pfd=cap.open_root(destination.parent)
    try:
        info=os.fstat(pfd)
        if info.st_uid!=os.geteuid() or info.st_mode&0o022:raise Blocked('DESTINATION_PARENT_NOT_PROTECTED')
    finally:os.close(pfd)
    handles=[];stage=None
    try:
        for name,dig,limit in [('current.tar',archive_sha,cap.MAX_ARCHIVE_BYTES),('index.json',index_sha,MAX_INDEX_BYTES),('capture-proof.json',proof_sha,65536)]:
            fd,st=pinned_input(directory,name,dig,limit);handles.append((fd,st))
        with os.fdopen(os.dup(handles[1][0]),'rb') as f:indexbytes=f.read(MAX_INDEX_BYTES+1)
        with os.fdopen(os.dup(handles[2][0]),'rb') as f:proof=json.load(f)
        index=json.loads(indexbytes);expected=validate_index(index,roots,fixtures)
        if set(proof)!={'schema','startedAt','completedAt','baselineCatalogSha256','treeCount','runtimeFixtureCount','productionDataWrites','servicesStopped','completeBeforeAfterEqual','globalAtomicSnapshot','exclusions','archive','indexSha256','totals','authenticatedOffsite'} or proof.get('servicesStopped') is not False or proof.get('globalAtomicSnapshot') is not False or proof.get('authenticatedOffsite') is not False:raise Blocked('CAPTURE_PROOF_SCHEMA')
        if proof.get('schema')!='platform.extra-mounted-trees-capture/v1' or proof.get('baselineCatalogSha256')!=cap.CATALOG_SHA256 or proof.get('indexSha256')!=index_sha or proof.get('archive')!={'file':'current.tar','bytes':handles[0][1].st_size,'sha256':archive_sha} or proof.get('treeCount')!=len(roots) or proof.get('runtimeFixtureCount')!=len(fixtures) or proof.get('completeBeforeAfterEqual') is not True or proof.get('productionDataWrites') is not False or proof.get('exclusions')!=[] or proof.get('totals')!=index['capture']['totals']:raise Blocked('CAPTURE_PROOF_BINDING')
        stage=Path(tempfile.mkdtemp(prefix='.extra-restore-',dir=destination.parent));os.chmod(stage,0o700)
        seen={};groups={}
        with os.fdopen(os.dup(handles[0][0]),'rb') as source:
            raw_prescan(source)
            with tarfile.open(fileobj=source,mode='r:') as archive:
                for member in archive:
                    if member.name in seen:raise Blocked('TAR_DUPLICATE')
                    if member.name=='index.json':
                        if not member.isfile() or member.size!=len(indexbytes) or archive.extractfile(member).read(MAX_INDEX_BYTES+1)!=indexbytes:raise Blocked('EMBEDDED_INDEX_DIFFERS')
                        seen[member.name]=None;continue
                    row=expected.get(member.name)
                    if row is None:raise Blocked('TAR_UNKNOWN_MEMBER')
                    if (member.uid,member.gid,member.mode)!=(row['uid'],row['gid'],row['mode']) or member.pax_headers.get('PLATFORM.mtimeNs')!=str(row['mtimeNs']) or json.loads(member.pax_headers.get('PLATFORM.xattrs.json','null'))!=row['xattrs']:raise Blocked('TAR_METADATA_BINDING')
                    if set(member.pax_headers)-{'mtime','PLATFORM.mtimeNs','PLATFORM.xattrs.json','path','linkpath','uid','gid'}:raise Blocked('TAR_UNKNOWN_PAX_FIELD')
                    target=stage.joinpath(*PurePosixPath(member.name).parts)
                    if row['path']=='.':(stage/'trees').mkdir(mode=0o700,exist_ok=True)
                    if row['type']=='directory':
                        if not member.isdir():raise Blocked('TAR_DIRECTORY_TYPE')
                        target.mkdir(mode=0o700)
                    else:
                        inode=(row['device'],row['inode']);first=groups.get(inode)
                        if member.islnk():
                            if first is None or member.linkname!=first or member.linkname not in seen or member.size:raise Blocked('TAR_HARDLINK_BINDING')
                            os.link(stage/member.linkname,target,follow_symlinks=False)
                        else:
                            if not member.isfile() or member.size!=row['bytes'] or first is not None:raise Blocked('TAR_FILE_BINDING')
                            h=hashlib.sha256();count=0
                            with archive.extractfile(member) as inp,open(target,'xb') as out:
                                os.fchmod(out.fileno(),0o600)
                                for chunk in iter(lambda:inp.read(1024*1024),b''):h.update(chunk);count+=len(chunk);out.write(chunk)
                                out.flush();os.fsync(out.fileno())
                            if count!=row['bytes'] or h.hexdigest()!=row['sha256']:raise Blocked('TAR_CONTENT_HASH')
                            groups[inode]=member.name
                    seen[member.name]=row
        if set(seen)!=set(expected)|{'index.json'}:raise Blocked('TAR_MEMBER_SET')
        for name in fixtures:
            for row in index['capture']['trees'][name]['entries']:
                target=stage/'fixtures'/name
                if row['path']!='.':target=target/row['path']
                if row['path']=='.':(stage/'fixtures').mkdir(mode=0o700,exist_ok=True)
                if row['type']=='directory':target.mkdir(mode=0o700)
                else:os.mkfifo(target,0o600)
        bindings=[]
        for name,tree in index['capture']['trees'].items():
            base=stage/('fixtures' if name in fixtures else 'trees')/name
            for row in tree['entries']:bindings.append((base if row['path']=='.' else base/row['path'],row))
        bindings.sort(key=lambda pair:(pair[1]['type']=='directory',-len(pair[0].parts)))
        for path,row in bindings:apply_metadata(path,row)
        after=cap.scan({n:stage/'trees'/n for n in roots},{n:stage/'fixtures'/n for n in fixtures})
        projection=lambda rows:[{k:v for k,v in r.items() if k not in ('ctimeNs','device','inode')} for r in rows]
        for name,tree in after['trees'].items():
            if projection(tree['entries'])!=projection(index['capture']['trees'][name]['entries']):raise Blocked('RESTORED_TREE_VERIFICATION')
        for fd,before in handles:
            if cap.signature(os.fstat(fd))!=cap.signature(before):raise Blocked('INPUT_CHANGED_DURING_RESTORE')
        result={'schema':'platform.extra-mounted-trees-private-restore/v1','status':'passed','archiveSha256':archive_sha,'indexSha256':index_sha,'captureProofSha256':proof_sha,'treeCount':len(roots),'runtimeFixtureCount':len(fixtures),'contentMetadataAndHardlinksVerified':True,'productionModified':False,'offsiteAuthenticated':False,'liveRestoreVerified':False}
        cap.write_file(stage/'restore-proof.json',cap.canonical(result));cap.sync_dir(stage)
        if destination.exists() or destination.is_symlink():raise Blocked('DESTINATION_APPEARED')
        os.rename(stage,destination);cap.sync_dir(destination.parent);stage=None
        return result
    finally:
        for fd,_ in handles:os.close(fd)
        if stage is not None and stage.exists():shutil.rmtree(stage)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--input',type=Path,required=True)
    for name in ('archive','index','proof'):parser.add_argument('--'+name+'-sha256',required=True)
    args=parser.parse_args()
    if os.geteuid()!=0 or sys.platform!='linux':raise Blocked('LINUX_ROOT_REQUIRED')
    os.umask(0o077)
    result=restore(args.input,DESTINATION,args.archive_sha256,args.index_sha256,args.proof_sha256)
    print(json.dumps({'status':result['status'],'trees':result['treeCount'],'runtimeFixtures':result['runtimeFixtureCount'],'productionModified':False}))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'blocked','errorType':type(error).__name__,'reason':str(error) if isinstance(error,Blocked) else 'PRIVATE_RESTORE_FAILED'}));sys.exit(1)
