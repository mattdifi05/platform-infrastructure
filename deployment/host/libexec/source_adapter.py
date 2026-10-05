"""Fixture-only full-source directory replacement. No production entry point."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tempfile

SOURCE_COUNT = 16
MAX_MEMBERS = 10000
MAX_REGULAR_BYTES = 64 * 1024 * 1024


class Blocked(RuntimeError):
    pass


def production_apply(*_args, **_kwargs):
    raise Blocked('PRODUCTION_SOURCE_REPLACE_UNAVAILABLE')


def sha_file(path):
    h=hashlib.sha256()
    with open(path,'rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):
            h.update(chunk)
    return h.hexdigest()


def tree_hash(records):
    h=hashlib.sha256()
    for record in sorted(records,key=lambda x:x['path']):
        h.update(json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode())
        h.update(b'\n')
    return h.hexdigest()


def _record(path,kind,mode,uid,gid,mtime,**extra):
    return {'path':path,'type':kind,'mode':mode,'uid':uid,'gid':gid,'mtime':int(mtime),**extra}


def _member_record(member,relative):
    common=(relative,'directory' if member.isdir() else 'file' if member.isfile() else 'symlink',
            member.mode & 0o7777,member.uid,member.gid,member.mtime)
    if member.isfile():
        return _record(*common,size=member.size,sha256=None)
    if member.issym():
        return _record(*common,target=member.linkname)
    return _record(*common)


def _safe_relative(value):
    if not isinstance(value,str) or not value or value.startswith('/') or '\x00' in value or '\\' in value:
        raise Blocked('UNSAFE_ARCHIVE_PATH')
    parts=value.split('/')
    if any(part in ('','.','..') for part in parts):
        raise Blocked('UNSAFE_ARCHIVE_PATH')
    return parts


def _safe_link(relative,target):
    if not isinstance(target,str) or not target or target.startswith('/') or '\x00' in target or '\\' in target:
        raise Blocked('UNSAFE_SYMLINK')
    stack=relative.split('/')[:-1]
    for part in target.split('/'):
        if part in ('','.'): continue
        if part=='..':
            if not stack: raise Blocked('SYMLINK_ESCAPE')
            stack.pop()
        else: stack.append(part)


def _tree_records(root):
    root=Path(root)
    if root.is_symlink() or not root.is_dir(): raise Blocked('UNSAFE_TREE_ROOT')
    records=[]
    def append(path,relative):
        info=path.lstat()
        mode=stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            records.append(_record(relative,'directory',mode,info.st_uid,info.st_gid,info.st_mtime))
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink!=1: raise Blocked('HARDLINK_IN_TREE')
            records.append(_record(relative,'file',mode,info.st_uid,info.st_gid,info.st_mtime,
                                   size=info.st_size,sha256=sha_file(path)))
        elif stat.S_ISLNK(info.st_mode):
            target=os.readlink(path);_safe_link(relative,target)
            records.append(_record(relative,'symlink',mode,info.st_uid,info.st_gid,info.st_mtime,target=target))
        else: raise Blocked('SPECIAL_FILE_IN_TREE')
    append(root,'.')
    for current,dirs,files in os.walk(root,followlinks=False):
        dirs.sort();files.sort();base=Path(current)
        for name in list(dirs):
            path=base/name
            if path.is_symlink(): dirs.remove(name)
            append(path,path.relative_to(root).as_posix())
        for name in files:
            path=base/name
            append(path,path.relative_to(root).as_posix())
    return records


def tree_digest(root):
    return tree_hash(_tree_records(root))


def _atomic_json(path,value):
    path=Path(path)
    fd,name=tempfile.mkstemp(prefix='.journal-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(value,stream,sort_keys=True,separators=(',',':'))
            stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
        dfd=os.open(path.parent,os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if os.path.exists(name): os.unlink(name)


class SourceFixture:
    @classmethod
    def create(cls,resources):
        if len(resources)!=SOURCE_COUNT or len(set(resources))!=SOURCE_COUNT or 'source:stream' not in resources:
            raise Blocked('INCOMPLETE_SOURCE_SCOPE')
        if any(not x.startswith('source:') or '/' in x or '..' in x or len(x)>180 for x in resources):
            raise Blocked('INVALID_SOURCE_ID')
        root=Path(tempfile.mkdtemp(prefix='source-replace-fixture-')).resolve()
        os.chmod(root,0o700)
        for name in ('live','stage','snapshots','retired'):
            (root/name).mkdir(mode=0o700)
        config={'schema':'source-replace-fixture/v1','root':str(root),'resources':sorted(resources)}
        _atomic_json(root/'fixture.json',config)
        return cls(root)

    def __init__(self,root):
        self.root=Path(root).absolute()
        temporary=Path(tempfile.gettempdir()).resolve()
        if (self.root.is_symlink() or self.root.resolve()!=self.root or self.root.parent!=temporary or
            not self.root.name.startswith('source-replace-fixture-') or self.root.stat().st_uid!=os.geteuid() or
            self.root.stat().st_mode & 0o077):
            raise Blocked('UNSAFE_FIXTURE_ROOT')
        config=json.loads((self.root/'fixture.json').read_text())
        if config.get('schema')!='source-replace-fixture/v1' or config.get('root')!=str(self.root):
            raise Blocked('FIXTURE_IDENTITY_MISMATCH')
        self.resources=config['resources']
        if (not isinstance(self.resources,list) or len(self.resources)!=SOURCE_COUNT or
            len(set(self.resources))!=SOURCE_COUNT or 'source:stream' not in self.resources):
            raise Blocked('INCOMPLETE_SOURCE_SCOPE')
        for category in ('live','stage','snapshots','retired'):
            path=self.root/category
            info=path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode & 0o077:
                raise Blocked('UNSAFE_FIXTURE_CATEGORY')
        self.slots={rid:str(i) for i,rid in enumerate(self.resources)}
        self.fault=lambda phase,rid:None

    def path(self,category,rid):
        if category not in ('live','stage','snapshots','retired') or rid not in self.slots:
            raise Blocked('INVALID_FIXTURE_PATH')
        return self.root/category/self.slots[rid]

    def _journal(self,value):
        _atomic_json(self.root/'journal.json',value)

    def stage(self,archive,entries,archive_sha256):
        if (self.root/'journal.json').exists(): raise Blocked('OPERATION_ALREADY_STARTED')
        archive=Path(archive)
        if archive.is_symlink() or not archive.is_file() or archive.stat().st_nlink!=1 or sha_file(archive)!=archive_sha256:
            raise Blocked('ARCHIVE_IDENTITY_MISMATCH')
        by_resource={x.get('resource'):x for x in entries if x.get('kind')=='full-current-source-snapshot'}
        if len(by_resource)!=SOURCE_COUNT or set(by_resource)!=set(self.resources) or len(entries)!=SOURCE_COUNT:
            raise Blocked('INCOMPLETE_SOURCE_SCOPE')
        for rid,entry in by_resource.items():
            if (entry.get('path')!='runtime/'+rid or entry.get('restore')!='replace-entire-directory' or
                not isinstance(entry.get('restorableTreeSha256'),str) or len(entry['restorableTreeSha256'])!=64):
                raise Blocked('INVALID_SOURCE_BINDING')
        records={rid:[] for rid in self.resources};seen={rid:set() for rid in self.resources}
        directories=[];symlinks=[];count=0;total=0
        with tarfile.open(archive,'r:*') as tf:
            for member in tf:
                if not member.name.startswith('runtime/'):
                    continue  # Other authenticated supplement categories are out of scope.
                count+=1
                if count>MAX_MEMBERS: raise Blocked('ARCHIVE_MEMBER_LIMIT')
                parts=_safe_relative(member.name)
                if len(parts)<2 or parts[0]!='runtime' or parts[1] not in by_resource:
                    raise Blocked('UNKNOWN_SOURCE_MEMBER')
                rid=parts[1]
                relative='.' if len(parts)==2 else '/'.join(parts[2:])
                if relative in seen[rid]: raise Blocked('DUPLICATE_ARCHIVE_MEMBER')
                seen[rid].add(relative)
                if not (member.isdir() or member.isfile() or member.issym()):
                    raise Blocked('UNSAFE_ARCHIVE_MEMBER')
                if member.uid!=os.geteuid() or member.gid!=os.getegid() or member.mode & 0o7000:
                    raise Blocked('FIXTURE_METADATA_UNSUPPORTED')
                record=_member_record(member,relative)
                if member.issym(): _safe_link(relative,member.linkname)
                if member.isdir() and (member.mode & 0o500)!=0o500:
                    raise Blocked('FIXTURE_DIRECTORY_NOT_TRAVERSABLE')
                records[rid].append(record)
                destination=self.path('stage',rid)
                if relative=='.':
                    if not member.isdir(): raise Blocked('SOURCE_ROOT_NOT_DIRECTORY')
                    destination.mkdir(mode=0o700)
                    directories.append((destination,member))
                    continue
                parent=destination.joinpath(*relative.split('/')[:-1])
                if not parent.is_dir() or parent.is_symlink(): raise Blocked('MISSING_OR_SYMLINK_PARENT')
                target=destination.joinpath(*relative.split('/'))
                if member.isdir():
                    target.mkdir(mode=0o700)
                    directories.append((target,member))
                elif member.issym():
                    target.symlink_to(member.linkname)
                    symlinks.append((target,member))
                else:
                    total+=member.size
                    if total>MAX_REGULAR_BYTES: raise Blocked('FIXTURE_BYTES_LIMIT')
                    stream=tf.extractfile(member)
                    if stream is None: raise Blocked('MISSING_FILE_PAYLOAD')
                    h=hashlib.sha256();remaining=member.size
                    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with os.fdopen(fd,'wb') as out:
                        while remaining:
                            chunk=stream.read(min(1024*1024,remaining))
                            if not chunk: raise Blocked('TRUNCATED_FILE_PAYLOAD')
                            out.write(chunk);h.update(chunk);remaining-=len(chunk)
                        out.flush();os.fsync(out.fileno())
                    record['sha256']=h.hexdigest()
                    os.chmod(target,member.mode & 0o777)
                    os.utime(target,(int(member.mtime),int(member.mtime)))
            for target,member in symlinks:
                try: os.utime(target,(int(member.mtime),int(member.mtime)),follow_symlinks=False)
                except (NotImplementedError,OSError): raise Blocked('SYMLINK_METADATA_UNSUPPORTED') from None
            for target,member in reversed(directories):
                os.chmod(target,member.mode & 0o777)
                os.utime(target,(int(member.mtime),int(member.mtime)))
        for rid,entry in by_resource.items():
            if '.' not in seen[rid] or tree_hash(records[rid])!=entry['restorableTreeSha256']:
                raise Blocked('ARCHIVE_TREE_HASH_MISMATCH')
            if tree_digest(self.path('stage',rid))!=entry['restorableTreeSha256']:
                raise Blocked('EXTRACTED_TREE_HASH_MISMATCH')
        return {rid:entry['restorableTreeSha256'] for rid,entry in by_resource.items()}

    def apply(self,staged_hashes):
        if (self.root/'journal.json').exists(): raise Blocked('EXISTING_OPERATION_RECOVER_ONLY')
        if set(staged_hashes)!=set(self.resources): raise Blocked('INCOMPLETE_SOURCE_SCOPE')
        originals={}
        for rid in self.resources:
            live=self.path('live',rid);stage=self.path('stage',rid)
            if not live.is_dir() or live.is_symlink() or tree_digest(stage)!=staged_hashes[rid]:
                raise Blocked('LIVE_OR_STAGE_INVALID')
            original=tree_digest(live)
            shutil.copytree(live,self.path('snapshots',rid),symlinks=True,copy_function=shutil.copy2)
            if tree_digest(self.path('snapshots',rid))!=original:
                raise Blocked('SAFETY_SNAPSHOT_INVALID')
            originals[rid]=original
        journal={'schema':'source-replace-journal/v1','phase':'ready','attempted':[],
                 'originalHashes':originals,'stagedHashes':staged_hashes}
        self._journal(journal)
        for rid in self.resources:
            for check in self.resources:
                if tree_digest(self.path('snapshots',check))!=originals[check]:
                    raise Blocked('SAFETY_SNAPSHOT_INVALID')
            journal['attempted'].append(rid);journal['phase']='promoting';self._journal(journal)
            self.fault('before-retire',rid)
            os.replace(self.path('live',rid),self.path('retired',rid))
            self.fault('after-retire',rid)
            os.replace(self.path('stage',rid),self.path('live',rid))
            self.fault('after-promote',rid)
            if tree_digest(self.path('live',rid))!=staged_hashes[rid]:
                raise Blocked('PROMOTED_TREE_HASH_MISMATCH')
            journal['phase']='promoted';self._journal(journal)
        journal['phase']='completed';self._journal(journal)
        return 'completed'

    def recover(self):
        journal_path=self.root/'journal.json'
        if not journal_path.is_file(): raise Blocked('NO_OPERATION_TO_RECOVER')
        journal=json.loads(journal_path.read_text())
        if journal.get('schema')!='source-replace-journal/v1' or set(journal.get('originalHashes',{}))!=set(self.resources):
            raise Blocked('INVALID_JOURNAL')
        for rid in self.resources:
            if tree_digest(self.path('snapshots',rid))!=journal['originalHashes'][rid]:
                raise Blocked('SAFETY_SNAPSHOT_INVALID')
        if journal['phase']=='rolled-back':
            for rid in self.resources:
                if tree_digest(self.path('live',rid))!=journal['originalHashes'][rid]:
                    raise Blocked('ROLLBACK_TREE_HASH_MISMATCH')
            return 'rolled-back'
        for rid in reversed(journal['attempted']):
            journal['phase']='rolling-back';self._journal(journal)
            self.fault('before-rollback',rid)
            live=self.path('live',rid)
            if live.exists():
                if live.is_symlink() or not live.is_dir(): raise Blocked('UNSAFE_LIVE_TREE')
                shutil.rmtree(live)
            shutil.copytree(self.path('snapshots',rid),live,symlinks=True,copy_function=shutil.copy2)
            self.fault('after-rollback',rid)
            if tree_digest(live)!=journal['originalHashes'][rid]:
                raise Blocked('ROLLBACK_TREE_HASH_MISMATCH')
        journal['phase']='rolled-back';self._journal(journal)
        return 'rolled-back'
