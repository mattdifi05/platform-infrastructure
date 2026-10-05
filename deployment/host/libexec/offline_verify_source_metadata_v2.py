#!/usr/bin/python3
"""Strict verifier for metadata-v2 full-source snapshots; never applies to production."""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile

MAX_MEMBERS=1_000_000
MAX_BYTES=70_000_000_000
MAX_XATTRS_PER_MEMBER=128
MAX_XATTR_NAME_BYTES=1024
MAX_XATTR_VALUE_BYTES=65536
MAX_XATTR_BYTES_PER_MEMBER=262144
PAX_XATTR_PREFIX='CODEX.xattr.b64.'
PAX_MTIME_NS='CODEX.mtime_ns'
PAX_HARDLINK_GROUP='CODEX.hardlink_group'
PAX_HARDLINK_POLICY='CODEX.hardlink_policy'
SOURCE_ID=re.compile(r'source:[a-z0-9][a-z0-9._-]{0,179}')


class Blocked(RuntimeError):
    pass


def private_directory(path, strict_root):
    path=Path(path).absolute()
    if path.is_symlink() or path.resolve()!=path or not path.is_dir():raise Blocked('UNSAFE_OUTPUT_PARENT')
    info=path.stat()
    if info.st_uid!=os.geteuid() or info.st_mode & 0o077:raise Blocked('PRIVATE_OUTPUT_PARENT_REQUIRED')
    if strict_root:
        if os.geteuid()!=0:raise Blocked('ROOT_HOST_REQUIRED')
        for ancestor in [path,*path.parents]:
            i=ancestor.lstat()
            if ancestor.is_symlink() or not stat.S_ISDIR(i.st_mode) or i.st_uid!=0 or i.st_mode & 0o022:
                raise Blocked('UNSAFE_OUTPUT_ANCESTRY')
    return path


def private_input(path, strict_root):
    path=Path(path).absolute();info=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
        raise Blocked('UNSAFE_INPUT_ARTIFACT')
    if strict_root and (info.st_uid!=0 or info.st_mode & 0o077):raise Blocked('PRIVATE_INPUT_REQUIRED')
    return path


def _safe_relative(value):
    if not isinstance(value,str) or not value or value.startswith('/') or '\x00' in value or '\\' in value:
        raise Blocked('UNSAFE_ARCHIVE_PATH')
    parts=value.split('/')
    if any(part in ('','.','..') for part in parts):raise Blocked('UNSAFE_ARCHIVE_PATH')
    return parts


def _safe_link(relative,target):
    if not isinstance(target,str) or not target or target.startswith('/') or '\x00' in target or '\\' in target:
        raise Blocked('UNSAFE_SYMLINK')
    stack=relative.split('/')[:-1]
    for part in target.split('/'):
        if part in ('','.'):continue
        if part=='..':
            if not stack:raise Blocked('SYMLINK_ESCAPE')
            stack.pop()
        else:stack.append(part)


def _xattrs(path, follow_symlinks=False):
    try:
        names=os.listxattr(path,follow_symlinks=follow_symlinks)
        if len(names)>MAX_XATTRS_PER_MEMBER:raise Blocked('XATTR_COUNT_BOUND')
        rows=[];total=0
        for name in names:
            raw_name=os.fsencode(name)
            if not raw_name or len(raw_name)>MAX_XATTR_NAME_BYTES:raise Blocked('XATTR_NAME_BOUND')
            value=os.getxattr(path,name,follow_symlinks=follow_symlinks)
            if len(value)>MAX_XATTR_VALUE_BYTES:raise Blocked('XATTR_VALUE_BOUND')
            total+=len(raw_name)+len(value)
            if total>MAX_XATTR_BYTES_PER_MEMBER:raise Blocked('XATTR_TOTAL_BOUND')
            rows.append({'nameB64':base64.b64encode(raw_name).decode('ascii'),
                         'valueB64':base64.b64encode(value).decode('ascii')})
        return sorted(rows,key=lambda row:row['nameB64'])
    except Blocked:raise
    except (AttributeError,OSError) as exc:raise Blocked('XATTR_UNAVAILABLE_OR_UNREADABLE') from exc


def _decode_b64(value,code):
    if not isinstance(value,str):raise Blocked(code)
    try:return base64.b64decode(value,validate=True)
    except (ValueError,TypeError):raise Blocked(code) from None


def _member_metadata(member):
    headers=member.pax_headers or {}
    raw_ns=headers.get(PAX_MTIME_NS)
    if not isinstance(raw_ns,str) or not re.fullmatch(r'-?[0-9]{1,20}',raw_ns):
        raise Blocked('NANOSECOND_MTIME_MISSING_OR_INVALID')
    mtime_ns=int(raw_ns)
    if not -(2**63)<mtime_ns<2**63:raise Blocked('NANOSECOND_MTIME_OUT_OF_RANGE')
    rows=[];total=0;seen=set()
    for key,value in headers.items():
        if not key.startswith(PAX_XATTR_PREFIX):continue
        token=key[len(PAX_XATTR_PREFIX):]
        if not token or not re.fullmatch(r'[A-Za-z0-9_-]+',token):raise Blocked('XATTR_PAX_NAME_INVALID')
        try:raw_name=base64.urlsafe_b64decode(token+'='*((-len(token))%4))
        except (ValueError,TypeError):raise Blocked('XATTR_PAX_NAME_INVALID') from None
        if base64.urlsafe_b64encode(raw_name).decode('ascii').rstrip('=')!=token:
            raise Blocked('XATTR_PAX_NAME_NONCANONICAL')
        if not raw_name or len(raw_name)>MAX_XATTR_NAME_BYTES or raw_name in seen:
            raise Blocked('XATTR_PAX_NAME_BOUND_OR_DUPLICATE')
        raw_value=_decode_b64(value,'XATTR_PAX_VALUE_INVALID')
        if len(raw_value)>MAX_XATTR_VALUE_BYTES:raise Blocked('XATTR_VALUE_BOUND')
        seen.add(raw_name);total+=len(raw_name)+len(raw_value)
        if total>MAX_XATTR_BYTES_PER_MEMBER:raise Blocked('XATTR_TOTAL_BOUND')
        rows.append({'nameB64':base64.b64encode(raw_name).decode('ascii'),
                     'valueB64':base64.b64encode(raw_value).decode('ascii')})
    if len(rows)>MAX_XATTRS_PER_MEMBER:raise Blocked('XATTR_COUNT_BOUND')
    rows.sort(key=lambda row:row['nameB64'])
    group=headers.get(PAX_HARDLINK_GROUP)
    policy=headers.get(PAX_HARDLINK_POLICY)
    if group is not None and (not re.fullmatch(r'hg-[a-f0-9]{24}',group) or
                              policy!='materialized-independent-files'):
        raise Blocked('HARDLINK_POLICY_INVALID')
    if policy is not None and policy!='materialized-independent-files':
        raise Blocked('HARDLINK_POLICY_INVALID')
    return mtime_ns,rows,group


def _record(member,relative,metadata,sha256=None):
    mtime_ns,xattrs,group=metadata
    kind='directory' if member.isdir() else 'file' if member.isfile() else 'symlink'
    row={'path':relative,'type':kind,'mode':member.mode & 0o7777,'uid':member.uid,'gid':member.gid,
         'mtime':int(mtime_ns//1_000_000_000),'mtimeNs':mtime_ns,'xattrs':xattrs}
    if kind=='file':row.update(size=member.size,sha256=sha256)
    elif kind=='symlink':row['target']=member.linkname
    if group:row['hardlinkGroup']=group
    return row


def _records_digest(records):
    h=hashlib.sha256()
    for row in sorted(records,key=lambda item:item['path']):
        h.update(json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8'))
        h.update(b'\n')
    return h.hexdigest()


def _read_payload(stream,size,output=None):
    h=hashlib.sha256();remaining=size
    while remaining:
        data=stream.read(min(1024*1024,remaining))
        if not data:raise Blocked('TRUNCATED_ARCHIVE_PAYLOAD')
        remaining-=len(data);h.update(data)
        if output is not None:output.write(data)
    return h.hexdigest()


def _apply_owner(path,member,strict_root,symlink=False):
    if strict_root:
        os.chown(path,member.uid,member.gid,follow_symlinks=not symlink)
    elif member.uid!=os.geteuid() or member.gid!=os.getegid():
        raise Blocked('FIXTURE_OWNER_UNSUPPORTED')


def _apply_metadata(path,member,metadata,strict_root,symlink=False):
    mtime_ns,xattrs,_=metadata
    _apply_owner(path,member,strict_root,symlink)
    for row in xattrs:
        raw_name=_decode_b64(row['nameB64'],'XATTR_NAME_INVALID')
        raw_value=_decode_b64(row['valueB64'],'XATTR_VALUE_INVALID')
        os.setxattr(path,os.fsdecode(raw_name),raw_value,follow_symlinks=not symlink)
    if not symlink:os.chmod(path,member.mode & 0o7777,follow_symlinks=False)
    os.utime(path,ns=(mtime_ns,mtime_ns),follow_symlinks=not symlink)


def _path_record(path,relative,expected_group=None):
    info=path.lstat()
    if stat.S_ISDIR(info.st_mode):kind='directory'
    elif stat.S_ISREG(info.st_mode):kind='file'
    elif stat.S_ISLNK(info.st_mode):kind='symlink'
    else:raise Blocked('EXTRACTED_SPECIAL_FILE')
    row={'path':relative,'type':kind,'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid,
         'mtime':int(info.st_mtime_ns//1_000_000_000),'mtimeNs':info.st_mtime_ns,
         'xattrs':_xattrs(path,follow_symlinks=False)}
    if kind=='file':
        if info.st_nlink!=1:raise Blocked('HARDLINK_NOT_MATERIALIZED')
        h=hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
        row.update(size=info.st_size,sha256=h.hexdigest())
    elif kind=='symlink':row['target']=os.readlink(path)
    if expected_group:row['hardlinkGroup']=expected_group
    return row


def verify(archive,report,out,expected_manifest_digest,strict_root=True):
    archive=private_input(archive,strict_root);report=private_input(report,strict_root)
    data=json.loads(report.read_text())
    if (data.get('schema')!='platform.backup-completeness-candidate/v1' or
        data.get('sourceMetadataVersion')!=2 or
        data.get('sourceCaptureMode')!='full-current-source-snapshot' or
        data.get('manifestDigest')!=expected_manifest_digest or
        not re.fullmatch('[0-9a-f]{64}',expected_manifest_digest)):
        raise Blocked('REPORT_MANIFEST_MODE_OR_METADATA_VERSION_MISMATCH')
    if sha_file(archive)!=data.get('archiveSha256') or archive.stat().st_size!=data.get('supplementBytes'):
        raise Blocked('ARCHIVE_IDENTITY_MISMATCH')
    entries=data.get('entries',[])
    sources=[e for e in entries if e.get('kind')=='full-current-source-snapshot']
    by_id={e.get('resource'):e for e in sources}
    if (len(sources)!=16 or len(by_id)!=16 or 'source:stream' not in by_id or
        any(not SOURCE_ID.fullmatch(str(rid)) for rid in by_id)):
        raise Blocked('INCOMPLETE_SOURCE_SCOPE')
    for rid,e in by_id.items():
        if (e.get('path')!='runtime/'+rid or e.get('restore')!='replace-entire-directory' or
            e.get('metadataPolicy')!='pax-xattrs-mtime-ns-v2' or
            e.get('hardlinkPolicy')!='materialized-independent-files' or
            type(e.get('hardlinkGroups')) is not int or e['hardlinkGroups']<0 or
            not re.fullmatch('[a-f0-9]{64}',str(e.get('restorableTreeSha256'))) or
            type(e.get('regularBytes')) is not int or e['regularBytes']<0):
            raise Blocked('INVALID_SOURCE_BINDING')
    expected_source_bytes=sum(e['regularBytes'] for e in sources)
    if expected_source_bytes!=data.get('fullSourceRegularBytes') or expected_source_bytes>MAX_BYTES:
        raise Blocked('SOURCE_BYTES_BOUND_INVALID')
    opaque={e.get('path'):e for e in entries if e.get('kind') in
            ('docker-image-archive','database-acl-inventory','docker-image-inventory')}
    if len(opaque)!=3 or len(entries)!=60:raise Blocked('UNSUPPORTED_COMPLETENESS_CATEGORIES')
    for path,e in opaque.items():
        _safe_relative(path)
        if type(e.get('bytes')) is not int or e['bytes']<0 or not re.fullmatch('[a-f0-9]{64}',str(e.get('sha256'))):
            raise Blocked('OPAQUE_BINDING_INVALID')
    out=Path(out).absolute();parent=private_directory(out.parent,strict_root)
    if out.exists() or out.is_symlink():raise Blocked('OUTPUT_ALREADY_EXISTS')
    scratch=Path(tempfile.mkdtemp(prefix='.isolated-source-v2-',dir=parent));os.chmod(scratch,0o700)
    roots={rid:scratch/rid[len('source:'):] for rid in by_id}
    records={rid:[] for rid in by_id};seen={rid:set() for rid in by_id}
    source_bytes={rid:0 for rid in by_id};directories=[];symlinks=[];opaque_seen=set();members=0
    groups={rid:{} for rid in by_id};group_members={rid:{} for rid in by_id}
    xattrs_verified=0;acl_xattrs=0
    try:
        with tarfile.open(archive,'r|*') as tf:
            for member in tf:
                members+=1
                if members>MAX_MEMBERS:raise Blocked('ARCHIVE_MEMBER_LIMIT')
                parts=_safe_relative(member.name)
                if not (member.isdir() or member.isfile() or member.issym()):raise Blocked('UNSAFE_MEMBER_TYPE')
                if not all(type(x) is int and 0<=x<2**32-1 for x in (member.uid,member.gid)):
                    raise Blocked('INVALID_NUMERIC_OWNER')
                if parts[0]!='runtime':
                    if member.name not in opaque or member.name in opaque_seen or not member.isfile():
                        raise Blocked('UNKNOWN_OR_DUPLICATE_OPAQUE_MEMBER')
                    e=opaque[member.name];stream=tf.extractfile(member)
                    if member.size!=e['bytes'] or _read_payload(stream,member.size)!=e['sha256']:
                        raise Blocked('OPAQUE_PAYLOAD_MISMATCH')
                    opaque_seen.add(member.name);continue
                if len(parts)<2 or parts[1] not in by_id:raise Blocked('UNKNOWN_SOURCE_MEMBER')
                rid=parts[1];relative='.' if len(parts)==2 else '/'.join(parts[2:])
                if relative in seen[rid]:raise Blocked('DUPLICATE_SOURCE_MEMBER')
                seen[rid].add(relative);metadata=_member_metadata(member)
                record=_record(member,relative,metadata);records[rid].append(record)
                if metadata[2]:
                    group_members[rid].setdefault(metadata[2],[]).append(relative)
                xattrs_verified+=len(metadata[1])
                for attr in metadata[1]:
                    raw_name=_decode_b64(attr['nameB64'],'XATTR_NAME_INVALID')
                    if raw_name in (b'system.posix_acl_access',b'system.posix_acl_default'):
                        acl_xattrs+=1
                destination=roots[rid]
                if relative=='.':
                    if not member.isdir():raise Blocked('SOURCE_ROOT_NOT_DIRECTORY')
                    destination.mkdir(mode=0o700);directories.append((destination,member,metadata));continue
                ancestor=destination
                for part in relative.split('/')[:-1]:
                    ancestor=ancestor/part
                    if ancestor.is_symlink() or not ancestor.is_dir():raise Blocked('UNSAFE_OR_MISSING_PARENT')
                if not destination.is_dir() or destination.is_symlink():raise Blocked('SOURCE_ROOT_MISSING')
                target=destination.joinpath(*relative.split('/'))
                if member.isdir():
                    target.mkdir(mode=0o700);directories.append((target,member,metadata))
                elif member.issym():
                    _safe_link(relative,member.linkname);symlinks.append((target,member,metadata))
                else:
                    if member.size<0:raise Blocked('INVALID_FILE_SIZE')
                    source_bytes[rid]+=member.size
                    if source_bytes[rid]>by_id[rid]['regularBytes']:raise Blocked('SOURCE_EXPANSION_BOUND')
                    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with os.fdopen(fd,'wb') as output:
                        record['sha256']=_read_payload(tf.extractfile(member),member.size,output)
                        output.flush();os.fsync(output.fileno())
                    _apply_metadata(target,member,metadata,strict_root)
        for target,member,metadata in symlinks:
            target.symlink_to(member.linkname);_apply_metadata(target,member,metadata,strict_root,symlink=True)
        for target,member,metadata in reversed(directories):_apply_metadata(target,member,metadata,strict_root)
        if opaque_seen!=set(opaque):raise Blocked('MISSING_OPAQUE_MEMBER')
        digests={};materialized_groups=0
        for rid,e in by_id.items():
            if '.' not in seen[rid] or source_bytes[rid]!=e['regularBytes']:
                raise Blocked('SOURCE_COVERAGE_MISMATCH')
            if _records_digest(records[rid])!=e['restorableTreeSha256']:
                raise Blocked('ARCHIVE_TREE_HASH_MISMATCH')
            if len(group_members[rid])!=e['hardlinkGroups']:
                raise Blocked('HARDLINK_GROUP_COUNT_MISMATCH')
            expected_groups={rel:group for group,rels in group_members[rid].items() for rel in rels}
            actual=[]
            for rel in sorted(seen[rid]):
                path=roots[rid] if rel=='.' else roots[rid].joinpath(*rel.split('/'))
                row=_path_record(path,rel,expected_groups.get(rel))
                actual.append(row)
            if _records_digest(actual)!=e['restorableTreeSha256']:
                raise Blocked('EXTRACTED_METADATA_OR_CONTENT_MISMATCH')
            materialized_groups+=len(group_members[rid])
            digests[rid]=e['restorableTreeSha256']
        os.replace(scratch,out)
        dfd=os.open(parent,os.O_RDONLY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
        return {'schema':'platform.isolated-full-source-proof/v2','status':'passed',
                'sourceCount':16,'streamIncluded':True,'regularSourceBytes':sum(source_bytes.values()),
                'memberCount':members,'opaqueFilesVerified':len(opaque_seen),'sourceHashes':digests,
                'archiveSha256':data['archiveSha256'],'manifestId':data['manifestId'],
                'manifestDigest':expected_manifest_digest,'completedAt':dt.datetime.now(dt.timezone.utc).isoformat(),
                'sourceRestoreVerified':True,'sourceMetadataVersion':2,'xattrsVerified':xattrs_verified,
                'posixAclXattrsVerified':acl_xattrs,'nanosecondMtimesVerified':True,
                'hardlinkGroupsMaterialized':materialized_groups,'hardlinksPreserved':False,
                'fullyRecoverable':False,'crossResourceConsistencyVerified':False,
                'productionModified':False,'networkUsed':False,'restoredRoot':str(out)}
    except BaseException:
        shutil.rmtree(scratch,ignore_errors=True)
        raise


def sha_file(path):
    h=hashlib.sha256()
    with open(path,'rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--archive',required=True);p.add_argument('--report',required=True)
    p.add_argument('--out',required=True);p.add_argument('--expected-manifest-digest',required=True)
    p.add_argument('--proof',required=True)
    a=p.parse_args();os.umask(0o077)
    proof=verify(a.archive,a.report,a.out,a.expected_manifest_digest)
    target=Path(a.proof).absolute();private_directory(target.parent,True)
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:
        json.dump(proof,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    print(json.dumps({k:v for k,v in proof.items() if k!='sourceHashes'},sort_keys=True))


if __name__=='__main__':main()
