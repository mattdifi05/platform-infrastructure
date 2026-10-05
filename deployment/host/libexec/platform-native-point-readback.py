#!/usr/bin/python3
"""Assemble an authenticated readback proof for the first G16 overlay on G15.

This is local evidence processing only. It performs no network, install, signing,
restore, service, or production data operation.
"""
from __future__ import annotations
import argparse, hashlib, hmac, importlib.util, json, os, re, stat, sys, tarfile, tempfile
from pathlib import Path

PARENT_ID='manifest-scheduled-platform-20260929-182357-1f9954'
PARENT_DIGEST='baf72a7c4ff5d2266b71afe4865ebffeb8be6c363dfc31c12f3a865389009b2c'
PARENT_RECEIPT='1868a512b5a47fe9cc4808622dfb4707d8fe988b0a1d523f801c12ad4c419030'
BASE_ARCHIVE='77de6d262d269db484aa48fbe63ca064a151a9c5ecc081374bf9be4d3e034987'
BASE_BYTES=14_123_697_104
MAX_CAPSULE_PLAINTEXT_BYTES=2_000_000_000
MAX_CAPSULE_ENTRIES=30_000
ESCAPED_REGULAR_MEMBERS={'host/etc/systemd/system/snap-canonical\\x2dlivepatch-414.mount'}
ESCAPED_SYMLINK_MEMBERS={
 'host/etc/systemd/system/multi-user.target.wants/snap-canonical\\x2dlivepatch-414.mount',
 'host/etc/systemd/system/snapd.mounts.target.wants/snap-canonical\\x2dlivepatch-414.mount'}
PARENT_MANIFEST_SHA='ae093766108a3bc177cbaca539b513755a8032e17c4b50d49fd1c09ba2511106'
FULL_BINDINGS_SHA='6fa2068e6d1d759c308ed0f1792936df600aba5166157cd10462ae0570fa5edf'
PRIVATE240_PLAN_SHA='c6f09fd00d7f8a7e1dc8794e214dfec1f0bf48f663fec2b0f26b8575b34d4c29'
NATIVE_READER_SHA='ae35f52e33cb03d1621a7b98ee897bdcf3723ad69dffe3ed48baff76d03e8581'
MOUNTED_CONFIG_READER_SHA='adc2406fba1cce0aa4086cc15cd50ac76411c8f4b144cbe33cb8284e1dcda99a'
PARENT_SELECTED_MEMBERS_SHA='fbd57667ad7f70423a8aeb9b43691f091592921f9bfdca2149eeed173cfc647b'
DURABLE_SUPPLEMENT_RECEIPT_SHA='d275da1dd5092345b155b9c8a1e832d0161b2c8f44f4bbb22cf356dbc58012cb'
DURABLE_INDEX_SHA='dc57f3390b82b1f91faa9d85df5c22b47bd9594fb2a22ff1c9361ac4c3d8bd23'
NATIVE_STATE_PROOF_SHA='a51b790bc55af4228c7e2bab0e18471779d5d18f9c8029bf875fa745b421de2f'
REDIS_PROVIDER_PROOF_SHA='e15f8f351531f36e9086376f9218865b6fec2880ff3d6002689b58b526be10e4'
REDIS_PROVIDER_PROOF_BYTES=1_176
REDIS_INNER_MANIFEST_SHA='7ed784f122cd938cf816d19214737496daab0f1d169416106d53a40b2286de53'
REDIS_INNER_MANIFEST_BYTES=2_146
REDIS_SIGNED_LATEST_SHA='95a3c1b9db10d245b86400968e50786d9aac6ad789cdc8397faa519d803207ef'
RUSTFS_PROVIDER_PROOF_SHA='f06bf4e9045132d95960e8033b157d60019e4a023adf15ae39dc833227ee5f24'
RUSTFS_SIGNED_OUTER_PROOF_SHA='9625ce36be111eea06b66af110be63c3343efe1ebd1e4a14c4014e80a9eb2926'
RUSTFS_TREE_INDEX_SHA='051cf08614dd350643bbe123e30d18c85ea4259f8ff11406bb6e3356bc703b98'
HISTORICAL_READER_SHA='800eca18ff492250b948bc6997c9111016741052f26cadac289b33e1ea8c60c9'
METADATA_READER_SHA='30bfde6ae7d68d8ed22f016e67f2bf23f2bbc79933b6047f4201eed536cdd79d'
KEY_PATH=Path('/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase')
REDIS_ROOT=Path('/var/lib/platform-isolated-stack-20260930/recovered-inputs/redis-snapshots')
REDIS_LATEST_PATH=Path('/var/lib/platform-isolated-stack-20260930/authenticated-state-inputs/redis-recovery/latest.json')
RUSTFS_PROOF_PATH=Path('/var/lib/platform-isolated-stack-20260930/recovered-inputs/rustfs-parent-tree/proof.json')
RUSTFS_TREE_ROOT=Path('/var/lib/platform-isolated-stack-20260930/recovered-inputs/rustfs-parent-tree/restored/data')
HERE=Path(__file__).resolve().parent
def _native_dir(here=HERE):
 if here.name=='host' and here.parent.name=='platform-mounted-config-v5':
  candidates=(here.parent/'native',here/'platform-mounted-config-v5'/'native',here.parent.parent/'platform-mounted-config-v5'/'native')
 else:
  candidates=(here/'platform-mounted-config-v5'/'native',here.parent/'platform-mounted-config-v5'/'native',here.parent/'native')
 return next((candidate for candidate in candidates if candidate.is_dir()),candidates[-1])
def _mapping_file(name, here=HERE, installed_native=None):
 native=installed_native if installed_native is not None else _native_dir(here)
 candidates=(native/name,here/name)
 return next((candidate for candidate in candidates if candidate.exists()),candidates[-1])
def _mounted_config_module(here=HERE, installed=Path('/usr/local/libexec/platform-mounted-config-v5/native/mounted_config_sidecar_v5.py')):
 local=_native_dir(here)/'mounted_config_sidecar_v5.py'
 return local if local.exists() else installed if installed.exists() else local
def _lineage_module(here=HERE, installed=Path('/usr/local/libexec/platform-native-lineage-membership.py')):
 candidates=(here/'lineage_membership_v4.py',_native_dir(here).parent/'host'/'lineage_membership_v4.py')
 local=next((p for p in candidates if p.exists()),candidates[0])
 return local if local.exists() else installed if installed.exists() else here/'platform-native-lineage-membership.py'
DEFAULT_PARENT_MANIFEST=_mapping_file('g16-historical-parent-manifest.json')
DEFAULT_FULL_BINDINGS=_mapping_file('g16-full-bindings.json')
DEFAULT_PRIVATE_PLAN=_mapping_file('g16-private240-plan.json')
MOUNTED_CONFIG_MODULE=_mounted_config_module()
LINEAGE_MODULE=_lineage_module()
HIST='/var/lib/platform-host-recovery/recovery-records/'+PARENT_ID
OLD_TREES='/var/lib/platform-host-recovery/extra-mounted-trees'
SQL='/var/lib/platform-host-recovery/extra-database-exports'
class Blocked(RuntimeError): pass
def canonical(x): return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def sha_bytes(b): return hashlib.sha256(b).hexdigest()
def sha_file(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
 return h.hexdigest()

def verify_ciphertext_file(path, proof):
 """Hash a protected ciphertext through one no-follow descriptor.

 The signed point proof supplies the exact expected byte count and digest.
 Checking both on the opened inode avoids accepting a same-path replacement
 between lstat and hashing.
 """
 p=Path(path)
 expected_bytes=proof.get('encryptedBytes') if isinstance(proof,dict) else None
 expected_sha=proof.get('encryptedSha256') if isinstance(proof,dict) else None
 if (type(expected_bytes) is not int or not 0<expected_bytes<=70_000_000_000 or
     not re.fullmatch('[a-f0-9]{64}',str(expected_sha or ''))):
  raise Blocked('CAPSULE_CIPHERTEXT_PROOF_SHAPE')
 flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)
 try: fd=os.open(p,flags)
 except OSError: raise Blocked('CAPSULE_CIPHERTEXT_OPEN') from None
 try:
  before=os.fstat(fd)
  if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or
      stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or before.st_size!=expected_bytes):
   raise Blocked('CAPSULE_CIPHERTEXT_METADATA')
  h=hashlib.sha256();count=0
  while True:
   block=os.read(fd,1024*1024)
   if not block: break
   count+=len(block)
   if count>expected_bytes: raise Blocked('CAPSULE_CIPHERTEXT_SIZE_CHANGED')
   h.update(block)
  after=os.fstat(fd)
  try: named=p.lstat()
  except OSError: raise Blocked('CAPSULE_CIPHERTEXT_PATH_CHANGED') from None
  identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns)
  if (count!=expected_bytes or identity(before)!=identity(after) or identity(after)!=identity(named) or
      stat.S_ISLNK(named.st_mode) or h.hexdigest()!=expected_sha):
   raise Blocked('CAPSULE_CIPHERTEXT_READBACK')
  return h.hexdigest()
 finally: os.close(fd)

def _fixed_private_bytes(path,expected_sha,expected_bytes=None):
 p=Path(path)
 if not p.is_absolute(): raise Blocked('PROVIDER_FILE_PATH_ALIAS')
 try:resolved=p.resolve(strict=True)
 except OSError:raise Blocked('PROVIDER_FILE_PATH_MISSING') from None
 if resolved!=p: raise Blocked('PROVIDER_FILE_PATH_ALIAS')
 for parent in (p.parent,*p.parent.parents):
  st=parent.lstat()
  if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_mode&0o022:
   raise Blocked('PROVIDER_FILE_PARENT_PROTECTION')
 flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)
 try: fd=os.open(p,flags)
 except OSError: raise Blocked('PROVIDER_FILE_OPEN') from None
 try:
  before=os.fstat(fd)
  if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_mode&0o022 or
      before.st_size<=0 or (expected_bytes is not None and before.st_size!=expected_bytes)):
   raise Blocked('PROVIDER_FILE_METADATA')
  h=hashlib.sha256();count=0;chunks=[]
  while True:
   block=os.read(fd,1024*1024)
   if not block: break
   count+=len(block)
   if count>before.st_size: raise Blocked('PROVIDER_FILE_SIZE_CHANGED')
   h.update(block);chunks.append(block)
  after=os.fstat(fd);named=p.lstat()
  ident=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_uid,x.st_gid,x.st_mode,x.st_nlink,x.st_mtime_ns,x.st_ctime_ns)
  if (count!=before.st_size or ident(before)!=ident(after) or ident(after)!=ident(named) or
      stat.S_ISLNK(named.st_mode) or h.hexdigest()!=expected_sha):
   raise Blocked('PROVIDER_FILE_HASH_OR_IDENTITY')
  return b''.join(chunks)
 finally: os.close(fd)

def _fixed_private_file(path,expected_sha,expected_bytes=None):
 data=_fixed_private_bytes(path,expected_sha,expected_bytes)
 return len(data),hashlib.sha256(data).hexdigest()

def verify_redis_snapshot_files(latest,root=REDIS_ROOT,latest_path=REDIS_LATEST_PATH):
 """Rehash both extracted RDB members against the signed parent submember."""
 latest_raw=_fixed_private_bytes(latest_path,REDIS_SIGNED_LATEST_SHA)
 try: actual_latest=json.loads(latest_raw)
 except (ValueError,TypeError):raise Blocked('REDIS_SIGNED_LATEST_JSON') from None
 if canonical(actual_latest)!=canonical(latest):raise Blocked('REDIS_SIGNED_LATEST_DOCUMENT_DIFFERS')
 return verify_redis_instance_files(latest,root)

def verify_redis_instance_files(latest,root):
 """Hash the fixed two RDB filenames after signed latest has been checked."""
 root=Path(root)
 try:rst=root.lstat()
 except OSError:raise Blocked('REDIS_SNAPSHOT_ROOT_MISSING') from None
 if root.is_symlink() or not stat.S_ISDIR(rst.st_mode) or root.resolve(strict=True)!=root or rst.st_mode&0o022:
  raise Blocked('REDIS_SNAPSHOT_ROOT_PROTECTION')
 expected={}
 for row in latest.get('instances',[]) if isinstance(latest,dict) else []:
  if not isinstance(row,dict) or row.get('container') not in {'gf-redis','students-beta-redis'}:
   raise Blocked('REDIS_LATEST_ROW')
  name=row.get('file')
  if name not in {'gf-redis.rdb','students-beta-redis.rdb'} or name in expected:
   raise Blocked('REDIS_LATEST_FILE_SET')
  expected[name]=(row.get('bytes'),row.get('sha256'))
 if set(expected)!={'gf-redis.rdb','students-beta-redis.rdb'}: raise Blocked('REDIS_LATEST_FILE_SET')
 try:observed={entry.name for entry in os.scandir(root)}
 except OSError:raise Blocked('REDIS_SNAPSHOT_SCAN') from None
 if observed!={'gf-redis.rdb','students-beta-redis.rdb','manifest.json','provider-proof.json','gnupg'}:
  raise Blocked('REDIS_SNAPSHOT_MEMBER_SET')
 _fixed_private_file(root/'manifest.json',REDIS_INNER_MANIFEST_SHA,REDIS_INNER_MANIFEST_BYTES)
 _fixed_private_file(root/'provider-proof.json',REDIS_PROVIDER_PROOF_SHA,REDIS_PROVIDER_PROOF_BYTES)
 # The private GnuPG working directory is staging, not an RDB member. Its
 # only expected child is the empty pubring keybox created for symmetric GPG.
 gnupg=root/'gnupg'
 try:gst=gnupg.lstat()
 except OSError:raise Blocked('REDIS_GNUPG_DIRECTORY') from None
 if (gnupg.is_symlink() or not stat.S_ISDIR(gst.st_mode) or gst.st_uid!=os.geteuid() or
     stat.S_IMODE(gst.st_mode)!=0o700 or gnupg.resolve(strict=True)!=gnupg):
  raise Blocked('REDIS_GNUPG_DIRECTORY')
 try:gnupg_names={entry.name for entry in os.scandir(gnupg)}
 except OSError:raise Blocked('REDIS_GNUPG_DIRECTORY') from None
 if gnupg_names!={'pubring.kbx'}:raise Blocked('REDIS_GNUPG_MEMBER_SET')
 keybox=gnupg/'pubring.kbx'
 try:kfd=os.open(keybox,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 except OSError:raise Blocked('REDIS_GNUPG_KEYBOX') from None
 try:
  kst=os.fstat(kfd);knamed=keybox.lstat()
  ident=lambda st:(st.st_dev,st.st_ino,st.st_size,st.st_uid,st.st_gid,st.st_mode,st.st_nlink)
  if (not stat.S_ISREG(kst.st_mode) or kst.st_uid!=os.geteuid() or kst.st_gid!=os.getegid() or
      stat.S_IMODE(kst.st_mode)!=0o600 or kst.st_nlink!=1 or kst.st_size!=32 or ident(kst)!=ident(knamed)):
   raise Blocked('REDIS_GNUPG_KEYBOX')
 finally:os.close(kfd)
 for name,(size,digest) in expected.items():
  if type(size) is not int or not re.fullmatch('[a-f0-9]{64}',str(digest or '')):
   raise Blocked('REDIS_LATEST_DIGEST')
  _fixed_private_file(Path(root)/name,digest,size)
 return {name:{'bytes':expected[name][0],'sha256':expected[name][1]} for name in sorted(expected)}

def verify_rustfs_outer_proof_file(expected_proof,proof_path=RUSTFS_PROOF_PATH):
 raw=_fixed_private_bytes(proof_path,RUSTFS_SIGNED_OUTER_PROOF_SHA)
 try: actual=json.loads(raw)
 except (ValueError,TypeError):raise Blocked('RUSTFS_SIGNED_PROOF_JSON') from None
 if canonical(actual)!=canonical(expected_proof):raise Blocked('RUSTFS_SIGNED_PROOF_DOCUMENT_DIFFERS')
 return sha_bytes(raw)

def verify_rustfs_tree(root,index,expected_filesystem=None):
 """Compare every private extracted RustFS entry and provider digest."""
 root=Path(root);rst=root.lstat()
 if root.is_symlink() or not stat.S_ISDIR(rst.st_mode) or root.resolve(strict=True)!=root:
  raise Blocked('RUSTFS_TREE_ROOT_PROTECTION')
 expected={}
 for row in index.get('entries',[]) if isinstance(index,dict) else []:
  name=row.get('name') if isinstance(row,dict) else None
  if not isinstance(name,str) or name in expected: raise Blocked('RUSTFS_INDEX_ENTRY_DUPLICATE')
  expected[name]=row
 observed=set();actual_records=[];regular_bytes=0
 def walk(directory,rel='.'):
  nonlocal regular_bytes
  try: entries=list(os.scandir(directory))
  except OSError: raise Blocked('RUSTFS_TREE_SCAN') from None
  for ent in entries:
   name=ent.name if rel=='.' else rel+'/'+ent.name
   st=ent.stat(follow_symlinks=False)
   if stat.S_ISLNK(st.st_mode) or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
    raise Blocked('RUSTFS_TREE_UNSUPPORTED_TYPE')
   if name not in expected: raise Blocked('RUSTFS_TREE_EXTRA_ENTRY')
   row=expected[name];kind='directory' if stat.S_ISDIR(st.st_mode) else 'file'
   if (row.get('type')!=kind or row.get('bytes')!=(0 if kind=='directory' else st.st_size) or
       row.get('uid')!=st.st_uid or row.get('gid')!=st.st_gid or row.get('mode')!=stat.S_IMODE(st.st_mode)):
    raise Blocked('RUSTFS_TREE_METADATA_DIFFERS')
   if kind=='file':
    _fixed_private_file(Path(directory)/ent.name,row.get('sha256'),row.get('bytes'))
    regular_bytes+=st.st_size
    actual_records.append([name,'file',st.st_size,row['sha256']])
   else:
    actual_records.append([name,'dir',0,None])
   observed.add(name)
   if kind=='directory': walk(Path(directory)/ent.name,name)
 walk(root)
 root_row=expected.get('.')
 if not isinstance(root_row,dict) or root_row.get('type')!='directory' or (
    root_row.get('uid'),root_row.get('gid'),root_row.get('mode'))!=(rst.st_uid,rst.st_gid,stat.S_IMODE(rst.st_mode)):
  raise Blocked('RUSTFS_TREE_ROOT_METADATA')
 observed.add('.')
 if observed!=set(expected): raise Blocked('RUSTFS_TREE_MEMBER_SET')
 # Match producer order: sorted(Path(root.rglob('*'))), i.e. component-wise paths.
 actual_records.sort(key=lambda row:Path(row[0]))
 filesystem={'sha256':sha_bytes(json.dumps(actual_records,separators=(',',':')).encode()),
             'entries':len(actual_records),'bytes':regular_bytes}
 if expected_filesystem is not None and filesystem!=expected_filesystem:
  raise Blocked('RUSTFS_PROVIDER_FILESYSTEM_DIGEST')
 return {'entryCount':len(observed)-1,'indexedEntries':len(observed),
         'regularBytes':regular_bytes,'entriesSha256':sha_bytes(canonical(index['entries'])),
         'filesystem':filesystem}

def verify_capsule_file_index(plaintext_path,file_index,expected_plaintext_sha):
 """Recompute the external staging index from the exact decrypted capsule.

 The old 9fa/0176 index is nested inside the immutable historical record. This
 verifies the fresh outer capsule index, which contains that record plus this
 cycle's captures. Links are recorded but never followed or materialized.
 """
 p=Path(plaintext_path);st=p.lstat()
 if (p.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or
     stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1 or
     not 0<st.st_size<=MAX_CAPSULE_PLAINTEXT_BYTES or sha_file(p)!=expected_plaintext_sha):
  raise Blocked('CAPSULE_PLAINTEXT_READBACK_BINDING')
 files=file_index.get('files');links=file_index.get('linksNotMaterialized')
 if (file_index.get('schema')!='platform.extended-capsule-file-staging/v1' or
     file_index.get('noLinksFollowed') is not True or not isinstance(files,dict) or
     not isinstance(links,list) or len(files)>MAX_CAPSULE_ENTRIES or len(links)>MAX_CAPSULE_ENTRIES):
  raise Blocked('CAPSULE_INDEX_SHAPE')
 observed_files={};observed_links=[];observed_dirs=set();seen=set();total=0;entries=0
 try:
  with tarfile.open(p,'r|gz') as archive:
   for member in archive:
    entries+=1
    if entries>MAX_CAPSULE_ENTRIES:raise Blocked('CAPSULE_MEMBER_COUNT_BOUND')
    name=member.name
    while name.startswith('./'):name=name[2:]
    if member.isdir():name=name.rstrip('/')
    if name=='host/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase':
     raise Blocked('CAPSULE_CREDENTIAL_MUST_BE_OMITTED')
    path=Path(name)
    if (not name or name.startswith('/') or any(part in ('','.','..') for part in name.split('/')) or '\x00' in name or
        ('\\' in name and name not in ESCAPED_REGULAR_MEMBERS|ESCAPED_SYMLINK_MEMBERS) or
        name in seen or member.uid<0 or member.gid<0 or member.mode<0):
     raise Blocked('CAPSULE_MEMBER_PATH_OR_METADATA')
    if name in ESCAPED_REGULAR_MEMBERS and not member.isfile():raise Blocked('CAPSULE_ESCAPED_MEMBER_TYPE')
    if name in ESCAPED_SYMLINK_MEMBERS and not member.issym():raise Blocked('CAPSULE_ESCAPED_MEMBER_TYPE')
    seen.add(name)
    if member.isfile():
     row=files.get(name)
     if not isinstance(row,dict) or set(row)!={'sha256','bytes','uid','gid','mode'}:
      raise Blocked('CAPSULE_INDEX_FILE_ROW')
     source=archive.extractfile(member)
     if source is None:raise Blocked('CAPSULE_MEMBER_UNREADABLE')
     h=hashlib.sha256();count=0
     for block in iter(lambda:source.read(1024*1024),b''):
      count+=len(block);total+=len(block)
      if count>member.size or total>MAX_CAPSULE_PLAINTEXT_BYTES:raise Blocked('CAPSULE_MEMBER_STREAM_BOUND')
      h.update(block)
     digest=h.hexdigest()
     if count!=member.size or (row.get('bytes'),row.get('sha256'),row.get('uid'),row.get('gid'),row.get('mode'))!=(count,digest,member.uid,member.gid,member.mode):
      raise Blocked('CAPSULE_MEMBER_INDEX_DIFFERS')
     observed_files[name]={'bytes':count,'sha256':digest,'uid':member.uid,'gid':member.gid,'mode':member.mode}
    elif member.isdir():observed_dirs.add(name)
    elif member.issym():observed_links.append({'name':name,'type':'symlink'})
    elif member.islnk():observed_links.append({'name':name,'type':'hardlink'})
    else:raise Blocked('CAPSULE_SPECIAL_MEMBER')
 except (OSError,tarfile.TarError):raise Blocked('CAPSULE_ARCHIVE_PARSE') from None
 if (observed_files!=files or sorted(observed_links,key=lambda row:row['name'])!=sorted(links,key=lambda row:row.get('name','')) or
     file_index.get('regularFiles')!=len(observed_files) or file_index.get('regularBytes')!=total or
     file_index.get('entries')!=entries or entries!=len(observed_files)+len(observed_links)+len(observed_dirs)):
  raise Blocked('CAPSULE_INDEX_DIFFERS_FROM_DECRYPTED_ARCHIVE')
 return {'plaintextSha256':expected_plaintext_sha,'fileIndexSha256':sha_bytes(canonical({k:v for k,v in file_index.items() if k!='_fileSha256'})),
         'regularFiles':len(observed_files),'directories':len(observed_dirs),'links':len(observed_links),'entries':entries,'regularBytes':total}

def verify_historical_record_content(plaintext_path,file_index,readback_proof):
 """Extract the exact historical record from the verified outer tar and run
 the independently pinned historical-record reader over its actual bytes."""
 if (not isinstance(readback_proof,dict) or readback_proof.get('schema')!='platform.recovery-record-readback/v1' or
     readback_proof.get('status')!='passed' or readback_proof.get('remoteReadbackVerified') is not True or
     readback_proof.get('decryptedAfterReadback') is not True or readback_proof.get('offsiteVerified') is not True or
     readback_proof.get('manifestId')!=PARENT_ID or readback_proof.get('manifestDigest')!=PARENT_DIGEST or
     readback_proof.get('parentReceiptSha256')!=PARENT_RECEIPT):
  raise Blocked('HISTORICAL_RECORD_READBACK_SCHEMA')
 files=file_index.get('files',{})
 names=[HIST+'/current.tar',HIST+'/index.json',HIST+'/proof.json']
 expected={}
 for name in names:
  row=files.get('host'+name)
  if not isinstance(row,dict) or type(row.get('bytes')) is not int or row['bytes']<=0 or row['bytes']>600_000_000:
   raise Blocked('HISTORICAL_RECORD_OUTER_INDEX_BINDING')
  expected[name]=row
 reader_path=HERE/'verify_historical_recovery_record.py'
 if not reader_path.is_file():reader_path=Path('/usr/local/libexec/platform-host-recovery-verify-historical-record.py')
 rst=reader_path.lstat()
 if (reader_path.is_symlink() or not stat.S_ISREG(rst.st_mode) or rst.st_uid not in {0,os.geteuid()} or
     rst.st_mode&0o022 or sha_file(reader_path)!=HISTORICAL_READER_SHA):
  raise Blocked('HISTORICAL_READER_CODE_PIN')
 spec=importlib.util.spec_from_file_location('pinned_g16_historical_record_reader',reader_path)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 with tempfile.TemporaryDirectory(prefix='g16-historical-record-',dir=Path(plaintext_path).parent) as tmp:
  root=Path(tmp);os.chmod(root,0o700);record=root/'record';record.mkdir(mode=0o700)
  wanted={Path(name).name:name for name in names};found=set()
  with tarfile.open(plaintext_path,'r|gz') as tar:
   for member in tar:
    member_name=member.name.removeprefix('./')
    target_name=next((n for n in names if member_name=='host'+n),None)
    if target_name is None:continue
    if target_name in found or not member.isfile() or member.size!=expected[target_name]['bytes']:
     raise Blocked('HISTORICAL_RECORD_MEMBER_TYPE_OR_SIZE')
    src=tar.extractfile(member)
    if src is None:raise Blocked('HISTORICAL_RECORD_MEMBER_UNREADABLE')
    target=record/Path(target_name).name;fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    h=hashlib.sha256();count=0
    with os.fdopen(fd,'wb') as out:
     for block in iter(lambda:src.read(1024*1024),b''):
      count+=len(block)
      if count>member.size or count>600_000_000:raise Blocked('HISTORICAL_RECORD_MEMBER_STREAM_BOUND')
      out.write(block);h.update(block)
     out.flush();os.fsync(out.fileno())
    if count!=member.size or h.hexdigest()!=expected[target_name]['sha256']:
     raise Blocked('HISTORICAL_RECORD_MEMBER_HASH')
    found.add(target_name)
    if found==set(names):break
  if found!=set(names):raise Blocked('HISTORICAL_RECORD_MEMBER_SET')
  content=module.verify_record(record,{'manifestId':PARENT_ID,'manifestDigest':PARENT_DIGEST,'receiptSha256':PARENT_RECEIPT})
  expected_record={'archiveBytes':expected[HIST+'/current.tar']['bytes'],
   'recordMemberSha256':expected[HIST+'/current.tar']['sha256'],
   'indexSha256':expected[HIST+'/index.json']['sha256'],
   'proofMemberSha256':expected[HIST+'/proof.json']['sha256']}
  if (readback_proof.get('artifactSha256')!=content.get('artifactSha256') or
      readback_proof.get('artifactSetSha256')!=content.get('artifactSetSha256') or
      readback_proof.get('recordMemberSha256')!=expected_record['recordMemberSha256'] or
      readback_proof.get('indexSha256')!=expected_record['indexSha256'] or
      readback_proof.get('proofMemberSha256')!=expected_record['proofMemberSha256'] or
      content.get('recordMemberSha256')!=expected_record['recordMemberSha256'] or
      content.get('indexSha256')!=expected_record['indexSha256'] or
      content.get('proofSha256')!=expected_record['proofMemberSha256'] or
      readback_proof.get('extendedCapsuleVerified')!=content.get('extendedCapsuleVerified')):
   raise Blocked('HISTORICAL_RECORD_READBACK_CONTENT_DIFFERS')
  return {'contentProofSha256':sha_bytes(canonical(content)),
          'recordArchiveSha256':expected_record['recordMemberSha256'],
          'recordIndexSha256':expected_record['indexSha256'],
          'recordProofMemberSha256':expected_record['proofMemberSha256'],
          'nestedCapsuleCipherSha256':content['extendedCapsuleVerified']['cipherSha256'],
          'nestedCapsulePlaintextSha256':content['extendedCapsuleVerified']['plaintextSha256'],
          'databaseBundleSha256':content['extendedCapsuleVerified']['databaseBundleSha256']}
def private_json(path,limit=16*1024*1024):
 p=Path(path);st=p.lstat()
 if p.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1 or not 0<st.st_size<=limit: raise Blocked('PRIVATE_INPUT_PROTECTION')
 value=json.loads(p.read_bytes())
 if not isinstance(value,dict): raise Blocked('INPUT_OBJECT_REQUIRED')
 return value,sha_file(p)
def load_key(path):
 p=Path(path)
 if p!=KEY_PATH: raise Blocked('RECOVERY_KEY_PATH')
 fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=1000 or st.st_gid!=1000 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1 or not 0<st.st_size<=65536: raise Blocked('RECOVERY_KEY_METADATA')
  here=p.lstat()
  if stat.S_ISLNK(here.st_mode) or (st.st_dev,st.st_ino,st.st_uid,st.st_gid,st.st_mode,st.st_nlink)!=(here.st_dev,here.st_ino,here.st_uid,here.st_gid,here.st_mode,here.st_nlink) or p.resolve(strict=True)!=p: raise Blocked('RECOVERY_KEY_IDENTITY')
  for parent in (p.parent,*p.parent.parents):
   info=parent.lstat()
   if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode): raise Blocked('RECOVERY_KEY_PARENT_ALIAS')
  chunks=[];size=0
  while True:
   b=os.read(fd,4096)
   if not b: break
   size+=len(b)
   if size>65536: raise Blocked('RECOVERY_KEY_SIZE')
   chunks.append(b)
  end=os.fstat(fd)
  if (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)!=(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns): raise Blocked('RECOVERY_KEY_CHANGED')
  return b''.join(chunks)
 finally: os.close(fd)
def verify_doc(doc,domain,key):
 if not isinstance(doc,dict) or set(doc)!={'payload','hmacSha256'} or not isinstance(doc['payload'],dict): raise Blocked('SIGNED_DOCUMENT_SHAPE')
 expected=hmac.new(key,domain+canonical(doc['payload']),hashlib.sha256).hexdigest()
 if not hmac.compare_digest(expected,str(doc['hmacSha256'])): raise Blocked('SIGNED_DOCUMENT_HMAC')
 return doc['payload'],sha_bytes(canonical(doc))
def load_lineage_module():
 path=_lineage_module()
 st=path.lstat()
 if (path.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid not in {0,os.geteuid()} or st.st_mode&0o022 or
     sha_file(path)!=LINEAGE_CODE_SHA): raise Blocked('LINEAGE_DERIVATION_CODE_PIN')
 spec=importlib.util.spec_from_file_location('pinned_lineage_membership_v4',path)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 return module

def assemble(publisher,native_restore,capsule_proof,file_index,key_bytes,
             parent_manifest=None,full_bindings=None,private_plan=None,source_proof_shas=None,
             historical_record_proof=None,capsule_plaintext_path=None,selected_members=None,
             selected_members_sha=None,durable_receipt_document=None,durable_index=None,durable_index_sha=None,
             provider_proofs=None,live_host_root=Path('/')):
 if publisher.get('schema')!='platform.g16-native-publisher-readback/v1' or publisher.get('status')!='published-readback-verified' or publisher.get('offsiteVerified') is not True or publisher.get('remoteReceiptReadbackVerified') is not True: raise Blocked('PUBLISHER_READBACK_REQUIRED')
 parent,parent_receipt_sha=verify_doc(publisher.get('receiptDocument'),b'platform-ftps-receipt-v1\n',key_bytes)
 base,base_sha=verify_doc(publisher.get('baseCompletenessDocument'),b'platform-ftps-supplement-v1\n',key_bytes)
 overlay,overlay_sha=verify_doc(publisher.get('overlayReceiptDocument'),b'platform-ftps-supplement-v1\n',key_bytes)
 if (parent.get('manifestId')!=PARENT_ID or parent.get('manifestDigest')!=PARENT_DIGEST or
     parent_receipt_sha!=PARENT_RECEIPT or parent.get('bundle')!='backup-'+PARENT_ID+'.tar.gpg' or
     parent.get('status')!='passed' or parent.get('encryptedSha256')!=publisher.get('sourceArchiveSha256')): raise Blocked('G15_PARENT_LINEAGE')
 rows=[x for x in base.get('files',[]) if isinstance(x,dict) and x.get('name')=='full-runtime.tar.gz']
 if (base.get('kind')!='runtime-completeness-material' or base.get('status')!='passed' or len(rows)!=1 or
     rows[0].get('sha256')!=BASE_ARCHIVE or rows[0].get('bytes')!=BASE_BYTES or
     base.get('parentManifestId')!=PARENT_ID or base.get('parentManifestDigest')!=PARENT_DIGEST or
     base.get('parentReceiptSha256')!=PARENT_RECEIPT or base.get('parentEncryptedSha256')!=parent.get('encryptedSha256') or
     publisher.get('baseCompletenessReceiptSha256')!=base_sha): raise Blocked('G15_COMPLETENESS_LINEAGE')
 if (overlay.get('schema')!='platform.ftps-source-metadata-overlay/v4' or overlay.get('kind')!='source-metadata-overlay-v4' or overlay.get('status')!='passed' or
     overlay.get('parentManifestId')!=PARENT_ID or overlay.get('parentManifestDigest')!=PARENT_DIGEST or
     overlay.get('parentReceiptSha256')!=PARENT_RECEIPT or overlay.get('parentEncryptedSha256')!=parent.get('encryptedSha256') or
     overlay.get('baseCompletenessCiphertext')!=base.get('ciphertext') or overlay.get('baseCompletenessEncryptedSha256')!=base.get('encryptedSha256') or
     overlay.get('baseCompletenessReceiptSha256')!=base_sha or overlay.get('baseArchiveSha256')!=BASE_ARCHIVE or
     overlay.get('baseArchiveBytes')!=BASE_BYTES or overlay.get('encryptedSha256')!=publisher.get('sourceOverlaySha256') or
     publisher.get('overlayReceiptSha256')!=overlay_sha): raise Blocked('G16_TYPED_OVERLAY_LINEAGE')
 parts=overlay.get('parts')
 observed=publisher.get('remotePartReadback')
 if not isinstance(parts,list) or not parts or not isinstance(observed,list): raise Blocked('REMOTE_PART_READBACK_REQUIRED')
 normalize=lambda seq:[{'name':x.get('name'),'bytes':x.get('bytes'),'sha256':x.get('sha256')} for x in seq if isinstance(x,dict)]
 if len(normalize(parts))!=len(parts) or normalize(parts)!=normalize(observed) or publisher.get('encryptedBytes')!=overlay.get('encryptedBytes') or publisher.get('encryptedSha256')!=overlay.get('encryptedSha256'): raise Blocked('REMOTE_PART_HASHES_DIFFER')
 if (native_restore.get('status')!='passed' or native_restore.get('metadataValidated') is not True or
     native_restore.get('overlayPackageSha256')!=overlay.get('overlayPackageSha256') or
     native_restore.get('capsuleCiphertextSha256')!=overlay.get('capsuleSha256') or
     native_restore.get('innerTypedReceiptSha256')!=overlay.get('overlayReceiptSha256') or
     native_restore.get('nativeReaderCodeSha256')!=NATIVE_READER_SHA or
     native_restore.get('mountedConfigModuleCodeSha256')!=MOUNTED_CONFIG_READER_SHA or
     native_restore.get('sourceMetadataReaderCodeSha256')!=METADATA_READER_SHA): raise Blocked('NATIVE_READER_RECEIPT_BINDING')
 proof_plain=capsule_proof.get('plaintextArchiveSha256');proof_cipher=capsule_proof.get('encryptedSha256')
 proof_sha=file_index.get('_fileSha256')
 if (capsule_proof.get('status')!='passed' or not re.fullmatch('[a-f0-9]{64}',str(proof_cipher or '')) or
     type(capsule_proof.get('encryptedBytes')) is not int or not 0<capsule_proof['encryptedBytes']<=70_000_000_000 or
     not re.fullmatch('[a-f0-9]{64}',str(proof_plain or '')) or overlay.get('capsuleSha256')!=proof_cipher or
     publisher.get('hostCapsuleSha256')!=proof_cipher or overlay.get('capsuleProofSha256')!=capsule_proof.get('_proofFileSha256') or
     publisher.get('hostCapsuleProofSha256')!=capsule_proof.get('_proofFileSha256') or
     not re.fullmatch('[a-f0-9]{64}',str(proof_sha or '')) or
     file_index.get('schema')!='platform.extended-capsule-file-staging/v1' or file_index.get('noLinksFollowed') is not True): raise Blocked('CAPSULE_PROOF_CHAIN')
 if capsule_plaintext_path is None: raise Blocked('CAPSULE_PLAINTEXT_INPUT_REQUIRED')
 capsule_index_proof=verify_capsule_file_index(capsule_plaintext_path,file_index,proof_plain)
 module_path=MOUNTED_CONFIG_MODULE
 mst=module_path.lstat()
 if (module_path.is_symlink() or module_path.resolve(strict=True)!=module_path or not stat.S_ISREG(mst.st_mode) or
     mst.st_uid!=os.geteuid() or mst.st_mode&0o022 or mst.st_nlink!=1 or sha_file(module_path)!=MOUNTED_CONFIG_READER_SHA):
  raise Blocked('MOUNTED_CONFIG_READER_PIN')
 for ancestor in (module_path.parent,*module_path.parent.parents):
  ast=ancestor.lstat()
  if ancestor.is_symlink() or not stat.S_ISDIR(ast.st_mode) or ast.st_mode&0o022:
   raise Blocked('MOUNTED_CONFIG_READER_ANCESTRY')
 spec=importlib.util.spec_from_file_location('mounted_config_sidecar_v5',module_path)
 if spec is None or spec.loader is None:raise Blocked('MOUNTED_CONFIG_READER_IMPORT')
 mounted=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mounted;spec.loader.exec_module(mounted)
 sidecar_bytes,sidecar_member_sha,sidecar_archive_sha,sidecar_archive_bytes=mounted.read_capsule_sidecar_member(capsule_plaintext_path)
 try:sidecar_document=json.loads(sidecar_bytes)
 except (ValueError,UnicodeDecodeError):raise Blocked('MOUNTED_CONFIG_SIDECAR_JSON') from None
 capture_descriptor=mounted.descriptor(sidecar_bytes,sidecar_document)
 if (capture_descriptor!=overlay.get('mountedConfigCapture') or
     sidecar_archive_sha!=proof_plain or sidecar_archive_bytes!=Path(capsule_plaintext_path).stat().st_size):
  raise Blocked('MOUNTED_CONFIG_SIGNED_MEMBER_BINDING')
 typed_rows=[r for r in overlay.get('files',[]) if isinstance(r,dict) and r.get('name')==mounted.MEMBER]
 if len(typed_rows)!=1 or typed_rows[0]!={'name':mounted.MEMBER,'bytes':len(sidecar_bytes),'sha256':sidecar_member_sha}:
  raise Blocked('MOUNTED_CONFIG_TYPED_FILE_ROW')
 capsule_file_row=file_index.get('files',{}).get('host/var/lib/platform-host-recovery/mounted-config-tree-records.json')
 if (not isinstance(capsule_file_row,dict) or
     (capsule_file_row.get('bytes'),capsule_file_row.get('sha256'),capsule_file_row.get('uid'),
      capsule_file_row.get('gid'),capsule_file_row.get('mode'))!=(len(sidecar_bytes),sidecar_member_sha,0,0,0o600)):
  raise Blocked('MOUNTED_CONFIG_CAPSULE_FILE_INDEX_BINDING')
 import gzip
 with Path(capsule_plaintext_path).open('rb') as raw:
  decompressor=gzip.GzipFile(fileobj=raw,mode='rb')
  try:mounted_readback=mounted.verify_capsule_plaintext(sidecar_document,sidecar_bytes,decompressor)
  finally:decompressor.close()
 if (mounted_readback.get('status')!='passed' or mounted_readback.get('sidecarMemberSha256')!=sidecar_member_sha or
     mounted_readback.get('cycleId')!=capture_descriptor.get('cycleId') or mounted_readback.get('credentialArchived') is not False):
  raise Blocked('MOUNTED_CONFIG_SAME_CYCLE_READBACK')
 native_capsule_readback=native_restore.get('mountedConfigCapsuleReadback')
 if (not isinstance(native_capsule_readback,dict) or
     native_capsule_readback.get('capsuleCipherSha256')!=proof_cipher or
     native_capsule_readback.get('capsulePlaintextSha256')!=proof_plain or
     native_capsule_readback.get('sidecarMemberSha256')!=sidecar_member_sha or
     native_capsule_readback.get('cycleId')!=capture_descriptor.get('cycleId') or
     native_capsule_readback.get('credentialContentRead') is not False):
  raise Blocked('NATIVE_MOUNTED_CONFIG_READBACK_BINDING')
 current_live=mounted.verify_current_live(sidecar_document,live_host_root)
 if (current_live.get('status')!='passed' or current_live.get('cycleId')!=capture_descriptor.get('cycleId') or
     current_live.get('sourceCount')!=89 or current_live.get('credentialContentRead') is not False):
  raise Blocked('CURRENT_MOUNTED_CONFIG_NOT_EQUIVALENT')
 files=file_index.get('files');links=file_index.get('linksNotMaterialized')
 if not isinstance(files,dict) or not isinstance(links,list): raise Blocked('CAPSULE_INDEX_COUNTS')
 def indexed(path):
  name='host'+path
  row=files.get(name)
  if not isinstance(row,dict) or set(row)!={'sha256','bytes','uid','gid','mode'} or not re.fullmatch('[a-f0-9]{64}',str(row.get('sha256',''))) or type(row.get('bytes')) is not int: raise Blocked('CAPSULE_MEMBER_NOT_AUTHENTICATED:'+path)
  return row
 historic={name:indexed(HIST+'/'+name) for name in ('current.tar','index.json','proof.json')}
 trees={name:indexed(OLD_TREES+'/'+name) for name in ('current.tar','index.json','capture-proof.json')}
 sql=indexed(SQL+'/current.tar')
 if (historic['current.tar']['bytes']>600_000_000 or historic['index.json']['bytes']>16_777_216 or
     historic['proof.json']['bytes']>1_000_000 or trees['current.tar']['bytes']>536_870_912 or
     trees['index.json']['bytes']>16_777_216 or trees['capture-proof.json']['bytes']>1_000_000 or
     sql['bytes']>536_870_912): raise Blocked('CAPSULE_REQUIRED_MEMBER_SIZE_BOUND')
 if historical_record_proof is not None:
  authenticated_record=historical_record_proof.get('authenticatedRecordMembers')
  if authenticated_record!={'current.tar':historic['current.tar']['sha256'],'index.json':historic['index.json']['sha256'],'proof.json':historic['proof.json']['sha256']}:
   raise Blocked('HISTORICAL_RECORD_INDEX_BINDING')
  historical_content=verify_historical_record_content(capsule_plaintext_path,file_index,historical_record_proof)
 else:
  historical_content=None
 index_projection={'fileStagingProofSha256':proof_sha,'files':files,'linksNotMaterialized':links,'entries':file_index['entries']}
 point={'schema':'platform.native-point-readback/v1','status':'passed','cryptographicReceiptChainVerified':True,
  'remotePartReadbackVerified':True,'nativeOverlayReaderVerified':True,'signedReceiptVerified':True,
  'fullRemoteReadback':True,'allMemberHashesVerified':True,'offsiteVerified':True,'typedOverlayReadback':True,'nativeReaderVerified':True,
  'manifestId':PARENT_ID,'manifestDigest':PARENT_DIGEST,'parentReceiptSha256':parent_receipt_sha,
  'baseArchiveSha256':BASE_ARCHIVE,'baseArchiveBytes':BASE_BYTES,'receiptSha256':parent_receipt_sha,
  'overlayReceiptSha256':overlay_sha,'baseCompletenessReceiptSha256':base_sha,
  'sourceArchiveSha256':parent['encryptedSha256'],'sourceOverlaySha256':overlay['encryptedSha256'],
  'hostCapsuleSha256':proof_cipher,'hostCapsulePlaintextSha256':proof_plain,'hostCapsuleProofSha256':capsule_proof.get('_proofFileSha256'),
  'mountedConfigCapture':capture_descriptor,'mountedConfigCapsuleReadback':mounted_readback,
  'mountedConfigCurrentLiveVerification':current_live,
  'databaseBundleSha256':sql['sha256'],'extraTreesArchiveSha256':trees['current.tar']['sha256'],
  'extraTreesIndexSha256':trees['index.json']['sha256'],'extraTreesCaptureProofSha256':trees['capture-proof.json']['sha256'],
  'authenticatedMembers':{HIST+'/'+name:row['sha256'] for name,row in historic.items()}|{OLD_TREES+'/'+name:row['sha256'] for name,row in trees.items()}|{SQL+'/current.tar':sql['sha256']},
  'authenticatedArtifactIndexSha256':sha_bytes(canonical(index_projection)),'capsuleIndexRecomputed':True,
  'capsuleIndexReadback':capsule_index_proof,
  'receiptDocument':publisher['receiptDocument'],'baseCompletenessDocument':publisher['baseCompletenessDocument'],
  'overlayReceiptDocument':publisher['overlayReceiptDocument'],'nativeOverlayRestore':native_restore,
  'remotePartReadback':observed,'capsuleFileStagingProofSha256':proof_sha,'offsiteVerified':True}
 if parent_manifest is not None:
  if full_bindings is None or private_plan is None or not isinstance(source_proof_shas,dict):
   raise Blocked('AUTHENTICATED_MEMBERSHIP_INPUTS_REQUIRED')
  if not isinstance(historical_record_proof,dict):raise Blocked('HISTORICAL_RECORD_READBACK_REQUIRED')
  authenticated_record=historical_record_proof.get('authenticatedRecordMembers')
  if (historical_record_proof.get('schema')!='platform.recovery-record-readback/v1' or historical_record_proof.get('status')!='passed' or
      historical_record_proof.get('remoteReadbackVerified') is not True or historical_record_proof.get('decryptedAfterReadback') is not True or
      historical_record_proof.get('offsiteVerified') is not True or historical_record_proof.get('manifestId')!=PARENT_ID or
      historical_record_proof.get('manifestDigest')!=PARENT_DIGEST or historical_record_proof.get('parentReceiptSha256')!=parent_receipt_sha or
      historical_record_proof.get('baseArchiveSha256')!=BASE_ARCHIVE or historical_record_proof.get('baseArchiveBytes')!=BASE_BYTES or
      historical_record_proof.get('overlayReceiptSha256')!=overlay_sha or historical_record_proof.get('hostCapsuleSha256')!=proof_cipher or
      historical_record_proof.get('hostCapsulePlaintextSha256')!=proof_plain or not isinstance(authenticated_record,dict) or
      authenticated_record!={'current.tar':historic['current.tar']['sha256'],'index.json':historic['index.json']['sha256'],'proof.json':historic['proof.json']['sha256']}):
   raise Blocked('HISTORICAL_RECORD_READBACK_BINDING')
  derivation=load_lineage_module()
  durable_payload,durable_receipt_sha=verify_doc(durable_receipt_document,b'platform-ftps-supplement-v1\n',key_bytes)
  if durable_receipt_sha!=DURABLE_SUPPLEMENT_RECEIPT_SHA:raise Blocked('DURABLE_RECEIPT_DOCUMENT_SHA')
  if not isinstance(provider_proofs,dict):raise Blocked('NATIVE_PROVIDER_PROOFS_REQUIRED')
  def provider_doc(name,expected):
   value=provider_proofs.get(name)
   if not isinstance(value,tuple) or len(value)!=2 or value[1]!=expected or not isinstance(value[0],dict):
    raise Blocked('NATIVE_PROVIDER_PROOF_PIN:'+name)
   return value
  native_state,native_state_sha=provider_doc('native-state-actual-proof.json',NATIVE_STATE_PROOF_SHA)
  redis_provider,redis_provider_sha=provider_doc('redis-provider-proof-actual.json',REDIS_PROVIDER_PROOF_SHA)
  redis_inner_manifest,redis_inner_manifest_sha=provider_doc('redis-inner-manifest-actual.json',REDIS_INNER_MANIFEST_SHA)
  redis_latest,redis_latest_sha=provider_doc('redis-signed-latest-submember-actual.json',REDIS_SIGNED_LATEST_SHA)
  rustfs_provider,rustfs_provider_sha=provider_doc('rustfs-provider-proof-actual.json',RUSTFS_PROVIDER_PROOF_SHA)
  rustfs_outer,rustfs_outer_sha=provider_doc('rustfs-signed-outer-submember-proof-actual.json',RUSTFS_SIGNED_OUTER_PROOF_SHA)
  rustfs_tree_index,rustfs_tree_index_sha=provider_doc('rustfs-extracted-tree-index-actual.json',RUSTFS_TREE_INDEX_SHA)
  redis_files=verify_redis_snapshot_files(redis_latest)
  verify_rustfs_outer_proof_file(rustfs_outer)
  rustfs_files=verify_rustfs_tree(RUSTFS_TREE_ROOT,rustfs_tree_index,rustfs_provider.get('filesystem'))
  maps,parent_ids,source_ids,cold_ids,extra_ids,target_members=derivation.derive(
   parent_manifest,full_bindings,private_plan,base,overlay,
   native_restore.get('sourceResourceIds',[]),file_index,selected_members,selected_members_sha,
   durable_payload,durable_receipt_sha,durable_index,durable_index_sha,
   native_state,native_state_sha,redis_provider,redis_provider_sha,redis_inner_manifest,redis_inner_manifest_sha,
   redis_latest,redis_latest_sha,rustfs_provider,rustfs_provider_sha,rustfs_outer,rustfs_outer_sha,
   rustfs_tree_index,rustfs_tree_index_sha)
  coverage=derivation.audit_active87(maps,full_bindings['resources'],target_members)
  point['authenticatedMembership']={
   'schema':'platform.active87-authenticated-membership/v1','status':'passed',
   'parent':{'manifestId':PARENT_ID,'manifestDigest':PARENT_DIGEST,'receiptSha256':parent_receipt_sha},
   'receipts':{'parent':parent_receipt_sha,'base-completeness':base_sha,'source-overlay':overlay_sha,
               'parent-durable-supplement':DURABLE_SUPPLEMENT_RECEIPT_SHA},
   'sourceProofs':dict(sorted({**source_proof_shas,'nativeOverlayRestoreSha256':sha_bytes(canonical(native_restore)),
                               'historicalRecordContentSha256':historical_content['contentProofSha256']}.items())),
   'indexSha256':{'parentManifest':PARENT_MANIFEST_SHA,'baseSupplement':base_sha,
                  'sourceOverlay':overlay_sha,'capsuleFileStaging':proof_sha},
   'membershipByRole':maps,
   'targetToAuthenticatedMembers':target_members,
   'derivationCodeSha256':sha_file(Path(__file__).resolve()),
   'lineageDerivationCodeSha256':LINEAGE_CODE_SHA,
   'sourceDocumentsSha256':{'fullBindings':FULL_BINDINGS_SHA,'private240Plan':PRIVATE240_PLAN_SHA},
   'resourceCounts':{'parent':len(parent_ids),'source':len(source_ids),'coldVolumes':len(cold_ids),'extraTrees':len(extra_ids)},
   'providerMemberReadback':{'redisRdbs':redis_files,'rustfsTree':rustfs_files,
      'redisProviderProofSha256':redis_provider_sha,'redisInnerManifestSha256':redis_inner_manifest_sha,
      'redisSignedLatestMemberSha256':redis_latest_sha,'rustfsProviderProofSha256':rustfs_provider_sha,
      'rustfsSignedOuterProofSha256':rustfs_outer_sha,'rustfsTreeIndexSha256':rustfs_tree_index_sha},
  'active87Coverage':coverage}
 if 'authenticatedMembership' in point:
  membership_sha=sha_bytes(canonical(point['authenticatedMembership']))
  config_scope=mounted.output_equivalence_rows(mounted_readback,overlay['encryptedSha256'],membership_sha)
  point['mountedConfigScope']={'schema':'platform.active87-mounted-config-equivalence/v2','status':'passed',
    'manifestId':PARENT_ID,'manifestDigest':PARENT_DIGEST,'nativeMembershipSha256':membership_sha,
    'hostCapsuleCipherSha256':proof_cipher,'mountedConfigSidecarSha256':sidecar_member_sha,
    'cycleId':capture_descriptor['cycleId'],**config_scope,
    'currentLiveVerification':current_live,'offsiteVerified':True,'productionModified':False}
 point['proofSha256']=sha_bytes(canonical(point))
 return point

LINEAGE_CODE_SHA='dc56bc44849794911eaf76ac5658d30ed30bc1d46d5aa21a604e134814c0010a'

def _pinned_json(path,expected_sha,limit=32*1024*1024):
 p=Path(path);st=p.lstat()
 if (p.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or
     st.st_nlink!=1 or st.st_size<=0 or st.st_size>limit or stat.S_IMODE(st.st_mode)&0o022 or p.resolve(strict=True)!=p):
  raise Blocked('PINNED_LINEAGE_DOCUMENT_PROTECTION:'+p.name)
 fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  before=os.fstat(fd);data=b''
  with os.fdopen(os.dup(fd),'rb') as f:data=f.read(limit+1)
  after=os.fstat(fd)
  if len(data)>limit or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise Blocked('PINNED_LINEAGE_DOCUMENT_CHANGED:'+p.name)
 finally:os.close(fd)
 digest=sha_bytes(data);value=json.loads(data)
 if not isinstance(value,dict):raise Blocked('PINNED_LINEAGE_DOCUMENT_OBJECT:'+p.name)
 if digest!=expected_sha: raise Blocked('PINNED_LINEAGE_DOCUMENT_SHA:'+Path(path).name)
 return value

def verify_membership(folder,proof):
 """Recompute a stored point and its four role maps from protected inputs.

 Folder names are fixed: publisher-readback.json, native-overlay-restore.json,
 capsule-ciphertext.gpg, capsule-plaintext.tar.gz, capsule-proof.json, file-staging-index.json,
 source-apply-proof.json, sql10-complete-proof.json and historical-record-proof.json.
 The supplied proof is compared byte-canonically; no caller membership map is trusted.
 """
 folder=Path(folder)
 root_stat=folder.lstat()
 if folder.is_symlink() or not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid!=os.geteuid() or stat.S_IMODE(root_stat.st_mode)!=0o700 or folder.resolve(strict=True)!=folder:
  raise Blocked('MEMBERSHIP_INPUT_DIRECTORY_PROTECTION')
 for parent_dir in (folder.parent,*folder.parent.parents):
  parent_stat=parent_dir.lstat()
  if (parent_dir.is_symlink() or not stat.S_ISDIR(parent_stat.st_mode) or
      parent_stat.st_uid not in {0,os.geteuid()} or parent_stat.st_mode&0o022):
   raise Blocked('MEMBERSHIP_INPUT_ANCESTRY_PROTECTION')
 def read(name,limit=32*1024*1024): return private_json(folder/name,limit)[0]
 pub=read('publisher-readback.json');native=read('native-overlay-restore.json')
 capsule=read('capsule-proof.json',1_000_000);index=read('file-staging-index.json')
 cap=folder/'capsule-ciphertext.gpg'
 verify_ciphertext_file(cap,capsule)
 parent=_pinned_json(DEFAULT_PARENT_MANIFEST,PARENT_MANIFEST_SHA)
 bindings=_pinned_json(DEFAULT_FULL_BINDINGS,FULL_BINDINGS_SHA)
 plan=_pinned_json(DEFAULT_PRIVATE_PLAN,PRIVATE240_PLAN_SHA)
 source_names=('source-apply-proof.json','sql10-complete-proof.json','historical-record-proof.json',
               'parent-selected-members.json','parent-durable-supplement-receipt.json','parent-durable-index.json',
               'native-state-actual-proof.json','redis-provider-proof-actual.json','redis-inner-manifest-actual.json',
               'redis-signed-latest-submember-actual.json','rustfs-provider-proof-actual.json',
               'rustfs-signed-outer-submember-proof-actual.json','rustfs-extracted-tree-index-actual.json')
 source_proofs={name:sha_file(folder/name) for name in source_names}
 if not proof or not isinstance(proof,dict): raise Blocked('MEMBERSHIP_PROOF_OBJECT')
 key=load_key(KEY_PATH)
 capsule['_proofFileSha256']=sha_file(folder/'capsule-proof.json');index['_fileSha256']=sha_file(folder/'file-staging-index.json')
 plain=folder/'capsule-plaintext.tar.gz';pst=plain.lstat()
 if plain.is_symlink() or not stat.S_ISREG(pst.st_mode) or pst.st_uid!=os.geteuid() or stat.S_IMODE(pst.st_mode)!=0o600 or pst.st_nlink!=1:
  raise Blocked('CAPSULE_PLAINTEXT_READBACK_FILE')
 source_apply=read('source-apply-proof.json');sql10=read('sql10-complete-proof.json');historical=read('historical-record-proof.json')
 selected_members,selected_members_sha=private_json(folder/'parent-selected-members.json')
 durable_doc,durable_receipt_sha=private_json(folder/'parent-durable-supplement-receipt.json')
 durable_index,durable_index_sha=private_json(folder/'parent-durable-index.json')
 provider_proofs={name:private_json(folder/name) for name in source_names[6:]}
 if selected_members_sha!=PARENT_SELECTED_MEMBERS_SHA or durable_receipt_sha!=DURABLE_SUPPLEMENT_RECEIPT_SHA or durable_index_sha!=DURABLE_INDEX_SHA:
  raise Blocked('PARENT_MEMBERSHIP_INPUT_PIN')
 if (source_apply.get('schema')!='platform.source-overlay-private-apply/v1' or source_apply.get('status')!='passed' or
     source_apply.get('metadataAppliedAndVerified') is not True or source_apply.get('sourceCount')!=57 or
     source_apply.get('baselineArchiveSha256')!=BASE_ARCHIVE or source_apply.get('productionModified') is not False):
  raise Blocked('SOURCE_APPLY_PROOF_NOT_VERIFIED')
 if (sql10.get('schema')!='platform.private-ten-database-rebuild/v2' or sql10.get('status')!='passed' or
     sql10.get('manifestId')!=PARENT_ID or sql10.get('manifestDigest')!=PARENT_DIGEST or
     sql10.get('receiptSha256')!=PARENT_RECEIPT or sql10.get('databaseCount')!=10 or sql10.get('productionModified') is not False):
  raise Blocked('SQL10_PROOF_NOT_VERIFIED')
 actual=assemble(pub,native,capsule,index,key,parent,bindings,plan,source_proofs,historical,plain,
                 selected_members,selected_members_sha,durable_doc,durable_index,durable_index_sha,provider_proofs)
 if canonical(actual)!=canonical(proof): raise Blocked('AUTHENTICATED_MEMBERSHIP_RECOMPUTE_DIFFERS')
 return {'status':'passed','schema':'platform.active87-authenticated-membership/v1',
         'manifestId':PARENT_ID,'manifestDigest':PARENT_DIGEST,
         'proofSha256':actual['proofSha256'],
         'membershipSha256':sha_bytes(canonical(actual['authenticatedMembership']))}
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for arg in ('publisher-readback','native-overlay-restore','capsule-ciphertext','capsule-plaintext','capsule-proof','file-staging-index','output'):p.add_argument('--'+arg,required=True,type=Path)
 p.add_argument('--key',type=Path,default=KEY_PATH);p.add_argument('--restore-proofs',type=Path)
 p.add_argument('--phase',choices=('bootstrap','membership'),default='membership');a=p.parse_args()
 try:
  publisher,_=private_json(a.publisher_readback);native,_=private_json(a.native_overlay_restore)
  proof,proof_sha=private_json(a.capsule_proof,1_000_000);index,index_sha=private_json(a.file_staging_index,16*1024*1024)
  cap=a.capsule_ciphertext
  verify_ciphertext_file(cap,proof)
  plaintext=a.capsule_plaintext;plainst=plaintext.lstat()
  if plaintext.is_symlink() or not stat.S_ISREG(plainst.st_mode) or plainst.st_uid!=os.geteuid() or stat.S_IMODE(plainst.st_mode)!=0o600 or plainst.st_nlink!=1:raise Blocked('CAPSULE_PLAINTEXT_READBACK_FILE')
  proof['_proofFileSha256']=proof_sha;index['_fileSha256']=index_sha
  parent=_pinned_json(DEFAULT_PARENT_MANIFEST,PARENT_MANIFEST_SHA)
  bindings=_pinned_json(DEFAULT_FULL_BINDINGS,FULL_BINDINGS_SHA)
  plan=_pinned_json(DEFAULT_PRIVATE_PLAN,PRIVATE240_PLAN_SHA)
  if a.phase=='bootstrap':
   point=assemble(publisher,native,proof,index,load_key(a.key),capsule_plaintext_path=plaintext)
   point['bootstrapForHistoricalVerification']=True
   point['proofSha256']=sha_bytes(canonical({k:v for k,v in point.items() if k!='proofSha256'}))
   out=Path(a.output);parent_dir=out.parent
   if out.exists() or out.is_symlink() or parent_dir.is_symlink() or not parent_dir.is_dir() or parent_dir.resolve()!=parent_dir:
    raise Blocked('OUTPUT_MUST_BE_NEW_AND_CANONICAL')
   temp=out.with_name(out.name+'.tmp');fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
   with os.fdopen(fd,'wb') as f:f.write(canonical(point)+b'\n');f.flush();os.fsync(f.fileno())
   os.replace(temp,out);dfd=os.open(parent_dir,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(dfd);os.close(dfd)
   print(json.dumps({'status':'passed','phase':'bootstrap','proofSha256':point['proofSha256'],
                     'manifestId':PARENT_ID,'offsiteVerified':True,'authenticatedMembership':False},sort_keys=True));return 0
  lineage=a.restore_proofs or a.publisher_readback.parent
  source_apply=private_json(lineage/'source-apply-proof.json')[0]
  sql10=private_json(lineage/'sql10-complete-proof.json')[0]
  historical=private_json(lineage/'historical-record-proof.json')[0]
  if (source_apply.get('schema')!='platform.source-overlay-private-apply/v1' or source_apply.get('status')!='passed' or
      source_apply.get('metadataAppliedAndVerified') is not True or source_apply.get('sourceCount')!=57 or
      source_apply.get('baselineArchiveSha256')!=BASE_ARCHIVE or source_apply.get('productionModified') is not False or
      sql10.get('schema')!='platform.private-ten-database-rebuild/v2' or sql10.get('status')!='passed' or
      sql10.get('manifestId')!=PARENT_ID or sql10.get('manifestDigest')!=PARENT_DIGEST or sql10.get('receiptSha256')!=PARENT_RECEIPT or
      sql10.get('databaseCount')!=10 or sql10.get('productionModified') is not False):
   raise Blocked('LOCAL_RESTORE_PROOF_GATES')
  source_names=('source-apply-proof.json','sql10-complete-proof.json','historical-record-proof.json',
                'parent-selected-members.json','parent-durable-supplement-receipt.json','parent-durable-index.json',
                'native-state-actual-proof.json','redis-provider-proof-actual.json','redis-inner-manifest-actual.json',
                'redis-signed-latest-submember-actual.json','rustfs-provider-proof-actual.json',
                'rustfs-signed-outer-submember-proof-actual.json','rustfs-extracted-tree-index-actual.json')
  source_proofs={name:sha_file(lineage/name) for name in source_names}
  selected_members,selected_members_sha=private_json(lineage/'parent-selected-members.json')
  durable_doc,durable_receipt_sha=private_json(lineage/'parent-durable-supplement-receipt.json')
  durable_index,durable_index_sha=private_json(lineage/'parent-durable-index.json')
  provider_proofs={name:private_json(lineage/name) for name in source_names[6:]}
  if selected_members_sha!=PARENT_SELECTED_MEMBERS_SHA or durable_receipt_sha!=DURABLE_SUPPLEMENT_RECEIPT_SHA or durable_index_sha!=DURABLE_INDEX_SHA:
   raise Blocked('PARENT_MEMBERSHIP_INPUT_PIN')
  point=assemble(publisher,native,proof,index,load_key(a.key),parent,bindings,plan,source_proofs,historical,plaintext,
                 selected_members,selected_members_sha,durable_doc,durable_index,durable_index_sha,provider_proofs)
  out=Path(a.output);parent=out.parent
  if out.exists() or out.is_symlink() or parent.is_symlink() or not parent.is_dir() or parent.resolve()!=parent:raise Blocked('OUTPUT_MUST_BE_NEW_AND_CANONICAL')
  temp=out.with_name(out.name+'.tmp');fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as f:f.write(canonical(point)+b'\n');f.flush();os.fsync(f.fileno())
  os.replace(temp,out);dfd=os.open(parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(dfd);os.close(dfd)
  print(json.dumps({'status':'passed','proofSha256':point['proofSha256'],'manifestId':PARENT_ID,'offsiteVerified':True},sort_keys=True));return 0
 except (Blocked,OSError,ValueError,KeyError,TypeError) as e:
  print(json.dumps({'status':'blocked','reason':str(e)},sort_keys=True),file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
