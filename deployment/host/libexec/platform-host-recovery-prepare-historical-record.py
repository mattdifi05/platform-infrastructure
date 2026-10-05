#!/usr/bin/python3
"""Build/verify the immutable G15 recovery record before the 40* live-tree capture.

Reads only fixed, hash-pinned root-private artifacts. The output is a separate
historical record, never the current cycle's 9-tree capture. It does not decrypt,
sign, upload, prune, or alter any source.
"""
from __future__ import annotations
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile

PARENT_ID='manifest-scheduled-platform-20260929-182357-1f9954'
PARENT_DIGEST='baf72a7c4ff5d2266b71afe4865ebffeb8be6c363dfc31c12f3a865389009b2c'
PARENT_RECEIPT='1868a512b5a47fe9cc4808622dfb4707d8fe988b0a1d523f801c12ad4c419030'
BASE_ARCHIVE='77de6d262d269db484aa48fbe63ca064a151a9c5ecc081374bf9be4d3e034987'
OUT=Path('/var/lib/platform-host-recovery/recovery-records')/PARENT_ID
MAX_ARCHIVE=600_000_000
# Member names and source locations are fixed; expected digests come from the
# verified historical capture proofs and never from a caller-provided manifest.
SOURCES={
  'historical-extra-trees/current.tar':('/var/lib/platform-host-recovery/extra-mounted-trees/current.tar',97_607_680,'6ed00c6e14abf23cb7d84ae9e4453206d5e33c8aaee7b37cb3485b20995ff8e3'),
 'historical-extra-trees/index.json':('/var/lib/platform-host-recovery/extra-mounted-trees/index.json',2_199_258,'3f032c289a77460aaaa7bfa9613a581e7d448cb6970b132343f0a19ae15ab7ce'),
 'historical-extra-trees/proof.json':('/var/lib/platform-host-recovery/extra-mounted-trees/proof.json',697,'c03827eb9e24a101218185cd2f4052f4130760ba659d251514d60d918b3e4a14'),
 'extended-capsule/host-recovery-current.tar.gz.gpg':('/var/lib/platform-extended-recovery-capsule-20260930/input/host-recovery-current.tar.gz.gpg',45_074_060,'9fa5cf40056cb166cc2e3d5103c8bd0dc3548c4554b9e51f10976e887af23360'),
 'extended-capsule/host-recovery-proof.json':('/var/lib/platform-extended-recovery-capsule-20260930/input/host-recovery-proof.json',750,'b166bae6283f3bd8a3271d8d556926b44828d08553c36ede5720dd726c06f194'),
 'extended-capsule/prepared-proof.json':('/var/lib/platform-extended-recovery-capsule-20260930/prepared-proof.json',1_196,'4909ca488290c5fdc8e8885b83aee2b1bdd3df0892be890fb9349ba914987869'),
 'extended-capsule/file-staging-proof.json':('/var/lib/platform-extended-recovery-capsule-20260930/file-staging-proof.json',1_302_417,'0176a8b4a6dee70deb82b3807326e3ab0602fdfaeed237874c221afd00cfcaf3'),
 'extended-capsule/capsule.tar.gz':('/var/lib/platform-extended-recovery-capsule-20260930/capsule.tar.gz',45_073_972,'bc356f5e6e7ab1dbcf1581c445bff41b3f5051004931672f053f271ebccb43f0'),
 'extended-capsule/extra-databases/control_center.dump':('/var/lib/platform-extended-recovery-capsule-20260930/extra-databases/control_center.dump',16_714_093,'f59b6803635b9232032a9f078bba472a18fa9797ceb28346c6c3da5a29b6e44a'),
 'extended-capsule/extra-databases/phpmyadmin.sql':('/var/lib/platform-extended-recovery-capsule-20260930/extra-databases/phpmyadmin.sql',20_335,'69dd358680066c3765a5ed05b83774da81c60d327ecd164e4de605be60df111a'),
 'extended-capsule/extra-databases/capture-proof.json':('/var/lib/platform-extended-recovery-capsule-20260930/extra-databases/capture-proof.json',1_645,'b697f9765daf54ea183d5114d261c244f41bd52d5e562618d4842c76e1f62218'),
 # Bind the historical record to the immutable copy inside the already sealed
 # capsule. The host's global `current.tar` is a rotating capture output and is
 # not a stable source for this one-off historical record.
 'extended-capsule/extra-databases/current.tar':('/var/lib/platform-extended-recovery-capsule-20260930/files/host/var/lib/platform-host-recovery/extra-database-exports/current.tar',16_742_400,'e282ff9de94559703906bfd31a74a3759a6950a0900a97eba94e6c5baa612fe6'),
 'source-metadata/metadata-records.ndjson.gz':('/var/lib/platform-completeness-candidate-20260930/source-metadata-prescan-v3/metadata-records.ndjson.gz',35_341_580,'951d2ffdd3eb56e44245bee03b7e2eafdd10d0b4758db4fc19dfd9434fe0150d'),
 'source-metadata/prescan-proof.json':('/var/lib/platform-completeness-candidate-20260930/source-metadata-prescan-v3/prescan-proof.json',18_351,'5ce7fc3cf7603262a2fa51e8f057e73de6b8bae247fe3deb56deaa7f1b710972'),
 'source-metadata/expected-sources.json':('/var/lib/platform-completeness-candidate-20260930/readonly-prescan-code-v3/expected-sources.json',8_600,'7ca377a9e7e724c4aa475d2fda8f75402c4836113dd83af405c0d597732d3605'),
 'source-metadata/expired-cache-descriptor.json':('/var/lib/platform-completeness-candidate-20260930/readonly-prescan-code-v3/stream-expired-cache-descriptor-actual.json',3_924,'31a788278a35f189770996f4c224e1c67f9a7bb3223447e90ac7ae85354665f2'),
 'source-metadata/private-apply-proof.json':('/var/lib/platform-isolated-stack-20260930/recovered-inputs/sources-metadata-v3/apply-proof.json',8_133,'5da76d15fc06b71ef23ed339a1d86a61f02acc000f40b30c5b9151213ea18c4d'),
}
ARTIFACT_MEMBER_MAP={
 'oldExtraTreesArchiveSha256':'historical-extra-trees/current.tar',
 'oldExtraTreesIndexSha256':'historical-extra-trees/index.json',
 'oldExtraTreesProofSha256':'historical-extra-trees/proof.json',
 'extendedCapsuleSha256':'extended-capsule/host-recovery-current.tar.gz.gpg',
 'extendedCapsuleProofSha256':'extended-capsule/host-recovery-proof.json',
 'extendedCapsulePreparedProofSha256':'extended-capsule/prepared-proof.json',
 'extendedCapsuleFileStagingProofSha256':'extended-capsule/file-staging-proof.json',
 'extendedCapsulePlaintextSha256':'extended-capsule/capsule.tar.gz',
 'extraControlCenterDumpSha256':'extended-capsule/extra-databases/control_center.dump',
 'extraPhpmyadminDumpSha256':'extended-capsule/extra-databases/phpmyadmin.sql',
 'extraDatabaseCaptureProofSha256':'extended-capsule/extra-databases/capture-proof.json',
 'extraDatabaseBundleSha256':'extended-capsule/extra-databases/current.tar',
 'sourceMetadataCompressedSha256':'source-metadata/metadata-records.ndjson.gz',
 'sourceMetadataPrescanProofSha256':'source-metadata/prescan-proof.json',
 'sourceMetadataApplyProofSha256':'source-metadata/private-apply-proof.json',
 'expectedSourcesSha256':'source-metadata/expected-sources.json',
 'expiredCacheDescriptorSha256':'source-metadata/expired-cache-descriptor.json',
}
class Blocked(RuntimeError): pass
def expected_owner(): return 0 if os.geteuid()==0 else os.geteuid()
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
def hash_file(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def protected_path(path):
 p=Path(path)
 if not p.is_absolute() or p.resolve(strict=True)!=p:raise Blocked('INPUT_PATH_NOT_CANONICAL')
 for parent in (p.parent,*p.parent.parents):
  st=parent.lstat()
  if not stat.S_ISDIR(st.st_mode) or parent.is_symlink() or st.st_uid not in ({0,expected_owner()}) or st.st_mode&0o022:raise Blocked('INPUT_ANCESTOR_NOT_PROTECTED')
 st=p.lstat()
 if p.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=expected_owner() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:raise Blocked('INPUT_FILE_NOT_ROOT_PRIVATE')
 return st
def validate_sources(sources=SOURCES):
 rows=[]
 for name,(source,expected_bytes,expected_sha) in sorted(sources.items()):
  path=Path(source); before=protected_path(path)
  if expected_bytes is not None and before.st_size!=expected_bytes:raise Blocked('INPUT_SIZE_DRIFT:'+name)
  if not 0<before.st_size<=MAX_ARCHIVE:raise Blocked('INPUT_SIZE_BOUND:'+name)
  digest=hash_file(path); after=path.lstat()
  if digest!=expected_sha or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise Blocked('INPUT_DIGEST_OR_DRIFT:'+name)
  rows.append({'name':name,'bytes':before.st_size,'sha256':digest})
 if sum(x['bytes'] for x in rows)>MAX_ARCHIVE:raise Blocked('RECORD_SIZE_BOUND')
 return rows
def expected_rows(sources=SOURCES):
 rows=[]
 for name,(_source,expected_bytes,expected_sha) in sorted(sources.items()):
  if expected_bytes is None:raise Blocked('PINNED_MEMBER_SIZE_MISSING:'+name)
  rows.append({'name':name,'bytes':expected_bytes,'sha256':expected_sha})
 return rows
def make_index(rows):
 return {'schema':'platform.historical-recovery-record-index/v1','status':'historical-inputs-verified','historicalParent':{'manifestId':PARENT_ID,'manifestDigest':PARENT_DIGEST,'receiptSha256':PARENT_RECEIPT,'sourceArchiveSha256':BASE_ARCHIVE},'artifactSha256':{key:next(r['sha256'] for r in rows if r['name']==member) for key,member in ARTIFACT_MEMBER_MAP.items()},'artifactBytes':{key:next(r['bytes'] for r in rows if r['name']==member) for key,member in ARTIFACT_MEMBER_MAP.items()},'members':rows,'memberCount':len(rows),'productionModified':False,'offsiteVerified':False,'fullyRecoverable':False}
def verify_record(directory,rows=None,sources=SOURCES):
 d=Path(directory);st=d.lstat()
 if d.is_symlink() or not stat.S_ISDIR(st.st_mode) or st.st_uid!=expected_owner() or stat.S_IMODE(st.st_mode)!=0o700:raise Blocked('RECORD_DIRECTORY_NOT_PRIVATE')
 if sorted(p.name for p in d.iterdir())!=['current.tar','index.json','proof.json']:raise Blocked('RECORD_MEMBER_SET')
 rows=rows if rows is not None else expected_rows_for_verify(sources)
 index_bytes=canonical(make_index(rows));idx=d/'index.json';proof=d/'proof.json';archive=d/'current.tar'
 for path in (idx,proof,archive):
  info=path.lstat()
  if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=expected_owner() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise Blocked('RECORD_MEMBER_PROTECTION')
 if idx.read_bytes()!=index_bytes:raise Blocked('RECORD_INDEX_DIFFERS')
 proof_obj=json.loads(proof.read_bytes())
 if proof_obj.get('schema')!='platform.historical-recovery-record-proof/v1' or proof_obj.get('historicalParent')!=make_index(rows)['historicalParent'] or proof_obj.get('archiveSha256')!=hash_file(archive) or proof_obj.get('archiveBytes')!=archive.stat().st_size or proof_obj.get('indexSha256')!=hash_file(idx):raise Blocked('RECORD_PROOF_INVALID')
 seen={}
 try:
  with tarfile.open(archive,'r:') as tar:
   for m in tar:
    if not m.isfile() or m.name in seen or m.name.startswith('/') or '..' in Path(m.name).parts or m.size>MAX_ARCHIVE:raise Blocked('RECORD_ARCHIVE_MEMBER_INVALID')
    f=tar.extractfile(m)
    if f is None:raise Blocked('RECORD_ARCHIVE_MEMBER_UNREADABLE')
    h=hashlib.sha256();count=0
    for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk);count+=len(chunk)
    seen[m.name]={'name':m.name,'bytes':count,'sha256':h.hexdigest()}
 except (OSError,tarfile.TarError): raise Blocked('RECORD_ARCHIVE_INVALID') from None
 if [seen[n] for n in sorted(seen)]!=rows:raise Blocked('RECORD_ARCHIVE_CONTENT_DIFFERS')
 return {'status':'passed','recordPath':str(d),'archiveSha256':hash_file(archive),'archiveBytes':archive.stat().st_size,'indexSha256':hash_file(idx),'proofSha256':hash_file(proof),'memberCount':len(seen),'historicalParentManifestId':PARENT_ID,'productionModified':False,'offsiteVerified':False}
def expected_rows_for_verify(sources=SOURCES):
 return expected_rows(sources)
def prepare(out=OUT,sources=SOURCES,allow_nonroot_test=False):
 if os.geteuid()!=0 and not allow_nonroot_test:raise Blocked('ROOT_REQUIRED')
 if Path(out).exists() or Path(out).is_symlink():return verify_record(out,expected_rows(sources),sources)
 rows=validate_sources(sources)
 if rows!=expected_rows(sources):raise Blocked('CAPTURED_INPUTS_DIFF_FROM_PINNED_RECORD')
 parent=Path(out).parent
 if not parent.exists():parent.mkdir(mode=0o700)
 pst=parent.lstat()
 if parent.is_symlink() or not stat.S_ISDIR(pst.st_mode) or pst.st_uid!=expected_owner() or pst.st_mode&0o077:raise Blocked('RECORD_PARENT_NOT_PRIVATE')
 if Path(out).exists() or Path(out).is_symlink():return verify_record(out,rows,sources)
 stage=Path(tempfile.mkdtemp(prefix='.historical-record-',dir=parent));os.chmod(stage,0o700)
 try:
  archive=stage/'current.tar';idx=stage/'index.json';proof=stage/'proof.json'
  with tarfile.open(archive,'w',format=tarfile.PAX_FORMAT) as tar:
   for row in rows:
    source=dict(sources)[row['name']][0];info=protected_path(source);fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
    try:
     opened=os.fstat(fd)
     if (opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns)!=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns):raise Blocked('INPUT_CHANGED_BEFORE_ARCHIVE')
     class Reader:
      def __init__(self,stream):self.stream=stream;self.h=hashlib.sha256();self.count=0
      def read(self,n=-1):
       b=self.stream.read(n);self.h.update(b);self.count+=len(b);return b
     stream=Reader(os.fdopen(fd,'rb',closefd=False));member=tarfile.TarInfo(row['name']);member.size=row['bytes'];member.mode=0o600;member.uid=0;member.gid=0;member.uname='';member.gname='';member.mtime=0
     tar.addfile(member,stream)
     after=os.fstat(fd)
     if stream.count!=row['bytes'] or stream.h.hexdigest()!=row['sha256'] or (opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise Blocked('INPUT_CHANGED_DURING_ARCHIVE')
    finally:os.close(fd)
  os.chmod(archive,0o600)
  with archive.open('rb') as f:os.fsync(f.fileno())
  if archive.stat().st_size>MAX_ARCHIVE:raise Blocked('RECORD_ARCHIVE_SIZE_BOUND')
  index_bytes=canonical(make_index(rows));idx.write_bytes(index_bytes);os.chmod(idx,0o600)
  with idx.open('rb') as f:os.fsync(f.fileno())
  proof_bytes=canonical({'schema':'platform.historical-recovery-record-proof/v1','historicalParent':make_index(rows)['historicalParent'],'archiveBytes':archive.stat().st_size,'archiveSha256':hash_file(archive),'indexBytes':len(index_bytes),'indexSha256':hashlib.sha256(index_bytes).hexdigest(),'sourceInputsRevalidated':True,'productionModified':False,'offsiteVerified':False,'fullyRecoverable':False})
  proof.write_bytes(proof_bytes);os.chmod(proof,0o600)
  with proof.open('rb') as f:os.fsync(f.fileno())
  d=os.open(stage,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
  try:os.rename(stage,out)
  except FileExistsError:return verify_record(out,rows,sources)
  d=os.open(parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
  return verify_record(out,rows,sources)
 finally:
  if stage.exists():
   import shutil;shutil.rmtree(stage)
def main():
 if os.geteuid()!=0:raise Blocked('ROOT_REQUIRED')
 result=prepare();print(json.dumps(result,sort_keys=True,separators=(',',':')))
if __name__=='__main__':
 try:main()
 except Exception as error:
  print(json.dumps({'status':'blocked','reason':str(error) if isinstance(error,Blocked) else 'HISTORICAL_RECORD_PREPARATION_FAILED','errorType':type(error).__name__},sort_keys=True,separators=(',',':')));raise SystemExit(1)
