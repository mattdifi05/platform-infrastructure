#!/usr/bin/python3
"""Verify the 9-tree bundle from the same encrypted host capsule, privately."""
import hashlib, hmac, importlib.util, json, os, re, shutil, stat, subprocess, tarfile, tempfile
from datetime import datetime, timezone
from pathlib import Path

CAPTURE_SHA='336da4bb00e7f8e80b7ca7462d19b395025961623f0968e9241af00aa34c0fbe'
RESTORE_SHA='25cf2e46a0165494cb0e1f50dd74d4d34564a0fdfabe15a98a3f9083777ec47a'
CAPTURE_NAME='platform-host-recovery-extra-mounted-trees.py'
RESTORE_NAME='platform-host-recovery-extra-mounted-trees-restore.py'
HISTORICAL_PARENT='manifest-scheduled-platform-20260929-182357-1f9954'
HISTORICAL_ROOT='/var/lib/platform-host-recovery/recovery-records/'+HISTORICAL_PARENT
HISTORICAL_VERIFY_NAME='platform-host-recovery-verify-historical-record.py'
HISTORICAL_VERIFY_SHA='800eca18ff492250b948bc6997c9111016741052f26cadac289b33e1ea8c60c9'
HISTORICAL_MEMBERS={
 'host'+HISTORICAL_ROOT+'/current.tar':('current.tar',600_000_000),
 'host'+HISTORICAL_ROOT+'/index.json':('index.json',16*1024*1024),
 'host'+HISTORICAL_ROOT+'/proof.json':('proof.json',1_000_000),
}
GPG_KEY_PATH=Path('/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase')
GPG_KEY_UID=1000
GPG_KEY_GID=1000
EXTENDED_REGULAR_FILES=4_895
EXTENDED_DIRECTORY_COUNT=504
EXTENDED_SYMLINK_COUNT=170
EXTENDED_ENTRY_COUNT=5_569
FILE_INDEX_SHA256='0176a8b4a6dee70deb82b3807326e3ab0602fdfaeed237874c221afd00cfcaf3'
HISTORICAL_PARENT_DIGEST='baf72a7c4ff5d2266b71afe4865ebffeb8be6c363dfc31c12f3a865389009b2c'
HISTORICAL_BASE_ARCHIVE='77de6d262d269db484aa48fbe63ca064a151a9c5ecc081374bf9be4d3e034987'
LINUX_LITERAL_BACKSLASH_MEMBERS={
 'host/etc/systemd/system/snap-canonical\\x2dlivepatch-414.mount',
 'host/etc/systemd/system/multi-user.target.wants/snap-canonical\\x2dlivepatch-414.mount',
 'host/etc/systemd/system/snapd.mounts.target.wants/snap-canonical\\x2dlivepatch-414.mount',
}
MEMBERS={
 'host/var/lib/platform-host-recovery/extra-mounted-trees/current.tar':('current.tar',192*1024*1024),
 'host/var/lib/platform-host-recovery/extra-mounted-trees/index.json':('index.json',32*1024*1024),
 'host/var/lib/platform-host-recovery/extra-mounted-trees/capture-proof.json':('capture-proof.json',1_000_000),
}
class Blocked(RuntimeError):pass
def digest(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def parse_time(x):
 d=datetime.fromisoformat(x.replace('Z','+00:00'))
 if d.tzinfo is None:raise Blocked('NAIVE_TIME')
 return d.astimezone(timezone.utc)
def module(path,name,expected):
 p=Path(path);st=p.lstat()
 if p.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o022 or st.st_nlink!=1 or digest(p)!=expected:raise Blocked('TRANSITIVE_HELPER_PIN')
 spec=importlib.util.spec_from_file_location(name,p);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
def private_file(path,limit):
 p=Path(path);st=p.lstat()
 if p.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1 or st.st_size>limit:raise Blocked('BUNDLE_FILE_PROTECTION')
 return st
def write_outer_member(archive,member,target,limit,expected=None):
 if not member.isfile() or not 0<member.size<=limit:raise Blocked('OUTER_MEMBER_METADATA')
 if expected is not None and (set(expected)!={'sha256','bytes','uid','gid','mode'} or (member.size,member.uid,member.gid,member.mode)!=(expected['bytes'],expected['uid'],expected['gid'],expected['mode'])):raise Blocked('OUTER_MEMBER_INDEX_METADATA')
 src=archive.extractfile(member)
 if src is None:raise Blocked('OUTER_MEMBER_UNREADABLE')
 h=hashlib.sha256();count=0
 fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as out:
  for b in iter(lambda:src.read(1024*1024),b''):
   count+=len(b)
   if count>member.size or count>limit:raise Blocked('OUTER_MEMBER_SIZE')
   h.update(b);out.write(b)
  out.flush();os.fsync(out.fileno())
 if count!=member.size:raise Blocked('OUTER_MEMBER_SIZE')
 result={'bytes':count,'sha256':h.hexdigest()}
 if expected is not None and (expected.get('bytes')!=count or expected.get('sha256')!=result['sha256']):raise Blocked('OUTER_MEMBER_INDEX_DIGEST')
 return result

def validate_file_staging_index(index, expected_sha=None):
 if (not isinstance(index,dict) or index.get('schema')!='platform.extended-capsule-file-staging/v1' or
     index.get('noLinksFollowed') is not True or type(index.get('entries')) is not int or
     not 0<index['entries']<=30_000 or type(index.get('regularFiles')) is not int or
     not 0<=index['regularFiles']<=30_000 or type(index.get('regularBytes')) is not int or
     not 0<=index['regularBytes']<=2_000_000_000):raise Blocked('FILE_STAGING_INDEX_INVALID')
 files=index.get('files');links=index.get('linksNotMaterialized')
 if not isinstance(files,dict) or len(files)!=index['regularFiles'] or not isinstance(links,list) or len(links)>30_000:raise Blocked('FILE_STAGING_INDEX_SET_INVALID')
 names=set()
 for name,row in files.items():
  if (not isinstance(name,str) or name.startswith('/') or ('\\' in name and name not in LINUX_LITERAL_BACKSLASH_MEMBERS) or '\x00' in name or '..' in Path(name).parts or
      not isinstance(row,dict) or set(row)!={'sha256','bytes','uid','gid','mode'} or type(row.get('bytes')) is not int or
      row['bytes']<0 or not re.fullmatch('[a-f0-9]{64}',str(row.get('sha256',''))) or
      any(type(row.get(k)) is not int or row[k]<0 for k in ('uid','gid','mode'))):raise Blocked('FILE_STAGING_FILE_ROW_INVALID')
  names.add(name)
 link_names=set()
 for row in links:
  if not isinstance(row,dict) or set(row)!={'name','type'} or row.get('type')!='symlink':raise Blocked('FILE_STAGING_LINK_ROW_INVALID')
  name=row.get('name')
  if (not isinstance(name,str) or name.startswith('/') or ('\\' in name and name not in LINUX_LITERAL_BACKSLASH_MEMBERS) or '\x00' in name or '..' in Path(name).parts or
      not name or name in names or name in link_names):raise Blocked('FILE_STAGING_LINK_NAME_INVALID')
  link_names.add(name)
 if expected_sha is not None and len(expected_sha)!=64:raise Blocked('FILE_STAGING_INDEX_EXPECTED_SHA_INVALID')
 return files,link_names

def load_file_staging_index(path, expected_sha):
 p=Path(path);st=p.lstat()
 if p.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1 or not 0<st.st_size<=16*1024*1024:raise Blocked('FILE_STAGING_INDEX_PROTECTION')
 if digest(p)!=expected_sha:raise Blocked('FILE_STAGING_INDEX_SHA')
 index=json.loads(p.read_bytes());files,links=validate_file_staging_index(index,expected_sha)
 return index,files,links

def validate_gpg_key_metadata(st, path):
 p=Path(path)
 if (p!=GPG_KEY_PATH or p.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=GPG_KEY_UID or
     st.st_gid!=GPG_KEY_GID or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1):raise Blocked('GPG_KEY_PROTECTION')
 cur=Path('/')
 for component in p.parts[1:-1]:
  cur=cur/component;part=cur.lstat()
  if stat.S_ISLNK(part.st_mode) or not stat.S_ISDIR(part.st_mode):raise Blocked('GPG_KEY_ANCESTOR_ALIAS')
 if p.resolve(strict=True)!=p:raise Blocked('GPG_KEY_ALIAS')

def open_gpg_key(path):
 p=Path(path)
 try:fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 except OSError:raise Blocked('GPG_KEY_OPEN') from None
 try:
  before=os.fstat(fd);validate_gpg_key_metadata(before,p)
  by_path=p.lstat()
  if (before.st_dev,before.st_ino,before.st_uid,before.st_gid,before.st_mode,before.st_nlink)!=(by_path.st_dev,by_path.st_ino,by_path.st_uid,by_path.st_gid,by_path.st_mode,by_path.st_nlink):raise Blocked('GPG_KEY_IDENTITY_RACE')
  chunks=[];total=0
  while True:
   block=os.read(fd,4096)
   if not block:break
   total+=len(block)
   if total>65_536:raise Blocked('GPG_KEY_SIZE_BOUND')
   chunks.append(block)
  after=os.fstat(fd)
  if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise Blocked('GPG_KEY_CHANGED_DURING_READ')
  os.lseek(fd,0,os.SEEK_SET)
  return fd,b''.join(chunks)
 except BaseException:
  os.close(fd);raise
def _signed_document(point,name,domain,key):
 doc=point.get(name)
 if not isinstance(doc,dict) or set(doc)!={'payload','hmacSha256'} or not isinstance(doc.get('payload'),dict):raise Blocked('SIGNED_POINT_DOCUMENT_REQUIRED:'+name)
 payload=doc['payload'];raw=json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
 mac=hmac.new(key,domain+raw,hashlib.sha256).hexdigest()
 if not hmac.compare_digest(mac,str(doc['hmacSha256'])):raise Blocked('SIGNED_POINT_DOCUMENT_HMAC:'+name)
 return payload,hashlib.sha256(json.dumps(doc,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def _verify_signed_point_documents(point,key):
 if not isinstance(key,bytes) or not key:raise Blocked('SIGNING_KEY_UNAVAILABLE')
 def verify_doc(name,domain):
  return _signed_document(point,name,domain,key)
 base,receipt_sha=verify_doc('receiptDocument',b'platform-ftps-receipt-v1\n')
 base_completeness,base_completeness_sha=verify_doc('baseCompletenessDocument',b'platform-ftps-supplement-v1\n')
 supplement,supplement_sha=verify_doc('overlayReceiptDocument',b'platform-ftps-supplement-v1\n')
 complete_schema=base_completeness.get('schema')
 base_files=base_completeness.get('files')
 full_rows=[x for x in base_files if isinstance(x,dict) and x.get('name')=='full-runtime.tar.gz'] if isinstance(base_files,list) else []
 parts=base_completeness.get('parts')
 if (complete_schema not in {'platform.ftps-point-completeness/v2','platform.ftps-point-completeness/v3'} or
     not isinstance(base_completeness.get('knownGaps'),list) or not base_completeness['knownGaps'] or
     not isinstance(parts,list) or not 1<=len(parts)<=70 or len(full_rows)!=1 or
     full_rows[0].get('bytes')!=14_123_697_104 or full_rows[0].get('sha256')!=HISTORICAL_BASE_ARCHIVE):
  raise Blocked('G15_COMPLETENESS_BINDING')
 if complete_schema=='platform.ftps-point-completeness/v3':
  pf=base_completeness.get('archivePreflight',{})
  if (pf.get('schema')!='platform.completeness-preflight/v1' or pf.get('verifiedBeforeUpload') is not True or
      pf.get('gpgExitCode')!=0 or pf.get('tarInputSha256')!=HISTORICAL_BASE_ARCHIVE or pf.get('tarInputBytes')!=14_123_697_104):
   raise Blocked('G15_COMPLETENESS_PREFLIGHT_BINDING')
 for i,part in enumerate(parts):
  if (not isinstance(part,dict) or set(part)!={'name','bytes','sha256'} or
      part.get('name')!=base_completeness.get('ciphertext')+'.part'+str(i).zfill(3) or
      type(part.get('bytes')) is not int or not 0<part['bytes']<=1_000_000_000 or
      not re.fullmatch('[a-f0-9]{64}',str(part.get('sha256','')))):
   raise Blocked('G15_COMPLETENESS_PART_BINDING')
 if sum(x['bytes'] for x in parts)!=base_completeness.get('encryptedBytes'):
  raise Blocked('G15_COMPLETENESS_PART_TOTAL')
 g16_fields={"schema","status","kind","parentManifestId","parentManifestDigest","parentReceiptSha256","parentEncryptedSha256","backupAt","ciphertext","encryptedBytes","encryptedSha256","parts","verifiedAt","fullyRecoverable","knownGaps","baseCompletenessCiphertext","baseCompletenessEncryptedSha256","baseCompletenessReceiptSha256","baseArchiveSha256","baseArchiveBytes","overlayPackageSha256","overlayReceiptSha256","sourceMapSha256","metadataIndexSha256","metadataIndexRawSha256","metadataIndexCompressedBytes","metadataIndexRawBytes","metadataRecordCount","capsuleSha256","capsuleProofSha256","files"}
 g16_v4_fields=g16_fields|{"mountedConfigCapture"}
 if set(supplement) not in (g16_fields,g16_v4_fields):raise Blocked('G16_OVERLAY_FIELD_SET')
 is_v4=supplement.get('schema')=='platform.ftps-source-metadata-overlay/v4'
 if is_v4 != (set(supplement)==g16_v4_fields):raise Blocked('G16_OVERLAY_FIELD_SET')
 if ((is_v4 and supplement.get('kind')!='source-metadata-overlay-v4') or
     (not is_v4 and (supplement.get('schema')!='platform.ftps-source-metadata-overlay/v3' or
                     supplement.get('kind')!='source-metadata-overlay-v3'))):
  raise Blocked('G16_OVERLAY_FIELD_SET')
 g16_parts=supplement.get('parts')
 if not isinstance(g16_parts,list) or not 1<=len(g16_parts)<=70:raise Blocked('G16_OVERLAY_PARTS')
 for i,part in enumerate(g16_parts):
  if (not isinstance(part,dict) or set(part)!={'name','bytes','sha256'} or
      part.get('name')!=supplement.get('ciphertext')+'.part'+str(i).zfill(3) or
      type(part.get('bytes')) is not int or not 0<part['bytes']<=250_000_000 or
      not re.fullmatch('[a-f0-9]{64}',str(part.get('sha256','')))):
   raise Blocked('G16_OVERLAY_PART_BINDING')
 if sum(x['bytes'] for x in g16_parts)!=supplement.get('encryptedBytes'):
  raise Blocked('G16_OVERLAY_PART_TOTAL')
 if is_v4:
  files=supplement.get('files'); config=supplement.get('mountedConfigCapture')
  expected_names={'receipt.json','metadata/records.ndjson.gz','host-capsule/current.gpg','mounted-config/records.json'}
  if (supplement.get('kind')!='source-metadata-overlay-v4' or not isinstance(files,list) or len(files)!=4 or
      {x.get('name') for x in files if isinstance(x,dict)}!=expected_names or
      any(not isinstance(x,dict) or set(x)!={'name','bytes','sha256'} or type(x.get('bytes')) is not int or
          x['bytes']<0 or not re.fullmatch('[a-f0-9]{64}',str(x.get('sha256',''))) for x in files) or
      not isinstance(config,dict) or set(config)!={'member','bytes','sha256','cycleId','catalogSha256','planSha256','sourceCount','recordCount','providerCounts'} or
      config.get('member')!='mounted-config/records.json' or config.get('sourceCount')!=89 or
      config.get('catalogSha256')!='f5cea1410282bcf5df8b722b11b7e1ccb67cc497c5fc401bab549152b5b52e69' or
      config.get('planSha256')!='c6f09fd00d7f8a7e1dc8794e214dfec1f0bf48f663fec2b0f26b8575b34d4c29' or
      config.get('providerCounts')!={'parent-capsule-exact-binding':76,'fresh-capsule-regular-file':8,'authenticated-students-secret-file':5} or
      type(config.get('bytes')) is not int or config['bytes']<=0 or type(config.get('recordCount')) is not int or
      config['recordCount']<89 or not re.fullmatch('[a-f0-9]{64}',str(config.get('sha256',''))) or
      not isinstance(config.get('cycleId'),str) or not config['cycleId']):
   raise Blocked('G16_V5_MOUNTED_CONFIG_BINDING')
  row=next((x for x in files if x.get('name')=='mounted-config/records.json'),None)
  if row!={'name':config['member'],'bytes':config['bytes'],'sha256':config['sha256']}:
   raise Blocked('G16_V5_MOUNTED_CONFIG_BINDING')
 if (base.get('manifestId')!=HISTORICAL_PARENT or base.get('manifestDigest')!=HISTORICAL_PARENT_DIGEST or
     base.get('encryptedSha256')!=point.get('sourceArchiveSha256') or base.get('bundle')!='backup-'+str(base.get('manifestId'))+'.tar.gpg' or
     base.get('manifestId')!=point.get('manifestId') or base.get('manifestDigest')!=point.get('manifestDigest') or
     base_completeness.get('kind')!='runtime-completeness-material' or
     base_completeness.get('parentManifestId')!=base.get('manifestId') or
     base_completeness.get('parentManifestDigest')!=base.get('manifestDigest') or
     base_completeness.get('parentReceiptSha256')!=receipt_sha or
     base_completeness.get('parentEncryptedSha256')!=base.get('encryptedSha256') or
     supplement.get('schema') not in {'platform.ftps-source-metadata-overlay/v3','platform.ftps-source-metadata-overlay/v4'} or
     supplement.get('kind') not in {'source-metadata-overlay-v3','source-metadata-overlay-v4'} or supplement.get('status')!='passed' or
     supplement.get('parentManifestId')!=base.get('manifestId') or supplement.get('parentManifestDigest')!=base.get('manifestDigest') or
     supplement.get('parentReceiptSha256')!=receipt_sha or supplement.get('parentEncryptedSha256')!=base.get('encryptedSha256') or
     supplement.get('baseCompletenessCiphertext')!=base_completeness.get('ciphertext') or
     supplement.get('baseCompletenessEncryptedSha256')!=base_completeness.get('encryptedSha256') or
     supplement.get('baseCompletenessReceiptSha256')!=base_completeness_sha or
     supplement.get('baseArchiveSha256')!=HISTORICAL_BASE_ARCHIVE or supplement.get('baseArchiveBytes')!=14_123_697_104 or
     supplement.get('encryptedSha256')!=point.get('sourceOverlaySha256') or supplement.get('fullyRecoverable') is not False or
     point.get('manifestId')!=HISTORICAL_PARENT or point.get('manifestDigest')!=HISTORICAL_PARENT_DIGEST or
     point.get('parentReceiptSha256')!=receipt_sha or point.get('receiptSha256')!=receipt_sha or point.get('overlayReceiptSha256')!=supplement_sha):
  raise Blocked('SIGNED_POINT_DOCUMENT_BINDING')
 if base.get('status')!='passed' or base.get('manifestId')!=point.get('manifestId') or base_completeness.get('status')!='passed' or base_completeness.get('fullyRecoverable') is not False:
  raise Blocked('SIGNED_POINT_PARENT_INVALID')
 return receipt_sha,base_completeness_sha,supplement_sha
def verify_bundle(directory,capsule_proof,restore_path,live_directory=None):
 directory=Path(directory);archive=directory/'current.tar';index=directory/'index.json';proof_path=directory/'capture-proof.json'
 ast=private_file(archive,192*1024*1024);ist=private_file(index,32*1024*1024);pst=private_file(proof_path,1_000_000)
 proof=json.loads(proof_path.read_bytes())
 if (proof.get('schema')!='platform.extra-mounted-trees-capture/v1' or proof.get('completeBeforeAfterEqual') is not True or proof.get('productionDataWrites') is not False or proof.get('servicesStopped') is not False or proof.get('globalAtomicSnapshot') is not False or proof.get('exclusions')!=[] or proof.get('treeCount')!=9 or proof.get('runtimeFixtureCount')!=2 or proof.get('archive')!={'file':'current.tar','bytes':ast.st_size,'sha256':digest(archive)} or proof.get('indexSha256')!=digest(index)):
  raise Blocked('CAPTURE_PROOF_INVALID')
 lag=(parse_time(capsule_proof['capturedAt'])-parse_time(proof['completedAt'])).total_seconds()
 if lag<0 or lag>900 or parse_time(proof['startedAt'])>parse_time(proof['completedAt']):raise Blocked('CAPTURE_NOT_SAME_CYCLE')
 restore=module(restore_path,'g16_tree_restore',RESTORE_SHA)
 destination=directory.parent/'materialized'
 result=restore.restore(directory,destination,digest(archive),digest(index),digest(proof_path))
 if result.get('status')!='passed' or result.get('treeCount')!=9:raise Blocked('PRIVATE_MATERIALIZATION_FAILED')
 shutil.rmtree(destination)
 result={'status':'passed','treeCount':9,'runtimeFixtureCount':2,'archiveBytes':ast.st_size,'archiveSha256':digest(archive),'indexBytes':ist.st_size,'indexSha256':digest(index),'captureProofSha256':digest(proof_path),'sameCapsule':True,'privateRestoreVerified':True}
 if live_directory is not None:
  live=Path(live_directory)
  for ancestor in (live, *live.parents):
   st=ancestor.lstat()
   if not stat.S_ISDIR(st.st_mode) or ancestor.is_symlink() or st.st_uid!=0 or st.st_mode&0o022:raise Blocked('LIVE_CAPTURE_ANCESTOR_PROTECTION')
  mapping={'current.tar':result['archiveSha256'],'index.json':result['indexSha256'],'capture-proof.json':result['captureProofSha256']}
  for name,expected in mapping.items():
   p=live/name;private_file(p,192*1024*1024)
   if digest(p)!=expected:raise Blocked('LIVE_CAPTURE_DRIFT')
  result['liveCaptureBindingVerified']=True
 return result
def verify(capsule_path,capsule_proof,key_path,tmp_parent='/run',popen=subprocess.Popen,
           capture_path='/usr/local/libexec/'+CAPTURE_NAME,
           restore_path='/usr/local/libexec/'+RESTORE_NAME,
           live_directory='/var/lib/platform-host-recovery/extra-mounted-trees',
           historical_verify_path='/usr/local/libexec/'+HISTORICAL_VERIFY_NAME,
           capsule_proof_path=None,
           file_staging_index_path=None,
           authenticated_g16_point=None):
 if os.geteuid()!=0:raise Blocked('ROOT_REQUIRED')
 parent=Path(tmp_parent);pst=parent.lstat()
 if parent.is_symlink() or not stat.S_ISDIR(pst.st_mode) or pst.st_uid!=0 or pst.st_mode&0o022:raise Blocked('SCRATCH_PARENT_PROTECTION')
 cap_path=Path(capsule_path);capst=cap_path.lstat()
 if cap_path.is_symlink() or not stat.S_ISREG(capst.st_mode) or capst.st_uid!=0 or capst.st_nlink!=1 or capst.st_size!=capsule_proof.get('encryptedBytes') or digest(cap_path)!=capsule_proof.get('encryptedSha256'):raise Blocked('CAPSULE_BINDING')
 if type(capsule_proof.get('encryptedBytes')) is not int or not 0<capsule_proof['encryptedBytes']<=2_000_000_000 or not re.fullmatch('[a-f0-9]{64}',str(capsule_proof.get('plaintextArchiveSha256',''))):raise Blocked('CAPSULE_PROOF_BOUNDS')
 capture_path=Path(capture_path);module(capture_path,'g16_tree_capture',CAPTURE_SHA)
 if capsule_proof_path is None:raise Blocked('CAPSULE_PROOFS_REQUIRED')
 cproof_path=Path(capsule_proof_path);cproof_stat=private_file(cproof_path,1_000_000)
 if json.loads(cproof_path.read_bytes())!=capsule_proof:raise Blocked('CAPSULE_PROOF_FILE_OBJECT_DIFFERS')
 if file_staging_index_path is not None:
  index,index_files,index_links=load_file_staging_index(file_staging_index_path,digest(file_staging_index_path))
 else:
  index,index_files,index_links=None,None,None
 key_fd,key_bytes=open_gpg_key(key_path)
 scratch=Path(tempfile.mkdtemp(prefix='host-extra-tree-',dir=parent));os.chmod(scratch,0o700);process=None
 try:
  cmd=['gpg','--no-options','--batch','--yes','--pinentry-mode','loopback','--passphrase-file',f'/proc/self/fd/{key_fd}','--homedir',str(scratch),'--decrypt','--output','-',str(cap_path)]
  process=popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True,pass_fds=(key_fd,))
  total=0;plain_hash=hashlib.sha256();bundle=scratch/'bundle';bundle.mkdir(mode=0o700);historical=scratch/'historical';historical.mkdir(mode=0o700);found=set();seen_files={};seen_links={};seen_dirs=set();entry_count=0;regular_bytes=0
  class Bounded:
   def read(self,size=-1):
    nonlocal total
    data=process.stdout.read(size);total+=len(data)
    if total>2_000_000_000:raise Blocked('PLAINTEXT_LIMIT')
    plain_hash.update(data);return data
  source=Bounded()
  with tarfile.open(fileobj=source,mode='r|gz') as outer:
   for count,member in enumerate(outer,1):
    if count>30000:raise Blocked('OUTER_MEMBER_COUNT')
    entry_count+=1;name=member.name.removeprefix('./').rstrip('/') if member.isdir() else member.name.removeprefix('./')
    if name.startswith('/') or '..' in Path(name).parts or ('\\' in name and name not in LINUX_LITERAL_BACKSLASH_MEMBERS) or '\x00' in name:raise Blocked('OUTER_MEMBER_PATH')
    if member.isfile():
     row=index_files.get(name) if index_files is not None else None
     if (index_files is not None and row is None) or name in seen_files or name in seen_links or name in seen_dirs:raise Blocked('OUTER_MEMBER_NOT_IN_INDEX')
     if name in MEMBERS or name in HISTORICAL_MEMBERS:
      if member.name in found:raise Blocked('DUPLICATE_TREE_MEMBER')
      if name in MEMBERS:out_name,limit=MEMBERS[name];target=bundle/out_name
      else:out_name,limit=HISTORICAL_MEMBERS[name];target=historical/out_name
      target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
      result=write_outer_member(outer,member,target,limit,row);found.add(name)
     else:
      h=hashlib.sha256();size=0;stream=outer.extractfile(member)
      if stream is None:raise Blocked('OUTER_MEMBER_UNREADABLE')
      for block in iter(lambda:stream.read(1024*1024),b''):
       size+=len(block)
       if size>member.size:raise Blocked('OUTER_MEMBER_STREAM_LIMIT')
       h.update(block)
      result={'bytes':size,'sha256':h.hexdigest()}
      if index_files is not None and (size!=row['bytes'] or result['sha256']!=row['sha256'] or (member.uid,member.gid,member.mode)!=(row['uid'],row['gid'],row['mode'])):raise Blocked('OUTER_MEMBER_INDEX_DIFFERS')
     if name in seen_links or name in seen_dirs:raise Blocked('OUTER_MEMBER_DUPLICATE')
     seen_files[name]=result;regular_bytes+=result['bytes']
    elif member.issym():
     if (index_links is not None and name not in index_links) or name in seen_links or name in seen_files or name in seen_dirs:raise Blocked('OUTER_LINK_NOT_INDEXED')
     if '\x00' in member.linkname or len(member.linkname.encode('utf-8','surrogatepass'))>4096:raise Blocked('OUTER_LINK_TARGET_INVALID')
     seen_links[name]={'name':name,'type':'symlink'}
    elif member.isdir():
     if name in seen_dirs or name in seen_files or name in seen_links:raise Blocked('OUTER_MEMBER_DUPLICATE')
     seen_dirs.add(name)
    else:raise Blocked('OUTER_MEMBER_SPECIAL')
  for block in iter(lambda:source.read(1024*1024),b''):pass
  if (found!=set(MEMBERS)|set(HISTORICAL_MEMBERS) or
      (index is not None and (set(seen_files)!=set(index_files) or set(seen_links)!=index_links or
       entry_count!=index.get('entries') or len(seen_files)!=index.get('regularFiles') or regular_bytes!=index.get('regularBytes'))) or
      entry_count!=capsule_proof.get('entryCount') or len(seen_files)+len(seen_dirs)+len(seen_links)!=entry_count or
      plain_hash.hexdigest()!=capsule_proof.get('plaintextArchiveSha256')):raise Blocked('CAPSULE_TREE_OR_HISTORICAL_RECORD_OR_PLAINTEXT_HASH')
  if process.wait(timeout=180)!=0:raise Blocked('GPG_DECRYPT_FAILED')
  if digest(cap_path)!=capsule_proof.get('encryptedSha256'):raise Blocked('CAPSULE_CHANGED')
  tree_result=verify_bundle(bundle,capsule_proof,restore_path,live_directory)
  record_mod=module(historical_verify_path,'g16_historical_record_verify',HISTORICAL_VERIFY_SHA)
  record_result=record_mod.verify_record(historical)
  record={
   'schema':'platform.recovery-record-capsule-binding/v1',
   'status':'passed','source':'same-cycle-decrypted-host-capsule-before-publication',
   'remoteReadbackVerified':False,'decryptedAfterReadback':False,
   'recordPath':HISTORICAL_ROOT,'historicalParentManifestId':record_result['historicalParentManifestId'],
   'historicalParentManifestDigest':record_result['historicalParentManifestDigest'],
   'historicalParentReceiptSha256':record_result['historicalParentReceiptSha256'],
   'historicalSourceArchiveSha256':record_result['historicalSourceArchiveSha256'],
   'artifactSha256':record_result['artifactSha256'],'artifactSetSha256':hashlib.sha256(json.dumps(record_result['artifactSha256'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),
   'indexSha256':record_result['indexSha256'],'archiveMemberPath':HISTORICAL_ROOT+'/current.tar','indexMemberPath':HISTORICAL_ROOT+'/index.json','proofMemberPath':HISTORICAL_ROOT+'/proof.json',
   'recordMemberSha256':record_result['recordMemberSha256'],'capsuleMemberSha256':record_result['recordMemberSha256'],
   'proofMemberSha256':record_result['proofSha256'],'hostCapsuleSha256':capsule_proof['encryptedSha256'],
   'hostCapsulePlaintextSha256':capsule_proof['plaintextArchiveSha256'],'extendedCapsuleVerified':record_result['extendedCapsuleVerified'],'productionModified':False,'offsiteVerified':False,
  }
  if authenticated_g16_point is not None:
   point=authenticated_g16_point
   if point.get('schema')!='platform.native-point-readback/v1' or point.get('signedReceiptVerified') is not True or point.get('fullRemoteReadback') is not True or point.get('allMemberHashesVerified') is not True or point.get('offsiteVerified') is not True or point.get('hostCapsuleSha256')!=capsule_proof['encryptedSha256'] or point.get('hostCapsulePlaintextSha256')!=capsule_proof['plaintextArchiveSha256']:
    raise Blocked('G16_POINT_READBACK_BINDING')
   receipt_sha,base_completeness_sha,supplement_sha=_verify_signed_point_documents(point,key_bytes)
   overlay=point['overlayReceiptDocument']['payload']
   capsule_proof_sha=digest(cproof_path)
   if (overlay.get('capsuleSha256')!=capsule_proof.get('encryptedSha256') or
       overlay.get('capsuleProofSha256')!=capsule_proof_sha or
       point.get('hostCapsuleSha256')!=capsule_proof.get('encryptedSha256') or
       point.get('hostCapsuleProofSha256')!=capsule_proof_sha or
       point.get('hostCapsulePlaintextSha256')!=capsule_proof.get('plaintextArchiveSha256')):
    raise Blocked('G16_OVERLAY_CAPSULE_BINDING')
   reader=point.get('nativeOverlayRestore',{})
   if (reader.get('status')!='passed' or reader.get('metadataValidated') is not True or
       reader.get('overlayPackageSha256')!=overlay.get('overlayPackageSha256') or
       reader.get('capsuleCiphertextSha256')!=overlay.get('capsuleSha256') or
       reader.get('innerTypedReceiptSha256')!=overlay.get('overlayReceiptSha256')):raise Blocked('G16_NATIVE_READER_BINDING')
   indexed=point.get('authenticatedMembers',{})
   expected={HISTORICAL_ROOT+'/current.tar':record_result['recordMemberSha256'],HISTORICAL_ROOT+'/index.json':record_result['indexSha256'],HISTORICAL_ROOT+'/proof.json':record_result['proofSha256']}
   for path,expected_sha in expected.items():
    if indexed.get(path)!=expected_sha:raise Blocked('G16_READBACK_RECORD_MEMBER_BINDING')
   record.update({'schema':'platform.recovery-record-readback/v1','source':'decrypted-current-host-capsule-after-full-remote-readback','remoteReadbackVerified':True,'decryptedAfterReadback':True,'manifestId':point['manifestId'],'manifestDigest':point['manifestDigest'],'parentReceiptSha256':receipt_sha,'receiptSha256':receipt_sha,'baseCompletenessReceiptSha256':base_completeness_sha,'baseArchiveSha256':overlay['baseArchiveSha256'],'baseArchiveBytes':overlay['baseArchiveBytes'],'overlayReceiptSha256':supplement_sha,'sourceArchiveSha256':point['sourceArchiveSha256'],'sourceOverlaySha256':point['sourceOverlaySha256'],'hostCapsuleSha256':capsule_proof['encryptedSha256'],'hostCapsulePlaintextSha256':capsule_proof['plaintextArchiveSha256'],'hostCapsuleProofSha256':capsule_proof_sha,'authenticatedArtifactIndexSha256':point['authenticatedArtifactIndexSha256'],'authenticatedRecordMembers':{'current.tar':record_result['recordMemberSha256'],'index.json':record_result['indexSha256'],'proof.json':record_result['proofSha256']},'offsiteVerified':True})
  tree_result['historicalRecordCapture']=record
  return tree_result
 except Blocked:
  if process is not None and process.poll() is None:process.kill();process.wait()
  raise
 except (OSError,ValueError,KeyError,TypeError,tarfile.TarError,subprocess.SubprocessError):
  if process is not None and process.poll() is None:process.kill();process.wait()
  raise Blocked('CAPSULE_TREE_VERIFICATION_FAILED') from None
 finally:
  if scratch.parent==parent:shutil.rmtree(scratch)
  os.close(key_fd)
