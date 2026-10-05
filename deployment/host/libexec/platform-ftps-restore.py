#!/usr/bin/python3
"""Download one frozen FTPS receipt, verify every artifact, then boot RustFS in isolation."""
import fcntl,hashlib,importlib.util,json,os,pathlib,re,shutil,subprocess,sys,tarfile,tempfile,time

s=importlib.util.spec_from_file_location('backup','/usr/local/libexec/platform-ftps-backup.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
RUSTFS_ARCHIVE=re.compile(r'rustfs-[0-9]{8}T[0-9]{6}Z\.tar\.gz\.gpg')

def receipt_bytes(f,name):
 data=bytearray()
 def collect(chunk):
  data.extend(chunk)
  if len(data)>131072:raise RuntimeError('Remote receipt exceeds bound')
 f.retrbinary('RETR '+name,collect,blocksize=65536)
 return bytes(data)

def selected_rustfs_artifact(manifest,restored,target):
 artifacts=manifest['artifacts'];native=[a for a in artifacts if a['resourceId']=='platform-state:rustfs-data']
 legacy=[a for a in artifacts if a['resourceId']=='platform-state:control-center-state']
 if len(native)==1:return extract_native_rustfs(restored/native[0]['path'],target)
 if len(native)>1 or len(legacy)!=1:raise RuntimeError('Signed manifest has no unambiguous RustFS resource')
 return extract_legacy_rustfs(restored/legacy[0]['path'],target)

def safe_member(member,allow_dir=False):
 p=pathlib.PurePosixPath(member.name)
 if p.is_absolute() or '..' in p.parts or not(member.isfile() or (allow_dir and member.isdir())):raise RuntimeError('Unsafe RustFS recovery member')
 return p.as_posix()

def extract_native_rustfs(bundle,target):
 proof=None;archive=None;seen=set()
 with tarfile.open(bundle,'r:') as tar:
  for member in tar:
   name=safe_member(member)
   if name not in ['proof.json','rustfs-data.tar.gz.gpg'] or name in seen:raise RuntimeError('Native RustFS resource has unexpected members')
   seen.add(name)
   if name=='proof.json':
    if member.size>1024*1024:raise RuntimeError('RustFS proof too large')
    proof=json.loads(tar.extractfile(member).read())
   else:
    if member.size>32*1024**3:raise RuntimeError('RustFS archive too large')
    archive=target/'rustfs-data.tar.gz.gpg'
    with archive.open('xb') as dest:shutil.copyfileobj(tar.extractfile(member),dest,1024*1024)
 if seen!={'proof.json','rustfs-data.tar.gz.gpg'} or not proof:raise RuntimeError('Native RustFS resource incomplete')
 if not RUSTFS_ARCHIVE.fullmatch(pathlib.PurePosixPath(proof.get('archive','')).name):raise RuntimeError('Native RustFS proof archive invalid')
 proof_file=target/'rustfs-proof.json';proof_file.write_text(json.dumps(proof)+'\n')
 return archive,proof_file,'native-resource'

def extract_legacy_rustfs(bundle,target):
 latest=None;sidecar={};seen=set();entries=0
 with tarfile.open(bundle,'r:gz') as tar:
  for member in tar:
   entries+=1
   if entries>250000:raise RuntimeError('Legacy state archive entry bound exceeded')
   name=safe_member(member,allow_dir=True).removeprefix('./')
   if member.isdir():continue
   if name=='rustfs-recovery/latest.json':
    if name in seen or member.size>1024*1024:raise RuntimeError('Invalid RustFS latest proof')
    latest=json.loads(tar.extractfile(member).read());seen.add(name)
   elif name.startswith('rustfs-recovery/archives/'):
    leaf=name.removeprefix('rustfs-recovery/archives/')
    if '/' in leaf or not re.fullmatch(r'rustfs-[0-9]{8}T[0-9]{6}Z\.(?:json|tar\.gz\.gpg)',leaf):continue
    if name in seen:raise RuntimeError('Duplicate RustFS state member')
    seen.add(name)
    if leaf.endswith('.json'):
     if member.size>1024*1024:raise RuntimeError('RustFS proof too large')
     sidecar[leaf]=json.loads(tar.extractfile(member).read())
 if not isinstance(latest,dict) or not re.fullmatch(r'archives/rustfs-[0-9]{8}T[0-9]{6}Z\.tar\.gz\.gpg',latest.get('archive','')):raise RuntimeError('Legacy RustFS latest proof unavailable')
 leaf=pathlib.PurePosixPath(latest['archive']).name;proof_name=leaf.removesuffix('.tar.gz.gpg')+'.json'
 if sidecar.get(proof_name)!=latest:raise RuntimeError('Legacy RustFS archive and proof differ')
 archive=None
 with tarfile.open(bundle,'r:gz') as tar:
  for member in tar:
   name=safe_member(member,allow_dir=True).removeprefix('./')
   if member.isdir() or name!='rustfs-recovery/archives/'+leaf:continue
   if archive is not None or member.size>32*1024**3:raise RuntimeError('Duplicate or oversized selected RustFS archive')
   archive=target/leaf
   with archive.open('xb') as dest:shutil.copyfileobj(tar.extractfile(member),dest,1024*1024)
 if archive is None:raise RuntimeError('Selected RustFS archive is absent')
 proof_file=target/'rustfs-proof.json';proof_file.write_text(json.dumps(latest)+'\n')
 return archive,proof_file,'legacy-control-center-state'

def restore_rustfs(manifest,restored,target,expected_image=None,expected_image_id=None):
 archive,proof_file,source=selected_rustfs_artifact(manifest,restored,target)
 proof=json.loads(proof_file.read_text())
 if expected_image is not None and (proof.get('image')!=expected_image or proof.get('imageId')!=expected_image_id):raise RuntimeError('RustFS proof differs from frozen signed image pin before isolated boot')
 spec=importlib.util.spec_from_file_location('rustfs_restore','/usr/local/libexec/platform-rustfs-restore.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 result=module.restore_archive(archive,proof_file,keep_target=False,require_native_admission=expected_image is not None,expected_image=expected_image,expected_image_id=expected_image_id)
 if result.get('status')!='passed' or result.get('productionModified') is not False or result.get('network')!='none' or result.get('targetRemoved') is not True:raise RuntimeError('RustFS isolated restore proof incomplete')
 return {'source':source,'archiveSha256':result['archiveSha256'],'rustfsImage':result['rustfsImage'],'rustfsImageId':result['rustfsImageId'],'isolatedTarget':result['isolatedTarget'],'s3Inventory':result['s3Inventory'],'targetRemoved':True}

def restore_capacity(proof,supplements):
 # All attachments are retained as ciphertext + tar + verified extracted files.
 # Reserve before downloading anything, including multipart temporary fragments.
 parent=proof['encryptedBytes']+2*proof['artifactBytes']+10*1024**3
 fragments=max((p['bytes'] for p in proof.get('parts',[])),default=0)
 attachments=sum(item['encryptedBytes']+2*sum(f['bytes'] for f in item['files']) for item in supplements)
 fragments=max(fragments,max((p['bytes'] for item in supplements for p in item.get('parts',[])),default=0))
 return parent+attachments+fragments+64*1024**2

def main(argv):
 if len(argv)==1 and b.NAME.fullmatch(argv[0]):name=argv[0];expected_receipt_sha=None;expected_image=None;expected_image_id=None
 elif (len(argv)==7 and b.NAME.fullmatch(argv[0]) and argv[1]=='--expected-receipt-sha256' and re.fullmatch(r'[a-f0-9]{64}',argv[2])
       and argv[3]=='--expected-rustfs-image' and re.fullmatch(r'rustfs/rustfs@sha256:[a-f0-9]{64}',argv[4])
       and argv[5]=='--expected-rustfs-image-id' and re.fullmatch(r'sha256:[a-f0-9]{64}',argv[6])):
  name=argv[0];expected_receipt_sha=argv[2];expected_image=argv[4];expected_image_id=argv[6]
 else:raise SystemExit('Pass exact bundle; native operator must freeze receipt SHA256 and RustFS image/ref ID')
 os.umask(0o077);b.WORK.mkdir(mode=0o700,exist_ok=True)
 with (b.WORK/'transfer.lock').open('a') as lock:
  b.wait_for_transfer_lock(lock,timeout=14400)
  f=b.connect();target=None
  try:
   listing=b.inventory(f);raw=receipt_bytes(f,name+'.receipt.json')
   receipt_sha=hashlib.sha256(raw).hexdigest()
   if expected_receipt_sha is not None and receipt_sha!=expected_receipt_sha:raise RuntimeError('Frozen receipt SHA256 differs before ciphertext download')
   proof=b.verify(json.loads(raw));confirmed=b.points(f,listing)
   if not any(p==proof for p in confirmed):raise RuntimeError('Selected point not in authenticated inventory')
   objects=b.point_objects(proof)
   if proof.get('bundle')!=name or proof.get('status')!='passed' or any(listing.get(k)!=v for k,v in objects.items()):raise RuntimeError('Selected FTPS point differs')
   b.ensure_source_fresh(proof['backupAt'],time.time())
   attachments=b.point_supplements(f,{n:v for n,v in listing.items() if n.startswith(name+'.')},[proof])[name]
   if shutil.disk_usage(b.WORK).free<restore_capacity(proof,attachments):raise RuntimeError('Insufficient isolated restore capacity including all attachments')
   target=pathlib.Path(tempfile.mkdtemp(prefix='recovered-',dir=b.WORK));encrypted=target/'downloaded.gpg';plain=target/'downloaded.tar';restored=target/'backups';restored.mkdir(mode=0o700);received=0
   if proof['schema']=='platform.ftps-recovery-point/v1':
    f=b.download_resilient(f,name,encrypted,proof['encryptedBytes']);received=encrypted.stat().st_size
   else:
    with encrypted.open('wb') as output:
     for part in proof['parts']:
      fragment=target/'downloaded-part';f=b.download_resilient(f,part['name'],fragment,part['bytes'])
      if b.sha(fragment)!=part['sha256']:raise RuntimeError('Downloaded part SHA256 differs')
      with fragment.open('rb') as source:shutil.copyfileobj(source,output,1024*1024)
      received+=fragment.stat().st_size;fragment.unlink()
   f,supplements=b.restore_supplements(f,listing,proof,target)
  finally:
   try:f.quit()
   except Exception:f.close()
  if received!=proof['encryptedBytes'] or b.sha(encrypted)!=proof['encryptedSha256']:raise RuntimeError('Downloaded FTPS ciphertext differs')
  home=target/'gnupg';home.mkdir(mode=0o700)
  r=subprocess.run(['gpg','--no-options','--homedir',str(home),'--batch','--pinentry-mode','loopback','--passphrase-file',str(b.KEY),'--decrypt','--output',str(plain),str(encrypted)],capture_output=True)
  if r.returncode:raise RuntimeError('FTPS ciphertext decryption failed')
  expected_manifest='manifests/'+proof['manifestId']+'.json';seen=set();total=0;expected=None;manifest=None
  with tarfile.open(plain,'r:') as tar:
   for member in tar:
    p=pathlib.PurePosixPath(member.name)
    if p.is_absolute() or '..' in p.parts or not member.isfile() or member.name in seen:raise RuntimeError('Unsafe restored archive member')
    if not seen:
     if member.name!=expected_manifest or member.size>2*1024**2:raise RuntimeError('Expected first signed manifest')
     manifest=json.loads(tar.extractfile(member).read());expected={expected_manifest}
     for artifact in manifest['artifacts']:
      for suffix in ['', '.sha256', '.sig.json']:expected.add(artifact['path']+suffix)
    if member.name not in expected:raise RuntimeError('Unexpected restored artifact')
    seen.add(member.name);total+=member.size
    if total>proof['artifactBytes']+16*1024**2:raise RuntimeError('Restored artifact size bound exceeded')
    tar.extract(member,path=restored,filter='data')
  if seen!=expected:raise RuntimeError('Restored set incomplete')
  for p in [restored,*restored.rglob('*')]:os.chown(p,1000,1000)
  verified=b.d.verify(restored,proof['manifestId']+'.json')
  if verified['manifestDigest']!=proof['manifestDigest'] or verified['artifactCount']!=proof['artifactCount'] or verified['artifactBytes']!=proof['artifactBytes']:raise RuntimeError('Restored signed manifest binding differs')
  rustfs=restore_rustfs(manifest,restored,target,expected_image,expected_image_id)
  result={'schema':'platform.ftps-isolated-restore/v2','status':'passed','verifiedAt':b.now(),'manifestId':proof['manifestId'],'manifestDigest':proof['manifestDigest'],'receiptSha256':receipt_sha,'bundle':name,'restoredPath':str(restored),'artifactCount':verified['artifactCount'],'actualRemoteDownloadVerified':True,'decryptionVerified':True,'everyArtifactShaAndHmacVerified':True,'restoreBackend':rustfs['source'],'rustfsRestoreVerified':True,'rustfsImage':rustfs['rustfsImage'],'rustfsImageId':rustfs['rustfsImageId'],'rustfs':rustfs,'productionModified':False,'sourceFormat':proof['schema'],'partCount':len(objects),'supplements':supplements}
  b.save(target/'restore-proof.json',result);print(json.dumps(result))

if __name__=='__main__':main(sys.argv[1:])
