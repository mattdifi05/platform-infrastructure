#!/usr/bin/python3
"""Encrypted full server recovery points over certificate-verified explicit FTPS."""
import sys; sys.path.insert(0,'/usr/local/libexec'); import platform_backup_safe_state as safe_state
import datetime,fcntl,ftplib,hashlib,hmac,importlib.util,json,os,pathlib,re,shutil,ssl,stat,subprocess,tarfile,tempfile,uuid,sys,time
CONFIG=pathlib.Path('/etc/platform-ftps-backup/config.json');WORK=pathlib.Path('/var/lib/platform-ftps-backup')
STATE=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/state/host-recovery')
KEY=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase')
PART_BYTES=1_000_000_000
CAP=70_000_000_000;MAX_POINTS=6;MAX_AGE=14*86400;FOLDER='/server-platform-backups'
NAME=re.compile(r'backup-(manifest-[a-z0-9][a-z0-9-]{15,127})\.tar\.gpg')
MARKER='.platform-backup-owner.json'
INDEX=pathlib.Path('/var/lib/platform-backup-schedule/ftps-retention-index.json')
FREEZE=pathlib.Path('/var/lib/platform-backup-schedule/offsite-freeze.json')
spec=importlib.util.spec_from_file_location('dedup','/usr/local/libexec/platform-local-dedup.py');d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def save(path,data,shared=False):
 safe_state.write_json(path,data,shared)

def mac(v):return hmac.new(KEY.read_bytes(),b'platform-ftps-receipt-v1\n'+canonical(v),hashlib.sha256).hexdigest()
def sign(v):return {'payload':v,'hmacSha256':mac(v)}
def verify(v):
 if set(v)!= {'payload','hmacSha256'} or not hmac.compare_digest(mac(v['payload']),v['hmacSha256']):raise RuntimeError('FTPS receipt authentication failed')
 return v['payload']
def connect():
 cfg=json.loads(CONFIG.read_text())
 if cfg['host']!='92.113.28.106' or cfg['port']!=21 or cfg['tlsName']!='hstgr.io' or cfg['folder']!=FOLDER:raise RuntimeError('Unexpected FTPS fixed endpoint')
 f=ftplib.FTP_TLS(context=ssl.create_default_context(),timeout=90);f.connect(cfg['host'],cfg['port']);f.host=cfg['tlsName'];f.auth();f.login(cfg['username'],cfg['password']);f.prot_p();f.cwd(FOLDER)
 if f.pwd()!=FOLDER:raise RuntimeError('FTPS destination is not the exact dedicated account-root folder')
 return f
def inventory(f):
 result={}
 for name,facts in f.mlsd():
  if facts.get('type') in ['cdir','pdir']:continue
  if facts.get('type')!='file' or '/' in name or name in ['.','..']:raise RuntimeError('Unexpected object in managed FTPS folder')
  if len(result)>=1024:raise RuntimeError('FTPS managed inventory exceeds bound')
  result[name]=int(facts['size'])
 return result
def get_json(f,name,max_bytes=131072):
 data=bytearray()
 def collect(chunk):
  data.extend(chunk)
  if len(data)>max_bytes:raise RuntimeError('Remote metadata exceeds bound')
 f.retrbinary('RETR '+name,collect,blocksize=65536);return json.loads(data)
def upload_bytes(f,name,data):
 import io
 f.storbinary('STOR '+name,io.BytesIO(data),blocksize=65536)
def publish_receipt(proof,attempts=3):
 # Local decrypt/HMAC checks can outlive the server control-session idle limit.
 # Always establish verified TLS anew, then reconcile an uncertain STOR/rename.
 receipt=canonical(sign(proof));name=proof['bundle']+'.receipt.json';partial=name+'.partial'
 if len(receipt)>131072:raise RuntimeError('Multipart receipt exceeds bound')
 objects=point_objects(proof)
 for attempt in range(attempts):
  f=None
  try:
   f=connect();listing=inventory(f);verify_owner(f)
   ensure_source_fresh(proof['backupAt'],time.time())
   if any(listing.get(k)!=v for k,v in objects.items()):raise RuntimeError('Receipt publication parts differ')
   if name in listing:
    if verify(get_json(f,name))!=proof:raise RuntimeError('Existing receipt differs from verified recovery point')
    if partial in listing:
     if verify(get_json(f,partial))!=proof:raise RuntimeError('Duplicate receipt partial differs')
     f.delete(partial)
    return f
   points(f,{k:v for k,v in listing.items() if k not in objects and k!=partial})
   if sum(listing.values())-listing.get(partial,0)+len(receipt)>CAP:raise RuntimeError('Receipt publication would exceed hard cap')
   upload_bytes(f,partial,receipt)
   if verify(get_json(f,partial))!=proof:raise RuntimeError('Uploaded receipt differs')
   f.rename(partial,name)
   if verify(get_json(f,name))!=proof:raise RuntimeError('Published receipt differs')
   return f
  except (OSError,EOFError,ftplib.Error):
   if f is not None:f.close()
   if attempt+1==attempts:raise
   time.sleep(1)
  except Exception:
   if f is not None:f.close()
   raise
 raise RuntimeError('Receipt publication attempts exhausted')

def validate_downloaded(pending,tmp):
 for parent in [WORK,tmp]:
  st=parent.lstat()
  if parent.is_symlink() or not parent.is_dir() or st.st_uid!=0 or st.st_mode&0o077:raise RuntimeError('Prior download parent is not root protected')
 path=tmp/'downloaded.tar.gpg'
 if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or path.stat().st_mode&0o077 or path.stat().st_size!=pending['encryptedBytes']:raise RuntimeError('Protected prior download is unavailable')
 whole=hashlib.sha256()
 with path.open('rb') as stream:
  for part in pending['parts']:
   digest=hashlib.sha256();remaining=part['bytes']
   while remaining:
    chunk=stream.read(min(1024*1024,remaining))
    if not chunk:raise RuntimeError('Prior download truncated')
    remaining-=len(chunk);digest.update(chunk);whole.update(chunk)
   if digest.hexdigest()!=part['sha256']:raise RuntimeError('Prior downloaded part hash differs')
  if stream.read(1):raise RuntimeError('Prior download has extra bytes')
 if whole.hexdigest()!=pending['encryptedSha256']:raise RuntimeError('Prior download global hash differs')
 return path

def point_objects(p):
 bundle=p.get('bundle','')
 if not NAME.fullmatch(bundle):raise RuntimeError('Invalid recovery point name')
 if p.get('schema')=='platform.ftps-recovery-point/v1':return {bundle:p['encryptedBytes']}
 if p.get('schema')!='platform.ftps-recovery-point/v2':raise RuntimeError('Unsupported recovery format')
 parts=p.get('parts',[])
 if not isinstance(parts,list) or not 1<=len(parts)<=70:raise RuntimeError('Invalid multipart count')
 result={}
 for i,part in enumerate(parts):
  name=bundle+'.part'+str(i).zfill(3)
  if set(part)!={'name','bytes','sha256'} or part['name']!=name or not isinstance(part['bytes'],int) or not 0<part['bytes']<=1_000_000_000 or not re.fullmatch('[a-f0-9]{64}',part['sha256']):raise RuntimeError('Invalid ordered multipart binding')
  result[name]=part['bytes']
 if sum(result.values())!=p['encryptedBytes']:raise RuntimeError('Multipart total differs')
 return result
def verify_owner(f):
 marker=get_json(f,MARKER)
 if marker!={'schema':'platform.ftps-owner/v1','owner':'server-platform-vpn','folder':FOLDER,'quotaBytes':CAP}:raise RuntimeError('FTPS ownership marker differs')
SUPPLEMENT_SCHEMA='platform.ftps-point-supplement/v1'
SUPPLEMENT_LIMIT=64_000_000
SUPPLEMENT_RECEIPT_LIMIT=1_048_576
SUPPLEMENT_MAX_FILES=1024
SUPPLEMENT_REQUIRED={'platform-ftps-backup.py','platform-ftps-restore.py','RECOVERY.md'}
def supplement_member_name(name):
 if not isinstance(name,str) or not 1<=len(name.encode('utf-8'))<=512 or name.startswith('/') or '\\' in name or any(c in name for c in ['\x00','\r','\n']):return False
 return all(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',part) and part not in ['.','..'] for part in name.split('/'))
def protected_supplement_path(path,directory=False):
 import stat
 path=pathlib.Path(path)
 # All components beneath the fixed root-owned spool must be non-link root objects.
 if not path.is_relative_to(WORK):raise RuntimeError('Supplement path outside fixed spool')
 for node in [WORK,*list(path.relative_to(WORK).parents)[::-1]]:
  if node!=WORK:node=WORK/node
  st=node.lstat()
  if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o077:raise RuntimeError('Unprotected supplement ancestor')
 st=path.lstat()
 if st.st_uid!=0 or st.st_mode&0o077 or (not stat.S_ISDIR(st.st_mode) if directory else not stat.S_ISREG(st.st_mode) or st.st_nlink!=1):raise RuntimeError('Unprotected supplement object')
 return st
def remove_supplement_scratch(path):
 path=pathlib.Path(path)
 if path.parent!=WORK or not re.fullmatch(r'supplement-[a-z0-9_]{8,}',path.name):raise RuntimeError('Unexpected supplement scratch')
 protected_supplement_path(path,True)
 home=path/'gnupg'
 if home.exists():
  protected_supplement_path(home,True)
  subprocess.run(['gpgconf','--homedir',str(home),'--kill','gpg-agent'],capture_output=True,check=True,timeout=15)
  deadline=time.monotonic()+5
  while any(p.name.startswith('S.gpg-agent') for p in home.iterdir()):
   if time.monotonic()>deadline:raise RuntimeError('Private GPG agent sockets did not close')
   time.sleep(0.1)
 for root,dirs,files in os.walk(path,followlinks=False):
  for name in dirs:protected_supplement_path(pathlib.Path(root)/name,True)
  for name in files:protected_supplement_path(pathlib.Path(root)/name)
 shutil.rmtree(path)
def supplement_receipt_bytes(payload):
 data=canonical(sign_supplement(payload))
 if len(data)>SUPPLEMENT_RECEIPT_LIMIT:raise RuntimeError('Supplement receipt exceeds bound')
 return data
def sign_supplement(v):
 return {'payload':v,'hmacSha256':hmac.new(KEY.read_bytes(),b'platform-ftps-supplement-v1\n'+canonical(v),hashlib.sha256).hexdigest()}
def verify_supplement(document,parent,staged=False):
 if document.get('payload',{}).get('schema') in COMPLETENESS_SCHEMAS:return verify_completeness(document,parent,staged)
 if len(canonical(document))>SUPPLEMENT_RECEIPT_LIMIT:raise RuntimeError('Supplement receipt exceeds bound')
 if set(document)!={'payload','hmacSha256'} or not hmac.compare_digest(sign_supplement(document['payload'])['hmacSha256'],document['hmacSha256']):raise RuntimeError('Supplement HMAC differs')
 p=document['payload']
 fields={'schema','status','kind','parentManifestId','parentManifestDigest','parentReceiptSha256','parentEncryptedSha256','backupAt','ciphertext','encryptedBytes','encryptedSha256','files','verifiedAt'}
 if set(p)!=fields or p['schema']!=SUPPLEMENT_SCHEMA or p['status']!='passed' or p['kind']!='host-recovery-helper-delta':raise RuntimeError('Invalid supplement schema')
 if not staged:
  try:verified_epoch=datetime.datetime.fromisoformat(p['verifiedAt'].replace('Z','+00:00')).timestamp()
  except (AttributeError,ValueError,TypeError):raise RuntimeError('Supplement verification time is invalid')
  if verified_epoch>time.time()+300:raise RuntimeError('Supplement verification time is in the future')
 expected={'parentManifestId':parent['manifestId'],'parentManifestDigest':parent['manifestDigest'],'parentReceiptSha256':hashlib.sha256(canonical(sign(parent))).hexdigest(),'parentEncryptedSha256':parent['encryptedSha256'],'backupAt':parent['backupAt']}
 if any(p.get(k)!=v for k,v in expected.items()):raise RuntimeError('Supplement parent binding differs')
 if not re.fullmatch('[a-f0-9]{64}',p['encryptedSha256']) or p['ciphertext']!=parent['bundle']+'.supplement-'+p['encryptedSha256'][:16]+'.tar.gpg':raise RuntimeError('Unsafe supplement ciphertext name')
 if type(p['encryptedBytes']) is not int or not 0<p['encryptedBytes']<=SUPPLEMENT_LIMIT:raise RuntimeError('Supplement size exceeds bound')
 files=p['files']
 if not isinstance(files,list) or not 1<=len(files)<=SUPPLEMENT_MAX_FILES:raise RuntimeError('Invalid supplement file count')
 seen=set();total=0
 for item in files:
  if set(item)!={'name','bytes','sha256'} or not supplement_member_name(item['name']) or item['name'] in seen or type(item['bytes']) is not int or item['bytes']<0 or not re.fullmatch('[a-f0-9]{64}',item['sha256']):raise RuntimeError('Unsafe supplement member')
  seen.add(item['name']);total+=item['bytes']
 if total>SUPPLEMENT_LIMIT or not SUPPLEMENT_REQUIRED<=seen:raise RuntimeError('Incomplete or oversized recovery supplement')
 return p

# Additive v2 format: at most one legacy helper + one completeness attachment.
# "Completeness" names the intended material, never proof of whole-server restore.
COMPLETENESS_V2_SCHEMA='platform.ftps-point-completeness/v2'
COMPLETENESS_V3_SCHEMA='platform.ftps-point-completeness/v3'
COMPLETENESS_SCHEMA=COMPLETENESS_V3_SCHEMA
COMPLETENESS_SCHEMAS={COMPLETENESS_V2_SCHEMA,COMPLETENESS_SCHEMA}
def supplement_objects(p):
 if p['schema']==SUPPLEMENT_SCHEMA:return {p['ciphertext']:p['encryptedBytes']}
 if p['schema'] not in COMPLETENESS_SCHEMAS:raise RuntimeError('Unknown supplement format')
 result={}
 parts=p.get('parts')
 if not isinstance(parts,list) or not 1<=len(parts)<=70:raise RuntimeError('Invalid completeness part count')
 for i,item in enumerate(parts):
  if set(item)!={'name','bytes','sha256'} or item['name']!=p['ciphertext']+'.part'+str(i).zfill(3) or type(item['bytes']) is not int or not 0<item['bytes']<=PART_BYTES or not re.fullmatch('[a-f0-9]{64}',item['sha256']):raise RuntimeError('Invalid completeness multipart binding')
  result[item['name']]=item['bytes']
 if sum(result.values())!=p['encryptedBytes']:raise RuntimeError('Completeness multipart total differs')
 return result

def validate_supplement_set(items):
 kinds=[item['kind'] for item in items]
 if len(kinds)>2 or len(kinds)!=len(set(kinds)) or not set(kinds)<={'host-recovery-helper-delta','runtime-completeness-material'}:raise RuntimeError('Duplicate or unsupported supplement kind')

def verify_completeness(document,parent,staged=False):
 if len(canonical(document))>SUPPLEMENT_RECEIPT_LIMIT:raise RuntimeError('Completeness receipt exceeds bound')
 if set(document)!={'payload','hmacSha256'} or not hmac.compare_digest(sign_supplement(document['payload'])['hmacSha256'],document['hmacSha256']):raise RuntimeError('Completeness HMAC differs')
 p=document['payload']
 fields={'schema','status','kind','parentManifestId','parentManifestDigest','parentReceiptSha256','parentEncryptedSha256','backupAt','ciphertext','encryptedBytes','encryptedSha256','files','verifiedAt','parts','fullyRecoverable','knownGaps'}
 if p.get('schema')==COMPLETENESS_V3_SCHEMA:fields.add('archivePreflight')
 if set(p)!=fields or p['schema'] not in COMPLETENESS_SCHEMAS or p['status']!='passed' or p['kind']!='runtime-completeness-material' or p['fullyRecoverable'] is not False:raise RuntimeError('Invalid completeness schema or coverage claim')
 if not isinstance(p['knownGaps'],list) or not 1<=len(p['knownGaps'])<=128 or any(not isinstance(x,str) or not 1<=len(x)<=512 for x in p['knownGaps']):raise RuntimeError('Explicit completeness gaps required')
 if not staged:
  try:stamp=datetime.datetime.fromisoformat(p['verifiedAt'].replace('Z','+00:00')).timestamp()
  except (AttributeError,ValueError,TypeError):raise RuntimeError('Invalid completeness verification time')
  if stamp>time.time()+300:raise RuntimeError('Completeness verification is future dated')
 expected={'parentManifestId':parent['manifestId'],'parentManifestDigest':parent['manifestDigest'],'parentReceiptSha256':hashlib.sha256(canonical(sign(parent))).hexdigest(),'parentEncryptedSha256':parent['encryptedSha256'],'backupAt':parent['backupAt']}
 if any(p[k]!=v for k,v in expected.items()):raise RuntimeError('Completeness parent binding differs')
 if not re.fullmatch('[a-f0-9]{64}',p['encryptedSha256']) or p['ciphertext']!=parent['bundle']+'.supplement-full-'+p['encryptedSha256'][:16]+'.tar.gpg':raise RuntimeError('Unsafe completeness ciphertext name')
 if type(p['encryptedBytes']) is not int or not 0<p['encryptedBytes']<=CAP:raise RuntimeError('Completeness size exceeds capacity')
 supplement_objects(p)
 files=p['files'];seen=set();total=0
 if not isinstance(files,list) or not 2<=len(files)<=SUPPLEMENT_MAX_FILES:raise RuntimeError('Invalid completeness file count')
 for item in files:
  if set(item)!={'name','bytes','sha256'} or not supplement_member_name(item['name']) or item['name'] in seen or type(item['bytes']) is not int or item['bytes']<0 or not re.fullmatch('[a-f0-9]{64}',item['sha256']):raise RuntimeError('Unsafe completeness member')
  seen.add(item['name']);total+=item['bytes']
 if total>CAP or not {'coverage.json','RECOVERY.md'}<=seen:raise RuntimeError('Incomplete or oversized completeness archive')
 if p['schema']==COMPLETENESS_V3_SCHEMA:
  proof=p['archivePreflight']
  if (not isinstance(proof,dict) or set(proof)!={'schema','tarInputSha256','tarInputBytes','gpgExitCode','verifiedBeforeUpload','memberCount','members'} or
      proof.get('schema')!='platform.completeness-preflight/v1' or proof.get('gpgExitCode')!=0 or
      proof.get('verifiedBeforeUpload') is not True or type(proof.get('tarInputBytes')) is not int or
      not 0<proof['tarInputBytes']<=CAP or not re.fullmatch('[a-f0-9]{64}',str(proof.get('tarInputSha256',''))) or
      proof.get('memberCount')!=len(files) or proof.get('members')!=[
          {'name':item['name'],'bytes':item['bytes'],'sha256':item['sha256']} for item in files]):
   raise RuntimeError('Completeness signed preflight closure differs')
 return p

def verify_exact_parent_receipt(f,parent):
 expected=canonical(sign(parent));received=bytearray()
 def collect(chunk):
  received.extend(chunk)
  if len(received)>131072:raise RuntimeError('Parent receipt exceeds bound')
 f.retrbinary('RETR '+parent['bundle']+'.receipt.json',collect,blocksize=65536)
 if bytes(received)!=expected:raise RuntimeError('Exact parent receipt bytes differ')
 # HMAC/domain verification remains explicit in addition to byte equality.
 if verify(json.loads(received))!=parent:raise RuntimeError('Exact parent receipt differs')
 return hashlib.sha256(received).hexdigest()

def reserve_completeness(f,payload,parent):
 # Called under the shared transfer lock before uploading any new bulk bytes.
 # Does not prune retained points to make space and does not mutate remote state.
 verify_completeness(sign_supplement(payload),parent,staged=True)
 ensure_source_fresh(parent['backupAt'],time.time())
 listing=inventory(f);receipt=payload['ciphertext']+'.receipt.json'
 verify_exact_parent_receipt(f,parent)
 objects=supplement_objects(payload);extras={*objects,receipt,receipt+'.partial'}
 clean={n:v for n,v in listing.items() if n not in extras}
 confirmed=points(f,clean)
 existing=point_supplements(f,clean,confirmed).get(parent['bundle'],[])
 validate_supplement_set([*existing,payload])
 for name,size in objects.items():
  if name in listing and listing[name]!=size:raise RuntimeError('Partial completeness part requires reconciliation')
 for name in [receipt,receipt+'.partial']:
  if name in listing and verify_completeness(get_json(f,name,SUPPLEMENT_RECEIPT_LIMIT),parent,staged=True)!=payload:raise RuntimeError('Existing completeness receipt differs')
 reserved={**payload,'verifiedAt':'9999-12-31T23:59:59.999999+00:00'}
 receipt_bytes=len(supplement_receipt_bytes(reserved))
 additional=sum(size for name,size in objects.items() if name not in listing)
 if receipt not in listing:additional+=receipt_bytes
 if sum(listing.values())+additional>CAP:raise RuntimeError('Completeness reservation exceeds shared capacity')
 return {'additionalBytes':additional,'projectedBytes':sum(listing.values())+additional,'existingPointsPreserved':True}

def download_supplement(f,item,destination):
 if item['schema']==SUPPLEMENT_SCHEMA:return download_resilient(f,item['ciphertext'],destination,item['encryptedBytes'])
 # Unique private scratch destination; a failed download is retained for review,
 # never mistaken for a complete reassembled ciphertext.
 with destination.open('xb') as output:
  for index,part in enumerate(item['parts']):
   scratch=destination.with_name('part-'+str(index).zfill(3)+'.gpg')
   f=download_resilient(f,part['name'],scratch,part['bytes'])
   if sha(scratch)!=part['sha256']:raise RuntimeError('Completeness part SHA differs')
   with scratch.open('rb') as source:shutil.copyfileobj(source,output,1024*1024)
   scratch.unlink()
  output.flush();os.fsync(output.fileno())
 if destination.stat().st_size!=item['encryptedBytes'] or sha(destination)!=item['encryptedSha256']:raise RuntimeError('Completeness ciphertext SHA differs')
 return f

def point_supplements(f,listing,confirmed):
 parents={p['bundle']:p for p in confirmed};result={p['bundle']:[] for p in confirmed}
 for name in listing:
  if '.supplement-' not in name or not name.endswith('.receipt.json'):continue
  document=get_json(f,name,SUPPLEMENT_RECEIPT_LIMIT);claimed=document.get('payload',{});parent=next((p for p in confirmed if p.get('manifestId')==claimed.get('parentManifestId')),None)
  if parent is None:raise RuntimeError('Orphan supplement receipt')
  p=verify_supplement(document,parent)
  if name!=p['ciphertext']+'.receipt.json' or any(listing.get(n)!=size for n,size in supplement_objects(p).items()):raise RuntimeError('Supplement ciphertext/receipt differs')
  result[parent['bundle']].append(p)
  validate_supplement_set(result[parent['bundle']])
 return result

def group_objects(f,listing,p):
 objects={**point_objects(p),p['bundle']+'.receipt.json':listing[p['bundle']+'.receipt.json']}
 # Scope this lookup to the selected parent's prefix; other authenticated points are handled separately.
 selected={n:size for n,size in listing.items() if n.startswith(p['bundle']+'.')}
 supplements=point_supplements(f,selected,[p])[p['bundle']]
 for item in supplements:objects.update({**supplement_objects(item),item['ciphertext']+'.receipt.json':listing[item['ciphertext']+'.receipt.json']})
 return objects,supplements

def restore_supplement_archive(plain,destination,p):
 expected={item['name']:item for item in p['files']};seen=set();total=0
 destination.mkdir(mode=0o700,exist_ok=False)
 with tarfile.open(plain,'r:') as tar:
  for member in tar:
   item=expected.get(member.name)
   if not member.isfile() or item is None or member.name in seen or member.size!=item['bytes']:raise RuntimeError('Unsafe supplement archive entry')
   seen.add(member.name);total+=member.size
   if total>(CAP if p['schema'] in COMPLETENESS_SCHEMAS else SUPPLEMENT_LIMIT):raise RuntimeError('Supplement extracted size exceeds bound')
   if not supplement_member_name(member.name):raise RuntimeError('Unsafe supplement path')
   target=destination/member.name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
   with tar.extractfile(member) as source,target.open('xb') as output:shutil.copyfileobj(source,output,65536)
   os.chmod(target,0o600)
   if sha(target)!=item['sha256']:raise RuntimeError('Supplement member SHA differs')
 if seen!=set(expected):raise RuntimeError('Supplement archive incomplete')
 return {'status':'passed','files':len(seen),'bytes':total,'automaticallyExecuted':False}

def restore_supplements(f,listing,parent,target):
 attachments=point_supplements(f,{n:v for n,v in listing.items() if n.startswith(parent['bundle']+'.')},[parent])[parent['bundle']];results=[]
 for item in attachments:
  folder=target/('supplement-'+item['encryptedSha256'][:16]);folder.mkdir(mode=0o700)
  encrypted=folder/'downloaded.gpg';f=download_supplement(f,item,encrypted)
  if sha(encrypted)!=item['encryptedSha256']:raise RuntimeError('Supplement ciphertext SHA differs')
  plain=folder/'downloaded.tar';home=folder/'gnupg';home.mkdir(mode=0o700)
  subprocess.run(['gpg','--no-options','--homedir',str(home),'--batch','--pinentry-mode','loopback','--passphrase-file',str(KEY),'--decrypt','--output',str(plain),str(encrypted)],capture_output=True,check=True)
  result=restore_supplement_archive(plain,folder/'files',item)
  if item['schema'] in COMPLETENESS_SCHEMAS:result.update(fullyRecoverable=False,coverageVerified=False,knownGaps=item['knownGaps'])
  result.update(ciphertext=item['ciphertext'],parentManifestId=parent['manifestId'],receiptHmacVerified=True,actualDownloadDecryptVerified=True);results.append(result)
 return f,results

def publish_supplement_receipt(payload,parent,attempts=3,precommit_guard=None):
 def guard():
  if FREEZE.exists():raise RuntimeError('Offsite freeze prevents supplement receipt commit')
  ensure_source_fresh(parent['backupAt'],time.time())
  if precommit_guard is not None:precommit_guard()
 signed=sign_supplement(payload);verify_supplement(signed,parent);data=supplement_receipt_bytes(payload);name=payload['ciphertext']+'.receipt.json';partial=name+'.partial'
 for attempt in range(attempts):
  f=None
  try:
   guard()
   f=connect();verify_owner(f);listing=inventory(f);ensure_source_fresh(parent['backupAt'],time.time())
   if payload['schema'] in COMPLETENESS_SCHEMAS:verify_exact_parent_receipt(f,parent)
   elif verify(get_json(f,parent['bundle']+'.receipt.json'))!=parent:raise RuntimeError('Supplement parent changed before publication')
   if any(listing.get(n)!=size for n,size in supplement_objects(payload).items()):raise RuntimeError('Supplement ciphertext size differs before publication')
   if name in listing:
    if verify_supplement(get_json(f,name,SUPPLEMENT_RECEIPT_LIMIT),parent)!=payload:raise RuntimeError('Published supplement receipt differs')
    if partial in listing:
     if payload['schema'] in COMPLETENESS_SCHEMAS:
      received=bytearray()
      def collect(chunk):
       received.extend(chunk)
       if len(received)>len(data):raise RuntimeError('Duplicate completeness partial exceeds bound')
      f.retrbinary('RETR '+partial,collect,blocksize=65536)
      if not data.startswith(bytes(received)):raise RuntimeError('Duplicate completeness partial differs')
     elif verify_supplement(get_json(f,partial,SUPPLEMENT_RECEIPT_LIMIT),parent)!=payload:raise RuntimeError('Duplicate supplement receipt differs')
     f.delete(partial)
    return f
   clean={n:v for n,v in listing.items() if n not in {*supplement_objects(payload),partial}}
   confirmed=points(f,clean)
   existing=point_supplements(f,clean,confirmed).get(parent['bundle'],[])
   validate_supplement_set([*existing,payload])
   if sum(listing.values())-listing.get(partial,0)+len(data)>CAP:raise RuntimeError('Supplement receipt exceeds shared capacity')
   guard();upload_bytes(f,partial,data)
   if verify_supplement(get_json(f,partial,SUPPLEMENT_RECEIPT_LIMIT),parent)!=payload:raise RuntimeError('Supplement staged receipt differs')
   guard();f.rename(partial,name)
   if verify_supplement(get_json(f,name,SUPPLEMENT_RECEIPT_LIMIT),parent)!=payload:raise RuntimeError('Supplement receipt readback differs')
   return f
  except (OSError,EOFError,ftplib.Error):
   if f:f.close()
   if attempt+1==attempts:raise
   time.sleep(1)
  except Exception:
   if f:f.close()
   raise
 raise RuntimeError('Supplement publication exhausted retries')

def publish_helper_supplement(bundle):
 if FREEZE.exists():raise RuntimeError('Offsite freeze prevents supplement publication')
 if not NAME.fullmatch(bundle):raise RuntimeError('Invalid parent bundle')
 os.umask(0o077);ledger=WORK/'supplement-inflight.json';source=WORK/'supplement-source'
 with (WORK/'transfer.lock').open('a') as lock:
  wait_for_transfer_lock(lock)
  if (WORK/'upload-inflight.json').exists() or (WORK/'upload-preserved.json').exists():raise RuntimeError('Bulk transfer pending; supplement deferred')
  f=connect();completed=False;tmp=None
  try:
   reconcile_retention(f);listing=inventory(f)
   protected_supplement_path(WORK,True)
   if ledger.exists():protected_supplement_path(ledger)
   pending=json.loads(ledger.read_text()) if ledger.exists() else None
   if pending:
    if pending.get('schema')!='platform.ftps-supplement-ledger/v1' or pending['bundle']!=bundle:raise RuntimeError('Different supplement pending')
    parent=verify(pending['parentReceipt']);payload=pending['payload'];verify_supplement(sign_supplement(payload),parent,staged=payload['verifiedAt'] is None);tmp=pathlib.Path(pending['scratch']);cipher=tmp/'cipher.gpg'
    protected_supplement_path(tmp,True);protected_supplement_path(cipher)
    if tmp.parent!=WORK or not tmp.name.startswith('supplement-') or tmp.is_symlink() or tmp.stat().st_uid!=0 or tmp.stat().st_mode&0o077 or cipher.is_symlink() or cipher.stat().st_uid!=0 or cipher.stat().st_mode&0o077 or cipher.stat().st_size!=payload['encryptedBytes'] or sha(cipher)!=payload['encryptedSha256']:raise RuntimeError('Unsafe pending supplement spool')
    if verify(get_json(f,bundle+'.receipt.json'))!=parent:raise RuntimeError('Pending supplement parent changed')
   else:
    confirmed=points(f,listing);parent=next((p for p in confirmed if p['bundle']==bundle),None)
    if parent is None:raise RuntimeError('Parent recovery point not found')
    ensure_source_fresh(parent['backupAt'],time.time())
    if any(x['kind']=='host-recovery-helper-delta' for x in point_supplements(f,listing,confirmed)[bundle]):raise RuntimeError('Parent already has an authenticated helper supplement')
    protected_supplement_path(source,True)
    files=[]
    for root,dirs,names in os.walk(source,followlinks=False):
     for name in dirs:protected_supplement_path(pathlib.Path(root)/name,True)
     for name in names:
      p=pathlib.Path(root)/name;st=protected_supplement_path(p);relative=p.relative_to(source).as_posix()
      if not supplement_member_name(relative):raise RuntimeError('Unexpected supplement source name')
      files.append({'name':relative,'bytes':st.st_size,'sha256':sha(p)})
      if len(files)>SUPPLEMENT_MAX_FILES:raise RuntimeError('Supplement source count exceeds bound')
    files.sort(key=lambda item:item['name'])
    if sum(p['bytes'] for p in files)>SUPPLEMENT_LIMIT:raise RuntimeError('Supplement source exceeds bound')
    f.close();tmp=pathlib.Path(tempfile.mkdtemp(prefix='supplement-',dir=WORK));plain=tmp/'source.tar';cipher=tmp/'cipher.gpg';home=tmp/'gnupg';home.mkdir(mode=0o700)
    with tarfile.open(plain,'w:') as tar:
     for item in files:tar.add(source/item['name'],arcname=item['name'],recursive=False)
    subprocess.run(['gpg','--no-options','--homedir',str(home),'--batch','--yes','--pinentry-mode','loopback','--passphrase-file',str(KEY),'--symmetric','--cipher-algo','AES256','--compress-algo','none','--s2k-digest-algo','SHA512','--s2k-count','65011712','--output',str(cipher),str(plain)],capture_output=True,check=True)
    digest=sha(cipher);payload={'schema':SUPPLEMENT_SCHEMA,'status':'passed','kind':'host-recovery-helper-delta','parentManifestId':parent['manifestId'],'parentManifestDigest':parent['manifestDigest'],'parentReceiptSha256':hashlib.sha256(canonical(sign(parent))).hexdigest(),'parentEncryptedSha256':parent['encryptedSha256'],'backupAt':parent['backupAt'],'ciphertext':bundle+'.supplement-'+digest[:16]+'.tar.gpg','encryptedBytes':cipher.stat().st_size,'encryptedSha256':digest,'files':files,'verifiedAt':None}
    # Binding/size validation does not mean publication; status is never exposed before roundtrip.
    verify_supplement(sign_supplement(payload),parent,staged=True)
    pending={'schema':'platform.ftps-supplement-ledger/v1','bundle':bundle,'parentReceipt':sign(parent),'payload':payload,'scratch':str(tmp)};save(ledger,pending);f=connect()
   ensure_source_fresh(parent['backupAt'],time.time());listing=inventory(f)
   extras={payload['ciphertext'],payload['ciphertext']+'.receipt.json.partial',payload['ciphertext']+'.receipt.json'}
   points(f,{n:v for n,v in listing.items() if n not in extras})
   if any('.supplement-' in n and '.supplement-full-' not in n and n.startswith(bundle+'.') and n not in extras for n in listing):raise RuntimeError('Conflicting parent supplement')
   reserved={**payload,'verifiedAt':'9999-12-31T23:59:59.999999+00:00'}
   receipt_reservation=len(supplement_receipt_bytes(reserved))
   if sum(listing.values())+max(0,payload['encryptedBytes']-listing.get(payload['ciphertext'],0))+receipt_reservation>CAP:raise RuntimeError('Supplement complete point reservation exceeds capacity')
   f=upload_resilient(f,cipher,payload['ciphertext'],payload['encryptedBytes'],reserve_bytes=receipt_reservation)
   downloaded=tmp/'downloaded.gpg';f=download_resilient(f,payload['ciphertext'],downloaded,payload['encryptedBytes'])
   if sha(downloaded)!=payload['encryptedSha256']:raise RuntimeError('Actual supplement download SHA differs')
   restored_tar=tmp/'restored.tar';home=tmp/'gnupg'
   subprocess.run(['gpg','--no-options','--homedir',str(home),'--batch','--yes','--pinentry-mode','loopback','--passphrase-file',str(KEY),'--decrypt','--output',str(restored_tar),str(downloaded)],capture_output=True,check=True)
   restored=tmp/'verified-files'
   if restored.exists():
    protected_supplement_path(restored,True)
    for root,dirs,files in os.walk(restored,followlinks=False):
     for name in dirs:protected_supplement_path(pathlib.Path(root)/name,True)
     for name in files:protected_supplement_path(pathlib.Path(root)/name)
    shutil.rmtree(restored)
   result=restore_supplement_archive(restored_tar,restored,payload)
   if payload['verifiedAt'] is None:payload['verifiedAt']=now();pending['payload']=payload;save(ledger,pending)
   f.close();f=publish_supplement_receipt(payload,parent);listing=inventory(f);confirmed=points(f,listing)
   assert sum(listing.values())<=CAP
   cache_retention_index(confirmed);result.update(parentManifestId=parent['manifestId'],remoteBytes=sum(listing.values()),receipt=sign_supplement(payload),originalPointUnchanged=True)
   save(WORK/'supplement-proof.json',result);save(STATE/'ftps-supplement-proof.json',result,True);ledger.unlink();completed=True;print(json.dumps(result))
  finally:
   try:f.quit()
   except Exception:f.close()
   if completed and tmp:remove_supplement_scratch(tmp)

def points(f,listing):
 verify_owner(f)
 values=[];known={MARKER}
 for name,size in listing.items():
  if not name.endswith('.receipt.json') or '.supplement-' in name:continue
  value=verify(get_json(f,name));bundle=value.get('bundle','');objects=point_objects(value)
  if value.get('status')!='passed' or name!=bundle+'.receipt.json' or any(listing.get(k)!=v for k,v in objects.items()):raise RuntimeError('Invalid completed FTPS point')
  values.append(value);known.update([*objects,name])
 for attachments in point_supplements(f,listing,values).values():
  for item in attachments:known.update([*supplement_objects(item),item['ciphertext']+'.receipt.json'])
 if set(listing)-known:raise RuntimeError('Unknown or incomplete FTPS objects require bounded recovery before new upload')
 return sorted(values,key=lambda p:p['backupAt'],reverse=True)
def clean_interrupted(f):
 if (WORK/'supplement-inflight.json').exists():raise RuntimeError('Supplement pending; preserve all objects until controlled retry')
 if (WORK/'upload-preserved.json').exists():raise RuntimeError('Preserved incomplete FTPS upload requires controlled retry; no cleanup performed')
 if pathlib.Path('/var/lib/platform-ftps-resume/baseline/active.json').exists():raise RuntimeError('Protected operator upload adoption requires completion before cleanup')
 file=WORK/'upload-inflight.json'
 if not file.exists():return
 v=json.loads(file.read_text())
 if v.get('schema')=='platform.ftps-upload-ledger/v2':raise RuntimeError('Multipart upload pending; automatic retry preserves parts before retention')
 name=v['partial'];final=v['bundle'];receipt=final+'.receipt.json';listing=inventory(f)
 if not re.fullmatch(r'\.partial-[a-f0-9]{32}\.tar\.gpg',name) or not NAME.fullmatch(final):raise RuntimeError('Invalid interrupted upload ledger')
 # A published authenticated receipt is a complete point and must never be removed here.
 if receipt in listing:
  verify(get_json(f,receipt));file.unlink();return
 for candidate in [name,final,receipt+'.partial']:
  if candidate in listing:f.delete(candidate)
 file.unlink()
def assert_capacity(listing,size):
 if size<0 or any(v<0 for v in listing.values()) or sum(listing.values())+size+131072>CAP:raise RuntimeError('70,000,000,000-byte FTPS hard cap would be exceeded; existing verified points preserved')
def expired_points(confirmed,epoch):
 return [p for index,p in enumerate(confirmed) if index>=MAX_POINTS or epoch-datetime.datetime.fromisoformat(p['backupAt']).timestamp()>=MAX_AGE]
def reconcile_retention(f):
 journal=WORK/'retention-inflight.json'
 if not journal.exists():return []
 document=json.loads(journal.read_text())
 if document.get('schema')=='platform.ftps-retention-journal/v2':
  if document.get('folder')!=FOLDER or set(document)!={'schema','folder','groups'}:raise RuntimeError('Invalid grouped retention journal')
  removed=[]
  for group in document['groups']:
   p=verify(group['point']);attachments=[verify_supplement(x,p) for x in group['supplements']]
   validate_supplement_set(attachments)
   listing=inventory(f);receipt=p['bundle']+'.receipt.json'
   if receipt in listing and verify(get_json(f,receipt))!=p:raise RuntimeError('Retention parent receipt changed')
   for item in attachments:
    meta=item['ciphertext']+'.receipt.json'
    if meta in listing and verify_supplement(get_json(f,meta,SUPPLEMENT_RECEIPT_LIMIT),p)!=item:raise RuntimeError('Retention supplement changed')
    for object_name,object_size in supplement_objects(item).items():
     if object_name in listing:
      if listing[object_name]!=object_size:raise RuntimeError('Retention supplement size changed')
      f.delete(object_name)
    if meta in listing:f.delete(meta)
   for name,size in point_objects(p).items():
    if name in listing:
     if listing[name]!=size:raise RuntimeError('Retention part size changed')
     f.delete(name)
   if receipt in listing:f.delete(receipt)
   removed.append(p['manifestId'])
  journal.unlink();return removed
 if document.get('schema')!='platform.ftps-retention-journal/v1' or document.get('folder')!=FOLDER:raise RuntimeError('Invalid FTPS retention journal')
 removed=[]
 for signed in document['points']:
  p=verify(signed);bundle=p.get('bundle','')
  if not NAME.fullmatch(bundle):raise RuntimeError('Unsafe journal bundle')
  listing=inventory(f);receipt=bundle+'.receipt.json'
  if receipt in listing and verify(get_json(f,receipt))!=p:raise RuntimeError('Retention receipt changed after authorization')
  for name,size in point_objects(p).items():
   if name in listing:
    if listing[name]!=size:raise RuntimeError('Retention object size changed')
    f.delete(name)
  if receipt in listing:f.delete(receipt)
  removed.append(p['manifestId'])
 journal.unlink();return removed
def delete_points(f,selected):
 if not selected:return []
 listing=inventory(f);groups=[]
 for p in selected:
  _,attachments=group_objects(f,listing,p);groups.append({'point':sign(p),'supplements':[sign_supplement(a) for a in attachments]})
 save(WORK/'retention-inflight.json',{'schema':'platform.ftps-retention-journal/v2','folder':FOLDER,'groups':groups})
 return reconcile_retention(f)
def retain(f,reservation=0):
 listing=inventory(f);confirmed=points(f,listing);epoch=datetime.datetime.now(datetime.timezone.utc).timestamp()
 selected=expired_points(confirmed,epoch);selected_names={p['bundle'] for p in selected}
 after=sum(listing.values())-sum(sum(group_objects(f,listing,p)[0].values()) for p in selected)
 for p in reversed(confirmed[1:]):
  if after+reservation<=CAP:break
  if p['bundle'] not in selected_names:
   selected.append(p);selected_names.add(p['bundle']);after-=sum(group_objects(f,listing,p)[0].values())
 if after+reservation>CAP:raise RuntimeError('FTPS capacity cannot fit the new point while preserving the newest verified point')
 removed=delete_points(f,selected);listing=inventory(f);remaining=points(f,listing);cache_retention_index(remaining)
 return listing,remaining,removed
def ensure_source_fresh(backup_at,epoch):
 age=epoch-datetime.datetime.fromisoformat(backup_at.replace('Z','+00:00')).timestamp()
 if age>=MAX_AGE or age < -300:raise RuntimeError('Source backup is outside the14-day offsite recovery window')
def wait_for_transfer_lock(lock,timeout=14400):
 deadline=time.monotonic()+timeout
 while True:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);return
  except BlockingIOError:
   if time.monotonic()>=deadline:raise TimeoutError('Another FTPS transfer did not finish within four hours; this recovery point remains local')
   time.sleep(min(5,max(0,deadline-time.monotonic())))
def upload_resilient(f,encrypted,partial,size,attempts=5,reserve_bytes=131072):
 for attempt in range(attempts):
  try:
   listing=inventory(f);offset=listing.get(partial,0)
   if not 0<=offset<=size:raise RuntimeError('Partial upload exceeds exact ciphertext size')
   if sum(listing.values())+(size-offset)+reserve_bytes>CAP:raise RuntimeError('Resumed upload would exceed hard cap')
   if offset<size:
    with encrypted.open('rb') as stream:
     stream.seek(offset);f.storbinary(('APPE ' if offset else 'STOR ')+partial,stream,blocksize=1024*1024)
   f.voidcmd('TYPE I')
   if f.size(partial)!=size:raise RuntimeError('Resumed ciphertext size differs')
   return f
  except (OSError,EOFError,ftplib.Error):
   try:f.close()
   except Exception:pass
   if attempt+1==attempts:raise
   time.sleep(3);f=connect()
 raise RuntimeError('Upload attempts exhausted')
def download_resilient(f,partial,target,size,attempts=5):
 for attempt in range(attempts):
  try:
   received=0
   with target.open('wb') as output:
    def consume(chunk):
     nonlocal received
     received+=len(chunk)
     if received>size:raise RuntimeError('Downloaded ciphertext exceeds authenticated bound')
     output.write(chunk)
    f.retrbinary('RETR '+partial,consume,blocksize=1024*1024)
   if received!=size:raise RuntimeError('Downloaded ciphertext length differs')
   return f
  except (OSError,EOFError,ftplib.Error):
   try:f.close()
   except Exception:pass
   if attempt+1==attempts:raise
   time.sleep(3);f=connect()
 raise RuntimeError('Download attempts exhausted')
def main_v1():
 os.umask(0o077);WORK.mkdir(mode=0o700,parents=True,exist_ok=True)
 with (WORK/'transfer.lock').open('a') as lock:
  wait_for_transfer_lock(lock)
  if (WORK/'upload-preserved.json').exists():raise RuntimeError('Preserved incomplete FTPS upload requires controlled retry; no cleanup performed')
  if pathlib.Path('/var/lib/platform-ftps-resume/baseline/active.json').exists():raise RuntimeError('Protected operator upload adoption requires completion before cleanup')
  for stale in WORK.glob('transfer-*'):
   if stale.is_symlink() or not stale.is_dir() or stale.stat().st_uid!=0:raise RuntimeError('Unexpected FTPS scratch ownership')
   shutil.rmtree(stale)
  start=now();save(STATE/'ftps-last-attempt.json',{'status':'running','startedAt':start},True)
  candidates=[]
  for candidate in (d.DATA/'manifests').glob('manifest-*.json'):
   record=json.loads(candidate.read_text())
   if record.get('operation')=='backup' and record.get('scope',{}).get('kind')=='platform' and record.get('coverage',{}).get('complete'):candidates.append((record['createdAt'],candidate))
  manifest=sorted(candidates)[-1][1]
  source=d.verify(d.DATA,manifest.name);backup_at=json.loads(manifest.read_text())['createdAt'];ensure_source_fresh(backup_at,datetime.datetime.now(datetime.timezone.utc).timestamp());bundle='backup-'+source['manifestId']+'.tar.gpg'
  if not NAME.fullmatch(bundle):raise RuntimeError('Unsafe source manifest name')
  if shutil.disk_usage(WORK).free<source['artifactBytes']*4+10*1024**3:raise RuntimeError('Insufficient isolated FTPS spool/restore capacity')
  f=connect();reconcile_retention(f);clean_interrupted(f);listing=inventory(f);prior=points(f,listing)
  existing=next((p for p in prior if p['bundle']==bundle),None)
  if existing:
   listing,remaining,deleted=retain(f);existing=dict(existing);existing.update(remoteBytes=sum(listing.values()),retainedPointCount=len(remaining),deletedExpiredManifestIds=deleted)
   save(WORK/'latest-proof.json',existing);save(STATE/'ftps-proof.json',existing,True);save(STATE/'ftps-last-attempt.json',{'status':'passed','finishedAt':now(),'unchanged':True},True);f.quit();print(json.dumps({'status':'unchanged','manifestId':source['manifestId'],'remoteBytes':sum(listing.values()),'retainedPointCount':len(remaining)}));return
  f.quit()
  tmp=pathlib.Path(tempfile.mkdtemp(prefix='transfer-',dir=WORK));partial='.partial-'+uuid.uuid4().hex+'.tar.gpg';published=False;completed=False
  try:
   encrypted=tmp/'recovery.tar.gpg';gnupg=WORK/'gnupg';gnupg.mkdir(mode=0o700,exist_ok=True)
   common=['gpg','--no-options','--homedir',str(gnupg),'--batch','--yes','--pinentry-mode','loopback','--passphrase-file',str(KEY)]
   encryption=subprocess.Popen(common+['--symmetric','--cipher-algo','AES256','--compress-algo','none','--s2k-digest-algo','SHA512','--s2k-count','65011712','--output',str(encrypted)],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   try:
    with tarfile.open(fileobj=encryption.stdin,mode='w|',dereference=False) as tar:
     for rel in source['paths']:
      file=d.DATA/rel
      if not file.is_file() or file.is_symlink():raise RuntimeError('Unexpected source artifact')
      tar.add(file,arcname=rel,recursive=False)
   finally:encryption.stdin.close()
   if encryption.wait()!=0:raise RuntimeError('FTPS bundle encryption failed')
   size=encrypted.stat().st_size;digest=sha(encrypted);f=connect();reconcile_retention(f);clean_interrupted(f);listing,prior,predeleted=retain(f,size+131072)
   # Exact ciphertext size plus bounded signed receipt and ownership marker; all existing partials are counted.
   assert_capacity(listing,size)
   save(WORK/'upload-inflight.json',{'partial':partial,'bundle':bundle,'encryptedBytes':size,'encryptedSha256':digest,'startedAt':start})
   f=upload_resilient(f,encrypted,partial,size)
   downloaded=tmp/'downloaded.tar.gpg'
   f=download_resilient(f,partial,downloaded,size)
   if downloaded.stat().st_size!=size or sha(downloaded)!=digest:raise RuntimeError('Actual FTPS downloaded ciphertext differs')
   plain=tmp/'downloaded.tar';r=subprocess.run(common+['--decrypt','--output',str(plain),str(downloaded)],capture_output=True)
   if r.returncode:raise RuntimeError('Actual FTPS downloaded archive decryption failed')
   restore=tmp/'restore';restore.mkdir(mode=0o700);seen=set();total=0
   with tarfile.open(plain,'r:') as tar:
    for member in tar:
     if not member.isfile() or member.name not in source['paths'] or member.name in seen:raise RuntimeError('FTPS archive contains unexpected or duplicate member')
     seen.add(member.name);total+=member.size
     if total>source['artifactBytes']+16*1024**2:raise RuntimeError('FTPS extracted set exceeds bound')
     tar.extract(member,path=restore,filter='data')
   if seen!=set(source['paths']):raise RuntimeError('FTPS archive member set differs')
   for p in [restore,*restore.rglob('*')]:os.chown(p,1000,1000)
   restored=d.verify(restore,manifest.name)
   if restored!=source:raise RuntimeError('Actual FTPS restored signed artifact set differs')
   assert_restored_timestamp(restore,manifest.name,backup_at)
   ensure_source_fresh(backup_at,datetime.datetime.now(datetime.timezone.utc).timestamp())
   proof={'schema':'platform.ftps-recovery-point/v1','status':'passed','startedAt':start,'verifiedAt':now(),'backupAt':backup_at,'manifestId':source['manifestId'],'manifestDigest':source['manifestDigest'],'artifactCount':source['artifactCount'],'artifactBytes':source['artifactBytes'],'bundle':bundle,'encryptedBytes':size,'encryptedSha256':digest,'tlsVerified':True,'tlsName':'hstgr.io','endpoint':'92.113.28.106:21','remoteFolder':FOLDER,'outsidePublicHtml':True,'actualDownloadVerified':True,'decryptVerified':True,'manifestHmacVerified':True,'everyArtifactShaAndHmacVerified':True,'retentionDays':14,'maximumPoints':MAX_POINTS,'maximumRemoteBytes':CAP}
   receipt=canonical(sign(proof))
   if len(receipt)>131072:raise RuntimeError('FTPS receipt exceeds reserved bound')
   upload_bytes(f,bundle+'.receipt.json.partial',receipt)
   f.rename(partial,bundle);f.rename(bundle+'.receipt.json.partial',bundle+'.receipt.json');published=True
   current=inventory(f)
   if sum(current.values())>CAP:raise RuntimeError('FTPS hard cap verification failed')
   confirmed=points(f,current)
   if not any(p==proof for p in confirmed):raise RuntimeError('Published FTPS receipt differs')
   final,remaining,deleted=retain(f);deleted=predeleted+deleted
   proof.update(remoteBytes=sum(final.values()),retainedPointCount=len(remaining),deletedExpiredManifestIds=deleted)
   save(WORK/'latest-proof.json',proof);save(STATE/'ftps-proof.json',proof,True);save(STATE/'ftps-last-attempt.json',{'status':'passed','finishedAt':now()},True)
   (WORK/'upload-inflight.json').unlink();completed=True;print(json.dumps(proof))
  finally:
   try:f.quit()
   except Exception:f.close()
   if tmp.parent!=WORK or not tmp.name.startswith('transfer-'):raise RuntimeError('Unsafe FTPS restore scratch cleanup')
   if completed:shutil.rmtree(tmp)
   elif encrypted.exists():save(WORK/'upload-preserved.json',{'schema':'platform.ftps-preserved-upload/v1','ciphertext':str(encrypted),'partial':partial,'manifestId':source['manifestId'],'reason':'Incomplete upload retained for controlled retry'})
def validate_pending(v):
 if v.get('schema')!='platform.ftps-upload-ledger/v2' or not NAME.fullmatch(v.get('bundle','')):raise RuntimeError('Unsupported pending upload ledger')
 if v.get('manifestFile')!=v.get('manifestId','')+'.json' or v['bundle']!='backup-'+v.get('manifestId','')+'.tar.gpg':raise RuntimeError('Pending manifest name binding differs')
 cipher=pathlib.Path(v['ciphertext']);root=cipher.parent
 if root.parent!=WORK or not re.fullmatch('transfer-[a-zA-Z0-9_-]+',root.name) or root.is_symlink() or root.stat().st_uid!=0 or root.stat().st_mode&0o077:raise RuntimeError('Unsafe preserved multipart spool')
 if cipher.name!='recovery.tar.gpg' or cipher.is_symlink() or cipher.stat().st_uid!=0 or cipher.stat().st_mode&0o077 or cipher.stat().st_size!=v['encryptedBytes'] or sha(cipher)!=v['encryptedSha256']:raise RuntimeError('Preserved ciphertext authentication differs')
 point_objects({**v,'schema':'platform.ftps-recovery-point/v2'})
 for part in v['parts']:
  local=root/part['name']
  if local.is_symlink() or local.stat().st_size!=part['bytes'] or sha(local)!=part['sha256']:raise RuntimeError('Preserved part hash differs')
 return root,cipher
def create_multipart(source,manifest,backup_at):
 tmp=pathlib.Path(tempfile.mkdtemp(prefix='transfer-',dir=WORK));cipher=tmp/'recovery.tar.gpg';bundle='backup-'+source['manifestId']+'.tar.gpg'
 gnupg=WORK/'gnupg';gnupg.mkdir(mode=0o700,exist_ok=True)
 common=['gpg','--no-options','--homedir',str(gnupg),'--batch','--yes','--pinentry-mode','loopback','--passphrase-file',str(KEY)]
 encryption=subprocess.Popen(common+['--symmetric','--cipher-algo','AES256','--compress-algo','none','--s2k-digest-algo','SHA512','--s2k-count','65011712','--output',str(cipher)],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 try:
  with tarfile.open(fileobj=encryption.stdin,mode='w|',dereference=False) as tar:
   for rel in source['paths']:
    file=d.DATA/rel
    if not file.is_file() or file.is_symlink():raise RuntimeError('Unexpected source artifact')
    tar.add(file,arcname=rel,recursive=False)
 finally:encryption.stdin.close()
 if encryption.wait()!=0:raise RuntimeError('FTPS bundle encryption failed')
 parts=[]
 with cipher.open('rb') as stream:
  while True:
   first=stream.read(min(1024*1024,PART_BYTES))
   if not first:break
   name=bundle+'.part'+str(len(parts)).zfill(3);path=tmp/name;count=0;digest=hashlib.sha256()
   with path.open('xb') as output:
    chunk=first
    while chunk:
     output.write(chunk);digest.update(chunk);count+=len(chunk)
     if count==PART_BYTES:break
     chunk=stream.read(min(1024*1024,PART_BYTES-count))
   parts.append({'name':name,'bytes':count,'sha256':digest.hexdigest()})
 v={'schema':'platform.ftps-upload-ledger/v2','manifestId':source['manifestId'],'manifestDigest':source['manifestDigest'],'manifestFile':manifest.name,'backupAt':backup_at,'bundle':bundle,'ciphertext':str(cipher),'encryptedBytes':cipher.stat().st_size,'encryptedSha256':sha(cipher),'parts':parts,'startedAt':now(),'sourceVerification':sign({**source,'backupAt':backup_at})}
 save(WORK/'upload-inflight.json',v);return v

def main(resume_downloaded=False,expected=None):
 if expected is not None and FREEZE.exists():raise RuntimeError('Offsite freeze prevents native sync')
 if resume_downloaded and FREEZE.exists():raise RuntimeError('Operator offsite freeze prevents explicit download recovery')
 os.umask(0o077);WORK.mkdir(mode=0o700,parents=True,exist_ok=True)
 with (WORK/'transfer.lock').open('a') as lock:
  wait_for_transfer_lock(lock)
  if (WORK/'supplement-inflight.json').exists():raise RuntimeError('Preserve pending supplement before new bulk operation')
  if pathlib.Path('/var/lib/platform-ftps-resume/baseline/active.json').exists():raise RuntimeError('Protected operator adoption is still active')
  ledger=WORK/'upload-inflight.json';pending=json.loads(ledger.read_text()) if ledger.exists() else None
  if pending:
   if pending.get('schema')!='platform.ftps-upload-ledger/v2':raise RuntimeError('Legacy interrupted upload requires explicit operator recovery')
   tmp,cipher=validate_pending(pending);manifest=d.DATA/'manifests'/pending['manifestFile'];bound=verify(pending['sourceVerification']);source={k:v for k,v in bound.items() if k!='backupAt'}
   if bound['backupAt']!=pending['backupAt']:raise RuntimeError('Pending source timestamp binding differs')
   if source['manifestId']!=pending['manifestId'] or source['manifestDigest']!=pending['manifestDigest']:raise RuntimeError('Preserved source binding differs')
   backup_at=pending['backupAt']
  else:
   if resume_downloaded:raise RuntimeError('Explicit download recovery requires an existing pending ledger')
   if (WORK/'upload-preserved.json').exists():raise RuntimeError('Unmatched preserved upload requires operator recovery')
   current=current_local_point();manifest=d.DATA/'manifests'/(current['manifestId']+'.json');source=d.verify(d.DATA,manifest.name)
   if source['manifestId']!=current['manifestId'] or source['manifestDigest']!=current['manifestDigest']:raise RuntimeError('Current local recovery proof binding differs')
   backup_at=json.loads(manifest.read_text())['createdAt']
  if expected is not None and any(source[k]!=expected[k] for k in ['manifestId','manifestDigest']):raise RuntimeError('Frozen native sync selection differs before network')
  ensure_source_fresh(backup_at,time.time());bundle='backup-'+source['manifestId']+'.tar.gpg'
  if shutil.disk_usage(WORK).free<source['artifactBytes']*5+10*1024**3:raise RuntimeError('Insufficient bounded multipart recovery space')
  f=connect();completed=False;reused_verified_receipt=False
  try:
   reconcile_retention(f);listing=inventory(f)
   if not pending:
    prior=points(f,listing);existing=next((p for p in prior if p['bundle']==bundle),None)
    if existing:
     final,remaining,deleted=retain(f);proof=dict(existing);proof.update(remoteBytes=sum(final.values()),retainedPointCount=len(remaining),deletedExpiredManifestIds=deleted)
     save(WORK/'latest-proof.json',proof);save(STATE/'ftps-proof.json',proof,True);save(STATE/'ftps-last-attempt.json',{'status':'passed','finishedAt':now(),'unchanged':True},True);print(json.dumps(proof));return
    f.quit();pending=create_multipart(source,manifest,backup_at);tmp,cipher=validate_pending(pending);f=connect()
    listing,prior,predeleted=retain(f,pending['encryptedBytes']+131072)
   else:predeleted=[]
   listing=inventory(f);receipt_name=bundle+'.receipt.json';part_objects={p['name']:p['bytes'] for p in pending['parts']}
   if receipt_name in listing:
    confirmed=points(f,listing);proof=next(p for p in confirmed if p['bundle']==bundle)
    if proof['encryptedSha256']!=pending['encryptedSha256'] or proof.get('parts')!=pending['parts']:raise RuntimeError('Completed pending receipt binding differs')
    reused_verified_receipt=True
   else:
    filtered={k:v for k,v in listing.items() if k not in part_objects and k!=receipt_name+'.partial'};points(f,filtered)
    if any(listing.get(k,0)>size for k,size in part_objects.items()):raise RuntimeError('Remote part exceeds authenticated size')
    remaining=sum(size-listing.get(k,0) for k,size in part_objects.items())
    if sum(listing.values())+remaining+131072>CAP:raise RuntimeError('Multipart total would exceed hard cap')
    save(STATE/'ftps-last-attempt.json',{'status':'running','startedAt':pending['startedAt'],'manifestId':source['manifestId'],'format':'multipart-v2','partCount':len(pending['parts'])},True)
    if resume_downloaded:
     if any(listing.get(k)!=v for k,v in part_objects.items()):raise RuntimeError('Prior download recovery requires every complete remote part')
     combined=validate_downloaded(pending,tmp)
    else:
     for part in pending['parts']:
      f=upload_resilient(f,tmp/part['name'],part['name'],part['bytes'])
     combined=tmp/'downloaded.tar.gpg'
     with combined.open('wb') as output:
      for part in pending['parts']:
       downloaded=tmp/'part-download';f=download_resilient(f,part['name'],downloaded,part['bytes'])
       if sha(downloaded)!=part['sha256']:raise RuntimeError('Actual remote part hash differs')
       with downloaded.open('rb') as stream:shutil.copyfileobj(stream,output,1024*1024)
       downloaded.unlink()
     if combined.stat().st_size!=pending['encryptedBytes'] or sha(combined)!=pending['encryptedSha256']:raise RuntimeError('Reassembled ciphertext hash differs')
    plain=tmp/'downloaded.tar';common=['gpg','--no-options','--homedir',str(WORK/'gnupg'),'--batch','--yes','--pinentry-mode','loopback','--passphrase-file',str(KEY)]
    subprocess.run(common+['--decrypt','--output',str(plain),str(combined)],capture_output=True,check=True)
    restore=tmp/'restore'
    if restore.exists():shutil.rmtree(restore)
    restore.mkdir(mode=0o700);seen=set();total=0
    with tarfile.open(plain,'r:') as tar:
     for member in tar:
      if not member.isfile() or member.name not in source['paths'] or member.name in seen:raise RuntimeError('Unexpected multipart restored member')
      seen.add(member.name);total+=member.size
      if total>source['artifactBytes']+16*1024**2:raise RuntimeError('Restored size exceeds bound')
      tar.extract(member,path=restore,filter='data')
    if seen!=set(source['paths']):raise RuntimeError('Restored set incomplete')
    for p in [restore,*restore.rglob('*')]:os.chown(p,1000,1000)
    if d.verify(restore,manifest.name)!=source:raise RuntimeError('Actual restored signed artifacts differ')
    assert_restored_timestamp(restore,manifest.name,backup_at)
    ensure_source_fresh(backup_at,time.time())
    proof={'schema':'platform.ftps-recovery-point/v2','status':'passed','startedAt':pending['startedAt'],'verifiedAt':now(),'backupAt':backup_at,'manifestId':source['manifestId'],'manifestDigest':source['manifestDigest'],'artifactCount':source['artifactCount'],'artifactBytes':source['artifactBytes'],'bundle':bundle,'encryptedBytes':pending['encryptedBytes'],'encryptedSha256':pending['encryptedSha256'],'parts':pending['parts'],'maximumPartBytes':1_000_000_000,'tlsVerified':True,'tlsName':'hstgr.io','endpoint':'92.113.28.106:21','remoteFolder':FOLDER,'outsidePublicHtml':True,'actualDownloadVerified':True,'everyPartShaVerified':True,'decryptVerified':True,'manifestHmacVerified':True,'everyArtifactShaAndHmacVerified':True,'retentionDays':14,'maximumPoints':MAX_POINTS,'maximumRemoteBytes':CAP}
    receipt=canonical(sign(proof))
    if len(receipt)>131072:raise RuntimeError('Multipart receipt exceeds bound')
    f.close();f=publish_receipt(proof)
   current=inventory(f)
   if sum(current.values())>CAP or not any(p==proof for p in points(f,current)):raise RuntimeError('Published multipart point or cap differs')
   final,remaining,deleted=retain(f);proof.update(remoteBytes=sum(final.values()),retainedPointCount=len(remaining),deletedExpiredManifestIds=predeleted+deleted,reusedVerifiedReceipt=reused_verified_receipt,resumedPriorDownloadedCiphertext=resume_downloaded)
   save(WORK/'latest-proof.json',proof);save(STATE/'ftps-proof.json',proof,True);save(STATE/'ftps-last-attempt.json',{'status':'passed','finishedAt':now()},True)
   ledger.unlink();(WORK/'upload-preserved.json').unlink(missing_ok=True);completed=True;print(json.dumps(proof))
  finally:
   try:f.quit()
   except Exception:f.close()
   if pending:
    if completed:shutil.rmtree(tmp)
    else:save(WORK/'upload-preserved.json',{'schema':'platform.ftps-preserved-upload/v2','manifestId':pending['manifestId'],'ciphertext':pending['ciphertext'],'reason':'Incomplete multipart point retained for automatic retry'})

def assert_restored_timestamp(restore,manifest_name,backup_at):
 if json.loads((restore/'manifests'/manifest_name).read_text())['createdAt']!=backup_at:raise RuntimeError('Verified restored manifest timestamp differs from retention binding')

def current_local_point():
 proof=d.WORK/'latest-proof.json'
 for path in [d.WORK,proof]:
  if path.is_symlink() or path.stat().st_uid!=0 or path.stat().st_mode&0o022:raise RuntimeError('Local verified recovery proof is not root protected')
 value=json.loads(proof.read_text())
 if value.get('status')!='passed' or value.get('restoreVerified') is not True or value.get('manifestSignatureVerified') is not True or not NAME.fullmatch('backup-'+value.get('manifestId','')+'.tar.gpg') or not re.fullmatch('[a-f0-9]{64}',value.get('manifestDigest','')):raise RuntimeError('Current local verified recovery proof is invalid')
 return value

def run_latest():
 # Root's actual local-restore proof identifies the current signed full; raw metadata cannot redefine it.
 for turn in range(2):
  main();current=current_local_point();uploaded=json.loads((WORK/'latest-proof.json').read_text())
  if uploaded['manifestId']==current['manifestId'] and uploaded['manifestDigest']==current['manifestDigest']:return
 raise RuntimeError('Current locally verified backup was not uploaded; no latest-cycle success')

def cache_retention_index(confirmed):
 expiries=[datetime.datetime.fromisoformat(p['backupAt']).timestamp()+MAX_AGE for p in confirmed]
 save(INDEX,sign({'schema':'platform.ftps-retention-index/v1','observedAt':now(),'inventoryComplete':True,'pointCount':len(confirmed),'nextExpiryEpoch':min(expiries) if expiries else None}))
def expiry_check():
 cached=verify(json.loads(INDEX.read_text()))
 if cached.get('schema')!='platform.ftps-retention-index/v1':raise RuntimeError('Invalid authenticated expiry index schema')
 deadline=cached.get('nextExpiryEpoch')
 if cached.get('inventoryComplete') is True:
  if deadline is None:return {'status':'not-due','reason':'No completed remote points'}
  if not isinstance(deadline,(int,float)) or deadline<0:raise RuntimeError('Invalid authenticated expiry timestamp')
  if datetime.datetime.now(datetime.timezone.utc).timestamp()<deadline-300:return {'status':'not-due','nextExpiryEpoch':deadline}
 return retention_only(grace=300,expiry_deadline=deadline)
def retention_only(grace=0,expiry_deadline=None):
 os.umask(0o077);WORK.mkdir(mode=0o700,parents=True,exist_ok=True)
 with (WORK/'transfer.lock').open('a') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:
   overdue=expiry_deadline is not None and datetime.datetime.now(datetime.timezone.utc).timestamp()>=expiry_deadline
   proof={'status':'failed' if overdue else 'deferred','at':now(),'reason':'An active transfer holds the exclusive FTPS lock; expiry cleanup will retry','nextExpiryEpoch':expiry_deadline}
   save(STATE/'ftps-retention-proof.json',proof,True);print(json.dumps(proof));return
  f=connect()
  try:
   recovered=reconcile_retention(f);clean_interrupted(f);listing=inventory(f);confirmed=points(f,listing);epoch=datetime.datetime.now(datetime.timezone.utc).timestamp()
   selected=[p for p in confirmed if epoch+grace-datetime.datetime.fromisoformat(p['backupAt']).timestamp()>=MAX_AGE]
   removed=delete_points(f,selected);listing=inventory(f);confirmed=points(f,listing);cache_retention_index(confirmed)
   proof={'status':'passed','at':now(),'deletedExpiredManifestIds':recovered+removed,'remoteBytes':sum(listing.values()),'retainedPointCount':len(confirmed),'maximumAgeDays':14}
   save(STATE/'ftps-retention-proof.json',proof,True);print(json.dumps(proof))
  finally:
   try:f.quit()
   except Exception:f.close()
def native_select_latest():
 f=connect()
 try:
  listing=inventory(f);confirmed=points(f,listing)
  if not confirmed:raise RuntimeError('No authenticated remote recovery point')
  selected=max(confirmed,key=lambda p:(datetime.datetime.fromisoformat(p['backupAt']).timestamp(),p['manifestId']))
  ensure_source_fresh(selected['backupAt'],time.time())
  return {'manifestId':selected['manifestId'],'manifestDigest':selected['manifestDigest'],'bundle':selected['bundle'],'receiptSha256':hashlib.sha256(canonical(sign(selected))).hexdigest()}
 finally:
  try:f.quit()
  except Exception:f.close()

COMPLETENESS_MODULES={
 'completeness_producer':('/usr/local/libexec/completeness_producer.py','9f5b086d62e27e3dec2791d40b5a550296d7239133205f22b07563144d63c028'),
 'platform_completeness_publisher':('/usr/local/libexec/platform-completeness-publisher.py','bdec539bd2e1c77f16b60e667403ca4fc06327199adb8b6e6ef2a6c7f1c48ef5'),
}
_G16_NATIVE_DIR=pathlib.Path(__file__).resolve().parent/'platform-mounted-config-v5'/'native'
_g16_path=_G16_NATIVE_DIR/'g16_overlay_native.py'
_G16_NATIVE_SHA256='ae35f52e33cb03d1621a7b98ee897bdcf3723ad69dffe3ed48baff76d03e8581'
G16_PINS_SHA256='7c57d994d4b53fcea94dd3c0d495c64829043303149f12be06b14ce602c7b137'
_g16_info=_g16_path.lstat()
if _g16_path.is_symlink() or not stat.S_ISREG(_g16_info.st_mode) or _g16_info.st_uid!=0 or _g16_info.st_mode&0o022 or _g16_info.st_nlink!=1 or sha(_g16_path)!=_G16_NATIVE_SHA256:
 raise RuntimeError('g16 native dispatch module pin differs')
_g16_spec=importlib.util.spec_from_file_location('g16_overlay_native',_g16_path)
if _g16_spec is None or _g16_spec.loader is None:raise RuntimeError('g16 overlay native module is missing')
_g16_module=importlib.util.module_from_spec(_g16_spec);_g16_spec.loader.exec_module(_g16_module)
_g16_module.install(globals())

# G16 remains byte-for-byte pinned for retained historical points. G17 layers
# only the new 91-root variant over it; every signed parent receipt is still
# verified by the existing FTPS helper before its overlay can be read.
_G17_NATIVE_DIR=pathlib.Path(__file__).resolve().parent/'platform-mounted-config-g17'/'native'
_g17_path=_G17_NATIVE_DIR/'g16_overlay_native.py'
_G17_NATIVE_SHA256='45c7263951fde86bc064c425e9224c233ce73669d88b4aa1f0e02c81e2b5db60'
G17_PINS_SHA256='709879c17509cdb4a3dc82711dae013d15e4766481624e80b2b9be3b7c23c320'
_g17_info=_g17_path.lstat()
if (_g17_path.is_symlink() or not stat.S_ISREG(_g17_info.st_mode) or
        _g17_info.st_uid!=0 or _g17_info.st_mode&0o022 or _g17_info.st_nlink!=1 or
        sha(_g17_path)!=_G17_NATIVE_SHA256):
 raise RuntimeError('g17 native dispatch module pin differs')
_g17_spec=importlib.util.spec_from_file_location('g17_overlay_native',_g17_path)
if _g17_spec is None or _g17_spec.loader is None:raise RuntimeError('g17 overlay native module is missing')
_g17_module=importlib.util.module_from_spec(_g17_spec);_g17_spec.loader.exec_module(_g17_module)
_g17_module.install(globals())

# G18 adds the reduced 16-source overlay while G16/G17 readers remain pinned.
_G18_NATIVE_DIR=pathlib.Path(__file__).resolve().parent/'platform-mounted-config-g18'/'native'
_g18_path=_G18_NATIVE_DIR/'g16_overlay_native.py'
_G18_NATIVE_SHA256='044706e9e209566a0702c0310cc89c0a2fc924efa43c1e5cc5ebd6307679a012'
G18_PINS_SHA256='05653a50eb8963147e7fd9000bccdd6310d4d6a2a415171cabb22f6ef5e8258c'
_g18_info=_g18_path.lstat()
if (_g18_path.is_symlink() or not stat.S_ISREG(_g18_info.st_mode) or
        _g18_info.st_uid!=0 or _g18_info.st_mode&0o022 or _g18_info.st_nlink!=1 or
        sha(_g18_path)!=_G18_NATIVE_SHA256):
 raise RuntimeError('g18 native dispatch module pin differs')
_g18_spec=importlib.util.spec_from_file_location('g18_overlay_native',_g18_path)
if _g18_spec is None or _g18_spec.loader is None:raise RuntimeError('g18 overlay native module is missing')
_g18_module=importlib.util.module_from_spec(_g18_spec);_g18_spec.loader.exec_module(_g18_module)
_g18_module.install(globals())

def publish_source_overlay(bundle,v1_root_override=None,source_proof_override=None,*,generation='g16'):
 if os.geteuid()!=0 or not NAME.fullmatch(bundle):raise RuntimeError('Root exact g16 parent point required')
 if generation not in ('g16','g17','g18'):raise RuntimeError('Unknown overlay generation')
 candidate_dir={'g16':_G16_NATIVE_DIR,'g17':_G17_NATIVE_DIR,'g18':_G18_NATIVE_DIR}[generation]
 module_paths={
  'source_metadata_overlay_v3.py':candidate_dir/'source_metadata_overlay_v3.py',
  'stream-expired-cache-descriptor-actual.json':candidate_dir/'stream-expired-cache-descriptor-actual.json',
  'source_metadata_overlay_producer_g16.py':candidate_dir/'source_metadata_overlay_producer_g16.py',
  'mounted_config_sidecar_v5.py':candidate_dir/'mounted_config_sidecar_v5.py',
  'expected-sources.json':candidate_dir/'expected-sources.json',
 }
 # The signed g16 admission must carry this helper and the pinned module set.
 pins_name={'g16':'g16-pins.json','g17':'g17-pins.json','g18':'g18-pins.json'}[generation]
 pins_path=pathlib.Path('/usr/local/libexec')/pins_name
 if not pins_path.exists():
  pins_path=candidate_dir/pins_name
 if sha(pins_path)!={'g16':G16_PINS_SHA256,'g17':G17_PINS_SHA256,'g18':G18_PINS_SHA256}[generation]:raise RuntimeError('overlay pins document digest differs')
 pins=json.loads(pins_path.read_text())
 for name,path in module_paths.items():
  expected=pins['files'].get(name)
  info=path.lstat()
  if not expected or path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_nlink!=1 or sha(path)!=expected:
   raise RuntimeError('g16 producer/module pin differs')
 metadata_path=module_paths['source_metadata_overlay_v3.py']
 metadata_spec=importlib.util.spec_from_file_location('source_metadata_overlay_v3',metadata_path)
 if metadata_spec is None or metadata_spec.loader is None:raise RuntimeError('g16 metadata module is missing')
 metadata_module=importlib.util.module_from_spec(metadata_spec);sys.modules[metadata_spec.name]=metadata_module;metadata_spec.loader.exec_module(metadata_module)
 metadata_module.load_expiration_descriptor(module_paths['stream-expired-cache-descriptor-actual.json'])
 # Check and load the exact native publisher before its authority verifier runs.
 for name,(filename,digest) in COMPLETENESS_MODULES.items():
  path=pathlib.Path(filename);info=path.lstat()
  if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_nlink!=1 or sha(path)!=digest:
   raise RuntimeError('g16 authority publisher pin differs')
  ms=importlib.util.spec_from_file_location(name,path);loaded=importlib.util.module_from_spec(ms);sys.modules[name]=loaded;ms.loader.exec_module(loaded)
 publisher=sys.modules['platform_completeness_publisher']
 transfer_lock_path=publisher.STAGING/'transfer.lock'
 lock=os.open(transfer_lock_path,os.O_RDWR|os.O_NOFOLLOW)
 lock_info=os.fstat(lock)
 if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid!=0 or lock_info.st_mode&0o077 or lock_info.st_nlink!=1:
  os.close(lock);raise RuntimeError('g16 global transfer lock is unsafe')
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try:
  authority=publisher.verify_authority(sys.modules[__name__])
  capsule_path=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/state/host-recovery/host-recovery-current.tar.gz.gpg')
  capsule_proof=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/state/host-recovery/host-recovery-proof.json')
  source_proof=pathlib.Path(source_proof_override) if source_proof_override else pathlib.Path('/var/lib/platform-completeness-candidate-20260930/isolated-source-proof.json')
  def guard(payload=None):
   if FREEZE.exists():raise RuntimeError('g16 offsite publication frozen')
   if publisher.verify_authority(sys.modules[__name__])!=authority:raise RuntimeError('g16 publication authority drift')
   if payload is not None:
    if sha(capsule_path)!=payload['capsuleSha256'] or sha(capsule_proof)!=payload['capsuleProofSha256']:
     raise RuntimeError('g16 capsule/proof changed after source capture')
    observed=json.loads(capsule_proof.read_text())
    if observed.get('status')!='passed' or observed.get('encryptedSha256')!=payload['capsuleSha256']:
     raise RuntimeError('g16 current capsule proof no longer matches')
  guard()
  spec=importlib.util.spec_from_file_location('source_metadata_overlay_producer_'+generation,module_paths['source_metadata_overlay_producer_g16.py'])
  module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
  return module.publish_source_overlay(sys.modules[__name__],bundle,
   pathlib.Path('/home/platform_infrastructure/v1-fresh-data/src'),
   pathlib.Path(v1_root_override) if v1_root_override else pathlib.Path('/var/lib/platform-completeness-candidate-20260930/isolated-source-restored'),
   module_paths['expected-sources.json'],capsule_path,capsule_proof,
   WORK/('source-overlay-'+generation),KEY,source_proof,guard)
 finally:
  os.close(lock)

def publish_source_overlay_g17(bundle,v1_root_override=None,source_proof_override=None):
 return publish_source_overlay(bundle,v1_root_override,source_proof_override,generation='g17')

def publish_source_overlay_g18(bundle,v1_root_override=None,source_proof_override=None):
 return publish_source_overlay(bundle,v1_root_override,source_proof_override,generation='g18')

def publish_completeness(bundle):
 if os.geteuid()!=0 or not NAME.fullmatch(bundle):raise RuntimeError('Root exact completeness point required')
 # The signed admission pins this helper, which transitively pins both modules.
 for name,(filename,digest) in COMPLETENESS_MODULES.items():
  path=pathlib.Path(filename);info=path.lstat()
  if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_nlink!=1 or sha(path)!=digest:
   raise RuntimeError('Completeness module root/code binding differs')
  module_spec=importlib.util.spec_from_file_location(name,path)
  module=importlib.util.module_from_spec(module_spec);sys.modules[name]=module;module_spec.loader.exec_module(module)
 return sys.modules['platform_completeness_publisher'].publish(sys.modules[__name__],bundle)

if __name__=='__main__':
 if sys.argv[1:]==['--native-select-latest']:
  print(json.dumps(native_select_latest()));raise SystemExit(0)
 freeze=FREEZE
 if not sys.argv[1:] and freeze.exists():
  deadline=time.monotonic()+14400
  while freeze.exists():
   if time.monotonic()>=deadline:raise TimeoutError('Operator final-state freeze still active after four hours; local backup preserved')
   time.sleep(5)
  os.execv(sys.executable,[sys.executable,__file__])
 native_sync=len(sys.argv)==5 and sys.argv[1]=='--expected-manifest-id' and sys.argv[3]=='--expected-manifest-digest'
 expected={'manifestId':sys.argv[2],'manifestDigest':sys.argv[4]} if native_sync else None
 if native_sync and (not NAME.fullmatch('backup-'+expected['manifestId']+'.tar.gpg') or not re.fullmatch('[a-f0-9]{64}',expected['manifestDigest'])):raise SystemExit('Invalid native sync selection')
 supplement=len(sys.argv)==3 and sys.argv[1]=='--publish-helper-supplement'
 completeness=len(sys.argv)==3 and sys.argv[1]=='--publish-completeness'
 g16_overlay=len(sys.argv)==3 and sys.argv[1]=='--publish-source-overlay'
 g17_overlay=len(sys.argv)==3 and sys.argv[1]=='--publish-source-overlay-g17'
 g18_overlay=len(sys.argv)==3 and sys.argv[1]=='--publish-source-overlay-g18'
 maintenance=sys.argv[1:]==['--retention-only']
 recovery=sys.argv[1:]==['--resume-downloaded']
 if sys.argv[1:] and not maintenance and not recovery and not supplement and not completeness and not g16_overlay and not g17_overlay and not g18_overlay and not native_sync:raise SystemExit('Unknown or malformed FTPS helper action')
 try:
  if completeness:
   with pathlib.Path('/var/lib/platform-backup-schedule/operation.lock').open('a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);publish_completeness(sys.argv[2])
  elif supplement:
   with pathlib.Path('/var/lib/platform-backup-schedule/operation.lock').open('a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);publish_helper_supplement(sys.argv[2])
  elif g16_overlay:
   with pathlib.Path('/var/lib/platform-backup-schedule/operation.lock').open('a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);publish_source_overlay(sys.argv[2])
  elif g17_overlay:
   with pathlib.Path('/var/lib/platform-backup-schedule/operation.lock').open('a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);publish_source_overlay_g17(sys.argv[2])
  elif g18_overlay:
   with pathlib.Path('/var/lib/platform-backup-schedule/operation.lock').open('a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);publish_source_overlay_g18(sys.argv[2])
  elif native_sync:main(expected=expected)
  elif recovery:main(resume_downloaded=True)
  elif maintenance:retention_only()
  else:run_latest()
 except Exception as error:
  failure={'status':'failed','finishedAt':now(),'error':str(error)[:300]}
  save(STATE/('ftps-retention-proof.json' if maintenance else 'ftps-last-attempt.json'),failure,True);print(json.dumps(failure));raise
