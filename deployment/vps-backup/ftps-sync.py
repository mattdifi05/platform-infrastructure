#!/usr/bin/python3
"""Native encrypted multipart FTPS publication for the dedicated VPS namespace."""
import contextlib,datetime,ftplib,hashlib,hmac,importlib.util,json,os,pathlib,re,ssl,sys,tempfile,time,shutil
HERE=pathlib.Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('vps_runner',HERE/'platform-vps-backup-runner.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
s=importlib.util.spec_from_file_location('shared_quota',HERE/'platform_ftps_shared_quota.py');q=importlib.util.module_from_spec(s);s.loader.exec_module(q)
FOLDER='/platform-server-public-backups'
CONFIG=pathlib.Path('/etc/platform-infrastructure/backup-vps/ftps-config.json')
OWNER='.platform-backup-owner.json'
PART=1_000_000_000
POINT=re.compile(r'backup-manifest-vps-[a-z0-9-]+\.tar\.gpg')

def sign(payload):return {'payload':payload,'hmacSha256':hmac.new(b.KEY.read_bytes(),b'platform-ftps-receipt-v1\n'+b.canonical(payload),hashlib.sha256).hexdigest()}
def authenticate(record):
 if set(record)!={'payload','hmacSha256'} or not hmac.compare_digest(sign(record['payload'])['hmacSha256'],record['hmacSha256']):raise RuntimeError('VPS receipt authentication failed')
 p=record['payload']
 if p.get('remoteFolder')!=FOLDER or p.get('host')!=b.HOST or not POINT.fullmatch(p.get('bundle','')):raise RuntimeError('Foreign recovery receipt')
 return p

def connect():
 c=q.protected_json(CONFIG)
 if c.get('host')!='92.113.28.106' or c.get('port')!=21 or c.get('tlsName')!='hstgr.io' or c.get('folder')!=FOLDER:raise RuntimeError('Unexpected VPS FTPS endpoint')
 f=ftplib.FTP_TLS(context=ssl.create_default_context(),timeout=90);f.connect(c['host'],c['port']);f.host=c['tlsName'];f.auth();f.login(c['username'],c['password']);f.prot_p();f.cwd(FOLDER)
 if f.pwd()!=FOLDER:raise RuntimeError('Unexpected VPS FTPS working directory')
 return f

def inventory(f):
 out={}
 for n,a in f.mlsd():
  if a.get('type') in ('cdir','pdir'):continue
  if a.get('type')!='file' or not n or '/' in n or '\\' in n or len(out)>=1024 or not str(a.get('size','')).isdigit():raise RuntimeError('Unexpected VPS archive inventory')
  out[n]=int(a['size'])
 return out

def read_json(f,name):
 data=bytearray()
 def append(chunk):
  data.extend(chunk)
  if len(data)>131072:raise RuntimeError('Remote receipt exceeds bound')
 f.retrbinary('RETR '+name,append);return json.loads(data)

def write_json(f,name,value):
 import io
 data=b.canonical(value);f.storbinary('STOR '+name,io.BytesIO(data))
 if read_json(f,name)!=value:raise RuntimeError('Remote JSON readback differs')

def ownership(f,listing,create=False):
 wanted={'schema':'platform.ftps-owner/v1','owner':b.HOST,'folder':FOLDER,'quotaBytes':q.LIMIT}
 if OWNER not in listing:
  if listing or not create:raise RuntimeError('VPS namespace lacks a verified owner marker')
  write_json(f,OWNER,wanted)
 elif read_json(f,OWNER)!=wanted:raise RuntimeError('VPS owner marker differs')

def points(f,listing):
 result=[];owned={OWNER}
 for name in listing:
  if not name.endswith('.receipt.json'):continue
  p=authenticate(read_json(f,name))
  if name!=p['bundle']+'.receipt.json' or p.get('schema')!='platform.ftps-recovery-point/v2' or p.get('actualDownloadVerified') is not True:raise RuntimeError('Incomplete recovery receipt')
  owned.add(name)
  parts=p.get('parts',[])
  if not 1<=len(parts)<=70:raise RuntimeError('Invalid multipart receipt')
  for i,part in enumerate(parts):
   expected=p['bundle']+'.part'+str(i).zfill(3)
   if part.get('name')!=expected or listing.get(expected)!=part.get('bytes') or not re.fullmatch('[a-f0-9]{64}',part.get('sha256','')):raise RuntimeError('Recovery point parts differ')
   owned.add(expected)
  result.append(p)
 if set(listing)-owned:raise RuntimeError('Uncommitted or foreign VPS objects require reconciliation; none deleted')
 return result

def sync_once():
 profile,_=b.profile()
 if profile.get('offsiteAuthorized') is not True:raise RuntimeError('FTPS activation gate is not open')
 proof=json.loads(b.private(b.WORK/'latest-local.json').read_text());bundle=b.WORK/'points'/proof['bundle'];b.private(bundle)
 if not POINT.fullmatch(bundle.name) or b.sha(bundle)!=proof['encryptedSha256'] or proof.get('encryptedRoundtripVerified') is not True:raise RuntimeError('Latest local encrypted point differs')
 with q.writer_budget(CONFIG,FOLDER) as cap:
  f=connect();tmp=pathlib.Path(tempfile.mkdtemp(prefix='ftps-',dir=b.WORK))
  try:
   listing=inventory(f);ownership(f,listing,create=True);listing=inventory(f);prior=points(f,listing)
   for p in prior:
    if p['manifestId']==proof['manifestId']:
     if p['encryptedSha256']!=proof['encryptedSha256']:raise RuntimeError('Remote manifest identity conflict')
     b.save(b.WORK/'latest-offsite.json',p);print(json.dumps({'status':'unchanged','manifestId':p['manifestId']}));return
   if sum(listing.values())+bundle.stat().st_size+131072>cap:raise RuntimeError('Combined quota cannot fit new point while preserving all verified points')
   parts=[]
   with bundle.open('rb') as src:
    index=0
    while True:
     chunk=tmp/'part';remaining=PART;h=hashlib.sha256();size=0
     with chunk.open('wb') as dst:
      while remaining:
       data=src.read(min(1024*1024,remaining))
       if not data:break
       dst.write(data);h.update(data);remaining-=len(data);size+=len(data)
     if not size:break
     name=bundle.name+'.part'+str(index).zfill(3);partial=name+'.partial'
     with chunk.open('rb') as data:f.storbinary('STOR '+partial,data,blocksize=1024*1024)
     # Each part is independently downloaded before atomic publication.
     check=hashlib.sha256();read=0
     def verify(data):
      nonlocal read
      check.update(data);read+=len(data)
     f.retrbinary('RETR '+partial,verify,blocksize=1024*1024)
     if check.hexdigest()!=h.hexdigest() or read!=size:raise RuntimeError('Uploaded part download verification differs')
     f.rename(partial,name);parts.append({'name':name,'bytes':size,'sha256':h.hexdigest()});index+=1
   restored=tmp/'downloaded.tar.gpg'
   with restored.open('wb') as out:
    for part in parts:f.retrbinary('RETR '+part['name'],out.write,blocksize=1024*1024)
   if b.sha(restored)!=proof['encryptedSha256']:raise RuntimeError('Downloaded complete ciphertext differs')
   plain=tmp/'downloaded.tar';b.gpg(['--decrypt','--output',str(plain),str(restored)]);b.verify_bundle(plain)
   if b.sha(plain)!=proof['plaintextSha256']:raise RuntimeError('Downloaded plaintext differs')
   point={'schema':'platform.ftps-recovery-point/v2','host':b.HOST,'status':'passed','verifiedAt':b.now(),'backupAt':proof['createdAt'],'manifestId':proof['manifestId'],'manifestDigest':proof['manifestDigest'],'bundle':bundle.name,'encryptedBytes':proof['encryptedBytes'],'encryptedSha256':proof['encryptedSha256'],'parts':parts,'maximumPartBytes':PART,'remoteFolder':FOLDER,'maximumRemoteBytes':q.LIMIT,'maximumPoints':2,'retentionDays':14,'artifactCount':proof['artifactCount'],'tlsVerified':True,'tlsName':'hstgr.io','endpoint':'92.113.28.106:21','outsidePublicHtml':True,'actualDownloadVerified':True,'decryptVerified':True,'manifestHmacVerified':True,'everyArtifactShaAndHmacVerified':True,'productionModified':False}
   # Reconnect after potentially slow decrypt; remote exclusion lease still held.
   f.close();f=connect();name=bundle.name+'.receipt.json';write_json(f,name+'.partial',sign(point));f.rename(name+'.partial',name)
   if authenticate(read_json(f,name))!=point:raise RuntimeError('Published receipt differs')
   b.save(b.WORK/'latest-offsite.json',point)
   # Only authenticated older points, only own namespace, only after verified replacement.
   existing=points(f,inventory(f));existing.sort(key=lambda p:p['backupAt'],reverse=True)
   cutoff=time.time()-14*86400
   for i,old in enumerate(existing):
    if old['bundle']==point['bundle']:continue
    if i<2 and datetime.datetime.fromisoformat(old['backupAt']).timestamp()>=cutoff:continue
    for part in old['parts']:f.delete(part['name'])
    f.delete(old['bundle']+'.receipt.json')
   remaining_points=points(f,inventory(f))
   b.publish_catalog(remaining_points)
   # Local retention is equally bounded and only runs after verified remote replacement.
   local=[]
   for meta in (b.WORK/'points').glob('backup-manifest-vps-*.tar.gpg.local.json'):
    item=json.loads(b.private(meta).read_text())
    if not POINT.fullmatch(item.get('bundle','')) or item.get('host')!=b.HOST:raise RuntimeError('Unexpected local retention record')
    local.append((item,meta))
   local.sort(key=lambda pair:pair[0]['createdAt'],reverse=True)
   for index,(old,meta) in enumerate(local):
    if old['bundle']==point['bundle']:continue
    if index<2 and datetime.datetime.fromisoformat(old['createdAt']).timestamp()>=cutoff:continue
    target=b.private(b.WORK/'points'/old['bundle'])
    if b.sha(target)!=old['encryptedSha256']:raise RuntimeError('Local retention ciphertext identity differs')
    target.unlink();meta.unlink()
   total=q.tree_bytes(f,q.FOLDERS[0])+q.tree_bytes(f,q.FOLDERS[1])
   if total>q.LIMIT:raise RuntimeError('Combined server quota exceeded')
   print(json.dumps({'status':'passed','manifestId':point['manifestId'],'parts':len(parts),'combinedServerBytes':total,'offsiteVerified':True}))
  finally:f.close();shutil.rmtree(tmp)
def sync():
 # Home and VPS keep independent schedules; bounded retry handles incidental overlap.
 for attempt in range(31):
  try:return sync_once()
  except q.SharedQuotaBusy:
   if attempt==30:raise
   time.sleep(60)

@contextlib.contextmanager
def downloaded_restore(manifest_id,expected_digest=None,scratch=None):
 # Read-only isolated restore, selected immutable manifest from authenticated portal queue.
 if not re.fullmatch('manifest-vps-[a-z0-9-]+',manifest_id):raise RuntimeError('Exact VPS manifest selection required')
 profile,_=b.profile()
 if profile.get('offsiteAuthorized') is not True:raise RuntimeError('FTPS activation gate is not open')
 with q.writer_budget(CONFIG,FOLDER):
  f=connect();tmp=pathlib.Path(scratch) if scratch is not None else pathlib.Path(tempfile.mkdtemp(prefix='restore-',dir=b.WORK))
  if scratch is not None:tmp.mkdir(mode=0o700)
  try:
   listing=inventory(f);ownership(f,listing)
   matches=[p for p in points(f,listing) if p['manifestId']==manifest_id]
   if len(matches)!=1:raise RuntimeError('Selected authenticated VPS restore point unavailable')
   point=matches[0];cipher=tmp/'restore.tar.gpg'
   if shutil.disk_usage(b.WORK).free<point['encryptedBytes']*3+1024**3:raise RuntimeError('Insufficient isolated restore reserve')
   with cipher.open('wb') as dest:
    for part in point['parts']:
     h=hashlib.sha256();size=0
     def receive(data):
      nonlocal size
      dest.write(data);h.update(data);size+=len(data)
     f.retrbinary('RETR '+part['name'],receive,blocksize=1024*1024)
     if h.hexdigest()!=part['sha256'] or size!=part['bytes']:raise RuntimeError('Downloaded restore part differs')
   if b.sha(cipher)!=point['encryptedSha256']:raise RuntimeError('Restore ciphertext differs')
   plain=tmp/'restore.tar';b.gpg(['--decrypt','--output',str(plain),str(cipher)]);b.verify_bundle(plain)
   import tarfile
   with tarfile.open(plain,'r:') as archive:manifest=json.load(archive.extractfile('manifest.json'))
   if manifest.get('id')!=manifest_id or manifest.get('signature',{}).get('digest')!=point['manifestDigest'] or (expected_digest and point['manifestDigest']!=expected_digest):raise RuntimeError('Downloaded manifest identity differs from selected point')
   proof={'status':'passed','manifestId':manifest_id,'manifestDigest':point['manifestDigest'],'receiptSha256':hashlib.sha256(b.canonical(sign(point))).hexdigest(),'actualDownloadVerified':True,'decryptVerified':True,'everyArtifactShaAndHmacVerified':True,'productionModified':False,'isolatedScratchRemoved':True,'verifiedAt':b.now()}
   f.close()
   yield plain,point,proof
  finally:f.close();shutil.rmtree(tmp)

def restore_proof(manifest_id):
 with downloaded_restore(manifest_id) as (_,_,proof):pass
 b.save(b.WORK/'latest-restore.json',proof);print(json.dumps(proof))

if __name__=='__main__':
 try:
  if os.geteuid()!=0 or not(len(sys.argv)==1 or (len(sys.argv)==3 and sys.argv[1]=='--restore-manifest-id')):raise RuntimeError('Root native FTPS typed operation required')
  import fcntl
  os.umask(0o077)
  with (b.WORK/'operation.lock').open('a') as lock:
   fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
   if len(sys.argv)==1:sync()
   else:restore_proof(sys.argv[2])
 except Exception as e:print(json.dumps({'status':'failed','error':str(e)[:250]}));sys.exit(1)
