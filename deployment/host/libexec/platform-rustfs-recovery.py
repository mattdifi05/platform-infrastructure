#!/usr/bin/python3
"""Explicit operator RustFS recovery bridge; independent from signed legacy MinIO broker."""
import sys; sys.path.insert(0,'/usr/local/libexec'); import platform_backup_safe_state as safe_state
import datetime,fcntl,hashlib,hmac,importlib.util,json,os,pathlib,shutil,subprocess,tarfile,tempfile,time,signal,stat
CONTAINER='gf-rustfs'
IMAGE='rustfs/rustfs@sha256:8cc9801755448b71a786705ce76692c77e14936cccd87cf2fc31842e58f4d1ff'
VOLUME='platform_rustfs_data'
WORK=pathlib.Path('/var/lib/platform-rustfs-recovery')
OUTPUT=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/state/rustfs-recovery')
KEY=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase')
SECRETS=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/maintenance/20260927/rustfs-production/secrets')
PROBE='/usr/local/libexec/rustfs-s3-readonly-inventory.py'
CLIENT='platform/minio-test-client:20260927'
ADMISSION=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/local-private-backup/trust/admission.json')
JOB_CAPABILITY=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/local-private-backup/trust/docker_action_backup_job_execute')
CHECKPOINT_DOMAIN=b'platform-rustfs-checkpoint-v1\0'

def canonical(value):
 # Match the broker's canonical JSON number spelling for integral JSON floats.
 def normalized(item):
  if isinstance(item,float):
   if not item.is_integer():return item
   return int(item)
  if isinstance(item,list):return [normalized(v) for v in item]
  if isinstance(item,dict):return {k:normalized(v) for k,v in item.items()}
  return item
 return json.dumps(normalized(value),sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

def protected_bytes(path,limit=131072):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_mode&0o077 or before.st_size<1 or before.st_size>limit:raise RuntimeError('Checkpoint trust input is not a protected regular file')
  data=os.read(fd,before.st_size+1);after=os.fstat(fd)
  if len(data)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise RuntimeError('Checkpoint trust input changed while read')
  return data
 finally:os.close(fd)

def checkpoint_admission(image_id):
 admission=json.loads(protected_bytes(ADMISSION))
 if set(admission)!={'schema','payload','signature'} or admission['schema']!='platform.local-private-backup-admission/v2':raise RuntimeError('Native signed admission is unavailable')
 spec=importlib.util.spec_from_file_location('native_operator','/usr/local/libexec/platform-backup-operator.py');operator=importlib.util.module_from_spec(spec);spec.loader.exec_module(operator)
 operator.verify_signature(admission,operator.PUBLIC)
 payload=admission['payload'];objects=payload.get('resources',{});store=objects.get('objectStore',{})
 if store!={'backend':'rustfs','container':CONTAINER,'volume':VOLUME,'image':IMAGE,'imageId':image_id,'archiveFormat':'rustfs-volume/v1','rootMarker':'.rustfs.sys','restoreMode':'isolated-only'}:raise RuntimeError('RustFS checkpoint does not match admitted object store')
 if payload.get('generation',0)<1 or not isinstance(payload.get('generation'),int):raise RuntimeError('Invalid native generation')
 now=datetime.datetime.now(datetime.timezone.utc)
 if not(datetime.datetime.fromisoformat(payload['issuedAt'].replace('Z','+00:00'))<=now<=datetime.datetime.fromisoformat(payload['expiresAt'].replace('Z','+00:00'))):raise RuntimeError('Native admission expired')
 key=protected_bytes(JOB_CAPABILITY,4096)
 if hashlib.sha256(key).hexdigest()!=objects['capabilityFiles']['capability.backup.job.execute']['sha256']:raise RuntimeError('Checkpoint capability differs from admission')
 return hashlib.sha256(canonical(payload)).hexdigest(),key

def run(args,timeout=300):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if r.returncode:raise RuntimeError('Recovery command failed: '+args[0]+' exit '+str(r.returncode))
 return r.stdout

def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def inspect(name):return json.loads(run(['docker','inspect',name]))[0]

def inventory(name):
 args=['docker','run','--rm','--network','container:'+name,'--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','512m','--cpus','1','--pids-limit','64','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777','--mount','type=bind,src='+str(SECRETS)+',dst=/run/s3-secrets,readonly','--mount','type=bind,src='+PROBE+',dst=/probe.py,readonly','--entrypoint','python3',CLIENT,'/probe.py']
 return json.loads(run(args,timeout=1800))

def tree(root):
 records=[];total=0
 for p in sorted(root.rglob('*')):
  if p.is_symlink() or not(p.is_file() or p.is_dir()):raise RuntimeError('Unsupported object store data type')
  if len(records)>=250000:raise RuntimeError('Object store inventory exceeds entry bound')
  size=p.stat().st_size if p.is_file() else 0;total+=size
  if total>32*1024**3:raise RuntimeError('Object store data exceeds32GiB bridge bound')
  records.append([str(p.relative_to(root)),'file' if p.is_file() else 'dir',size,sha(p) if p.is_file() else None])
 return {'sha256':hashlib.sha256(json.dumps(records,separators=(',',':')).encode()).hexdigest(),'entries':len(records),'bytes':total}

def wait_ready(name):
 for _ in range(90):
  r=subprocess.run(['docker','exec',name,'curl','-fsS','http://127.0.0.1:9000/health/ready'],capture_output=True)
  if r.returncode==0:return
  time.sleep(1)
 raise RuntimeError('RustFS did not become ready')

def main():
 os.umask(0o077);WORK.mkdir(mode=0o700,exist_ok=True)
 with (WORK/'backup.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  start=datetime.datetime.now(datetime.timezone.utc);stamp=start.strftime('%Y%m%dT%H%M%SZ')
  live=inspect(CONTAINER)
  if live['Config']['Image']!=IMAGE or live['Config'].get('User') not in ['10001','10001:10001'] or not live['State']['Running']:raise RuntimeError('Unexpected live RustFS runtime identity')
  admitted_digest,_=checkpoint_admission(live['Image'])
  mounts=[m for m in live['Mounts'] if m['Destination']=='/data']
  if len(mounts)!=1 or mounts[0]['Type']!='volume' or mounts[0].get('Name')!=VOLUME:raise RuntimeError('Unexpected RustFS data volume')
  sourceRoot=pathlib.Path(mounts[0]['Source']);sourceSize=0;count=0
  for p in sourceRoot.rglob('*'):
   count+=1
   if count>250000 or p.is_symlink():raise RuntimeError('Unbounded or symlinked source inventory')
   if p.is_file():sourceSize+=p.stat().st_size
   if sourceSize>32*1024**3:raise RuntimeError('Bridge source size limit exceeded')
  if shutil.disk_usage(WORK).free < sourceSize*5+10*1024**3:raise RuntimeError('Insufficient free space for verified RustFS backup')
  if KEY.is_symlink() or KEY.stat().st_mode&0o077:raise RuntimeError('Recovery encryption key is not private')
  before=inventory(CONTAINER)
  tmp=pathlib.Path(tempfile.mkdtemp(prefix='snapshot-',dir=WORK));restoreName='platform-rustfs-restore-'+stamp.lower();targetCreated=False;pausedAt=None;downtime=0
  try:
   restart=WORK/'restart-needed.json'
   with restart.open('w') as f:
    json.dump({'containerId':live['Id'],'image':IMAGE},f);f.flush();os.fsync(f.fileno())
   pausedAt=time.monotonic()
   try:
    run(['docker','stop','--time','60',CONTAINER],timeout=90)
    if inspect(CONTAINER)['State']['Running']:raise RuntimeError('RustFS failed to quiesce')
    run(['docker','cp',CONTAINER+':/data',str(tmp/'data')],timeout=1800)
   finally:
    run(['docker','start',CONTAINER],timeout=90);wait_ready(CONTAINER)
    downtime=round(time.monotonic()-pausedAt,3)
    restart.unlink(missing_ok=True)
   source=tmp/'data'
   if not (source/'.rustfs.sys').is_dir() or (source/'.minio.sys').exists():raise RuntimeError('Not an unambiguous RustFS v1 volume')
   fingerprint=tree(source);archive=tmp/'rustfs-data.tar.gz'
   with tarfile.open(archive,'w:gz',dereference=False) as tar:tar.add(source,arcname='data')
   restored=tmp/'restored';restored.mkdir(mode=0o700)
   with tarfile.open(archive,'r:gz') as tar:
    for member in tar:
     name=pathlib.PurePosixPath(member.name)
     if name.is_absolute() or '..' in name.parts or not(member.isfile() or member.isdir()) or not name.parts or name.parts[0]!='data':raise RuntimeError('Unsafe RustFS archive member')
     tar.extract(member,path=restored,filter='data')
   if tree(restored/'data')!=fingerprint:raise RuntimeError('RustFS restored filesystem differs')
   for p in [restored/'data',*(restored/'data').rglob('*')]:os.chown(p,10001,10001)
   logs=tmp/'logs';logs.mkdir(mode=0o700);os.chown(logs,10001,10001)
   args=['docker','run','-d','--name',restoreName,'--network','none','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','1g','--cpus','2','--pids-limit','128','--log-driver','json-file','--log-opt','max-size=10m','--log-opt','max-file=3','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777','--mount','type=bind,src='+str(restored/'data')+',dst=/data','--mount','type=bind,src='+str(logs)+',dst=/logs','--mount','type=bind,src='+str(SECRETS)+',dst=/run/recovery-secrets,readonly','-e','RUSTFS_VOLUMES=/data','-e','RUSTFS_ACCESS_KEY_FILE=/run/recovery-secrets/access','-e','RUSTFS_SECRET_KEY_FILE=/run/recovery-secrets/secret','-e','RUSTFS_CONSOLE_ENABLE=false','-e','RUST_LOG=warn',IMAGE]
   run(args);targetCreated=True;wait_ready(restoreName)
   restoredInventory=inventory(restoreName)
   if restoredInventory!=before:raise RuntimeError('RustFS S3 semantic restore differs; writes may have raced pre-quiescence inventory')
   gnupg=WORK/'gnupg';gnupg.mkdir(mode=0o700,exist_ok=True);encrypted=tmp/'rustfs-data.tar.gz.gpg';decrypted=tmp/'decrypt-check.tar.gz'
   common=['gpg','--no-options','--homedir',str(gnupg),'--batch','--yes','--pinentry-mode','loopback','--passphrase-file',str(KEY)]
   run(common+['--symmetric','--cipher-algo','AES256','--s2k-digest-algo','SHA512','--s2k-count','65011712','--output',str(encrypted),str(archive)])
   run(common+['--decrypt','--output',str(decrypted),str(encrypted)])
   if sha(decrypted)!=sha(archive):raise RuntimeError('RustFS encrypted archive roundtrip differs')
   proof={'schema':'platform.rustfs-operator-backup/v1','backend':'rustfs','format':'rustfs-volume/v1','producerVersion':'1.0.0','sourceContainer':CONTAINER,'image':IMAGE,'imageId':live['Image'],'volume':VOLUME,'rootMarker':'.rustfs.sys','startedAt':start.isoformat(),'verifiedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'passed','quiescence':'graceful-stop-copy-immediate-restart','serviceInterruptionSeconds':downtime,'filesystem':fingerprint,'s3Inventory':restoredInventory,'restoreNetwork':'none','restoreBootVerified':True,'s3SemanticRestoreVerified':True,'encryptedArchiveSha256':sha(encrypted),'plaintextArchiveSha256':sha(archive),'encryptedBytes':encrypted.stat().st_size,'decryptRoundtripVerified':True,'signedBrokerCompatible':False,'restoreRoute':'root-operator-rustfs-v1','legacyMinioModified':False,'existingBackupsDeleted':False,'archive':'archives/rustfs-'+stamp+'.tar.gz.gpg'}
   archives=OUTPUT/'archives';os.close(safe_state.directory(OUTPUT,True));os.close(safe_state.directory(archives,True))
   destination=OUTPUT/proof['archive']
   if destination.exists():raise RuntimeError('Refusing snapshot overwrite')
   safe_state.copy_file(encrypted,destination,True)
   safe_state.write_json(archives/('rustfs-'+stamp+'.json'),proof,True)
   current_digest,key=checkpoint_admission(live['Image'])
   if current_digest!=admitted_digest:raise RuntimeError('Native admission changed during RustFS checkpoint')
   checkpoint={'schema':'platform.rustfs-checkpoint/v1','admissionSha256':admitted_digest,'createdAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'backend':'rustfs','proof':proof}
   safe_state.write_json(OUTPUT/'latest.native.json',{'payload':checkpoint,'hmacSha256':hmac.new(key,CHECKPOINT_DOMAIN+canonical(checkpoint),hashlib.sha256).hexdigest()},True)
   safe_state.write_json(OUTPUT/'latest.json',proof,True)
   safe_state.write_json(OUTPUT/'last-attempt.json',{'status':'passed','finishedAt':proof['verifiedAt']},True)
   print(json.dumps(proof))
  finally:
   if targetCreated:run(['docker','rm','-f',restoreName],timeout=90)
   if tmp.parent!=WORK or not tmp.name.startswith('snapshot-'):raise RuntimeError('Unsafe temporary recovery cleanup')
   shutil.rmtree(tmp)
def interrupted(signum,frame):raise RuntimeError('Recovery interrupted by shutdown signal')
if __name__=='__main__':
 for sig in [signal.SIGTERM,signal.SIGINT]:signal.signal(sig,interrupted)
 try:main()
 except Exception as error:
  os.close(safe_state.directory(OUTPUT,True))
  failure={'schema':'platform.rustfs-operator-backup-attempt/v1','status':'failed','finishedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'error':str(error)[:500]}
  safe_state.write_json(OUTPUT/'last-attempt.json',failure,True)
  print(json.dumps(failure));raise
