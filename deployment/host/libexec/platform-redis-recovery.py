#!/usr/bin/python3
"""Consistent per-instance Redis RDB export and isolated restore; only ciphertext is published."""
import sys; sys.path.insert(0,'/usr/local/libexec'); import platform_backup_safe_state as safe_state
import datetime,fcntl,hashlib,json,os,pathlib,re,shutil,subprocess,tarfile,tempfile,time,uuid
BASE=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime')
WORK=pathlib.Path('/var/lib/platform-redis-recovery');OUTPUT=BASE/'state/redis-recovery'
KEY=BASE/'critical/v1-local-private_confidential-backup-passphrase'
PROFILES=[{'name':'gf-redis','user':'platform','password':BASE/'secrets/redis_password.txt','ca':'/run/platform-db-tls/ca.crt'}, {'name':'students-beta-redis','user':'default','password':BASE/'state/students-beta-secrets/redis-password','ca':'/run/redis-tls/ca.crt'}]
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def run(args,timeout=120,input=None):
 r=subprocess.run(args,input=input,capture_output=True,timeout=timeout)
 if r.returncode:raise RuntimeError('Redis recovery subprocess failed: '+args[0]+' exit '+str(r.returncode)+((': '+r.stderr.decode(errors='replace')[-300:]) if args[:2]==['docker','cp'] else ''))
 return r.stdout

def cli(profile,args,timeout=30):
 return run(['docker','exec','-i',profile['name'],'redis-cli','--tls','--cacert',profile['ca'],'--sni',profile['name'],'-h','127.0.0.1','-p','6380','--user',profile['user'],'--askpass','--raw',*args],timeout,profile['password'].read_bytes().strip()+b'\n')
def counts(text):
 result={}
 for line in text.decode(errors='replace').splitlines():
  match=re.fullmatch(r'(db\d+):keys=(\d+),expires=(\d+),avg_ttl=(\d+)(?:,.*)?',line.strip())
  if match:result[match[1]]={'keys':int(match[2]),'expiringKeys':int(match[3])}
 return result
def restore(rdb,image,tmp):
 if not re.fullmatch(r'sha256:[a-f0-9]{64}',image):raise RuntimeError('Invalid pinned Redis image')
 target=tmp/('restore-'+uuid.uuid4().hex);target.mkdir(mode=0o700);os.chown(target,1000,1000)
 copied=target/'dump.rdb';shutil.copyfile(rdb,copied);os.chmod(copied,0o600);os.chown(copied,1000,1000)
 expected=sha(rdb)
 container='platform-redis-restore-'+uuid.uuid4().hex[:16]
 common=['docker','run','--pull','never','--network','none','--read-only','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','768m','--cpus','1','--log-driver','json-file','--log-opt','max-size=1m','--log-opt','max-file=2','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777','--mount','type=bind,src='+str(target)+',dst=/data']
 run(common+['--rm','--entrypoint','redis-check-rdb',image,'/data/dump.rdb'])
 created=False
 try:
  run(common+['-d','--name',container,'--entrypoint','redis-server',image,'--port','0','--unixsocket','/tmp/recovery.sock','--unixsocketperm','700','--dir','/data','--dbfilename','dump.rdb','--appendonly','no','--save','']);created=True
  ready=False
  for _ in range(30):
   r=subprocess.run(['docker','exec',container,'redis-cli','-s','/tmp/recovery.sock','--raw','PING'],capture_output=True,timeout=5)
   if r.returncode==0 and r.stdout.strip()==b'PONG':ready=True;break
   time.sleep(0.5)
  if not ready:raise RuntimeError('Isolated Redis restore did not become ready')
  restored=counts(run(['docker','exec',container,'redis-cli','-s','/tmp/recovery.sock','--raw','INFO','keyspace']))
  if sha(copied)!=expected:raise RuntimeError('Isolated restored RDB bytes changed')
  return {'rdbCheckPassed':True,'isolatedBootPassed':True,'network':'none','restoredDatabaseCounts':restored,'restoredRdbSha256':expected,'productionRestorePerformed':False}
 finally:
  if created:
   subprocess.run(['docker','stop','--time','10',container],capture_output=True,timeout=20)
   subprocess.run(['docker','rm',container],capture_output=True,timeout=20)
def publish(path,data):
 safe_state.write_json(path,data,True)

def main():
 os.umask(0o077);WORK.mkdir(mode=0o700,parents=True,exist_ok=True);os.close(safe_state.directory(OUTPUT,True))
 with (WORK/'capture.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);publish(OUTPUT/'last-attempt.json',{'status':'running','startedAt':now()})
  tmp=pathlib.Path(tempfile.mkdtemp(prefix='capture-',dir=WORK));payload=tmp/'payload';payload.mkdir(mode=0o700)
  try:
   profiles=[]
   for profile in PROFILES:
    started=now();source=json.loads(run(['docker','inspect',profile['name']]))[0]
    if not source['State']['Running']:raise RuntimeError('Redis source is not running')
    server=cli(profile,['INFO','server']).decode(errors='replace')
    if not re.search(r'^redis_version:8\.10\.2\s*$',server,re.M):raise RuntimeError('Redis source version differs from8.10.2')
    before=counts(cli(profile,['INFO','keyspace']));remote='/tmp/platform-recovery-'+uuid.uuid4().hex+'.rdb';rdb=payload/(profile['name']+'.rdb')
    try:
     cli(profile,['--rdb',remote],timeout=240)
     with rdb.open('wb') as output:
      copied=subprocess.run(['docker','exec',profile['name'],'cat',remote],stdout=output,stderr=subprocess.PIPE,timeout=60)
     if copied.returncode:raise RuntimeError('Redis exported RDB could not be read from its container namespace')
    finally:subprocess.run(['docker','exec',profile['name'],'rm','-f','--',remote],capture_output=True,timeout=15)
    if not rdb.is_file() or rdb.stat().st_size>256*1024**2 or rdb.open('rb').read(5)!=b'REDIS':raise RuntimeError('Redis RDB is invalid or exceeds bound')
    after=counts(cli(profile,['INFO','keyspace']));proof=restore(rdb,source['Image'],tmp)
    profiles.append({'container':profile['name'],'imageId':source['Image'],'startedAt':started,'capturedAt':now(),'file':rdb.name,'bytes':rdb.stat().st_size,'sha256':sha(rdb),'sourceCountsBefore':before,'sourceCountsAfter':after,**proof})
   manifest={'schema':'platform.redis-recovery/v1','capturedAt':now(),'consistency':'individual Redis instance RDB snapshots; no cross-database atomicity','instances':profiles};(payload/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
   archive=tmp/'redis-recovery.tar.gz'
   with tarfile.open(archive,'w:gz') as tar:
    for p in sorted(payload.iterdir()):tar.add(p,arcname=p.name,recursive=False)
   home=WORK/'gnupg';home.mkdir(mode=0o700,exist_ok=True);encrypted=tmp/'redis-recovery-current.tar.gz.gpg';decrypted=tmp/'decrypted.tar.gz'
   common=['gpg','--no-options','--homedir',str(home),'--batch','--yes','--pinentry-mode','loopback','--passphrase-file',str(KEY)]
   run(common+['--symmetric','--cipher-algo','AES256','--s2k-digest-algo','SHA512','--s2k-count','65011712','--output',str(encrypted),str(archive)])
   run(common+['--decrypt','--output',str(decrypted),str(encrypted)])
   if sha(archive)!=sha(decrypted):raise RuntimeError('Encrypted Redis recovery roundtrip differs')
   final=OUTPUT/encrypted.name;safe_state.copy_file(encrypted,final,True)
   proof={'schema':'platform.redis-recovery-proof/v1','status':'passed','verifiedAt':now(),'encryptedFile':final.name,'encryptedSha256':sha(encrypted),'encryptedBytes':encrypted.stat().st_size,'decryptRoundtripVerified':True,'allInstancesIsolatedRestoreVerified':True,'consistency':manifest['consistency'],'instances':profiles}
   publish(OUTPUT/'latest.json',proof);publish(OUTPUT/'last-attempt.json',{'status':'passed','finishedAt':now()});print(json.dumps(proof))
  except Exception as error:
   publish(OUTPUT/'last-attempt.json',{'status':'failed','finishedAt':now(),'error':str(error)[:300]});raise
  finally:shutil.rmtree(tmp)
if __name__=='__main__':main()
