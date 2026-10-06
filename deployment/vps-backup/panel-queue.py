#!/usr/bin/python3
"""Consume the product's owner-authenticated queue within the VPS root profile.
Only full enrolled infrastructure backup and immutable isolated restore are allowed.
"""
import fcntl,importlib.util,json,os,pathlib,re,subprocess,sys
HERE=pathlib.Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('runner',HERE/'platform-vps-backup-runner.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
QUEUE=b.WORK/'queue'
CONTROL=HERE.parents[1]/'scripts/backup-queue-control.mjs'

def queue_command(*args):
 env=os.environ.copy();env.update(BACKUP_QUEUE_SHARED_UID='1000',BACKUP_QUEUE_SHARED_GID='1000')
 r=subprocess.run(['node',str(CONTROL),*args,'--jobsDir',str(QUEUE)],capture_output=True,env=env,timeout=60)
 if r.returncode:raise RuntimeError('Native queue lifecycle command failed')
 return r.stdout.decode().strip()

def main():
 if os.geteuid()!=0 or len(sys.argv)!=1:raise RuntimeError('Root queue consumer only')
 os.umask(0o077);b.private(b.WORK,True)
 p,_=b.profile()
 if not(p.get('captureAuthorized') and p.get('offsiteAuthorized')):return
 with (b.WORK/'operation.lock').open('a') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:return
  running=queue_command('claim')
  if not running:return
  jobpath=pathlib.Path(running);root=QUEUE/'running'
  if jobpath.parent!=root or not re.fullmatch('[a-z0-9][a-z0-9-]{15,127}\\.json',jobpath.name):raise RuntimeError('Unexpected claimed job path')
  fd=os.open(jobpath,os.O_RDONLY|os.O_NOFOLLOW)
  with os.fdopen(fd,'rb') as file:
   st=os.fstat(file.fileno())
   if st.st_uid!=1000 or st.st_mode&0o077 or st.st_nlink!=1 or st.st_size>131072:raise RuntimeError('Unexpected claimed job ownership')
   job=json.load(file)
  ident=job.get('id','')
  if ident!=jobpath.stem or not re.fullmatch('[a-z0-9][a-z0-9-]{15,127}',ident):raise RuntimeError('Claimed job identity changed')
  ledger=b.WORK/'operations';ledger.mkdir(mode=0o700,exist_ok=True);record=ledger/(ident+'.json')
  if record.exists():
   queue_command('mark-unknown','--jobId',ident,'--summary','Operation already has a persistent root outcome; reconcile before replay','--exitCode','74');return
  try:
   if job.get('schema')!='platform.backup-job/v1' or job.get('status')!='running' or job.get('scope')!={'kind':'platform','id':'platform'} or not job.get('requestedBy'):raise RuntimeError('Only authenticated full platform queue jobs are supported')
   wanted=sorted(b.enrolled_resources(p),key=lambda r:r['id'])
   if sorted(job.get('resources',[]),key=lambda r:r['id'])!=wanted:raise RuntimeError('Queue resource set differs from signed VPS profile')
   b.save(record,{'jobId':ident,'requestSha256':__import__('hashlib').sha256(b.canonical(job)).hexdigest(),'status':'running','startedAt':b.now(),'profileSha256':b.sha(b.PROFILE)})
   spec=importlib.util.spec_from_file_location('ftps',HERE/'ftps-sync.py');f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
   if job['operation']=='backup':b.capture();f.sync()
   elif job['operation']=='restore-drill':
    reference=job.get('sourceManifestPath','')
    if not re.fullmatch('manifests/manifest-vps-[a-z0-9-]+\\.json',reference):raise RuntimeError('Restore requires immutable native VPS manifest')
    f.restore_proof(pathlib.PurePosixPath(reference).stem)
   else:raise RuntimeError('Unsupported privileged queue operation')
   b.save(record,{**json.loads(record.read_text()),'jobId':ident,'status':'done','finishedAt':b.now(),'operation':job['operation']})
   queue_command('finish','--jobId',ident,'--status','done','--summary','Native VPS encrypted backup or isolated immutable restore verified','--exitCode','0')
  except Exception:
   b.save(record,{**(json.loads(record.read_text()) if record.exists() else {}),'jobId':ident,'status':'failed','finishedAt':b.now()})
   queue_command('finish','--jobId',ident,'--status','failed','--summary','Native VPS operation failed; protected root evidence retained','--exitCode','1')
   raise
if __name__=='__main__':
 try:main()
 except Exception as e:print(json.dumps({'status':'failed','error':str(e)[:200]}));sys.exit(1)
