#!/usr/bin/python3
"""MWF root operator orchestration; original signed broker retains local authorization."""
import sys; sys.path.insert(0,'/usr/local/libexec'); import platform_backup_safe_state as safe_state
import datetime,fcntl,json,os,pathlib,subprocess
WORK=pathlib.Path('/var/lib/platform-backup-schedule');STATE=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/state/host-recovery')
CLIENT='/usr/local/libexec/platform-admitted-backup-client.py'
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save(proof):
 for path in [WORK/'last-attempt.json',STATE/'schedule-proof.json']:
  safe_state.write_json(path,proof,path.parent==STATE)

PRE=[('ftps-age-retention',['python3','/usr/local/libexec/platform-ftps-backup.py','--retention-only']),('rustfs-consistent-recovery',['systemctl','start','platform-rustfs-recovery.service']),('redis-consistent-recovery',['systemctl','start','platform-redis-recovery.service']),('host-encrypted-capsule',['systemctl','start','platform-host-recovery.service'])]
CATALOG=[('signed-full-catalog',['python3',CLIENT,'backup-platform-catalog'])]
POST=[('local-dedup-restore',['systemctl','start','platform-local-dedup.service']),('local-retention-two',['python3','/usr/local/libexec/platform-backup-retention.py','--apply']),('signed-ftps-offsite-encrypted-restore',['python3',CLIENT,'offsite-backup-ftps']),('durable-volume-supplement',['python3','/usr/local/libexec/platform-durable-supplement.py'])]
def run_phases(phases,trigger='scheduled'):
 WORK.mkdir(mode=0o700,exist_ok=True)
 proof={'schema':'platform.backup-schedule/v2','startedAt':now(),'status':'running','trigger':trigger,'schedule':'Mon,Wed,Fri 03:05 Europe/Rome','offsite':'ftps','phases':[]};save(proof)
 try:
  for name,args in phases:
   proof['activePhase']=name;save(proof)
   with (WORK/(name+'.log')).open('w') as log:
    try:code=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT,timeout=300 if name=='ftps-age-retention' else None).returncode
    except subprocess.TimeoutExpired:code=124
   proof['phases'].append({'name':name,'exitCode':code,'finishedAt':now()});save(proof)
   if code and name=='ftps-age-retention':
    proof.setdefault('warnings',[]).append({'phase':name,'exitCode':code,'localBackupContinues':True});save(proof)
   elif code:raise RuntimeError(name+' failed with exit '+str(code))
  proof.update(status='passed',finishedAt=now());proof.pop('activePhase',None);save(proof)
 except Exception as exc:
  proof.update(status='failed',finishedAt=now(),error=str(exc));save(proof);raise
if __name__=='__main__':
 WORK.mkdir(mode=0o700,exist_ok=True)
 with (WORK/'operation.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);run_phases(PRE+CATALOG+POST)
