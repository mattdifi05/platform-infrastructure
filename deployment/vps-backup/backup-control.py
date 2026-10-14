"""Root-owned scalar switch subordinate to the existing signed backup admission."""
import hashlib,json,re,subprocess
SCHEMA='platform.backup-control/v1'
TIMERS=('platform-vps-backup.timer',)
QUEUE_TIMER='platform-vps-backup-queue.timer'
def state_path(b):return b.CONFIG/'backup-control.json'
def revision(b,body):return hashlib.sha256(b.canonical(body)).hexdigest()
def status(b,profile):
 available=isinstance(profile,dict) and profile.get('captureAuthorized') is True and profile.get('offsiteAuthorized') is True
 path=state_path(b)
 if not path.exists() and not path.is_symlink():
  return {'available':available,'enabled':available,'revision':revision(b,{'schema':SCHEMA,'legacyProfileSha256':b.sha(b.PROFILE) if profile else ''}),'updatedAt':'','requestId':''}
 value=json.loads(b.private(path).read_text())
 if not isinstance(value,dict) or set(value)!={'schema','enabled','revision','updatedAt','requestId'} or value['schema']!=SCHEMA or type(value['enabled']) is not bool or not isinstance(value['updatedAt'],str) or not isinstance(value['requestId'],str) or not isinstance(value.get('revision'),str) or not re.fullmatch('[a-f0-9]{64}',value.get('revision','')):raise RuntimeError('Invalid protected backup control state')
 body={k:v for k,v in value.items() if k!='revision'}
 if revision(b,body)!=value['revision']:raise RuntimeError('Backup control state revision differs')
 return {'available':available,'enabled':available and value['enabled'],'revision':value['revision'],'updatedAt':value['updatedAt'],'requestId':value['requestId']}
def require_enabled(b,profile):
 path=state_path(b)
 if profile and not path.exists() and not path.is_symlink():return  # Preserve enrolled local-only legacy capture too.
 if status(b,profile)['enabled'] is not True:raise RuntimeError('Backup capture and publication are disabled by root control')
def timer_loaded(timer):
 result=subprocess.run(['systemctl','show',timer,'--property=LoadState','--value'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
 return result.returncode==0 and result.stdout.strip()==b'loaded'
def timers(enabled):
 for timer in TIMERS:
  if not timer_loaded(timer):
   if enabled and timer=='platform-vps-backup.timer':raise RuntimeError('Native backup schedule is unavailable')
   continue
  result=subprocess.run(['systemctl','enable' if enabled else 'disable','--now',timer],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
  if result.returncode:raise RuntimeError('Backup schedule could not follow root control')
 # This existing worker is the control channel, including while capture is OFF.
 result=subprocess.run(['systemctl','enable','--now',QUEUE_TIMER],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 if result.returncode:raise RuntimeError('Backup control queue could not remain available')
def apply(b,profile,job):
 if type(job.get('backupEnabled')) is not bool or not isinstance(job.get('expectedControlRevision'),str) or not isinstance(job.get('id'),str) or not re.fullmatch('[a-f0-9]{64}',job.get('expectedControlRevision','')) or not re.fullmatch('[a-z0-9][a-z0-9-]{15,127}',job.get('id','')):raise RuntimeError('Invalid typed backup control request')
 before=status(b,profile)
 if job['expectedControlRevision']!=before['revision']:raise RuntimeError('Backup control revision changed; refresh before retry')
 enabled=job['backupEnabled']
 if enabled and not before['available']:raise RuntimeError('Signed backup admission does not authorize activation')
 body={'schema':SCHEMA,'enabled':enabled,'updatedAt':b.now(),'requestId':job['id']};value={**body,'revision':revision(b,body)}
 # OFF gates writes before stopping schedules. ON remains compensatable until
 # root persistence and catalog publication have both succeeded.
 if not enabled:
  b.save(state_path(b),value);timers(False);return status(b,profile)
 try:
  timers(True);b.save(state_path(b),value);return status(b,profile)
 except Exception:
  force_off(b,profile,job)
  raise

def force_off(b,profile,job):
 body={'schema':SCHEMA,'enabled':False,'updatedAt':b.now(),'requestId':job['id']};failures=[]
 try:b.save(state_path(b),{**body,'revision':revision(b,body)})
 except Exception:failures.append('persistent state')
 try:timers(False)
 except Exception:failures.append('schedules')
 if failures:raise RuntimeError('Backup control compensation incomplete: '+', '.join(failures)+'; root reconciliation required')
 return status(b,profile)

def apply_and_publish(b,profile,job):
 state=apply(b,profile,job)
 try:b.publish_catalog()
 except Exception:
  if job['backupEnabled']:force_off(b,profile,job)
  raise
 return state
