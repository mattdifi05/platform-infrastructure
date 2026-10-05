#!/usr/bin/python3
import fcntl,importlib.util,json,pathlib,re,subprocess
BASE=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/local-private-backup/data/backup-jobs')
CLIENT='/usr/local/libexec/platform-admitted-backup-client.py'
WORK=pathlib.Path('/var/lib/platform-backup-schedule');WORK.mkdir(mode=0o700,exist_ok=True)
if not any((BASE/'queued').glob('*.json')):raise SystemExit(0)
with (WORK/'operation.lock').open('a') as lock:
 try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except BlockingIOError:raise SystemExit(0)
 def call(args):return subprocess.run(['python3',CLIENT,*args],capture_output=True,text=True)
 claimed=call(['queue-control','claim'])
 if claimed.returncode:raise SystemExit(claimed.returncode)
 name=pathlib.Path(claimed.stdout.strip()).name
 if not name:raise SystemExit(0)
 if not re.fullmatch('[a-z0-9][a-z0-9-]{15,127}\\.json',name):raise RuntimeError('Unsafe claimed queue filename')
 job_document=json.loads((BASE/'running'/name).read_text())
 spec=importlib.util.spec_from_file_location('schedule','/usr/local/libexec/platform-backup-schedule.py');schedule=importlib.util.module_from_spec(spec);spec.loader.exec_module(schedule)
 if job_document.get('operation')=='backup':
  try:schedule.run_phases(schedule.PRE,'manual-queue-preparation')
  except Exception:
   call(['queue-control','finish','--jobId',name[:-5],'--status','failed','--summary','Coherent state preparation failed before admitted backup execution','--exitCode','1'])
   raise
 result=call(['execute-backup-job','--jobFileName',name]);job=name[:-5]
 if result.returncode==74:
  final=call(['queue-control','mark-unknown','--jobId',job,'--summary','Original admitted broker outcome unknown; operator reconciliation required','--exitCode','74'])
 else:
  final=call(['queue-control','finish','--jobId',job,'--status','done' if result.returncode==0 else 'failed','--summary','Executed using unchanged admitted client and original broker','--exitCode',str(result.returncode)])
 print(json.dumps({'jobId':job,'clientExitCode':result.returncode,'queueExitCode':final.returncode}))
 if final.returncode==0 and result.returncode==0 and job_document.get('operation')=='backup':
  full=job_document.get('scope')=={'kind':'platform','id':'platform'}
  schedule.run_phases(([] if full else schedule.CATALOG)+schedule.POST,'manual-queue-offsite')
 raise SystemExit(final.returncode)
