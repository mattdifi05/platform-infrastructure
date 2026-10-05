#!/usr/bin/python3
"""Operator trigger using unchanged admitted client image and original broker authorization."""
import json,pathlib,re,subprocess,sys
BASE=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/local-private-backup')

def invocation(entrypoint,args):
 original=json.loads(subprocess.check_output(['docker','inspect','gf-backup-scheduler']))[0]
 admission=json.loads((BASE/'trust/admission.json').read_text())
 if original['Image']!=admission['payload']['schedulerImageId']:raise RuntimeError('Original scheduler image is not the admitted identity')
 if original['State']['Running']:raise RuntimeError('Legacy scheduler must be stopped to prevent duplicate schedules')
 command=['docker','run','--rm','--network','none','--read-only','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','512m','--cpus','1','--pids-limit','128','--log-driver','json-file','--log-opt','max-size=10m','--log-opt','max-file=3','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777']
 allowed={str(BASE/'broker-runtime'):'/run/platform/docker-action-broker',str(BASE/'trust'):'/run/platform/docker-action-broker/client',str(BASE/'data/scheduler-logs'):'/var/log/platform',str(BASE/'data/backup-jobs'):'/var/lib/platform-backup-data/backup-jobs'}
 for mount in original['Mounts']:
  source=mount['Source'];dest=mount['Destination']
  if allowed.get(source)!=dest:raise RuntimeError('Unexpected scheduler mount')
  readonly=source in [str(BASE/'broker-runtime'),str(BASE/'trust')]
  command+=['--mount','type=bind,src='+source+',dst='+dest+(',readonly' if readonly else '')]
 for item in original['Config']['Env']:
  if item.split('=',1)[0]=='HOSTNAME':continue
  command+=['-e',item]
 return command+['--entrypoint',entrypoint,original['Image'],*args]

def main():
 args=sys.argv[1:]
 if not args:raise SystemExit('Typed operation required')
 if args[0]=='queue-control':
  if len(args)<2 or args[1] not in ['claim','finish','mark-unknown','acquire-lease','release-lease']:raise SystemExit('Unsupported queue operation')
  cmd=invocation('node',['/opt/platform-backup-scheduler/scripts/backup-queue-control.mjs',*args[1:],'--jobsDir','/var/lib/platform-backup-data/backup-jobs','--logDir','/var/log/platform'])
 elif args[0] in ['backup-platform-catalog','offsite-backup-restic','offsite-backup-ftps','offsite-restore-proof'] and len(args)==1:
  cmd=invocation('/opt/platform-backup-scheduler/backup-scheduler.sh',['--run',*args])
 elif args[0]=='execute-backup-job' and len(args)==3 and args[1]=='--jobFileName' and re.fullmatch('[a-z0-9][a-z0-9-]{15,127}\\.json',args[2]):
  cmd=invocation('/opt/platform-backup-scheduler/backup-scheduler.sh',['--run',*args])
 else:raise SystemExit('Unsupported typed operation or parameters')
 raise SystemExit(subprocess.run(cmd).returncode)
if __name__=='__main__':main()
