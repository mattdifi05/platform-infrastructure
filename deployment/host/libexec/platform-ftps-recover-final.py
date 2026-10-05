#!/usr/bin/python3
import os,pathlib,json,subprocess,fcntl,datetime,shutil,hashlib
os.umask(0o077)
W=pathlib.Path('/var/lib/platform-ftps-recovery');W.mkdir(mode=0o700,exist_ok=True)
EXPECTED='manifest-scheduled-platform-20260928-012231-ee83d2'
DIGEST='3ddb2e7c92aa9bccddbacf30d3ef5cbf99163c35968aef562593e882a2827ac3'
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
with pathlib.Path('/var/lib/platform-backup-schedule/operation.lock').open('a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 state=subprocess.check_output(['systemctl','show','platform-backup-schedule.service','-p','ActiveState','-p','SubState','-p','MainPID','-p','Result','-p','ExecMainStatus'],text=True)
 fields=dict(line.split('=',1) for line in state.splitlines())
 if fields['MainPID']!='0' or fields['ActiveState'] not in ['inactive','failed']:raise RuntimeError('Original scheduler is not quiescent')
 ledger=json.loads(pathlib.Path('/var/lib/platform-ftps-backup/upload-inflight.json').read_text())
 if ledger['manifestId']!=EXPECTED or ledger['manifestDigest']!=DIGEST:raise RuntimeError('Unexpected final recovery point')
 for name,source in [('original-schedule-proof.json','/var/lib/platform-backup-schedule/last-attempt.json'),('original-ftps-error.log','/var/lib/platform-backup-schedule/ftps-offsite-encrypted-restore.log'),('original-upload-ledger.json','/var/lib/platform-ftps-backup/upload-inflight.json')]:
  target=W/name
  if not target.exists():shutil.copyfile(source,target);os.chmod(target,0o600)
 (W/'original-unit-state.json').write_text(json.dumps(fields))
 proof={'schema':'platform.ftps-publication-recovery/v1','status':'running','startedAt':now(),'manifestId':EXPECTED,'manifestDigest':DIGEST,'originalUnitResult':fields,'newCatalog':False,'bulkReupload':False,'bulkRedownload':False}
 (W/'proof.json').write_text(json.dumps(proof))
 with (W/'recovery.log').open('w') as log:
  result=subprocess.run(['python3','/usr/local/libexec/platform-ftps-backup.py','--resume-downloaded'],stdout=log,stderr=subprocess.STDOUT)
 proof.update(finishedAt=now(),exitCode=result.returncode,status='passed' if result.returncode==0 else 'failed')
 if result.returncode==0:
  latest=json.loads(pathlib.Path('/var/lib/platform-ftps-backup/latest-proof.json').read_text())
  if latest['manifestId']!=EXPECTED or latest['manifestDigest']!=DIGEST or not latest['resumedPriorDownloadedCiphertext'] or latest['artifactCount']!=69:raise RuntimeError('Recovery result binding differs')
  proof['ftpsProofSha256']=hashlib.sha256(pathlib.Path('/var/lib/platform-ftps-backup/latest-proof.json').read_bytes()).hexdigest()
 (W/'proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof));raise SystemExit(result.returncode)
