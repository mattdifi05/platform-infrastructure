#!/usr/bin/python3
"""Operator retention for dedicated server repository, preserving signed restore anchor."""
import datetime,json,os,pathlib,subprocess,tempfile
BASE=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime');WORK=pathlib.Path('/var/lib/platform-backup-schedule')
IMAGE='sha256:32e8f7cdd40792105bbf5a50b497aa66a730de02f8c88151108cd23c1055d574'
def restic(args):
 cmd=['docker','run','--rm','--network','platform_infra_greenfield_platform_egress','--read-only','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','1g','--cpus','2','--pids-limit','128','--log-driver','json-file','--log-opt','max-size=5m','--log-opt','max-file=2','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777','-e','HOME=/tmp','-e','RESTIC_REPOSITORY=rclone:platform-onedrive:platform-infrastructure/restic','-e','RESTIC_PASSWORD_FILE=/run/password','-e','RCLONE_CONFIG=/rclone-config/rclone.conf','--mount','type=bind,src='+str(BASE/'critical/rclone')+',dst=/rclone-config,readonly','--mount','type=bind,src='+str(BASE/'critical/restic_password.txt')+',dst=/run/password,readonly','--entrypoint','restic',IMAGE,'--no-cache','--stuck-request-timeout','45s','-o','rclone.connections=2','-o','rclone.args=serve restic --stdio --timeout 45s --contimeout 10s --low-level-retries 3',*args]
 r=subprocess.run(cmd,capture_output=True,text=True)
 if r.returncode:raise RuntimeError('Offsite maintenance failed: '+r.stderr[-1500:])
 return r.stdout
snapshots=json.loads(restic(['--no-lock','snapshots','--json']));snapshots.sort(key=lambda x:x['time'],reverse=True)
valid=[s for s in snapshots if 'platform-backups' in s.get('tags',[]) and any(t.startswith('platform-manifest-id=') for t in s.get('tags',[]))]
if len(valid)<2:raise RuntimeError('Two manifest-bound offsite snapshots are required')
admission=json.loads((BASE/'local-private-backup/trust/admission.json').read_text());anchor=admission['payload']['resources']['offsite']['restore']['snapshotId']
keep={s['id'] for s in valid[:2]}|{anchor}
if not any(s['id']==anchor for s in snapshots):raise RuntimeError('Mandatory admission restore snapshot is missing')
if len(snapshots)>4096:raise RuntimeError('Offsite snapshot inventory exceeds bound')
# Match each retained snapshot with a successful producer receipt and the exact authenticated manifest digest.
reports=BASE/'local-private-backup/data/reports/offsite-backups'
receipts=[]
for p in reports.glob('*.json'):
 if p.stat().st_size<1024*1024:
  try:receipts.append(json.loads(p.read_text()))
  except ValueError:pass
for snap in valid[:2]:
 receipt=next((r for r in receipts if r.get('status')=='passed' and r.get('snapshotId')==snap['id']),None)
 if not receipt:raise RuntimeError('Retained snapshot lacks successful producer receipt')
 tags=snap.get('tags',[])
 if 'platform-manifest-id='+receipt['manifestId'] not in tags or 'platform-manifest-digest='+receipt['manifestDigest'] not in tags:raise RuntimeError('Offsite receipt binding differs')
# Authenticate the exact manifest read back from each remote snapshot using the existing HMAC verifier.
for snap in valid[:2]:
 manifest_id=next(t.split('=',1)[1] for t in snap['tags'] if t.startswith('platform-manifest-id='))
 remote_manifest=json.loads(restic(['--no-lock','dump',snap['id'],'/backups/manifests/'+manifest_id+'.json']))
 with tempfile.TemporaryDirectory(prefix='offsite-manifest-',dir=WORK) as tmp:
  os.chmod(tmp,0o700);os.chown(tmp,1000,1000);file=pathlib.Path(tmp)/'manifest.json';file.write_text(json.dumps(remote_manifest));os.chmod(file,0o600);os.chown(file,1000,1000)
  cmd=['docker','run','--rm','--network','none','--read-only','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges:true','--mount','type=bind,src='+str(file)+',dst=/manifest.json,readonly','--mount','type=bind,src='+str(BASE/'secrets/backup_signing_keys.txt')+',dst=/run/signing-keys,readonly','--entrypoint','node','sha256:6551adf9508adb25947f263b8cb7f84c23956f7c6d85b9c1d69bac3e2c242dee','--input-type=module','-e',"import {verifyOffsiteManifest} from '/opt/platform-infrastructure/scripts/local-private-docker-action-broker.mjs'; const {manifest}=verifyOffsiteManifest('/manifest.json','/run/signing-keys'); if(!manifest.coverage.complete) throw Error('incomplete'); console.log(manifest.signature.digest);"]
  result=subprocess.run(cmd,capture_output=True,text=True)
  expected=next(t.split('=',1)[1] for t in snap['tags'] if t.startswith('platform-manifest-digest='))
  if result.returncode or result.stdout.strip()!=expected:raise RuntimeError('Remote retained manifest authentication failed')
  expected_paths={'/backups/manifests/'+manifest_id+'.json'}
  for artifact in remote_manifest['artifacts']:
   for suffix in ['', '.sha256', '.sig.json']:expected_paths.add('/backups/'+artifact['path']+suffix)
  if set(snap.get('paths',[]))!=expected_paths:raise RuntimeError('Remote snapshot differs from signed manifest artifact set')
restic(['--no-lock','check'])
remove=[s['id'] for s in snapshots if s['id'] not in keep]
plan={'schema':'platform.offsite-retention-two/v1','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'namespace':'platform-onedrive:platform-infrastructure/restic','latestTwoSnapshotIds':[s['id'] for s in valid[:2]],'mandatoryAdmissionAnchor':anchor,'deleteSnapshotIds':remove,'deleteCount':len(remove),'applied':False}
WORK.mkdir(mode=0o700,exist_ok=True);(WORK/'offsite-retention-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
if remove:
 restic(['forget','--dry-run',*remove]);restic(['forget',*remove]);restic(['prune','--max-repack-size','0']);restic(['--no-lock','check'])
plan['applied']=True;(WORK/'offsite-retention-result.json').write_text(json.dumps(plan,indent=2)+'\n');print(json.dumps(plan))
