#!/usr/bin/python3
"""Fresh root-native VPS authority and capture profile; never reads home authority."""
import importlib.util,json,os,pathlib,secrets,sys
here=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('runner',here/'platform-vps-backup-runner.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
def main():
 if os.geteuid()!=0 or len(sys.argv)!=1:raise RuntimeError('Fresh local root enrollment only')
 os.umask(0o077)
 for p in (b.CONFIG,b.WORK):
  if p.exists():raise RuntimeError('Existing VPS enrollment preserved')
  p.mkdir(mode=0o700)
 (b.WORK/'queue').mkdir(mode=0o700);os.chown(b.WORK/'queue',1000,1000)
 (b.WORK/'operations').mkdir(mode=0o700)
 rows=b.inspect()
 if len(rows)!=21:raise RuntimeError('Expected reviewed 21 infrastructure containers')
 vols={m['Name'] for r in rows for m in r['Mounts'] if m['Type']=='volume'}
 if len(vols)!=13:raise RuntimeError('Expected reviewed 13 persistent volumes')
 for p in (b.KEY,b.SIGNING):
  fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as f:f.write(secrets.token_urlsafe(64).encode() if p==b.KEY else secrets.token_bytes(64));f.flush();os.fsync(f.fileno())
 b.run(['openssl','genpkey','-algorithm','ED25519','-out',str(b.CONFIG/'authority-private.pem')]);os.chmod(b.CONFIG/'authority-private.pem',0o600)
 b.run(['openssl','pkey','-in',str(b.CONFIG/'authority-private.pem'),'-pubout','-out',str(b.CONFIG/'authority-public.pem')])
 roots=['/srv/platform-infrastructure','/etc/platform-infrastructure','/etc/cloudflared','/etc/systemd/system','/etc/docker','/etc/ufw','/etc/ssh','/etc/hostname','/etc/hosts','/etc/machine-id','/etc/fstab','/etc/netplan','/usr/local/libexec','/var/lib/platform-server-ai-admin','/var/lib/platform-vps-backup/queue','/var/lib/platform-vps-backup/operations']
 roots=[p for p in roots if pathlib.Path(p).exists()]
 if not all(x in roots for x in ('/srv/platform-infrastructure','/etc/platform-infrastructure','/etc/cloudflared')):raise RuntimeError('Required enrolled recovery roots absent')
 p={'hostname':b.HOST,'machineId':b.sha('/etc/machine-id'),'generation':1,'previousAdmissionSha256':'0'*64,'enrolledAt':b.now(),'pins':b.pins(rows),'volumeCount':len(vols),'captureRoots':roots,'productionRestoreAuthorized':False,'captureAuthorized':False,'pauseAuthorized':True,'offsiteAuthorized':False,'databaseRecovery':'native-online-logical','recoveryKeysCustodied':False}
 b.save(b.PROFILE,p)
 b.run(['openssl','pkeyutl','-sign','-inkey',str(b.CONFIG/'authority-private.pem'),'-rawin','-in',str(b.PROFILE),'-out',str(b.CONFIG/'profile.sig')])
 print(json.dumps({'enrolled':True,'containers':len(rows),'volumes':len(vols),'captureRoots':len(roots),'productionRestoreAuthorized':False,'captureAuthorized':False,'offsiteAuthorized':False}))
if __name__=='__main__':main()
