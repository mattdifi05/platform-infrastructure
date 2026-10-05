#!/usr/bin/python3
"""Additive encrypted local backup copy. Never forgets, prunes or deletes any backup."""
import sys; sys.path.insert(0,'/usr/local/libexec'); import platform_backup_safe_state as safe_state
import datetime,fcntl,hashlib,json,os,pathlib,secrets,shutil,subprocess,tempfile
BASE=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/local-private-backup')
DATA=BASE/'data/backups'
REPO=BASE/'repository-local'
WORK=pathlib.Path('/var/lib/platform-local-dedup')
PASSWORD=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/critical/local-restic-password')
SIGNING='/home/platform_infrastructure/v1-fresh-runtime/secrets/backup_signing_keys.txt'
CAPSULE=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/state/host-recovery')
CAPSULE_KEY=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase')
OPS='sha256:72aef4d30ba01f0e13242a2617c5f548600a1957fa075a1c341337e33290aa1e'
RESTIC='sha256:32e8f7cdd40792105bbf5a50b497aa66a730de02f8c88151108cd23c1055d574'

def digest(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def call(args):
 r=subprocess.run(args,capture_output=True,text=True)
 if r.returncode:raise RuntimeError('Isolated local backup command failed: '+r.stderr[-1500:])
 return r.stdout

def container(image,mounts,args,entrypoint):
 return ['docker','run','--rm','--network','none','--read-only','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','1g','--cpus','2','--pids-limit','128','--log-driver','json-file','--log-opt','max-size=10m','--log-opt','max-file=3','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=268435456,mode=1777',*sum((['--mount','type=bind,src='+str(src)+',dst='+dst+(',readonly' if ro else '')] for src,dst,ro in mounts),[]),'--entrypoint',entrypoint,image,*args]

def verify(root,manifest):
 args=container(OPS,[(root,'/backups',True),(SIGNING,'/run/signing-keys',True),('/usr/local/libexec/verify-local-dedup-input.mjs','/verify.mjs',True)],['/verify.mjs','/backups','/backups/manifests/'+manifest],'node')
 return json.loads(call(args))

def main():
 os.umask(0o077);WORK.mkdir(mode=0o700,exist_ok=True)
 with (WORK/'copy.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  manifests=[]
  for candidate in (DATA/'manifests').glob('manifest-*.json'):
   record=json.loads(candidate.read_text())
   if record.get('operation')=='backup' and record.get('scope',{}).get('kind')=='platform' and record.get('coverage',{}).get('complete'):manifests.append((record['createdAt'],candidate))
  manifests=[p for _,p in sorted(manifests)]
  if not manifests:raise RuntimeError('No completed platform manifest')
  manifest=manifests[-1];raw=json.loads(manifest.read_text())
  if not raw.get('coverage',{}).get('complete'):raise RuntimeError('Latest platform manifest is incomplete')
  capsule_proof=json.loads((CAPSULE/'host-recovery-proof.json').read_text())
  if capsule_proof.get('status')!='passed' or not capsule_proof.get('decryptRoundtripVerified'):raise RuntimeError('Host recovery capsule not verified')
  if digest(CAPSULE/'host-recovery-current.tar.gz.gpg')!=capsule_proof['encryptedSha256']:raise RuntimeError('Host capsule encrypted digest mismatch')
  if (WORK/'latest-proof.json').exists():
   previous=json.loads((WORK/'latest-proof.json').read_text())
   if previous.get('manifestDigest')==raw.get('signature',{}).get('digest') and previous.get('status')=='passed' and previous.get('capsuleEncryptedSha256')==capsule_proof['encryptedSha256'] and previous.get('capsuleDecryptVerified') is True:
    print(json.dumps({'status':'unchanged','manifestId':raw['id']}));return
  proof=verify(DATA,manifest.name)
  if shutil.disk_usage(BASE).free<proof['artifactBytes']*2+20*1024**3:raise RuntimeError('Insufficient reserve for isolated local copy and restore')
  if not PASSWORD.exists():
   with PASSWORD.open('x') as f:f.write(secrets.token_urlsafe(64)+'\n')
   os.chmod(PASSWORD,0o600);os.chown(PASSWORD,1000,1000)
  if PASSWORD.is_symlink() or PASSWORD.stat().st_mode&0o077:raise RuntimeError('Local repository key is not private')
  REPO.mkdir(mode=0o700,exist_ok=True);os.chmod(REPO,0o700);os.chown(REPO,1000,1000)
  tmp=pathlib.Path(tempfile.mkdtemp(prefix='copy-',dir=WORK));os.chown(tmp,1000,1000)
  try:
   listing=tmp/'files.txt';listing.write_text('\n'.join('/backups/'+p for p in proof['paths'])+'\n');os.chown(listing,1000,1000)
   def restic(args,extra=[]):
    mounts=[(REPO,'/repository',False),(PASSWORD,'/run/password',True),(DATA,'/backups',True),(tmp,'/work',False),(CAPSULE,'/recovery',True),*extra]
    return call(container(RESTIC,mounts,['--repo','/repository','--password-file','/run/password','--no-cache',*args],'restic'))
   if not (REPO/'config').exists():restic(['init'])
   result=restic(['backup','--json','--host','platform-infrastructure','--tag','platform-local-dedup','--tag','manifest='+proof['manifestId'],'--files-from','/work/files.txt'])
   summary=next(v for v in reversed([json.loads(x) for x in result.splitlines()]) if v.get('message_type')=='summary')
   snap=summary['snapshot_id'];restore=tmp/'restore';restore.mkdir(mode=0o700);os.chown(restore,1000,1000)
   restic(['restore',snap,'--target','/work/restore','--verify'])
   restored=verify(restore/'backups',manifest.name)
   if restored!=proof:raise RuntimeError('Restored local backup set differs')
   capsule_result=restic(['backup','--json','--host','platform-infrastructure','--tag','platform-host-recovery-capsule','/recovery/host-recovery-current.tar.gz.gpg','/recovery/host-recovery-proof.json'])
   capsule_summary=next(v for v in reversed([json.loads(x) for x in capsule_result.splitlines()]) if v.get('message_type')=='summary')
   restic(['restore',capsule_summary['snapshot_id'],'--target','/work/capsule-restore','--verify'])
   restored_capsule=tmp/'capsule-restore/recovery/host-recovery-current.tar.gz.gpg'
   restored_capsule_proof=json.loads((tmp/'capsule-restore/recovery/host-recovery-proof.json').read_text())
   if restored_capsule_proof!=capsule_proof or digest(restored_capsule)!=capsule_proof['encryptedSha256']:raise RuntimeError('Restored host capsule differs')
   gnupg=WORK/'gnupg';gnupg.mkdir(mode=0o700,exist_ok=True);plaintext=tmp/'capsule-decrypt-check.tar.gz'
   call(['gpg','--no-options','--homedir',str(gnupg),'--batch','--pinentry-mode','loopback','--passphrase-file',str(CAPSULE_KEY),'--decrypt','--output',str(plaintext),str(restored_capsule)])
   if digest(plaintext)!=capsule_proof['plaintextArchiveSha256']:raise RuntimeError('Restored host capsule decryption mismatch')
   repoBytes=sum(p.stat().st_size for p in REPO.rglob('*') if p.is_file())
   proof.update(schema='platform.local-dedup-copy/v1',status='passed',verifiedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),snapshotId=snap,repositoryBytes=repoBytes,dataAddedPacked=summary.get('data_added_packed'),restoreVerified=True,repositoryEncrypted=True,repositoryOffsite=False,existingBackupsDeleted=False,retentionApplied=False,capsuleSnapshotId=capsule_summary['snapshot_id'],capsuleDataAddedPacked=capsule_summary.get('data_added_packed'),capsuleEncryptedSha256=capsule_proof['encryptedSha256'],capsuleDecryptVerified=True)
   del proof['paths']
   safe_state.write_json(WORK/'latest-proof.json',proof)
   safe_state.write_json(pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/state/host-recovery/local-dedup-proof.json'),proof,True)
   print(json.dumps(proof))
  finally:
   if tmp.parent!=WORK or not tmp.name.startswith('copy-'):raise RuntimeError('Unsafe local restore scratch cleanup')
   shutil.rmtree(tmp)
if __name__=='__main__':main()
