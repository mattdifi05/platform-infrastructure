#!/usr/bin/python3
"""Restore a verified RustFS recovery archive to a new isolated, stopped target only."""
import datetime,importlib.util,json,os,pathlib,re,subprocess,sys,tarfile,tempfile
spec=importlib.util.spec_from_file_location('bridge','/usr/local/libexec/platform-rustfs-recovery.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)

def restore_archive(archive,proof_file,keep_target=True,require_native_admission=False,expected_image=None,expected_image_id=None):
 name=archive.name
 if archive.is_symlink() or proof_file.is_symlink():raise RuntimeError('Symlink archive rejected')
 proof=json.loads(proof_file.read_text())
 if proof.get('schema')!='platform.rustfs-operator-backup/v1' or proof.get('format')!='rustfs-volume/v1' or proof.get('image')!=b.IMAGE or proof.get('status')!='passed' or b.sha(archive)!=proof.get('encryptedArchiveSha256'):raise RuntimeError('Invalid RustFS archive binding')
 if require_native_admission and (proof.get('image')!=expected_image or proof.get('imageId')!=expected_image_id):raise RuntimeError('RustFS proof differs from frozen native image identity')
 if require_native_admission:b.checkpoint_admission(proof.get('imageId'))
 pinned=json.loads(b.run(['docker','image','inspect',b.IMAGE]))[0]
 if pinned['Id']!=proof.get('imageId'):raise RuntimeError('Isolated RustFS image ID differs from source proof')
 os.umask(0o077);work=pathlib.Path(tempfile.mkdtemp(prefix='isolated-restored-',dir=b.WORK));restore_name='platform-rustfs-restored-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S')
 plain=work/'data.tar.gz';created=False
 try:
  b.run(['gpg','--no-options','--homedir',str(b.WORK/'gnupg'),'--batch','--pinentry-mode','loopback','--passphrase-file',str(b.KEY),'--decrypt','--output',str(plain),str(archive)])
  if b.sha(plain)!=proof['plaintextArchiveSha256']:raise RuntimeError('Decrypted archive digest mismatch')
  total=0;entries=0
  with tarfile.open(plain,'r:gz') as tar:
   for member in tar:
    total+=member.size;entries+=1
    if total>32*1024**3 or entries>250001:raise RuntimeError('RustFS extraction bound exceeded')
    path=pathlib.PurePosixPath(member.name)
    if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0]!='data' or not(member.isfile() or member.isdir()):raise RuntimeError('Unsafe RustFS archive entry')
    tar.extract(member,path=work,filter='data')
  plain.unlink();data=work/'data'
  if b.tree(data)!=proof['filesystem'] or not(data/'.rustfs.sys').is_dir() or (data/'.minio.sys').exists():raise RuntimeError('Restored RustFS filesystem mismatch')
  for p in [data,*data.rglob('*')]:os.chown(p,10001,10001)
  logs=work/'logs';logs.mkdir(mode=0o700);os.chown(logs,10001,10001)
  args=['docker','run','-d','--name',restore_name,'--network','none','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','1g','--cpus','2','--pids-limit','128','--log-driver','json-file','--log-opt','max-size=10m','--log-opt','max-file=3','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777','--mount','type=bind,src='+str(data)+',dst=/data','--mount','type=bind,src='+str(logs)+',dst=/logs','--mount','type=bind,src='+str(b.SECRETS)+',dst=/run/recovery-secrets,readonly','-e','RUSTFS_VOLUMES=/data','-e','RUSTFS_ACCESS_KEY_FILE=/run/recovery-secrets/access','-e','RUSTFS_SECRET_KEY_FILE=/run/recovery-secrets/secret','-e','RUSTFS_CONSOLE_ENABLE=false','-e','RUST_LOG=warn',b.IMAGE]
  b.run(args);created=True;b.wait_ready(restore_name);inventory=b.inventory(restore_name)
  if inventory!=proof['s3Inventory']:raise RuntimeError('Restored RustFS S3 semantic inventory differs')
  b.run(['docker','stop','--timeout','60',restore_name],timeout=90)
  if b.inspect(restore_name)['State']['Running']:raise RuntimeError('Restored target failed to stop')
  created=False
  result={'schema':'platform.rustfs-existing-archive-restore/v1','status':'passed','verifiedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sourceArchive':name,'archiveSha256':b.sha(archive),'rustfsImage':b.IMAGE,'rustfsImageId':pinned['Id'],'isolatedTarget':restore_name,'restoredPath':str(data),'productionModified':False,'network':'none','s3Inventory':inventory,'targetStoppedAndPreserved':True}
  (work/'restore-proof.json').write_text(json.dumps(result,indent=2)+'\n')
  if not keep_target:b.run(['docker','rm',restore_name],timeout=90)
  result['targetRemoved']=not keep_target
  return result
 finally:
  if created:
   b.run(['docker','stop','--timeout','60',restore_name],timeout=90)
   b.run(['docker','rm',restore_name],timeout=90)

if __name__=='__main__':
 if len(sys.argv)!=2 or not re.fullmatch(r'rustfs-[0-9]{8}T[0-9]{6}Z\.tar\.gz\.gpg',sys.argv[1]):raise SystemExit('Pass exact RustFS archive basename')
 archive=b.OUTPUT/'archives'/sys.argv[1];proof=archive.with_name(archive.name.removesuffix('.tar.gz.gpg')+'.json');print(json.dumps(restore_archive(archive,proof)))
