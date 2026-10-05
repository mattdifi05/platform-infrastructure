#!/usr/bin/python3
"""Restore the current encrypted Redis supplement into isolated disposable targets."""
import importlib.util,json,pathlib,shutil,subprocess,tarfile,tempfile,os
s=importlib.util.spec_from_file_location('b','/usr/local/libexec/platform-redis-recovery.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
os.umask(0o077);proof=json.loads((b.OUTPUT/'latest.json').read_text());encrypted=b.OUTPUT/'redis-recovery-current.tar.gz.gpg'
if proof.get('status')!='passed' or b.sha(encrypted)!=proof.get('encryptedSha256'):raise RuntimeError('Current encrypted Redis recovery proof differs')
tmp=pathlib.Path(tempfile.mkdtemp(prefix='saved-restore-',dir=b.WORK))
try:
 archive=tmp/'decrypted.tar.gz';home=b.WORK/'gnupg'
 b.run(['gpg','--no-options','--homedir',str(home),'--batch','--pinentry-mode','loopback','--passphrase-file',str(b.KEY),'--decrypt','--output',str(archive),str(encrypted)])
 expected={'manifest.json','gf-redis.rdb','students-beta-redis.rdb'};seen=set();total=0
 with tarfile.open(archive,'r:gz') as tar:
  for member in tar:
   if not member.isfile() or member.name not in expected or member.name in seen:raise RuntimeError('Unexpected Redis recovery archive member')
   total+=member.size
   if total>513*1024**2:raise RuntimeError('Redis recovery extraction exceeds bound')
   seen.add(member.name);tar.extract(member,path=tmp,filter='data')
 if seen!=expected:raise RuntimeError('Redis recovery archive incomplete')
 manifest=json.loads((tmp/'manifest.json').read_text())
 if manifest.get('schema')!='platform.redis-recovery/v1' or {p['container'] for p in manifest['instances']}!={'gf-redis','students-beta-redis'} or len(manifest['instances'])!=2:raise RuntimeError('Redis recovery manifest differs')
 results=[]
 for p in manifest['instances']:
  if p['file']!=p['container']+'.rdb':raise RuntimeError('Invalid Redis recovery filename')
  rdb=tmp/p['file']
  if rdb.stat().st_size!=p['bytes'] or b.sha(rdb)!=p['sha256']:raise RuntimeError('Decrypted Redis RDB hash differs')
  results.append({'container':p['container'],**b.restore(rdb,p['imageId'],tmp)})
 result={'schema':'platform.redis-saved-restore-proof/v1','status':'passed','verifiedAt':b.now(),'encryptedSha256':proof['encryptedSha256'],'actualSavedCiphertextRestored':True,'instances':results,'productionModified':False}
 b.publish(b.OUTPUT/'saved-restore-proof.json',result);print(json.dumps(result))
finally:shutil.rmtree(tmp)
