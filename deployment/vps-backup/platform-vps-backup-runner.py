#!/usr/bin/python3
"""Root-native VPS capture, encrypted verification and separately gated FTPS sync.
No home paths, authority, project source, or production restore is accepted here.
"""
import base64,datetime,signal,fcntl,hashlib,hmac,importlib.util,json,os,pathlib,re,shutil,sqlite3,stat,subprocess,sys,tarfile,tempfile,time,uuid
HERE=pathlib.Path(__file__).resolve().parent
CONFIG=pathlib.Path('/etc/platform-vps-backup')
WORK=pathlib.Path('/var/lib/platform-vps-backup')
REPO=pathlib.Path('/srv/platform-infrastructure/first-install')
KEY=CONFIG/'encryption-key'
SIGNING=CONFIG/'manifest-key'
PROFILE=CONFIG/'profile.json'
ALLOW_PROJECTS={'platform_infra_vps','platform_server_ai'}
HOST='platform-server-public'
MAX_BYTES=70_000_000_000

def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(p):
 h=hashlib.sha256()
 with pathlib.Path(p).open('rb') as f:
  for data in iter(lambda:f.read(1024*1024),b''):h.update(data)
 return h.hexdigest()
def private(p,directory=False):
 p=pathlib.Path(p);s=p.lstat()
 if p.is_symlink() or s.st_uid!=0 or s.st_mode&0o077 or (not stat.S_ISDIR(s.st_mode) if directory else not stat.S_ISREG(s.st_mode)):raise RuntimeError('Private backup input is not root protected')
 return p

def save(p,v):
 p=pathlib.Path(p);tmp=p.with_name('.'+p.name+'-'+uuid.uuid4().hex)
 fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(canonical(v)+b'\n');f.flush();os.fsync(f.fileno())
 os.replace(tmp,p)

def run(args,timeout=300,output=None):
 # Command output may contain secrets. Never include stdout/stderr in exceptions.
 r=subprocess.run(args,stdout=output or subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 if r.returncode:raise RuntimeError('Native command failed: '+pathlib.Path(args[0]).name+' exit '+str(r.returncode))
 return r.stdout

def inspect():
 ids=run(['docker','ps','-q']).decode().split()
 if not ids or len(ids)>64:raise RuntimeError('Unexpected active container count')
 rows=json.loads(run(['docker','inspect',*ids]))
 if any((r['Config'].get('Labels') or {}).get('com.docker.compose.project') not in ALLOW_PROJECTS for r in rows):raise RuntimeError('Unclassified running container blocks capture')
 return sorted(rows,key=lambda r:r['Name'])

def pins(rows):return [{'name':r['Name'],'id':r['Id'],'image':r['Image'],'mounts':r['Mounts']} for r in rows]
def profile():
 private(CONFIG,True);private(PROFILE);private(KEY);private(SIGNING)
 p=json.loads(PROFILE.read_text());rows=inspect()
 if p.get('hostname')!=HOST or p.get('machineId')!=sha('/etc/machine-id') or p.get('pins')!=pins(rows):raise RuntimeError('Actual host/container identity differs from enrolled profile')
 if p.get('generation')!=1 or p.get('previousAdmissionSha256')!='0'*64:raise RuntimeError('Unexpected VPS genesis profile')
 # Fresh authority signature uses OpenSSL Ed25519, as the native admission does.
 run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(CONFIG/'authority-public.pem'),'-rawin','-in',str(PROFILE),'-sigfile',str(CONFIG/'profile.sig')])
 return p,rows

def archive(source,destination,arcname):
 with tarfile.open(destination,'w:',dereference=False) as out:
  def checked(info):
   if not(info.isfile() or info.isdir() or info.issym() or info.islnk()):raise RuntimeError('Unsupported persistent filesystem object')
   return info
  out.add(source,arcname=arcname,filter=checked)

def restore_archive_verify(path):
 # Validate archived member boundaries and read every byte before admission.
 count=0
 with tarfile.open(path,'r:') as t:
  for m in t:
   count+=1;p=pathlib.PurePosixPath(m.name)
   if count>500000 or p.is_absolute() or '..' in p.parts or not(m.isfile() or m.isdir() or m.issym() or m.islnk()):raise RuntimeError('Unsafe persistent archive member')
   if m.isfile():
    with t.extractfile(m) as f:
     read=0
     for b in iter(lambda:f.read(1024*1024),b''):read+=len(b)
     if read!=m.size:raise RuntimeError('Truncated persistent archive')
 return count

def gpg(args):
 home=WORK/'gnupg';home.mkdir(mode=0o700,exist_ok=True)
 run(['gpg','--no-options','--homedir',str(home),'--batch','--yes','--pinentry-mode','loopback','--passphrase-file',str(KEY),*args],timeout=7200)

def artifact_record(path,identity):
 digest=sha(path);signature=base64.urlsafe_b64encode(hmac.new(SIGNING.read_bytes(),('platform-postgres-backup-v1\n'+path.name+'\n'+digest+'\n').encode(),hashlib.sha256).digest()).decode().rstrip('=')
 save(path.with_name(path.name+'.sig.json'),{'version':1,'algorithm':'HMAC-SHA256','keyId':'vps-genesis-1','artifact':path.name,'sha256':digest,'signature':signature,'signedAt':now()})
 path.with_name(path.name+'.sha256').write_text(digest+'  '+path.name+'\n')
 return {'id':'artifact-'+identity,'resourceId':'platform-state:'+identity,'path':'artifacts/'+path.name,'sha256':sha(path),'sizeBytes':path.stat().st_size,'signatureKeyId':'vps-genesis-1'}

def capture():
 if (WORK/'paused.json').exists():raise RuntimeError('Prior pause journal must be reconciled before a new capture')
 p,rows=profile()
 # Fail before exporting secrets or pausing writers when a running image was removed.
 for image in sorted({r['Image'] for r in rows}):run(['docker','image','inspect',image])
 if p.get('captureAuthorized') is not True:raise RuntimeError('Local capture is not authorized in enrolled profile')
 stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ').lower();job='vps-'+stamp+'-'+uuid.uuid4().hex[:12]
 tmp=pathlib.Path(tempfile.mkdtemp(prefix='capture-',dir=WORK));art=tmp/'artifacts';art.mkdir(mode=0o700)
 paused=[];records=[];resources=[]
 def add(file,identity):
  records.append(artifact_record(file,identity));resources.append({'id':'platform-state:'+identity,'externalId':identity,'kind':'platform-state','projectId':'platform','name':identity})
 volumes={m['Name']:m['Source'] for r in rows for m in r['Mounts'] if m['Type']=='volume'}
 if len(volumes)!=p['volumeCount']:raise RuntimeError('Persistent volume count changed')
 if shutil.disk_usage(WORK).free<20*1024**3:raise RuntimeError('Insufficient protected capture reserve')
 try:
  # Profile contains explicit bounded roots; never infer personal/home paths.
  for root in p['captureRoots']:
   if not pathlib.Path(root).exists():raise RuntimeError('Required enrolled recovery root missing')
  runtime=tmp/'runtime';runtime.mkdir(mode=0o700)
  save(runtime/'containers.json',rows) # Encrypted only: includes runtime secret values.
  save(runtime/'profile.json',p)
  run(['docker','volume','inspect',*sorted(volumes)],output=(runtime/'volumes.json').open('wb'))
  run(['dpkg-query','-W','-f=${binary:Package}\t${Version}\n'],output=(runtime/'packages.tsv').open('wb'))
  # Logical exports supplement crash-consistent volume recovery.
  run(['docker','exec','enterprise-postgres','pg_dumpall','-U','postgres'],timeout=900,output=(runtime/'postgres-all.sql').open('wb'))
  run(['docker','exec','enterprise-mariadb','sh','-c','MYSQL_PWD="$(cat /run/secrets/mariadb_root_password)" exec mariadb-dump -uroot --all-databases --single-transaction --routines --events --triggers'],timeout=900,output=(runtime/'mariadb-all.sql').open('wb'))
  for file,marker in [(runtime/'postgres-all.sql',b'PostgreSQL database cluster dump complete'),(runtime/'mariadb-all.sql',b'Dump completed')]:
   with file.open('rb') as stream:
    stream.seek(max(0,file.stat().st_size-8192));tail=stream.read()
   if marker not in tail:raise RuntimeError('Native online database export lacks completion trailer')
  # Preserve live DB configuration/TLS as well as logical contents. Values stay encrypted.
  pgpaths={}
  for setting,name in [('hba_file','pg_hba.conf'),('ident_file','pg_ident.conf'),('config_file','postgresql.conf'),('data_directory','postgresql.auto.conf')]:
   source=run(['docker','exec','enterprise-postgres','psql','-U','postgres','-Atc','SHOW '+setting]).decode().strip()
   if not source.startswith('/') or '\n' in source or '..' in pathlib.PurePosixPath(source).parts:raise RuntimeError('Unexpected live PostgreSQL config path')
   if setting=='data_directory':source+='/postgresql.auto.conf'
   pgpaths[name]=source
   run(['docker','cp','enterprise-postgres:'+source,str(runtime/name)])
  save(runtime/'postgres-live-config-paths.json',pgpaths)
  tls=run(['docker','exec','enterprise-mariadb','sh','-c',"MYSQL_PWD=\"$(cat /run/secrets/mariadb_root_password)\" exec mariadb -uroot -N -B -e \"SHOW VARIABLES WHERE Variable_name IN ('ssl_ca','ssl_cert','ssl_key')\""]).decode().splitlines()
  tls_paths={}
  for line in tls:
   variable,source=line.split('\t',1)
   if not source:continue
   if variable not in ('ssl_ca','ssl_cert','ssl_key') or not source.startswith(('/var/lib/mysql/','/etc/','/run/')) or '..' in pathlib.PurePosixPath(source).parts:raise RuntimeError('Unexpected live MariaDB TLS path')
   run(['docker','cp','enterprise-mariadb:'+source,str(runtime/('mariadb-'+variable))]);tls_paths[variable]=source
  save(runtime/'mariadb-live-tls-paths.json',tls_paths)
  if p.get('pauseAuthorized') is not True:raise RuntimeError('Consistent filesystem capture requires explicit infrastructure pause authorization')
  pause_names={'gf-rustfs','enterprise-nats','enterprise-redis','enterprise-grafana','enterprise-prometheus','enterprise-loki','enterprise-alertmanager'}
  # Journal lets ExecStopPost recover only containers paused by this operation.
  save(WORK/'paused.json',{'containers':[],'operation':job})
  try:
   def expired(*_):raise TimeoutError('Non-database writer snapshot exceeded 30 seconds')
   signal.signal(signal.SIGALRM,expired);signal.alarm(30)
   for r in rows:
    if r['Name'].lstrip('/') not in pause_names:continue
    if r['State'].get('Paused'):raise RuntimeError('Container already paused by another operation')
    paused.append(r['Id']);save(WORK/'paused.json',{'containers':paused,'operation':job})
    run(['docker','pause',r['Id']],timeout=30)
   run(['sync'])
   for name,source in sorted(volumes.items()):
    if not re.fullmatch('[a-zA-Z0-9_-]+',name) or not source.startswith('/var/lib/docker/volumes/') or not source.endswith('/_data'):raise RuntimeError('Unexpected persistent volume boundary')
    target=art/(name+'.tar')
    if name in ('enterprise_postgres_data','enterprise_mariadb_data'):
     logical=runtime/('postgres-all.sql' if name=='enterprise_postgres_data' else 'mariadb-all.sql')
     with tarfile.open(target,'w:') as t:t.add(logical,arcname='logical/'+logical.name)
    else:archive(source,target,'data')
    add(target,'volume-'+name.replace('_','-'))
   signal.alarm(0)
   for ident in reversed(paused):run(['docker','unpause',ident],timeout=30)
   paused.clear();(WORK/'paused.json').unlink(missing_ok=True)
   # Native SQLite backup avoids relying on copying an active host database.
   db=pathlib.Path('/var/lib/platform-server-ai-admin/operations.sqlite')
   if db.exists():
    with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as src,sqlite3.connect(runtime/'admin-operations.sqlite') as dst:
     src.backup(dst)
     if dst.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise RuntimeError('Admin SQLite snapshot failed')
   target=art/'host-config.tar'
   with tarfile.open(target,'w:',dereference=False) as t:
    def filter_host(info):
     if info.name.startswith('host/var/lib/platform-server-ai-admin/operations.sqlite'):return None
     if not(info.isfile() or info.isdir() or info.issym() or info.islnk()):return None
     return info
    for source in p['captureRoots']:t.add(source,arcname='host/'+source.lstrip('/'),filter=filter_host)
    t.add(runtime,arcname='runtime')
   add(target,'host-config')
  finally:
   signal.alarm(0)
   failures=[]
   for ident in reversed(paused):
    try:run(['docker','unpause',ident],timeout=30)
    except Exception:failures.append(ident)
   if failures:save(WORK/'paused.json',{'containers':failures,'operation':job});raise RuntimeError('Some infrastructure containers still require unpause recovery')
   (WORK/'paused.json').unlink(missing_ok=True)
  # Include actual qualified image content, not merely mutable tag names.
  images=sorted({r['Image'] for r in rows})
  target=art/'images.tar';run(['docker','image','save','-o',str(target),*images],timeout=3600);add(target,'runtime-images')
  for item in records:restore_archive_verify(tmp/item['path'])
  seed={'jobId':job,'createdAt':now(),'resources':resources,'artifacts':records};save(tmp/'manifest-input.json',seed)
  manifest=tmp/'manifest.json'
  run(['node',str(HERE/'native-manifest.mjs'),'sign',str(tmp/'manifest-input.json'),str(SIGNING),str(manifest)])
  manifest_meta=json.loads(run(['node',str(HERE/'native-manifest.mjs'),'verify',str(manifest),str(SIGNING)]))
  plain=tmp/'complete.tar'
  with tarfile.open(plain,'w:') as t:
   t.add(manifest,arcname='manifest.json');t.add(art,arcname='artifacts')
  dest=WORK/'points'/('backup-'+manifest_meta['manifestId']+'.tar.gpg');dest.parent.mkdir(mode=0o700,exist_ok=True)
  gpg(['--symmetric','--cipher-algo','AES256','--compress-algo','none','--s2k-digest-algo','SHA512','--s2k-count','65011712','--output',str(dest),str(plain)])
  restored=tmp/'roundtrip.tar';gpg(['--decrypt','--output',str(restored),str(dest)])
  if sha(restored)!=sha(plain):raise RuntimeError('Encrypted archive restore differs')
  verify_bundle(restored)
  proof={'status':'passed','host':HOST,'createdAt':now(),**manifest_meta,'bundle':dest.name,'encryptedBytes':dest.stat().st_size,'encryptedSha256':sha(dest),'plaintextSha256':sha(plain),'imageCount':len(images),'containerCount':len(rows),'volumeCount':len(volumes),'artifactCount':len(records),'encryptedRoundtripVerified':True,'allArtifactHashesVerified':True,'semanticBootRestoreVerified':False,'offsiteVerified':False,'productionRestorePerformed':False,'databaseRecovery':'native-online-logical-dumps','dbRestartedOrPaused':False}
  (WORK/'manifests').mkdir(mode=0o700,exist_ok=True)
  save(WORK/'manifests'/(manifest_meta['manifestId']+'.json'),json.loads(manifest.read_text()))
  save(dest.with_suffix(dest.suffix+'.local.json'),proof);save(WORK/'latest-local.json',proof)
  print(json.dumps(proof))
 finally:
  # Plaintext only ever exists in the protected root scratch directory.
  if tmp.parent==WORK and tmp.name.startswith('capture-'):shutil.rmtree(tmp)

def verify_bundle(bundle):
 with tarfile.open(bundle,'r:') as t:
  members=t.getmembers();names=[m.name.rstrip('/') for m in members]
  if len(names)!=len(set(names)) or any(pathlib.PurePosixPath(n).is_absolute() or '..' in pathlib.PurePosixPath(n).parts for n in names):raise RuntimeError('Unsafe outer recovery bundle')
  m=t.extractfile('manifest.json').read();manifest=json.loads(m)
  scratch=pathlib.Path(tempfile.mkdtemp(prefix='verify-',dir=WORK))
  try:
   file=scratch/'manifest.json';file.write_bytes(m)
   run(['node',str(HERE/'native-manifest.mjs'),'verify',str(file),str(SIGNING)])
   wanted={'manifest.json','artifacts'}|{a['path']+suffix for a in manifest['artifacts'] for suffix in ('','.sig.json','.sha256')}
   if set(names)!=wanted:raise RuntimeError('Unmanifested recovery artifact')
   for a in manifest['artifacts']:
    member=t.getmember(a['path'])
    if not member.isfile() or member.size!=a['sizeBytes']:raise RuntimeError('Artifact type or size differs')
    h=hashlib.sha256()
    with t.extractfile(member) as f:
     for data in iter(lambda:f.read(1024*1024),b''):h.update(data)
    if h.hexdigest()!=a['sha256']:raise RuntimeError('Artifact integrity differs')
    side=json.load(t.extractfile(a['path']+'.sig.json'));name=pathlib.PurePosixPath(a['path']).name
    expected=base64.urlsafe_b64encode(hmac.new(SIGNING.read_bytes(),('platform-postgres-backup-v1\n'+name+'\n'+a['sha256']+'\n').encode(),hashlib.sha256).digest()).decode().rstrip('=')
    if side.get('version')!=1 or side.get('algorithm')!='HMAC-SHA256' or side.get('keyId')!='vps-genesis-1' or side.get('artifact')!=name or side.get('sha256')!=a['sha256'] or not hmac.compare_digest(side.get('signature',''),expected):raise RuntimeError('Artifact HMAC differs')
    if t.extractfile(a['path']+'.sha256').read().decode().split()[0]!=a['sha256']:raise RuntimeError('Artifact checksum sidecar differs')
  finally:shutil.rmtree(scratch)

def enrolled_resources(p):
 names=sorted({m['Name'] for r in p['pins'] for m in r['mounts'] if m['Type']=='volume'})
 ids=['volume-'+n.replace('_','-') for n in names]+['host-config','runtime-images']
 return [{'id':'platform-state:'+i,'externalId':i,'kind':'platform-state','projectId':'platform','name':i} for i in ids]

def publish_catalog(verified_points=None):
 p,_=profile();directory=WORK/'public';directory.mkdir(mode=0o750,exist_ok=True);os.chown(directory,0,1000);os.chmod(directory,0o750)
 current=directory/'catalog.json';retained=[]
 if verified_points is None and current.exists():retained=json.loads(current.read_text()).get('points',[])
 elif verified_points is not None:
  for point in verified_points:
   file=WORK/'manifests'/(point['manifestId']+'.json');manifest=json.loads(private(file).read_text())
   checked=json.loads(run(['node',str(HERE/'native-manifest.mjs'),'verify',str(file),str(SIGNING)]))
   if checked['manifestDigest']!=point['manifestDigest']:raise RuntimeError('Public catalog manifest differs from verified receipt')
   retained.append({'manifest':manifest,'offsiteVerified':True,'verifiedAt':point['verifiedAt']})
 schedule_active=subprocess.run(['systemctl','is-active','--quiet','platform-vps-backup.timer']).returncode==0
 queue_active=subprocess.run(['systemctl','is-active','--quiet','platform-vps-backup-queue.timer']).returncode==0
 body={'scheduleActive':schedule_active,'queueActive':queue_active,'schema':'platform.vps-backup-catalog/v1','host':HOST,'enabled':p.get('captureAuthorized') is True and p.get('offsiteAuthorized') is True,'resources':enrolled_resources(p),'points':retained,'updatedAt':now()}
 save(current,body);os.chown(current,0,1000);os.chmod(current,0o640)
 # No artifact bytes or credentials are exposed through the panel metadata mount.

def recover_unpause():
 f=WORK/'paused.json'
 if not f.exists():return
 private(f);p=json.loads(f.read_text())
 for ident in p['containers']:
  if not re.fullmatch('[a-f0-9]{64}',ident):raise RuntimeError('Malformed recovery journal')
  r=json.loads(run(['docker','inspect',ident]))[0]
  if (r['Config'].get('Labels') or {}).get('com.docker.compose.project') not in ALLOW_PROJECTS:raise RuntimeError('Foreign recovery journal container')
  if r['State'].get('Paused'):run(['docker','unpause',ident],timeout=30)
 f.unlink()

def main():
 if os.geteuid()!=0 or len(sys.argv)!=2:raise RuntimeError('Root and explicit capture/recover-unpause operation required')
 def interrupted(*_):raise RuntimeError('Native capture interrupted; unpause cleanup required')
 signal.signal(signal.SIGTERM,interrupted)
 os.umask(0o077);private(WORK,True)
 with (WORK/'operation.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if sys.argv[1]=='capture':capture()
  elif sys.argv[1]=='recover-unpause':recover_unpause()
  elif sys.argv[1]=='publish-catalog':publish_catalog()
  else:raise RuntimeError('Unsupported VPS backup operation')
if __name__=='__main__':
 try:main()
 except Exception as e:print(json.dumps({'status':'failed','error':str(e)[:250]}));sys.exit(1)
