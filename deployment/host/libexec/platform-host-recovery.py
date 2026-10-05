#!/usr/bin/python3
"""Root-owned bounded host configuration capture; only encrypted output enters shared state."""
import sys; sys.path.insert(0,'/usr/local/libexec'); import platform_backup_safe_state as safe_state
import datetime,fcntl,hashlib,json,os,pathlib,shutil,stat,subprocess,tarfile,tempfile,sqlite3,time
CONFIG=pathlib.Path('/etc/platform-host-recovery/paths.json')
WORK=pathlib.Path('/var/lib/platform-host-recovery')
OUTPUT=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/state/host-recovery')
KEY=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase')

def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def consistent_sqlite_backup(admin_db,admin_copy):
 if not admin_db.is_file() or admin_db.is_symlink() or admin_db.stat().st_size>256*1024**2:raise RuntimeError('Infrastructure administration SQLite state is missing or exceeds bound')
 deadline=time.monotonic()+30
 def progress(status,remaining,total):
  if time.monotonic()>deadline:raise RuntimeError('Infrastructure administration SQLite snapshot exceeded time bound')
 with sqlite3.connect(admin_db.as_uri()+'?mode=ro',uri=True,timeout=10) as source,sqlite3.connect(admin_copy) as destination:
  source.execute('PRAGMA query_only=ON');source.backup(destination,pages=256,progress=progress,sleep=0.05)
  if destination.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise RuntimeError('Infrastructure administration SQLite snapshot integrity failed')

def main():
 os.umask(0o077);WORK.mkdir(mode=0o700,parents=True,exist_ok=True)
 with (WORK/'capture.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  cfg=json.loads(CONFIG.read_text())
  if not KEY.is_file() or KEY.is_symlink() or KEY.stat().st_mode&0o077:raise RuntimeError('Recovery passphrase file is absent or not private')
  for name in cfg['requiredPaths']:
   if not pathlib.Path(name).exists():raise RuntimeError('A required recovery path is missing')
  tmp=pathlib.Path(tempfile.mkdtemp(prefix='capture-',dir=WORK))
  try:
   ids=subprocess.check_output(['docker','ps','-aq'],text=True).split()
   if len(ids)>512:raise RuntimeError('Container metadata inventory exceeds bound')
   containers=json.loads(subprocess.check_output(['docker','inspect',*ids]))
   metadata=tmp/'runtime';metadata.mkdir(mode=0o700)
   (metadata/'container-inspect.json').write_text(json.dumps(containers))
   for args,name in [(['iptables-save'],'iptables.rules'),(['ip6tables-save'],'ip6tables.rules'),(['ip','-json','address'],'ip-address.json'),(['ip','-json','route','show','table','all'],'ip-routes.json'),(['dpkg-query','-W','-f=${binary:Package}\t${Version}\n'],'packages.tsv')]:
    r=subprocess.run(args,capture_output=True,check=True);(metadata/name).write_bytes(r.stdout)
   pgpaths={}
   for setting,name in [('hba_file','pg_hba.conf'),('ident_file','pg_ident.conf'),('config_file','postgresql.conf'),('data_directory','postgresql.auto.conf')]:
    source=subprocess.check_output(['docker','exec','gf-postgres','psql','-U','postgres','-Atc','SHOW '+setting],text=True).strip()
    if not source.startswith('/') or '\n' in source or '..' in pathlib.PurePosixPath(source).parts:raise RuntimeError('Unexpected live PostgreSQL config path')
    if setting=='data_directory':source+='/postgresql.auto.conf'
    pgpaths[name]=source
    subprocess.run(['docker','cp','gf-postgres:'+source,str(metadata/name)],capture_output=True,check=True)
   (metadata/'postgres-live-config-paths.json').write_text(json.dumps(pgpaths))
   subprocess.run(['docker','cp','gf-redis:/run/platform-broker',str(metadata/'broker-config')],capture_output=True,check=True)
   for args,name in [(['docker','exec','gf-postgres','pg_dumpall','-U','postgres','--globals-only'],'postgres-globals.sql'),(['docker','exec','gf-mariadb','sh','-c','MYSQL_PWD="$(cat /run/secrets/mariadb_root_password)" mariadb-dump -uroot --system=users'],'mariadb-users-grants.sql')]:
    result=subprocess.run(args,capture_output=True,check=True)
    if not result.stdout or len(result.stdout)>32*1024*1024:raise RuntimeError('Database privilege export invalid or unbounded')
    (metadata/name).write_bytes(result.stdout)
   admin_db=pathlib.Path('/var/lib/platform-server-ai-admin/operations.sqlite')
   sqlite_live_paths={str(admin_db)+suffix for suffix in ['', '-wal', '-shm', '-journal']}
   admin_copy=metadata/'server-ai-admin-operations.sqlite';consistent_sqlite_backup(admin_db,admin_copy)
   (metadata/'server-ai-admin-state.json').write_text(json.dumps({'originalPath':str(admin_db),'archiveMember':'runtime/server-ai-admin-operations.sqlite','consistentSQLiteBackup':True,'sha256':sha(admin_copy)}))
   roots=[pathlib.Path(p) for p in cfg['paths']]
   for root in roots:
    if root==OUTPUT or OUTPUT in root.parents or root in OUTPUT.parents:raise RuntimeError('Recursive capsule capture path rejected')
   entries=[];seen=set();total=0
   def add(p,arc):
    nonlocal total
    if str(p) in sqlite_live_paths:return
    st=p.lstat()
    if stat.S_ISSOCK(st.st_mode) or stat.S_ISFIFO(st.st_mode):return
    if not(stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode)):raise RuntimeError('Unsupported recovery object type')
    if arc in seen:return
    seen.add(arc);entries.append((p,arc,st.st_mtime_ns,st.st_size,st.st_ino))
    if stat.S_ISREG(st.st_mode):total+=st.st_size
    if total>cfg['maximumTotalBytes'] or len(entries)>cfg['maximumEntries']:raise RuntimeError('Bounded recovery inventory exceeded')
    if stat.S_ISDIR(st.st_mode):
     for child in sorted(p.iterdir()):
      if child.name not in cfg['excludeNames']:add(child,arc+'/'+child.name)
   for p in roots:add(p,'host/'+str(p).lstrip('/'))
   add(metadata,'runtime')
   required_arcs={'host/'+p.lstrip('/') for p in cfg['requiredPaths']}
   if not required_arcs.issubset(seen):raise RuntimeError('A required recovery input is absent from archive membership')
   if any('/var/lib/platform-ftps-backup' in arc or '/state/host-recovery/' in arc for arc in seen):raise RuntimeError('Recursive FTPS or recovery spool capture rejected')
   archive=tmp/'recovery.tar.gz'
   with tarfile.open(archive,'w:gz',dereference=False) as tar:
    for p,arc,mtime,size,inode in entries:
     tar.add(p,arcname=arc,recursive=False)
     now=p.lstat()
     if now.st_mtime_ns!=mtime or now.st_ino!=inode or (p.is_file() and now.st_size!=size):raise RuntimeError('Recovery input changed during capture')
   encrypted=tmp/'host-recovery-current.tar.gz.gpg';gnupg=WORK/'gnupg';gnupg.mkdir(mode=0o700,exist_ok=True)
   common=['gpg','--no-options','--homedir',str(gnupg),'--batch','--yes','--pinentry-mode','loopback','--passphrase-file',str(KEY)]
   subprocess.run(common+['--symmetric','--cipher-algo','AES256','--s2k-digest-algo','SHA512','--s2k-count','65011712','--output',str(encrypted),str(archive)],capture_output=True,check=True)
   check=tmp/'decrypted-check.tar.gz'
   subprocess.run(common+['--decrypt','--output',str(check),str(encrypted)],capture_output=True,check=True)
   digest=sha(archive)
   if sha(check)!=digest:raise RuntimeError('Encrypted recovery roundtrip SHA256 mismatch')
   proof={'schema':'platform.host-recovery-capsule/v1','status':'passed','capturedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'configSha256':sha(CONFIG),'plaintextArchiveSha256':digest,'encryptedSha256':sha(encrypted),'encryptedBytes':encrypted.stat().st_size,'sourceBytes':total,'entryCount':len(entries),'boundedPathCount':len(roots),'requiredPathCount':len(required_arcs),'everyRequiredPathIncluded':True,'ftpsSpoolExcluded':True,'infrastructureAdminSQLiteConsistent':True,'decryptRoundtripVerified':True,'containsSensitiveMaterial':True,'sharedStatePlaintext':False}
   safe_state.copy_file(encrypted,OUTPUT/encrypted.name,True)
   safe_state.write_json(OUTPUT/'host-recovery-proof.json',proof,True)
   print(json.dumps(proof))
  finally:
   if tmp.parent!=WORK:raise RuntimeError('Unsafe scratch cleanup boundary')
   shutil.rmtree(tmp)

if __name__=='__main__':main()
