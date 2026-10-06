#!/usr/bin/python3
"""Manual same-host runtime recovery. No OS/network/authority restoration.
All selected artifacts authenticate before staging; native DB engines qualify the
staged state before stopping production. A root journal retains rollback paths.
"""
import importlib.util,json,os,pathlib,re,shutil,signal,stat,subprocess,tarfile,tempfile,time
HERE=pathlib.Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('runner',HERE/'platform-vps-backup-runner.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
JOURNAL=b.WORK/'production-restore.json'
DB_VOLUMES={'enterprise_postgres_data':'postgres','enterprise_mariadb_data':'mariadb'}
# Preserve the management plane, mounted host context and anti-replay state.
PRESERVE_PREFIXES=('/run','/var/run','/var/lib/docker/containers','/var/lib/platform-vps-backup','/etc/platform-infrastructure/cloudflare-dns','/etc/platform-infrastructure/first-enrollment','/etc/platform-infrastructure/server-ai/enrollment-vps')
PRESERVE_EXACT={'/etc/machine-id','/srv/platform-infrastructure','/srv/platform-infrastructure/first-install','/srv/platform-infrastructure/src','/etc/platform-infrastructure/server-ai/infrastructure-token','/etc/platform-infrastructure/server-ai/observer-token','/etc/platform-infrastructure/server-ai/openai-api-key'}

def within(value,root):return value==root or value.startswith(root+'/')
def bind_scope(source):
 if source in PRESERVE_EXACT or any(within(source,x) for x in PRESERVE_PREFIXES):return False
 return within(source,'/srv/platform-infrastructure/first-install') or source in ('/etc/platform-infrastructure/server-ai/searxng','/etc/platform-infrastructure/server-ai/settings.yml')

def selected_bind_roots(rows):
 sources=sorted({m['Source'] for r in rows for m in r['Mounts'] if m['Type']=='bind' and bind_scope(m['Source'])},key=lambda x:(len(x),x))
 return [p for p in sources if not any(p!=q and within(p,q) for q in sources)]

def extract_subset(archive,destination,prefix):
 """Extract only a selected subtree, with numeric owners and no link escapes."""
 destination=pathlib.Path(destination);destination.mkdir(mode=0o700,parents=True,exist_ok=True)
 with tarfile.open(archive,'r:') as t:
  selected=[m for m in t if m.name==prefix or m.name.startswith(prefix+'/')]
  if not selected:raise RuntimeError('Selected recovery path absent')
  names=set()
  for m in selected:
   p=pathlib.PurePosixPath(m.name)
   if p.is_absolute() or '..' in p.parts or m.name in names or not(m.isfile() or m.isdir() or m.issym() or m.islnk()):raise RuntimeError('Unsafe staged recovery entry')
   names.add(m.name)
   if m.issym() or m.islnk():
    target=pathlib.PurePosixPath(m.linkname)
    if target.is_absolute() or '..' in target.parts:raise RuntimeError('Recovery link leaves bounded subtree')
    if m.islnk() and not (m.linkname==prefix or m.linkname.startswith(prefix+'/')):raise RuntimeError('Recovery hardlink leaves selected subtree')
  # Python's data filter additionally rejects traversal through symlink parents.
  t.extractall(destination,members=selected,filter='data')
  # data filter intentionally strips numeric ownership/mode; restore explicit
  # archived permissions only after containment has been established.
  for m in sorted(selected,key=lambda x:len(pathlib.PurePosixPath(x.name).parts),reverse=True):
   p=destination/m.name
   if m.issym():os.lchown(p,m.uid,m.gid)
   else:os.chown(p,m.uid,m.gid);os.chmod(p,m.mode&0o7777)
 return destination/prefix

def unpack_bundle(plain,directory):
 b.verify_bundle(plain)
 with tarfile.open(plain,'r:') as t:
  manifest=json.load(t.extractfile('manifest.json'))
  for a in manifest['artifacts']:
   dest=directory/pathlib.PurePosixPath(a['path']).name
   with t.extractfile(a['path']) as src,dest.open('xb') as out:shutil.copyfileobj(src,out)
 return manifest

BOOTSTRAP_ENV={'CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS','CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS','CONTROL_CENTER_FIRST_CONFIGURATION_TOKEN_FILE'}
def persistent_env(row):
 ignored=BOOTSTRAP_ENV if row['Name']=='/enterprise-control-center' else set()
 return sorted(e for e in row['Config'].get('Env',[]) if e.split('=',1)[0] not in ignored)

def selected_running_state(current,snapshot):
 desired={r['Name']:bool(r['State'].get('Running')) for r in snapshot}
 if set(desired)!={r['Name'] for r in current}:raise RuntimeError('Selected runtime state differs from current membership')
 return [{**r,'State':{**r['State'],'Running':desired[r['Name']]}} for r in current]

def restore_file_metadata(destination,metadata):
 if set(metadata)!={'uid','gid','mode'} or any(type(v) is not int or v<0 for v in metadata.values()) or metadata['mode']&~0o7777:raise RuntimeError('Missing or invalid captured database file ownership')
 os.chown(destination,metadata['uid'],metadata['gid']);os.chmod(destination,metadata['mode'])

def compatible(snapshot,current,profile):
 old={r['Name']:r for r in snapshot};now={r['Name']:r for r in current}
 if set(old)!=set(now) or len(old)!=21:raise RuntimeError('Restore runtime membership differs')
 for name,r in old.items():
  if r['Image']!=now[name]['Image'] or r['Mounts']!=now[name]['Mounts']:raise RuntimeError('Restore requires the same enrolled images and mount topology')
  if any(r['Config'].get(k)!=now[name]['Config'].get(k) for k in ('Cmd','Entrypoint','User')):raise RuntimeError('Restore container configuration differs from selected point')
  if persistent_env(r)!=persistent_env(now[name]):raise RuntimeError('Persistent runtime environment differs from selected point')
 if sorted({m['Name'] for r in snapshot for m in r['Mounts'] if m['Type']=='volume'})!=sorted({m['Name'] for r in current for m in r['Mounts'] if m['Type']=='volume'}):raise RuntimeError('Restore volume scope differs')
 if any((r['Config'].get('Labels') or {}).get('com.docker.compose.project') not in b.ALLOW_PROJECTS for r in snapshot):raise RuntimeError('Foreign workload in restore capsule')

# Commands never include credential values. Native clients consume protected
# FILE references only; stdout is stored in encrypted capture or protected staging.
def pg_sql(container,sql,database='postgres'):
 return b.run(['docker','exec',container,'psql','-X','-U','postgres','-d',database,'-At','-v','ON_ERROR_STOP=1','-c',sql]).decode().strip()
def maria_sql(container,sql,isolated=False):
 if isolated:return b.run(['docker','exec',container,'mariadb','-uroot','-N','-B','-e',sql]).decode().strip()
 return b.run(['docker','exec',container,'sh','-c','MYSQL_PWD="$(cat /run/secrets/mariadb_root_password)" exec mariadb -uroot -N -B -e "$1"','sh',sql]).decode().strip()
def identifier(name,engine):
 q='"' if engine=='postgres' else '`';return q+name.replace(q,q+q)+q

def semantic_inventory(pg,maria,isolated=False):
 result={'postgres':{'databases':{},'roles':pg_sql(pg,"SELECT coalesce(json_agg(r ORDER BY rolname),'[]') FROM (SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls FROM pg_roles WHERE rolname !~ '^pg_') r")},'mariadb':{'databases':{},'accounts':maria_sql(maria,'SELECT User,Host,plugin FROM mysql.user ORDER BY User,Host',isolated)}}
 result['postgres']['membership']=pg_sql(pg,"SELECT coalesce(json_agg(r ORDER BY role,member),'[]') FROM (SELECT roleid::regrole::text AS role,member::regrole::text AS member,admin_option FROM pg_auth_members) r")
 result['postgres']['databaseGrants']=pg_sql(pg,"SELECT coalesce(json_agg(r ORDER BY datname),'[]') FROM (SELECT datname,pg_get_userbyid(datdba) AS owner,datacl::text FROM pg_database WHERE datallowconn AND NOT datistemplate) r")
 result['mariadb']['grants']={table:maria_sql(maria,'SELECT * FROM mysql.'+identifier(table,'mariadb')+' ORDER BY 1,2,3',isolated) for table in ('global_priv','db','tables_priv','columns_priv','procs_priv','roles_mapping')}
 for db in json.loads(pg_sql(pg,"SELECT coalesce(json_agg(datname ORDER BY datname),'[]') FROM pg_database WHERE datallowconn AND NOT datistemplate")):
  tables=json.loads(pg_sql(pg,"SELECT coalesce(json_agg(r ORDER BY schemaname,tablename),'[]') FROM (SELECT schemaname,tablename FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')) r",db))
  result['postgres']['databases'][db]={r['schemaname']+'.'+r['tablename']:pg_sql(pg,'SELECT count(*) FROM '+identifier(r['schemaname'],'postgres')+'.'+identifier(r['tablename'],'postgres'),db) for r in tables}
  result['postgres'].setdefault('tableGrants',{})[db]=pg_sql(pg,"SELECT coalesce(json_agg(r ORDER BY schema,name),'[]') FROM (SELECT n.nspname AS schema,c.relname AS name,pg_get_userbyid(c.relowner) AS owner,c.relacl::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND c.relkind IN ('r','p','S','v','m')) r",db)
 for db in maria_sql(maria,"SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('information_schema','performance_schema','mysql','sys') ORDER BY SCHEMA_NAME",isolated).splitlines():
  tables=maria_sql(maria,"SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='"+db.replace("'","''")+"' AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME",isolated).splitlines()
  result['mariadb']['databases'][db]={t:maria_sql(maria,'SELECT count(*) FROM '+identifier(db,'mariadb')+'.'+identifier(t,'mariadb'),isolated) for t in tables}
 return result

def pipe_file(command,file):
 with file.open('rb') as src:
  r=subprocess.run(command,stdin=src,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=3600)
 if r.returncode:raise RuntimeError('Native database restore failed')

def wait_database(name,engine):
 for _ in range(90):
  try:
   (pg_sql if engine=='postgres' else lambda c,q:maria_sql(c,q,True))(name,'SELECT 1');return
  except Exception:time.sleep(1)
 raise RuntimeError('Isolated database engine did not become ready')

def stage_databases(directory,runtime,rows,volumes,operation):
 names={};stages={};created=[]
 try:
  for volume,engine in DB_VOLUMES.items():
   row=next(r for r in rows if any(m.get('Name')==volume for m in r['Mounts']))
   mount=next(m for m in row['Mounts'] if m.get('Name')==volume)
   stage=directory/volume;stage.mkdir(mode=0o700);stages[volume]=stage
   name='platform-restore-'+engine+'-'+operation[-12:];names[engine]=name
   args=['docker','create','--name',name,'--network','none','--restart','no','--no-healthcheck','--mount','type=bind,src='+str(stage)+',dst='+mount['Destination']]
   if engine=='postgres':
    args+=['-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_USER=postgres']
    args += [part for e in row['Config']['Env'] if e.startswith('PGDATA=') for part in ['-e',e]]
    args += [row['Image'],'postgres','-c','listen_addresses=']
   else:args+=['-e','MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1',row['Image'],'mariadbd','--skip-networking','--skip-grant-tables']
   b.run(args);created.append(name);b.run(['docker','start',name]);wait_database(name,engine)
   if engine=='postgres':
    # pg_dumpall recreates the bootstrap role; this one existing identical role
    # is retained while its subsequent ALTER ROLE/password/grants are restored.
    filtered=directory/'postgres-restore.sql';skipped=0
    with (runtime/'postgres-all.sql').open('rb') as src,filtered.open('xb') as dst:
     for line in src:
      if line.rstrip() in (b'CREATE ROLE postgres;',b'CREATE ROLE "postgres";'):skipped+=1;continue
      dst.write(line)
    if skipped!=1:raise RuntimeError('Unexpected PostgreSQL bootstrap role declaration')
    pipe_file(['docker','exec','-i',name,'psql','-X','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1'],filtered)
   else:pipe_file(['docker','exec','-i',name,'mariadb','-uroot'],runtime/'mariadb-all.sql')
  expected=json.loads((runtime/'database-semantics.json').read_text())
  if semantic_inventory(names['postgres'],names['mariadb'],True)!=expected:raise RuntimeError('Restored database schema/row/role semantics differ from capture')
  for name in created:b.run(['docker','stop','--time','60',name],timeout=90)
  # Persist original database configuration and TLS files after clean shutdown.
  for volume,engine in DB_VOLUMES.items():
   row=next(r for r in rows if any(m.get('Name')==volume for m in r['Mounts']));mount=next(m for m in row['Mounts'] if m.get('Name')==volume)
   mapping=json.loads((runtime/('postgres-live-config-paths.json' if engine=='postgres' else 'mariadb-live-tls-paths.json')).read_text())
   metadata=json.loads((runtime/'database-file-metadata.json').read_text())[engine]
   for name,target in mapping.items():
    if not within(target,mount['Destination']):continue # Other paths are enrolled bind configs.
    dest=stages[volume]/pathlib.PurePosixPath(target).relative_to(mount['Destination']);dest.parent.mkdir(parents=True,exist_ok=True)
    if name not in metadata:raise RuntimeError('Missing original database configuration ownership')
    src=runtime/(name if engine=='postgres' else 'mariadb-'+name)
    shutil.copyfile(src,dest);restore_file_metadata(dest,metadata[name])
  return stages
 finally:
  for name in reversed(created):
   subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)

def health(rows,timeout=180):
 until=time.monotonic()+timeout
 while time.monotonic()<until:
  actual=json.loads(b.run(['docker','inspect',*[r['Id'] for r in rows]]))
  expected={r['Id']:bool(r['State'].get('Running')) for r in rows}
  if all(bool(r['State']['Running'])==expected[r['Id']] and (not expected[r['Id']] or r['State'].get('Health',{}).get('Status','healthy')=='healthy') for r in actual):return
  time.sleep(2)
 raise RuntimeError('Restored runtime failed health checks')

def boot(rows):
 active=[r for r in rows if r['State'].get('Running')]
 first=[b.database_container(rows,v) for v in DB_VOLUMES]
 if any(name not in {r['Name'].lstrip('/') for r in active} for name in first):raise RuntimeError('Database must be running before recovery')
 for name in first:b.run(['docker','start',name])
 for r in active:
  if r['Name'].lstrip('/') not in first:b.run(['docker','start',r['Id']])
 health(rows)

def switch_paths(items,journal):
 for item in items:
  target=pathlib.Path(item['target']);staged=pathlib.Path(item['staged']);previous=pathlib.Path(item['previous'])
  if previous.exists() or previous.is_symlink():raise RuntimeError('Rollback path already exists')
  item['state']='switching';b.save(JOURNAL,journal)
  os.rename(target,previous)
  os.chown(previous,0,0);os.chmod(previous,0o700 if previous.is_dir() else 0o600)
  os.rename(staged,target)
  item['state']='switched';b.save(JOURNAL,journal)

def rollback(journal):
 # Only explicit native reconciliation uses this function after a process crash.
 for item in reversed(journal['paths']):
  target=pathlib.Path(item['target']);previous=pathlib.Path(item['previous']);failed=pathlib.Path(item['staged'])
  if previous.exists():
   if target.exists() or target.is_symlink():
    if failed.exists() or failed.is_symlink():raise RuntimeError('Rollback requires manual path reconciliation')
    os.rename(target,failed)
   metadata=item.get('previousMetadata')
   if metadata:restore_file_metadata(previous,metadata)
   os.rename(previous,target)
  item['state']='rolled-back';b.save(JOURNAL,journal)
 journal['status']='rolled-back';journal['runtimeHealthVerified']=False;journal['finishedAt']=b.now();b.save(JOURNAL,journal)

def restore(manifest_id,digest,profile_digest,operation,qualify_only=False):
 b.settle_restore_journal(JOURNAL)
 if not re.fullmatch('[a-f0-9]{64}',digest) or not re.fullmatch('[a-f0-9]{64}',profile_digest):raise RuntimeError('Immutable restore digests required')
 def interrupted(*_):raise InterruptedError('Manual restore interrupted; rollback required')
 signal.signal(signal.SIGTERM,interrupted)
 p,rows=b.profile()
 if not qualify_only and p.get('productionRestoreAuthorized') is not True:raise RuntimeError('Manual production restore gate is closed')
 if b.sha(b.PROFILE)!=profile_digest:raise RuntimeError('Restore profile changed after owner review')
 if not re.fullmatch('[a-z0-9][a-z0-9-]{15,127}',operation):raise RuntimeError('Invalid restore operation identity')
 spec=importlib.util.spec_from_file_location('ftps',HERE/'ftps-sync.py');f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
 with f.downloaded_restore(manifest_id,digest) as (plain,point,_):
  scratch=pathlib.Path(tempfile.mkdtemp(prefix='production-stage-',dir=b.WORK));items=[];stopped=False;journal=None
  try:
   manifest=unpack_bundle(plain,scratch)
   if sorted(manifest['resources'],key=lambda r:r['id'])!=sorted(b.enrolled_resources(p),key=lambda r:r['id']):raise RuntimeError('Restore resource set differs from enrolled scope')
   runtime=extract_subset(scratch/'host-config.tar',scratch/'capsule','runtime')
   snapshot=json.loads((runtime/'containers.json').read_text());compatible(snapshot,rows,p);desired_rows=selected_running_state(rows,snapshot)
   volume_sources={m['Name']:m['Source'] for r in rows for m in r['Mounts'] if m['Type']=='volume'}
   metadata=json.loads(b.run(['docker','volume','inspect',*sorted(volume_sources)]))
   if len(volume_sources)!=13 or any(v['Driver']!='local' or v.get('Options') for v in metadata):raise RuntimeError('Only enrolled local persistent volumes can switch')
   dbstages=stage_databases(scratch,runtime,snapshot,volume_sources,operation)
   for name,target in sorted(volume_sources.items()):
    source=dbstages.get(name) or extract_subset(scratch/(name+'.tar'),scratch/('unpack-'+name),'data')
    items.append({'target':target,'source':str(source)})
   for target in selected_bind_roots(rows):
    source=extract_subset(scratch/'host-config.tar',scratch/('bind-'+str(len(items))),'host'+target)
    items.append({'target':target,'source':str(source)})
   proof={'manifestId':manifest_id,'manifestDigest':digest,'databaseSemanticsVerified':True,'productionModified':False,'scope':'enrolled-runtime-data-and-bind-configs','preserved':'OS-network-SSH-management-authority-and-current-queue','verifiedAt':b.now()}
   if qualify_only:
    b.save(b.WORK/('semantic-'+manifest_id+'.json'),proof);return proof
   # Sibling staging permits atomic same-filesystem rename and retains originals.
   for i,item in enumerate(items):
    target=pathlib.Path(item['target']);source=pathlib.Path(item.pop('source'));b.private(b.WORK,True)
    if target.is_symlink() or not(target.is_file() or target.is_dir()):raise RuntimeError('Restore target changed type')
    suffix='.platform-restore-'+operation[-12:]
    staged=target.with_name(target.name+suffix);previous=target.with_name(target.name+suffix+'-previous')
    if staged.exists() or staged.is_symlink() or previous.exists() or previous.is_symlink():raise RuntimeError('Restore sibling state already exists')
    original=target.stat()
    item.update(staged=str(staged),previous=str(previous),state='preparing',previousMetadata={'uid':original.st_uid,'gid':original.st_gid,'mode':stat.S_IMODE(original.st_mode)})
    if source.is_dir():shutil.copytree(source,staged,symlinks=True,copy_function=shutil.copy2)
    else:shutil.copy2(source,staged)
    # copy2 does not preserve uid/gid; apply exact extracted ownership recursively.
    paths=[source]+(list(source.rglob('*')) if source.is_dir() else [])
    for old in paths:
     dest=staged/old.relative_to(source) if old!=source else staged;st=old.lstat();os.lchown(dest,st.st_uid,st.st_gid)
    item.update(staged=str(staged),previous=str(previous),state='prepared')
   # Revalidate actual runtime and root profile immediately before downtime.
   b.profile()
   if b.sha(b.PROFILE)!=profile_digest:raise RuntimeError('Profile changed during staging')
   journal={'operation':operation,'manifestId':manifest_id,'manifestDigest':digest,'status':'stopping','startedAt':b.now(),'containers':[r['Id'] for r in rows],'runningContainers':[r['Id'] for r in rows if r['State'].get('Running')],'selectedRunningContainers':[r['Id'] for r in desired_rows if r['State'].get('Running')],'paths':items};b.save(JOURNAL,journal)
   # All clients stop before databases; cloudflared/SSH/network host plane remains up.
   dbnames={b.database_container(rows,v) for v in DB_VOLUMES}
   for r in sorted(rows,key=lambda r:r['Name'].lstrip('/') in dbnames):
    if not r['State'].get('Running'):continue
    stopped=True;b.run(['docker','stop','--time','60',r['Id']],timeout=90)
   journal['status']='switching';b.save(JOURNAL,journal);switch_paths(items,journal)
   journal['status']='starting';b.save(JOURNAL,journal);boot(desired_rows)
   journal['status']='done';journal['finishedAt']=b.now();journal['runtimeHealthVerified']=True;b.save(JOURNAL,journal)
   proof.update(productionModified=True,runtimeHealthVerified=True,rollbackRetained=True)
   b.save(b.WORK/'latest-production-restore.json',proof);return proof
  except BaseException:
   if stopped and journal:
    journal['status']='rollback-required';b.save(JOURNAL,journal)
    for r in rows:subprocess.run(['docker','stop','--time','30',r['Id']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)
    rollback(journal);boot(rows);journal['runtimeHealthVerified']=True;b.save(JOURNAL,journal)
   raise
  finally:
   if not stopped:
    for item in items:
     path=pathlib.Path(item['staged']) if item.get('staged') else None
     if path and path.exists():
      if path.is_dir():shutil.rmtree(path)
      else:path.unlink()
    shutil.rmtree(scratch)
   # After any production stop keep protected staging/journal for root review.

def recover_rollback():
 b.private(JOURNAL);journal=json.loads(JOURNAL.read_text());p=json.loads(b.private(b.PROFILE).read_text())
 b.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(b.CONFIG/'authority-public.pem'),'-rawin','-in',str(b.PROFILE),'-sigfile',str(b.CONFIG/'profile.sig')])
 if journal.get('status')=='done':raise RuntimeError('Completed restore requires a separately reviewed rollback decision')
 rows=json.loads(b.run(['docker','inspect',*journal['containers']]))
 if sorted(b.pins(rows),key=lambda r:r['name'])!=sorted(p['pins'],key=lambda r:r['name']):raise RuntimeError('Recovery runtime differs from enrolled pins')
 allowed={m['Source'] for r in rows for m in r['Mounts'] if m['Type']=='volume'}|set(selected_bind_roots(rows))
 operation=journal.get('operation','')
 if not re.fullmatch('[a-z0-9][a-z0-9-]{15,127}',operation):raise RuntimeError('Malformed rollback operation')
 for item in journal['paths']:
  target=item['target'];suffix='.platform-restore-'+operation[-12:]
  if target not in allowed or item['staged']!=target+suffix or item['previous']!=target+suffix+'-previous':raise RuntimeError('Rollback path outside enrolled scope')
 for r in rows:b.run(['docker','stop','--time','60',r['Id']],timeout=90)
 if not isinstance(journal.get('runningContainers'),list) or set(journal['runningContainers'])-set(journal['containers']):raise RuntimeError('Missing original runtime state')
 for r in rows:r['State']['Running']=r['Id'] in journal['runningContainers']
 rollback(journal);boot(rows);journal['runtimeHealthVerified']=True;b.save(JOURNAL,journal)
 print(json.dumps({'status':'rolled-back','runtimeHealthVerified':True,'operation':operation}))

if __name__=='__main__':
 import sys,fcntl
 try:
  if os.geteuid()!=0 or sys.argv[1:]!=['--recover-rollback']:raise RuntimeError('Production restore only accepts an owner-admitted job; root may reconcile interrupted rollback')
  with (b.WORK/'operation.lock').open('a') as lock:
   fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);recover_rollback()
 except Exception:print(json.dumps({'status':'failed','error':'Protected restore reconciliation required'}));sys.exit(1)
