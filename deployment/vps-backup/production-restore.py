#!/usr/bin/python3
"""Manual same-host runtime recovery. No OS/network/authority restoration.
All selected artifacts authenticate before staging; native DB engines qualify the
staged state before stopping production. A root journal retains rollback paths.
The signed profile may approve up to four exact, directional Control Center image
pairs in controlCenterImageCompatibility [{sourceImage,currentImage}]. These only
admit reviewed data compatibility; current management images remain in place and
an approval never constitutes a verified restore or bypasses other restore gates.
"""
import base64,importlib.util,json,os,pathlib,re,shutil,signal,stat,subprocess,tarfile,tempfile,time
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
 approvals=profile.get('controlCenterImageCompatibility',[])
 if not isinstance(approvals,list) or len(approvals)>4 or any(not isinstance(edge,dict) or set(edge)!={'sourceImage','currentImage'} or any(not isinstance(value,str) or not re.fullmatch(r'sha256:[a-f0-9]{64}',value) for value in edge.values()) for edge in approvals):raise RuntimeError('Invalid signed Control Center image compatibility')
 image_pairs={(edge['sourceImage'],edge['currentImage']) for edge in approvals}
 old={r['Name']:r for r in snapshot};now={r['Name']:r for r in current}
 b.reviewed_membership(current)
 expected={pin['name'] for pin in profile['pins']}
 if set(old)!=set(now) or set(now)!=expected or len(old)!=len(snapshot) or len(now)!=len(current):raise RuntimeError('Restore runtime membership differs from signed profile')
 for name,r in old.items():
  approved_image=name=='/enterprise-control-center' and (r['Image'],now[name]['Image']) in image_pairs
  if (r['Image']!=now[name]['Image'] and not approved_image) or r['Mounts']!=now[name]['Mounts']:raise RuntimeError('Restore requires matching or explicitly approved images and the same mount topology')
  if any(r['Config'].get(k)!=now[name]['Config'].get(k) for k in ('Cmd','Entrypoint','User')):raise RuntimeError('Restore container configuration differs from selected point')
  if persistent_env(r)!=persistent_env(now[name]):raise RuntimeError('Persistent runtime environment differs from selected point')
 if sorted({m['Name'] for r in snapshot for m in r['Mounts'] if m['Type']=='volume'})!=sorted({m['Name'] for r in current for m in r['Mounts'] if m['Type']=='volume'}):raise RuntimeError('Restore volume scope differs')
 if any((r['Config'].get('Labels') or {}).get('com.docker.compose.project') not in b.ALLOW_PROJECTS for r in snapshot):raise RuntimeError('Foreign workload in restore capsule')

# Commands never include credential values. Native clients consume protected
# FILE references only; stdout is stored in encrypted capture or protected staging.
def pg_sql(container,sql,database='postgres'):
 command=['docker','exec',container,'psql','-X','-U','postgres','-d',database,'-At','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-c',sql]
 result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=300)
 if result.returncode:
  code=re.search(rb'ERROR:\s+([A-Z0-9]{5}):',result.stderr)
  phase='acl-reset' if 'REVOKE ALL PRIVILEGES ON DATABASE' in sql else 'acl-grant' if '; GRANT ' in sql else 'acl-readiness' if 'has_database_privilege(' in sql else 'acl-expansion' if 'aclexplode(' in sql else 'semantic-read'
  raise RuntimeError('PostgreSQL '+phase+' failed: exit '+str(result.returncode)+' SQLSTATE '+(code.group(1).decode() if code else 'unavailable'))
 return result.stdout.decode().strip()
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

def sql_text(value):
 return "convert_from(decode('"+base64.b64encode(value.encode()).decode()+"','base64'),'UTF8')"

def database_acl_tuples(pg,rows):
 source="jsonb_to_recordset("+sql_text(json.dumps(rows))+"::jsonb) AS d(datname text,owner text,datacl text)"
 query="SELECT coalesce(json_agg(r ORDER BY datname,grantor,grantee,public,privilege_type,is_grantable),'[]') FROM (SELECT d.datname,pg_get_userbyid(a.grantor) AS grantor,CASE WHEN a.grantee=0 THEN NULL ELSE pg_get_userbyid(a.grantee) END AS grantee,(a.grantee=0) AS public,a.privilege_type,a.is_grantable FROM "+source+" JOIN pg_roles o ON o.rolname=d.owner CROSS JOIN LATERAL aclexplode(CASE WHEN cardinality(coalesce(d.datacl::aclitem[],acldefault('d',o.oid)))>0 THEN coalesce(d.datacl::aclitem[],acldefault('d',o.oid)) ELSE NULL::aclitem[] END) a) r"
 return json.loads(pg_sql(pg,query))

def replay_database_acl(tuples,ready,apply):
 pending=list(tuples)
 while pending:
  remaining=[]
  for grant in pending:
   if grant['privilege_type'] not in ('CREATE','CONNECT','TEMPORARY') or type(grant['is_grantable']) is not bool or type(grant['public']) is not bool or (grant['public'] and (grant['is_grantable'] or grant['grantee'] is not None)):raise RuntimeError('Invalid authenticated database grant')
   if not ready(grant):remaining.append(grant);continue
   grantee='PUBLIC' if grant['public'] else identifier(grant['grantee'],'postgres')
   apply('BEGIN; SET LOCAL ROLE '+identifier(grant['grantor'],'postgres')+'; GRANT '+grant['privilege_type']+' ON DATABASE '+identifier(grant['datname'],'postgres')+' TO '+grantee+(' WITH GRANT OPTION' if grant['is_grantable'] else '')+'; COMMIT;')
  if len(remaining)==len(pending):raise RuntimeError('Unresolvable authenticated database grant chain')
  pending=remaining

def restore_database_acl(pg,expected,actual):
 # Only called for the operation-owned, network-none staging engine after import.
 before=json.loads(expected['databaseGrants']);current=json.loads(actual['databaseGrants'])
 identities=lambda rows:sorted((x['datname'],x['owner']) for x in rows)
 if identities(before)!=identities(current) or len({x['datname'] for x in before})!=len(before) or json.loads(expected['roles'])!=json.loads(actual['roles']) or json.loads(expected['membership'])!=json.loads(actual['membership']):raise RuntimeError('Database ACL identity or role semantics differ')
 wanted=database_acl_tuples(pg,before);existing=database_acl_tuples(pg,current)
 owners={x['datname']:x['owner'] for x in before}
 for db in owners:
  targets={(g['public'],g['grantee']) for g in existing if g['datname']==db}
  for public,role in sorted(targets,key=str):
   target='PUBLIC' if public else identifier(role,'postgres')
   pg_sql(pg,'BEGIN; SET LOCAL ROLE '+identifier(owners[db],'postgres')+'; REVOKE ALL PRIVILEGES ON DATABASE '+identifier(db,'postgres')+' FROM '+target+' CASCADE; COMMIT;')
 def current_rows():return json.loads(pg_sql(pg,"SELECT coalesce(json_agg(r ORDER BY datname),'[]') FROM (SELECT datname,pg_get_userbyid(datdba) AS owner,datacl::text FROM pg_database WHERE datallowconn AND NOT datistemplate) r"))
 if database_acl_tuples(pg,current_rows()):raise RuntimeError('Database ACL reset incomplete')
 def ready(g):
  if g['grantor']==owners[g['datname']]:return True
  return pg_sql(pg,'SELECT has_database_privilege('+sql_text(g['grantor'])+','+sql_text(g['datname'])+','+sql_text(g['privilege_type']+' WITH GRANT OPTION')+')')=='t'
 replay_database_acl(wanted,ready,lambda sql:pg_sql(pg,sql))
 restored=current_rows()
 if identities(restored)!=identities(before) or database_acl_tuples(pg,restored)!=wanted:raise RuntimeError('Restored database effective ACL differs')
 return json.dumps(restored)

def database_grant_diagnostics(pg,expected,actual):
 before=json.loads(expected);after=json.loads(actual)
 old={r['datname']:r for r in before};new={r['datname']:r for r in after};shared=old.keys()&new.keys()
 def acl(rows,effective):
  encoded=base64.b64encode(json.dumps(rows).encode()).decode()
  source="jsonb_to_recordset(convert_from(decode('"+encoded+"','base64'),'UTF8')::jsonb) AS d(datname text,owner text,datacl text)"
  if effective:
   query="SELECT coalesce(json_agg(r ORDER BY datname,grantor,grantee,privilege_type,is_grantable),'[]') FROM (SELECT d.datname,a.grantor::regrole::text AS grantor,CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END AS grantee,a.privilege_type,a.is_grantable FROM "+source+" CROSS JOIN LATERAL aclexplode(coalesce(d.datacl::aclitem[],acldefault('d',d.owner::regrole))) a) r"
  else:
   query="SELECT coalesce(json_agg(r ORDER BY datname),'[]') FROM (SELECT d.datname,CASE WHEN d.datacl IS NULL THEN NULL ELSE (SELECT json_agg(x::text ORDER BY x::text) FROM unnest(d.datacl::aclitem[]) x) END AS acl FROM "+source+") r"
  return json.loads(pg_sql(pg,query))
 return {'datnameChangedCount':len(old.keys()^new.keys()),'ownerChangedCount':sum(old[k]['owner']!=new[k]['owner'] for k in shared),'dataclChangedCount':sum(old[k]['datacl']!=new[k]['datacl'] for k in shared),'arrayACLorderOnly':set(old)==set(new) and all(old[k]['owner']==new[k]['owner'] for k in shared) and acl(before,False)==acl(after,False),'effectiveACLsame':acl(before,True)==acl(after,True)}

def semantic_difference_summary(expected,actual,database_grants=None):
 # Diagnostic categories/counts only. This never weakens the equality gate.
 differences=[]
 for engine,categories in {'postgres':('roles','membership','databaseGrants','databases','tableGrants'),'mariadb':('accounts','grants','databases')}.items():
  for category in categories:
   before=expected.get(engine,{}).get(category);after=actual.get(engine,{}).get(category)
   if before==after:continue
   entries=[(category,before,after)]
   if engine=='mariadb' and category=='grants' and isinstance(before,dict) and isinstance(after,dict):
    entries=[('grants.'+name,before.get(name),after.get(name)) for name in ('global_priv','db','tables_priv','columns_priv','procs_priv','roles_mapping') if before.get(name)!=after.get(name)]
   for label,old,new in entries:
    item={'engine':engine,'category':label,'expectedType':type(old).__name__,'actualType':type(new).__name__}
    for side,value in [('expected',old),('actual',new)]:
     if isinstance(value,(dict,list)):item[side+'ItemCount']=len(value)
     elif isinstance(value,str):item[side+'RecordCount']=len(value.splitlines())
    if isinstance(old,dict) and isinstance(new,dict):
     item['changedEntryCount']=sum(old.get(k)!=new.get(k) for k in old.keys()|new.keys())
     item['sameKeySet']=set(old)==set(new)
    if isinstance(old,str) and isinstance(new,str):
     item['recordOrderOnly']=sorted(old.splitlines())==sorted(new.splitlines())
     try:item['jsonFormattingOnly']=json.loads(old)==json.loads(new)
     except (ValueError,TypeError):pass
    if engine=='postgres' and category=='databaseGrants' and database_grants is not None:item.update(database_grants)
    differences.append(item)
 return differences

def pipe_file(command,file):
 with file.open('rb') as src:
  r=subprocess.run(command,stdin=src,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=3600)
 if r.returncode:
  diagnostic=re.search(rb'ERROR(?:\s+(\d{3,5}))?(?:\s+\(([A-Z0-9]{5})\))?(?:\s+at line\s+(\d+))?',r.stderr)
  engine='postgres' if 'psql' in command else 'mariadb'
  code=diagnostic.group(1).decode() if diagnostic and diagnostic.group(1) else 'unknown'
  state=diagnostic.group(2).decode() if diagnostic and diagnostic.group(2) else 'unknown'
  line=diagnostic.group(3).decode() if diagnostic and diagnostic.group(3) else 'unknown'
  hints=[label for label,needle in [('not-running',b'not running'),('exec-failed',b'OCI runtime exec failed'),('unknown-command',b'Unknown command'),('permission-denied',b'Permission denied'),('access-denied',b'Access denied'),('connection-lost',b'Lost connection'),('server-gone',b'Server has gone away'),('syntax-error',b'syntax'),('unknown-option',b'unknown variable')] if needle.lower() in r.stderr.lower()]
  raise RuntimeError('Native database restore failed: '+engine+' rc='+str(r.returncode)+' code='+code+' state='+state+' line='+line+' classes='+','.join(hints))

def wait_database(name,engine):
 for _ in range(90):
  try:
   # Entry points expose a temporary SQL server while initializing system tables.
   # Only the final engine as PID1 is ready to accept the captured system schemas.
   process=b.run(['docker','exec',name,'cat','/proc/1/comm']).decode().strip()
   if process!=('postgres' if engine=='postgres' else 'mariadbd'):time.sleep(1);continue
   (pg_sql if engine=='postgres' else lambda c,q:maria_sql(c,q,True))(name,'SELECT 1');return
  except Exception:time.sleep(1)
 raise RuntimeError('Isolated database engine did not become ready')

def prepare_database_directory(source,destination):
 original=pathlib.Path(source).lstat()
 if not stat.S_ISDIR(original.st_mode):raise RuntimeError('Enrolled database volume is not a directory')
 destination.mkdir(mode=0o700)
 os.chown(destination,original.st_uid,original.st_gid)
 os.chmod(destination,stat.S_IMODE(original.st_mode))

def stage_databases(directory,runtime,rows,volumes,operation,journal):
 names={};stages={};created=[]
 try:
  for volume,engine in DB_VOLUMES.items():
   row=next(r for r in rows if any(m.get('Name')==volume for m in r['Mounts']))
   mount=next(m for m in row['Mounts'] if m.get('Name')==volume)
   stage=directory/volume;prepare_database_directory(volumes[volume],stage);stages[volume]=stage
   name='platform-restore-'+engine+'-'+operation[-12:];names[engine]=name
   planned={'name':name,'image':row['Image'],'source':str(stage),'destination':mount['Destination'],'id':None}
   journal['stagingContainers'].append(planned);b.save(JOURNAL,journal)
   args=['docker','create','--label','platform.vps.restore.operation='+operation,'--name',name,'--network','none','--restart','no','--no-healthcheck','--mount','type=bind,src='+str(stage)+',dst='+mount['Destination']]
   if engine=='postgres':
    args+=['-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_USER=postgres']
    args += [part for e in row['Config']['Env'] if e.startswith('PGDATA=') for part in ['-e',e]]
    args += [row['Image'],'postgres','-c','listen_addresses=']
   else:args+=['-e','MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1',row['Image'],'mariadbd','--skip-networking']
   ident=b.run(args).decode().strip()
   if not re.fullmatch('[a-f0-9]{64}',ident):raise RuntimeError('Unexpected staged container identity')
   planned['id']=ident;created.append(name);b.save(JOURNAL,journal)
   b.run(['docker','start',name]);wait_database(name,engine)
   if engine=='mariadb':
    # Maria's entrypoint must initialize its system accounts with grants enabled.
    # Reuse only this isolated initialized directory for system-grant import.
    b.run(['docker','stop','--time','60',name],timeout=90);b.run(['docker','rm',name])
    planned['id']=None;b.save(JOURNAL,journal)
    ident=b.run([*args,'--skip-grant-tables']).decode().strip()
    if not re.fullmatch('[a-f0-9]{64}',ident):raise RuntimeError('Unexpected staged container identity')
    planned['id']=ident;b.save(JOURNAL,journal)
    b.run(['docker','start',name]);wait_database(name,engine)
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
  actual=semantic_inventory(names['postgres'],names['mariadb'],True)
  if actual.get('postgres',{}).get('databaseGrants')!=expected.get('postgres',{}).get('databaseGrants'):
   restore_database_acl(names['postgres'],expected['postgres'],actual['postgres'])
   actual=semantic_inventory(names['postgres'],names['mariadb'],True)
   # Physical ACL array ordering/NULL defaults may differ; the native tuple
   # guard above preserves every effective grant and database owner exactly.
   if database_acl_tuples(names['postgres'],json.loads(actual['postgres']['databaseGrants']))==database_acl_tuples(names['postgres'],json.loads(expected['postgres']['databaseGrants'])):actual['postgres']['databaseGrants']=expected['postgres']['databaseGrants']
  if actual!=expected:
   grants=None
   if expected['postgres']['databaseGrants']!=actual['postgres']['databaseGrants']:grants=database_grant_diagnostics(names['postgres'],expected['postgres']['databaseGrants'],actual['postgres']['databaseGrants'])
   summary=semantic_difference_summary(expected,actual,grants)
   b.save(b.WORK/('semantic-differences-'+operation+'.json'),{'operation':operation,'manifestId':journal.get('manifestId'),'differences':summary,'productionModified':False})
   raise RuntimeError('Restored database semantics differ: '+','.join(x['engine']+'.'+x['category'] for x in summary))
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
  b.durable_rename(target,previous)
  os.chown(previous,0,0);os.chmod(previous,0o700 if previous.is_dir() else 0o600)
  b.durable_rename(staged,target)
  item['state']='switched';b.save(JOURNAL,journal)

def rollback(journal):
 # Only explicit native reconciliation uses this function after a process crash.
 for item in reversed(journal['paths']):
  target=pathlib.Path(item['target']);previous=pathlib.Path(item['previous']);failed=pathlib.Path(item['staged'])
  if previous.exists():
   if target.exists() or target.is_symlink():
    if failed.exists() or failed.is_symlink():raise RuntimeError('Rollback requires manual path reconciliation')
    b.durable_rename(target,failed)
   metadata=item.get('previousMetadata')
   if metadata:restore_file_metadata(previous,metadata)
   b.durable_rename(previous,target)
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
 scratch=b.WORK/('production-stage-'+operation);items=[];stopped=False
 if scratch.exists() or scratch.is_symlink():raise RuntimeError('Restore staging path already exists')
 journal={'operation':operation,'manifestId':manifest_id,'manifestDigest':digest,'status':'preparing','productionStopped':False,'startedAt':b.now(),'containers':[r['Id'] for r in rows],'runningContainers':[r['Id'] for r in rows if r['State'].get('Running')],'paths':items,'scratch':str(scratch),'stagingContainers':[]}
 b.save(JOURNAL,journal) # Durable intent precedes decrypt, filesystem staging and Docker create.
 try:
  scratch.mkdir(mode=0o700);b.fsync_directory(scratch.parent)
  with f.downloaded_restore(manifest_id,digest,scratch/'download',prefer_local=qualify_only) as (plain,point,download_proof):
   manifest=unpack_bundle(plain,scratch)
   if sorted(manifest['resources'],key=lambda r:r['id'])!=sorted(b.enrolled_resources(p),key=lambda r:r['id']):raise RuntimeError('Restore resource set differs from enrolled scope')
   runtime=extract_subset(scratch/'host-config.tar',scratch/'capsule','runtime')
   snapshot=json.loads((runtime/'containers.json').read_text());compatible(snapshot,rows,p);desired_rows=selected_running_state(rows,snapshot)
   volume_sources={m['Name']:m['Source'] for r in rows for m in r['Mounts'] if m['Type']=='volume'}
   metadata=json.loads(b.run(['docker','volume','inspect',*sorted(volume_sources)]))
   if len(volume_sources)!=13 or any(v['Driver']!='local' or v.get('Options') for v in metadata):raise RuntimeError('Only enrolled local persistent volumes can switch')
   dbstages=stage_databases(scratch,runtime,snapshot,volume_sources,operation,journal)
   for name,target in sorted(volume_sources.items()):
    source=dbstages.get(name) or extract_subset(scratch/(name+'.tar'),scratch/('unpack-'+name),'data')
    items.append({'target':target,'source':str(source)})
   for target in selected_bind_roots(rows):
    source=extract_subset(scratch/'host-config.tar',scratch/('bind-'+str(len(items))),'host'+target)
    items.append({'target':target,'source':str(source)})
   proof={'manifestId':manifest_id,'manifestDigest':digest,'ciphertextSource':download_proof['ciphertextSource'],'freshDownloadVerified':download_proof['actualDownloadVerified'],'previousReceiptDownloadVerified':download_proof['previousReceiptDownloadVerified'],'databaseSemanticsVerified':True,'productionModified':False,'scope':'enrolled-runtime-data-and-bind-configs','preserved':'OS-network-SSH-management-authority-and-current-queue','verifiedAt':b.now()}
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
    journal['paths']=items;b.save(JOURNAL,journal)
    if source.is_dir():shutil.copytree(source,staged,symlinks=True,copy_function=shutil.copy2)
    else:shutil.copy2(source,staged)
    # copy2 does not preserve uid/gid; apply exact extracted ownership recursively.
    paths=[source]+(list(source.rglob('*')) if source.is_dir() else [])
    for old in paths:
     dest=staged/old.relative_to(source) if old!=source else staged;st=old.lstat();os.lchown(dest,st.st_uid,st.st_gid)
    item.update(staged=str(staged),previous=str(previous),state='prepared')
   # Flush staged file contents/metadata before a durable switch can be recorded.
   devices=set()
   for item in items:
    device=os.stat(item['staged']).st_dev
    if device not in devices:b.run(['sync','-f',item['staged']]);devices.add(device)
   # Revalidate actual runtime and root profile immediately before downtime.
   b.profile()
   if b.sha(b.PROFILE)!=profile_digest:raise RuntimeError('Profile changed during staging')
   stopped=True
   journal.update(status='stopping',productionStopped=True,selectedRunningContainers=[r['Id'] for r in desired_rows if r['State'].get('Running')],paths=items);b.save(JOURNAL,journal)
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
  if not stopped and journal.get('productionStopped') is not True:
   cleanup_staging(journal,rows)
   health(rows);journal.update(status='rolled-back',runtimeHealthVerified=True,finishedAt=b.now());b.save(JOURNAL,journal)
  # After a production stop retain protected staging/journal for root review.

def cleanup_staging(journal,rows):
 operation=journal.get('operation','')
 if not re.fullmatch('[a-z0-9][a-z0-9-]{15,127}',operation):raise RuntimeError('Malformed staging operation')
 scratch=b.WORK/('production-stage-'+operation)
 if journal.get('scratch')!=str(scratch) or scratch.is_symlink():raise RuntimeError('Staging root differs from journal')
 expected={x['name']:x for x in journal.get('stagingContainers',[])}
 ids=b.run(['docker','ps','-aq','--no-trunc','--filter','label=platform.vps.restore.operation='+operation]).decode().split()
 if ids:
  stages=json.loads(b.run(['docker','inspect',*ids]))
  if {row['Id'] for row in stages}!=set(ids) or len(stages)!=len(ids):raise RuntimeError('Incomplete staged identity lookup')
  for row in stages:
   name=row['Name'].lstrip('/');planned=expected.get(name)
   if not planned or name not in {'platform-restore-'+engine+'-'+operation[-12:] for engine in DB_VOLUMES.values()}:raise RuntimeError('Unexpected staged container name')
   mounts=row['Mounts'];source=pathlib.Path(planned['source'])
   if source.parent!=scratch or source.name not in DB_VOLUMES or planned.get('id') not in (None,row['Id']) or row['Image']!=planned['image'] or row['HostConfig']['NetworkMode']!='none' or row['Config'].get('Labels',{}).get('platform.vps.restore.operation')!=operation:raise RuntimeError('Staging identity differs from journal')
   if not any(m['Type']=='bind' and m['Source']==str(source) and m['Destination']==planned['destination'] for m in mounts) or any(m['Type']=='bind' and m['Source']!=str(source) for m in mounts):raise RuntimeError('Unexpected staged container mount')
  b.run(['docker','rm','-f',*ids])
 allowed={m['Source'] for row in rows for m in row['Mounts'] if m['Type']=='volume'}|set(selected_bind_roots(rows))
 for item in journal.get('paths',[]):
  if not item.get('staged'):continue
  target=item.get('target','');expected_path=target+'.platform-restore-'+operation[-12:]
  if target not in allowed or item['staged']!=expected_path:raise RuntimeError('Staged sibling outside enrolled scope')
  staged=pathlib.Path(item['staged'])
  if staged.is_symlink():raise RuntimeError('Staged sibling became a symlink')
  if staged.exists():
   if staged.is_dir():shutil.rmtree(staged)
   else:staged.unlink()
   b.fsync_directory(staged.parent)
 if scratch.exists():b.private(scratch,True);shutil.rmtree(scratch);b.fsync_directory(scratch.parent)

def recover_rollback():
 b.private(JOURNAL);journal=json.loads(JOURNAL.read_text());p=json.loads(b.private(b.PROFILE).read_text())
 b.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(b.CONFIG/'authority-public.pem'),'-rawin','-in',str(b.PROFILE),'-sigfile',str(b.CONFIG/'profile.sig')])
 if journal.get('status')=='done':raise RuntimeError('Completed restore requires a separately reviewed rollback decision')
 rows=json.loads(b.run(['docker','inspect',*journal['containers']]))
 if sorted(b.pins(rows),key=lambda r:r['name'])!=sorted(p['pins'],key=lambda r:r['name']):raise RuntimeError('Recovery runtime differs from enrolled pins')
 if journal.get('productionStopped') is False:
  cleanup_staging(journal,rows)
  original=set(journal['runningContainers'])
  for row in rows:row['State']['Running']=row['Id'] in original
  health(rows);journal.update(status='rolled-back',runtimeHealthVerified=True,finishedAt=b.now());b.save(JOURNAL,journal)
  print(json.dumps({'status':'staging-reconciled','productionModified':False}));return
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
