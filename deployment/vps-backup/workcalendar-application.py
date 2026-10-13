#!/usr/bin/python3
"""Finite application operations in the existing native authority/queue/ledger.

Production apply restores application data and source mirror, never runtime
images, management configuration, database principals or current credentials.
"""
import collections,datetime,importlib.util,json,os,pathlib,re,shutil,signal,subprocess,tarfile,tempfile,time,uuid
HERE=pathlib.Path(__file__).resolve().parent
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
r=load('application_restore','production-restore.py');b=r.b
PROJECT='workcalendar';DATABASE='workcalendar_app';PG='workcalendar-postgres'

def same_resources(a,z):return b.canonical(sorted(a,key=lambda v:v['id']))==b.canonical(sorted(z,key=lambda v:v['id']))
def source_safe(profile):
 b.validate_workcalendar_management(profile.get('workcalendarManagement'))
 source=pathlib.Path(b.WORKCALENDAR_SOURCE)
 if source.is_symlink() or not source.is_dir():raise RuntimeError('Admitted application source is not a regular directory')
 return source
def app_rows(rows):return [row for row in rows if row['Name'] in b.WORKCALENDAR_NAMES]
def health_rows(rows):return app_rows(rows)
def target_identity():
 result=json.loads(r.pg_sql(PG,"SELECT json_build_object('database',current_database(),'owner',(SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()),'super',rolsuper,'createRole',rolcreaterole,'createDb',rolcreatedb,'replication',rolreplication,'bypass',rolbypassrls) FROM pg_roles WHERE rolname='workcalendar_app'",DATABASE))
 if result.get('database')!=DATABASE or result.get('owner')!='workcalendar_app' or any(result.get(k) is not False for k in ('super','createRole','createDb','replication','bypass')):raise RuntimeError('Application database identity or privileges differ')
 return result
def database_semantics():return r.postgres_semantic_inventory(PG)['databases'][DATABASE]
def database_structure(container=PG,full_names=False):
 # Stable logical identities, including columns/constraints/routines/ACL, reject
 # a live-only object that pg_restore --clean could otherwise silently retain.
 sql="""WITH ns AS (SELECT oid,nspname FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'), objects AS (
 SELECT 'schema' AS kind,nspname AS name,json_build_array(pg_get_userbyid(nspowner),nspacl::text)::text AS definition FROM pg_namespace WHERE oid IN (SELECT oid FROM ns)
 UNION ALL SELECT 'relation',n.nspname||'.'||c.relname,json_build_array(c.relkind,pg_get_userbyid(c.relowner),c.relacl::text)::text FROM pg_class c JOIN ns n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p','S','v','m','i','I','f')
 UNION ALL SELECT 'index',n.nspname||'.'||c.relname,pg_get_indexdef(c.oid) FROM pg_class c JOIN ns n ON n.oid=c.relnamespace WHERE c.relkind IN ('i','I')
 UNION ALL SELECT 'view',n.nspname||'.'||c.relname,pg_get_viewdef(c.oid,true) FROM pg_class c JOIN ns n ON n.oid=c.relnamespace WHERE c.relkind IN ('v','m')
 UNION ALL SELECT 'column',n.nspname||'.'||c.relname||'.'||a.attname,json_build_array(a.attnum,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,coalesce(pg_get_expr(d.adbin,d.adrelid),''))::text FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN ns n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE a.attnum>0 AND NOT a.attisdropped AND c.relkind IN ('r','p','v','m','f')
 UNION ALL SELECT 'constraint',n.nspname||'.'||coalesce(c.relname,'')||'.'||x.conname,pg_get_constraintdef(x.oid,true) FROM pg_constraint x JOIN ns n ON n.oid=x.connamespace LEFT JOIN pg_class c ON c.oid=x.conrelid
 UNION ALL SELECT 'routine',n.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')',md5(pg_get_functiondef(p.oid)) FROM pg_proc p JOIN ns n ON n.oid=p.pronamespace WHERE p.prokind IN ('f','p')
 UNION ALL SELECT 'type',n.nspname||'.'||t.typname,json_build_array(t.typtype,t.typcategory)::text FROM pg_type t JOIN ns n ON n.oid=t.typnamespace
 UNION ALL SELECT 'enum',n.nspname||'.'||t.typname||'.'||e.enumlabel,e.enumsortorder::text FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid JOIN ns n ON n.oid=t.typnamespace
 UNION ALL SELECT 'extension',extname,extversion FROM pg_extension
 ) SELECT coalesce(json_agg(objects ORDER BY kind,name),'[]') FROM objects"""
 if full_names:
  # The first UNION branch otherwise coerces concatenated object identities to
  # PostgreSQL's 63-byte name type. Explicit text retains the complete identity.
  sql=sql.replace('nspname AS name','nspname::text AS name').replace('ORDER BY kind,name','ORDER BY kind,name,definition')
 return json.loads(r.pg_sql(container,sql,DATABASE))
def structure_document(objects):return {'schema':'workcalendar-database-structure/v2','objects':objects}
def structure_entries(document,production=False):
 full=isinstance(document,dict)
 if full:
  if set(document)!={'schema','objects'}or document.get('schema')!='workcalendar-database-structure/v2':raise RuntimeError('Unsupported application structure inventory')
  objects=document['objects']
 else:objects=document
 if not isinstance(objects,list)or len(objects)>100000 or any(not isinstance(x,dict)or set(x)!={'kind','name','definition'}or any(not isinstance(x[k],str)for k in x)for x in objects):raise RuntimeError('Malformed application structure inventory')
 if production and not full:raise RuntimeError('Legacy application structure inventory supports isolated drill only; capture a new application point before live restore')
 return objects,full
def same_structure(expected,actual):
 objects,_=structure_entries(expected)
 # Retain multiplicity: no constraint, column or definition is discarded when
 # legacy truncated identities have equal ordering keys.
 return collections.Counter(b.canonical(row)for row in objects)==collections.Counter(b.canonical(row)for row in actual)
def wait_database_quiescence():
 deadline=time.monotonic()+20
 while True:
  active=r.pg_sql(PG,"SELECT count(*) FROM pg_stat_activity WHERE datname='workcalendar_app' AND pid<>pg_backend_pid() AND backend_type='client backend' AND (state IS DISTINCT FROM 'idle' OR xact_start IS NOT NULL)")
  if active=='0':return
  if not active.isdigit()or time.monotonic()>deadline:raise RuntimeError('Application database writers did not settle')
  time.sleep(.1)
def dump_database(path):
 with pathlib.Path(path).open('xb') as output:b.run(['docker','exec',PG,'pg_dump','-U','postgres','-d',DATABASE,'-Fc'],timeout=300,output=output)
 with pathlib.Path(path).open('rb')as stream:
  if stream.read(5)!=b'PGDMP':raise RuntimeError('Application database export is not a custom native dump')
def private_tar(target,entries):
 with tarfile.open(target,'w:',dereference=False) as archive:
  def checked(info):
   if not(info.isfile() or info.isdir() or info.issym() or info.islnk()):raise RuntimeError('Unsupported application archive object')
   return info
  for source,name in entries:archive.add(source,arcname=name,filter=checked)
def runtime_entries(runtime):return [(file,'runtime/'+file.name)for file in runtime.iterdir()if file.is_file()and file.suffix=='.json']
def complete_point(directory,job,resources,artifacts,profile):
 seed={'jobId':job,'scope':{'kind':'application','id':PROJECT},'createdAt':b.now(),'resources':resources,'artifacts':artifacts};b.save(directory/'input.json',seed)
 manifest=directory/'manifest.json';b.run(['node',str(HERE/'native-manifest.mjs'),'sign',str(directory/'input.json'),str(b.SIGNING),str(manifest)])
 checked=json.loads(b.run(['node',str(HERE/'native-manifest.mjs'),'verify',str(manifest),str(b.SIGNING)]))
 plain=directory/'complete.tar'
 with tarfile.open(plain,'w:') as archive:archive.add(manifest,arcname='manifest.json');archive.add(directory/'artifacts',arcname='artifacts')
 dest=b.WORK/'points'/('backup-'+checked['manifestId']+'.tar.gpg');dest.parent.mkdir(mode=0o700,exist_ok=True)
 b.gpg(['--symmetric','--cipher-algo','AES256','--compress-algo','none','--s2k-digest-algo','SHA512','--s2k-count','65011712','--output',str(dest),str(plain)])
 decoded=directory/'verified.tar';b.gpg(['--decrypt','--output',str(decoded),str(dest)])
 if b.sha(decoded)!=b.sha(plain):raise RuntimeError('Application encryption roundtrip differs')
 b.verify_bundle(decoded)
 proof={'status':'passed','host':b.HOST,'createdAt':seed['createdAt'],**checked,'scope':seed['scope'],'profileSha256':b.sha(b.PROFILE),'containerCount':len(profile['pins']),'bundle':dest.name,'encryptedBytes':dest.stat().st_size,'encryptedSha256':b.sha(dest),'plaintextSha256':b.sha(plain),'encryptedRoundtripVerified':True,'allArtifactHashesVerified':True,'semanticBootRestoreVerified':False,'offsiteVerified':False,'productionRestorePerformed':False}
 proof['applicationMode']=b.workcalendar_mode(profile,resources)
 if any(resource['kind']=='database'for resource in resources):proof['applicationStructureSchema']='workcalendar-database-structure/v2'
 (b.WORK/'manifests').mkdir(mode=0o700,exist_ok=True);b.save(b.WORK/'manifests'/(checked['manifestId']+'.json'),json.loads(manifest.read_text()));b.save(dest.with_suffix(dest.suffix+'.local.json'),proof);b.save(b.WORK/'latest-local.json',proof)
 return proof
def capture(resources):
 b.settle_restore_journal();profile,rows=b.profile();source=source_safe(profile);mode=b.workcalendar_mode(profile,resources)
 if profile.get('captureAuthorized') is not True or profile.get('pauseAuthorized') is not True:raise RuntimeError('Application capture gate is closed')
 if (b.WORK/'paused.json').exists():raise RuntimeError('Existing pause requires reconciliation')
 target_identity();digest=b.sha(b.PROFILE)
 if shutil.disk_usage(b.WORK).free<20*1024**3:raise RuntimeError('Insufficient private application backup reserve')
 job='vps-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dt%H%M%Sz')+'-'+uuid.uuid4().hex[:12]
 directory=pathlib.Path(tempfile.mkdtemp(prefix='application-capture-',dir=b.WORK));art=directory/'artifacts';art.mkdir(mode=0o700);runtime=directory/'runtime';runtime.mkdir(mode=0o700);paused=[];records=[];prior=None
 def interrupted(*_):raise InterruptedError('Application capture interrupted; unpause recovery required')
 previous_term=signal.signal(signal.SIGTERM,interrupted)
 def add(file,resource):
  rec=b.artifact_record(file,resource['externalId']);rec.update(id='artifact-'+resource['externalId'],resourceId=resource['id']);records.append(rec)
 try:
  b.save(runtime/'profile.json',profile);b.save(runtime/'containers.json',app_rows(rows));b.save(runtime/'resources.json',resources)
  def expired(*_):raise TimeoutError('Application consistent snapshot exceeded thirty seconds')
  prior=signal.signal(signal.SIGALRM,expired);signal.alarm(30)
  b.save(b.WORK/'paused.json',{'containers':[],'operation':job})
  for row in rows:
   if row['Name'] not in ('/node-workcalendar','/workcalendar-redis') or not row['State'].get('Running'):continue
   if row['State'].get('Paused'):raise RuntimeError('Application writer is already paused')
   if row['Name']=='/workcalendar-redis':b.prepare_workcalendar_redis_pause(rows,paused,row,job,runtime)
   paused.append(row['Id']);b.save(b.WORK/'paused.json',{'containers':paused,'operation':job});b.run(['docker','pause',row['Id']],timeout=5)
  wait_database_quiescence()
  for resource in resources:
   if resource['kind']=='database':
    dump=runtime/'database.dump';dump_database(dump);b.save(runtime/'database-semantics.json',database_semantics());b.save(runtime/'database-structure.json',structure_document(database_structure(full_names=True)));b.save(runtime/'database-identity.json',target_identity())
    file=art/'workcalendar-database.tar';private_tar(file,[(dump,'database.dump'),(runtime/'database-semantics.json','database-semantics.json'),(runtime/'database-structure.json','database-structure.json'),(runtime/'database-identity.json','database-identity.json')]);add(file,resource)
   elif resource['kind']=='source':
    file=art/'workcalendar-source.tar';private_tar(file,[(source,'source'),*runtime_entries(runtime)]);add(file,resource)
   else:
    file=art/'workcalendar-state.tar';private_tar(file,[(pathlib.Path(root),'state'+root)for root in profile['workcalendarRuntime']['persistentRoots']]+runtime_entries(runtime));add(file,resource)
  signal.alarm(0);signal.signal(signal.SIGALRM,prior)
  for ident in reversed(paused):b.run(['docker','unpause',ident],timeout=5)
  paused.clear();(b.WORK/'paused.json').unlink(missing_ok=True)
  if b.sha(b.PROFILE)!=digest:raise RuntimeError('Application profile changed during capture')
  return complete_point(directory,job,resources,records,profile)
 finally:
  signal.alarm(0)
  if prior is not None:signal.signal(signal.SIGALRM,prior)
  signal.signal(signal.SIGTERM,previous_term)
  failures=[]
  for ident in reversed(paused):
   try:b.run(['docker','unpause',ident],timeout=5)
   except Exception:failures.append(ident)
  if failures:b.save(b.WORK/'paused.json',{'containers':failures,'operation':job})
  else:(b.WORK/'paused.json').unlink(missing_ok=True)
  shutil.rmtree(directory)
  if failures:raise RuntimeError('Application writer requires unpause recovery')

def pg_restore(name,dump,database=DATABASE):
 with pathlib.Path(dump).open('rb') as stream:
  reply=subprocess.run(['docker','exec','-i',name,'pg_restore','-U','postgres','-d',database,'--clean','--if-exists','--single-transaction','--exit-on-error','--no-owner','--no-privileges','--role=workcalendar_app'],stdin=stream,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=300)
 if reply.returncode:raise RuntimeError('Scoped native database transaction failed')
def qualify_database(root,dump,expected,rows,operation,journal,structure=None,record=None):
 row=next(x for x in rows if x['Name']=='/workcalendar-postgres');stage=root/'database-stage';stage.mkdir(mode=0o700);os.chown(stage,70,70)
 name='platform-workcalendar-drill-'+operation[-12:];planned={'name':name,'id':None,'image':row['Image'],'source':str(stage),'destination':'/var/lib/postgresql'};journal['stagingContainers'].append(planned);b.save(root/'journal.json',journal)
 if record is not None:b.save(record,journal)
 args=['docker','create','--name',name,'--label','platform.vps.application.operation='+operation,'--network','none','--restart','no','--no-healthcheck','--user','70:70','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','2g','--cpus','2','--pids-limit','256','--mount','type=bind,src='+str(stage)+',dst=/var/lib/postgresql','--tmpfs','/var/run/postgresql:rw,nosuid,nodev,size=8m,uid=70,gid=70,mode=0775','--tmpfs','/tmp:rw,nosuid,nodev,size=16m,uid=70,gid=70','--entrypoint','/usr/local/bin/docker-entrypoint.sh','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_USER=postgres']
 args += [part for e in row['Config'].get('Env',[])if e.startswith('PGDATA=')for part in ['-e',e]];args += [row['Image'],'postgres','-c','listen_addresses=','-c','ssl=off']
 try:
  ident=b.run(args).decode().strip()
  if not re.fullmatch('[a-f0-9]{64}',ident):raise RuntimeError('Unexpected isolated application database identity')
  planned['id']=ident;b.save(root/'journal.json',journal)
  if record is not None:b.save(record,journal)
  b.run(['docker','start',ident]);r.wait_database(name,'postgres')
  r.pg_sql(name,'CREATE ROLE workcalendar_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;');r.pg_sql(name,'CREATE DATABASE workcalendar_app OWNER workcalendar_app;')
  pg_restore(name,dump)
  actual=r.postgres_semantic_inventory(name)['databases'][DATABASE]
  if actual!=expected:raise RuntimeError('Isolated application database counts differ from signed capture')
  if structure is not None:
   _,full_names=structure_entries(structure)
   if not same_structure(structure,database_structure(name,full_names=full_names)):raise RuntimeError('Isolated application database structure differs from signed capture')
  return {'databaseLogicalBootVerified':True,'tableCountsVerified':True,'network':'none','productionRestorePerformed':False}
 finally:
  if planned['id']:b.run(['docker','rm','-f',planned['id']],timeout=60)

def cleanup(root,journal):
 if not re.fullmatch('[a-z0-9][a-z0-9-]{15,127}',journal.get('operation',''))or root.is_symlink()or root.parent!=b.WORK or not root.name.startswith('workcalendar-restore-'):raise RuntimeError('Unexpected application staging root')
 ids=b.run(['docker','ps','-aq','--no-trunc','--filter','label=platform.vps.application.operation='+journal['operation']]).decode().split()
 if ids:
  rows=json.loads(b.run(['docker','inspect',*ids]));plans={p['name']:p for p in journal['stagingContainers']}
  if len(rows)!=len(ids)or{row['Id']for row in rows}!=set(ids):raise RuntimeError('Incomplete application staging identities')
  for row in rows:
   plan=plans.get(row['Name'].lstrip('/'))
   if not plan or plan['name']!='platform-workcalendar-drill-'+journal['operation'][-12:]or pathlib.Path(plan['source'])!=root/'database-stage'or row['Image']!=plan['image']or row['HostConfig']['NetworkMode']!='none' or plan.get('id')not in(None,row['Id'])or (row['Config'].get('Labels')or{}).get('platform.vps.application.operation')!=journal['operation']or not any(m['Type']=='bind'and m['Source']==plan['source']and m['Destination']==plan['destination']for m in row['Mounts'])or any(m['Type']=='bind'and m['Source']!=plan['source']for m in row['Mounts']):raise RuntimeError('Unexpected application staging identity')
  b.run(['docker','rm','-f',*ids],timeout=60)
 for item in journal.get('paths',[]):
  target=pathlib.Path(item['target']);staged=pathlib.Path(item['staged'])
  if str(target)not in(b.WORKCALENDAR_SOURCE,b.WORKCALENDAR_ROOT+'/data/legacy')or str(staged)!=str(target)+'.platform-restore-'+journal['operation'][-12:]or staged.is_symlink():raise RuntimeError('Application staged sibling outside admitted boundaries')
  if staged.exists():shutil.rmtree(staged);b.fsync_directory(staged.parent)
 shutil.rmtree(root)
def purge_volatile_state():
 script="set -eu; set +x; export REDISCLI_AUTH=\"$(cat /run/secrets/redis-password)\"; exec redis-cli --tls --cacert /run/tls/ca.crt --sni workcalendar-redis -h workcalendar-redis FLUSHDB"
 if b.run(['docker','exec','workcalendar-redis','sh','-c',script],timeout=10).strip()!=b'OK':raise RuntimeError('Application volatile state reset failed')
def rollback_paths(journal,record):
 # Infer only the three exact path states left by an atomic rename; durable
 # intent precedes each rename, so interruption after rename is recoverable.
 for item in reversed(journal['paths']):
  target,staged,previous=map(pathlib.Path,(item['target'],item['staged'],item['previous']))
  if any(path.is_symlink()for path in (target,staged,previous)):raise RuntimeError('Application rollback path changed type')
  if previous.exists():
   if target.exists():
    if staged.exists():raise RuntimeError('Ambiguous application rollback paths')
    b.durable_rename(target,staged)
   elif not staged.exists():raise RuntimeError('Missing application staged and current paths')
   b.durable_rename(previous,target)
  elif not target.exists():raise RuntimeError('Missing application original path')
  item['state']='rolled-back';b.save(record,journal)

def restore(manifest_id,digest,profile_digest,operation,resources,apply=False):
 b.settle_restore_journal();profile,rows=b.profile();source=source_safe(profile);mode=b.workcalendar_mode(profile,resources)
 if not re.fullmatch('[a-f0-9]{64}',digest)or b.sha(b.PROFILE)!=profile_digest or not re.fullmatch('[a-z0-9][a-z0-9-]{15,127}',operation):raise RuntimeError('Immutable application restore identity differs')
 if apply and profile.get('productionRestoreAuthorized')is not True:raise RuntimeError('Application production restore gate is closed')
 identity=target_identity();root=pathlib.Path(tempfile.mkdtemp(prefix='workcalendar-restore-',dir=b.WORK));journal={'operation':operation,'scope':{'kind':'application','id':PROJECT},'scratch':str(root),'status':'staging','manifestId':manifest_id,'profileSha256':profile_digest,'containers':[row['Id']for row in rows],'productionStopped':False,'stagingContainers':[],'paths':[]};changed=False;stopped=[];rollback_dump=None;prepared=[];record=b.WORK/'workcalendar-application-restore.json';writer=None
 def interrupted(*_):raise InterruptedError('Application restore interrupted; protected rollback required')
 previous_term=signal.signal(signal.SIGTERM,interrupted)
 try:
  b.save(record,journal) # Intent precedes decrypt, archive extraction and Docker create.
  ftps=load('application_ftps','ftps-sync.py')
  with ftps.downloaded_restore(manifest_id,digest,root/'download',prefer_local=not apply)as(plain,point,download_proof):
   manifest=r.unpack_bundle(plain,root)
   if manifest.get('scope')!={'kind':'application','id':PROJECT}:raise RuntimeError('A platform point cannot be interpreted as application-only restore')
   b.workcalendar_mode(profile,manifest['resources'])
   if any(resource not in manifest['resources']for resource in resources):raise RuntimeError('Selected resources are not captured by the immutable point')
   database_root=None
   if any(x['kind']=='database'for x in resources):
    database_root=r.extract_subset(root/'workcalendar-database.tar',root/'database','database.dump').parent
    expected=r.extract_subset(root/'workcalendar-database.tar',root/'database-meta','database-semantics.json')
    expected=json.loads(expected.read_text());structure=json.loads(r.extract_subset(root/'workcalendar-database.tar',root/'structure','database-structure.json').read_text());_,full_names=structure_entries(structure,production=apply)
    captured_identity=r.extract_subset(root/'workcalendar-database.tar',root/'identity','database-identity.json')
    if json.loads(captured_identity.read_text())!=identity:raise RuntimeError('Captured application database identity differs from current principal')
    qualify_database(root,database_root/'database.dump',expected,rows,operation,journal,structure,record)
   if any(x['kind']=='source'for x in resources):prepared.append((source,r.extract_subset(root/'workcalendar-source.tar',root/'source','source')))
   if any(x['kind']=='platform-state'for x in resources):
    legacy=pathlib.Path(profile['workcalendarRuntime']['persistentRoots'][0]);prepared.append((legacy,r.extract_subset(root/'workcalendar-state.tar',root/'state','state'+str(legacy))))
   proof={'status':'passed','scope':{'kind':'application','id':PROJECT},'mode':mode,'manifestId':manifest_id,'manifestDigest':digest,'profileSha256':profile_digest,'isolatedDatabaseVerified':database_root is not None,'sourceBoundariesVerified':any(x['kind']=='source'for x in resources),'legacyFileBoundariesVerified':mode=='all','productionRestorePerformed':False,'fullCoreRestoreVerified':False,'runtimeImagesChanged':False,'credentialsOrPrincipalsChanged':False,'volatileStatePolicy':'reset-after-data-restore','capturedRedisAofApplied':False,'verifiedAt':b.now()}
   if not apply:
    r.health(health_rows(rows));journal.update(status='done',runtimeHealthVerified=True,proof=proof);b.save(record,journal);return proof
   if b.sha(b.PROFILE)!=profile_digest or target_identity()!=identity:raise RuntimeError('Application admission or database identity changed after drill')
   journal.update(status='preparing',profileSha256=profile_digest,manifestId=manifest_id);b.save(record,journal)
   for target,staged in prepared:
    if target.is_symlink()or not target.is_dir():raise RuntimeError('Application target changed type')
    sibling=target.with_name(target.name+'.platform-restore-'+operation[-12:]);previous=target.with_name(sibling.name+'-previous')
    if sibling.exists()or previous.exists():raise RuntimeError('Application rollback path already exists')
    item={'target':str(target),'staged':str(sibling),'previous':str(previous),'state':'preparing'};journal['paths'].append(item);b.save(record,journal)
    shutil.copytree(staged,sibling,symlinks=True)
    for old in [staged,*staged.rglob('*')]:
     destination=sibling/old.relative_to(staged);metadata=old.lstat();os.lchown(destination,metadata.st_uid,metadata.st_gid)
    original=target.stat();os.chown(sibling,original.st_uid,original.st_gid);os.chmod(sibling,original.st_mode&0o7777);b.run(['sync','-f',str(sibling)]);item['state']='prepared';b.save(record,journal)
   journal.update(status='prepared');b.save(record,journal)
   b.profile()
   if b.sha(b.PROFILE)!=profile_digest:raise RuntimeError('Application admission changed before production stop')
   writer=next(x for x in rows if x['Name']=='/node-workcalendar');journal['productionStopped']=True;journal['originalRunningClients']=[row['Id']for row in rows if row['Name']in('/node-workcalendar',)and row['State'].get('Running')];b.save(record,journal)
   for client in rows:
    if client['Name']in('/node-workcalendar',)and client['State'].get('Running'):
     stopped.append(client['Id']);journal['stoppedClients']=list(stopped);b.save(record,journal);b.run(['docker','stop','--time','30',client['Id']],timeout=60)
   wait_database_quiescence()
   if database_root:
    rollback_dump=root/'current-database.dump';dump_database(rollback_dump);journal['rollbackDatabase']=str(rollback_dump);b.save(record,journal)
    if not same_structure(structure,database_structure(full_names=True)):raise RuntimeError('Current application structure differs from the selected point; no live import attempted')
    # Set and durably persist intent BEFORE a call that could commit and then be
    # interrupted before returning; the pre-operation dump handles both cases.
    changed=True;journal['databaseRestoreStarted']=True;b.save(record,journal);pg_restore(PG,database_root/'database.dump')
    if database_semantics()!=expected or not same_structure(structure,database_structure(full_names=True)):raise RuntimeError('Live application database differs from qualified restore')
    # Current principal/password and management credentials are not in a custom
    # database dump. Revoke restored application sessions to avoid resurrecting
    # stale cookies; the independent Control Center authentication is untouched.
    r.pg_sql(PG,"UPDATE account_sessions SET revoked_at=now() WHERE revoked_at IS NULL; DELETE FROM account_email_challenges;",DATABASE)
   for item in journal['paths']:
    item['state']='move-original-intent';b.save(record,journal);b.durable_rename(item['target'],item['previous']);item['state']='move-staged-intent';b.save(record,journal);b.durable_rename(item['staged'],item['target']);item['state']='switched';b.save(record,journal)
   if database_root or mode=='all':purge_volatile_state()
   for ident in stopped:b.run(['docker','start',ident])
   r.health(health_rows(rows));proof.update(productionRestorePerformed=True,applicationSessionsRevoked=database_root is not None,volatileStateReset=database_root is not None or mode=='all',rollbackRetained=True,verifiedAt=b.now())
   journal.update(status='done',runtimeHealthVerified=True,proof=proof);b.save(record,journal);return proof
 except BaseException:
  failures=[]
  if journal.get('productionStopped'):
   for ident in stopped:
    try:b.run(['docker','stop','--time','30',ident],timeout=60)
    except Exception:failures.append('writer-stop')
  if failures:
   journal.update(status='reconciliation-required',runtimeHealthVerified=False,unreconciled=failures);b.save(record,journal)
   raise RuntimeError('Application writers could not be stopped for protected rollback')
  try:rollback_paths(journal,record)
  except Exception:failures.append('filesystem')
  if changed and rollback_dump:
   try:pg_restore(PG,rollback_dump)
   except Exception:failures.append('database')
  for ident in stopped:
   try:b.run(['docker','start',ident])
   except Exception:failures.append('writer')
  if journal.get('productionStopped')and not failures:
   try:r.health(health_rows(rows))
   except Exception:failures.append('health')
  if record.exists():
   journal.update(status='reconciliation-required'if failures else'rolled-back',runtimeHealthVerified=not failures,unreconciled=failures);b.save(record,journal)
  if failures:raise RuntimeError('Application rollback requires protected reconciliation')
  raise
 finally:
  signal.signal(signal.SIGTERM,previous_term)
  # Preserve current-data rollback dump and original directories after any
  # production stop. Only terminal, health-verified journals unblock future work.
  if not journal.get('productionStopped')and journal.get('status')!='reconciliation-required':
   try:cleanup(root,journal)
   except BaseException:
    journal.update(status='reconciliation-required',runtimeHealthVerified=False,unreconciled=['staging-cleanup']);b.save(record,journal);raise
