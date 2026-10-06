import importlib.util,io,json,os,pathlib,shutil,tarfile,tempfile,unittest
from unittest.mock import patch
HERE=pathlib.Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('restore',HERE/'production-restore.py');r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
class RuntimeRestoreTests(unittest.TestCase):
 def setUp(self):
  self.root=pathlib.Path(tempfile.mkdtemp());self.old=r.JOURNAL;r.JOURNAL=self.root/'journal.json'
 def tearDown(self):r.JOURNAL=self.old;shutil.rmtree(self.root)
 def archive(self,entries):
  file=self.root/'state.tar'
  with tarfile.open(file,'w') as t:
   for name,kind,value in entries:
    m=tarfile.TarInfo(name);m.uid=os.getuid();m.gid=os.getgid();m.mode=0o640
    if kind=='link':m.type=tarfile.SYMTYPE;m.linkname=value;t.addfile(m)
    elif kind=='hard':m.type=tarfile.LNKTYPE;m.linkname=value;t.addfile(m)
    else:m.size=len(value);t.addfile(m,io.BytesIO(value))
  return file
 def test_extract_bounded_persistent_files_and_permissions(self):
  file=self.archive([('data/state','file',b'new-data')]);out=r.extract_subset(file,self.root/'out','data')
  self.assertEqual((out/'state').read_bytes(),b'new-data');self.assertEqual((out/'state').stat().st_mode&0o777,0o640)
 def test_reject_escaping_links_duplicates_and_traversal_before_extract(self):
  for entries in [[('data/link','link','/etc/shadow')],[('data/link','link','../../escape')],[('data/hard','hard','outside')],[('data/../escape','file',b'x')],[('data/x','file',b'a'),('data/x','file',b'b')]]:
   with self.subTest(entries=entries):
    file=self.archive(entries)
    with self.assertRaises(RuntimeError):r.extract_subset(file,self.root/'out','data')
    self.assertFalse((self.root/'escape').exists())
 def test_management_plane_and_nested_bind_scope_are_preserved(self):
  for path in ['/etc/ssh','/etc/machine-id','/run/docker.sock','/var/lib/platform-vps-backup/queue','/etc/platform-infrastructure/cloudflare-dns/api-token','/etc/platform-infrastructure/server-ai/infrastructure-token','/srv/platform-infrastructure','/srv/platform-infrastructure/src']:
   self.assertFalse(r.bind_scope(path),path)
  mounts=[{'Type':'bind','Source':p} for p in ['/srv/platform-infrastructure/first-install/traefik/certs','/srv/platform-infrastructure/first-install/traefik/certs/a.pem','/run/x']]
  self.assertEqual(r.selected_bind_roots([{'Mounts':mounts}]),['/srv/platform-infrastructure/first-install/traefik/certs'])
 def test_failed_mid_switch_rolls_back_all_originals(self):
  items=[]
  for i in range(2):
   target=self.root/('state'+str(i));target.mkdir();(target/'value').write_text('original')
   staged=self.root/('new'+str(i));staged.mkdir();(staged/'value').write_text('restored')
   items.append({'target':str(target),'staged':str(staged),'previous':str(self.root/('old'+str(i))),'state':'prepared'})
  journal={'paths':items};real=os.rename;calls=0
  def fail(source,target):
   nonlocal calls
   calls+=1
   if calls==4:raise OSError('injected failure after moving second original')
   return real(source,target)
  with patch.object(r.os,'rename',side_effect=fail):
   with self.assertRaises(OSError):r.switch_paths(items,journal)
  r.rollback(journal)
  for item in items:self.assertEqual((pathlib.Path(item['target'])/'value').read_text(),'original')
  self.assertEqual(json.loads(r.JOURNAL.read_text())['status'],'rolled-back')
 def test_closed_gate_refuses_before_ftp_or_docker_staging(self):
  with patch.object(r.b,'profile',return_value=({'productionRestoreAuthorized':False},[])):
   with self.assertRaisesRegex(RuntimeError,'gate is closed'):r.restore('manifest-vps-example','a'*64,'b'*64,'vps-restore-example-12345')
 def test_database_owner_is_resolved_from_enrolled_volume(self):
  self.assertEqual(r.b.database_container([{'Name':'/mariadb','Mounts':[{'Type':'volume','Name':'enterprise_mariadb_data'}]}],'enterprise_mariadb_data'),'mariadb')
 def test_stopped_enrolled_container_is_covered_but_missing_or_extra_is_denied(self):
  ids=['a'*64,'b'*64];rows=[{'Id':x,'Name':'/'+str(i),'Config':{'Labels':{'com.docker.compose.project':'platform_server_ai'}},'State':{'Running':i==0}} for i,x in enumerate(ids)]
  def commands(args):
   return (ids[0]+'\n').encode() if args[1]=='ps' else json.dumps(rows).encode()
  with patch.object(r.b,'run',side_effect=commands):
   self.assertEqual(len(r.b.inspect([{'id':x} for x in ids])),2)
  with patch.object(r.b,'run',side_effect=[(ids[0]+'\n').encode(),json.dumps(rows[:1]).encode()]):
   with self.assertRaisesRegex(RuntimeError,'Missing enrolled'):r.b.inspect([{'id':x} for x in ids])
  with patch.object(r.b,'run',return_value=('c'*64+'\n').encode()):
   with self.assertRaisesRegex(RuntimeError,'Unexpected running'):r.b.inspect([{'id':x} for x in ids])
 def test_pending_journal_blocks_and_verified_terminal_archives_without_deleting_originals(self):
  previous=self.root/'original';previous.write_text('keep')
  journal={'operation':'restore-example-123456','status':'rolled-back','paths':[{'previous':str(previous)}]}
  r.b.save(r.JOURNAL,journal)
  with patch.object(r.b,'private',side_effect=lambda p,*a:p):
   with self.assertRaisesRegex(RuntimeError,'Incomplete production'):r.b.settle_restore_journal(r.JOURNAL)
   journal['runtimeHealthVerified']=True;r.b.save(r.JOURNAL,journal);r.b.settle_restore_journal(r.JOURNAL)
   self.assertFalse(r.JOURNAL.exists());self.assertTrue((self.root/'restore-journals'/'restore-example-123456.json').exists())
   self.assertEqual(previous.read_text(),'keep');r.b.settle_restore_journal(r.JOURNAL)
 def test_selected_running_state_does_not_mutate_current_rollback_state(self):
  current=[{'Id':'current','Name':'/ai','State':{'Running':True}}];snapshot=[{'Name':'/ai','State':{'Running':False}}]
  selected=r.selected_running_state(current,snapshot)
  self.assertFalse(selected[0]['State']['Running']);self.assertTrue(current[0]['State']['Running']);self.assertEqual(selected[0]['Id'],'current')
 def test_only_cc_bootstrap_environment_is_exempt_from_persistent_comparison(self):
  base={'Name':'/enterprise-control-center','Config':{'Env':['PGDATABASE=original','CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS=old']}}
  changed={'Name':base['Name'],'Config':{'Env':['PGDATABASE=original','CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS=new']}}
  self.assertEqual(r.persistent_env(base),r.persistent_env(changed))
  changed['Config']['Env'][0]='PGDATABASE=other';self.assertNotEqual(r.persistent_env(base),r.persistent_env(changed))
  changed['Name']='/other';self.assertIn('CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS=new',r.persistent_env(changed))
 def test_database_configuration_uses_captured_numeric_ownership_and_file_mode(self):
  file=self.root/'tls.key';file.write_text('fixture')
  with patch.object(r.os,'chown') as ownership:
   r.restore_file_metadata(file,{'uid':999,'gid':999,'mode':0o600});ownership.assert_called_once_with(file,999,999)
  self.assertEqual(file.stat().st_mode&0o777,0o600)
  with self.assertRaisesRegex(RuntimeError,'ownership'):r.restore_file_metadata(file,{'uid':999,'gid':999})
 def test_atomic_save_and_switch_sync_parent_directories(self):
  file=self.root/'durable.json'
  with patch.object(r.b,'fsync_directory') as sync:
   r.b.save(file,{'status':'prepared'});sync.assert_called_once_with(file.parent)
  other=self.root/'renamed.json'
  with patch.object(r.b,'fsync_directory') as sync:
   r.b.durable_rename(file,other);sync.assert_called_once_with(file.parent)
 def staging_fixture(self):
  operation='restore-example-123456';scratch=self.root/('production-stage-'+operation);scratch.mkdir(mode=0o700)
  name='platform-restore-postgres-'+operation[-12:];source=scratch/'enterprise_postgres_data';source.mkdir()
  ident='c'*64;planned={'name':name,'id':None,'source':str(source),'destination':'/var/lib/postgresql','image':'sha256:example'}
  journal={'operation':operation,'scratch':str(scratch),'stagingContainers':[planned],'paths':[],'productionStopped':False}
  row={'Id':ident,'Name':'/'+name,'Image':planned['image'],'HostConfig':{'NetworkMode':'none'},'Config':{'Labels':{'platform.vps.restore.operation':operation}},'Mounts':[{'Type':'bind','Source':str(source),'Destination':planned['destination']}]}
  return journal,row,scratch
 def test_interrupted_create_cleans_only_recorded_isolated_stage_even_before_id_saved(self):
  journal,row,scratch=self.staging_fixture();commands=[]
  def run(args):
   commands.append(args)
   if args[1]=='ps':return (row['Id']+'\n').encode()
   if args[1]=='inspect':return json.dumps([row]).encode()
   return b''
  with patch.object(r.b,'WORK',self.root),patch.object(r.b,'private',side_effect=lambda p,*a:p),patch.object(r.b,'run',side_effect=run):r.cleanup_staging(journal,[])
  self.assertFalse(scratch.exists());self.assertIn(['docker','rm','-f',row['Id']],commands)
  self.assertFalse(any('stop' in command for command in commands))
 def test_interrupted_stage_refuses_foreign_network_without_removal(self):
  journal,row,scratch=self.staging_fixture();row['HostConfig']['NetworkMode']='host'
  with patch.object(r.b,'WORK',self.root),patch.object(r.b,'run',side_effect=[(row['Id']+'\n').encode(),json.dumps([row]).encode()]) as run:
   with self.assertRaisesRegex(RuntimeError,'Staging identity'):r.cleanup_staging(journal,[])
   self.assertEqual(run.call_count,2)
  self.assertTrue(scratch.exists())
 def test_database_stage_preserves_volume_directory_permissions_for_native_entrypoint(self):
  source=self.root/'enrolled-volume';source.mkdir();source.chmod(0o1777);destination=self.root/'stage'
  with patch.object(r.os,'chown') as ownership:
   r.prepare_database_directory(source,destination)
   ownership.assert_called_once_with(destination,source.stat().st_uid,source.stat().st_gid)
  self.assertEqual(destination.stat().st_mode&0o7777,0o1777)
 def test_database_readiness_waits_for_final_engine_not_temporary_init_server(self):
  with patch.object(r.b,'run',side_effect=[b'bash\n',b'mariadbd\n']),patch.object(r,'maria_sql',return_value='1') as sql,patch.object(r.time,'sleep'):
   r.wait_database('isolated-maria','mariadb');sql.assert_called_once_with('isolated-maria','SELECT 1',True)
 def test_maria_initializes_before_grant_disabled_import_on_same_private_directory(self):
  runtime=self.root/'runtime';runtime.mkdir();stage=self.root/'stage';stage.mkdir();sources={};rows=[]
  for volume,engine in r.DB_VOLUMES.items():
   source=self.root/volume;source.mkdir();sources[volume]=str(source)
   rows.append({'Name':'/'+engine,'Image':'sha256:'+engine,'Config':{'Env':[]},'Mounts':[{'Name':volume,'Destination':'/data'}]})
  (runtime/'postgres-all.sql').write_text('CREATE ROLE postgres;\n');(runtime/'mariadb-all.sql').write_text('-- fixture\n')
  for file,data in [('database-semantics.json',{}),('postgres-live-config-paths.json',{}),('mariadb-live-tls-paths.json',{}),('database-file-metadata.json',{'postgres':{},'mariadb':{}})]:
   (runtime/file).write_text(json.dumps(data))
  commands=[]
  def run(args,**kwargs):
   commands.append(args)
   return ('a'*64+'\n').encode() if args[1]=='create' else b''
  with patch.object(r.b,'run',side_effect=run),patch.object(r,'wait_database'),patch.object(r,'pipe_file'),patch.object(r,'semantic_inventory',return_value={}),patch.object(r.subprocess,'run'):
   r.stage_databases(stage,runtime,rows,sources,'restore-example-123456',{'stagingContainers':[]})
  creates=[c for c in commands if c[1]=='create' and 'sha256:mariadb' in c]
  self.assertEqual(len(creates),2);self.assertNotIn('--skip-grant-tables',creates[0]);self.assertIn('--skip-grant-tables',creates[1])
  self.assertEqual(creates[0][creates[0].index('--mount')+1],creates[1][creates[1].index('--mount')+1])
 def test_semantic_diagnostic_contains_categories_counts_and_never_values(self):
  old={'postgres':{'roles':'[{"role":"private-canary"}]'},'mariadb':{'grants':{'global_priv':'private-canary\told-value'}}}
  new={'postgres':{'roles':'[ {"role":"private-canary"} ]'},'mariadb':{'grants':{'global_priv':'private-canary\tnew-value'}}}
  summary=r.semantic_difference_summary(old,new);encoded=json.dumps(summary)
  self.assertEqual(len(summary),2);self.assertTrue(summary[0]['jsonFormattingOnly'])
  self.assertEqual(summary[1]['category'],'grants.global_priv');self.assertEqual(summary[1]['expectedRecordCount'],1)
  for value in ['private-canary','old-value','new-value']:self.assertNotIn(value,encoded)
 def test_reviewed_membership_only_adds_the_exact_readonly_metrics_service(self):
  base=[{'Name':name,'Config':{},'Mounts':[]} for name in r.b.BASE_CONTAINER_NAMES];r.b.reviewed_membership(base)
  node={'Name':'/enterprise-node-exporter','Config':{'Labels':{'com.docker.compose.project':'platform_infra_vps','com.docker.compose.service':'node-exporter'}},'Mounts':[{'Type':'bind','Source':source,'Destination':target,'RW':False} for source,target in r.b.NODE_EXPORTER_BINDS.items()]}
  r.b.reviewed_membership([*base,node])
  with self.assertRaisesRegex(RuntimeError,'membership'):r.b.reviewed_membership([*base,{'Name':'/unreviewed'}])
  node['Mounts'][0]['RW']=True
  with self.assertRaisesRegex(RuntimeError,'Metrics mounts'):r.b.reviewed_membership([*base,node])
 def test_database_acl_diagnostic_checks_defaults_and_effective_grant_attributes(self):
  before=json.dumps([{'datname':'private-db','owner':'private-owner','datacl':None}]);after=json.dumps([{'datname':'private-db','owner':'private-owner','datacl':'{}'}]);queries=[]
  def query(pg,sql):queries.append(sql);return '[]'
  with patch.object(r,'pg_sql',side_effect=query):details=r.database_grant_diagnostics('isolated',before,after)
  self.assertEqual(details['ownerChangedCount'],0);self.assertEqual(details['dataclChangedCount'],1);self.assertTrue(details['effectiveACLsame'])
  self.assertTrue(any('aclexplode' in q and 'acldefault' in q and 'is_grantable' in q for q in queries))
  self.assertNotIn('private-owner',json.dumps(details));self.assertNotIn('private-db',json.dumps(details))
class DatabaseAclReplayTests(unittest.TestCase):
 def grant(self,**overrides):
  return dict({'datname':'db"quote','grantor':'owner"quote','grantee':'reader"quote','public':False,'privilege_type':'CONNECT','is_grantable':False},**overrides)
 def test_pg_error_exposes_only_phase_and_sqlstate(self):
  result=type('Result',(),{'returncode':1,'stdout':b'','stderr':b'ERROR: 42601: private-identifier secret-data'})()
  with patch.object(r.subprocess,'run',return_value=result):
   with self.assertRaisesRegex(RuntimeError,'acl-expansion failed: exit 1 SQLSTATE 42601') as caught:r.pg_sql('isolated','SELECT aclexplode(NULL)')
  self.assertNotIn('private-identifier',str(caught.exception));self.assertNotIn('secret-data',str(caught.exception))
 def test_quotes_public_and_grant_options(self):
  commands=[]
  r.replay_database_acl([self.grant(is_grantable=True),self.grant(public=True,grantee=None),self.grant(grantee='PUBLIC')],lambda g:True,commands.append)
  self.assertIn('SET LOCAL ROLE "owner""quote"',commands[0]);self.assertIn('DATABASE "db""quote"',commands[0]);self.assertIn('TO "reader""quote" WITH GRANT OPTION',commands[0])
  self.assertIn(' TO PUBLIC;',commands[1]);self.assertIn(' TO "PUBLIC";',commands[2])
 def test_dependency_replay_and_unresolvable_chain(self):
  commands=[];ready_roles={'owner'}
  grants=[self.grant(grantor='intermediate',grantee='leaf'),self.grant(grantor='owner',grantee='intermediate',is_grantable=True)]
  def apply(sql):commands.append(sql);ready_roles.add('intermediate')
  r.replay_database_acl(grants,lambda g:g['grantor'] in ready_roles,apply)
  self.assertIn('ROLE "owner"',commands[0]);self.assertIn('ROLE "intermediate"',commands[1])
  with self.assertRaisesRegex(RuntimeError,'Unresolvable'):r.replay_database_acl(grants,lambda g:False,lambda sql:self.fail('No SQL expected'))
 def test_invalid_public_grant_option_is_rejected(self):
  with self.assertRaisesRegex(RuntimeError,'Invalid authenticated'):r.replay_database_acl([self.grant(public=True,grantee=None,is_grantable=True)],lambda g:True,lambda sql:self.fail('No SQL expected'))
 def test_role_or_owner_mismatch_prevents_any_mutation(self):
  before={'databaseGrants':json.dumps([{'datname':'db','owner':'owner','datacl':None}]),'roles':'[]','membership':'[]'}
  after={**before,'databaseGrants':json.dumps([{'datname':'db','owner':'different','datacl':None}])}
  with patch.object(r,'pg_sql') as query:
   with self.assertRaisesRegex(RuntimeError,'identity'):r.restore_database_acl('isolated',before,after)
   query.assert_not_called()
 def test_reset_and_final_exact_tuple_guard(self):
  record=[{'datname':'db','owner':'owner','datacl':'{}'}]
  state={'databaseGrants':json.dumps(record),'roles':'[]','membership':'[]'}
  wanted=[self.grant(datname='db',grantor='owner',grantee='reader')];current=[self.grant(datname='db',grantor='owner',grantee=None,public=True)]
  commands=[]
  def query(pg,sql):commands.append(sql);return json.dumps(record) if sql.startswith('SELECT coalesce') else ''
  with patch.object(r,'pg_sql',side_effect=query),patch.object(r,'database_acl_tuples',side_effect=[wanted,current,[],wanted]):r.restore_database_acl('isolated',state,state)
  self.assertTrue(any('REVOKE ALL PRIVILEGES ON DATABASE "db" FROM PUBLIC CASCADE' in sql for sql in commands))
  self.assertTrue(any('GRANT CONNECT ON DATABASE "db" TO "reader"' in sql for sql in commands))
  with patch.object(r,'pg_sql',side_effect=query),patch.object(r,'database_acl_tuples',side_effect=[wanted,current,[],current]):
   with self.assertRaisesRegex(RuntimeError,'effective ACL differs'):r.restore_database_acl('isolated',state,state)
  with patch.object(r,'pg_sql',side_effect=query),patch.object(r,'database_acl_tuples',side_effect=[wanted,current,current]):
   with self.assertRaisesRegex(RuntimeError,'reset incomplete'):r.restore_database_acl('isolated',state,state)
 def test_effective_tuple_query_preserves_public_grantor_and_defaults(self):
  with patch.object(r,'pg_sql',return_value='[]') as query:r.database_acl_tuples('isolated',[{'datname':'db','owner':'owner','datacl':None}])
  sql=query.call_args.args[1]
  for clause in ('aclexplode','acldefault','pg_get_userbyid(a.grantor)','a.grantee=0','a.is_grantable','JOIN pg_roles o ON o.rolname=d.owner'):self.assertIn(clause,sql)
if __name__=='__main__':unittest.main()
