"""Synthetic regressions for the finite signed Scripta extension; no Docker/VPS."""
import copy,datetime,hashlib,importlib.util,json,pathlib,subprocess,tempfile,unittest,uuid
from unittest import mock
HERE=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('restore_scripta',HERE/'production-restore.py');r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
b=r.b
def digest(value):return hashlib.sha256(value.encode()).hexdigest()
def fixture():
 rows=[]
 for name in sorted(b.BASE_CONTAINER_NAMES):
  rows.append({'Name':name,'Id':digest('container:'+name),'Image':'sha256:'+digest('image:'+name),'Mounts':[],'Config':{'Labels':{'com.docker.compose.project':'platform_infra_vps'},'Env':[]},'State':{'Running':True}})
 rows[0]['Mounts']=[{'Type':'volume','Name':'unit_core_'+str(i),'Source':'/var/lib/docker/volumes/unit_core_'+str(i)+'/_data','Destination':'/unit'+str(i),'RW':True} for i in range(13)]
 services={'/node-scriptastudents':('backend','data/legacy','/data'),'/students-beta-redis':('redis','data/redis','/data'),'/scripta-postgres':('postgres','data/postgres','/var/lib/postgresql'),'/scriptastudents-ingress':('ingress','ingress.conf','/etc/nginx/nginx.conf')}
 for name,(service,source,target) in services.items():
  rows.append({'Name':name,'Id':digest('container:'+name),'Image':'sha256:'+digest('image:'+name),'Mounts':[{'Type':'bind','Source':b.SCRIPTA_ROOT+'/'+source,'Destination':target,'RW':service!='ingress'}],'Config':{'Labels':{'com.docker.compose.project':'scriptastudents_vps','com.docker.compose.service':service},'Env':['PGDATA=/var/lib/postgresql/18/docker']},'State':{'Running':True}})
 rows.sort(key=lambda x:x['Name'])
 extension={'schema':'scripta-reviewed-runtime/v1','project':'scriptastudents_vps','previousProfileSha256':digest('synthetic predecessor'),'containers':[{'name':x['Name'],'id':x['Id'],'image':x['Image'],'mounts':copy.deepcopy(x['Mounts']),'labels':copy.deepcopy(x['Config']['Labels'])} for x in rows if x['Name'] in b.SCRIPTA_NAMES],'persistentRoots':[b.SCRIPTA_ROOT+'/data/legacy',b.SCRIPTA_ROOT+'/data/redis'],'postgresData':b.SCRIPTA_ROOT+'/data/postgres'}
 return rows,extension

class ScriptaRuntimeTests(unittest.TestCase):
 def test_legacy_core_remains_supported_but_four_apps_need_the_exact_signed_extension(self):
  rows,extension=fixture();core=[x for x in rows if x['Name'] not in b.SCRIPTA_NAMES]
  b.reviewed_membership(core);b.reviewed_membership(rows,extension)
  with self.assertRaises(RuntimeError):b.reviewed_membership(rows)
  with self.assertRaises(RuntimeError):b.reviewed_membership(rows+[{'Name':'/unknown'}],extension)
 def test_app_identity_image_mount_label_and_predecessor_drift_cannot_be_adopted(self):
  rows,extension=fixture()
  for field in ('id','image','mounts','labels'):
   changed=copy.deepcopy(extension);changed['containers'][0][field]='unreviewed'
   with self.assertRaises(RuntimeError):b.reviewed_membership(rows,changed)
  for change in [lambda x:x.update(previousProfileSha256='latest'),lambda x:x.update(postgresData='/unrelated'),lambda x:x.update(persistentRoots=['/unrelated']),lambda x:x['containers'].pop()]:
   changed=copy.deepcopy(extension);change(changed)
   with self.assertRaises(RuntimeError):b.reviewed_membership(rows,changed)
 def test_only_one_new_resource_is_added_to_existing_thirteen_volume_scope(self):
  rows,extension=fixture();pins=b.pins(rows)
  core={'pins':[p for p in pins if p['name'] not in b.SCRIPTA_NAMES]}
  current={'pins':pins,'scriptaRuntime':extension}
  old_resources=b.enrolled_resources(core);new_resources=b.enrolled_resources(current)
  self.assertEqual(len(old_resources),15);self.assertEqual(len(new_resources),16)
  self.assertEqual([x for x in new_resources if x not in old_resources],[{'id':'platform-state:scriptastudents-persistent','externalId':'scriptastudents-persistent','kind':'platform-state','projectId':'platform','name':'scriptastudents-persistent'}])
 def test_durability_requires_one_authenticated_tls_connection_and_real_local_ack(self):
  rows,_=fixture();ident=next(x['Id'] for x in rows if x['Name']=='/students-beta-redis')
  operation='vps-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dt%H%M%Sz')+'-'+uuid.uuid4().hex[:12]
  info='aof_enabled:1\r\naof_buffer_length:0\r\naof_pending_bio_fsync:0\r\naof_last_write_status:ok\r\n'
  reply=lambda ack:subprocess.CompletedProcess([],0,('\n'.join(json.dumps(x) for x in [1,ack,info])+'\n').encode(),b'')
  with mock.patch.object(b.subprocess,'run',return_value=reply([1,0])) as native:
   receipt=b.scripta_redis_durability(ident,operation)
  self.assertEqual(native.call_count,1);self.assertEqual(receipt['localAcknowledgements'],1)
  args=native.call_args.args[0];commands=native.call_args.kwargs['input'].decode().splitlines()
  self.assertEqual(args[:6],['docker','exec','-i',ident,'sh','-c'])
  self.assertIn('cat /run/secrets/redis-password',args[-1]);self.assertIn('--tls',args[-1]);self.assertNotIn(' -a ',args[-1])
  self.assertEqual(commands[1],'WAITAOF 1 0 2000');self.assertEqual(commands[2],'EVAL "return redis.call(\'INFO\',\'persistence\')" 0')
  for ack in ([0,0],[True,0],[1,False]):
   with mock.patch.object(b.subprocess,'run',return_value=reply(ack)):
    with self.assertRaises(RuntimeError):b.scripta_redis_durability(ident,operation)
 def test_fence_receipt_is_not_emitted_until_actual_writer_is_paused_and_sql_settled(self):
  rows,_=fixture();writer=next(x for x in rows if x['Name']=='/node-scriptastudents');cache=next(x for x in rows if x['Name']=='/students-beta-redis');events=[]
  with mock.patch.object(b,'wait_scripta_sql',side_effect=lambda:events.append('sql') or 1),mock.patch.object(b,'scripta_redis_durability',side_effect=lambda *_:events.append('fence') or {'localAcknowledgements':1}),mock.patch.object(b,'save',side_effect=lambda *_:events.append('receipt')):
   b.prepare_scripta_redis_pause(rows,[writer['Id']],cache,'synthetic-fixture',pathlib.Path('/synthetic-runtime'))
  self.assertEqual(events,['sql','fence','receipt'])
  with mock.patch.object(b,'wait_scripta_sql') as sql,mock.patch.object(b,'scripta_redis_durability') as fence:
   with self.assertRaises(RuntimeError):b.prepare_scripta_redis_pause(rows,[],cache,'synthetic-fixture',pathlib.Path('/synthetic-runtime'))
   sql.assert_not_called();fence.assert_not_called()
 def test_pg_stage_uses_same_captured_image_and_native_logical_semantics_without_ports(self):
  rows,extension=fixture();pg=next(x for x in rows if x['Name']=='/scripta-postgres');operation='scripta-test-'+uuid.uuid4().hex
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory);runtime=root/'runtime';runtime.mkdir();stage=root/'stage';stage.mkdir()
   (runtime/'scripta-postgres-all.sql').write_text('CREATE ROLE postgres;\n-- synthetic logical dump\n')
   for name,value in [('scripta-database-semantics.json',{'databases':{'synthetic':{'public.notes':'2'}},'roles':'[]','membership':'[]'}),('scripta-postgres-live-config-paths.json',{}),('scripta-postgres-file-metadata.json',{})]:(runtime/name).write_text(json.dumps(value))
   expected=json.loads((runtime/'scripta-database-semantics.json').read_text());commands=[]
   def native(args,**kwargs):
    commands.append(args);return (digest('temporary engine')+'\n').encode() if args[1]=='create' else b''
   with mock.patch.object(r,'JOURNAL',root/'journal.json'),mock.patch.object(r,'prepare_database_directory',side_effect=lambda _,target:target.mkdir()),mock.patch.object(b,'run',side_effect=native),mock.patch.object(r,'wait_database'),mock.patch.object(r,'pipe_file') as restore_sql,mock.patch.object(r,'postgres_semantic_inventory',return_value=expected),mock.patch.object(r.subprocess,'run') as cleanup:
    result=r.stage_scripta_postgres(stage,runtime,rows,{'scriptaRuntime':extension},operation,{'stagingContainers':[]})
   create=next(command for command in commands if command[1]=='create')
   self.assertEqual(create[create.index('--network')+1],'none');self.assertIn(pg['Image'],create);self.assertNotIn('-p',create)
   self.assertEqual(create[create.index('--entrypoint')+1],'/usr/local/bin/docker-entrypoint.sh')
   self.assertIn('ssl=off',create);self.assertIn('ON_ERROR_STOP=1',restore_sql.call_args.args[0]);self.assertEqual(result,stage/'scripta-postgres-data')
   cleanup.assert_called_once();self.assertEqual(cleanup.call_args.args[0][1:3],['rm','-f'])
 def test_persistent_application_binds_stay_selected_but_management_keys_are_preserved(self):
  rows,_=fixture();roots=r.selected_bind_roots(rows)
  self.assertIn(b.SCRIPTA_ROOT+'/data/postgres',roots);self.assertIn(b.SCRIPTA_ROOT+'/data/redis',roots)
  for path in ('/etc/machine-id','/etc/ssh','/run/docker.sock','/var/lib/platform-vps-backup/queue','/etc/platform-infrastructure/server-ai/infrastructure-token'):
   self.assertFalse(r.bind_scope(path))

if __name__=='__main__':unittest.main()
