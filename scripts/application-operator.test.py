#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

spec = importlib.util.spec_from_file_location('operator_impl', Path(__file__).resolve().parents[1] / 'deployment/host/libexec/platform-application-operator.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

class OperatorTests(unittest.TestCase):
    def test_reject_path_and_identifier_injection(self):
        for value in ['../x', '/tmp/x', 'a/../b', 'a//b', 'a\\b']:
            with self.assertRaises(m.Rejected): m.relative(value)
        for value in ['a;id', '../x', 'A', '-x']:
            with self.assertRaises(m.Rejected): m.identifier(value)

    def test_copy_excludes_credentials_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); src = root/'source'; src.mkdir()
            (src/'app').mkdir(); (src/'app'/'file.txt').write_text('payload')
            (src/'app'/'.env').write_text('not copied')
            (src/'app'/'credential.txt').write_text('not copied')
            dest = root/'clone'
            m.copy_tree(src, dest, ['app'], ['app/credential.txt'], [], lambda: None)
            self.assertEqual((dest/'app/file.txt').read_text(), 'payload')
            self.assertFalse((dest/'app/.env').exists())
            self.assertFalse((dest/'app/credential.txt').exists())
            (src/'app/link').symlink_to('/etc/passwd')
            with self.assertRaises(m.Rejected): m.copy_tree(src, root/'bad', ['app'], [], [], lambda: None)

    def test_sqlite_backup_includes_committed_wal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); src = root/'source'; src.mkdir()
            c = sqlite3.connect(src/'app.db')
            c.execute('pragma journal_mode=wal'); c.execute('create table value(n integer)'); c.execute('insert into value values (42)'); c.commit()
            # Only filesystem ownership guard mocked; real SQLite backup including live WAL.
            with patch.object(m, 'protected', return_value=src):
                m.copy_tree(src, root/'clone', ['app.db'], [], ['app.db'], lambda: None)
            out = sqlite3.connect(root/'clone/app.db')
            self.assertEqual(out.execute('select n from value').fetchone(), (42,))
            out.close(); c.close()

    def test_plan_requires_pinned_live_source_and_apex_domain(self):
        app = {'container':'app','containerId':'a'*64,'imageId':'sha256:'+'b'*64,'sourceRoot':'/srv/app','domain':'stream.example.com','baseDomain':'example.com','database':None,'dataRoots':[]}
        config = {'cloneRecoveryAdmitted':True,'apps':{'source':app},'routingNetwork':'routing'}
        inspected = {'Name':'/app','Id':'a'*64,'Image':app['imageId'],'State':{'Running':True},'Mounts':[{'Type':'bind','Source':'/srv/app'}]}
        with patch.object(m,'inspect_container',return_value=inspected), patch.object(m,'run',side_effect=lambda argv: b'[{"Internal":true}]' if 'network' in argv else b'[{"Config":{}}]'):
            p = m.plan(config,'source','copy')
            self.assertEqual(p['domain'],'local-stream.example.com')
            self.assertEqual(p['network'],'clone-copy'); self.assertFalse(p['startsWorkload'])
            app['domain']='example.com'
            self.assertEqual(m.plan(config,'source','copy')['domain'],'local.example.com')
            inspected['Image']='sha256:'+'c'*64
            with self.assertRaises(m.Rejected): m.plan(config,'source','copy')

    def test_durable_idempotency_and_target_reservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); (root/'clones').mkdir()
            op=m.Operator({'cloneRecoveryAdmitted':True,'cloneRoot':str(root/'clones')},root/'state')
            req={'operation':'clone','requestId':str(uuid.uuid4()),'sourceId':'source','targetId':'copy'}
            with patch.object(m,'plan',return_value={}), patch.object(op.pool,'submit') as submit:
                first=op.handle(req); second=op.handle(req)
                self.assertEqual(first,second); self.assertEqual(submit.call_count,1)
                with self.assertRaises(m.Rejected): op.handle({**req,'requestId':str(uuid.uuid4())})
                with self.assertRaises(m.Rejected): op.handle({**req,'targetId':'other'})
            op.pool.shutdown()
            restarted=m.Operator({'cloneRecoveryAdmitted':True,'cloneRoot':str(root/'clones')},root/'state')
            self.assertEqual(restarted.status(req['requestId'])['status'],'interrupted')
            restarted.pool.shutdown()

    def test_clone_stages_stopped_then_requires_private_publication_and_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); source=root/'source'; source.mkdir()
            (source/'index.txt').write_text('original')
            clones=root/'clones'; clones.mkdir()
            cid='c'*64; image='sha256:'+'b'*64
            app={'container':'source','containerId':'a'*64,'imageId':image,
                 'sourceRoot':str(source),'domain':'example.com','baseDomain':'example.com',
                 'include':['index.txt'],'exclude':[],'sqlite':[],'dataRoots':[],'database':None,
                 'runtime':{'argv':['/bin/web'],'uid':1234,'gid':1234,'environment':{},
                            'mountPath':'/application','databaseBinding':None,'healthcheck':['/bin/check'],'port':3000}}
            ingress_dir=root/'ingress'; ingress_dir.mkdir()
            config={'cloneRecoveryAdmitted':True,'apps':{'source':app},'cloneRoot':str(clones),'routingNetwork':'routing','ingress':{'container':'ingress','containerId':'e'*64,'imageId':'sha256:'+'f'*64,'configRoot':str(ingress_dir)}}
            rid=str(uuid.uuid4()); calls=[]
            def fake(argv,**kw):
                calls.append(argv)
                if argv[:3]==['docker','network','inspect']: return b'[{"Internal":true}]'
                if argv[:3]==['docker','image','inspect']: return b'[{"Config":{"Env":["OLD_KEY=not-inherited"]}}]'
                if argv[:2]==['docker','create']: return cid.encode()
                return b''
            source_info={'Name':'/source','Id':'a'*64,'Image':image,'State':{'Running':True},'Mounts':[{'Type':'bind','Source':str(source)}]}
            clone_info={'Name':'/clone-copy','Id':cid,'Config':{'Labels':{'platform.application-clone':rid}},'State':{'Running':True,'Health':{'Status':'healthy'}}}
            def inspect(name,expected):
                if name=='ingress': return {'Image':config['ingress']['imageId'],'State':{'Running':True},'Mounts':[{'Source':str(ingress_dir),'Destination':'/etc/nginx/conf.d','RW':False}], 'NetworkSettings':{'Networks':{'routing':{}}}, 'HostConfig':{'PortBindings':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'18181'}]}}}
                return source_info if name=='source' else clone_info
            op=m.Operator(config,root/'state')
            with op.connection() as c: c.execute('INSERT INTO jobs(id,source,target,status) VALUES (?,?,?,?)',(rid,'source','copy','queued'))
            with patch.object(m,'run',side_effect=fake),patch.object(m,'inspect_container',side_effect=inspect),patch.object(m.os,'chown'):
                op.execute(rid,'source','copy')
                self.assertEqual(op.status(rid)['status'],'staged')
                self.assertFalse(any(a[:2]==['docker','start'] for a in calls))
                create=next(a for a in calls if a[:2]==['docker','create'])
                self.assertIn('OLD_KEY=',create); self.assertNotIn('OLD_KEY=not-inherited',create)
                self.assertNotIn('--privileged',create); self.assertNotIn('--publish',create)
                self.assertEqual((source/'index.txt').read_text(),'original')
                self.assertEqual((clones/'copy/application/index.txt').read_text(),'original')
                receipt={'hostname':'local.example.com','verifiedAt':0,'accessApplicationId':str(uuid.uuid4())}
                with self.assertRaises(m.Rejected): op.activate(rid,receipt)
                receipt['verifiedAt']=m.time.time()
                self.assertEqual(op.activate(rid,receipt)['status'],'available')
                self.assertTrue(any(a[:2]==['docker','start'] for a in calls))
                self.assertIn('proxy_pass http://clone-copy:3000', (ingress_dir/'clone-copy.conf').read_text())
                self.assertTrue(any(a[-3:]==['nginx','-s','reload'] for a in calls))
            op.pool.shutdown()

    def test_ingress_rejects_public_listener_or_egress_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            config={'routingNetwork':'private','ingress':{'container':'ingress','containerId':'a'*64,'imageId':'sha256:'+'b'*64,'configRoot':tmp}}
            op=m.Operator(config,Path(tmp)/'state')
            info={'Image':config['ingress']['imageId'],'State':{'Running':True},'Mounts':[{'Source':tmp,'Destination':'/etc/nginx/conf.d','RW':False}], 'NetworkSettings':{'Networks':{'private':{}}},'HostConfig':{'PortBindings':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'18181'}]}}}
            with patch.object(m,'inspect_container',return_value=info), patch.object(m,'run',return_value=b'[{"Internal":true}]'):
                self.assertEqual(op.ingress(),config['ingress'])
                info['HostConfig']['PortBindings']['8080/tcp'][0]['HostIp']='0.0.0.0'
                with self.assertRaises(m.Rejected): op.ingress()
                info['HostConfig']['PortBindings']['8080/tcp'][0]['HostIp']='127.0.0.1'
                info['NetworkSettings']['Networks']['bridge']={}
                with self.assertRaises(m.Rejected): op.ingress()
            op.pool.shutdown()

    def test_peer_requires_exact_pinned_container_and_uid(self):
        pin='a'*64; config={'peerUid':1000,'peerContainerId':pin}
        with patch.object(m,'peer_cgroup',return_value='0::/system.slice/docker-'+pin+'.scope\n'), patch.object(m,'run',return_value=json.dumps([{'Id':pin,'State':{'Running':True}}]).encode()):
            m.authorize_peer(config,123,1000)
            with self.assertRaises(m.Rejected): m.authorize_peer(config,123,1001)
        for group in ['0::/system.slice/docker-'+('b'*64)+'.scope\n','0::/system.slice/docker-'+pin+'extra.scope\n','0::/user.slice/1000\n']:
            with patch.object(m,'peer_cgroup',return_value=group), patch.object(m,'run') as docker:
                with self.assertRaises(m.Rejected): m.authorize_peer(config,123,1000)
                docker.assert_not_called()
        with patch.object(m,'peer_cgroup',return_value='0::/docker/'+pin+'\n'), patch.object(m,'run',return_value=json.dumps([{'Id':'b'*64,'State':{'Running':True}}]).encode()):
            with self.assertRaises(m.Rejected): m.authorize_peer(config,123,1000)
        with patch.object(m,'peer_cgroup',return_value='0::/docker/'+pin+'\n'), patch.object(m,'run',return_value=json.dumps([{'Id':pin,'State':{'Running':False}}]).encode()):
            with self.assertRaises(m.Rejected): m.authorize_peer(config,123,1000)

    def test_fresh_cache_never_inherits_source_data_or_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls=[]
            def fake(argv,**kwargs):
                calls.append(argv)
                if argv[:2]==['docker','create']: return ('c'*64).encode()
                return b'OK'
            rid=str(uuid.uuid4())
            with patch.object(m,'run',side_effect=fake), patch.object(m.os,'chown'):
                info,url=m.fresh_cache({'imageId':'sha256:'+'b'*64},rid,Path(tmp),'clone-private',1000,1000,lambda:None)
            self.assertEqual(info['state'],'fresh-empty')
            self.assertIn(info['containerName'],url)
            create=calls[0]
            self.assertIn('--read-only',create); self.assertIn('--cap-drop',create)
            self.assertNotIn('--publish',create)
            password=url.split(':',2)[2].split('@')[0]
            self.assertFalse(any(password in value for argv in calls for value in argv))
            self.assertEqual((Path(tmp)/'cache-config/redis.conf').stat().st_mode & 0o777,0o440)

    def test_static_companion_copies_only_allowlist_and_targets_clone_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); source=root/'source'; source.mkdir(); (source/'site').mkdir()
            (source/'site/style.css').write_text('body {}'); (source/'index.html').write_text('<html>fixture</html>')
            (source/'private.txt').write_text('excluded')
            dest=root/'clone'; dest.mkdir(); profile={'sourceRoot':str(source),'include':['site','index.html'],'exclude':[],'sitePath':'site','indexPath':'index.html','uid':101,'gid':101,'imageId':'sha256:'+'b'*64}
            with patch.object(m,'run',return_value=('c'*64).encode()) as docker, patch.object(m.os,'chown'):
                result=m.static_frontend(profile,str(uuid.uuid4()),'fixture',dest,'private','clone-fixture',3000,'local.example.com',lambda:None)
            self.assertEqual(result['containerName'],'clone-web-fixture')
            config=(dest/'static-nginx.conf').read_text()
            self.assertIn('proxy_pass http://clone-fixture:3000',config)
            self.assertIn('internal; alias /site/index.html',config)
            self.assertFalse((dest/'static-site/private.txt').exists())
            self.assertIn('--read-only',docker.call_args.args[0])

    def test_encryption_secret_rejects_redirects_and_unadmitted_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp).resolve()/'secret'; path.write_bytes(b'a'*64); path.chmod(0o600)
            binding={'sourcePath':str(path),'ownerUid':path.stat().st_uid}
            with patch.object(m,'protected'):
                self.assertEqual(m.encryption_path(binding),path)
                with self.assertRaises(m.Rejected): m.encryption_path({**binding,'ownerUid':path.stat().st_uid+1})
                link=path.parent/'redirect'; link.symlink_to(path)
                with self.assertRaises(m.Rejected): m.encryption_path({**binding,'sourcePath':str(link)})

    def test_recovery_gate_defaults_closed_before_any_docker_operation(self):
        for value in [None,False]:
            with tempfile.TemporaryDirectory() as tmp:
                config={'apps':{'source':{'domain':'example.com','baseDomain':'example.com'}}}
                if value is not None: config['cloneRecoveryAdmitted']=value
                op=m.Operator(config,Path(tmp)/'state')
                with patch.object(m,'run') as docker:
                    self.assertEqual(op.handle({'operation':'list'}),{'apps':[]})
                    for operation in ['plan','clone']:
                        with self.assertRaises(m.Rejected): op.handle({'operation':operation,'requestId':str(uuid.uuid4()),'sourceId':'source','targetId':'copy'})
                    with self.assertRaises(m.Rejected): m.plan(config,'source','copy')
                    docker.assert_not_called()
                with op.connection() as c: self.assertEqual(c.execute('select count(*) from jobs').fetchone()[0],0)
                op.pool.shutdown()

    def test_root_profile_validates_recovery_and_dependency_admissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(); src=root/'source'; src.mkdir(); key=src/'secret'; key.write_bytes(b'a'*64); key.chmod(0o600)
            owner=key.stat().st_uid; runtime_uid=owner or 1000
            app={'container':'source','containerId':'a'*64,'imageId':'sha256:'+'b'*64,'domain':'example.com','baseDomain':'example.com','sourceRoot':str(src),'include':['secret'],'exclude':['secret'],'sqlite':[],'dataRoots':[],'database':None,'runtime':{'argv':['/usr/local/bin/node','/app/server.js'],'uid':runtime_uid,'gid':1000,'environment':{},'mountPath':'/application','databaseBinding':None,'healthcheck':['/usr/bin/check'],'port':3000},'secretBindings':[{'sourcePath':str(key),'environmentName':'SCRIPTA_ACCOUNT_SECRET_FILE','purpose':'data-encryption','ownerUid':owner}],'cache':{'container':'source-redis','containerId':'c'*64,'imageId':'sha256:'+'d'*64,'environmentName':'STUDENTS_REDIS_URL_FILE'}}
            config={'version':1,'peerUid':1000,'peerContainerId':'e'*64,'cloneRoot':'/var/lib/platform-application-operator/clones','routingNetwork':'private','ingress':{'container':'private-ingress','containerId':'f'*64,'imageId':'sha256:'+'a'*64,'configRoot':'/var/lib/platform-application-operator/ingress'},'apps':{'source':app}}
            path=root/'profile.json'
            # Only filesystem root-ownership guard mocked: schema/file checks execute.
            with patch.object(m,'PROFILE',str(path)), patch.object(m,'protected',side_effect=lambda p,**kw:Path(p)):
                path.write_text(json.dumps(config)); self.assertNotIn('cloneRecoveryAdmitted',m.load_profile())
                config['cloneRecoveryAdmitted']=True; path.write_text(json.dumps(config)); self.assertTrue(m.load_profile()['cloneRecoveryAdmitted'])
                config['cloneRecoveryAdmitted']=1; path.write_text(json.dumps(config))
                with self.assertRaises(m.Rejected): m.load_profile()
                config['cloneRecoveryAdmitted']=True
                app['secretBindings'][0]['environmentName']='OPENAI_API_KEY_FILE'; path.write_text(json.dumps(config))
                with self.assertRaises(m.Rejected): m.load_profile()

    def test_database_commands_are_scoped_new_identity(self):
        for engine in ['postgres','mariadb']:
            with self.subTest(engine=engine), tempfile.TemporaryDirectory() as tmp:
                calls=[]
                def fake_run(argv,data=None,output=None,timeout=600):
                    calls.append((argv,data))
                    if output: output.write(b'snapshot')
                    if argv[:2] == ['docker','create']: return ('c'*64).encode()
                    if argv[:2] == ['docker','run']: return b'70'
                    if argv[:3] == ['docker','image','inspect']: return b'[{"Config":{"Volumes":{}}}]'
                    if data and b'information_schema' in data: return b'0'
                    return b''
                class Pipe:
                    def write(self,data): return len(data)
                    def close(self): pass
                class Proc:
                    stdin=Pipe()
                    def __enter__(self): return self
                    def __exit__(self,*args): pass
                    def wait(self,**kw): return 0
                rid=str(uuid.uuid4())
                with patch.object(m,'inspect_container'), patch.object(m,'run',side_effect=fake_run), patch.object(m.subprocess,'Popen',return_value=Proc()), patch.object(m.os,'chown') as chown:
                    result=m.database_clone({'engine':engine,'container':'db','containerId':'a'*64,'name':'production','imageId':'sha256:'+'d'*64},rid,Path(tmp),'clone-net',lambda:None)
                self.assertEqual(result['name'],'clone_'+uuid.UUID(rid).hex)
                chown.assert_called_once_with(Path(tmp)/'database-data',70,70)
                sql=next(data for _,data in calls if data and b'CREATE' in data)
                self.assertNotIn(b'DROP',sql)
                self.assertNotIn(b'production',sql)
                self.assertEqual((Path(tmp)/'database.json').stat().st_mode & 0o777,0o600)
                self.assertFalse((Path(tmp)/'database.snapshot').exists())

if __name__ == '__main__': unittest.main()
