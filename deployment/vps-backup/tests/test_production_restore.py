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
if __name__=='__main__':unittest.main()
