import importlib.util,os,pathlib,stat,tempfile,types,unittest
from unittest.mock import patch

SOURCE=pathlib.Path(__file__).resolve().parents[2]/'deployment/host/libexec/platform-server-ai-admin.py'
def load():
 spec=importlib.util.spec_from_file_location('admin_scope_test',SOURCE)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 module.PORTABLE=True
 return module

class InfrastructureScopeTests(unittest.TestCase):
 def setUp(self):self.a=load()
 def test_service_change_preserves_restart_but_protects_stop_lockout(self):
  a=self.a
  def unit_status(argv,**kwargs):return 'Id='+argv[2]+'\nLoadState=loaded\nFragmentPath=/usr/lib/systemd/system/'+argv[2]+'\nCanReload=yes\nUnitFileState=enabled\n'
  with patch.object(a,'discovered_unit',side_effect=lambda name:name),patch.object(a,'command',side_effect=unit_status),patch.object(a.pathlib.Path,'stat',return_value=types.SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=0)):
   self.assertEqual(a.writable_service('ssh.service','service_restart'),'ssh.service')
   self.assertEqual(a.writable_service('rsyslog.service','service_stop'),'rsyslog.service')
   for target in ['ssh.service','docker.service','platform-server-ai-admin.service','systemd-resolved.service','platform-vps-backup.service','php-app.service']:
    with self.subTest(target=target),self.assertRaises(a.Rejected):a.writable_service(target,'service_stop')
 def test_package_candidate_requires_official_origin_and_no_hold(self):
  a=self.a
  policy='chrony:\n  Installed: 1\n  Candidate: 2\n  Version table:\n     2 500\n        500 http://archive.ubuntu.com/ubuntu resolute/main amd64 Packages\n'
  with patch.object(a,'command',side_effect=lambda argv,**kw:'' if argv[:2]==['apt-mark','showhold'] else policy):
   self.assertEqual(a.official_apt_candidate('chrony'),'2')
  with patch.object(a,'command',side_effect=lambda argv,**kw:'' if argv[:2]==['apt-mark','showhold'] else policy.replace('archive.ubuntu.com','example.net')):
   with self.assertRaises(a.Rejected):a.official_apt_candidate('chrony')
  vendor=policy.replace('http://archive.ubuntu.com/ubuntu','https://download.docker.com/linux/ubuntu')
  with patch.object(a,'command',side_effect=lambda argv,**kw:'' if argv[:2]==['apt-mark','showhold'] else vendor):
   self.assertEqual(a.official_apt_candidate('chrony',allow_vendor=True),'2')
   with self.assertRaises(a.Rejected):a.official_apt_candidate('chrony',allow_vendor=False)
  with self.assertRaises(a.Rejected):a.official_apt_candidate('--unsafe')
 def test_apt_plan_checks_every_transitive_candidate(self):
  a=self.a
  simulation='Inst chrony [1] (2 Ubuntu)\nInst dependency (1 Ubuntu)\n'
  with patch.object(a,'official_apt_candidate',side_effect=lambda name,**kw: (_ for _ in ()).throw(a.Rejected('third party')) if name=='dependency' else '2'),patch.object(a,'command',return_value=simulation):
   with self.assertRaises(a.Rejected):a.checked_apt_plan('chrony',False)
 def test_read_targets_do_not_accept_paths_or_shell(self):
  a=self.a
  with patch.object(a,'portable_catalog',return_value=(['config','services','logs'],[],[],[],{})):
   for target in ['/etc/shadow','../profile','chrony.service;id','chrony.service\nother']:
    with self.subTest(target=target),self.assertRaises(a.Rejected):a.read('config',target,'owner')
   with self.assertRaises(a.Rejected):a.read('config','authority-private','owner')
 def test_package_inventory_page_is_bounded_and_lookup_exact(self):
  a=self.a
  with patch.object(a,'portable_catalog',return_value=(['packages'],[],[],[],{})),patch.object(a,'package_rows',return_value=[[f'pkg-{n}','1.0'] for n in range(120)]):
   first=a.read('packages','','owner');second=a.read('packages','page:1','owner')
   self.assertEqual((len(first['installed']),first['total']), (50,120))
   self.assertEqual(len(second['installed']),50)
   self.assertEqual(a.read('packages','pkg-119','owner')['installed'],[['pkg-119','1.0']])
   with self.assertRaises(a.Rejected):a.read('packages','page:1;id','owner')
 def test_log_redaction_masks_opaque_values(self):
  a=self.a
  self.assertNotIn('A'*64,a.clean('trace='+'A'*64))
  self.assertNotIn('abc123',a.clean('https://example.com/x?code=abc123'))
 def test_typed_config_patch_rejects_unsafe_calendar_and_ssh_values(self):
  a=self.a
  with patch.object(a,'portable_catalog',return_value=([],['config_patch'],[],[],{})):
   self.assertEqual(a.validate_change('config_patch',{'target':'vps-backup-timer','onCalendar':'Fri *-*-* 06:05:00 Europe/Rome'})['target'],'vps-backup-timer')
   self.assertEqual(a.validate_change('config_patch',{'target':'sshd-hardening','maxAuthTries':4})['maxAuthTries'],4)
   for args in [{'target':'vps-backup-timer','onCalendar':'daily 00:00'},{'target':'sshd-hardening','maxAuthTries':1},{'target':'sshd-hardening','logLevel':'NOTICE'},{'target':'sshd-hardening','logLevel':'QUIET'},{'target':'sshd-hardening','port':22}]:
    with self.subTest(args=args),self.assertRaises(a.Rejected):a.validate_change('config_patch',args)
 def test_fixed_config_replacement_fsyncs_file_and_parent_directory(self):
  a=self.a
  with tempfile.TemporaryDirectory() as tmp:
   parent=pathlib.Path(tmp);target=parent/'schedule.conf';real_stat=pathlib.Path.stat;real_fsync=os.fsync
   def protected_parent(path,*args,**kwargs):
    if path==parent:return types.SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0)
    return real_stat(path,*args,**kwargs)
   with patch.object(a.pathlib.Path,'stat',autospec=True,side_effect=protected_parent),patch.object(a.os,'fsync',wraps=real_fsync) as fsync:
    a.replace_fixed_config(target,b'[Timer]\nOnCalendar=Fri *-*-* 06:05:00 Europe/Rome\n')
    self.assertEqual(target.read_bytes().splitlines()[0],b'[Timer]')
    self.assertGreaterEqual(fsync.call_count,2)
    target.unlink();a.sync_config_directory(parent)
    self.assertGreaterEqual(fsync.call_count,3)

if __name__=='__main__':unittest.main()
