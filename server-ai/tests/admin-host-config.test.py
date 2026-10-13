import importlib.util,pathlib,unittest
from unittest.mock import patch
SOURCE=pathlib.Path(__file__).resolve().parents[2]/'deployment/host/libexec/platform-server-ai-admin.py'
def load():
 spec=importlib.util.spec_from_file_location('admin_test',SOURCE);a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a);return a
class ConfigTests(unittest.TestCase):
 def setUp(self):
  self.a=load();self.identity='a'*64
  self.cfg={'version':1,'machineId':self.identity,'containers':['gf-postgres','gf-control-center'],'services':['docker.service'],'jobs':{},'inventoryFile':'/etc/platform-infrastructure/server-ai/infrastructure-inventory.json','backupRoot':None,'runtimeRoot':None}
 def test_home_defaults_preserved_without_config(self):
  a=self.a
  self.assertFalse(a.PORTABLE);self.assertIn('php-anniversary',a.CONTAINERS)
  self.assertEqual(str(a.BACKUP),'/home/platform_infrastructure/v1-fresh-runtime/local-private-backup')
  self.assertEqual(a.JOBS['backup'],'platform-backup-schedule.service')
 def test_empty_host_valid_with_no_home_paths_or_jobs(self):
  cfg=self.a.validate_host_config(self.cfg,self.identity)
  self.assertIsNone(cfg['backupRoot']);self.assertEqual(cfg['jobs'],{})
 def test_foreign_machine_unknown_fields_apps_readers_and_arbitrary_units_rejected(self):
  cases=[('machineId','b'*64),('version',2),('version',True),('jobs',{'invented':None}),('containers',['php-anniversary']),('containers',['gf-server-ai-project-source-reader']),('services',['arbitrary-root.service']),('jobs',{'backup':'arbitrary-root.service'}),('inventoryFile','/tmp/inventory.json')]
  for key,value in cases:
   with self.subTest(key=key,value=value):
    with self.assertRaises(self.a.Rejected):self.a.validate_host_config({**self.cfg,key:value},self.identity)
  with self.assertRaises(self.a.Rejected):self.a.validate_host_config({**self.cfg,'unknown':True},self.identity)
 def test_standard_core_names_are_explicitly_supported_without_wildcards(self):
  cfg={**self.cfg,'containers':['enterprise-postgres','enterprise-control-center','mariadb']}
  self.a.validate_host_config(cfg,self.identity)
  with self.assertRaises(self.a.Rejected):self.a.validate_host_config({**cfg,'containers':['enterprise-unreviewed-project']},self.identity)
 def test_bounded_paths_and_backup_state_requirement(self):
  for value in ['/etc','/tmp/backup','/srv/platform-infrastructure/../secrets','/var/lib/platform-infrastructure/./backup','/srv/platform-infrastructure//backup','relative']:
   with self.subTest(value=value):
    with self.assertRaises(self.a.Rejected):self.a.bounded_runtime_path(value)
  with self.assertRaises(self.a.Rejected):self.a.validate_host_config({**self.cfg,'jobs':{'backup':'platform-backup-schedule.service'}},self.identity)
 def test_portable_catalog_does_not_offer_home_actions_or_uninstalled_jobs(self):
  a=self.a;a.PORTABLE=True;a.CONTAINERS=frozenset(self.cfg['containers']);a.SERVICES=frozenset(['docker.service','chrony.service']);a.JOBS={'backup':'platform-backup-schedule.service'};a.RUNTIME=None
  with patch.object(a,'loaded_unit',side_effect=lambda name:name=='docker.service'),patch.object(a.shutil,'which',return_value='/usr/bin/tool'),patch.object(a,'command',return_value='gf-postgres\ngf-control-center\n'):
   topics,ops,containers,services,jobs=a.portable_catalog()
  self.assertEqual(services,['docker.service']);self.assertEqual(jobs,{})
  self.assertNotIn('backups',topics);self.assertNotIn('tls',topics)
  for op in ['dns_record_set','dns_record_remove','firewall_reapply','maintenance_run','firewall_ban']:self.assertNotIn(op,ops)
  self.assertIn('container_restart',ops);self.assertIn('service_restart',ops);self.assertIn('database_reload',ops)
 def test_config_loader_rejects_arbitrary_path_before_read(self):
  with self.assertRaises(self.a.Rejected):self.a.configure_host('/tmp/config.json')
if __name__=='__main__':unittest.main()
