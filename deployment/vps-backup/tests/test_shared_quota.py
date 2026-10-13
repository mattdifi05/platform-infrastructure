import importlib.util, pathlib, unittest
from unittest.mock import patch
p=pathlib.Path(__file__).resolve().parents[1]/'platform_ftps_shared_quota.py'
s=importlib.util.spec_from_file_location('quota',p);q=importlib.util.module_from_spec(s);s.loader.exec_module(q)
class FTP:
 def __init__(self, entries): self.entries=entries; self.read=[]
 def mlsd(self,path): self.read.append(path); return self.entries[path]
class Tests(unittest.TestCase):
 def test_counts_nested_peer_without_touching_other_files(self):
  f=FTP({q.FOLDERS[1]: [('point',{'type':'dir'}),('partial',{'type':'file','size':'7'})],q.FOLDERS[1]+'/point':[('data',{'type':'file','size':'13'})]})
  self.assertEqual(q.tree_bytes(f,q.FOLDERS[1]),20)
  self.assertEqual(f.read,[q.FOLDERS[1],q.FOLDERS[1]+'/point'])
 def test_personal_scope_rejected(self):
  with self.assertRaises(RuntimeError):q.tree_bytes(FTP({}),'/public_html')
 def test_links_rejected(self):
  with self.assertRaises(RuntimeError):q.tree_bytes(FTP({q.FOLDERS[0]: [('link',{'type':'OS.unix=slink'})]}),q.FOLDERS[0])
 def test_missing_size_rejected(self):
  with self.assertRaises(RuntimeError):q.tree_bytes(FTP({q.FOLDERS[0]: [('data',{'type':'file'})]}),q.FOLDERS[0])
 def test_path_escape_rejected(self):
  with self.assertRaises(RuntimeError):q.tree_bytes(FTP({q.FOLDERS[0]: [('../personal',{'type':'dir'})]}),q.FOLDERS[0])
class LeaseTests(unittest.TestCase):
 def policy(self):return {'version':1,'bothWritersQualified':True,'folders':list(q.FOLDERS),'maximumBytes':q.LIMIT,'lockDirectory':q.LOCK}
 def config(self):return {'host':'92.113.28.106','port':21,'tlsName':'hstgr.io','folder':q.FOLDERS[0],'username':'test','password':'test'}
 def fake(self):
  from unittest.mock import MagicMock
  f=MagicMock();f.mlsd.side_effect=lambda p:[('data',{'type':'file','size':'100' if p==q.FOLDERS[0] else '200'})];return f
 def test_budget_and_lock_release(self):
  f=self.fake()
  with patch.object(q,'protected_json',side_effect=[self.policy(),self.config()]),patch.object(q.ftplib,'FTP_TLS',return_value=f):
   with q.writer_budget('/config',q.FOLDERS[0]) as budget:self.assertEqual(budget,q.LIMIT-200);f.rmd.assert_not_called()
  f.mkd.assert_called_once_with(q.LOCK);f.rmd.assert_called_once_with(q.LOCK)
 def test_existing_lock_never_removed(self):
  f=self.fake();f.mkd.side_effect=q.ftplib.error_perm('550 exists')
  with patch.object(q,'protected_json',side_effect=[self.policy(),self.config()]),patch.object(q.ftplib,'FTP_TLS',return_value=f),self.assertRaises(q.ftplib.error_perm):
   with q.writer_budget('/config',q.FOLDERS[0]):self.fail('Contending writer entered')
  f.rmd.assert_not_called();f.mlsd.assert_not_called()
 def test_unqualified_peer_fails_before_connect(self):
  p=self.policy();p['bothWritersQualified']=False
  with patch.object(q,'protected_json',return_value=p),patch.object(q.ftplib,'FTP_TLS') as f,self.assertRaises(RuntimeError):
   with q.writer_budget('/config',q.FOLDERS[0]):self.fail('Unqualified writer entered')
  f.assert_not_called()
 def test_combined_overflow_blocks_upload(self):
  f=self.fake();f.mlsd.return_value=[];f.mlsd.side_effect=lambda p:[('data',{'type':'file','size':str(q.LIMIT)})]
  with patch.object(q,'protected_json',side_effect=[self.policy(),self.config()]),patch.object(q.ftplib,'FTP_TLS',return_value=f),self.assertRaises(RuntimeError):
   with q.writer_budget('/config',q.FOLDERS[0]):self.fail('Overflow writer entered')
  f.rmd.assert_called_once_with(q.LOCK)
if __name__=='__main__':unittest.main()

class ProvenBusyTests(unittest.TestCase):
 def test_proven_lock_is_retryable_and_never_removed(self):
  from unittest.mock import MagicMock
  f=MagicMock();f.mkd.side_effect=q.ftplib.error_perm('550 exists');f.pwd.return_value=q.LOCK
  policy={'version':1,'bothWritersQualified':True,'folders':list(q.FOLDERS),'maximumBytes':q.LIMIT,'lockDirectory':q.LOCK}
  config={'host':'92.113.28.106','port':21,'tlsName':'hstgr.io','folder':q.FOLDERS[0],'username':'test','password':'test'}
  with patch.object(q,'protected_json',side_effect=[policy,config]),patch.object(q.ftplib,'FTP_TLS',return_value=f),self.assertRaises(q.SharedQuotaBusy):
   with q.writer_budget('/config',q.FOLDERS[0]):self.fail('Contender entered')
  f.rmd.assert_not_called();f.mlsd.assert_not_called()
