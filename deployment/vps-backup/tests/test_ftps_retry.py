import importlib.util,pathlib,unittest
from unittest.mock import patch
p=pathlib.Path(__file__).resolve().parents[1]/'ftps-sync.py'
s=importlib.util.spec_from_file_location('vps_ftps',p);f=importlib.util.module_from_spec(s);s.loader.exec_module(f)
class RetryTests(unittest.TestCase):
 def test_retries_only_proven_contention_without_recapture(self):
  with patch.object(f,'sync_once',side_effect=[f.q.SharedQuotaBusy('busy'),'completed']) as run,patch.object(f.time,'sleep') as sleep:
   self.assertEqual(f.sync(),'completed');self.assertEqual(run.call_count,2);sleep.assert_called_once_with(60)
 def test_other_failures_are_not_hidden(self):
  with patch.object(f,'sync_once',side_effect=RuntimeError('integrity failed')) as run,patch.object(f.time,'sleep') as sleep,self.assertRaises(RuntimeError):f.sync()
  self.assertEqual(run.call_count,1);sleep.assert_not_called()
if __name__=='__main__':unittest.main()
