import importlib.util,json,os,pathlib,tempfile,types,unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[1]
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,ROOT/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
c=load('control_fixture','backup-control.py');runner=load('runner_fixture','platform-vps-backup-runner.py')
class BackupControl(unittest.TestCase):
 def setUp(self):
  self.scratch=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.scratch.name);(self.root/'profile.json').write_text('{}');self.profile={'captureAuthorized':True,'offsiteAuthorized':True}
  def private(path,*args):
   p=pathlib.Path(path)
   if p.is_symlink() or p.stat().st_mode&0o077:raise RuntimeError('Unprotected fixture state')
   return p
  self.b=types.SimpleNamespace(CONFIG=self.root,PROFILE=self.root/'profile.json',canonical=runner.canonical,sha=runner.sha,save=runner.save,now=runner.now,private=private)
  self.timer_calls=[];self.timers=mock.patch.object(c,'timers',side_effect=lambda enabled:self.timer_calls.append(enabled));self.timers.start()
 def tearDown(self):self.timers.stop();self.scratch.cleanup()
 def job(self,enabled,revision=None,identity='control-job-00000000000001'):
  return {'id':identity,'backupEnabled':enabled,'expectedControlRevision':revision or c.status(self.b,self.profile)['revision']}
 def disable(self):return c.apply(self.b,self.profile,self.job(False))
 def test_absent_file_preserves_enrolled_legacy_behavior(self):
  self.assertTrue(c.status(self.b,self.profile)['enabled']);self.assertFalse(c.status(self.b,{})['available'])
  c.require_enabled(self.b,{'captureAuthorized':True,'offsiteAuthorized':False})
  with self.assertRaisesRegex(RuntimeError,'disabled'):c.require_enabled(self.b,{})
 def test_off_is_durable_and_blocks_before_backup_side_effect(self):
  state=self.disable();self.assertFalse(state['enabled']);self.assertEqual(len(state['revision']),64);self.assertEqual((self.root/'backup-control.json').stat().st_mode&0o777,0o600)
  reloaded=load('reloaded_control','backup-control.py');self.assertEqual(reloaded.status(self.b,self.profile),state)
  with self.assertRaisesRegex(RuntimeError,'disabled'):reloaded.require_enabled(self.b,self.profile)
 def test_stale_revision_rejected_and_on_never_expands_signed_capability(self):
  before=c.status(self.b,self.profile)['revision'];self.disable()
  with self.assertRaisesRegex(RuntimeError,'revision changed'):c.apply(self.b,self.profile,self.job(True,before))
  denied={'captureAuthorized':True,'offsiteAuthorized':False}
  with self.assertRaisesRegex(RuntimeError,'Signed'):c.apply(self.b,denied,self.job(True))
 def test_on_arms_timers_before_root_ack_and_off_gates_first(self):
  self.disable();seen=[]
  with mock.patch.object(c,'timers',side_effect=lambda enabled:seen.append(c.status(self.b,self.profile)['enabled'])):enabled=c.apply(self.b,self.profile,self.job(True,identity='control-job-00000000000002'))
  self.assertEqual(seen,[False]);self.assertTrue(enabled['enabled'])
  with mock.patch.object(c,'timers',side_effect=lambda enabled:seen.append(c.status(self.b,self.profile)['enabled'])):self.disable()
  self.assertEqual(seen,[False,False])
 def test_corrupt_or_unprotected_state_fails_closed(self):
  self.disable();p=self.root/'backup-control.json';value=json.loads(p.read_text());value['enabled']=True;p.write_text(json.dumps(value))
  with self.assertRaisesRegex(RuntimeError,'revision differs'):c.require_enabled(self.b,self.profile)
 def test_capture_and_publication_gates_run_before_other_work(self):
  with mock.patch.object(runner,'assert_backup_enabled',side_effect=RuntimeError('disabled')),mock.patch.object(runner,'settle_restore_journal',side_effect=AssertionError('must not mutate journal')):
   with self.assertRaisesRegex(RuntimeError,'disabled'):runner.capture()
  ftp=load('ftp_gate_fixture','ftps-sync.py')
  with mock.patch.object(ftp.b,'assert_backup_enabled',side_effect=RuntimeError('disabled')),mock.patch.object(ftp.b,'profile',side_effect=AssertionError('must gate before FTPS work')):
   with self.assertRaisesRegex(RuntimeError,'disabled'):ftp.sync_once()
 def test_timer_failure_keeps_off_durable(self):
  with mock.patch.object(c,'timers',side_effect=RuntimeError('fixture scheduling failure')):
   with self.assertRaisesRegex(RuntimeError,'scheduling failure'):self.disable()
  self.assertFalse(c.status(self.b,self.profile)['enabled'])
 def test_timer_policy_keeps_only_control_channel_active_when_off(self):
  self.timers.stop()
  for enabled in (False,True):
   commands=[]
   with mock.patch.object(c,'timer_loaded',return_value=True),mock.patch.object(c.subprocess,'run',side_effect=lambda args,**kwargs:commands.append(args) or types.SimpleNamespace(returncode=0)):c.timers(enabled)
   self.assertIn(['systemctl','enable' if enabled else 'disable','--now','platform-vps-backup.timer'],commands)
   self.assertIn(['systemctl','enable','--now','platform-vps-backup-queue.timer'],commands)
   if hasattr(c,'OBSERVER_TIMER'):
    self.assertIn(['systemctl','disable','--now',c.OBSERVER_TIMER],commands)
    self.assertFalse(any(args[1]=='enable' and args[-1]==c.OBSERVER_TIMER for args in commands))
  self.timers.start()
 def test_failed_on_catalog_publication_reverts_gate_and_schedules(self):
  self.disable();self.b.publish_catalog=mock.Mock(side_effect=RuntimeError('fixture catalog failure'))
  with self.assertRaisesRegex(RuntimeError,'catalog failure'):c.apply_and_publish(self.b,self.profile,self.job(True,identity='control-job-00000000000004'))
  self.assertFalse(c.status(self.b,self.profile)['enabled']);self.assertEqual(self.timer_calls[-2:],[True,False])
 def test_on_persistence_failure_always_stops_schedules(self):
  self.disable();original=self.b.save
  def failing_save(path,value):
   if value.get('enabled') is True:raise OSError('fixture persistence failure')
   return original(path,value)
  self.b.save=failing_save
  with self.assertRaisesRegex(OSError,'persistence failure'):c.apply(self.b,self.profile,self.job(True,identity='control-job-00000000000005'))
  self.assertFalse(c.status(self.b,self.profile)['enabled']);self.assertEqual(self.timer_calls[-2:],[True,False])
 def test_compensation_persistence_failure_still_disables_schedules(self):
  self.disable();original=self.b.save
  def partially_committed_save(path,value):
   if value['enabled']:original(path,value)
   raise OSError('fixture filesystem failure')
  self.b.save=partially_committed_save
  with self.assertRaisesRegex(RuntimeError,'root reconciliation'):c.apply(self.b,self.profile,self.job(True,identity='control-job-00000000000006'))
  self.assertTrue(c.status(self.b,self.profile)['enabled']);self.assertEqual(self.timer_calls[-2:],[True,False])
 def queue_fixture(self,operation='backup',queued=True):
  q=load('queue_guard_fixture','panel-queue.py');work=self.root/'guard-work';running=work/'queue/running';running.mkdir(parents=True);(work/'operation.lock').touch();identity='backup-job-00000000000009';file=running/(identity+'.json')
  resource={'id':'platform-state:host-config','externalId':'host-config','kind':'platform-state','projectId':'platform','name':'host-config'}
  job={'id':identity,'schema':'platform.backup-job/v1','status':'running','scope':{'kind':'platform','id':'platform'},'requestedBy':'authenticated-owner','operation':operation,'resources':[resource]};file.write_text(json.dumps(job))
  b=types.SimpleNamespace(**vars(self.b));b.WORK=work;b.profile=mock.Mock(side_effect=RuntimeError('Unexpected running container blocks capture'));b.private=lambda path,*args:path;b.settle_restore_journal=mock.Mock();b.enrolled_resources=mock.Mock(return_value=[resource]);b.backup_control=lambda:c;b.capture=mock.Mock(side_effect=AssertionError('capture must not run'));b.assert_backup_enabled=lambda profile:c.require_enabled(b,profile)
  calls=[]
  def command(*args):calls.append(args);return str(file) if queued and args[0]=='claim' else ''
  stat=types.SimpleNamespace(st_uid=1000,st_mode=0o100600,st_nlink=1,st_size=file.stat().st_size)
  return q,b,work,file,calls,command,stat
 def run_queue_fixture(self,values):
  q,b,work,file,calls,command,stat=values
  with mock.patch.object(q,'b',b),mock.patch.object(q,'QUEUE',work/'queue'),mock.patch.object(q,'queue_command',side_effect=command),mock.patch.object(q.os,'geteuid',return_value=0),mock.patch.object(q.os,'fstat',return_value=stat),mock.patch.object(q.sys,'argv',['panel-queue.py']):q.main()
 def test_idle_off_queue_never_runs_capture_admission_or_recovery(self):
  self.disable();values=self.queue_fixture(queued=False);self.run_queue_fixture(values);q,b,work,file,calls,command,stat=values
  b.profile.assert_not_called();b.settle_restore_journal.assert_not_called();b.capture.assert_not_called();self.assertEqual(calls,[('claim',)])
 def test_queued_backup_off_is_denied_before_stale_runtime_admission_and_no_capture(self):
  self.disable();values=self.queue_fixture();self.run_queue_fixture(values);q,b,work,file,calls,command,stat=values
  b.profile.assert_not_called();b.settle_restore_journal.assert_not_called();b.enrolled_resources.assert_not_called();b.capture.assert_not_called()
  record=json.loads((work/'operations'/(file.stem+'.json')).read_text());self.assertEqual(record['status'],'failed');self.assertEqual(record['reason'],'backup-disabled')
  finish=next(call for call in calls if call[0]=='finish');self.assertIn('failed',finish);self.assertTrue(any('no capture or offsite' in field for field in finish))
  self.assertFalse(c.status(self.b,self.profile)['enabled']);self.assertEqual(self.timer_calls,[False])
 def test_on_queue_still_requires_full_runtime_admission_and_never_bypasses_capture_guard(self):
  values=self.queue_fixture()
  with self.assertRaisesRegex(RuntimeError,'Unexpected running'):self.run_queue_fixture(values)
  q,b,work,file,calls,command,stat=values;b.profile.assert_called_once();b.capture.assert_not_called()
  self.assertTrue(any(call[0]=='finish' and 'failed' in call for call in calls))
 def test_raw_off_guard_requires_valid_protected_state_and_preserves_legacy_default(self):
  self.assertFalse(c.capture_disabled(self.b));self.disable();self.assertTrue(c.capture_disabled(self.b))
  file=self.root/'backup-control.json';value=json.loads(file.read_text());value['enabled']=True;file.write_text(json.dumps(value))
  with self.assertRaisesRegex(RuntimeError,'revision differs'):c.capture_disabled(self.b)
 def test_existing_queue_handles_control_while_off_without_capture(self):
  before=self.disable();q=load('queue_fixture','panel-queue.py');work=self.root/'work';running=work/'queue/running';running.mkdir(parents=True);(work/'operation.lock').touch();identity='control-job-00000000000003';file=running/(identity+'.json')
  resource={'id':'platform-state:host-config','externalId':'host-config','kind':'platform-state','projectId':'platform','name':'host-config'}
  job={**self.job(False,before['revision'],identity), 'schema':'platform.backup-job/v1','status':'running','scope':{'kind':'platform','id':'platform'},'requestedBy':'authenticated-owner','operation':'backup-control','resources':[resource]};file.write_text(json.dumps(job));calls=[];published=[]
  b=types.SimpleNamespace(**vars(self.b));b.WORK=work;b.profile=lambda:(self.profile,[]);b.private=lambda path,*a:path;b.settle_restore_journal=lambda:None;b.enrolled_resources=lambda p:[resource];b.backup_control=lambda:c;b.publish_catalog=lambda:published.append(c.status(b,self.profile));b.assert_backup_enabled=lambda p:c.require_enabled(b,p);b.capture=lambda: self.fail('control-only OFF worker must never capture')
  stat=types.SimpleNamespace(st_uid=1000,st_mode=0o100600,st_nlink=1,st_size=file.stat().st_size)
  def command(*args):
   calls.append(args);return str(file) if args[0]=='claim' else ''
  with mock.patch.object(q,'b',b),mock.patch.object(q,'QUEUE',work/'queue'),mock.patch.object(q,'queue_command',side_effect=command),mock.patch.object(q.os,'geteuid',return_value=0),mock.patch.object(q.os,'fstat',return_value=stat),mock.patch.object(q.sys,'argv',['panel-queue.py']):q.main()
  self.assertEqual(published[0]['requestId'],identity);self.assertFalse(published[0]['enabled']);self.assertTrue(any(call[0]=='finish' and 'done' in call for call in calls));self.assertEqual(json.loads((work/'operations'/(identity+'.json')).read_text())['status'],'done')
if __name__=='__main__':unittest.main()
