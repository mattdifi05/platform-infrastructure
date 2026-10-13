import importlib.util,json,os,pathlib,re,shutil,subprocess,tarfile,tempfile,unittest
HERE=pathlib.Path(__file__).resolve().parents[1]
ROOT=HERE.parents[1]
s=importlib.util.spec_from_file_location('runner',HERE/'platform-vps-backup-runner.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
class BundleTests(unittest.TestCase):
 def setUp(self):
  self.temp=pathlib.Path(tempfile.mkdtemp());self.old=(b.WORK,b.SIGNING);b.WORK=self.temp;b.SIGNING=self.temp/'key';b.SIGNING.write_bytes(os.urandom(64));self.art=self.temp/'artifacts';self.art.mkdir()
 def tearDown(self):b.WORK,b.SIGNING=self.old;shutil.rmtree(self.temp)
 def bundle(self,corrupt=False):
  artifact=self.art/'state.tar'
  with tarfile.open(artifact,'w:') as t:
   source=self.temp/'state';source.write_text('fresh synthetic test state');t.add(source,arcname='state')
  record=b.artifact_record(artifact,'state')
  seed={'jobId':'vps-unit-test-20261006','createdAt':b.now(),'resources':[{'id':'platform-state:state','externalId':'state','kind':'platform-state','projectId':'platform','name':'state'}],'artifacts':[record]}
  b.save(self.temp/'input.json',seed)
  b.run(['node',str(HERE/'native-manifest.mjs'),'sign',str(self.temp/'input.json'),str(b.SIGNING),str(self.temp/'manifest.json')])
  if corrupt:artifact.write_bytes(b'changed')
  bundle=self.temp/'bundle.tar'
  with tarfile.open(bundle,'w:') as t:t.add(self.temp/'manifest.json',arcname='manifest.json');t.add(self.art,arcname='artifacts')
  return bundle
 def test_native_product_manifest_and_each_artifact_authenticate(self):b.verify_bundle(self.bundle())
 def test_changed_artifact_fails(self):
  with self.assertRaises(RuntimeError):b.verify_bundle(self.bundle(True))
 def test_unauthenticated_sidecar_fails(self):
  self.bundle();p=self.art/'state.tar.sig.json';s=json.loads(p.read_text());s['signature']='invalid';p.write_text(json.dumps(s))
  bundle=self.temp/'tampered.tar'
  with tarfile.open(bundle,'w:') as t:t.add(self.temp/'manifest.json',arcname='manifest.json');t.add(self.art,arcname='artifacts')
  with self.assertRaises(RuntimeError):b.verify_bundle(bundle)
 def test_clean_installed_node_bundle_has_all_imports(self):
  # Stage exactly the file sets named by install.sh, without a host extension.
  script=(HERE/'install.sh').read_text()
  groups=re.findall(r'^for name in (.+); do$',script,re.M)
  self.assertEqual(len(groups),2)
  stage=self.temp/'installed'
  for source,names in ((HERE,groups[0]),(ROOT/'control-center/backup',groups[1])):
   relative=source.relative_to(ROOT)
   target=stage/relative
   target.mkdir(parents=True,exist_ok=True)
   for name in names.split():shutil.copy2(source/name,target/name)
  control=stage/'scripts/backup-queue-control.mjs'
  control.parent.mkdir(parents=True,exist_ok=True)
  shutil.copy2(ROOT/'scripts/backup-queue-control.mjs',control)
  env={**os.environ}
  env.pop('CONTROL_CENTER_HOST_EXTENSION_FILE',None)
  manifest=stage/'deployment/vps-backup/native-manifest.mjs'
  seed={'jobId':'vps-clean-install-20261013','createdAt':b.now(),
        'resources':[{'id':'platform-state:state','externalId':'state','kind':'platform-state','projectId':'platform','name':'state'}],
        'artifacts':[{'id':'artifact-state','resourceId':'platform-state:state','path':'artifacts/state.tar','sha256':'a'*64,'sizeBytes':1,'signatureKeyId':'vps-genesis-1'}]}
  input_file=self.temp/'clean-input.json';input_file.write_text(json.dumps(seed))
  signed=self.temp/'clean-manifest.json'
  subprocess.run(['node',str(manifest),'sign',str(input_file),str(b.SIGNING),str(signed)],env=env,check=True,capture_output=True,text=True)
  verified=subprocess.run(['node',str(manifest),'verify',str(signed),str(b.SIGNING)],env=env,check=True,capture_output=True,text=True)
  self.assertTrue(json.loads(verified.stdout)['coverageComplete'])
  queue=subprocess.run(['node',str(control),'invalid'],env=env,capture_output=True,text=True)
  self.assertNotIn('ERR_MODULE_NOT_FOUND',queue.stderr)
  self.assertIn('Missing required option: --jobsDir',queue.stderr)
if __name__=='__main__':unittest.main()
