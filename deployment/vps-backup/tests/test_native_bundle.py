import importlib.util,json,os,pathlib,shutil,tarfile,tempfile,unittest
HERE=pathlib.Path(__file__).resolve().parents[1]
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
if __name__=='__main__':unittest.main()
