import sys,tempfile,pathlib,os,json,shutil
sys.path.insert(0,'/usr/local/libexec')
import platform_backup_safe_state as s
root=pathlib.Path(tempfile.mkdtemp(prefix='safe-state-test-',dir='/var/tmp'))
try:
 victim=root/'victim';victim.write_text('preserve')
 out=root/'out';out.mkdir();(out/'proof.json').symlink_to(victim)
 s.write_json(out/'proof.json',{'ok':True},True)
 assert victim.read_text()=='preserve' and not (out/'proof.json').is_symlink()
 assert (out/'proof.json').stat().st_uid==0 and (out/'proof.json').stat().st_gid==1000
 assert (out/'proof.json').stat().st_mode&0o777==0o640
 link=root/'link';link.symlink_to(out,target_is_directory=True)
 try:s.write_json(link/'bad',{},True)
 except OSError:pass
 else:raise AssertionError('symlink directory accepted')
 moved=root/'moved';target=root/'target';target.mkdir()
 def race(f):
  out.rename(moved);out.symlink_to(target,target_is_directory=True);f.write(b'bound')
 try:s.publish(out/'race',race,True)
 except (OSError,RuntimeError):pass
 else:raise AssertionError('Moved publication falsely reported success')
 assert (moved/'race').read_bytes()==b'bound' and not (target/'race').exists()
 private=root/'private';s.write_json(private/'proof',{})
 assert private.stat().st_mode&0o777==0o700 and (private/'proof').stat().st_mode&0o777==0o600
 print(json.dumps({'status':'passed','tests':4,'targetSymlinkDidNotOverwriteVictim':True,'directorySymlinkRejected':True,'renameRaceConfinedAndFailedClosed':True,'rootOwnershipAndSharedReadModes':True}))
finally:shutil.rmtree(root)
