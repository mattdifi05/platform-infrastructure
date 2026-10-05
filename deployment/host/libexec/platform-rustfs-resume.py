#!/usr/bin/python3
import json,pathlib,subprocess,time
marker=pathlib.Path('/var/lib/platform-rustfs-recovery/restart-needed.json')
if marker.exists():
 state=json.loads(marker.read_text());actual=json.loads(subprocess.check_output(['docker','inspect','gf-rustfs']))[0]
 if actual['Id']!=state['containerId'] or actual['Config']['Image']!=state['image']:raise RuntimeError('RustFS restart marker identity differs')
 subprocess.run(['docker','start','gf-rustfs'],check=True,stdout=subprocess.DEVNULL)
 for _ in range(90):
  result=subprocess.run(['docker','exec','gf-rustfs','curl','-fsS','http://127.0.0.1:9000/health/ready'],capture_output=True)
  if result.returncode==0:marker.unlink();break
  time.sleep(1)
 else:raise RuntimeError('RustFS recovery restart is not healthy')
