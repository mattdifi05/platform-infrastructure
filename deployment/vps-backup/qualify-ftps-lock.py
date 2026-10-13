#!/usr/bin/python3
"""Explicit operator-only minimal MKD exclusivity check. Does not upload backups.
Run only after root authorizes namespace/lock qualification; not called by install.
"""
import ftplib,json,pathlib,ssl,sys
CONFIG=pathlib.Path('/etc/platform-infrastructure/backup-vps/ftps-config.json')
LOCK='/.platform-server-backup-writer-lock'
TARGETS=['/server-platform-backups','/platform-server-public-backups']
def connect(c):
 f=ftplib.FTP_TLS(context=ssl.create_default_context(),timeout=60);f.connect(c['host'],c['port']);f.host=c['tlsName'];f.auth();f.login(c['username'],c['password']);f.prot_p();return f

def main():
 import os
 if os.geteuid()!=0 or sys.argv[1:]!=['--root-authorized-mkd-test']:raise RuntimeError('Explicit root-authorized provider qualification required')
 s=CONFIG.lstat()
 if CONFIG.is_symlink() or s.st_uid!=0 or s.st_mode&0o077:raise RuntimeError('FTPS configuration must be root protected')
 c=json.loads(CONFIG.read_text())
 if c.get('host')!='92.113.28.106' or c.get('port')!=21 or c.get('tlsName')!='hstgr.io' or c.get('folder')!=TARGETS[1]:raise RuntimeError('Unexpected FTPS endpoint')
 a=connect(c);b=connect(c);owned=False
 try:
  # No personal account listing and no directory creation. Missing target blocks.
  for target in TARGETS:
   a.cwd(target)
   if a.pwd()!=target:raise RuntimeError('Dedicated target path differs')
  a.mkd(LOCK);owned=True
  rejected=False
  try:b.mkd(LOCK)
  except ftplib.error_perm as e:
   if str(e).split()[0] not in ('550','521'):raise
   rejected=True
  if not rejected:raise RuntimeError('Provider MKD is not exclusive')
  print(json.dumps({'tlsVerified':True,'twoNamespacesExist':True,'independentSessions':2,'secondMkdRejected':True,'backupDataModified':False}))
 finally:
  try:
   if owned:a.rmd(LOCK)
  finally:a.close();b.close()
if __name__=='__main__':main()
