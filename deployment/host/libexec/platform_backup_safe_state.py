"""Root publication into shared backup state without following user-planted symlinks."""
import json,os,pathlib,shutil,uuid

def directory(path,shared=False):
 path=pathlib.Path(path)
 if not path.is_absolute() or '..' in path.parts:raise ValueError('Absolute normalized state directory required')
 current=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in path.parts[1:]:
   try:next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current)
   except FileNotFoundError:
    os.mkdir(part,0o700,dir_fd=current);next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current)
   os.close(current);current=next_fd
  os.fchown(current,0,1000 if shared else 0);os.fchmod(current,0o750 if shared else 0o700)
  return current
 except BaseException:os.close(current);raise

def publish(path,writer,shared=False):
 path=pathlib.Path(path)
 if path.name in ['', '.', '..'] or '/' in path.name:raise ValueError('Invalid state filename')
 parent=directory(path.parent,shared);temp='.publish-'+uuid.uuid4().hex
 try:
  fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
  with os.fdopen(fd,'wb') as output:
   os.fchown(output.fileno(),0,1000 if shared else 0);os.fchmod(output.fileno(),0o640 if shared else 0o600)
   writer(output);output.flush();os.fsync(output.fileno())
  os.rename(temp,path.name,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
  canonical=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   actual=os.fstat(parent);current=os.fstat(canonical)
   if (actual.st_dev,actual.st_ino)!=(current.st_dev,current.st_ino):raise RuntimeError('Published state directory moved from canonical path')
  finally:os.close(canonical)
 finally:
  try:os.unlink(temp,dir_fd=parent)
  except FileNotFoundError:pass
  os.close(parent)

def write_json(path,value,shared=False):
 data=(json.dumps(value,indent=2)+'\n').encode();publish(path,lambda output:output.write(data),shared)

def copy_file(source,target,shared=False):
 def writer(output):
  fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
  with os.fdopen(fd,'rb') as input:shutil.copyfileobj(input,output,1024*1024)
 publish(target,writer,shared)
