"""Full producer protocol in a closed fixture harness; production disabled.

Real GPG is the default crypto backend. Only the exact in-memory FTP class below
is accepted, and all inputs/key/spool must be inside one private fixture root.
"""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from unittest.mock import patch

class FakeFTP:
    def __init__(self, files=None, fault=None):
        self.files = dict(files or {})
        self.fault = fault or (lambda event, name: None)
        self.deleted = []
        self.uploads = []
    def mlsd(self):
        return [(n, {'type':'file','size':len(v)}) for n,v in self.files.items()]
    def retrbinary(self, cmd, callback, blocksize=65536):
        name=cmd[5:]
        for start in range(0,len(self.files[name]),blocksize):
            self.fault('download',name)
            callback(self.files[name][start:start+blocksize])
    def storbinary(self,cmd,stream,blocksize=65536):
        name=cmd[5:]
        self.uploads.append(name)
        if cmd.startswith('STOR '):self.files[name]=b''
        while True:
            chunk=stream.read(blocksize)
            if not chunk:break
            self.files[name]=self.files.get(name,b'')+chunk
            self.fault('upload',name)
    def rename(self,a,b):
        self.files[b]=self.files.pop(a)
        self.fault('rename',b)
    def delete(self,name):
        self.deleted.append(name);del self.files[name]
    def voidcmd(self,cmd):return '200'
    def size(self,name):return len(self.files[name])
    def close(self):pass
    def quit(self):pass


def durable(path,value):
    data=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    fd,name=tempfile.mkstemp(prefix='.journal-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as output:
            output.write(data);output.flush();os.fsync(output.fileno())
        os.replace(name,path)
        sync_dir(path.parent)
    finally:
        if os.path.exists(name):os.unlink(name)


def sync_dir(path):
    fd=os.open(path,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)


def private(path,root,directory=False):
    path=Path(path)
    if root not in path.parents or path.resolve()!=path or path.is_symlink():
        raise RuntimeError('Fixture path escape or symlink')
    st=path.stat()
    if st.st_mode & 0o077 or st.st_uid!=os.getuid():raise RuntimeError('Fixture input is not private')
    if directory:
        if not path.is_dir():raise RuntimeError('Expected private directory')
    elif not path.is_file() or st.st_nlink!=1:raise RuntimeError('Expected private regular file')
    return path


class FileHashReader:
    """Bounded streaming reader that hashes the exact tar bytes sent to GPG."""
    def __init__(self,path):
        self.path=Path(path);self.stream=self.path.open('rb')
        self._hash=hashlib.sha256();self.bytes_read=0
    @property
    def hexdigest(self):return self._hash.hexdigest()
    def read(self,size):
        if size<=0 or size>1024*1024:raise RuntimeError('Unbounded source archive read')
        data=self.stream.read(size)
        self.bytes_read+=len(data);self._hash.update(data)
        return data
    def close(self):self.stream.close()


class HashingWriter:
    """Hash tar stream bytes while writing them without buffering the archive."""
    def __init__(self,stream):self.stream=stream;self._hash=hashlib.sha256();self.bytes_written=0
    def write(self,data):
        if len(data)>1024*1024:raise RuntimeError('Unbounded tar stream write')
        written=self.stream.write(data)
        if written!=len(data):raise RuntimeError('Short tar stream write')
        self._hash.update(data);self.bytes_written+=written
        return written
    def flush(self):return self.stream.flush()
    @property
    def proof(self):return {'sha256':self._hash.hexdigest(),'bytes':self.bytes_written}


def create_source_archive(source,files,output):
    source=Path(source);output=Path(output)
    with output.open('xb') as raw:
        os.chmod(output,0o600);writer=HashingWriter(raw)
        with tarfile.open(fileobj=writer,mode='w|') as archive:
            for item in files:
                archive.add(source/item['name'],arcname=item['name'],recursive=False)
        writer.flush();raw.flush();os.fsync(raw.fileno())
        proof=writer.proof
    return proof


def verify_archive_members(archive_path,files,expected_names):
    rows={item['name']:item for item in files}
    if len(rows)!=len(files) or set(rows)!=set(expected_names):
        raise RuntimeError('Preflight expected member map differs')
    seen=set();result=[];total=0
    with Path(archive_path).open('rb') as raw,tarfile.open(fileobj=raw,mode='r|') as archive:
        for member in archive:
            if member.name not in rows or member.name in seen or not member.isfile():
                raise RuntimeError('Preflight archive member scope differs')
            expected=rows[member.name]
            if member.size!=expected['bytes']:raise RuntimeError('Preflight member size differs')
            stream=archive.extractfile(member)
            if stream is None:raise RuntimeError('Preflight member unreadable')
            digest=hashlib.sha256();count=0
            with stream:
                while True:
                    block=stream.read(1024*1024)
                    if not block:break
                    count+=len(block);total+=len(block)
                    if count>expected['bytes'] or total>sum(x['bytes'] for x in files):
                        raise RuntimeError('Preflight archive exceeds signed source bound')
                    digest.update(block)
            actual=digest.hexdigest()
            if count!=expected['bytes'] or actual!=expected['sha256']:
                raise RuntimeError('Preflight member hash differs:'+member.name)
            seen.add(member.name)
            result.append({'name':member.name,'bytes':count,'sha256':actual})
    if seen!=set(expected_names):raise RuntimeError('Preflight archive member missing')
    return result


class GPG:
    real=True
    def common(self,key,home):
        return ['gpg','--no-options','--homedir',str(home),'--batch','--yes',
                '--pinentry-mode','loopback','--passphrase-file',str(key)]
    def encrypt(self,source_archive,key,home,output):
        command=self.common(key,home)+['--symmetric','--cipher-algo','AES256',
             '--compress-algo','none','--s2k-digest-algo','SHA512','--s2k-count','65011712','--output',str(output)]
        process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            reader=FileHashReader(source_archive)
            try:
                while True:
                    block=reader.read(1024*1024)
                    if not block:break
                    process.stdin.write(block)
            finally:
                reader.close()
            process.stdin.close()
            if process.wait()!=0:raise RuntimeError('Fixture GPG encryption failed')
            return {'sha256':reader.hexdigest,'bytes':reader.bytes_read}
        except BaseException:
            if process.poll() is None:process.kill()
            process.wait()
            raise
    def decrypt(self,cipher,key,home,output):
        subprocess.run(self.common(key,home)+['--decrypt','--output',str(output),str(cipher)],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def production_publish(*args,**kwargs):
    raise RuntimeError('PRODUCTION_COMPLETENESS_PUBLISH_DISABLED')


def source_index(b,source,root):
    private(source,root,True)
    files=[]
    for path in sorted(source.rglob('*')):
        if path.is_dir():private(path,root,True);continue
        private(path,root)
        name=path.relative_to(source).as_posix()
        if not b.supplement_member_name(name):raise RuntimeError('Unsafe source member')
        files.append({'name':name,'bytes':path.stat().st_size,'sha256':b.sha(path)})
    if not {'coverage.json','RECOVERY.md'}<={item['name'] for item in files}:
        raise RuntimeError('Missing coverage or recovery instructions')
    if len(files)>b.SUPPLEMENT_MAX_FILES or sum(i['bytes'] for i in files)>b.CAP:
        raise RuntimeError('Source exceeds completeness bounds')
    coverage=json.loads((source/'coverage.json').read_text())
    if coverage.get('fullyRecoverable') is not False or not coverage.get('knownGaps'):
        raise RuntimeError('Explicit incomplete coverage required')
    return files,coverage['knownGaps']


def reserve_pending(b,f,payload,parent):
    listing=b.inventory(f);objects=b.supplement_objects(payload)
    receipt=payload['ciphertext']+'.receipt.json';partial=receipt+'.partial'
    extras={*objects,receipt,partial}
    confirmed=b.points(f,{n:v for n,v in listing.items() if n not in extras})
    if parent not in confirmed:raise RuntimeError('Exact retained parent is absent')
    b.ensure_source_fresh(parent['backupAt'],b.time.time())
    b.verify_exact_parent_receipt(f,parent)
    existing=b.point_supplements(f,{n:v for n,v in listing.items() if n not in extras},confirmed)[parent['bundle']]
    b.validate_supplement_set([*existing,payload])
    for name,size in objects.items():
        if name in listing and not 0<=listing[name]<=size:raise RuntimeError('Pending part exceeds bound')
    if receipt in listing and b.verify_supplement(b.get_json(f,receipt,b.SUPPLEMENT_RECEIPT_LIMIT),parent)!=payload:
        raise RuntimeError('Existing receipt differs from pending operation')
    if partial in listing:
        # A crash during STOR can leave invalid JSON. Only the exact prefix of
        # this ledger-bound signed receipt may be retried; never adopt a conflict.
        expected=b.supplement_receipt_bytes(payload);received=bytearray()
        def collect(chunk):
            received.extend(chunk)
            if len(received)>len(expected):raise RuntimeError('Partial receipt exceeds expected bound')
        f.retrbinary('RETR '+partial,collect,blocksize=65536)
        if not expected.startswith(bytes(received)):raise RuntimeError('Partial receipt conflicts with ledger')
    reservation=len(b.supplement_receipt_bytes({**payload,'verifiedAt':'9999-12-31T23:59:59.999999+00:00'}))
    missing=sum(size-listing.get(name,0) for name,size in objects.items())
    # A partial receipt and its final replacement may coexist during reconcile;
    # conservatively reserve the full final receipt, in addition to current bytes.
    if sum(listing.values())+missing+(0 if receipt in listing else reservation)>b.CAP:
        raise RuntimeError('Completeness whole-upload reservation exceeds capacity')
    return reservation


def publish_fixture(b,f,root,source,parent_receipt,key,crypto=None,part_bytes=None,fault=None):
    """Caller supplies ONLY fixture data and fake transport; never a production key."""
    if type(f) is not FakeFTP:raise RuntimeError('FakeFTP is mandatory until live qualification')
    if Path(source).is_symlink() or Path(key).is_symlink():raise RuntimeError('Fixture input symlink')
    root=Path(root).resolve();source=Path(source).resolve();key=Path(key).resolve()
    if root.stat().st_mode & 0o077 or root.stat().st_uid!=os.getuid():raise RuntimeError('Private fixture root required')
    private(source,root,True);private(key,root)
    crypto=crypto or GPG();fault=fault or (lambda phase:None)
    work=root/'work';work.mkdir(mode=0o700,exist_ok=True);private(work,root,True)
    with patch.multiple(b,KEY=key,WORK=work,FREEZE=root/'freeze',INDEX=work/'index'),patch.object(b,'connect',return_value=f):
        parent=b.verify(parent_receipt)
        lock=work/'transfer.lock'
        if lock.exists():private(lock,root)
        fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            st=os.fstat(fd)
            if st.st_uid!=os.getuid() or st.st_mode & 0o077 or st.st_nlink!=1:raise RuntimeError('Unsafe transfer lock')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            return _locked(b,f,root,source,parent_receipt,parent,key,crypto,part_bytes or b.PART_BYTES,fault)
        finally:os.close(fd)


def _locked(b,f,root,source,parent_receipt,parent,key,crypto,part_bytes,fault,
            work_override=None,freeze_override=None,completed_name='completeness-completed.json',
            precommit_guard=None):
    connections=[f]
    try:
        return _locked_impl(b,f,root,source,parent_receipt,parent,key,crypto,part_bytes,fault,
                            work_override,freeze_override,completed_name,precommit_guard,connections)
    finally:
        for connection in connections:
            try:connection.close()
            except Exception:pass


def _locked_impl(b,f,root,source,parent_receipt,parent,key,crypto,part_bytes,fault,
                 work_override,freeze_override,completed_name,precommit_guard,connections):
    if not 0<part_bytes<=b.PART_BYTES:raise RuntimeError('Invalid part bound')
    work=Path(work_override) if work_override is not None else root/'work'
    freeze=Path(freeze_override) if freeze_override is not None else root/'freeze'
    if (work!=root and root not in work.parents) or work.resolve()!=work:
        raise RuntimeError('Publisher work path escapes private root')
    if '/' in completed_name or not completed_name.startswith('completeness-completed') or not completed_name.endswith('.json'):
        raise RuntimeError('Invalid publisher completion name')
    ledger=work/'supplement-inflight.json';completed=work/completed_name
    def guard():
        if freeze.exists():raise RuntimeError('Offsite freeze prevents receipt commit')
        b.ensure_source_fresh(parent['backupAt'],b.time.time())
        if precommit_guard is not None:precommit_guard()
    def reconnect(connection):
        # Hashing, GPG and splitting can take longer than an FTPS idle timeout.
        # Never treat the control session from before that work as current.
        connection.close()
        connection=b.connect();connections.append(connection);b.verify_owner(connection)
        return connection
    if freeze.exists():raise RuntimeError('Offsite freeze prevents publication')
    if any((work/name).exists() for name in ['upload-inflight.json','upload-preserved.json','retention-inflight.json']):
        raise RuntimeError('Other transfer or retention pending')
    files,gaps=source_index(b,source,root)
    source_digest=hashlib.sha256(b.canonical(files)).hexdigest()
    parent_digest=hashlib.sha256(b.canonical(parent_receipt)).hexdigest()
    f=reconnect(f)
    if not ledger.exists() and completed.exists():
        private(completed,root);old=json.loads(completed.read_text())
        if old['sourceDigest']!=source_digest or old['parentDigest']!=parent_digest:
            raise RuntimeError('Different completed operation requires explicit new workspace')
        payload=old['payload'];listing=b.inventory(f)
        if parent not in b.points(f,listing):raise RuntimeError('Completed parent changed')
        b.ensure_source_fresh(parent['backupAt'],b.time.time())
        b.verify_exact_parent_receipt(f,parent)
        if b.verify_supplement(b.get_json(f,payload['ciphertext']+'.receipt.json',b.SUPPLEMENT_RECEIPT_LIMIT),parent)!=payload:
            raise RuntimeError('Completed receipt changed')
        if any(listing.get(n)!=size for n,size in b.supplement_objects(payload).items()):raise RuntimeError('Completed object changed')
        # An idempotent retry must not report a historical proof as current when
        # remote ciphertext was changed without changing its length.
        for part in payload['parts']:
            hasher=hashlib.sha256();count=[0]
            def consume(chunk):
                count[0]+=len(chunk)
                if count[0]>part['bytes']:raise RuntimeError('Completed part exceeds bound')
                hasher.update(chunk)
            f.retrbinary('RETR '+part['name'],consume,blocksize=1024*1024)
            if count[0]!=part['bytes'] or hasher.hexdigest()!=part['sha256']:raise RuntimeError('Completed part hash differs')
        return old['proof']
    if ledger.exists():
        private(ledger,root);state=json.loads(ledger.read_text())
        if state.get('schema')!='platform.completeness-publisher-ledger/v1' or state['sourceDigest']!=source_digest or state['parentDigest']!=parent_digest:
            raise RuntimeError('Pending operation binding differs')
        if state['phase']=='preparing':raise RuntimeError('Interrupted preparation retained; explicit reconciliation required')
        scratch=Path(state['scratch']);private(scratch,root,True)
        payload=state['payload'];b.verify_supplement(b.sign_supplement(payload),parent,staged=payload['verifiedAt'] is None)
    else:
        # Reserve local peak: ciphertext, parts, downloaded cipher, plaintext,
        # extracted artifacts plus padding, including tar headers and a
        # separately streamed source archive used for pre-upload verification.
        tar_overhead=10240*len(files)+1024*1024
        if shutil.disk_usage(work).free < sum(i['bytes'] for i in files)*5+tar_overhead+32*1024*1024:
            raise RuntimeError('Insufficient private scratch capacity')
        listing=b.inventory(f);parents=b.points(f,listing)
        if parent not in parents:raise RuntimeError('Exact retained parent is absent')
        b.verify_exact_parent_receipt(f,parent)
        b.ensure_source_fresh(parent['backupAt'],b.time.time())
        existing=b.point_supplements(f,listing,parents)[parent['bundle']]
        if any(i['kind']=='runtime-completeness-material' for i in existing):raise RuntimeError('Completeness already published without local ledger')
        scratch=Path(tempfile.mkdtemp(prefix='completeness-',dir=work));home=scratch/'gnupg';home.mkdir(mode=0o700)
        state={'schema':'platform.completeness-publisher-ledger/v1','phase':'preparing','sourceDigest':source_digest,'parentDigest':parent_digest,'scratch':str(scratch)}
        durable(ledger,state);fault('preparing')
        source_archive=scratch/'source.tar'
        source_tar=create_source_archive(source,files,source_archive)
        private(source_archive,root)
        if source_index(b,source,root)[0]!=files:raise RuntimeError('Source changed during tar capture')
        cipher=scratch/'cipher.gpg';encrypted_input=crypto.encrypt(source_archive,key,home,cipher)
        private(cipher,root)
        with cipher.open('rb') as stream:os.fsync(stream.fileno())
        if (not isinstance(encrypted_input,dict) or encrypted_input!=source_tar or
                encrypted_input.get('bytes')!=source_archive.stat().st_size):
            raise RuntimeError('GPG input stream differs from captured source archive')
        preflight_tar=scratch/'preflight.tar'
        crypto.decrypt(cipher,key,home,preflight_tar)
        private(preflight_tar,root)
        preflight_sha=b.sha(preflight_tar);preflight_bytes=preflight_tar.stat().st_size
        if preflight_sha!=source_tar['sha256'] or preflight_bytes!=source_tar['bytes']:
            raise RuntimeError('Locally encrypted GPG plaintext differs from tar input')
        preflight_members=verify_archive_members(preflight_tar,files,{item['name'] for item in files})
        preflight={'schema':'platform.completeness-preflight/v1','tarInputSha256':source_tar['sha256'],
                   'tarInputBytes':source_tar['bytes'],'gpgExitCode':0,'verifiedBeforeUpload':True,
                   'memberCount':len(preflight_members),'members':preflight_members}
        preflight_tar.unlink();source_archive.unlink();sync_dir(scratch)
        size=cipher.stat().st_size;digest=b.sha(cipher)
        if not 0<size<=b.CAP:raise RuntimeError('Ciphertext exceeds capacity')
        name=parent['bundle']+'.supplement-full-'+digest[:16]+'.tar.gpg'
        parts=[]
        with cipher.open('rb') as stream:
            while stream.tell()<size:
                index=len(parts);target=scratch/(name+'.part'+str(index).zfill(3));remaining=min(part_bytes,size-stream.tell());count=remaining;hasher=hashlib.sha256()
                with target.open('xb') as output:
                    os.chmod(target,0o600)
                    while remaining:
                        data=stream.read(min(1024*1024,remaining))
                        if not data:raise RuntimeError('Ciphertext truncated during splitting')
                        remaining-=len(data);hasher.update(data);output.write(data)
                    output.flush();os.fsync(output.fileno())
                parts.append({'name':target.name,'bytes':count,'sha256':hasher.hexdigest()})
                if len(parts)>70:raise RuntimeError('Too many parts')
        sync_dir(scratch)
        payload={'schema':b.COMPLETENESS_SCHEMA,'status':'passed','kind':'runtime-completeness-material','parentManifestId':parent['manifestId'],'parentManifestDigest':parent['manifestDigest'],'parentReceiptSha256':parent_digest,'parentEncryptedSha256':parent['encryptedSha256'],'backupAt':parent['backupAt'],'ciphertext':name,'encryptedBytes':size,'encryptedSha256':digest,'files':files,'verifiedAt':None,'parts':parts,'fullyRecoverable':False,'knownGaps':gaps,'archivePreflight':preflight}
        b.verify_supplement(b.sign_supplement(payload),parent,staged=True)
        state.update(phase='ready',payload=payload);durable(ledger,state);fault('ready')
    for part in payload['parts']:
        path=scratch/part['name'];private(path,root)
        if path.stat().st_size!=part['bytes'] or b.sha(path)!=part['sha256']:raise RuntimeError('Pending spool hash differs')
    f=reconnect(f)
    reserve=reserve_pending(b,f,payload,parent)
    state['phase']='uploading';durable(ledger,state);fault('uploading')
    for part in payload['parts']:
        b.ensure_source_fresh(parent['backupAt'],b.time.time())
        if freeze.exists():raise RuntimeError('Offsite freeze during transfer')
        f=b.upload_resilient(f,scratch/part['name'],part['name'],part['bytes'],reserve_bytes=reserve)
        connections.append(f)
        fault('part-uploaded')
    state['phase']='verifying';durable(ledger,state);fault('verifying')
    required=payload['encryptedBytes']+2*sum(item['bytes'] for item in payload['files'])+max(item['bytes'] for item in payload['parts'])+64*1024*1024
    if shutil.disk_usage(scratch).free<required:raise RuntimeError('Insufficient scratch for verification retry')
    attempt=Path(tempfile.mkdtemp(prefix='verify-',dir=scratch))
    downloaded=attempt/'downloaded.gpg';f=b.download_supplement(f,payload,downloaded)
    connections.append(f)
    plain=attempt/'downloaded.tar';home=scratch/'gnupg'
    crypto.decrypt(downloaded,key,home,plain)
    result=b.restore_supplement_archive(plain,attempt/'files',payload)
    coverage=json.loads((attempt/'files/coverage.json').read_text())
    if coverage.get('fullyRecoverable') is not False or coverage.get('knownGaps')!=payload['knownGaps']:
        raise RuntimeError('Restored coverage claims differ')
    fault('verified')
    guard()
    if payload['verifiedAt'] is None:payload['verifiedAt']=b.now()
    state.update(phase='publishing',payload=payload);durable(ledger,state);fault('publishing')
    guard()
    f.close()
    f=b.publish_supplement_receipt(payload,parent,precommit_guard=guard)
    connections.append(f)
    fault('receipt-published')
    b.points(f,b.inventory(f))
    proof={'schema':'completeness-fixture-proof/v1','status':'passed','realGpgVerified':crypto.real,
           'realFtpsVerified':False,'transport':'in-memory FakeFTP','files':result['files'],
           'actualDownloadAndMemberHashesVerified':True,'fullyRecoverable':False,
           'knownGaps':payload['knownGaps'],'productionModified':False,
           'parentReceiptSha256':parent_digest,'partCount':len(payload['parts'])}
    state.update(phase='completed',proof=proof);durable(completed,state)
    ledger.unlink();sync_dir(work)
    # Only this operation's private scratch is disposable after durable commit.
    # Idempotent retries use the receipt and rehash all remote parts.
    private(scratch,root,True)
    if scratch.parent!=work or not scratch.name.startswith('completeness-'):
        raise RuntimeError('Unexpected completed scratch path')
    shutil.rmtree(scratch);sync_dir(work)
    return proof
