#!/usr/bin/python3
"""Bounded DNS/DoH response checks for the local hosting infrastructure."""
import http.client, os, pathlib, secrets, socket, ssl, struct, tempfile, time

HOST='scriptastudents.platform-infrastructure.com'
ADDRESS='192.168.1.202'
CA='/home/platform_infrastructure/v1-fresh-runtime/certs/local-cert.pem'
DEST='/home/platform_infrastructure/v1-fresh-runtime/local-private-backup/data/runtime-state/node-exporter-textfile/platform_dns_probe.prom'

def portal_tls_context():
    # Explicit dedicated trust store: never add ambient system roots here.
    ca=pathlib.Path('/etc/platform-infrastructure/tls/portal-new-root.pem')
    info=ca.lstat()
    if ca.is_symlink() or not ca.is_file() or info.st_uid!=0 or info.st_mode & 0o022:
        raise ValueError('Invalid dedicated Portal CA ownership or permissions')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(ca))
    context.verify_mode=ssl.CERT_REQUIRED
    context.check_hostname=True
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    return context

def validate(data, ident):
    if len(data)<12: raise ValueError('short header')
    rid,flags,qd,an,_,_=struct.unpack('!HHHHHH',data[:12])
    if rid!=ident or not flags&0x8000 or flags&0x020f or qd!=1 or an<1: raise ValueError('bad DNS status')
    def skip(pos):
        for _ in range(128):
            if pos>=len(data): raise ValueError('truncated name')
            size=data[pos]; pos+=1
            if size&0xc0==0xc0:
                if pos>=len(data): raise ValueError('truncated pointer')
                return pos+1
            if size&0xc0: raise ValueError('invalid label')
            if size==0:return pos
            pos+=size
        raise ValueError('name too long')
    pos=skip(12)+4
    found=False
    for _ in range(an):
        pos=skip(pos)
        if pos+10>len(data):raise ValueError('truncated rr')
        kind,cls,ttl,n=struct.unpack('!HHIH',data[pos:pos+10]);pos+=10
        if pos+n>len(data):raise ValueError('truncated rdata')
        if kind==1 and cls==1 and n==4 and socket.inet_ntoa(data[pos:pos+4])==ADDRESS:found=True
        pos+=n
    if not found:raise ValueError('expected A response missing')

def exact(sock,count):
    result=b''
    while len(result)<count:
        chunk=sock.recv(count-len(result))
        if not chunk:raise ValueError('truncated TCP DNS')
        result+=chunk
    return result

def probe(protocol):
    ident=secrets.randbelow(65536)
    wire=struct.pack('!HHHHHH',ident,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in HOST.split('.'))+b'\0\0\1\0\1'
    if protocol=='udp':
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(3);s.connect((ADDRESS,53));s.send(wire);answer=s.recv(65535)
    elif protocol=='tcp':
        with socket.create_connection((ADDRESS,53),3) as s:
            s.sendall(struct.pack('!H',len(wire))+wire);n=struct.unpack('!H',exact(s,2))[0];answer=exact(s,n)
    else:
        context=portal_tls_context()
        with socket.create_connection((ADDRESS,5443),3) as raw:
            with context.wrap_socket(raw,server_hostname=HOST) as s:
                header=(f'POST /dns-query HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {len(wire)}\r\nConnection: close\r\n\r\n').encode()
                s.sendall(header+wire);r=http.client.HTTPResponse(s);r.begin()
                if r.status!=200 or r.getheader('Content-Type','').split(';')[0]!='application/dns-message':raise ValueError('bad DoH status')
                answer=r.read(65536)
                if len(answer)>65535:raise ValueError('oversized DoH')
    validate(answer,ident)

def main():
    lines=['# TYPE platform_dns_probe_success gauge','# TYPE platform_dns_probe_duration_seconds gauge']
    for protocol in ('udp','tcp','doh'):
        start=time.monotonic()
        try:probe(protocol);ok=1
        except Exception:ok=0
        lines += [f'platform_dns_probe_success{{protocol="{protocol}"}} {ok}',f'platform_dns_probe_duration_seconds{{protocol="{protocol}"}} {time.monotonic()-start:.6f}']
    lines += [f'platform_dns_probe_timestamp_seconds {time.time():.0f}']
    target=pathlib.Path(DEST)
    fd,tmp=tempfile.mkstemp(prefix='.dns-probe.',dir=target.parent)
    try:
        with os.fdopen(fd,'w') as f:f.write('\n'.join(lines)+'\n')
        os.chmod(tmp,0o644);os.replace(tmp,target)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    print('\n'.join(lines))

if __name__=='__main__':main()
