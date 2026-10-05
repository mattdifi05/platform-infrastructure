#!/usr/bin/python3
"""Publish expiration and read errors for internal DB and Portal TLS certificates."""
import datetime, os, pathlib, re, subprocess, tempfile, time

root = pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/maintenance/20260927/db-tls')
destination = pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/local-private-backup/data/runtime-state/node-exporter-textfile/platform_db_tls.prom')
lines = ['# TYPE platform_db_tls_certificate_not_after_seconds gauge', '# TYPE platform_db_tls_certificate_read_success gauge']
for name, path in [('ca',root/'authority/ca.crt')] + [(n,root/n/'server.crt') for n in ('postgres','mariadb','redis','students-beta-redis')] + [('portal-root',pathlib.Path('/etc/platform-infrastructure/tls/portal-new-root.pem')),('portal-chain',pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/certs/portal-cross-fullchain.pem'))]:
    try:
        certificates = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',path.read_text(),re.S)
        if len(certificates) != (2 if name == 'portal-chain' else 1): raise ValueError('Unexpected certificate chain length')
        expirations = []
        for certificate in certificates:
            result = subprocess.run(['openssl','x509','-noout','-enddate'],input=certificate,capture_output=True,text=True,check=True,timeout=5)
            expirations.append(datetime.datetime.strptime(result.stdout.strip().split('=',1)[1],'%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc).timestamp())
        expiry = min(expirations)
        lines += [f'platform_db_tls_certificate_not_after_seconds{{certificate="{name}"}} {expiry:.0f}', f'platform_db_tls_certificate_read_success{{certificate="{name}"}} 1']
    except Exception:
        lines += [f'platform_db_tls_certificate_read_success{{certificate="{name}"}} 0']
lines += [f'platform_db_tls_collection_timestamp_seconds {time.time():.0f}']
fd, temp = tempfile.mkstemp(prefix='.platform_db_tls.',dir=destination.parent)
try:
    with os.fdopen(fd,'w') as f:
        f.write('\n'.join(lines)+'\n')
    os.chmod(temp,0o644)
    os.replace(temp,destination)
finally:
    if os.path.exists(temp): os.unlink(temp)
