#!/usr/bin/env python3
"""Enroll only observed runtimes. Run on the VPS as root; never installs runtimes."""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

SOURCE = pathlib.Path(__file__).resolve().parents[1]
CONFIG = pathlib.Path('/etc/platform-infrastructure/updates')


def command(args):
    return subprocess.check_output(args, text=True)


def discover(rows, infra):
    groups = {}
    active = {(x['Config'].get('Labels', {}).get('com.docker.compose.project'), x['Config'].get('Labels', {}).get('com.docker.compose.service')) for x in rows if x['State']['Running']}
    official = {x['Image']: x['Config']['Image'] for x in rows if re.match(r'^(?:docker.io/)?(?:nginx|traefik|nats|prom/(?:prometheus|alertmanager|node-exporter)|grafana/(?:grafana|promtail|loki)):', x['Config']['Image'])}
    for row in rows:
        labels = row['Config'].get('Labels') or {}
        if not labels.get('com.docker.compose.project') or '-rollback-' in row['Name'] or '-update-' in row['Name']:
            continue
        env = dict(x.split('=', 1) for x in row['Config'].get('Env', []) if '=' in x)
        image = row['Config']['Image']
        name = row['Name'].lstrip('/')
        service = labels.get('com.docker.compose.service', name)
        if not row['State']['Running'] and ((labels.get('com.docker.compose.project'), service) in active or name not in {service, 'enterprise-' + service, labels.get('com.docker.compose.project', '') + '-' + service + '-1'}):
            continue
        image = official.get(row['Image'], image)
        entry = {'strategy': 'observe', 'category': 'Piattaforma', 'compatibility': 'minor', 'tagSuffix': '', 'tagPrefix': '', 'architecture': 'amd64'}
        if 'phpmyadmin' in name:
            entry.update(label='phpMyAdmin', category='Amministrazione', repository='library/phpmyadmin', strategy='reviewed-build', dockerfile=str(infra / 'deployment/docker/phpmyadmin-remediated.Dockerfile'), probe=['php', '-r', 'echo PMA_VERSION;'])
        elif 'phppgadmin' in name:
            entry.update(label='phpPgAdmin', category='Amministrazione', blockedReason='Il pacchetto usa un builder dedicato senza una release stabile numerata verificabile. Richiede manutenzione assistita.')
        elif 'PHP_VERSION' in env:
            entry.update(label='PHP ' + '.'.join(env['PHP_VERSION'].split('.')[:2]), category='Runtime', repository='library/php', strategy='php-build', tagSuffix='-apache', versionEnv='PHP_VERSION', dockerfile=str(infra / 'docker/php-apache.Dockerfile'), probe=['php', '-r', 'echo PHP_VERSION;'])
        elif 'NODE_VERSION' in env:
            # Same-major Node binary layered over the exact existing application image.
            service = labels.get('com.docker.compose.service', name)
            entry.update(label='Node.js · ' + service, category='Runtime', repository='library/node', strategy='node-layer', compatibility='major', tagSuffix='-alpine', versionEnv='NODE_VERSION', probe=['node', '--version'])
        elif 'PG_VERSION' in env:
            entry.update(label='PostgreSQL ' + env.get('PG_MAJOR', ''), category='Database', repository='library/postgres', strategy='reviewed-build', compatibility='major', tagSuffix='-alpine', versionEnv='PG_VERSION', dockerfile=str(infra / 'deployment/docker/postgres-remediated.Dockerfile'), probe=['postgres', '--version'], recoveryPolicy='offline-snapshot-v1')
        elif 'MARIADB_VERSION' in env:
            entry.update(label='MariaDB', category='Database', repository='library/mariadb', strategy='reviewed-build', versionEnv='MARIADB_VERSION', dockerfile=str(infra / 'deployment/docker/mariadb-remediated.Dockerfile'), probe=['mariadbd', '--version'], recoveryPolicy='offline-snapshot-v1')
        elif 'REDIS_VERSION' in env:
            entry.update(label='Redis', category='Database', repository='library/redis', strategy='image', tagSuffix='-alpine', versionEnv='REDIS_VERSION', probe=['redis-server', '--version'], recoveryPolicy='offline-snapshot-v1')
        else:
            providers = [
                ('nginx', 'Nginx', 'library/nginx', ['nginx', '-v'], '', '-alpine', 'Rete'),
                ('traefik', 'Traefik', 'library/traefik', ['traefik', 'version'], 'v', '', 'Rete'),
                ('nats', 'NATS', 'library/nats', ['nats-server', '-v'], '', '-alpine', 'Messaggistica'),
                ('node-exporter', 'Node Exporter', 'prom/node-exporter', ['/bin/node_exporter', '--version'], 'v', '', 'Monitoraggio'),
                ('prometheus', 'Prometheus', 'prom/prometheus', ['/bin/prometheus', '--version'], 'v', '', 'Monitoraggio'),
                ('alertmanager', 'Alertmanager', 'prom/alertmanager', ['/bin/alertmanager', '--version'], 'v', '', 'Monitoraggio'),
                ('grafana', 'Grafana', 'grafana/grafana', ['grafana', '--version'], '', '', 'Monitoraggio'),
                ('promtail', 'Promtail', 'grafana/promtail', ['/usr/bin/promtail', '--version'], '', '', 'Monitoraggio'),
                ('loki', 'Loki', 'grafana/loki', ['/usr/bin/loki', '--version'], '', '', 'Monitoraggio'),
            ]
            for match, label, repository, probe, prefix, suffix, category in providers:
                expected = repository.removeprefix('library/')
                if image.removeprefix('docker.io/').startswith(expected + ':'):
                    entry.update(label=label, category=category, repository=repository, probe=probe, tagPrefix=prefix, tagSuffix=suffix, strategy='image')
                    break
            if entry['strategy'] == 'observe':
                entry.update(label=name, blockedReason='Componente della piattaforma con rilascio dedicato: aggiornamento assistito per preservare le personalizzazioni.')
        if entry['strategy'] in ['reviewed-build', 'php-build']:
            entry['buildContext'] = str(infra)
            if not pathlib.Path(entry['dockerfile']).is_file():
                entry.update(strategy='observe', blockedReason='Builder del componente non disponibile su questo server.')
        if entry['strategy'] in ['image', 'reviewed-build'] and any(m.get('RW') and m['Type'] in ['bind', 'volume'] for m in row.get('Mounts', [])):
            entry.update(requiresRecovery=True, recoveryPolicy='offline-snapshot-v1')
        # Distinct deployed application images are separate Node update targets.
        key = (row['Image'], entry['label'].split(' · ')[0])
        if key not in groups:
            identity = re.sub('[^a-z0-9-]', '-', entry['label'].lower()).strip('-')[:48] + '-' + row['Image'][-10:]
            groups[key] = {**entry, 'id': identity, 'containers': [], 'initialImage': row['Image']}
        groups[key]['containers'].append(name)
    return list(groups.values())


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run as root on the target VPS')
    os.umask(0o077)
    infra = pathlib.Path(os.environ.get('PLATFORM_INFRA_ROOT', '/srv/platform-infrastructure/first-install'))
    ids = command(['docker', 'ps', '-aq']).split()
    rows = json.loads(command(['docker', 'inspect', *ids])) if ids else []
    # Include stopped tools, while excluding retained rollback snapshots.
    components = discover(rows, infra)
    CONFIG.mkdir(mode=0o750, parents=True, exist_ok=True)
    value = {'schema': 'platform-runtime-updates/v1', 'recoveryLimitBytes': 20 * 1024 ** 3, 'components': components}
    config = CONFIG / 'config.json'
    if config.exists():
        old = json.loads(config.read_text())
        # Stable IDs/policy survive installer reruns and runtime replacements.
        by_membership = {tuple(sorted(x['containers'])): x for x in old['components']}
        for row in value['components']:
            prior = by_membership.get(tuple(sorted(row['containers'])))
            if prior:
                row['id'] = prior['id']
    config.write_text(json.dumps(value, indent=2) + '\n')
    config.chmod(0o600)
    key = CONFIG / 'bridge-key'
    if not key.exists():
        with key.open('xb') as f:
            f.write(os.urandom(32))
    os.chown(key, 0, 1000)
    key.chmod(0o640)
    for name in ['platform_runtime_updates.py', 'platform_runtime_releases.py']:
        shutil.copy2(SOURCE / 'deployment/host/libexec' / name, pathlib.Path('/usr/local/libexec') / name)
        (pathlib.Path('/usr/local/libexec') / name).chmod(0o755)
    shutil.copy2(SOURCE / 'deployment/host/systemd/platform-runtime-updates.service', '/etc/systemd/system/platform-runtime-updates.service')
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'platform-runtime-updates.service'], check=True)
    print('Enrolled runtime groups:', len(components))
    print('No installed runtime was upgraded or installed.')


if __name__ == '__main__':
    main()
