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


def official_provider_repository(reference):
    if not isinstance(reference, str):
        return None
    normalized = reference.removeprefix('docker.io/').removeprefix('index.docker.io/')
    match = re.fullmatch(r'([a-z0-9/-]+)(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}|@sha256:[a-f0-9]{64})', normalized)
    if not match:
        return None
    repository = match.group(1)
    if repository in ['nginx', 'traefik', 'nats']:
        repository = 'library/' + repository
    return repository if repository in {'library/nginx', 'library/traefik', 'library/nats', 'prom/prometheus', 'prom/alertmanager', 'prom/node-exporter', 'grafana/grafana', 'grafana/promtail', 'grafana/loki'} else None


def image_provider_identities(image_metadata):
    identities = {}
    for image in image_metadata:
        repositories = {repository for reference in image.get('RepoDigests') or [] if isinstance(reference, str) and '@sha256:' in reference and (repository := official_provider_repository(reference))}
        if len(repositories) == 1:
            identities[image['Id']] = next(iter(repositories))
    return identities


def discover(rows, infra, image_metadata=None):
    groups = {}
    active = {(x['Config'].get('Labels', {}).get('com.docker.compose.project'), x['Config'].get('Labels', {}).get('com.docker.compose.service')) for x in rows if x['State']['Running']}
    official = image_provider_identities(image_metadata) if image_metadata is not None else {x['Image']: repository for x in rows if (repository := official_provider_repository(x['Config']['Image']))}
    for row in rows:
        labels = row['Config'].get('Labels') or {}
        if not labels.get('com.docker.compose.project') or '-rollback-' in row['Name'] or '-update-' in row['Name']:
            continue
        env = dict(x.split('=', 1) for x in row['Config'].get('Env', []) if '=' in x)
        image = row['Config']['Image']
        name = row['Name'].lstrip('/')
        service = labels.get('com.docker.compose.service', name)
        if not row['State']['Running'] and service.endswith(('-init', '-bootstrap')):
            continue
        if not row['State']['Running'] and ((labels.get('com.docker.compose.project'), service) in active or name not in {service, 'enterprise-' + service, labels.get('com.docker.compose.project', '') + '-' + service + '-1'}):
            continue
        entry = {'strategy': 'observe', 'category': 'Piattaforma', 'compatibility': 'latest', 'tagSuffix': '', 'tagPrefix': '', 'architecture': 'amd64'}
        if 'phpmyadmin' in name:
            entry.update(label='phpMyAdmin', category='Amministrazione', repository='library/phpmyadmin', strategy='reviewed-build', dockerfile=str(infra / 'deployment/docker/phpmyadmin-remediated.Dockerfile'), probe=['php', '-r', 'define("VERSION_SUFFIX", ""); require "/var/www/html/libraries/classes/Version.php"; echo \\PhpMyAdmin\\Version::VERSION;'])
        elif 'phppgadmin' in name:
            entry.update(label='phpPgAdmin', category='Amministrazione', blockedReason='Il pacchetto usa un builder dedicato senza una release stabile numerata verificabile. Richiede manutenzione assistita.')
        elif 'PHP_VERSION' in env:
            entry.update(label='PHP', category='Runtime', repository='library/php', strategy='php-build', tagSuffix='-apache', versionEnv='PHP_VERSION', dockerfile=str(infra / 'docker/php-apache.Dockerfile'), probe=['php', '-r', 'echo PHP_VERSION;'])
        elif 'NODE_VERSION' in env:
            # One Node family; preserve every application's exact image in its runtime layer.
            entry.update(label='Node.js', category='Runtime', repository='library/node', strategy='node-layer', compatibility='latest', tagSuffix='-alpine', versionEnv='NODE_VERSION', probe=['node', '--version'])
        elif 'PG_VERSION' in env:
            entry.update(label='PostgreSQL', category='Database', repository='library/postgres', strategy='reviewed-build', compatibility='latest', tagSuffix='-alpine', versionEnv='PG_VERSION', dockerfile=str(infra / 'deployment/docker/postgres-remediated.Dockerfile'), probe=['postgres', '--version'], recoveryPolicy='offline-snapshot-v1')
        elif 'MARIADB_VERSION' in env:
            entry.update(label='MariaDB', category='Database', repository='library/mariadb', strategy='reviewed-build', versionEnv='MARIADB_VERSION', dockerfile=str(infra / 'deployment/docker/mariadb-remediated.Dockerfile'), probe=['mariadbd', '--version'], recoveryPolicy='offline-snapshot-v1')
        elif 'REDIS_VERSION' in env:
            entry.update(label='Redis', category='Database', repository='library/redis', strategy='image', tagSuffix='-alpine', versionEnv='REDIS_VERSION', probe=['redis-server', '--version'], recoveryPolicy='offline-snapshot-v1')
        elif image.startswith('quay.io/keycloak/keycloak:'):
            entry.update(label='Keycloak', category='Identità', versionLabel='org.opencontainers.image.version', blockedReason='L’aggiornamento di Keycloak richiede anche il piano di recupero del database esterno.')
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
                if official.get(row['Image']) == repository:
                    entry.update(label=label, category=category, repository=repository, probe=probe, tagPrefix=prefix, tagSuffix=suffix, strategy='image')
                    if repository == 'library/nginx':
                        entry['versionEnv'] = 'NGINX_VERSION'
                    break
            if entry['strategy'] == 'observe':
                entry.update(label=name, blockedReason='Componente della piattaforma con rilascio dedicato: aggiornamento assistito per preservare le personalizzazioni.')
        if entry['strategy'] in ['reviewed-build', 'php-build']:
            entry['buildContext'] = str(infra)
            if not pathlib.Path(entry['dockerfile']).is_file():
                entry.update(strategy='observe', blockedReason='Builder del componente non disponibile su questo server.')
        if entry['strategy'] in ['image', 'reviewed-build'] and any(m.get('RW') and m['Type'] in ['bind', 'volume'] for m in row.get('Mounts', [])):
            entry.update(requiresRecovery=True, recoveryPolicy='offline-snapshot-v1')
        # Known suppliers form one family regardless of application or image digest.
        # Dedicated/unrecognized builds remain separate and cannot become plain images.
        repository = entry.get('repository')
        family = repository.replace('library/', '').replace('/', '-') if repository else None
        key = ('supplier', repository) if family else ('dedicated', row['Image'], entry['label'])
        if key not in groups:
            identity = family or (re.sub('[^a-z0-9-]', '-', entry['label'].lower()).strip('-')[:48] + '-' + row['Image'][-10:])
            groups[key] = {**entry, 'id': identity, 'containers': [], 'initialImages': [], 'familyPolicy': 'single-version-v1' if family else None, 'targetPolicy': 'latest-stable-direct-v1' if family else None}
        group = groups[key]
        if group['strategy'] != entry['strategy']:
            group.update(strategy='observe', blockedReason='Le istanze della famiglia richiedono un builder comune verificato.')
        if entry.get('requiresRecovery'):
            group.update(requiresRecovery=True, recoveryPolicy='offline-snapshot-v1')
        group['containers'].append(name)
        group['initialImages'] = sorted(set(group['initialImages'] + [row['Image']]))
    for group in groups.values():
        group['containers'].sort()
    return list(groups.values())


def preserve_enrollment_policy(components, previous):
    # Keep root-admitted HTTP probes when enrollment discovers new image IDs.
    by_membership = {tuple(sorted(x['containers'])): x for x in previous}
    for row in components:
        prior = by_membership.get(tuple(sorted(row['containers'])))
        if row.get('repository') == 'library/traefik':
            prior_family = next((entry for entry in previous if entry.get('repository') == 'library/traefik'), None)
            if prior_family and 'routeProbes' in prior_family:
                row['routeProbes'] = prior_family['routeProbes']
        if prior and row.get('familyPolicy') != 'single-version-v1':
            row['id'] = prior['id']


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run as root on the target VPS')
    os.umask(0o077)
    infra = pathlib.Path(os.environ.get('PLATFORM_INFRA_ROOT', '/srv/platform-infrastructure/first-install'))
    ids = command(['docker', 'ps', '-aq']).split()
    rows = json.loads(command(['docker', 'inspect', *ids])) if ids else []
    # Include stopped tools, while excluding retained rollback snapshots.
    image_ids = sorted({row['Image'] for row in rows})
    image_metadata = []
    if image_ids:
        # Fetch only identity metadata, never image ENV or application configuration.
        metadata = command(['docker', 'image', 'inspect', '--format', '{{json .Id}}|{{json .RepoDigests}}', *image_ids])
        for line in metadata.splitlines():
            identity, references = line.split('|', 1)
            image_metadata.append({'Id': json.loads(identity), 'RepoDigests': json.loads(references)})
    components = discover(rows, infra, image_metadata=image_metadata)
    CONFIG.mkdir(mode=0o750, parents=True, exist_ok=True)
    value = {'schema': 'platform-runtime-updates/v1', 'recoveryLimitBytes': 20 * 1024 ** 3, 'components': components}
    config = CONFIG / 'config.json'
    if config.exists():
        old = json.loads(config.read_text())
        preserve_enrollment_policy(value['components'], old['components'])
    config.write_text(json.dumps(value, indent=2) + '\n')
    config.chmod(0o600)
    key = CONFIG / 'bridge-key'
    if not key.exists():
        with key.open('xb') as f:
            f.write(os.urandom(32))
    os.chown(key, 0, 1000)
    key.chmod(0o640)
    for name in ['platform_runtime_updates.py', 'platform_runtime_releases.py', 'platform_host_updates.py']:
        shutil.copy2(SOURCE / 'deployment/host/libexec' / name, pathlib.Path('/usr/local/libexec') / name)
        (pathlib.Path('/usr/local/libexec') / name).chmod(0o755)
    shutil.copy2(SOURCE / 'deployment/host/systemd/platform-runtime-updates.service', '/etc/systemd/system/platform-runtime-updates.service')
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'platform-runtime-updates.service'], check=True)
    print('Enrolled runtime groups:', len(components))
    print('No installed runtime was upgraded or installed.')


if __name__ == '__main__':
    main()
