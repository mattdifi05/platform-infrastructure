"""Bounded, read-only release discovery from Docker Hub and its registry."""
import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

_HUB = 'https://hub.docker.com'
_REGISTRY = 'https://registry-1.docker.io'
_DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
_REPOSITORY = re.compile(r'^[a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:[._-][a-z0-9]+)*$')
_GITHUB = {
    'prom/prometheus': 'prometheus/prometheus',
    'prom/alertmanager': 'prometheus/alertmanager',
    'prom/node-exporter': 'prometheus/node_exporter',
    'grafana/grafana': 'grafana/grafana',
    'grafana/loki': 'grafana/loki',
    'grafana/alloy': 'grafana/alloy',
    'rustfs/rustfs': 'rustfs/rustfs',
}
_VERSION = re.compile(r'^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?$')
_WAF_TAG = re.compile(r'^((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))-nginx-([0-9]{12})$')


def _version(value):
    match = _VERSION.fullmatch(str(value))
    if not match:
        raise ValueError('version must be an explicit stable numeric version')
    return tuple(int(part or 0) for part in match.groups())


def compare_versions(left, right):
    """Compare stable numeric versions; missing patch is equivalent to zero."""
    a, b = _version(left), _version(right)
    return (a > b) - (a < b)


class _Client:
    def __init__(self):
        self.deadline = time.monotonic() + 20

    def get(self, url, headers=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('release discovery deadline exceeded')
        request = urllib.request.Request(url, headers={'User-Agent': 'platform-runtime-releases/1', **(headers or {})})
        # All URLs are constructed locally; redirects cannot leave official hosts.
        class Redirects(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                parsed = urllib.parse.urlsplit(newurl)
                if parsed.scheme != 'https' or parsed.hostname not in {'hub.docker.com', 'registry-1.docker.io', 'auth.docker.io', 'raw.githubusercontent.com', 'api.github.com'}:
                    raise ValueError('untrusted redirect')
                return super().redirect_request(req, fp, code, msg, hdrs, newurl)
        with urllib.request.build_opener(Redirects()).open(request, timeout=min(4, remaining)) as response:
            limit = (32 if url.startswith('https://api.github.com/') else 4) * 1024 * 1024
            raw = response.read(limit + 1)
            if len(raw) > limit:
                raise ValueError('release response too large')
            if url.startswith(_REGISTRY + '/v2/') and '/manifests/' in url:
                digest = response.headers.get('Docker-Content-Digest', '')
                if digest != 'sha256:' + hashlib.sha256(raw).hexdigest():
                    raise ValueError('registry manifest digest mismatch')
            return (raw.decode('utf-8') if url.startswith('https://raw.githubusercontent.com/') else json.loads(raw)), response.headers


def _public_github_latest(client, repository):
    """GitHub's public latest route selects its non-prerelease published release.

    Read only the first response; never follow a Location to an untrusted host.
    """
    remaining = client.deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('release discovery deadline exceeded')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            return None
    releases_url = 'https://github.com/' + repository + '/releases'
    request = urllib.request.Request(releases_url + '/latest',
                                     method='HEAD', headers={'User-Agent': 'platform-runtime-releases/1'})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=min(4, remaining)):
            raise ValueError('public latest release did not redirect')
    except urllib.error.HTTPError as error:
        if error.code != 302:
            raise
        location = error.headers.get('Location', '')
        match = re.fullmatch(re.escape(releases_url) + r'/tag/(v?)([0-9]+\.[0-9]+\.[0-9]+)', location)
        if not match:
            raise ValueError('untrusted or non-stable public GitHub release')
        version = match.group(2)
        _version(version)
        return {'tag_name': match.group(1) + version, 'draft': False, 'prerelease': False}


def _release(client, repository, tag, architecture):
    images = tag.get('images', [])
    if not any(image.get('os') == 'linux' and image.get('architecture') == architecture
               and _DIGEST.fullmatch(str(image.get('digest', ''))) for image in images):
        return None
    # Always resolve the registry index: a Hub image digest may identify a child.
    query = urllib.parse.urlencode({'service': 'registry.docker.io', 'scope': 'repository:' + repository + ':pull'})
    auth, _ = client.get('https://auth.docker.io/token?' + query)
    token = auth.get('token') or auth.get('access_token')
    if not isinstance(token, str) or not token:
        raise ValueError('registry token unavailable')
    manifest, headers = client.get(_REGISTRY + '/v2/' + repository + '/manifests/' + urllib.parse.quote(tag['name'], safe=''), {
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json',
    })
    digest = headers.get('Docker-Content-Digest', '')
    manifests = manifest.get('manifests')
    if not isinstance(manifests, list):
        raise ValueError('registry response is not a multi-platform index')
    if not any(item.get('platform', {}).get('os') == 'linux' and item.get('platform', {}).get('architecture') == architecture and _DIGEST.fullmatch(str(item.get('digest', ''))) for item in manifests):
        return None
    if not _DIGEST.fullmatch(str(digest)):
        raise ValueError('registry digest unavailable')
    if repository in {'owasp/modsecurity-crs', 'rustfs/rustfs'}:
        matches = [item['digest'] for item in manifests
                   if item.get('platform', {}).get('os') == 'linux'
                   and item.get('platform', {}).get('architecture') == architecture
                   and _DIGEST.fullmatch(str(item.get('digest', '')))]
        if len(matches) != 1 or not any(image.get('os') == 'linux' and image.get('architecture') == architecture
                                      and image.get('digest') == matches[0] for image in images):
            raise ValueError('WAF architecture manifest mismatch' if repository == 'owasp/modsecurity-crs' else 'RustFS architecture manifest mismatch')
        digest = matches[0]
    return {'version': tag['_version'], 'imageReference': 'docker.io/' + repository + ':' + tag['name'], 'imageDigest': digest,
            'sourceUrl': _HUB + '/r/' + repository + '/tags?name=' + urllib.parse.quote(tag['name'], safe='')}


def resolve_release(component, current_version):
    """Return the latest stable directly, with explicit migration or assistance blocks.

    Network, pagination and validation failures deliberately return no releases;
    a partial listing must never be represented as the latest official release.
    """
    unavailable = {'latestStable': None, 'candidateRelease': None}
    try:
        repository = component.get('repository', '')
        prefix, suffix = component.get('tagPrefix', ''), component.get('tagSuffix', '')
        compatibility = component.get('compatibility', 'latest')
        architecture = component.get('architecture', 'amd64')
        if not _REPOSITORY.fullmatch(repository) or prefix not in ('', 'v') or not re.fullmatch(r'(?:-[a-zA-Z0-9][a-zA-Z0-9_.-]*)?', suffix):
            raise ValueError('invalid repository or tag format')
        if compatibility not in ('latest', 'major', 'minor', 'exact') or component.get('versionScheme', 'semver') != 'semver' or architecture not in ('amd64', 'arm64', 'arm', '386', 'ppc64le', 's390x', 'riscv64'):
            raise ValueError('unsupported release policy')
        current = _version(current_version)
        include_current = component.get('includeCurrent') is True
        client = _Client()
        path = '/v2/repositories/' + repository + '/tags/'
        url = _HUB + path + '?page_size=100&ordering=last_updated'
        waf = repository == 'owasp/modsecurity-crs'
        if waf:
            if prefix or suffix:
                raise ValueError('WAF requires the explicit dated nginx tag policy')
            url += '&name=-nginx-'
        tags = {}
        official = repository.startswith('library/')
        github = _GITHUB.get(repository)
        if github:
            try:
                releases = []
                newest, _ = client.get('https://api.github.com/repos/' + github + '/releases/latest')
                releases.append(newest)
                for page in range(1, 3):
                    batch, headers = client.get('https://api.github.com/repos/' + github + '/releases?per_page=100&page=' + str(page))
                    if not isinstance(batch, list):
                        raise ValueError('invalid official release listing')
                    releases.extend(batch)
                    if len(batch) < 100:
                        break
            except urllib.error.HTTPError as error:
                # These channels can use the public stable release redirect when
                # rate-limited. Authorization and transport failures stay visible.
                if (repository not in {'rustfs/rustfs', 'grafana/alloy'} or not error.url.startswith('https://api.github.com/repos/' + github + '/releases')
                        or not (error.code == 429 or error.code == 403 and error.headers.get('X-RateLimit-Remaining') == '0')):
                    raise
                releases = [_public_github_latest(client, github)]
            for release in releases:
                if release.get('draft') or release.get('prerelease'):
                    continue
                version = release.get('tag_name', '').removeprefix('v')
                try:
                    _version(version)
                except ValueError:
                    continue
                name = prefix + version + suffix
                tags[name] = {'name': name, '_version': version, '_needsMetadata': True}
        if official:
            source = 'https://raw.githubusercontent.com/docker-library/official-images/master/library/' + repository.split('/')[1]
            document, _ = client.get(source)
            if not isinstance(document, str):
                raise ValueError('invalid official-images document')
            names = {name.strip() for line in document.splitlines() if line.startswith('Tags:') for name in line[5:].split(',')}
            for name in names:
                if not name.startswith(prefix) or (suffix and not name.endswith(suffix)):
                    continue
                version = name[len(prefix):len(name)-len(suffix) if suffix else None]
                try:
                    _version(version)
                except ValueError:
                    continue
                tags[name] = {'name': name, '_version': version, '_needsMetadata': True}
        for page in range(0 if official or github else (16 if waf else 8)):
            payload, _ = client.get(url)
            if not isinstance(payload.get('results'), list):
                raise ValueError('invalid tag listing')
            for tag in payload['results']:
                name = tag.get('name', '')
                if waf:
                    match = _WAF_TAG.fullmatch(name) if isinstance(name, str) else None
                    if not match:
                        continue
                    version, build_date = match.groups()
                else:
                    build_date = ''
                if not isinstance(name, str) or not name.startswith(prefix) or (suffix and not name.endswith(suffix)):
                    continue
                if not waf:
                    version = name[len(prefix):len(name)-len(suffix) if suffix else None]
                try:
                    parsed = _version(version)
                except ValueError:
                    continue
                entry = dict(tag, _version=version, _buildDate=build_date)
                # The same tag appearing on two pages must have identical metadata.
                if name in tags and tags[name] != entry:
                    raise ValueError('tag changed during discovery')
                tags[name] = entry
            next_url = payload.get('next')
            if not next_url:
                break
            parsed_url = urllib.parse.urlsplit(next_url)
            if parsed_url.scheme != 'https' or parsed_url.netloc != 'hub.docker.com' or parsed_url.path != path or parsed_url.fragment:
                raise ValueError('untrusted pagination URL')
            url = next_url
        else:
            if not official and not github:
                raise ValueError('release listing exceeds pagination limit')
        if repository == 'library/nginx':
            # NGINX's documented stable channel uses even minor versions;
            # odd minor versions are mainline, despite having numeric tags.
            tags = {name: tag for name, tag in tags.items() if _version(tag['_version'])[1] % 2 == 0}
        ordered = sorted(tags.values(), key=lambda item: (_version(item['_version']), item.get('_buildDate', ''), item['name']), reverse=True)
        latest = None
        for tag in ordered:
            if tag.get('_needsMetadata'):
                metadata, _ = client.get(_HUB + path + urllib.parse.quote(tag['name'], safe='') + '/')
                if metadata.get('name') != tag['name']:
                    raise ValueError('exact tag metadata mismatch')
                tag = dict(metadata, _version=tag['_version'])
            latest = _release(client, repository, tag, architecture)
            if latest is not None:
                break
        if latest is None:
            return dict(unavailable, reason='unavailable: no stable release for architecture and tag policy')
        version = _version(latest['version'])
        result = {'latestStable': latest, 'candidateRelease': None, 'reason': None}
        if version < current or version == current and not include_current:
            result['reason'] = 'already current or newer than latest stable'
        elif component.get('strategy') == 'observe':
            result['reason'] = 'assisted update required: dedicated runtime strategy'
        elif version[0] != current[0] and (
            component.get('category') == 'Database'
            or repository in {'library/postgres', 'library/mysql', 'library/mariadb', 'library/redis', 'library/mongo', 'library/cassandra', 'library/elasticsearch'}
        ):
            # Database storage formats require an explicit, tested migration path.
            # Never hide a newer major behind an older same-major patch target.
            result['reason'] = 'migration required: database major upgrade to ' + latest['version'] + ' needs an explicit migration plan'
        else:
            # Legacy major/minor policies are accepted only for config compatibility.
            # Runtime/build/config/recovery gates remain the worker's responsibility.
            result['candidateRelease'] = latest
        return result
    except (ValueError, TypeError, KeyError, AttributeError, OSError, TimeoutError) as error:
        return dict(unavailable, reason='unavailable: ' + str(error))
