import { createHash } from 'node:crypto';

const HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function visibilityHostnames(project, zones) {
  const slug = String(project?.id || project?.slug || '').toLowerCase();
  const hostname = String(project?.hostname || '').trim().toLowerCase();
  const baseDomain = String(project?.baseDomain || '').trim().toLowerCase();
  if (!SLUG.test(slug) || !HOST.test(hostname) || !HOST.test(baseDomain)
    || !(hostname === baseDomain || hostname.endsWith(`.${baseDomain}`))) {
    throw Error('Project visibility admission is invalid');
  }
  const zone = zones.filter(item => hostname === item.name || hostname.endsWith(`.${item.name}`))
    .sort((left, right) => right.name.length - left.name.length)[0];
  if (!zone || !(baseDomain === zone.name || baseDomain.endsWith(`.${zone.name}`))) {
    throw Error('Project hostname is outside verified Cloudflare zones');
  }
  const privateHostname = hostname === baseDomain
    ? `local.${baseDomain}`
    : `local-${hostname.slice(0, hostname.indexOf('.'))}.${hostname.slice(hostname.indexOf('.') + 1)}`;
  if (!HOST.test(privateHostname) || privateHostname === hostname) throw Error('Private hostname derivation failed');
  return { slug, hostname, baseDomain, privateHostname, zone };
}

export function visibilityDigest(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}
