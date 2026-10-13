#!/usr/bin/env node
// Generates only public registries; never opens token/API/private-key files.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { canonicalJson, readHostMachineId, validateRegistry, attestContainer } from './server-ai-controller.mjs';

export function buildRegistry({ machineId, policy, containers }) {
  const bindings = [
    { name: 'gf-searxng', service: 'searxng', mountSources: { '/etc/searxng': policy.searxngConfigDir, '/run/secrets/searxng-settings.yml': policy.searxngSettingsFile } },
    { name: 'gf-server-ai-observer', service: 'server-ai-observer', mountSources: { '/run/platform-docker-observer': '/run/platform-docker-observer', '/run/secrets/server_ai_observer_token': policy.observerTokenFile } },
  ];
  const registry = { version: 2, machineId, services: bindings.map((binding, index) => ({ ...binding, imageId: containers[index]?.Image, configHash: containers[index]?.Config?.Labels?.['com.docker.compose.config-hash'] })) };
  validateRegistry(registry);
  for (let index = 0; index < bindings.length; index++) {
    if (!attestContainer(containers[index], registry.services[index], machineId).compatible) throw new Error(`Enrollment rejected: ${bindings[index].service} violates reviewed runtime policy`);
  }
  return registry;
}
function protectedPath(filename, directory = false, token = false) {
  if (!path.isAbsolute(filename) || path.normalize(filename) !== filename) throw new Error('Input path is not canonical');
  let current = filename;
  while (true) {
    const st = fs.lstatSync(current);
    const leaf = current === filename;
    if (st.isSymbolicLink() || (st.mode & 0o022) || (st.uid !== 0 && !(leaf && token && st.uid === 1000))
      || leaf && (directory ? !st.isDirectory() : !st.isFile() || st.nlink !== 1)) throw new Error('Input path is not protected');
    if (leaf && token && (st.mode & 0o007)) throw new Error('Observer token is world accessible');
    if (current === '/') break;
    current = path.dirname(current);
  }
}
function inspect(name) {
  return new Promise((resolve, reject) => {
    const req = http.get({ socketPath: '/var/run/docker.sock', path: `/containers/${name}/json`, timeout: 5000 }, res => {
      let bytes = 0; const parts = [];
      res.on('data', part => { bytes += part.length; if (bytes > 256 * 1024) req.destroy(new Error('Docker response exceeds bound')); else parts.push(part); });
      res.on('error', reject);
      res.on('end', () => { try { if (res.statusCode !== 200) throw new Error('Required container is absent'); resolve(JSON.parse(Buffer.concat(parts))); } catch (error) { reject(error); } });
    });
    req.on('timeout', () => req.destroy(new Error('Docker inspect timed out'))); req.on('error', reject);
  });
}
async function main() {
  if (process.getuid?.() !== 0 || process.argv.length !== 4) throw new Error('Run as root: node enroll-empty-host.mjs ROOT_OWNED_POLICY_JSON NEW_OUTPUT_DIRECTORY');
  const [, , policyFile, output] = process.argv;
  protectedPath(policyFile);
  if (fs.statSync(policyFile).size > 8192) throw new Error('Policy too large');
  const policy = JSON.parse(fs.readFileSync(policyFile, 'utf8'));
  if (Object.keys(policy).sort().join(',') !== 'observerTokenFile,searxngConfigDir,searxngSettingsFile') throw new Error('Policy fields invalid');
  protectedPath(policy.searxngConfigDir, true); protectedPath(policy.searxngSettingsFile); protectedPath(policy.observerTokenFile, false, true);
  protectedPath('/run', true);
  const proxyDir = fs.lstatSync('/run/platform-docker-observer');
  const proxySocket = fs.lstatSync('/run/platform-docker-observer/docker.sock');
  if (!proxyDir.isDirectory() || proxyDir.isSymbolicLink() || proxyDir.mode & 0o022
    || !proxySocket.isSocket() || proxySocket.uid !== proxyDir.uid || proxySocket.gid !== proxyDir.gid
    || proxySocket.mode & 0o007) throw new Error('Observer proxy socket is not protected');
  // Parent must exist and be root-owned. New directory avoids replacing a live enrollment.
  protectedPath(path.dirname(output), true);
  if (!path.isAbsolute(output) || path.normalize(output) !== output || fs.existsSync(output)) throw new Error('Output must be a new canonical absolute directory');
  const machineId = readHostMachineId('/etc/machine-id');
  const containers = await Promise.all(['gf-searxng', 'gf-server-ai-observer'].map(inspect));
  const registry = buildRegistry({ machineId, policy, containers });
  const machines = { version: 1, machines: [{ id: machineId, label: 'platform-server-public', local: true, configured: true, controllerSocket: '/run/server-ai-controller/controller.sock', searxngUrl: 'http://searxng:8080', observerUrl: 'http://server-ai-observer:8090', observerTokenFile: '/run/secrets/server_ai_observer_token' }] };
  fs.mkdirSync(output, { mode: 0o755 });
  fs.writeFileSync(path.join(output, 'controller-registry.json'), canonicalJson(registry) + '\n', { flag: 'wx', mode: 0o644 });
  fs.writeFileSync(path.join(output, 'machine-registry.json'), canonicalJson(machines) + '\n', { flag: 'wx', mode: 0o644 });
  process.stdout.write('Created fresh public registries from attested Docker containers. No credentials read.\n');
}
if (import.meta.url === `file://${process.argv[1]}`) main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
