import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('./infra-ops.mjs', import.meta.url));

test('certificate expiry CLI authenticates TLS before accepting expiry evidence', async t => {
  const root = fs.mkdtempSync(path.join(process.env.SECURITY_TEST_ARTIFACT_ROOT || fs.realpathSync(os.homedir()), 'certificate-expiry-'));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const openssl = (...args) => execFileSync('openssl', args, { cwd: root, stdio: 'ignore' });
  fs.writeFileSync(path.join(root, 'ca.cnf'), '[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\nCN=Ephemeral test CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
  fs.writeFileSync(path.join(root, 'leaf.cnf'), '[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:probe.example.test\n');
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '365', '-config', 'ca.cnf');
  openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=probe.example.test');
  for (const [name, days] of [['leaf.pem', '90'], ['near.pem', '1']]) {
    openssl('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', name, '-days', days, '-extfile', 'leaf.cnf', '-extensions', 'leaf');
  }
  fs.chmodSync(path.join(root, 'ca.pem'), 0o600);
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'extra-ca.key', '-out', 'extra-ca.pem', '-days', '365', '-config', 'ca.cnf', '-subj', '/CN=Ephemeral extra CA');
  fs.writeFileSync(path.join(root, 'docs.cnf'), fs.readFileSync(path.join(root, 'leaf.cnf'), 'utf8').replace('probe.example.test', 'docs.example.test'));
  openssl('x509', '-req', '-in', 'leaf.csr', '-CA', 'extra-ca.pem', '-CAkey', 'extra-ca.key', '-CAcreateserial', '-out', 'docs.pem', '-days', '90', '-extfile', 'docs.cnf', '-extensions', 'leaf');
  const preload = path.join(root, 'local-transport.cjs');
  // Redirect the connection only; TLS certificate and hostname validation remain real.
  fs.writeFileSync(preload, "const tls=require('node:tls');const connect=tls.connect;tls.connect=(options,...args)=>connect({...options,host:'127.0.0.1',port:Number(process.env.TEST_TLS_PORT)},...args);\n");
  let runNumber = 0;
  async function check(cert, hosts, ca, expected, extraCa = '') {
    const server = tls.createServer({ key: fs.readFileSync(path.join(root, 'leaf.key')), cert: fs.readFileSync(path.join(root, cert)) }, socket => socket.end());
    server.addContext('docs.example.test', { key: fs.readFileSync(path.join(root, 'leaf.key')), cert: fs.readFileSync(path.join(root, 'docs.pem')) });
    server.on('tlsClientError', () => {});
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const dataRoot = path.join(root, `run-${++runNumber}`);
    try {
      const result = await new Promise((resolve, reject) => {
        const child = spawn(process.execPath, ['--require', preload, script, 'certificate-expiry-check', '--hosts', hosts, ...(ca ? ['--caFile', ca] : [])], {
          env: { ...process.env, PLATFORM_INFRA_ROOT: root, PLATFORM_DATA_ROOT: dataRoot, TEST_TLS_PORT: String(server.address().port), CERTIFICATE_EXPIRY_CA_FILE: '', NODE_EXTRA_CA_CERTS: extraCa, NODE_TLS_REJECT_UNAUTHORIZED: '0' },
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        let output = ''; child.stdout.on('data', value => output += value); child.stderr.on('data', value => output += value);
        child.on('error', reject); child.on('close', code => resolve({ code, output }));
      });
      assert.equal(result.code, expected ? 0 : 1, result.output);
      const reports = path.join(dataRoot, 'reports/local-checks');
      const report = JSON.parse(fs.readFileSync(path.join(reports, fs.readdirSync(reports).find(name => name.endsWith('.json'))), 'utf8'));
      assert.equal(report.status, expected ? 'passed' : 'failed');
      return result.output;
    } finally { await new Promise(resolve => server.close(resolve)); }
  }
  await check('leaf.pem', 'probe.example.test', undefined, false);
  await check('leaf.pem', 'probe.example.test', path.join(root, 'ca.pem'), true);
  await check('leaf.pem', 'docs.example.test', undefined, true, path.join(root, 'extra-ca.pem'));
  await check('leaf.pem', 'probe.example.test,docs.example.test', path.join(root, 'ca.pem'), true, path.join(root, 'extra-ca.pem'));
  assert.match(await check('leaf.pem', '', path.join(root, 'ca.pem'), false), /requires at least one hostname/);
  assert.match(await check('leaf.pem', ', ,', path.join(root, 'ca.pem'), false), /requires at least one hostname/);
  await check('leaf.pem', 'wrong.example.test', path.join(root, 'ca.pem'), false);
  assert.match(await check('near.pem', 'probe.example.test', path.join(root, 'ca.pem'), false), /expires in less than 30 days/);
  fs.symlinkSync(path.join(root, 'ca.pem'), path.join(root, 'linked-ca.pem'));
  await check('leaf.pem', 'probe.example.test', path.join(root, 'linked-ca.pem'), false);
  fs.chmodSync(path.join(root, 'ca.pem'), 0o622);
  await check('leaf.pem', 'probe.example.test', path.join(root, 'ca.pem'), false);
  fs.chmodSync(path.join(root, 'ca.pem'), 0o600);
  // Reject the ephemeral key generated by this test, without embedding key markers in source.
  fs.chmodSync(path.join(root, 'ca.key'), 0o600);
  await check('leaf.pem', 'probe.example.test', path.join(root, 'ca.key'), false);
});
