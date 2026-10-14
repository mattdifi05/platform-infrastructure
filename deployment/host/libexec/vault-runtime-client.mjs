// Installed inside the protected, read-only host extension tree.
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { createHmac, randomBytes } from 'node:crypto';
export async function vaultRuntime(body) {
  const envelope = { body, timestamp: Date.now(), nonce: randomBytes(16).toString('hex') };
  const raw = Buffer.from(JSON.stringify(envelope));
  const signature = createHmac('sha256', readFileSync('/run/secrets/control_center_vault_bridge_token')).update(raw).digest('hex');
  return new Promise((resolve, reject) => {
    const request = http.request({ socketPath: '/run/platform-vault/runtime.sock', path: '/v1/runtime', method: 'POST', headers: { 'content-type': 'application/json', 'content-length': raw.length, 'x-platform-signature': signature }, timeout: 30000 }, response => {
      const chunks = []; let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > 256 * 1024) request.destroy(Error('Vault runtime response too large')); else chunks.push(chunk); });
      response.on('end', () => { try { const value = JSON.parse(Buffer.concat(chunks)); if (response.statusCode !== 200 || value.error) reject(Error(value.error || 'Vault runtime unavailable')); else resolve(value); } catch { reject(Error('Vault runtime unavailable')); } });
    });
    request.on('timeout', () => request.destroy(Error('Vault runtime unavailable')));
    request.on('error', () => reject(Error('Vault runtime unavailable')));
    request.end(raw);
  });
}
