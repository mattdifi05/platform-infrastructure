import { request } from 'node:http';
export const APPLICATION_OPERATOR_SOCKET = '/run/platform-application-operator/operator.sock';
export function createApplicationOperator({ requestImpl = request } = {}) {
  return async body => {
    if (!['list', 'plan', 'clone', 'status', 'cancel', 'activate'].includes(body?.operation)) throw Error('Unsupported native operation');
    const payload = JSON.stringify(body);
    return await new Promise((resolve, reject) => {
      const req = requestImpl({ socketPath: APPLICATION_OPERATOR_SOCKET, path: '/v1/operator', method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } }, res => {
        let text = ''; res.setEncoding('utf8');
        res.on('data', chunk => { text += chunk; if (text.length > 1024 * 1024) req.destroy(Error('Native response too large')); });
        res.on('end', () => { try { const value = JSON.parse(text); if (res.statusCode !== 200 || value.error) throw Error('Native application operator rejected operation'); resolve(value); } catch { reject(Error('Native application operator unavailable')); } });
      });
      req.setTimeout(body.operation === 'activate' ? 90000 : 15000, () => req.destroy(Error('Native application operator timed out')));
      req.on('error', () => reject(Error('Native application operator unavailable'))); req.end(payload);
    });
  };
}
