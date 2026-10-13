import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const HOST_EXTENSION_FILE = '/run/platform-host-extension/index.mjs';

export function validateHostExtensionPath(value) {
  if (value !== HOST_EXTENSION_FILE) throw Error('Host extension must use the fixed protected deployment path');
  return value;
}

function protectedEntry(filename, directory) {
  const info = lstatSync(filename);
  if (info.isSymbolicLink() || info.uid !== 0 || info.mode & 0o022
      || (directory ? !info.isDirectory() : !info.isFile())) {
    throw Error('Host extension ownership or file type is unsafe');
  }
}

function verifyCodeTree(root, budget = { files: 0 }) {
  protectedEntry(root, true);
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const filename = path.join(root, entry.name);
    if (++budget.files > 128) throw Error('Host extension exceeds the bounded code bundle');
    if (entry.isDirectory()) verifyCodeTree(filename, budget);
    else protectedEntry(filename, false);
  }
}

const configured = process.env.CONTROL_CENTER_HOST_EXTENSION_FILE;
let extension = {};
if (configured !== undefined) {
  validateHostExtensionPath(configured);
  const root = path.dirname(configured);
  for (let ancestor = path.dirname(root); ; ancestor = path.dirname(ancestor)) {
    protectedEntry(ancestor, true);
    if (ancestor === '/') break;
  }
  verifyCodeTree(root);
  const mountedReadOnly = readFileSync('/proc/self/mountinfo', 'utf8').split('\n').some(line => {
    const fields = line.split(' ');
    return fields[4] === root && fields[5]?.split(',').includes('ro');
  });
  if (!mountedReadOnly) throw Error('Host extension requires its fixed read-only code mount');
  extension = (await import(pathToFileURL(configured).href)).default;
  if (!extension || typeof extension !== 'object' || Array.isArray(extension)) throw Error('Invalid host extension interface');
}
export const hostExtension = Object.freeze(extension);
