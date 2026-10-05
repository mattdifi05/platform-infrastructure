const MAX_SEGMENT_BYTES = 16 * 1024;
const MAX_OUTPUT_BYTES = 64 * 1024;
const TOKEN_CHAR = /[A-Za-z0-9+/_=.-]/;
const FLAG_LONG = /^(?:serverinstance|password|username|credential|database|passwd|server|host|user)$/i;
const FLAG_SHORT = new Set(["p", "u", "h"]);
const DECORATION = new Set(["`", "*", "_", "~", '"', "'"]);
const FIELD_NAMES = [
  "host database", "database host", "database name", "database nome", "nome database",
  "database user", "db user", "utente database", "utente db", "nome utente",
  "password database", "password db", "session id", "session_id", "session-id", "api key", "api_key", "api-key",
  "username", "password", "passwd", "pwd", "credenziale", "credential",
  "authorization", "cookie", "secret", "segreto", "token", "database",
];
FIELD_NAMES.sort((left, right) => right.length - left.length);

const REPLACEMENTS = Object.freeze({
  assignment: "[redatto]",
  credential: "[credenziale rimossa]",
  token: "[token rimosso]",
  privateKey: "[chiave privata rimossa]",
});
const PRIORITY = Object.freeze({ assignment: 1, credential: 2, token: 3, privateKey: 4 });

function invalid(message) { throw new TypeError(message); }

function ensureInputs({ prefix = "", target, suffix = "" } = {}, { maxOutputBytes } = {}) {
  if (typeof prefix !== "string" || typeof target !== "string" || typeof suffix !== "string") invalid("Attachment redaction expects decoded UTF-8 strings.");
  for (const [name, value] of [["prefix", prefix], ["target", target], ["suffix", suffix]]) {
    if (Buffer.byteLength(value, "utf8") > MAX_SEGMENT_BYTES) invalid(`${name} exceeds the bounded redaction window.`);
  }
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1 || maxOutputBytes > MAX_OUTPUT_BYTES) invalid("maxOutputBytes is outside the bounded redaction limit.");
}

function boundaryChar(value, index) {
  const char = value[index];
  return char !== undefined && /[A-Za-z0-9_-]/.test(char);
}

function markRange(mask, targetStart, targetEnd, start, end, kind) {
  const from = Math.max(start, targetStart) - targetStart;
  const to = Math.min(end, targetEnd) - targetStart;
  if (to <= from) return;
  const priority = PRIORITY[kind];
  for (let index = from; index < to; index += 1) if (priority > mask[index]) mask[index] = priority;
}

function scanPrivateKeys(value, mark) {
  const begin = /-----BEGIN [A-Z0-9 ]{0,64}PRIVATE KEY-----/gi;
  const end = /-----END [A-Z0-9 ]{0,64}PRIVATE KEY-----/gi;
  let match;
  while ((match = begin.exec(value))) {
    const start = match.index;
    end.lastIndex = start + match[0].length;
    const endMatch = end.exec(value);
    if (!endMatch) {
      mark(start, value.length, "privateKey");
      break;
    }
    mark(start, endMatch.index + endMatch[0].length, "privateKey");
    begin.lastIndex = endMatch.index + endMatch[0].length;
  }
}

function scanSimplePatterns(value, mark) {
  const userPass = /\bhttps?:\/\/[^/\s:@]+:[^/\s@]+@/gi;
  for (const match of value.matchAll(userPass)) {
    const schemeEnd = match[0].indexOf("://") + 3;
    mark(match.index + schemeEnd, match.index + match[0].length - 1, "credential");
  }

  const token = /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/gi;
  for (const match of value.matchAll(token)) mark(match.index, match.index + match[0].length, "token");

  let index = 0;
  while (index < value.length) {
    if (boundaryChar(value, index - 1) || !/b/i.test(value[index])) { index += 1; continue; }
    const bearer = value.slice(index, index + 6).toLowerCase() === "bearer";
    const basic = value.slice(index, index + 5).toLowerCase() === "basic";
    if (!bearer && !basic) { index += 1; continue; }
    const scheme = bearer ? "bearer" : "basic";
    let cursor = index + scheme.length;
    while (/[ \t]/.test(value[cursor] || "")) cursor += 1;
    const tokenStart = cursor;
    while (TOKEN_CHAR.test(value[cursor] || "")) cursor += 1;
    if (cursor > tokenStart) mark(tokenStart, cursor, "credential");
    else if (tokenStart >= value.length) mark(tokenStart, value.length, "credential");
    index = Math.max(cursor, index + 1);
  }
}

function matchField(value, index) {
  if (boundaryChar(value, index - 1)) return null;
  for (const field of FIELD_NAMES) {
    if (value.slice(index, index + field.length).toLowerCase() !== field) continue;
    const end = index + field.length;
    if (boundaryChar(value, end)) continue;
    return { end, field };
  }
  let end = index;
  while (/[A-Za-z0-9_-]/.test(value[end] || "")) end += 1;
  const identifier = value.slice(index, end).toLowerCase();
  if (end > index && /(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|session[_-]?id|credential)/.test(identifier)) return { end, field: identifier };
  return null;
}

function consumeDecorations(value, index) {
  let cursor = index;
  for (let count = 0; count < 3 && DECORATION.has(value[cursor]); count += 1) cursor += 1;
  return cursor;
}

function consumeValue(value, start, { table = false } = {}) {
  let cursor = start;
  if (cursor >= value.length) return { start, end: start };
  const quote = value[cursor];
  if (["'", '"', "`"].includes(quote)) {
    cursor += 1;
    while (cursor < value.length && value[cursor] !== quote && value[cursor] !== "\r" && value[cursor] !== "\n") cursor += 1;
    return { start, end: cursor < value.length && value[cursor] === quote ? cursor + 1 : value.length };
  }
  while (cursor < value.length) {
    const char = value[cursor];
    if (char === "\r" || char === "\n" || char === "," || char === ";" || char === "|" || (!table && /\s/.test(char))) break;
    cursor += 1;
  }
  return { start, end: cursor };
}

function scanAssignments(value, mark) {
  let index = 0;
  while (index < value.length) {
    if (value[index] === "|") {
      const fieldStart = index + 1;
      const fieldEnd = value.indexOf("|", fieldStart);
      if (fieldEnd >= 0) {
        const field = value.slice(fieldStart, fieldEnd).trim();
        if (FIELD_NAMES.some(name => field.replace(/[`*_~"']/g, "").trim().toLowerCase() === name)) {
          const next = value.indexOf("|", fieldEnd + 1);
          mark(fieldEnd + 1, next < 0 ? value.length : next, "assignment");
          index = next < 0 ? value.length : next + 1;
          continue;
        }
      }
    }
    const decorated = consumeDecorations(value, index);
    const match = matchField(value, decorated);
    if (!match) { index += 1; continue; }
    let cursor = consumeDecorations(value, match.end);
    while (/\s/.test(value[cursor] || "")) cursor += 1;
    if (value.startsWith("=>", cursor)) cursor += 2;
    else if ([":", "="].includes(value[cursor])) cursor += 1;
    else { index += 1; continue; }
    while (/\s/.test(value[cursor] || "")) cursor += 1;
    const result = consumeValue(value, cursor);
    if (result.end > result.start) mark(result.start, result.end, "assignment");
    index = Math.max(result.end, index + 1);
  }
}

function scanDatabaseFlags(value, mark) {
  let index = 0;
  while (index < value.length) {
    if (value[index] !== "-" || (index > 0 && !/\s/.test(value[index - 1]))) { index += 1; continue; }
    let cursor = index + 1;
    if (value[cursor] === "-") cursor += 1;
    const flagStart = cursor;
    if (value[index + 1] !== "-" && FLAG_SHORT.has(value[index + 1]?.toLowerCase())) {
      cursor = index + 2;
      if (value[cursor] === "=") cursor += 1;
      else while (/\s/.test(value[cursor] || "")) cursor += 1;
      const result = consumeValue(value, cursor);
      if (result.end > result.start) mark(result.start, result.end, "assignment");
      index = Math.max(result.end, index + 1);
      continue;
    }
    while (/[A-Za-z]/.test(value[cursor] || "")) cursor += 1;
    const flag = value.slice(flagStart, cursor);
    if (!(flag.length > 1 ? FLAG_LONG.test(flag) : FLAG_SHORT.has(flag.toLowerCase()))) { index += 1; continue; }
    if (value[cursor] === "=") cursor += 1;
    else while (/\s/.test(value[cursor] || "")) cursor += 1;
    const result = consumeValue(value, cursor);
    if (result.end > result.start) mark(result.start, result.end, "assignment");
    index = Math.max(result.end, index + 1);
  }
}

function clipUtf8(value, maxBytes) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length <= maxBytes) return value;
  let end = maxBytes;
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) end -= 1;
  return bytes.subarray(0, end).toString("utf8");
}

/**
 * Redacts a bounded UTF-8 window while returning only the target segment.
 * Prefix and suffix are context for patterns crossing the target boundary;
 * they are never included in the result.
 */
export function redactAttachmentWindow({ prefix = "", target, suffix = "" } = {}, { maxOutputBytes } = {}) {
  ensureInputs({ prefix, target, suffix }, { maxOutputBytes });
  const value = `${prefix}${target}${suffix}`;
  const targetStart = prefix.length;
  const targetEnd = targetStart + target.length;
  const mask = new Uint8Array(target.length);
  const mark = (start, end, kind) => markRange(mask, targetStart, targetEnd, start, end, kind);
  scanPrivateKeys(value, mark);
  scanSimplePatterns(value, mark);
  scanAssignments(value, mark);
  scanDatabaseFlags(value, mark);

  let output = "";
  let index = 0;
  while (index < target.length) {
    if (!mask[index]) { output += target[index]; index += 1; continue; }
    let priority = mask[index];
    let end = index + 1;
    while (end < target.length && mask[end]) { priority = Math.max(priority, mask[end]); end += 1; }
    const kind = Object.keys(PRIORITY).find(name => PRIORITY[name] === priority) || "assignment";
    output += REPLACEMENTS[kind];
    index = end;
  }
  return clipUtf8(output, maxOutputBytes);
}

export const ATTACHMENT_REDACTION_LIMITS = Object.freeze({ maxSegmentBytes: MAX_SEGMENT_BYTES, maxOutputBytes: MAX_OUTPUT_BYTES });
