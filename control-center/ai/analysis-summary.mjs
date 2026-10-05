import { redactText } from "./web.mjs";

const OPEN = "<analysis_summary>";
const CLOSE = "</analysis_summary>";
const MAX_LEADING_WHITESPACE_BYTES = 256;
export const MAX_ANALYSIS_SUMMARY_CHARS = 1200;
const MAX_ANALYSIS_SUMMARY_BYTES = 6 * 1024;
const MAX_PROTOCOL_BUFFER_BYTES = 6 * 1024;

function clipCodePoints(value, maximum) {
  return Array.from(value).slice(0, maximum).join("");
}

function clipUtf8(value, maximum) {
  let output = "";
  let used = 0;
  for (const character of value) {
    const bytes = Buffer.byteLength(character);
    if (used + bytes > maximum) break;
    output += character;
    used += bytes;
  }
  return output;
}

export function normalizeAnalysisSummary(value, { truncate = false } = {}) {
  if (typeof value !== "string") return null;
  let text = redactText(value, MAX_ANALYSIS_SUMMARY_BYTES * 2)
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  // `length` counts UTF-16 code units, while the persisted/UI contract is in
  // user-visible Unicode characters. Keep the separate byte bound for memory.
  if (truncate) text = clipUtf8(clipCodePoints(text, MAX_ANALYSIS_SUMMARY_CHARS), MAX_ANALYSIS_SUMMARY_BYTES).trim();
  if (!text || Array.from(text).length > MAX_ANALYSIS_SUMMARY_CHARS || Buffer.byteLength(text) > MAX_ANALYSIS_SUMMARY_BYTES) return null;
  // The protocol delimiters are transport-only. Nested markup would make the
  // UI/parser ambiguous, so fail closed rather than storing it as analysis.
  if (text.includes("<") || text.includes(">")) return null;
  return text;
}

function splitReservedPrefix(value) {
  const max = Math.min(Math.max(OPEN.length, CLOSE.length) - 1, value.length);
  for (let length = max; length > 0; length -= 1) {
    const suffix = value.slice(-length);
    if (OPEN.startsWith(suffix) || CLOSE.startsWith(suffix)) return [value.slice(0, -length), suffix];
  }
  return [value, ""];
}

// Extract exactly one public, model-authored status block only when it begins
// the assistant's round (after harmless leading whitespace). `thinking` never
// reaches this parser. Malformed protocol is downgraded to ordinary visible
// content with protocol delimiters removed, so a final answer is never lost.
export function createAnalysisSummaryParser({ onSummary = async () => {}, onContent = async () => {} } = {}) {
  let state = "prefix";
  let prefix = "";
  let summary = "";
  let reservedPending = "";
  let stripReservedTokens = false;
  let emittedSummary = false;

  const emitContent = async text => { if (text) await onContent(text); };
  const emitPlain = async text => {
    if (!text) return;
    if (!stripReservedTokens) return emitContent(text);
    let pending = `${reservedPending}${text}`;
    reservedPending = "";
    for (;;) {
      const openAt = pending.indexOf(OPEN);
      const closeAt = pending.indexOf(CLOSE);
      const tokenAt = openAt < 0 ? closeAt : closeAt < 0 ? openAt : Math.min(openAt, closeAt);
      if (tokenAt < 0) break;
      await emitContent(pending.slice(0, tokenAt));
      pending = pending.slice(tokenAt + (tokenAt === openAt ? OPEN.length : CLOSE.length));
    }
    const [ready, suffix] = splitReservedPrefix(pending);
    await emitContent(ready);
    reservedPending = suffix;
  };
  const downgradeSummary = async ({ tail = "" } = {}) => {
    state = "plain";
    await emitPlain(`${summary}${tail}`);
    summary = "";
  };

  async function push(value) {
    const chunk = String(value || "");
    if (!chunk) return;
    if (state === "plain") return emitPlain(chunk);
    if (state === "prefix") {
      prefix += chunk;
      const leading = prefix.match(/^\s*/)?.[0] || "";
      if (Buffer.byteLength(leading) > MAX_LEADING_WHITESPACE_BYTES) {
        state = "plain";
        await emitPlain(prefix);
        prefix = "";
        return;
      }
      const candidate = prefix.slice(leading.length);
      if (!candidate) return;
      if (candidate.startsWith(OPEN)) {
        state = "summary";
        stripReservedTokens = true;
        prefix = "";
        return push(candidate.slice(OPEN.length));
      }
      if (OPEN.startsWith(candidate)) return;
      state = "plain";
      await emitPlain(prefix);
      prefix = "";
      return;
    }
    summary += chunk;
    const closeAt = summary.indexOf(CLOSE);
    if (closeAt >= 0) {
      const rawSummary = summary.slice(0, closeAt);
      const candidate = normalizeAnalysisSummary(rawSummary);
      const tail = summary.slice(closeAt + CLOSE.length);
      summary = "";
      state = "plain";
      if (candidate && !emittedSummary) {
        emittedSummary = true;
        await onSummary(candidate);
        await emitPlain(tail);
      } else {
        // A malformed protocol is not analysis, but its human-facing words
        // still belong to the normal response; omit delimiters only.
        await emitPlain(`${rawSummary}${tail}`);
      }
      return;
    }
    if (Buffer.byteLength(summary) > MAX_PROTOCOL_BUFFER_BYTES) await downgradeSummary();
  }

  async function finish() {
    if (state === "prefix") {
      // A partial protocol opener is transport noise, not a user-facing
      // answer. Ordinary legacy output never reaches this branch.
      const leading = prefix.match(/^\s*/)?.[0] || "";
      const candidate = prefix.slice(leading.length);
      if (!OPEN.startsWith(candidate)) await emitPlain(prefix);
      state = "plain";
      prefix = "";
    } else if (state === "summary") {
      // Closing delimiter never arrived. Preserve the answer body but do not
      // render the protocol opener and do not persist an unvalidated summary.
      await downgradeSummary();
    }
    // Any held prefix is a truncated reserved marker after a protocol attempt.
    // It is transport syntax, not answer text.
    reservedPending = "";
  }

  return Object.freeze({ push, finish });
}
