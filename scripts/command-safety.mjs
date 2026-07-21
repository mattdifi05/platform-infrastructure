import { spawnSync } from "node:child_process";

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function encodedForms(value) {
  const raw = String(value ?? "");
  if (raw.length < 4) return [];
  return [raw, encodeURIComponent(raw), Buffer.from(raw).toString("base64"), Buffer.from(raw).toString("base64url")]
    .filter((item, index, values) => item.length >= 4 && values.indexOf(item) === index);
}

export function redactSensitiveText(value, sensitiveValues = []) {
  let clean = String(value ?? "");
  const forms = sensitiveValues.flatMap(encodedForms).sort((a, b) => b.length - a.length);
  for (const form of forms) clean = clean.replace(new RegExp(escapeRegExp(form), "g"), "[REDACTED]");
  clean = clean
    .replace(/([a-z][a-z0-9+.-]*:\/\/)([^/@\s?#]+)@/gi, "$1[REDACTED]@")
    .replace(/([?&](?:access[_-]?key|api[_-]?key|auth|credential|password|secret|signature|token)=)[^&#\s]*/gi, "$1[REDACTED]");
  return clean;
}

export function runCommandSync(bin, args = [], options = {}) {
  const sensitiveValues = options.sensitiveValues ?? [];
  const capture = Boolean(options.capture) || sensitiveValues.length > 0;
  const result = spawnSync(bin, args, {
    cwd: options.cwd,
    env: options.env,
    input: options.input,
    encoding: options.encoding ?? "utf8",
    maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
    stdio: capture ? ["pipe", "pipe", "pipe"] : [options.input ? "pipe" : "inherit", "inherit", "inherit"],
  });
  const stdout = redactSensitiveText(result.stdout ?? "", sensitiveValues);
  const stderr = redactSensitiveText(result.stderr ?? "", sensitiveValues);
  if (result.error) {
    const message = redactSensitiveText(result.error.message ?? result.error, sensitiveValues);
    if (options.allowFailure) return { status: 1, stdout, stderr: message };
    throw new Error(message);
  }
  if (result.status !== 0 && !options.allowFailure) {
    const command = redactSensitiveText(`${bin} ${args.join(" ")}`, sensitiveValues);
    const details = [stderr, stdout].filter(Boolean).join("\n").trim();
    throw new Error(`${command} failed${details ? `:\n${details}` : ""}`);
  }
  return { ...result, stdout, stderr };
}

