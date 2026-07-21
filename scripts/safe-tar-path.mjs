export function validateTarEntryName(value, label = "archive source name") {
  const name = String(value ?? "");
  if (!name || name === "." || name === "..") throw new Error(`Invalid ${label}.`);
  if (name.startsWith("-") || name.startsWith("@")) {
    throw new Error(`Invalid ${label}: option-like names are forbidden.`);
  }
  if (/[\/\\\0\r\n\t]/.test(name) || /[\u0000-\u001f\u007f]/.test(name)) {
    throw new Error(`Invalid ${label}: path separators and control characters are forbidden.`);
  }
  return name;
}

export function safeTarCreateArgs({ archivePath, excludeArgs = [], sourceRoot, entryName }) {
  const safeName = validateTarEntryName(entryName);
  return ["-czf", archivePath, ...excludeArgs, "-C", sourceRoot, "--", safeName];
}

