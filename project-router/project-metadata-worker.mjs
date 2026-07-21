import { parentPort, workerData } from "node:worker_threads";

try {
  preflightText(workerData.text, workerData.budgets);
  const value = JSON.parse(workerData.text);
  validateStructure(value, workerData.budgets);
  parentPort.postMessage({ ok: true, value });
} catch (error) {
  parentPort.postMessage({
    ok: false,
    code: String(error?.code || "PROJECT_METADATA_INVALID"),
    message: String(error?.message || "Project metadata is invalid."),
  });
}

function preflightText(text, budgets) {
  let depth = 0;
  let keys = 0;
  let inString = false;
  let escaped = false;
  for (const character of text) {
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') {
      inString = true;
      continue;
    }
    if (character === "{" || character === "[") {
      depth += 1;
      if (depth - 1 > budgets.maxDepth) budget("Project metadata exceeds the nesting budget.");
    } else if (character === "}" || character === "]") {
      depth -= 1;
    } else if (character === ":") {
      keys += 1;
      if (keys > budgets.maxKeys) budget("Project metadata exceeds the key budget.");
    }
  }
}

function validateStructure(root, budgets) {
  if (!root || typeof root !== "object" || Array.isArray(root)) invalid("Project metadata root must be an object.");
  const stack = [{ value: root, depth: 0, key: "" }];
  let nodes = 0;
  let keys = 0;
  let aliases = 0;
  while (stack.length) {
    const current = stack.pop();
    nodes += 1;
    if (nodes > budgets.maxNodes) budget("Project metadata exceeds the node budget.");
    if (current.depth > budgets.maxDepth) budget("Project metadata exceeds the nesting budget.");
    if (!current.value || typeof current.value !== "object") continue;
    if (Array.isArray(current.value)) {
      if (current.value.length > budgets.maxArrayItems) budget("Project metadata exceeds the array-item budget.");
      if (current.key === "aliases") {
        aliases += current.value.length;
        if (aliases > budgets.maxAliases) budget("Project metadata exceeds the alias budget.");
      }
      for (let index = current.value.length - 1; index >= 0; index -= 1) {
        stack.push({ value: current.value[index], depth: current.depth + 1, key: current.key });
      }
      continue;
    }
    const entries = Object.entries(current.value);
    keys += entries.length;
    if (keys > budgets.maxKeys) budget("Project metadata exceeds the key budget.");
    for (let index = entries.length - 1; index >= 0; index -= 1) {
      const [key, value] = entries[index];
      stack.push({ value, depth: current.depth + 1, key });
    }
  }
}

function invalid(message) {
  const error = new Error(message);
  error.code = "PROJECT_METADATA_INVALID";
  throw error;
}

function budget(message) {
  const error = new Error(message);
  error.code = "PROJECT_METADATA_COMPLEXITY";
  throw error;
}
