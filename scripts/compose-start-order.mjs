#!/usr/bin/env node
import fs from "node:fs";
import process from "node:process";

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

const [modelPath, ...selectedNames] = process.argv.slice(2);
if (!modelPath || selectedNames.length === 0) {
  fail("Usage: compose-start-order.mjs MODEL_JSON SERVICE...");
}
let model;
try {
  model = JSON.parse(fs.readFileSync(modelPath, "utf8"));
} catch {
  fail("Compose start-order model is unreadable.");
}
const selected = new Set(selectedNames);
if (selected.size !== selectedNames.length) fail("Compose start-order service selection contains duplicates.");
for (const name of selected) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(name) || !model?.services?.[name]) {
    fail(`Compose start-order service is not present in the exact model: ${name}`);
  }
}
const dependencies = new Map();
for (const name of selected) {
  const definition = model.services[name];
  const raw = definition.depends_on ?? {};
  const names = Array.isArray(raw) ? raw.map(String) : Object.keys(raw);
  const required = names.filter((dependency) => selected.has(dependency)).sort();
  const missing = names.filter((dependency) => !selected.has(dependency));
  if (missing.length > 0) fail(`${name} depends on services outside the exact start set: ${missing.sort().join(",")}`);
  dependencies.set(name, new Set(required));
}
let pending = [...selected].sort();
let layer = 0;
while (pending.length > 0) {
  const ready = pending.filter((name) => dependencies.get(name).size === 0).sort();
  if (ready.length === 0) fail(`Compose service dependency cycle: ${pending.join(",")}`);
  for (const name of ready) process.stdout.write(`${layer}\t${name}\n`);
  const readySet = new Set(ready);
  pending = pending.filter((name) => !readySet.has(name));
  for (const name of pending) {
    for (const dependency of readySet) dependencies.get(name).delete(dependency);
  }
  layer += 1;
}
