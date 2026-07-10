#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const state = fs.mkdtempSync(path.join(os.tmpdir(), "t14-secret-manager-"));
fs.chmodSync(state, 0o700);

try {
  for (const command of ["init", "verify"]) {
    const result = spawnSync(process.execPath, [
      path.join(root, "scripts", "infra-secret-manager.mjs"),
      command,
      "--secretsDir",
      state,
      "--envFile",
      path.join(root, ".env.example"),
    ], { encoding: "utf8" });
    if (result.status !== 0) {
      throw new Error(`Secret Manager ${command} failed: ${result.stderr || result.stdout}`);
    }
  }

  const passwords = [
    "backend_db_password",
    "worker_jobs_db_password",
    "worker_notifications_db_password",
  ];
  const urls = [
    "backend_database_url",
    "worker_jobs_database_url",
    "worker_notifications_database_url",
  ];
  const readValue = (name) => {
    const file = path.join(state, `${name}.txt`);
    if (!fs.existsSync(file)) throw new Error(`Missing materialized secret: ${name}`);
    const value = fs.readFileSync(file, "utf8").trim();
    if (!value) throw new Error(`Empty materialized secret: ${name}`);
    return value;
  };
  const values = [...passwords, ...urls].map(readValue);
  if (new Set(values.slice(0, 3)).size !== 3) throw new Error("Scoped database passwords are not distinct.");
  const users = values.slice(3).map((value) => new URL(value).username);
  if (new Set(users).size !== 3) throw new Error("Scoped database URL principals are not distinct.");

  for (let index = 0; index < passwords.length; index += 1) {
    const before = readValue(passwords[index]);
    const result = spawnSync(process.execPath, [
      path.join(root, "scripts", "infra-secret-manager.mjs"),
      "rotate",
      "--name",
      passwords[index],
      "--force",
      "--secretsDir",
      state,
      "--envFile",
      path.join(root, ".env.example"),
    ], { encoding: "utf8" });
    if (result.status !== 0) throw new Error(`Secret Manager rotation failed: ${result.stderr || result.stdout}`);
    const after = readValue(passwords[index]);
    const derived = new URL(readValue(urls[index]));
    if (after === before || derived.password !== after) throw new Error(`Scoped rotation did not refresh ${urls[index]}.`);
  }
  process.stdout.write("Scoped Secret Manager materialization and rotation passed 6/6 files with 3 distinct principals.\n");
} finally {
  fs.rmSync(state, { force: true, recursive: true });
}
