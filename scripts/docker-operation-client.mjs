#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";

const operation = process.argv[2];
const rest = process.argv.slice(3);
const parameters = {};
if (operation === "execute-backup-job") {
  if (rest.length !== 2 || rest[0] !== "--jobFileName") throw new Error("execute-backup-job requires --jobFileName <name>.json");
  parameters.jobFileName = rest[1];
} else if (rest.length !== 0) {
  throw new Error("This typed operation does not accept arguments.");
}

const principal = "backup-scheduler";
const tokenFile = process.env.BACKUP_SCHEDULER_DOCKER_GATEWAY_TOKEN_FILE || "/run/secrets/backup_scheduler_docker_gateway_token";
const token = fs.readFileSync(tokenFile, "utf8").trim();
if (token.length < 32) throw new Error("Docker operation gateway token is missing or too short.");
const base = new URL(process.env.PLATFORM_DOCKER_GATEWAY_URL || "http://docker-operation-gateway:8787");
const url = new URL("/v1/operations", base);
const response = await fetch(url, {
  method: "POST",
  headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
  body: JSON.stringify({ version: 1, principal, requestId: crypto.randomUUID(), issuedAt: new Date().toISOString(), operation, parameters }),
});
const result = await response.json().catch(() => ({}));
if (!response.ok || result.status !== "completed") throw new Error(`Typed platform operation failed (${response.status}).`);
process.stdout.write(`${operation} completed through the typed Docker gateway.\n`);
