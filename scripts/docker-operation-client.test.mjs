import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createDockerOperationGateway } from "./docker-operation-gateway.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const clientPath = path.join(root, "scripts", "docker-operation-client.mjs");
const token = "consumer-gateway-token-".padEnd(64, "7");

test("FG-011 scheduler consumer completes an allowed typed operation through the HTTP gateway", async (t) => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "docker-operation-consumer-"));
  const tokenFile = path.join(temp, "scheduler-token");
  fs.writeFileSync(tokenFile, `${token}\n`, { mode: 0o600 });
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));

  const observed = [];
  const server = createDockerOperationGateway({
    principalTokens: { "backup-scheduler": token },
    runOperation: async (operation) => {
      observed.push(operation);
      return { status: 0 };
    },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const result = await runClient(["backup-platform-catalog"], tokenFile, server.address().port);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "backup-platform-catalog completed through the typed Docker gateway.\n");
  assert.equal(result.stderr, "");
  assert.deepEqual(observed.map(({ principal, operation, args }) => ({ principal, operation, args })), [{
    principal: "backup-scheduler",
    operation: "backup-platform-catalog",
    args: ["backup-platform-catalog"],
  }]);
});

test("FG-011 scheduler consumer cannot widen the gateway operation vocabulary", async (t) => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "docker-operation-consumer-deny-"));
  const tokenFile = path.join(temp, "scheduler-token");
  fs.writeFileSync(tokenFile, `${token}\n`, { mode: 0o600 });
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));

  let privilegedCalls = 0;
  const server = createDockerOperationGateway({
    principalTokens: { "backup-scheduler": token },
    runOperation: async () => {
      privilegedCalls += 1;
      return { status: 0 };
    },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const result = await runClient(["container-exec"], tokenFile, server.address().port);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Typed platform operation failed \(403\)/);
  assert.doesNotMatch(`${result.stdout}${result.stderr}`, new RegExp(token));
  assert.equal(privilegedCalls, 0);
});

function runClient(args, tokenFile, port) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [clientPath, ...args], {
      cwd: root,
      env: {
        ...process.env,
        BACKUP_SCHEDULER_DOCKER_GATEWAY_TOKEN_FILE: tokenFile,
        PLATFORM_DOCKER_GATEWAY_URL: `http://127.0.0.1:${port}`,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("exit", (status, signal) => resolve({ status, signal, stdout, stderr }));
  });
}
