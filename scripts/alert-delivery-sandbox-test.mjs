#!/usr/bin/env node
import { randomBytes, randomUUID } from "node:crypto";
import { chmodSync, chownSync, cpSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const sandboxRoot = "/sandbox";
const hostRoot = String(process.env.SANDBOX_HOST_ROOT || "").trim();
if (!hostRoot.startsWith("/")) throw new Error("SANDBOX_HOST_ROOT must be an absolute host path.");

const suffix = `${process.pid}-${Date.now()}`;
const network = `platform-t09-alert-${suffix}`;
const receiverContainer = `${network}-receiver`;
const alertmanagerContainer = `${network}-alertmanager`;
const deniedContainer = `${network}-denied`;
const nodeImage = "node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606";
const alertmanagerImage = "prom/alertmanager:v0.32.2@sha256:b85533a2eb45865835315810315f6951331b2dbc8c93a6cf9a51e156a006a706";
const token = randomBytes(48).toString("base64url");
const tokenFile = path.join(sandboxRoot, "alertmanager_webhook_token.txt");
const deniedTokenFile = path.join(sandboxRoot, "denied", "alertmanager_webhook_token.txt");
const configFile = path.join(sandboxRoot, "alertmanager.yml");
const receiverFile = path.join(sandboxRoot, "receiver.mjs");
const replicaRoot = path.join(sandboxRoot, "infra");
const runtimeGid = 1000;

function command(program, args, { allowFailure = false, env = {} } = {}) {
  const result = spawnSync(program, args, { encoding: "utf8", env: { ...process.env, ...env } });
  if (!allowFailure && result.status !== 0) {
    const detail = String(result.stderr || result.stdout || "command failed").replaceAll(token, "[redacted]").trim().slice(-800);
    throw new Error(`${program} failed: ${detail}`);
  }
  return result;
}

function docker(args, options = {}) {
  return command("docker", args, options);
}

function waitForExec(container, args, attempts = 60) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (docker(["exec", container, ...args], { allowFailure: true }).status === 0) return;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);
  }
  throw new Error(`${container} did not become ready.`);
}

function hostPath(relative) {
  return path.join(hostRoot, relative);
}

const receiverSource = `
import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
const token = readFileSync("/run/secrets/alertmanager_webhook_token", "utf8").trim();
const receipts = new Set();
let requests = 0;
let firing = 0;
let resolved = 0;
function authorized(request) {
  const supplied = String(request.headers.authorization || "").replace(/^Bearer\\s+/i, "");
  const left = Buffer.from(supplied);
  const right = Buffer.from(token);
  return left.length === right.length && timingSafeEqual(left, right);
}
function respond(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}
createServer((request, response) => {
  if (request.url === "/healthz") return respond(response, 200, { status: "ok" });
  if (request.url === "/metrics") {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end([
      '# TYPE platform_alert_webhook_requests_total counter',
      'platform_alert_webhook_requests_total ' + requests,
      '# TYPE platform_alert_webhook_alerts_total counter',
      'platform_alert_webhook_alerts_total{status="firing"} ' + firing,
      'platform_alert_webhook_alerts_total{status="resolved"} ' + resolved,
      'platform_alert_delivery_total{channel="email",result="success"} 0',
      'platform_alert_delivery_total{channel="forward",result="success"} 0',
      '',
    ].join('\\n'));
    return;
  }
  if (!authorized(request)) return respond(response, 401, { error: "unauthorized" });
  if (request.method === "GET" && request.url.startsWith("/receipts/")) {
    const id = decodeURIComponent(request.url.slice("/receipts/".length));
    return receipts.has(id) ? respond(response, 200, { status: "received", probeId: id }) : respond(response, 404, { error: "not_found" });
  }
  if (request.method !== "POST" || request.url !== "/alerts/prometheus") return respond(response, 404, { error: "not_found" });
  const chunks = [];
  let size = 0;
  request.on("data", (chunk) => {
    size += chunk.length;
    if (size > 131072) request.destroy();
    else chunks.push(chunk);
  });
  request.on("end", () => {
    try {
      const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
      requests += 1;
      firing += alerts.filter((alert) => alert?.status === "firing").length;
      resolved += alerts.filter((alert) => alert?.status === "resolved").length;
      for (const alert of alerts) {
        const id = String(alert?.labels?.platform_probe_id || "");
        if (/^[a-f0-9-]{36}$/.test(id)) receipts.add(id);
      }
      console.log(JSON.stringify({ event: "prometheus_alerts_received", alerts: alerts.map((alert) => ({ alertname: alert?.labels?.alertname })) }));
      respond(response, 202, { status: "accepted" });
    } catch {
      respond(response, 400, { error: "invalid_payload" });
    }
  });
}).listen(3000, "0.0.0.0");
`;

const alertmanagerConfig = `
global:
  resolve_timeout: 1m
route:
  receiver: sandbox-receiver
  group_by: [alertname, service, severity]
  group_wait: 0s
  group_interval: 1m
  repeat_interval: 1h
receivers:
  - name: sandbox-receiver
    webhook_configs:
      - url: http://receiver:3000/alerts/prometheus
        send_resolved: true
        http_config:
          authorization:
            type: Bearer
            credentials_file: /run/secrets/alertmanager_webhook_token
`;

const liveIdsBefore = {
  alertmanager: docker(["inspect", "--format", "{{.Id}}", "enterprise-alertmanager"], { allowFailure: true }).stdout.trim(),
  receiver: docker(["inspect", "--format", "{{.Id}}", "enterprise-platform-alert-dispatcher"], { allowFailure: true }).stdout.trim(),
};

try {
  mkdirSync(path.dirname(deniedTokenFile), { recursive: true, mode: 0o700 });
  writeFileSync(tokenFile, `${token}\n`, { mode: 0o600 });
  writeFileSync(deniedTokenFile, `${token}\n`, { mode: 0o600 });
  chownSync(deniedTokenFile, -1, runtimeGid);
  writeFileSync(configFile, alertmanagerConfig, { mode: 0o644 });
  writeFileSync(receiverFile, receiverSource, { mode: 0o644 });
  for (const directory of [
    path.join(replicaRoot, "scripts"),
    path.join(replicaRoot, "alertmanager"),
    path.join(replicaRoot, "prometheus", "rules"),
    path.join(replicaRoot, "platform-alert-dispatcher"),
    path.join(replicaRoot, "control-center", "backup"),
  ]) mkdirSync(directory, { recursive: true, mode: 0o700 });
  for (const relative of [
    "compose.yaml",
    "compose.secrets.yaml",
    "scripts/infra-ops.mjs",
    "scripts/infra-secret-manager.mjs",
    "scripts/alertmanager-secret-permissions.sh",
    "scripts/network-segmentation-policy.mjs",
    "scripts/runtime-isolation-policy.mjs",
    "scripts/supply-chain-policy.mjs",
    "scripts/github-governance-policy.mjs",
    "scripts/release-trust.mjs",
    "scripts/bounded-file-hash.mjs",
    "scripts/command-safety.mjs",
    "scripts/restic-secret-transport.mjs",
    "scripts/safe-tar-path.mjs",
    "scripts/secret-store-metadata.mjs",
    "scripts/backup-import-policy.mjs",
    "scripts/postgres-restore-sandbox.mjs",
    "scripts/offsite-restore-contract.mjs",
    "scripts/canonical-compose-topology.mjs",
    "scripts/candidate-identity.mjs",
    "scripts/evidence-trust-envelope.mjs",
    "scripts/evidence-bundle-anchor.mjs",
    "alertmanager/alertmanager.yml",
    "prometheus/rules/enterprise-alerts.yml",
    "platform-alert-dispatcher/server.mjs",
    "control-center/backup/contracts.mjs",
  ]) cpSync(path.join(repositoryRoot, relative), path.join(replicaRoot, relative));

  const permissionScript = path.join(repositoryRoot, "scripts", "alertmanager-secret-permissions.sh");
  const initialCheck = command("sh", [permissionScript, "--file", tokenFile, "--gid", String(runtimeGid)], { allowFailure: true });
  if (initialCheck.status === 0 || !`${initialCheck.stderr}${initialCheck.stdout}`.includes("mode must be 640")) throw new Error("Mode 0600 did not fail the permission contract.");
  const unconfirmed = command("sh", [permissionScript, "--file", tokenFile, "--gid", String(runtimeGid), "--apply"], { allowFailure: true });
  if (unconfirmed.status === 0 || !`${unconfirmed.stderr}${unconfirmed.stdout}`.includes("Apply requires")) throw new Error("Unconfirmed secret permission mutation was accepted.");
  const applied = command("sh", [permissionScript, "--file", tokenFile, "--gid", String(runtimeGid), "--apply", "--confirm", "APPLY-ALERTMANAGER-SECRET-PERMISSIONS"]);
  const permissionReceipt = JSON.parse(applied.stdout.trim());
  if (permissionReceipt.mode !== "640" || permissionReceipt.gid !== runtimeGid || permissionReceipt.contentRead !== false) throw new Error("Permission receipt is incomplete.");

  docker(["network", "create", network]);
  docker(["run", "-d", "--rm", "--name", receiverContainer, "--network", network, "--network-alias", "receiver", "--user", "1000:1000", "-v", `${hostPath("receiver.mjs")}:/app/receiver.mjs:ro`, "-v", `${hostPath("alertmanager_webhook_token.txt")}:/run/secrets/alertmanager_webhook_token:ro`, nodeImage, "node", "/app/receiver.mjs"]);
  waitForExec(receiverContainer, ["node", "-e", "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]);

  const wrongAuth = docker(["exec", receiverContainer, "node", "-e", "fetch('http://127.0.0.1:3000/receipts/missing',{headers:{authorization:'Bearer wrong'}}).then(r=>process.exit(r.status===401?0:1)).catch(()=>process.exit(1))"], { allowFailure: true });
  if (wrongAuth.status !== 0) throw new Error("Receiver did not reject an invalid bearer token.");

  docker(["run", "-d", "--name", deniedContainer, "--network", network, "--user", "65534:65534", "--group-add", String(runtimeGid), "-v", `${hostPath("alertmanager.yml")}:/etc/alertmanager/alertmanager.yml:ro`, "-v", `${hostPath("denied/alertmanager_webhook_token.txt")}:/run/secrets/alertmanager_webhook_token:ro`, "--tmpfs", "/alertmanager:rw,noexec,nosuid,nodev,uid=65534,gid=65534,mode=0700", alertmanagerImage, "--config.file=/etc/alertmanager/alertmanager.yml", "--storage.path=/alertmanager"]);
  waitForExec(deniedContainer, ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:9093/-/ready"]);
  const deniedHealth = docker(["exec", deniedContainer, "sh", "-ec", "test -r /run/secrets/alertmanager_webhook_token && wget -q -O /dev/null http://127.0.0.1:9093/-/ready"], { allowFailure: true });
  if (deniedHealth.status === 0) throw new Error("Functional healthcheck accepted an unreadable 0600 token.");
  docker(["rm", "-f", deniedContainer], { allowFailure: true });

  docker(["run", "-d", "--rm", "--name", alertmanagerContainer, "--network", network, "--network-alias", "alertmanager", "--user", "65534:65534", "--group-add", String(runtimeGid), "-v", `${hostPath("alertmanager.yml")}:/etc/alertmanager/alertmanager.yml:ro`, "-v", `${hostPath("alertmanager_webhook_token.txt")}:/run/secrets/alertmanager_webhook_token:ro`, "--tmpfs", "/alertmanager:rw,noexec,nosuid,nodev,uid=65534,gid=65534,mode=0700", alertmanagerImage, "--config.file=/etc/alertmanager/alertmanager.yml", "--storage.path=/alertmanager"]);
  waitForExec(alertmanagerContainer, ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:9093/-/ready"]);

  const operationalEvidence = command(process.execPath, [
    path.join(replicaRoot, "scripts", "infra-ops.mjs"),
    "alert-evidence",
    "--sendTest",
    "--enforce",
    "--timeoutMs",
    "20000",
    "--dispatcherContainer",
    receiverContainer,
  ], {
    env: {
      ALERT_EVIDENCE_ALERTMANAGER_HOST: "alertmanager",
    },
  });
  if (!operationalEvidence.stdout.includes("Alert evidence written")) throw new Error("Operational alert evidence command did not complete.");
  const alertReportDirectory = path.join(replicaRoot, "reports", "alerts");
  const alertReportName = readdirSync(alertReportDirectory).filter((name) => name.endsWith(".json")).sort().at(-1);
  const alertReport = JSON.parse(readFileSync(path.join(alertReportDirectory, alertReportName), "utf8"));
  if (alertReport.status !== "passed" || alertReport.runtime?.exactReceiverReceipt !== true) {
    throw new Error("Operational alert evidence did not prove the exact Alertmanager delivery path.");
  }
  command(process.execPath, [
    path.join(replicaRoot, "scripts", "infra-ops.mjs"),
    "alert-evidence",
    "--sendTest",
    "--timeoutMs",
    "1000",
    "--alertmanagerHost",
    "missing-alertmanager",
    "--dispatcherContainer",
    receiverContainer,
  ], {
    env: {
    },
  });
  const negativeReportName = readdirSync(alertReportDirectory).filter((name) => name.endsWith(".json")).sort().at(-1);
  const negativeReport = JSON.parse(readFileSync(path.join(alertReportDirectory, negativeReportName), "utf8"));
  if (negativeReport.status !== "warning" || negativeReport.runtime?.errorRedacted !== true || negativeReport.runtime?.exactReceiverReceipt !== false) {
    throw new Error("Failed delivery did not produce a redacted warning report.");
  }

  const probeId = randomUUID();
  const sendScript = `const id=process.env.PROBE_ID; const now=new Date(); const alert={labels:{alertname:'PlatformAlertDeliverySandbox',service:'platform',severity:'info',platform_probe:'alert-delivery',platform_probe_id:id},annotations:{summary:'sandbox delivery probe'},startsAt:now.toISOString(),endsAt:new Date(now.getTime()+60000).toISOString()}; fetch('http://alertmanager:9093/api/v2/alerts',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify([alert])}).then(async r=>{if(!r.ok) throw new Error(await r.text());}).catch(e=>{console.error(e.message);process.exit(1);});`;
  docker(["run", "--rm", "--network", network, "-e", `PROBE_ID=${probeId}`, nodeImage, "node", "-e", sendScript]);
  waitForExec(receiverContainer, ["node", "-e", `const fs=require('node:fs');const token=fs.readFileSync('/run/secrets/alertmanager_webhook_token','utf8').trim();fetch('http://127.0.0.1:3000/receipts/${probeId}',{headers:{authorization:'Bearer '+token}}).then(r=>process.exit(r.status===200?0:1)).catch(()=>process.exit(1))`], 80);

  const liveIdsAfter = {
    alertmanager: docker(["inspect", "--format", "{{.Id}}", "enterprise-alertmanager"], { allowFailure: true }).stdout.trim(),
    receiver: docker(["inspect", "--format", "{{.Id}}", "enterprise-platform-alert-dispatcher"], { allowFailure: true }).stdout.trim(),
  };
  if (JSON.stringify(liveIdsBefore) !== JSON.stringify(liveIdsAfter)) throw new Error("Live alert runtime changed during sandbox testing.");

  process.stdout.write(`${JSON.stringify({
    status: "passed",
    secret0600Rejected: true,
    unconfirmedPermissionChangeRejected: true,
    secret0640RuntimeGroupReadable: true,
    invalidBearerRejected: true,
    exactAlertmanagerReceiptPassed: true,
    operationalAlertEvidencePassed: true,
    failedDeliveryReportRedacted: true,
    liveAlertRuntimeChanged: false,
    operationalSecretContentRead: false,
  })}\n`);
} finally {
  docker(["rm", "-f", alertmanagerContainer, receiverContainer, deniedContainer], { allowFailure: true });
  docker(["network", "rm", network], { allowFailure: true });
  for (const entry of readdirSync(sandboxRoot)) rmSync(path.join(sandboxRoot, entry), { recursive: true, force: true });
  chmodSync(sandboxRoot, 0o700);
}
