import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { pathToFileURL } from "node:url";

const serviceName = "platform-alert-dispatcher";

function json(response, status, payload) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(payload));
}

function log(level, event, fields = {}) {
  process.stdout.write(`${JSON.stringify({ level, event, service: serviceName, ...fields })}\n`);
}

function readSecretFile(environmentName, { required = true } = {}) {
  const file = String(process.env[environmentName] || "").trim();
  if (!file) {
    if (required) throw new Error(`${environmentName} is required`);
    return "";
  }
  const value = fs.readFileSync(file, "utf8").trim();
  if (!value && required) throw new Error(`${environmentName} is empty`);
  return value;
}

function authorized(header, token) {
  if (!header || !token) return false;
  const supplied = Buffer.from(String(header));
  const expected = Buffer.from(`Bearer ${token}`);
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

function readJsonBody(request, limit = 128 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let failed = false;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        failed = true;
        chunks.length = 0;
        reject(new Error("payload_too_large"));
        request.resume();
        return;
      }
      if (!failed) chunks.push(chunk);
    });
    request.on("error", reject);
    request.on("end", () => {
      if (failed) return;
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch {
        reject(new Error("invalid_json"));
      }
    });
  });
}

function alertSummary(alert) {
  return {
    alertname: String(alert?.labels?.alertname || "unknown").slice(0, 160),
    service: String(alert?.labels?.service || "unknown").slice(0, 160),
    severity: String(alert?.labels?.severity || "unknown").slice(0, 40),
    status: String(alert?.status || "unknown").slice(0, 40),
  };
}

function emailMessage(payload, firing, to) {
  const first = firing[0] || {};
  const name = String(first?.labels?.alertname || "Platform alert");
  const severity = String(first?.labels?.severity || "info");
  const lines = [
    `Receiver: ${String(payload.receiver || "unknown")}`,
    `Firing alerts: ${firing.length}`,
    "",
  ];
  for (const [index, alert] of firing.slice(0, 10).entries()) {
    lines.push(
      `#${index + 1} ${String(alert?.labels?.alertname || "Alert")}`,
      `severity=${String(alert?.labels?.severity || "unknown")}`,
      `service=${String(alert?.labels?.service || "unknown")}`,
      `job=${String(alert?.labels?.job || "unknown")}`,
      `summary=${String(alert?.annotations?.summary || "n/a")}`,
      `description=${String(alert?.annotations?.description || "n/a")}`,
      "",
    );
  }
  return { subject: `[${severity}] ${name} (${firing.length} firing)`, text: lines.join("\n"), to };
}

export function createAlertDispatcher(options = {}) {
  const startedAt = options.startedAt || Date.now();
  const token = String(options.token || "");
  const emailTo = String(options.emailTo || "").trim();
  const forwardUrl = String(options.forwardUrl || "").trim();
  const deliverEmail = options.deliverEmail || sendEmail;
  const deliverForward = options.deliverForward || forwardPayload;
  const requireDelivery = options.requireDelivery === true;
  const counters = {
    requests: 0,
    alerts: 0,
    firing: 0,
    resolved: 0,
    unauthorized: 0,
    emailOk: 0,
    emailFailed: 0,
    forwardOk: 0,
    forwardFailed: 0,
  };

  const configuredChannels = Number(Boolean(emailTo)) + Number(Boolean(forwardUrl));
  const ready = Boolean(token) && (!requireDelivery || configuredChannels > 0);

  const server = http.createServer(async (request, response) => {
    const pathname = new URL(request.url || "/", "http://localhost").pathname;
    if (pathname === "/health" && request.method === "GET") {
      json(response, ready ? 200 : 503, {
        status: ready ? "ok" : "not-ready",
        service: serviceName,
        deliveryChannels: configuredChannels,
        uptimeSeconds: Math.max(0, Math.floor((Date.now() - startedAt) / 1000)),
      });
      return;
    }
    if (pathname === "/metrics" && request.method === "GET") {
      response.writeHead(200, { "content-type": "text/plain; version=0.0.4; charset=utf-8" });
      response.end([
        "# HELP platform_alert_webhook_requests_total Authenticated Alertmanager webhook requests.",
        "# TYPE platform_alert_webhook_requests_total counter",
        `platform_alert_webhook_requests_total ${counters.requests}`,
        "# HELP platform_alert_webhook_alerts_total Alerts received by status.",
        "# TYPE platform_alert_webhook_alerts_total counter",
        `platform_alert_webhook_alerts_total{status=\"firing\"} ${counters.firing}`,
        `platform_alert_webhook_alerts_total{status=\"resolved\"} ${counters.resolved}`,
        `platform_alert_webhook_alerts_total{status=\"total\"} ${counters.alerts}`,
        "# HELP platform_alert_delivery_total Delivery attempts by channel and result.",
        "# TYPE platform_alert_delivery_total counter",
        `platform_alert_delivery_total{channel=\"email\",result=\"success\"} ${counters.emailOk}`,
        `platform_alert_delivery_total{channel=\"email\",result=\"failed\"} ${counters.emailFailed}`,
        `platform_alert_delivery_total{channel=\"forward\",result=\"success\"} ${counters.forwardOk}`,
        `platform_alert_delivery_total{channel=\"forward\",result=\"failed\"} ${counters.forwardFailed}`,
        "# HELP platform_alert_unauthorized_total Rejected webhook authorization attempts.",
        "# TYPE platform_alert_unauthorized_total counter",
        `platform_alert_unauthorized_total ${counters.unauthorized}`,
        "",
      ].join("\n"));
      return;
    }
    if (pathname !== "/alerts/prometheus" || request.method !== "POST") {
      json(response, 404, { error: "not_found" });
      return;
    }
    if (!authorized(request.headers.authorization, token)) {
      counters.unauthorized += 1;
      json(response, 401, { error: "alert_webhook_unauthorized" });
      return;
    }

    try {
      const payload = await readJsonBody(request);
      const alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
      const firing = alerts.filter((alert) => alert?.status === "firing");
      const resolved = alerts.filter((alert) => alert?.status === "resolved");
      counters.requests += 1;
      counters.alerts += alerts.length;
      counters.firing += firing.length;
      counters.resolved += resolved.length;
      log("info", "alerts_received", {
        firing: firing.length,
        resolved: resolved.length,
        alerts: alerts.slice(0, 8).map(alertSummary),
      });

      const deliveries = [];
      if (emailTo && firing.length > 0) {
        deliveries.push(deliverEmail(emailMessage(payload, firing, emailTo)).then(
          () => { counters.emailOk += 1; return true; },
          (error) => { counters.emailFailed += 1; log("warn", "email_delivery_failed", { message: String(error?.message || error) }); return false; },
        ));
      }
      if (forwardUrl) {
        deliveries.push(deliverForward(forwardUrl, payload).then(
          () => { counters.forwardOk += 1; return true; },
          (error) => { counters.forwardFailed += 1; log("warn", "forward_delivery_failed", { message: String(error?.message || error) }); return false; },
        ));
      }
      const results = await Promise.all(deliveries);
      if (requireDelivery && firing.length > 0 && (results.length === 0 || !results.some(Boolean))) {
        json(response, 502, { error: "alert_delivery_failed" });
        return;
      }
      json(response, 202, { status: "accepted", alerts: alerts.length });
    } catch (error) {
      const message = String(error?.message || "invalid_payload");
      json(response, message === "payload_too_large" ? 413 : 400, { error: message });
    }
  });

  return { server, ready };
}

function env(name, required = true) {
  const value = String(process.env[name] || "").trim();
  if (!value && required) throw new Error(`${name} is required`);
  return value;
}

async function sendEmail(message) {
  const mail = {
    host: env("SMTP_HOST"),
    port: Number(process.env.SMTP_PORT || 465),
    secure: String(process.env.SMTP_SECURE || "true").toLowerCase() !== "false",
    user: env("SMTP_USER"),
    password: readSecretFile("SMTP_PASSWORD_FILE"),
    from: env("MAILER_FROM"),
    replyTo: env("MAILER_REPLY_TO", false) || env("MAILER_FROM"),
    ...message,
  };
  if (!Number.isInteger(mail.port) || mail.port < 1 || mail.port > 65535) throw new Error("SMTP_PORT is invalid");
  await sendSmtp(mail);
}

function address(value) {
  const match = String(value).trim().match(/<([^>]+)>/);
  const result = String(match?.[1] || value).trim();
  if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(result)) throw new Error("email address is invalid");
  return result;
}

function readSmtp(socket, codes) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const cleanup = () => { socket.off("data", onData); socket.off("error", onError); };
    const onError = (error) => { cleanup(); reject(error); };
    const onData = (chunk) => {
      buffer += chunk.toString("utf8");
      const last = buffer.split(/\r?\n/).filter(Boolean).at(-1);
      if (!last || !/^\d{3}\s/.test(last)) return;
      cleanup();
      const code = Number(last.slice(0, 3));
      if (!codes.includes(code)) reject(new Error(`SMTP command failed with ${code}`));
      else resolve(buffer);
    };
    socket.on("data", onData);
    socket.once("error", onError);
  });
}

async function sendSmtp(mail) {
  const options = { host: mail.host, port: mail.port, servername: mail.host, timeout: 15000 };
  const socket = await new Promise((resolve, reject) => {
    const connection = mail.secure ? tls.connect(options, () => resolve(connection)) : net.connect(options, () => resolve(connection));
    connection.once("error", reject);
    connection.once("timeout", () => connection.destroy(new Error("SMTP connection timed out")));
  });
  const command = async (value, codes) => { socket.write(`${value}\r\n`); await readSmtp(socket, codes); };
  try {
    await readSmtp(socket, [220]);
    await command(`EHLO ${process.env.SMTP_CLIENT_NAME || "platform.local"}`, [250]);
    await command("AUTH LOGIN", [334]);
    await command(Buffer.from(mail.user).toString("base64"), [334]);
    await command(Buffer.from(mail.password).toString("base64"), [235]);
    await command(`MAIL FROM:<${address(mail.from)}>`, [250]);
    for (const recipient of String(mail.to).split(",").map(address)) await command(`RCPT TO:<${recipient}>`, [250, 251]);
    await command("DATA", [354]);
    const text = String(mail.text).replace(/\r?\n/g, "\r\n").split("\r\n").map((line) => line.startsWith(".") ? `.${line}` : line).join("\r\n");
    socket.write([
      `From: ${mail.from}`,
      `To: ${mail.to}`,
      `Reply-To: ${mail.replyTo}`,
      `Subject: ${String(mail.subject).replace(/[\r\n]+/g, " ")}`,
      `Date: ${new Date().toUTCString()}`,
      `Message-ID: <${crypto.randomUUID()}@platform.local>`,
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=utf-8",
      "",
      text,
      ".",
      "",
    ].join("\r\n"));
    await readSmtp(socket, [250]);
    await command("QUIT", [221]);
  } finally {
    socket.end();
  }
}

function forwardPayload(target, payload) {
  return new Promise((resolve, reject) => {
    const url = new URL(target);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error("forward URL protocol is invalid");
    const body = Buffer.from(JSON.stringify(payload));
    const request = (url.protocol === "https:" ? https : http).request(url, {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": body.length },
      timeout: 5000,
    }, (response) => {
      response.resume();
      response.on("end", () => response.statusCode >= 200 && response.statusCode < 300 ? resolve() : reject(new Error(`forward returned HTTP ${response.statusCode}`)));
    });
    request.on("error", reject);
    request.on("timeout", () => request.destroy(new Error("forward timeout")));
    request.end(body);
  });
}

export async function startAlertDispatcher() {
  const token = readSecretFile("ALERTMANAGER_WEBHOOK_TOKEN_FILE");
  const forwardUrl = readSecretFile("ALERT_FORWARD_WEBHOOK_URL_FILE", { required: false });
  const emailTo = String(process.env.ALERT_EMAIL_TO || "").trim();
  if (emailTo) {
    env("SMTP_HOST");
    env("SMTP_USER");
    env("MAILER_FROM");
    readSecretFile("SMTP_PASSWORD_FILE");
    const smtpPort = Number(process.env.SMTP_PORT || 465);
    if (!Number.isInteger(smtpPort) || smtpPort < 1 || smtpPort > 65535) throw new Error("SMTP_PORT is invalid");
  }
  const dispatcher = createAlertDispatcher({ token, forwardUrl, emailTo, requireDelivery: true });
  if (!dispatcher.ready) throw new Error("At least one alert delivery channel is required");
  const port = Number(process.env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("PORT is invalid");
  await new Promise((resolve) => dispatcher.server.listen(port, "0.0.0.0", resolve));
  log("info", "dispatcher_started", { port, channels: Number(Boolean(emailTo)) + Number(Boolean(forwardUrl)) });
  return dispatcher;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startAlertDispatcher().catch((error) => {
    log("error", "dispatcher_start_failed", { message: String(error?.message || error) });
    process.exitCode = 1;
  });
}
