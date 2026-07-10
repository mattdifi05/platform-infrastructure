import assert from "node:assert/strict";
import test from "node:test";
import { createAlertDispatcher } from "./server.mjs";

async function listen(dispatcher) {
  await new Promise((resolve) => dispatcher.server.listen(0, "127.0.0.1", resolve));
  const address = dispatcher.server.address();
  return {
    base: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolve, reject) => dispatcher.server.close((error) => error ? reject(error) : resolve())),
  };
}

async function post(base, token, body) {
  const response = await fetch(`${base}/alerts/prometheus`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

test("health fails closed without token or delivery channel", async () => {
  const first = await listen(createAlertDispatcher({ requireDelivery: true }));
  try {
    assert.equal((await fetch(`${first.base}/health`)).status, 503);
  } finally {
    await first.close();
  }
  const second = await listen(createAlertDispatcher({ token: "secret", requireDelivery: true }));
  try {
    assert.equal((await fetch(`${second.base}/health`)).status, 503);
  } finally {
    await second.close();
  }
});

test("webhook rejects missing and incorrect bearer tokens", async () => {
  const running = await listen(createAlertDispatcher({ token: "correct-token" }));
  try {
    const missing = await fetch(`${running.base}/alerts/prometheus`, { method: "POST", body: "{}" });
    assert.equal(missing.status, 401);
    const wrong = await post(running.base, "wrong-token", { alerts: [] });
    assert.equal(wrong.status, 401);
    const metrics = await (await fetch(`${running.base}/metrics`)).text();
    assert.match(metrics, /platform_alert_unauthorized_total 2/);
  } finally {
    await running.close();
  }
});

test("firing alerts deliver through configured channels", async () => {
  const email = [];
  const forwarded = [];
  const dispatcher = createAlertDispatcher({
    token: "correct-token",
    emailTo: "ops@example.test",
    forwardUrl: "https://example.test/alerts",
    requireDelivery: true,
    deliverEmail: async (message) => email.push(message),
    deliverForward: async (_url, payload) => forwarded.push(payload),
  });
  const running = await listen(dispatcher);
  try {
    const result = await post(running.base, "correct-token", {
      receiver: "platform",
      alerts: [{ status: "firing", labels: { alertname: "HostDown", severity: "critical" }, annotations: { summary: "Host unavailable" } }],
    });
    assert.equal(result.status, 202);
    assert.equal(email.length, 1);
    assert.equal(forwarded.length, 1);
    assert.match(email[0].subject, /HostDown/);
    const metrics = await (await fetch(`${running.base}/metrics`)).text();
    assert.match(metrics, /platform_alert_delivery_total\{channel="email",result="success"\} 1/);
    assert.match(metrics, /platform_alert_delivery_total\{channel="forward",result="success"\} 1/);
  } finally {
    await running.close();
  }
});

test("required delivery failure returns a retryable server error", async () => {
  const running = await listen(createAlertDispatcher({
    token: "correct-token",
    emailTo: "ops@example.test",
    requireDelivery: true,
    deliverEmail: async () => { throw new Error("smtp unavailable"); },
  }));
  try {
    const result = await post(running.base, "correct-token", { alerts: [{ status: "firing", labels: { alertname: "HostDown" } }] });
    assert.equal(result.status, 502);
    assert.deepEqual(result.body, { error: "alert_delivery_failed" });
  } finally {
    await running.close();
  }
});

test("resolved-only alerts do not require an email send", async () => {
  let sends = 0;
  const running = await listen(createAlertDispatcher({
    token: "correct-token",
    emailTo: "ops@example.test",
    requireDelivery: true,
    deliverEmail: async () => { sends += 1; },
  }));
  try {
    const result = await post(running.base, "correct-token", { alerts: [{ status: "resolved", labels: { alertname: "HostDown" } }] });
    assert.equal(result.status, 202);
    assert.equal(sends, 0);
  } finally {
    await running.close();
  }
});

test("malformed and oversized bodies are rejected", async () => {
  const running = await listen(createAlertDispatcher({ token: "correct-token" }));
  try {
    const malformed = await fetch(`${running.base}/alerts/prometheus`, {
      method: "POST",
      headers: { authorization: "Bearer correct-token" },
      body: "{",
    });
    assert.equal(malformed.status, 400);
    const oversized = await fetch(`${running.base}/alerts/prometheus`, {
      method: "POST",
      headers: { authorization: "Bearer correct-token", "content-type": "application/json" },
      body: JSON.stringify({ padding: "x".repeat(129 * 1024) }),
    });
    assert.equal(oversized.status, 413);
  } finally {
    await running.close();
  }
});
