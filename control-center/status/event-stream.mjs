import { EventEmitter } from "node:events";

export class StatusEventStreamError extends Error {
  constructor(message, code = "STATUS_STREAM_ERROR", status = 503) {
    super(message);
    this.name = "StatusEventStreamError";
    this.code = code;
    this.status = status;
  }
}

export function createStatusEventBroker(options = {}) {
  return new StatusEventBroker(options);
}

export class StatusEventBroker {
  constructor({
    maxSubscribers = 64,
    maxSubscribersPerPrincipal = 4,
    maxSubscribersPerRun = 16,
    maxQueueEvents = 128,
    maxQueueBytes = 1024 * 1024,
  } = {}) {
    this.maxSubscribers = boundedInteger(maxSubscribers, 1, 4096, "global subscriber quota");
    this.maxSubscribersPerPrincipal = boundedInteger(maxSubscribersPerPrincipal, 1, this.maxSubscribers, "principal subscriber quota");
    this.maxSubscribersPerRun = boundedInteger(maxSubscribersPerRun, 1, this.maxSubscribers, "run subscriber quota");
    this.maxQueueEvents = boundedInteger(maxQueueEvents, 1, 10_000, "subscriber queue event limit");
    this.maxQueueBytes = boundedInteger(maxQueueBytes, 1024, 64 * 1024 * 1024, "subscriber queue byte limit");
    this.subscribers = new Set();
    this.byPrincipal = new Map();
    this.byRun = new Map();
    this.closed = false;
  }

  subscribe({ principal, runId, afterSequence = 0 }) {
    if (this.closed) throw new StatusEventStreamError("Status event broker is closed.", "STATUS_STREAM_CLOSED", 503);
    const principalKey = requiredKey(principal, "principal");
    const runKey = requiredKey(runId, "run ID");
    const cursor = boundedInteger(afterSequence, 0, Number.MAX_SAFE_INTEGER, "event cursor");
    if (this.subscribers.size >= this.maxSubscribers) {
      throw new StatusEventStreamError("Status stream global capacity is exhausted.", "STATUS_STREAM_GLOBAL_QUOTA", 429);
    }
    if ((this.byPrincipal.get(principalKey)?.size || 0) >= this.maxSubscribersPerPrincipal) {
      throw new StatusEventStreamError("Status stream principal capacity is exhausted.", "STATUS_STREAM_PRINCIPAL_QUOTA", 429);
    }
    if ((this.byRun.get(runKey)?.size || 0) >= this.maxSubscribersPerRun) {
      throw new StatusEventStreamError("Status stream run capacity is exhausted.", "STATUS_STREAM_RUN_QUOTA", 429);
    }

    const subscription = new StatusEventSubscription(this, {
      principal: principalKey,
      runId: runKey,
      afterSequence: cursor,
      maxQueueEvents: this.maxQueueEvents,
      maxQueueBytes: this.maxQueueBytes,
    });
    this.subscribers.add(subscription);
    addToIndex(this.byPrincipal, principalKey, subscription);
    addToIndex(this.byRun, runKey, subscription);
    return subscription;
  }

  publish(event) {
    if (this.closed) return 0;
    const runId = requiredKey(event?.runId, "run ID");
    const sequence = boundedInteger(event?.sequence, 1, Number.MAX_SAFE_INTEGER, "event sequence");
    const safeEvent = Object.freeze(structuredClone({ ...event, runId, sequence }));
    const byteLength = Buffer.byteLength(JSON.stringify(safeEvent));
    let delivered = 0;
    for (const subscription of [...(this.byRun.get(runId) || [])]) {
      if (subscription.push(safeEvent, byteLength)) delivered += 1;
    }
    return delivered;
  }

  release(subscription) {
    if (!this.subscribers.delete(subscription)) return;
    removeFromIndex(this.byPrincipal, subscription.principal, subscription);
    removeFromIndex(this.byRun, subscription.runId, subscription);
  }

  stats() {
    return {
      active: this.subscribers.size,
      principals: this.byPrincipal.size,
      runs: this.byRun.size,
      queuedEvents: [...this.subscribers].reduce((sum, item) => sum + item.queue.length, 0),
      queuedBytes: [...this.subscribers].reduce((sum, item) => sum + item.queuedBytes, 0),
    };
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    for (const subscription of [...this.subscribers]) subscription.close("broker-closed");
  }
}

export class StatusEventSubscription extends EventEmitter {
  constructor(broker, { principal, runId, afterSequence, maxQueueEvents, maxQueueBytes }) {
    super();
    this.broker = broker;
    this.principal = principal;
    this.runId = runId;
    this.highWatermark = afterSequence;
    this.maxQueueEvents = maxQueueEvents;
    this.maxQueueBytes = maxQueueBytes;
    this.queue = [];
    this.queuedBytes = 0;
    this.waiter = null;
    this.closed = false;
    this.closeReason = "";
    this.closeError = null;
  }

  push(event, byteLength) {
    if (this.closed || event.sequence <= this.highWatermark) return false;
    this.highWatermark = event.sequence;
    if (this.waiter) {
      const waiter = this.takeWaiter();
      waiter.resolve({ type: "event", event });
      return true;
    }
    if (this.queue.length >= this.maxQueueEvents || this.queuedBytes + byteLength > this.maxQueueBytes) {
      this.close(
        "queue-overflow",
        new StatusEventStreamError("Status stream consumer queue overflowed.", "STATUS_STREAM_QUEUE_OVERFLOW", 503),
      );
      return false;
    }
    this.queue.push({ event, byteLength });
    this.queuedBytes += byteLength;
    return true;
  }

  next({ timeoutMs = 15_000 } = {}) {
    const wait = boundedInteger(timeoutMs, 1, 300_000, "subscription wait timeout");
    if (this.queue.length) {
      const item = this.queue.shift();
      this.queuedBytes -= item.byteLength;
      return Promise.resolve({ type: "event", event: item.event });
    }
    if (this.closed) return Promise.resolve({ type: "closed", reason: this.closeReason, error: this.closeError });
    if (this.waiter) {
      return Promise.reject(new StatusEventStreamError("Concurrent subscription waits are not allowed.", "STATUS_STREAM_CONCURRENT_WAIT", 500));
    }
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        if (!this.waiter) return;
        this.waiter = null;
        resolve({ type: "timeout" });
      }, wait);
      timer.unref?.();
      this.waiter = { resolve, timer };
    });
  }

  close(reason = "closed", error = null) {
    if (this.closed) return;
    this.closed = true;
    this.closeReason = reason;
    this.closeError = error;
    this.queue = [];
    this.queuedBytes = 0;
    if (this.waiter) {
      const waiter = this.takeWaiter();
      waiter.resolve({ type: "closed", reason, error });
    }
    this.broker.release(this);
    this.emit("close", { reason, error });
    this.removeAllListeners();
  }

  takeWaiter() {
    const waiter = this.waiter;
    this.waiter = null;
    clearTimeout(waiter.timer);
    return waiter;
  }
}

export async function pumpStatusEventStream({
  response,
  subscription,
  replayEvents = [],
  afterSequence = 0,
  heartbeatMs = 15_000,
  maxDurationMs = 6 * 60 * 1000,
  backpressureTimeoutMs = 5000,
  signal,
  now = () => Date.now(),
}) {
  const heartbeat = boundedInteger(heartbeatMs, 1, 300_000, "stream heartbeat");
  const duration = boundedInteger(maxDurationMs, 1, 24 * 60 * 60 * 1000, "stream duration");
  let cursor = boundedInteger(afterSequence, 0, Number.MAX_SAFE_INTEGER, "event cursor");
  const deadline = now() + duration;
  try {
    for (const event of replayEvents) {
      const sequence = boundedInteger(event?.sequence, 1, Number.MAX_SAFE_INTEGER, "event sequence");
      if (sequence <= cursor) continue;
      if (sequence !== cursor + 1) throw sequenceGap(cursor, sequence);
      await writeSseFrame(response, statusEventFrame(event), { timeoutMs: backpressureTimeoutMs, signal });
      cursor = sequence;
      if (event.type === "run-completed") return { reason: "run-completed", lastSequence: cursor };
    }

    while (!signal?.aborted && now() < deadline) {
      const waitMs = Math.max(1, Math.min(heartbeat, deadline - now()));
      const item = await subscription.next({ timeoutMs: waitMs });
      if (item.type === "closed") {
        if (item.error) throw item.error;
        return { reason: item.reason || "closed", lastSequence: cursor };
      }
      if (item.type === "timeout") {
        await writeSseFrame(response, ": keepalive\n\n", { timeoutMs: backpressureTimeoutMs, signal });
        continue;
      }
      const sequence = boundedInteger(item.event?.sequence, 1, Number.MAX_SAFE_INTEGER, "event sequence");
      if (sequence <= cursor) continue;
      if (sequence !== cursor + 1) throw sequenceGap(cursor, sequence);
      await writeSseFrame(response, statusEventFrame(item.event), { timeoutMs: backpressureTimeoutMs, signal });
      cursor = sequence;
      if (item.event.type === "run-completed") return { reason: "run-completed", lastSequence: cursor };
    }
    return { reason: signal?.aborted ? "aborted" : "deadline", lastSequence: cursor };
  } finally {
    subscription.close(signal?.aborted ? "aborted" : "stream-finished");
  }
}

export function statusEventFrame(event) {
  const sequence = boundedInteger(event?.sequence, 1, Number.MAX_SAFE_INTEGER, "event sequence");
  return `id: ${sequence}\nevent: status\ndata: ${JSON.stringify(event)}\n\n`;
}

export function writeSseFrame(response, frame, { timeoutMs = 5000, signal } = {}) {
  const timeout = boundedInteger(timeoutMs, 1, 60_000, "backpressure timeout");
  if (signal?.aborted || response.destroyed || response.writableEnded) {
    return Promise.reject(new StatusEventStreamError("Status stream connection is closed.", "STATUS_STREAM_CONNECTION_CLOSED", 499));
  }
  if (response.write(frame)) return Promise.resolve();

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      response.removeListener("drain", onDrain);
      response.removeListener("close", onClose);
      response.removeListener("error", onError);
      signal?.removeEventListener("abort", onAbort);
      if (error) reject(error);
      else resolve();
    };
    const onDrain = () => finish();
    const onClose = () => finish(new StatusEventStreamError("Status stream connection closed during backpressure.", "STATUS_STREAM_CONNECTION_CLOSED", 499));
    const onError = () => finish(new StatusEventStreamError("Status stream response failed during backpressure.", "STATUS_STREAM_WRITE_ERROR", 503));
    const onAbort = () => finish(new StatusEventStreamError("Status stream request was aborted.", "STATUS_STREAM_ABORTED", 499));
    const timer = setTimeout(() => finish(new StatusEventStreamError("Status stream backpressure timed out.", "STATUS_STREAM_BACKPRESSURE_TIMEOUT", 503)), timeout);
    timer.unref?.();
    response.once("drain", onDrain);
    response.once("close", onClose);
    response.once("error", onError);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function addToIndex(index, key, value) {
  const values = index.get(key) || new Set();
  values.add(value);
  index.set(key, values);
}

function removeFromIndex(index, key, value) {
  const values = index.get(key);
  if (!values) return;
  values.delete(value);
  if (values.size === 0) index.delete(key);
}

function requiredKey(value, label) {
  const key = String(value || "").trim();
  if (!key || key.length > 256) throw new StatusEventStreamError(`Invalid status stream ${label}.`, "STATUS_STREAM_INVALID_KEY", 422);
  return key;
}

function sequenceGap(cursor, sequence) {
  return new StatusEventStreamError(
    `Status stream sequence gap after ${cursor}; received ${sequence}.`,
    "STATUS_STREAM_SEQUENCE_GAP",
    409,
  );
}

function boundedInteger(value, minimum, maximum, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new StatusEventStreamError(`Invalid ${label}.`, "STATUS_STREAM_INVALID_LIMIT", 500);
  }
  return parsed;
}
