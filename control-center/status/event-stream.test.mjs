import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import {
  createStatusEventBroker,
  pumpStatusEventStream,
  StatusEventStreamError,
  writeSseFrame,
} from "./event-stream.mjs";

test("status event broker enforces global, principal, and run quotas before allocation", () => {
  const broker = createStatusEventBroker({
    maxSubscribers: 2,
    maxSubscribersPerPrincipal: 1,
    maxSubscribersPerRun: 1,
  });
  const first = broker.subscribe({ principal: "alice", runId: "run-a" });
  assert.throws(
    () => broker.subscribe({ principal: "alice", runId: "run-b" }),
    (error) => error instanceof StatusEventStreamError && error.code === "STATUS_STREAM_PRINCIPAL_QUOTA" && error.status === 429,
  );
  assert.throws(
    () => broker.subscribe({ principal: "bob", runId: "run-a" }),
    (error) => error instanceof StatusEventStreamError && error.code === "STATUS_STREAM_RUN_QUOTA" && error.status === 429,
  );
  const second = broker.subscribe({ principal: "bob", runId: "run-b" });
  assert.throws(
    () => broker.subscribe({ principal: "carol", runId: "run-c" }),
    (error) => error instanceof StatusEventStreamError && error.code === "STATUS_STREAM_GLOBAL_QUOTA" && error.status === 429,
  );
  assert.deepEqual(broker.stats(), { active: 2, principals: 2, runs: 2, queuedEvents: 0, queuedBytes: 0 });

  first.close("fixture-complete");
  second.close("fixture-complete");
  assert.deepEqual(broker.stats(), { active: 0, principals: 0, runs: 0, queuedEvents: 0, queuedBytes: 0 });
});

test("status event broker delivers without polling and closes overflowing consumers", async () => {
  const broker = createStatusEventBroker({ maxQueueEvents: 1, maxQueueBytes: 1024 });
  const live = broker.subscribe({ principal: "alice", runId: "run-live" });
  const pending = live.next({ timeoutMs: 100 });
  assert.equal(broker.publish(statusEvent("run-live", 1, "check-started")), 1);
  assert.deepEqual(await pending, { type: "event", event: statusEvent("run-live", 1, "check-started") });

  assert.equal(broker.publish(statusEvent("run-live", 2, "check-completed")), 1);
  assert.equal(broker.publish(statusEvent("run-live", 3, "run-completed")), 0);
  assert.equal(live.closed, true);
  assert.equal(live.closeReason, "queue-overflow");
  assert.equal(broker.stats().active, 0);
});

test("SSE writes yield for drain and remove all backpressure listeners", async () => {
  const response = new FixtureResponse({ writable: false });
  let eventLoopTicked = false;
  setImmediate(() => {
    eventLoopTicked = true;
    response.emit("drain");
  });
  await writeSseFrame(response, ": fixture\n\n", { timeoutMs: 100 });
  assert.equal(eventLoopTicked, true);
  assert.equal(response.listenerCount("drain"), 0);
  assert.equal(response.listenerCount("close"), 0);
  assert.equal(response.listenerCount("error"), 0);
});

test("SSE backpressure timeout and abort paths clean listeners and subscriber quota", async () => {
  const timedOut = new FixtureResponse({ writable: false });
  await assert.rejects(
    writeSseFrame(timedOut, ": blocked\n\n", { timeoutMs: 5 }),
    (error) => error instanceof StatusEventStreamError && error.code === "STATUS_STREAM_BACKPRESSURE_TIMEOUT",
  );
  assert.equal(timedOut.listenerCount("drain"), 0);
  assert.equal(timedOut.listenerCount("close"), 0);
  assert.equal(timedOut.listenerCount("error"), 0);

  const broker = createStatusEventBroker();
  const subscription = broker.subscribe({ principal: "alice", runId: "run-abort" });
  const response = new FixtureResponse({ writable: false });
  const controller = new AbortController();
  setImmediate(() => controller.abort());
  await assert.rejects(pumpStatusEventStream({
    response,
    subscription,
    replayEvents: [statusEvent("run-abort", 1, "run-started")],
    heartbeatMs: 10,
    maxDurationMs: 100,
    backpressureTimeoutMs: 100,
    signal: controller.signal,
  }), (error) => error instanceof StatusEventStreamError && error.code === "STATUS_STREAM_ABORTED");
  assert.equal(broker.stats().active, 0);
  assert.equal(response.listenerCount("drain"), 0);
  assert.equal(response.listenerCount("close"), 0);
  assert.equal(response.listenerCount("error"), 0);
});

test("SSE pump replays once, de-duplicates queued overlap, and releases on completion", async () => {
  const broker = createStatusEventBroker();
  const subscription = broker.subscribe({ principal: "alice", runId: "run-replay" });
  broker.publish(statusEvent("run-replay", 2, "check-completed"));
  broker.publish(statusEvent("run-replay", 3, "run-completed"));
  const response = new FixtureResponse({ writable: true });
  const result = await pumpStatusEventStream({
    response,
    subscription,
    replayEvents: [
      statusEvent("run-replay", 1, "run-started"),
      statusEvent("run-replay", 2, "check-completed"),
    ],
    heartbeatMs: 100,
    maxDurationMs: 1000,
    backpressureTimeoutMs: 100,
  });
  assert.deepEqual(result, { reason: "run-completed", lastSequence: 3 });
  assert.deepEqual(response.frames.filter((frame) => frame.startsWith("id:")).map((frame) => Number(frame.match(/^id: (\d+)/)?.[1])), [1, 2, 3]);
  assert.equal(broker.stats().active, 0);
});

test("SSE pump fails closed on a live sequence gap and releases the subscription", async () => {
  const broker = createStatusEventBroker();
  const subscription = broker.subscribe({ principal: "alice", runId: "run-gap" });
  broker.publish(statusEvent("run-gap", 2, "check-started"));
  const response = new FixtureResponse({ writable: true });
  await assert.rejects(pumpStatusEventStream({
    response,
    subscription,
    heartbeatMs: 100,
    maxDurationMs: 1000,
    backpressureTimeoutMs: 100,
  }), (error) => error instanceof StatusEventStreamError && error.code === "STATUS_STREAM_SEQUENCE_GAP");
  assert.equal(broker.stats().active, 0);
  assert.deepEqual(response.frames, []);
});

test("SSE pump heartbeats without polling storage and stops at its deadline", async () => {
  let clock = 0;
  let waits = 0;
  let closed = false;
  const subscription = {
    next: () => new Promise((resolve) => setImmediate(() => {
      waits += 1;
      clock += 5;
      resolve({ type: "timeout" });
    })),
    close: () => { closed = true; },
  };
  const response = new FixtureResponse({ writable: true });
  const result = await pumpStatusEventStream({
    response,
    subscription,
    heartbeatMs: 5,
    maxDurationMs: 12,
    backpressureTimeoutMs: 100,
    now: () => clock,
  });
  assert.deepEqual(result, { reason: "deadline", lastSequence: 0 });
  assert.equal(waits, 3);
  assert.equal(response.frames.every((frame) => frame === ": keepalive\n\n"), true);
  assert.equal(closed, true);
});

function statusEvent(runId, sequence, type) {
  return { schemaVersion: 1, runId, sequence, type, timestamp: "2026-07-21T00:00:00.000Z" };
}

class FixtureResponse extends EventEmitter {
  constructor({ writable }) {
    super();
    this.writable = writable;
    this.destroyed = false;
    this.writableEnded = false;
    this.frames = [];
  }

  write(frame) {
    this.frames.push(frame);
    return this.writable;
  }
}
