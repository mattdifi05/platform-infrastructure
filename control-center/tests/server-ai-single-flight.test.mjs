import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { createMemoryConversationStore } from '../ai/conversations.mjs';
import { createConversationHttp } from '../ai/conversation-http.mjs';
import { createAIService } from '../ai/service.mjs';

const machineId = 'a'.repeat(64), ownerId = 'fixture-owner';
const settle = () => new Promise(resolve => setImmediate(resolve));
async function until(predicate) {
  for (let attempt = 0; attempt < 50; attempt += 1) { if (await predicate()) return; await settle(); }
  assert.fail('background operation did not settle');
}
async function fixture() {
  const store = createMemoryConversationStore({ nodeEnvironment: 'test' });
  const conversation = await store.create({ ownerId, machineId });
  const scope = { ownerId, machineId, conversationId: conversation.id };
  const calls = [], controllers = new Map();
  const manager = {
    list: () => [{ id: machineId }], status: async () => ({ state: 'active' }),
    registerChat: async (_machine, key, controller) => { controllers.set(key, controller); return true; },
    unregisterChat: async (_machine, key, controller) => { if (controllers.get(key) === controller) controllers.delete(key); },
    cancelChat: async (_machine, key) => { const controller = controllers.get(key); controller?.abort(); return Boolean(controller); },
    chat: async (_machine, req, res, options) => {
      const call = { options }; calls.push(call);
      await options.onLifecycle('started', { analysisSummary: 'Sintesi pubblica delle evidenze.' });
      await new Promise(resolve => { call.finish = resolve; });
      await options.onLifecycle('completed', { content: 'Risposta verificata.', analysisSummary: 'Sintesi pubblica delle evidenze.' });
    },
  };
  const makeHandler = () => createConversationHttp({ store, manager, readPayload: async req => req.payload,
    json: (res, body, status = 200) => ({ status, body }) });
  const handle = makeHandler();
  const request = (operation, payload = {}, handler = handle) => handler({ payload }, { setHeader() {} }, new URL('http://fixture.invalid'),
    { operationId: `ai.conversations.${operation}`, method: operation === 'read' ? 'GET' : 'POST', parameters: { machineId, conversationId: conversation.id } }, { subject: ownerId, role: 'owner' });
  const send = (payload, handler) => request('send', { message: 'Controlla il server.', requestedMode: 'auto', requestId: randomUUID(), ...payload }, handler);
  const complete = async index => { await until(() => Boolean(calls[index]?.finish)); calls[index].finish(); await until(async () => !(await store.get(scope)).messages.some(m => ['pending','streaming'].includes(m.generationStatus))); };
  return { store, scope, calls, manager, request, send, complete, makeHandler };
}

test('competing tabs admit one direct turn, return busy 409, and accept the next send after completion', async () => {
  const f = await fixture();
  const results = await Promise.all([f.send({}), f.send({}, f.makeHandler())]);
  assert.deepEqual(results.map(r => r.status).sort(), [202,409]);
  assert.equal(results.find(r => r.status === 409).body.error, 'GENERATION_ACTIVE');
  assert.equal(results.find(r => r.status === 409).body.generationStatus, 'active');
  await until(() => f.calls.length === 1);
  assert.equal((await f.store.get(f.scope)).messages.length, 2);
  assert.deepEqual(await f.store.listQueue(f.scope), []);
  await f.complete(0);
  assert.equal((await f.send({})).status, 202);
  await f.complete(1);
});

test('durable request ID deduplicates pending and terminal retries, rejects changed data, and stays private', async () => {
  const f = await fixture(), requestId = randomUUID();
  const first = await f.send({ requestId });
  const retry = await f.send({ requestId }, f.makeHandler());
  assert.equal(retry.body.assistantId, first.body.assistantId);
  assert.equal(retry.body.idempotent, true);
  await assert.rejects(f.send({ requestId, message: 'Riavvia il server.' }), error => error.code === 'REQUEST_ID_CONFLICT' && error.status === 409);
  await f.complete(0);
  const terminal = await f.send({ requestId }, f.makeHandler());
  assert.equal(terminal.body.assistantId, first.body.assistantId);
  assert.equal(terminal.body.generationStatus, 'completed');
  assert.equal(f.calls.length, 1);
  const detail = await f.request('read');
  assert.equal(detail.body.messages.length, 2);
  assert.equal(detail.body.messages[1].toolMetadata.clientRequest, undefined);
  assert.equal((await f.store.get(f.scope)).messages[1].toolMetadata.clientRequest.id, requestId);
});

test('Stop covers pre-registration attachment work and is idempotent without launching a model turn', async () => {
  const f = await fixture(); let release, entered = false;
  f.store.getAttachmentContext = async () => { entered = true; return new Promise(resolve => { release = () => resolve([]); }); };
  const sending = f.send({});
  await until(() => entered);
  assert.equal((await f.request('cancel')).body.status, 'stopping');
  release(); await sending;
  await until(async () => (await f.store.get(f.scope)).messages[1]?.generationStatus === 'aborted');
  assert.equal(f.calls.length, 0);
  assert.equal((await f.request('cancel')).body.status, 'stopped');
  assert.equal((await f.request('cancel')).status, 200);
});

test('legacy queue rows and replay IDs survive retirement but reads never execute them', async () => {
  const f = await fixture(), requestId = randomUUID();
  await f.store.enqueueQueue({ ...f.scope, requestId, message: 'Vecchia richiesta conservata.', requestedMode: 'auto', attachmentIds: [], delivery: 'queue' });
  await f.store.recoverQueuedOnStartup({ machineIds: [machineId] });
  const detail = await f.request('read'); await settle();
  assert.equal(detail.body.queue[0].message, 'Vecchia richiesta conservata.');
  assert.equal(detail.body.queue[0].status, 'failed');
  assert.equal(detail.body.queue[0].errorCode, 'CHAT_QUEUE_RETIRED');
  assert.equal(f.calls.length, 0);
  await assert.rejects(f.send({ requestId }), error => error.code === 'CHAT_QUEUE_RETIRED');
  for (const delivery of ['queue','immediate']) await assert.rejects(f.send({ delivery }), error => error.code === 'CHAT_QUEUE_DISABLED');
  for (const requestedMode of ['fast','deep']) await assert.rejects(f.send({ requestedMode }), error => error.status === 400);
});

test('AUTO routes fast/deep internally and only deep persists public analysis summaries', async () => {
  for (const [message, mode] of [['Controlla il server.', 'fast'], ['Analizza la causa radice del problema.', 'deep']]) {
    const f = await fixture();
    const accepted = await f.send({ message });
    assert.equal(accepted.body.requestedMode, 'auto'); assert.equal(accepted.body.resolvedMode, mode);
    await f.complete(0);
    const assistant = (await f.store.get(f.scope)).messages[1];
    assert.equal(assistant.resolvedMode, mode); assert.equal(assistant.toolMetadata.resolvedMode, mode);
    assert.equal(assistant.toolMetadata.requestedMode, 'auto');
    assert.equal(Boolean(assistant.toolMetadata.analysisSummary), mode === 'deep');
  }
});

function transport() {
  const req = new EventEmitter(), res = new EventEmitter(), events = [];
  res.setHeader = () => {}; res.write = chunk => { events.push(String(chunk)); return true; };
  res.end = () => { res.writableEnded = true; };
  return { req, res, events };
}
function mockedService() {
  const executed = [], service = createAIService({ registry: {
    definitions: () => [{ type: 'function', function: { name: 'changeInfrastructure', description: 'fixture', parameters: { type: 'object', properties: {}, additionalProperties: false } } }],
    execute: async name => { executed.push(name); return {}; },
  } });
  service.accepting = true; service.ensureProviderReady = async () => {};
  service.createPublicAnalysisSummary = async () => 'Sintesi pubblica delle evidenze.';
  return { service, executed };
}
const serviceOptions = (mode, key, lifecycle) => ({ subject: ownerId, role: 'owner', detached: true, generationKey: key, onLifecycle: lifecycle,
  trustedRequest: { requestedMode: 'auto', resolvedMode: mode, projectScope: 'machine', messages: [{ role: 'user', content: 'Riavvia il servizio autorizzato.' }] } });

test('Stop immediately before a tool execution prevents the mutator, including after progress awaits', async () => {
  const { service, executed } = mockedService(), key = 'fixture-generation-key', t = transport();
  service.streamOpenAIResponseRound = async () => ({ content: '', metrics: {}, outputItems: [], toolCalls: [{ id: 'call', function: { name: 'changeInfrastructure', arguments: {} } }] });
  const lifecycle = [];
  await service.handleChat(t.req, t.res, serviceOptions('fast', key, async (type, payload) => {
    lifecycle.push(type);
    if (type === 'progress' && payload.state === 'tools') service.abortGeneration(key);
  }));
  assert.deepEqual(executed, []); assert.equal(lifecycle.at(-1), 'aborted');
});

test('FAST emits no reasoning summary or summary request; DEEP emits tagged public summaries', async () => {
  for (const mode of ['fast','deep']) {
    const { service } = mockedService(), t = transport(); let summaryCalls = 0;
    service.createPublicAnalysisSummary = async () => { summaryCalls += 1; return 'Sintesi pubblica delle evidenze.'; };
    service.streamOpenAIResponseRound = async options => {
      await options.onThinking(); await options.onAnalysisSummary('Sintesi pubblica delle evidenze.');
      await options.onContent('Risposta.'); return { content: 'Risposta.', toolCalls: [], outputItems: [], metrics: {} };
    };
    await service.handleChat(t.req, t.res, serviceOptions(mode, 'summary-fixture-key'));
    const stream = t.events.join('');
    assert.equal(stream.includes('event: analysis_summary'), mode === 'deep');
    assert.equal(stream.includes('"state":"thinking"'), mode === 'deep');
    assert.equal(summaryCalls > 0, mode === 'deep');
    assert.match(stream, new RegExp('"resolvedMode":"' + mode + '"'));
  }
});
