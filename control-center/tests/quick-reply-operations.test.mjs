import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createAIService } from "../ai/service.mjs";

const definition = name => ({ type: "function", function: { name, description: name,
  parameters: { type: "object", properties: {}, additionalProperties: false } } });

async function run(message, { attemptedTool = null } = {}) {
  const calls = [], rounds = [], events = [];
  const service = createAIService({ registry: {
    definitions: () => ["readInfrastructure", "changeInfrastructure", "removePortalApplication", "getInfrastructureOperation", "createChatFile", "createChatZip", "analyzeChatAttachment"].map(definition),
    execute: async name => { calls.push(name); return { status: "completed" }; },
  } });
  service.accepting = true;
  service.ensureProviderReady = async () => {};
  service.createPublicAnalysisSummary = async () => null;
  service.streamOpenAIResponseRound = async options => {
    rounds.push(options);
    if (attemptedTool && rounds.length === 1) return { content: "", metrics: {}, outputItems: [],
      toolCalls: [{ id: "fixture-call", function: { name: attemptedTool, arguments: {} } }] };
    const content = "Il job TLS risulta completato con esito positivo, come verificato nella risposta precedente.";
    await options.onContent(content);
    return { content, toolCalls: [], outputItems: [], metrics: {} };
  };
  const req = new EventEmitter(), res = new EventEmitter();
  res.setHeader = () => {};
  res.write = () => true;
  res.end = () => { res.writableEnded = true; };
  await service.handleChat(req, res, { subject: "fixture-owner", role: "owner", detached: true,
    onLifecycle: async (type, payload) => events.push({ type, payload }),
    trustedRequest: { requestedMode: "fast", resolvedMode: "fast", projectScope: "machine",
      continuationGuidance: "Mantieni l’esito già verificato e continua l’ultima risposta.",
      messages: [
        { role: "user", content: "Aggiorna le metriche TLS interne del server." },
        { role: "assistant", content: "Il job TLS è completato. Result=success, ExecMainStatus=0." },
        { role: "user", content: message },
      ] },
  });
  return { calls, rounds, events };
}

test("summary preserves completed operation context and offers no tool even without attachments", async () => {
  const result = await run("Riassumi");
  assert.equal(result.rounds.length, 1);
  assert.deepEqual(result.rounds[0].tools, []);
  const input = JSON.stringify(result.rounds[0].input);
  assert.match(input, /Result=success, ExecMainStatus=0/);
  assert.match(input, /Mantieni l’esito già verificato/);
  assert.match(input, /Il comando precedente è storico/);
  assert.deepEqual(result.calls, []);
  assert.equal(result.events.at(-1).type, "completed");
});

test("expansion keeps read tools and removes mutation capability", async () => {
  const result = await run("Approfondisci.");
  assert.deepEqual(result.rounds[0].tools.map(t => t.function.name), ["readInfrastructure", "getInfrastructureOperation"]);
  assert.match(JSON.stringify(result.rounds[0].input), /prove in sola lettura/);
  assert.equal(result.events.at(-1).type, "completed");
});

test("a new explicit operation still receives the mutation tool", async () => {
  const result = await run("Aggiorna le metriche TLS interne del server.");
  assert.ok(result.rounds[0].tools.some(t => t.function.name === "changeInfrastructure"));
  assert.equal(result.events.at(-1).type, "completed");
});

test("a provider mutation call during a summary is rejected before registry execution", async () => {
  const result = await run("Riassumi", { attemptedTool: "changeInfrastructure" });
  assert.deepEqual(result.calls, []);
  assert.equal(result.events.at(-1).type, "failed");
  assert.equal(result.events.at(-1).payload.code, "TOOL_NOT_ALLOWED");
});

test("an expansion cannot remove an application from the portal", async () => {
  const result = await run("Approfondisci", { attemptedTool: "removePortalApplication" });
  assert.deepEqual(result.calls, []);
  assert.equal(result.events.at(-1).type, "failed");
  assert.equal(result.events.at(-1).payload.code, "TOOL_NOT_ALLOWED");
});

test("all curated fresh checks execute reads and discard stale continuation guidance", async () => {
  const requests = [
    "Controlla lo stato attuale del VPS e segnala solo problemi sostenuti da dati recenti.",
    "Controlla servizi e container infrastrutturali effettivamente presenti.",
    "Controlla gli esiti dei backup e le pianificazioni server-side visibili dagli strumenti.",
    "Controlla nuovamente lo stato attuale del VPS.",
    "Leggi i log recenti del servizio coinvolto e verifica la diagnosi.",
    "Verifica l’esito dell’operazione precedente senza ripeterla.",
    "Controlla l’ultimo esito del backup e distingui dati verificati e dati mancanti.",
    "Verifica la pianificazione dei backup sul server e la prossima esecuzione.",
    "Ricontrolla disponibilità e salute dei servizi e container coinvolti.",
    "Verifica lo stato attuale di rete, DNS e TLS del server.",
    "Verifica le risorse attuali del server e gli eventuali colli di bottiglia.",
    "Leggi l’audit recente relativo all’operazione precedente.",
  ];
  for (const message of requests) {
    const result = await run(message, { attemptedTool: "readInfrastructure" });
    assert.deepEqual(result.calls, ["readInfrastructure"], message);
    assert.deepEqual(result.rounds[0].tools.map(t => t.function.name), ["readInfrastructure", "getInfrastructureOperation"], message);
    const input = JSON.stringify(result.rounds[0].input);
    assert.match(input, /letture recenti degli strumenti disponibili/);
    assert.doesNotMatch(input, /Approfondisci l’ultima risposta|Mantieni l’esito già verificato e continua/);
    assert.equal(result.events.at(-1).type, "completed", message);
  }
});

test("fresh-check mutations are rejected even after an explicitly authorized historical operation", async () => {
  for (const attemptedTool of ["changeInfrastructure", "removePortalApplication", "createChatFile", "createChatZip", "analyzeChatAttachment"]) {
    const result = await run("Verifica l’esito dell’operazione precedente senza ripeterla.", { attemptedTool });
    assert.deepEqual(result.calls, [], attemptedTool);
    assert.equal(result.events.at(-1).type, "failed", attemptedTool);
    assert.equal(result.events.at(-1).payload.code, "TOOL_NOT_ALLOWED", attemptedTool);
  }
});
