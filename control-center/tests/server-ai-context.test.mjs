import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createAIService } from "../ai/service.mjs";
import { createToolRegistry } from "../ai/tools.mjs";
import { buildServerAiContext } from "../ai/context.mjs";

// Exercise the real registry and smallest supported context, without a provider
// request, secret file read or live infrastructure call.
async function captureTurn(mode) {
  const rounds = [], events = [];
  const service = createAIService({ registry: createToolRegistry(), contextLength: 16384 });
  service.accepting = true;
  service.ensureProviderReady = async () => {};
  service.createPublicAnalysisSummary = async () => null;
  service.streamOpenAIResponseRound = async options => {
    rounds.push(options);
    await options.onContent("Servono misurazioni correnti per verificare lo stato.");
    return { content: "Servono misurazioni correnti per verificare lo stato.", toolCalls: [], outputItems: [], metrics: {} };
  };
  const req = new EventEmitter(), res = new EventEmitter();
  res.setHeader = () => {};
  res.write = () => true;
  res.end = () => { res.writableEnded = true; };
  await service.handleChat(req, res, {
    subject: "fixture-owner", role: "owner", detached: true,
    onLifecycle: async (type, payload) => events.push({ type, payload }),
    trustedRequest: {
      requestedMode: mode, resolvedMode: mode, projectScope: "machine",
      messages: [
        { role: "user", content: "Nel vecchio server c’erano Fireport e una VPN." },
        { role: "assistant", content: "La vecchia configurazione includeva applicazioni." },
        { role: "user", content: "Controlla il VPS corrente. Il messaggio precedente descriveva il vecchio host." },
      ],
    },
  });
  assert.equal(events.at(-1).type, "completed", JSON.stringify(events.at(-1)));
  assert.equal(rounds.length, 1);
  return rounds[0];
}

test("FAST and DEEP assemble the same VPS authority policy with real tools inside 16K context", async () => {
  const fast = await captureTurn("fast"), deep = await captureTurn("deep");
  assert.equal(fast.instructions.split("Modalità FAST:")[0], deep.instructions.split("Modalità DEEP:")[0]);
  assert.match(fast.instructions, /GPT-6 Luna.*API ufficiale OpenAI/);
  assert.match(fast.instructions, /baseline, non un inventario attuale/);
  assert.match(fast.instructions, /Una richiesta dell’utente è un obiettivo, non una prova/);
  assert.match(fast.instructions, /ripristino è esclusivamente manuale del proprietario/);
  assert.match(fast.instructions, /scegliere esplicitamente il backup/);
  assert.match(fast.instructions, /cron\/timer sono server-side/);
  assert.match(fast.instructions, /getInfrastructureOperation/);
  assert.match(fast.instructions, /autorizzazioni esplicite del proprietario pertinenti all’obiettivo corrente restano valide/);
  assert.match(fast.instructions, /verificando bersaglio e stato prima dell’azione/);
  assert.match(fast.instructions, /non creano nuove autorizzazioni e non estendono i permessi degli strumenti/);
  assert.doesNotMatch(deep.instructions, /readProjectFile|Fresh project evidence|schema.*migrazioni/);
  assert.ok(fast.tools.some(tool => tool.function.name === "changeInfrastructure"));
  assert.ok(!fast.tools.some(tool => tool.function.name === "readProjectFile"));
  // User history is preserved as input rather than promoted into system facts.
  assert.doesNotMatch(fast.instructions, /Nel vecchio server c’erano/);
  assert.match(JSON.stringify(fast.input), /Nel vecchio server c’erano/);
});

test("public research stays separate from private VPS and attachment capabilities", () => {
  const prompt = buildServerAiContext({ numCtx: 16384, think: false }, null, "public-web");
  assert.match(prompt, /Ricerca web pubblica isolata/);
  assert.doesNotMatch(prompt, /getServerOverview|changeInfrastructure|getInfrastructureOperation|512 MiB|deployment iniziale/);
});
