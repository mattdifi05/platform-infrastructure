import test from "node:test";
import assert from "node:assert/strict";
import { assistantContinuationKind, isCanonicalAssistantContinuation, shouldReloadHistoricalAttachmentContext } from "../ai/quick-reply.mjs";

const explicitAttachmentId = "2a4b8a5e-6df2-4f07-9b20-4de1b3397930";

test("quick-reply commands continue the immediately preceding assistant answer", () => {
  assert.equal(isCanonicalAssistantContinuation("Approfondisci"), true);
  assert.equal(isCanonicalAssistantContinuation("Riassumi."), true);
  assert.equal(isCanonicalAssistantContinuation("R Iassumi"), false);
  assert.equal(isCanonicalAssistantContinuation("Riassumi il documento"), false);
});

test("quick replies do not silently reload historical attachments", () => {
  assert.equal(shouldReloadHistoricalAttachmentContext("Approfondisci", []), false);
  assert.equal(shouldReloadHistoricalAttachmentContext("Riassumi", []), false);
  assert.equal(shouldReloadHistoricalAttachmentContext("Riassumi il documento", []), true);
  assert.equal(shouldReloadHistoricalAttachmentContext("Riassumi", [explicitAttachmentId]), true);
  assert.equal(shouldReloadHistoricalAttachmentContext("Approfondisci", [], true), true);
});

test("fresh checks require a complete canonical request, not an inferred option or permission", () => {
  assert.equal(assistantContinuationKind(" VERIFICA L'ESITO DELL'OPERAZIONE PRECEDENTE SENZA RIPETERLA! "), "fresh-read");
  assert.equal(assistantContinuationKind("Leggi l’audit recente relativo all’operazione precedente."), "fresh-read");
  for (const prose of ["Sì, procedi", "Scelgo riavviare il server.", "Vuoi che controlli lo stato?", "> Controlla nuovamente lo stato attuale del VPS.", "Controlla nuovamente lo stato attuale del VPS. Poi riavvialo."]) {
    assert.equal(assistantContinuationKind(prose), null, prose);
  }
  const request = "Verifica lo stato attuale di rete, DNS e TLS del server.";
  assert.equal(shouldReloadHistoricalAttachmentContext(request, []), false);
  assert.equal(shouldReloadHistoricalAttachmentContext(request, [explicitAttachmentId]), true);
  assert.equal(shouldReloadHistoricalAttachmentContext(request, [], true), true);
  assert.equal(assistantContinuationKind("Riassumi"), "summary");
  assert.equal(assistantContinuationKind("Approfondisci"), "expand");
});
