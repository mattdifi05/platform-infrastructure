import test from "node:test";
import assert from "node:assert/strict";
import { isCanonicalAssistantContinuation, shouldReloadHistoricalAttachmentContext } from "../ai/quick-reply.mjs";

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
