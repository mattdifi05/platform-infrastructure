export const SERVER_AI_MODEL = "gpt-6-luna";
export const SERVER_AI_MODEL_LABEL = "GPT-6 Luna · OpenAI API";
export const SERVER_AI_DEFAULT_CONTEXT = 32768;
export const SERVER_AI_CONTEXT_LENGTHS = Object.freeze([16384, 32768, 65536, 131072, 250000]);
// Operator-owned context cap. Requests and model tool arguments cannot change it.
export function normalizeServerAiContext(value = SERVER_AI_DEFAULT_CONTEXT) {
  if (!Number.isSafeInteger(value) || !SERVER_AI_CONTEXT_LENGTHS.includes(value)) throw new RangeError("Contesto Server AI non valido.");
  return value;
}
