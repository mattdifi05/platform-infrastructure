// Node 26 strips the type-only syntax in the canonical TypeScript router.
// Existing consumers retain this stable JavaScript import path.
export { normalizeRequestedMode, resolveServerAiMode } from "./mode-router.ts";
