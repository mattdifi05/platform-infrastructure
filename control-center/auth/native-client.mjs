import { createPublicKey, randomBytes, verify } from "node:crypto";
import { listNativeRouteDefinitions } from "./route-capabilities.mjs";

export function nativeAuthenticationMetadata(auth) {
  return {
    mode: auth.mode,
    origin: auth.config.publicOrigin || "",
    rpId: auth.config.rpId || "",
    freshAuthSeconds: auth.config.freshAuthSeconds || 0,
    associationConfigured: Boolean(auth.config.associatedAppIds?.length),
    vaultFaceIDSupported: auth.mode === "app-passkey",
  };
}

export function nativeAssociationDocument(config) {
  return { webcredentials: { apps: [...(config.associatedAppIds || [])] } };
}

export function nativeSessionBootstrap(auth, session) {
  const identity = session.identity || {};
  return {
    schemaVersion: 1,
    authentication: nativeAuthenticationMetadata(auth),
    session: {
      subject: identity.subject,
      email: identity.email || "",
      displayName: identity.displayName || "",
      role: session.role,
      roles: identity.roles || [session.role],
      authTime: identity.authTime || null,
      expiresAt: identity.expiresAt || null,
      vaultFaceIDRegistered: Boolean(identity.nativeVaultPublicKey),
    },
    csrfToken: identity.csrfToken || "",
    capabilities: listNativeRouteDefinitions().map((definition) => {
      const decision = auth.authorize({ method: definition.method, controlCenterOperation: definition }, new URL("/", auth.config.publicOrigin || "https://localhost"), session);
      return { ...definition, allowed: decision.ok, requiresFreshAuthentication: decision.status === 428 };
    }),
  };
}

function p256PublicKey(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{87}$/.test(value)) return null;
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 65 || bytes[0] !== 4 || bytes.toString("base64url") !== value) return null;
  try {
    return createPublicKey({ format: "jwk", key: {
      kty: "EC", crv: "P-256",
      x: bytes.subarray(1, 33).toString("base64url"),
      y: bytes.subarray(33).toString("base64url"),
    } });
  } catch { return null; }
}

export function isNativeVaultPublicKey(value) {
  return Boolean(p256PublicKey(value));
}

export function createNativeVaultChallenges(now = () => performance.now()) {
  const pending = new Map();
  return {
    issue(session, itemId) {
      const timestamp = now();
      for (const [id, challenge] of pending) {
        if (challenge.expiresAt <= timestamp) pending.delete(id);
      }
      const sessionId = session.sessionTokenHash;
      if (!pending.has(sessionId) && pending.size >= 512) return null;
      const nonce = randomBytes(32).toString("base64url");
      pending.set(sessionId, { nonce, itemId, expiresAt: timestamp + 60_000 });
      return nonce;
    },
    consume(session, itemId, { challenge, signature }) {
      const sessionId = session.sessionTokenHash;
      const expected = pending.get(sessionId);
      if (!expected || expected.expiresAt <= now() || expected.itemId !== itemId || expected.nonce !== challenge) return false;
      pending.delete(sessionId);
      const publicKey = p256PublicKey(session.identity?.nativeVaultPublicKey);
      if (!publicKey || typeof signature !== "string" || !/^[A-Za-z0-9_-]{11,96}$/.test(signature)) return false;
      try {
        return verify("sha256", Buffer.from(`platform-vault-reveal-v1\n${challenge}`, "utf8"), publicKey, Buffer.from(signature, "base64url"));
      } catch { return false; }
    },
  };
}
