import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

const KEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
const MIN_KEY_MATERIAL_LENGTH = 48;

export class VaultKeyringError extends Error {}

export function parseVaultKeyring(value, { activeKeyId = "" } = {}) {
  const entries = String(value ?? "")
    .split(/\r?\n|,/)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const separator = entry.indexOf("=");
      if (separator <= 0) throw new VaultKeyringError("Vault keyring contains an invalid entry.");
      const id = entry.slice(0, separator).trim();
      const material = entry.slice(separator + 1).trim();
      if (!KEY_ID_PATTERN.test(id) || material.length < MIN_KEY_MATERIAL_LENGTH || !/^[A-Za-z0-9_-]+$/.test(material)) {
        throw new VaultKeyringError("Vault keyring contains an invalid key id or key material.");
      }
      return { id, material };
    });

  if (!entries.length) throw new VaultKeyringError("Vault keyring is empty.");
  const keys = new Map();
  for (const entry of entries) {
    if (keys.has(entry.id)) throw new VaultKeyringError("Vault keyring contains a duplicate key id.");
    keys.set(entry.id, entry.material);
  }

  const selectedId = String(activeKeyId || "").trim()
    || [...keys.keys()].sort().at(-1);
  if (!keys.has(selectedId)) throw new VaultKeyringError("Configured active Vault key id is not present in the keyring.");
  return { activeKeyId: selectedId, keys };
}

export function loadVaultKeyring({ keyFile, activeKeyId = "" } = {}) {
  const file = String(keyFile || "").trim();
  if (!file || !existsSync(file)) throw new VaultKeyringError("Dedicated Vault keyring file is not configured.");
  return parseVaultKeyring(readFileSync(file, "utf8"), { activeKeyId });
}

export function sealVaultPlaintext(value, itemId, keyring, createdAt = new Date().toISOString()) {
  const keyId = keyring?.activeKeyId;
  const material = keyring?.keys?.get(keyId);
  if (!keyId || !material) throw new VaultKeyringError("Active Vault key is unavailable.");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", deriveKey(material), iv);
  cipher.setAAD(aadV2(itemId, keyId));
  const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  return {
    version: 2,
    alg: "aes-256-gcm",
    keyId,
    iv: iv.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    data: encrypted.toString("base64url"),
    createdAt,
  };
}

export function openVaultCiphertext(sealedValue, itemId, keyring) {
  if (Number(sealedValue?.version) !== 2 || sealedValue?.alg !== "aes-256-gcm") {
    throw new VaultKeyringError("Vault ciphertext version is not supported by the keyring reader.");
  }
  const keyId = String(sealedValue.keyId || "");
  const material = keyring?.keys?.get(keyId);
  if (!material) throw new VaultKeyringError("Vault ciphertext references an unavailable key id.");
  return decrypt({ sealedValue, key: deriveKey(material), aad: aadV2(itemId, keyId) });
}

export function openLegacyVaultCiphertext(sealedValue, itemId, legacyMaterial) {
  const material = String(legacyMaterial || "").trim();
  if (!material) throw new VaultKeyringError("Legacy Vault key material is unavailable.");
  if (sealedValue?.alg !== "aes-256-gcm") throw new VaultKeyringError("Legacy Vault ciphertext algorithm is unsupported.");
  const expectedRef = createHash("sha256").update(material).digest("hex").slice(0, 16);
  if (sealedValue?.keyRef && sealedValue.keyRef !== expectedRef) {
    throw new VaultKeyringError("Legacy Vault ciphertext key reference does not match the escrowed key.");
  }
  return decrypt({
    sealedValue,
    key: createHash("sha256").update(material).digest(),
    aad: Buffer.from(`control-center-vault:${itemId}`, "utf8"),
  });
}

export function migrateVaultState({ state, keyring, legacyMaterial = "" } = {}) {
  if (!state || typeof state !== "object" || Array.isArray(state)) throw new VaultKeyringError("Vault state is invalid.");
  const items = state.items && typeof state.items === "object" && !Array.isArray(state.items) ? state.items : {};
  const migratedIds = [];
  const verifiedIds = [];
  const nextItems = {};

  for (const [id, item] of Object.entries(items)) {
    if (!item || typeof item !== "object" || item.deletedAt) continue;
    const sealed = item.sealedValue;
    if (!sealed) throw new VaultKeyringError(`Vault item ${id} has no ciphertext.`);
    if (Number(sealed.version) === 2) {
      openVaultCiphertext(sealed, id, keyring);
      verifiedIds.push(id);
      nextItems[id] = item;
      continue;
    }
    const plaintext = openLegacyVaultCiphertext(sealed, id, legacyMaterial);
    nextItems[id] = {
      ...item,
      sealedValue: sealVaultPlaintext(plaintext, id, keyring, sealed.createdAt || new Date().toISOString()),
      updatedAt: new Date().toISOString(),
    };
    migratedIds.push(id);
  }

  return {
    state: {
      ...state,
      version: 2,
      updatedAt: new Date().toISOString(),
      items: nextItems,
    },
    report: {
      total: Object.keys(nextItems).length,
      migrated: migratedIds.length,
      alreadyV2: verifiedIds.length,
      migratedIds,
      verifiedIds,
      activeKeyId: keyring.activeKeyId,
    },
  };
}

export function readLegacyVaultMaterial(file) {
  const value = String(file || "").trim();
  return value && existsSync(value) ? readFileSync(value, "utf8").trim() : "";
}

function deriveKey(material) {
  return createHash("sha256").update(`control-center-vault:v2:${material}`).digest();
}

function aadV2(itemId, keyId) {
  return Buffer.from(`control-center-vault:v2:${keyId}:${itemId}`, "utf8");
}

function decrypt({ sealedValue, key, aad }) {
  if (!sealedValue?.iv || !sealedValue?.tag || !sealedValue?.data) {
    throw new VaultKeyringError("Vault ciphertext is incomplete.");
  }
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(sealedValue.iv, "base64url"));
    decipher.setAAD(aad);
    decipher.setAuthTag(Buffer.from(sealedValue.tag, "base64url"));
    return Buffer.concat([
      decipher.update(Buffer.from(sealedValue.data, "base64url")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    throw new VaultKeyringError("Vault ciphertext authentication failed.");
  }
}
