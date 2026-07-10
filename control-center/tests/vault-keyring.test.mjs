import {
  createCipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import {
  migrateVaultState,
  openVaultCiphertext,
  parseVaultKeyring,
  sealVaultPlaintext,
  VaultKeyringError,
} from "../vault/keyring.mjs";

const materialA = "a".repeat(64);
const materialB = "b".repeat(64);
const materialC = "c".repeat(64);

test("Vault ciphertext survives keyring reordering and rotation", () => {
  const original = parseVaultKeyring(`v20260101000000=${materialA},v20260201000000=${materialB}`);
  const sealed = sealVaultPlaintext("reorder-safe-value", "item-1", original);
  assert.equal(sealed.keyId, "v20260201000000");

  const reordered = parseVaultKeyring(`v20260201000000=${materialB},v20260101000000=${materialA}`);
  assert.equal(reordered.activeKeyId, original.activeKeyId);
  assert.equal(openVaultCiphertext(sealed, "item-1", reordered), "reorder-safe-value");

  const rotated = parseVaultKeyring(`v20260301000000=${materialC},v20260101000000=${materialA},v20260201000000=${materialB}`);
  assert.equal(openVaultCiphertext(sealed, "item-1", rotated), "reorder-safe-value");
  assert.equal(sealVaultPlaintext("new-value", "item-2", rotated).keyId, "v20260301000000");
});

test("Vault key lookup and authenticated encryption fail closed", () => {
  const full = parseVaultKeyring(`v20260101000000=${materialA},v20260201000000=${materialB}`);
  const sealed = sealVaultPlaintext("protected-value", "item-1", full);
  const missing = parseVaultKeyring(`v20260101000000=${materialA}`);
  assert.throws(() => openVaultCiphertext(sealed, "item-1", missing), VaultKeyringError);
  const tamperedData = `${sealed.data.startsWith("A") ? "B" : "A"}${sealed.data.slice(1)}`;
  assert.throws(() => openVaultCiphertext({ ...sealed, data: tamperedData }, "item-1", full), VaultKeyringError);
  assert.throws(() => parseVaultKeyring(`v20260101000000=${materialA}`, { activeKeyId: "missing" }), VaultKeyringError);
});

test("Legacy Vault migration validates every item and emits only v2 ciphertext", () => {
  const legacyMaterial = "legacy-gateway-keyring-material-that-is-long-enough";
  const legacy = legacySeal("legacy-value-must-not-leak", "legacy-item", legacyMaterial);
  const keyring = parseVaultKeyring(`v20260301000000=${materialC}`);
  const migration = migrateVaultState({
    state: {
      version: 1,
      items: {
        "legacy-item": { id: "legacy-item", sealedValue: legacy },
      },
    },
    keyring,
    legacyMaterial,
  });

  assert.deepEqual(migration.report.migratedIds, ["legacy-item"]);
  assert.equal(migration.report.migrated, 1);
  assert.equal(migration.state.version, 2);
  const migrated = migration.state.items["legacy-item"].sealedValue;
  assert.equal(migrated.version, 2);
  assert.equal(migrated.keyId, "v20260301000000");
  assert.equal(openVaultCiphertext(migrated, "legacy-item", keyring), "legacy-value-must-not-leak");
  assert.doesNotMatch(JSON.stringify(migration), /legacy-value-must-not-leak/);
});

function legacySeal(value, itemId, material) {
  const key = createHash("sha256").update(material).digest();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(`control-center-vault:${itemId}`, "utf8"));
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return {
    alg: "aes-256-gcm",
    keyRef: createHash("sha256").update(material).digest("hex").slice(0, 16),
    iv: iv.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    data: encrypted.toString("base64url"),
    createdAt: "2026-07-10T00:00:00.000Z",
  };
}
