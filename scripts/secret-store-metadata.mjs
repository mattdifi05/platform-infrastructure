export function legacyPlaintextFingerprintNames(store) {
  return Object.entries(store?.secrets ?? {})
    .filter(([, record]) => record && Object.prototype.hasOwnProperty.call(record, "fingerprint"))
    .map(([name]) => name)
    .sort();
}

export function assertNoPlaintextFingerprints(store, context = "secret manager store") {
  const names = legacyPlaintextFingerprintNames(store);
  if (names.length) {
    throw new Error(`${context} contains legacy plaintext-derived fingerprints for ${names.join(", ")}; run migrate-metadata before verification or export.`);
  }
  return true;
}

