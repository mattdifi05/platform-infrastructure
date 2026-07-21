import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import test from "node:test";

// Public, synthetic certificates generated only for this offline regression
// suite. No private key or network listener is required by these checks.
const ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
MIIC5TCCAc2gAwIBAgIJAIlnf3sr0vZtMA0GCSqGSIb3DQEBCwUAMB0xGzAZBgNV
BAMMEkZHMDA2IFRlc3QgUm9vdCBDQTAgFw0yNjA3MjExOTUxNDdaGA8yMTI2MDYy
NzE5NTE0N1owHTEbMBkGA1UEAwwSRkcwMDYgVGVzdCBSb290IENBMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxRREYiuUZCWbHo0p0FvrBA2d/edA+f3t
nJQ58LlAiVIMnU/0GYh6SlTRSES1efuQDI7pMJqwJXMoFUn2GO5/ByjWTUQyTHpV
pPXZ7Izcy1QHJbIVu27qY+qI5Pgz0DCKLNHmSIUJB74fyZgXKu2QupFWN6vXg38c
BMlqIWsgi8TEm0Qsn7k2pgeHUwSnRB+5PFCUjCE6NAwrU50LTodbvUjI5+YpswwN
2qWzRzTQeGKbHF+ZYtP+5IwiiXl3gpMdwhjxqbOjVOZSdHLrS8szD2XEmZGxiYK3
sGbb8hmwgvmpZ50F6YiucTeWwHOouAT3EOtuF/zANfzTDEQiIYx0tQIDAQABoyYw
JDASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0B
AQsFAAOCAQEAWenOBeDNGnjANqdWSUPk/jDU1xMlPCPoVsNu8J4VTEd2oSjJiQf6
2UJ7ZpgJOmYqF8Yt2gB38454eaCR6hYQw5x8DbrIS6X9jbgxB/V5Yj+7AACtm2mP
yagyPkQRjWqRmhHT606pGQ3XojgnbFLDpVQ+AFBbhCdGuSKOPeLPBERkCt8aRLyu
husf88xAxwnZblmG7z+bjLBtzF0V8ka2QJEEMx2uZAeBy9PjdiVZU4qd0CI5CkH3
Apc4IPCqM4PRJfGdNBS19RwRBGEDgwmNn0A2CxO/EouhGvwShnOt00KHCOd5WrdH
fB4xQpcusKOfd7qtUurqMSMclAg7dV0HTQ==
-----END CERTIFICATE-----`;

const INTERMEDIATE_CA_PEM = `-----BEGIN CERTIFICATE-----
MIIDRTCCAi2gAwIBAgIJAPqx3aGob2uqMA0GCSqGSIb3DQEBCwUAMB0xGzAZBgNV
BAMMEkZHMDA2IFRlc3QgUm9vdCBDQTAgFw0yNjA3MjExOTUxNDdaGA8yMTI2MDYy
NzE5NTE0N1owJTEjMCEGA1UEAwwaRkcwMDYgVGVzdCBJbnRlcm1lZGlhdGUgQ0Ew
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/5OR0Q4cKdfuaYOjntecg
iz78u+hq9IQS3UXvDM0hXS4GmllAo0n8fbRD991Gua3btUXHre2DoHbWHAiucBz2
4h6OBKK19H0Dp7ZUDujCAaKxO1N2UtrBy2HEMTPFA/063AP/sOtKY4jUsLcrb31X
NyJO4gjR8zJV5JhHVF6kmXUP4pe2TflZ6S71oCxclJGYCTMG7Pg75SkLkUjPZd0a
fiXfoyeqHO7Xdz0Vcz8aOmuATTlJUPjCP4Y9GgR1bqyBWaW4TM2pI1qzJuNw7p2U
JoqRJhGkFa6zPu/Y37YjqqHKIEU1r+PPBDtj5/W0v9Gn4h3yGwpGuvi3Vi8eOCMZ
AgMBAAGjfjB8MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMB0G
A1UdDgQWBBQPU8V3WRMdjcYcBj8CH40bOM6sajA3BgNVHSMEMDAuoSGkHzAdMRsw
GQYDVQQDDBJGRzAwNiBUZXN0IFJvb3QgQ0GCCQCJZ397K9L2bTANBgkqhkiG9w0B
AQsFAAOCAQEAat9qf7uqmxRVlLzC20CilS03j722UfP6ZxQd/JuLmc9CTFDQq6Ja
2tq3V1BmAk6FJtMplqKk2Xf9pqgAb+Qr82smMlr22U7uWpOfMXLCqlL3XGud4R/u
LcUKhIJFiUmRNWQmyCyIL+t9/+uWcq5bU3QpmKllDvr7oMn97syqDAmAxsIHjutH
39UBPov9a8A8aimmaf79i5hioKslVY/JAmzgk0JqY3JtRIbJv9wXnHCboN52x3BQ
2R6voSgswXXt70zV1f69hrWpP/qB9ScI4q+e2K6GkeD4RcXNIux5qS9wGI1Vmezx
1dCfE4GD2FTLyBOqOjkSfgTLye58J5vkUg==
-----END CERTIFICATE-----`;

const IDENTITY_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDYzCCAkugAwIBAgIJAPqx3aGob2urMA0GCSqGSIb3DQEBCwUAMCUxIzAhBgNV
BAMMGkZHMDA2IFRlc3QgSW50ZXJtZWRpYXRlIENBMCAXDTI2MDcyMTE5NTE0N1oY
DzIxMjYwNjI3MTk1MTQ3WjAgMR4wHAYDVQQDDBVpZGVudGl0eS5leGFtcGxlLnRl
c3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDoOkAKS9Q4L0QtmBkT
cMxeo9ro2vHqcHqaxtlcakwU7oZsEsytFlnhOAe++gHvBh+eDwQ+h59/WbNKnlqA
eHM7Sg8RgybGQTwIHfbP3aEo5s5pX9FcYJGlKOIa1k80qLHCx0mk3/JhwEI5t2fJ
Pu7Y2alHgMfXiQatRtMFiLtpNlHefXkWDYnz7MslMSsY7EjD5imYMz4at45ZD8TO
X24MOi+o0hTBJqKzLQUyLOi82MUvZplXdQNaB9EwWf1rHfxYlKrVMAFaEjc7+DkG
PPYvkYQcXG9U3Pgx9mSFHfSOl3sFK7ZuT1a9FTW7nWIO/7T+b9LEYQXl7wQBUt6w
buRTAgMBAAGjgZgwgZUwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYD
VR0lBAwwCgYIKwYBBQUHAwEwIAYDVR0RBBkwF4IVaWRlbnRpdHkuZXhhbXBsZS50
ZXN0MB0GA1UdDgQWBBQ4/6bzA8wxPnb07shj3xhtrBUHVDAfBgNVHSMEGDAWgBQP
U8V3WRMdjcYcBj8CH40bOM6sajANBgkqhkiG9w0BAQsFAAOCAQEARZdq0gEPr/bR
a9+N3z09A0dNQkgmk0sKkqBxIdpd0l0kD6REbx/axNlBB1EBzYGYEm9In9MPuDvX
PQjZ/PrjHuw+kxnHg+A6w8BmP6N/UHVT+uEycgCzN7QPzpv1yydaiZGLDyQ5m7bn
8oaAauTrrPZNaBmzD88emiY8QRetiKoRv5ik9AcjfMgmEJfWuI7+pIqlMDJ/4kRm
pI9gRTFoUzUi1NvoPwj1znfsdgX+Z6yxHcTJqLsamc+mdSPADqLsLzQ+Y79kNXHS
Kx/V3gLNJZNlSFD4NvA7pjsFkAD6ZwrupS+T9wlVZQqWVXgyS6Gn9u3Ad71XnIhO
8x1oXJsP0Q==
-----END CERTIFICATE-----`;

const UNRELATED_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
MIIC7zCCAdegAwIBAgIJANwSRaeRPVaAMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNV
BAMMF0ZHMDA2IFVucmVsYXRlZCBSb290IENBMCAXDTI2MDcyMTE5NTE0N1oYDzIx
MjYwNjI3MTk1MTQ3WjAiMSAwHgYDVQQDDBdGRzAwNiBVbnJlbGF0ZWQgUm9vdCBD
QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMB0PSzE9iQaez2P5AHw
4iOUjuITCgrxBZZOC2RK8O3rJzb6/Xo/B7Fdp+9xuRGJV/tf+O7jCOhwaPXB7lTX
WLmwD2F7bdbzgED3Y5SKPzJxAHgI4dxA9rfyyNHCeJwZZVcIXM5Tm6waLLyZs1js
BF0xqZ7z8zPaYsC9izh3ly0iu2xJAA5EnOiQZOESHkGvQ+MdhnPp90wdvI3qPeBO
T4FA3edkTK17LoHzWs4QK4u4V9mpuV4Tf63JtenqRJdyQGVbgeeP2iiIxMW6go48
ytCmlTiM9ZwAa/pNXKNkEixyG0BtUGB4F+RvOpAoVNaRyVAv5ymOo678fm770F5c
36UCAwEAAaMmMCQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYw
DQYJKoZIhvcNAQELBQADggEBAG+E3HUaUMoyn/hZm4bwsELJLF9S6sLOk84orNXo
MT5wFXjTCoDfTo+/LRFrYA/cMtV7zzdF69Y+H4FQeZx3KTZhHMYoA6GFa4VDOW52
Mp8T/5n0aWMs7wdTw9xtduD+dpetRO3j3e9HqFx5vgENAwv9uwOQbl/4Onj9rqGi
iGM+VeCX8P4ElK8THfF3e1WF1vmDv+r78b9nMUWJJFLJ2mCz0tVHnLzLDOrE/TQV
+uztQPGQNOocEvetjKqbzFbxG2FlzgUs0IJr4BUM0J2SEwbELtXp9EueIrOwC4Id
mu4JVcJBXqxtt2+QBU6qnUJPonCvF4CK+Bskd1ewXQbduwE=
-----END CERTIFICATE-----`;

const root = new X509Certificate(ROOT_CA_PEM);
const intermediate = new X509Certificate(INTERMEDIATE_CA_PEM);
const identity = new X509Certificate(IDENTITY_CERT_PEM);
const unrelatedRoot = new X509Certificate(UNRELATED_ROOT_CA_PEM);
const fixtureValidationTime = new Date("2030-01-01T00:00:00.000Z");

function verifyOfflineServerTrust({
  certificate = identity,
  intermediates = [intermediate],
  trustAnchor = root,
  hostname = "identity.example.test",
  validationTime = fixtureValidationTime,
} = {}) {
  if (certificate.ca || !trustAnchor.ca || intermediates.some((item) => !item.ca)) {
    throw new Error("OIDC TLS certificate roles are invalid.");
  }
  if (!certificate.keyUsage?.includes("1.3.6.1.5.5.7.3.1")) {
    throw new Error("OIDC TLS certificate is not valid for server authentication.");
  }
  if (!certificate.checkHost(hostname)) {
    throw new Error("OIDC TLS certificate hostname mismatch.");
  }

  for (const item of [certificate, ...intermediates, trustAnchor]) {
    const instant = validationTime.getTime();
    if (instant < Date.parse(item.validFrom) || instant > Date.parse(item.validTo)) {
      throw new Error("OIDC TLS certificate is outside its validity window.");
    }
  }

  let child = certificate;
  for (const issuer of [...intermediates, trustAnchor]) {
    if (!child.checkIssued(issuer) || !child.verify(issuer.publicKey)) {
      throw new Error("OIDC TLS certificate chain is incomplete or untrusted.");
    }
    child = issuer;
  }
  if (!trustAnchor.checkIssued(trustAnchor) || !trustAnchor.verify(trustAnchor.publicKey)) {
    throw new Error("OIDC TLS trust anchor is invalid.");
  }
}

test("offline OIDC TLS policy accepts a valid certificate and complete trusted chain", () => {
  assert.doesNotThrow(() => verifyOfflineServerTrust());
});

test("offline OIDC TLS policy rejects an unknown certificate authority", () => {
  assert.throws(
    () => verifyOfflineServerTrust({ trustAnchor: unrelatedRoot }),
    /chain is incomplete or untrusted/,
  );
});

test("offline OIDC TLS policy rejects a missing intermediate certificate", () => {
  assert.throws(
    () => verifyOfflineServerTrust({ intermediates: [] }),
    /chain is incomplete or untrusted/,
  );
});

test("offline OIDC TLS policy rejects a hostname mismatch", () => {
  assert.throws(
    () => verifyOfflineServerTrust({ hostname: "attacker.example.test" }),
    /hostname mismatch/,
  );
});

test("offline OIDC TLS policy rejects an expired certificate", () => {
  const afterExpiry = new Date(Date.parse(identity.validTo) + 1);
  assert.throws(
    () => verifyOfflineServerTrust({ validationTime: afterExpiry }),
    /outside its validity window/,
  );
});
