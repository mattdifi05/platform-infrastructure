export const FIRST_CONFIGURATION_STATES = Object.freeze({
  REQUIRED: "FIRST_CONFIGURATION_REQUIRED",
  COMPLETE: "FIRST_CONFIGURATION_COMPLETE",
});

export class FirstConfigurationError extends Error {
  constructor(message, status = 400, code = "first_configuration_rejected") {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export async function createFirstConfiguration({ env = process.env, auth } = {}) {
  const mode = String(env.CONTROL_CENTER_FIRST_CONFIGURATION_MODE || "disabled").trim().toLowerCase();
  if (mode === "disabled") return new DisabledFirstConfiguration();
  if (mode !== "required") {
    throw new FirstConfigurationError(
      "CONTROL_CENTER_FIRST_CONFIGURATION_MODE must be required or disabled.",
      500,
      "first_configuration_config_invalid",
    );
  }
  if (!auth || auth.mode !== "app-passkey") {
    throw new FirstConfigurationError(
      "Application passkey authentication is unavailable.",
      503,
      "first_configuration_app_passkey_unavailable",
    );
  }
  return new DirectFirstConfiguration(auth);
}

class DirectFirstConfiguration {
  constructor(auth) {
    this.enabled = true;
    this.direct = true;
    this.auth = auth;
    this.config = auth.config;
  }

  async status() {
    const passkeys = await this.auth.store.listPasskeys(this.config.adminSubject);
    const complete = passkeys.length >= 1;
    return {
      state: complete ? FIRST_CONFIGURATION_STATES.COMPLETE : FIRST_CONFIGURATION_STATES.REQUIRED,
      complete,
      adminSubject: this.config.adminSubject,
      adminUsername: this.config.adminUsername,
      adminEmail: this.config.adminEmail,
      passkeyCount: passkeys.length,
      minimumPasskeys: 1,
      passkeys: passkeys.map((item) => ({ id: item.id, createdAt: item.createdAt, expiresAt: item.expiresAt })),
      publicOrigin: this.config.publicOrigin,
      identityOrigin: this.config.publicOrigin,
      rpId: this.config.rpId,
    };
  }

  async close() {}
}

class DisabledFirstConfiguration {
  constructor() { this.enabled = false; }
  async status() { return { enabled: false, state: "DISABLED" }; }
  async close() {}
}
