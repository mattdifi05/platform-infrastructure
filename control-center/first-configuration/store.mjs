import pg from "pg";

const { Pool } = pg;

export const FIRST_CONFIGURATION_STATES = Object.freeze({
  REQUIRED: "FIRST_CONFIGURATION_REQUIRED",
  ADMIN_CONFIRMED: "ADMIN_CONFIRMED",
  ENROLLMENT_REQUIRED: "PASSKEY_ENROLLMENT_REQUIRED",
  PASSKEYS_READY: "PASSKEYS_READY",
  LOGIN_REQUIRED: "PASSKEY_LOGIN_REQUIRED",
  LOGOUT_VERIFICATION_REQUIRED: "PASSKEY_LOGOUT_VERIFICATION_REQUIRED",
  RELOGIN_REQUIRED: "PASSKEY_RELOGIN_REQUIRED",
  FINALIZING: "FIRST_CONFIGURATION_FINALIZING",
  COMPLETE: "FIRST_CONFIGURATION_COMPLETE",
});

export class PostgresFirstConfigurationStore {
  constructor(connectionString) {
    this.pool = new Pool({ connectionString, max: 3, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 5_000 });
  }

  async ready({ bootstrapTokenHash, bootstrapTokenExpiresAt }) {
    const tables = await this.pool.query(
      `select to_regclass('control_auth.first_configuration') as state,
              to_regclass('control_auth.first_configuration_sessions') as sessions`,
    );
    if (!tables.rows[0]?.state || !tables.rows[0]?.sessions) {
      throw new Error("Control Center first-configuration migration 004 is not applied.");
    }
    const inserted = await this.pool.query(
      `insert into control_auth.first_configuration
       (singleton,state,bootstrap_token_hash,bootstrap_token_expires_at)
       values (true,$1,$2,$3)
       on conflict (singleton) do nothing
       returning state`,
      [FIRST_CONFIGURATION_STATES.REQUIRED, bootstrapTokenHash, bootstrapTokenExpiresAt],
    );
    if (inserted.rowCount === 0) {
      const current = await this.getState();
      if (!current) throw new Error("First-configuration state is unavailable.");
      if (current.state !== FIRST_CONFIGURATION_STATES.COMPLETE && current.bootstrapTokenHash !== bootstrapTokenHash) {
        await this.rotateBootstrapToken({ bootstrapTokenHash, bootstrapTokenExpiresAt });
      }
    }
  }

  async rotateBootstrapToken({ bootstrapTokenHash, bootstrapTokenExpiresAt }) {
    const client = await this.pool.connect();
    try {
      await client.query("begin");
      const result = await client.query(
        `update control_auth.first_configuration
         set bootstrap_token_hash=$1,bootstrap_token_expires_at=$2,
             bootstrap_token_consumed_at=null,updated_at=now()
         where singleton=true and state<>$3
         returning state`,
        [bootstrapTokenHash, bootstrapTokenExpiresAt, FIRST_CONFIGURATION_STATES.COMPLETE],
      );
      if (result.rowCount !== 1) throw new Error("First-configuration bootstrap rotation was rejected.");
      await client.query(
        "update control_auth.first_configuration_sessions set revoked_at=now() where revoked_at is null",
      );
      await client.query("commit");
    } catch (error) {
      await client.query("rollback");
      throw error;
    } finally {
      client.release();
    }
  }

  async getState(client = this.pool) {
    const result = await client.query(
      `select state,bootstrap_token_hash,bootstrap_token_expires_at,bootstrap_token_consumed_at,
              admin_subject,admin_username,admin_email,passkey_count,passkey_independence_confirmed_at,cutover_at,
              passkey_login_verified_at,logout_verified_at,completed_at,created_at,updated_at
       from control_auth.first_configuration where singleton=true`,
    );
    return normalizeState(result.rows[0]);
  }

  async consumeBootstrapToken({ bootstrapTokenHash, sessionTokenHash, csrfHash, peerHash, expiresAt }) {
    const client = await this.pool.connect();
    try {
      await client.query("begin");
      const state = await this.getStateForUpdate(client);
      const now = Date.now();
      if (!state || state.state === FIRST_CONFIGURATION_STATES.COMPLETE ||
          state.bootstrapTokenHash !== bootstrapTokenHash ||
          state.bootstrapTokenExpiresAt.getTime() <= now) {
        await client.query("rollback");
        return null;
      }
      await client.query(
        `update control_auth.first_configuration
         set bootstrap_token_consumed_at=now(),updated_at=now()
         where singleton=true`,
      );
      await client.query(
        "update control_auth.first_configuration_sessions set revoked_at=now() where revoked_at is null",
      );
      await client.query(
        `insert into control_auth.first_configuration_sessions
         (token_hash,csrf_hash,peer_hash,expires_at) values ($1,$2,$3,$4)`,
        [sessionTokenHash, csrfHash, peerHash, expiresAt],
      );
      await client.query("commit");
      return { ...state, bootstrapTokenConsumedAt: new Date() };
    } catch (error) {
      await client.query("rollback");
      throw error;
    } finally {
      client.release();
    }
  }

  async getSession(tokenHash, peerHash, idleSeconds) {
    const result = await this.pool.query(
      `update control_auth.first_configuration_sessions
       set last_seen_at=now()
       where token_hash=$1 and peer_hash=$2 and revoked_at is null and expires_at > now()
         and last_seen_at > now() - ($3::text || ' seconds')::interval
       returning csrf_hash,created_at,last_seen_at,expires_at`,
      [tokenHash, peerHash, idleSeconds],
    );
    if (!result.rows[0]) return null;
    return {
      csrfHash: result.rows[0].csrf_hash,
      createdAt: result.rows[0].created_at,
      lastSeenAt: result.rows[0].last_seen_at,
      expiresAt: result.rows[0].expires_at,
    };
  }

  async revokeSession(tokenHash) {
    await this.pool.query(
      "update control_auth.first_configuration_sessions set revoked_at=now() where token_hash=$1 and revoked_at is null",
      [tokenHash],
    );
  }

  async recordAdministrator({ subject, username, email }) {
    return this.transition(
      [FIRST_CONFIGURATION_STATES.REQUIRED, FIRST_CONFIGURATION_STATES.ADMIN_CONFIRMED, FIRST_CONFIGURATION_STATES.ENROLLMENT_REQUIRED],
      FIRST_CONFIGURATION_STATES.ENROLLMENT_REQUIRED,
      `admin_subject=$3,admin_username=$4,admin_email=$5`,
      [subject, username, email],
    );
  }

  async recordPasskeyCount({ subject, count }) {
    return this.transition(
      [FIRST_CONFIGURATION_STATES.ENROLLMENT_REQUIRED],
      FIRST_CONFIGURATION_STATES.ENROLLMENT_REQUIRED,
      "passkey_count=$3",
      [count],
      { expectedSubject: subject },
    );
  }

  async confirmPasskeyIndependence({ subject }) {
    const result = await this.pool.query(
      `update control_auth.first_configuration
       set state=$1,passkey_independence_confirmed_at=now(),updated_at=now()
       where singleton=true and state=$2 and admin_subject=$3 and passkey_count >= 2
       returning *`,
      [FIRST_CONFIGURATION_STATES.PASSKEYS_READY, FIRST_CONFIGURATION_STATES.ENROLLMENT_REQUIRED, subject],
    );
    if (result.rowCount !== 1) throw new Error("Independent passkey confirmation was rejected.");
    return normalizeState(result.rows[0]);
  }

  async recordCutover({ subject, count }) {
    return this.transition(
      [FIRST_CONFIGURATION_STATES.PASSKEYS_READY],
      FIRST_CONFIGURATION_STATES.LOGIN_REQUIRED,
      "passkey_count=$3,cutover_at=now()",
      [count],
      { expectedSubject: subject },
    );
  }

  async recordPasskeyLogin({ subject }) {
    return this.transition(
      [FIRST_CONFIGURATION_STATES.LOGIN_REQUIRED],
      FIRST_CONFIGURATION_STATES.LOGOUT_VERIFICATION_REQUIRED,
      "passkey_login_verified_at=now()",
      [],
      { expectedSubject: subject },
    );
  }

  async recordLogoutVerification({ subject }) {
    return this.transition(
      [FIRST_CONFIGURATION_STATES.LOGOUT_VERIFICATION_REQUIRED],
      FIRST_CONFIGURATION_STATES.RELOGIN_REQUIRED,
      "logout_verified_at=now()",
      [],
      { expectedSubject: subject },
    );
  }

  async recordFinalizing({ subject }) {
    return this.transition(
      [FIRST_CONFIGURATION_STATES.RELOGIN_REQUIRED],
      FIRST_CONFIGURATION_STATES.FINALIZING,
      "",
      [],
      { expectedSubject: subject },
    );
  }

  async recordComplete({ subject }) {
    const client = await this.pool.connect();
    try {
      await client.query("begin");
      const result = await client.query(
        `update control_auth.first_configuration
         set state=$1,completed_at=coalesce(completed_at,now()),updated_at=now()
         where singleton=true and state=any($2::text[]) and admin_subject=$3
         returning *`,
        [
          FIRST_CONFIGURATION_STATES.COMPLETE,
          [FIRST_CONFIGURATION_STATES.FINALIZING, FIRST_CONFIGURATION_STATES.COMPLETE],
          subject,
        ],
      );
      if (result.rowCount !== 1) throw new Error("First-configuration completion transition was rejected.");
      await client.query(
        "update control_auth.first_configuration_sessions set revoked_at=now() where revoked_at is null",
      );
      await client.query("commit");
      return normalizeState(result.rows[0]);
    } catch (error) {
      await client.query("rollback");
      throw error;
    } finally {
      client.release();
    }
  }

  async transition(allowedStates, targetState, assignments = "", values = [], { expectedSubject = "" } = {}) {
    const params = [targetState, allowedStates, ...values];
    let subjectPredicate = "";
    if (expectedSubject) {
      params.push(expectedSubject);
      subjectPredicate = ` and admin_subject=$${params.length}`;
    }
    const sql = `update control_auth.first_configuration
      set state=$1${assignments ? `,${assignments}` : ""},updated_at=now()
      where singleton=true and state=any($2::text[])${subjectPredicate}
      returning *`;
    const result = await this.pool.query(sql, params);
    if (result.rowCount !== 1) throw new Error("First-configuration state transition was rejected.");
    return normalizeState(result.rows[0]);
  }

  async getStateForUpdate(client) {
    const result = await client.query(
      `select state,bootstrap_token_hash,bootstrap_token_expires_at,bootstrap_token_consumed_at,
              admin_subject,admin_username,admin_email,passkey_count,passkey_independence_confirmed_at,cutover_at,
              passkey_login_verified_at,logout_verified_at,completed_at,created_at,updated_at
       from control_auth.first_configuration where singleton=true for update`,
    );
    return normalizeState(result.rows[0]);
  }

  async close() { await this.pool.end(); }
}

export class MemoryFirstConfigurationStore {
  constructor() {
    this.state = null;
    this.sessions = new Map();
  }

  async ready({ bootstrapTokenHash, bootstrapTokenExpiresAt }) {
    if (!this.state) {
      this.state = normalizeState({
        state: FIRST_CONFIGURATION_STATES.REQUIRED,
        bootstrap_token_hash: bootstrapTokenHash,
        bootstrap_token_expires_at: bootstrapTokenExpiresAt,
        bootstrap_token_consumed_at: null,
        admin_subject: "",
        admin_username: "",
        admin_email: "",
        passkey_count: 0,
        passkey_independence_confirmed_at: null,
        cutover_at: null,
        passkey_login_verified_at: null,
        logout_verified_at: null,
        completed_at: null,
        created_at: new Date(),
        updated_at: new Date(),
      });
    } else if (this.state.state !== FIRST_CONFIGURATION_STATES.COMPLETE && this.state.bootstrapTokenHash !== bootstrapTokenHash) {
      this.state.bootstrapTokenHash = bootstrapTokenHash;
      this.state.bootstrapTokenExpiresAt = bootstrapTokenExpiresAt;
      this.state.bootstrapTokenConsumedAt = null;
      this.state.updatedAt = new Date();
      for (const session of this.sessions.values()) {
        if (!session.revokedAt) session.revokedAt = new Date();
      }
    }
  }

  async getState() { return structuredClone(this.state); }

  async consumeBootstrapToken({ bootstrapTokenHash, sessionTokenHash, csrfHash, peerHash, expiresAt }) {
    if (!this.state || this.state.state === FIRST_CONFIGURATION_STATES.COMPLETE || this.state.bootstrapTokenHash !== bootstrapTokenHash ||
        this.state.bootstrapTokenExpiresAt.getTime() <= Date.now()) return null;
    for (const session of this.sessions.values()) {
      if (!session.revokedAt) session.revokedAt = new Date();
    }
    this.state.bootstrapTokenConsumedAt = new Date();
    this.state.updatedAt = new Date();
    this.sessions.set(sessionTokenHash, { csrfHash, peerHash, createdAt: new Date(), lastSeenAt: new Date(), expiresAt, revokedAt: null });
    return structuredClone(this.state);
  }

  async getSession(tokenHash, peerHash, idleSeconds) {
    const session = this.sessions.get(tokenHash);
    const now = Date.now();
    if (!session || session.peerHash !== peerHash || session.revokedAt || session.expiresAt.getTime() <= now ||
        session.lastSeenAt.getTime() <= now - idleSeconds * 1000) return null;
    session.lastSeenAt = new Date();
    return structuredClone(session);
  }

  async revokeSession(tokenHash) { const session = this.sessions.get(tokenHash); if (session) session.revokedAt = new Date(); }

  async recordAdministrator({ subject, username, email }) {
    return this.memoryTransition(
      [FIRST_CONFIGURATION_STATES.REQUIRED, FIRST_CONFIGURATION_STATES.ADMIN_CONFIRMED, FIRST_CONFIGURATION_STATES.ENROLLMENT_REQUIRED],
      FIRST_CONFIGURATION_STATES.ENROLLMENT_REQUIRED,
      { adminSubject: subject, adminUsername: username, adminEmail: email },
    );
  }

  async recordPasskeyCount({ subject, count }) {
    return this.memoryTransition(
      [FIRST_CONFIGURATION_STATES.ENROLLMENT_REQUIRED],
      FIRST_CONFIGURATION_STATES.ENROLLMENT_REQUIRED,
      { passkeyCount: count },
      subject,
    );
  }

  async confirmPasskeyIndependence({ subject }) {
    if (this.state?.passkeyCount < 2) throw new Error("Independent passkey confirmation was rejected.");
    return this.memoryTransition(
      [FIRST_CONFIGURATION_STATES.ENROLLMENT_REQUIRED],
      FIRST_CONFIGURATION_STATES.PASSKEYS_READY,
      { passkeyIndependenceConfirmedAt: new Date() },
      subject,
    );
  }

  async recordCutover({ subject, count }) {
    return this.memoryTransition([FIRST_CONFIGURATION_STATES.PASSKEYS_READY], FIRST_CONFIGURATION_STATES.LOGIN_REQUIRED, { passkeyCount: count, cutoverAt: new Date() }, subject);
  }

  async recordPasskeyLogin({ subject }) {
    return this.memoryTransition([FIRST_CONFIGURATION_STATES.LOGIN_REQUIRED], FIRST_CONFIGURATION_STATES.LOGOUT_VERIFICATION_REQUIRED, { passkeyLoginVerifiedAt: new Date() }, subject);
  }

  async recordLogoutVerification({ subject }) {
    return this.memoryTransition([FIRST_CONFIGURATION_STATES.LOGOUT_VERIFICATION_REQUIRED], FIRST_CONFIGURATION_STATES.RELOGIN_REQUIRED, { logoutVerifiedAt: new Date() }, subject);
  }

  async recordComplete({ subject }) {
    const completedAt = this.state?.completedAt || new Date();
    const state = this.memoryTransition(
      [FIRST_CONFIGURATION_STATES.FINALIZING, FIRST_CONFIGURATION_STATES.COMPLETE],
      FIRST_CONFIGURATION_STATES.COMPLETE,
      { completedAt },
      subject,
    );
    for (const session of this.sessions.values()) session.revokedAt = new Date();
    return state;
  }

  async recordFinalizing({ subject }) {
    return this.memoryTransition([FIRST_CONFIGURATION_STATES.RELOGIN_REQUIRED], FIRST_CONFIGURATION_STATES.FINALIZING, {}, subject);
  }

  memoryTransition(allowed, target, changes, expectedSubject = "") {
    if (!this.state || !allowed.includes(this.state.state) || (expectedSubject && this.state.adminSubject !== expectedSubject)) {
      throw new Error("First-configuration state transition was rejected.");
    }
    Object.assign(this.state, changes, { state: target, updatedAt: new Date() });
    return structuredClone(this.state);
  }

  async close() {}
}

function normalizeState(row) {
  if (!row) return null;
  return {
    state: row.state,
    bootstrapTokenHash: row.bootstrap_token_hash,
    bootstrapTokenExpiresAt: asDate(row.bootstrap_token_expires_at),
    bootstrapTokenConsumedAt: asDate(row.bootstrap_token_consumed_at),
    adminSubject: row.admin_subject || "",
    adminUsername: row.admin_username || "",
    adminEmail: row.admin_email || "",
    passkeyCount: Number(row.passkey_count || 0),
    passkeyIndependenceConfirmedAt: asDate(row.passkey_independence_confirmed_at),
    cutoverAt: asDate(row.cutover_at),
    passkeyLoginVerifiedAt: asDate(row.passkey_login_verified_at),
    logoutVerifiedAt: asDate(row.logout_verified_at),
    completedAt: asDate(row.completed_at),
    createdAt: asDate(row.created_at),
    updatedAt: asDate(row.updated_at),
  };
}

function asDate(value) { return value ? new Date(value) : null; }
