const ROLES = new Set(["owner", "admin", "viewer"]);

function validSubject(value) {
  return typeof value === "string" && value.length >= 1 && value.length <= 256 && value.trim() === value;
}

function acceptedSubject(config, subject) {
  if (subject === config?.adminSubject) return true;
  return config?.nodeEnvironment === "test"
    && config?.store === "memory"
    && ["127.0.0.1", "::1", "localhost"].includes(String(config?.bindHost || "").toLowerCase())
    && config?.testFixtureSubjects instanceof Set
    && config.testFixtureSubjects.has(subject);
}

function memorySessionActive(item, { subject, role, policyVersion, idleSeconds, now }) {
  return item?.subject === subject
    && item?.role === role
    && item?.policyVersion === policyVersion
    && !item?.revokedAt
    && item?.expiresAt instanceof Date
    && item.expiresAt.getTime() > now
    && item?.lastSeenAt instanceof Date
    && item.lastSeenAt.getTime() > now - idleSeconds * 1000;
}

/**
 * Revalidates the identity that created a durable automatic continuation.
 * This is intentionally session-presence only: the current project registry
 * remains the authority for project access, and there is no machine-grant
 * table in the app-passkey model.
 */
export function createContinuationAuthorizer(controlAuth) {
  const config = controlAuth?.config;
  const store = controlAuth?.store;
  return async ({ ownerId, role } = {}) => {
    if (!validSubject(ownerId) || !ROLES.has(role)) return false;
    if (controlAuth?.mode === "test-disabled") return ownerId === "test-owner" && role === "owner";
    if (controlAuth?.mode !== "app-passkey" || !acceptedSubject(config, ownerId)) return false;
    const policyVersion = String(config?.sessionPolicyVersion || "");
    const idleSeconds = Number(config?.sessionIdleSeconds);
    if (!policyVersion || !Number.isSafeInteger(idleSeconds) || idleSeconds < 1) return false;
    if (store?.pool && typeof store.pool.query === "function") {
      const result = await store.pool.query(
        `select exists(
           select 1 from control_auth.sessions
           where subject=$1 and role=$2 and policy_version=$3
             and revoked_at is null and expires_at > now()
             and last_seen_at > now() - ($4::text || ' seconds')::interval
         ) as active`,
        [ownerId, role, policyVersion, idleSeconds],
      );
      return result?.rows?.[0]?.active === true;
    }
    if (store?.sessions instanceof Map) {
      const now = Date.now();
      return [...store.sessions.values()].some(item => memorySessionActive(item, {
        subject: ownerId, role, policyVersion, idleSeconds, now,
      }));
    }
    return false;
  };
}
