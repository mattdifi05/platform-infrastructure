export const resticPassthroughEnvironmentKeys = Object.freeze([
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_DEFAULT_REGION",
  "RESTIC_AWS_ASSUME_ROLE_ARN",
  "RESTIC_AWS_ASSUME_ROLE_SESSION_NAME",
  "RESTIC_AWS_ASSUME_ROLE_EXTERNAL_ID",
  "RESTIC_AWS_ASSUME_ROLE_REGION",
  "RESTIC_AWS_ASSUME_ROLE_STS_ENDPOINT",
  "B2_ACCOUNT_ID",
  "B2_ACCOUNT_KEY",
  "AZURE_ACCOUNT_NAME",
  "AZURE_ACCOUNT_KEY",
  "AZURE_ACCOUNT_SAS",
  "AZURE_ENDPOINT_SUFFIX",
  "GOOGLE_PROJECT_ID",
  "GOOGLE_ACCESS_TOKEN",
  "OS_AUTH_URL",
  "OS_REGION_NAME",
  "OS_USERNAME",
  "OS_USER_ID",
  "OS_PASSWORD",
  "OS_TENANT_ID",
  "OS_TENANT_NAME",
  "OS_USER_DOMAIN_NAME",
  "OS_USER_DOMAIN_ID",
  "OS_PROJECT_NAME",
  "OS_PROJECT_DOMAIN_NAME",
  "RCLONE_CONFIG_PASS",
]);

const sensitiveQueryParameter = /(?:access[_-]?key|api[_-]?key|auth|credential|password|secret|signature|token)/i;

function decodeCredential(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function repositoryCredentialValues(repository) {
  const values = new Set([repository]);
  const candidates = [repository];
  const backendPrefix = repository.match(/^[a-z][a-z0-9+.-]*:(https?:\/\/.*)$/i);
  if (backendPrefix) candidates.push(backendPrefix[1]);
  for (const candidate of candidates) {
    let parsed;
    try {
      parsed = new URL(candidate);
    } catch {
      continue;
    }
    if (parsed.username) values.add(decodeCredential(parsed.username));
    if (parsed.password) values.add(decodeCredential(parsed.password));
    for (const [key, value] of parsed.searchParams) {
      if (value && sensitiveQueryParameter.test(key)) values.add(value);
    }
  }
  return [...values].filter(Boolean);
}

export function resticSecretTransport(repository, containerPasswordFile) {
  const cleanRepository = String(repository ?? "").trim();
  if (!cleanRepository) throw new Error("Restic repository is required.");
  const cleanPasswordFile = String(containerPasswordFile ?? "").trim();
  if (!cleanPasswordFile.startsWith("/")) throw new Error("Restic password file must be an absolute container path.");
  return {
    dockerArgs: ["-e", "RESTIC_REPOSITORY", "-e", "RESTIC_PASSWORD_FILE"],
    processEnv: { RESTIC_REPOSITORY: cleanRepository, RESTIC_PASSWORD_FILE: cleanPasswordFile },
    sensitiveValues: repositoryCredentialValues(cleanRepository),
    sensitiveEnvironmentKeys: [
      "RESTIC_REPOSITORY",
      "RESTIC_PASSWORD",
      ...resticPassthroughEnvironmentKeys,
    ],
  };
}
