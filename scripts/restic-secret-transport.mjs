export function resticSecretTransport(repository, containerPasswordFile) {
  const cleanRepository = String(repository ?? "").trim();
  if (!cleanRepository) throw new Error("Restic repository is required.");
  const cleanPasswordFile = String(containerPasswordFile ?? "").trim();
  if (!cleanPasswordFile.startsWith("/")) throw new Error("Restic password file must be an absolute container path.");
  return {
    dockerArgs: ["-e", "RESTIC_REPOSITORY", "-e", "RESTIC_PASSWORD_FILE"],
    processEnv: { RESTIC_REPOSITORY: cleanRepository, RESTIC_PASSWORD_FILE: cleanPasswordFile },
    sensitiveValues: [cleanRepository],
  };
}

