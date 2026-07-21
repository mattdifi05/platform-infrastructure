export function assertDeploymentAdmissionConfigured(policy) {
  if (policy?.status !== "READY" || !policy?.trustedVerifierChannel || policy?.selfAssertedAnnotationsAccepted !== false) {
    throw new Error(`EXTERNAL-PENDING: ${policy?.reason ?? "trusted deployment admission verifier channel is not configured"}`);
  }
  return true;
}
