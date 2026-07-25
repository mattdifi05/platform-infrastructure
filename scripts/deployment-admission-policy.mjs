import { trustedProducerConfiguration } from "./trusted-provider-run-policy.mjs";

export function assertDeploymentAdmissionConfigured(policy) {
  if (
    policy?.status !== "READY"
    || !policy?.trustedVerifierChannel
    || !/^[a-z0-9.-]+(?::[0-9]+)?(?:\/[a-z0-9._-]+)+$/.test(String(policy?.trustedOpsImageRepository ?? ""))
    || policy?.selfAssertedAnnotationsAccepted !== false
  ) {
    throw new Error(`EXTERNAL-PENDING: ${policy?.reason ?? "trusted deployment admission verifier channel is not configured"}`);
  }
  trustedProducerConfiguration(policy);
  return true;
}
