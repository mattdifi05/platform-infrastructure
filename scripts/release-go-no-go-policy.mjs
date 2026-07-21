export function releaseEvidenceAdmissionReady(payload) {
  return Boolean(
    payload?.mode === "evidence"
    && payload?.status === "passed"
    && payload?.admission?.artifactVerification === "passed"
    && payload?.admission?.deploymentAdmission === "READY"
    && payload?.artifacts?.admissionReceipt?.kind === "platform-trusted-deployment-admission/v1"
    && payload?.artifacts?.admissionReceipt?.status === "READY"
    && /^[a-f0-9]{64}$/.test(String(payload?.artifacts?.admissionReceipt?.sha256 ?? "")),
  );
}
