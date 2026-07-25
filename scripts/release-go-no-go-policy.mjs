export function releaseEvidenceAdmissionReady(payload, verifiedAdmission = null) {
  const receipt = payload?.artifacts?.admissionReceipt;
  return Boolean(
    payload?.mode === "evidence"
    && payload?.status === "passed"
    && payload?.admission?.artifactVerification === "passed"
    && payload?.admission?.deploymentAdmission === "READY"
    && receipt?.kind === "platform-trusted-deployment-admission/v1"
    && receipt?.status === "READY"
    && verifiedAdmission?.status === "READY"
    && /^[a-f0-9]{64}$/.test(String(receipt?.sha256 ?? ""))
    && receipt.sha256 === verifiedAdmission.deploymentReceiptSha256
    && receipt.artifactReceiptSha256 === verifiedAdmission.artifactReceiptSha256
    && receipt.providerMetadataSha256 === verifiedAdmission.providerMetadataSha256
    && receipt.repository === verifiedAdmission.repository
    && receipt.commitSha === verifiedAdmission.commitSha
    && receipt.treeSha === verifiedAdmission.treeSha
    && String(receipt.providerRunId) === String(verifiedAdmission.providerRunId)
    && Number(receipt.providerRunAttempt) === Number(verifiedAdmission.providerRunAttempt),
  );
}
