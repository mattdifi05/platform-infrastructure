package stexor.admission

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not contains(container.image, "@sha256:")
  msg := sprintf("container %s image must be digest-pinned", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf("container %s image must not use :latest", [container.name])
}

deny[msg] {
  input.metadata.annotations["cosign.sigstore.dev/verified"] != "true"
  msg := "deployment must be admitted only after cosign signature verification"
}

deny[msg] {
  input.metadata.annotations["slsa.dev/provenance"] != "verified"
  msg := "deployment must include verified SLSA provenance"
}
