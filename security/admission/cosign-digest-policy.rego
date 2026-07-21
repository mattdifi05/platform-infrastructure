package platform.admission

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
  input.kind == "Deployment"
  msg := "EXTERNAL-PENDING: repository policy has no trusted admission-controller verifier channel; self-asserted annotations are never accepted"
}
