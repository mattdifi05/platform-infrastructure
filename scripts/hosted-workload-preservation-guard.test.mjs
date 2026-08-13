#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const gatePath = path.join(import.meta.dirname, "hosted-workload-activation-gate.sh");
const gateSource = fs.readFileSync(gatePath, "utf8");
const authorityBoundaryFunctions = extractSection(
  gateSource,
  "canonical_host_path",
  "assert_project_preservation_boundary",
);
const guardFunction = extractFunction(
  gateSource,
  "assert_project_preservation_boundary",
  "assert_candidate_resource_boundary",
);
const resourceBoundaryFunction = extractSection(
  gateSource,
  "normalize_transaction_volume_inspection",
  "canonical_file",
);
const resourceRecoveryFunctions = resourceBoundaryFunction;
const bindTransactionModelFunction = extractFunction(
  gateSource,
  "bind_transaction_runtime_model",
  "verify_release_context_unchanged",
);
const registerFunction = extractFunction(
  gateSource,
  "register_transaction_created_containers",
  "create_services",
);
const createFunction = extractFunction(
  gateSource,
  "create_services",
  "start_services",
);
const startFunction = extractFunction(
  gateSource,
  "start_services",
  "stop_and_prove",
);
const stopTransactionFunction = extractFunction(
  gateSource,
  "stop_transaction_created_and_prove",
  "remove_transaction_created_and_prove",
);
const removeTransactionFunction = extractFunction(
  gateSource,
  "remove_transaction_created_and_prove",
  "cleanup",
);

test("preservation guard is ahead of every legacy mutation boundary", () => {
  assert.ok(guardFunction, "assert_project_preservation_boundary() is missing");
  const mainStart = gateSource.indexOf("for command in awk bash docker");
  assert.notEqual(mainStart, -1, "activation main boundary is missing");
  const main = gateSource.slice(mainStart);
  const guardCall = main.indexOf("assert_project_preservation_boundary || exit 70");
  const authorityCall = main.indexOf("assert_global_docker_authority_boundary || exit 70");
  assert.notEqual(guardCall, -1, "the preservation guard is not invoked fail-closed");
  assert.notEqual(authorityCall, -1, "the global Docker authority guard is not invoked fail-closed");
  for (const marker of [
    "previous_journal=$(state_read_optional journal.json)",
    "journal_phase intent",
    "create_services \"$CURRENT_RUNTIME_MODEL\"",
    "firewall preflight",
    "start_services_ordered \"$CURRENT_RUNTIME_MODEL\"",
  ]) {
    const boundary = main.indexOf(marker);
    assert.notEqual(boundary, -1, `activation boundary is missing: ${marker}`);
    assert.ok(guardCall < boundary, `preservation guard follows ${marker}`);
    assert.ok(authorityCall < boundary, `global Docker authority guard follows ${marker}`);
  }
  assert.doesNotMatch(gateSource, /stop_entire_project_for_recovery\s*\(\)/);
  assert.doesNotMatch(gateSource, /remove_stale_project_containers\s*\(\)/);
  assert.ok(registerFunction, "transaction container registration is missing");
  assert.ok(createFunction, "create_services() is missing");
  const createGuard = createFunction.indexOf("assert_project_preservation_boundary");
  const createAuthorityGuard = createFunction.indexOf("assert_global_docker_authority_boundary");
  const composeCreate = createFunction.indexOf(" compose --project-directory");
  assert.notEqual(createGuard, -1);
  assert.notEqual(createAuthorityGuard, -1);
  assert.notEqual(composeCreate, -1);
  assert.ok(
    createGuard < composeCreate,
    "create_services does not recheck the exact-empty boundary immediately before Compose",
  );
  assert.ok(
    createAuthorityGuard < composeCreate,
    "create_services does not recheck all container Docker authority immediately before Compose",
  );
  assert.match(createFunction, /create .*--no-recreate/);
  assert.match(createFunction, /unset COMPOSE_REMOVE_ORPHANS/);
  assert.match(gateSource, /com\.platform\.activation\.transaction-id/);
  assert.match(gateSource, /com\.platform\.activation\.source-model-sha256/);
  assert.ok(bindTransactionModelFunction, "transaction runtime-model derivation is missing");
  const bindCall = main.indexOf("bind_transaction_runtime_model \"$CURRENT_RUNTIME_MODEL\"");
  const currentCreateCall = main.indexOf("create_services \"$CURRENT_RUNTIME_MODEL\"");
  assert.notEqual(bindCall, -1);
  assert.notEqual(currentCreateCall, -1);
  assert.ok(
    bindCall < currentCreateCall,
    "the transaction label is not bound before create",
  );
  assert.ok(resourceBoundaryFunction, "candidate volume/network collision boundary is missing");
  const resourceCall = main.indexOf("assert_candidate_resource_boundary \"$CURRENT_RUNTIME_MODEL\"");
  assert.notEqual(resourceCall, -1);
  assert.ok(resourceCall < main.indexOf("firewall preflight"));
  assert.ok(resourceCall < main.indexOf("journal_phase intent"));
  assert.ok(resourceCall < currentCreateCall);
  assert.match(registerFunction, /docker --host .* inspect/s);
  assert.match(registerFunction, /Config\.Image/);
  assert.match(registerFunction, /com\.docker\.compose\.service/);
  assert.match(registerFunction, /transactionLabel/);
  const registrationCall = createFunction.indexOf("register_transaction_created_containers");
  const resourceRegistrationCall = createFunction.indexOf("register_transaction_resources \"$model\"");
  assert.notEqual(resourceRegistrationCall, -1, "successful create does not register resource identities");
  assert.ok(
    composeCreate < resourceRegistrationCall && resourceRegistrationCall < registrationCall,
    "transaction resource CAS must be established before adopting created containers",
  );
  assert.match(
    createFunction,
    /register_transaction_resources "\$model" "\$registration_mode" "\$@"/,
    "resource registration must distinguish exact success from partial-create subset",
  );
  const createGlobalChecks = [...createFunction.matchAll(/assert_global_docker_authority_boundary/g)]
    .map((match) => match.index);
  assert.equal(createGlobalChecks.length, 2, "create must recheck global authority after registration");
  assert.ok(createGlobalChecks[1] > registrationCall);
  assert.ok(startFunction, "start_services() is missing");
  const startGlobalChecks = [...startFunction.matchAll(/assert_global_docker_authority_boundary \"\$model\"/g)]
    .map((match) => match.index);
  const startResourceChecks = [...startFunction.matchAll(/assert_registered_transaction_resources/g)]
    .map((match) => match.index);
  const dockerStart = startFunction.indexOf("docker --host \"$CANONICAL_DOCKER_HOST\" start");
  assert.notEqual(dockerStart, -1);
  assert.equal(startGlobalChecks.length, 2, "start must bracket mutation with global authority checks");
  assert.equal(startResourceChecks.length, 2, "start must bracket mutation with resource CAS checks");
  assert.ok(startGlobalChecks[0] < dockerStart && dockerStart < startGlobalChecks[1]);
  assert.ok(startResourceChecks[0] < dockerStart && dockerStart < startResourceChecks[1]);
  const orderedFunction = extractFunction(
    gateSource,
    "start_services_ordered",
    "verify_exact_workload_inventory",
  );
  const healthCheck = orderedFunction.indexOf("verify_running_services");
  assert.ok(healthCheck >= 0);
  assert.ok(
    orderedFunction.indexOf("assert_registered_transaction_resources", healthCheck) > healthCheck,
    "resource CAS is not revalidated after the health boundary",
  );
  assert.ok(
    orderedFunction.indexOf("assert_global_docker_authority_boundary \"$model\"", healthCheck) > healthCheck,
    "global Docker authority is not revalidated after the health boundary",
  );
  const transactionStop = stopTransactionFunction.indexOf("docker --host \"$CANONICAL_DOCKER_HOST\" stop");
  const stopResourceChecks = [...stopTransactionFunction.matchAll(/assert_registered_transaction_resources/g)]
    .map((match) => match.index);
  assert.ok(stopResourceChecks.some((index) => index < transactionStop));
  assert.ok(stopResourceChecks.some((index) => index > transactionStop));
  const transactionRemove = removeTransactionFunction.indexOf("docker --host \"$CANONICAL_DOCKER_HOST\" rm");
  const removeResourceChecks = [...removeTransactionFunction.matchAll(/assert_registered_transaction_resources/g)]
    .map((match) => match.index);
  assert.ok(removeResourceChecks.some((index) => index < transactionRemove));
  assert.ok(removeResourceChecks.some((index) => index > transactionRemove));
  const cleanupStart = gateSource.indexOf("cleanup() {");
  const cleanupEnd = gateSource.indexOf("\n}\nsignal_failure()", cleanupStart);
  assert.notEqual(cleanupStart, -1);
  assert.notEqual(cleanupEnd, -1);
  const cleanup = gateSource.slice(cleanupStart, cleanupEnd);
  assert.match(cleanup, /stop_transaction_created_and_prove/);
  assert.doesNotMatch(cleanup, /rollback_no_hosted|stop_all_known_and_prove|stop_and_prove/);
});

test("foreign-project raw Docker and host-parent owners stop with zero mutation", () => {
  assert.ok(authorityBoundaryFunctions, "global Docker authority boundary is missing");
  for (const source of [
    "/run/docker.sock",
    "/var/run",
    "/",
    "/var/lib/docker",
    "/var/lib",
  ]) {
    const fixture = authorityFixture(source);
    try {
      const result = runAuthorityBoundary(fixture);
      assert.equal(result.status, 70, `${source}: ${result.stderr}`);
      assert.match(result.stderr, /Docker socket or host-parent authority/i);
      const trace = fs.readFileSync(fixture.trace, "utf8");
      assert.match(trace, / ps -aq --no-trunc$/m);
      assert.match(trace, / inspect [a-f0-9]{64}$/m);
      assert.doesNotMatch(trace, /(?:^|\s)(?:create|start|stop|rm|down|prune)(?:\s|$)/m);
      assert.doesNotMatch(trace, /--remove-orphans|volume rm|system prune|volume prune/);
      assert.equal(fs.existsSync(fixture.mutationSentinel), false);
    } finally {
      fs.rmSync(fixture.root, { recursive: true, force: true });
    }
  }
});

test("global Docker authority inventory races and malformed inspection fail closed", () => {
  assert.ok(authorityBoundaryFunctions, "global Docker authority boundary is missing");
  for (const mode of ["inventory-race", "malformed-inspection"]) {
    const fixture = authorityFixture("/srv/application-data", mode);
    try {
      const result = runAuthorityBoundary(fixture);
      assert.equal(result.status, 70, `${mode}: ${result.stderr}`);
      assert.doesNotMatch(fs.readFileSync(fixture.trace, "utf8"), /(?:^|\s)(?:create|start|stop|rm|down|prune)(?:\s|$)/m);
      assert.equal(fs.existsSync(fixture.mutationSentinel), false);
    } finally {
      fs.rmSync(fixture.root, { recursive: true, force: true });
    }
  }
});

test("named volumes and Docker-root descendants are not mistaken for host-parent authority", () => {
  for (const [source, mode] of [
    ["/var/lib/docker/volumes/application_data/_data", "named-volume"],
    ["/var/lib/docker/containers", "authority"],
  ]) {
    const fixture = authorityFixture(source, mode);
    try {
      const result = runAuthorityBoundary(fixture);
      assert.equal(result.status, 0, `${source}: ${result.stderr}`);
      assert.doesNotMatch(fs.readFileSync(fixture.trace, "utf8"), /(?:^|\s)(?:create|start|stop|rm|down|prune)(?:\s|$)/m);
    } finally {
      fs.rmSync(fixture.root, { recursive: true, force: true });
    }
  }
});

test("path normalization uses isolated fixed Python despite poisoned cwd and PATH", () => {
  const fixture = authorityFixture("/srv/application-data", "poison-python");
  const poisonMarker = path.join(fixture.root, "python-poisoned");
  try {
    fs.writeFileSync(path.join(fixture.root, "sitecustomize.py"), `open(${JSON.stringify(poisonMarker)}, "w").write("cwd\\n")\n`);
    fs.writeFileSync(path.join(fixture.fakeBin, "python3"), `#!/bin/sh\nprintf 'path\\n' > ${JSON.stringify(poisonMarker)}\nexit 91\n`, { mode: 0o755 });
    const result = runAuthorityBoundary(fixture);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.existsSync(poisonMarker), false);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("34 legacy containers fail closed without touching containers, firewall, volumes, or binds", () => {
  assert.ok(guardFunction, "assert_project_preservation_boundary() is missing");
  const fixture = preservationFixture({ legacyContainers: 34, volumes: 139 });
  try {
    const result = runGuard(fixture, false);
    assert.equal(result.status, 70, result.stderr);
    assert.match(result.stderr, /pre-existing project container/i);
    const trace = fs.readFileSync(fixture.trace, "utf8");
    assert.match(trace, / ps -aq --no-trunc --filter label=com\.docker\.compose\.project=platform_infra_vps/);
    assert.doesNotMatch(trace, /(?:^|\s)(?:stop|start|rm|create|down|prune)(?:\s|$)/m);
    assert.doesNotMatch(trace, /--remove-orphans|volume rm|system prune|volume prune/);
    assert.doesNotMatch(trace, /^sudo:/m);
    assert.equal(fs.existsSync(fixture.laterSentinel), false);
    assert.equal(fs.readFileSync(fixture.bindSentinel, "utf8"), "uploaded-user-data\n");
    assert.equal(countVolumeSentinels(fixture.volumeRoot), 139);
    assert.equal(fs.existsSync(fixture.firewallSentinel), false);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("an empty greenfield project reaches the next sentinel without global Docker calls", () => {
  assert.ok(guardFunction, "assert_project_preservation_boundary() is missing");
  const fixture = preservationFixture({ legacyContainers: 0, volumes: 139 });
  try {
    const result = runGuard(fixture, true);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.readFileSync(fixture.laterSentinel, "utf8"), "later-boundary\n");
    const trace = fs.readFileSync(fixture.trace, "utf8");
    assert.match(trace, / ps -aq --no-trunc --filter label=com\.docker\.compose\.project=platform_infra_vps/);
    assert.doesNotMatch(trace, /(?:^|\s)(?:stop|start|rm|create|down|prune)(?:\s|$)/m);
    assert.doesNotMatch(trace, /--remove-orphans/);
    assert.doesNotMatch(trace, /^sudo:/m);
    assert.equal(fs.readFileSync(fixture.bindSentinel, "utf8"), "uploaded-user-data\n");
    assert.equal(countVolumeSentinels(fixture.volumeRoot), 139);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("a same-project service collision cannot be adopted as transaction-owned", () => {
  const fixture = transactionFixture({ authenticated: false });
  try {
    const result = runCreate(fixture);
    assert.notEqual(result.status, 0, result.stderr);
    assert.match(result.stderr, /transaction|ownership|identity/i);
    assert.match(fs.readFileSync(fixture.trace, "utf8"), / create .*--no-recreate/);
    assert.equal(result.stdout.includes("registered:"), false);
    assert.doesNotMatch(fs.readFileSync(fixture.trace, "utf8"), /(?:^|\s)(?:stop|rm|down|prune)(?:\s|$)/m);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("only an exact transaction-labelled created container is registered", () => {
  const fixture = transactionFixture({ authenticated: true });
  try {
    const result = runCreate(fixture);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /registered:cid-database/);
    assert.match(fs.readFileSync(fixture.trace, "utf8"), / create .*--no-recreate/);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("successful create registers exact transaction-owned volume and network CAS", () => {
  const fixture = transactionFixture({ authenticated: true, resourceRace: "exact" });
  try {
    const result = runCreate(fixture);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /registered-resources:1:1/);
    const trace = fs.readFileSync(fixture.trace, "utf8");
    const createIndex = trace.search(/ compose .* create /);
    const volumeInspectIndex = trace.indexOf(" volume inspect platform_infra_vps_data", createIndex);
    const networkInspectIndex = trace.indexOf(" network inspect platform_infra_vps_private", createIndex);
    assert.ok(createIndex >= 0 && volumeInspectIndex > createIndex && networkInspectIndex > createIndex);
    assert.doesNotMatch(trace, /(?:^|\s)(?:start|stop|rm|down|prune)(?:\s|$)/m);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("successful Compose resource races with foreign labels fail before container cleanup or start", () => {
  for (const resourceRace of ["volume-label", "network-label"]) {
    const fixture = transactionFixture({ authenticated: true, resourceRace });
    try {
      const result = runCreate(fixture);
      assert.notEqual(result.status, 0, `${resourceRace}: expected fail-closed`);
      assert.match(result.stderr, /not exact transaction-owned state|resource CAS/i);
      const trace = fs.readFileSync(fixture.trace, "utf8");
      assert.match(trace, / compose .* create /);
      assert.doesNotMatch(trace, /(?:^|\s)(?:start|stop|rm|down|prune)(?:\s|$)/m);
      assert.doesNotMatch(trace, /volume rm|network rm|--remove-orphans/);
    } finally {
      fs.rmSync(fixture.root, { recursive: true, force: true });
    }
  }
});

test("successful create fails when a used model resource is missing from Engine state", () => {
  const fixture = transactionFixture({ authenticated: true, resourceRace: "missing" });
  try {
    const result = runCreate(fixture);
    assert.notEqual(result.status, 0, "missing used volume/network were accepted as empty CAS");
    assert.match(result.stderr, /missing|exact resource|projection/i);
    const trace = fs.readFileSync(fixture.trace, "utf8");
    assert.match(trace, / compose .* create /);
    assert.doesNotMatch(trace, /(?:^|\s)(?:start|stop|rm|down|prune)(?:\s|$)/m);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("successful create rejects a container mounted to the wrong named-volume identity", () => {
  const fixture = transactionFixture({ authenticated: true, resourceRace: "mount-mismatch" });
  try {
    const result = runCreate(fixture);
    assert.notEqual(result.status, 0, "wrong container mount identity was accepted");
    assert.match(result.stderr, /container identities|mount|ownership/i);
    const trace = fs.readFileSync(fixture.trace, "utf8");
    assert.match(trace, / compose .* create /);
    assert.doesNotMatch(trace, /(?:^|\s)(?:start|stop|rm|down|prune)(?:\s|$)/m);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("container CAS accepts the exact broker socket bind with Docker default rprivate propagation", () => {
  const fixture = transactionFixture({ authenticated: true });
  try {
    const modelValue = JSON.parse(fs.readFileSync(fixture.model, "utf8"));
    modelValue.services["docker-action-broker"] = {
      ...modelValue.services.database,
      volumes: [{
        type: "bind",
        source: "/var/run/docker.sock",
        target: "/var/run/docker.sock",
        read_only: true,
        bind: { create_host_path: false },
      }],
    };
    delete modelValue.services.database;
    fs.writeFileSync(fixture.model, JSON.stringify(modelValue));
    const inspection = JSON.parse(fs.readFileSync(fixture.inspection, "utf8"));
    inspection[0].Config.Labels["com.docker.compose.service"] = "docker-action-broker";
    inspection[0].Mounts = [{
      Type: "bind",
      Source: "/var/run/docker.sock",
      Destination: "/var/run/docker.sock",
      RW: false,
      Propagation: "rprivate",
    }];
    fs.writeFileSync(fixture.inspection, JSON.stringify(inspection));
    fixture.releaseContext = JSON.stringify({ subjects: [{
      serviceName: "docker-action-broker",
      imageReference: inspection[0].Config.Image,
      imageId: inspection[0].Image,
    }] });
    fs.writeFileSync(fixture.state, "cid-database\n");
    const result = runContainerRegistration(fixture, "docker-action-broker");
    assert.equal(result.status, 0, result.stderr);
    const cas = JSON.parse(result.stdout);
    assert.deepEqual(cas[0].mounts, [{
      type: "bind",
      source: "/var/run/docker.sock",
      target: "/var/run/docker.sock",
      rw: false,
      propagation: "rprivate",
    }]);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("a partial Compose create failure discovers, stops, and removes only its exact transaction subset", () => {
  assert.ok(removeTransactionFunction, "exact transaction container removal is missing");
  const fixture = transactionFixture({ authenticated: true, partialFailure: true });
  try {
    const result = runCreateWithFailureCleanup(fixture);
    assert.equal(
      result.status,
      72,
      `${result.stderr}\nTRACE:\n${fs.readFileSync(fixture.trace, "utf8")}`,
    );
    const trace = fs.readFileSync(fixture.trace, "utf8");
    assert.match(trace, / create .*database worker/);
    assert.match(trace, / stop --time 30 cid-database$/m);
    assert.match(trace, / rm cid-database$/m);
    assert.doesNotMatch(trace, /volume rm|network rm|down|prune|--remove-orphans/);
    assert.equal(fs.readFileSync(fixture.state, "utf8"), "");
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("an unknown container racing a partial create causes zero cleanup", () => {
  const fixture = transactionFixture({ authenticated: true, partialFailure: true, unknownAddition: true });
  try {
    const result = runCreateWithFailureCleanup(fixture);
    assert.notEqual(result.status, 0);
    const trace = fs.readFileSync(fixture.trace, "utf8");
    assert.match(trace, / create .*database worker/);
    assert.doesNotMatch(trace, /(?:^|\s)(?:stop|rm)(?:\s|$)/m);
    assert.match(fs.readFileSync(fixture.state, "utf8"), /cid-foreign/);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("foreign raw authority racing after successful create blocks start with zero later mutation", () => {
  for (const source of ["/var/run/docker.sock", "/"]) {
    const fixture = transactionFixture({ authenticated: true, foreignAuthoritySource: source });
    try {
      const result = runCreateThenStart(fixture);
      assert.equal(result.status, 70, `${source}: ${result.stderr}`);
      const trace = fs.readFileSync(fixture.trace, "utf8");
      const createIndex = trace.search(/ compose .* create /);
      const laterGlobalInventory = trace.indexOf(" ps -aq --no-trunc\n", createIndex);
      assert.ok(createIndex >= 0 && laterGlobalInventory > createIndex);
      assert.ok(
        (trace.slice(createIndex).match(/^docker:.* ps -aq --no-trunc$/gm) || []).length >= 2,
        "post-create global inventory was not snapshot/reinspected",
      );
      assert.match(trace, / inspect cid-database cid-raw-foreign$/m);
      assert.doesNotMatch(trace, /(?:^|\s)start(?:\s|$)/m);
      assert.doesNotMatch(trace, /(?:^|\s)(?:stop|rm|down|prune)(?:\s|$)/m);
    } finally {
      fs.rmSync(fixture.root, { recursive: true, force: true });
    }
  }
});

test("foreign raw authority appearing during start fails closed and cleanup stops only transaction IDs", () => {
  for (const source of ["/var/run/docker.sock", "/"]) {
    const fixture = transactionFixture({ authenticated: true, foreignDuringStartSource: source });
    try {
      const result = runCreateStartWithFailureCleanup(fixture);
      assert.equal(result.status, 72, `${source}: ${result.stderr}`);
      const trace = fs.readFileSync(fixture.trace, "utf8");
      const startIndex = trace.search(/ start cid-database$/m);
      const postStartInventory = trace.indexOf(" ps -aq --no-trunc\n", startIndex);
      assert.ok(startIndex >= 0 && postStartInventory > startIndex);
      assert.match(trace, / inspect cid-database cid-raw-foreign$/m);
      assert.match(trace, / stop --time 30 cid-database$/m);
      assert.doesNotMatch(trace, /stop .*cid-raw-foreign|(?:^|\s)rm(?:\s|$)|down|prune|--remove-orphans/m);
      assert.match(fs.readFileSync(fixture.state, "utf8"), /^cid-database$/m);
      assert.equal(fs.existsSync(fixture.foreignActive), true);
    } finally {
      fs.rmSync(fixture.root, { recursive: true, force: true });
    }
  }
});

test("the transaction model derivation adds only the exact transaction label", () => {
  assert.ok(bindTransactionModelFunction);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hosted-preservation-model-"));
  try {
    const source = path.join(root, "source.json");
    const output = path.join(root, "transaction.json");
    const transactionId = "f".repeat(64);
    const sourceModel = {
      services: {
        database: { image: "example.invalid/database@sha256:a" },
        worker: { image: "example.invalid/worker@sha256:b", labels: { existing: "preserve" } },
      },
      volumes: { data: {} },
      networks: { private: { internal: true } },
    };
    fs.writeFileSync(source, JSON.stringify(sourceModel));
    const result = runTransactionModel(source, output, transactionId);
    assert.equal(result.status, 0, result.stderr);
    const derived = JSON.parse(fs.readFileSync(output, "utf8"));
    for (const definition of Object.values(derived.services)) {
      assert.equal(definition.labels["com.platform.activation.transaction-id"], transactionId);
      assert.match(definition.labels["com.platform.activation.source-model-sha256"], /^[a-f0-9]{64}$/);
    }
    delete derived.services.database.labels["com.platform.activation.transaction-id"];
    delete derived.services.database.labels["com.platform.activation.source-model-sha256"];
    delete derived.services.database.labels;
    delete derived.services.worker.labels["com.platform.activation.transaction-id"];
    delete derived.services.worker.labels["com.platform.activation.source-model-sha256"];
    assert.equal(derived.volumes.data.labels["com.platform.activation.transaction-id"], transactionId);
    assert.equal(derived.networks.private.labels["com.platform.activation.transaction-id"], transactionId);
    delete derived.volumes.data.labels["com.platform.activation.transaction-id"];
    delete derived.volumes.data.labels["com.platform.activation.source-model-sha256"];
    delete derived.volumes.data.labels;
    delete derived.networks.private.labels["com.platform.activation.transaction-id"];
    delete derived.networks.private.labels["com.platform.activation.source-model-sha256"];
    delete derived.networks.private.labels;
    assert.deepEqual(derived, sourceModel);

    const forged = path.join(root, "forged.json");
    fs.writeFileSync(forged, JSON.stringify({
      services: {
        database: {
          image: "example.invalid/database@sha256:a",
          labels: { "com.platform.activation.transaction-id": "0".repeat(64) },
        },
      },
    }));
    assert.notEqual(runTransactionModel(forged, path.join(root, "rejected.json"), transactionId).status, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("persistent resource collisions stop a container-empty project", () => {
  assert.ok(resourceBoundaryFunction);
  for (const collision of [
    "volume",
    "network",
    "external-volume",
    "rw-bind",
    "rw-bind-absent",
    "read-only-bind-absent",
    "symlink-parent",
    "socket-impostor",
    "aliased-socket",
  ]) {
    const fixture = resourceFixture(collision);
    try {
      const result = runResourceBoundary(fixture);
      assert.equal(result.status, 70, `${collision}: ${result.stderr}`);
      assert.match(result.stderr, /candidate-owned .* already exists|external persistent volume|writable bind|Docker socket or host-parent|canonical|read-only bind source/i);
      assert.doesNotMatch(fs.readFileSync(fixture.trace, "utf8"), /(?:^|\s)(?:create|start|stop|rm|down|prune)(?:\s|$)/m);
    } finally {
      fs.rmSync(fixture.root, { recursive: true, force: true });
    }
  }
});

test("same-transaction resource CAS permits retry but rejects identity drift without mutation", () => {
  assert.ok(
    resourceRecoveryFunctions?.includes("register_transaction_resources()"),
    "transaction resource registration is missing",
  );
  for (const drift of ["none", "network-id", "volume-label"]) {
    const fixture = transactionResourceFixture(drift);
    try {
      const result = runTransactionResourceRetry(fixture);
      if (drift === "none") assert.equal(result.status, 0, result.stderr);
      else assert.equal(result.status, 70, `${drift}: ${result.stderr}`);
      const trace = fs.readFileSync(fixture.trace, "utf8");
      assert.doesNotMatch(trace, /(?:^|\s)(?:create|start|stop|rm|down|prune)(?:\s|$)/m);
      assert.doesNotMatch(trace, /volume rm|network rm|--remove-orphans/);
    } finally {
      fs.rmSync(fixture.root, { recursive: true, force: true });
    }
  }
});

test("partial-create resource CAS extends monotonically from subset to exact on retry", () => {
  const fixture = transactionResourceFixture("none");
  try {
    const result = runTransactionResourceExtension(fixture);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /subset:1:0/);
    assert.match(result.stdout, /exact:1:1/);
    const trace = fs.readFileSync(fixture.trace, "utf8");
    assert.doesNotMatch(trace, /(?:^|\s)(?:create|start|stop|rm|down|prune)(?:\s|$)/m);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("the release-bound exact broker model is necessary for candidate raw-socket authority", () => {
  const fixture = resourceFixture("authorized-broker-socket");
  try {
    const result = runBrokerContract(fixture);
    assert.equal(result.status, 0, result.stderr);
    assert.match(resourceBoundaryFunction, /-S "\$source"/);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("an exact read-only bind remains eligible in an otherwise empty control fixture", () => {
  const fixture = resourceFixture("read-only-bind");
  try {
    const result = runResourceBoundary(fixture);
    assert.equal(result.status, 0, result.stderr);
    assert.doesNotMatch(fs.readFileSync(fixture.trace, "utf8"), /(?:^|\s)(?:create|start|stop|rm|down|prune)(?:\s|$)/m);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("cleanup stops the exact registered CAS identity and refuses an added unknown", () => {
  assert.ok(stopTransactionFunction);
  const exact = transactionFixture({ authenticated: true });
  try {
    fs.writeFileSync(exact.state, "cid-database\n");
    const result = runCleanup(exact);
    assert.equal(result.status, 0, result.stderr);
    assert.match(fs.readFileSync(exact.trace, "utf8"), / stop --time 30 cid-database$/m);
  } finally {
    fs.rmSync(exact.root, { recursive: true, force: true });
  }

  const raced = transactionFixture({ authenticated: true });
  try {
    fs.writeFileSync(raced.state, "cid-database\ncid-foreign\n");
    const result = runCleanup(raced);
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(fs.readFileSync(raced.trace, "utf8"), / stop --time 30 /);
  } finally {
    fs.rmSync(raced.root, { recursive: true, force: true });
  }
});

function extractFunction(source, name, nextName) {
  const start = source.indexOf(`${name}() {`);
  if (start === -1) return null;
  const endMarker = `\n}\n\n${nextName}()`;
  const end = source.indexOf(endMarker, start);
  if (end === -1) return null;
  return source.slice(start, end + 2);
}

function extractSection(source, firstName, nextName) {
  const start = source.indexOf(`${firstName}() {`);
  const end = source.indexOf(`\n${nextName}() {`, start);
  if (start === -1 || end === -1) return null;
  return source.slice(start, end);
}

function authorityFixture(source, mode = "authority") {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-global-authority-")));
  const fakeBin = path.join(root, "bin");
  const trace = path.join(root, "docker.trace");
  const inventoryCount = path.join(root, "inventory-count");
  const inspection = path.join(root, "inspection.json");
  const mutationSentinel = path.join(root, "mutation-called");
  const id = "a".repeat(64);
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(trace, "");
  fs.writeFileSync(inventoryCount, "0\n");
  fs.writeFileSync(inspection, mode === "malformed-inspection" ? "{not-json\n" : JSON.stringify([{
    Id: id,
    Config: { Labels: { "com.docker.compose.project": "foreign_project" } },
    Mounts: [{ Type: mode === "named-volume" ? "volume" : "bind", Source: source, Destination: "/mnt/host", RW: false }],
  }]));
  fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh
set -eu
printf 'docker:%s\\n' "$*" >> "$HOSTED_TEST_DOCKER_TRACE"
case " $* " in
  *" info --format {{.DockerRootDir}} "*) printf '/var/lib/docker\\n' ;;
  *" ps -aq --no-trunc "*)
    count=$(cat "$HOSTED_TEST_INVENTORY_COUNT")
    count=$((count + 1))
    printf '%s\\n' "$count" > "$HOSTED_TEST_INVENTORY_COUNT"
    if [ "$HOSTED_TEST_MODE" = inventory-race ] && [ "$count" -gt 1 ]; then
      printf '%s\\n' '${"b".repeat(64)}'
    else
      printf '%s\\n' '${id}'
    fi
    ;;
  *" inspect ${id} "*) cat "$HOSTED_TEST_INSPECTION" ;;
  *" create "*|*" start "*|*" stop "*|*" rm "*|*" down "*|*" prune "*)
    : > "$HOSTED_TEST_MUTATION_SENTINEL"
    exit 97
    ;;
  *) exit 97 ;;
esac
`, { mode: 0o755 });
  fs.writeFileSync(path.join(fakeBin, "timeout"), "#!/bin/sh\nshift\nexec \"$@\"\n", { mode: 0o755 });
  return { root, fakeBin, trace, inventoryCount, inspection, mutationSentinel, mode };
}

function runAuthorityBoundary(fixture) {
  return spawnSync("/bin/bash", [
    "-c",
    `set -euo pipefail
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock
VERIFY_TIMEOUT=5
${authorityBoundaryFunctions}
status=0
assert_global_docker_authority_boundary || status=$?
exit "$status"
`,
    "global-authority-guard",
  ], {
    encoding: "utf8",
    cwd: fixture.root,
    env: {
      ...process.env,
      PATH: `${fixture.fakeBin}:/usr/bin:/bin`,
      HOSTED_TEST_DOCKER_TRACE: fixture.trace,
      HOSTED_TEST_INVENTORY_COUNT: fixture.inventoryCount,
      HOSTED_TEST_INSPECTION: fixture.inspection,
      HOSTED_TEST_MUTATION_SENTINEL: fixture.mutationSentinel,
      HOSTED_TEST_MODE: fixture.mode,
    },
  });
}

function preservationFixture({ legacyContainers, volumes }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hosted-preservation-guard-"));
  const fakeBin = path.join(root, "bin");
  const trace = path.join(root, "docker.trace");
  const ids = path.join(root, "container-ids");
  const inventory = path.join(root, "container-inventory.json");
  const volumeRoot = path.join(root, "volumes");
  const bindRoot = path.join(root, "bind-data");
  const bindSentinel = path.join(bindRoot, "user-upload.bin");
  const firewallSentinel = path.join(root, "firewall-called");
  const laterSentinel = path.join(root, "later-boundary");
  fs.mkdirSync(fakeBin, { recursive: true });
  fs.mkdirSync(volumeRoot);
  fs.mkdirSync(bindRoot);
  fs.writeFileSync(trace, "");
  fs.writeFileSync(bindSentinel, "uploaded-user-data\n");

  const categories = ["database-postgres", "legacy-backend", "foreign-service", "orphan-service"];
  const containers = Array.from({ length: legacyContainers }, (_, index) => ({
    id: (index + 1).toString(16).padStart(64, "0"),
    name: categories[index] || `legacy-application-${String(index).padStart(2, "0")}`,
    project: "platform_infra_vps",
  }));
  fs.writeFileSync(ids, containers.map(({ id }) => id).join("\n") + (containers.length ? "\n" : ""));
  fs.writeFileSync(inventory, JSON.stringify(containers));
  for (let index = 0; index < volumes; index += 1) {
    const directory = path.join(volumeRoot, `volume-${String(index).padStart(3, "0")}`);
    fs.mkdirSync(directory);
    fs.writeFileSync(path.join(directory, "sentinel"), `preserve-${index}\n`);
  }

  fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh
set -eu
printf 'docker:%s\\n' "$*" >> "$HOSTED_TEST_DOCKER_TRACE"
case " $* " in
  *" ps -aq --no-trunc --filter label=com.docker.compose.project=platform_infra_vps "*)
    cat "$HOSTED_TEST_CONTAINER_IDS"
    ;;
  *" volume ls --format {{.Name}} "*|*" network ls --format {{.Name}} "*)
    ;;
  *)
    printf 'forbidden:%s\\n' "$*" >> "$HOSTED_TEST_DOCKER_TRACE"
    exit 97
    ;;
esac
`, { mode: 0o755 });
  fs.writeFileSync(path.join(fakeBin, "timeout"), `#!/bin/sh
set -eu
shift
exec "$@"
`, { mode: 0o755 });
  fs.writeFileSync(path.join(fakeBin, "sudo"), `#!/bin/sh
set -eu
printf 'sudo:%s\\n' "$*" >> "$HOSTED_TEST_DOCKER_TRACE"
: > "$HOSTED_TEST_FIREWALL_SENTINEL"
exit 97
`, { mode: 0o755 });
  return {
    root,
    fakeBin,
    trace,
    ids,
    inventory,
    volumeRoot,
    bindSentinel,
    firewallSentinel,
    laterSentinel,
  };
}

function runGuard(fixture, expectSuccess) {
  return spawnSync("/bin/bash", [
    "-c",
    `set -euo pipefail
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock
VERIFY_TIMEOUT=5
PROJECT_NAME=platform_infra_vps
EXPECTED_DAEMON_ID=test-daemon
TRANSACTION_CREATED_CONTAINER_IDS=()
${guardFunction}
status=0
assert_project_preservation_boundary || status=$?
if (( status == 0 )); then
  printf 'later-boundary\\n' > "$HOSTED_TEST_LATER_SENTINEL"
  exit 0
fi
exit "$status"
`,
    expectSuccess ? "greenfield-preservation-guard" : "legacy-preservation-guard",
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fixture.fakeBin}:/usr/bin:/bin`,
      HOSTED_TEST_DOCKER_TRACE: fixture.trace,
      HOSTED_TEST_CONTAINER_IDS: fixture.ids,
      HOSTED_TEST_LATER_SENTINEL: fixture.laterSentinel,
      HOSTED_TEST_FIREWALL_SENTINEL: fixture.firewallSentinel,
    },
  });
}

function transactionFixture({
  authenticated,
  partialFailure = false,
  unknownAddition = false,
  foreignAuthoritySource = "",
  foreignDuringStartSource = "",
  resourceRace = "none",
}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hosted-preservation-transaction-"));
  const fakeBin = path.join(root, "bin");
  const trace = path.join(root, "docker.trace");
  const state = path.join(root, "container-ids");
  const inspection = path.join(root, "inspection.json");
  const foreignInspection = path.join(root, "foreign-inspection.json");
  const foreignActive = path.join(root, "foreign-active");
  const resourceActive = path.join(root, "resource-active");
  const volumeInspection = path.join(root, "volume-inspection.json");
  const networkInspection = path.join(root, "network-inspection.json");
  const model = path.join(root, "transaction-model.json");
  const transactionId = "e".repeat(64);
  const imageReference = `example.invalid/database@sha256:${"a".repeat(64)}`;
  const imageId = `sha256:${"d".repeat(64)}`;
  const sourceModelSha256 = "b".repeat(64);
  const configHash = "c".repeat(64);
  const labels = {
    "com.platform.runtime.candidate-id": "candidate-fixture",
    "com.platform.activation.transaction-id": transactionId,
    "com.platform.activation.source-model-sha256": sourceModelSha256,
  };
  fs.mkdirSync(fakeBin, { recursive: true });
  fs.writeFileSync(trace, "");
  fs.writeFileSync(state, "");
  const workerImageReference = `example.invalid/worker@sha256:${"9".repeat(64)}`;
  const services = { database: { image: imageReference, labels } };
  if (partialFailure) services.worker = { image: workerImageReference, labels };
  const modelValue = { name: "platform_infra_vps", services };
  if (resourceRace !== "none") {
    services.database.volumes = [{
      type: "volume",
      source: "data",
      target: "/var/lib/example-data",
      read_only: false,
    }];
    services.database.networks = { private: null };
    modelValue.volumes = {
      data: { name: "platform_infra_vps_data", labels },
    };
    modelValue.networks = {
      private: { name: "platform_infra_vps_private", internal: true, labels },
    };
  }
  fs.writeFileSync(model, JSON.stringify(modelValue));
  fs.writeFileSync(inspection, JSON.stringify([{
    Id: "cid-database",
    Image: imageId,
    Config: {
      Image: imageReference,
      Labels: {
        "com.docker.compose.project": "platform_infra_vps",
        "com.docker.compose.service": "database",
        "com.docker.compose.config-hash": configHash,
        "com.platform.runtime.candidate-id": "candidate-fixture",
        ...(authenticated ? {
          "com.platform.activation.transaction-id": transactionId,
          "com.platform.activation.source-model-sha256": sourceModelSha256,
        } : {}),
      },
    },
    State: {
      Running: false,
      Paused: false,
      Restarting: false,
      Status: "created",
      StartedAt: "0001-01-01T00:00:00Z",
      FinishedAt: "0001-01-01T00:00:00Z",
    },
    Mounts: resourceRace === "none" ? [] : [{
      Type: "volume",
      Name: resourceRace === "mount-mismatch" ? "foreign_data" : "platform_infra_vps_data",
      Source: `/var/lib/docker/volumes/${resourceRace === "mount-mismatch" ? "foreign_data" : "platform_infra_vps_data"}/_data`,
      Destination: "/var/lib/example-data",
      RW: true,
    }],
    NetworkSettings: {
      Networks: resourceRace === "none" ? {} : { platform_infra_vps_private: {} },
    },
  }]));
  const rawAuthoritySource = foreignAuthoritySource || foreignDuringStartSource;
  fs.writeFileSync(foreignInspection, JSON.stringify([{
    Id: "cid-raw-foreign",
    Config: {
      Labels: {
        "com.docker.compose.project": "foreign_project",
        "com.docker.compose.service": "foreign-raw-owner",
      },
    },
    Mounts: rawAuthoritySource ? [{
      Type: "bind",
      Source: rawAuthoritySource,
      Destination: "/mnt/raw-host",
      RW: false,
    }] : [],
  }]));
  const volumeLabels = {
    "com.docker.compose.project": "platform_infra_vps",
    "com.docker.compose.version": "2.29.0",
    "com.docker.compose.volume": "data",
    ...labels,
  };
  if (resourceRace === "volume-label") {
    volumeLabels["com.platform.activation.source-model-sha256"] = "0".repeat(64);
  }
  fs.writeFileSync(volumeInspection, JSON.stringify([{
    Name: "platform_infra_vps_data",
    Driver: "local",
    Scope: "local",
    Labels: volumeLabels,
    Options: null,
    Mountpoint: "/var/lib/docker/volumes/platform_infra_vps_data/_data",
    CreatedAt: "2026-08-09T00:00:00Z",
  }]));
  const networkLabels = {
    "com.docker.compose.project": "platform_infra_vps",
    "com.docker.compose.version": "2.29.0",
    "com.docker.compose.network": "private",
    ...labels,
  };
  if (resourceRace === "network-label") {
    networkLabels["com.platform.activation.source-model-sha256"] = "0".repeat(64);
  }
  fs.writeFileSync(networkInspection, JSON.stringify([{
    Id: "network-private-id",
    Name: "platform_infra_vps_private",
    Driver: "bridge",
    Scope: "local",
    Internal: true,
    Attachable: false,
    Ingress: false,
    ConfigOnly: false,
    EnableIPv4: true,
    EnableIPv6: false,
    Labels: networkLabels,
    Options: null,
    IPAM: { Driver: "default", Options: null, Config: [] },
  }]));
  fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh
set -eu
printf 'docker:%s\\n' "$*" >> "$HOSTED_TEST_DOCKER_TRACE"
case " $* " in
  *" info --format {{.DockerRootDir}} "*)
    printf '/var/lib/docker\\n'
    ;;
  *" ps -aq --no-trunc "*"label=com.platform.activation.transaction-id="*)
    grep '^cid-database$' "$HOSTED_TEST_CONTAINER_IDS" || true
    ;;
  *" ps -aq --no-trunc "*"label=com.docker.compose.project=platform_infra_vps "*)
    cat "$HOSTED_TEST_CONTAINER_IDS"
    ;;
  *" ps -aq --no-trunc "*)
    cat "$HOSTED_TEST_CONTAINER_IDS"
    [ ! -e "$HOSTED_TEST_FOREIGN_ACTIVE" ] || printf 'cid-raw-foreign\\n'
    ;;
  *" compose "*" create "*)
    printf 'cid-database\\n' > "$HOSTED_TEST_CONTAINER_IDS"
    if [ "$HOSTED_TEST_RESOURCE_RACE" != none ] && [ "$HOSTED_TEST_RESOURCE_RACE" != missing ]; then
      : > "$HOSTED_TEST_RESOURCE_ACTIVE"
    fi
    if [ "$HOSTED_TEST_UNKNOWN_ADDITION" = 1 ]; then
      printf 'cid-foreign\\n' >> "$HOSTED_TEST_CONTAINER_IDS"
    fi
    if [ -n "$HOSTED_TEST_FOREIGN_AUTHORITY_SOURCE" ]; then
      : > "$HOSTED_TEST_FOREIGN_ACTIVE"
    fi
    [ "$HOSTED_TEST_PARTIAL_FAILURE" != 1 ] || exit 88
    ;;
  *" compose "*" ps -aq "*)
    cat "$HOSTED_TEST_CONTAINER_IDS"
    ;;
  *" volume ls --format {{.Name}} "*)
    [ ! -e "$HOSTED_TEST_RESOURCE_ACTIVE" ] || printf 'platform_infra_vps_data\\n'
    ;;
  *" network ls --format {{.Name}} "*)
    [ ! -e "$HOSTED_TEST_RESOURCE_ACTIVE" ] || printf 'platform_infra_vps_private\\n'
    ;;
  *" volume inspect platform_infra_vps_data "*)
    cat "$HOSTED_TEST_VOLUME_INSPECTION"
    ;;
  *" network inspect platform_infra_vps_private "*)
    cat "$HOSTED_TEST_NETWORK_INSPECTION"
    ;;
  *" inspect cid-database cid-raw-foreign "*)
    jq -s '.[0] + .[1]' "$HOSTED_TEST_INSPECTION" "$HOSTED_TEST_FOREIGN_INSPECTION"
    ;;
  *" inspect cid-database "*)
    grep -q '^cid-database$' "$HOSTED_TEST_CONTAINER_IDS" || exit 1
    cat "$HOSTED_TEST_INSPECTION"
    ;;
  *" start cid-database "*)
    if [ -n "$HOSTED_TEST_FOREIGN_DURING_START_SOURCE" ]; then
      : > "$HOSTED_TEST_FOREIGN_ACTIVE"
    fi
    ;;
  *" stop --time 30 cid-database "*)
    ;;
  *" rm cid-database "*)
    grep -v '^cid-database$' "$HOSTED_TEST_CONTAINER_IDS" > "$HOSTED_TEST_CONTAINER_IDS.next" || true
    mv "$HOSTED_TEST_CONTAINER_IDS.next" "$HOSTED_TEST_CONTAINER_IDS"
    ;;
  *)
    printf 'forbidden:%s\\n' "$*" >> "$HOSTED_TEST_DOCKER_TRACE"
    exit 97
    ;;
esac
`, { mode: 0o755 });
  fs.writeFileSync(path.join(fakeBin, "timeout"), `#!/bin/sh
set -eu
shift
exec "$@"
`, { mode: 0o755 });
  return {
    root,
    fakeBin,
    trace,
    state,
    inspection,
    foreignInspection,
    foreignActive,
    resourceActive,
    volumeInspection,
    networkInspection,
    model,
    transactionId,
    sourceModelSha256,
    configHash,
    partialFailure,
    unknownAddition,
    foreignAuthoritySource,
    foreignDuringStartSource,
    resourceRace,
    releaseContext: JSON.stringify({ subjects: [
      { serviceName: "database", imageReference, imageId },
      ...(partialFailure ? [{ serviceName: "worker", imageReference: workerImageReference, imageId }] : []),
    ].sort((left, right) => left.serviceName.localeCompare(right.serviceName)) }),
  };
}

function runCreate(fixture) {
  return spawnSync("/bin/bash", [
    "-c",
    `set -euo pipefail
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock
VERIFY_TIMEOUT=5
ACTIVATION_TIMEOUT=5
PROJECT_NAME=platform_infra_vps
INFRA_ROOT=$1
TRANSACTION_ID=$2
TRANSACTION_LABEL=com.platform.activation.transaction-id
TRANSACTION_MODEL_LABEL=com.platform.activation.source-model-sha256
TRANSACTION_SOURCE_MODEL_SHA256=$5
TRANSACTION_CONTAINER_CAS='[]'
TRANSACTION_VOLUME_CAS='[]'
TRANSACTION_NETWORK_CAS='[]'
TRANSACTION_CONTAINERS_REMOVABLE=0
RELEASE_CONTEXT_JSON=$3
TRANSACTION_CREATED_CONTAINER_IDS=()
assert_daemon_identity() { return 0; }
${authorityBoundaryFunctions}
${guardFunction}
${resourceBoundaryFunction}
${registerFunction}
${createFunction}
create_services "$4" database
printf 'registered:%s\\n' "\${TRANSACTION_CREATED_CONTAINER_IDS[*]}"
printf 'registered-resources:%s:%s\\n' \
  "$(printf '%s' "$TRANSACTION_VOLUME_CAS" | jq -r 'length')" \
  "$(printf '%s' "$TRANSACTION_NETWORK_CAS" | jq -r 'length')"
`,
    "transaction-create-guard",
    fixture.root,
    fixture.transactionId,
    fixture.releaseContext,
    fixture.model,
    fixture.sourceModelSha256,
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fixture.fakeBin}:/usr/bin:/bin`,
      HOSTED_TEST_DOCKER_TRACE: fixture.trace,
      HOSTED_TEST_CONTAINER_IDS: fixture.state,
      HOSTED_TEST_INSPECTION: fixture.inspection,
      HOSTED_TEST_FOREIGN_INSPECTION: fixture.foreignInspection,
      HOSTED_TEST_FOREIGN_ACTIVE: fixture.foreignActive,
      HOSTED_TEST_FOREIGN_AUTHORITY_SOURCE: fixture.foreignAuthoritySource,
      HOSTED_TEST_FOREIGN_DURING_START_SOURCE: fixture.foreignDuringStartSource,
      HOSTED_TEST_RESOURCE_ACTIVE: fixture.resourceActive,
      HOSTED_TEST_RESOURCE_RACE: fixture.resourceRace,
      HOSTED_TEST_VOLUME_INSPECTION: fixture.volumeInspection,
      HOSTED_TEST_NETWORK_INSPECTION: fixture.networkInspection,
      HOSTED_TEST_PARTIAL_FAILURE: fixture.partialFailure ? "1" : "0",
      HOSTED_TEST_UNKNOWN_ADDITION: fixture.unknownAddition ? "1" : "0",
      COMPOSE_REMOVE_ORPHANS: "1",
    },
  });
}

function runCreateWithFailureCleanup(fixture) {
  return spawnSync("/bin/bash", [
    "-c",
    `set -euo pipefail
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock
VERIFY_TIMEOUT=5
ACTIVATION_TIMEOUT=5
STOP_TIMEOUT=5
PROJECT_NAME=platform_infra_vps
INFRA_ROOT=$1
TRANSACTION_ID=$2
TRANSACTION_LABEL=com.platform.activation.transaction-id
TRANSACTION_MODEL_LABEL=com.platform.activation.source-model-sha256
TRANSACTION_SOURCE_MODEL_SHA256=$5
TRANSACTION_CONTAINER_CAS='[]'
TRANSACTION_VOLUME_CAS='[]'
TRANSACTION_NETWORK_CAS='[]'
TRANSACTION_CONTAINERS_REMOVABLE=0
RELEASE_CONTEXT_JSON=$3
TRANSACTION_CREATED_CONTAINER_IDS=()
assert_daemon_identity() { return 0; }
${authorityBoundaryFunctions}
${guardFunction}
${resourceBoundaryFunction}
${registerFunction}
${createFunction}
${stopTransactionFunction}
${removeTransactionFunction}
create_status=0
create_services "$4" database worker || create_status=$?
(( create_status != 0 )) || exit 91
if ((\${#TRANSACTION_CREATED_CONTAINER_IDS[@]} == 0)); then exit 73; fi
stop_transaction_created_and_prove || exit 73
remove_transaction_created_and_prove || exit 73
exit 72
`,
    "partial-transaction-create-guard",
    fixture.root,
    fixture.transactionId,
    fixture.releaseContext,
    fixture.model,
    fixture.sourceModelSha256,
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fixture.fakeBin}:/usr/bin:/bin`,
      HOSTED_TEST_DOCKER_TRACE: fixture.trace,
      HOSTED_TEST_CONTAINER_IDS: fixture.state,
      HOSTED_TEST_INSPECTION: fixture.inspection,
      HOSTED_TEST_FOREIGN_INSPECTION: fixture.foreignInspection,
      HOSTED_TEST_FOREIGN_ACTIVE: fixture.foreignActive,
      HOSTED_TEST_FOREIGN_AUTHORITY_SOURCE: fixture.foreignAuthoritySource,
      HOSTED_TEST_FOREIGN_DURING_START_SOURCE: fixture.foreignDuringStartSource,
      HOSTED_TEST_RESOURCE_ACTIVE: fixture.resourceActive,
      HOSTED_TEST_RESOURCE_RACE: fixture.resourceRace,
      HOSTED_TEST_VOLUME_INSPECTION: fixture.volumeInspection,
      HOSTED_TEST_NETWORK_INSPECTION: fixture.networkInspection,
      HOSTED_TEST_PARTIAL_FAILURE: fixture.partialFailure ? "1" : "0",
      HOSTED_TEST_UNKNOWN_ADDITION: fixture.unknownAddition ? "1" : "0",
      COMPOSE_REMOVE_ORPHANS: "1",
    },
  });
}

function runCreateThenStart(fixture) {
  return spawnSync("/bin/bash", [
    "-c",
    `set -euo pipefail
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock
VERIFY_TIMEOUT=5
ACTIVATION_TIMEOUT=5
PROJECT_NAME=platform_infra_vps
INFRA_ROOT=$1
TRANSACTION_ID=$2
TRANSACTION_LABEL=com.platform.activation.transaction-id
TRANSACTION_MODEL_LABEL=com.platform.activation.source-model-sha256
TRANSACTION_SOURCE_MODEL_SHA256=$5
TRANSACTION_CONTAINER_CAS='[]'
TRANSACTION_VOLUME_CAS='[]'
TRANSACTION_NETWORK_CAS='[]'
TRANSACTION_CONTAINERS_REMOVABLE=0
RELEASE_CONTEXT_JSON=$3
TRANSACTION_CREATED_CONTAINER_IDS=()
assert_daemon_identity() { return 0; }
${authorityBoundaryFunctions}
${guardFunction}
${resourceBoundaryFunction}
${registerFunction}
${createFunction}
${startFunction}
create_services "$4" database
start_services "$4" database
`,
    "post-create-authority-race",
    fixture.root,
    fixture.transactionId,
    fixture.releaseContext,
    fixture.model,
    fixture.sourceModelSha256,
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fixture.fakeBin}:/usr/bin:/bin`,
      HOSTED_TEST_DOCKER_TRACE: fixture.trace,
      HOSTED_TEST_CONTAINER_IDS: fixture.state,
      HOSTED_TEST_INSPECTION: fixture.inspection,
      HOSTED_TEST_FOREIGN_INSPECTION: fixture.foreignInspection,
      HOSTED_TEST_FOREIGN_ACTIVE: fixture.foreignActive,
      HOSTED_TEST_FOREIGN_AUTHORITY_SOURCE: fixture.foreignAuthoritySource,
      HOSTED_TEST_FOREIGN_DURING_START_SOURCE: fixture.foreignDuringStartSource,
      HOSTED_TEST_RESOURCE_ACTIVE: fixture.resourceActive,
      HOSTED_TEST_RESOURCE_RACE: fixture.resourceRace,
      HOSTED_TEST_VOLUME_INSPECTION: fixture.volumeInspection,
      HOSTED_TEST_NETWORK_INSPECTION: fixture.networkInspection,
      HOSTED_TEST_PARTIAL_FAILURE: "0",
      HOSTED_TEST_UNKNOWN_ADDITION: "0",
      COMPOSE_REMOVE_ORPHANS: "1",
    },
  });
}

function runCreateStartWithFailureCleanup(fixture) {
  return spawnSync("/bin/bash", [
    "-c",
    `set -euo pipefail
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock
VERIFY_TIMEOUT=5
ACTIVATION_TIMEOUT=5
STOP_TIMEOUT=5
PROJECT_NAME=platform_infra_vps
INFRA_ROOT=$1
TRANSACTION_ID=$2
TRANSACTION_LABEL=com.platform.activation.transaction-id
TRANSACTION_MODEL_LABEL=com.platform.activation.source-model-sha256
TRANSACTION_SOURCE_MODEL_SHA256=$5
TRANSACTION_CONTAINER_CAS='[]'
TRANSACTION_VOLUME_CAS='[]'
TRANSACTION_NETWORK_CAS='[]'
TRANSACTION_CONTAINERS_REMOVABLE=0
RELEASE_CONTEXT_JSON=$3
TRANSACTION_CREATED_CONTAINER_IDS=()
assert_daemon_identity() { return 0; }
${authorityBoundaryFunctions}
${guardFunction}
${resourceBoundaryFunction}
${registerFunction}
${createFunction}
${startFunction}
${stopTransactionFunction}
create_services "$4" database
start_status=0
start_services "$4" database || start_status=$?
(( start_status != 0 )) || exit 91
stop_transaction_created_and_prove || exit 73
exit 72
`,
    "post-start-authority-race",
    fixture.root,
    fixture.transactionId,
    fixture.releaseContext,
    fixture.model,
    fixture.sourceModelSha256,
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fixture.fakeBin}:/usr/bin:/bin`,
      HOSTED_TEST_DOCKER_TRACE: fixture.trace,
      HOSTED_TEST_CONTAINER_IDS: fixture.state,
      HOSTED_TEST_INSPECTION: fixture.inspection,
      HOSTED_TEST_FOREIGN_INSPECTION: fixture.foreignInspection,
      HOSTED_TEST_FOREIGN_ACTIVE: fixture.foreignActive,
      HOSTED_TEST_FOREIGN_AUTHORITY_SOURCE: fixture.foreignAuthoritySource,
      HOSTED_TEST_FOREIGN_DURING_START_SOURCE: fixture.foreignDuringStartSource,
      HOSTED_TEST_RESOURCE_ACTIVE: fixture.resourceActive,
      HOSTED_TEST_RESOURCE_RACE: fixture.resourceRace,
      HOSTED_TEST_VOLUME_INSPECTION: fixture.volumeInspection,
      HOSTED_TEST_NETWORK_INSPECTION: fixture.networkInspection,
      HOSTED_TEST_PARTIAL_FAILURE: "0",
      HOSTED_TEST_UNKNOWN_ADDITION: "0",
      COMPOSE_REMOVE_ORPHANS: "1",
    },
  });
}

function runContainerRegistration(fixture, service) {
  return spawnSync("/bin/bash", [
    "-c",
    `set -euo pipefail
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock
VERIFY_TIMEOUT=5
PROJECT_NAME=platform_infra_vps
TRANSACTION_ID=$1
TRANSACTION_LABEL=com.platform.activation.transaction-id
TRANSACTION_MODEL_LABEL=com.platform.activation.source-model-sha256
TRANSACTION_SOURCE_MODEL_SHA256=$4
TRANSACTION_CONTAINER_CAS='[]'
TRANSACTION_CREATED_CONTAINER_IDS=()
TRANSACTION_CONTAINERS_REMOVABLE=0
RELEASE_CONTEXT_JSON=$2
assert_daemon_identity() { return 0; }
${guardFunction}
${registerFunction}
register_transaction_created_containers "$3" exact "$5"
printf '%s\n' "$TRANSACTION_CONTAINER_CAS"
`,
    "container-mount-registration",
    fixture.transactionId,
    fixture.releaseContext,
    fixture.model,
    fixture.sourceModelSha256,
    service,
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fixture.fakeBin}:/usr/bin:/bin`,
      HOSTED_TEST_DOCKER_TRACE: fixture.trace,
      HOSTED_TEST_CONTAINER_IDS: fixture.state,
      HOSTED_TEST_INSPECTION: fixture.inspection,
      HOSTED_TEST_FOREIGN_ACTIVE: fixture.foreignActive,
    },
  });
}

function runTransactionModel(source, output, transactionId) {
  return spawnSync("/bin/bash", [
    "-c",
    `set -euo pipefail
TRANSACTION_ID=$1
TRANSACTION_LABEL=com.platform.activation.transaction-id
TRANSACTION_MODEL_LABEL=com.platform.activation.source-model-sha256
sha256_file() { shasum -a 256 "$1" | awk '{ print $1 }'; }
${bindTransactionModelFunction}
bind_transaction_runtime_model "$2" "$3"
`,
    "transaction-model-guard",
    transactionId,
    source,
    output,
  ], { encoding: "utf8", env: { ...process.env, PATH: "/usr/bin:/bin" } });
}

function resourceFixture(collision) {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-preservation-resource-")));
  const fakeBin = path.join(root, "bin");
  const trace = path.join(root, "docker.trace");
  const model = path.join(root, "model.json");
  const bindSource = path.join(root, "existing-bind");
  fs.mkdirSync(fakeBin);
  fs.mkdirSync(bindSource);
  fs.writeFileSync(trace, "");
  const modelValue = {
    name: "platform_infra_vps",
    services: { database: { image: "example.invalid/database@sha256:a" } },
    volumes: { data: { name: "candidate_data" } },
    networks: { private: { name: "candidate_private", internal: true } },
  };
  if (collision === "external-volume") {
    modelValue.volumes = { data: { name: "enterprise_mariadb_data", external: true } };
  }
  if (["rw-bind", "rw-bind-absent", "read-only-bind", "read-only-bind-absent"].includes(collision)) {
    modelValue.volumes = {};
    modelValue.services.database.volumes = [{
      type: "bind",
      source: bindSource,
      target: "/var/lib/application-data",
      read_only: collision.startsWith("read-only-bind"),
      bind: { create_host_path: false },
    }];
  }
  if (["rw-bind-absent", "read-only-bind-absent"].includes(collision)) {
    fs.rmSync(bindSource, { recursive: true, force: true });
  }
  if (collision === "symlink-parent") {
    const actualParent = path.join(root, "actual-parent");
    const aliasParent = path.join(root, "alias-parent");
    fs.mkdirSync(path.join(actualParent, "data"), { recursive: true });
    fs.symlinkSync(actualParent, aliasParent, "dir");
    modelValue.volumes = {};
    modelValue.services.database.volumes = [{
      type: "bind",
      source: path.join(aliasParent, "data"),
      target: "/var/lib/application-data",
      read_only: true,
      bind: { create_host_path: false },
    }];
  }
  if (["socket-impostor", "aliased-socket"].includes(collision)) {
    modelValue.volumes = {};
    modelValue.services.database.volumes = [{
      type: "bind",
      source: collision === "socket-impostor" ? "/var/run/docker.sock" : "/var/run/../run/docker.sock",
      target: "/var/run/docker.sock",
      read_only: true,
      bind: { create_host_path: false },
    }];
  }
  let releaseContext = { subjects: [] };
  if (collision === "authorized-broker-socket") {
    const imageReference = `example.invalid/docker-action-broker@sha256:${"1".repeat(64)}`;
    const imageId = `sha256:${"2".repeat(64)}`;
    modelValue.volumes = {};
    modelValue.services = {
      "docker-action-broker": {
        image: imageReference,
        init: true,
        user: "0:0",
        read_only: true,
        pids_limit: 256,
        restart: "unless-stopped",
        network_mode: "none",
        cap_drop: ["ALL"],
        security_opt: ["no-new-privileges:true"],
        entrypoint: ["node", "/opt/platform-docker-broker/docker-action-broker.mjs"],
        environment: {
          DOCKER_ACTION_BROKER_SOCKET: "/run/platform/docker-action-broker/broker.sock",
        },
        volumes: [{
          type: "bind",
          source: "/var/run/docker.sock",
          target: "/var/run/docker.sock",
          read_only: true,
          bind: { create_host_path: false },
        }],
        healthcheck: {
          test: ["CMD", "node", "/opt/platform-docker-broker/docker-action-readiness.mjs", "--require-trusted-activation"],
        },
      },
    };
    releaseContext = { subjects: [{ serviceName: "docker-action-broker", imageReference, imageId }] };
  }
  fs.writeFileSync(model, JSON.stringify(modelValue));
  fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh
set -eu
printf 'docker:%s\\n' "$*" >> "$HOSTED_TEST_DOCKER_TRACE"
case " $* " in
  *" info --format {{.DockerRootDir}} "*)
    printf '/var/lib/docker\\n'
    ;;
  *" volume ls --format {{.Name}} "*)
    case "$HOSTED_TEST_COLLISION" in
      volume) printf 'candidate_data\\n' ;;
      external-volume) printf 'enterprise_mariadb_data\\n' ;;
    esac
    ;;
  *" network ls --format {{.Name}} "*)
    [ "$HOSTED_TEST_COLLISION" != network ] || printf 'candidate_private\\n'
    ;;
  *) exit 97 ;;
esac
`, { mode: 0o755 });
  fs.writeFileSync(path.join(fakeBin, "timeout"), "#!/bin/sh\nshift\nexec \"$@\"\n", { mode: 0o755 });
  return { root, fakeBin, trace, model, collision, bindSource, releaseContext: JSON.stringify(releaseContext) };
}

function transactionResourceFixture(drift) {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-preservation-resource-retry-")));
  const fakeBin = path.join(root, "bin");
  const trace = path.join(root, "docker.trace");
  const model = path.join(root, "transaction-model.json");
  const networkActive = path.join(root, "network-active");
  const transactionId = "7".repeat(64);
  const sourceModelSha256 = "8".repeat(64);
  const labels = {
    "com.platform.activation.transaction-id": transactionId,
    "com.platform.activation.source-model-sha256": sourceModelSha256,
  };
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(trace, "");
  fs.writeFileSync(model, JSON.stringify({
    name: "platform_infra_vps",
    services: { database: {
      image: `example.invalid/database@sha256:${"a".repeat(64)}`,
      volumes: [{ type: "volume", source: "data", target: "/var/lib/example-data" }],
      networks: { private: null },
    } },
    volumes: {
      data: { name: "platform_infra_vps_data", labels },
    },
    networks: {
      private: { name: "platform_infra_vps_private", internal: true, labels },
    },
  }));
  const volumeLabels = {
    "com.docker.compose.project": "platform_infra_vps",
    "com.docker.compose.version": "2.29.0",
    "com.docker.compose.volume": "data",
    ...labels,
  };
  if (drift === "volume-label") volumeLabels["com.platform.activation.source-model-sha256"] = "9".repeat(64);
  fs.writeFileSync(path.join(root, "volume.json"), JSON.stringify([{
    Name: "platform_infra_vps_data",
    Driver: "local",
    Scope: "local",
    Labels: volumeLabels,
    Options: null,
    Mountpoint: "/var/lib/docker/volumes/platform_infra_vps_data/_data",
    CreatedAt: "2026-08-09T00:00:00Z",
  }]));
  fs.writeFileSync(path.join(root, "network.json"), JSON.stringify([{
    Id: "net-original",
    Name: "platform_infra_vps_private",
    Driver: "bridge",
    Scope: "local",
    Internal: true,
    Attachable: false,
    Ingress: false,
    ConfigOnly: false,
    EnableIPv6: false,
    Labels: {
      "com.docker.compose.project": "platform_infra_vps",
      "com.docker.compose.version": "2.29.0",
      "com.docker.compose.network": "private",
      ...labels,
    },
    Options: null,
    IPAM: { Driver: "default", Options: null, Config: [] },
  }]));
  fs.writeFileSync(path.join(root, "network-mutated.json"), JSON.stringify([{
    ...JSON.parse(fs.readFileSync(path.join(root, "network.json"), "utf8"))[0],
    Id: "net-drift",
  }]));
  fs.writeFileSync(path.join(fakeBin, "docker"), `#!/bin/sh
set -eu
printf 'docker:%s\\n' "$*" >> "$HOSTED_TEST_DOCKER_TRACE"
case " $* " in
  *" volume ls --format {{.Name}} "*) printf 'platform_infra_vps_data\\n' ;;
  *" network ls --format {{.Name}} "*)
    if [ "$HOSTED_TEST_STAGED_RESOURCES" != 1 ] || [ -e "$HOSTED_TEST_NETWORK_ACTIVE" ]; then
      printf 'platform_infra_vps_private\\n'
    fi
    ;;
  *" volume inspect platform_infra_vps_data "*) cat "$HOSTED_TEST_VOLUME_INSPECTION" ;;
  *" network inspect platform_infra_vps_private "*) cat "$HOSTED_TEST_NETWORK_INSPECTION" ;;
  *" info --format {{.DockerRootDir}} "*) printf '/var/lib/docker\\n' ;;
  *" create "*|*" start "*|*" stop "*|*" rm "*|*" down "*|*" prune "*) exit 97 ;;
  *) exit 97 ;;
esac
`, { mode: 0o755 });
  fs.writeFileSync(path.join(fakeBin, "timeout"), "#!/bin/sh\nshift\nexec \"$@\"\n", { mode: 0o755 });
  return {
    root,
    fakeBin,
    trace,
    model,
    transactionId,
    sourceModelSha256,
    drift,
    networkActive,
    volume: path.join(root, "volume.json"),
    network: path.join(root, "network.json"),
    networkMutated: path.join(root, "network-mutated.json"),
  };
}

function runTransactionResourceRetry(fixture) {
  return spawnSync("/bin/bash", [
    "-c",
    `set -euo pipefail
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock
VERIFY_TIMEOUT=5
PROJECT_NAME=platform_infra_vps
TRANSACTION_ID=$1
TRANSACTION_LABEL=com.platform.activation.transaction-id
TRANSACTION_MODEL_LABEL=com.platform.activation.source-model-sha256
TRANSACTION_SOURCE_MODEL_SHA256=$2
TRANSACTION_VOLUME_CAS='[]'
TRANSACTION_NETWORK_CAS='[]'
RELEASE_CONTEXT_JSON='{}'
${authorityBoundaryFunctions}
${resourceRecoveryFunctions}
register_transaction_resources "$3" exact database || exit 70
if [[ "$4" == network-id ]]; then cp "$HOSTED_TEST_NETWORK_MUTATED" "$HOSTED_TEST_NETWORK_INSPECTION"; fi
assert_candidate_resource_boundary "$3" || exit 70
`,
    "transaction-resource-retry",
    fixture.transactionId,
    fixture.sourceModelSha256,
    fixture.model,
    fixture.drift,
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fixture.fakeBin}:/usr/bin:/bin`,
      HOSTED_TEST_DOCKER_TRACE: fixture.trace,
      HOSTED_TEST_VOLUME_INSPECTION: fixture.volume,
      HOSTED_TEST_NETWORK_INSPECTION: fixture.network,
      HOSTED_TEST_NETWORK_MUTATED: fixture.networkMutated,
      HOSTED_TEST_STAGED_RESOURCES: "0",
      HOSTED_TEST_NETWORK_ACTIVE: fixture.networkActive,
    },
  });
}

function runTransactionResourceExtension(fixture) {
  return spawnSync("/bin/bash", [
    "-c",
    `set -euo pipefail
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock
VERIFY_TIMEOUT=5
PROJECT_NAME=platform_infra_vps
TRANSACTION_ID=$1
TRANSACTION_LABEL=com.platform.activation.transaction-id
TRANSACTION_MODEL_LABEL=com.platform.activation.source-model-sha256
TRANSACTION_SOURCE_MODEL_SHA256=$2
TRANSACTION_VOLUME_CAS='[]'
TRANSACTION_NETWORK_CAS='[]'
TRANSACTION_RESOURCE_PROJECTION='{"volumes":[],"networks":[]}'
TRANSACTION_RESOURCE_MODE=none
RELEASE_CONTEXT_JSON='{}'
${authorityBoundaryFunctions}
${resourceRecoveryFunctions}
register_transaction_resources "$3" subset database || exit 70
printf 'subset:%s:%s\n' \
  "$(printf '%s' "$TRANSACTION_VOLUME_CAS" | jq -r length)" \
  "$(printf '%s' "$TRANSACTION_NETWORK_CAS" | jq -r length)"
: > "$HOSTED_TEST_NETWORK_ACTIVE"
register_transaction_resources "$3" exact database || exit 70
printf 'exact:%s:%s\n' \
  "$(printf '%s' "$TRANSACTION_VOLUME_CAS" | jq -r length)" \
  "$(printf '%s' "$TRANSACTION_NETWORK_CAS" | jq -r length)"
`,
    "transaction-resource-extension",
    fixture.transactionId,
    fixture.sourceModelSha256,
    fixture.model,
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fixture.fakeBin}:/usr/bin:/bin`,
      HOSTED_TEST_DOCKER_TRACE: fixture.trace,
      HOSTED_TEST_VOLUME_INSPECTION: fixture.volume,
      HOSTED_TEST_NETWORK_INSPECTION: fixture.network,
      HOSTED_TEST_NETWORK_MUTATED: fixture.networkMutated,
      HOSTED_TEST_STAGED_RESOURCES: "1",
      HOSTED_TEST_NETWORK_ACTIVE: fixture.networkActive,
    },
  });
}

function runResourceBoundary(fixture) {
  return spawnSync("/bin/bash", [
    "-c",
    `set -euo pipefail
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock
VERIFY_TIMEOUT=5
PROJECT_NAME=platform_infra_vps
RELEASE_CONTEXT_JSON=$2
TRANSACTION_VOLUME_CAS='[]'
TRANSACTION_NETWORK_CAS='[]'
${authorityBoundaryFunctions}
${resourceBoundaryFunction}
status=0
assert_candidate_resource_boundary "$1" || status=$?
exit "$status"
`,
    "candidate-resource-guard",
    fixture.model,
    fixture.releaseContext,
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fixture.fakeBin}:/usr/bin:/bin`,
      HOSTED_TEST_DOCKER_TRACE: fixture.trace,
      HOSTED_TEST_COLLISION: fixture.collision,
    },
  });
}

function runBrokerContract(fixture) {
  return spawnSync("/bin/bash", [
    "-c",
    `set -euo pipefail
RELEASE_CONTEXT_JSON=$2
${authorityBoundaryFunctions}
assert_candidate_broker_socket_contract \
  "$1" docker-action-broker /var/run/docker.sock /var/run/docker.sock true false
`,
    "candidate-broker-contract",
    fixture.model,
    fixture.releaseContext,
  ], {
    encoding: "utf8",
    env: { ...process.env, PATH: `${fixture.fakeBin}:/usr/bin:/bin` },
  });
}

function runCleanup(fixture) {
  return spawnSync("/bin/bash", [
    "-c",
    `set -euo pipefail
CANONICAL_DOCKER_HOST=unix:///var/run/docker.sock
VERIFY_TIMEOUT=5
STOP_TIMEOUT=5
PROJECT_NAME=platform_infra_vps
TRANSACTION_ID=$1
TRANSACTION_LABEL=com.platform.activation.transaction-id
TRANSACTION_MODEL_LABEL=com.platform.activation.source-model-sha256
TRANSACTION_SOURCE_MODEL_SHA256=$2
TRANSACTION_CREATED_CONTAINER_IDS=(cid-database)
TRANSACTION_CONTAINER_CAS='[{"id":"cid-database","configHash":"'$3'","mounts":[],"networks":[]}]'
TRANSACTION_VOLUME_CAS='[]'
TRANSACTION_NETWORK_CAS='[]'
TRANSACTION_RESOURCE_PROJECTION='{"volumes":[],"networks":[]}'
TRANSACTION_RESOURCE_MODE=exact
assert_daemon_identity() { return 0; }
${guardFunction}
${stopTransactionFunction}
stop_transaction_created_and_prove
`,
    "transaction-cleanup-guard",
    fixture.transactionId,
    fixture.sourceModelSha256,
    fixture.configHash,
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${fixture.fakeBin}:/usr/bin:/bin`,
      HOSTED_TEST_DOCKER_TRACE: fixture.trace,
      HOSTED_TEST_CONTAINER_IDS: fixture.state,
      HOSTED_TEST_INSPECTION: fixture.inspection,
    },
  });
}

function countVolumeSentinels(volumeRoot) {
  return fs.readdirSync(volumeRoot)
    .filter((name) => fs.existsSync(path.join(volumeRoot, name, "sentinel"))).length;
}
