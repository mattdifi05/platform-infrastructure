#!/usr/bin/env node
import assert from "node:assert/strict";
import test from "node:test";

import {
  validateRenderedWorkloads,
  validateWorkloadManifest,
} from "./hosted-workload-contract.mjs";
import { brokerPolicySha256 } from "./workload-broker-policy.mjs";

test("final Node consumer rejects a sole claimant stealing another workload secret", () => {
  const fixture = renderedFixture({
    workloadIds: ["billing", "billingapi"],
    consumerId: "billing",
    secretName: "billingapi-api-key",
    fileTarget: "billingapi-api-key",
  });
  assert.equal(
    fixture.lock.workloads.find((workload) => workload.id === "billing").secrets[0],
    "billingapi-api-key",
  );
  assert.equal(
    fixture.combined.services["billing-web"].secrets[0].source,
    "billingapi-api-key",
  );
  assert.throws(
    () => validateRenderedWorkloads(fixture),
    /canonical secret owner|secret owner.*billingapi|belongs to workload billingapi/i,
  );
});

test("final Node consumer rejects an _FILE target without an exact secret grant", () => {
  const fixture = renderedFixture({
    workloadIds: ["billing"],
    consumerId: "billing",
    secretName: "billing-api-key",
    fileTarget: "ungranted-secret",
  });
  assert.throws(
    () => validateRenderedWorkloads(fixture),
    /secret file.*grant|ungranted secret target/i,
  );
});

test("final Node consumer rejects duplicate exact secret grant targets", () => {
  const fixture = renderedFixture({
    workloadIds: ["billing"],
    consumerId: "billing",
    secretNames: ["billing-api-key", "billing-signing-key"],
    grants: [
      { source: "billing-api-key", target: "billing-token" },
      { source: "billing-signing-key", target: "billing-token" },
    ],
    fileTarget: "billing-token",
  });
  assert.throws(
    () => validateRenderedWorkloads(fixture),
    /duplicate secret grant target|secret target.*duplicate/i,
  );
});

test("final Node consumer rejects noncanonical workload ids without normalization", () => {
  for (const workloadId of ["b", "billing_api", "billing.api", `b${"a".repeat(63)}`]) {
    const fixture = renderedFixture({
      workloadIds: [workloadId],
      consumerId: workloadId,
      secretNames: [],
      grants: [],
      fileTarget: null,
      forgeManifests: true,
    });
    assert.throws(
      () => validateRenderedWorkloads(fixture),
      /canonical workload id/i,
      workloadId,
    );
  }
});

test("manifest intake rejects workload id case and whitespace normalization", () => {
  for (const workloadId of ["Billing", " billing "]) {
    assert.throws(
      () => validateWorkloadManifest({
        version: 1,
        id: workloadId,
        composeFile: "compose.yaml",
        secrets: [],
        services: [{ name: "billing-web", role: "web", routes: [] }],
      }),
      /workload id.*invalid|canonical workload id/i,
    );
  }
});

test("manifest intake rejects raw service role route and secret normalization", () => {
  const mutations = [
    ["service case", (document) => { document.services[0].name = "Billing-Web"; }],
    ["service whitespace", (document) => { document.services[0].name = " billing-web "; }],
    ["role case", (document) => { document.services[0].role = "WEB"; }],
    ["role whitespace", (document) => { document.services[0].role = " web "; }],
    ["route case", (document) => { document.services[0].routes[0].slug = "Billing"; }],
    ["route whitespace", (document) => { document.services[0].routes[0].slug = " billing "; }],
    ["secret whitespace", (document) => { document.secrets[0] = " billing-key "; }],
  ];
  for (const [label, mutate] of mutations) {
    const document = {
      version: 1,
      id: "billing",
      composeFile: "compose.yaml",
      secrets: ["billing-key"],
      services: [{
        name: "billing-web",
        role: "web",
        routes: [{ slug: "billing", host: "billing.example.com", port: 3000 }],
      }],
    };
    mutate(document);
    assert.throws(
      () => validateWorkloadManifest(document),
      /invalid|canonical|unsupported|prefixed/i,
      label,
    );
  }
});

test("workload id leaves exact room for a canonical service and secret suffix", () => {
  const maxId = `a${"b".repeat(60)}`;
  assert.equal(maxId.length, 61);
  assert.equal(`${maxId}-x`.length, 63);
  assert.equal(`${maxId}-s`.length, 63);
  assert.doesNotThrow(() => validateWorkloadManifest({
    version: 1,
    id: maxId,
    composeFile: "compose.yaml",
    secrets: [`${maxId}-s`],
    services: [{ name: `${maxId}-x`, role: "worker", routes: [] }],
  }));
  const maxRouteSlug = `a${"b".repeat(62)}`;
  assert.equal(maxRouteSlug.length, 63);
  assert.doesNotThrow(() => validateWorkloadManifest({
    version: 1,
    id: "billing",
    composeFile: "compose.yaml",
    secrets: [],
    services: [{
      name: "billing-web",
      role: "web",
      routes: [{ slug: maxRouteSlug, host: `${maxRouteSlug}.example.com`, port: 3000 }],
    }],
  }));

  for (const length of [62, 63, 64]) {
    const workloadId = `a${"b".repeat(length - 1)}`;
    assert.throws(
      () => validateWorkloadManifest({
        version: 1,
        id: workloadId,
        composeFile: "compose.yaml",
        secrets: [],
        services: [{ name: `${workloadId}-x`, role: "worker", routes: [] }],
      }),
      /workload id.*invalid/i,
      `length=${length}`,
    );
  }
});

for (const [label, grant, fileTarget] of [
  ["short syntax", "billing-api-key", "billing-api-key"],
  ["long alias", { source: "billing-api-key", target: "billing-token" }, "billing-token"],
  ["long default target", { source: "billing-api-key" }, "billing-api-key"],
]) {
  test(`final Node consumer preserves ${label} secret grants`, () => {
    const fixture = renderedFixture({
      workloadIds: ["billing"],
      consumerId: "billing",
      secretName: "billing-api-key",
      grants: [grant],
      fileTarget,
    });
    assert.doesNotThrow(() => validateRenderedWorkloads(fixture));
  });
}

function renderedFixture({
  workloadIds,
  consumerId,
  secretName,
  secretNames = [secretName],
  grants = [{ source: secretName, target: secretName }],
  fileTarget,
  forgeManifests = false,
}) {
  const projectName = "fixture";
  const core = {
    services: {
      "project-router": {
        image: `example.invalid/router@sha256:${"a".repeat(64)}`,
        networks: { platform_routing: null },
      },
    },
    networks: { platform_routing: { internal: true } },
  };
  const manifests = workloadIds.map((workloadId) => {
    const document = {
      version: 1,
      id: workloadId,
      composeFile: "compose.yaml",
      projectMetadataFile: null,
      secrets: workloadId === consumerId ? secretNames : [],
      services: [{ name: `${workloadId}-web`, role: "web", routes: [] }],
      migrationRoots: [],
    };
    if (!forgeManifests && document.secrets.every((name) => name.startsWith(`${workloadId}-`))) {
      return validateWorkloadManifest(document);
    }
    // Model a digest-coherent forged lock that bypassed the earlier parser.
    return document;
  });
  const combined = {
    services: {
      "project-router": structuredClone(core.services["project-router"]),
    },
    networks: {
      platform_routing: structuredClone(core.networks.platform_routing),
    },
    secrets: Object.fromEntries(secretNames.map((name) => [
      name,
      {
        external: true,
        name: `${projectName}_${name}`,
      },
    ])),
  };
  for (const workloadId of workloadIds) {
    const serviceName = `${workloadId}-web`;
    const networkName = `${workloadId.replaceAll("-", "_")}_ingress`;
    combined.services[serviceName] = workloadService(workloadId, networkName);
    combined.networks[networkName] = {
      internal: true,
      name: `${projectName}_${networkName}`,
    };
  }
  combined.services[`${consumerId}-web`].secrets = grants;
  combined.services[`${consumerId}-web`].environment = fileTarget == null ? {} : {
    [`${consumerId.toUpperCase().replaceAll("-", "_")}_TOKEN_FILE`]: `/run/secrets/${fileTarget}`,
  };
  return {
    core,
    combined,
    lock: {
      projectName,
      workloads: manifests,
      brokerPolicySha256: brokerPolicySha256(manifests),
      rawPolicyReceipt: {
        protectedNetworkNames: ["platform_routing"],
        protectedResourceNames: {
          configs: [],
          networks: ["platform_routing"],
          secrets: [],
          services: ["project-router"],
          volumes: [],
        },
        workloads: workloadIds.map((workloadId) => ({
          workloadId,
          platformExtensions: [],
        })),
      },
    },
  };
}

function workloadService(workloadId, networkName) {
  return {
    image: `example.invalid/${workloadId}@sha256:${"b".repeat(64)}`,
    read_only: true,
    init: true,
    restart: "no",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    user: "1000:1000",
    logging: { driver: "local", options: { "max-size": "10m", "max-file": "3" } },
    pids_limit: 128,
    cpu_shares: 256,
    blkio_config: { weight: 300 },
    ulimits: { nofile: { soft: 8192, hard: 8192 } },
    cpus: 0.5,
    mem_limit: String(256 * 1024 * 1024),
    memswap_limit: String(256 * 1024 * 1024),
    mem_reservation: String(64 * 1024 * 1024),
    healthcheck: { test: ["CMD", "true"] },
    environment: {},
    secrets: [],
    networks: { [networkName]: null },
    labels: {
      "com.platform.workload-id": workloadId,
      "com.platform.workload-role": "web",
    },
  };
}
