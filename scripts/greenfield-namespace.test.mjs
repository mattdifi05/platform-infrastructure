import assert from "node:assert/strict";
import test from "node:test";
import {
  GREENFIELD_PROJECT_NAME,
  BROWNFIELD_PROJECT_NAME,
  GREENFIELD_ALL_SERVICES,
  GREENFIELD_CORE_SERVICES,
  evaluateGreenfieldNamespace,
  greenfieldContainerName,
  greenfieldNetworkName,
  greenfieldSecretPhysicalName,
  greenfieldVolumeName,
  greenfieldVolumePhysicalNameForKey,
  greenfieldNetworkPhysicalNameForKey,
  greenfieldEdgeBinds,
  isBrownfieldOwnedPhysicalName,
  isGreenfieldOwnedPhysicalName,
  GREENFIELD_TOPOLOGY_PARALLEL,
  GREENFIELD_TOPOLOGY_CUTOVER,
} from "./greenfield-namespace.mjs";

test("greenfield physical names use the dedicated namespace", () => {
  assert.equal(greenfieldContainerName("postgres"), "gf-postgres");
  assert.equal(greenfieldVolumeName("postgres_data"), "greenfield_postgres_data");
  assert.equal(greenfieldVolumePhysicalNameForKey("enterprise_mariadb_data"), "greenfield_mariadb_data");
  assert.equal(greenfieldVolumePhysicalNameForKey("redis_auth_config"), "greenfield_redis_auth_config");
  assert.equal(greenfieldNetworkName("platform_edge"), "platform_infra_greenfield_platform_edge");
  assert.equal(greenfieldNetworkPhysicalNameForKey("enterprise_net"), "platform_infra_greenfield_enterprise_net");
  assert.throws(() => greenfieldNetworkPhysicalNameForKey("enterprise_other"), TypeError);
  assert.equal(greenfieldSecretPhysicalName("redis_password"), "platform_infra_greenfield_redis_password");
});

test("brownfield-owned names are detected fail-closed", () => {
  for (const name of [
    "enterprise-postgres",
    "enterprise-waf",
    "enterprise_postgres_data",
    "enterprise_net",
    "platform_infra_vps",
    "platform_infra_vps_edge",
    "platform_infra_vps_redis_password",
  ]) {
    assert.equal(isBrownfieldOwnedPhysicalName(name), true, name);
    assert.equal(isGreenfieldOwnedPhysicalName(name), false, name);
  }
  assert.equal(isBrownfieldOwnedPhysicalName("gf-postgres"), false);
  assert.equal(isGreenfieldOwnedPhysicalName("greenfield_postgres_data"), true);
  assert.equal(isGreenfieldOwnedPhysicalName("platform_infra_greenfield_enterprise_net"), true);
});

test("edge binds never collide with brownfield during the parallel phase", () => {
  const parallel = greenfieldEdgeBinds(GREENFIELD_TOPOLOGY_PARALLEL);
  assert.equal(parallel.http, "0.0.0.0:18080");
  assert.equal(parallel.https, "0.0.0.0:18443");
  const cutover = greenfieldEdgeBinds(GREENFIELD_TOPOLOGY_CUTOVER);
  assert.deepEqual(cutover, { http: "0.0.0.0:80", https: "0.0.0.0:443" });
  assert.throws(() => greenfieldEdgeBinds("BOGUS"), TypeError);
});

test("logical name validation rejects brownfield-flavoured identifiers", () => {
  assert.throws(() => greenfieldVolumeName("enterprise_postgres_data_raw"), TypeError);
  assert.throws(() => greenfieldContainerName("../escape"), TypeError);
  assert.throws(() => greenfieldNetworkName(""), TypeError);
});

test("a fully projected render passes the namespace evaluator", () => {
  const render = {
    name: GREENFIELD_PROJECT_NAME,
    services: {
      postgres: {
        container_name: "gf-postgres",
        networks: { platform_postgres: null },
        volumes: [{ type: "volume", source: "enterprise_postgres_data", target: "/var/lib/postgresql" }],
      },
      waf: { container_name: "gf-waf", networks: { platform_edge: null } },
      mariadb: { container_name: "gf-mariadb", networks: { enterprise_net: null } },
    },
    networks: {
      enterprise_net: { name: "platform_infra_greenfield_enterprise_net", external: false },
      platform_postgres: { name: "platform_infra_greenfield_platform_postgres", internal: true },
      platform_edge: { name: "platform_infra_greenfield_platform_edge", internal: true },
    },
    volumes: {
      enterprise_postgres_data: { name: "greenfield_postgres_data" },
    },
  };
  assert.deepEqual(evaluateGreenfieldNamespace(render), []);
});

test("the namespace evaluator rejects every brownfield inheritance vector", () => {
  const base = {
    name: GREENFIELD_PROJECT_NAME,
    services: {},
    networks: {},
    volumes: {},
  };
  const cases = [
    [{ ...base, name: BROWNFIELD_PROJECT_NAME }, ["render:project-name"]],
    [{
      ...base,
      services: { traefik: { container_name: "enterprise-traefik" } },
    }, ["service:traefik:container-name:brownfield"]],
    [{
      ...base,
      services: { traefik: {} },
    }, ["service:traefik:container-name:missing"]],
    [{
      ...base,
      services: { traefik: { container_name: "gf-traefik" } },
      networks: { platform_edge: { name: "enterprise_sneaky" } },
    }, ["network:platform_edge:physical-name:brownfield"]],
    [{
      ...base,
      networks: { enterprise_net: { name: "enterprise_net", external: true } },
    }, ["network:enterprise_net:physical-name:brownfield"]],
    [{
      ...base,
      networks: { platform_cache: {} },
    }, ["network:platform_cache:physical-name:missing"]],
    [{
      ...base,
      volumes: { enterprise_mariadb_data: { name: "enterprise_mariadb_data", external: true } },
    }, ["volume:enterprise_mariadb_data:physical-name:brownfield"]],
    [{
      ...base,
      services: { redis: { container_name: "gf-redis", networks: { ghost_net: null } } },
    }, ["service:redis:network:undeclared:ghost_net"]],
    [{
      ...base,
      services: {
        redis: {
          container_name: "gf-redis",
          volumes: [{ type: "volume", source: "undeclared_vol", target: "/data" }],
        },
      },
    }, ["service:redis:volume:undeclared:undeclared_vol"]],
  ];
  for (const [render, expected] of cases) {
    assert.deepEqual(evaluateGreenfieldNamespace(render), expected, JSON.stringify(render));
  }
});

test("service inventory covers core and auxiliary sets without overlap", () => {
  assert.equal(new Set(GREENFIELD_ALL_SERVICES).size, GREENFIELD_ALL_SERVICES.length);
  for (const service of ["waf", "traefik", "postgres", "keycloak", "control-center"]) {
    assert.ok(GREENFIELD_CORE_SERVICES.includes(service), service);
  }
  for (const service of ["php-apache", "local-dns", "local-registry"]) {
    assert.ok(GREENFIELD_ALL_SERVICES.includes(service), service);
  }
});
