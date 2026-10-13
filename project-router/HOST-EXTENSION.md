# External project-router host profile

The generic infrastructure install starts with no project routes. Host-specific project routing belongs to the machine owner and must stay outside this repository.

To enable routes, provision one JSON manifest at `/run/platform-host-extension/project-router.json`. The platform owner must own the file and its parent directory; neither may be writable by the router process or other untrusted users. Mount the file read-only into the project-router container at that exact path and set `PROJECT_ROUTER_HOST_EXTENSION_FILE` to the fixed path and `PROJECT_ROUTER_HOST_EXTENSION_SHA256` to the manifest's SHA-256 in the host-owned runtime environment. The generic Compose profile leaves both values empty.

The manifest uses schema `platform-project-router-host-extension/v1` and has exactly these fields:

```json
{
  "schema": "platform-project-router-host-extension/v1",
  "hostSuffix": ".example.test",
  "services": ["node-example:3000"],
  "routes": [
    {
      "slug": "example",
      "sourceSlug": "example",
      "projectSlug": "example",
      "type": "node",
      "service": "node-example",
      "port": 3000
    }
  ]
}
```

Use an empty `services` array and empty `routes` array for a host profile with no project applications. Route and service inventories must be sorted, unique, and exact. Routes bind a DNS slug to one source directory, project slug, runtime type, and internal service/port. Service names must use the matching `node-`, `php-`, or `static-` prefix. The parser rejects reserved platform routes, duplicate route ownership, unused services, unknown fields, suffix mismatches, and invalid ports. Aliases must be separate explicit route entries with the same owner tuple.

The manifest is an external host configuration input, not authority to add Compose services or mount application data. Keep service definitions, application source, runtime state, catalogs, and credentials under their existing host-specific owners. If the file is absent, the router exposes no project routes.
