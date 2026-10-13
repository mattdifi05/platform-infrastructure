# Application Runtime Boundary

This repository describes the generic platform runtime. A clean installation
starts with an empty application catalog: no application source, application
repository, application database, app-specific hostname, or route is seeded by
the platform repository.

The VPS provides the shared platform base. Existing home and VPS installations
keep their own application sources, catalogs, credentials, data and route
profiles. Host-specific routes and service mappings live in a read-only,
digest-pinned extension outside Git at
`/run/platform-host-extension/project-router.json`. An absent extension means
that the project router exposes no application routes. Keep the home and VPS
extensions and their secrets independent.

## Platform boundary

The platform repository owns Compose, networks, the generic project router,
WAF, shared runtime images and Control Center. Application source remains in
its owning repository and is materialized on the relevant host. Application
environment files, uploads, logs, caches, databases, catalogs and credentials
are external host state. None of these host-specific inputs belongs in the
generic installation profile.

## Generic runtime contract

The project router starts with only the Control Center upstream allowlisted.
Local compatibility mode accepts application routes only from the pinned
external host extension. The extension binds each route to its owning source,
project, runtime type and service. Compose defaults, CI fixtures and the clean
install profile contain no concrete application service or repository.

The shared PHP runtime is generic. Optional host workloads can use pinned Node,
PHP or static runtime services when that host's external profile authorizes
them. Application runtimes and their data remain independently managed on each
host; the platform base does not copy or synchronize application catalogs
between home and VPS.

## Persistent state boundary

Platform databases, Control Center state, certificates, Docker volumes,
backup metadata and platform credentials remain external to Git. Each host
retains its own application databases, uploaded files, queues and secrets.
Recovery and synchronization must preserve those host boundaries and must not
replace an existing host catalog with the empty clean-install catalog.

## Clean-install gate

A fresh installation must render and start with an empty application catalog
and zero project routes when no host extension is mounted. Existing host routes
become available only after that host's separately maintained extension has
been validated and pinned. A successful platform-only installation does not
claim that any application has been installed or synchronized.
