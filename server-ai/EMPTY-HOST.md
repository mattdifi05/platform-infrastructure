# Enroll an empty infrastructure host

This is an operator procedure for a new host. It does not copy home admissions, credentials, project data, registry hashes or machine identities. The `server-ai` profile uses SearXNG and the bounded Docker observer; no reader profile, Ollama, GPU services, VPN or application is required. Existing four-service version-1 controller registries retain their original policy. The new version-2 registry explicitly enrolls only SearXNG and observer.

## Prerequisites and protected inputs

Use the intended VPS through native SSH. Docker Compose and Node.js 22+ must be available for enrollment. Run commands as root from the checkout. Before starting, review the effective Compose and the existing core stack's Control Center UID. Its secret-file and socket access must agree with the AI service UID 1000; do not solve mismatches by making secrets world-readable.

Keep values in a root-managed host `.env.server-ai`, outside source control. `.env.server-ai.example` lists references only. Supply the actual Docker and observer proxy socket GIDs. `SERVER_AI_MACHINE_ID` is SHA-256 of the exact `/etc/machine-id` file bytes (including any newline), never the home host's ID. Obtain it without reading credentials:

```sh
sha256sum /etc/machine-id
getent group docker
sh server-ai/scripts/install-observer-proxy.sh
```

The installer installs the repository's existing bounded proxy and systemd unit, creates its dedicated system user if absent, starts the service, then reports only its socket GID. It exposes no TCP port and does not restart Docker. The proxy mount is always `/run/platform-docker-observer`; use its reported group for `SERVER_AI_OBSERVER_PROXY_GID`.

Prepare root-owned SearXNG config directory and root-owned settings file at reviewed VPS paths. The pinned entrypoint also requires a readable settings.yml inside the config directory even when SEARXNG_SETTINGS_PATH points to the separately mounted settings file; provision an identical protected settings.yml there before startup. Grant settings read access to container UID/GID 977 (for example root:977 mode 0440). Configure a fresh SearXNG secret and JSON search output using the pinned image's supported settings. Generate a fresh observer token to a protected file, never print it. The token must be readable by UID 1000 in observer and Control Center (for example UID 1000 mode 0400); parent directories must be root-owned and not group/world writable. Token content is not read by the enrollment generator. Create a controller socket directory owned by UID/GID 1000 with mode 0700. Systemd may own the proxy socket directory under its dedicated user; enrollment checks that its socket owner/group match and no world access exists.

Set the authorized existing OpenAI key source only as `SERVER_AI_OPENAI_API_KEY_FILE=/protected/path`. The Control Center mount target and environment must remain `/run/secrets/server_ai_openai_api_key`; its reader enforces ownership and private permissions. Do not include key contents in environment, logs, shell arguments or repository files. Infrastructure-admin token/socket are separate inputs and must belong to the new host. Do not reuse home controller/admin tokens.

## Start services, then attest actual Docker state

1. Assign planned absolute paths to `SERVER_AI_CONTROLLER_REGISTRY_FILE` and `SERVER_AI_MACHINE_REGISTRY_SOURCE`; they will be generated below. No placeholder JSON or fake image SHA is needed.
2. Build and start only the two inspected services. The controller is deliberately deferred until enrollment exists:

```sh
docker compose --env-file /etc/platform-infrastructure/server-ai/.env.server-ai -p platform_server_ai -f compose.server-ai.yaml --profile server-ai up -d --build searxng server-ai-observer
```

3. Create a root-owned, non-writable-by-group/world JSON policy file with **exactly** these three fields, whose values are the real host source paths used by Compose:

```json
{
  "searxngConfigDir": "/etc/platform-infrastructure/server-ai/searxng",
  "searxngSettingsFile": "/etc/platform-infrastructure/server-ai/settings.yml",
  "observerTokenFile": "/etc/platform-infrastructure/server-ai/observer-token"
}
```

These sample paths are not evidence of existing files. Use actual protected files and match the `.env.server-ai` inputs. Then enroll into a new directory under a root-owned parent:

```sh
node server-ai/scripts/enroll-empty-host.mjs /etc/platform-infrastructure/server-ai/enrollment-policy.json /etc/platform-infrastructure/server-ai/enrollment-vps
```

Enrollment performs Docker GET inspect calls, verifies the exact machine label, project/service identity, read-only binds and approved source paths, network set, dropped capabilities, privileges and resource limits. It writes canonical `controller-registry.json` and `machine-registry.json` containing real image/config IDs. It rejects absent containers, drift or an existing output directory. It never reads secret bytes, and never creates fake reader entries. Review the generated public JSON, set both environment file references to these outputs, then start the controller:

```sh
docker compose --env-file /etc/platform-infrastructure/server-ai/.env.server-ai -p platform_server_ai -f compose.server-ai.yaml --profile server-ai up -d --build server-ai-controller
curl --fail --silent --show-error --unix-socket /run/server-ai-controller/controller.sock http://localhost/status
```

The controller socket source in this example is `/run/server-ai-controller`; use the actual configured source if different. Status must identify this VPS, report compatible/coreHealthy, and list exactly two services. `projectReadersHealthy: false` is expected for an empty host. A missing/incompatible container is not enrollment success. Any rebuilt/reconfigured enrolled service requires a freshly verified registry before lifecycle operations; preserve prior enrollment until replacement is reviewed.

## Attach Control Center

Layer `compose.server-ai-control-center.yaml` and then `compose.server-ai-empty-host-control-center.yaml` onto the existing core stack using its own project name and full existing compose/env arguments. The extra empty-host layer mounts the private controller socket and observer token and joins only the observer/search/API egress networks already created by the AI project. Never use the AI project's name for the core stack. Preserve core service volumes, networks and configuration. The generated local machine registry has no project reader or auxiliary model endpoints. Native AI settings default to disabled: after Control Center attaches, its reconciliation deliberately stops the dedicated services until this machine is enabled. For an authorized initial deployment, use the native createMachineAiSettings/setEnabled store for the verified local machine ID or the normal authenticated UI; preserve any existing user-selected state. Enabling triggers the product's normal provider prewarm. It does not configure or bypass owner authentication or passkeys.

The infrastructure admin host bridge is a separate typed service. Enroll the actual VPS inventory with the procedure below before starting it. Unavailable backup/admission state remains unavailable; chat and observer do not depend on home-only backup evidence.

The existing application already uses `gpt-6-luna` with `https://api.openai.com/v1/responses`, `store:false`, and key-file-only authentication. Apply the core application's existing migrations including 013. In an authenticated Control Center owner session, enable the VPS AI, run its existing readiness flow (model access plus a short Responses request), then issue a short chat and read VPS infrastructure. Confirm status refers to the VPS and no projects appear. Provider/model access is established only by that live readiness result; a passing local test is not an API availability claim. Register additional machines, including a Mac, only after their own real identity/controller enrollment exists.

## Targeted local checks

```sh
node --test server-ai/tests/empty-host-controller.test.mjs
node --check server-ai/scripts/enroll-empty-host.mjs
sh -n server-ai/scripts/install-observer-proxy.sh
```

## Enroll the native infrastructure admin bridge

After the intended core and AI containers exist, run as root on the VPS:

```sh
python3 server-ai/scripts/enroll-infrastructure-admin.py
install -o root -g root -m 0755 deployment/host/libexec/platform-server-ai-admin.py /usr/local/libexec/platform-server-ai-admin.py
install -o root -g root -m 0644 deployment/host/systemd/platform-server-ai-admin-vps.service /etc/systemd/system/platform-server-ai-admin.service
systemctl daemon-reload
systemctl enable --now platform-server-ai-admin.service
systemctl is-active platform-server-ai-admin.service
```

Before starting the service, provision the protected 32-byte infrastructure HMAC token at `/etc/platform-infrastructure/server-ai/infrastructure-token` and mount that same file as `/run/secrets/server_ai_infrastructure_token` in Control Center. Its UID must match Control Center and mode must be 0400 or 0600; retain already provisioned VPS token if present. This token is independent of the OpenAI credential: reuse of the user's already-authorized OpenAI key remains supported and requires no new OpenAI key.

Enrollment reads actual Docker metadata and loaded systemd units; it does not read container environment variables into the saved inventory or print secrets. It saves root-owned mode-0600 files `admin-host.json`, `infrastructure-inventory.json`, and `admin-host.env` under `/etc/platform-infrastructure/server-ai`. It refuses existing files and any known project/reader containers. The config binds this host's machine identity, an explicit finite infrastructure container/service catalog, and exact Docker IDs/images/mounts/labels. No application names are seeded. Review generated files locally without exposing contents unnecessarily. Recreated containers require reviewed re-enrollment; identity drift fails closed.

The VPS-specific unit requires the protected env file and orders startup after Docker, network and UFW. The separate home unit is unchanged. `SERVER_AI_ADMIN_CONFIG` accepts only the fixed protected JSON path; invalid config or machine mismatch stops service startup. With no env selection the home defaults remain unchanged. In VPS mode, no home zone, TLS root, LAN resolver, backup path or job is used by default. DNS read returns the live resolver configuration only. Capability discovery filters absent containers, unloaded units and unavailable utilities; fail2ban writes require a working sshd jail. OS/package/container/service actions retain bounded typed arguments, HMAC, freshness, role and trusted-turn checks. No arbitrary command, SQL, application code or project data endpoint is added.

The initial maintenance catalog is empty. To add a real installed native maintenance job later, an operator must review its exact existing typed target/unit, amend the root-owned config, and restart the bridge. Backup/restore jobs additionally require existing, root-protected `backupRoot` and `runtimeRoot` beneath the explicitly bounded infrastructure roots; no copied home proof qualifies. Unsupported DNS/TLS writes and home egress reload remain unavailable in VPS mode. Once installed, verify through authenticated Control Center `readInfrastructure(capabilities)`, `os`, and `containers`, checking the VPS machine ID and actual health before claiming admin ready.

Additional focused checks:

```sh
python3 server-ai/tests/admin-host-config.test.py
python3 -m py_compile deployment/host/libexec/platform-server-ai-admin.py server-ai/scripts/enroll-infrastructure-admin.py
```
