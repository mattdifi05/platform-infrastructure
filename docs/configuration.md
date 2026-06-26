# Configuration

Configuration is split between examples, local `.env`, Docker secrets and provider evidence.

## Example files

- `.env.example`: local development defaults.
- `.env.vps.example`: Linux VPS profile.
- `.env.staging.example`: staging profile.
- `config/platform.example.json`: platform metadata.
- `config/project-manifest.example.json`: application attachment example.

## Important variables

- `PLATFORM_NAME`: display name.
- `DOMAIN`: production/root domain.
- `LOCAL_DOMAIN`: local development domain.
- `ADMIN_HOST`: Admin Control Center host, normally `admin.<domain>`.
- `CONTROL_CENTER_HOST`: explicit Admin Control Center override.
- `APP_HOST`: default public app host when used by an app profile.
- `API_HOST`: API host when routed.
- `AUTH_HOST`: Keycloak/Auth host when routed.
- `STORAGE_HOST`: storage console host when routed and protected.
- `GRAFANA_HOST`: Grafana host when routed and protected.
- `PROVIDER_PROFILE`: environment profile, not branding.
- `PROJECTS_HOST`: deprecated legacy alias. Keep empty for new installs.
- `*_FILE`: path to Docker secret file or mounted secret.
- `CONTROL_CENTER_AUTH_REQUIRED`: enable admin auth outside local quickstart.
- `CONTROL_CENTER_ADMIN_PASSWORD_SHA256`: admin password hash, never plaintext.

## Provider profiles

- `local`: local development.
- `home-vps`: LAN/home server style VPS.
- `generic-vps`: provider-neutral Linux VPS.
- `hostinger`: optional provider profile.
- `aws`: future/provider-specific profile.
- `custom`: project-specific integration.

## Production rules

- Do not leave placeholders in production.
- Do not commit `.env`.
- Do not commit secrets, dumps, generated SBOMs, reports or evidence bundles.
- Use Docker secrets or the secret manager workflow for sensitive values.
- Provider profile must not change platform branding.
