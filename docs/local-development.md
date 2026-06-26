# Local Development

Local development is Docker-first. Docker Desktop is acceptable for development, but production operations target Linux/Docker.

## Typical flow

```sh
cp .env.example .env
sh ./scripts/infra-secret-manager.sh init
docker compose --env-file .env -p platform_infra_local -f compose.yaml -f compose.build.yaml -f compose.secrets.yaml up -d --build
sh ./scripts/infra-health.sh
```

## Safe local reset

```sh
docker compose -p platform_infra_local down
```

Avoid `down -v` unless deleting local data is intended.

## Local project code

Keep application repositories outside this repo. Point the platform to external projects with manifests, image references or runtime configuration.
