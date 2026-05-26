# MinIO notes

MinIO starts as an S3-compatible object store with credentials from `.env`.

For local development, create the optional initial bucket after startup:

```sh
docker run --rm --network enterprise_net "${MINIO_MC_IMAGE:?Set a digest-pinned minio/mc image}" sh -c \
  'mc alias set enterprise http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" && mc mb --ignore-existing enterprise/"$MINIO_DEFAULT_BUCKET"'
```

In production, keep both the API and console internal unless you intentionally
publish them through a private network, VPN, or a hardened Traefik route.
