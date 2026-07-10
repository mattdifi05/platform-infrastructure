# MinIO notes

MinIO starts as an object store with S3 APIs and root bootstrap material mounted
only into the MinIO service and an explicitly invoked one-shot identity tool.
Hosted workloads must never receive the root username or password.

Create buckets through the storage lifecycle workflow. Once a bucket exists,
plan a per-workload identity without reading any secret value:

```sh
MODE=plan \
MINIO_BUCKET=example-app \
MINIO_PREFIX=runtime/ \
sh scripts/minio-service-identity.sh
```

In production, keep both the API and console internal unless you intentionally
publish them through a private network, VPN, or a hardened Traefik route.

The apply path requires root and scoped access/secret key files, an explicit
confirmation token, and the digest-pinned `mc` image. Verification proves list
and object operations only in the selected prefix, and denies cross-prefix,
cross-bucket and admin APIs. See `SERVICE-IDENTITY-AND-TENANCY.md`.
