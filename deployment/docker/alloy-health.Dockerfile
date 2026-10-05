FROM busybox:stable-musl@sha256:3c6ae8008e2c2eedd141725c30b20d9c36b026eb796688f88205845ef17aa213 AS probe
FROM grafana/alloy:v1.20.0@sha256:f111cce835516c5f99166342be7038496b52ced16667be5a11e19258a3e4cd30
COPY --from=probe /bin/busybox /busybox
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s CMD ["/busybox","wget","-q","-O","/dev/null","http://127.0.0.1:9080/-/ready"]
