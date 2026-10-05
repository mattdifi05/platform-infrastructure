FROM busybox:stable-musl@sha256:3c6ae8008e2c2eedd141725c30b20d9c36b026eb796688f88205845ef17aa213 AS probe
FROM coredns/coredns:1.14.7@sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286
COPY --from=probe /bin/busybox /busybox
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/busybox", "wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/health"]
