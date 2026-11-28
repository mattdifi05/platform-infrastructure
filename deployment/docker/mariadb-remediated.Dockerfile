FROM mariadb:13.0.2@sha256:d4fdec0510ad498e4f3127da30a99df3745bd6d5e611ae6ac5f76403d9284a8d AS runtime
FROM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS gosu-build
ENV GOTOOLCHAIN=local
RUN CGO_ENABLED=0 go install -trimpath github.com/tianon/gosu@1.19
FROM runtime
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
COPY --from=gosu-build --chmod=0755 /go/bin/gosu /usr/local/bin/gosu
