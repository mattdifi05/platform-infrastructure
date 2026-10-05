FROM mariadb:13.0.2@sha256:d4fdec0510ad498e4f3127da30a99df3745bd6d5e611ae6ac5f76403d9284a8d
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
COPY --from=platform/runtime-helpers:go1.27.1 --chmod=0755 /gosu /usr/local/bin/gosu
