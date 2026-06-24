# syntax=docker/dockerfile:1.7
ARG NODE_IMAGE=node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606
FROM ${NODE_IMAGE}

USER root

RUN apk add --no-cache \
    bash \
    ca-certificates \
    curl \
    dcron \
    docker-cli \
    docker-cli-compose \
    git \
    openssh-client \
    tini

WORKDIR /infra

ENTRYPOINT ["tini", "--", "node", "/infra/scripts/stexor-ops.mjs"]
