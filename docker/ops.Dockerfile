# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
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

COPY control-center/package.json control-center/package-lock.json /infra/control-center/
RUN npm ci --prefix /infra/control-center --omit=dev --ignore-scripts --no-audit --no-fund

WORKDIR /infra

ENTRYPOINT ["tini", "--", "node", "/infra/scripts/infra-ops.mjs"]
