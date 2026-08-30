# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG NODE_IMAGE=node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606
FROM ${NODE_IMAGE}

RUN apk add --no-cache mariadb-client postgresql-client

WORKDIR /app

COPY control-center/package.json control-center/package-lock.json ./
RUN --mount=type=cache,id=control-center-npm,target=/root/.npm,sharing=locked \
    npm ci --omit=dev --ignore-scripts

COPY control-center/ ./
RUN chmod -R a+rX /app
