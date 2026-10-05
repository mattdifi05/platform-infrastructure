# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG NODE_IMAGE=node:26.10.0-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80
FROM ${NODE_IMAGE}

RUN apk add --no-cache mariadb-client postgresql-client
RUN npm install --global npm@12.1.0

WORKDIR /app

COPY control-center/package.json control-center/package-lock.json ./
RUN --mount=type=cache,id=control-center-npm-os-candidate,target=/root/.npm,sharing=locked \
    npm ci --omit=dev --ignore-scripts

COPY control-center/ ./
RUN chmod -R a+rX /app
