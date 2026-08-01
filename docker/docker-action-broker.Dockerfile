# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606
WORKDIR /opt/platform-docker-broker
COPY --chown=0:0 --chmod=0555 scripts/docker-action-contract.mjs /opt/platform-docker-broker/docker-action-contract.mjs
COPY --chown=0:0 --chmod=0555 scripts/docker-action-activation.mjs /opt/platform-docker-broker/docker-action-activation.mjs
COPY --chown=0:0 --chmod=0555 scripts/docker-action-helper-plan.mjs /opt/platform-docker-broker/docker-action-helper-plan.mjs
COPY --chown=0:0 --chmod=0555 scripts/docker-action-broker.mjs /opt/platform-docker-broker/docker-action-broker.mjs
COPY --chown=0:0 --chmod=0555 scripts/docker-action-worker.mjs /opt/platform-docker-worker/docker-action-worker.mjs
COPY --chown=0:0 --chmod=0400 policy/docker-action-activation-policy.json /opt/platform-docker-broker/docker-action-activation-policy.json
ENTRYPOINT ["node","/opt/platform-docker-broker/docker-action-broker.mjs"]
