ARG NODE_IMAGE=node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606
FROM ${NODE_IMAGE}

WORKDIR /opt/platform-docker-broker

COPY scripts/docker-action-contract.mjs /opt/platform-docker-broker/docker-action-contract.mjs
COPY scripts/docker-action-activation.mjs /opt/platform-docker-broker/docker-action-activation.mjs
COPY scripts/docker-action-broker.mjs /opt/platform-docker-broker/docker-action-broker.mjs
COPY scripts/docker-action-worker.mjs /opt/platform-docker-worker/docker-action-worker.mjs
COPY policy/docker-action-activation-policy.json /opt/platform-docker-broker/docker-action-activation-policy.json

RUN chmod 0555 \
      /opt/platform-docker-broker/docker-action-contract.mjs \
      /opt/platform-docker-broker/docker-action-activation.mjs \
      /opt/platform-docker-broker/docker-action-broker.mjs \
      /opt/platform-docker-worker/docker-action-worker.mjs \
    && chmod 0400 /opt/platform-docker-broker/docker-action-activation-policy.json \
    && chown -R root:root /opt/platform-docker-broker /opt/platform-docker-worker

ENTRYPOINT ["node", "/opt/platform-docker-broker/docker-action-broker.mjs"]
