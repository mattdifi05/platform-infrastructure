# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG NODE_IMAGE=node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606
FROM ${NODE_IMAGE}

USER root

ARG GH_VERSION=2.93.0
ARG GH_SHA256=02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0

RUN apk add --no-cache \
    bash \
    bind-tools \
    ca-certificates \
    curl \
    dcron \
    docker-cli \
    docker-cli-compose \
    git \
    jq \
    openssh-client \
    python3 \
    ruby \
    tini

RUN curl --fail --location --silent --show-error \
      "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz" \
      --output /tmp/gh.tar.gz \
    && printf '%s  %s\n' "$GH_SHA256" /tmp/gh.tar.gz | sha256sum -c - \
    && tar -xzf /tmp/gh.tar.gz -C /tmp \
    && install -m 0755 "/tmp/gh_${GH_VERSION}_linux_amd64/bin/gh" /usr/local/bin/gh \
    && rm -rf /tmp/gh.tar.gz "/tmp/gh_${GH_VERSION}_linux_amd64" \
    && gh --version

COPY control-center/package.json control-center/package-lock.json /tmp/control-center-dependencies/
RUN npm ci --prefix /tmp/control-center-dependencies --omit=dev --ignore-scripts --no-audit --no-fund \
    && mv /tmp/control-center-dependencies/node_modules /node_modules \
    && rm -rf /tmp/control-center-dependencies

COPY scripts/ /opt/platform-infrastructure/scripts/
COPY governance/ /opt/platform-infrastructure/governance/
COPY control-center/backup/ /opt/platform-infrastructure/control-center/backup/
RUN chmod -R a-w /opt/platform-infrastructure \
    && chmod 0555 /opt/platform-infrastructure \
    && find /opt/platform-infrastructure -type d -exec chmod 0555 {} + \
    && find /opt/platform-infrastructure -type f -exec chmod 0444 {} + \
    && chmod 0555 \
      /opt/platform-infrastructure/scripts/ops-image-entrypoint.sh \
      /opt/platform-infrastructure/scripts/deploy-vps.sh \
      /opt/platform-infrastructure/scripts/deploy-vps-remote.sh \
      /opt/platform-infrastructure/scripts/activation-bundle.mjs \
      /opt/platform-infrastructure/scripts/activation-request.mjs \
      /opt/platform-infrastructure/scripts/activation-receipt-policy.mjs \
      /opt/platform-infrastructure/scripts/dast-activation-authorization.mjs \
      /opt/platform-infrastructure/scripts/docker-action-activation.mjs \
      /opt/platform-infrastructure/scripts/docker-action-contract.mjs \
      /opt/platform-infrastructure/scripts/ssh-known-host-endpoint.sh \
      /opt/platform-infrastructure/scripts/pinned-ssh-host-key.mjs

WORKDIR /workspace

ENV GH_CONFIG_DIR=/tmp/gh \
    GH_NO_UPDATE_NOTIFIER=1 \
    GH_PROMPT_DISABLED=1

ENTRYPOINT ["tini", "--", "/opt/platform-infrastructure/scripts/ops-image-entrypoint.sh"]
