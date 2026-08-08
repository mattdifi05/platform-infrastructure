# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG NODE_IMAGE=node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606
FROM ${NODE_IMAGE}

USER root
WORKDIR /opt/platform-backup-scheduler

COPY --chmod=0555 scripts/backup-scheduler.sh /opt/platform-backup-scheduler/backup-scheduler.sh
COPY --chmod=0444 scripts/docker-action-client.mjs scripts/docker-action-contract.mjs /opt/platform-backup-scheduler/
COPY --chmod=0444 scripts/backup-queue-control.mjs /opt/platform-backup-scheduler/scripts/backup-queue-control.mjs
COPY --chmod=0444 control-center/backup/contracts.mjs control-center/backup/queue-admission.mjs control-center/backup/queue-operation-adapter.mjs /opt/platform-backup-scheduler/control-center/backup/

ENTRYPOINT ["/opt/platform-backup-scheduler/backup-scheduler.sh"]
