# syntax=docker/dockerfile:1.7

ARG RESTIC_IMAGE=restic/restic:0.18.0
ARG RCLONE_IMAGE=rclone/rclone:1.70.3

FROM ${RCLONE_IMAGE} AS rclone

FROM ${RESTIC_IMAGE}
COPY --from=rclone /usr/local/bin/rclone /usr/local/bin/rclone
