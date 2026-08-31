# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG RESTIC_IMAGE=restic/restic:0.18.0@sha256:4cf4a61ef9786f4de53e9de8c8f5c040f33830eb0a10bf3d614410ee2fcb6120
ARG RCLONE_IMAGE=rclone/rclone:1.70.3@sha256:34c729127386abec1c610b2aa024e39b4498dc2b4a72a0798ae21fbdc1b0493b

FROM ${RCLONE_IMAGE} AS rclone

FROM ${RESTIC_IMAGE}
RUN mkdir -p /restic-password /rclone-config
COPY --from=rclone /usr/local/bin/rclone /usr/local/bin/rclone
