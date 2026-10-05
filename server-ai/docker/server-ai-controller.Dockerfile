# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM node:26.10.0-alpine3.23@sha256:c3c6e314fd42e41962360b2482fc18d150beb47976c3aa7b8b9689d7ef42a5c2
WORKDIR /opt/server-ai-controller
COPY --chown=0:0 --chmod=0555 server-ai/scripts/server-ai-controller.mjs ./server-ai-controller.mjs
RUN mkdir -p /etc/server-ai-controller /run/server-ai-controller \
    && chown 1000:1000 /run/server-ai-controller \
    && chmod 0755 /run/server-ai-controller
USER 1000:1000
ENTRYPOINT ["node", "/opt/server-ai-controller/server-ai-controller.mjs"]
