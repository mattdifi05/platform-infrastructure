# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG NODE_IMAGE=node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606
FROM ${NODE_IMAGE}

ENV NODE_ENV=production
WORKDIR /app
COPY --chown=node:node project-router/server.mjs /app/server.mjs
COPY --chown=node:node project-router/project-metadata.mjs /app/project-metadata.mjs
COPY --chown=node:node project-router/project-metadata-worker.mjs /app/project-metadata-worker.mjs
COPY --chown=node:node project-router/verified-workload-lock.mjs /app/verified-workload-lock.mjs
COPY --chown=node:node project-router/workload-route-lock.mjs /app/workload-route-lock.mjs
USER node
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 CMD node -e "fetch('http://127.0.0.1:8080/__health').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "/app/server.mjs"]
