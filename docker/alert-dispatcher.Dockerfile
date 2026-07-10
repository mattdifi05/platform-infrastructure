# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG NODE_IMAGE=node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606
FROM ${NODE_IMAGE}

ENV NODE_ENV=production
WORKDIR /app
COPY --chown=node:node platform-alert-dispatcher/server.mjs /app/server.mjs
USER node
EXPOSE 3000
HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=5 CMD node -e "fetch('http://127.0.0.1:3000/health').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "/app/server.mjs"]
