# syntax=docker/dockerfile:1.7
ARG NODE_IMAGE=node:26-alpine@sha256:e71ac5e964b9201072425d59d2e876359efa25dc96bb1768cb73295728d6e4ea
FROM ${NODE_IMAGE} AS build
ARG PNPM_VERSION=11.0.9

ENV NEXT_TELEMETRY_DISABLED=1 \
    PNPM_HOME=/pnpm \
    PNPM_STORE_PATH=/pnpm/store \
    PATH=/pnpm:$PATH

WORKDIR /workspace

RUN npm install -g pnpm@${PNPM_VERSION}
RUN mkdir -p /pnpm/store && chown -R node:node /workspace /pnpm

USER node

COPY --chown=node:node package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY --chown=node:node apps/backend/package.json apps/backend/package.json
COPY --chown=node:node packages/observability/package.json packages/observability/package.json
COPY --chown=node:node packages/types/package.json packages/types/package.json
RUN --mount=type=cache,target=/pnpm/store,uid=1000,gid=1000 \
    pnpm install --frozen-lockfile --filter ./apps/backend... --store-dir /pnpm/store

COPY --chown=node:node apps/backend apps/backend
COPY --chown=node:node packages/observability packages/observability
COPY --chown=node:node packages/types packages/types
RUN pnpm --filter ./apps/backend build

FROM ${NODE_IMAGE} AS runtime
ARG PNPM_VERSION=11.0.9

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PNPM_HOME=/pnpm \
    PNPM_STORE_PATH=/pnpm/store \
    PATH=/pnpm:$PATH

WORKDIR /workspace

RUN npm install -g pnpm@${PNPM_VERSION}
RUN mkdir -p /pnpm/store && chown -R node:node /workspace /pnpm

USER node

COPY --chown=node:node package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY --chown=node:node apps/backend/package.json apps/backend/package.json
COPY --chown=node:node packages/observability/package.json packages/observability/package.json
COPY --chown=node:node packages/types/package.json packages/types/package.json
RUN --mount=type=cache,target=/pnpm/store,uid=1000,gid=1000 \
    pnpm install --frozen-lockfile --filter ./apps/backend... --prod --store-dir /pnpm/store

COPY --chown=node:node packages/observability packages/observability
COPY --from=build --chown=node:node /workspace/apps/backend/dist apps/backend/dist

WORKDIR /workspace/apps/backend

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD node -e "fetch('http://127.0.0.1:3000/health').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "--enable-source-maps", "dist/server.js"]
