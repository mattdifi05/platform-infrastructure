# syntax=docker/dockerfile:1.7
ARG NODE_IMAGE=node:26-alpine@sha256:3ad34ca6292aec4a91d8ddeb9229e29d9c2f689efd0dd242860889ac71842eba
FROM ${NODE_IMAGE} AS build
ARG PNPM_VERSION=11.9.0
ARG NEXT_PUBLIC_API_URL=https://api.localhost.com
ARG NEXT_PUBLIC_UI_URL=https://ui.localhost.com
ARG NEXT_PUBLIC_ACCOUNT_URL=https://account.localhost.com
ARG NEXT_PUBLIC_BOT_PROTECTION_PROVIDER=disabled
ARG NEXT_PUBLIC_GOOGLE_RECAPTCHA_SITE_KEY=
ARG NEXT_PUBLIC_CLOUDFLARE_TURNSTILE_SITE_KEY=
ARG ACCOUNT_HOST=account.localhost.com
ARG ACCOUNT_PUBLIC_URL=https://account.localhost.com
ARG NEXTAUTH_URL=https://account.localhost.com
ARG KEYCLOAK_ISSUER=https://auth.localhost.com/realms/platform

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000 \
    NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_PUBLIC_UI_URL=${NEXT_PUBLIC_UI_URL} \
    NEXT_PUBLIC_ACCOUNT_URL=${NEXT_PUBLIC_ACCOUNT_URL} \
    NEXT_PUBLIC_BOT_PROTECTION_PROVIDER=${NEXT_PUBLIC_BOT_PROTECTION_PROVIDER} \
    NEXT_PUBLIC_GOOGLE_RECAPTCHA_SITE_KEY=${NEXT_PUBLIC_GOOGLE_RECAPTCHA_SITE_KEY} \
    NEXT_PUBLIC_CLOUDFLARE_TURNSTILE_SITE_KEY=${NEXT_PUBLIC_CLOUDFLARE_TURNSTILE_SITE_KEY} \
    ACCOUNT_HOST=${ACCOUNT_HOST} \
    ACCOUNT_PUBLIC_URL=${ACCOUNT_PUBLIC_URL} \
    NEXTAUTH_URL=${NEXTAUTH_URL} \
    KEYCLOAK_ISSUER=${KEYCLOAK_ISSUER} \
    PNPM_HOME=/pnpm \
    PNPM_STORE_PATH=/pnpm/store \
    PATH=/pnpm:$PATH

WORKDIR /workspace

RUN npm install -g pnpm@${PNPM_VERSION}
RUN mkdir -p /pnpm/store && chown -R node:node /workspace /pnpm

USER node

COPY --chown=node:node package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY --chown=node:node apps/web/package.json apps/web/package.json
COPY --chown=node:node packages/types/package.json packages/types/package.json
COPY --chown=node:node packages/ui/package.json packages/ui/package.json
RUN --mount=type=cache,target=/pnpm/store,uid=1000,gid=1000 \
    pnpm install --frozen-lockfile --filter ./apps/web... --filter ./packages/ui... --store-dir /pnpm/store

COPY --chown=node:node apps/web apps/web
COPY --chown=node:node packages/types packages/types
COPY --chown=node:node packages/ui packages/ui
RUN mkdir -p apps/web/.next && chown -R node:node apps/web/.next
RUN --mount=type=cache,target=/workspace/apps/web/.next/cache,uid=1000,gid=1000 \
    pnpm --filter ./apps/web build

FROM ${NODE_IMAGE} AS runtime
ARG NEXT_PUBLIC_API_URL=https://api.localhost.com
ARG NEXT_PUBLIC_UI_URL=https://ui.localhost.com
ARG NEXT_PUBLIC_ACCOUNT_URL=https://account.localhost.com
ARG NEXT_PUBLIC_BOT_PROTECTION_PROVIDER=disabled
ARG NEXT_PUBLIC_GOOGLE_RECAPTCHA_SITE_KEY=
ARG NEXT_PUBLIC_CLOUDFLARE_TURNSTILE_SITE_KEY=
ARG ACCOUNT_HOST=account.localhost.com
ARG ACCOUNT_PUBLIC_URL=https://account.localhost.com
ARG NEXTAUTH_URL=https://account.localhost.com
ARG KEYCLOAK_ISSUER=https://auth.localhost.com/realms/platform

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_PUBLIC_UI_URL=${NEXT_PUBLIC_UI_URL} \
    NEXT_PUBLIC_ACCOUNT_URL=${NEXT_PUBLIC_ACCOUNT_URL} \
    NEXT_PUBLIC_BOT_PROTECTION_PROVIDER=${NEXT_PUBLIC_BOT_PROTECTION_PROVIDER} \
    NEXT_PUBLIC_GOOGLE_RECAPTCHA_SITE_KEY=${NEXT_PUBLIC_GOOGLE_RECAPTCHA_SITE_KEY} \
    NEXT_PUBLIC_CLOUDFLARE_TURNSTILE_SITE_KEY=${NEXT_PUBLIC_CLOUDFLARE_TURNSTILE_SITE_KEY} \
    ACCOUNT_HOST=${ACCOUNT_HOST} \
    ACCOUNT_PUBLIC_URL=${ACCOUNT_PUBLIC_URL} \
    NEXTAUTH_URL=${NEXTAUTH_URL} \
    KEYCLOAK_ISSUER=${KEYCLOAK_ISSUER}

WORKDIR /workspace

COPY --from=build --chown=node:node /workspace/apps/web/.next/standalone ./
COPY --from=build --chown=node:node /workspace/apps/web/.next/static apps/web/.next/static
COPY --from=build --chown=node:node /workspace/apps/web/public apps/web/public

EXPOSE 3000
USER node
WORKDIR /workspace/apps/web
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD node -e "fetch('http://127.0.0.1:3000/health').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["sh", "-lc", "HOSTNAME=0.0.0.0 exec node server.js"]
