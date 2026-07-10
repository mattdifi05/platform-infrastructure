ARG NODE_IMAGE=node:26.3.1-alpine
FROM ${NODE_IMAGE}

RUN apk add --no-cache mariadb-client postgresql-client

WORKDIR /app

COPY control-center/package.json control-center/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY control-center/ ./
