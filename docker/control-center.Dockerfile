ARG NODE_IMAGE=node:26.3.1-alpine
FROM ${NODE_IMAGE}

RUN apk add --no-cache mariadb-client postgresql-client

WORKDIR /app
