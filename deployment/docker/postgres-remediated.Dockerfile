FROM postgres:18.6-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873
RUN apk upgrade --no-cache
COPY --from=platform/runtime-helpers:go1.27.1 --chmod=0755 /gosu /usr/local/bin/gosu
