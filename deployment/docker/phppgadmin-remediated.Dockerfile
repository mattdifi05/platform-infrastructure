FROM tozd/phppgadmin@sha256:5ff61bbf9a22aa194872f5f6ca5cf2324fa8baba0965a504f70a591a43178fc3
USER root
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
COPY --from=platform/runtime-helpers:go1.27.1 --chmod=0755 /dinit /dinit
COPY --from=platform/runtime-helpers:go1.27.1 --chmod=0755 /regex2json /usr/local/bin/regex2json
