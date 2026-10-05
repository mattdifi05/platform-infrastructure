FROM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build
ENV GOTOOLCHAIN=local
RUN CGO_ENABLED=1 go install -trimpath -ldflags='-linkmode external -extldflags "-static"' gitlab.com/tozd/dinit/cmd/dinit@v0.4.0
RUN CGO_ENABLED=0 go install -trimpath gitlab.com/tozd/regex2json/cmd/regex2json@v0.13.0
RUN CGO_ENABLED=0 go install -trimpath github.com/tianon/gosu@1.19
FROM scratch
COPY --from=build /go/bin/dinit /go/bin/regex2json /go/bin/gosu /
