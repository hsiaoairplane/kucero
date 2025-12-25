FROM golang:1.25-bookworm AS build
WORKDIR /src

ARG VERSION=latest

COPY . .
RUN go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w -X main.version=${VERSION}" -o kucero cmd/kucero/*.go

FROM cgr.dev/chainguard/wolfi-base
WORKDIR /usr/bin
COPY --from=build /src/kucero .
ENTRYPOINT ["/usr/bin/kucero"]
