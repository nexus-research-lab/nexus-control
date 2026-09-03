# syntax=docker/dockerfile:1.7
ARG GO_IMAGE=golang:1.26.2-bookworm

FROM ${GO_IMAGE} AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -o /out/nexus-control ./cmd/nexus-control

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1002 control \
    && useradd --system --uid 1002 --gid control --home-dir /var/lib/nexus-control --create-home control
COPY --from=builder --chown=root:root --chmod=0755 /out/nexus-control /usr/local/bin/nexus-control
USER control
WORKDIR /var/lib/nexus-control
EXPOSE 8020
ENTRYPOINT ["/usr/local/bin/nexus-control"]
