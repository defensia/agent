FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=0.0.0
ARG BUILD_TAGS=""
RUN CGO_ENABLED=0 GOOS=linux go build \
    -tags "${BUILD_TAGS}" \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /defensia-agent \
    ./cmd/defensia-agent

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM alpine:3.23

RUN apk add --no-cache \
    iptables \
    ip6tables \
    ipset \
    ca-certificates \
    curl \
    bash

COPY --from=builder /defensia-agent /usr/local/bin/defensia-agent
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh /usr/local/bin/defensia-agent

ENV DEFENSIA_CONFIG=/etc/defensia/config.json
ENV DEFENSIA_SERVER_URL=https://defensia.cloud

ENTRYPOINT ["docker-entrypoint.sh"]
