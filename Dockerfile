# Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only
# https://threatecho.com
#
# Multi-stage build for the ThreatEcho CLI.
#
#   docker build -t threatecho .
#   docker run --rm threatecho version

# ── Builder ──────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build.
COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 go build \
      -ldflags "-s -w \
        -X github.com/ThreatEcho/threatecho/pkg/version.Version=${VERSION} \
        -X github.com/ThreatEcho/threatecho/pkg/version.Commit=${COMMIT} \
        -X github.com/ThreatEcho/threatecho/pkg/version.BuildTime=${BUILD_DATE}" \
      -o /threatecho ./cmd/threatecho

RUN CGO_ENABLED=0 go build \
      -ldflags "-s -w \
        -X github.com/ThreatEcho/threatecho/pkg/version.Version=${VERSION} \
        -X github.com/ThreatEcho/threatecho/pkg/version.Commit=${COMMIT} \
        -X github.com/ThreatEcho/threatecho/pkg/version.BuildTime=${BUILD_DATE}" \
      -o /threatecho-agent ./cmd/threatecho-agent

# ── Runtime ──────────────────────────────────────────────────────────
FROM alpine:3.24

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 threatecho

COPY --from=builder /threatecho /usr/local/bin/threatecho
COPY --from=builder /threatecho-agent /usr/local/bin/threatecho-agent

# Include the built-in campaign library and sample policies.
COPY --from=builder /src/campaigns/ /data/campaigns/
COPY --from=builder /src/policies/ /data/policies/
COPY --from=builder /src/agents/ /data/agents/

RUN chown -R threatecho:threatecho /data

USER threatecho
WORKDIR /data

ENTRYPOINT ["threatecho"]
CMD ["help"]

LABEL org.opencontainers.image.title="ThreatEcho" \
      org.opencontainers.image.description="Detection Engineering for AI Agents" \
      org.opencontainers.image.url="https://threatecho.com" \
      org.opencontainers.image.source="https://github.com/ThreatEcho/threatecho" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.vendor="ThreatEcho"
