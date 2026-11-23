# SPDX-FileCopyrightText: 2026 SGNL fork contributors
#
# SPDX-License-Identifier: Apache-2.0

# SGNL's production image: builds frontend and backend from source (like upstream's Dockerfile.dev, but a production
# build: no `dev` tag, no coverage instrumentation, version stamped). Build from the repository root:
#
#   docker buildx build --platform linux/amd64 -f sgnl/Dockerfile \
#     --build-arg BUILD_TAG=v4.40.0-sgnl.1 --build-arg BUILD_COMMIT=$(git rev-parse HEAD) -t authelia-sgnl .

# ===== Frontend =====
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS builder-frontend

WORKDIR /node/src/app

ENV \
	SHELL="/bin/sh" \
	PNPM_HOME="/usr/local"

COPY --link web ./

RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
	wget -qO /tmp/pnpm-install.sh https://raw.githubusercontent.com/pnpm/get.pnpm.io/febc5a15277bb53a4d92430e4bbebeccad4828fe/install.sh && \
	ENV="/root/.profile" sh /tmp/pnpm-install.sh && \
	pnpm install --frozen-lockfile --ignore-scripts --store-dir /pnpm/store && \
	pnpm build

# ===== Backend =====
FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS builder-backend

WORKDIR /go/src/app

COPY --link go.mod go.sum ./

RUN go mod download

COPY --link / ./

COPY --link --from=builder-frontend /node/src/internal/server/public_html internal/server/public_html

ARG BUILD_TAG=""
ARG BUILD_COMMIT="unknown"
ARG BUILD_BRANCH="sgnl"

RUN \
	mv api internal/server/public_html/api && \
	X="github.com/authelia/authelia/v4/internal/utils" && \
	if [ -n "${BUILD_TAG}" ]; then STATE="tagged clean"; else STATE="untagged clean"; fi && \
	CGO_ENABLED=1 CGO_CPPFLAGS="-D_FORTIFY_SOURCE=2 -fstack-protector-strong" CGO_LDFLAGS="-Wl,-z,relro,-z,now" go build \
	-ldflags "-linkmode=external -s -w \
	-X '${X}.BuildTag=${BUILD_TAG}' -X '${X}.BuildCommit=${BUILD_COMMIT}' -X '${X}.BuildBranch=${BUILD_BRANCH}' \
	-X '${X}.BuildState=${STATE}' -X '${X}.BuildExtra=sgnl' -X '${X}.BuildDate=$(date -u '+%a, %d %b %Y %H:%M:%S +0000')'" \
	-trimpath -buildmode=pie -o authelia ./cmd/authelia

# ===== Runtime =====
FROM authelia/base:latest@sha256:9e43b55e958a38020d25dec4b690c3040f184168cf3dc1a63d8a580df876215d

WORKDIR /app

ENV \
	PATH="/app:${PATH}" \
	PUID=0 \
	PGID=0 \
	X_AUTHELIA_CONFIG="/config/configuration.yml"

COPY --link --from=builder-backend /go/src/app/authelia /go/src/app/LICENSE /go/src/app/entrypoint.sh /go/src/app/healthcheck.sh ./

COPY --link --from=builder-backend --chmod=666 /go/src/app/.healthcheck.env ./

EXPOSE 9091

ENTRYPOINT ["/app/entrypoint.sh"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=1m CMD /app/healthcheck.sh
