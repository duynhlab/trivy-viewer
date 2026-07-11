# syntax=docker/dockerfile:1

# --- Frontend build ---
# Runs on the builder's native platform: the JS/CSS output is
# architecture-independent, so there is no reason to emulate it per target.
FROM --platform=$BUILDPLATFORM node:26-alpine AS frontend
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
# Vite outDir is ../internal/web/static; create the target so the build lands there.
RUN mkdir -p /app/internal/web/static && npm run build

# --- Go build ---
# Cross-compile on the builder's native platform instead of emulating the
# target via QEMU (the emulated arm64 leg took ~18 min vs ~2 min native).
# CGO is disabled, so GOOS/GOARCH is all Go needs.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /app
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Bring in the freshly built frontend assets for go:embed.
COPY --from=frontend /app/internal/web/static/ ./internal/web/static/
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -ldflags "-s -w \
      -X github.com/duynhlab/trivy-viewer/internal/buildinfo.Version=${VERSION} \
      -X github.com/duynhlab/trivy-viewer/internal/buildinfo.Commit=${COMMIT} \
      -X github.com/duynhlab/trivy-viewer/internal/buildinfo.BuildDate=${BUILD_DATE}" \
    -o /out/trivy-viewer ./cmd/trivy-viewer

# --- Runtime ---
FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="trivy-viewer" \
      org.opencontainers.image.description="Multi-cluster Trivy report collector and viewer (Go)" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/duynhlab/trivy-viewer"
COPY --from=build /out/trivy-viewer /app/trivy-viewer
EXPOSE 3000 8080
ENV MODE=server \
    STORAGE_PATH=/data \
    SERVER_PORT=3000 \
    HEALTH_PORT=8080 \
    LOG_FORMAT=json
USER nonroot:nonroot
ENTRYPOINT ["/app/trivy-viewer"]
