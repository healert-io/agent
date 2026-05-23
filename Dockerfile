# =============================================================================
# Dockerfile — Healert Go Agent v0.1.1
# =============================================================================
#
# Copyright 2026 Healert OÜ
# Licensed under the Apache License, Version 2.0
# https://www.apache.org/licenses/LICENSE-2.0
#
# =============================================================================
# ENTERPRISE REQUIREMENTS ADDRESSED
# =============================================================================
#
# 1. PRIVATE REGISTRY SUPPORT
#    Enterprises cannot pull from gcr.io or docker.io directly.
#    Use BUILD ARGS to override base images at build time:
#
#      docker build \
#        --build-arg BUILDER_IMAGE=registry.company.com/mirror/golang:1.22-alpine \
#        --build-arg FINAL_IMAGE=registry.company.com/mirror/distroless-static:nonroot \
#        -t registry.company.com/healert/agent:0.1.1 .
#
# 2. MULTI-ARCHITECTURE
#    Enterprises run mixed clusters (amd64 control-plane, arm64 workers,
#    AWS Graviton, Azure Ampere). TARGETARCH auto-detects via buildx.
#
#      docker buildx build \
#        --platform linux/amd64,linux/arm64 \
#        --build-arg BUILDER_IMAGE=registry.company.com/mirror/golang:1.22-alpine \
#        --build-arg FINAL_IMAGE=registry.company.com/mirror/distroless-static:nonroot \
#        -t registry.company.com/healert/agent:0.1.1 \
#        --push .
#
# 3. PROVENANCE AND SBOM
#    Enterprises require supply chain attestations for compliance (SOC2, ISO27001).
#
#      docker buildx build \
#        --provenance=true \
#        --sbom=true \
#        --platform linux/amd64,linux/arm64 \
#        -t registry.company.com/healert/agent:0.1.1 \
#        --push .
#
# 4. IMAGE SIGNING (Cosign / Notary)
#    After push:
#      cosign sign --key cosign.key registry.company.com/healert/agent:0.1.1
#      cosign verify --key cosign.pub registry.company.com/healert/agent:0.1.1
#
# 5. VULNERABILITY SCANNING
#    Before deploying to production:
#      trivy image ghcr.io/healert/agent:0.1.1
#      grype ghcr.io/healert/agent:0.1.1
#    Distroless base has near-zero CVEs vs alpine or ubuntu.
#
# 6. BUILD REPRODUCIBILITY
#    Pin base image digests for fully reproducible builds:
#      docker pull golang:1.22-alpine
#      docker inspect golang:1.22-alpine --format "{{.Id}}"
#    Then use: FROM golang:1.22-alpine@sha256:<digest> AS builder
#
# 7. PROXY AND FIREWALL
#    Enterprises route all traffic through proxies. Pass at build time:
#
#      docker build \
#        --build-arg HTTP_PROXY=http://proxy.company.com:8080 \
#        --build-arg HTTPS_PROXY=http://proxy.company.com:8080 \
#        --build-arg NO_PROXY=localhost,127.0.0.1,.company.com \
#        -t registry.company.com/healert/agent:0.1.1 .
#
# 8. CUSTOM RULES WITHOUT REBUILD
#    Mount custom rules.yaml at runtime — no image rebuild on rule changes:
#
#      kubectl create configmap healert-rules \
#        --from-file=rules.yaml=/etc/healert/rules.yaml \
#        -n healert-system
#    Then mount in daemonset.yaml:
#      volumes:
#        - name: rules
#          configMap:
#            name: healert-rules
#      volumeMounts:
#        - name: rules
#          mountPath: /rules.yaml
#          subPath: rules.yaml
#          readOnly: true
#
# =============================================================================
# SIMPLE BUILD (development / single-node k3s)
# =============================================================================
#
#   docker build -t ghcr.io/healert/agent:0.1.1 .
#   docker run --rm \
#     --add-host=host.docker.internal:host-gateway \
#     -e HEALERT_BACKEND_URL=http://host.docker.internal:8000 \
#     -e HEALERT_API_KEY="$(grep HEALERT_API_KEY .env | cut -d= -f2-)" \
#     -e AUDIT_LOG_PATH=/var/log/k3s-audit.log \
#     -e RULES_PATH=/rules.yaml \
#     -e ENTITY_NAMESPACE=default \
#     -v /var/log/k3s-audit.log:/var/log/k3s-audit.log:ro \
#     ghcr.io/healert/agent:0.1.1
#
# =============================================================================

# ── Build arguments — override for private registries ─────────────────────────
#
# Default to public registries for open-source / development use.
# Enterprise teams override with their internal mirrors:
#
#   --build-arg BUILDER_IMAGE=registry.company.com/mirror/golang:1.22-alpine
#   --build-arg FINAL_IMAGE=registry.company.com/mirror/distroless-static:nonroot
#
ARG BUILDER_IMAGE=golang:1.22-alpine
ARG FINAL_IMAGE=gcr.io/distroless/static:nonroot

# ── Build metadata labels ─────────────────────────────────────────────────────
#
# OCI standard labels — used by enterprise image scanners, registries,
# and governance tools (Harbor, Artifactory, Quay, ECR).
# These appear in: docker inspect, trivy, grype, Snyk, Prisma Cloud.
ARG BUILD_DATE
ARG GIT_COMMIT
ARG GIT_BRANCH=main
ARG VERSION=0.1.1

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM ${BUILDER_IMAGE} AS builder

# Re-declare ARGs after FROM — they reset scope per stage
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=0.1.1
ARG GIT_COMMIT=unknown
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

# Proxy support — enterprise networks route Docker builds through proxies
ENV HTTP_PROXY=${HTTP_PROXY} \
    HTTPS_PROXY=${HTTPS_PROXY} \
    NO_PROXY=${NO_PROXY}

# Minimal build dependencies only
# ca-certificates: required in final image for HTTPS backend connections
# tzdata:          accurate UTC timestamps in friction event payloads
# No git: zero external Go dependencies — go mod download is a no-op
RUN apk add --no-cache \
      ca-certificates \
      tzdata

WORKDIR /build

# Copy go.mod first for layer caching — dependencies only re-fetched
# when go.mod changes, not on every source code change
COPY go.mod ./
RUN go mod download

# Copy source files
COPY main.go    ./
COPY rules.yaml ./

# Build static binary
#   CGO_ENABLED=0      — pure Go, static binary, works in distroless
#   GOOS/GOARCH        — from buildx TARGETPLATFORM, supports multi-arch
#   -w -s              — strip DWARF and symbol table (~30% smaller)
#   -trimpath          — remove local build paths from binary (security)
#                        prevents leaking developer machine paths in stack traces
#   -X main.version    — embed version string accessible in agent startup log
#   -X main.gitCommit  — embed git commit for traceability in enterprise audit
RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    go build \
      -trimpath \
      -ldflags="-w -s \
        -X main.version=${VERSION} \
        -X main.gitCommit=${GIT_COMMIT}" \
      -o healert-agent \
      main.go

# Verify: no CGO symbols in binary (faster and more reliable than ldd/file)
# go tool nm lists all symbols — cgo_init only exists in CGO binaries
RUN if go tool nm healert-agent 2>/dev/null | grep -q "cgo_init"; then \
      echo "ERROR: CGO symbols found — binary is not static"; exit 1; \
    else \
      echo "OK: binary is static (no CGO symbols)"; \
    fi

# ── Stage 2: Final distroless image ───────────────────────────────────────────
#
# gcr.io/distroless/static:nonroot:
#   - No shell, no package manager, no libc, no coreutils
#   - Only: CA certs, tzdata, nonroot user (uid=65532, gid=65532)
#   - Near-zero CVEs vs alpine (~20 CVEs) or ubuntu (~50 CVEs)
#   - Final image: ~20MB vs ~300MB for alpine-based agents
#
# Enterprise mirror: set FINAL_IMAGE build arg to your internal copy.
FROM ${FINAL_IMAGE}

# Re-declare build ARGs for this stage
ARG BUILD_DATE
ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=main
ARG VERSION=0.1.1

# OCI standard image labels
# Used by: Harbor, Artifactory, Quay, ECR, image scanners, k8s admission policies
LABEL org.opencontainers.image.title="Healert Agent" \
      org.opencontainers.image.description="Kubernetes audit log friction detection agent" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.ref.name="${GIT_BRANCH}" \
      org.opencontainers.image.source="https://github.com/healert/agent" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Healert OÜ" \
      org.opencontainers.image.documentation="https://github.com/healert/agent/blob/main/README.md"

# Copy timezone data — UTC timestamps in all friction event payloads
COPY --chown=nonroot:nonroot --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy CA certificates — HTTPS connections to backend (if TLS enabled)
COPY --chown=nonroot:nonroot --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy compiled agent binary
COPY --chown=nonroot:nonroot --from=builder /build/healert-agent /healert-agent

# Copy default rules.yaml — bundled as fallback for simple deployments.
#
# ENTERPRISE RECOMMENDATION: mount a ConfigMap instead of using bundled rules.
# This avoids rebuilding the image on every rule change:
#
#   kubectl create configmap healert-rules \
#     --from-file=rules.yaml=/path/to/rules.yaml \
#     -n healert-system
#
# Then in daemonset.yaml add:
#   volumes:
#     - name: rules
#       configMap:
#         name: healert-rules
#   volumeMounts:
#     - name: rules
#       mountPath: /rules.yaml
#       subPath: rules.yaml
#       readOnly: true
COPY --chown=nonroot:nonroot --from=builder /build/rules.yaml /rules.yaml

# Run as nonroot (uid=65532)
# Matches daemonset.yaml securityContext:
#   runAsNonRoot: true
#   runAsUser: 65532
USER nonroot:nonroot

# All configuration via environment variables — see .env.example
# No hardcoded values — safe for enterprise secret management (Vault, AWS SSM)
ENTRYPOINT ["/healert-agent"]
