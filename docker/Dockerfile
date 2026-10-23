# syntax=docker/dockerfile:1.7
# ─── Build stage ──────────────────────────────────────────────────────────────
# Review both multi-architecture index digests when updating the toolchain or OS.
FROM rust:1.99.1-slim-bookworm@sha256:54e39a2f4480fd827ebfa47736212703a1e46be0fddf7e1590aa0e94b8d0cae1 AS builder

WORKDIR /build

# Install build dependencies
RUN grep -Fxq 'VERSION_CODENAME=bookworm' /etc/os-release \
    && apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && rustc --version | grep -Fq 'rustc 1.99.1 ' \
    && dpkg-query -W -f='${Package}:${Architecture}=${Version}\n' | sort > /build/builder-packages.txt \
    && rustc --version > /build/toolchain.txt \
    && cargo --version >> /build/toolchain.txt

# Cache dependencies separately from source
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs && echo '' > src/lib.rs
RUN cargo build --release --locked 2>/dev/null || true
RUN rm src/main.rs src/lib.rs

# Build the real binary
ARG SOURCE_COMMIT=unknown
COPY src ./src
RUN touch src/main.rs src/lib.rs && \
    (test "$SOURCE_COMMIT" = unknown || printf '%s' "$SOURCE_COMMIT" | grep -Eq '^[0-9a-f]{40}$') && \
    GIT_COMMIT="$SOURCE_COMMIT" \
    BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
    RUST_VERSION=$(rustc --version) \
    cargo build --release --locked

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime

RUN grep -Fxq 'VERSION_CODENAME=bookworm' /etc/os-release \
    && apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/share/request-guard-mcp \
    && dpkg-query -W -f='${Package}:${Architecture}=${Version}\n' | sort > /usr/share/request-guard-mcp/runtime-packages.txt

COPY --from=builder /build/builder-packages.txt /usr/share/request-guard-mcp/builder-packages.txt
COPY --from=builder /build/toolchain.txt /usr/share/request-guard-mcp/toolchain.txt

# Create non-root user
RUN groupadd -r mcp && useradd -r -g mcp -d /app -s /sbin/nologin mcp

WORKDIR /app

# Copy binary
COPY --from=builder /build/target/release/request-guard-mcp /usr/local/bin/request-guard-mcp
RUN chmod +x /usr/local/bin/request-guard-mcp

# Switch to non-root user
USER mcp

EXPOSE 8085

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8085/health || exit 1

ENTRYPOINT ["/usr/local/bin/request-guard-mcp"]
