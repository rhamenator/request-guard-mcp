# syntax=docker/dockerfile:1.7
# ─── Build stage ──────────────────────────────────────────────────────────────
FROM rust:1-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies separately from source
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs && echo '' > src/lib.rs
RUN cargo build --release --locked 2>/dev/null || true
RUN rm src/main.rs src/lib.rs

# Build the real binary
COPY src ./src
RUN touch src/main.rs src/lib.rs && \
    GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown") \
    BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
    RUST_VERSION=$(rustc --version) \
    cargo build --release --locked

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r mcp && useradd -r -g mcp -d /app -s /sbin/nologin mcp

WORKDIR /app

# Copy binary
COPY --from=builder /build/target/release/ai-scraping-defense-mcp /usr/local/bin/ai-scraping-defense-mcp
RUN chmod +x /usr/local/bin/ai-scraping-defense-mcp

# Switch to non-root user
USER mcp

EXPOSE 8085

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8085/health || exit 1

ENTRYPOINT ["/usr/local/bin/ai-scraping-defense-mcp"]
