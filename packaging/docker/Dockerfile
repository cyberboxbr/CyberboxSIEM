# =============================================================================
# Cyberbox SIEM Agent — Docker image
# =============================================================================
#
# Multi-stage build: compile with musl for a fully static binary,
# then copy into a minimal distroless image.
#
# Build:
#   docker build -f packaging/docker/Dockerfile -t cyberbox-agent:latest .
#
# Run:
#   docker run -d --name cyberbox-agent \
#     -v /path/to/agent.toml:/etc/cyberbox/agent.toml:ro \
#     -v cyberbox-queue:/var/lib/cyberbox/queue \
#     cyberbox-agent:latest
#
# Mount the host Docker socket for container event monitoring:
#   docker run -d \
#     -v /var/run/docker.sock:/var/run/docker.sock:ro \
#     -v /path/to/agent.toml:/etc/cyberbox/agent.toml:ro \
#     cyberbox-agent:latest

# -- Stage 1: Build -----------------------------------------------------------
FROM rust:1.94-bookworm AS builder

RUN apt-get update && apt-get install -y musl-tools && \
    rustup target add x86_64-unknown-linux-musl

WORKDIR /build
COPY . .

RUN cargo build --release -p cyberbox-agent --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/cyberbox-agent

# -- Stage 2: Runtime ---------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="Cyberbox SIEM Agent"
LABEL org.opencontainers.image.description="Lightweight log-forwarding agent for CyberboxSIEM"
LABEL org.opencontainers.image.source="https://github.com/cyberboxsiem/CyberboxSIEM"
LABEL org.opencontainers.image.vendor="Cyberbox Security"

# Copy binary
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/cyberbox-agent /usr/bin/cyberbox-agent

# Copy default config
COPY --from=builder /build/apps/cyberbox-agent/agent.example.toml /etc/cyberbox/agent.toml

# Copy branding
COPY --from=builder /build/web/cyberbox-ui/public/cyberboxlogo.png /usr/share/cyberbox/logo.png

# Data volume for disk-backed queue
VOLUME ["/var/lib/cyberbox/queue"]

ENTRYPOINT ["/usr/bin/cyberbox-agent"]
CMD ["run", "--config", "/etc/cyberbox/agent.toml"]
